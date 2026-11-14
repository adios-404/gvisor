// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bbr_test

import (
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/simnet"
)

// Each test below is the Appendix A case of the same number. The comments
// quote the case's steps by number; where the test departs from a step, the
// comment says why.

// TestA01StartupExitsOnBandwidthPlateau is A.1, "Exiting STARTUP on
// Bandwidth Plateau".
func TestA01StartupExitsOnBandwidthPlateau(t *testing.T) {
	r := newRun(t, standard)
	// 1-2. Start a flow in Startup with enough data to send.
	r.f.Bulk()
	s := r.leave(10*time.Second, tcp.BBRStartup)
	// 5. Startup to Drain.
	if s.bbr.State != tcp.BBRDrain {
		t.Fatalf("Startup left for %v, want Drain", s.bbr.State)
	}
	// 3. BBR.max_bw within 2% of the path's bandwidth.
	if want := r.goodput(); !within(s.bbr.MaxBw, want, 2) {
		t.Errorf("max_bw = %d, want within 2%% of %d", s.bbr.MaxBw, want)
	}
	// 4. Three rounds of less than 25% growth set full_bw_now and
	// full_bw_reached.
	if !s.bbr.FullBwNow || !s.bbr.FullBwReached || s.bbr.FullBwCount != 3 {
		t.Errorf("full_bw_now %t, full_bw_reached %t, full_bw_count %d; want true, true, 3", s.bbr.FullBwNow, s.bbr.FullBwReached, s.bbr.FullBwCount)
	}
	// A plateau, not loss, ended Startup.
	if st := r.n.Data.Stats(); st.QueueDrops+st.RandomDrops != 0 {
		t.Errorf("the path dropped %d packets", st.QueueDrops+st.RandomDrops)
	}
}

// TestA02StartupExitsOnLossWhenAppLimited is A.2, "Exiting STARTUP on Loss
// When Application-Limited".
func TestA02StartupExitsOnLossWhenAppLimited(t *testing.T) {
	r := newRun(t, standard)
	// 1-2. Startup, with the application sending at a quarter of the path's
	// rate.
	r.f.Limit(r.goodputAt(r.p.rate) / 4)
	r.n.RunFor(time.Second)
	if s := r.last(); s.bbr.State != tcp.BBRStartup {
		t.Fatalf("application-limited flow left Startup without loss: %s", describe(s))
	}
	// 3. Drop a third of the data for two round trips, so that at least one
	// whole loss round sees BBR.StartupFullLossCnt (6) separate losses and
	// more than BBR.LossThresh (2%) of what was in flight.
	var drops int
	start := r.now()
	r.n.SetFilter(r.n.Data, dropEvery(r, 3, start+2*r.p.rtt, &drops))
	s := r.leave(2*time.Second, tcp.BBRStartup)
	// 4-5. CheckStartupHighLoss() ended Startup: full_bw_reached is set
	// although the samples were application-limited, and Startup went to
	// Drain. Little is in flight, so Drain, and ProbeBW_DOWN after it, end
	// on the same ACK; that Drain began in this round shows it was entered.
	if !s.bbr.FullBwReached || s.bbr.DrainStartRound != s.bbr.RoundCount {
		t.Fatalf("after loss: %s, drain_start_round %d; want Drain entered with full_bw_reached", describe(s), s.bbr.DrainStartRound)
	}
	if s.bbr.MaxBw > r.goodput()/2 {
		t.Errorf("max_bw = %d, more than half the path's %d: the flow was not application-limited", s.bbr.MaxBw, r.goodput())
	}
	// CheckStartupHighLoss() also sets BBR.inflight_longterm.
	if s.bbr.InflightLongterm == infinity {
		t.Error("inflight_longterm is not set")
	}
	if s.at > start+3*r.p.rtt+r.p.rtt/2 {
		t.Errorf("Startup ended %v after the losses began, want within 3.5 round trips", s.at-start)
	}
	t.Logf("dropped %d packets; Startup ended %v after the first", drops, s.at-start)
}

// TestA03DrainExitsOnInflight is A.3, "Exiting DRAIN Based on Inflight".
func TestA03DrainExitsOnInflight(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	// 1-2. Drain paces at BBR.DrainPacingGain (0.5).
	d := r.enter(10*time.Second, tcp.BBRDrain)
	if d.bbr.PacingGain != 500 {
		t.Errorf("pacing_gain in Drain = %d/1000, want 500", d.bbr.PacingGain)
	}
	i := r.mark()
	s := r.leave(5*time.Second, tcp.BBRDrain)
	for _, x := range r.since(i) {
		if x.bbr.State == tcp.BBRDrain && x.bbr.PacingGain != 500 {
			t.Fatalf("pacing_gain in Drain = %d/1000 at %v, want 500", x.bbr.PacingGain, x.at)
		}
	}
	// 3-4. Drain ends when C.inflight <= BBRInflight(1.0), before its three
	// rounds are up, and goes to ProbeBW (through DOWN, which ends at once
	// for the same reason).
	if s.bbr.State != tcp.BBRProbeBWDown && s.bbr.State != tcp.BBRProbeBWCruise {
		t.Fatalf("Drain left for %v, want ProbeBW", s.bbr.State)
	}
	if rounds := s.bbr.RoundCount - d.bbr.DrainStartRound; rounds > 3 {
		t.Errorf("Drain lasted %d rounds, want at most 3 (else it ended on time)", rounds)
	}
	if target := max(bytesInTime(s.bbr.MaxBw, s.bbr.MinRTT), s.bbr.OffloadBudget); s.rate.InFlight > target {
		t.Errorf("C.inflight = %d when Drain ended, above BBRInflight(1.0) = %d", s.rate.InFlight, target)
	}
}

// TestA04DrainExitsOnTime is A.4, "Exiting DRAIN Based on Time".
func TestA04DrainExitsOnTime(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	d := r.enter(10*time.Second, tcp.BBRDrain)
	// 2-3. Reduce the bandwidth upon entering Drain, so that C.inflight stays
	// above BBRInflight(1.0). The case suggests 10%; on this path that lets
	// the queue drain in under three rounds, so the bandwidth is halved,
	// which Drain's pacing gain of 0.5 can no longer drain.
	r.n.Data.SetRate(r.p.rate / 2)
	i := r.mark()
	s := r.leave(5*time.Second, tcp.BBRDrain)
	// 4-5. After three rounds in Drain, ProbeBW.
	if s.bbr.State != tcp.BBRProbeBWDown {
		t.Fatalf("Drain left for %v, want ProbeBW_DOWN", s.bbr.State)
	}
	if rounds := s.bbr.RoundCount - d.bbr.DrainStartRound; rounds != 4 {
		t.Errorf("Drain ended %d rounds after it started, want 4 (more than BBR.DrainMaxRounds = 3)", rounds)
	}
	for _, x := range r.since(i) {
		if x.bbr.State != tcp.BBRDrain {
			break
		}
		if target := max(bytesInTime(x.bbr.MaxBw, x.bbr.MinRTT), x.bbr.OffloadBudget); x.rate.InFlight <= target {
			t.Fatalf("C.inflight = %d at %v, down to BBRInflight(1.0) = %d", x.rate.InFlight, x.at, target)
		}
	}
}

// probeBWUp runs a bulk flow until it starts probing for bandwidth in
// ProbeBW_UP, and returns the first sample there.
func probeBWUp(r *run) sample {
	r.t.Helper()
	r.f.Bulk()
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	return r.enter(10*time.Second, tcp.BBRProbeBWUp)
}

// TestA05ProbeUpExitsOnBandwidthPlateau is A.5, "Exiting PROBE_UP on
// Bandwidth Plateau".
func TestA05ProbeUpExitsOnBandwidthPlateau(t *testing.T) {
	r := newRun(t, standard)
	// 1. ProbeBW_UP.
	up := probeBWUp(r)
	// 2-3. The queue never overflows, so there is no loss, and the delivery
	// rate plateaus. The flow sends all it may: it is never
	// application-limited. (ProbeBW_UP paces at 1.25 times max_bw, and on
	// this path the rate plateaus before C.inflight reaches cwnd.)
	i := r.mark()
	s := r.leave(5*time.Second, tcp.BBRProbeBWUp)
	for _, x := range r.since(i) {
		if x.bbr.State == tcp.BBRProbeBWUp && x.rate.AppLimited != 0 {
			t.Fatalf("application-limited in ProbeBW_UP at %v", x.at)
		}
	}
	// 4-5. Three rounds without 25% growth set full_bw_now, and
	// BBRIsTimeToGoDown() moves to ProbeBW_DOWN.
	if s.bbr.State != tcp.BBRProbeBWDown {
		t.Fatalf("ProbeBW_UP left for %v, want ProbeBW_DOWN", s.bbr.State)
	}
	if !s.bbr.FullBwNow || s.bbr.FullBwCount != 3 {
		t.Errorf("full_bw_now %t, full_bw_count %d; want true, 3", s.bbr.FullBwNow, s.bbr.FullBwCount)
	}
	if rounds := s.bbr.RoundCount - up.bbr.RoundCount; rounds < 3 {
		t.Errorf("ProbeBW_UP lasted %d rounds, want at least 3", rounds)
	}
	if st := r.n.Data.Stats(); st.QueueDrops+st.RandomDrops != 0 {
		t.Errorf("the path dropped %d packets", st.QueueDrops+st.RandomDrops)
	}
}

// TestA06ProbeUpExitsOnLossWhenAppLimited is A.6, "Exiting PROBE_UP on Loss
// When Application-Limited".
func TestA06ProbeUpExitsOnLossWhenAppLimited(t *testing.T) {
	r := newRun(t, standard)
	// 1-2. ProbeBW_UP, then the application sends at half the path's rate,
	// until the samples are application-limited.
	r.f.Bulk()
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	r.limitBacklog()
	before := r.enter(10*time.Second, tcp.BBRProbeBWUp)
	r.f.Limit(r.goodput() / 2)
	// Once the connection is marked application-limited (C.app_limited),
	// the packets it sends, and so the samples a round trip later, are too.
	r.until(time.Second, "C.app_limited", func(s *sample) bool { return s.rate.AppLimited != 0 })
	r.n.RunFor(r.p.rtt)
	if s := r.last(); s.bbr.State != tcp.BBRProbeBWUp || s.rate.AppLimited == 0 {
		t.Fatalf("before any loss: %s, C.app_limited %d; want ProbeBW_UP and application-limited", describe(s), s.rate.AppLimited)
	}
	// 3. Drop a third of the data for a round trip.
	var drops int
	start := r.now()
	r.n.SetFilter(r.n.Data, dropEvery(r, 3, start+r.p.rtt, &drops))
	s := r.leave(2*time.Second, tcp.BBRProbeBWUp)
	// 4-5. The loss rate ends ProbeBW_UP although the flow is
	// application-limited. Little is in flight, so ProbeBW_DOWN may give way
	// to ProbeBW_CRUISE on the same ACK; undo_state and prev_probe_too_high
	// show that BBRHandleInflightTooHigh() started ProbeBW_DOWN.
	if s.bbr.State != tcp.BBRProbeBWDown && s.bbr.State != tcp.BBRProbeBWCruise {
		t.Fatalf("ProbeBW_UP left for %v, want ProbeBW_DOWN", s.bbr.State)
	}
	if !s.bbr.PrevProbeTooHigh || s.bbr.UndoState != tcp.BBRProbeBWUp {
		t.Errorf("prev_probe_too_high %t, undo_state %v; want true, ProbeBW_UP (BBRHandleInflightTooHigh())", s.bbr.PrevProbeTooHigh, s.bbr.UndoState)
	}
	// BBRHandleInflightTooHigh() sets inflight_longterm only from samples
	// that are not application-limited. The case's "updated appropriately,
	// regardless of the application-limited state" is read as that rule:
	// this flow's lost packets were all sent application-limited.
	if s.bbr.InflightLongterm != before.bbr.InflightLongterm {
		t.Errorf("inflight_longterm = %s, want it unchanged at %s", volume(s.bbr.InflightLongterm), volume(before.bbr.InflightLongterm))
	}
	if s.at > start+2*r.p.rtt {
		t.Errorf("ProbeBW_UP ended %v after the losses began, want within 2 round trips", s.at-start)
	}
}

// TestA07NeverExitsWhenAppLimitedWithoutLoss is A.7, "Never Exiting PROBE_UP
// (or STARTUP) When Application-Limited With No Loss".
func TestA07NeverExitsWhenAppLimitedWithoutLoss(t *testing.T) {
	t.Run("Startup", func(t *testing.T) {
		r := newRun(t, standard)
		r.f.Limit(r.goodputAt(r.p.rate) / 4)
		i := r.mark()
		// ProbeRTT, every 10 seconds, interrupts Startup and returns to it
		// (A.20), so it is allowed.
		r.n.RunFor(30 * time.Second)
		for _, s := range r.since(i) {
			if s.bbr.State != tcp.BBRStartup && s.bbr.State != tcp.BBRProbeRTT {
				t.Fatalf("left Startup for %v at %v: %s", s.bbr.State, s.at, describe(s))
			}
		}
		if s := r.last(); s.bbr.State != tcp.BBRStartup || s.bbr.FullBwReached {
			t.Errorf("after 30s: %s; want Startup without full_bw_reached", describe(s))
		}
	})
	t.Run("ProbeBW_UP", func(t *testing.T) {
		r := newRun(t, standard)
		r.f.Bulk()
		r.enter(10*time.Second, tcp.BBRProbeBWCruise)
		r.limitBacklog()
		up := r.enter(10*time.Second, tcp.BBRProbeBWUp)
		r.f.Limit(r.goodput() / 2)
		r.until(time.Second, "C.app_limited", func(s *sample) bool { return s.rate.AppLimited != 0 })
		// ProbeBW_UP lasts until ProbeRTT, which this case does not cover,
		// takes over once BBR.min_rtt is 10 seconds old.
		s := r.leave(20*time.Second, tcp.BBRProbeBWUp)
		if s.bbr.State != tcp.BBRProbeRTT {
			t.Fatalf("ProbeBW_UP left for %v at %v, want ProbeRTT: %s", s.bbr.State, s.at, describe(s))
		}
		if d := s.at - up.at; d < 5*time.Second {
			t.Errorf("ProbeBW_UP lasted only %v", d)
		}
	})
}

// TestA08ProbeDownExitsOnInflight is A.8, "Exiting PROBE_DOWN on Inflight".
func TestA08ProbeDownExitsOnInflight(t *testing.T) {
	r := newRun(t, standard)
	// 1. ProbeBW_DOWN after probing, so that there is a queue to drain.
	probeBWUp(r)
	down := r.enter(5*time.Second, tcp.BBRProbeBWDown)
	// 2. Pacing gain 0.9.
	if down.bbr.PacingGain != 900 {
		t.Errorf("pacing_gain in ProbeBW_DOWN = %d/1000, want 900", down.bbr.PacingGain)
	}
	// 3-5. Once C.inflight is down to BBRInflightWithHeadroom() and
	// BBRInflight(1.0), ProbeBW_CRUISE.
	s := r.leave(5*time.Second, tcp.BBRProbeBWDown)
	if s.bbr.State != tcp.BBRProbeBWCruise {
		t.Fatalf("ProbeBW_DOWN left for %v, want ProbeBW_CRUISE", s.bbr.State)
	}
	if down.rate.InFlight <= bytesInTime(down.bbr.MaxBw, down.bbr.MinRTT) {
		t.Errorf("C.inflight = %d on entering ProbeBW_DOWN: no queue to drain", down.rate.InFlight)
	}
	if target := max(bytesInTime(s.bbr.MaxBw, s.bbr.MinRTT), s.bbr.OffloadBudget); s.rate.InFlight > target {
		t.Errorf("C.inflight = %d on entering ProbeBW_CRUISE, above BBRInflight(1.0) = %d", s.rate.InFlight, target)
	}
	if headroom := inflightWithHeadroom(s); s.rate.InFlight > headroom {
		t.Errorf("C.inflight = %d on entering ProbeBW_CRUISE, above BBRInflightWithHeadroom() = %d", s.rate.InFlight, headroom)
	}
	if d := s.at - down.at; d >= down.bbr.BwProbeWait {
		t.Errorf("ProbeBW_DOWN lasted %v, not less than bw_probe_wait %v", d, down.bbr.BwProbeWait)
	}
}

// TestA09ProbeDownExitsAfterMaxTime is A.9, "Exiting PROBE_DOWN After Max
// Time".
func TestA09ProbeDownExitsAfterMaxTime(t *testing.T) {
	r := newRun(t, standard)
	probeBWUp(r)
	down := r.enter(5*time.Second, tcp.BBRProbeBWDown)
	// 2. Keep C.inflight above BBRInflight(1.0) by reducing the bandwidth on
	// entering ProbeBW_DOWN. As in A.4, 10% is not enough on this path: the
	// pacing gain of 0.9 with its 1% margin drains the queue within the
	// probe wait. A 20% cut keeps a queue.
	r.n.Data.SetRate(r.p.rate * 8 / 10)
	s := r.leave(5*time.Second, tcp.BBRProbeBWDown)
	// 3-4. After bw_probe_wait, ProbeBW_REFILL, bypassing ProbeBW_CRUISE.
	if s.bbr.State != tcp.BBRProbeBWRefill {
		t.Fatalf("ProbeBW_DOWN left for %v, want ProbeBW_REFILL", s.bbr.State)
	}
	if d := s.at - down.at; d < down.bbr.BwProbeWait {
		t.Errorf("ProbeBW_DOWN lasted %v, less than bw_probe_wait %v", d, down.bbr.BwProbeWait)
	}
	// The wall clock, not the Reno-coexistence round count, ended it.
	if rounds := s.bbr.RoundCount - down.bbr.RoundCount; rounds >= 63 {
		t.Errorf("ProbeBW_DOWN lasted %d rounds", rounds)
	}
}

// TestA10EnterAndExitProbeRTT is A.10, "Entering and Exiting PROBE_RTT".
func TestA10EnterAndExitProbeRTT(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	// 1. ProbeBW.
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	// 2-3. Ten seconds without a lower RTT sample: ProbeRTT, with a cwnd
	// gain of 0.5 and C.cwnd bounded by ProbeRTTCwnd().
	i := r.mark()
	in := r.enter(15*time.Second, tcp.BBRProbeRTT)
	if prev := r.since(i)[0]; prev.bbr.State == tcp.BBRStartup || prev.bbr.State == tcp.BBRDrain {
		t.Fatalf("ProbeRTT entered from %v", prev.bbr.State)
	}
	if in.bbr.CwndGain != 500 {
		t.Errorf("cwnd_gain in ProbeRTT = %d/1000, want 500", in.bbr.CwndGain)
	}
	j := r.mark()
	out := r.leave(2*time.Second, tcp.BBRProbeRTT)
	var drained time.Duration
	var drainedRound uint64
	for _, s := range append([]sample{in}, r.since(j)...) {
		if s.bbr.State != tcp.BBRProbeRTT {
			break
		}
		bound := max(bytesInTime(s.bbr.Bw, s.bbr.MinRTT)/2, 4*uint64(s.mss))
		if s.bbr.Cwnd > bound {
			t.Fatalf("C.cwnd = %d in ProbeRTT at %v, above ProbeRTTCwnd() = %d", s.bbr.Cwnd, s.at, bound)
		}
		if drained == 0 && s.rate.InFlight <= bound {
			drained, drainedRound = s.at, s.bbr.RoundCount
		}
	}
	// 4. Once C.inflight <= ProbeRTTCwnd(), at least BBR.ProbeRTTDuration
	// (200 ms) and at least a round.
	if drained == 0 {
		t.Fatal("C.inflight never fell to ProbeRTTCwnd()")
	}
	if d := out.at - drained; d <= 200*time.Millisecond || out.bbr.RoundCount <= drainedRound {
		t.Errorf("ProbeRTT ended %v and %d rounds after C.inflight fell to ProbeRTTCwnd(), want over 200ms and at least a round", d, out.bbr.RoundCount-drainedRound)
	}
	// 5. Back to ProbeBW, with the default cwnd gain, sending again.
	if out.bbr.State != tcp.BBRProbeBWCruise || out.bbr.CwndGain != 2000 {
		t.Fatalf("ProbeRTT left for %v with cwnd_gain %d/1000, want ProbeBW_CRUISE with 2000", out.bbr.State, out.bbr.CwndGain)
	}
	received := r.f.Received()
	r.n.RunFor(time.Second)
	if got, want := r.f.Received()-received, r.goodput()*9/10; got < want {
		t.Errorf("received %d bytes in the second after ProbeRTT, want at least %d", got, want)
	}
}

// TestA11IdleSkipsProbeRTT is A.11, "Skipping PROBE_RTT Due to
// Application-Limited Sending".
func TestA11IdleSkipsProbeRTT(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	// 1. ProbeBW.
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	// 2-3. The application stops, C.inflight drops to zero, and
	// BBR.MinRTTFilterLen (10 seconds) passes.
	r.f.Stop()
	r.until(5*time.Second, "C.inflight = 0", func(s *sample) bool { return s.rate.InFlight == 0 })
	idle := r.last()
	r.n.RunFor(11 * time.Second)
	// 4-5. On sending again, BBRHandleRestartFromIdle() sets idle_restart,
	// so BBR.min_rtt expires without ProbeRTT.
	i := r.mark()
	r.f.Bulk()
	first := r.until(time.Second, "an ACK", func(*sample) bool { return true })
	if !first.bbr.MinRTTExpired {
		t.Fatalf("min_rtt not expired after %v idle: %s", r.now()-idle.at, describe(first))
	}
	if first.bbr.MinRTTStamp.Sub(idle.bbr.MinRTTStamp) <= 0 {
		t.Errorf("min_rtt_stamp not renewed by the first sample after idle")
	}
	r.n.RunFor(time.Second)
	for _, s := range r.since(i) {
		if s.bbr.State == tcp.BBRProbeRTT {
			t.Fatalf("ProbeRTT at %v after restarting from idle", s.at)
		}
	}
}

// TestA12StartupWithACKAggregation is A.12, "Achieving Expected STARTUP
// Bandwidth on a Link With Aggregation".
func TestA12StartupWithACKAggregation(t *testing.T) {
	r := newRun(t, standard)
	// 1. ACKs arrive in bursts every 20 ms, as on a Wi-Fi or cellular link.
	r.n.SetFilter(r.n.Acks, aggregateAcks(r, 20*time.Millisecond))
	// 2. Startup.
	r.f.Bulk()
	i := r.mark()
	s := r.leave(10*time.Second, tcp.BBRStartup)
	// 3. BBR.extra_acked measures the bursts, about 20 ms of data, and
	// C.cwnd exceeds 2 * BDP by as much. (Without aggregation both stay
	// near a packet.)
	burst := bytesInTime(r.goodput(), 20*time.Millisecond)
	var maxExtra, maxAbove uint64
	for _, x := range r.since(i) {
		if x.bbr.State != tcp.BBRStartup {
			break
		}
		maxExtra = max(maxExtra, x.bbr.ExtraAcked)
		if x.bbr.Cwnd > 2*x.bbr.BDP {
			maxAbove = max(maxAbove, x.bbr.Cwnd-2*x.bbr.BDP)
		}
	}
	if maxExtra < burst/2 || maxAbove < burst/2 {
		t.Errorf("in Startup extra_acked reached %d and C.cwnd exceeded 2 * BDP by %d, want both at least half a 20 ms burst (%d)", maxExtra, maxAbove, burst)
	}
	// 4. The bandwidth estimate still finds the path's bandwidth. It may
	// overshoot: a packet sent between the ACKs of one burst counts the
	// rest of that burst as delivered within its interval. That adds at
	// most one burst per round trip, 20 ms in 100 ms here. Capping the
	// interval by the send time does not help in Startup, which sends 2.77
	// times faster than the path.
	if s.bbr.State != tcp.BBRDrain {
		t.Fatalf("Startup left for %v, want Drain", s.bbr.State)
	}
	if want := r.goodput(); s.bbr.MaxBw < want*98/100 || s.bbr.MaxBw > want*120/100 {
		t.Errorf("max_bw = %d, want 98-120%% of %d", s.bbr.MaxBw, want)
	}
	t.Logf("max_bw %d is %.1f%% of the path's %d", s.bbr.MaxBw, 100*float64(s.bbr.MaxBw)/float64(r.goodput()), r.goodput())
}

// TestA13CruiseWithACKAggregation is A.13, "Achieving Expected Cruise
// Bandwidth on a Link With Aggregation".
func TestA13CruiseWithACKAggregation(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	// 1-2. ProbeBW_CRUISE, then ACKs arrive in bursts every 20 ms.
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	r.n.SetFilter(r.n.Acks, aggregateAcks(r, 20*time.Millisecond))
	i := r.mark()
	received := r.f.Received()
	r.n.RunFor(time.Second)
	// 3. extra_acked follows the bursts: about 20 ms of data.
	var maxExtra uint64
	var augmented bool
	for _, s := range r.since(i) {
		maxExtra = max(maxExtra, s.bbr.ExtraAcked)
		if s.bbr.State == tcp.BBRProbeBWCruise && s.bbr.ExtraAcked > 0 && s.bbr.Cwnd > 2*s.bbr.BDP {
			augmented = true
		}
	}
	if burst := bytesInTime(r.goodput(), 20*time.Millisecond); maxExtra < burst/2 {
		t.Errorf("extra_acked reached %d, want at least half of a 20 ms burst (%d)", maxExtra, burst)
	}
	// 4. C.cwnd grows by extra_acked, so the flow keeps the path busy.
	if !augmented {
		t.Error("C.cwnd never exceeded 2 * BDP in ProbeBW_CRUISE")
	}
	if got, want := r.f.Received()-received, r.goodput()*95/100; got < want {
		t.Errorf("received %d bytes in a second, want at least %d", got, want)
	}
}

// TestA14SubPacketBDP is A.14, "Correctly Managing Sub-Packet BDPs".
func TestA14SubPacketBDP(t *testing.T) {
	// 1. 100 kbit/s with 10 ms of delay: a BDP of 125 bytes. A full packet
	// takes 120 ms to send.
	r := newRun(t, path{rate: 12_500, rtt: 10 * time.Millisecond})
	r.f.Bulk()
	// 2. ProbeBW.
	r.enter(60*time.Second, tcp.BBRProbeBWCruise)
	i := r.mark()
	received := r.f.Received()
	r.n.RunFor(20 * time.Second)
	// 3. BBR.MinPipeCwnd (4 packets) is a floor for C.cwnd.
	var cruise int
	for _, s := range r.since(i) {
		if s.bbr.Cwnd < 4*uint64(s.mss) {
			t.Fatalf("C.cwnd = %d at %v, below 4 packets", s.bbr.Cwnd, s.at)
		}
		// 4. The pacing rate matches the bandwidth.
		if s.bbr.State == tcp.BBRProbeBWCruise {
			cruise++
			if want := r.goodput(); !within(s.bbr.PacingRate, want, 5) {
				t.Fatalf("pacing rate %d in ProbeBW_CRUISE at %v, want within 5%% of %d", s.bbr.PacingRate, s.at, want)
			}
		}
	}
	if cruise == 0 {
		t.Fatal("no samples in ProbeBW_CRUISE")
	}
	// The window allows delayed ACKs without stalling: the path stays busy.
	if got, want := r.f.Received()-received, r.goodput()*20*9/10; got < want {
		t.Errorf("received %d bytes in 20s, want at least %d", got, want)
	}
}

// TestA15BandwidthIncrease is A.15, "Increasing Bandwidth 10x and Ensuring
// Full Bandwidth is Reached".
func TestA15BandwidthIncrease(t *testing.T) {
	// 5 Mbit/s with 40 ms of delay and a queue of one BDP, so that loss sets
	// inflight_longterm, then 50 Mbit/s.
	p := path{rate: 625_000, rtt: 40 * time.Millisecond, queue: 25_000}
	r := newRun(t, p)
	r.f.Bulk()
	// 1. ProbeBW, with inflight_longterm set.
	r.until(30*time.Second, "ProbeBW_CRUISE with inflight_longterm", func(s *sample) bool {
		return s.bbr.State == tcp.BBRProbeBWCruise && s.bbr.InflightLongterm != infinity
	})
	// 2. Ten times the bandwidth.
	r.n.Data.SetRate(10 * p.rate)
	up := r.enter(10*time.Second, tcp.BBRProbeBWUp)
	i := r.mark()
	// 4. The full 50 Mbit/s is found within O(log(BDP)) rounds of
	// probing: the pacing gain of 1.25 raises the rate by a quarter per
	// round, log_1.25(10) = 10.3 rounds, and inflight_longterm, whose step
	// doubles per round, reaches the new BDP of 176 packets in
	// log_2(176) = 7.5 more. 20 rounds allow for both.
	want := r.goodputAt(10*p.rate) * 9 / 10
	s := r.until(10*time.Second, "max_bw at the new bandwidth", func(s *sample) bool { return s.bbr.MaxBw >= want })
	rounds := s.bbr.RoundCount - up.bbr.RoundCount
	t.Logf("max_bw reached %d after %d rounds (%v)", s.bbr.MaxBw, rounds, s.at-up.at)
	if rounds > 20 {
		t.Errorf("max_bw took %d rounds to reach %d, want at most 20", rounds, want)
	}
	// 3. While ProbeBW_UP is held back by inflight_longterm, the step added
	// to it each round doubles.
	var steps []uint64
	prev := up.bbr.InflightLongterm
	for _, x := range r.since(i) {
		if x.bbr.State != tcp.BBRProbeBWUp {
			break
		}
		if x.bbr.RoundStart && x.bbr.InflightLongterm != infinity {
			if x.bbr.InflightLongterm < prev {
				t.Fatalf("inflight_longterm fell from %d to %d in ProbeBW_UP at %v", prev, x.bbr.InflightLongterm, x.at)
			}
			steps = append(steps, x.bbr.InflightLongterm-prev)
			prev = x.bbr.InflightLongterm
		}
	}
	t.Logf("inflight_longterm steps per round: %v", steps)
	var doubled int
	for k := 1; k < len(steps); k++ {
		if steps[k-1] > 0 && steps[k] >= steps[k-1]*3/2 {
			doubled++
		}
	}
	if doubled < 2 {
		t.Errorf("inflight_longterm steps %v: want the step to double for at least 2 rounds", steps)
	}
}

// TestA16BandwidthDecrease is A.16, "Decreasing Bandwidth 10x and Ensuring
// Max Bandwidth Adapts Down".
func TestA16BandwidthDecrease(t *testing.T) {
	// 50 Mbit/s with 40 ms of delay and a queue of one BDP, then 5 Mbit/s.
	p := path{rate: 6_250_000, rtt: 40 * time.Millisecond, queue: 250_000}
	r := newRun(t, p)
	r.f.Bulk()
	// 1. ProbeBW.
	before := r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	// 2. A tenth of the bandwidth.
	r.n.Data.SetRate(p.rate / 10)
	start := r.now()
	newRate := r.goodputAt(p.rate / 10)
	// 3. The loss from the overflowing queue brings bw_shortterm down, by
	// at least BBR.Beta (0.7). That takes a few seconds here. The full
	// queue adds 400 ms to the round trip, and the sender's RTO follows a
	// longer round trip only slowly, so a retransmission timeout fires while
	// a repair is still in the queue. The small cwnd after a timeout makes
	// BBR probe for bandwidth at once (the Reno coexistence rule), and each
	// probe starts by resetting the short-term model.
	s := r.until(5*time.Second, "bw_shortterm down", func(s *sample) bool {
		return s.bbr.BwShortterm <= before.bbr.MaxBw*7/10
	})
	t.Logf("bw_shortterm %d after %v", s.bbr.BwShortterm, s.at-start)
	// 4. Once the max_bw window of two ProbeBW cycles has passed, max_bw
	// matches the new bandwidth.
	s = r.until(30*time.Second, "max_bw down", func(s *sample) bool { return s.bbr.MaxBw < before.bbr.MaxBw/2 })
	cycles := s.bbr.CycleCount - before.bbr.CycleCount
	t.Logf("max_bw %d after %v and %d cycles", s.bbr.MaxBw, s.at-start, cycles)
	if !within(s.bbr.MaxBw, newRate, 10) {
		t.Errorf("max_bw = %d, want within 10%% of %d", s.bbr.MaxBw, newRate)
	}
	// The window is the cycle in progress and the one before, so the old
	// samples leave it after at most two cycle advances.
	if cycles < 1 || cycles > 2 {
		t.Errorf("max_bw took %d cycle advances to adapt, want 1 or 2", cycles)
	}
}

// TestA17TokenBucketPolicer is A.17, "Handling Token Bucket Policers".
func TestA17TokenBucketPolicer(t *testing.T) {
	// 1. A 20 Mbit/s link with 40 ms of delay behind a 5 Mbit/s policer with
	// a 64 KB bucket. The link is faster than the policer, so nothing
	// queues.
	p := path{rate: 2_500_000, rtt: 40 * time.Millisecond, policerRate: 625_000, policerBurst: 64 << 10}
	r := newRun(t, p)
	r.f.Bulk()
	// 2. ProbeBW.
	r.until(30*time.Second, "ProbeBW", func(s *sample) bool { return inProbeBW(s.bbr.State) })
	// 3. The policer's drops make BBR set bw_shortterm or
	// inflight_shortterm.
	r.until(30*time.Second, "a short-term bound", func(s *sample) bool {
		return s.bbr.BwShortterm != infinity || s.bbr.InflightShortterm != infinity
	})
	// 4. A stable operating point at the token rate, without excessive
	// loss. BBRv3 has no policer detection, and each probe for bandwidth
	// finds the bucket empty, so some loss remains. On this path CUBIC
	// loses 4.2% at 96% of the token rate, and BBR about 5% at 99%; BBR
	// must not lose more than 6%.
	r.n.RunFor(10 * time.Second)
	before, received := r.n.Data.Stats(), r.f.Received()
	const window = 50
	r.n.RunFor(window * time.Second)
	after := r.n.Data.Stats()
	offered := after.Offered - before.Offered
	drops := after.PolicerDrops - before.PolicerDrops
	rate := (r.f.Received() - received) / window
	t.Logf("last %ds: %d bytes/s, %d of %d packets dropped (%.2f%%)", window, rate, drops, offered, 100*float64(drops)/float64(offered))
	if want := r.goodputAt(p.policerRate); rate < want*9/10 || rate > want*105/100 {
		t.Errorf("rate %d bytes/s, want 90-105%% of the token rate's %d", rate, want)
	}
	if drops*100 > offered*6 {
		t.Errorf("%d of %d packets dropped, want under 6%%", drops, offered)
	}
}

// spuriousCase runs A.18 or A.19: in ProbeBW_UP, filter, installed on Data or
// on Acks, causes a loss recovery that turns out to be spurious.
func spuriousCase(t *testing.T, onAcks bool, makeFilter func(r *run) simnet.Filter) {
	r := newRun(t, standard)
	probeBWUp(r)
	dir := r.n.Data
	if onAcks {
		dir = r.n.Acks
	}
	pre := r.last()
	stats := r.n.Client.Stats().TCP
	timeouts, recoveries := stats.Timeouts.Value(), stats.SACKRecovery.Value()
	r.n.SetFilter(dir, makeFilter(r))
	i := r.mark()
	// 3. The sender finds the recovery spurious, and
	// BBRHandleSpuriousLossDetection() restores the saved state.
	sp := r.until(5*time.Second, "spurious recovery", func(s *sample) bool { return s.spuriousRecovery })
	if onAcks {
		if stats.Timeouts.Value() == timeouts {
			t.Fatal("no retransmission timeout")
		}
	} else if stats.SACKRecovery.Value() == recoveries {
		t.Fatal("no fast recovery")
	}
	if sp.rate.Lost == pre.rate.Lost {
		t.Fatal("no packet was declared lost")
	}
	// 2. Before that, the losses were too many for ProbeBW_UP: it saved its
	// state in undo_state and went to ProbeBW_DOWN, and the bounds it had
	// were saved too. (SaveStateUponLoss() itself sets undo_state to None
	// in the pseudocode; the case's "saves the current BBR.state" is this
	// step of BBRHandleInflightTooHigh().) During an RTO no ACK arrives, so
	// only the outcome shows.
	for _, s := range r.since(i) {
		if s.spuriousRecovery {
			break
		}
		if s.bbr.InLossRecovery && (s.bbr.UndoBwShortterm != pre.bbr.BwShortterm ||
			s.bbr.UndoInflightShortterm != pre.bbr.InflightShortterm ||
			s.bbr.UndoInflightLongterm != pre.bbr.InflightLongterm) {
			t.Fatalf("at %v in recovery: undo_bw_shortterm %s, undo_inflight_shortterm %s, undo_inflight_longterm %s; want %s, %s, %s",
				s.at, volume(s.bbr.UndoBwShortterm), volume(s.bbr.UndoInflightShortterm), volume(s.bbr.UndoInflightLongterm),
				volume(pre.bbr.BwShortterm), volume(pre.bbr.InflightShortterm), volume(pre.bbr.InflightLongterm))
		}
		if s.bbr.State == tcp.BBRProbeBWDown && s.bbr.UndoState != tcp.BBRProbeBWUp {
			t.Fatalf("at %v in ProbeBW_DOWN: undo_state %v, want ProbeBW_UP", s.at, s.bbr.UndoState)
		}
	}
	if !onAcks && !slices.Contains(transitions(r.since(i-1)), "ProbeBW_UP->ProbeBW_DOWN") {
		t.Errorf("states %v: the losses did not end ProbeBW_UP", transitions(r.since(i-1)))
	}
	if sp.bbr.UndoState != tcp.BBRStateNone {
		t.Errorf("undo_state = %v after the undo, want None", sp.bbr.UndoState)
	}
	if sp.bbr.InflightLongterm < pre.bbr.InflightLongterm || sp.bbr.BwShortterm < pre.bbr.BwShortterm || sp.bbr.InflightShortterm < pre.bbr.InflightShortterm {
		t.Errorf("after the undo: %s; want the bounds of %s", describe(sp), describe(pre))
	}
	// 4. Back to bandwidth probing: ProbeBW_REFILL, which leads to
	// ProbeBW_UP.
	if sp.bbr.State != tcp.BBRProbeBWRefill {
		t.Errorf("state after the undo = %v, want ProbeBW_REFILL", sp.bbr.State)
	}
	r.enter(time.Second, tcp.BBRProbeBWUp)
	t.Logf("fault at %v, spurious at %v; states %v", pre.at, sp.at, transitions(r.since(i-1)))
}

// TestA18SpuriousFastRecovery is A.18, "Handling Spurious Fast Recovery".
func TestA18SpuriousFastRecovery(t *testing.T) {
	// 1. Reordering: hold back four data packets in a row by 40 ms, longer
	// than RACK's reordering window (min_rtt / 4) but shorter than a round
	// trip. RACK declares them lost and retransmits them, and the
	// originals, arriving first, show the loss was spurious. Four packets
	// are 4% of what is in flight in ProbeBW_UP, above BBR.LossThresh.
	spuriousCase(t, false, func(r *run) simnet.Filter {
		held := 0
		return func(pkt *stack.PacketBuffer) simnet.Verdict {
			if held < 4 && isData(pkt) {
				held++
				return simnet.Verdict{Delay: 40 * time.Millisecond}
			}
			return simnet.Verdict{}
		}
	})
}

// TestA19SpuriousRTORecovery is A.19, "Handling Spurious RTO Recovery".
func TestA19SpuriousRTORecovery(t *testing.T) {
	// 1. A delay spike: every ACK for the next second is held until the
	// second ends, longer than the retransmission timeout. The sender times
	// out and retransmits, and the held ACKs, which acknowledge the
	// originals, show the timeout was spurious.
	spuriousCase(t, true, func(r *run) simnet.Filter {
		end := r.now() + time.Second
		return func(*stack.PacketBuffer) simnet.Verdict {
			if now := r.now(); now < end {
				return simnet.Verdict{Delay: end - now}
			}
			return simnet.Verdict{}
		}
	})
}

// TestA20ProbeRTTDuringStartup is A.20, "Entering and Exiting PROBE_RTT
// During STARTUP".
func TestA20ProbeRTTDuringStartup(t *testing.T) {
	r := newRun(t, standard)
	// 1. An application-limited flow stays in Startup until min_rtt expires.
	r.f.Limit(r.goodputAt(r.p.rate) / 4)
	i := r.mark()
	in := r.enter(15*time.Second, tcp.BBRProbeRTT)
	for _, s := range r.since(i) {
		if s.bbr.State != tcp.BBRStartup && s.bbr.State != tcp.BBRProbeRTT {
			t.Fatalf("in %v before ProbeRTT", s.bbr.State)
		}
	}
	if in.bbr.FullBwReached {
		t.Fatal("full_bw_reached before ProbeRTT")
	}
	// 2-3. After ProbeRTT, back to Startup, not ProbeBW.
	out := r.leave(2*time.Second, tcp.BBRProbeRTT)
	if out.bbr.State != tcp.BBRStartup {
		t.Fatalf("ProbeRTT left for %v, want Startup", out.bbr.State)
	}
	if d := out.at - in.at; d < 200*time.Millisecond {
		t.Errorf("ProbeRTT lasted %v, want at least 200ms", d)
	}
}

// TestA21LossInProbeUpAfterInflightLongtermSet is A.21, "Handling Loss During
// PROBE_UP After inflight_longterm is Set".
func TestA21LossInProbeUpAfterInflightLongtermSet(t *testing.T) {
	// A queue of one BDP, so that probing finds loss and sets
	// inflight_longterm.
	p := standard
	p.queue = int(p.bdp())
	r := newRun(t, p)
	r.f.Bulk()
	// 1-2. ProbeBW with inflight_longterm set, then ProbeBW_UP.
	r.until(30*time.Second, "ProbeBW_CRUISE with inflight_longterm", func(s *sample) bool {
		return s.bbr.State == tcp.BBRProbeBWCruise && s.bbr.InflightLongterm != infinity
	})
	up := r.enter(10*time.Second, tcp.BBRProbeBWUp)
	i := r.mark()
	// 3. Drop four data packets in a row, before a plateau.
	var drops int
	r.n.SetFilter(r.n.Data, func(pkt *stack.PacketBuffer) simnet.Verdict {
		if drops < 4 && isData(pkt) {
			drops++
			return simnet.Verdict{Drop: true}
		}
		return simnet.Verdict{}
	})
	before := r.last()
	s := r.leave(2*time.Second, tcp.BBRProbeBWUp)
	// 4-5. BBRHandleInflightTooHigh() scales inflight_longterm down, to no
	// less than BBR.Beta (0.7) times the BDP, and ProbeBW_UP gives way to
	// ProbeBW_DOWN at once.
	if s.bbr.State != tcp.BBRProbeBWDown {
		t.Fatalf("ProbeBW_UP left for %v, want ProbeBW_DOWN", s.bbr.State)
	}
	if s.bbr.FullBwNow {
		t.Error("full_bw_now: a plateau, not the loss, ended ProbeBW_UP")
	}
	if s.bbr.InflightLongterm >= before.bbr.InflightLongterm {
		t.Errorf("inflight_longterm %d, want below %d", s.bbr.InflightLongterm, before.bbr.InflightLongterm)
	}
	floor := bytesInTime(s.bbr.MaxBw, s.bbr.MinRTT) * 7 / 10
	if s.bbr.InflightLongterm < floor-uint64(s.mss) {
		t.Errorf("inflight_longterm %d, want at least 0.7 * BDP = %d", s.bbr.InflightLongterm, floor)
	}
	// It is max(RS.tx_in_flight at the loss, 0.7 * BDP), and nothing was in
	// flight beyond what the samples saw.
	var peak uint64
	for _, x := range append([]sample{up}, r.since(i)...) {
		peak = max(peak, x.rate.InFlight)
	}
	if s.bbr.InflightLongterm > max(peak, floor+uint64(s.mss)) {
		t.Errorf("inflight_longterm %d, above both the most in flight (%d) and 0.7 * BDP (%d)", s.bbr.InflightLongterm, peak, floor)
	}
	if s.at-up.at > 2*r.p.rtt {
		t.Errorf("ProbeBW_DOWN %v after ProbeBW_UP began, want within 2 round trips", s.at-up.at)
	}
}

// TestA22AppLimitedDuringRefill is A.22, "Handling Application-Limited
// Sending During PROBE_REFILL".
func TestA22AppLimitedDuringRefill(t *testing.T) {
	r := newRun(t, standard)
	r.f.Bulk()
	r.enter(10*time.Second, tcp.BBRProbeBWCruise)
	r.limitBacklog()
	// 1. ProbeBW_REFILL.
	refill := r.enter(10*time.Second, tcp.BBRProbeBWRefill)
	// 2. The application slows to a quarter of the path's rate. (Stopping it
	// outright would leave no new samples at all.)
	r.f.Limit(r.goodput() / 4)
	i := r.mark()
	up := r.enter(2*time.Second, tcp.BBRProbeBWUp)
	if rounds := up.bbr.RoundCount - refill.bbr.RoundCount; rounds != 1 {
		t.Errorf("ProbeBW_REFILL lasted %d rounds, want 1", rounds)
	}
	// 3. The application-limited samples, lower than max_bw, leave it alone.
	// The samples of the REFILL round are of data sent before it; those of
	// data sent once the connection is application-limited arrive a round
	// trip later, so the check covers two more round trips. max_bw is a
	// windowed maximum, so a low sample could only show once the window
	// moves on, which takes a sample that is not application-limited;
	// TestBBRMaxBwWindow checks that the filter skips such samples.
	r.n.RunFor(2 * r.p.rtt)
	var appLimited bool
	for _, s := range r.since(i) {
		if s.bbr.MaxBw != refill.bbr.MaxBw {
			t.Fatalf("max_bw changed from %d to %d at %v (%v)", refill.bbr.MaxBw, s.bbr.MaxBw, s.at, s.bbr.State)
		}
		if s.rate.AppLimited != 0 {
			appLimited = true
		}
	}
	if !appLimited {
		t.Error("the connection was never application-limited (C.app_limited)")
	}
	// 4. Probing goes on once the application sends again.
	r.f.Client.SocketOptions().SetSendBufferSize(tcp.DefaultSendBufferSize, true /* notify */)
	r.f.Bulk()
	down := r.leave(5*time.Second, tcp.BBRProbeBWUp)
	if down.bbr.State != tcp.BBRProbeBWDown || down.bbr.MaxBw < refill.bbr.MaxBw {
		t.Errorf("after probing: %s; want ProbeBW_DOWN with max_bw at least %d", describe(down), refill.bbr.MaxBw)
	}
}

// inProbeBW reports whether st is one of the phases of ProbeBW.
func inProbeBW(st tcp.BBRState) bool {
	switch st {
	case tcp.BBRProbeBWDown, tcp.BBRProbeBWCruise, tcp.BBRProbeBWRefill, tcp.BBRProbeBWUp:
		return true
	default:
		return false
	}
}

// inflightWithHeadroom is BBRInflightWithHeadroom() for the state in s.
func inflightWithHeadroom(s sample) uint64 {
	lt := s.bbr.InflightLongterm
	if lt == infinity {
		return infinity
	}
	headroom := max(uint64(s.mss), lt*15/100)
	if headroom > lt {
		headroom = lt
	}
	return max(lt-headroom, 4*uint64(s.mss))
}

// bytesInTime returns how many bytes rate bytes per second sends in d.
func bytesInTime(rate uint64, d time.Duration) uint64 {
	if rate == infinity {
		return infinity
	}
	return rate * uint64(d) / uint64(time.Second)
}
