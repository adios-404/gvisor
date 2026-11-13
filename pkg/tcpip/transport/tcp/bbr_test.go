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

package tcp

import (
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	bbrTestMSS  = 1000
	bbrTestRTT  = 10 * time.Millisecond
	bbrTestRate = 2_000_000
	// bbrTestBDP is the BDP of the test path, 20 segments.
	bbrTestBDP = bbrTestRate * uint64(bbrTestRTT) / uint64(time.Second)
)

// bbrTest drives BBR with synthetic rate samples on a manual clock. The test
// plays the sender: it sets the sampler's state and calls the hooks the
// sender would call.
type bbrTest struct {
	t     *testing.T
	clock *faketime.ManualClock
	s     *sender
	b     *bbrState
}

// +checklocksignore
func newBBRTest(t *testing.T, sack bool) *bbrTest {
	clock := faketime.NewManualClock()
	st := stack.New(stack.Options{Clock: clock})
	t.Cleanup(st.Destroy)
	// SACKPermitted is a field of an embedded struct; setting it in the
	// composite literal crashes the staticcheck version nogo uses.
	ep := &Endpoint{stack: st}
	ep.SACKPermitted = sack
	s := &sender{ep: ep}
	s.MaxPayloadSize = bbrTestMSS
	s.SndCwnd = InitialCwnd
	s.rate.enabled = true
	// The handshake gave an RTT sample.
	s.rtt.TCPRTTState.SRTT = bbrTestRTT
	s.rtt.TCPRTTState.SRTTInited = true
	return &bbrTest{t: t, clock: clock, s: s, b: newBBR(s)}
}

// round delivers one packet-timed round trip's worth of data at rate, in one
// ACK that starts a new round, after advancing the clock by bbrTestRTT. It
// sets C.inflight to inflight first.
//
// +checklocksignore
func (bt *bbrTest) round(rate, inflight uint64) rateSample {
	return bt.ackWith(rateSample{deliveryRate: rate}, inflight)
}

// ackWith processes an ACK with the given sample, filling in what the test
// left out: a full round trip of data at the sample's rate, but at least a
// segment, a valid RTT and prior_delivered starting a new round. The clock
// advances by the round trip, or by the time the data takes at the sample's
// rate if that is longer.
//
// +checklocksignore
func (bt *bbrTest) ackWith(rs rateSample, inflight uint64) rateSample {
	if rs.delivered == 0 {
		rs.delivered = max(bytesInTime(rs.deliveryRate, bbrTestRTT), bbrTestMSS)
	}
	elapsed := bbrTestRTT
	if rs.deliveryRate > 0 {
		elapsed = max(elapsed, time.Duration(rs.delivered*uint64(time.Second)/rs.deliveryRate))
	}
	bt.clock.Advance(elapsed)
	now := bt.clock.NowMonotonic()
	bt.s.rate.InFlight = inflight
	rs.hasData = true
	if rs.newlyAcked == 0 {
		rs.newlyAcked = rs.delivered
	}
	if rs.rtt == 0 {
		// Use -1 for an ACK without an RTT sample.
		rs.rtt = bbrTestRTT
	}
	if rs.priorDelivered == 0 {
		rs.priorDelivered = bt.s.rate.Delivered
	}
	if rs.txInFlight == 0 {
		rs.txInFlight = inflight
	}
	bt.s.rate.Delivered += rs.newlyAcked
	bt.b.OnACK(&rs, now)
	return rs
}

// fillPipe runs Startup with a rate that doubles and then stays at
// bbrTestRate until BBR has filled the pipe, keeping inflight high so that it
// stays in Drain.
//
// +checklocksignore
func (bt *bbrTest) fillPipe() {
	bt.t.Helper()
	bt.round(bbrTestRate/2, 2*bbrTestBDP)
	for i := 0; i < 10 && !bt.b.FullBwReached; i++ {
		bt.round(bbrTestRate, 2*bbrTestBDP)
	}
	if !bt.b.FullBwReached || bt.b.State != BBRDrain {
		bt.t.Fatalf("pipe not filled: state %s, full_bw_reached %t", bt.b.State, bt.b.FullBwReached)
	}
}

// toProbeBW leaves Drain by time and returns in ProbeBW_DOWN with the pipe
// still full.
//
// +checklocksignore
func (bt *bbrTest) toProbeBW() {
	bt.t.Helper()
	bt.fillPipe()
	for i := 0; i < 10 && bt.b.State == BBRDrain; i++ {
		bt.round(bbrTestRate, 2*bbrTestBDP)
	}
	if bt.b.State != BBRProbeBWDown {
		bt.t.Fatalf("state %s after Drain, want ProbeBW_DOWN", bt.b.State)
	}
}

// untilState runs rounds at bbrTestRate with the given inflight until BBR is
// in state, and returns how many it took.
//
// +checklocksignore
func (bt *bbrTest) untilState(state BBRState, inflight uint64, maxRounds int) int {
	bt.t.Helper()
	for i := 1; i <= maxRounds; i++ {
		bt.round(bbrTestRate, inflight)
		if bt.b.State == state {
			return i
		}
	}
	bt.t.Fatalf("not in %s after %d rounds: in %s", state, maxRounds, bt.b.State)
	return 0
}

// +checklocksignore
func TestBBRInit(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	if b.State != BBRStartup || b.PacingGain != bbrStartupPacingGain || b.CwndGain != bbrDefaultCwndGain {
		t.Errorf("state %s gains %d/%d, want Startup %d/%d", b.State, b.PacingGain, b.CwndGain, bbrStartupPacingGain, bbrDefaultCwndGain)
	}
	// The initial window over the smoothed RTT, times the Startup gain.
	if got, want := b.TCPBBRState.PacingRate, uint64(InitialCwnd*bbrTestMSS*uint64(time.Second/bbrTestRTT)*bbrStartupPacingGain/bbrUnit); got != want {
		t.Errorf("initial pacing rate %d, want %d", got, want)
	}
	if b.Cwnd != InitialCwnd*bbrTestMSS || bt.s.SndCwnd != InitialCwnd {
		t.Errorf("cwnd %d bytes, %d segments, want %d, %d", b.Cwnd, bt.s.SndCwnd, InitialCwnd*bbrTestMSS, InitialCwnd)
	}
	if b.MinRTT != bbrTestRTT || b.InflightLongterm != bbrInfinity || b.BwShortterm != bbrInfinity || b.ProbeRTTCwnd != bbrInfinity {
		t.Errorf("min_rtt %v, inflight_longterm %d, bw_shortterm %d, probe_rtt_cwnd %d: want srtt and infinite",
			b.MinRTT, b.InflightLongterm, b.BwShortterm, b.ProbeRTTCwnd)
	}
}

// TestBBRStartupPlateau is A.1 at the unit level.
//
// +checklocksignore
func TestBBRStartupPlateau(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.round(bbrTestRate/2, 2*bbrTestBDP)
	bt.round(bbrTestRate, 2*bbrTestBDP)
	// Growth of 25% or more restarts the count.
	if b.FullBw != bbrTestRate || b.FullBwCount != 0 {
		t.Fatalf("full_bw %d count %d after growth, want %d, 0", b.FullBw, b.FullBwCount, bbrTestRate)
	}
	for i := uint64(1); i < bbrFullBwRounds; i++ {
		// Less than 25% more.
		bt.round(bbrTestRate*124/100, 2*bbrTestBDP)
		if b.FullBwCount != i || b.FullBwReached || b.State != BBRStartup {
			t.Fatalf("flat round %d: count %d, full_bw_reached %t, state %s", i, b.FullBwCount, b.FullBwReached, b.State)
		}
	}
	bt.round(bbrTestRate, 2*bbrTestBDP)
	if !b.FullBwNow || !b.FullBwReached || b.State != BBRDrain {
		t.Fatalf("after %d flat rounds: full_bw_now %t, full_bw_reached %t, state %s, want true, true, Drain", bbrFullBwRounds, b.FullBwNow, b.FullBwReached, b.State)
	}
	if b.MaxBw != bbrTestRate*124/100 || b.PacingGain != bbrDrainPacingGain {
		t.Errorf("max_bw %d pacing_gain %d, want %d, %d", b.MaxBw, b.PacingGain, bbrTestRate*124/100, bbrDrainPacingGain)
	}
}

// TestBBRStartupAppLimitedNeverExits is A.7 for Startup at the unit level.
//
// +checklocksignore
func TestBBRStartupAppLimitedNeverExits(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	for i := 0; i < 50; i++ {
		bt.ackWith(rateSample{deliveryRate: bbrTestRate / 4, isAppLimited: true}, bbrTestBDP/4)
	}
	if bt.b.State != BBRStartup || bt.b.FullBwReached {
		t.Errorf("state %s, full_bw_reached %t after app-limited rounds, want Startup, false", bt.b.State, bt.b.FullBwReached)
	}
}

// TestBBRStartupHighLoss is A.2 at the unit level: loss ends Startup even when
// the samples are application-limited.
//
// +checklocksignore
func TestBBRStartupHighLoss(t *testing.T) {
	for _, sack := range []bool{true, false} {
		name := "NoSACK"
		if sack {
			name = "SACK"
		}
		t.Run(name, func(t *testing.T) {
			bt := newBBRTest(t, sack)
			b := bt.b
			bt.ackWith(rateSample{deliveryRate: bbrTestRate / 2, isAppLimited: true}, bbrTestBDP)
			// Six losses (enough with SACK) in fast recovery, then the ACK
			// that ends the loss round reports 3% lost.
			var p segRate
			for i := 0; i < bbrStartupFullLossCnt; i++ {
				bt.s.rate.Lost += bbrTestMSS
				b.OnLoss(&p, bbrTestMSS)
			}
			b.OnEnterRecovery(false /* rto */)
			txInFlight := uint64(100 * bbrTestMSS)
			bt.ackWith(rateSample{deliveryRate: bbrTestRate / 2, isAppLimited: true, txInFlight: txInFlight, lost: 3 * bbrTestMSS}, bbrTestBDP)
			if !b.FullBwReached || b.State != BBRDrain || b.UndoState != BBRStartup {
				t.Fatalf("full_bw_reached %t, state %s, undo_state %s, want true, Drain, Startup", b.FullBwReached, b.State, b.UndoState)
			}
			if want := max(b.BDP, b.InflightLatest); b.InflightLongterm != want {
				t.Errorf("inflight_longterm %d, want max(bdp, inflight_latest) = %d", b.InflightLongterm, want)
			}
		})
	}
}

// TestBBRDrainExits is A.3 and A.4 at the unit level.
//
// +checklocksignore
func TestBBRDrainExits(t *testing.T) {
	t.Run("Inflight", func(t *testing.T) {
		bt := newBBRTest(t, true /* sack */)
		bt.fillPipe()
		bt.round(bbrTestRate, bbrTestBDP)
		if bt.b.State == BBRDrain || !bt.b.isInAProbeBWState() {
			t.Errorf("state %s with inflight at the BDP, want a ProbeBW state", bt.b.State)
		}
	})
	t.Run("Time", func(t *testing.T) {
		bt := newBBRTest(t, true /* sack */)
		bt.fillPipe()
		start := bt.b.DrainStartRound
		n := bt.untilState(BBRProbeBWDown, 2*bbrTestBDP, 10)
		if n != bbrDrainMaxRounds+1 || bt.b.RoundCount != start+bbrDrainMaxRounds+1 {
			t.Errorf("left Drain after %d rounds (round %d, entered at %d), want %d", n, bt.b.RoundCount, start, bbrDrainMaxRounds+1)
		}
	})
}

// TestBBRProbeBWCycle walks the ProbeBW cycle (A.5, A.8) at the unit level.
//
// +checklocksignore
func TestBBRProbeBWCycle(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	if b.PacingGain != bbrProbeBWDownPacingGain || b.CwndGain != bbrDefaultCwndGain {
		t.Errorf("ProbeBW_DOWN gains %d/%d, want %d/%d", b.PacingGain, b.CwndGain, bbrProbeBWDownPacingGain, bbrDefaultCwndGain)
	}
	// DOWN stays while inflight is above the BDP, and cruises below it.
	bt.round(bbrTestRate, 2*bbrTestBDP)
	if b.State != BBRProbeBWDown {
		t.Fatalf("state %s with inflight above the BDP, want ProbeBW_DOWN", b.State)
	}
	bt.round(bbrTestRate, bbrTestBDP)
	if b.State != BBRProbeBWCruise || b.PacingGain != bbrProbeBWCruisePacingGain {
		t.Fatalf("state %s pacing_gain %d at the BDP, want ProbeBW_CRUISE %d", b.State, b.PacingGain, bbrProbeBWCruisePacingGain)
	}
	// Reno coexistence: probe once the rounds since DOWN started, plus 0 or
	// 1 picked at random, reach the BDP in segments.
	downStart := b.RoundCount - 2
	bt.untilState(BBRProbeBWRefill, bbrTestBDP, 100)
	if rounds, target := b.RoundCount-downStart, bbrTestBDP/bbrTestMSS; rounds < target-1 || rounds > target {
		t.Errorf("REFILL %d rounds after DOWN started, want %d or %d", rounds, target-1, target)
	}
	// One round of REFILL, then UP.
	bt.round(bbrTestRate, bbrTestBDP)
	if b.State != BBRProbeBWUp || !b.CheckProbeLoss || b.PacingGain != bbrProbeBWUpPacingGain || b.CwndGain != bbrProbeBWUpCwndGain {
		t.Fatalf("after a REFILL round: state %s check_probe_loss %t gains %d/%d, want ProbeBW_UP true %d/%d",
			b.State, b.CheckProbeLoss, b.PacingGain, b.CwndGain, bbrProbeBWUpPacingGain, bbrProbeBWUpCwndGain)
	}
	// A plateau ends UP after three rounds (A.5).
	for i := 1; i < bbrFullBwRounds; i++ {
		bt.round(bbrTestRate, bbrTestBDP)
		if b.State != BBRProbeBWUp {
			t.Fatalf("left UP after %d flat rounds", i)
		}
	}
	bt.round(bbrTestRate, bbrTestBDP)
	if b.State != BBRProbeBWDown || b.PrevProbeTooHigh {
		t.Errorf("after %d flat rounds in UP: state %s prev_probe_too_high %t, want ProbeBW_DOWN false", bbrFullBwRounds, b.State, b.PrevProbeTooHigh)
	}
}

// TestBBRProbeWaitByTime checks that DOWN goes straight to REFILL when its
// wall clock wait runs out (A.9 at the unit level).
//
// +checklocksignore
func TestBBRProbeWaitByTime(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	if b.BwProbeWait < bbrProbeWaitBase || b.BwProbeWait >= bbrProbeWaitBase+bbrProbeWaitRandom {
		t.Errorf("bw_probe_wait %v, want in [2s, 3s)", b.BwProbeWait)
	}
	// Keep the Reno bound out of the way and inflight above the BDP.
	b.RoundsSinceProbeUp = 0
	bt.clock.Advance(b.BwProbeWait)
	b.RoundsSinceProbeUp = 0
	bt.round(bbrTestRate, 2*bbrTestBDP)
	if b.State != BBRProbeBWRefill {
		t.Errorf("state %s after bw_probe_wait, want ProbeBW_REFILL", b.State)
	}
}

// toProbeUp drives BBR into ProbeBW_UP.
//
// +checklocksignore
func (bt *bbrTest) toProbeUp() {
	bt.t.Helper()
	bt.toProbeBW()
	bt.untilState(BBRProbeBWRefill, bbrTestBDP, 100)
	bt.untilState(BBRProbeBWUp, bbrTestBDP, 2)
}

// TestBBRLossInProbeUp is A.21 at the unit level.
//
// +checklocksignore
func TestBBRLossInProbeUp(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeUp()
	target := b.targetInflight()
	// A segment sent with 30 segments in flight, of which 3 have been lost
	// since: 10%, above the 2% threshold.
	p := segRate{txInFlight: 30 * bbrTestMSS, lost: bt.s.rate.Lost}
	bt.s.rate.Lost += 3 * bbrTestMSS
	b.OnLoss(&p, bbrTestMSS)
	if b.State != BBRProbeBWDown || !b.PrevProbeTooHigh || b.CheckProbeLoss || b.UndoState != BBRProbeBWUp {
		t.Fatalf("after high loss in UP: state %s prev_probe_too_high %t check_probe_loss %t undo_state %s, want ProbeBW_DOWN true false ProbeBW_UP",
			b.State, b.PrevProbeTooHigh, b.CheckProbeLoss, b.UndoState)
	}
	want := max(inflightAtLoss(bbrTestMSS, 30*bbrTestMSS, 3*bbrTestMSS), target*bbrBeta/bbrUnit)
	if b.InflightLongterm != want {
		t.Errorf("inflight_longterm %d, want %d", b.InflightLongterm, want)
	}
}

func TestBBRInflightAtLoss(t *testing.T) {
	for _, test := range []struct {
		size, txInFlight, lost, want uint64
	}{
		// 1.5 segments lost before this one, out of 99: the threshold of
		// 2% is crossed 489 bytes into it.
		{size: 1000, txInFlight: 100_000, lost: 2500, want: 99_000 + (99_000*20-1500*1000)/980},
		// Already past the threshold before this segment: lost_prefix is
		// negative.
		{size: 1000, txInFlight: 100_000, lost: 3000, want: 99_000 - (2000*1000-99_000*20)/980},
		// Inconsistent input: no prefix can be computed.
		{size: 1000, txInFlight: 500, lost: 1000, want: 500},
	} {
		if got := inflightAtLoss(test.size, test.txInFlight, test.lost); got != test.want {
			t.Errorf("inflightAtLoss(%d, %d, %d) = %d, want %d", test.size, test.txInFlight, test.lost, got, test.want)
		}
	}
}

// TestBBRShortTermModel checks the response to loss when not probing.
//
// +checklocksignore
func TestBBRShortTermModel(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	bt.untilState(BBRProbeBWCruise, bbrTestBDP, 2)
	// The path slows down: a round at half the rate, then a loss, then the
	// ACK that ends the loss round. BBR.bw_latest and inflight_latest are
	// the largest of the round.
	bt.round(bbrTestRate/2, bbrTestBDP)
	cwnd := b.Cwnd
	var p segRate
	bt.s.rate.Lost += bbrTestMSS
	b.OnLoss(&p, bbrTestMSS)
	rs := bt.ackWith(rateSample{deliveryRate: bbrTestRate / 2}, bbrTestBDP)
	wantBw := max(rs.deliveryRate, uint64(bbrTestRate)*bbrBeta/bbrUnit)
	wantInflight := max(rs.delivered, cwnd*bbrBeta/bbrUnit)
	if b.BwShortterm != wantBw || b.InflightShortterm != wantInflight {
		t.Errorf("bw_shortterm %d inflight_shortterm %d, want %d, %d", b.BwShortterm, b.InflightShortterm, wantBw, wantInflight)
	}
	if b.Bw != min(b.MaxBw, wantBw) {
		t.Errorf("bw %d, want min(max_bw, bw_shortterm) = %d", b.Bw, min(b.MaxBw, wantBw))
	}
}

// TestBBRInflightLongtermGrowth checks that ProbeBW_UP grows
// inflight_longterm by 1, 2, 4... segments per round (A.15 at the unit
// level).
//
// +checklocksignore
func TestBBRInflightLongtermGrowth(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeUp()
	// Make the window the limit: cwnd-limited at inflight_longterm.
	b.InflightLongterm = b.Cwnd
	b.IsCwndLimited = true
	b.BwProbeUpRounds = 0
	// The step for round r is set at the start of round r from the cwnd of
	// then: one segment per cwnd/2^r bytes ACKed.
	raisedAt := b.Cwnd
	b.raiseInflightLongtermSlope()
	// The path got faster: each round delivers 30% more, so the plateau
	// detector does not end UP.
	rate := uint64(bbrTestRate)
	for r := uint64(0); r < 4; r++ {
		rate = rate * 13 / 10
		perInc := b.ProbeUpAckedPerInc
		if want := max(raisedAt>>r, bbrTestMSS); perInc != want {
			t.Fatalf("round %d: probe_up_acked_per_inc %d, want %d/2^%d = %d", r, perInc, raisedAt, r, want)
		}
		before := b.InflightLongterm
		b.CwndLimitedInRound = true
		b.Cwnd = before
		raisedAt = before
		// One round trip's worth of ACKs of a full window.
		bt.ackWith(rateSample{deliveryRate: rate, newlyAcked: before, delivered: before}, before)
		if b.State != BBRProbeBWUp {
			t.Fatalf("round %d: left UP for %s", r, b.State)
		}
		if got, want := b.InflightLongterm-before, (before/perInc)*bbrTestMSS; got != want {
			t.Errorf("round %d: inflight_longterm grew by %d, want %d", r, got, want)
		}
	}
}

// TestBBRProbeRTT is A.10 at the unit level.
//
// +checklocksignore
func TestBBRProbeRTT(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	cwnd := b.Cwnd
	// No lower RTT for 10 seconds.
	bt.clock.Advance(bbrMinRTTFilterLen)
	bt.ackWith(rateSample{deliveryRate: bbrTestRate, rtt: 2 * bbrTestRTT}, 2*bbrTestBDP)
	if b.State != BBRProbeRTT || b.CwndGain != bbrProbeRTTCwndGain || b.PacingGain != bbrProbeRTTPacingGain {
		t.Fatalf("state %s gains %d/%d after min_rtt expired, want ProbeRTT %d/%d", b.State, b.PacingGain, b.CwndGain, bbrProbeRTTPacingGain, bbrProbeRTTCwndGain)
	}
	if b.Cwnd > b.probeRTTCwnd() || b.PriorCwnd < cwnd {
		t.Errorf("cwnd %d prior_cwnd %d, want at most %d and at least %d", b.Cwnd, b.PriorCwnd, b.probeRTTCwnd(), cwnd)
	}
	// Once inflight is down to ProbeRTTCwnd(), 200ms and a round.
	bt.round(bbrTestRate, bbrMinPipeCwndSegments*bbrTestMSS)
	if !b.ProbeRTTDoneStampSet {
		t.Fatalf("probe_rtt_done_stamp not set with inflight at the minimum")
	}
	for i := 0; i < 100 && b.State == BBRProbeRTT; i++ {
		bt.round(bbrTestRate, bbrMinPipeCwndSegments*bbrTestMSS)
	}
	if b.State != BBRProbeBWCruise || b.CwndGain != bbrDefaultCwndGain {
		t.Fatalf("state %s cwnd_gain %d after ProbeRTT, want ProbeBW_CRUISE %d", b.State, b.CwndGain, bbrDefaultCwndGain)
	}
	if elapsed := bt.clock.NowMonotonic().Sub(b.ProbeRTTDoneStamp.Add(-bbrProbeRTTDuration)); elapsed <= bbrProbeRTTDuration {
		t.Errorf("left ProbeRTT %v after inflight dropped, want more than %v", elapsed, bbrProbeRTTDuration)
	}
}

// TestBBRProbeRTTDuringStartup is A.20 at the unit level.
//
// +checklocksignore
func TestBBRProbeRTTDuringStartup(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.round(bbrTestRate, 2*bbrTestBDP)
	bt.clock.Advance(bbrMinRTTFilterLen)
	bt.ackWith(rateSample{deliveryRate: 2 * bbrTestRate, rtt: 2 * bbrTestRTT}, 2*bbrTestBDP)
	if b.State != BBRProbeRTT {
		t.Fatalf("state %s, want ProbeRTT", b.State)
	}
	// ProbeRTT marks the connection application-limited, so its samples
	// are, and do not count towards a full pipe.
	for i := 0; i < 100 && b.State == BBRProbeRTT; i++ {
		bt.ackWith(rateSample{deliveryRate: 4 * bbrTestRate, isAppLimited: true}, bbrMinPipeCwndSegments*bbrTestMSS)
	}
	if b.State != BBRStartup {
		t.Errorf("state %s after ProbeRTT before the pipe was full, want Startup", b.State)
	}
}

// TestBBRIdleSkipsProbeRTT is A.11 at the unit level.
//
// +checklocksignore
func TestBBRIdleSkipsProbeRTT(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	// The connection goes idle for longer than the min_rtt filter.
	bt.s.rate.InFlight = 0
	bt.s.rate.markAppLimited()
	bt.clock.Advance(bbrMinRTTFilterLen + time.Second)
	b.OnTransmit(bt.clock.NowMonotonic(), bbrTestMSS)
	if !b.IdleRestart {
		t.Fatalf("idle_restart not set when sending after idle")
	}
	if want := uint64(bbrTestRate) * (100 - bbrPacingMarginPercent) / 100; b.TCPBBRState.PacingRate != want {
		t.Errorf("pacing rate %d after idle in ProbeBW, want bw = %d", b.TCPBBRState.PacingRate, want)
	}
	bt.ackWith(rateSample{deliveryRate: bbrTestRate, isAppLimited: true}, bbrTestMSS)
	if b.State == BBRProbeRTT {
		t.Errorf("entered ProbeRTT after idle")
	}
	if b.IdleRestart {
		t.Errorf("idle_restart still set after data was delivered")
	}
}

// TestBBRRecovery checks cwnd on an RTO, on leaving recovery and on a
// spurious recovery in ProbeBW_UP (A.19 at the unit level).
//
// +checklocksignore
func TestBBRRecovery(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeUp()
	cwnd := b.Cwnd
	bt.s.rate.InFlight = 0
	b.OnEnterRecovery(true /* rto */)
	if b.Cwnd != bbrTestMSS || bt.s.SndCwnd != 1 || b.PriorCwnd != cwnd || !b.InLossRecovery {
		t.Fatalf("after RTO: cwnd %d (%d segments) prior_cwnd %d in_recovery %t, want %d (1) %d true", b.Cwnd, bt.s.SndCwnd, b.PriorCwnd, b.InLossRecovery, bbrTestMSS, cwnd)
	}
	// A second RTO keeps the best window seen.
	b.OnEnterRecovery(true /* rto */)
	if b.PriorCwnd != cwnd {
		t.Errorf("prior_cwnd %d after a second RTO, want %d", b.PriorCwnd, cwnd)
	}
	// A loss while probing makes the episode one to undo.
	b.UndoState = BBRProbeBWUp
	b.State = BBRProbeBWDown
	b.OnSpuriousRecovery()
	if b.Cwnd != cwnd || b.State != BBRProbeBWRefill || b.UndoState != BBRStateNone {
		t.Errorf("after spurious recovery: cwnd %d state %s undo_state %s, want %d ProbeBW_REFILL None", b.Cwnd, b.State, b.UndoState, cwnd)
	}
	b.OnExitRecovery()
	if b.InLossRecovery || b.Cwnd != cwnd {
		t.Errorf("after recovery: in_recovery %t cwnd %d, want false %d", b.InLossRecovery, b.Cwnd, cwnd)
	}
}

// TestBBRLossInProbeUpBetaFloor checks that losses with little in flight
// lower inflight_longterm no further than BBR.Beta times the target
// (section 5.5.10.2, HandleInflightTooHigh()).
//
// +checklocksignore
func TestBBRLossInProbeUpBetaFloor(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeUp()
	floor := b.targetInflight() * bbrBeta / bbrUnit
	// A segment sent with 4 segments in flight, of which 2 have been lost
	// since.
	p := segRate{txInFlight: 4 * bbrTestMSS, lost: bt.s.rate.Lost}
	bt.s.rate.Lost += 2 * bbrTestMSS
	if atLoss := inflightAtLoss(bbrTestMSS, 4*bbrTestMSS, 2*bbrTestMSS); atLoss >= floor {
		t.Fatalf("inflight at loss %d is not below the floor %d", atLoss, floor)
	}
	b.OnLoss(&p, bbrTestMSS)
	if b.State != BBRProbeBWDown || b.InflightLongterm != floor {
		t.Errorf("after the loss: state %s inflight_longterm %d, want ProbeBW_DOWN %d", b.State, b.InflightLongterm, floor)
	}
}

// TestBBRLossesBeforeRecoveryKeepUndoState checks the order in which this
// sender reports an episode's first losses: before it enters recovery. The
// state saved for an undo must be the one before those losses, and the
// undo_state they set must survive the entry into recovery, and any further
// entry before recovery ends: a timeout during fast recovery, a later
// timeout, or fast recovery after a timeout.
//
// +checklocksignore
func TestBBRLossesBeforeRecoveryKeepUndoState(t *testing.T) {
	type entry int
	const (
		none entry = iota
		fast
		rto
	)
	names := []string{"none", "fast", "rto"}
	for _, first := range []entry{fast, rto} {
		for _, again := range []entry{none, fast, rto} {
			t.Run(fmt.Sprintf("first=%s/again=%s", names[first], names[again]), func(t *testing.T) {
				bt := newBBRTest(t, true /* sack */)
				b := bt.b
				bt.toProbeUp()
				longterm, shortterm := b.InflightLongterm, b.BwShortterm
				// Losses too high for ProbeBW_UP, as RACK or a timeout
				// reports them.
				p := segRate{txInFlight: 30 * bbrTestMSS, lost: bt.s.rate.Lost}
				bt.s.rate.Lost += 3 * bbrTestMSS
				b.OnLoss(&p, bbrTestMSS)
				if b.State != BBRProbeBWDown || b.InflightLongterm == longterm {
					t.Fatalf("after high loss in UP: state %s inflight_longterm %d, want ProbeBW_DOWN and a new bound", b.State, b.InflightLongterm)
				}
				// More losses of the same burst, after StartProbeBW_DOWN()
				// reset loss_in_round.
				b.OnLoss(&p, bbrTestMSS)
				b.OnLoss(&p, bbrTestMSS)
				b.OnEnterRecovery(first == rto)
				if again != none {
					b.InflightLongterm = 55 * bbrTestMSS
					b.OnLoss(&p, bbrTestMSS)
					b.OnEnterRecovery(again == rto)
				}
				if b.UndoState != BBRProbeBWUp || b.UndoInflightLongterm != longterm || b.UndoBwShortterm != shortterm {
					t.Fatalf("in recovery: undo_state %s undo_inflight_longterm %d undo_bw_shortterm %d, want ProbeBW_UP %d %d", b.UndoState, b.UndoInflightLongterm, b.UndoBwShortterm, longterm, shortterm)
				}
				b.OnSpuriousRecovery()
				if b.State != BBRProbeBWRefill || b.InflightLongterm != longterm {
					t.Errorf("after the undo: state %s inflight_longterm %d, want ProbeBW_REFILL %d", b.State, b.InflightLongterm, longterm)
				}
				// The next episode, started by entering recovery (dupacks
				// without RACK), saves the state then.
				b.OnExitRecovery()
				b.InflightLongterm = 77 * bbrTestMSS
				b.OnEnterRecovery(false)
				if b.UndoInflightLongterm != 77*bbrTestMSS || b.UndoState != BBRStateNone {
					t.Errorf("next episode: undo_inflight_longterm %d undo_state %s, want %d None", b.UndoInflightLongterm, b.UndoState, 77*bbrTestMSS)
				}
			})
		}
	}
}

// TestBBRMinPipeCwnd is A.14 at the unit level.
//
// +checklocksignore
func TestBBRMinPipeCwnd(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	// 10 KB/s over 10ms: a BDP of 100 bytes.
	const rate = 10_000
	bt.round(rate/2, bbrTestMSS)
	for i := 0; i < 20; i++ {
		bt.round(rate, bbrTestMSS)
	}
	b := bt.b
	if !b.FullBwReached || b.BDP >= bbrTestMSS {
		t.Fatalf("full_bw_reached %t bdp %d, want true and below one segment", b.FullBwReached, b.BDP)
	}
	// BBR.MinPipeCwnd is the floor, but for TCP the offload budget, three
	// send quanta of at least two segments each, is above it (section
	// 5.5.8.1). ProbeBW_UP allows two segments more.
	want := max(2*b.BDP+b.ExtraAcked, 3*2*bbrTestMSS, b.minPipeCwnd())
	if b.State == BBRProbeBWUp {
		want += 2 * bbrTestMSS
	}
	if b.MaxInflight != want || b.Cwnd > b.MaxInflight || b.Cwnd < b.minPipeCwnd() {
		t.Errorf("in %s: max_inflight %d, cwnd %d, want max_inflight %d and cwnd between %d and it", b.State, b.MaxInflight, b.Cwnd, want, b.minPipeCwnd())
	}
	if want := uint64(rate) * (100 - bbrPacingMarginPercent) / 100 * b.PacingGain / bbrUnit; b.TCPBBRState.PacingRate != want {
		t.Errorf("pacing rate %d, want %d", b.TCPBBRState.PacingRate, want)
	}
}

// TestBBROffloadBudgetCoversLateTimer checks that above the rate at which a
// send quantum reaches its 64KB cap, the offload budget is what the pacer
// lets out at once after its timer fired late: pacingTimerSlack of data. On a
// path between two hosts of one machine the round trip is microseconds and
// the BDP next to nothing, so cwnd is the offload budget. Three quanta of
// 64KB would then be all that may be in flight, however fast the path, while
// netstack itself takes hundreds of microseconds to turn an ACK into the next
// transmission.
//
// +checklocksignore
func TestBBROffloadBudgetCoversLateTimer(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	// 1 GB/s with a round trip of 10us: a BDP of 10KB.
	const (
		rate = 1_000_000_000
		rtt  = 10 * time.Microsecond
	)
	bt.ackWith(rateSample{deliveryRate: rate / 2, rtt: rtt}, bbrTestMSS)
	for i := 0; i < 20; i++ {
		bt.ackWith(rateSample{deliveryRate: rate, rtt: rtt}, bbrTestMSS)
	}
	if !b.FullBwReached || b.BDP != 10_000 {
		t.Fatalf("full_bw_reached %t bdp %d, want true and 10000", b.FullBwReached, b.BDP)
	}
	if b.SendQuantum != maxSendQuantum {
		t.Fatalf("send quantum %d, want %d", b.SendQuantum, maxSendQuantum)
	}
	budget := bytesInTime(b.TCPBBRState.PacingRate, pacingTimerSlack)
	if budget <= 3*maxSendQuantum {
		t.Fatalf("pacing rate %d: %s of data is %d, want more than three send quanta", b.TCPBBRState.PacingRate, pacingTimerSlack, budget)
	}
	if b.OffloadBudget != budget {
		t.Errorf("offload budget %d, want %s of data at the pacing rate, %d", b.OffloadBudget, pacingTimerSlack, budget)
	}
	want := max(mulDiv(b.BDP, b.CwndGain, bbrUnit)+b.ExtraAcked, budget)
	if b.State == BBRProbeBWUp {
		want += 2 * bbrTestMSS
	}
	if b.MaxInflight != want {
		t.Errorf("in %s: max_inflight %d, want %d", b.State, b.MaxInflight, want)
	}
}

// TestBBRMaxBwWindow checks that max_bw remembers two ProbeBW cycles (A.16
// at the unit level).
//
// +checklocksignore
func TestBBRMaxBwWindow(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	rs := rateSample{deliveryRate: 1000}
	b.updateMaxBw(&rs)
	b.advanceMaxBwFilter()
	rs.deliveryRate = 500
	b.updateMaxBw(&rs)
	if b.MaxBw != 1000 {
		t.Errorf("max_bw %d one cycle later, want 1000", b.MaxBw)
	}
	b.advanceMaxBwFilter()
	b.updateMaxBw(&rs)
	if b.MaxBw != 500 {
		t.Errorf("max_bw %d two cycles later, want 500", b.MaxBw)
	}
	// An application-limited sample below max_bw stays out of the filter
	// (section 5.5.5): once 500 leaves the window, max_bw comes from the
	// samples that were not application-limited.
	b.advanceMaxBwFilter()
	low := rateSample{deliveryRate: 400, isAppLimited: true}
	b.updateMaxBw(&low)
	b.advanceMaxBwFilter()
	rs.deliveryRate = 300
	b.updateMaxBw(&rs)
	if b.MaxBw != 300 {
		t.Errorf("max_bw %d after an application-limited 400 and a 300, want 300", b.MaxBw)
	}
}

func TestWindowedMaxFilter(t *testing.T) {
	var f windowedMaxFilter
	for _, step := range []struct {
		at, v, want uint64
	}{
		{at: 0, v: 10, want: 10},
		{at: 1, v: 5, want: 10},
		{at: 5, v: 7, want: 10},
		{at: 10, v: 3, want: 10},
		// 10 is out of the window: 7, from 5, is the best left.
		{at: 11, v: 2, want: 7},
		{at: 16, v: 1, want: 3},
		{at: 17, v: 20, want: 20},
		// Everything expired.
		{at: 40, v: 4, want: 4},
	} {
		if got := f.update(step.at, 10, step.v); got != step.want {
			t.Errorf("update(at=%d, v=%d) = %d, want %d", step.at, step.v, got, step.want)
		}
	}
}

func TestBBRSelection(t *testing.T) {
	s := stack.New(stack.Options{TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	t.Cleanup(s.Destroy)
	bbr := tcpip.CongestionControlOption(ccBBR)
	if err := s.SetTransportProtocolOption(ProtocolNumber, &bbr); err == nil {
		t.Fatalf("selected BBR before making it available")
	}
	for _, test := range []struct {
		avail string
		ok    bool
	}{
		{"reno cubic vegas", false},
		// The default, reno, must stay available.
		{"cubic bbr", false},
		{"", false},
		// Duplicates are dropped; the order is kept.
		{"reno cubic bbr cubic reno", true},
	} {
		opt := tcpip.TCPAvailableCongestionControlOption(test.avail)
		if err := s.SetTransportProtocolOption(ProtocolNumber, &opt); (err == nil) != test.ok {
			t.Errorf("setting available algorithms to %q: error %v, want success %t", test.avail, err, test.ok)
		}
	}
	if err := s.SetTransportProtocolOption(ProtocolNumber, &bbr); err != nil {
		t.Fatalf("selecting BBR once available: %s", err)
	}
	var got tcpip.TCPAvailableCongestionControlOption
	if err := s.TransportProtocolOption(ProtocolNumber, &got); err != nil || got != "reno cubic bbr" {
		t.Errorf("available algorithms %q, %v, want \"reno cubic bbr\"", got, err)
	}
}

// TestBBRInvalidSampleNotARound checks that an ACK without a valid rate
// sample neither starts a round nor counts towards a full pipe.
//
// +checklocksignore
func TestBBRInvalidSampleNotARound(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.round(bbrTestRate, 2*bbrTestBDP)
	rounds, count := b.RoundCount, b.FullBwCount
	for _, rs := range []rateSample{
		// A sample the sampler discarded: its interval was shorter than
		// min_rtt, so its rate is zero.
		{hasData: true, delivered: bbrTestMSS, newlyAcked: bbrTestMSS, rtt: -1},
		// A duplicate ACK.
		{rtt: -1},
	} {
		bt.clock.Advance(bbrTestRTT)
		rs.priorDelivered = bt.s.rate.Delivered
		bt.s.rate.Delivered += rs.newlyAcked
		b.OnACK(&rs, bt.clock.NowMonotonic())
		if b.RoundCount != rounds || b.RoundStart || b.FullBwCount != count || b.LossRoundStart {
			t.Errorf("after %+v: round_count %d round_start %t full_bw_count %d loss_round_start %t, want %d false %d false",
				rs, b.RoundCount, b.RoundStart, b.FullBwCount, b.LossRoundStart, rounds, count)
		}
	}
}

// TestBBRStartupHighLossNeedsSixEvents checks that, with SACK, fewer than
// BBR.StartupFullLossCnt loss events in a round do not end Startup.
//
// +checklocksignore
func TestBBRStartupHighLossNeedsSixEvents(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.round(bbrTestRate/2, bbrTestBDP)
	var p segRate
	for i := 0; i < bbrStartupFullLossCnt-1; i++ {
		bt.s.rate.Lost += bbrTestMSS
		b.OnLoss(&p, bbrTestMSS)
	}
	b.OnEnterRecovery(false /* rto */)
	bt.ackWith(rateSample{deliveryRate: bbrTestRate / 2, txInFlight: 100 * bbrTestMSS, lost: 5 * bbrTestMSS}, bbrTestBDP)
	if b.FullBwReached || b.State != BBRStartup {
		t.Errorf("full_bw_reached %t state %s after %d loss events, want false Startup", b.FullBwReached, b.State, bbrStartupFullLossCnt-1)
	}
}

// TestBBRCwndLimited checks that C.is_cwnd_limited follows transmissions that
// fill cwnd, for the round in which they happen and the next.
//
// +checklocksignore
func TestBBRCwndLimited(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.round(bbrTestRate, bbrTestMSS)
	if b.isCwndLimited() {
		t.Fatalf("cwnd-limited before any transmission filled cwnd")
	}
	bt.s.rate.InFlight = b.Cwnd - bbrTestMSS
	b.OnTransmit(bt.clock.NowMonotonic(), bbrTestMSS)
	if !b.isCwndLimited() {
		t.Fatalf("not cwnd-limited after a transmission filled cwnd")
	}
	// It lasts for the next round, and ends after one without.
	bt.round(bbrTestRate, bbrTestMSS)
	if !b.IsCwndLimited || b.CwndLimitedInRound {
		t.Errorf("next round: is_cwnd_limited %t, in round %t, want true false", b.IsCwndLimited, b.CwndLimitedInRound)
	}
	bt.round(bbrTestRate, bbrTestMSS)
	if b.isCwndLimited() {
		t.Errorf("still cwnd-limited a round after the last full window")
	}
}

// TestBBRCwndLimitedCountsPackets checks that C.is_cwnd_limited is decided
// the way the sender decides whether cwnd has room: in whole packets, with a
// short segment in flight taking a packet. A count in bytes disagrees with
// the sender when cwnd is not a whole number of segments or short segments
// are in flight, and then a flow that cwnd holds back never probes
// BBR.inflight_longterm upward.
//
// +checklocksignore
func TestBBRCwndLimitedCountsPackets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		inFlight uint64
		size     int
		want     bool
	}{
		// cwnd is 100 and three quarters of a segment: 101 packets.
		{name: "last packet, short segment in flight", inFlight: 99*bbrTestMSS + bbrTestMSS/2, size: bbrTestMSS, want: true},
		{name: "one packet left", inFlight: 98*bbrTestMSS + bbrTestMSS/2, size: bbrTestMSS, want: false},
		{name: "large segment fills cwnd", inFlight: 50 * bbrTestMSS, size: 51 * bbrTestMSS, want: true},
		{name: "large segment leaves room", inFlight: 50 * bbrTestMSS, size: 40 * bbrTestMSS, want: false},
		{name: "short segment takes the last packet", inFlight: 100 * bbrTestMSS, size: 1, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bt := newBBRTest(t, true /* sack */)
			b := bt.b
			bt.round(bbrTestRate, bbrTestMSS)
			// The sender applies a rate-based algorithm's cwnd to the
			// sampler's count of bytes in flight.
			bt.s.rcc = b
			b.Cwnd = 100*bbrTestMSS + 3*bbrTestMSS/4
			b.applyCwnd()
			bt.s.rate.InFlight = tc.inFlight
			if room := bt.s.cwndRoom(); room <= 0 {
				t.Fatalf("cwndRoom() = %d before the transmission, want room", room)
			}
			b.OnTransmit(bt.clock.NowMonotonic(), tc.size)
			bt.s.rate.InFlight += uint64(tc.size)
			if got := bt.s.cwndRoom() <= 0; got != tc.want {
				t.Fatalf("cwnd used up after the transmission = %t, want %t: the test is wrong", got, tc.want)
			}
			if got := b.isCwndLimited(); got != tc.want {
				t.Errorf("is_cwnd_limited = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestBBRACKAggregation is A.13 at the unit level: ACKs that arrive in a
// burst raise BBR.extra_acked, and cwnd with it.
//
// +checklocksignore
func TestBBRACKAggregation(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	bt.untilState(BBRProbeBWCruise, bbrTestBDP, 2)
	// A quiet 5ms, then 5 BDPs' worth of ACKs within the same round.
	bt.clock.Advance(5 * time.Millisecond)
	now := bt.clock.NowMonotonic()
	before := b.MaxInflight
	for i := 0; i < 5; i++ {
		rs := rateSample{hasData: true, deliveryRate: bbrTestRate, delivered: bbrTestBDP, newlyAcked: bbrTestBDP, rtt: -1, priorDelivered: b.NextRoundDelivered - 1}
		bt.s.rate.Delivered += rs.newlyAcked
		b.OnACK(&rs, now)
	}
	if b.ExtraAcked == 0 || b.MaxInflight <= before {
		t.Errorf("extra_acked %d max_inflight %d (was %d), want extra_acked > 0 and max_inflight higher", b.ExtraAcked, b.MaxInflight, before)
	}
	if b.ExtraAcked > b.Cwnd {
		t.Errorf("extra_acked %d above cwnd %d", b.ExtraAcked, b.Cwnd)
	}
}

// TestBBRIdleRestartStartsAggregationEpoch checks that restarting from idle
// starts a new ACK aggregation epoch: the count of data delivered in the
// epoch is reset along with the epoch's start time, as in Linux
// (bbr3_cwnd_event_tx_start()). The pseudocode of section 5.4.1 resets only
// the start time. Then data delivered before the idle period is measured
// against the time since it, the excess never returns to zero, and on a path
// where every flight is acknowledged before the next one leaves
// BBR.extra_acked, and cwnd with it, grow without bound.
//
// +checklocksignore
func TestBBRIdleRestartStartsAggregationEpoch(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	bt.untilState(BBRProbeBWCruise, bbrTestBDP, 2)
	// Half a BDP is sent after an idle period and acknowledged a tenth of
	// a round trip later, 40 times over. That is less than half of what
	// the path can carry, in bursts of half a BDP.
	const chunk = bbrTestBDP / 2
	for i := 0; i < 40; i++ {
		bt.s.rate.InFlight = 0
		bt.s.rate.markAppLimited()
		bt.clock.Advance(bbrTestRTT)
		b.OnTransmit(bt.clock.NowMonotonic(), bbrTestMSS)
		bt.s.rate.InFlight = chunk
		bt.clock.Advance(bbrTestRTT / 10)
		rs := rateSample{hasData: true, deliveryRate: bbrTestRate, isAppLimited: true, delivered: chunk, newlyAcked: chunk, rtt: bbrTestRTT, priorDelivered: bt.s.rate.Delivered, txInFlight: chunk}
		bt.s.rate.Delivered += rs.newlyAcked
		bt.s.rate.InFlight = 0
		b.OnACK(&rs, bt.clock.NowMonotonic())
	}
	if b.ExtraAckedDelivered > chunk {
		t.Errorf("extra_acked_delivered %d, want at most the %d delivered since the last restart from idle", b.ExtraAckedDelivered, chunk)
	}
	if b.ExtraAcked > chunk {
		t.Errorf("extra_acked %d, want at most one burst of %d", b.ExtraAcked, chunk)
	}
}

// TestBBRPacingRateNeverZero checks that a zero bandwidth estimate does not
// turn pacing off.
//
// +checklocksignore
func TestBBRPacingRateNeverZero(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	rate := b.TCPBBRState.PacingRate
	b.FullBwReached = true
	b.setPacingRate()
	if b.Bw != 0 || b.TCPBBRState.PacingRate != rate {
		t.Errorf("bw %d pacing rate %d, want 0 and the initial %d", b.Bw, b.TCPBBRState.PacingRate, rate)
	}
}

// TestBBRIdleRestartEndsProbeRTT checks that restarting from idle in ProbeRTT,
// once it is done, gives the sender the restored window at once.
//
// +checklocksignore
func TestBBRIdleRestartEndsProbeRTT(t *testing.T) {
	bt := newBBRTest(t, true /* sack */)
	b := bt.b
	bt.toProbeBW()
	bt.clock.Advance(bbrMinRTTFilterLen)
	bt.ackWith(rateSample{deliveryRate: bbrTestRate, rtt: 2 * bbrTestRTT}, bbrMinPipeCwndSegments*bbrTestMSS)
	bt.round(bbrTestRate, bbrMinPipeCwndSegments*bbrTestMSS)
	bt.round(bbrTestRate, bbrMinPipeCwndSegments*bbrTestMSS)
	if b.State != BBRProbeRTT || !b.ProbeRTTDoneStampSet || !b.ProbeRTTRoundDone {
		t.Fatalf("state %s done stamp set %t round done %t, want ProbeRTT true true", b.State, b.ProbeRTTDoneStampSet, b.ProbeRTTRoundDone)
	}
	// Idle past the done stamp, then send.
	bt.s.rate.InFlight = 0
	bt.s.rate.markAppLimited()
	bt.clock.Advance(bbrProbeRTTDuration + time.Millisecond)
	b.OnTransmit(bt.clock.NowMonotonic(), bbrTestMSS)
	if b.State == BBRProbeRTT {
		t.Fatalf("still in ProbeRTT after restarting from idle past its end")
	}
	if want := int((b.Cwnd + bbrTestMSS - 1) / bbrTestMSS); bt.s.SndCwnd != want || b.Cwnd < b.PriorCwnd {
		t.Errorf("sender cwnd %d segments, BBR cwnd %d prior %d, want %d segments and the prior window restored", bt.s.SndCwnd, b.Cwnd, b.PriorCwnd, want)
	}
}
