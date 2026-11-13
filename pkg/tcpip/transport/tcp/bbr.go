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
	"math"
	"math/bits"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// This file implements the BBR congestion control algorithm, version 3, as
// specified in https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-07.
// Each function carries the name of the draft's pseudocode function it
// implements, and the code follows that pseudocode in order. Names such as
// BBR.max_bw and C.cwnd in comments are the draft's.
//
// Volumes of data are in bytes and rates in bytes per second, as the draft
// recommends. Gains and fractions are integers in thousandths of bbrUnit, so
// that no decision depends on floating point.
//
// ECN is not supported; netstack does not negotiate it.

const (
	// bbrUnit is the scale of gains and fractions: 1.0 is bbrUnit.
	bbrUnit = 1000

	// bbrStartupPacingGain is BBR.StartupPacingGain, 4 * ln(2) ~= 2.7726,
	// rounded up so that the sending rate at least doubles each round
	// (section 2.5).
	bbrStartupPacingGain = 2773

	// bbrDrainPacingGain is BBR.DrainPacingGain (section 2.5).
	bbrDrainPacingGain = 500

	// The pacing gains of the ProbeBW phases and ProbeRTT (section 5.6.1).
	bbrProbeBWDownPacingGain   = 900
	bbrProbeBWCruisePacingGain = 1000
	bbrProbeBWRefillPacingGain = 1000
	bbrProbeBWUpPacingGain     = 1250
	bbrProbeRTTPacingGain      = 1000

	// bbrDefaultCwndGain is BBR.DefaultCwndGain (section 2.6).
	bbrDefaultCwndGain = 2000

	// bbrProbeBWUpCwndGain is the cwnd gain in ProbeBW_UP (section 5.3.3.5).
	bbrProbeBWUpCwndGain = 2250

	// bbrProbeRTTCwndGain is BBR.ProbeRTTCwndGain (section 2.16.2).
	bbrProbeRTTCwndGain = 500

	// bbrPacingMarginPercent is BBR.PacingMarginPercent (section 2.5).
	bbrPacingMarginPercent = 1

	// bbrLossThresh is BBR.LossThresh, 2% (section 2.8).
	bbrLossThresh = 20

	// bbrBeta is BBR.Beta, 0.7 (section 2.8).
	bbrBeta = 700

	// bbrHeadroom is BBR.Headroom, 0.15 (section 2.8).
	bbrHeadroom = 150

	// bbrMinPipeCwndSegments is BBR.MinPipeCwnd in units of C.SMSS (section
	// 2.8).
	bbrMinPipeCwndSegments = 4

	// bbrExtraAckedFilterLen is BBR.ExtraAckedFilterLen, in round trips
	// (section 2.12).
	bbrExtraAckedFilterLen = 10

	// bbrStartupFullLossCnt is BBR.StartupFullLossCnt (section 2.13).
	bbrStartupFullLossCnt = 6

	// bbrFullBwRounds is the number of rounds without 25% growth after which
	// the pipe is full, and bbrFullBwGrowth that growth as a fraction of
	// bbrUnit (section 5.3.1.2).
	bbrFullBwRounds = 3
	bbrFullBwGrowth = 1250

	// bbrMinRTTFilterLen is BBR.MinRTTFilterLen (section 2.16.1).
	bbrMinRTTFilterLen = 10 * time.Second

	// bbrProbeRTTDuration is BBR.ProbeRTTDuration (section 2.16.2).
	bbrProbeRTTDuration = 200 * time.Millisecond

	// bbrDrainMaxRounds is how long Drain lasts at most, in round trips
	// (section 5.3.2).
	bbrDrainMaxRounds = 3

	// bbrRenoCoexistenceMaxRounds bounds the round trips between bandwidth
	// probes (section 5.3.3.8.3).
	bbrRenoCoexistenceMaxRounds = 63

	// bbrProbeWaitBase and bbrProbeWaitRandom define the wall clock time
	// between bandwidth probes, bbrProbeWaitBase plus a random time up to
	// bbrProbeWaitRandom (section 5.3.3.8, PickProbeWait()).
	bbrProbeWaitBase   = 2 * time.Second
	bbrProbeWaitRandom = time.Second

	// bbrMaxProbeUpRounds caps BBR.bw_probe_up_rounds (section 5.3.3.9,
	// RaiseInflightLongtermSlope()).
	bbrMaxProbeUpRounds = 30

	// bbrInitialRTT is the RTT assumed before there is an RTT sample (section
	// 5.6.2, InitPacingRate()).
	bbrInitialRTT = time.Millisecond

	// bbrInfinity is "Infinity" for volumes of data and rates.
	bbrInfinity = math.MaxUint64

	// bbrInfiniteRTT is "Infinity" for BBR.min_rtt.
	bbrInfiniteRTT = time.Duration(math.MaxInt64)
)

// bbrState is the BBR congestion control algorithm.
//
// +stateify savable
type bbrState struct {
	TCPBBRState

	// maxBw holds the largest delivery rate sample of the current and of the
	// previous ProbeBW cycle, indexed by BBR.cycle_count modulo 2. With a
	// window of exactly two cycles, BBR.MaxBwFilterLen, this is the windowed
	// max filter of section 5.5.5.
	maxBw [2]uint64

	// extraAckedFilter is BBR.extra_acked_filter (section 5.5.9).
	extraAckedFilter windowedMaxFilter

	// savedForRecovery is true once the losses that are about to start a
	// loss recovery episode have saved the state that the episode would
	// undo. See OnEnterRecovery.
	savedForRecovery bool

	s *sender
}

var _ rateCongestionControl = (*bbrState)(nil)

// newBBR returns BBR for the sender s. It takes over the sender's congestion
// window, so that switching to BBR on an established connection keeps it.
//
// +checklocks:s.ep.mu
func newBBR(s *sender) *bbrState {
	b := &bbrState{s: s}
	b.Cwnd = uint64(s.SndCwnd) * b.smss()
	b.onInit()
	return b
}

// onInit is OnInit() (section 5.2.1).
//
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) onInit() {
	now := b.s.ep.stack.Clock().NowMonotonic()
	b.maxBw = [2]uint64{}
	b.MaxBw = 0
	b.MinRTT = bbrInfiniteRTT
	if srtt := b.srtt(); srtt > 0 {
		b.MinRTT = srtt
	}
	b.MinRTTStamp = now
	b.MinRTTExpired = false
	b.ProbeRTTDoneStampSet = false
	b.ProbeRTTRoundDone = false
	b.ProbeRTTCwnd = bbrInfinity
	b.PriorCwnd = 0
	b.UndoState = BBRStateNone
	b.UndoBwShortterm = 0
	b.UndoInflightShortterm = 0
	b.UndoInflightLongterm = 0
	b.IdleRestart = false
	b.ExtraAckedIntervalStart = now
	b.ExtraAckedDelivered = 0
	b.FullBwReached = false
	b.InflightLongterm = bbrInfinity
	b.ProbeUpAckedPerInc = bbrInfinity
	b.BwProbeUpAcked = 0
	b.BwProbeUpRounds = 0
	b.RoundsSinceProbeUp = 0
	b.CheckProbeLoss = false
	b.PrevProbeTooHigh = false
	b.PrevProbePrecautionary = false
	b.IsBwProbeStopping = false
	b.CycleStamp = tcpip.MonotonicTime{}
	b.BwProbeWait = 0
	b.resetCongestionSignals()
	b.resetShortTermModel()
	b.initRoundCounting()
	b.resetFullBW()
	b.initPacingRate()
	b.setSendQuantum()
	b.enterStartup()
}

// HandleLossDetected implements congestionControl.HandleLossDetected. BBR
// responds to losses in OnLoss and OnEnterRecovery instead.
func (*bbrState) HandleLossDetected() {}

// HandleRTOExpired implements congestionControl.HandleRTOExpired. BBR
// responds to the timeout in OnEnterRecovery.
func (*bbrState) HandleRTOExpired() {}

// HandleWindowRestart implements congestionControl.HandleWindowRestart. The
// sender does not restart the window of a rate-based algorithm; BBR handles
// restarts from idle in OnTransmit.
func (*bbrState) HandleWindowRestart() {}

// Update implements congestionControl.Update. BBR works from OnACK.
func (*bbrState) Update(int, time.Duration, tcpip.MonotonicTime) {}

// PostRecovery implements congestionControl.PostRecovery. BBR works from
// OnExitRecovery.
func (*bbrState) PostRecovery() {}

// OnTransmit implements rateCongestionControl.OnTransmit: OnTransmit()
// (section 5.2.2). It also notes whether the transmission uses up cwnd, for
// C.is_cwnd_limited.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) OnTransmit(now tcpip.MonotonicTime, size int) {
	cwnd := b.Cwnd
	b.handleRestartFromIdle(now)
	if b.Cwnd != cwnd {
		// Restarting from idle in ProbeRTT may have ended it.
		b.applyCwnd()
	}
	// Why not compare bytes in flight with cwnd: the sender stops when the
	// packets in flight, rounded up, reach cwnd in packets. With cwnd not a
	// whole number of segments, or a short segment in flight, a byte count
	// can stay below cwnd while the sender has no room, and a flow that is
	// held at BBR.inflight_longterm would then never raise it.
	if b.s.rateCCRoomAfter(size) <= 0 {
		b.CwndLimitedInRound = true
	}
}

// OnACK implements rateCongestionControl.OnACK: UpdateOnACK() (section
// 5.2.3), after the sender has generated the rate sample.
//
// +checklocks:b.s.ep.mu
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) OnACK(rs *rateSample, now tcpip.MonotonicTime) {
	b.updateModelAndState(rs, now)
	b.updateControlParameters(rs)
	b.applyCwnd()
}

// OnLoss implements rateCongestionControl.OnLoss: HandleLostPacket() (section
// 5.5.10.2).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) OnLoss(p *segRate, size int) {
	b.handleLostPacket(p, size)
}

// OnEnterRecovery implements rateCongestionControl.OnEnterRecovery:
// OnEnterRTO() or OnEnterFastRecovery() (section 5.6.4.4).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) OnEnterRecovery(rto bool) {
	b.saveCwnd()
	// The draft saves the state upon entering recovery, before any loss of
	// the episode reaches the model. This sender reports the losses that
	// start an episode (RACK, or a retransmission timeout) just before it
	// enters recovery, and they may already have changed the model and set
	// BBR.undo_state (HandleInflightTooHigh()). The first of them saved the
	// state as it was before, which a second save here would overwrite.
	//
	// Entering recovery again before it has ended, on a timeout during
	// fast recovery, a later timeout, or fast recovery after a timeout,
	// continues the episode, as the sender's detection of spurious
	// recovery (RFC 3522) does, so the state saved at its start is kept.
	if !b.InLossRecovery && !b.savedForRecovery {
		b.saveStateUponLoss()
	}
	b.savedForRecovery = false
	if rto {
		// The draft sets C.cwnd = C.inflight + 1, from when cwnd was counted
		// in packets: it "allows 1 C.SMSS to be transmitted". In bytes that
		// is one SMSS more than what is in flight.
		b.Cwnd = b.s.rate.InFlight + b.smss()
		b.applyCwnd()
	}
	b.InLossRecovery = true
}

// OnExitRecovery implements rateCongestionControl.OnExitRecovery (section
// 5.6.4.4).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) OnExitRecovery() {
	b.InLossRecovery = false
	b.savedForRecovery = false
	b.restoreCwnd()
	b.applyCwnd()
}

// OnSpuriousRecovery implements rateCongestionControl.OnSpuriousRecovery:
// HandleSpuriousLossDetection() (section 5.5.11.2).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) OnSpuriousRecovery() {
	b.handleSpuriousLossDetection(b.s.ep.stack.Clock().NowMonotonic())
	b.applyCwnd()
}

// PacingRate implements rateCongestionControl.PacingRate: C.pacing_rate.
func (b *bbrState) PacingRate() uint64 {
	return b.TCPBBRState.PacingRate
}

// applyCwnd sets the sender's congestion window, counted in segments, from
// C.cwnd, rounding up.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) applyCwnd() {
	smss := b.smss()
	segments := b.Cwnd / smss
	if b.Cwnd%smss != 0 {
		segments++
	}
	b.s.SndCwnd = int(min(max(segments, 1), math.MaxInt32))
}

// smss returns C.SMSS.
//
// +checklocksignore
func (b *bbrState) smss() uint64 {
	return uint64(max(b.s.MaxPayloadSize, 1))
}

// srtt returns C.srtt, or zero if there is no RTT sample yet.
//
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) srtt() time.Duration {
	b.s.rtt.Lock()
	defer b.s.rtt.Unlock()
	if !b.s.rtt.TCPRTTState.SRTTInited {
		return 0
	}
	return b.s.rtt.TCPRTTState.SRTT
}

// minPipeCwnd returns BBR.MinPipeCwnd.
func (b *bbrState) minPipeCwnd() uint64 {
	return bbrMinPipeCwndSegments * b.smss()
}

// initialCwnd returns C.InitialCwnd in bytes.
func (b *bbrState) initialCwnd() uint64 {
	return InitialCwnd * b.smss()
}

// updateModelAndState is UpdateModelAndState() (section 5.2.3).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateModelAndState(rs *rateSample, now tcpip.MonotonicTime) {
	b.updateLatestDeliverySignals(rs)
	b.updateCongestionSignals(rs)
	b.updateACKAggregation(rs, now)
	b.checkFullBWReached(rs)
	b.checkStartupDone(rs)
	b.checkDrainDone(now)
	b.updateProbeBWCyclePhase(rs, now)
	b.updateMinRTT(rs, now)
	b.checkProbeRTT(rs, now)
	b.advanceLatestDeliverySignals(rs)
	b.boundBWForModel()
}

// updateControlParameters is UpdateControlParameters() (section 5.2.3).
//
// +checklocks:b.s.ep.mu
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) updateControlParameters(rs *rateSample) {
	b.setPacingRate()
	b.setSendQuantum()
	b.setCwnd(rs)
}

// enterStartup is EnterStartup() (section 5.3.1.1).
func (b *bbrState) enterStartup() {
	b.State = BBRStartup
	b.PacingGain = bbrStartupPacingGain
	b.CwndGain = bbrDefaultCwndGain
}

// checkStartupDone is CheckStartupDone() (section 5.3.1.1).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) checkStartupDone(rs *rateSample) {
	b.checkStartupHighLoss(rs)
	if b.State == BBRStartup && b.FullBwReached {
		b.enterDrain()
	}
}

// resetFullBW is ResetFullBW() (section 5.3.1.2).
func (b *bbrState) resetFullBW() {
	b.FullBw = 0
	b.FullBwCount = 0
	b.FullBwNow = false
}

// checkFullBWReached is CheckFullBWReached() (section 5.3.1.2).
func (b *bbrState) checkFullBWReached(rs *rateSample) {
	if b.FullBwNow || !b.RoundStart || rs.isAppLimited {
		// No need to check for a full pipe now.
		return
	}
	if mulDiv(rs.deliveryRate, bbrUnit, 1) >= mulDiv(b.FullBw, bbrFullBwGrowth, 1) {
		// Bandwidth is still growing, so reset and record the new baseline.
		b.resetFullBW()
		b.FullBw = rs.deliveryRate
		return
	}
	// Another round without much growth.
	b.FullBwCount++
	b.FullBwNow = b.FullBwCount >= bbrFullBwRounds
	if b.FullBwNow {
		b.FullBwReached = true
	}
}

// checkStartupHighLoss is CheckStartupHighLoss() (section 5.3.1.3). It sets
// BBR.full_bw_reached, not BBR.full_bw_now, as the pseudocode does; test A.2
// also mentions BBR.full_bw_now, which only matters in ProbeBW_UP, where it is
// reset on entry.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) checkStartupHighLoss(rs *rateSample) {
	if b.FullBwReached || !b.LossRoundStart || !b.InLossRecovery {
		return
	}
	if b.LossEventsInRound < bbrStartupFullLossCnt && b.s.ep.SACKPermitted {
		return
	}
	if !b.isInflightTooHigh(rs.lost, rs.txInFlight) {
		return
	}
	b.UndoState = BBRStartup
	b.FullBwReached = true
	b.InflightLongterm = max(b.BDP, b.InflightLatest)
}

// enterDrain is EnterDrain() (section 5.3.2).
func (b *bbrState) enterDrain() {
	b.State = BBRDrain
	b.PacingGain = bbrDrainPacingGain
	b.CwndGain = bbrDefaultCwndGain
	b.DrainStartRound = b.RoundCount
}

// checkDrainDone is CheckDrainDone() (section 5.3.2).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) checkDrainDone(now tcpip.MonotonicTime) {
	if b.State == BBRDrain && (b.s.rate.InFlight <= b.inflight(b.Bw, bbrUnit) || b.RoundCount > b.DrainStartRound+bbrDrainMaxRounds) {
		b.enterProbeBW(now)
	}
}

// isTimeToProbeBW is IsTimeToProbeBW() (section 5.3.3.8): is it time to go
// from DOWN or CRUISE to REFILL?
//
// +checklocks:b.s.ep.mu
func (b *bbrState) isTimeToProbeBW(now tcpip.MonotonicTime) bool {
	if b.hasElapsedInPhase(b.BwProbeWait, now) || b.isRenoCoexistenceProbeTime() {
		b.startProbeBWRefill()
		return true
	}
	return false
}

// pickProbeWait is PickProbeWait() (section 5.3.3.8): a randomized decision
// about how long to wait until probing for bandwidth, in round trips and in
// wall clock time.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) pickProbeWait() {
	rng := b.s.ep.stack.InsecureRNG()
	b.RoundsSinceProbeUp = uint64(rng.Int63n(2))
	b.BwProbeWait = bbrProbeWaitBase + time.Duration(rng.Int63n(int64(bbrProbeWaitRandom)))
}

// isRenoCoexistenceProbeTime is IsRenoCoexistenceProbeTime() (section
// 5.3.3.8). Reno grows its window by one segment per round trip, so the
// number of round trips it needs to fill the target inflight is that
// inflight in segments. The pseudocode compares the target inflight with a
// count of rounds directly, which only works in packet units.
func (b *bbrState) isRenoCoexistenceProbeTime() bool {
	renoRounds := b.targetInflight() / b.smss()
	rounds := min(renoRounds, bbrRenoCoexistenceMaxRounds)
	return b.RoundsSinceProbeUp >= rounds
}

// targetInflight is TargetInflight() (section 5.3.3.8): the estimated BDP,
// unless congestion cut C.cwnd.
func (b *bbrState) targetInflight() uint64 {
	return min(b.BDP, b.Cwnd)
}

// enterProbeBW is EnterProbeBW() (section 5.3.3.9).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) enterProbeBW(now tcpip.MonotonicTime) {
	b.CwndGain = bbrDefaultCwndGain
	b.startProbeBWDown(now)
}

// startProbeBWDown is StartProbeBW_DOWN() (section 5.3.3.9).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) startProbeBWDown(now tcpip.MonotonicTime) {
	b.resetCongestionSignals()
	// Not growing BBR.inflight_longterm.
	b.ProbeUpAckedPerInc = bbrInfinity
	b.pickProbeWait()
	// Start the wall clock.
	b.CycleStamp = now
	b.IsBwProbeStopping = true
	b.startRound()
	b.State = BBRProbeBWDown
	b.PacingGain = bbrProbeBWDownPacingGain
	b.CwndGain = bbrDefaultCwndGain
}

// startProbeBWCruise is StartProbeBW_CRUISE() (section 5.3.3.9).
func (b *bbrState) startProbeBWCruise() {
	b.State = BBRProbeBWCruise
	b.PacingGain = bbrProbeBWCruisePacingGain
	b.CwndGain = bbrDefaultCwndGain
}

// startProbeBWRefill is StartProbeBW_REFILL() (section 5.3.3.9).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) startProbeBWRefill() {
	b.resetShortTermModel()
	b.BwProbeUpRounds = 0
	b.BwProbeUpAcked = 0
	b.PrevProbePrecautionary = false
	b.IsBwProbeStopping = false
	b.startRound()
	b.State = BBRProbeBWRefill
	b.PacingGain = bbrProbeBWRefillPacingGain
	b.CwndGain = bbrDefaultCwndGain
}

// startProbeBWUp is StartProbeBW_UP() (section 5.3.3.9).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) startProbeBWUp(rs *rateSample) {
	b.startRound()
	b.resetFullBW()
	b.FullBw = rs.deliveryRate
	b.State = BBRProbeBWUp
	b.PacingGain = bbrProbeBWUpPacingGain
	b.CwndGain = bbrProbeBWUpCwndGain
	b.raiseInflightLongtermSlope()
}

// updateProbeBWCyclePhase is UpdateProbeBWCyclePhase() (section 5.3.3.9):
// the core state machine logic for ProbeBW. The draft runs it on each ACK
// that acknowledges new data.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateProbeBWCyclePhase(rs *rateSample, now tcpip.MonotonicTime) {
	if rs.newlyAcked == 0 {
		return
	}
	if !b.FullBwReached {
		// Only handling steady-state behavior here.
		return
	}
	if b.adaptLongTermModel(rs, now) {
		// Already decided a state transition.
		return
	}
	switch b.State {
	case BBRProbeBWDown:
		if b.isTimeToProbeBW(now) {
			return
		}
		if b.isTimeToCruise() {
			b.startProbeBWCruise()
		}
	case BBRProbeBWCruise:
		b.isTimeToProbeBW(now)
	case BBRProbeBWRefill:
		// After one round of REFILL, start UP.
		if b.RoundStart {
			b.CheckProbeLoss = true
			b.startProbeBWUp(rs)
		}
	case BBRProbeBWUp:
		if b.isTimeToGoDown(rs) {
			// No high loss (yet).
			b.PrevProbeTooHigh = false
			b.startProbeBWDown(now)
		}
	}
}

// isInAProbeBWState is IsInAProbeBWState() (section 5.3.3.9).
func (b *bbrState) isInAProbeBWState() bool {
	switch b.State {
	case BBRProbeBWDown, BBRProbeBWCruise, BBRProbeBWRefill, BBRProbeBWUp:
		return true
	default:
		return false
	}
}

// isTimeToCruise is IsTimeToCruise() (section 5.3.3.9): time to go from DOWN
// to CRUISE?
//
// +checklocks:b.s.ep.mu
func (b *bbrState) isTimeToCruise() bool {
	inflight := b.s.rate.InFlight
	if inflight > b.inflightWithHeadroom() {
		// Not enough headroom.
		return false
	}
	if inflight > b.inflight(b.MaxBw, bbrUnit) {
		// C.inflight > estimated BDP.
		return false
	}
	return true
}

// isTimeToGoDown is IsTimeToGoDown() (section 5.3.3.9): time to go from UP
// to DOWN?
//
// +checklocks:b.s.ep.mu
func (b *bbrState) isTimeToGoDown(rs *rateSample) bool {
	// Precautionary Bandwidth Probing: Deceleration.
	if b.PrevProbeTooHigh && b.s.rate.InFlight >= b.InflightLongterm {
		b.PrevProbePrecautionary = true
		return true
	}
	if b.isCwndLimited() && b.Cwnd >= b.InflightLongterm {
		// Bandwidth is limited by BBR.inflight_longterm.
		b.resetFullBW()
		b.FullBw = rs.deliveryRate
	} else if b.FullBwNow {
		// We estimate we've fully used the path's bandwidth.
		return true
	}
	return false
}

// isProbingBW is IsProbingBW() (section 5.3.3.9).
func (b *bbrState) isProbingBW() bool {
	switch b.State {
	case BBRStartup, BBRProbeBWRefill, BBRProbeBWUp:
		return true
	default:
		return false
	}
}

// hasElapsedInPhase is HasElapsedInPhase() (section 5.3.3.9).
func (b *bbrState) hasElapsedInPhase(interval time.Duration, now tcpip.MonotonicTime) bool {
	return now.After(b.CycleStamp.Add(interval))
}

// inflightWithHeadroom is InflightWithHeadroom() (section 5.3.3.9): a volume
// of data that tries to leave free headroom in the bottleneck buffer or link
// for other flows, for fairness convergence and lower RTTs and loss.
func (b *bbrState) inflightWithHeadroom() uint64 {
	if b.InflightLongterm == bbrInfinity {
		return bbrInfinity
	}
	headroom := max(b.smss(), mulDiv(b.InflightLongterm, bbrHeadroom, bbrUnit))
	return max(subClamped(b.InflightLongterm, headroom), b.minPipeCwnd())
}

// raiseInflightLongtermSlope is RaiseInflightLongtermSlope() (section
// 5.3.3.9).
func (b *bbrState) raiseInflightLongtermSlope() {
	growthThisRound := uint64(1) << b.BwProbeUpRounds
	b.BwProbeUpRounds = min(b.BwProbeUpRounds+1, bbrMaxProbeUpRounds)
	b.ProbeUpAckedPerInc = max(b.Cwnd/growthThisRound, b.smss())
}

// probeInflightLongtermUpward is ProbeInflightLongtermUpward() (section
// 5.3.3.9).
func (b *bbrState) probeInflightLongtermUpward(rs *rateSample) {
	if !b.isCwndLimited() || b.Cwnd < b.InflightLongterm {
		// Not fully using BBR.inflight_longterm, so don't grow it.
		return
	}
	b.BwProbeUpAcked += rs.newlyAcked
	if b.BwProbeUpAcked >= b.ProbeUpAckedPerInc {
		delta := b.BwProbeUpAcked / b.ProbeUpAckedPerInc
		b.BwProbeUpAcked -= delta * b.ProbeUpAckedPerInc
		b.InflightLongterm = addSaturating(b.InflightLongterm, delta*b.smss())
	}
	if b.RoundStart {
		b.raiseInflightLongtermSlope()
	}
}

// adaptLongTermModel is AdaptLongTermModel() (section 5.3.3.9): it tracks ACK
// state and updates the BBR.max_bw window and BBR.inflight_longterm, and
// returns true if it decided a state transition.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) adaptLongTermModel(rs *rateSample, now tcpip.MonotonicTime) bool {
	if b.IsBwProbeStopping && b.RoundStart {
		// End of samples from the bandwidth probing phase.
		b.CheckProbeLoss = false
		b.IsBwProbeStopping = false
		if b.isInAProbeBWState() && !rs.isAppLimited {
			b.advanceMaxBwFilter()
		}
		// Precautionary Bandwidth Probing: Acceleration.
		if b.isInAProbeBWState() && b.PrevProbePrecautionary && !b.PrevProbeTooHigh {
			b.startProbeBWRefill()
			return true
		}
	}
	if !b.isInflightTooHigh(rs.lost, rs.txInFlight) {
		// The loss rate is safe. Adjust upper bounds upward.
		if b.InflightLongterm == bbrInfinity {
			// No upper bounds to raise.
			return false
		}
		if rs.txInFlight > b.InflightLongterm {
			b.InflightLongterm = rs.txInFlight
		}
		if b.State == BBRProbeBWUp {
			b.probeInflightLongtermUpward(rs)
		}
	}
	return false
}

// updateMinRTT is UpdateMinRTT() (section 5.3.4.3).
func (b *bbrState) updateMinRTT(rs *rateSample, now tcpip.MonotonicTime) {
	b.MinRTTExpired = now.After(b.MinRTTStamp.Add(bbrMinRTTFilterLen))
	if b.MinRTTExpired {
		b.ProbeRTTCwnd = b.bdpMultiple(bbrProbeRTTCwndGain)
	}
	if rs.rtt >= 0 && (rs.rtt < b.MinRTT || b.MinRTTExpired) {
		b.MinRTT = rs.rtt
		b.MinRTTStamp = now
	}
}

// checkProbeRTT is CheckProbeRTT() (section 5.3.4.3).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) checkProbeRTT(rs *rateSample, now tcpip.MonotonicTime) {
	if b.State != BBRProbeRTT && b.MinRTTExpired && !b.IdleRestart {
		b.saveCwnd()
		b.enterProbeRTT()
		b.ProbeRTTDoneStampSet = false
		b.IsBwProbeStopping = true
		b.startRound()
	}
	if b.State == BBRProbeRTT {
		b.handleProbeRTT(now)
	}
	if rs.hasData && rs.delivered > 0 {
		b.IdleRestart = false
	}
}

// enterProbeRTT is EnterProbeRTT() (section 5.3.4.3).
func (b *bbrState) enterProbeRTT() {
	b.State = BBRProbeRTT
	b.PacingGain = bbrProbeRTTPacingGain
	b.CwndGain = bbrProbeRTTCwndGain
}

// handleProbeRTT is HandleProbeRTT() (section 5.3.4.3).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) handleProbeRTT(now tcpip.MonotonicTime) {
	// Ignore low rate samples during ProbeRTT.
	b.s.rate.markAppLimited()
	if !b.ProbeRTTDoneStampSet && b.s.rate.InFlight <= b.probeRTTCwnd() {
		// Wait for at least BBR.ProbeRTTDuration to elapse, and for at
		// least one round to elapse.
		b.ProbeRTTDoneStamp = now.Add(bbrProbeRTTDuration)
		b.ProbeRTTDoneStampSet = true
		b.ProbeRTTRoundDone = false
		b.startRound()
	} else if b.ProbeRTTDoneStampSet {
		if b.RoundStart {
			b.ProbeRTTRoundDone = true
		}
		if b.ProbeRTTRoundDone {
			b.checkProbeRTTDone(now)
		}
	}
}

// checkProbeRTTDone is CheckProbeRTTDone() (section 5.3.4.3).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) checkProbeRTTDone(now tcpip.MonotonicTime) {
	if b.ProbeRTTDoneStampSet && now.After(b.ProbeRTTDoneStamp) {
		// Schedule the next ProbeRTT.
		b.MinRTTStamp = now
		b.restoreCwnd()
		b.exitProbeRTT(now)
	}
}

// exitProbeRTT is ExitProbeRTT() (section 5.3.4.4).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) exitProbeRTT(now tcpip.MonotonicTime) {
	b.resetShortTermModel()
	if b.FullBwReached {
		b.startProbeBWDown(now)
		b.startProbeBWCruise()
	} else {
		b.enterStartup()
	}
}

// handleRestartFromIdle is HandleRestartFromIdle() (section 5.4.1).
//
// The pseudocode restarts the ACK aggregation interval without clearing the
// data counted in it. The data delivered before the idle period would then
// be measured against the time since it, and the excess could not return to
// zero: on a path where every flight is acknowledged before the next one
// leaves, which restarts from idle each time, BBR.extra_acked and C.cwnd
// would grow without bound. So the count is cleared too, as Linux does in
// bbr3_cwnd_event_tx_start().
//
// +checklocks:b.s.ep.mu
func (b *bbrState) handleRestartFromIdle(now tcpip.MonotonicTime) {
	if b.s.rate.InFlight == 0 && b.s.rate.AppLimited != 0 {
		b.IdleRestart = true
		b.ExtraAckedIntervalStart = now
		b.ExtraAckedDelivered = 0
		if b.isInAProbeBWState() {
			b.setPacingRateWithGain(bbrUnit)
		} else if b.State == BBRProbeRTT {
			b.checkProbeRTTDone(now)
		}
	}
}

// initRoundCounting is InitRoundCounting() (section 5.5.1).
func (b *bbrState) initRoundCounting() {
	b.NextRoundDelivered = 0
	b.RoundStart = false
	b.RoundCount = 0
}

// validSample reports whether the ACK yielded a delivery rate sample. The
// sampler discards a sample whose interval is implausibly short (shorter than
// C.min_rtt) by leaving its rate zero; as in Linux, such an ACK is not a valid
// observation for round counting or the latest delivery signals.
func validSample(rs *rateSample) bool {
	return rs.hasData && rs.deliveryRate > 0
}

// updateRound is UpdateRound() (section 5.5.1). It also rolls
// C.is_cwnd_limited over to the round that starts. As in Linux, only an ACK
// that yields a valid rate sample can start a round.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateRound(rs *rateSample) {
	if validSample(rs) && rs.priorDelivered >= b.NextRoundDelivered {
		b.startRound()
		b.RoundCount++
		b.RoundsSinceProbeUp++
		b.RoundStart = true
		b.IsCwndLimited = b.CwndLimitedInRound
		b.CwndLimitedInRound = false
	} else {
		b.RoundStart = false
	}
}

// startRound is StartRound() (section 5.5.1).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) startRound() {
	b.NextRoundDelivered = b.s.rate.Delivered
}

// isCwndLimited is C.is_cwnd_limited (section 2.2): has the connection fully
// used C.cwnd at any point in the last packet-timed round trip?
func (b *bbrState) isCwndLimited() bool {
	return b.IsCwndLimited || b.CwndLimitedInRound
}

// updateMaxBw is UpdateMaxBw() (section 5.5.5).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateMaxBw(rs *rateSample) {
	b.updateRound(rs)
	if rs.deliveryRate > 0 && (rs.deliveryRate >= b.MaxBw || !rs.isAppLimited) {
		slot := &b.maxBw[b.CycleCount%2]
		*slot = max(*slot, rs.deliveryRate)
		b.MaxBw = max(b.maxBw[0], b.maxBw[1])
	}
}

// advanceMaxBwFilter is AdvanceMaxBwFilter() (section 5.5.6). The samples of
// the cycle before the previous one leave the window.
func (b *bbrState) advanceMaxBwFilter() {
	b.CycleCount++
	b.maxBw[b.CycleCount%2] = 0
}

// updateACKAggregation is UpdateACKAggregation() (section 5.5.9). As in
// Linux, an ACK that acknowledges nothing new is not an aggregation sample.
func (b *bbrState) updateACKAggregation(rs *rateSample, now tcpip.MonotonicTime) {
	if rs.newlyAcked == 0 {
		return
	}
	// Find excess ACKed beyond expected amount over this interval.
	interval := now.Sub(b.ExtraAckedIntervalStart)
	expectedDelivered := uint64(0)
	if interval > 0 {
		expectedDelivered = bytesInTime(b.Bw, interval)
	}
	// Reset the interval if the ACK rate is below the expected rate.
	if b.ExtraAckedDelivered <= expectedDelivered {
		b.ExtraAckedDelivered = 0
		b.ExtraAckedIntervalStart = now
		expectedDelivered = 0
	}
	b.ExtraAckedDelivered += rs.newlyAcked
	extra := min(b.ExtraAckedDelivered-expectedDelivered, b.Cwnd)
	filterLen := uint64(bbrExtraAckedFilterLen)
	if !b.FullBwReached {
		// In Startup, just remember one round.
		filterLen = 1
	}
	b.ExtraAcked = b.extraAckedFilter.update(b.RoundCount, filterLen, extra)
}

// isInflightTooHigh is IsInflightTooHigh() (section 5.5.10.2): do loss
// signals suggest C.inflight was too high? lost and txInFlight are RS.lost
// and RS.tx_in_flight.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) isInflightTooHigh(lost, txInFlight uint64) bool {
	return mulDiv(lost, bbrUnit, 1) > mulDiv(txInFlight, bbrLossThresh, 1) ||
		(lost > 0 && !b.s.ep.SACKPermitted)
}

// handleInflightTooHigh is HandleInflightTooHigh() (section 5.5.10.2), with
// the fields of RS it reads as arguments.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) handleInflightTooHigh(isAppLimited bool, txInFlight uint64, now tcpip.MonotonicTime) {
	b.PrevProbeTooHigh = true
	// Only react once per bandwidth probe.
	b.CheckProbeLoss = false
	if !isAppLimited {
		b.InflightLongterm = max(txInFlight, mulDiv(b.targetInflight(), bbrBeta, bbrUnit))
	}
	if b.State == BBRProbeBWUp {
		b.UndoState = BBRProbeBWUp
		b.startProbeBWDown(now)
	}
}

// noteLoss is NoteLoss() (section 5.5.10.2), without its call to
// SaveStateUponLoss() on the first loss of each round.
//
// Why: TCP has explicit loss recovery episodes, and the state an episode
// would undo is saved once, when it starts (handleLostPacket and
// OnEnterRecovery), which is what sections 5.5.11.1 and 5.6.4.4 ask for. A
// save on the first loss of a later round overwrites that: in particular,
// when losses end ProbeBW_UP, StartProbeBW_DOWN() resets
// BBR.loss_in_round, so the next lost packet of the same burst would save
// again, setting BBR.undo_state to None and the undo bounds to the reduced
// ones, and a spurious recovery (A.18, A.19) could not be undone. An undo
// therefore returns to the start of the episode, not of its latest round.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) noteLoss() {
	if !b.IsLossInRound {
		// The first loss in this round trip.
		b.LossRoundDelivered = b.s.rate.Delivered
	}
	b.IsLossInRound = true
	b.LossEventsInRound++
}

// handleLostPacket is HandleLostPacket() (section 5.5.10.2). It works on
// copies of the RS fields it sets, so that the sample of the ACK being
// processed, if any, is left alone.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) handleLostPacket(p *segRate, size int) {
	if !b.InLossRecovery && !b.savedForRecovery {
		// This loss is about to start a recovery episode: save the state
		// the episode would undo, before the loss changes it. See
		// noteLoss.
		b.saveStateUponLoss()
		b.savedForRecovery = true
	}
	b.noteLoss()
	if !b.CheckProbeLoss {
		// Not a packet sent while probing bandwidth.
		return
	}
	txInFlight := p.txInFlight
	lost := subClamped(b.s.rate.Lost, p.lost)
	if b.isInflightTooHigh(lost, txInFlight) {
		txInFlight = inflightAtLoss(uint64(size), txInFlight, lost)
		b.handleInflightTooHigh(p.appLimited, txInFlight, b.s.ep.stack.Clock().NowMonotonic())
	}
}

// inflightAtLoss is InflightAtLoss() (section 5.5.10.2): at what C.inflight
// did losses exceed BBR.LossThresh, given a lost "packet" of size bytes,
// which may be an offload burst, sent with txInFlight in flight, and lost
// bytes lost since it was sent?
//
// If the threshold was already crossed before this packet, lost_prefix is
// negative and the result is below inflight_prev, as the draft's formula
// gives, but not below zero. txInFlight and lost include the packet itself;
// if they do not, no prefix can be computed and txInFlight is returned.
func inflightAtLoss(size, txInFlight, lost uint64) uint64 {
	if txInFlight < size || lost < size {
		return txInFlight
	}
	// What was in flight, and lost, before this packet?
	inflightPrev := txInFlight - size
	lostPrev := lost - size
	// lost_prefix = (LossThresh * inflight_prev - lost_prev) / (1 - LossThresh)
	allowed := mulDiv(inflightPrev, bbrLossThresh, 1)
	already := mulDiv(lostPrev, bbrUnit, 1)
	if already > allowed {
		return subClamped(inflightPrev, (already-allowed)/(bbrUnit-bbrLossThresh))
	}
	return inflightPrev + (allowed-already)/(bbrUnit-bbrLossThresh)
}

// updateLatestDeliverySignals is UpdateLatestDeliverySignals() (section
// 5.5.10.3). As in Linux, only an ACK that yields a valid rate sample counts.
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateLatestDeliverySignals(rs *rateSample) {
	b.LossRoundStart = false
	if !validSample(rs) {
		return
	}
	b.BwLatest = max(b.BwLatest, rs.deliveryRate)
	b.InflightLatest = max(b.InflightLatest, rs.delivered)
	if rs.priorDelivered >= b.LossRoundDelivered {
		b.LossRoundDelivered = b.s.rate.Delivered
		b.LossRoundStart = true
	}
}

// advanceLatestDeliverySignals is AdvanceLatestDeliverySignals() (section
// 5.5.10.3).
func (b *bbrState) advanceLatestDeliverySignals(rs *rateSample) {
	if b.LossRoundStart {
		b.BwLatest = rs.deliveryRate
		b.InflightLatest = rs.delivered
		b.LossEventsInRound = 0
	}
}

// resetCongestionSignals is ResetCongestionSignals() (section 5.5.10.3).
func (b *bbrState) resetCongestionSignals() {
	b.IsLossInRound = false
	b.LossEventsInRound = 0
	b.BwLatest = 0
	b.InflightLatest = 0
}

// updateCongestionSignals is UpdateCongestionSignals() (section 5.5.10.3).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) updateCongestionSignals(rs *rateSample) {
	b.updateMaxBw(rs)
	if !b.LossRoundStart {
		// Wait until the end of the round trip.
		return
	}
	// Once per round, adapt.
	b.adaptLowerBoundsFromCongestion()
	b.IsLossInRound = false
}

// adaptLowerBoundsFromCongestion is AdaptLowerBoundsFromCongestion() (section
// 5.5.10.3): once per round trip, respond to congestion.
func (b *bbrState) adaptLowerBoundsFromCongestion() {
	if b.isProbingBW() {
		return
	}
	if b.IsLossInRound {
		b.initLowerBounds()
		b.lossLowerBounds()
	}
}

// initLowerBounds is InitLowerBounds() (section 5.5.10.3): handle the first
// congestion episode in this cycle.
func (b *bbrState) initLowerBounds() {
	if b.BwShortterm == bbrInfinity {
		b.BwShortterm = b.MaxBw
	}
	if b.InflightShortterm == bbrInfinity {
		b.InflightShortterm = b.Cwnd
	}
}

// lossLowerBounds is LossLowerBounds() (section 5.5.10.3): adjust the model
// once per round based on loss.
func (b *bbrState) lossLowerBounds() {
	b.BwShortterm = max(b.BwLatest, mulDiv(b.BwShortterm, bbrBeta, bbrUnit))
	b.InflightShortterm = max(b.InflightLatest, mulDiv(b.InflightShortterm, bbrBeta, bbrUnit))
}

// resetShortTermModel is ResetShortTermModel() (section 5.5.10.3).
func (b *bbrState) resetShortTermModel() {
	b.BwShortterm = bbrInfinity
	b.InflightShortterm = bbrInfinity
}

// boundBWForModel is BoundBWForModel() (section 5.5.10.3).
func (b *bbrState) boundBWForModel() {
	b.Bw = min(b.MaxBw, b.BwShortterm)
}

// saveStateUponLoss is SaveStateUponLoss() (section 5.5.11.1): save state in
// case a loss episode is later declared spurious.
func (b *bbrState) saveStateUponLoss() {
	b.saveCwnd()
	b.UndoState = BBRStateNone
	b.UndoBwShortterm = b.BwShortterm
	b.UndoInflightShortterm = b.InflightShortterm
	b.UndoInflightLongterm = b.InflightLongterm
}

// handleSpuriousLossDetection is HandleSpuriousLossDetection() (section
// 5.5.11.2).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) handleSpuriousLossDetection(now tcpip.MonotonicTime) {
	b.restoreCwnd()
	b.IsLossInRound = false
	b.LossEventsInRound = 0
	b.resetFullBW()
	b.BwShortterm = max(b.BwShortterm, b.UndoBwShortterm)
	b.InflightShortterm = max(b.InflightShortterm, b.UndoInflightShortterm)
	b.InflightLongterm = max(b.InflightLongterm, b.UndoInflightLongterm)
	// If the flow was probing bandwidth, return to that state.
	if b.UndoState == BBRStartup && b.State != BBRStartup {
		b.FullBwReached = false
		if b.State != BBRProbeRTT {
			b.enterStartup()
		}
	} else if b.UndoState == BBRProbeBWUp && b.State != BBRProbeBWUp {
		if b.State != BBRProbeRTT {
			b.startProbeBWRefill()
		}
	}
	b.UndoState = BBRStateNone
}

// initPacingRate is InitPacingRate() (section 5.6.2).
//
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) initPacingRate() {
	srtt := b.srtt()
	if srtt > 0 {
		b.HasSeenRTT = true
	} else {
		srtt = bbrInitialRTT
	}
	nominalBandwidth := bytesPerSecond(b.initialCwnd(), srtt)
	b.TCPBBRState.PacingRate = mulDiv(nominalBandwidth, bbrStartupPacingGain, bbrUnit)
}

// setPacingRateWithGain is SetPacingRateWithGain() (section 5.6.2). A rate of
// zero, which BBR.bw can give before any bandwidth sample, would turn pacing
// off and let the sender burst, so the previous rate is kept instead.
func (b *bbrState) setPacingRateWithGain(pacingGain uint64) {
	rate := mulDiv(mulDiv(b.Bw, pacingGain, bbrUnit), 100-bbrPacingMarginPercent, 100)
	if rate != 0 && (b.FullBwReached || rate > b.TCPBBRState.PacingRate) {
		b.TCPBBRState.PacingRate = rate
	}
}

// setPacingRate is SetPacingRate() (section 5.6.2). The pacing rate set from
// the initial window is set again once there is a smoothed RTT, which section
// 5.6.2 calls for ("the initial C.srtt after the first non-zero RTT sample").
//
// +checklocksexclude:b.s.rtt.rttMutex
func (b *bbrState) setPacingRate() {
	if !b.HasSeenRTT && b.srtt() > 0 {
		b.initPacingRate()
	}
	b.setPacingRateWithGain(b.PacingGain)
}

// setSendQuantum is SetSendQuantum() (section 5.6.3). The pacer derives the
// same value from the pacing rate; BBR needs it for BBR.offload_budget.
func (b *bbrState) setSendQuantum() {
	b.SendQuantum = uint64(sendQuantum(b.TCPBBRState.PacingRate, int(b.smss())))
}

// bdpMultiple is BDPMultiple() (section 5.6.4.2).
func (b *bbrState) bdpMultiple(gain uint64) uint64 {
	return b.bdpMultipleWith(b.Bw, gain)
}

// bdpMultipleWith is BDPMultiple() for a bandwidth of bw. It sets BBR.bdp to
// the BDP for bw.
func (b *bbrState) bdpMultipleWith(bw, gain uint64) uint64 {
	if b.MinRTT == bbrInfiniteRTT {
		// No valid RTT samples yet.
		return b.initialCwnd()
	}
	b.BDP = bytesInTime(bw, b.MinRTT)
	return mulDiv(b.BDP, gain, bbrUnit)
}

// quantizationBudget is QuantizationBudget() (section 5.6.4.2), with
// UpdateOffloadBudget() for TCP (section 5.5.8.1).
//
// BBR.offload_budget is the data that must be allowed in flight for the
// sender's and receiver's batching not to hold the flow back, which the
// draft leaves to the implementation and for TCP suggests as three send
// quanta. A send quantum is capped at 64KB because a stack that schedules
// each quantum to the microsecond sends no more than that at once. Netstack
// cannot: the timer that wakes its pacer fires up to pacingTimerSlack late,
// and the pacer then sends what fell due meanwhile at once (pacer.ready). So
// above the rate at which a quantum reaches the cap, the budget is that much
// data. Without this, on a path whose round trip is microseconds (two
// sandboxes on one machine) cwnd is three quanta however fast the path,
// while netstack itself takes hundreds of microseconds from an ACK to the
// next transmission, and the flow gets about half of what Reno or CUBIC get.
func (b *bbrState) quantizationBudget(inflightCap uint64) uint64 {
	b.OffloadBudget = max(3*b.SendQuantum, bytesInTime(b.TCPBBRState.PacingRate, pacingTimerSlack))
	inflightCap = max(inflightCap, b.OffloadBudget)
	inflightCap = max(inflightCap, b.minPipeCwnd())
	if b.State == BBRProbeBWUp {
		inflightCap = addSaturating(inflightCap, 2*b.smss())
	}
	return inflightCap
}

// inflight is Inflight() (section 5.6.4.2), for a bandwidth of bw: the
// draft's Inflight(gain) uses BBR.bw, and IsTimeToCruise() calls it with
// BBR.max_bw.
func (b *bbrState) inflight(bw, gain uint64) uint64 {
	return b.quantizationBudget(b.bdpMultipleWith(bw, gain))
}

// updateMaxInflight is UpdateMaxInflight() (section 5.6.4.2).
func (b *bbrState) updateMaxInflight() {
	inflightCap := b.bdpMultiple(b.CwndGain)
	inflightCap = addSaturating(inflightCap, b.ExtraAcked)
	b.MaxInflight = b.quantizationBudget(inflightCap)
}

// saveCwnd is SaveCwnd() (section 5.6.4.4).
func (b *bbrState) saveCwnd() {
	if !b.InLossRecovery && b.State != BBRProbeRTT {
		b.PriorCwnd = b.Cwnd
	} else {
		b.PriorCwnd = max(b.PriorCwnd, b.Cwnd)
	}
}

// restoreCwnd is RestoreCwnd() (section 5.6.4.4).
func (b *bbrState) restoreCwnd() {
	b.Cwnd = max(b.Cwnd, b.PriorCwnd)
}

// probeRTTCwnd is ProbeRTTCwnd() (section 5.6.4.5).
func (b *bbrState) probeRTTCwnd() uint64 {
	probeRTTCwnd := b.bdpMultiple(bbrProbeRTTCwndGain)
	probeRTTCwnd = min(probeRTTCwnd, b.ProbeRTTCwnd)
	return max(probeRTTCwnd, b.minPipeCwnd())
}

// boundCwndForProbeRTT is BoundCwndForProbeRTT() (section 5.6.4.5).
func (b *bbrState) boundCwndForProbeRTT() {
	if b.State == BBRProbeRTT {
		b.Cwnd = min(b.Cwnd, b.probeRTTCwnd())
	}
}

// setCwnd is SetCwnd() (section 5.6.4.6).
//
// +checklocks:b.s.ep.mu
func (b *bbrState) setCwnd(rs *rateSample) {
	b.updateMaxInflight()
	if b.FullBwReached {
		b.Cwnd = min(addSaturating(b.Cwnd, rs.newlyAcked), b.MaxInflight)
	} else if b.Cwnd < b.MaxInflight || b.s.rate.Delivered < b.initialCwnd() {
		b.Cwnd = addSaturating(b.Cwnd, rs.newlyAcked)
	}
	b.Cwnd = max(b.Cwnd, b.minPipeCwnd())
	b.boundCwndForProbeRTT()
	b.boundCwndForModel()
}

// boundCwndForModel is BoundCwndForModel() (section 5.6.4.7). The summary
// table of section 5.6.1 also lists BBR.inflight_longterm as a cap in Drain;
// the pseudocode, followed here, applies it only in ProbeBW.
func (b *bbrState) boundCwndForModel() {
	limit := uint64(bbrInfinity)
	if b.isInAProbeBWState() && b.State != BBRProbeBWCruise {
		limit = b.InflightLongterm
	} else if b.State == BBRProbeRTT || b.State == BBRProbeBWCruise {
		limit = b.inflightWithHeadroom()
	}
	// Apply BBR.inflight_shortterm (possibly infinite).
	limit = min(limit, b.InflightShortterm)
	limit = max(limit, b.minPipeCwnd())
	b.Cwnd = min(b.Cwnd, limit)
}

// mulDiv returns a * b / c, saturating instead of overflowing. c must not be
// zero.
func mulDiv(a, b, c uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi >= c {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, c)
	return q
}

// addSaturating returns a + b, or math.MaxUint64 if that overflows.
func addSaturating(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return sum
}
