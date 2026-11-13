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

package tcp_pacing_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

const (
	maxPayload = 100
	mtu        = header.TCPMinimumSize + header.IPv4MinimumSize + maxPayload

	// rate paces the smallest send quantum, two full-sized segments, every
	// gap.
	rate = 100000
	gap  = 2 * maxPayload * time.Second / rate
)

// pacingTestContext is a connected endpoint on a manual clock.
type pacingTestContext struct {
	t      *testing.T
	c      *context.Context
	clock  *faketime.ManualClock
	states chan tcp.TCPSenderState
	data   []byte
	// received is the number of bytes of data read from the link so far.
	received int
	// optLen is the length of the TCP options in data segments.
	optLen int
}

// newPacingTestContext returns a context connected without SACK or
// timestamps.
func newPacingTestContext(t *testing.T) *pacingTestContext {
	t.Helper()
	tc := newUnconnectedPacingTestContext(t, mtu)
	tc.c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)
	return tc
}

// newSACKPacingTestContext returns a context connected with SACK and
// timestamps. RACK is enabled if rack is true.
func newSACKPacingTestContext(t *testing.T, rack bool) *pacingTestContext {
	t.Helper()
	tc := newUnconnectedPacingTestContext(t, mtu+e2e.MaxTCPOptionSize)
	tc.optLen = e2e.TSOptionSize
	e2e.SetStackSACKPermitted(t, tc.c, true)
	if !rack {
		e2e.SetStackTCPRecovery(t, tc.c, 0)
	}
	e2e.CreateConnectedWithSACKAndTS(tc.c)
	return tc
}

func newUnconnectedPacingTestContext(t *testing.T, mtu uint32) *pacingTestContext {
	t.Helper()
	tc := &pacingTestContext{
		t:      t,
		clock:  faketime.NewManualClock(),
		states: make(chan tcp.TCPSenderState, 1),
	}
	tc.c = context.NewWithOpts(t, context.Options{
		EnableV4: true,
		MTU:      mtu,
		Clock:    tc.clock,
		Probe: func(state *tcp.TCPEndpointState) {
			// Keep only the most recent state.
			select {
			case <-tc.states:
			default:
			}
			tc.states <- state.Sender
		},
	})
	return tc
}

// write writes segments full-sized segments of data.
func (tc *pacingTestContext) write(segments int) {
	tc.t.Helper()
	start := len(tc.data)
	for i := 0; i < segments*maxPayload; i++ {
		tc.data = append(tc.data, byte(start+i))
	}
	var r bytes.Reader
	r.Reset(tc.data[start:])
	if _, err := tc.c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		tc.t.Fatalf("Write failed: %s", err)
	}
}

// receive reads segments new full-sized segments from the link and checks
// that nothing else has been sent.
func (tc *pacingTestContext) receive(segments int, when string) {
	tc.t.Helper()
	for i := 0; i < segments; i++ {
		tc.c.ReceiveAndCheckPacketWithOptions(tc.data, tc.received, maxPayload, tc.optLen)
		tc.received += maxPayload
	}
	tc.checkNothingSent(when)
}

// receivePacket reads one new packet that carries segments full-sized
// segments of data from the link.
func (tc *pacingTestContext) receivePacket(segments int) {
	tc.t.Helper()
	tc.c.ReceiveAndCheckPacketWithOptions(tc.data, tc.received, segments*maxPayload, tc.optLen)
	tc.received += segments * maxPayload
}

// receiveRetransmit reads a retransmission of the given full-sized segment
// from the link and checks that nothing else has been sent. Segments are
// numbered from zero.
func (tc *pacingTestContext) receiveRetransmit(segment int, when string) {
	tc.t.Helper()
	tc.c.ReceiveAndCheckPacketWithOptions(tc.data, segment*maxPayload, maxPayload, tc.optLen)
	tc.checkNothingSent(when)
}

// sackBlock returns the SACK block covering the given range of full-sized
// segments. Segments are numbered from zero and end is exclusive.
func (tc *pacingTestContext) sackBlock(start, end int) header.SACKBlock {
	first := tc.c.IRS.Add(1)
	return header.SACKBlock{
		Start: first.Add(seqnum.Size(start * maxPayload)),
		End:   first.Add(seqnum.Size(end * maxPayload)),
	}
}

// checkNothingSent checks that no packet is waiting on the link.
func (tc *pacingTestContext) checkNothingSent(when string) {
	tc.t.Helper()
	if p := tc.c.GetPacketNonBlocking(); p != nil {
		p.Release()
		tc.t.Fatalf("%s: got an unexpected packet", when)
	}
}

// ack sends an ACK for the first acked bytes of data, with the given SACK
// blocks, and returns the sender state once it has been processed.
func (tc *pacingTestContext) ack(acked int, sackBlocks ...header.SACKBlock) tcp.TCPSenderState {
	tc.t.Helper()
	select {
	case <-tc.states:
	default:
	}
	tc.c.SendAckWithSACK(seqnum.Value(context.TestInitialSequenceNumber).Add(1), acked, sackBlocks)
	select {
	case state := <-tc.states:
		return state
	case <-time.After(5 * time.Second):
		tc.t.Fatal("timed out waiting for the ACK to be processed")
		return tcp.TCPSenderState{}
	}
}

func (tc *pacingTestContext) tcpInfo() tcpip.TCPInfoOption {
	tc.t.Helper()
	var info tcpip.TCPInfoOption
	if err := tc.c.EP.GetSockOpt(&info); err != nil {
		tc.t.Fatalf("GetSockOpt(%T) failed: %s", &info, err)
	}
	return info
}

// TestPacingOffByDefault checks that SO_MAX_PACING_RATE has no limit unless
// it is set, and that the endpoint then does not pace.
func TestPacingOffByDefault(t *testing.T) {
	tc := newPacingTestContext(t)
	defer tc.c.Cleanup()

	if got := tc.c.EP.SocketOptions().GetMaxPacingRate(); got != tcpip.UnlimitedPacingRate {
		t.Errorf("got SO_MAX_PACING_RATE %d, want %d", got, uint64(tcpip.UnlimitedPacingRate))
	}
	if info := tc.tcpInfo(); info.PacingRate != 0 || info.MaxPacingRate != tcpip.UnlimitedPacingRate {
		t.Errorf("got TCPInfoOption PacingRate = %d, MaxPacingRate = %d, want 0, %d", info.PacingRate, info.MaxPacingRate, uint64(tcpip.UnlimitedPacingRate))
	}

	// The initial congestion window goes out at once.
	tc.write(tcp.InitialCwnd)
	tc.receive(tcp.InitialCwnd, "unpaced")
}

// TestPacingSpacesQuanta checks that with SO_MAX_PACING_RATE set, data leaves
// one send quantum at a time, each quantum after the time the previous one
// takes to send at the pacing rate.
func TestPacingSpacesQuanta(t *testing.T) {
	tc := newPacingTestContext(t)
	defer tc.c.Cleanup()

	tc.c.EP.SocketOptions().SetMaxPacingRate(rate)
	if info := tc.tcpInfo(); info.PacingRate != rate || info.MaxPacingRate != rate {
		t.Errorf("got TCPInfoOption PacingRate = %d, MaxPacingRate = %d, want %d, %d", info.PacingRate, info.MaxPacingRate, rate, rate)
	}

	// The congestion window would let all of it out at once.
	const quanta = tcp.InitialCwnd / 2
	tc.write(2 * quanta)
	tc.receive(2, "first quantum")
	for i := 1; i < quanta; i++ {
		tc.clock.Advance(gap - time.Microsecond)
		tc.checkNothingSent("just before the next quantum is due")
		tc.clock.Advance(time.Microsecond)
		tc.receive(2, "when the next quantum is due")
	}
}

// TestPacingQuantumRemainder checks that with segmentation offload a segment
// is not cut down to what is left of a send quantum: it carries up to a whole
// quantum, and the excess delays the next quantum.
func TestPacingQuantumRemainder(t *testing.T) {
	tc := newUnconnectedPacingTestContext(t, mtu)
	defer tc.c.Cleanup()
	tc.c.SetGSOEnabled(true)
	defer tc.c.SetGSOEnabled(false)
	tc.c.CreateConnected(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

	// A quantum of four full-sized segments is due every millisecond.
	const quantum = 4
	tc.c.EP.SocketOptions().SetMaxPacingRate(quantum * maxPayload * uint64(time.Second/time.Millisecond))

	// The first write leaves one segment of the first quantum unused.
	tc.write(quantum - 1)
	tc.receivePacket(quantum - 1)
	tc.checkNothingSent("after the first write")

	// The next write goes out as a whole quantum in one piece, not as the
	// one segment that was left.
	tc.write(tcp.InitialCwnd - quantum + 1)
	tc.receivePacket(quantum)

	// The seven segments sent so far take 1.75ms at the pacing rate. The
	// rest of what the congestion window allows follows then.
	const sent = 2*quantum - 1
	wait := sent * time.Millisecond / quantum
	tc.clock.Advance(wait - time.Microsecond)
	tc.checkNothingSent("before the data sent has had its time")
	tc.clock.Advance(time.Microsecond)
	tc.receivePacket(tcp.InitialCwnd - sent)
	tc.checkNothingSent("after the congestion window is full")
}

// TestPacingRateFollowsCwnd checks that the pacing rate is what the congestion
// window allows, doubled in slow start, when that is below SO_MAX_PACING_RATE,
// as in Linux.
func TestPacingRateFollowsCwnd(t *testing.T) {
	tc := newPacingTestContext(t)
	defer tc.c.Cleanup()

	const (
		maxRate = 1000000000
		rtt     = 20 * time.Millisecond
	)
	tc.c.EP.SocketOptions().SetMaxPacingRate(maxRate)
	tc.write(1)
	tc.receive(1, "first segment")
	tc.clock.Advance(rtt)
	state := tc.ack(maxPayload)

	// In slow start: 2 * cwnd * mss / srtt.
	if got, want := state.Pacing.Rate, uint64(2*state.SndCwnd*maxPayload)*uint64(time.Second/rtt); got != want {
		t.Errorf("with cwnd %d and srtt %s: got pacing rate %d, want %d", state.SndCwnd, rtt, got, want)
	}
	if got, want := state.Pacing.Quantum, 2*maxPayload; got != want {
		t.Errorf("got send quantum %d, want %d", got, want)
	}
}

// TestPacingUnset checks that data held back by pacing goes out as soon as
// SO_MAX_PACING_RATE is set back to no limit.
func TestPacingUnset(t *testing.T) {
	tc := newPacingTestContext(t)
	defer tc.c.Cleanup()

	tc.c.EP.SocketOptions().SetMaxPacingRate(rate)
	tc.write(tcp.InitialCwnd)
	tc.receive(2, "first quantum")

	tc.c.EP.SocketOptions().SetMaxPacingRate(tcpip.UnlimitedPacingRate)
	tc.receive(tcp.InitialCwnd-2, "after pacing is turned off")
	if info := tc.tcpInfo(); info.PacingRate != 0 {
		t.Errorf("got TCPInfoOption PacingRate = %d, want 0", info.PacingRate)
	}
}

// TestPacingRetransmitTimeout checks that a retransmission after a timeout is
// sent at once even if the next quantum is not yet due.
func TestPacingRetransmitTimeout(t *testing.T) {
	tc := newPacingTestContext(t)
	defer tc.c.Cleanup()

	// A quantum of two segments takes 2s at this rate, longer than the
	// initial retransmission timeout of 1s.
	const slowRate = maxPayload
	tc.c.EP.SocketOptions().SetMaxPacingRate(slowRate)
	tc.write(4)
	tc.receive(2, "first quantum")

	tc.clock.Advance(tcp.InitialRTO)
	tc.c.ReceiveAndCheckPacket(tc.data, 0, maxPayload)
	tc.checkNothingSent("after the retransmission")
}

// TestPacingLossRecovery checks that retransmissions in SACK recovery are
// paced, apart from the fast retransmission that starts recovery, both when
// RACK declares segments lost and in RFC 6675 recovery.
func TestPacingLossRecovery(t *testing.T) {
	for _, rack := range []bool{true, false} {
		name := "RFC6675"
		if rack {
			name = "RACK"
		}
		t.Run(name, func(t *testing.T) {
			testPacingLossRecovery(t, rack)
		})
	}
}

func testPacingLossRecovery(t *testing.T, rack bool) {
	tc := newSACKPacingTestContext(t, rack)
	defer tc.c.Cleanup()

	const (
		rtt = 20 * time.Millisecond
		// slowRate paces one full-sized segment every segmentGap, slower
		// than the congestion window allows.
		slowRate   = 20000
		segmentGap = maxPayload * time.Second / slowRate
	)

	// Measure the RTT with a first segment.
	tc.write(1)
	tc.receive(1, "first segment")
	tc.clock.Advance(rtt)
	tc.ack(maxPayload)

	// Send eight more, of which the first four go missing.
	tc.write(8)
	tc.receive(8, "eight segments")
	tc.clock.Advance(rtt)
	tc.c.EP.SocketOptions().SetMaxPacingRate(slowRate)

	// Three duplicate ACKs SACK three of the others and start recovery.
	for sacked := 1; sacked <= 3; sacked++ {
		state := tc.ack(maxPayload, tc.sackBlock(5, 5+sacked))
		if got := state.Pacing.Rate; got != slowRate {
			t.Fatalf("SACK %d: got pacing rate %d, want %d", sacked, got, slowRate)
		}
	}
	tc.receiveRetransmit(1, "after the fast retransmission")

	// The other three lost segments follow at the pacing rate, a quantum of
	// two at a time.
	tc.clock.Advance(segmentGap - time.Microsecond)
	tc.checkNothingSent("just before the first quantum is due")
	tc.clock.Advance(time.Microsecond)
	tc.c.ReceiveAndCheckPacketWithOptions(tc.data, 2*maxPayload, maxPayload, tc.optLen)
	tc.receiveRetransmit(3, "after the first quantum")

	tc.clock.Advance(2*segmentGap - time.Microsecond)
	tc.checkNothingSent("just before the second quantum is due")
	tc.clock.Advance(time.Microsecond)
	tc.receiveRetransmit(4, "after the second quantum")
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	// Allow TCP async work to complete to avoid false reports of leaks.
	// TODO(gvisor.dev/issue/5940): Use fake clock in tests.
	time.Sleep(1 * time.Second)
	refs.DoLeakCheck()
	os.Exit(code)
}
