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

package tcp_rate_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

const (
	maxPayload = 100
	mtu        = header.TCPMinimumSize + header.IPv4MinimumSize + e2e.MaxTCPOptionSize + maxPayload
)

// rateTestContext is a connected endpoint on a manual clock whose delivery
// rate state can be read after each ACK it processes.
type rateTestContext struct {
	t      *testing.T
	c      *context.Context
	clock  *faketime.ManualClock
	states chan tcp.TCPSenderState
	data   []byte
	// received is the number of bytes of data read from the link so far.
	received int
}

// newRateTestContext returns a context connected with SACK, timestamps and
// delivery rate sampling. RACK is enabled if rack is true.
func newRateTestContext(t *testing.T, rack bool) *rateTestContext {
	t.Helper()
	return newRateTestContextWithSampling(t, rack, true /* sampling */)
}

// newRateTestContextWithSampling is like newRateTestContext, but enables
// delivery rate sampling only if sampling is true.
func newRateTestContextWithSampling(t *testing.T, rack, sampling bool) *rateTestContext {
	t.Helper()
	tc := &rateTestContext{
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
	e2e.SetStackSACKPermitted(t, tc.c, true)
	if !rack {
		e2e.SetStackTCPRecovery(t, tc.c, 0)
	}
	if sampling {
		setStackSampling(t, tc.c, true)
	}
	e2e.CreateConnectedWithSACKAndTS(tc.c)
	return tc
}

// setStackSampling sets the tcpip.TCPDeliveryRateSamplingEnabled option of the
// context stack.
func setStackSampling(t *testing.T, c *context.Context, enable bool) {
	t.Helper()
	opt := tcpip.TCPDeliveryRateSamplingEnabled(enable)
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
	}
}

// write writes segments full-sized segments of data.
func (tc *rateTestContext) write(segments int) {
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

// receive reads segments new full-sized segments from the link.
func (tc *rateTestContext) receive(segments int) {
	tc.t.Helper()
	for i := 0; i < segments; i++ {
		tc.c.ReceiveAndCheckPacketWithOptions(tc.data, tc.received, maxPayload, e2e.TSOptionSize)
		tc.received += maxPayload
	}
}

// receiveRetransmit reads a retransmission of the given full-sized segment
// from the link. Segments are numbered from zero.
func (tc *rateTestContext) receiveRetransmit(segment int) {
	tc.t.Helper()
	tc.c.ReceiveAndCheckPacketWithOptions(tc.data, segment*maxPayload, maxPayload, e2e.TSOptionSize)
}

// ack sends an ACK for the first acked bytes of data, with the given SACK
// blocks, and returns the delivery rate state once it has been processed.
func (tc *rateTestContext) ack(acked int, sackBlocks ...header.SACKBlock) tcp.TCPDeliveryRateState {
	tc.t.Helper()
	select {
	case <-tc.states:
	default:
	}
	tc.c.SendAckWithSACK(seqnum.Value(context.TestInitialSequenceNumber).Add(1), acked, sackBlocks)
	select {
	case state := <-tc.states:
		return state.DeliveryRate
	case <-time.After(5 * time.Second):
		tc.t.Fatal("timed out waiting for the ACK to be processed")
		return tcp.TCPDeliveryRateState{}
	}
}

// sackBlock returns the SACK block covering the given range of full-sized
// segments. Segments are numbered from zero and end is exclusive.
func (tc *rateTestContext) sackBlock(start, end int) header.SACKBlock {
	first := tc.c.IRS.Add(1)
	return header.SACKBlock{
		Start: first.Add(seqnum.Size(start * maxPayload)),
		End:   first.Add(seqnum.Size(end * maxPayload)),
	}
}

func rackName(rack bool) string {
	if rack {
		return "RACK"
	}
	return "NoRACK"
}

// TestDeliveryRateBulkTransfer checks the delivery rate over a transfer in
// which the application always has more data queued than the congestion
// window allows, and then runs dry.
func TestDeliveryRateBulkTransfer(t *testing.T) {
	for _, rack := range []bool{true, false} {
		t.Run(rackName(rack), func(t *testing.T) {
			tc := newRateTestContext(t, rack)
			defer tc.c.Cleanup()

			const (
				initialFlight = tcp.InitialCwnd
				total         = 3 * initialFlight
				rtt           = 20 * time.Millisecond
			)
			// Before anything is sent there is no rate, and the connection
			// is limited by the application.
			var info tcpip.TCPInfoOption
			if err := tc.c.EP.GetSockOpt(&info); err != nil {
				t.Fatalf("GetSockOpt(%T) failed: %s", &info, err)
			}
			if info.DeliveryRate != 0 || !info.DeliveryRateAppLimited {
				t.Errorf("before sending: got TCPInfoOption DeliveryRate = %d, DeliveryRateAppLimited = %t, want 0, true", info.DeliveryRate, info.DeliveryRateAppLimited)
			}

			tc.write(total)
			tc.receive(initialFlight)

			// ACK the first flight one segment at a time, 1ms apart. In slow
			// start each ACK lets two more segments out.
			tc.clock.Advance(rtt)
			var state tcp.TCPDeliveryRateState
			for i := 1; i <= initialFlight; i++ {
				if i > 1 {
					tc.clock.Advance(time.Millisecond)
				}
				state = tc.ack(i * maxPayload)
				tc.receive(2)
				if got, want := state.Delivered, uint64(i*maxPayload); got != want {
					t.Fatalf("ACK %d: got Delivered = %d, want %d", i, got, want)
				}
				if got, want := state.InFlight, uint64((initialFlight+i)*maxPayload); got != want {
					t.Fatalf("ACK %d: got InFlight = %d, want %d", i, got, want)
				}
			}
			// The first flight was sent in one burst when the connection had
			// nothing else to send, so its samples are application-limited
			// and span the time it took to ACK: 1000 bytes over 29ms.
			if got, want := state.Rate, uint64(34482); got != want {
				t.Errorf("after the first flight: got Rate = %d, want %d", got, want)
			}
			if !state.RateAppLimited {
				t.Errorf("after the first flight: got RateAppLimited = false, want true")
			}
			if state.AppLimited != 0 {
				t.Errorf("after the first flight: got AppLimited = %d, want 0", state.AppLimited)
			}
			if got, want := state.MinRTT, rtt; got != want {
				t.Errorf("got MinRTT = %s, want %s", got, want)
			}

			// The segments released by the first ACK were sent with data
			// queued behind them and a full window: 1000 bytes were delivered
			// in the 20ms between sending and ACKing them.
			tc.clock.Advance(rtt - (initialFlight-1)*time.Millisecond)
			state = tc.ack((initialFlight + 1) * maxPayload)
			if got, want := state.Rate, uint64(50000); got != want {
				t.Errorf("first segment sent with data queued: got Rate = %d, want %d", got, want)
			}
			if state.RateAppLimited {
				t.Errorf("first segment sent with data queued: got RateAppLimited = true, want false")
			}
			if state.AppLimited != 0 {
				t.Errorf("with a full window: got AppLimited = %d, want 0", state.AppLimited)
			}

			// Everything has been sent and the window is no longer full, so
			// from the next ACK on the application limits the connection.
			state = tc.ack((initialFlight + 2) * maxPayload)
			if got, want := state.AppLimited, uint64(total*maxPayload); got != want {
				t.Errorf("after running dry: got AppLimited = %d, want %d", got, want)
			}
			if got, want := state.Rate, uint64(55000); got != want {
				t.Errorf("after running dry: got Rate = %d, want %d", got, want)
			}

			state = tc.ack(total * maxPayload)
			if got, want := state.Delivered, uint64(total*maxPayload); got != want {
				t.Errorf("got Delivered = %d, want %d", got, want)
			}
			if state.InFlight != 0 || state.Lost != 0 || state.LostPending != 0 {
				t.Errorf("got InFlight = %d, Lost = %d, LostPending = %d, want 0, 0, 0", state.InFlight, state.Lost, state.LostPending)
			}

			if err := tc.c.EP.GetSockOpt(&info); err != nil {
				t.Fatalf("GetSockOpt(%T) failed: %s", &info, err)
			}
			if info.DeliveryRate != state.Rate || info.DeliveryRateAppLimited != state.RateAppLimited {
				t.Errorf("got TCPInfoOption DeliveryRate = %d, DeliveryRateAppLimited = %t, want %d, %t", info.DeliveryRate, info.DeliveryRateAppLimited, state.Rate, state.RateAppLimited)
			}
		})
	}
}

// TestDeliveryRateSACK checks that data which is selectively and then
// cumulatively acknowledged is counted as delivered once, and that the loss
// of a segment is counted, with and without RACK.
func TestDeliveryRateSACK(t *testing.T) {
	for _, rack := range []bool{true, false} {
		t.Run(rackName(rack), func(t *testing.T) {
			tc := newRateTestContext(t, rack)
			defer tc.c.Cleanup()

			// Measure the RTT with a first segment: 100 bytes in 20ms.
			const rtt = 20 * time.Millisecond
			tc.write(1)
			tc.receive(1)
			tc.clock.Advance(rtt)
			state := tc.ack(maxPayload)
			if state.Delivered != 100 || state.MinRTT != rtt || state.Rate != 5000 {
				t.Fatalf("after the first segment: got Delivered = %d, MinRTT = %s, Rate = %d, want 100, %s, 5000", state.Delivered, state.MinRTT, state.Rate, rtt)
			}

			// Send four more, of which the first goes missing. Each of the
			// other three is SACKed by its own duplicate ACK.
			tc.write(4)
			tc.receive(4)
			tc.clock.Advance(rtt)
			for sacked := 1; sacked <= 3; sacked++ {
				state = tc.ack(maxPayload, tc.sackBlock(2, 2+sacked))
				if !rack {
					// Without RACK, SACKed data is counted when the
					// cumulative ACK reaches it.
					if state.Delivered != 100 || state.InFlight != 400 || state.Rate != 5000 {
						t.Errorf("SACK %d: got Delivered = %d, InFlight = %d, Rate = %d, want 100, 400, 5000", sacked, state.Delivered, state.InFlight, state.Rate)
					}
					continue
				}
				// RACK walks the SACKed segments, so each is counted as it
				// is SACKed, 20ms after the flight was sent.
				if got, want := state.Delivered, uint64((1+sacked)*maxPayload); got != want {
					t.Errorf("SACK %d: got Delivered = %d, want %d", sacked, got, want)
				}
				if got, want := state.Rate, uint64(5000*sacked); got != want {
					t.Errorf("SACK %d: got Rate = %d, want %d", sacked, got, want)
				}
			}

			// The third duplicate ACK starts recovery. With RACK the missing
			// segment is marked lost and then retransmitted, so it is the
			// only data in flight. Without RACK the retransmission itself
			// reports the loss and the SACKed data still counts as in flight.
			tc.receiveRetransmit(1)
			wantInFlight := uint64(4 * maxPayload)
			if rack {
				wantInFlight = maxPayload
			}
			if state.Lost != 100 || state.LostPending != 0 || state.InFlight != wantInFlight {
				t.Errorf("after the retransmission: got Lost = %d, LostPending = %d, InFlight = %d, want 100, 0, %d", state.Lost, state.LostPending, state.InFlight, wantInFlight)
			}

			// The original transmission arrives after all, 2ms later.
			tc.clock.Advance(2 * time.Millisecond)
			state = tc.ack(5 * maxPayload)
			if got, want := state.Delivered, uint64(5*maxPayload); got != want {
				t.Errorf("got Delivered = %d, want %d", got, want)
			}
			if state.InFlight != 0 || state.LostPending != 0 || state.Lost != 100 {
				t.Errorf("got InFlight = %d, LostPending = %d, Lost = %d, want 0, 0, 100", state.InFlight, state.LostPending, state.Lost)
			}
			// With RACK only the retransmission was in flight, so the
			// sampling interval restarted when it was sent. The 2ms it took
			// to be acknowledged is less than the minimum RTT, so the sample
			// is implausible and the rate is unchanged. Without RACK the
			// sample covers the whole flight: 400 bytes in 22ms.
			wantRate := uint64(18181)
			if rack {
				wantRate = 15000
			}
			if got := state.Rate; got != wantRate {
				t.Errorf("got Rate = %d, want %d", got, wantRate)
			}
		})
	}
}

// TestDeliveryRatePartialACK checks an ACK that covers part of a segment.
func TestDeliveryRatePartialACK(t *testing.T) {
	tc := newRateTestContext(t, true /* rack */)
	defer tc.c.Cleanup()

	tc.write(2)
	tc.receive(2)
	tc.clock.Advance(20 * time.Millisecond)

	state := tc.ack(maxPayload + maxPayload/2)
	if got, want := state.Delivered, uint64(maxPayload+maxPayload/2); got != want {
		t.Errorf("got Delivered = %d, want %d", got, want)
	}
	if got, want := state.InFlight, uint64(maxPayload/2); got != want {
		t.Errorf("got InFlight = %d, want %d", got, want)
	}
	// The sample comes from the segment that was delivered in full, and
	// covers every byte delivered since it was sent: 150 bytes in 20ms.
	if got, want := state.Rate, uint64(7500); got != want {
		t.Errorf("got Rate = %d, want %d", got, want)
	}

	state = tc.ack(2 * maxPayload)
	if got, want := state.Delivered, uint64(2*maxPayload); got != want {
		t.Errorf("got Delivered = %d, want %d", got, want)
	}
	if state.InFlight != 0 {
		t.Errorf("got InFlight = %d, want 0", state.InFlight)
	}
}

// TestDeliveryRateRTO checks the state across a retransmission timeout.
func TestDeliveryRateRTO(t *testing.T) {
	// Without RACK there is no tail loss probe ahead of the timeout.
	tc := newRateTestContext(t, false /* rack */)
	defer tc.c.Cleanup()

	const segments = 5
	tc.write(segments)
	tc.receive(segments)

	// Nothing is ACKed. The initial RTO is one second, after which the whole
	// flight is presumed lost and its first segment is retransmitted.
	tc.clock.Advance(time.Second)
	tc.receiveRetransmit(0)

	tc.clock.Advance(20 * time.Millisecond)
	state := tc.ack(maxPayload)
	// The ACK lets the next two segments out.
	tc.receiveRetransmit(1)
	tc.receiveRetransmit(2)
	if got, want := state.Lost, uint64(segments*maxPayload); got != want {
		t.Errorf("got Lost = %d, want %d", got, want)
	}
	if got, want := state.Delivered, uint64(maxPayload); got != want {
		t.Errorf("got Delivered = %d, want %d", got, want)
	}
	if got, want := state.InFlight, uint64(2*maxPayload); got != want {
		t.Errorf("got InFlight = %d, want %d", got, want)
	}
	if got, want := state.LostPending, uint64(2*maxPayload); got != want {
		t.Errorf("got LostPending = %d, want %d", got, want)
	}
	// The sampling interval restarted at the retransmission, since nothing
	// was in flight any more: 100 bytes in 20ms.
	if got, want := state.Rate, uint64(5000); got != want {
		t.Errorf("got Rate = %d, want %d", got, want)
	}

	// The original transmissions of the rest arrive after all.
	state = tc.ack(segments * maxPayload)
	if got, want := state.Delivered, uint64(segments*maxPayload); got != want {
		t.Errorf("got Delivered = %d, want %d", got, want)
	}
	if state.InFlight != 0 || state.LostPending != 0 {
		t.Errorf("got InFlight = %d, LostPending = %d, want 0, 0", state.InFlight, state.LostPending)
	}
}

// TestDeliveryRateSegmentSplit checks that the amounts in flight and
// delivered still add up after transmitted segments are split, here because
// the path MTU dropped.
func TestDeliveryRateSegmentSplit(t *testing.T) {
	states := make(chan tcp.TCPSenderState, 1)
	c := context.NewWithOpts(t, context.Options{
		EnableV4: true,
		MTU:      1500,
		Clock:    faketime.NewManualClock(),
		Probe: func(state *tcp.TCPEndpointState) {
			select {
			case <-states:
			default:
			}
			states <- state.Sender
		},
	})
	defer c.Cleanup()
	setStackSampling(t, c, true)

	const (
		maxPayload    = 1500 - header.TCPMinimumSize - header.IPv4MinimumSize
		writeSize     = 3200
		newMTU        = 1200
		newMaxPayload = newMTU - header.IPv4MinimumSize - header.TCPMinimumSize
	)
	c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	})

	data := make([]byte, writeSize)
	for i := range data {
		data[i] = byte(i)
	}
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	receive := func(sizes []int) *buffer.View {
		t.Helper()
		var first *buffer.View
		seq := uint32(c.IRS) + 1
		for i, size := range sizes {
			p := c.GetPacket()
			if i == 0 {
				first = p
			} else {
				defer p.Release()
			}
			checker.IPv4(t, p,
				checker.PayloadLen(size+header.TCPMinimumSize),
				checker.TCP(checker.TCPSeqNum(seq)),
			)
			seq += uint32(size)
		}
		return first
	}
	first := receive([]int{maxPayload, maxPayload, writeSize - 2*maxPayload})
	defer first.Release()

	// A "packet too big" message makes the stack split the two full-sized
	// segments and send all of the pieces again.
	mtuView := buffer.NewViewWithData([]byte{0, 0, newMTU / 256, newMTU % 256})
	defer mtuView.Release()
	c.SendICMPPacket(header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, mtuView, first, newMTU)
	sizes := []int{newMaxPayload, maxPayload - newMaxPayload, newMaxPayload, maxPayload - newMaxPayload, writeSize - 2*maxPayload}
	receive(sizes).Release()

	ack := func(acked int) tcp.TCPDeliveryRateState {
		t.Helper()
		select {
		case <-states:
		default:
		}
		c.SendAck(seqnum.Value(context.TestInitialSequenceNumber).Add(1), acked)
		select {
		case state := <-states:
			return state.DeliveryRate
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the ACK to be processed")
			return tcp.TCPDeliveryRateState{}
		}
	}

	// ACK the pieces one at a time. The retransmissions were not caused by
	// loss, so nothing is counted as lost.
	acked := 0
	for i, size := range sizes {
		acked += size
		state := ack(acked)
		if got, want := state.Delivered, uint64(acked); got != want {
			t.Errorf("piece %d: got Delivered = %d, want %d", i, got, want)
		}
		if got, want := state.InFlight, uint64(writeSize-acked); got != want {
			t.Errorf("piece %d: got InFlight = %d, want %d", i, got, want)
		}
		if state.Lost != 0 || state.LostPending != 0 {
			t.Errorf("piece %d: got Lost = %d, LostPending = %d, want 0, 0", i, state.Lost, state.LostPending)
		}
	}
}

// TestDeliveryRateSamplingOption checks that delivery rate sampling is off by
// default and can be switched on.
func TestDeliveryRateSamplingOption(t *testing.T) {
	c := context.New(t, mtu)
	defer c.Cleanup()

	var got tcpip.TCPDeliveryRateSamplingEnabled
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &got); err != nil {
		t.Fatalf("TransportProtocolOption(%d, &%T): %s", tcp.ProtocolNumber, got, err)
	}
	if got {
		t.Errorf("got %T = true by default, want false", got)
	}

	setStackSampling(t, c, true)
	if err := c.Stack().TransportProtocolOption(tcp.ProtocolNumber, &got); err != nil {
		t.Fatalf("TransportProtocolOption(%d, &%T): %s", tcp.ProtocolNumber, got, err)
	}
	if !got {
		t.Errorf("got %T = false after enabling it, want true", got)
	}
}

// TestDeliveryRateSamplingDisabled checks that a connection established
// without delivery rate sampling reports no delivery rate.
func TestDeliveryRateSamplingDisabled(t *testing.T) {
	tc := newRateTestContextWithSampling(t, true /* rack */, false /* sampling */)
	defer tc.c.Cleanup()

	tc.write(2)
	tc.receive(2)
	tc.clock.Advance(20 * time.Millisecond)
	if got := tc.ack(2 * maxPayload); got != (tcp.TCPDeliveryRateState{}) {
		t.Errorf("got delivery rate state %+v, want the zero value", got)
	}

	var info tcpip.TCPInfoOption
	if err := tc.c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt(%T) failed: %s", &info, err)
	}
	if info.DeliveryRate != 0 || info.DeliveryRateAppLimited {
		t.Errorf("got TCPInfoOption DeliveryRate = %d, DeliveryRateAppLimited = %t, want 0, false", info.DeliveryRate, info.DeliveryRateAppLimited)
	}
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
