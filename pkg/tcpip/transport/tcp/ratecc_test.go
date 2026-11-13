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
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fakeLoss is a call of fakeRateCC.OnLoss.
type fakeLoss struct {
	size       int
	txInFlight uint64
	priorLost  uint64
	// lost is the sampler's C.lost at the time of the call.
	lost uint64
}

// fakeRateCC is a rate-based congestion control algorithm that records the
// calls it receives. It never changes the congestion window, so any change
// to it during a test is the sender's.
type fakeRateCC struct {
	s *sender

	// pacingRate is returned by PacingRate.
	pacingRate uint64
	// transmitRate, if not zero, replaces pacingRate on each OnTransmit.
	transmitRate uint64

	// events lists the calls in order, by method name.
	events []string
	// acks holds a copy of the sample passed to each OnACK.
	acks []rateSample
	// losses holds the arguments of each OnLoss.
	losses []fakeLoss
	// enters holds the argument of each OnEnterRecovery.
	enters []bool
	// enterInFlight holds the sampler's C.inflight at each OnEnterRecovery.
	enterInFlight []uint64
	// transmitInFlight holds the sampler's C.inflight at each OnTransmit.
	transmitInFlight []uint64
}

var _ rateCongestionControl = (*fakeRateCC)(nil)

func (f *fakeRateCC) HandleLossDetected() { f.events = append(f.events, "HandleLossDetected") }
func (f *fakeRateCC) HandleRTOExpired()   { f.events = append(f.events, "HandleRTOExpired") }
func (f *fakeRateCC) HandleWindowRestart() {
	f.events = append(f.events, "HandleWindowRestart")
}
func (f *fakeRateCC) Update(int, time.Duration, tcpip.MonotonicTime) {
	f.events = append(f.events, "Update")
}
func (f *fakeRateCC) PostRecovery() { f.events = append(f.events, "PostRecovery") }

// +checklocksignore
func (f *fakeRateCC) OnTransmit(tcpip.MonotonicTime, int) {
	f.events = append(f.events, "OnTransmit")
	f.transmitInFlight = append(f.transmitInFlight, f.s.rate.InFlight)
	if f.transmitRate != 0 {
		f.pacingRate = f.transmitRate
	}
}

func (f *fakeRateCC) OnACK(rs *rateSample, _ tcpip.MonotonicTime) {
	f.events = append(f.events, "OnACK")
	f.acks = append(f.acks, *rs)
}

// +checklocksignore
func (f *fakeRateCC) OnLoss(p *segRate, size int) {
	f.events = append(f.events, "OnLoss")
	f.losses = append(f.losses, fakeLoss{size: size, txInFlight: p.txInFlight, priorLost: p.lost, lost: f.s.rate.Lost})
}

// +checklocksignore
func (f *fakeRateCC) OnEnterRecovery(rto bool) {
	f.events = append(f.events, "OnEnterRecovery")
	f.enters = append(f.enters, rto)
	f.enterInFlight = append(f.enterInFlight, f.s.rate.InFlight)
}

func (f *fakeRateCC) OnExitRecovery()     { f.events = append(f.events, "OnExitRecovery") }
func (f *fakeRateCC) OnSpuriousRecovery() { f.events = append(f.events, "OnSpuriousRecovery") }
func (f *fakeRateCC) PacingRate() uint64  { return f.pacingRate }

// count returns how many times the method called name was called.
func (f *fakeRateCC) count(name string) int {
	n := 0
	for _, e := range f.events {
		if e == name {
			n++
		}
	}
	return n
}

var (
	rccLocalAddr  = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	rccRemoteAddr = tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
)

const (
	rccRemotePort uint16 = 9000
	rccMTU               = 1500
	rccPeerWindow        = 65535
	rccPeerISS           = seqnum.Value(5000)
)

// rccTest is a connected endpoint on a manual clock. The test plays the peer:
// it reads the endpoint's packets from the link and sends ACKs back.
type rccTest struct {
	t         *testing.T
	clock     *faketime.ManualClock
	stack     *stack.Stack
	link      *channel.Endpoint
	ep        *Endpoint
	wq        waiter.Queue
	processed chan struct{}

	// iss is the endpoint's initial sequence number.
	iss seqnum.Value
	// localPort is the endpoint's port.
	localPort uint16
	// mss is the payload size of a full segment.
	mss int
	// written is the number of bytes written to the endpoint.
	written int

	// ts is true if the timestamp option is in use. Then tsVal is the last
	// timestamp the peer sent and tsRecent the last one it received.
	ts       bool
	tsVal    uint32
	tsRecent uint32

	fake *fakeRateCC
}

// newRCCTest returns an endpoint connected to the test, with SACK if sack is
// true, RACK if rack is true and the timestamp option if ts is true.
func newRCCTest(t *testing.T, sack, rack, ts bool) *rccTest {
	t.Helper()
	tc := &rccTest{
		t:         t,
		clock:     faketime.NewManualClock(),
		link:      channel.New(1000, rccMTU, ""),
		processed: make(chan struct{}, 1000),
		ts:        ts,
		tsVal:     1,
	}
	tc.stack = stack.New(stack.Options{
		Clock:            tc.clock,
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocolProbe(func(*TCPEndpointState) {
			tc.processed <- struct{}{}
		})},
	})
	t.Cleanup(func() {
		if tc.ep != nil {
			tc.ep.Abort()
		}
		tc.stack.Close()
		tc.stack.Wait()
		tc.stack.Destroy()
		tc.link.Close()
	})

	sackOpt := tcpip.TCPSACKEnabled(sack)
	if err := tc.stack.SetTransportProtocolOption(ProtocolNumber, &sackOpt); err != nil {
		t.Fatalf("SetTransportProtocolOption(%T): %s", sackOpt, err)
	}
	recovery := tcpip.TCPRecovery(0)
	if rack {
		recovery = tcpip.TCPRACKLossDetection
	}
	if err := tc.stack.SetTransportProtocolOption(ProtocolNumber, &recovery); err != nil {
		t.Fatalf("SetTransportProtocolOption(%T): %s", recovery, err)
	}
	if err := tc.stack.CreateNIC(1, tc.link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	if err := tc.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: rccLocalAddr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	tc.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ep, err := tc.stack.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &tc.wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	tc.ep = ep.(*Endpoint)
	if err := tc.ep.Connect(tcpip.FullAddress{Addr: rccRemoteAddr, Port: rccRemotePort}); err == nil {
		t.Fatalf("Connect succeeded at once, want ErrConnectStarted")
	} else if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		t.Fatalf("Connect: %s", err)
	}

	// SYN.
	syn := tc.readPacket()
	tc.iss = seqnum.Value(syn.SequenceNumber())
	tc.localPort = syn.SourcePort()
	synOpts := header.ParseSynOptions(syn.Options(), false /* isAck */)

	// SYN-ACK.
	opts := make([]byte, header.TCPOptionsMaximumSize)
	off := header.EncodeMSSOption(rccMTU-header.IPv4MinimumSize-header.TCPMinimumSize, opts)
	if sack {
		off += header.EncodeSACKPermittedOption(opts[off:])
	}
	if ts {
		off += header.EncodeTSOption(tc.tsVal, synOpts.TSVal, opts[off:])
	}
	off += header.AddTCPOptionPadding(opts, off)
	tc.send(header.TCPFlagSyn|header.TCPFlagAck, rccPeerISS, tc.iss+1, rccPeerWindow, opts[:off])

	// ACK of the SYN-ACK.
	if ack := tc.readPacket(); ack.Flags() != header.TCPFlagAck {
		t.Fatalf("got flags %s after SYN-ACK, want ACK", ack.Flags())
	}
	tc.waitFor("established", func() bool { return tc.ep.EndpointState() == StateEstablished })
	tc.mss = tc.senderState().MaxPayloadSize
	return tc
}

// locked calls f with the endpoint's sender while holding the endpoint lock.
// f may read only fields that checklocks does not guard: it cannot see that
// the lock is held.
func (tc *rccTest) locked(f func(s *sender)) {
	tc.ep.mu.Lock()
	defer tc.ep.mu.Unlock()
	f(tc.ep.snd)
}

// install makes a fakeRateCC the sender's congestion control algorithm, with
// a congestion window of cwnd packets unless cwnd is zero.
func (tc *rccTest) install(cwnd int, pacingRate uint64) *fakeRateCC {
	tc.t.Helper()
	s := tc.ep.snd
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	tc.fake = &fakeRateCC{s: s, pacingRate: pacingRate}
	if cwnd != 0 {
		s.SndCwnd = cwnd
	}
	s.setCongestionControl(tc.fake)
	s.updatePacingRate()
	return tc.fake
}

// senderState returns a copy of the sender's TCPSenderState.
func (tc *rccTest) senderState() TCPSenderState {
	s := tc.ep.snd
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	return s.TCPSenderState
}

// cwnd returns the sender's congestion window.
func (tc *rccTest) cwnd() int {
	return tc.senderState().SndCwnd
}

// advanceUntil advances the clock in small steps, for at most limit, until
// cond holds with the endpoint locked.
func (tc *rccTest) advanceUntil(what string, limit time.Duration, cond func(s *sender) bool) {
	tc.t.Helper()
	const step = 10 * time.Millisecond
	for elapsed := time.Duration(0); ; elapsed += step {
		done := false
		tc.locked(func(s *sender) { done = cond(s) })
		if done {
			return
		}
		if elapsed >= limit {
			tc.t.Fatalf("%s did not happen within %s", what, limit)
		}
		tc.clock.Advance(step)
	}
}

// waitFor waits, in real time, until cond holds.
func (tc *rccTest) waitFor(what string, cond func() bool) {
	tc.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tc.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// readPacket reads the next packet the endpoint sends, waiting for it in
// real time, and returns its TCP header and payload.
func (tc *rccTest) readPacket() header.TCP {
	tc.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pkt := tc.link.ReadContext(ctx)
	if pkt == nil {
		tc.t.Fatalf("no packet sent")
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	tcpHdr := header.TCP(slices.Clone(header.IPv4(view.AsSlice()).Payload()))
	if tc.ts {
		if opts := header.ParseTCPOptions(tcpHdr.Options()); opts.TS {
			tc.tsRecent = opts.TSVal
		}
	}
	return tcpHdr
}

// recv reads n data segments from the link without waiting and returns their
// offsets in the data written to the endpoint.
func (tc *rccTest) recv(n int) []int {
	tc.t.Helper()
	var offsets []int
	for len(offsets) < n {
		pkt := tc.link.Read()
		if pkt == nil {
			tc.t.Fatalf("got %d data segments, want %d", len(offsets), n)
		}
		view := pkt.ToView()
		tcpHdr := header.TCP(header.IPv4(view.AsSlice()).Payload())
		if len(tcpHdr.Payload()) != 0 {
			offsets = append(offsets, int(seqnum.Value(tcpHdr.SequenceNumber())-tc.iss-1))
		}
		if tc.ts {
			if opts := header.ParseTCPOptions(tcpHdr.Options()); opts.TS {
				tc.tsRecent = opts.TSVal
			}
		}
		view.Release()
		pkt.DecRef()
	}
	return offsets
}

// recvSegs is like recv, but returns segment numbers.
func (tc *rccTest) recvSegs(n int) []int {
	tc.t.Helper()
	offsets := tc.recv(n)
	for i := range offsets {
		offsets[i] /= tc.mss
	}
	return offsets
}

// drain discards the packets queued on the link.
func (tc *rccTest) drain() {
	tc.link.Drain()
}

// write writes segs full segments of data to the endpoint.
func (tc *rccTest) write(segs int) {
	tc.t.Helper()
	tc.writeBytes(segs * tc.mss)
}

// writeBytes writes n bytes of data to the endpoint.
func (tc *rccTest) writeBytes(n int) {
	tc.t.Helper()
	data := bytes.Repeat([]byte{'x'}, n)
	var r bytes.Reader
	r.Reset(data)
	if _, err := tc.ep.Write(&r, tcpip.WriteOptions{}); err != nil {
		tc.t.Fatalf("Write: %s", err)
	}
	tc.written += len(data)
}

// send sends a segment without payload from the peer, and waits until the
// endpoint has processed it if it is established.
func (tc *rccTest) send(flags header.TCPFlags, seq, ack seqnum.Value, window uint16, opts []byte) {
	tc.t.Helper()
	for len(tc.processed) > 0 {
		<-tc.processed
	}
	buf := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(opts))
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(ProtocolNumber),
		SrcAddr:     rccRemoteAddr,
		DstAddr:     rccLocalAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	t := header.TCP(buf[header.IPv4MinimumSize:])
	copy(t[header.TCPMinimumSize:], opts)
	t.Encode(&header.TCPFields{
		SrcPort:    rccRemotePort,
		DstPort:    tc.localPort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(header.TCPMinimumSize + len(opts)),
		Flags:      flags,
		WindowSize: window,
	})
	xsum := header.PseudoHeaderChecksum(ProtocolNumber, rccRemoteAddr, rccLocalAddr, uint16(len(t)))
	t.SetChecksum(^t.CalculateChecksum(xsum))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
	tc.link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()

	if flags&header.TCPFlagSyn == 0 {
		select {
		case <-tc.processed:
		case <-time.After(10 * time.Second):
			tc.t.Fatalf("segment not processed")
		}
	}
}

// ack sends an ACK of the first acked segments, selectively acknowledging
// the segments [start, end) given as pairs in sacks.
func (tc *rccTest) ack(acked int, sacks ...[2]int) {
	tc.t.Helper()
	tc.ackFull(acked, rccPeerWindow, tc.tsRecent, sacks...)
}

// ackFull is like ack, but also sets the window and the timestamp echo.
func (tc *rccTest) ackFull(acked int, window uint16, tsEcr uint32, sacks ...[2]int) {
	tc.t.Helper()
	base := tc.iss + 1
	opts := make([]byte, header.TCPOptionsMaximumSize)
	off := 0
	if tc.ts {
		tc.tsVal++
		off += header.EncodeTSOption(tc.tsVal, tsEcr, opts[off:])
	}
	if len(sacks) > 0 {
		var blocks []header.SACKBlock
		for _, sb := range sacks {
			blocks = append(blocks, header.SACKBlock{
				Start: base.Add(seqnum.Size(sb[0] * tc.mss)),
				End:   base.Add(seqnum.Size(sb[1] * tc.mss)),
			})
		}
		off += header.EncodeNOP(opts[off:])
		off += header.EncodeNOP(opts[off:])
		off += header.EncodeSACKBlocks(blocks, opts[off:])
	}
	off += header.AddTCPOptionPadding(opts, off)
	tc.send(header.TCPFlagAck, rccPeerISS+1, base.Add(seqnum.Size(acked*tc.mss)), window, opts[:off])
}

// rccModes are the loss recovery setups a rate-based algorithm must work in.
var rccModes = []struct {
	name       string
	sack, rack bool
}{
	{"RACK", true, true},
	{"SACK", true, false},
	{"NoSACK", false, false},
}

// lossEpisode sends 10 segments, acknowledges the first, and then sends
// duplicate ACKs until the sender has entered fast recovery and
// retransmitted the second segment. It returns the number of ACKs sent.
func (tc *rccTest) lossEpisode(sack bool) int {
	tc.t.Helper()
	tc.write(10)
	tc.recv(10)
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(1)
	acks := 1
	for i := 0; i < nDupAckThreshold; i++ {
		if sack {
			tc.ack(1, [2]int{2, 3 + i})
		} else {
			tc.ack(1)
		}
		acks++
	}
	if got := tc.recvSegs(1); got[0] != 1 {
		tc.t.Fatalf("retransmitted segment %d, want 1", got[0])
	}
	tc.drain()
	return acks
}

func TestRateCCWindowLeftToAlgorithm(t *testing.T) {
	const cwnd = 20
	for _, mode := range rccModes {
		t.Run(mode.name, func(t *testing.T) {
			tc := newRCCTest(t, mode.sack, mode.rack, false /* ts */)
			fake := tc.install(cwnd, 0 /* pacingRate */)
			check := func(when string) {
				t.Helper()
				if got := tc.cwnd(); got != cwnd {
					t.Fatalf("%s: got cwnd %d, want %d", when, got, cwnd)
				}
			}

			// Entering fast recovery sets cwnd to ssthresh + 3, which is
			// math.MaxInt + 3 here, as the fake never sets ssthresh.
			acks := tc.lossEpisode(mode.sack)
			check("entering recovery")
			tc.locked(func(*sender) {
				if got, want := fake.enters, []bool{false}; !slices.Equal(got, want) {
					t.Errorf("OnEnterRecovery calls %v, want %v", got, want)
				}
			})

			// Without SACK, a duplicate ACK in recovery inflates cwnd.
			if mode.sack {
				tc.ack(1, [2]int{2, 6})
			} else {
				tc.ack(1)
			}
			acks++
			check("duplicate ACK in recovery")

			// Leaving recovery sets cwnd to ssthresh.
			tc.ack(10)
			acks++
			check("leaving recovery")

			// After an idle period cwnd is reset to the initial window.
			tc.clock.Advance(5 * time.Second)
			tc.write(1)
			tc.recv(1)
			check("restart after idle")

			tc.locked(func(*sender) {
				if got := fake.count("OnACK"); got != acks {
					t.Errorf("OnACK called %d times for %d ACKs", got, acks)
				}
				if got := fake.count("OnExitRecovery"); got != 1 {
					t.Errorf("OnExitRecovery called %d times, want 1", got)
				}
				// The other algorithms' events are still reported.
				for _, name := range []string{"HandleLossDetected", "PostRecovery", "Update"} {
					if fake.count(name) == 0 {
						t.Errorf("%s not called", name)
					}
				}
				if fake.count("HandleWindowRestart") != 0 {
					t.Errorf("HandleWindowRestart called after idle")
				}
			})
		})
	}
}

// TestRateCCWindowAppliesToInFlight checks that the window of a rate-based
// algorithm limits what the delivery rate sampler counts as in flight. Data
// that is selectively acknowledged outside loss recovery has left the
// network, so it makes room for new data at once; the sender's own estimate
// of the packets outstanding keeps counting it, and is wrong from then on.
//
// RACK is off: with all the segments sent at the same instant of the test's
// clock, it would declare the unacknowledged ones lost at once and start a
// recovery. The bbr tests cover the window after a recovery with RACK.
func TestRateCCWindowAppliesToInFlight(t *testing.T) {
	const cwnd = 6
	tc := newRCCTest(t, true /* sack */, false /* rack */, false /* ts */)
	tc.install(cwnd, 0 /* pacingRate */)
	mss := uint64(tc.mss)
	check := func(when string, first, n int) {
		t.Helper()
		got := tc.recvSegs(n)
		for i, seg := range got {
			if seg != first+i {
				t.Fatalf("%s: sent segments %v, want %d to %d", when, got, first, first+n-1)
			}
		}
		if pkt := tc.link.Read(); pkt != nil {
			pkt.DecRef()
			t.Fatalf("%s: sent more than %d segments", when, n)
		}
		tc.locked(func(s *sender) {
			if s.rate.InFlight != cwnd*mss {
				t.Errorf("%s: %d bytes in flight, want %d", when, s.rate.InFlight, cwnd*mss)
			}
		})
	}
	tc.write(14)
	check("at first", 0, cwnd)

	// The third and fourth segments arrive; the first two are late, not
	// lost.
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(0, [2]int{2, 4})
	check("after a SACK", 6, 2)

	// The first six arrive: four more leave the network.
	tc.ack(6)
	check("after the cumulative ACK", 8, 4)

	// And so on, with nothing left over from the SACK.
	tc.ack(8)
	check("after the next ACK", 12, 2)
}

// TestRateCCWindowCountsShortSegment checks that a segment shorter than the
// maximum payload takes a whole packet of a rate-based algorithm's window:
// the window is in packets, and what is in flight is counted in bytes.
func TestRateCCWindowCountsShortSegment(t *testing.T) {
	const (
		cwnd  = 3
		short = 100
	)
	tc := newRCCTest(t, true /* sack */, false /* rack */, false /* ts */)
	tc.install(cwnd, 0 /* pacingRate */)

	// Two full segments and a short one fill the window.
	tc.writeBytes(2*tc.mss + short)
	tc.recv(cwnd)
	tc.write(1)
	if pkt := tc.link.Read(); pkt != nil {
		pkt.DecRef()
		t.Fatalf("sent a fourth segment with a window of %d packets", cwnd)
	}
	tc.locked(func(s *sender) {
		if want := uint64(2*tc.mss + short); s.rate.InFlight != want {
			t.Errorf("%d bytes in flight, want %d", s.rate.InFlight, want)
		}
	})

	// The first segment's delivery makes room for the fourth.
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(1)
	if got, want := tc.recv(1), 2*tc.mss+short; got[0] != want {
		t.Errorf("sent data at offset %d after the ACK, want %d", got[0], want)
	}
}

func TestRateCCRecoveryEvents(t *testing.T) {
	for _, mode := range rccModes {
		t.Run(mode.name, func(t *testing.T) {
			tc := newRCCTest(t, mode.sack, mode.rack, false /* ts */)
			fake := tc.install(20, 0 /* pacingRate */)
			tc.lossEpisode(mode.sack)
			tc.ack(10)
			tc.locked(func(s *sender) {
				// Recovery is entered once, before the retransmission, and
				// left once.
				var got []string
				for _, e := range fake.events {
					switch e {
					case "OnEnterRecovery", "OnExitRecovery":
						got = append(got, e)
					}
				}
				if want := []string{"OnEnterRecovery", "OnExitRecovery"}; !slices.Equal(got, want) {
					t.Errorf("recovery events %v, want %v", got, want)
				}
				if s.state != tcpip.Open {
					t.Errorf("sender state %d, want Open (%d)", s.state, tcpip.Open)
				}
			})
		})
	}
}

func TestRateCCLossReported(t *testing.T) {
	for _, mode := range rccModes {
		t.Run(mode.name, func(t *testing.T) {
			tc := newRCCTest(t, mode.sack, mode.rack, false /* ts */)
			fake := tc.install(20, 0 /* pacingRate */)
			tc.lossEpisode(mode.sack)
			tc.locked(func(s *sender) {
				// The second segment is lost once, and reported with the
				// state recorded when it was first sent: two segments in
				// flight and nothing lost before.
				want := []fakeLoss{{size: tc.mss, txInFlight: uint64(2 * tc.mss), priorLost: 0, lost: uint64(tc.mss)}}
				if !slices.Equal(fake.losses, want) {
					t.Errorf("OnLoss calls %+v, want %+v", fake.losses, want)
				}
				if s.rate.Lost != uint64(tc.mss) {
					t.Errorf("sampler lost %d bytes, want %d", s.rate.Lost, tc.mss)
				}
			})
		})
	}
}

// TestRateCCLossBeforeACK checks that an algorithm sees the losses that RACK
// detects on an ACK before it sees the ACK, so that the ACK's rate sample
// counts them.
func TestRateCCLossBeforeACK(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, true /* rack */, false /* ts */)
	fake := tc.install(20, 0 /* pacingRate */)
	tc.write(5)
	tc.recv(5)
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(1)
	tc.locked(func(*sender) { fake.events = nil })

	// Three segments SACKed above the second one make RACK's reordering
	// window zero, so the second is lost at once.
	tc.ack(1, [2]int{2, 5})
	tc.locked(func(*sender) {
		want := []string{"OnLoss", "OnEnterRecovery", "OnACK"}
		var got []string
		for _, e := range fake.events {
			if e != "Update" && e != "HandleLossDetected" && e != "OnTransmit" {
				got = append(got, e)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("events %v, want %v", got, want)
		}
		if n := len(fake.acks); n == 0 {
			t.Fatalf("no OnACK")
		}
		rs := fake.acks[len(fake.acks)-1]
		if rs.lost != uint64(tc.mss) || rs.newlyAcked != uint64(3*tc.mss) {
			t.Errorf("sample lost = %d, newlyAcked = %d, want %d, %d", rs.lost, rs.newlyAcked, tc.mss, 3*tc.mss)
		}
	})
}

func TestRateCCRetransmissionTimeout(t *testing.T) {
	for _, mode := range rccModes {
		t.Run(mode.name, func(t *testing.T) {
			tc := newRCCTest(t, mode.sack, mode.rack, false /* ts */)
			fake := tc.install(20, 0 /* pacingRate */)
			tc.write(4)
			tc.recv(4)

			// The first timeout declares every segment lost before the
			// algorithm hears of it, so nothing is in flight then. With
			// RACK, a tail loss probe goes first; it is not a loss.
			tc.advanceUntil("timeout", 5*time.Second, func(*sender) bool { return len(fake.enters) == 1 })
			tc.drain()
			tc.locked(func(s *sender) {
				if got := len(fake.losses); got != 4 {
					t.Errorf("OnLoss called %d times, want 4", got)
				}
				for i, l := range fake.losses {
					if want := uint64((i + 1) * tc.mss); l.txInFlight != want {
						t.Errorf("loss %d: txInFlight %d, want %d", i, l.txInFlight, want)
					}
				}
				if !slices.Equal(fake.enters, []bool{true}) || !slices.Equal(fake.enterInFlight, []uint64{0}) {
					t.Errorf("OnEnterRecovery calls %v with inflight %v, want [true] with [0]", fake.enters, fake.enterInFlight)
				}
			})
			if got := tc.cwnd(); got != 20 {
				t.Errorf("cwnd %d after timeout, want 20", got)
			}

			// A second timeout is reported too, without leaving recovery.
			tc.advanceUntil("second timeout", 10*time.Second, func(*sender) bool { return len(fake.enters) == 2 })
			tc.drain()
			tc.locked(func(*sender) {
				if !slices.Equal(fake.enters, []bool{true, true}) || fake.count("OnExitRecovery") != 0 {
					t.Errorf("after two timeouts: OnEnterRecovery %v, OnExitRecovery %d times, want [true true], 0",
						fake.enters, fake.count("OnExitRecovery"))
				}
			})

			// Recovery ends once all the data is acknowledged.
			tc.ack(4)
			tc.locked(func(s *sender) {
				if got := fake.count("OnExitRecovery"); got != 1 {
					t.Errorf("OnExitRecovery called %d times, want 1", got)
				}
				if s.rate.InFlight != 0 || s.rate.LostPending != 0 {
					t.Errorf("sampler inflight %d, lostPending %d after the final ACK, want 0, 0", s.rate.InFlight, s.rate.LostPending)
				}
			})
		})
	}
}

// TestRateCCRecoveryExitAfterDuplicateACK checks that the algorithm is told
// that recovery ended when a duplicate ACK arrived before the end. After a
// timeout, a duplicate ACK that does not start fast recovery takes the sender
// out of the RTORecovery state, but the episode goes on until the data that
// was outstanding at the timeout is acknowledged.
func TestRateCCRecoveryExitAfterDuplicateACK(t *testing.T) {
	for _, mode := range rccModes {
		t.Run(mode.name, func(t *testing.T) {
			tc := newRCCTest(t, mode.sack, mode.rack, false /* ts */)
			fake := tc.install(20, 0 /* pacingRate */)
			tc.write(4)
			tc.recv(4)
			tc.advanceUntil("timeout", 5*time.Second, func(*sender) bool { return len(fake.enters) == 1 })
			tc.drain()

			// The original transmission of the third segment arrived.
			if mode.sack {
				tc.ack(0, [2]int{2, 3})
			} else {
				tc.ack(0)
			}
			tc.drain()
			tc.locked(func(*sender) {
				if got := fake.count("OnExitRecovery"); got != 0 {
					t.Errorf("OnExitRecovery called %d times after a duplicate ACK, want 0", got)
				}
			})

			tc.ack(4)
			tc.locked(func(s *sender) {
				if got := fake.count("OnExitRecovery"); got != 1 {
					t.Errorf("OnExitRecovery called %d times, want 1", got)
				}
				if s.state != tcpip.Open {
					t.Errorf("sender state %d, want Open (%d)", s.state, tcpip.Open)
				}
			})

			// Later ACKs do not end it again.
			tc.write(1)
			tc.recv(1)
			tc.ack(5)
			tc.locked(func(*sender) {
				if got := fake.count("OnExitRecovery"); got != 1 {
					t.Errorf("OnExitRecovery called %d times after a later ACK, want 1", got)
				}
			})
		})
	}
}

func TestRateCCSpuriousRecovery(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, true /* rack */, true /* ts */)
	fake := tc.install(20, 0 /* pacingRate */)
	tc.clock.Advance(10 * time.Millisecond)
	tc.write(2)
	tc.recv(2)
	original := tc.tsRecent

	// The timeout retransmits the first segment, but the ACK that arrives
	// next echoes the original transmission.
	tc.advanceUntil("timeout", 5*time.Second, func(s *sender) bool { return s.state == tcpip.RTORecovery })
	tc.drain()
	tc.ackFull(1, rccPeerWindow, original)
	tc.locked(func(*sender) {
		if got := fake.count("OnSpuriousRecovery"); got != 1 {
			t.Errorf("OnSpuriousRecovery called %d times, want 1", got)
		}
	})
}

func TestRateCCSACKWithoutRACK(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, false /* rack */, false /* ts */)
	fake := tc.install(20, 0 /* pacingRate */)
	tc.write(6)
	tc.recv(6)
	tc.clock.Advance(10 * time.Millisecond)

	// Two SACK blocks deliver three segments before the cumulative ACK.
	tc.ack(0, [2]int{4, 5}, [2]int{1, 3})
	mss := uint64(tc.mss)
	tc.locked(func(s *sender) {
		rs := fake.acks[len(fake.acks)-1]
		if rs.newlyAcked != 3*mss || s.rate.Delivered != 3*mss || s.rate.InFlight != 3*mss {
			t.Errorf("after SACK: newlyAcked %d, delivered %d, inflight %d, want %d, %d, %d",
				rs.newlyAcked, s.rate.Delivered, s.rate.InFlight, 3*mss, 3*mss, 3*mss)
		}
		if !rs.hasData || rs.deliveryRate == 0 {
			t.Errorf("after SACK: no rate sample: %+v", rs)
		}
	})

	// The cumulative ACK counts only the rest.
	tc.ack(6)
	tc.locked(func(s *sender) {
		rs := fake.acks[len(fake.acks)-1]
		if rs.newlyAcked != 3*mss || s.rate.Delivered != 6*mss || s.rate.InFlight != 0 {
			t.Errorf("after ACK: newlyAcked %d, delivered %d, inflight %d, want %d, %d, 0",
				rs.newlyAcked, s.rate.Delivered, s.rate.InFlight, 3*mss, 6*mss)
		}
	})
}

func TestRateCCPacing(t *testing.T) {
	const rate = 1_000_000
	tc := newRCCTest(t, true /* sack */, true /* rack */, false /* ts */)
	fake := tc.install(20, rate)
	tc.locked(func(s *sender) {
		if s.pacer.Rate != rate {
			t.Fatalf("pacing rate %d, want %d", s.pacer.Rate, rate)
		}
	})

	// The first quantum, two segments at this rate, goes at once. The
	// algorithm hears of each transmission before it is in flight.
	tc.write(4)
	tc.recv(2)
	if pkt := tc.link.Read(); pkt != nil {
		pkt.DecRef()
		t.Fatalf("third segment sent before its time")
	}
	mss := uint64(tc.mss)
	tc.locked(func(*sender) {
		if want := []uint64{0, mss}; !slices.Equal(fake.transmitInFlight, want) {
			t.Errorf("inflight at OnTransmit %v, want %v", fake.transmitInFlight, want)
		}
	})
	tc.clock.Advance(pacingDelay(2*mss, rate))
	tc.recv(2)

	// SO_MAX_PACING_RATE caps the algorithm's rate.
	tc.ep.SocketOptions().SetMaxPacingRate(rate / 2)
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(4)
	tc.locked(func(s *sender) {
		if s.pacer.Rate != rate/2 {
			t.Errorf("pacing rate %d with SO_MAX_PACING_RATE %d, want %d", s.pacer.Rate, rate/2, rate/2)
		}
	})

	// A rate the algorithm changes on transmission applies at once.
	tc.ep.SocketOptions().SetMaxPacingRate(tcpip.UnlimitedPacingRate)
	tc.locked(func(*sender) { fake.transmitRate = 3 * rate })
	tc.write(1)
	tc.recv(1)
	tc.locked(func(s *sender) {
		if s.pacer.Rate != 3*rate {
			t.Errorf("pacing rate %d after OnTransmit, want %d", s.pacer.Rate, 3*rate)
		}
	})
}

func TestRateCCZeroWindowProbeACK(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, true /* rack */, false /* ts */)
	fake := tc.install(20, 0 /* pacingRate */)
	tc.write(1)
	tc.recv(1)
	tc.ackFull(1, 0 /* window */, 0)

	// Data that does not fit the window makes the sender probe it.
	tc.write(1)
	tc.clock.Advance(time.Second)
	tc.drain()
	tc.locked(func(s *sender) {
		if !s.zeroWindowProbing || s.unackZeroWindowProbes == 0 {
			t.Fatalf("sender not probing a zero window")
		}
	})
	acks := 0
	tc.locked(func(*sender) { acks = fake.count("OnACK") })
	tc.ackFull(1, 0 /* window */, 0)
	tc.locked(func(*sender) {
		if got := fake.count("OnACK"); got != acks+1 {
			t.Errorf("OnACK called %d times for the probe's ACK, want 1", got-acks)
		}
	})
}

func TestRateCCSwitchMidConnection(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, true /* rack */, false /* ts */)
	tc.write(4)
	tc.recv(4)
	tc.locked(func(s *sender) {
		if s.rate.enabled {
			t.Fatalf("sampling enabled before switching")
		}
	})
	cwnd := tc.cwnd()

	// Switching keeps the window and counts the segments in flight.
	fake := tc.install(0 /* cwnd */, 0 /* pacingRate */)
	mss := uint64(tc.mss)
	if got := tc.cwnd(); got != cwnd {
		t.Errorf("cwnd %d after switching, want %d", got, cwnd)
	}
	tc.locked(func(s *sender) {
		if !s.rate.enabled || s.rate.InFlight != 4*mss {
			t.Errorf("sampling enabled %t with inflight %d, want true with %d", s.rate.enabled, s.rate.InFlight, 4*mss)
		}
	})

	// Segments sent before the switch are counted when delivered, but no
	// sample is based on them.
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(2)
	tc.locked(func(s *sender) {
		rs := fake.acks[len(fake.acks)-1]
		if rs.hasData || rs.newlyAcked != 2*mss || s.rate.Delivered != 2*mss {
			t.Errorf("ACK of old segments: hasData %t, newlyAcked %d, delivered %d, want false, %d, %d",
				rs.hasData, rs.newlyAcked, s.rate.Delivered, 2*mss, 2*mss)
		}
	})

	// A segment sent after the switch yields a sample.
	tc.write(1)
	tc.recv(1)
	tc.clock.Advance(10 * time.Millisecond)
	tc.ack(5)
	tc.locked(func(s *sender) {
		rs := fake.acks[len(fake.acks)-1]
		if !rs.hasData || s.rate.Delivered != 5*mss || s.rate.InFlight != 0 {
			t.Errorf("ACK of new segment: hasData %t, delivered %d, inflight %d, want true, %d, 0",
				rs.hasData, s.rate.Delivered, s.rate.InFlight, 5*mss)
		}
	})
}

// TestRateCCSwitchDuringRecovery switches to another rate-based algorithm
// during a loss recovery. The new algorithm was not told that the recovery
// began, so it is not told that it ends.
func TestRateCCSwitchDuringRecovery(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, true /* rack */, false /* ts */)
	first := tc.install(20, 0 /* pacingRate */)
	tc.lossEpisode(true /* sack */)
	second := tc.install(0 /* cwnd */, 0 /* pacingRate */)
	tc.ack(10)
	tc.locked(func(s *sender) {
		if s.state != tcpip.Open {
			t.Fatalf("sender state %d after the recovery, want Open (%d)", s.state, tcpip.Open)
		}
		if got := first.count("OnEnterRecovery"); got != 1 {
			t.Errorf("OnEnterRecovery called %d times on the first algorithm, want 1", got)
		}
		if got := first.count("OnExitRecovery"); got != 0 {
			t.Errorf("OnExitRecovery called %d times on the algorithm that was replaced", got)
		}
		if got := second.count("OnExitRecovery"); got != 0 {
			t.Errorf("OnExitRecovery called %d times on an algorithm that never entered recovery", got)
		}
	})
}

// TestRateCCSwitchAfterTimeout switches while segments sent before a
// retransmission timeout wait to be sent again. They are not in flight, and
// their late delivery yields no sample.
func TestRateCCSwitchAfterTimeout(t *testing.T) {
	tc := newRCCTest(t, true /* sack */, false /* rack */, false /* ts */)
	tc.write(4)
	tc.recv(4)
	tc.advanceUntil("timeout", 5*time.Second, func(s *sender) bool { return s.state == tcpip.RTORecovery })
	if got := tc.recvSegs(1); got[0] != 0 {
		t.Fatalf("retransmitted segment %d after the timeout, want 0", got[0])
	}
	tc.drain()

	fake := tc.install(0 /* cwnd */, 0 /* pacingRate */)
	mss := uint64(tc.mss)
	tc.locked(func(s *sender) {
		if s.rate.InFlight != mss || s.rate.LostPending != 3*mss {
			t.Errorf("after switching: inflight %d, lostPending %d, want %d, %d", s.rate.InFlight, s.rate.LostPending, mss, 3*mss)
		}
	})

	// The original transmissions all arrived after all.
	tc.ack(4)
	tc.locked(func(s *sender) {
		rs := fake.acks[len(fake.acks)-1]
		if rs.hasData || rs.newlyAcked != 4*mss || s.rate.Rate != 0 {
			t.Errorf("late ACK: hasData %t, newlyAcked %d, rate %d, want false, %d, 0", rs.hasData, rs.newlyAcked, s.rate.Rate, 4*mss)
		}
		if s.rate.InFlight != 0 || s.rate.LostPending != 0 || s.rate.Delivered != 4*mss {
			t.Errorf("late ACK: inflight %d, lostPending %d, delivered %d, want 0, 0, %d", s.rate.InFlight, s.rate.LostPending, s.rate.Delivered, 4*mss)
		}
	})
}

// String makes test failures readable.
func (l fakeLoss) String() string {
	return fmt.Sprintf("{size %d txInFlight %d priorLost %d lost %d}", l.size, l.txInFlight, l.priorLost, l.lost)
}
