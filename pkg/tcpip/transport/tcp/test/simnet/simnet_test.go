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

package simnet

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

func TestClockOrder(t *testing.T) {
	c := NewClock()
	var got []string
	note := func(s string) func() { return func() { got = append(got, s) } }
	c.AfterFunc(2*time.Millisecond, note("b"))
	c.AfterFunc(time.Millisecond, note("a"))
	c.AfterFunc(2*time.Millisecond, note("c"))
	stopped := c.AfterFunc(time.Millisecond, note("stopped"))
	reset := c.AfterFunc(time.Millisecond, note("reset"))
	if !stopped.Stop() {
		t.Error("Stop of a set timer returned false")
	}
	if stopped.Stop() {
		t.Error("second Stop returned true")
	}
	reset.Reset(3 * time.Millisecond)
	for c.Step() {
	}
	if want := []string{"a", "b", "c", "reset"}; !slices.Equal(got, want) {
		t.Errorf("timers ran in order %v, want %v", got, want)
	}
	if got, want := c.Elapsed(), 3*time.Millisecond; got != want {
		t.Errorf("Elapsed() = %v, want %v", got, want)
	}
	if got, want := c.NowMonotonic().Sub(tcpip.MonotonicTime{}), 3*time.Millisecond; got != want {
		t.Errorf("NowMonotonic() is %v after zero, want %v", got, want)
	}
}

func TestClockZeroDelayWaitsForStep(t *testing.T) {
	c := NewClock()
	ran := false
	c.AfterFunc(0, func() { ran = true })
	c.AfterFunc(-time.Second, func() {})
	if ran {
		t.Fatal("a timer with no delay ran before Step")
	}
	if at, ok := c.Next(); !ok || at != 0 {
		t.Fatalf("Next() = %v, %t; want 0, true", at, ok)
	}
	c.Step()
	if !ran || c.Elapsed() != 0 {
		t.Fatalf("after Step: ran = %t, Elapsed() = %v; want true, 0", ran, c.Elapsed())
	}
}

func TestClockTimerSetsTimer(t *testing.T) {
	c := NewClock()
	var times []time.Duration
	var tick tcpip.Timer
	tick = c.AfterFunc(time.Millisecond, func() {
		times = append(times, c.Elapsed())
		if len(times) < 3 {
			tick.Reset(time.Millisecond)
		}
	})
	for c.Step() {
	}
	if want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}; !slices.Equal(times, want) {
		t.Errorf("timer ran at %v, want %v", times, want)
	}
	if tick.Stop() {
		t.Error("Stop of an expired timer returned true")
	}
}

func TestClockAdvanceTo(t *testing.T) {
	c := NewClock()
	c.AfterFunc(time.Second, func() {})
	c.AdvanceTo(time.Second)
	if c.Elapsed() != time.Second {
		t.Fatalf("Elapsed() = %v, want 1s", c.Elapsed())
	}
	defer func() {
		if recover() == nil {
			t.Error("AdvanceTo past a timer did not panic")
		}
	}()
	c.AdvanceTo(2 * time.Second)
}

// path returns a 20 Mbit/s path with 20 ms of round-trip delay, a queue of
// one bandwidth-delay product and the given loss on the data direction.
func path(lossPPM uint32, seed uint64) (pathmodel.Config, pathmodel.Config) {
	const rate = 2_500_000
	const rtt = 20 * time.Millisecond
	bdp := int(rate * uint64(rtt) / uint64(time.Second))
	data := pathmodel.Config{Rate: rate, Delay: rtt / 2, QueueBytes: bdp, LossPPM: lossPPM, Seed: seed}
	acks := pathmodel.Config{Rate: rate, Delay: rtt / 2}
	return data, acks
}

// event is what a run records: the client's state after a segment
// (dir = -1), or a packet that leaves a direction of the path (dir = 0 for
// Data, 1 for Acks).
type event struct {
	at       time.Duration
	dir      int
	una, nxt seqnum.Value
	cwnd     int
	seg      Segment
}

// recorder records events.
type recorder struct {
	mu     sync.Mutex
	clock  *Clock
	events []event
}

func (r *recorder) probe(s *tcp.TCPEndpointState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event{at: r.clock.Elapsed(), dir: -1, una: s.Sender.SndUna, nxt: s.Sender.SndNxt, cwnd: s.Sender.SndCwnd})
}

// packets returns a filter that records the packets of direction dir and
// lets them through.
func (r *recorder) packets(dir int) Filter {
	return func(pkt *stack.PacketBuffer) Verdict {
		seg, _ := ParseSegment(pkt)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.events = append(r.events, event{at: r.clock.Elapsed(), dir: dir, seg: seg})
		return Verdict{}
	}
}

// transfer sends size bytes over a lossy path and returns every packet and
// every state of the client the run recorded, the time it took and the
// client's retransmissions.
func transfer(t *testing.T, cc tcpip.CongestionControlOption, seed uint64, size uint64) ([]event, time.Duration, uint64) {
	t.Helper()
	r := &recorder{}
	data, acks := path(10_000, seed)
	n, err := New(Config{Data: data, Acks: acks, CC: cc, RACK: true, Probe: r.probe, Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	r.clock = n.Clock
	n.SetFilter(n.Data, r.packets(0))
	n.SetFilter(n.Acks, r.packets(1))
	f, err := n.Dial()
	if err != nil {
		t.Fatal(err)
	}
	ep := f.Client.(*tcp.Endpoint)
	ep.LockUser()
	sack, ts := ep.SACKPermitted, ep.SendTSOk
	ep.UnlockUser()
	if !sack || !ts {
		t.Fatalf("SACK %t, timestamps %t; want both negotiated", sack, ts)
	}
	start := n.Clock.Elapsed()
	f.Bulk()
	if err := n.Run(time.Minute, func() bool { return f.Received() >= size }); err != nil {
		t.Fatal(err)
	}
	if f.Err() != nil {
		t.Fatal(f.Err())
	}
	if n.Data.Stats().RandomDrops == 0 {
		t.Error("no packet was lost on a path with 1% loss")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events, n.Clock.Elapsed() - start, n.Client.Stats().TCP.Retransmits.Value()
}

// TestDeterministic checks that the same configuration gives the same run:
// the same packets, at the same times, in both directions, and the same
// states of the sender.
func TestDeterministic(t *testing.T) {
	for _, cc := range []tcpip.CongestionControlOption{"cubic", "bbr"} {
		t.Run(string(cc), func(t *testing.T) {
			const size = 2 << 20
			start := time.Now()
			first, took, rxt := transfer(t, cc, 1, size)
			elapsed := time.Since(start)
			t.Logf("%d bytes in %v of simulated time (%v real), %d retransmits, %d events", size, took, elapsed, rxt, len(first))
			again, _, _ := transfer(t, cc, 1, size)
			if !slices.Equal(first, again) {
				i := 0
				for i < min(len(first), len(again)) && first[i] == again[i] {
					i++
				}
				t.Fatalf("runs differ from event %d of %d/%d", i, len(first), len(again))
			}
			other, _, _ := transfer(t, cc, 2, size)
			if slices.Equal(first, other) {
				t.Error("a different seed gave the same run")
			}
		})
	}
}

// TestBufferSize checks that Config.BufferSize sets the send and receive
// buffers of the sockets at both ends, and that the default is the stacks'.
func TestBufferSize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		snd, rcv int64
	}{
		{name: "default", snd: tcp.DefaultSendBufferSize, rcv: tcp.DefaultReceiveBufferSize},
		{name: "8MiB", size: 8 << 20, snd: 8 << 20, rcv: 8 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, acks := path(0, 1)
			n, err := New(Config{Data: data, Acks: acks, RACK: true, Seed: 1, BufferSize: tc.size})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			f, err := n.Dial()
			if err != nil {
				t.Fatal(err)
			}
			for _, end := range []struct {
				name string
				ep   tcpip.Endpoint
			}{{"client", f.Client}, {"server", f.Server}} {
				if got := end.ep.SocketOptions().GetSendBufferSize(); got != tc.snd {
					t.Errorf("%s: send buffer = %d, want %d", end.name, got, tc.snd)
				}
				if got := end.ep.SocketOptions().GetReceiveBufferSize(); got != tc.rcv {
					t.Errorf("%s: receive buffer = %d, want %d", end.name, got, tc.rcv)
				}
			}
		})
	}
	data, acks := path(0, 1)
	if n, err := New(Config{Data: data, Acks: acks, BufferSize: tcp.MinBufferSize - 1}); err == nil {
		n.Close()
		t.Errorf("New with BufferSize %d succeeded, want an error", tcp.MinBufferSize-1)
	}
}

func TestFilter(t *testing.T) {
	data, acks := path(0, 1)
	n, err := New(Config{Data: data, Acks: acks, RACK: true, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	f, err := n.Dial()
	if err != nil {
		t.Fatal(err)
	}
	// Drop the third data segment and hold the tenth back by 5 ms, so it
	// arrives after later ones.
	var segs int
	n.SetFilter(n.Data, func(pkt *stack.PacketBuffer) Verdict {
		s, ok := ParseSegment(pkt)
		if !ok || s.PayloadLen == 0 {
			return Verdict{}
		}
		segs++
		switch segs {
		case 3:
			return Verdict{Drop: true}
		case 10:
			return Verdict{Delay: 5 * time.Millisecond}
		}
		return Verdict{}
	})
	const size = 256 << 10
	f.Bulk()
	if err := n.Run(time.Minute, func() bool { return f.Received() >= size }); err != nil {
		t.Fatal(err)
	}
	if f.Err() != nil {
		t.Fatal(f.Err())
	}
	if got := n.FilterDrops(n.Data); got != 1 {
		t.Errorf("FilterDrops(Data) = %d, want 1", got)
	}
	if got := n.Client.Stats().TCP.Retransmits.Value(); got == 0 {
		t.Error("the dropped segment was not retransmitted")
	}
	if got := n.Server.Stats().TCP.ValidSegmentsReceived.Value(); got == 0 {
		t.Error("server received nothing")
	}
}

func TestParseSegment(t *testing.T) {
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+5)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), Protocol: uint8(header.TCPProtocolNumber), TTL: 64, SrcAddr: ClientAddr, DstAddr: ServerAddr})
	header.TCP(ip.Payload()).Encode(&header.TCPFields{SeqNum: 7, AckNum: 9, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagAck})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	defer pkt.DecRef()
	got, ok := ParseSegment(pkt)
	want := Segment{Seq: 7, Ack: 9, PayloadLen: 5, Flags: header.TCPFlagAck}
	if !ok || got != want {
		t.Errorf("ParseSegment() = %+v, %t; want %+v, true", got, ok, want)
	}
}

func ExampleNetwork() {
	data := pathmodel.Config{Rate: 1_250_000, Delay: 20 * time.Millisecond}
	acks := pathmodel.Config{Delay: 20 * time.Millisecond}
	n, err := New(Config{Data: data, Acks: acks, CC: "cubic", RACK: true})
	if err != nil {
		panic(err)
	}
	defer n.Close()
	f, err := n.Dial()
	if err != nil {
		panic(err)
	}
	f.Bulk()
	n.RunFor(10 * time.Second)
	fmt.Printf("%.1f MB/s\n", float64(f.Received())/10/1e6)
	// Output: 1.2 MB/s
}
