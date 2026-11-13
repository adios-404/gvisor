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

package pathmodel

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

// delivery is a packet that a Direction delivered: when, measured from the
// start of the test, and its number.
type delivery struct {
	at time.Duration
	id uint32
}

// dirTest drives one Direction on a manual clock.
type dirTest struct {
	t      *testing.T
	clock  *faketime.ManualClock
	start  tcpip.MonotonicTime
	d      *Direction
	nextID uint32

	mu  sync.Mutex
	got []delivery
}

func newDirTest(t *testing.T, cfg Config) *dirTest {
	dt := &dirTest{t: t, clock: faketime.NewManualClock()}
	dt.start = dt.clock.NowMonotonic()
	dt.d = NewDirection(dt.clock, cfg, func(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
		id := binary.BigEndian.Uint32(pkt.Data().AsRange().ToSlice())
		dt.mu.Lock()
		defer dt.mu.Unlock()
		dt.got = append(dt.got, delivery{at: dt.clock.NowMonotonic().Sub(dt.start), id: id})
	})
	t.Cleanup(dt.d.Close)
	return dt
}

// send offers n packets of size bytes, numbered from the next free number.
func (dt *dirTest) send(n, size int) {
	for i := 0; i < n; i++ {
		b := make([]byte, size)
		binary.BigEndian.PutUint32(b, dt.nextID)
		dt.nextID++
		dt.d.Send(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)}))
	}
}

// advanceTo moves the clock to at, measured from the start of the test.
func (dt *dirTest) advanceTo(at time.Duration) {
	dt.clock.Advance(at - dt.clock.NowMonotonic().Sub(dt.start))
}

// deliveries returns what has been delivered so far.
func (dt *dirTest) deliveries() []delivery {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	return slices.Clone(dt.got)
}

func (dt *dirTest) check(want []delivery) {
	dt.t.Helper()
	if got := dt.deliveries(); !slices.Equal(got, want) {
		dt.t.Errorf("deliveries %v, want %v", got, want)
	}
}

const ms = time.Millisecond

func TestRateSpacesPackets(t *testing.T) {
	// 1000 bytes take 1ms at 1,000,000 bytes per second.
	dt := newDirTest(t, Config{Rate: 1_000_000})
	dt.send(3, 1000)
	dt.advanceTo(10 * ms)
	dt.check([]delivery{{1 * ms, 0}, {2 * ms, 1}, {3 * ms, 2}})
}

func TestDelay(t *testing.T) {
	dt := newDirTest(t, Config{Delay: 10 * ms})
	dt.send(2, 100)
	dt.advanceTo(5 * ms)
	dt.send(1, 100)
	dt.advanceTo(9 * ms)
	dt.check(nil)
	dt.advanceTo(20 * ms)
	dt.check([]delivery{{10 * ms, 0}, {10 * ms, 1}, {15 * ms, 2}})
}

func TestRateAndDelay(t *testing.T) {
	dt := newDirTest(t, Config{Rate: 1_000_000, Delay: 10 * ms})
	dt.send(2, 1000)
	// The bottleneck is idle again by 5ms, so this packet does not wait.
	dt.advanceTo(5 * ms)
	dt.send(1, 500)
	dt.advanceTo(20 * ms)
	dt.check([]delivery{{11 * ms, 0}, {12 * ms, 1}, {15*ms + 500*time.Microsecond, 2}})
}

func TestDropTailQueue(t *testing.T) {
	// A packet leaves the queue when it leaves the bottleneck, not when it is
	// delivered.
	for _, delay := range []time.Duration{0, 10 * ms} {
		t.Run(fmt.Sprintf("delay=%v", delay), func(t *testing.T) {
			dt := newDirTest(t, Config{Rate: 1_000_000, Delay: delay, QueueBytes: 3000})
			dt.send(5, 1000)
			// The first packet has left the bottleneck at 1ms, which makes
			// room for one more.
			dt.advanceTo(1 * ms)
			dt.send(2, 1000)
			dt.advanceTo(20 * ms)
			dt.check([]delivery{{delay + 1*ms, 0}, {delay + 2*ms, 1}, {delay + 3*ms, 2}, {delay + 4*ms, 5}})
			if got, want := dt.d.Stats(), (Stats{Offered: 7, Delivered: 4, DeliveredBytes: 4000, QueueDrops: 3, MaxQueueBytes: 3000, QueueWaitTotal: 5 * ms, MaxQueueWait: 2 * ms}); got != want {
				t.Errorf("stats %+v, want %+v", got, want)
			}
		})
	}
}

func TestRandomLoss(t *testing.T) {
	const packets = 100_000
	lossPattern := func(seed uint64) []uint32 {
		dt := newDirTest(t, Config{Delay: ms, LossPPM: 10_000, Seed: seed})
		dt.send(packets, 4)
		dt.advanceTo(ms)
		var lost []uint32
		next := uint32(0)
		for _, d := range dt.deliveries() {
			for ; next < d.id; next++ {
				lost = append(lost, next)
			}
			next = d.id + 1
		}
		for ; next < packets; next++ {
			lost = append(lost, next)
		}
		if got := dt.d.Stats().RandomDrops; got != uint64(len(lost)) {
			t.Errorf("seed %d: RandomDrops %d, but %d packets missing", seed, got, len(lost))
		}
		return lost
	}
	a := lossPattern(1)
	// 1% of 100,000 is 1,000, with a standard deviation of about 31.
	if n := len(a); n < 900 || n > 1100 {
		t.Errorf("lost %d of %d packets at 1%%, want 900 to 1100", n, packets)
	}
	if b := lossPattern(1); !slices.Equal(a, b) {
		t.Errorf("the same seed lost different packets")
	}
	if c := lossPattern(2); slices.Equal(a, c) {
		t.Errorf("different seeds lost the same packets")
	}
}

func TestSetRate(t *testing.T) {
	dt := newDirTest(t, Config{Rate: 1_000_000})
	dt.send(4, 1000)
	// At 1.5ms the second packet is half sent. It finishes at the old rate;
	// the two behind it are sent at the new one.
	dt.advanceTo(1500 * time.Microsecond)
	dt.d.SetRate(2_000_000)
	dt.advanceTo(10 * ms)
	dt.check([]delivery{{1 * ms, 0}, {2 * ms, 1}, {2500 * time.Microsecond, 2}, {3 * ms, 3}})

	// A rate of zero removes the limit.
	dt.d.SetRate(0)
	dt.send(2, 1000)
	dt.advanceTo(20 * ms)
	if got := dt.deliveries()[4:]; !slices.Equal(got, []delivery{{10 * ms, 4}, {10 * ms, 5}}) {
		t.Errorf("deliveries without a limit %v, want both at 10ms", got)
	}
}

func TestPolicer(t *testing.T) {
	dt := newDirTest(t, Config{Delay: ms, PolicerRate: 1_000_000, PolicerBurst: 3000})
	// The bucket starts full: the burst passes and the rest is dropped.
	dt.send(5, 1000)
	// 1ms refills 1000 bytes.
	dt.advanceTo(ms)
	dt.send(2, 1000)
	// A long pause refills only up to the burst.
	dt.advanceTo(100 * ms)
	dt.send(4, 1000)
	dt.advanceTo(200 * ms)
	var ids []uint32
	for _, d := range dt.deliveries() {
		ids = append(ids, d.id)
	}
	if want := []uint32{0, 1, 2, 5, 7, 8, 9}; !slices.Equal(ids, want) {
		t.Errorf("delivered %v, want %v", ids, want)
	}
	if got := dt.d.Stats().PolicerDrops; got != 4 {
		t.Errorf("PolicerDrops %d, want 4", got)
	}
}

func TestCloseReleasesPackets(t *testing.T) {
	dt := newDirTest(t, Config{Delay: time.Second})
	dt.send(3, 100)
	dt.d.Close()
	// Packets offered after Close are dropped too. TestMain checks that none
	// leaks.
	dt.send(1, 100)
	dt.advanceTo(2 * time.Second)
	dt.check(nil)
}

// capture records the packets a link endpoint receives.
type capture struct {
	clock *faketime.ManualClock
	start tcpip.MonotonicTime

	mu  sync.Mutex
	got []delivery
}

func (c *capture) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	id := binary.BigEndian.Uint32(pkt.Data().AsRange().ToSlice())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, delivery{at: c.clock.NowMonotonic().Sub(c.start), id: id})
}

func (*capture) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestJoin(t *testing.T) {
	clock := faketime.NewManualClock()
	a, b := channel.New(16, 1500, ""), channel.New(16, 1500, "")
	captures := [2]*capture{{clock: clock, start: clock.NowMonotonic()}, {clock: clock, start: clock.NowMonotonic()}}
	a.Attach(captures[0])
	b.Attach(captures[1])
	p := Join(clock, a, b, Config{Delay: 10 * ms}, Config{Delay: 20 * ms})
	t.Cleanup(func() {
		p.Close()
		a.Close()
		b.Close()
	})

	write := func(link *channel.Endpoint, id uint32) {
		var pkts stack.PacketBufferList
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, id)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
		pkts.PushBack(pkt)
		defer pkts.DecRef()
		if n, err := link.WritePackets(pkts); err != nil || n != 1 {
			t.Fatalf("WritePackets = %d, %v", n, err)
		}
	}
	write(a, 1)
	write(b, 2)
	// The pumps run on their own goroutines.
	deadline := time.Now().Add(10 * time.Second)
	for p.AB.Stats().Offered != 1 || p.BA.Stats().Offered != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("packets not offered to the path")
		}
		time.Sleep(time.Millisecond)
	}
	clock.Advance(30 * ms)
	for i, want := range [][]delivery{{{20 * ms, 2}}, {{10 * ms, 1}}} {
		captures[i].mu.Lock()
		got := slices.Clone(captures[i].got)
		captures[i].mu.Unlock()
		if !slices.Equal(got, want) {
			t.Errorf("link %d received %v, want %v", i, got, want)
		}
	}
}
