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

// Package pathmodel models a network path between two link endpoints, for
// tests and benchmarks of TCP over paths that are slow, long, lossy or
// congested.
//
// Each direction of a path has a bottleneck that sends packets one at a time
// at a fixed rate, with a drop-tail queue in front of it, followed by a fixed
// propagation delay. Packets can also be dropped at random, with a seeded
// generator so that runs are repeatable, and by a token-bucket policer.
// Packets are never reordered.
//
// All timing goes through a tcpip.Clock, so a path runs on real time or on a
// faketime.ManualClock. The time a packet leaves the bottleneck is computed,
// not measured, so a timer that fires late delays delivery but does not lower
// the rate.
package pathmodel

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// partsPerMillion is the denominator of Config.LossPPM.
const partsPerMillion = 1_000_000

// Config describes one direction of a path.
type Config struct {
	// Rate is the rate of the bottleneck in bytes per second. Zero means that
	// the bottleneck takes no time to send a packet.
	Rate uint64

	// Delay is the propagation delay after the bottleneck.
	Delay time.Duration

	// QueueBytes is the most data that may wait for, or be in, the
	// bottleneck. A packet that does not fit is dropped. Zero means no limit.
	QueueBytes int

	// LossPPM is the probability, in parts per million, that a packet is
	// dropped before the queue.
	LossPPM uint32

	// Seed seeds the generator that decides which packets are dropped.
	Seed uint64

	// PolicerRate, if not zero, polices the traffic with a token bucket that
	// fills at PolicerRate bytes per second up to PolicerBurst bytes. A
	// packet that finds too few tokens is dropped. The bucket starts full.
	PolicerRate uint64

	// PolicerBurst is the size of the policer's bucket in bytes.
	PolicerBurst int
}

// Stats counts what happened to the packets offered to a direction.
type Stats struct {
	// Offered is the number of packets offered with Send.
	Offered uint64

	// Delivered and DeliveredBytes count the packets delivered.
	Delivered      uint64
	DeliveredBytes uint64

	// PolicerDrops, RandomDrops and QueueDrops count the packets dropped by
	// the policer, at random and because the queue was full.
	PolicerDrops uint64
	RandomDrops  uint64
	QueueDrops   uint64

	// MaxQueueBytes is the most data that was ever queued at the bottleneck,
	// including the packet being sent.
	MaxQueueBytes int

	// QueueWaitTotal and MaxQueueWait are the total and the longest time
	// that the packets accepted waited for the bottleneck, as computed when
	// they arrived.
	QueueWaitTotal time.Duration
	MaxQueueWait   time.Duration
}

// pending is a packet accepted by the bottleneck and not yet delivered.
type pending struct {
	pkt      *stack.PacketBuffer
	proto    tcpip.NetworkProtocolNumber
	size     int
	arrival  tcpip.MonotonicTime
	departed tcpip.MonotonicTime
}

// Direction is one direction of a path.
type Direction struct {
	clock   tcpip.Clock
	deliver func(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)

	// deliverMu serializes deliveries, so that two late timer callbacks do
	// not reorder packets.
	deliverMu sync.Mutex

	mu sync.Mutex

	// +checklocks:mu
	cfg Config

	// +checklocks:mu
	rng *rand.Rand

	// pkts holds the packets accepted and not yet delivered, in the order
	// they arrived, which is also the order they leave the bottleneck.
	//
	// +checklocks:mu
	pkts []*pending

	// queued is the index in pkts of the first packet that had not left the
	// bottleneck when the queue was last updated, and queueBytes the size of
	// that packet and those after it.
	//
	// +checklocks:mu
	queued int
	// +checklocks:mu
	queueBytes int

	// busyUntil is when the bottleneck finishes the last packet accepted.
	//
	// +checklocks:mu
	busyUntil tcpip.MonotonicTime

	// tokens is the content of the policer's bucket, in billionths of a byte
	// so that it fills exactly at any rate, and tokensTime when it was last
	// filled.
	//
	// +checklocks:mu
	tokens uint64
	// +checklocks:mu
	tokensTime tcpip.MonotonicTime

	// timer delivers the first packet in pkts at timerTarget, if timerArmed.
	//
	// +checklocks:mu
	timer tcpip.Timer
	// +checklocks:mu
	timerArmed bool
	// +checklocks:mu
	timerTarget tcpip.MonotonicTime

	// +checklocks:mu
	closed bool

	// +checklocks:mu
	stats Stats
}

// NewDirection returns a direction that passes the packets offered to it to
// deliver, which must not call Send or Close of the same direction.
func NewDirection(clock tcpip.Clock, cfg Config, deliver func(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)) *Direction {
	if cfg.Delay < 0 || cfg.QueueBytes < 0 || cfg.PolicerBurst < 0 || cfg.LossPPM > partsPerMillion {
		panic(fmt.Sprintf("invalid path configuration %+v", cfg))
	}
	d := &Direction{
		clock:   clock,
		deliver: deliver,
		cfg:     cfg,
		rng:     rand.New(rand.NewPCG(cfg.Seed, cfg.Seed)),
		tokens:  uint64(cfg.PolicerBurst) * uint64(time.Second),
	}
	d.tokensTime = clock.NowMonotonic()
	return d
}

// Send offers pkt, of the given network protocol, to the direction, which
// takes over the caller's reference to it.
func (d *Direction) Send(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	size := pkt.Size()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.Offered++
	if d.closed {
		pkt.DecRef()
		return
	}
	now := d.clock.NowMonotonic()
	if !d.policerAllowsLocked(size, now) {
		d.stats.PolicerDrops++
		pkt.DecRef()
		return
	}
	if d.cfg.LossPPM != 0 && d.rng.Uint32N(partsPerMillion) < d.cfg.LossPPM {
		d.stats.RandomDrops++
		pkt.DecRef()
		return
	}
	d.updateQueueLocked(now)
	if d.cfg.QueueBytes != 0 && d.queueBytes+size > d.cfg.QueueBytes {
		d.stats.QueueDrops++
		pkt.DecRef()
		return
	}
	start := now
	if d.busyUntil.After(now) {
		start = d.busyUntil
	}
	p := &pending{
		pkt:      pkt,
		proto:    proto,
		size:     size,
		arrival:  now,
		departed: start.Add(sendTime(size, d.cfg.Rate)),
	}
	d.busyUntil = p.departed
	wait := start.Sub(now)
	d.stats.QueueWaitTotal += wait
	d.stats.MaxQueueWait = max(d.stats.MaxQueueWait, wait)
	d.pkts = append(d.pkts, p)
	d.queueBytes += size
	d.stats.MaxQueueBytes = max(d.stats.MaxQueueBytes, d.queueBytes)
	d.armLocked(now)
}

// SetRate changes the rate of the bottleneck. A packet being sent finishes
// at the old rate; the packets queued behind it are sent at the new one.
func (d *Direction) SetRate(rate uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock.NowMonotonic()
	d.updateQueueLocked(now)
	d.cfg.Rate = rate
	for i := d.queued; i < len(d.pkts); i++ {
		p := d.pkts[i]
		start := p.arrival
		if i > 0 && d.pkts[i-1].departed.After(start) {
			start = d.pkts[i-1].departed
		}
		if !start.After(now) {
			// Being sent.
			continue
		}
		p.departed = start.Add(sendTime(p.size, rate))
	}
	if n := len(d.pkts); n > 0 && d.pkts[n-1].departed.After(now) {
		d.busyUntil = d.pkts[n-1].departed
	}
	d.armLocked(now)
}

// Stats returns the direction's counters.
func (d *Direction) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// Close drops the packets in the direction and those offered later. A
// delivery in progress finishes first; none starts after Close returns.
func (d *Direction) Close() {
	d.deliverMu.Lock()
	defer d.deliverMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timerArmed = false
	for _, p := range d.pkts {
		p.pkt.DecRef()
	}
	d.pkts = nil
	d.queued = 0
	d.queueBytes = 0
}

// sendTime returns how long the bottleneck takes to send size bytes at rate
// bytes per second.
func sendTime(size int, rate uint64) time.Duration {
	if rate == 0 {
		return 0
	}
	return time.Duration(uint64(size) * uint64(time.Second) / rate)
}

// policerAllowsLocked fills the policer's bucket up to now and takes size
// bytes from it, if it holds that many.
//
// +checklocks:d.mu
func (d *Direction) policerAllowsLocked(size int, now tcpip.MonotonicTime) bool {
	rate := d.cfg.PolicerRate
	if rate == 0 {
		return true
	}
	full := uint64(d.cfg.PolicerBurst) * uint64(time.Second)
	if elapsed := now.Sub(d.tokensTime); elapsed > 0 {
		// Compare times first: elapsed * rate can overflow after a long
		// pause.
		if uint64(elapsed) >= (full-d.tokens)/rate {
			d.tokens = full
		} else {
			d.tokens += uint64(elapsed) * rate
		}
		d.tokensTime = now
	}
	cost := uint64(size) * uint64(time.Second)
	if d.tokens < cost {
		return false
	}
	d.tokens -= cost
	return true
}

// updateQueueLocked removes the packets that have left the bottleneck by now
// from the queue.
//
// +checklocks:d.mu
func (d *Direction) updateQueueLocked(now tcpip.MonotonicTime) {
	for d.queued < len(d.pkts) && !d.pkts[d.queued].departed.After(now) {
		d.queueBytes -= d.pkts[d.queued].size
		d.queued++
	}
}

// armLocked arms the timer for the delivery of the first packet.
//
// +checklocks:d.mu
func (d *Direction) armLocked(now tcpip.MonotonicTime) {
	if len(d.pkts) == 0 {
		return
	}
	target := d.pkts[0].departed.Add(d.cfg.Delay)
	if d.timerArmed && d.timerTarget == target {
		return
	}
	d.timerArmed = true
	d.timerTarget = target
	wait := target.Sub(now)
	if d.timer == nil {
		d.timer = d.clock.AfterFunc(wait, d.deliverDue)
		return
	}
	d.timer.Reset(wait)
}

// deliverDue delivers the packets whose time has come.
func (d *Direction) deliverDue() {
	d.deliverMu.Lock()
	defer d.deliverMu.Unlock()

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.timerArmed = false
	now := d.clock.NowMonotonic()
	var due []*pending
	for len(d.pkts) > 0 && !d.pkts[0].departed.Add(d.cfg.Delay).After(now) {
		p := d.pkts[0]
		d.pkts[0] = nil
		d.pkts = d.pkts[1:]
		if d.queued > 0 {
			d.queued--
		} else {
			// It left the bottleneck before the queue was last updated.
			d.queueBytes -= p.size
		}
		d.stats.Delivered++
		d.stats.DeliveredBytes += uint64(p.size)
		due = append(due, p)
	}
	d.armLocked(now)
	d.mu.Unlock()

	for _, p := range due {
		d.deliver(p.proto, p.pkt)
		p.pkt.DecRef()
	}
}

// Path joins two link endpoints with a direction each way.
type Path struct {
	// AB carries the packets sent by the first endpoint to the second, and
	// BA those sent by the second to the first.
	AB, BA *Direction

	cancel context.CancelFunc
	pumps  sync.WaitGroup
}

// Join returns a path that carries the packets sent by a to b through a
// direction configured by ab, and those sent by b to a through one
// configured by ba. The endpoints should not use GSO: a GSO packet would
// cross the path as one packet.
func Join(clock tcpip.Clock, a, b *channel.Endpoint, ab, ba Config) *Path {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Path{
		AB:     NewDirection(clock, ab, b.InjectInbound),
		BA:     NewDirection(clock, ba, a.InjectInbound),
		cancel: cancel,
	}
	p.pump(ctx, a, p.AB)
	p.pump(ctx, b, p.BA)
	return p
}

// Close stops the path and drops the packets in it.
func (p *Path) Close() {
	p.cancel()
	p.pumps.Wait()
	p.AB.Close()
	p.BA.Close()
}

// notifier wakes a pump when its endpoint has packets to read.
type notifier chan struct{}

// WriteNotify implements channel.Notification.WriteNotify.
func (n notifier) WriteNotify() {
	select {
	case n <- struct{}{}:
	default:
	}
}

// pump offers the packets that from sends to to.
func (p *Path) pump(ctx context.Context, from *channel.Endpoint, to *Direction) {
	p.pumps.Add(1)
	go func() {
		defer p.pumps.Done()
		notify := make(notifier, 1)
		h := from.AddNotify(notify)
		defer from.RemoveNotify(h)
		for {
			for pkt := from.Read(); pkt != nil; pkt = from.Read() {
				if ctx.Err() != nil {
					pkt.DecRef()
					return
				}
				// The packet was built to be sent. The receiver needs one
				// that has not been parsed yet.
				in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(pkt.ToView())})
				proto := pkt.NetworkProtocolNumber
				pkt.DecRef()
				to.Send(proto, in)
			}
			select {
			case <-ctx.Done():
				return
			case <-notify:
			}
		}
	}()
}
