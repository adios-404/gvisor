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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// at returns the monotonic time d after time zero.
func at(d time.Duration) tcpip.MonotonicTime {
	return tcpip.MonotonicTime{}.Add(d)
}

func TestPacerOff(t *testing.T) {
	var p pacer
	p.init(0)
	for _, now := range []tcpip.MonotonicTime{at(0), at(time.Second)} {
		p.onSent(100000, now)
		if d := p.ready(now); d != 0 {
			t.Errorf("ready(%v) = %s, want 0 while pacing is off", now, d)
		}
	}
	if got := p.limit(12345, 1000); got != 12345 {
		t.Errorf("limit(12345, 1000) = %d, want 12345 while pacing is off", got)
	}
}

func TestPacerSendQuantum(t *testing.T) {
	const smss = 1000
	for _, tc := range []struct {
		name string
		rate uint64
		want int
	}{
		// 1ms at 1 MB/s is 1000 bytes, less than two segments.
		{name: "two segments at least", rate: 1000000, want: 2 * smss},
		// 1ms at 10 MB/s.
		{name: "one millisecond of data", rate: 10000000, want: 10000},
		// 1ms at 1 GB/s is far more than 64 KB.
		{name: "64 KB at most", rate: 1000000000, want: 64 << 10},
		{name: "huge rate", rate: math.MaxUint64, want: 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p pacer
			p.init(0)
			p.setRate(tc.rate, smss)
			if p.Quantum != tc.want {
				t.Errorf("setRate(%d, %d): got Quantum %d, want %d", tc.rate, smss, p.Quantum, tc.want)
			}
			if d := p.ready(at(0)); d != 0 {
				t.Fatalf("ready = %s, want 0", d)
			}
			if got := p.limit(1<<20, smss); got != tc.want {
				t.Errorf("limit(1 MiB, %d) = %d, want %d", smss, got, tc.want)
			}
			if got := p.limit(100, smss); got != 100 {
				t.Errorf("limit(100, %d) = %d, want 100", smss, got)
			}
		})
	}
}

// TestPacerSpacing checks the departure times of section 5.6.2 on a precise
// clock: a quantum goes out at once, and the next one waits for as long as
// the first takes to send at the pacing rate.
func TestPacerSpacing(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1000000, 1000) // 1 MB/s, quantum 2000 bytes.

	for i := 0; i < 2; i++ {
		if d := p.ready(at(0)); d != 0 {
			t.Fatalf("segment %d of the first quantum: ready = %s, want 0", i, d)
		}
		p.onSent(1000, at(0))
	}
	for _, tc := range []struct {
		now  time.Duration
		want time.Duration
	}{
		{0, 2 * time.Millisecond},
		{time.Millisecond, time.Millisecond},
		{2 * time.Millisecond, 0},
	} {
		if got := p.ready(at(tc.now)); got != tc.want {
			t.Errorf("ready at %s = %s, want %s", tc.now, got, tc.want)
		}
	}
	if got, want := p.NextSendTime, at(2*time.Millisecond); got != want {
		t.Errorf("got NextSendTime %v, want %v", got, want)
	}
}

// TestPacerFullSegments checks that a segment is not shortened to fit the end
// of a quantum, and that the excess delays the next quantum.
func TestPacerFullSegments(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1000000, 1000) // 1 MB/s, quantum 2000 bytes.

	p.ready(at(0))
	p.onSent(1500, at(0))
	if got := p.limit(1000, 1000); got != 1000 {
		t.Errorf("with 500 bytes of the quantum left: limit(1000, 1000) = %d, want 1000", got)
	}
	p.onSent(1000, at(0))
	if got, want := p.ready(at(0)), 2500*time.Microsecond; got != want {
		t.Errorf("after 2500 bytes: ready = %s, want %s", got, want)
	}
}

// TestPacerWholeSegmentsWithOffload checks that with segmentation offload a
// segment is not cut to what is left of a quantum either. A segment of
// nearly 64KB leaves a few bytes of a 64KB quantum; cutting the next one to
// them, or to one full-sized segment, would send a large and a tiny segment
// for every quantum, two writes to the link where one will do.
func TestPacerWholeSegmentsWithOffload(t *testing.T) {
	var p pacer
	p.init(0)
	const (
		rate = 1000000000 // 1 GB/s, quantum 64KB.
		smss = 1448
		gso  = 65474
	)
	p.setRate(rate, smss)

	if d := p.ready(at(0)); d != 0 {
		t.Fatalf("ready = %s, want 0", d)
	}
	if got := p.limit(gso, smss); got != gso {
		t.Fatalf("at the start of a quantum: limit(%d, %d) = %d, want %d", gso, smss, got, gso)
	}
	p.onSent(gso, at(0))
	if d := p.ready(at(0)); d != 0 {
		t.Fatalf("with %d bytes of the quantum left: ready = %s, want 0", p.Quantum-gso, d)
	}
	if got := p.limit(gso, smss); got != gso {
		t.Errorf("with %d bytes of the quantum left: limit(%d, %d) = %d, want %d", p.Quantum-gso, gso, smss, got, gso)
	}
	p.onSent(gso, at(0))
	// The excess delays the next quantum: the rate is kept.
	if got, want := p.ready(at(0)), pacingDelay(2*gso, rate); got != want {
		t.Errorf("after two segments: ready = %s, want %s", got, want)
	}
	// A segment is never larger than a quantum.
	if d := p.ready(at(time.Second)); d != 0 {
		t.Fatalf("a second later: ready = %s, want 0", d)
	}
	if got := p.limit(1<<20, smss); got != p.Quantum {
		t.Errorf("limit(1 MiB, %d) = %d, want the quantum, %d", smss, got, p.Quantum)
	}
}

// TestPacerIdle checks that time spent idle is not saved up for a burst:
// after a long pause one quantum goes out at once.
func TestPacerIdle(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(10000000, 1000) // 10 MB/s, quantum 10000 bytes, 1ms each.
	p.ready(at(0))
	p.onSent(p.Quantum, at(0))

	now := at(time.Second)
	sent := 0
	for p.ready(now) == 0 && sent < 100 {
		p.onSent(p.Quantum, now)
		sent++
	}
	if sent != 1 {
		t.Errorf("after an idle second sent %d quanta at once, want 1", sent)
	}
}

// sendFor simulates a sender that always has data and is woken by a timer
// that fires late by lateness and only at multiples of resolution. It
// returns the bytes sent in duration.
func sendFor(p *pacer, duration, lateness, resolution time.Duration) int {
	total := 0
	now := at(0)
	end := at(duration)
	for now.Before(end) {
		for p.ready(now) == 0 {
			p.onSent(p.Quantum, now)
			total += p.Quantum
		}
		wake := now.Add(p.ready(now) + lateness)
		if resolution > 0 {
			// Round up to the next tick.
			ticks := (wake.Sub(at(0)) + resolution - 1) / resolution
			wake = at(ticks * resolution)
		}
		now = wake
	}
	return total
}

// TestPacerLateTimer checks that a timer that fires late does not lower the
// rate: the time it was late is made up by the next send.
func TestPacerLateTimer(t *testing.T) {
	const (
		rate     = 10000000 // 10 MB/s, quantum 10000 bytes, 1ms each.
		duration = time.Second
	)
	var p pacer
	p.init(0)
	p.setRate(rate, 1000)
	got := sendFor(&p, duration, 300*time.Microsecond, 0)
	want := int(rate * duration / time.Second)
	if got < want*99/100 || got > want+2*p.Quantum {
		t.Errorf("sent %d bytes in %s with a timer 300µs late, want %d", got, duration, want)
	}
}

// TestPacerLateTimerHighRate checks the rate when the timer fires much later
// than the gap between quanta, as Go's timers do on Linux when the process is
// otherwise idle: about 1ms late even for a 20µs timer.
func TestPacerLateTimerHighRate(t *testing.T) {
	const (
		rate     = 1250000000 // 10 Gbit/s, 64 KB quanta 52µs apart.
		duration = 100 * time.Millisecond
	)
	var p pacer
	p.init(0)
	p.setRate(rate, 1460)
	got := sendFor(&p, duration, time.Millisecond, 0)
	want := int(uint64(rate) * uint64(duration) / uint64(time.Second))
	if got < want*99/100 || got > want+int(rate*pacingTimerSlack/time.Second)+2*p.Quantum {
		t.Errorf("sent %d bytes in %s with a timer 1ms late, want %d", got, duration, want)
	}
}

// TestPacerCatchUpBounded checks that a sender woken far too late catches up
// by at most pacingTimerSlack of its schedule, so that it does not send a
// large burst.
func TestPacerCatchUpBounded(t *testing.T) {
	const rate = 1250000000 // 10 Gbit/s.
	var p pacer
	p.init(0)
	p.setRate(rate, 1460)
	now := at(0)
	for p.ready(now) == 0 {
		p.onSent(p.Quantum, now)
	}
	// Held back; woken 10ms late.
	now = now.Add(p.ready(now) + 10*time.Millisecond)
	burst := 0
	for p.ready(now) == 0 {
		p.onSent(p.Quantum, now)
		burst += p.Quantum
	}
	if max := int(rate*pacingTimerSlack/time.Second) + 2*p.Quantum; burst > max {
		t.Errorf("sent a burst of %d bytes after a late wake-up, want at most %d", burst, max)
	}
	if min := int(rate * pacingTimerSlack / time.Second); burst < min {
		t.Errorf("sent a burst of %d bytes after a late wake-up, want at least %d", burst, min)
	}
}

// TestPacerCoarseClock checks the rate when the clock and timers are coarser
// than the gap between quanta, as on Windows: everything that is due is sent
// at each tick.
func TestPacerCoarseClock(t *testing.T) {
	const (
		rate       = 1250000000 // 10 Gbit/s, 64 KB quanta 52µs apart.
		resolution = 500 * time.Microsecond
		duration   = 100 * time.Millisecond
	)
	var p pacer
	p.init(resolution)
	p.setRate(rate, 1460)
	got := sendFor(&p, duration, 0, resolution)
	want := int(uint64(rate) * uint64(duration) / uint64(time.Second))
	if got < want*99/100 || got > want+int(rate*resolution/time.Second)+2*p.Quantum {
		t.Errorf("sent %d bytes in %s on a %s clock, want %d", got, duration, resolution, want)
	}
}

// TestPacerUnpacedTransmission checks that a transmission that does not wait
// for its turn, such as a retransmission after a timeout, delays the data
// that follows it.
func TestPacerUnpacedTransmission(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1000000, 1000) // 1 MB/s, quantum 2000 bytes.

	// Idle: departs now.
	p.onSent(1000, at(time.Second))
	if got, want := p.ready(at(time.Second)), time.Millisecond; got != want {
		t.Errorf("after 1000 bytes sent while idle: ready = %s, want %s", got, want)
	}
	// Held back: pushes the next quantum further.
	p.onSent(1000, at(time.Second))
	if got, want := p.ready(at(time.Second)), 2*time.Millisecond; got != want {
		t.Errorf("after 1000 more bytes: ready = %s, want %s", got, want)
	}
}

// TestPacerSendOneNow checks that one segment may skip its wait, and that it
// still delays the data that follows it.
func TestPacerSendOneNow(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1000000, 1000) // 1 MB/s, quantum 2000 bytes.
	p.ready(at(0))
	p.onSent(2000, at(0))

	if !p.sendOneNow() {
		t.Fatalf("sendOneNow returned false while waiting")
	}
	if d := p.ready(at(0)); d != 0 {
		t.Fatalf("after sendOneNow: ready = %s, want 0", d)
	}
	// It is one full-sized segment, not a quantum.
	if got := p.limit(5000, 1000); got != 1000 {
		t.Errorf("after sendOneNow: limit(5000, 1000) = %d, want 1000", got)
	}
	p.onSent(1000, at(0))
	p.cancelSendOneNow()
	if got, want := p.ready(at(0)), 3*time.Millisecond; got != want {
		t.Errorf("after the segment: ready = %s, want %s", got, want)
	}

	// Unused, it is withdrawn.
	if !p.sendOneNow() {
		t.Fatalf("sendOneNow returned false while waiting")
	}
	p.cancelSendOneNow()
	if got, want := p.ready(at(0)), 3*time.Millisecond; got != want {
		t.Errorf("after an unused sendOneNow: ready = %s, want %s", got, want)
	}
}

// TestPacerRestart checks that after a restart a quantum may be sent at once.
func TestPacerRestart(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1000000, 1000) // 1 MB/s, quantum 2000 bytes.
	p.ready(at(0))
	p.onSent(2000, at(0))
	p.restart()
	if d := p.ready(at(0)); d != 0 {
		t.Errorf("after restart: ready = %s, want 0", d)
	}
}

func TestPacerSlowRateNoOverflow(t *testing.T) {
	var p pacer
	p.init(0)
	p.setRate(1, 1000) // 1 byte per second.
	p.ready(at(0))
	p.onSent(64<<10, at(0))
	if got, want := p.ready(at(0)), (64<<10)*time.Second; got != want {
		t.Errorf("ready = %s, want %s", got, want)
	}
}

func TestPacingDelaySaturates(t *testing.T) {
	if got := pacingDelay(math.MaxUint64, 1); got != time.Duration(math.MaxInt64) {
		t.Errorf("pacingDelay(MaxUint64, 1) = %d, want %d", got, time.Duration(math.MaxInt64))
	}
	if got, want := pacingDelay(1500, 1500000), time.Millisecond; got != want {
		t.Errorf("pacingDelay(1500, 1500000) = %s, want %s", got, want)
	}
}
