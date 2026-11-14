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
	"container/heap"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Clock is a tcpip.Clock for discrete-event simulation. Its time moves only
// when Step or AdvanceTo is called, and Step jumps straight to the earliest
// timer and runs it on the caller's goroutine.
//
// Unlike faketime.ManualClock, the order of events never depends on goroutine
// scheduling: timers that expire at the same time run one at a time in the
// order they were set, and a timer set to expire now or in the past runs at
// the next Step rather than at once in a new goroutine.
//
// Like faketime.ManualClock, the clock starts at the Unix epoch, and its
// monotonic reading starts at zero.
type Clock struct {
	mu sync.Mutex

	// now is the time since the clock started.
	//
	// +checklocks:mu
	now time.Duration

	// seq numbers timers in the order they were set.
	//
	// +checklocks:mu
	seq uint64

	// timers holds the timers that are set, earliest first.
	//
	// +checklocks:mu
	timers timerHeap
}

// NewClock returns a clock that reads the Unix epoch.
func NewClock() *Clock {
	return &Clock{}
}

// Now implements tcpip.Clock.Now.
func (c *Clock) Now() time.Time {
	return time.Unix(0, 0).Add(c.Elapsed())
}

// NowMonotonic implements tcpip.Clock.NowMonotonic.
func (c *Clock) NowMonotonic() tcpip.MonotonicTime {
	var t tcpip.MonotonicTime
	return t.Add(c.Elapsed())
}

// Elapsed returns the time since the clock started.
func (c *Clock) Elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc implements tcpip.Clock.AfterFunc. f runs on the goroutine that
// calls Step, at least d after now.
func (c *Clock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	t := &timer{c: c, f: f, index: -1}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(t, d)
	return t
}

// Next returns when the earliest timer expires, as a time since the clock
// started, and false if no timer is set.
func (c *Clock) Next() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 {
		return 0, false
	}
	return c.timers[0].at, true
}

// Step moves the clock to the earliest timer and runs it. It returns false,
// and leaves the clock alone, if no timer is set.
func (c *Clock) Step() bool {
	c.mu.Lock()
	if len(c.timers) == 0 {
		c.mu.Unlock()
		return false
	}
	t := heap.Pop(&c.timers).(*timer)
	c.now = t.at
	c.mu.Unlock()
	// Why unlocked: f may set or stop timers.
	t.f()
	return true
}

// AdvanceTo moves the clock to elapsed, a time since the clock started, which
// must not be after the earliest timer. Use Step to run timers.
func (c *Clock) AdvanceTo(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) > 0 && elapsed > c.timers[0].at {
		panic("simnet: AdvanceTo skips a timer")
	}
	c.now = max(c.now, elapsed)
}

// setLocked sets t to expire d after now.
//
// +checklocks:c.mu
func (c *Clock) setLocked(t *timer, d time.Duration) {
	t.at = c.now + max(d, 0)
	t.seq = c.seq
	c.seq++
	heap.Push(&c.timers, t)
}

// timer is a timer of a Clock. Its fields other than c and f are protected by
// c.mu.
type timer struct {
	c *Clock
	f func()

	// at is when the timer expires, as a time since the clock started.
	at time.Duration
	// seq orders timers that expire at the same time.
	seq uint64
	// index is the timer's position in c.timers, or -1 if it is not set.
	index int
}

// Stop implements tcpip.Timer.Stop.
func (t *timer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if t.index < 0 {
		return false
	}
	heap.Remove(&t.c.timers, t.index)
	return true
}

// Reset implements tcpip.Timer.Reset.
func (t *timer) Reset(d time.Duration) {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if t.index >= 0 {
		heap.Remove(&t.c.timers, t.index)
	}
	t.c.setLocked(t, d)
}

// timerHeap orders timers by expiry, then by the order they were set. It
// implements heap.Interface; its users hold the clock's lock.
type timerHeap []*timer

// Len implements sort.Interface.Len.
func (h timerHeap) Len() int { return len(h) }

// Less implements sort.Interface.Less.
func (h timerHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}

// Swap implements sort.Interface.Swap.
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

// Push implements heap.Interface.Push.
func (h *timerHeap) Push(x any) {
	t := x.(*timer)
	t.index = len(*h)
	*h = append(*h, t)
}

// Pop implements heap.Interface.Pop.
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.index = -1
	*h = old[:n-1]
	return t
}
