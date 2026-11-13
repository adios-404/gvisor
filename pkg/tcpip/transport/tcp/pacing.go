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

// This file implements pacing as described in sections 5.6.2 and 5.6.3 of
// https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-07.
//
// A paced sender sends at most one send quantum of data at a time, and after
// sending a quantum waits for as long as the quantum takes to send at the
// pacing rate. Names in comments such as C.pacing_rate are the draft's.
//
// The draft schedules each packet, where a packet may be a GSO aggregate of up
// to one quantum. Netstack mostly sends full-sized segments one by one, and
// waking a timer for each of them would cost too much CPU time at high rates
// and is impossible on a coarse clock. So the quantum is used as the unit of
// scheduling instead: when a quantum is due, segments are sent until it is
// used up, and the next quantum is due once the data sent so far would have
// left at the pacing rate. Section 5.6.3 allows such alternate approaches.

const (
	// sendQuantumTime is the time it takes to send a send quantum at the
	// pacing rate, before the limits below are applied: the 1ms of
	// SetSendQuantum().
	sendQuantumTime = time.Millisecond

	// maxSendQuantum is the largest send quantum, in bytes: the 64 KBytes of
	// SetSendQuantum().
	maxSendQuantum = 64 << 10

	// pacingTimerSlack is how late the timer that wakes a held-back sender
	// may fire, and so how far behind its schedule the sender may catch up.
	// Go's timers fire this late on Linux when the process has nothing else
	// to do: the runtime then waits in epoll, which counts in milliseconds.
	// Measured with Go 1.27.3 on x86 Linux (14 Nov 2026), a 20µs timer fired
	// a median 1.03ms late, a 1ms timer 76µs late.
	pacingTimerSlack = time.Millisecond
)

// pacer schedules the departure of data so that it leaves no faster than the
// pacing rate.
//
// +stateify savable
type pacer struct {
	// TCPPacingState is the state that the TCP probe reports. Pacing is off
	// while Rate is zero.
	TCPPacingState

	// burst is the data, in bytes, that may still be sent as part of the
	// current quantum.
	burst int

	// oneNow is true while sendOneNow lets one full-sized segment skip
	// its wait.
	oneNow bool

	// behind is true from when the sender is told to wait until the data it
	// sends catches up with the schedule, that is until C.next_send_time is
	// no longer in the past after a transmission.
	behind bool

	// resolution is an upper bound on how coarse the clock and timers are.
	resolution time.Duration
}

// init initializes a pacer that is off. resolution is an upper bound on the
// quantization of the clock that will be passed to it and of the timers that
// wake the sender.
func (p *pacer) init(resolution time.Duration) {
	*p = pacer{resolution: resolution}
}

// setRate sets the pacing rate, in bytes per second, and the send quantum
// for that rate. smss is the sender's maximum segment size. A rate of zero
// turns pacing off.
func (p *pacer) setRate(rate uint64, smss int) {
	p.Rate = rate

	// SetSendQuantum(), section 5.6.3.
	quantum := min(bytesInTime(rate, sendQuantumTime), maxSendQuantum)
	p.Quantum = max(int(quantum), 2*smss)
}

// ready returns how long the sender must wait at time now before it may send
// more data, or zero if it may send now. When it returns zero and the
// previous quantum has been used up, a new quantum starts.
//
// Section 5.6.2 starts each departure at max(Now(), C.next_send_time), which
// assumes that a packet can be sent at exactly its departure time. Netstack
// sends when a timer fires, and a timer can fire late, or only at a tick of a
// coarse clock long after the departure time. Each such delay would be added
// to the gap between quanta and lower the rate: on Linux, where Go's timers
// fire up to about 1ms late, a 10 Gbit/s sender would reach a tenth of its
// rate. So while a sender that was held back catches up, a quantum starts at
// C.next_send_time even if that is in the past, by up to the longest of the
// time it takes to send one quantum, the clock's resolution and
// pacingTimerSlack, and what is due is sent at once. A sender that was not
// held back, for example because it had nothing to send, starts at Now() as
// in the draft, so idle time is not saved up for a burst.
func (p *pacer) ready(now tcpip.MonotonicTime) time.Duration {
	if p.Rate == 0 || p.burst > 0 {
		return 0
	}
	if now.Before(p.NextSendTime) {
		p.behind = true
		return p.NextSendTime.Sub(now)
	}
	start := now
	if p.behind {
		start = now.Add(-max(pacingDelay(uint64(p.Quantum), p.Rate), p.resolution, pacingTimerSlack))
	}
	if p.NextSendTime.Before(start) {
		p.NextSendTime = start
	}
	p.burst = p.Quantum
	return 0
}

// limit returns the most data, in bytes, that may be sent in one segment
// given that up to n bytes could otherwise be sent. It must only be called
// after ready returned zero. smss is the sender's maximum segment size.
//
// A segment is at most one quantum, and it is not shortened to fit what is
// left of the current quantum: the excess delays the next quantum instead,
// so less than two quanta leave at once and the rate is kept. Shortening
// would cost the most with segmentation offload at high rates, where the
// quantum is 64KB and a segment a little less: every quantum would go out as
// one large segment and one small one, two writes to the link instead of one.
func (p *pacer) limit(n, smss int) int {
	if p.Rate == 0 {
		return n
	}
	if p.oneNow {
		return min(n, smss)
	}
	return min(n, p.Quantum)
}

// sendOneNow lets one full-sized segment go without waiting for its departure
// time, and reports whether that changed anything. The segment still delays
// the data that follows it. If sendOneNow returns true, cancelSendOneNow must
// be called once the segment has been sent, or could not be.
func (p *pacer) sendOneNow() bool {
	if p.Rate == 0 || p.burst != 0 {
		return false
	}
	p.burst = 1
	p.oneNow = true
	return true
}

// cancelSendOneNow withdraws what sendOneNow allowed if no segment used it.
func (p *pacer) cancelSendOneNow() {
	if p.oneNow {
		p.oneNow = false
		p.burst = 0
	}
}

// restart forgets the schedule, so that a quantum may be sent at once. It is
// used after restore, since departure times from before the save mean
// nothing to the pacing timer, which is not saved.
func (p *pacer) restart() {
	p.NextSendTime = tcpip.MonotonicTime{}
	p.burst = 0
	p.oneNow = false
	p.behind = false
}

// onSent accounts for size bytes sent at time now, whether or not the
// transmission waited for ready: C.next_send_time advances by
// packet.size / C.pacing_rate (section 5.6.2).
func (p *pacer) onSent(size int, now tcpip.MonotonicTime) {
	if p.Rate == 0 {
		return
	}
	if p.burst == 0 && !p.behind && p.NextSendTime.Before(now) {
		// A transmission that did not wait for ready, such as a
		// retransmission after a timeout, departs at Now().
		p.NextSendTime = now
	}
	p.burst = max(p.burst-size, 0)
	p.oneNow = false
	p.NextSendTime = p.NextSendTime.Add(pacingDelay(uint64(size), p.Rate))
	if !p.NextSendTime.Before(now) {
		p.behind = false
	}
}

// pacingDelay returns the time it takes to send n bytes at rate bytes per
// second, which must be positive. The result saturates instead of
// overflowing.
func pacingDelay(n, rate uint64) time.Duration {
	hi, lo := bits.Mul64(n, uint64(time.Second))
	if hi >= rate {
		return math.MaxInt64
	}
	d, _ := bits.Div64(hi, lo, rate)
	if d > math.MaxInt64 {
		return math.MaxInt64
	}
	return time.Duration(d)
}

// bytesInTime returns the number of bytes sent in d at rate bytes per second,
// saturating instead of overflowing.
func bytesInTime(rate uint64, d time.Duration) uint64 {
	hi, lo := bits.Mul64(rate, uint64(d))
	if hi >= uint64(time.Second) {
		return math.MaxUint64
	}
	n, _ := bits.Div64(hi, lo, uint64(time.Second))
	return n
}
