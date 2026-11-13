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
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// This file implements delivery rate sampling as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-07#section-4.1.
//
// The sampler estimates the rate at which the network delivers the
// connection's data. Each transmitted segment records how much data had been
// delivered when it was sent. When the segment is acknowledged, the data
// delivered since then, divided by the time that took, is a delivery rate
// sample.
//
// All amounts are in bytes and all rates are in bytes per second. Names in
// comments such as C.delivered, P.delivered and RS.interval are the draft's.

// segRate is the delivery rate state kept for each transmitted segment. A
// segment that carries several packets (GSO) is tracked as one aggregate, as
// recommended by section 4.1.3.1.
//
// See section 4.1.2.1.2, "Per-packet (P) state".
//
// +stateify savable
type segRate struct {
	// delivered is P.delivered: C.delivered when the segment was last sent.
	delivered uint64

	// deliveredTime is P.delivered_time: C.delivered_time when the segment
	// was last sent.
	deliveredTime tcpip.MonotonicTime

	// firstSendTime is P.first_send_time: C.first_send_time when the segment
	// was last sent.
	firstSendTime tcpip.MonotonicTime

	// txInFlight is P.tx_in_flight: C.inflight just after the segment was
	// last sent, including the segment itself.
	txInFlight uint64

	// lost is P.lost: C.lost when the segment was last sent.
	lost uint64

	// appLimited is P.is_app_limited.
	appLimited bool

	// inFlight is true while the segment's bytes are counted in
	// rateSampler.InFlight.
	inFlight bool

	// lostPending is true while the segment's bytes are counted in
	// rateSampler.lostPending.
	lostPending bool

	// done is true once the segment has been counted as delivered. The draft
	// encodes this as P.delivered_time == 0, which cannot be used here
	// because a monotonic time of zero is a valid time.
	done bool

	// unsampled is true if the segment was last sent before sampling was
	// enabled, so that no snapshot was taken. Its delivery is counted, but no
	// sample is based on it.
	unsampled bool
}

// rateSample is the result of processing one ACK.
//
// See section 4.1.2.1.3, "Rate Sample (rs) Output".
//
// +stateify savable
type rateSample struct {
	// hasData is true if the ACK newly delivered at least one whole segment,
	// so that the fields taken from that segment are valid.
	hasData bool

	// deliveryRate is RS.delivery_rate in bytes per second. It is zero when
	// the ACK did not yield a reliable sample.
	deliveryRate uint64

	// isAppLimited is RS.is_app_limited.
	isAppLimited bool

	// interval is RS.interval.
	interval time.Duration

	// delivered is RS.delivered: the data delivered over interval.
	delivered uint64

	// priorDelivered is RS.prior_delivered.
	priorDelivered uint64

	// priorTime is RS.prior_time.
	priorTime tcpip.MonotonicTime

	// sendElapsed is RS.send_elapsed.
	sendElapsed time.Duration

	// ackElapsed is RS.ack_elapsed.
	ackElapsed time.Duration

	// lastAckedEnd is RS.last_acked_packet_id: the ending sequence number of
	// the most recently sent segment that this ACK delivered.
	lastAckedEnd seqnum.Value

	// newlyAcked is RS.newly_acked: the data this ACK newly delivered.
	newlyAcked uint64

	// txInFlight is RS.tx_in_flight.
	txInFlight uint64

	// lost is RS.lost: the data declared lost since the most recently sent
	// delivered segment was transmitted.
	lost uint64

	// priorLost is P.lost of the most recently sent delivered segment.
	priorLost uint64

	// rtt is RS.rtt: the round-trip time of the most recently sent segment
	// this ACK delivered, or -1 if that segment had been retransmitted, which
	// makes its round-trip time ambiguous (Karn's algorithm).
	rtt time.Duration
}

// rateSampler samples the delivery rate of a connection.
//
// The sender calls the sampler only if it is enabled. Its state is then
// updated on every segment sent and every ACK, a measurable cost for a sender
// that does not use the samples, so it is enabled only on request.
//
// +stateify savable
type rateSampler struct {
	// enabled is true if the sender calls the sampler. It is set when the
	// sender is created.
	enabled bool

	// TCPDeliveryRateState is the per-connection state. See section
	// 4.1.2.1.1, "Per-connection (C) state".
	TCPDeliveryRateState

	// rs is the sample for the ACK being processed.
	rs rateSample
}

// onSent records the delivery state in a segment of size bytes that is being
// transmitted at time now.
//
// See section 4.1.2.2, OnPacketSent().
func (r *rateSampler) onSent(p *segRate, size int, now tcpip.MonotonicTime) {
	if p.done {
		// The segment was SACKed and is sent again only because the SACK
		// information has been discarded. Its delivery is already counted.
		return
	}
	n := uint64(size)
	if p.lostPending {
		p.lostPending = false
		r.LostPending = subClamped(r.LostPending, n)
	}
	if r.InFlight == 0 {
		// Nothing is in flight, so the sampling interval starts now.
		r.FirstSendTime = now
		r.DeliveredTime = now
	}
	if !p.inFlight {
		p.inFlight = true
		r.InFlight += n
	}
	p.firstSendTime = r.FirstSendTime
	p.deliveredTime = r.DeliveredTime
	p.delivered = r.Delivered
	p.appLimited = r.AppLimited != 0
	p.txInFlight = r.InFlight
	p.lost = r.Lost
	p.unsampled = false
}

// beginACK starts the sample for a newly received ACK.
//
// See section 4.1.2.3, InitRateSample().
func (r *rateSampler) beginACK() {
	r.rs = rateSample{rtt: -1}
}

// onDelivered is called for each segment that the ACK being processed newly
// acknowledges in full, cumulatively or selectively. size, sendTime and end
// are the segment's payload size, last transmit time and ending sequence
// number. now is the arrival time of the ACK. once is true if the segment was
// transmitted only once, so that now - sendTime is a valid RTT sample.
//
// See section 4.1.2.3, UpdateRateSample().
func (r *rateSampler) onDelivered(p *segRate, size int, sendTime tcpip.MonotonicTime, end seqnum.Value, now tcpip.MonotonicTime, once bool) {
	if p.done {
		return
	}
	p.done = true
	r.deliver(p, uint64(size), now)
	if p.unsampled {
		return
	}

	// Base the sample on the most recently sent segment.
	isNewest := sendTime.After(r.FirstSendTime) ||
		(sendTime == r.FirstSendTime && r.rs.lastAckedEnd.LessThan(end))
	if r.rs.hasData && !isNewest {
		return
	}
	r.rs.hasData = true
	r.rs.priorDelivered = p.delivered
	r.rs.priorTime = p.deliveredTime
	r.rs.isAppLimited = p.appLimited
	r.rs.sendElapsed = sendTime.Sub(p.firstSendTime)
	r.rs.ackElapsed = r.DeliveredTime.Sub(p.deliveredTime)
	r.rs.lastAckedEnd = end
	r.rs.txInFlight = p.txInFlight
	r.rs.priorLost = p.lost
	r.rs.rtt = -1
	if once {
		r.rs.rtt = now.Sub(sendTime)
	}
	r.FirstSendTime = sendTime
}

// onPartialDelivered is called when the ACK being processed cumulatively
// acknowledges only the first n bytes of a segment. The bytes are counted as
// delivered, but the segment stays outstanding and does not contribute its
// send-time state to the sample.
func (r *rateSampler) onPartialDelivered(p *segRate, n int, now tcpip.MonotonicTime) {
	if p.done {
		return
	}
	r.deliver(p, uint64(n), now)
}

// deliver counts n bytes of a segment as delivered at time now.
func (r *rateSampler) deliver(p *segRate, n uint64, now tcpip.MonotonicTime) {
	if p.inFlight {
		r.InFlight = subClamped(r.InFlight, n)
		p.inFlight = !p.done
	}
	if p.lostPending {
		// Declared lost, yet delivered before it was retransmitted.
		r.LostPending = subClamped(r.LostPending, n)
		p.lostPending = !p.done
	}
	r.Delivered += n
	r.DeliveredTime = now
	r.rs.newlyAcked += n
}

// onLost is called when a segment of size bytes is declared lost. It returns
// false if the segment was not in flight, in which case its loss has already
// been counted, or it has been delivered.
func (r *rateSampler) onLost(p *segRate, size int) bool {
	if p.done || !p.inFlight {
		return false
	}
	n := uint64(size)
	p.inFlight = false
	p.lostPending = true
	r.InFlight = subClamped(r.InFlight, n)
	r.Lost += n
	r.LostPending += n
	return true
}

// adopt starts tracking a segment of size bytes that was sent before sampling
// was enabled. It is counted as in flight unless it has already been
// selectively acknowledged (sacked) or is waiting to be retransmitted (lost).
// Bytes delivered or lost before sampling was enabled are not counted.
//
// Segments are adopted in the order they were sent. Each records the bytes in
// flight and lost so far, as if the adopted segments had been sent back to
// back, so that a loss of one can still be compared with the data in flight
// (draft HandleLostPacket()). Its send and delivery times are unknown, so no
// rate sample is based on it.
func (r *rateSampler) adopt(p *segRate, size int, sacked, lost bool) {
	*p = segRate{unsampled: true}
	n := uint64(size)
	switch {
	case sacked:
		p.done = true
	case lost:
		p.lostPending = true
		r.LostPending += n
	default:
		p.inFlight = true
		r.InFlight += n
	}
	p.txInFlight = r.InFlight
	p.lost = r.Lost
}

// onRTT is called with each RTT sample to maintain C.min_rtt. A sample that
// is not positive is ignored: unknownRTT, and the zero that millisecond
// timestamps give on a path faster than that.
func (r *rateSampler) onRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	if r.MinRTT == 0 || rtt < r.MinRTT {
		r.MinRTT = rtt
	}
}

// endACK completes the sample once every segment newly acknowledged by the
// ACK being processed has been passed to onDelivered. The returned sample is
// valid until the next call to beginACK.
//
// See section 4.1.2.3, GenerateRateSample().
func (r *rateSampler) endACK() *rateSample {
	rs := &r.rs

	// Clear the application-limited mark once all the data that was in
	// flight when the application ran dry has been delivered.
	if r.AppLimited != 0 && r.Delivered > r.AppLimited {
		r.AppLimited = 0
	}

	if !rs.hasData {
		// Nothing was delivered on this ACK.
		return rs
	}

	// Use the longer of the send and ACK intervals, so that neither a burst
	// of transmissions nor a burst of ACKs inflates the rate.
	//
	// Delivery times are ACK arrival times while send times are read when a
	// segment is sent, so an ACK that waited to be processed can carry a time
	// earlier than a transmission that preceded its processing. That can make
	// ackElapsed negative, in which case sendElapsed is used.
	rs.interval = max(rs.sendElapsed, rs.ackElapsed)
	rs.delivered = r.Delivered - rs.priorDelivered
	rs.lost = r.Lost - rs.priorLost

	// The time from the only transmission of the newest delivered segment
	// to this ACK is an RTT sample too, and the minimum RTT must follow it.
	// The samples passed to onRTT come from TCP timestamps when the
	// connection uses them, and those count in milliseconds: on a path with
	// a round trip of 100us they read 1ms, and with that as the minimum the
	// check below would throw away every sample taken over less than 1ms. A
	// paced sender whose bursts are each acknowledged before the next one
	// leaves has only such samples, and would never get a delivery rate.
	r.onRTT(rs.rtt)

	// An interval shorter than the minimum RTT is implausible. It happens
	// when a retransmitted segment is acknowledged by the ACK of its
	// original transmission.
	if rs.interval < r.MinRTT {
		return rs
	}
	if rs.interval <= 0 {
		return rs
	}
	rs.deliveryRate = bytesPerSecond(rs.delivered, rs.interval)

	// Report the most recent sample that was not application-limited, or an
	// application-limited one that is at least as high as the reported rate:
	// an application-limited sample is only a lower bound on what the path
	// can deliver.
	if !rs.isAppLimited || rs.deliveryRate >= r.Rate {
		r.Rate = rs.deliveryRate
		r.RateAppLimited = rs.isAppLimited
	}
	return rs
}

// checkAppLimited marks the connection as application-limited if it has run
// out of data to send while the congestion window, cwndBytes, would have
// allowed more. noUnsentData is true if there is no data waiting to be sent
// for the first time.
//
// The draft also requires C.pending_transmissions to be zero. Netstack hands
// segments to the link endpoint as it sends them and has no view of queues
// below the transport layer, so that is always taken to be the case.
//
// See section 4.1.2.4, CheckIfApplicationLimited().
func (r *rateSampler) checkAppLimited(noUnsentData bool, cwndBytes uint64) {
	if !noUnsentData || r.InFlight >= cwndBytes || r.LostPending != 0 {
		return
	}
	r.markAppLimited()
}

// markAppLimited marks the connection as application-limited until the data
// now in flight has been delivered.
//
// See section 4.1.2.4, MarkConnectionAppLimited().
func (r *rateSampler) markAppLimited() {
	r.AppLimited = max(r.Delivered+r.InFlight, 1)
}

// reset is called when no sent data remains unacknowledged, at which point
// nothing can be in flight or waiting to be retransmitted.
func (r *rateSampler) reset() {
	r.InFlight = 0
	r.LostPending = 0
}

// subClamped returns a-b, or zero if b is greater than a.
func subClamped(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

// bytesPerSecond returns the rate at which n bytes are delivered in d, which
// must be positive. The result saturates instead of overflowing.
func bytesPerSecond(n uint64, d time.Duration) uint64 {
	hi, lo := bits.Mul64(n, uint64(time.Second))
	if hi >= uint64(d) {
		return math.MaxUint64
	}
	rate, _ := bits.Div64(hi, lo, uint64(d))
	return rate
}
