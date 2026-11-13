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
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// ratePacket is a transmitted packet in a rateSampler test.
type ratePacket struct {
	rate     segRate
	size     int
	sendTime tcpip.MonotonicTime
	end      seqnum.Value
}

// rateTest drives a rateSampler with hand-built send and ACK sequences. Its
// clock starts at the zero time, so that nothing can depend on timestamps
// being non-zero.
type rateTest struct {
	r       rateSampler
	now     tcpip.MonotonicTime
	nextSeq seqnum.Value
}

func (rt *rateTest) advance(d time.Duration) {
	rt.now = rt.now.Add(d)
}

func (rt *rateTest) send(size int) *ratePacket {
	rt.nextSeq = rt.nextSeq.Add(seqnum.Size(size))
	p := &ratePacket{size: size, sendTime: rt.now, end: rt.nextSeq}
	rt.r.onSent(&p.rate, size, rt.now)
	return p
}

// ack processes one ACK that newly delivers pkts and returns a copy of the
// resulting rate sample.
func (rt *rateTest) ack(pkts ...*ratePacket) rateSample {
	rt.r.beginACK()
	for _, p := range pkts {
		rt.r.onDelivered(&p.rate, p.size, p.sendTime, p.end, rt.now, true /* once */)
	}
	return *rt.r.endACK()
}

func TestRateSamplerSteadyRate(t *testing.T) {
	// One 1000 byte packet is sent every millisecond and each is ACKed 10ms
	// after it was sent, so the path delivers 1,000,000 bytes per second.
	const (
		size    = 1000
		packets = 40
		delay   = 10
	)
	rt := rateTest{}
	var sent []*ratePacket
	for ms := 0; ms < packets+delay; ms++ {
		if ms >= delay {
			p := sent[ms-delay]
			rs := rt.ack(p)
			if !rs.hasData {
				t.Fatalf("ack at %dms: got hasData = false, want true", ms)
			}
			if got, want := rs.newlyAcked, uint64(size); got != want {
				t.Errorf("ack at %dms: got newlyAcked = %d, want %d", ms, got, want)
			}
			// A packet sent after the first ACK arrived was sent with a full
			// round trip of delivery history behind it.
			if ms >= 2*delay {
				if got, want := rs.deliveryRate, uint64(1_000_000); got != want {
					t.Errorf("ack at %dms: got deliveryRate = %d, want %d", ms, got, want)
				}
				if got, want := rs.interval, delay*time.Millisecond; got != want {
					t.Errorf("ack at %dms: got interval = %s, want %s", ms, got, want)
				}
				if got, want := rs.txInFlight, uint64(delay*size); got != want {
					t.Errorf("ack at %dms: got txInFlight = %d, want %d", ms, got, want)
				}
			}
		}
		if ms < packets {
			sent = append(sent, rt.send(size))
		}
		rt.advance(time.Millisecond)
	}
	if got, want := rt.r.Delivered, uint64(packets*size); got != want {
		t.Errorf("got delivered = %d, want %d", got, want)
	}
	if rt.r.InFlight != 0 {
		t.Errorf("got inflight = %d, want 0", rt.r.InFlight)
	}
	if got, want := rt.r.Rate, uint64(1_000_000); got != want {
		t.Errorf("got reported rate = %d, want %d", got, want)
	}
	if rt.r.RateAppLimited {
		t.Errorf("got rateAppLimited = true, want false")
	}
}

func TestRateSamplerUsesLongerInterval(t *testing.T) {
	t.Run("ACKInterval", func(t *testing.T) {
		// A burst sent in one instant and ACKed 1ms apart: the send interval
		// is zero, so the ACK interval sets the rate.
		rt := rateTest{}
		var sent []*ratePacket
		for i := 0; i < 5; i++ {
			sent = append(sent, rt.send(1000))
		}
		for i, p := range sent {
			rt.advance(time.Millisecond)
			rs := rt.ack(p)
			if got, want := rs.interval, time.Duration(i+1)*time.Millisecond; got != want {
				t.Errorf("ack %d: got interval = %s, want %s", i, got, want)
			}
			if got, want := rs.deliveryRate, uint64(1_000_000); got != want {
				t.Errorf("ack %d: got deliveryRate = %d, want %d", i, got, want)
			}
		}
	})
	t.Run("SendInterval", func(t *testing.T) {
		// c is sent 10ms after the flight began but its ACK arrives only 2ms
		// after the previous delivery (ACK compression). The longer send
		// interval must be used.
		rt := rateTest{}
		a := rt.send(1000)
		rt.advance(8 * time.Millisecond)
		b := rt.send(1000)
		rt.advance(2 * time.Millisecond)
		rt.ack(a)
		c := rt.send(1000)
		rt.advance(time.Millisecond)
		rt.ack(b)
		rt.advance(time.Millisecond)
		rs := rt.ack(c)
		if got, want := rs.sendElapsed, 10*time.Millisecond; got != want {
			t.Errorf("got sendElapsed = %s, want %s", got, want)
		}
		if got, want := rs.ackElapsed, 2*time.Millisecond; got != want {
			t.Errorf("got ackElapsed = %s, want %s", got, want)
		}
		if got, want := rs.delivered, uint64(2000); got != want {
			t.Errorf("got delivered = %d, want %d", got, want)
		}
		if got, want := rs.deliveryRate, uint64(200_000); got != want {
			t.Errorf("got deliveryRate = %d, want %d", got, want)
		}
	})
}

func TestRateSamplerStretchACKUsesNewestPacket(t *testing.T) {
	rt := rateTest{}
	var sent []*ratePacket
	for i := 0; i < 4; i++ {
		sent = append(sent, rt.send(1000))
		rt.advance(time.Millisecond)
	}
	rt.advance(6 * time.Millisecond)
	// Deliver out of order: the sample must still be based on the most
	// recently sent packet.
	rs := rt.ack(sent[3], sent[0], sent[2], sent[1])
	if got, want := rs.lastAckedEnd, sent[3].end; got != want {
		t.Errorf("got lastAckedEnd = %d, want %d", got, want)
	}
	if got, want := rs.newlyAcked, uint64(4000); got != want {
		t.Errorf("got newlyAcked = %d, want %d", got, want)
	}
	if got, want := rs.sendElapsed, 3*time.Millisecond; got != want {
		t.Errorf("got sendElapsed = %s, want %s", got, want)
	}
	if got, want := rt.r.FirstSendTime, sent[3].sendTime; got != want {
		t.Errorf("got firstSendTime = %v, want %v", got, want)
	}
}

func TestRateSamplerCountsSegmentOnce(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1000)
	q := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	// SACKed first.
	rt.ack(p)
	rt.advance(time.Millisecond)
	// Then covered by the cumulative ACK.
	rs := rt.ack(p, q)
	if got, want := rs.newlyAcked, uint64(1000); got != want {
		t.Errorf("got newlyAcked = %d, want %d", got, want)
	}
	if got, want := rt.r.Delivered, uint64(2000); got != want {
		t.Errorf("got delivered = %d, want %d", got, want)
	}
	if rt.r.InFlight != 0 {
		t.Errorf("got inflight = %d, want 0", rt.r.InFlight)
	}

	// A delivered segment that is sent again (the SACK scoreboard is dropped
	// on a retransmission timeout) is neither in flight nor delivered twice.
	rt.r.onSent(&p.rate, p.size, rt.now)
	if rt.r.InFlight != 0 {
		t.Errorf("after resending a delivered segment: got inflight = %d, want 0", rt.r.InFlight)
	}
	rt.ack(p)
	if got, want := rt.r.Delivered, uint64(2000); got != want {
		t.Errorf("after resending a delivered segment: got delivered = %d, want %d", got, want)
	}
}

func TestRateSamplerEmptyAck(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	rt.ack(p)
	before := rt.r
	rt.advance(time.Millisecond)
	rs := rt.ack()
	if rs.hasData {
		t.Errorf("got hasData = true, want false")
	}
	if rs.deliveryRate != 0 || rs.newlyAcked != 0 || rs.delivered != 0 {
		t.Errorf("got sample %+v, want an empty sample", rs)
	}
	if rt.r.Delivered != before.Delivered || rt.r.DeliveredTime != before.DeliveredTime || rt.r.Rate != before.Rate {
		t.Errorf("empty ACK changed the sampler: got %+v, want %+v", rt.r, before)
	}
}

func TestRateSamplerAppLimited(t *testing.T) {
	const cwnd = 10_000
	rt := rateTest{}

	// Unsent data, a full window or unretransmitted losses all mean the
	// application is not what limits the connection.
	rt.r.checkAppLimited(false /* noUnsentData */, cwnd)
	if rt.r.AppLimited != 0 {
		t.Fatalf("with unsent data: got appLimited = %d, want 0", rt.r.AppLimited)
	}
	rt.r.InFlight = cwnd
	rt.r.checkAppLimited(true, cwnd)
	if rt.r.AppLimited != 0 {
		t.Fatalf("with a full window: got appLimited = %d, want 0", rt.r.AppLimited)
	}
	rt.r.InFlight = 0
	rt.r.LostPending = 1
	rt.r.checkAppLimited(true, cwnd)
	if rt.r.AppLimited != 0 {
		t.Fatalf("with losses to retransmit: got appLimited = %d, want 0", rt.r.AppLimited)
	}
	rt.r.LostPending = 0

	// Nothing delivered and nothing in flight still has to produce a mark.
	rt.r.checkAppLimited(true, cwnd)
	if got, want := rt.r.AppLimited, uint64(1); got != want {
		t.Fatalf("got appLimited = %d, want %d", got, want)
	}

	a := rt.send(1000)
	b := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	if rs := rt.ack(a); !rs.isAppLimited {
		t.Errorf("first packet after the mark: got isAppLimited = false, want true")
	}
	if rt.r.AppLimited != 0 {
		t.Errorf("after delivering past the mark: got appLimited = %d, want 0", rt.r.AppLimited)
	}
	// b was sent while the mark was set, so its sample is still limited.
	if rs := rt.ack(b); !rs.isAppLimited {
		t.Errorf("second packet sent under the mark: got isAppLimited = false, want true")
	}
	c := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	if rs := rt.ack(c); rs.isAppLimited {
		t.Errorf("packet sent after the mark cleared: got isAppLimited = true, want false")
	}

	// The mark covers everything in flight when the application ran dry.
	d := rt.send(1000)
	rt.r.checkAppLimited(true, cwnd)
	if got, want := rt.r.AppLimited, rt.r.Delivered+1000; got != want {
		t.Errorf("got appLimited = %d, want %d", got, want)
	}
	rt.advance(10 * time.Millisecond)
	rt.ack(d)
	if rt.r.AppLimited == 0 {
		t.Errorf("got appLimited = 0 once delivered reached the mark, want it kept until delivered exceeds the mark")
	}
}

func TestRateSamplerMinRTTFilter(t *testing.T) {
	rt := rateTest{}
	rt.r.onRTT(20 * time.Millisecond)
	rt.r.onRTT(50 * time.Millisecond)
	rt.r.onRTT(unknownRTT)
	if got, want := rt.r.MinRTT, 20*time.Millisecond; got != want {
		t.Fatalf("got minRTT = %s, want %s", got, want)
	}
	// A retransmitted segment is acknowledged 5ms after its last
	// transmission, by the ACK of an earlier one.
	p := rt.send(1000)
	rt.advance(5 * time.Millisecond)
	rt.r.beginACK()
	rt.r.onDelivered(&p.rate, p.size, p.sendTime, p.end, rt.now, false /* once */)
	rs := *rt.r.endACK()
	if !rs.hasData || rs.deliveryRate != 0 {
		t.Errorf("interval below minRTT: got hasData = %t, deliveryRate = %d, want true, 0", rs.hasData, rs.deliveryRate)
	}
	if rt.r.Rate != 0 {
		t.Errorf("got reported rate = %d, want 0", rt.r.Rate)
	}
	if got, want := rt.r.MinRTT, 20*time.Millisecond; got != want {
		t.Errorf("after a retransmitted segment: got minRTT = %s, want %s", got, want)
	}
	q := rt.send(1000)
	rt.advance(20 * time.Millisecond)
	if rs := rt.ack(q); rs.deliveryRate == 0 {
		t.Errorf("interval of minRTT: got deliveryRate = 0, want non-zero")
	}
}

// TestRateSamplerMinRTTFromSegments checks that the minimum RTT also follows
// the send-to-ACK time of the segments themselves. The RTT samples that the
// sender passes to onRTT come from TCP timestamps when the connection uses
// them, and those count in milliseconds: on a path with a round trip of
// 100us they read 1ms (or zero), and with a minimum of 1ms every sample taken
// over a shorter interval would be thrown away.
func TestRateSamplerMinRTTFromSegments(t *testing.T) {
	rt := rateTest{}
	const rtt = 100 * time.Microsecond
	for i := 0; i < 5; i++ {
		p := rt.send(1000)
		rt.advance(rtt)
		rt.r.beginACK()
		rt.r.onDelivered(&p.rate, p.size, p.sendTime, p.end, rt.now, true /* once */)
		rt.r.onRTT(time.Millisecond)
		rs := *rt.r.endACK()
		if want := uint64(1000 * time.Second / rtt); rs.deliveryRate != want {
			t.Fatalf("packet %d: got deliveryRate = %d, want %d", i, rs.deliveryRate, want)
		}
		rt.advance(time.Millisecond)
	}
	if got := rt.r.MinRTT; got != rtt {
		t.Errorf("got minRTT = %s, want %s", got, rtt)
	}
}

func TestRateSamplerLossAccounting(t *testing.T) {
	rt := rateTest{}
	a := rt.send(1000)
	b := rt.send(1000)
	c := rt.send(1000)
	if got, want := rt.r.InFlight, uint64(3000); got != want {
		t.Fatalf("got inflight = %d, want %d", got, want)
	}

	rt.r.onLost(&a.rate, a.size)
	if rt.r.InFlight != 2000 || rt.r.Lost != 1000 || rt.r.LostPending != 1000 {
		t.Fatalf("after a loss: got inflight = %d, lost = %d, lostPending = %d, want 2000, 1000, 1000", rt.r.InFlight, rt.r.Lost, rt.r.LostPending)
	}
	// Marking it lost again changes nothing.
	rt.r.onLost(&a.rate, a.size)
	if rt.r.InFlight != 2000 || rt.r.Lost != 1000 || rt.r.LostPending != 1000 {
		t.Fatalf("after a repeated loss: got inflight = %d, lost = %d, lostPending = %d, want 2000, 1000, 1000", rt.r.InFlight, rt.r.Lost, rt.r.LostPending)
	}

	// Retransmit the lost packet.
	rt.advance(10 * time.Millisecond)
	a.sendTime = rt.now
	rt.r.onSent(&a.rate, a.size, rt.now)
	if rt.r.InFlight != 3000 || rt.r.Lost != 1000 || rt.r.LostPending != 0 {
		t.Fatalf("after the retransmission: got inflight = %d, lost = %d, lostPending = %d, want 3000, 1000, 0", rt.r.InFlight, rt.r.Lost, rt.r.LostPending)
	}

	// b was sent before the loss was declared, so its sample reports it.
	rs := rt.ack(b)
	if got, want := rs.lost, uint64(1000); got != want {
		t.Errorf("got rs.lost = %d, want %d", got, want)
	}
	// The retransmission was sent after it.
	rt.advance(10 * time.Millisecond)
	rs = rt.ack(a)
	if rs.lost != 0 {
		t.Errorf("got rs.lost = %d, want 0", rs.lost)
	}

	// A packet declared lost that is delivered before it is retransmitted
	// leaves nothing to retransmit.
	rt.r.onLost(&c.rate, c.size)
	rt.r.beginACK()
	rt.r.onDelivered(&c.rate, c.size, c.sendTime, c.end, rt.now, true /* once */)
	rt.r.endACK()
	if rt.r.InFlight != 0 || rt.r.LostPending != 0 {
		t.Errorf("got inflight = %d, lostPending = %d, want 0, 0", rt.r.InFlight, rt.r.LostPending)
	}
	if got, want := rt.r.Delivered, uint64(3000); got != want {
		t.Errorf("got delivered = %d, want %d", got, want)
	}
}

func TestRateSamplerLossInferredFromRetransmit(t *testing.T) {
	// Without RACK no segment is marked lost. A retransmission in recovery of
	// a segment that is still counted in flight is the loss signal: the
	// sender declares the segment lost and then sends it again.
	rt := rateTest{}
	a := rt.send(1000)
	rt.send(1000)
	rt.advance(10 * time.Millisecond)
	if !rt.r.onLost(&a.rate, a.size) {
		t.Fatalf("onLost of a segment in flight returned false")
	}
	rt.r.onSent(&a.rate, a.size, rt.now)
	if rt.r.InFlight != 2000 || rt.r.Lost != 1000 || rt.r.LostPending != 0 {
		t.Errorf("got inflight = %d, lost = %d, lostPending = %d, want 2000, 1000, 0", rt.r.InFlight, rt.r.Lost, rt.r.LostPending)
	}
	// A second retransmission of a segment that is back in flight is another
	// loss of the same bytes.
	if !rt.r.onLost(&a.rate, a.size) {
		t.Fatalf("onLost of a retransmitted segment in flight returned false")
	}
	rt.r.onSent(&a.rate, a.size, rt.now)
	if got, want := rt.r.Lost, uint64(2000); got != want {
		t.Errorf("got lost = %d, want %d", got, want)
	}
	// A segment that is no longer in flight is not lost again.
	if !rt.r.onLost(&a.rate, a.size) || rt.r.onLost(&a.rate, a.size) {
		t.Errorf("onLost twice in a row: want true, then false")
	}
}

func TestRateSamplerAdopt(t *testing.T) {
	// Sampling is enabled while three segments are outstanding: one in
	// flight, one SACKed and one declared lost.
	rt := rateTest{}
	var inFlight, sacked, lost segRate
	rt.r.adopt(&inFlight, 1000, false, false)
	rt.r.adopt(&sacked, 1000, true, false)
	rt.r.adopt(&lost, 1000, false, true)
	if rt.r.InFlight != 1000 || rt.r.LostPending != 1000 || rt.r.Delivered != 0 || rt.r.Lost != 0 {
		t.Fatalf("after adopt: got inflight = %d, lostPending = %d, delivered = %d, lost = %d, want 1000, 1000, 0, 0",
			rt.r.InFlight, rt.r.LostPending, rt.r.Delivered, rt.r.Lost)
	}
	// Each records the data in flight once it was adopted, as if the adopted
	// segments had been sent back to back.
	if inFlight.txInFlight != 1000 || sacked.txInFlight != 1000 || lost.txInFlight != 1000 {
		t.Errorf("adopted txInFlight = %d, %d, %d, want 1000, 1000, 1000", inFlight.txInFlight, sacked.txInFlight, lost.txInFlight)
	}

	// A new segment is sent and the adopted one in flight is delivered. Its
	// bytes count, but it carries no snapshot to base a sample on.
	n := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	rt.r.beginACK()
	rt.r.onDelivered(&inFlight, 1000, tcpip.MonotonicTime{}, 1000, rt.now, true /* once */)
	rs := *rt.r.endACK()
	if rs.hasData || rs.newlyAcked != 1000 || rt.r.Delivered != 1000 || rt.r.InFlight != 1000 {
		t.Errorf("adopted segment delivered: got hasData = %t, newlyAcked = %d, delivered = %d, inflight = %d, want false, 1000, 1000, 1000",
			rs.hasData, rs.newlyAcked, rt.r.Delivered, rt.r.InFlight)
	}

	// The SACKed segment is not counted again when it is cumulatively ACKed,
	// and the new segment yields a sample.
	rt.r.beginACK()
	rt.r.onDelivered(&sacked, 1000, tcpip.MonotonicTime{}, 2000, rt.now, true /* once */)
	rt.r.onDelivered(&n.rate, n.size, n.sendTime, n.end, rt.now, true /* once */)
	rs = *rt.r.endACK()
	if !rs.hasData || rs.newlyAcked != 1000 || rt.r.Delivered != 2000 {
		t.Errorf("new segment delivered: got hasData = %t, newlyAcked = %d, delivered = %d, want true, 1000, 2000",
			rs.hasData, rs.newlyAcked, rt.r.Delivered)
	}

	// Retransmitting the lost segment takes a snapshot, so a sample can be
	// based on it.
	rt.r.onSent(&lost, 1000, rt.now)
	if lost.unsampled || rt.r.LostPending != 0 || rt.r.InFlight != 1000 {
		t.Errorf("lost segment retransmitted: got unsampled = %t, lostPending = %d, inflight = %d, want false, 0, 1000",
			lost.unsampled, rt.r.LostPending, rt.r.InFlight)
	}
}

func TestRateSamplerPartialDelivery(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	rt.r.beginACK()
	rt.r.onPartialDelivered(&p.rate, 400, rt.now)
	rs := *rt.r.endACK()
	if rs.hasData {
		t.Errorf("partial delivery: got hasData = true, want false")
	}
	if rs.newlyAcked != 400 || rt.r.Delivered != 400 || rt.r.InFlight != 600 {
		t.Errorf("got newlyAcked = %d, delivered = %d, inflight = %d, want 400, 400, 600", rs.newlyAcked, rt.r.Delivered, rt.r.InFlight)
	}
	rt.advance(time.Millisecond)
	p.size = 600
	rt.ack(p)
	if rt.r.Delivered != 1000 || rt.r.InFlight != 0 {
		t.Errorf("got delivered = %d, inflight = %d, want 1000, 0", rt.r.Delivered, rt.r.InFlight)
	}
}

func TestRateSamplerSplit(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1000)
	rt.r.onLost(&p.rate, p.size)
	// The segment is split at 600 bytes. Both halves carry a copy of the
	// state, so the totals are unchanged whichever is handled first.
	q := &ratePacket{rate: p.rate, size: 400, sendTime: p.sendTime, end: p.end}
	p.size = 600
	p.end = p.end - 400
	rt.advance(10 * time.Millisecond)
	rt.r.onSent(&q.rate, q.size, rt.now)
	if rt.r.LostPending != 600 || rt.r.InFlight != 400 {
		t.Errorf("after resending the second half: got lostPending = %d, inflight = %d, want 600, 400", rt.r.LostPending, rt.r.InFlight)
	}
	rt.r.beginACK()
	rt.r.onPartialDelivered(&p.rate, 100, rt.now)
	rt.r.endACK()
	if rt.r.LostPending != 500 {
		t.Errorf("after a partial delivery of the first half: got lostPending = %d, want 500", rt.r.LostPending)
	}
	p.size = 500
	rt.ack(p, q)
	if rt.r.LostPending != 0 || rt.r.InFlight != 0 {
		t.Errorf("got lostPending = %d, inflight = %d, want 0, 0", rt.r.LostPending, rt.r.InFlight)
	}
	if got, want := rt.r.Delivered, uint64(1000); got != want {
		t.Errorf("got delivered = %d, want %d", got, want)
	}
}

func TestRateSamplerReportedRate(t *testing.T) {
	const cwnd = 1 << 20
	rt := rateTest{}
	a := rt.send(10_000)
	rt.advance(10 * time.Millisecond)
	rt.ack(a)
	if rt.r.Rate != 1_000_000 || rt.r.RateAppLimited {
		t.Fatalf("got rate = %d, appLimited = %t, want 1000000, false", rt.r.Rate, rt.r.RateAppLimited)
	}

	// A slower, application-limited sample does not replace it.
	rt.r.checkAppLimited(true, cwnd)
	b := rt.send(1000)
	rt.advance(10 * time.Millisecond)
	if rs := rt.ack(b); !rs.isAppLimited || rs.deliveryRate != 100_000 {
		t.Fatalf("got isAppLimited = %t, deliveryRate = %d, want true, 100000", rs.isAppLimited, rs.deliveryRate)
	}
	if rt.r.Rate != 1_000_000 || rt.r.RateAppLimited {
		t.Errorf("after a slower app-limited sample: got rate = %d, appLimited = %t, want 1000000, false", rt.r.Rate, rt.r.RateAppLimited)
	}

	// A faster application-limited sample does.
	rt.r.checkAppLimited(true, cwnd)
	c := rt.send(30_000)
	rt.advance(10 * time.Millisecond)
	rt.ack(c)
	if rt.r.Rate != 3_000_000 || !rt.r.RateAppLimited {
		t.Errorf("after a faster app-limited sample: got rate = %d, appLimited = %t, want 3000000, true", rt.r.Rate, rt.r.RateAppLimited)
	}

	// Any sample that is not application-limited does, even a slower one.
	d := rt.send(5000)
	rt.advance(10 * time.Millisecond)
	if rs := rt.ack(d); rs.isAppLimited {
		t.Fatalf("got isAppLimited = true, want false")
	}
	if rt.r.Rate != 500_000 || rt.r.RateAppLimited {
		t.Errorf("after an unlimited sample: got rate = %d, appLimited = %t, want 500000, false", rt.r.Rate, rt.r.RateAppLimited)
	}
}

func TestRateSamplerNoOverflow(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1 << 30)
	rt.advance(time.Microsecond)
	rs := rt.ack(p)
	if got, want := rs.deliveryRate, uint64(1<<30)*1_000_000; got != want {
		t.Errorf("got deliveryRate = %d, want %d", got, want)
	}

	// A rate that does not fit saturates.
	rt.r = rateSampler{}
	rt.r.Delivered = math.MaxUint64 - (1 << 40)
	q := rt.send(1 << 40)
	q.rate.delivered = 0
	rt.advance(time.Nanosecond)
	if rs := rt.ack(q); rs.deliveryRate != math.MaxUint64 {
		t.Errorf("got deliveryRate = %d, want %d", rs.deliveryRate, uint64(math.MaxUint64))
	}
}

func TestRateSamplerReset(t *testing.T) {
	rt := rateTest{}
	p := rt.send(1000)
	rt.r.onLost(&p.rate, p.size)
	rt.send(500)
	rt.r.reset()
	if rt.r.InFlight != 0 || rt.r.LostPending != 0 {
		t.Errorf("got inflight = %d, lostPending = %d, want 0, 0", rt.r.InFlight, rt.r.LostPending)
	}
	if got, want := rt.r.Lost, uint64(1000); got != want {
		t.Errorf("reset changed lost: got %d, want %d", got, want)
	}
}
