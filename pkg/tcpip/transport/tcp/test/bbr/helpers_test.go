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

// Package bbr_test runs the example test cases of the BBR draft
// (draft-ietf-ccwg-bbr-07, Appendix A) end to end: a BBR sender and a
// receiver, each on its own netstack stack, joined by a modelled path, on a
// simulated clock.
package bbr_test

import (
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/simnet"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

const (
	// mtu is the MTU of the links, and the size of a full packet.
	mtu = 1500

	// fullPayload is the payload of a full packet: the MTU less the IPv4
	// and TCP headers and the timestamp option, padded to 12 bytes.
	fullPayload = mtu - header.IPv4MinimumSize - header.TCPMinimumSize - 12

	// infinity is what BBR uses for an unbounded volume or rate.
	infinity = math.MaxUint64

	// unit is the denominator of BBR's gains.
	unit = 1000
)

// path describes the modelled path between the sender and the receiver.
type path struct {
	// rate is the bottleneck's rate in bytes per second, counting whole
	// packets.
	rate uint64
	// rtt is the round-trip propagation delay, split evenly between the
	// directions.
	rtt time.Duration
	// queue is the size of the bottleneck's queue in bytes; zero means no
	// limit.
	queue int
	// policerRate and policerBurst configure a token-bucket policer in front
	// of the bottleneck, if policerRate is not zero.
	policerRate  uint64
	policerBurst int
	// buffers is the size of the sockets' send and receive buffers in
	// bytes; zero means the stack's defaults.
	buffers int
}

// standard is the path of most cases: 10 Mbit/s with 100 ms of round-trip
// delay, a bandwidth-delay product of 86 full packets, and a queue that never
// overflows. At this BDP BBR waits for its 2 to 3 second timer before
// probing for bandwidth; the Reno-coexistence limit, 63 round trips, is
// longer.
var standard = path{rate: 1_250_000, rtt: 100 * time.Millisecond}

// bdp returns the path's bandwidth-delay product in bytes.
func (p path) bdp() uint64 {
	return p.rate * uint64(p.rtt) / uint64(time.Second)
}

// sample is the state of the sender after it processed a segment.
type sample struct {
	// at is the simulated time.
	at time.Duration

	bbr  tcp.TCPBBRState
	rate tcp.TCPDeliveryRateState

	// sndCwnd is the congestion window in packets, and mss the sender's
	// maximum payload size.
	sndCwnd int
	mss     int

	inRecovery       bool
	spuriousRecovery bool
}

// run is a BBR flow over a path, and the samples of its sender's state.
type run struct {
	t  *testing.T
	p  path
	cc tcpip.CongestionControlOption
	n  *simnet.Network
	f  *simnet.Flow

	mu      sync.Mutex
	samples []sample
	// next is the index of the first sample that until has not looked at.
	next int
}

// newRun returns a connected BBR flow over p, with RACK, that sends nothing
// yet.
func newRun(t *testing.T, p path) *run {
	t.Helper()
	return newRunCC(t, p, "bbr")
}

// newRunCC is newRun with the congestion control algorithm cc.
//
// Unless p sets them, the sockets keep the stack's default buffers, which do
// not limit the sender on the paths of these tests: the send buffer, 1MiB, is
// at least four times the largest BDP, and the receive buffer grows from 1MiB
// to 4MiB as needed. Larger send buffers would only add backlog for
// limitBacklog to wait out.
func newRunCC(t *testing.T, p path, cc tcpip.CongestionControlOption) *run {
	t.Helper()
	r := &run{t: t, p: p, cc: cc}
	data := pathmodel.Config{
		Rate:         p.rate,
		Delay:        p.rtt / 2,
		QueueBytes:   p.queue,
		PolicerRate:  p.policerRate,
		PolicerBurst: p.policerBurst,
		Seed:         1,
	}
	acks := pathmodel.Config{Delay: p.rtt / 2}
	n, err := simnet.New(simnet.Config{Data: data, Acks: acks, CC: cc, RACK: true, Probe: r.probe, Seed: 1, BufferSize: p.buffers})
	if err != nil {
		t.Fatal(err)
	}
	r.n = n
	t.Cleanup(func() {
		if r.f != nil && r.f.Err() != nil {
			t.Errorf("flow: %v", r.f.Err())
		}
		n.Close()
	})
	if r.f, err = n.Dial(); err != nil {
		t.Fatal(err)
	}
	return r
}

// probe records the sender's state.
func (r *run) probe(s *tcp.TCPEndpointState) {
	if s.Sender.BBR.State == tcp.BBRStateNone && r.cc == "bbr" {
		// Not yet the BBR sender: the handshake.
		return
	}
	smp := sample{
		at:               r.n.Clock.Elapsed(),
		bbr:              s.Sender.BBR,
		rate:             s.Sender.DeliveryRate,
		sndCwnd:          s.Sender.SndCwnd,
		mss:              s.Sender.MaxPayloadSize,
		inRecovery:       s.Sender.FastRecovery.Active,
		spuriousRecovery: s.Sender.SpuriousRecovery,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples = append(r.samples, smp)
}

// limitBacklog shrinks the client's send buffer to 1.25 times the path's
// BDP, so that when the application slows down, what it already wrote is
// sent within a round trip or two rather than after a megabyte of backlog.
// Startup needs more, so call it later.
func (r *run) limitBacklog() {
	r.f.Client.SocketOptions().SetSendBufferSize(int64(r.p.bdp()*5/4), true /* notify */)
}

// now returns the simulated time.
func (r *run) now() time.Duration {
	return r.n.Clock.Elapsed()
}

// last returns the latest sample.
func (r *run) last() sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.samples) == 0 {
		r.t.Fatal("no samples yet")
	}
	return r.samples[len(r.samples)-1]
}

// mark returns the index of the next sample, for since.
func (r *run) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.samples)
}

// since returns the samples from index i on.
func (r *run) since(i int) []sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sample(nil), r.samples[i:]...)
}

// until runs the network until a sample taken from now on satisfies cond,
// for at most limit of simulated time, and returns that sample.
func (r *run) until(limit time.Duration, what string, cond func(*sample) bool) sample {
	r.t.Helper()
	r.mu.Lock()
	r.next = len(r.samples)
	r.mu.Unlock()
	var found *sample
	done := func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for ; r.next < len(r.samples); r.next++ {
			if cond(&r.samples[r.next]) {
				s := r.samples[r.next]
				found = &s
				r.next++
				return true
			}
		}
		return false
	}
	if err := r.n.Run(limit, done); err != nil {
		state := "no samples"
		if r.mark() > 0 {
			state = describe(r.last())
		}
		r.t.Fatalf("waiting for %s: %v; at %v the sender is %s", what, err, r.now(), state)
	}
	return *found
}

// enter runs the network until BBR is in state st and returns the first
// sample in it.
func (r *run) enter(limit time.Duration, st tcp.BBRState) sample {
	r.t.Helper()
	return r.until(limit, st.String(), func(s *sample) bool { return s.bbr.State == st })
}

// leave runs the network until BBR is in a state other than st and returns
// the first sample in it.
func (r *run) leave(limit time.Duration, st tcp.BBRState) sample {
	r.t.Helper()
	return r.until(limit, "leaving "+st.String(), func(s *sample) bool { return s.bbr.State != st })
}

// goodput returns the path's rate in payload bytes per second, for full
// packets.
func (r *run) goodput() uint64 {
	return r.goodputAt(r.p.rate)
}

// goodputAt returns the payload rate of a bottleneck of rate bytes per
// second, for full packets.
func (r *run) goodputAt(rate uint64) uint64 {
	return rate * fullPayload / mtu
}

// describe summarises a sample for failure messages.
func describe(s sample) string {
	b := s.bbr
	return fmt.Sprintf("%v (round %d, max_bw %d, bw_shortterm %s, min_rtt %v, cwnd %d, inflight %d, inflight_longterm %s, inflight_shortterm %s, extra_acked %d, full_bw_reached %t)",
		b.State, b.RoundCount, b.MaxBw, volume(b.BwShortterm), b.MinRTT, b.Cwnd, s.rate.InFlight, volume(b.InflightLongterm), volume(b.InflightShortterm), b.ExtraAcked, b.FullBwReached)
}

// volume formats a volume or rate that may be infinite.
func volume(v uint64) string {
	if v == infinity {
		return "inf"
	}
	return fmt.Sprint(v)
}

// within reports whether got is within pct percent of want.
func within(got, want uint64, pct float64) bool {
	return math.Abs(float64(got)-float64(want)) <= float64(want)*pct/100
}

// isData reports whether pkt carries TCP payload.
func isData(pkt *stack.PacketBuffer) bool {
	s, ok := simnet.ParseSegment(pkt)
	return ok && s.PayloadLen > 0
}

// dropEvery returns a filter that drops every nth data packet that leaves
// the path before the simulated time end, and drops counts them.
func dropEvery(r *run, nth int, end time.Duration, drops *int) simnet.Filter {
	var seen int
	return func(pkt *stack.PacketBuffer) simnet.Verdict {
		if r.now() >= end || !isData(pkt) {
			return simnet.Verdict{}
		}
		seen++
		if seen%nth == 0 {
			*drops++
			return simnet.Verdict{Drop: true}
		}
		return simnet.Verdict{}
	}
}

// aggregateAcks returns a filter that holds every packet until the next
// multiple of interval, as a Wi-Fi or cellular link that sends ACKs in
// bursts does.
func aggregateAcks(r *run, interval time.Duration) simnet.Filter {
	return func(*stack.PacketBuffer) simnet.Verdict {
		// Always to a later boundary, so that ACKs stay in order.
		return simnet.Verdict{Delay: interval - r.now()%interval}
	}
}

// transitions returns the state changes in samples, as "A->B" strings.
func transitions(samples []sample) []string {
	var out []string
	for i := 1; i < len(samples); i++ {
		if a, b := samples[i-1].bbr.State, samples[i].bbr.State; a != b {
			out = append(out, fmt.Sprintf("%v->%v", a, b))
		}
	}
	return out
}
