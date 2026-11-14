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

package bbr_test

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/simnet"
)

// simPath is a path of the simulated comparisons.
type simPath struct {
	name    string
	rate    uint64
	rtt     time.Duration
	queue   float64 // in BDPs
	lossPPM uint32
	// ackLossPPM is the random loss of the direction that carries the
	// acknowledgements.
	ackLossPPM uint32
	// latePPM is the share of data packets that arrive lateBy late, and so
	// after packets sent after them.
	latePPM uint32
	lateBy  time.Duration
	// defaultBuffers leaves the sockets' buffers at the stack's defaults
	// rather than simBufferSize.
	defaultBuffers bool
}

// simBufferSize is the size of the socket buffers in the simulated
// comparisons. It is large enough that neither the sender's buffer nor the
// receiver's window limits a flow on any of the paths, so that the numbers
// compare the congestion control algorithms. With the stack's defaults the
// receiver's window does limit a flow that loses packets: see
// simnet.Config.BufferSize and the path "wifi/loss=1%/buffers=default".
const simBufferSize = 32 << 20

// bufferSize returns the simnet.Config.BufferSize of p.
func (p simPath) bufferSize() int {
	if p.defaultBuffers {
		return 0
	}
	return simBufferSize
}

const (
	// ackSeed is what the direction of the acknowledgements adds to a
	// run's seed, so that the two directions do not drop the same packets.
	ackSeed = 1 << 32

	// lateSeed is the second half of the seed of the generator that picks
	// the packets that arrive late.
	lateSeed = 2
)

// network returns a simulated network over p whose stacks default to cc,
// with RACK. The same seed always gives the same run.
func (p simPath) network(cc tcpip.CongestionControlOption, seed uint64) (*simnet.Network, error) {
	bdp := float64(p.rate) * p.rtt.Seconds()
	data := pathmodel.Config{Rate: p.rate, Delay: p.rtt / 2, QueueBytes: max(int(p.queue*bdp), 2*mtu), LossPPM: p.lossPPM, Seed: seed}
	acks := pathmodel.Config{Delay: p.rtt / 2, LossPPM: p.ackLossPPM, Seed: seed + ackSeed}
	n, err := simnet.New(simnet.Config{Data: data, Acks: acks, CC: cc, RACK: true, Seed: seed, BufferSize: p.bufferSize()})
	if err != nil {
		return nil, err
	}
	if p.latePPM != 0 {
		rng := rand.New(rand.NewPCG(seed, lateSeed))
		n.SetFilter(n.Data, func(*stack.PacketBuffer) simnet.Verdict {
			if rng.Uint32N(1_000_000) < p.latePPM {
				return simnet.Verdict{Delay: p.lateBy}
			}
			return simnet.Verdict{}
		})
	}
	return n, nil
}

// simPaths are the paths of the lossy benchmark in the benchmarks package: a
// Wi-Fi-like path at 0, 1 and 2% loss, the same path with a shallow buffer,
// and a slower path with a deep one. The last is the Wi-Fi-like path at 1%
// loss again, with the socket buffers a netstack application gets by
// default.
var simPaths = []simPath{
	{name: "wifi/loss=0", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1},
	{name: "wifi/loss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 10_000},
	{name: "wifi/loss=2%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 20_000},
	{name: "shallow", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 0.25},
	{name: "bufferbloat", rate: 2_500_000, rtt: 40 * time.Millisecond, queue: 10},
	{name: "wifi/loss=1%/buffers=default", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 10_000, defaultBuffers: true},
}

// BenchmarkSimulatedTransfer transfers 8MB over modelled paths on a
// simulated clock, with CUBIC and BBR. The metrics are those of the
// simulated run, not of the machine: sim-MB/s is the transfer's throughput
// in simulated time, retransmits/op and the queue waits come from the path.
// Each transfer uses the next seed for the random loss of its path and
// algorithm, so -count or -benchtime spread the runs over loss patterns, and
// the same flags always give the same numbers.
func BenchmarkSimulatedTransfer(b *testing.B) {
	seeds := make(map[string]uint64)
	const size = 8 << 20
	for _, p := range simPaths {
		for _, cc := range []tcpip.CongestionControlOption{"cubic", "bbr"} {
			b.Run(fmt.Sprintf("path=%s/cc=%s", p.name, cc), func(b *testing.B) {
				var simTime, wait, maxWait time.Duration
				var retransmits, accepted uint64
				for i := 0; i < b.N; i++ {
					seeds[b.Name()]++
					seed := seeds[b.Name()]
					n, err := p.network(cc, seed)
					if err != nil {
						b.Fatal(err)
					}
					f, err := n.Dial()
					if err != nil {
						b.Fatal(err)
					}
					start := n.Clock.Elapsed()
					f.Bulk()
					if err := n.Run(10*time.Minute, func() bool { return f.Received() >= size }); err != nil {
						b.Fatal(err)
					}
					if f.Err() != nil {
						b.Fatal(f.Err())
					}
					simTime += n.Clock.Elapsed() - start
					retransmits += n.Client.Stats().TCP.Retransmits.Value()
					st := n.Data.Stats()
					wait += st.QueueWaitTotal
					maxWait = max(maxWait, st.MaxQueueWait)
					accepted += st.Offered - st.PolicerDrops - st.RandomDrops - st.QueueDrops
					n.Close()
				}
				b.ReportMetric(float64(size)*float64(b.N)/simTime.Seconds()/1e6, "sim-MB/s")
				b.ReportMetric(float64(retransmits)/float64(b.N), "retransmits/op")
				if accepted > 0 {
					b.ReportMetric(float64(wait.Microseconds())/float64(accepted)/1000, "queue-wait-ms/pkt")
				}
				b.ReportMetric(float64(maxWait.Microseconds())/1000, "max-queue-wait-ms")
			})
		}
	}
}

// steadyPaths are the paths of BenchmarkSimulatedSteadyState: the Wi-Fi-like
// path of simPaths, clean; losing data packets at random; losing
// acknowledgements too; losing nothing but delivering one data packet in a
// hundred 5ms late, which is about 40 packets out of order; and the paths of
// simPaths with a shallow and with a deep buffer.
var steadyPaths = []simPath{
	{name: "loss=0", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1},
	{name: "loss=0.1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 1000},
	{name: "loss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 10_000},
	{name: "loss=2%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 20_000},
	{name: "loss=1%/ackloss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 10_000, ackLossPPM: 10_000},
	{name: "loss=2%/ackloss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, lossPPM: 20_000, ackLossPPM: 10_000},
	{name: "late=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, latePPM: 10_000, lateBy: 5 * time.Millisecond},
	{name: "late=1%/ackloss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queue: 1, ackLossPPM: 10_000, latePPM: 10_000, lateBy: 5 * time.Millisecond},
	simPaths[3],
	simPaths[4],
}

// BenchmarkSimulatedSteadyState runs a bulk flow over modelled paths for 20
// seconds of simulated time, with CUBIC and BBR, and reports what the flow
// did from the fifth second on: sim-Mbit/s is its throughput, to compare
// with the path's rate (100 Mbit/s, 20 Mbit/s for the deep buffer);
// retransmits/op its retransmissions, and retransmit-% their share of the
// data packets it sent; queue-wait-ms/pkt how long a packet waited for the
// bottleneck on average, which is what the flow adds to the path's round
// trip of 40ms.
// BenchmarkSimulatedTransfer's 8MB are over before an algorithm settles, and
// mostly measure how it starts; this measures how it carries on.
//
// The seeds work as in BenchmarkSimulatedTransfer. A run takes several
// seconds of real time.
func BenchmarkSimulatedSteadyState(b *testing.B) {
	const (
		warmup = 5 * time.Second
		window = 15 * time.Second
	)
	seeds := make(map[string]uint64)
	for _, p := range steadyPaths {
		for _, cc := range []tcpip.CongestionControlOption{"cubic", "bbr"} {
			b.Run(fmt.Sprintf("path=%s/cc=%s", p.name, cc), func(b *testing.B) {
				var received, retransmits, offered, accepted uint64
				var wait time.Duration
				for i := 0; i < b.N; i++ {
					seeds[b.Name()]++
					n, err := p.network(cc, seeds[b.Name()])
					if err != nil {
						b.Fatal(err)
					}
					f, err := n.Dial()
					if err != nil {
						b.Fatal(err)
					}
					f.Bulk()
					n.RunFor(warmup)
					r0 := f.Received()
					x0 := n.Client.Stats().TCP.Retransmits.Value()
					s0 := n.Data.Stats()
					n.RunFor(window)
					if f.Err() != nil {
						b.Fatal(f.Err())
					}
					received += f.Received() - r0
					retransmits += n.Client.Stats().TCP.Retransmits.Value() - x0
					s1 := n.Data.Stats()
					offered += s1.Offered - s0.Offered
					accepted += (s1.Offered - s1.PolicerDrops - s1.RandomDrops - s1.QueueDrops) - (s0.Offered - s0.PolicerDrops - s0.RandomDrops - s0.QueueDrops)
					wait += s1.QueueWaitTotal - s0.QueueWaitTotal
					n.Close()
				}
				b.ReportMetric(float64(received)*8/float64(b.N)/window.Seconds()/1e6, "sim-Mbit/s")
				b.ReportMetric(float64(retransmits)/float64(b.N), "retransmits/op")
				if offered > 0 {
					b.ReportMetric(100*float64(retransmits)/float64(offered), "retransmit-%")
				}
				if accepted > 0 {
					b.ReportMetric(float64(wait.Microseconds())/float64(accepted)/1000, "queue-wait-ms/pkt")
				}
			})
		}
	}
}

// sharePaths are the bottlenecks of the sharing test: a 20 Mbit/s path with
// a buffer of one BDP and the deep-buffered path of simPaths. Faster paths
// make the test slow; BenchmarkSimulatedSharing adds the Wi-Fi-like one.
var sharePaths = []simPath{
	{name: "shared", rate: 2_500_000, rtt: 40 * time.Millisecond, queue: 1},
	simPaths[4],
}

// shareStart and shareEnd are the stretch of a shareRun over which
// TestBBRSharesFairly and BenchmarkSimulatedSharing take the flows' shares.
const (
	shareStart = 10 * time.Second
	shareEnd   = 40 * time.Second
)

// shareRun runs two bulk flows, with congestion control first and second,
// over one bottleneck, the second starting a second after the first. It
// returns how many bytes each flow delivered from shareStart to shareEnd.
func shareRun(tb testing.TB, p simPath, first, second tcpip.CongestionControlOption, seed uint64) (uint64, uint64) {
	tb.Helper()
	return shareRunBetween(tb, p, first, second, seed, shareStart, shareEnd)
}

// shareRunBetween is shareRun for the stretch from start to end after the
// first flow starts.
func shareRunBetween(tb testing.TB, p simPath, first, second tcpip.CongestionControlOption, seed uint64, shareStart, shareEnd time.Duration) (uint64, uint64) {
	tb.Helper()
	const stagger = time.Second
	// Making BBR the stacks' default makes it available; each flow then
	// selects its own algorithm before it sends anything.
	n, err := p.network("bbr", seed)
	if err != nil {
		tb.Fatal(err)
	}
	defer n.Close()
	var flows [2]*simnet.Flow
	for i, cc := range []tcpip.CongestionControlOption{first, second} {
		f, err := n.Dial()
		if err != nil {
			tb.Fatal(err)
		}
		if err := f.Client.SetSockOpt(&cc); err != nil {
			tb.Fatalf("selecting %s: %s", cc, err)
		}
		flows[i] = f
	}
	start := n.Clock.Elapsed()
	flows[0].Bulk()
	n.RunFor(stagger)
	flows[1].Bulk()
	n.RunFor(start + shareStart - n.Clock.Elapsed())
	r0, r1 := flows[0].Received(), flows[1].Received()
	n.RunFor(shareEnd - shareStart)
	for _, f := range flows {
		if f.Err() != nil {
			tb.Fatal(f.Err())
		}
	}
	return flows[0].Received() - r0, flows[1].Received() - r1
}

// TestBBRSharesFairly checks that two BBR flows on one bottleneck split it
// within 60/40 after 10 seconds (DESIGN success criterion; draft-ietf-ccwg-bbr-07
// section 1 lists fairness among BBR flows as a goal), and keep the link busy.
func TestBBRSharesFairly(t *testing.T) {
	for _, p := range sharePaths {
		t.Run(p.name, func(t *testing.T) {
			for seed := uint64(1); seed <= 2; seed++ {
				d0, d1 := shareRun(t, p, "bbr", "bbr", seed)
				share := float64(d0) / float64(d0+d1)
				utilization := float64(d0+d1) / 30 / float64(p.rate)
				t.Logf("seed %d: first flow %.1f%%, link %.1f%% used", seed, 100*share, 100*utilization)
				if share < 0.4 || share > 0.6 {
					t.Errorf("seed %d: first flow's share = %.1f%%, want 40-60%%", seed, 100*share)
				}
				if utilization < 0.9 {
					t.Errorf("seed %d: link %.1f%% used, want at least 90%%", seed, 100*utilization)
				}
			}
		})
	}
}

// TestBBRLateFlowCatchesUp checks that a BBR flow that starts second on a
// fast path with large socket buffers reaches its share: from 20 to 30
// seconds the split is within 60/40.
//
// On this path both flows are held at BBR.inflight_longterm most of the
// time, and the second one gains only by raising it when it probes for
// bandwidth, which it does only if it knows that cwnd is what holds it back
// (C.is_cwnd_limited). When that was decided on a count of bytes that could
// disagree with the sender's count of packets, the first flow kept four
// fifths of this path for minutes. The paths of TestBBRSharesFairly are too
// slow to show it, and with the default buffers the receiver's window splits
// the path evenly whatever BBR does.
func TestBBRLateFlowCatchesUp(t *testing.T) {
	p := simPaths[0]
	const from, to = 20 * time.Second, 30 * time.Second
	d0, d1 := shareRunBetween(t, p, "bbr", "bbr", 1, from, to)
	share := float64(d0) / float64(d0+d1)
	utilization := float64(d0+d1) / (to - from).Seconds() / float64(p.rate)
	t.Logf("first flow %.1f%%, link %.1f%% used", 100*share, 100*utilization)
	if share < 0.4 || share > 0.6 {
		t.Errorf("first flow's share = %.1f%%, want 40-60%%", 100*share)
	}
	if utilization < 0.9 {
		t.Errorf("link %.1f%% used, want at least 90%%", 100*utilization)
	}
}

// BenchmarkSimulatedSharing reports how two flows share a bottleneck from 10
// to 40 seconds of simulated time: the first flow's share and how much of the
// link they used together. The pair BBR and CUBIC is informational: BBRv3
// does not aim at an equal split with CUBIC.
func BenchmarkSimulatedSharing(b *testing.B) {
	seeds := make(map[string]uint64)
	pairs := [][2]tcpip.CongestionControlOption{{"bbr", "bbr"}, {"bbr", "cubic"}, {"cubic", "bbr"}, {"cubic", "cubic"}}
	for _, p := range append([]simPath{simPaths[0]}, sharePaths...) {
		for _, pair := range pairs {
			b.Run(fmt.Sprintf("path=%s/flows=%s+%s", p.name, pair[0], pair[1]), func(b *testing.B) {
				var share, utilization float64
				for i := 0; i < b.N; i++ {
					seeds[b.Name()]++
					d0, d1 := shareRun(b, p, pair[0], pair[1], seeds[b.Name()])
					share += float64(d0) / float64(d0+d1)
					utilization += float64(d0+d1) / 30 / float64(p.rate)
				}
				b.ReportMetric(100*share/float64(b.N), "first-flow-%")
				b.ReportMetric(100*utilization/float64(b.N), "link-used-%")
			})
		}
	}
}
