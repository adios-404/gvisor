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

package tcp_benchmarks_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel"
)

// pathMTU is the MTU of the links joined by a modelled path. The links do not
// use GSO, so every packet crosses the path on its own, as on a real one.
const pathMTU = 1500

// pathCase is a modelled path: a bottleneck of rate bytes per second, a
// round-trip propagation delay of rtt, split evenly between the directions,
// and a queue of queueBDPs times the bandwidth-delay product. Packets from the
// client to the server are lost at random with probability lossPPM in a
// million; ACKs are not.
type pathCase struct {
	name      string
	rate      uint64
	rtt       time.Duration
	queueBDPs float64
	lossPPM   uint32
}

// bdp returns the bandwidth-delay product of the path in bytes.
func (c pathCase) bdp() int {
	return int(c.rate * uint64(c.rtt) / uint64(time.Second))
}

// configs returns the configuration of the client-to-server and
// server-to-client directions.
func (c pathCase) configs() (pathmodel.Config, pathmodel.Config) {
	data := pathmodel.Config{
		Rate:       c.rate,
		Delay:      c.rtt / 2,
		QueueBytes: max(int(c.queueBDPs*float64(c.bdp())), 2*pathMTU),
		LossPPM:    c.lossPPM,
		Seed:       1,
	}
	// ACKs are small and share the bottleneck's rate only nominally.
	acks := pathmodel.Config{Rate: c.rate, Delay: c.rtt / 2}
	return data, acks
}

// newPathTopology returns a client and a server stack, using the congestion
// control algorithm cc, joined by the modelled path c.
func newPathTopology(t testing.TB, c pathCase, cc tcpip.CongestionControlOption, rack bool) *topology {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	n := &topology{ctx: ctx, cancel: cancel}
	t.Cleanup(n.close)
	for i := range n.stacks {
		n.addStack(t, i, channel.New(4096, pathMTU, ""), cc, rack)
	}
	data, acks := c.configs()
	n.path = pathmodel.Join(n.stacks[0].Clock(), n.links[0], n.links[1], data, acks)
	return n
}

// TestTransferOverLossyPath checks that data crosses a slow, long and lossy
// path intact, with and without RACK.
func TestTransferOverLossyPath(t *testing.T) {
	c := pathCase{name: "lossy", rate: 2_500_000, rtt: 20 * time.Millisecond, queueBDPs: 1, lossPPM: 10_000}
	for _, cc := range []tcpip.CongestionControlOption{"reno", "cubic", "bbr"} {
		for _, rack := range []bool{true, false} {
			t.Run(fmt.Sprintf("cc=%s/rack=%t", cc, rack), func(t *testing.T) {
				n := newPathTopology(t, c, cc, rack)
				ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
				defer cancel()
				pair, err := n.connect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				data := make([]byte, 64<<10)
				for i := range data {
					data[i] = byte(i*31 + i/251)
				}
				const size = 512 << 10
				var got bytes.Buffer
				if err := transfer(ctx, pair, data, size, &got); err != nil {
					t.Fatal(err)
				}
				if want := bytes.Repeat(data, size/len(data)); !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("received %d bytes with incorrect content", got.Len())
				}
				if drops := n.path.AB.Stats().RandomDrops; drops == 0 {
					t.Errorf("no packet was lost on a path with 1%% loss")
				}
			})
		}
	}
}

// pathCases are the paths of the lossy benchmark (DESIGN §7): a Wi-Fi-like
// path at 0, 1 and 2% loss, the same path with a shallow buffer, and a slower
// path with a deep one (bufferbloat).
var pathCases = []pathCase{
	{name: "wifi/loss=0", rate: 12_500_000, rtt: 40 * time.Millisecond, queueBDPs: 1},
	{name: "wifi/loss=1%", rate: 12_500_000, rtt: 40 * time.Millisecond, queueBDPs: 1, lossPPM: 10_000},
	{name: "wifi/loss=2%", rate: 12_500_000, rtt: 40 * time.Millisecond, queueBDPs: 1, lossPPM: 20_000},
	{name: "shallow", rate: 12_500_000, rtt: 40 * time.Millisecond, queueBDPs: 0.25},
	{name: "bufferbloat", rate: 2_500_000, rtt: 40 * time.Millisecond, queueBDPs: 10},
}

// BenchmarkBulkPath measures bulk transfers over modelled paths. Besides
// throughput it reports retransmissions and the time packets wait in the
// bottleneck's queue.
func BenchmarkBulkPath(b *testing.B) {
	const size = 8 << 20
	for _, c := range pathCases {
		for _, cc := range []tcpip.CongestionControlOption{"cubic", "bbr"} {
			for _, rack := range []bool{true, false} {
				b.Run(fmt.Sprintf("path=%s/cc=%s/rack=%t", c.name, cc, rack), func(b *testing.B) {
					b.StopTimer()
					data := make([]byte, 128<<10)
					b.SetBytes(size)
					b.ResetTimer()
					var retransmits uint64
					var wait, maxWait time.Duration
					var accepted uint64
					for i := 0; i < b.N; i++ {
						n := newPathTopology(b, c, cc, rack)
						pair, err := n.connect(n.ctx)
						if err != nil {
							b.Fatal(err)
						}
						stats := n.stacks[0].Stats().TCP
						before := stats.Retransmits.Value()
						b.StartTimer()
						err = transfer(n.ctx, pair, data, size, io.Discard)
						b.StopTimer()
						if err != nil {
							b.Fatal(err)
						}
						retransmits += stats.Retransmits.Value() - before
						ps := n.path.AB.Stats()
						wait += ps.QueueWaitTotal
						maxWait = max(maxWait, ps.MaxQueueWait)
						accepted += ps.Offered - ps.PolicerDrops - ps.RandomDrops - ps.QueueDrops
						n.close()
					}
					b.ReportMetric(float64(retransmits)/float64(b.N), "retransmits/op")
					if accepted > 0 {
						b.ReportMetric(float64(wait.Microseconds())/float64(accepted), "queue-wait-us/pkt")
					}
					b.ReportMetric(float64(maxWait.Microseconds()), "max-queue-wait-us")
				})
			}
		}
	}
}
