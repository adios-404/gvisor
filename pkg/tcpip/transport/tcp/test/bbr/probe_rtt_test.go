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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// TestProbeRTTEndsAfterLoss checks that ProbeRTT ends on time on a path that
// lost packets earlier. ProbeRTT ends once C.inflight has fallen to its
// window, so the sender must apply the window to what is in flight. Its own
// estimate of the packets outstanding is left too low by a loss recovery
// that ends while retransmissions are still in flight, and a sender that
// went by the estimate would keep more in flight than ProbeRTT waits for.
func TestProbeRTTEndsAfterLoss(t *testing.T) {
	// A 50 Mbit/s path with 40ms of delay and a queue of one BDP, and
	// socket buffers of 1MiB, so that the receiver's window is two BDPs:
	// Startup fills the window and overflows the queue, and RACK repairs
	// the losses along with new data. No packet is lost after that.
	p := path{rate: 6_250_000, rtt: 40 * time.Millisecond, buffers: 1 << 20}
	p.queue = int(p.bdp())
	r := newRun(t, p)
	r.f.Bulk()
	// The first ProbeRTT comes 10 seconds after the handshake's RTT sample.
	r.n.RunFor(11500 * time.Millisecond)
	stats := r.n.Client.Stats().TCP
	if stats.Retransmits.Value() == 0 || stats.Timeouts.Value() != 0 {
		t.Fatalf("%d retransmissions and %d timeouts, want fast recovery only", stats.Retransmits.Value(), stats.Timeouts.Value())
	}
	// 200ms at the reduced window, after the round trip that gets there and
	// before the round trip that ends it.
	const limit = 200*time.Millisecond + 4*40*time.Millisecond
	var visits int
	var entered time.Duration
	in := false
	for _, s := range r.since(0) {
		switch probing := s.bbr.State == tcp.BBRProbeRTT; {
		case probing && !in:
			in, entered = true, s.at
			visits++
		case !probing && in:
			in = false
			if d := s.at - entered; d > limit {
				t.Errorf("ProbeRTT from %v took %v, want at most %v", entered, d, limit)
			}
		}
	}
	if in && r.now()-entered > limit {
		t.Errorf("in ProbeRTT since %v, at %v: %s", entered, r.now(), describe(r.last()))
	}
	if visits == 0 {
		t.Errorf("no ProbeRTT in %v", r.now())
	}
}
