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

// Package simnet runs TCP connections between two netstack stacks joined by a
// modelled path (package pathmodel) as a discrete-event simulation: the same
// configuration always gives the same packets at the same times, and a run
// takes far less real time than it simulates.
//
// Everything happens on the goroutine that calls Network.Run or RunFor: the
// timers of both stacks and of the path, one at a time on a virtual Clock,
// and the applications at both ends of each Flow. TCP's processor goroutines
// are the one exception; after the path delivers a packet, the network waits
// until the receiving stack's processors have handled everything queued to
// them (stack.TransportProtocol.Pause and Resume) before it moves on. Nothing
// depends on real time or on how goroutines are scheduled.
//
// The wait relies on Pause returning only once TCP's processors have handled
// every segment queued to them, and on segments reaching TCP only through
// the processors while no application call holds an endpoint. Both hold for
// the dispatcher in dispatcher.go; TestDeterministic would catch a change.
package simnet

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	// ClientAddr and ServerAddr are the addresses of the two stacks.
	ClientAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	ServerAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

const (
	// defaultMTU is the MTU of the links if Config.MTU is zero.
	defaultMTU = 1500

	// linkQueueLen is how many packets a link holds before the path takes
	// them. The path takes every packet as soon as it is sent, so this only
	// needs to cover one burst.
	linkQueueLen = 4096

	// firstPort is the server port of the first flow.
	firstPort = 1000

	// listenBacklog is the backlog of a flow's listener.
	listenBacklog = 16

	// rateTick is how often a flow limited to a rate writes.
	rateTick = time.Millisecond

	// maxWrite is the most a flow writes in one call.
	maxWrite = 64 << 10

	// patternLen is the period of the bytes a flow sends; it is prime so
	// that a shifted or repeated chunk does not match.
	patternLen = 251
)

// Config describes a simulated network.
type Config struct {
	// Data configures the direction of the path from the client to the
	// server, and Acks the other one.
	Data, Acks pathmodel.Config

	// MTU is the MTU of both links. Zero means 1500.
	MTU uint32

	// CC is the congestion control algorithm of both stacks. Empty means the
	// stack's default. BBR is made available before it is selected.
	CC tcpip.CongestionControlOption

	// RACK enables RACK loss detection. SACK is always enabled.
	RACK bool

	// BufferSize is the size in bytes of the send buffer and of the receive
	// buffer of every TCP socket of both stacks, and the most that either
	// may grow to. Zero means the stacks' defaults.
	//
	// A receiver advertises at most half its receive buffer as its window,
	// and a sender cannot send past the window while a lost packet is
	// repaired, which takes about two round trips. On a path that loses
	// packets this caps the sender near one window per two round trips,
	// whatever the congestion control: the defaults limit a 100 Mbit/s path
	// with 40ms of round-trip delay to less than half its rate.
	BufferSize int

	// Probe, if not nil, is called with the state of a client endpoint
	// after it processes each segment it receives, with the endpoint's lock
	// held.
	Probe tcp.TCPProbeFunc

	// Seed seeds the stacks' random number generators, which also choose
	// initial sequence numbers and ports.
	Seed uint64
}

// Verdict is what a Filter decides about a packet.
type Verdict struct {
	// Drop drops the packet.
	Drop bool

	// Delay holds the packet back for this long. Packets after it are not
	// held, so it arrives after them if they arrive within Delay.
	Delay time.Duration
}

// Filter decides what happens to each packet that a direction of the path
// delivers. It sees the packet's network header and payload, not parsed yet,
// and must not keep it.
type Filter func(pkt *stack.PacketBuffer) Verdict

// Network is a client stack and a server stack joined by a modelled path.
type Network struct {
	// Clock is the clock of the stacks and the path.
	Clock *Clock

	// Client and Server are the stacks at the two ends of the path.
	Client, Server *stack.Stack

	// Data carries the packets from the client to the server, and Acks those
	// from the server to the client.
	Data, Acks *pathmodel.Direction

	links [2]*channel.Endpoint
	tcp   [2]stack.TransportProtocol

	// The fields below are used only on the goroutine that runs the
	// network.

	// filters[i] and filterDrops[i] are the filter of Data (i = 0) or Acks
	// (i = 1), and the packets it dropped.
	filters     [2]Filter
	filterDrops [2]uint64

	// held holds the packets a filter delayed, until they are delivered.
	held map[*heldPacket]struct{}

	flows  []*Flow
	closed bool
}

// heldPacket is a packet a filter delayed.
type heldPacket struct {
	to    int
	proto tcpip.NetworkProtocolNumber
	pkt   *stack.PacketBuffer
}

// New returns a network configured by cfg.
func New(cfg Config) (*Network, error) {
	n := &Network{
		Clock: NewClock(),
		held:  make(map[*heldPacket]struct{}),
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	rng := &lockedReader{r: rand.NewChaCha8(seedBytes(cfg.Seed))}
	for i, addr := range []tcpip.Address{ClientAddr, ServerAddr} {
		proto := tcp.NewProtocol
		if i == 0 && cfg.Probe != nil {
			proto = tcp.NewProtocolProbe(cfg.Probe)
		}
		s := stack.New(stack.Options{
			Clock:              n.Clock,
			SecureRNG:          rng,
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{proto},
		})
		link := channel.New(linkQueueLen, mtu, "")
		n.links[i] = link
		if i == 0 {
			n.Client = s
		} else {
			n.Server = s
		}
		if err := configureStack(s, link, addr, cfg); err != nil {
			n.Close()
			return nil, err
		}
		n.tcp[i] = s.TransportProtocolInstance(tcp.ProtocolNumber)
	}
	n.Data = pathmodel.NewDirection(n.Clock, cfg.Data, n.deliverer(1))
	n.Acks = pathmodel.NewDirection(n.Clock, cfg.Acks, n.deliverer(0))
	n.links[0].AddNotify(&pump{from: n.links[0], to: n.Data})
	n.links[1].AddNotify(&pump{from: n.links[1], to: n.Acks})
	return n, nil
}

// configureStack gives s a NIC on link with address addr, and sets the TCP
// options of cfg.
func configureStack(s *stack.Stack, link *channel.Endpoint, addr tcpip.Address, cfg Config) error {
	if err := s.CreateNIC(1, link); err != nil {
		return fmt.Errorf("creating the NIC: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("adding the address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	opts := []tcpip.SettableTransportProtocolOption{}
	if cfg.CC == "bbr" {
		avail := tcpip.TCPAvailableCongestionControlOption("reno cubic bbr")
		opts = append(opts, &avail)
	}
	if cfg.CC != "" {
		cc := cfg.CC
		opts = append(opts, &cc)
	}
	recovery := tcpip.TCPRecovery(0)
	if cfg.RACK {
		recovery = tcpip.TCPRACKLossDetection
	}
	sack := tcpip.TCPSACKEnabled(true)
	opts = append(opts, &recovery, &sack)
	if cfg.BufferSize != 0 {
		if cfg.BufferSize < tcp.MinBufferSize {
			return fmt.Errorf("BufferSize = %d, want 0 or at least %d", cfg.BufferSize, tcp.MinBufferSize)
		}
		snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: cfg.BufferSize, Max: cfg.BufferSize}
		rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: cfg.BufferSize, Max: cfg.BufferSize}
		opts = append(opts, &snd, &rcv)
	}
	for _, opt := range opts {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fmt.Errorf("setting %T: %s", opt, err)
		}
	}
	return nil
}

// SetFilter sets the filter of d, Data or Acks; nil removes it.
func (n *Network) SetFilter(d *pathmodel.Direction, f Filter) {
	n.filters[n.index(d)] = f
}

// FilterDrops returns how many packets the filters of d, Data or Acks, have
// dropped.
func (n *Network) FilterDrops(d *pathmodel.Direction) uint64 {
	return n.filterDrops[n.index(d)]
}

// index returns 0 for Data and 1 for Acks.
func (n *Network) index(d *pathmodel.Direction) int {
	switch d {
	case n.Data:
		return 0
	case n.Acks:
		return 1
	default:
		panic("simnet: not a direction of this network")
	}
}

// deliverer returns the function through which a direction hands packets to
// the stack with index to: 0 for the client and 1 for the server.
func (n *Network) deliverer(to int) func(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	// Data (index 0) delivers to the server (1), and Acks (1) to the client
	// (0).
	dir := 1 - to
	return func(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
		if f := n.filters[dir]; f != nil {
			v := f(pkt)
			if v.Drop {
				n.filterDrops[dir]++
				return
			}
			if v.Delay > 0 {
				n.hold(to, proto, pkt, v.Delay)
				return
			}
		}
		n.inject(to, proto, pkt)
	}
}

// hold delivers pkt to stack to after d.
func (n *Network) hold(to int, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer, d time.Duration) {
	if n.closed {
		return
	}
	h := &heldPacket{to: to, proto: proto, pkt: pkt.IncRef()}
	n.held[h] = struct{}{}
	n.Clock.AfterFunc(d, func() {
		if _, ok := n.held[h]; !ok {
			// Released by Close.
			return
		}
		delete(n.held, h)
		n.inject(h.to, h.proto, h.pkt)
		h.pkt.DecRef()
	})
}

// inject delivers pkt to stack to and waits until the stack has processed
// it.
func (n *Network) inject(to int, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if n.closed {
		return
	}
	n.links[to].InjectInbound(proto, pkt)
	// Why: TCP processes segments on its processor goroutines. Pausing the
	// protocol returns once they have handled everything queued to them.
	n.tcp[to].Pause()
	n.tcp[to].Resume()
}

// Run runs the network until done, called after every event, returns true.
// It returns an error if that has not happened after limit of simulated
// time, or if nothing is left to happen.
func (n *Network) Run(limit time.Duration, done func() bool) error {
	end := n.Clock.Elapsed() + limit
	for !done() {
		at, ok := n.Clock.Next()
		if !ok {
			return fmt.Errorf("simnet: nothing left to happen at %v", n.Clock.Elapsed())
		}
		if at > end {
			n.Clock.AdvanceTo(end)
			return fmt.Errorf("simnet: condition not met after %v", limit)
		}
		n.step()
	}
	return nil
}

// RunFor runs the network for d of simulated time.
func (n *Network) RunFor(d time.Duration) {
	end := n.Clock.Elapsed() + d
	for {
		at, ok := n.Clock.Next()
		if !ok || at > end {
			break
		}
		n.step()
	}
	n.Clock.AdvanceTo(end)
}

// step runs the next event, then lets the applications act.
func (n *Network) step() {
	n.Clock.Step()
	for _, f := range n.flows {
		f.act()
	}
}

// Close releases the network's resources. The network must not be run again.
func (n *Network) Close() {
	if n.closed {
		return
	}
	n.closed = true
	if n.Data != nil {
		n.Data.Close()
		n.Acks.Close()
	}
	for h := range n.held {
		h.pkt.DecRef()
	}
	n.held = nil
	for _, f := range n.flows {
		f.stopTicks()
		f.Client.Close()
		f.Server.Close()
	}
	for _, s := range []*stack.Stack{n.Client, n.Server} {
		if s != nil {
			s.Close()
			s.Wait()
		}
	}
	for _, link := range n.links {
		if link != nil {
			link.Close()
		}
	}
}

// pump hands the packets a link sends to a direction of the path, on the
// goroutine that sends them.
type pump struct {
	// mu keeps packets in order if two goroutines send at once.
	mu   sync.Mutex
	from *channel.Endpoint
	to   *pathmodel.Direction
}

// WriteNotify implements channel.Notification.WriteNotify.
func (p *pump) WriteNotify() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for pkt := p.from.Read(); pkt != nil; pkt = p.from.Read() {
		// The packet was built to be sent. The receiver needs one that has
		// not been parsed yet.
		in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(pkt.ToView())})
		proto := pkt.NetworkProtocolNumber
		pkt.DecRef()
		p.to.Send(proto, in)
	}
}

// Segment describes a TCP segment carried by a packet.
type Segment struct {
	Seq, Ack   seqnum.Value
	PayloadLen int
	Flags      header.TCPFlags
}

// ParseSegment returns the TCP segment that pkt, as a Filter sees it,
// carries, and false if it carries none.
func ParseSegment(pkt *stack.PacketBuffer) (Segment, bool) {
	v := pkt.ToView()
	defer v.Release()
	ip := header.IPv4(v.AsSlice())
	if !ip.IsValid(len(ip)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return Segment{}, false
	}
	b := ip.Payload()
	if len(b) < header.TCPMinimumSize {
		return Segment{}, false
	}
	t := header.TCP(b)
	off := int(t.DataOffset())
	if off < header.TCPMinimumSize || off > len(b) {
		return Segment{}, false
	}
	return Segment{
		Seq:        seqnum.Value(t.SequenceNumber()),
		Ack:        seqnum.Value(t.AckNumber()),
		PayloadLen: len(b) - off,
		Flags:      t.Flags(),
	}, true
}

// lockedReader makes a random byte stream safe for concurrent use.
type lockedReader struct {
	mu sync.Mutex
	r  *rand.ChaCha8
}

// Read implements io.Reader.Read.
func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// seedBytes expands seed into a ChaCha8 seed.
func seedBytes(seed uint64) [32]byte {
	var b [32]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(seed >> (8 * i))
	}
	return b
}

// flowMode is what a flow's client application does.
type flowMode int

const (
	// idle writes nothing.
	idle flowMode = iota
	// bulk keeps the send buffer full.
	bulk
	// limited writes at a fixed rate.
	limited
)

// Flow is a TCP connection from the client to the server that carries data
// one way. The network plays both applications: the client writes as the
// flow's mode says, and the server reads everything as soon as it arrives.
// The data follows a pattern, which the server checks.
type Flow struct {
	n *Network

	// Client and Server are the two ends of the connection.
	Client, Server tcpip.Endpoint

	mode flowMode
	// rate and budget are the rate of a limited flow, and how many bytes it
	// may still write.
	rate   uint64
	budget uint64
	// carry is the remainder, in bytes times seconds, of the last tick's
	// budget.
	carry uint64
	tick  tcpip.Timer

	sent, received uint64
	err            error
	pattern        []byte
}

// Dial opens a flow from the client to the server and runs the network until
// the connection is established. The flow starts idle.
func (n *Network) Dial() (*Flow, error) {
	port := uint16(firstPort + len(n.flows))
	var lwq, cwq waiter.Queue
	l, err := n.Server.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &lwq)
	if err != nil {
		return nil, fmt.Errorf("creating an endpoint: %s", err)
	}
	defer l.Close()
	if err := l.Bind(tcpip.FullAddress{Port: port}); err != nil {
		return nil, fmt.Errorf("binding: %s", err)
	}
	// Why not a backlog of 1: it makes the listener answer with a SYN
	// cookie, which loses window scaling, SACK and timestamps.
	if err := l.Listen(listenBacklog); err != nil {
		return nil, fmt.Errorf("listening: %s", err)
	}
	cookies := n.Server.Stats().TCP.ListenOverflowSynCookieSent.Value()
	c, err := n.Client.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &cwq)
	if err != nil {
		return nil, fmt.Errorf("creating an endpoint: %s", err)
	}
	switch err := c.Connect(tcpip.FullAddress{Addr: ServerAddr, Port: port}); err.(type) {
	case nil, *tcpip.ErrConnectStarted:
	default:
		c.Close()
		return nil, fmt.Errorf("connecting: %s", err)
	}
	var s tcpip.Endpoint
	done := func() bool {
		if s == nil {
			if ep, _, err := l.Accept(nil); err == nil {
				s = ep
			}
		}
		return s != nil && c.(*tcp.Endpoint).EndpointState() == tcp.StateEstablished
	}
	if err := n.Run(time.Minute, done); err != nil {
		c.Close()
		if s != nil {
			s.Close()
		}
		return nil, fmt.Errorf("connecting: %w", err)
	}
	if n.Server.Stats().TCP.ListenOverflowSynCookieSent.Value() != cookies {
		c.Close()
		s.Close()
		return nil, fmt.Errorf("the server answered with a SYN cookie")
	}
	f := &Flow{n: n, Client: c, Server: s, pattern: makePattern()}
	n.flows = append(n.flows, f)
	return f, nil
}

// makePattern returns the bytes a flow sends, from any offset in the first
// patternLen bytes onwards for maxWrite bytes.
func makePattern() []byte {
	b := make([]byte, maxWrite+patternLen)
	for i := range b {
		b[i] = byte(i % patternLen)
	}
	return b
}

// Bulk makes the client write as much as the send buffer takes.
func (f *Flow) Bulk() {
	f.stopTicks()
	f.mode = bulk
	f.write(^uint64(0))
}

// Limit makes the client write rate bytes per second, in writes every
// millisecond.
func (f *Flow) Limit(rate uint64) {
	f.stopTicks()
	f.mode = limited
	f.rate = rate
	f.budget = 0
	f.carry = 0
	f.tick = f.n.Clock.AfterFunc(rateTick, f.onTick)
}

// Stop makes the client stop writing.
func (f *Flow) Stop() {
	f.stopTicks()
	f.mode = idle
}

// Sent returns how many bytes the client has written.
func (f *Flow) Sent() uint64 { return f.sent }

// Received returns how many bytes the server has read.
func (f *Flow) Received() uint64 { return f.received }

// Err returns the first error the applications saw, such as data that did
// not match what was sent.
func (f *Flow) Err() error { return f.err }

func (f *Flow) stopTicks() {
	if f.tick != nil {
		f.tick.Stop()
		f.tick = nil
	}
}

// onTick adds a tick's worth of data to a limited flow's budget and writes
// it.
func (f *Flow) onTick() {
	if f.mode != limited {
		return
	}
	// Exactly rate bytes per second, keeping the remainder.
	total := f.rate*uint64(rateTick) + f.carry
	f.budget += total / uint64(time.Second)
	f.carry = total % uint64(time.Second)
	f.budget -= f.write(f.budget)
	f.tick.Reset(rateTick)
}

// act lets the applications act after an event: the server reads what has
// arrived, and a bulk client fills the send buffer.
func (f *Flow) act() {
	f.read()
	if f.mode == bulk {
		f.write(^uint64(0))
	}
}

// write writes up to limit bytes without blocking and returns how many it
// wrote.
func (f *Flow) write(limit uint64) uint64 {
	var total uint64
	for total < limit {
		size := min(limit-total, maxWrite)
		start := f.sent % patternLen
		var r bytes.Reader
		r.Reset(f.pattern[start : start+size])
		n, err := f.Client.Write(&r, tcpip.WriteOptions{})
		f.sent += uint64(n)
		total += uint64(n)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				f.fail(fmt.Errorf("writing: %s", err))
			}
			break
		}
		if n == 0 {
			break
		}
	}
	return total
}

// read reads everything the server has received, checking it.
func (f *Flow) read() {
	for {
		_, err := f.Server.Read((*checker)(f), tcpip.ReadOptions{})
		if err != nil {
			switch err.(type) {
			case *tcpip.ErrWouldBlock, *tcpip.ErrClosedForReceive:
			default:
				f.fail(fmt.Errorf("reading: %s", err))
			}
			return
		}
	}
}

func (f *Flow) fail(err error) {
	if f.err == nil {
		f.err = err
	}
}

// checker is a Flow as the io.Writer the server reads into.
type checker Flow

// Write implements io.Writer.Write.
func (c *checker) Write(p []byte) (int, error) {
	f := (*Flow)(c)
	for i, b := range p {
		if want := byte((f.received + uint64(i)) % patternLen); b != want {
			err := fmt.Errorf("byte %d is %d, want %d", f.received+uint64(i), b, want)
			f.fail(err)
			return i, err
		}
	}
	f.received += uint64(len(p))
	return len(p), nil
}

var _ io.Writer = (*checker)(nil)
