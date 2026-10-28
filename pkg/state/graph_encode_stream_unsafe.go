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

package state

import (
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"reflect"
	"slices"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/state/wire"
)

// process encodes queued work until none remains.
func (es *graphEncodeState) process() {
	for es.queueHead < len(es.queue) {
		w := es.queue[es.queueHead]
		es.queueHead++
		o := es.obj(w.obj)
		if o.parent >= 0 && (!o.isArray || !es.sameTypeArrayChain(w.obj)) {
			// The object that absorbed this object encodes it.
			continue
		}
		start := len(es.out.b)
		if o.isArray {
			esz := o.ti.size
			lo, hi := o.addr+w.start*esz, o.addr+w.end*esz
			elem, n := leafArray(o.ti, w.end-w.start)
			p := add(o.base, w.start*esz)
			es.setupSplices(w.obj, lo, hi)
			es.encodeElems(elem, p, n)
			es.finishSplices()
			o = es.obj(w.obj)
			es.addChunk(o, chunk{elemRange: w.elemRange, seg: segment{start, len(es.out.b) - start}})
			continue
		}
		o.state = objEncoding
		if o.isMap {
			n := es.encodeMap(o.ti, o.base)
			es.obj(w.obj).n = uintptr(n)
		} else {
			base, end, ti := o.base, o.end, o.ti
			es.setupSplices(w.obj, o.addr, end)
			es.encodeValue(ti, base)
			es.finishSplices()
		}
		o = es.obj(w.obj)
		o.seg = segment{start, len(es.out.b) - start}
		o.state = objDone
	}
}

// arrayChunks appends the encoded chunks of the live array obj and of the
// arrays of the same type that it absorbed.
func (es *graphEncodeState) arrayChunks(obj int32, shift uintptr, out []chunk) []chunk {
	o := es.obj(obj)
	for _, ch := range es.chunkList(o) {
		ch.start += shift
		ch.end += shift
		out = append(out, ch)
	}
	for _, c := range o.childList() {
		if co := es.obj(c); co.isArray && co.ti == o.ti && co.parentOff%o.ti.size == 0 {
			out = es.arrayChunks(c, shift+co.parentOff/o.ti.size, out)
		}
	}
	return out
}

// streamMagic starts every stream.
const streamMagic = 0x32534776

// save serializes the object graph rooted at the value of type ti at root,
// and appends it to w.
//
// The stream is:
//
//   - streamMagic, and the schema fingerprint of the binary.
//   - The type table: the types of objects and of the values of interfaces.
//   - The object table: the kind and type of each object.
//   - The target table: the object and offset of each pointer target.
//   - The data of each object, in order. Pointers are target indices.
func (es *graphEncodeState) save(root unsafe.Pointer, ti *typeInfo, w *encBuf) {
	size := max(ti.size, 1)
	obj := es.newObject(root, uintptr(root)+size, ti, 1, false)
	if ti.size != 0 {
		es.index(obj)
	}
	es.enqueue(obj, 0, 1)
	es.process()
	if es.obj(0).parent >= 0 {
		Failf("root object %v is within another object", ti.typ)
	}

	// Resolve zero-sized targets within objects.
	for _, tid := range es.zeroTargets {
		t := es.target(tid)
		if t.addr == graphDummyAddr() {
			continue
		}
		if ov := es.query(t.addr, t.addr+1); len(ov) == 1 {
			o := es.obj(ov[0])
			off := t.addr - o.addr
			if o.isMap {
				continue
			}
			if o.isArray {
				esz := o.ti.size
				rElem, _ := leafArray(o.ti, o.n)
				tElem, _ := leafArray(t.ti, 1)
				if off < o.end-o.addr && ((off%rElem.size == 0 && tElem == rElem) || es.contains(o.ti, t.ti, off%esz, 1)) {
					t.obj, t.off = ov[0], off
				}
			} else if off < o.ti.size && es.contains(o.ti, t.ti, off, 1) {
				t.obj, t.off = ov[0], off
			}
		}
	}

	// Number the live objects.
	var n int32
	for i := int32(0); i < int32(es.objs.n); i++ {
		if es.obj(i).parent < 0 {
			es.obj(i).final = n
			n++
		}
	}

	// Object table.
	var tables encBuf
	tables.grow(int(n)*4 + es.targets.n*3 + 64)
	tables.uvarint(uint64(n))
	dataMaxBytes := 0
	for i := int32(0); i < int32(es.objs.n); i++ {
		o := es.obj(i)
		if o.isArray {
			for _, ch := range es.chunkList(o) {
				// Each chunk writes start-delta and length uvarints plus its payload.
				dataMaxBytes += 2*binary.MaxVarintLen64 + ch.seg.len
			}
		}
		if o.parent >= 0 {
			continue
		}
		switch {
		case o.isMap:
			tables.byte(objKindMap)
			tables.uvarint(uint64(o.n))
			// Map payload is prefixed with its byte-length uvarint.
			dataMaxBytes += binary.MaxVarintLen64 + o.seg.len
		case o.isArray:
			idx, flag := es.types.objectIndex(o.ti)
			tables.byte(objKindArray | flag)
			tables.uvarint(uint64(idx))
			tables.uvarint(uint64(o.n))
			// Array payload begins with a chunk-count uvarint, plus an optional
			// byte-length uvarint when inexact.
			dataMaxBytes += 2 * binary.MaxVarintLen64
		default:
			var (
				idx  int
				flag byte
			)
			if i == 0 {
				idx = es.types.rootIndex(o.ti)
			} else {
				idx, flag = es.types.objectIndex(o.ti)
			}
			tables.byte(objKindValue | flag)
			tables.uvarint(uint64(idx))
			// Value payload has an optional byte-length uvarint when inexact.
			dataMaxBytes += binary.MaxVarintLen64 + o.seg.len
		}
	}

	// Target table.
	tables.uvarint(uint64(es.targets.n))
	for i := int32(0); i < int32(es.targets.n); i++ {
		t := es.target(i)
		if t.obj < 0 {
			tables.byte(0)
			continue
		}
		r, off := es.root(t.obj)
		off += t.off
		final := uint64(es.obj(r).final) + 1
		if off == 0 {
			tables.uvarint(final << 1)
		} else {
			tables.uvarint(final<<1 | 1)
			tables.uvarint(uint64(off))
		}
	}

	// Pre-size w with an upper bound on the stream size: 4-byte streamMagic +
	// 8-byte schemaFingerprint + uvarint type count + serialized tables +
	// object payload upper bound.
	const streamHeaderMaxBytes = 4 + 8 + binary.MaxVarintLen64
	w.grow(streamHeaderMaxBytes + len(es.types.buf.b) + len(tables.b) + dataMaxBytes)
	w.uint32(streamMagic)
	w.uint64(schemaFingerprint())
	w.uvarint(uint64(len(es.types.types)))
	w.bytes(es.types.buf.b)
	w.bytes(tables.b)
	var chunks []chunk
	for i := int32(0); i < int32(es.objs.n); i++ {
		o := es.obj(i)
		if o.parent >= 0 {
			continue
		}
		inexact := !o.isMap && i != 0 && es.types.isInexact(o.ti)
		if o.isMap || (inexact && !o.isArray) {
			// Maps are allocated, and inexact objects are decoded, once
			// referred to, which may be after their data, so their data is
			// skippable.
			w.uvarint(uint64(o.seg.len))
		}
		if !o.isArray {
			w.bytes(es.out.b[o.seg.off : o.seg.off+o.seg.len])
			continue
		}
		chunks = es.arrayChunks(int32(i), 0, chunks[:0])
		if inexact {
			// Prefix the data with its length.
			var sub encBuf
			es.writeChunks(&sub, o, chunks)
			w.uvarint(uint64(len(sub.b)))
			w.bytes(sub.b)
			continue
		}
		es.writeChunks(w, o, chunks)
	}
	es.stats.objects = int(n)
	setHints(ti, len(w.b), es.targets.n)
}

// writeChunks writes the chunks of an array object.
func (es *graphEncodeState) writeChunks(w *encBuf, o *encObject, chunks []chunk) {
	if len(chunks) > 1 {
		slices.SortFunc(chunks, func(a, b chunk) int { return cmp.Compare(a.start, b.start) })
	}
	w.uvarint(uint64(len(chunks)))
	var last uintptr
	for j, ch := range chunks {
		if j > 0 && ch.start < chunks[j-1].end {
			Failf("internal error: overlapping chunks of %v", o.ti.typ)
		}
		w.uvarint(uint64(ch.start - last))
		w.uvarint(uint64(ch.end - ch.start))
		last = ch.end
		w.bytes(es.out.b[ch.seg.off : ch.seg.off+ch.seg.len])
	}
}

// maxStreamLength is the maximum length of an object graph.
const maxStreamLength = 1 << 40

func (ge *graphStructEncoder) save(slot int, objPtr any) {
	e := efaceOf(&objPtr)
	ti := ge.st.slotType(slot, e.typ, true)
	ge.es.encodeValue(ti, e.data)
}

func (ge *graphStructEncoder) saveValue(slot int, obj any) {
	e := efaceOf(&obj)
	ti := ge.st.slotType(slot, e.typ, false)
	ge.es.encodeDynamic(ti, e.data)
}

func saveGraph(ctx context.Context, w io.Writer, rootPtr any) (Stats, error) {
	start := gohacks.Nanotime()
	e := efaceOf(&rootPtr)
	var ti *typeInfo
	if err := safely(func() {
		ti = typeInfoForRtype(e.typ)
		if ti.kind != reflect.Pointer || e.data == nil {
			Failf("Save requires a non-nil pointer, got %T", rootPtr)
		}
	}); err != nil {
		return Stats{graph: graphStats{used: true}}, err
	}
	es := newGraphEncodeState(ctx, ti.elem)
	defer es.release()
	es.stats.used = true
	es.stats.enabled = collectStats.Load()
	out := &es.final
	err := safely(func() {
		if es.stats.enabled {
			es.stats.init()
			defer es.stats.done()
		}
		es.save(e.data, ti.elem, out)
	})
	es.stats.bytes = len(out.b)
	es.stats.elapsed = gohacks.Nanotime() - start
	if err != nil {
		return Stats{graph: es.stats}, err
	}
	ww := wire.Writer{Writer: w}
	if err := writeGraphHeader(&ww, uint64(len(out.b))); err != nil {
		return Stats{graph: es.stats}, err
	}
	if _, err := w.Write(out.b); err != nil {
		return Stats{graph: es.stats}, err
	}
	return Stats{graph: es.stats}, nil
}
