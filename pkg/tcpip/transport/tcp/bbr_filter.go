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

// maxFilterSample is a sample of a windowed max filter.
//
// +stateify savable
type maxFilterSample struct {
	// t is the time of the sample, in the filter's unit of time.
	t uint64

	// v is the value of the sample.
	v uint64
}

// windowedMaxFilter tracks the largest value of a series of samples over a
// sliding window of time, using Kathleen Nichols' algorithm: it keeps the
// best sample in the window, and the best samples from the later parts of the
// window, so that when the best one leaves the window the next best is
// already known. Time is any increasing count, such as round trips.
//
// See draft-ietf-ccwg-bbr-07 section 5.5.5, UpdateWindowedMaxFilter().
//
// +stateify savable
type windowedMaxFilter struct {
	// s holds the best sample in the window and the best samples after it,
	// in time order: s[0] is the best, s[1] the best after s[0], and s[2]
	// the best after s[1].
	s [3]maxFilterSample
}

// get returns the largest value in the window.
func (f *windowedMaxFilter) get() uint64 {
	return f.s[0].v
}

// reset makes v, at time t, the only sample in the filter.
func (f *windowedMaxFilter) reset(t, v uint64) {
	f.s = [3]maxFilterSample{{t, v}, {t, v}, {t, v}}
}

// update adds the sample v at time t, which must not be earlier than the
// previous sample's, and returns the largest value seen in the last window
// units of time.
func (f *windowedMaxFilter) update(t, window, v uint64) uint64 {
	sample := maxFilterSample{t, v}
	if v >= f.s[0].v || t-f.s[2].t > window {
		// A new best value, or nothing left in the window.
		f.reset(t, v)
		return v
	}
	switch {
	case v >= f.s[1].v:
		f.s[1] = sample
		f.s[2] = sample
	case v >= f.s[2].v:
		f.s[2] = sample
	}

	// Expire samples that have left the window, and make sure that the
	// later samples come from later quarters of the window, so that they
	// are fresh enough when they become the best.
	switch elapsed := t - f.s[0].t; {
	case elapsed > window:
		f.s[0], f.s[1], f.s[2] = f.s[1], f.s[2], sample
		if t-f.s[0].t > window {
			f.s[0], f.s[1], f.s[2] = f.s[1], f.s[2], sample
		}
	case f.s[1].t == f.s[0].t && elapsed > window/4:
		f.s[1] = sample
		f.s[2] = sample
	case f.s[2].t == f.s[1].t && elapsed > window/2:
		f.s[2] = sample
	}
	return f.s[0].v
}
