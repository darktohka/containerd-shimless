//go:build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package logdriver

import (
	"sync"
	"testing"
)

// recordingSink records every WriteLine call for assertions.
type recordingSink struct {
	mu      sync.Mutex
	lines   []string
	streams []string
}

func (r *recordingSink) WriteLine(stream, line string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	r.streams = append(r.streams, stream)
	return nil
}

func (r *recordingSink) Close() error { return nil }

func (r *recordingSink) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

func TestFramerSplitsLinesAndEmitsTrailingFragment(t *testing.T) {
	rec := &recordingSink{}
	f := NewFramer(rec, streamStdout)

	if err := f.Write([]byte("a\nb")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := []string{"a\n", "b"}
	got := rec.snapshot()
	if len(got) != len(want) {
		t.Fatalf("after Write(\"a\\nb\"): got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("after Write(\"a\\nb\"): got %q, want %q", got, want)
		}
	}

	// A fragment with no newline is emitted immediately (json-file is a sync
	// driver), and Flush must not duplicate it.
	if err := f.Write([]byte("c")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	want = []string{"a\n", "b", "c"}
	got = rec.snapshot()
	if len(got) != len(want) {
		t.Fatalf("after Write(\"c\")+Flush: got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("after Write(\"c\")+Flush: got %q, want %q", got, want)
		}
	}
}

func TestFramerFlushEmptyIsNoop(t *testing.T) {
	rec := &recordingSink{}
	f := NewFramer(rec, streamStderr)
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("Flush on empty framer emitted %q", got)
	}
	if err := f.Write([]byte("x\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rec.snapshot(); len(got) != 1 || got[0] != "x\n" {
		t.Fatalf("got %q, want [\"x\\n\"]", got)
	}
}
