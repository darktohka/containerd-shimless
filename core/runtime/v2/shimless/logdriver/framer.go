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
	"bytes"
	"sync"
)

// Framer splits a container's raw stdio into log lines and forwards them to a
// Sink. It mirrors nerdctl's loggingProcessAdapter.processStream when the
// driver is a synchronous driver (json-file): complete newline-terminated
// lines are emitted as they arrive, and because json-file is synchronous any
// trailing fragment is emitted immediately rather than buffered until the
// stream ends.
//
// As a consequence a single logical line may be split across several entries
// when it arrives in fragments; that is expected parity behaviour and must not
// be "fixed".
type Framer struct {
	sink   Sink
	stream string

	mu      sync.Mutex
	pending []byte
}

// NewFramer returns a Framer that writes lines for stream ("stdout" or
// "stderr") to sink.
func NewFramer(sink Sink, stream string) *Framer {
	return &Framer{sink: sink, stream: stream}
}

// Write appends p, emits every complete newline-terminated line (including the
// '\n'), then emits any remaining non-empty fragment as its own line and
// clears the buffer. It returns the first write error encountered.
func (f *Framer) Write(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.pending = append(f.pending, p...)
	for {
		i := bytes.IndexByte(f.pending, '\n')
		if i < 0 {
			break
		}
		if err := f.sink.WriteLine(f.stream, string(f.pending[:i+1])); err != nil {
			return err
		}
		f.pending = f.pending[i+1:]
	}
	if len(f.pending) > 0 {
		if err := f.sink.WriteLine(f.stream, string(f.pending)); err != nil {
			return err
		}
		f.pending = f.pending[:0]
	}
	return nil
}

// Flush emits any remaining fragment at stream end. It is a no-op when the
// buffer is empty, so it never duplicates a fragment Write already emitted.
func (f *Framer) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil
	}
	err := f.sink.WriteLine(f.stream, string(f.pending))
	f.pending = f.pending[:0]
	return err
}
