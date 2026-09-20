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

package shimless

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/runtime/v2/shimless/logdriver"
)

const (
	// inProcessLogCloseTimeout bounds how long inProcessLog.Close waits for the
	// reader goroutines to drain after their FIFOs are closed. It matches the
	// terminal bridge teardown budget so shutdown never blocks unbounded.
	inProcessLogCloseTimeout = 5 * time.Second

	// logReadChunk is the FIFO read size, matching the shim's logging reader.
	logReadChunk = 32 << 10

	// Stream names used by the logdriver contract.
	streamStdout = "stdout"
	streamStderr = "stderr"
)

// nerdctlLogDataStore returns the nerdctl data store encoded in a binary
// logging URI. nerdctl builds
// "binary://<nerdctl>?_NERDCTL_INTERNAL_LOGGING=<datastore>" so it can launch
// itself as the out-of-process logging consumer. When the query key is present
// with a non-empty value the engine can instead serve the container's
// log-config.json in-process. A plain binary URI (no query key) yields false.
func nerdctlLogDataStore(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}
	dataStore := u.Query().Get("_NERDCTL_INTERNAL_LOGGING")
	if dataStore == "" {
		return "", false
	}
	return dataStore, true
}

// inProcessLog consumes a task's crash-safe stdio FIFOs with an in-process
// logdriver.Sink, replacing the external nerdctl logging process for the
// drivers logdriver can serve. It owns the FIFO read descriptors and the sink.
//
// Close closes the descriptors (which unblocks the readers), waits for them
// with a bounded timeout, then closes the sink so the logger-lock is always
// released. Every method tolerates a nil receiver.
type inProcessLog struct {
	sink      logdriver.Sink
	out       *logdriver.Framer
	errFramer *logdriver.Framer

	readers []*os.File
	wg      sync.WaitGroup

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	closeErr  error
}

// startInProcessLog sets up an in-process logging session for a task. It
// creates the same per-task FIFOs the external logger uses, opens them O_RDWR
// and starts one reader goroutine per stream feeding a logdriver.Framer.
//
// It returns the FIFO descriptors so the caller can hand them to crun
// (non-terminal) or bridge the pty into them (terminal). bundle must be
// non-empty: without a bundle there is nowhere crash-safe to place the FIFOs,
// so logdriver.ErrUnsupported is returned and the caller falls back.
//
// tryLock mirrors logdriver.Open: with tryLock set a competing writer yields
// logdriver.ErrLocked, which the create path treats as "another writer is
// alive" and resolves by falling back to the external logger.
func startInProcessLog(dataStore, id, ns, bundle string, tryLock bool) (l *inProcessLog, stdout, stderr *os.File, err error) {
	if bundle == "" {
		// The crash-safe FIFO layout lives in the bundle; without one the
		// reader could not survive a daemon restart, so fall back.
		return nil, nil, nil, logdriver.ErrUnsupported
	}

	cfg, err := logdriver.LoadConfig(dataStore, ns, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if !logdriver.Supported(cfg.Driver) {
		return nil, nil, nil, logdriver.ErrUnsupported
	}

	outPath, errPath := fifoPaths(bundle, id)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return nil, nil, nil, fmt.Errorf("create stdio dir for %s: %w", id, err)
	}
	if err := mkfifo(outPath); err != nil {
		return nil, nil, nil, err
	}
	if err := mkfifo(errPath); err != nil {
		return nil, nil, nil, err
	}
	fifoOut, err := openFifoReadWrite(outPath)
	if err != nil {
		return nil, nil, nil, err
	}
	fifoErr, err := openFifoReadWrite(errPath)
	if err != nil {
		closeAll(fifoOut)
		return nil, nil, nil, err
	}

	// The reader goroutines use separate non-blocking descriptors. Closing a
	// blocking descriptor does not wake a read parked on it, whereas the
	// non-blocking one is pollable and is unblocked by Close. Keeping the
	// blocking descriptors for crun preserves blocking container writes.
	readOut, err := openFifoReadNonblock(outPath)
	if err != nil {
		closeAll(fifoOut, fifoErr)
		return nil, nil, nil, err
	}
	readErr, err := openFifoReadNonblock(errPath)
	if err != nil {
		closeAll(fifoOut, fifoErr, readOut)
		return nil, nil, nil, err
	}

	sink, err := logdriver.Open(dataStore, ns, id, cfg, tryLock)
	if err != nil {
		// Do not leave the freshly opened FIFOs behind on a failed start.
		closeAll(fifoOut, fifoErr, readOut, readErr)
		return nil, nil, nil, err
	}

	l = &inProcessLog{
		sink:      sink,
		out:       logdriver.NewFramer(sink, streamStdout),
		errFramer: logdriver.NewFramer(sink, streamStderr),
		readers:   []*os.File{readOut, readErr},
	}
	l.wg.Add(2)
	go l.readLoop(readOut, l.out)
	go l.readLoop(readErr, l.errFramer)
	return l, fifoOut, fifoErr, nil
}

// openFifoReadNonblock opens path O_RDWR|O_NONBLOCK for a reader goroutine.
// O_RDWR keeps a writer reference so the FIFO never reports EOF on its own; the
// non-blocking flag makes the descriptor pollable so closing it wakes a parked
// read.
func openFifoReadNonblock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open fifo %s for reading: %w", path, err)
	}
	return f, nil
}

// readLoop drains one FIFO into framer until the descriptor is closed. Closing
// the fd during shutdown makes Read return os.ErrClosed, which is the expected
// way this goroutine exits; any other error is recorded for Close to report.
// The goroutine lives outside any watcher loop, so a slow sink never blocks
// pidfd handling.
func (l *inProcessLog) readLoop(r *os.File, framer *logdriver.Framer) {
	defer l.wg.Done()
	buf := make([]byte, logReadChunk)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			if err := framer.Write(buf[:n]); err != nil {
				l.recordError(err)
				return
			}
		}
		if readErr != nil {
			// Flush the trailing fragment at stream end before returning.
			if err := framer.Flush(); err != nil {
				l.recordError(err)
			}
			if !errors.Is(readErr, os.ErrClosed) {
				l.recordError(readErr)
			}
			return
		}
	}
}

// recordError joins err into the error Close returns. It is called from the
// reader goroutines and from Close itself.
func (l *inProcessLog) recordError(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	l.closeErr = errors.Join(l.closeErr, err)
	l.mu.Unlock()
}

// Close stops the readers and closes the sink. It is idempotent.
//
// Closing the FIFO descriptors is what unblocks the readers; the subsequent
// wait is bounded so a stuck reader cannot wedge the daemon. The sink is always
// closed, even after a timeout, so the logger-lock is never leaked.
func (l *inProcessLog) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		readers := l.readers
		l.readers = nil
		sink := l.sink
		l.sink = nil
		l.mu.Unlock()

		for _, r := range readers {
			_ = r.Close()
		}

		drained := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(inProcessLogCloseTimeout):
			l.recordError(fmt.Errorf("timed out after %s waiting for log readers", inProcessLogCloseTimeout))
		}

		if sink != nil {
			if err := sink.Close(); err != nil {
				l.recordError(err)
			}
		}
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeErr
}
