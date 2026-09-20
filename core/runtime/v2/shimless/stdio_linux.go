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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/containerd/console"
	runc "github.com/containerd/go-runc"

	"github.com/containerd/containerd/v2/core/runtime"
)

// stdioConfig owns everything the engine needs to give a crun process correct
// stdio: the fds handed to crun, the pty console for terminal processes and its
// bridge to the client, and the optional binary logging process. It replaces
// the shim's processIO for the in-process engine.
//
// A stdioConfig is created per task/exec and closed when that process is
// deleted. It is nil for tasks reconciled after a daemon restart and re-attached
// on demand, so every method tolerates a nil receiver.
type stdioConfig struct {
	id       string
	ns       string
	bundle   string
	terminal bool

	// container-side files handed to crun for a non-terminal process. They are
	// always non-nil (empty paths open /dev/null) so the container never starts
	// with a closed fd 0/1/2.
	stdin  *os.File
	stdout *os.File
	stderr *os.File

	// terminal only: the socket crun sends the pty master over, and the master
	// once finish has received it.
	consoleSocket *runc.Socket
	console       console.Console
	consoleClosed bool

	// terminal only: the bridge between the client stdio paths and the pty.
	bridgeIn  io.ReadCloser
	bridgeOut io.WriteCloser
	bridgeWG  sync.WaitGroup

	// logger is the binary logging process, if a binary/binary-v2 URI was used.
	logger *exec.Cmd

	// log is the in-process logging consumer, set when a nerdctl binary URI
	// with a logdriver-supported driver was served in-process instead of by the
	// external logger process. It owns the stdio FIFO descriptors in that case.
	log *inProcessLog

	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// newStdioConfig parses the runtime IO paths and prepares everything crun needs.
// It never returns a config holding a typed-nil file: for a non-terminal
// process every stream is a real open descriptor, and for a terminal process it
// creates the console socket and the client-side bridge. bundle is the task
// bundle; it is empty for unit tests and for callers without a bundle, in which
// case binary logging falls back to anonymous pipes.
func newStdioConfig(ctx context.Context, id, ns, bundle string, stdio runtime.IO) (*stdioConfig, error) {
	s := &stdioConfig{id: id, ns: ns, bundle: bundle, terminal: stdio.Terminal}

	if stdio.Terminal {
		socket, err := runc.NewTempConsoleSocket()
		if err != nil {
			return nil, fmt.Errorf("create console socket: %w", err)
		}
		s.consoleSocket = socket

		if stdio.Stdin != "" {
			in, err := openBridgeInput(ctx, stdio.Stdin)
			if err != nil {
				_ = socket.Close()
				return nil, err
			}
			s.bridgeIn = in
		}

		// Terminal stderr is merged into the pty; only stdout carries output.
		out, logger, plog, err := s.openBridgeOutput(ctx, stdio.Stdout)
		if err != nil {
			_ = socket.Close()
			return nil, err
		}
		s.bridgeOut = out
		s.logger = logger
		s.log = plog
		return s, nil
	}

	stdin, err := openContainerInput(stdio.Stdin)
	if err != nil {
		return nil, err
	}
	s.stdin = stdin
	stdout, stderr, logger, plog, err := s.openContainerOutputs(ctx, stdio.Stdout, stdio.Stderr)
	if err != nil {
		s.closeContainerFiles()
		return nil, err
	}
	s.stdout, s.stderr, s.logger, s.log = stdout, stderr, logger, plog
	return s, nil
}

// apply hands the container-side stdio to crun. It only assigns non-nil files:
// assigning a typed-nil *os.File to exec.Cmd.Stdin (an interface field) would
// make the interface non-nil and leave the descriptor closed in the child.
// For a terminal process crun uses the pty for fd 0/1/2, so nothing is set.
func (s *stdioConfig) apply(cmd *exec.Cmd) {
	if s == nil || s.terminal {
		return
	}
	if s.stdin != nil {
		cmd.Stdin = s.stdin
	}
	if s.stdout != nil {
		cmd.Stdout = s.stdout
	}
	if s.stderr != nil {
		cmd.Stderr = s.stderr
	}
}

// finish is called once crun create/exec has returned. For a terminal process it
// receives the pty master and starts bridging it to the client; for a
// non-terminal process it releases the engine's copies of the container fds so
// a consumer observes EOF when the container exits.
//
// For binary logging the container fds are the per-task stdout/stderr FIFOs,
// opened O_RDWR. Closing the engine's copies here is safe and intentional: the
// container inherited the same open file description from crun and the logger
// inherited its own copy as fd 3/4, so the description stays alive. The
// container's inherited fd counts as a read reference, which is what prevents
// its next write from raising SIGPIPE when the engine no longer holds one.
func (s *stdioConfig) finish(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.terminal {
		// For an in-process log the engine's FIFO descriptors are the reader
		// goroutines' descriptors too: closing them here would starve the
		// readers and drop output buffered while the container was running.
		// They are closed by Close instead, which unblocks the readers.
		if s.log == nil {
			s.closeContainerFiles()
		}
		return nil
	}
	if s.consoleSocket == nil {
		return errors.New("terminal stdio has no console socket")
	}
	c, err := s.receiveConsole(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.console = c
	s.mu.Unlock()
	s.startBridge()
	return nil
}

// Resize resizes the pty master. A nil or non-terminal config is a no-op, so
// reconciled tasks (stdio == nil) and non-terminal processes tolerate it.
func (s *stdioConfig) Resize(size runtime.ConsoleSize) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.console == nil || s.consoleClosed {
		return nil
	}
	return s.console.Resize(console.WinSize{
		Width:  uint16(size.Width),
		Height: uint16(size.Height),
	})
}

// Close stops the bridge and the logging process and releases every fd. It is
// idempotent and tolerates a nil receiver.
func (s *stdioConfig) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.close()
	})
	return s.closeErr
}

func (s *stdioConfig) close() error {
	if s.bridgeIn != nil {
		_ = s.bridgeIn.Close()
	}
	s.closeConsole()
	drained := make(chan struct{})
	go func() {
		s.bridgeWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(bridgeCloseTimeout):
	}
	if s.bridgeOut != nil {
		_ = s.bridgeOut.Close()
	}

	s.closeContainerFiles()

	var errs []error
	if s.logger != nil {
		if err := stopLogger(s.logger); err != nil {
			errs = append(errs, err)
		}
		s.logger = nil
	}
	if s.consoleSocket != nil {
		if err := s.consoleSocket.Close(); err != nil {
			errs = append(errs, err)
		}
		s.consoleSocket = nil
	}
	// The in-process readers were already unblocked: closeContainerFiles ran
	// above for a non-terminal process and bridgeOut.Close ran for a terminal
	// one, so both already closed the FIFO descriptors. Close then waits for the
	// readers (bounded) and releases the logger lock by closing the sink.
	if s.log != nil {
		if err := s.log.Close(); err != nil {
			errs = append(errs, err)
		}
		s.log = nil
	}
	return errors.Join(errs...)
}

// containerFiles returns the fds handed to crun. It exists so tests can assert
// on the concrete files rather than on interface fields.
func (s *stdioConfig) containerFiles() (stdin, stdout, stderr *os.File) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stdin, s.stdout, s.stderr
}

// loggerPID returns the pid and start time of the external logging process, if
// one was started, so it can be persisted for reconcile. An in-process log has
// no external process, so (0, 0) is returned and reconcile will not treat one
// as having survived.
func (s *stdioConfig) loggerPID() (int, uint64) {
	if s == nil || s.log != nil || s.logger == nil || s.logger.Process == nil {
		return 0, 0
	}
	pid := s.logger.Process.Pid
	start, err := readStartTime(pid)
	if err != nil {
		return pid, 0
	}
	return pid, start
}

// closeContainerFiles releases the engine's copies of the container fds.
func (s *stdioConfig) closeContainerFiles() {
	s.mu.Lock()
	files := []*os.File{s.stdin, s.stdout, s.stderr}
	s.stdin, s.stdout, s.stderr = nil, nil, nil
	s.mu.Unlock()
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
