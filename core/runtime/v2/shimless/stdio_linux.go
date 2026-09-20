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
// deleted. It is nil for tasks reconciled after a daemon restart, so every
// method tolerates a nil receiver.
type stdioConfig struct {
	id       string
	ns       string
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

	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// newStdioConfig parses the runtime IO paths and prepares everything crun needs.
// It never returns a config holding a typed-nil file: for a non-terminal
// process every stream is a real open descriptor, and for a terminal process it
// creates the console socket and the client-side bridge.
func newStdioConfig(ctx context.Context, id, ns string, stdio runtime.IO) (*stdioConfig, error) {
	s := &stdioConfig{id: id, ns: ns, terminal: stdio.Terminal}

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
		out, logger, err := s.openBridgeOutput(ctx, stdio.Stdout)
		if err != nil {
			_ = socket.Close()
			return nil, err
		}
		s.bridgeOut = out
		s.logger = logger
		return s, nil
	}

	stdin, err := openContainerInput(stdio.Stdin)
	if err != nil {
		return nil, err
	}
	s.stdin = stdin
	stdout, stderr, logger, err := s.openContainerOutputs(ctx, stdio.Stdout, stdio.Stderr)
	if err != nil {
		s.closeContainerFiles()
		return nil, err
	}
	s.stdout, s.stderr, s.logger = stdout, stderr, logger
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
func (s *stdioConfig) finish(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.terminal {
		s.closeContainerFiles()
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
	return errors.Join(errs...)
}

// containerFiles returns the fds handed to crun. It exists so tests can assert
// on the concrete files rather than on interface fields.
func (s *stdioConfig) containerFiles() (stdin, stdout, stderr *os.File) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stdin, s.stdout, s.stderr
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
