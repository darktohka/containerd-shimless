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
	"fmt"
	"io"
	"time"

	"github.com/containerd/console"
)

const (
	// consoleReceiveTimeout bounds how long finish waits for crun to hand over
	// the pty master over the console socket.
	consoleReceiveTimeout = 30 * time.Second
	// bridgeCloseTimeout bounds how long Close waits for the terminal bridge
	// goroutines to drain before giving up on them.
	bridgeCloseTimeout = 5 * time.Second
)

// closeConsole closes the pty master at most once.
func (s *stdioConfig) closeConsole() {
	s.mu.Lock()
	c := s.console
	if c == nil || s.consoleClosed {
		s.mu.Unlock()
		return
	}
	s.consoleClosed = true
	s.mu.Unlock()
	_ = c.Close()
}

// receiveConsole waits for crun to send the pty master. The receive runs in a
// goroutine so a cancelled create context or a stuck runtime cannot hang the
// daemon forever; closing the socket unblocks it.
func (s *stdioConfig) receiveConsole(ctx context.Context) (console.Console, error) {
	type result struct {
		console console.Console
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := s.consoleSocket.ReceiveMaster()
		ch <- result{console: c, err: err}
	}()
	timer := time.NewTimer(consoleReceiveTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("receive pty master: %w", r.err)
		}
		return r.console, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("timed out after %s waiting for the pty master", consoleReceiveTimeout)
	}
}

// startBridge copies the client stdin into the pty and the pty output to the
// client stdout. Terminal stderr is part of the pty and is not bridged.
func (s *stdioConfig) startBridge() {
	if s.bridgeIn != nil {
		s.bridgeWG.Add(1)
		go func() {
			defer s.bridgeWG.Done()
			defer s.bridgeIn.Close()
			_, _ = io.Copy(s.console, s.bridgeIn)
			// The client closed stdin: drop the pty so the process sees EOF.
			s.closeConsole()
		}()
	}
	if s.bridgeOut != nil {
		s.bridgeWG.Add(1)
		go func() {
			defer s.bridgeWG.Done()
			_, _ = io.Copy(s.bridgeOut, s.console)
			if c, ok := s.bridgeOut.(io.Closer); ok {
				_ = c.Close()
			}
		}()
	}
}
