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
	"io"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	// binaryIOProcTermTimeout bounds how long Close waits for a logging binary
	// to exit after SIGTERM before killing it, mirroring the shim's
	// binaryIOProcTermTimeout.
	binaryIOProcTermTimeout = 12 * time.Second
)

// binaryIO holds the container-side write ends of the pipes feeding a logging
// binary. The engine hands them to crun and releases its own copies once crun
// has forked the container.
type binaryIO struct {
	cmd  *exec.Cmd
	outW *os.File
	errW *os.File
}

// startBinaryIO runs a custom binary process for pluggable logging, mirroring
// the shim's NewBinaryIO. The logger receives the container stdout and stderr
// write ends as fds 3 and 4 and a readiness pipe as fd 5; the engine keeps the
// write ends to hand to crun.
func startBinaryIO(uri *url.URL, id, ns string) (*binaryIO, error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	serrR, serrW, err := os.Pipe()
	if err != nil {
		closeAll(outR, outW)
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		closeAll(outR, outW, serrR, serrW)
		return nil, fmt.Errorf("create ready pipe: %w", err)
	}

	cmd := newBinaryCmd(uri, id, ns)
	cmd.ExtraFiles = []*os.File{outR, serrR, readyW}
	if err := cmd.Start(); err != nil {
		closeAll(outR, outW, serrR, serrW, readyR, readyW)
		return nil, fmt.Errorf("start logging binary %s: %w", uri.Path, err)
	}
	// The child owns the read ends and the readiness write end now.
	closeAll(outR, serrR, readyW)

	b := make([]byte, 1)
	n, rerr := readyR.Read(b)
	_ = readyR.Close()
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		closeAll(outW, serrW)
		_ = stopLogger(cmd)
		return nil, fmt.Errorf("wait for logging binary %s: %w", uri.Path, rerr)
	}
	if uri.Scheme == "binary-v2" && n == 0 {
		closeAll(outW, serrW)
		_ = stopLogger(cmd)
		return nil, fmt.Errorf("logging binary %s did not call ready", uri.Path)
	}
	return &binaryIO{cmd: cmd, outW: outW, errW: serrW}, nil
}

// newBinaryCmd builds the logging binary command from a binary URI, mirroring
// the shim's process.NewBinaryCmd.
func newBinaryCmd(uri *url.URL, id, ns string) *exec.Cmd {
	var args []string
	for k, vs := range uri.Query() {
		args = append(args, k)
		if len(vs) > 0 {
			args = append(args, vs[0])
		}
	}
	cmd := exec.Command(uri.Path, args...)
	cmd.Env = append(cmd.Env,
		"CONTAINER_ID="+id,
		"CONTAINER_NAMESPACE="+ns,
	)
	return cmd
}

// stopLogger sends SIGTERM to the logging process and waits for it, killing it
// after binaryIOProcTermTimeout. A process that exits because of the SIGTERM we
// sent is not an error.
func stopLogger(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		killErr := cmd.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		return errors.Join(
			fmt.Errorf("signal logging binary: %w", err),
			killErr,
			ignoreExitError(cmd.Wait()),
		)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if isSIGTERMExit(err) {
			return nil
		}
		return err
	case <-time.After(binaryIOProcTermTimeout):
		_ = cmd.Process.Kill()
		return nil
	}
}

// isSIGTERMExit reports whether err is the process exiting because of SIGTERM.
func isSIGTERMExit(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGTERM
}

// ignoreExitError drops a nonzero process exit from the caller's error while
// keeping the error that explains why we stopped the process.
func ignoreExitError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	return err
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
