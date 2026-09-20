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
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// binaryIOProcTermTimeout bounds how long Close waits for a logging binary
	// to exit after SIGTERM before killing it, mirroring the shim's
	// binaryIOProcTermTimeout.
	binaryIOProcTermTimeout = 12 * time.Second

	// binaryIOReadyTimeout bounds how long startBinaryIO waits for the logging
	// binary's readiness byte. A logger that survived a daemon restart can still
	// hold the logger lock, so an unbounded wait here could wedge the caller.
	binaryIOReadyTimeout = 60 * time.Second

	// stdioDirName is the per-bundle directory holding a task's crash-safe
	// stdio FIFOs. It survives a daemon restart, which is what lets a later
	// daemon re-open them and drain output buffered while it was down.
	stdioDirName = "stdio"
)

// binaryIO holds the container-side ends feeding a logging binary. For the
// FIFO path they are the named FIFOs the container inherits; the engine keeps
// its copies to hand to crun and releases them once crun has forked the
// container.
type binaryIO struct {
	cmd  *exec.Cmd
	outW *os.File
	errW *os.File
}

// fifoPaths returns the named FIFOs a task's binary logging output is routed
// through. They live inside the task bundle so they survive a daemon restart.
func fifoPaths(bundle, id string) (stdout, stderr string) {
	dir := filepath.Join(bundle, stdioDirName)
	return filepath.Join(dir, id+"-stdout.fifo"), filepath.Join(dir, id+"-stderr.fifo")
}

// startBinaryIO runs a custom binary process for pluggable logging, mirroring
// the shim's NewBinaryIO. When a bundle is available the container's output is
// routed through per-task named FIFOs opened O_RDWR; otherwise it falls back to
// the original anonymous-pipe implementation. In both cases the logger receives
// the container stdout and stderr ends as fds 3 and 4 and a readiness pipe as
// fd 5, and the engine keeps the write ends to hand to crun.
func startBinaryIO(uri *url.URL, id, ns, bundle string) (*binaryIO, error) {
	if bundle == "" {
		return startBinaryIOPipe(uri, id, ns)
	}
	return startBinaryIOFifo(uri, id, ns, bundle)
}

// startBinaryIOFifo is the crash-safe implementation. Opening the FIFOs O_RDWR
// makes the open return before any peer attaches, and the resulting shared open
// file description means the container's inherited fd counts as a read
// reference: the engine's death can no longer raise SIGPIPE/EPIPE in the
// container, and a late reader can reopen the FIFO to drain output buffered
// while the daemon was down.
func startBinaryIOFifo(uri *url.URL, id, ns, bundle string) (*binaryIO, error) {
	outPath, errPath := fifoPaths(bundle, id)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return nil, fmt.Errorf("create stdio dir for %s: %w", id, err)
	}
	if err := mkfifo(outPath); err != nil {
		return nil, err
	}
	if err := mkfifo(errPath); err != nil {
		return nil, err
	}
	fifoOut, err := openFifoReadWrite(outPath)
	if err != nil {
		return nil, err
	}
	fifoErr, err := openFifoReadWrite(errPath)
	if err != nil {
		closeAll(fifoOut)
		return nil, err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		closeAll(fifoOut, fifoErr)
		return nil, fmt.Errorf("create ready pipe: %w", err)
	}

	cmd := newBinaryCmd(uri, id, ns)
	cmd.ExtraFiles = []*os.File{fifoOut, fifoErr, readyW}
	if err := cmd.Start(); err != nil {
		closeAll(fifoOut, fifoErr, readyR, readyW)
		return nil, fmt.Errorf("start logging binary %s: %w", uri.Path, err)
	}
	// The child owns its copies of the FIFOs and of the readiness write end.
	_ = readyW.Close()

	n, rerr := waitBinaryReady(readyR)
	_ = readyR.Close()
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		closeAll(fifoOut, fifoErr)
		_ = stopLogger(cmd)
		return nil, fmt.Errorf("wait for logging binary %s: %w", uri.Path, rerr)
	}
	if uri.Scheme == "binary-v2" && n == 0 {
		closeAll(fifoOut, fifoErr)
		_ = stopLogger(cmd)
		return nil, fmt.Errorf("logging binary %s did not call ready", uri.Path)
	}
	return &binaryIO{cmd: cmd, outW: fifoOut, errW: fifoErr}, nil
}

// startBinaryIOPipe is the original anonymous-pipe implementation, kept for
// callers without a bundle.
func startBinaryIOPipe(uri *url.URL, id, ns string) (*binaryIO, error) {
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

	n, rerr := waitBinaryReady(readyR)
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

// mkfifo creates path as a FIFO. An existing FIFO is reused, so a re-attach
// after a daemon restart opens the same nodes the running container holds.
func mkfifo(path string) error {
	if err := unix.Mkfifo(path, 0o600); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create fifo %s: %w", path, err)
	}
	return nil
}

// openFifoReadWrite opens a FIFO O_RDWR. Linux returns immediately without
// waiting for a peer, and the descriptor keeps a read reference alive so the
// container's inherited fd never raises SIGPIPE on the engine's exit.
func openFifoReadWrite(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open fifo %s: %w", path, err)
	}
	return f, nil
}

// waitBinaryReady blocks until the logging binary writes its readiness byte or
// closes the pipe, bounded by binaryIOReadyTimeout.
func waitBinaryReady(readyR *os.File) (int, error) {
	_ = readyR.SetReadDeadline(time.Now().Add(binaryIOReadyTimeout))
	b := make([]byte, 1)
	return readyR.Read(b)
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
