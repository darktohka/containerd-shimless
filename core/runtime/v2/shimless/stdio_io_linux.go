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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containerd/fifo"
	"golang.org/x/sys/unix"
)

// parseStdioURL parses a stdio path. A missing scheme is the fifo scheme, which
// is how CRI passes container stdio (a bare fifo path).
func parseStdioURL(path string) (*url.URL, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse stdio path %q: %w", path, err)
	}
	if u.Scheme == "" {
		u.Scheme = "fifo"
	}
	return u, nil
}

// parseOutputURL parses an output path, returning nil for the empty path so the
// caller can substitute /dev/null.
func parseOutputURL(path string) (*url.URL, error) {
	if path == "" {
		return nil, nil
	}
	return parseStdioURL(path)
}

func isBinaryScheme(u *url.URL) bool {
	return u != nil && (u.Scheme == "binary" || u.Scheme == "binary-v2")
}

// binarySchemeURL returns the binary logging URI among the two output paths,
// preferring stdout, or nil when neither uses a binary scheme.
func binarySchemeURL(stdout, stderr *url.URL) *url.URL {
	if isBinaryScheme(stdout) {
		return stdout
	}
	if isBinaryScheme(stderr) {
		return stderr
	}
	return nil
}

// openNull opens /dev/null with the given flags.
func openNull(flag int) (*os.File, error) {
	f, err := os.OpenFile(os.DevNull, flag, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	return f, nil
}

// openContainerInput opens stdin for a non-terminal process. An empty path
// yields /dev/null so the container's fd 0 is always open.
func openContainerInput(path string) (*os.File, error) {
	if path == "" {
		return openNull(os.O_RDONLY)
	}
	u, err := parseStdioURL(path)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "fifo":
		f, err := os.OpenFile(u.Path, os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, fmt.Errorf("open stdin %s: %w", u.Path, err)
		}
		return f, nil
	case "file":
		f, err := os.OpenFile(u.Path, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("open stdin file %s: %w", u.Path, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("unsupported stdin scheme %q", u.Scheme)
	}
}

// openContainerOutputs opens stdout and stderr for a non-terminal process. An
// empty path yields /dev/null. A binary/binary-v2 URI starts one logging process
// that owns both streams, mirroring the shim's NewBinaryIO.
func (s *stdioConfig) openContainerOutputs(ctx context.Context, stdoutPath, stderrPath string) (stdout, stderr *os.File, logger *exec.Cmd, err error) {
	stdoutURL, err := parseOutputURL(stdoutPath)
	if err != nil {
		return nil, nil, nil, err
	}
	stderrURL, err := parseOutputURL(stderrPath)
	if err != nil {
		return nil, nil, nil, err
	}

	if bin := binarySchemeURL(stdoutURL, stderrURL); bin != nil {
		b, err := startBinaryIO(bin, s.id, s.ns)
		if err != nil {
			return nil, nil, nil, err
		}
		if bin == stdoutURL {
			return b.outW, b.errW, b.cmd, nil
		}
		// Only stderr uses a binary logger: the logger's stdout pipe is unused.
		if cerr := b.outW.Close(); cerr != nil {
			_ = b.errW.Close()
			_ = stopLogger(b.cmd)
			return nil, nil, nil, fmt.Errorf("close unused logging stdout pipe: %w", cerr)
		}
		out, err := openOutput(stdoutPath)
		if err != nil {
			_ = b.errW.Close()
			_ = stopLogger(b.cmd)
			return nil, nil, nil, err
		}
		return out, b.errW, b.cmd, nil
	}

	stdout, err = openOutput(stdoutPath)
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err = openOutput(stderrPath)
	if err != nil {
		_ = stdout.Close()
		return nil, nil, nil, err
	}
	return stdout, stderr, nil, nil
}

// openOutput opens one container output path. An empty path yields /dev/null so
// the container's fd 1/2 is always open.
func openOutput(path string) (*os.File, error) {
	if path == "" {
		return openNull(os.O_RDWR)
	}
	u, err := parseStdioURL(path)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "fifo":
		f, err := os.OpenFile(u.Path, os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, fmt.Errorf("open fifo %s: %w", u.Path, err)
		}
		return f, nil
	case "file":
		if err := os.MkdirAll(filepath.Dir(u.Path), 0o755); err != nil {
			return nil, fmt.Errorf("create log directory for %s: %w", u.Path, err)
		}
		f, err := os.OpenFile(u.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open log file %s: %w", u.Path, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("unsupported output scheme %q", u.Scheme)
	}
}

// openBridgeInput opens the client stdin side of a terminal bridge. A fifo is
// opened non-blocking so newStdioConfig never stalls waiting for a writer.
func openBridgeInput(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := parseStdioURL(path)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "fifo":
		in, err := fifo.OpenFifo(ctx, u.Path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, fmt.Errorf("open stdin fifo %s: %w", u.Path, err)
		}
		return in, nil
	case "file":
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, fmt.Errorf("open stdin file %s: %w", u.Path, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("unsupported stdin scheme %q", u.Scheme)
	}
}

// openBridgeOutput opens the client stdout side of a terminal bridge. A binary
// URI starts a logging process and its stdout pipe receives the pty output; the
// logger's stderr pipe is unused because terminal stderr is part of the pty.
func (s *stdioConfig) openBridgeOutput(ctx context.Context, path string) (io.WriteCloser, *exec.Cmd, error) {
	if path == "" {
		f, err := openNull(os.O_WRONLY)
		return f, nil, err
	}
	u, err := parseStdioURL(path)
	if err != nil {
		return nil, nil, err
	}
	switch u.Scheme {
	case "binary", "binary-v2":
		b, err := startBinaryIO(u, s.id, s.ns)
		if err != nil {
			return nil, nil, err
		}
		_ = b.errW.Close()
		return b.outW, b.cmd, nil
	case "fifo":
		f, err := openBridgeFifoOutput(u.Path)
		if err != nil {
			return nil, nil, err
		}
		return f, nil, nil
	case "file":
		f, err := openOutput(path)
		if err != nil {
			return nil, nil, err
		}
		return f, nil, nil
	default:
		return nil, nil, fmt.Errorf("unsupported terminal output scheme %q", u.Scheme)
	}
}

// openBridgeFifoOutput opens a fifo for the terminal bridge. O_RDWR makes the
// open succeed before the client attaches; leaving O_NONBLOCK clear makes the
// copy block on a slow client instead of failing with EAGAIN.
func openBridgeFifoOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open stdout fifo %s: %w", path, err)
	}
	return f, nil
}
