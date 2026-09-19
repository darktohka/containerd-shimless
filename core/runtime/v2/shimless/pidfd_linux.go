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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	errNoExitInfo = errors.New("pidfd does not report exit info yet")
	errNoPidfd    = errors.New("no pidfd received")
)

// openPidfd opens a pidfd for pid with pidfd_open(2).
func openPidfd(pid int) (int, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, &os.PathError{Op: "pidfd_open", Path: strconv.Itoa(pid), Err: err}
	}
	return fd, nil
}

// readPidfdExit reads the raw wait status recorded for a reaped process from a
// pidfd. The second return is false when the kernel has not attached exit
// information yet (for example while the process is still a zombie); callers
// should retry.
func readPidfdExit(fd int) (unix.WaitStatus, bool) {
	info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_EXIT}
	if err := unix.IoctlPidfdInfo(fd, &info); err != nil {
		return 0, false
	}
	if info.Mask&unix.PIDFD_INFO_EXIT == 0 {
		return 0, false
	}
	// Exit_code is the raw wait(2) status, not a plain exit code: shift by 8
	// for a normal exit and check the low bits for a signal.
	return unix.WaitStatus(info.Exit_code), true
}

// waitPidfdExit polls a pidfd until the kernel exposes the exit status, up to
// timeout. A pidfd becomes readable when the process dies, but PIDFD_GET_INFO
// only reports the exit status once the process has been reaped, so a short
// retry window is required when the engine is not the parent.
func waitPidfdExit(fd int, timeout time.Duration) (unix.WaitStatus, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if ws, ok := readPidfdExit(fd); ok {
			return ws, true
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// decodeWaitStatus converts a raw wait(2) status into the containerd exit
// status and signal. A signaled process reports 128+signal, matching the OCI
// runtime convention (for example SIGKILL => 137).
func decodeWaitStatus(ws unix.WaitStatus) (status, signal uint32) {
	switch {
	case ws.Exited():
		return uint32(ws.ExitStatus()), 0
	case ws.Signaled():
		sig := uint32(ws.Signal())
		return 128 + sig, sig
	default:
		return 255, 0
	}
}

// readPidFile reads the pid written by crun --pid-file.
func readPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("parse pid file %s: %w", path, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d in %s", pid, path)
	}
	return pid, nil
}

// readStartTime returns the starttime field (22) of /proc/<pid>/stat. It is
// used together with cgroup membership to defeat pid reuse after a restart.
func readStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The comm field is parenthesized and may contain spaces or parentheses,
	// so split on the final ')' rather than on every space.
	s := string(data)
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 || idx+2 > len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[idx+2:])
	// fields[0] is the state (overall field 3); starttime is overall field 22.
	const starttimeIndex = 22 - 3
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	start, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime for %d: %w", pid, err)
	}
	return start, nil
}

// pidfdReceiver is a unix stream socket that crun connects to when the
// run.oci.pidfd_receiver annotation is present. crun sends the container
// init's pidfd over SCM_RIGHTS, which is the race-free alternative to opening
// a pidfd after reading --pid-file.
type pidfdReceiver struct {
	fd   int
	path string
	dir  string
}

// newPidfdReceiver binds a listening socket for bundle. It prefers a path in
// the bundle but falls back to a private temporary directory when the bundle
// path would not fit in sockaddr_un.
func newPidfdReceiver(bundle string) (*pidfdReceiver, error) {
	path := filepath.Join(bundle, "pidfd.sock")
	var dir string
	if len(path) >= 100 {
		var err error
		dir, err = os.MkdirTemp("", "shimless-sock-")
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "pidfd.sock")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, fmt.Errorf("bind pidfd receiver %s: %w", path, err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		unix.Close(fd)
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, fmt.Errorf("listen pidfd receiver %s: %w", path, err)
	}
	return &pidfdReceiver{fd: fd, path: path, dir: dir}, nil
}

// Path is the socket path to advertise in the run.oci.pidfd_receiver
// annotation.
func (r *pidfdReceiver) Path() string { return r.path }

// Receive waits up to timeout for crun to connect and send the pidfd.
func (r *pidfdReceiver) Receive(timeout time.Duration) (int, error) {
	pfd := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, int(timeout.Milliseconds()))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return -1, err
		}
		if n == 0 {
			return -1, fmt.Errorf("timed out waiting for pidfd: %w", unix.ETIMEDOUT)
		}
		break
	}

	conn, _, err := unix.Accept4(r.fd, unix.SOCK_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("accept pidfd receiver: %w", err)
	}
	defer unix.Close(conn)

	buf := make([]byte, 32)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(conn, buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recv pidfd: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse pidfd control message: %w", err)
	}
	for i := range msgs {
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			return -1, fmt.Errorf("parse pidfd rights: %w", err)
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errNoPidfd
}

// Close releases the listening socket and its temporary directory, if any.
func (r *pidfdReceiver) Close() error {
	err := unix.Close(r.fd)
	os.Remove(r.path)
	if r.dir != "" {
		os.RemoveAll(r.dir)
	}
	return err
}
