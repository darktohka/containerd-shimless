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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	minCreatorFlagsMajor = 7
	minCreatorFlagsMinor = 1
)

// Features describes the kernel primitives the engine can rely on.
type Features struct {
	// PidfdOpen is true when pidfd_open(2) works (Linux >= 5.3).
	PidfdOpen bool
	// PidfdExitInfo is true when PIDFD_GET_INFO reports a reaped process'
	// exit status; otherwise exits are observed through crun or the cgroup.
	PidfdExitInfo bool
	// CreatorOnly reports that the creator-only clone3() flags (CLONE_AUTOREAP,
	// CLONE_NNP, CLONE_PIDFD_AUTOKILL) may be available. Discovered via
	// probeClone3, with a >= 7.1 kernel floor as the fallback.
	CreatorOnly bool
}

// Detect probes the running kernel for features the engine can use, preferring
// safe runtime discovery (pidfd_open, the PIDFD_GET_INFO ioctl, and a
// process-free clone3 probe) over kernel-version checks.
func Detect() Features {
	var f Features
	f.CreatorOnly = probeClone3() && kernelVersionAtLeast(minCreatorFlagsMajor, minCreatorFlagsMinor)

	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		// No pidfd_open: the engine cannot watch exits directly and must
		// fall back to crun state and cgroup liveness.
		return f
	}
	unix.Close(fd)
	f.PidfdOpen = true
	f.PidfdExitInfo = probePidfdExitInfo()
	return f
}

// probeClone3 reports whether clone3(2) is callable. A size below
// CLONE_ARGS_SIZE_VER0 is rejected with EINVAL before any process is created
// (kernel/fork.c copy_clone_args_from_user); ENOSYS means clone3 is absent.
// The userspace argument is never dereferenced.
func probeClone3() bool {
	var buf [64]byte
	_, _, errno := unix.Syscall(unix.SYS_CLONE3, uintptr(unsafe.Pointer(&buf[0])), 0, 0)
	return errno == unix.EINVAL
}

// probePidfdExitInfo reports whether the kernel exposes a reaped process'
// exit status through PIDFD_GET_INFO.
func probePidfdExitInfo() bool {
	path, err := exec.LookPath("true")
	if err != nil {
		return false
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return false
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Wait()
		return false
	}
	defer unix.Close(fd)

	// Reap the child so the kernel latches the exit information onto the
	// pidfd. The pidfd itself keeps the pid alive across the reap.
	if err := cmd.Wait(); err != nil {
		return false
	}

	info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_EXIT}
	if err := unix.IoctlPidfdInfo(fd, &info); err != nil {
		return false
	}
	return info.Mask&unix.PIDFD_INFO_EXIT != 0
}

// kernelVersionAtLeast reports whether the running kernel release is at least
// major.minor. It parses only the numeric major and minor components; vendor
// suffixes such as "7.3.0-rc1" are ignored.
func kernelVersionAtLeast(major, minor int) bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return false
	}
	rel := unix.ByteSliceToString(u.Release[:])
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return false
	}
	gotMajor, ok := leadingInt(parts[0])
	if !ok {
		return false
	}
	gotMinor, ok := leadingInt(parts[1])
	if !ok {
		return false
	}
	if gotMajor != major {
		return gotMajor > major
	}
	return gotMinor >= minor
}

// leadingInt parses the leading decimal digits of s.
func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}
