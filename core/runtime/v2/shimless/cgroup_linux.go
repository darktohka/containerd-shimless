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
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// cgroup is a handle to a cgroup v2 directory. cgroups v3 has no accessor for
// the controller path or the cgroup file descriptor, so the path is computed
// here and the directory is opened with O_DIRECTORY.
type cgroup struct {
	root string // cgroup2 mount point, e.g. /sys/fs/cgroup
	path string // path relative to root, without a leading slash
}

// newCgroup returns a handle for root/path. path may be absolute or relative.
func newCgroup(root, path string) *cgroup {
	rel := strings.TrimPrefix(filepath.Clean("/"+path), "/")
	return &cgroup{root: root, path: rel}
}

// Path returns the filesystem path of the cgroup directory.
func (c *cgroup) Path() string {
	return filepath.Join(c.root, c.path)
}

// Create creates the cgroup directory and any missing ancestors.
func (c *cgroup) Create() error {
	if err := os.MkdirAll(c.Path(), 0755); err != nil {
		return fmt.Errorf("create cgroup %s: %w", c.Path(), err)
	}
	return nil
}

// Delete removes the cgroup directory. A still-populated or already-removed
// cgroup is not an error: the caller only wants the directory gone if the
// kernel allows it.
func (c *cgroup) Delete() error {
	if err := os.Remove(c.Path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove cgroup %s: %w", c.Path(), err)
	}
	return nil
}

// openDir opens the cgroup directory with O_DIRECTORY|O_RDONLY|O_CLOEXEC.
func (c *cgroup) openDir() (int, error) {
	fd, err := unix.Open(c.Path(), unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: c.Path(), Err: err}
	}
	return fd, nil
}

// Populated reports whether the cgroup still contains processes, read from
// cgroup.events. A missing cgroup is reported as not populated with a
// not-exist error so callers can distinguish "gone" from "empty".
func (c *cgroup) Populated() (bool, error) {
	dirfd, err := c.openDir()
	if err != nil {
		return false, err
	}
	defer unix.Close(dirfd)

	data, err := readCgroupFile(dirfd, "cgroup.events")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			return fields[1] == "1", nil
		}
	}
	return false, fmt.Errorf("populated not found in %s/cgroup.events", c.Path())
}

// Procs returns the pids currently in the cgroup.
func (c *cgroup) Procs() ([]int, error) {
	dirfd, err := c.openDir()
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)

	data, err := readCgroupFile(dirfd, "cgroup.procs")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("parse pid %q in %s: %w", f, c.Path(), err)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Contains reports whether pid is a member of the cgroup.
func (c *cgroup) Contains(pid int) (bool, error) {
	pids, err := c.Procs()
	if err != nil {
		return false, err
	}
	for _, p := range pids {
		if p == pid {
			return true, nil
		}
	}
	return false, nil
}

// Kill kills every process in the cgroup by writing to cgroup.kill. This is
// the cgroup v2 interface and does not require SIGKILL to each pid.
func (c *cgroup) Kill() error {
	dirfd, err := c.openDir()
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)

	fd, err := unix.Openat(dirfd, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s/cgroup.kill: %w", c.Path(), err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("1")); err != nil {
		return fmt.Errorf("write %s/cgroup.kill: %w", c.Path(), err)
	}
	return nil
}

// readCgroupFile reads a file relative to dirfd. cgroup files are small except
// cgroup.procs, so the read loops until EOF with a hard cap to bound a
// misbehaving filesystem. Any reloaded offset still starts at 0 because the
// file descriptor is freshly opened.
func readCgroupFile(dirfd int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	defer unix.Close(fd)

	const maxSize = 1 << 20
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) < maxSize {
		n, err := unix.Read(fd, chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		switch err {
		case nil:
			if n == 0 {
				return buf, nil
			}
		case unix.EINTR, unix.EAGAIN:
			continue
		default:
			return nil, &os.PathError{Op: "read", Path: name, Err: err}
		}
	}
	return buf, nil
}
