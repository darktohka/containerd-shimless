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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNewCgroupPath(t *testing.T) {
	tests := []struct {
		root, path, want string
	}{
		{"/sys/fs/cgroup", "shimless/default/abc", "/sys/fs/cgroup/shimless/default/abc"},
		{"/sys/fs/cgroup", "/shimless/default/abc", "/sys/fs/cgroup/shimless/default/abc"},
		{"/sys/fs/cgroup", "/shimless/../foo//bar", "/sys/fs/cgroup/foo/bar"},
	}
	for _, tt := range tests {
		cg := newCgroup(tt.root, tt.path)
		if got := cg.Path(); got != tt.want {
			t.Errorf("newCgroup(%q,%q).Path() = %q, want %q", tt.root, tt.path, got, tt.want)
		}
	}
}

// delegatedCgroup returns the cgroup v2 root and the caller's own cgroup path
// relative to it, if the running process has a writable delegated subtree.
func delegatedCgroup(t *testing.T) (root, rel string, ok bool) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		return "/sys/fs/cgroup", strings.TrimPrefix(fields[2], "/"), true
	}
	return "", "", false
}

func TestCgroupHelpers(t *testing.T) {
	root, parent, ok := delegatedCgroup(t)
	if !ok {
		t.Skip("no cgroup v2 delegation for the test process")
	}
	name := filepath.Join(parent, "shimless-test-"+strconv.Itoa(os.Getpid()))
	cg := newCgroup(root, name)
	if err := cg.Create(); err != nil {
		t.Skipf("cannot create a delegated cgroup: %v", err)
	}
	defer cg.Delete()

	pop, err := cg.Populated()
	if err != nil {
		t.Fatalf("Populated: %v", err)
	}
	if pop {
		t.Fatalf("new cgroup reports populated")
	}
	if pids, err := cg.Procs(); err != nil || len(pids) != 0 {
		t.Fatalf("Procs = %v, %v; want empty", pids, err)
	}

	// Move a short-lived child into the cgroup and confirm it becomes
	// populated, then that cgroup.kill terminates it.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	procsFile := filepath.Join(cg.Path(), "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		t.Skipf("cannot move a child into the delegated cgroup: %v", err)
	}
	if in, err := cg.Contains(pid); err != nil || !in {
		t.Fatalf("Contains(%d) = %v, %v; want true", pid, in, err)
	}
	if pop, err := cg.Populated(); err != nil || !pop {
		t.Fatalf("Populated after moving child = %v, %v; want true", pop, err)
	}
	if err := cg.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		pop, err := cg.Populated()
		if err == nil && !pop {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cgroup still populated after kill: %v, %v", pop, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
