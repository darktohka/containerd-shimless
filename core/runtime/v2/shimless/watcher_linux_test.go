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
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDecodeWaitStatus(t *testing.T) {
	tests := []struct {
		name       string
		raw        unix.WaitStatus
		wantStatus uint32
		wantSignal uint32
	}{
		{"exit 7", unix.WaitStatus(7 << 8), 7, 0},
		{"exit 0", unix.WaitStatus(0), 0, 0},
		{"sigkill", unix.WaitStatus(unix.SIGKILL), 128 + uint32(unix.SIGKILL), uint32(unix.SIGKILL)},
		{"sigterm", unix.WaitStatus(unix.SIGTERM), 128 + uint32(unix.SIGTERM), uint32(unix.SIGTERM)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, signal := decodeWaitStatus(tt.raw)
			if status != tt.wantStatus || signal != tt.wantSignal {
				t.Fatalf("decodeWaitStatus(%d) = (%d,%d), want (%d,%d)", tt.raw, status, signal, tt.wantStatus, tt.wantSignal)
			}
		})
	}
}

func TestWatcherObservesExit(t *testing.T) {
	features := Detect()
	if !features.PidfdOpen {
		t.Skip("pidfd_open is not supported on this kernel")
	}

	exits := make(chan exitRecord, 1)
	w, err := newWatcher(features, func(_ int, _ string, rec exitRecord) {
		exits <- rec
	})
	if err != nil {
		t.Fatalf("newWatcher: %v", err)
	}
	defer w.Close()

	cmd := exec.Command("sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid
	fd, err := openPidfd(pid)
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("openPidfd: %v", err)
	}
	if err := w.Add(fd, "test-exit", 0); err != nil {
		unix.Close(fd)
		_ = cmd.Wait()
		t.Fatalf("watcher.Add: %v", err)
	}

	// Reap concurrently: PIDFD_GET_INFO only reports the exit status once the
	// process has been reaped, and the watcher retries until it appears.
	go func() { _ = cmd.Wait() }()

	select {
	case rec := <-exits:
		if !features.PidfdExitInfo {
			if rec.Source != "synthesize" {
				t.Fatalf("without PIDFD_GET_INFO source = %q, want synthesize", rec.Source)
			}
			return
		}
		if rec.Status != 7 || rec.Signal != 0 {
			t.Fatalf("exit = (%d,%d), want (7,0)", rec.Status, rec.Signal)
		}
		if rec.Source != "pidfd_info" {
			t.Fatalf("source = %q, want pidfd_info", rec.Source)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for watched exit")
	}
}

func TestWatcherRemoveBeforeExit(t *testing.T) {
	if !Detect().PidfdOpen {
		t.Skip("pidfd_open is not supported on this kernel")
	}
	exits := make(chan exitRecord, 1)
	w, err := newWatcher(Features{PidfdExitInfo: false}, func(_ int, _ string, rec exitRecord) {
		exits <- rec
	})
	if err != nil {
		t.Fatalf("newWatcher: %v", err)
	}
	defer w.Close()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	fd, err := openPidfd(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("openPidfd: %v", err)
	}
	if err := w.Add(fd, "removed", 0); err != nil {
		unix.Close(fd)
		t.Fatalf("watcher.Add: %v", err)
	}
	w.Remove(fd)
	select {
	case rec := <-exits:
		t.Fatalf("got unexpected exit after Remove: %+v", rec)
	case <-time.After(200 * time.Millisecond):
	}
}
