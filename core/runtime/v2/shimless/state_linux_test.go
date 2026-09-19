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
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	bundle := t.TempDir()
	created := time.Now().UTC().Truncate(time.Second)
	st := &taskState{
		Engine:    engineName,
		Crun:      "/usr/bin/crun",
		ID:        "abc",
		Namespace: "default",
		Bundle:    bundle,
		Pid:       1234,
		StartTime: 987654,
		Cgroup:    "shimless/default/abc",
		State:     stateCreated,
		CreatedAt: created,
	}
	if err := writeState(bundle, st); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	got, err := readState(bundle)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if got.Version != stateVersion {
		t.Errorf("version = %d, want %d", got.Version, stateVersion)
	}
	if got.ID != st.ID || got.Pid != st.Pid || got.StartTime != st.StartTime || got.Cgroup != st.Cgroup {
		t.Errorf("round trip mismatch: got %+v want %+v", got, st)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("createdAt = %v, want %v", got.CreatedAt, created)
	}
}

func TestStateAtomicWriteLeavesNoTemp(t *testing.T) {
	bundle := t.TempDir()
	if err := writeState(bundle, &taskState{ID: "a", State: stateCreated}); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	if err := writeState(bundle, &taskState{ID: "a", State: stateRunning}); err != nil {
		t.Fatalf("writeState second: %v", err)
	}
	entries, err := os.ReadDir(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != stateFileName {
			t.Errorf("unexpected leftover file %q after atomic writes", e.Name())
		}
	}
}

func TestExitStateIdempotent(t *testing.T) {
	bundle := t.TempDir()
	ex := &exitState{Pid: 42, Status: 137, Signal: 9, ExitedAt: time.Now().UTC().Truncate(time.Second), Source: "pidfd_info"}
	if err := writeExit(bundle, ex); err != nil {
		t.Fatalf("writeExit: %v", err)
	}
	got, err := readExit(bundle)
	if err != nil || got == nil {
		t.Fatalf("readExit: %v %v", got, err)
	}
	if got.Status != ex.Status || got.Signal != ex.Signal || got.Source != ex.Source {
		t.Errorf("exit mismatch: got %+v want %+v", got, ex)
	}
	// Rewriting the same record must be safe and produce the same value.
	if err := writeExit(bundle, ex); err != nil {
		t.Fatalf("writeExit second: %v", err)
	}
	again, err := readExit(bundle)
	if err != nil || again == nil {
		t.Fatalf("readExit second: %v %v", again, err)
	}
	if !again.ExitedAt.Equal(ex.ExitedAt) || again.Status != ex.Status {
		t.Errorf("second read changed the record: %+v", again)
	}
}

func TestReadExitMissing(t *testing.T) {
	bundle := t.TempDir()
	ex, err := readExit(bundle)
	if err != nil {
		t.Fatalf("readExit on missing file: %v", err)
	}
	if ex != nil {
		t.Fatalf("readExit on missing file = %+v, want nil", ex)
	}
}

func TestScanStateDir(t *testing.T) {
	stateDir := t.TempDir()
	write := func(ns, id string, st *taskState) string {
		dir := filepath.Join(stateDir, ns, id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		st.Bundle = dir
		if err := writeState(dir, st); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	write("default", "one", &taskState{ID: "one", Namespace: "default", State: stateRunning})
	write("default", "two", &taskState{ID: "two", Namespace: "default", State: stateStopped})
	write("other", "three", &taskState{ID: "three", Namespace: "other", State: stateCreated})

	states, err := scanStateDir(stateDir)
	if err != nil {
		t.Fatalf("scanStateDir: %v", err)
	}
	if len(states) != 3 {
		t.Fatalf("scanStateDir returned %d states, want 3", len(states))
	}
	seen := map[string]bool{}
	for _, st := range states {
		seen[st.ID] = true
		if st.Bundle == "" {
			t.Errorf("state %s has no bundle path", st.ID)
		}
	}
	for _, id := range []string{"one", "two", "three"} {
		if !seen[id] {
			t.Errorf("state %s not found", id)
		}
	}
}

func TestScanStateDirIgnoresCorruptRecords(t *testing.T) {
	stateDir := t.TempDir()
	good := filepath.Join(stateDir, "default", "good")
	bad := filepath.Join(stateDir, "default", "bad")
	for _, d := range []string{good, bad} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeState(good, &taskState{ID: "good", Namespace: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, stateFileName), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	states, err := scanStateDir(stateDir)
	if err != nil {
		t.Fatalf("scanStateDir: %v", err)
	}
	if len(states) != 1 || states[0].ID != "good" {
		t.Fatalf("scanStateDir = %+v, want only the good record", states)
	}
}

func TestRemoveState(t *testing.T) {
	bundle := t.TempDir()
	if err := writeState(bundle, &taskState{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFilePath(bundle), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeState(bundle); err != nil {
		t.Fatalf("removeState: %v", err)
	}
	for _, name := range []string{stateFileName, pidFileName, exitFileName} {
		if _, err := os.Stat(filepath.Join(bundle, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s still exists (err=%v)", name, err)
		}
	}
	// Removing again is a no-op.
	if err := removeState(bundle); err != nil {
		t.Fatalf("removeState second: %v", err)
	}
}
