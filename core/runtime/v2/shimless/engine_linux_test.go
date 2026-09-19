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
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func TestSupports(t *testing.T) {
	e := &Engine{cfg: Config{RuntimeName: engineName}}
	if !e.Supports("io.containerd.crun.v1") {
		t.Error("exact engine name should be supported")
	}
	if !e.Supports("io.containerd.crun.v1.experimental") {
		t.Error("prefix should be supported")
	}
	if e.Supports("io.containerd.runc.v2") {
		t.Error("unrelated runtime should not be supported")
	}
	if e.Supports("") {
		t.Error("empty runtime should not be supported")
	}
}

func newReconcileEngine(t *testing.T, stateDir string) *Engine {
	t.Helper()
	crunStub := "/bin/true"
	if p, err := exec.LookPath("true"); err == nil {
		crunStub = p
	}
	e, err := New(Config{
		StateDir: stateDir,
		CrunPath: crunStub,
		Features: Features{PidfdOpen: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestReconcileStoppedTaskIsIdempotent(t *testing.T) {
	stateDir := t.TempDir()
	ns, id := "default", "task1"
	bundle := filepath.Join(stateDir, ns, id)
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	st := &taskState{
		ID:        id,
		Namespace: ns,
		Bundle:    bundle,
		// A pid with no starttime and no cgroup cannot be verified, so the
		// task must be reconciled as stopped.
		Pid:       99999999,
		State:     stateRunning,
		CreatedAt: time.Now().UTC(),
	}
	if err := writeState(bundle, st); err != nil {
		t.Fatal(err)
	}

	e := newReconcileEngine(t, stateDir)
	ctx := namespaces.WithNamespace(context.Background(), ns)
	task, err := e.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after reconcile: %v", err)
	}
	state, err := task.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state.Status != runtime.StoppedStatus {
		t.Fatalf("reconciled status = %v, want Stopped", state.Status)
	}

	ex, err := readExit(bundle)
	if err != nil || ex == nil {
		t.Fatalf("readExit after reconcile = %v, %v; want a synthesized record", ex, err)
	}
	if ex.Source != "synthesize" {
		t.Fatalf("exit source = %q, want synthesize (no cgroup)", ex.Source)
	}

	before, err := os.ReadFile(exitStatePath(bundle))
	if err != nil {
		t.Fatal(err)
	}
	// A second scan must not rewrite the already-recorded exit.
	e2 := newReconcileEngine(t, stateDir)
	if _, err := e2.Get(ctx, id); err != nil {
		t.Fatalf("second reconcile Get: %v", err)
	}
	after, err := os.ReadFile(exitStatePath(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("reconcile is not idempotent:\nbefore=%s\nafter=%s", before, after)
	}
}
