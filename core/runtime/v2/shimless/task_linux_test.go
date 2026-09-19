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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func TestRemovePreservesObservedExit(t *testing.T) {
	stateDir := t.TempDir()
	bundle := filepath.Join(stateDir, "default", "task")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	e := newReconcileEngine(t, stateDir)
	st := &taskState{ID: "task", Namespace: "default", Bundle: bundle}
	tk := e.newTask(st, -1, nil)

	observedAt := time.Now().UTC().Truncate(time.Second)
	observed := &runtime.Exit{Pid: 42, Status: 137, Timestamp: observedAt}
	tk.mu.Lock()
	tk.exit = observed
	tk.exitRec = &exitState{Pid: 42, Status: 137, Signal: 9, ExitedAt: observedAt, Source: "pidfd_info"}
	tk.status = runtime.StoppedStatus
	tk.mu.Unlock()

	ctx := namespaces.WithNamespace(context.Background(), "default")
	ex, err := tk.remove(ctx)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if ex.Status != 137 || ex.Timestamp != observedAt {
		t.Fatalf("remove returned %+v, want the observed exit preserved", ex)
	}
}
