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
	"os"
	"path/filepath"
	"sync"
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

// TestWaitBroadcastsExitToMultipleWaiters locks in the fix for a task being
// awaited by more than one caller at once. The engine starts a logging consumer
// that waits on the task while a client (for example `nerdctl rm -f`) also
// waits, so the exit must be broadcast rather than delivered to a single waiter.
func TestWaitBroadcastsExitToMultipleWaiters(t *testing.T) {
	stateDir := t.TempDir()
	bundle := filepath.Join(stateDir, "default", "task")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	e := newReconcileEngine(t, stateDir)
	st := &taskState{ID: "task", Namespace: "default", Bundle: bundle}
	tk := e.newTask(st, -1, nil)

	const waiters = 4
	var wg sync.WaitGroup
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex, err := tk.Wait(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if ex == nil || ex.Status != 7 {
				errs <- fmt.Errorf("unexpected exit %+v", ex)
			}
		}()
	}

	// Give every waiter time to block on the exit signal before it fires.
	time.Sleep(50 * time.Millisecond)
	tk.finish(exitRecord{Pid: 42, Status: 7, ExitedAt: time.Now().UTC(), Source: "test"})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not all Wait callers returned; the exit signal is not broadcast")
	}
	close(errs)
	for err := range errs {
		t.Fatalf("Wait: %v", err)
	}
}
