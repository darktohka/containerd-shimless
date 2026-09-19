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
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// reconcile scans StateDir and rebuilds the in-memory registry from persisted
// state. It is idempotent: running tasks are re-watched and stopped tasks are
// only re-published the first time their exit is discovered.
func (e *Engine) reconcile(ctx context.Context) error {
	states, err := scanStateDir(e.cfg.StateDir)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return nil
	}
	e.logger.WithField("tasks", len(states)).Info("reconciling shimless tasks")
	for _, st := range states {
		e.reconcileOne(ctx, st)
	}
	return nil
}

func (e *Engine) reconcileOne(ctx context.Context, st *taskState) {
	if st.ID == "" || st.Namespace == "" || st.Bundle == "" {
		e.logger.WithField("state", st).Warn("ignoring incomplete shimless state record")
		return
	}
	logger := e.logger.WithFields(log.Fields{"id": st.ID, "ns": st.Namespace})

	var cg *cgroup
	if st.Cgroup != "" {
		cg = newCgroup(e.cfg.CgroupRoot, st.Cgroup)
	}

	running := false
	switch {
	case cg != nil:
		if pop, err := cg.Populated(); err == nil {
			running = pop
		}
	case st.Pid > 0 && st.StartTime > 0:
		if start, err := readStartTime(st.Pid); err == nil && start == st.StartTime {
			running = true
		}
	}

	if running && e.features.PidfdOpen && st.Pid > 0 && pidMatchesStart(st) && cgroupContains(cg, st.Pid) {
		if fd, err := openPidfd(st.Pid); err == nil {
			t := e.newTask(st, fd, cg)
			t.status = runtime.RunningStatus
			st.State = stateRunning
			if err := writeState(st.Bundle, st); err != nil {
				logger.WithError(err).Debug("failed to persist reconciled running state")
			}
			if err := e.tasks.AddWithNamespace(st.Namespace, t); err != nil {
				unix.Close(fd)
				// A second reconcile must not register the task twice.
				if !errdefs.IsAlreadyExists(err) {
					logger.WithError(err).Warn("failed to register reconciled running task")
				}
				return
			}
			if err := e.watch(fd, st.ID, st.Pid, t); err != nil {
				logger.WithError(err).Warn("failed to re-watch reconciled pidfd")
				t.mu.Lock()
				t.pidfd = -1
				t.mu.Unlock()
				unix.Close(fd)
			}
			logger.Info("reconciled running shimless task")
			return
		}
	}

	rec, isNew := e.exitForState(st)
	t := e.newTask(st, -1, cg)
	t.status = runtime.StoppedStatus
	t.exit = &runtime.Exit{Pid: rec.Pid, Status: rec.Status, Timestamp: rec.ExitedAt}
	t.exitRec = &exitState{
		Pid:      rec.Pid,
		Status:   rec.Status,
		Signal:   rec.Signal,
		ExitedAt: rec.ExitedAt,
		Source:   rec.Source,
	}
	if err := e.tasks.AddWithNamespace(st.Namespace, t); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			logger.WithError(err).Warn("failed to register reconciled stopped task")
		}
		return
	}
	if isNew {
		st.State = stateStopped
		if err := writeState(st.Bundle, st); err != nil {
			logger.WithError(err).Debug("failed to persist reconciled stopped state")
		}
		e.publish(namespaces.WithNamespace(context.Background(), st.Namespace), exitEvent(st.ID, st.ID, rec))
	}
	logger.Info("reconciled stopped shimless task")
}

// exitForState returns the recorded exit if one exists, otherwise it
// synthesizes one (cgroup liveness cannot recover the exit code) and persists
// it. The bool reports whether a new record was created, which decides whether
// TaskExit must be published.
func (e *Engine) exitForState(st *taskState) (exitRecord, bool) {
	if ex, err := readExit(st.Bundle); err == nil && ex != nil {
		return exitRecord{
			Pid:      ex.Pid,
			Status:   ex.Status,
			Signal:   ex.Signal,
			ExitedAt: ex.ExitedAt,
			Source:   ex.Source,
		}, false
	}

	rec := exitRecord{Pid: uint32(st.Pid), Status: 255, ExitedAt: time.Now().UTC(), Source: "cgroup"}
	if st.Cgroup == "" {
		rec.Source = "synthesize"
	}
	if st.ID != "" {
		if _, err := e.crun.state(context.Background(), st.ID); err != nil {
			e.logger.WithError(err).WithField("id", st.ID).Debug("crun state unavailable during reconcile")
		}
	}
	if err := writeExit(st.Bundle, &exitState{
		Pid:      rec.Pid,
		Status:   rec.Status,
		ExitedAt: rec.ExitedAt,
		Source:   rec.Source,
	}); err != nil {
		e.logger.WithError(err).WithField("id", st.ID).Warn("failed to persist reconcile exit")
	}
	return rec, true
}

func pidMatchesStart(st *taskState) bool {
	if st.StartTime == 0 {
		return true
	}
	start, err := readStartTime(st.Pid)
	return err == nil && start == st.StartTime
}

// cgroupContains reports whether pid is still a member of cg. A nil cgroup
// cannot contradict liveness, so it is treated as a match.
func cgroupContains(cg *cgroup, pid int) bool {
	if cg == nil {
		return true
	}
	in, err := cg.Contains(pid)
	return err == nil && in
}
