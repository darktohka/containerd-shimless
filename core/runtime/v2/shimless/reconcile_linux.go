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
	"errors"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/core/runtime/v2/shimless/logdriver"
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
			// Re-attach the logging consumer for a binary/binary-v2 task. The
			// container kept its inherited FIFO fds across the restart, so a
			// fresh logger can reopen them and drain buffered output. Failure is
			// non-fatal: reconcile must never block daemon startup.
			if cfg, rerr := reattachBinaryStdio(st); rerr != nil {
				logger.WithError(rerr).Warn("failed to re-attach logging consumer")
			} else if cfg != nil {
				t.mu.Lock()
				t.stdio = cfg
				t.mu.Unlock()
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

// reattachBinaryStdio rebuilds the logging consumer for a reconciled running
// task whose persisted stdio used a binary/binary-v2 URI. For a nerdctl logging
// URI whose driver logdriver supports it re-attaches an in-process sink; tryLock
// reports a writer that survived the restart so a duplicate consumer is never
// attached. Otherwise it reopens the task's FIFOs and spawns a fresh logger,
// returning a stdioConfig whose Close stops the consumer and releases the
// engine's FIFO fds. It returns (nil, nil) when the persisted stdio does not use
// a binary scheme or when a live writer makes re-attaching unsafe.
func reattachBinaryStdio(st *taskState) (*stdioConfig, error) {
	sio := st.Stdio
	if sio == nil {
		return nil, nil
	}
	// Terminal output flows through the engine's pty bridge, which does not
	// survive a daemon restart (the pty master is gone), so a fresh consumer
	// would only block on an empty FIFO. Skip it.
	if sio.Terminal {
		return nil, nil
	}
	// A logger that survived the restart still owns the FIFO read side and
	// holds the logger lock; spawning another consumer would duplicate it and
	// block on that lock. Detect it by pid plus start time.
	if st.LoggerPid > 0 {
		if start, err := readStartTime(st.LoggerPid); err == nil && start == st.LoggerStart {
			return nil, nil
		}
	}
	stdoutURL, err := parseOutputURL(sio.Stdout)
	if err != nil {
		return nil, err
	}
	stderrURL, err := parseOutputURL(sio.Stderr)
	if err != nil {
		return nil, err
	}
	bin := binarySchemeURL(stdoutURL, stderrURL)
	if bin == nil {
		return nil, nil
	}
	// A nerdctl logging URI can be served in-process. tryLock distinguishes a
	// writer that survived the restart (external logger or a previous in-process
	// holder) from a free lock, without disturbing it.
	if dataStore, ok := nerdctlLogDataStore(bin); ok {
		l, out, errF, lerr := startInProcessLog(dataStore, st.ID, st.Namespace, st.Bundle, true)
		switch {
		case lerr == nil:
			cfg := &stdioConfig{
				id:       st.ID,
				ns:       st.Namespace,
				bundle:   st.Bundle,
				terminal: sio.Terminal,
				log:      l,
			}
			if bin == stdoutURL {
				cfg.stdout, cfg.stderr = out, errF
			} else {
				// Only stderr uses the logger; the stdout FIFO is unused.
				_ = out.Close()
				cfg.stderr = errF
			}
			return cfg, nil
		case errors.Is(lerr, logdriver.ErrLocked):
			// A live writer still holds the logger-lock; attaching here would
			// duplicate it. Leave the task without a consumer.
			return nil, nil
		}
		// Any other error falls through to the external logger path below.
	}
	b, err := startBinaryIO(bin, st.ID, st.Namespace, st.Bundle)
	if err != nil {
		return nil, err
	}
	cfg := &stdioConfig{
		id:       st.ID,
		ns:       st.Namespace,
		bundle:   st.Bundle,
		terminal: sio.Terminal,
		logger:   b.cmd,
	}
	if bin == stdoutURL {
		cfg.stdout, cfg.stderr = b.outW, b.errW
	} else {
		// Only stderr uses the binary scheme; the logger's stdout end is unused.
		_ = b.outW.Close()
		cfg.stderr = b.errW
	}
	return cfg, nil
}
