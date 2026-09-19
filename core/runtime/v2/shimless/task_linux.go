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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/protobuf/types"
)

// task is the runtime.Task implementation for a shimless container. The crun
// init process is the container; the engine holds a pidfd (watched by the
// daemon-wide watcher) and the cgroup for liveness across restarts.
type task struct {
	engine    *Engine
	id        string
	namespace string
	bundle    string
	pid       int
	io        runtime.IO

	mu      sync.Mutex
	status  runtime.Status
	exit    *runtime.Exit
	exitRec *exitState
	// pidfd is owned by the watcher while the task is watched; the task only
	// reads it to send signals and hands it to the watcher on exit/delete.
	pidfd   int
	cgroup  *cgroup
	execs   map[string]*execProcess
	exitCh  chan *runtime.Exit
	deleted bool
	// started and exitPublished gate TaskExit publishing behind TaskStart.
	started       bool
	exitPublished bool
}

var (
	_ runtime.Task        = (*task)(nil)
	_ runtime.ExecProcess = (*task)(nil)
)

func (t *task) ID() string { return t.id }

func (t *task) Namespace() string { return t.namespace }

func (t *task) PID(context.Context) (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pid <= 0 {
		return 0, fmt.Errorf("task %s has no pid: %w", t.id, errdefs.ErrNotFound)
	}
	return uint32(t.pid), nil
}

func (t *task) State(context.Context) (runtime.State, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := runtime.State{
		Status:   t.status,
		Pid:      uint32(t.pid),
		Stdin:    t.io.Stdin,
		Stdout:   t.io.Stdout,
		Stderr:   t.io.Stderr,
		Terminal: t.io.Terminal,
	}
	if t.exit != nil {
		st.ExitStatus = t.exit.Status
		st.ExitedAt = t.exit.Timestamp
	}
	return st, nil
}

func (t *task) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.status == runtime.StoppedStatus {
		t.mu.Unlock()
		return fmt.Errorf("task %s has already exited: %w", t.id, errdefs.ErrFailedPrecondition)
	}
	t.mu.Unlock()

	if err := t.engine.crun.start(ctx, t.id); err != nil {
		return err
	}

	t.mu.Lock()
	if t.status != runtime.StoppedStatus {
		t.status = runtime.RunningStatus
	}
	pid := t.pid
	t.mu.Unlock()

	t.engine.persistState(t, stateRunning)
	t.engine.publish(ctx, &eventstypes.TaskStart{
		ContainerID: t.id,
		Pid:         uint32(pid),
	})

	// Mark started only after TaskStart is published so an exit observed during
	// crun start cannot be published before it.
	t.mu.Lock()
	t.started = true
	t.mu.Unlock()
	t.publishExit()
	return nil
}

func (t *task) Wait(ctx context.Context) (*runtime.Exit, error) {
	t.mu.Lock()
	if t.exit != nil {
		ex := t.exit
		t.mu.Unlock()
		return ex, nil
	}
	ch := t.exitChLocked()
	t.mu.Unlock()

	select {
	case ex := <-ch:
		return ex, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *task) Kill(ctx context.Context, signal uint32, all bool) error {
	t.mu.Lock()
	status, pidfd, pid, cg := t.status, t.pidfd, t.pid, t.cgroup
	t.mu.Unlock()
	if status == runtime.StoppedStatus || status == runtime.DeletedStatus {
		return fmt.Errorf("task %s is not running: %w", t.id, errdefs.ErrNotFound)
	}

	if all && cg != nil {
		if err := cg.Kill(); err == nil {
			return nil
		}
	}
	if pidfd >= 0 {
		if err := unix.PidfdSendSignal(pidfd, unix.Signal(signal), nil, 0); err == nil {
			return nil
		}
	}
	if err := unix.Kill(pid, unix.Signal(signal)); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("kill task %s: %w", t.id, errdefs.ErrNotFound)
		}
		return fmt.Errorf("kill task %s: %w", t.id, err)
	}
	return nil
}

func (t *task) ResizePty(context.Context, runtime.ConsoleSize) error {
	return fmt.Errorf("resize pty for task %s: %w", t.id, errdefs.ErrNotImplemented)
}

func (t *task) CloseIO(context.Context) error {
	// crun owns the container's stdio; the engine never holds a copy to close.
	return nil
}

func (t *task) Pause(ctx context.Context) error {
	if err := t.engine.crun.pause(ctx, t.id); err != nil {
		return err
	}
	t.mu.Lock()
	t.status = runtime.PausedStatus
	t.mu.Unlock()
	t.engine.publish(ctx, &eventstypes.TaskPaused{ContainerID: t.id})
	return nil
}

func (t *task) Resume(ctx context.Context) error {
	if err := t.engine.crun.resume(ctx, t.id); err != nil {
		return err
	}
	t.mu.Lock()
	t.status = runtime.RunningStatus
	t.mu.Unlock()
	t.engine.publish(ctx, &eventstypes.TaskResumed{ContainerID: t.id})
	return nil
}

func (t *task) Pids(ctx context.Context) ([]runtime.ProcessInfo, error) {
	pids, err := t.engine.crun.ps(ctx, t.id)
	if err != nil {
		return nil, err
	}
	out := make([]runtime.ProcessInfo, 0, len(pids))
	for _, pid := range pids {
		out = append(out, runtime.ProcessInfo{Pid: uint32(pid)})
	}
	return out, nil
}

func (t *task) Exec(ctx context.Context, id string, opts runtime.ExecOpts) (runtime.ExecProcess, error) {
	if id == "" {
		return nil, fmt.Errorf("exec id must not be empty: %w", errdefs.ErrInvalidArgument)
	}
	var proc specs.Process
	if opts.Spec != nil {
		if err := typeurl.UnmarshalTo(opts.Spec, &proc); err != nil {
			return nil, fmt.Errorf("unmarshal exec spec: %w", err)
		}
	}
	dir := filepath.Join(t.bundle, ".exec")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create exec dir: %w", err)
	}
	procFile := filepath.Join(dir, id+".json")
	if err := writeJSONAtomic(procFile, &proc); err != nil {
		return nil, fmt.Errorf("write exec spec: %w", err)
	}

	p := &execProcess{
		id:       id,
		task:     t,
		io:       opts.IO,
		procFile: procFile,
		status:   runtime.CreatedStatus,
	}

	t.mu.Lock()
	if t.status == runtime.StoppedStatus {
		t.mu.Unlock()
		return nil, fmt.Errorf("task %s has exited: %w", t.id, errdefs.ErrFailedPrecondition)
	}
	if t.execs == nil {
		t.execs = make(map[string]*execProcess)
	}
	if _, ok := t.execs[id]; ok {
		t.mu.Unlock()
		return nil, fmt.Errorf("exec %s: %w", id, errdefs.ErrAlreadyExists)
	}
	t.execs[id] = p
	t.mu.Unlock()

	t.engine.publish(ctx, &eventstypes.TaskExecAdded{
		ContainerID: t.id,
		ExecID:      id,
	})
	return p, nil
}

func (t *task) Process(ctx context.Context, id string) (runtime.ExecProcess, error) {
	if id == "" || id == t.id {
		return t, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.execs[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("process %s in task %s: %w", id, t.id, errdefs.ErrNotFound)
}

func (t *task) Checkpoint(context.Context, string, *types.Any) error {
	return fmt.Errorf("checkpoint task %s: %w", t.id, errdefs.ErrNotImplemented)
}

func (t *task) Update(context.Context, *types.Any, map[string]string) error {
	return fmt.Errorf("update task %s: %w", t.id, errdefs.ErrNotImplemented)
}

func (t *task) Stats(context.Context) (*types.Any, error) {
	return nil, fmt.Errorf("stats for task %s: %w", t.id, errdefs.ErrNotImplemented)
}

// Delete removes the init process. It is the ExecProcess.Delete implementation
// so Process("") can return the task itself, mirroring the shim's behavior; the
// task is actually removed through Engine.Delete.
func (t *task) Delete(ctx context.Context) (*runtime.Exit, error) {
	return t.engine.Delete(ctx, t.id)
}

// finish records an observed exit. It is called by the watcher, which already
// removed the pidfd from its table; the task must not close the pidfd.
func (t *task) finish(rec exitRecord) {
	t.mu.Lock()
	if t.exit != nil {
		t.mu.Unlock()
		return
	}
	ex := &runtime.Exit{Pid: uint32(t.pid), Status: rec.Status, Timestamp: rec.ExitedAt}
	t.exit = ex
	t.exitRec = &exitState{
		Pid:      uint32(t.pid),
		Status:   rec.Status,
		Signal:   rec.Signal,
		ExitedAt: rec.ExitedAt,
		Source:   rec.Source,
	}
	t.status = runtime.StoppedStatus
	t.pidfd = -1
	ch := t.exitChLocked()
	execs := make([]*execProcess, 0, len(t.execs))
	for _, p := range t.execs {
		execs = append(execs, p)
	}
	t.mu.Unlock()

	// Persist before publishing so a client that reacts to the event and
	// inspects the bundle sees a consistent record.
	if err := writeExit(t.bundle, t.exitRec); err != nil {
		t.engine.logger.WithError(err).WithField("id", t.id).Warn("failed to persist exit state")
	}
	t.engine.persistState(t, stateStopped)
	t.publishExit()

	for _, p := range execs {
		p.markParentExited()
	}

	select {
	case ch <- ex:
	default:
	}
}

// exitChLocked lazily creates the exit channel. The caller must hold t.mu.
func (t *task) exitChLocked() chan *runtime.Exit {
	if t.exitCh == nil {
		t.exitCh = make(chan *runtime.Exit, 1)
	}
	return t.exitCh
}

// publishExit publishes TaskExit at most once and only after TaskStart.
func (t *task) publishExit() {
	t.mu.Lock()
	if t.exit == nil || !t.started || t.exitPublished {
		t.mu.Unlock()
		return
	}
	t.exitPublished = true
	ex := t.exit
	pid, id, ns := t.pid, t.id, t.namespace
	t.mu.Unlock()

	ctx := namespaces.WithNamespace(context.Background(), ns)
	t.engine.publish(ctx, &eventstypes.TaskExit{
		ContainerID: id,
		ID:          id,
		Pid:         uint32(pid),
		ExitStatus:  ex.Status,
		ExitedAt:    timestamppb.New(ex.Timestamp),
	})
}

// waitExited waits up to timeout for the watcher to record an exit so Delete
// can report the real status instead of synthesizing one.
func (t *task) waitExited(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		exited := t.exit != nil
		t.mu.Unlock()
		if exited {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// remove stops the task if needed, releases its resources and publishes the
// terminal exit/delete events. It is called by Engine.Delete and is safe to
// run at most once per task.
func (t *task) remove(ctx context.Context) (*runtime.Exit, error) {
	t.mu.Lock()
	if t.deleted {
		ex := t.exit
		t.mu.Unlock()
		if ex == nil {
			return nil, fmt.Errorf("task %s already deleted: %w", t.id, errdefs.ErrNotFound)
		}
		return ex, nil
	}
	t.deleted = true
	status := t.status
	pidfd := t.pidfd
	cg := t.cgroup
	t.mu.Unlock()

	if status != runtime.StoppedStatus {
		if pidfd >= 0 {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		if cg != nil {
			_ = cg.Kill()
		}
		t.waitExited(2 * time.Second)
	}

	t.mu.Lock()
	pidfd = t.pidfd
	t.mu.Unlock()
	if pidfd >= 0 {
		t.engine.unwatch(pidfd)
		t.mu.Lock()
		t.pidfd = -1
		t.mu.Unlock()
	}

	// crun delete is what removes crun's own state; a failure here must not
	// prevent the engine from forgetting the task.
	if err := t.engine.crun.delete(context.WithoutCancel(ctx), t.id, true); err != nil {
		t.engine.logger.WithError(err).WithField("id", t.id).Debug("crun delete failed")
	}
	if cg != nil {
		if err := cg.Delete(); err != nil {
			t.engine.logger.WithError(err).WithField("id", t.id).Debug("failed to remove cgroup")
		}
	}
	_ = removeState(t.bundle)

	ex := t.ensureExit(ctx)
	t.engine.publish(ctx, &eventstypes.TaskDelete{
		ContainerID: t.id,
		Pid:         uint32(t.pid),
		ExitStatus:  ex.Status,
		ExitedAt:    timestamppb.New(ex.Timestamp),
	})
	return ex, nil
}

// ensureExit guarantees an exit is recorded, synthesizing one when the watcher
// never observed the process (for example a task deleted before it started, or
// an exit that happened while the daemon was down without an exit.json).
func (t *task) ensureExit(ctx context.Context) *runtime.Exit {
	t.mu.Lock()
	if t.exit != nil {
		ex := t.exit
		t.mu.Unlock()
		return ex
	}
	source := "synthesize"
	if t.cgroup != nil {
		source = "cgroup"
	}
	ex := &runtime.Exit{Pid: uint32(t.pid), Status: 255, Timestamp: time.Now().UTC()}
	t.exit = ex
	t.exitRec = &exitState{
		Pid:      uint32(t.pid),
		Status:   ex.Status,
		ExitedAt: ex.Timestamp,
		Source:   source,
	}
	t.status = runtime.StoppedStatus
	ch := t.exitChLocked()
	rec := *t.exitRec
	id := t.id
	t.mu.Unlock()

	if err := writeExit(t.bundle, &rec); err != nil {
		t.engine.logger.WithError(err).WithField("id", id).Warn("failed to persist synthesized exit")
	}
	t.publishExit()
	select {
	case ch <- ex:
	default:
	}
	return ex
}

// execProcess is a process started inside a task with crun exec.
type execProcess struct {
	id       string
	task     *task
	io       runtime.IO
	procFile string

	mu     sync.Mutex
	pid    int
	pidfd  int
	status runtime.Status
	exit   *runtime.Exit
	exitCh chan *runtime.Exit
}

var _ runtime.ExecProcess = (*execProcess)(nil)

func (p *execProcess) ID() string { return p.id }

func (p *execProcess) State(context.Context) (runtime.State, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := runtime.State{
		Status:   p.status,
		Pid:      uint32(p.pid),
		Stdin:    p.io.Stdin,
		Stdout:   p.io.Stdout,
		Stderr:   p.io.Stderr,
		Terminal: p.io.Terminal,
	}
	if p.exit != nil {
		st.ExitStatus = p.exit.Status
		st.ExitedAt = p.exit.Timestamp
	}
	return st, nil
}

func (p *execProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.status != runtime.CreatedStatus {
		p.mu.Unlock()
		return fmt.Errorf("exec %s already started: %w", p.id, errdefs.ErrFailedPrecondition)
	}
	p.mu.Unlock()

	pidFile := p.procFile + ".pid"
	if err := p.task.engine.crun.execProcess(ctx, p.task.id, p.procFile, pidFile, p.io); err != nil {
		return err
	}
	pid, err := readPidFile(pidFile)
	if err != nil {
		return err
	}
	pidfd := -1
	if p.task.engine.features.PidfdOpen {
		if fd, err := openPidfd(pid); err == nil {
			pidfd = fd
		}
	}

	p.mu.Lock()
	p.pid = pid
	p.pidfd = pidfd
	p.status = runtime.RunningStatus
	p.mu.Unlock()

	if pidfd >= 0 {
		if err := p.task.engine.watch(pidfd, p.id, pid, p); err != nil {
			p.task.engine.logger.WithError(err).WithField("exec", p.id).Warn("failed to watch exec pidfd")
		}
	}

	p.task.engine.publish(ctx, &eventstypes.TaskExecStarted{
		ContainerID: p.task.id,
		ExecID:      p.id,
		Pid:         uint32(pid),
	})
	return nil
}

func (p *execProcess) Wait(ctx context.Context) (*runtime.Exit, error) {
	p.mu.Lock()
	if p.exit != nil {
		ex := p.exit
		p.mu.Unlock()
		return ex, nil
	}
	if p.exitCh == nil {
		p.exitCh = make(chan *runtime.Exit, 1)
	}
	ch := p.exitCh
	p.mu.Unlock()

	select {
	case ex := <-ch:
		return ex, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *execProcess) Kill(ctx context.Context, signal uint32, all bool) error {
	p.mu.Lock()
	status, pidfd, pid := p.status, p.pidfd, p.pid
	p.mu.Unlock()
	if status == runtime.StoppedStatus {
		return fmt.Errorf("exec %s is not running: %w", p.id, errdefs.ErrNotFound)
	}
	if pidfd >= 0 {
		if err := unix.PidfdSendSignal(pidfd, unix.Signal(signal), nil, 0); err == nil {
			return nil
		}
	}
	if err := unix.Kill(pid, unix.Signal(signal)); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("kill exec %s: %w", p.id, errdefs.ErrNotFound)
		}
		return fmt.Errorf("kill exec %s: %w", p.id, err)
	}
	return nil
}

func (p *execProcess) ResizePty(context.Context, runtime.ConsoleSize) error {
	return fmt.Errorf("resize pty for exec %s: %w", p.id, errdefs.ErrNotImplemented)
}

func (p *execProcess) CloseIO(context.Context) error { return nil }

func (p *execProcess) Delete(ctx context.Context) (*runtime.Exit, error) {
	p.mu.Lock()
	if p.pidfd >= 0 {
		p.task.engine.unwatch(p.pidfd)
		p.pidfd = -1
	}
	ex := p.exit
	p.status = runtime.DeletedStatus
	p.mu.Unlock()

	p.task.mu.Lock()
	delete(p.task.execs, p.id)
	p.task.mu.Unlock()

	if ex == nil {
		ex = &runtime.Exit{Pid: uint32(p.pid), Status: 255, Timestamp: time.Now().UTC()}
	}
	return ex, nil
}

// finish records an observed exec exit.
func (p *execProcess) finish(rec exitRecord) {
	p.mu.Lock()
	if p.exit != nil {
		p.mu.Unlock()
		return
	}
	ex := &runtime.Exit{Pid: uint32(p.pid), Status: rec.Status, Timestamp: rec.ExitedAt}
	p.exit = ex
	p.status = runtime.StoppedStatus
	p.pidfd = -1
	if p.exitCh == nil {
		p.exitCh = make(chan *runtime.Exit, 1)
	}
	ch := p.exitCh
	taskID := p.task.id
	ns := p.task.namespace
	execID := p.id
	pid := p.pid
	p.mu.Unlock()

	ctx := namespaces.WithNamespace(context.Background(), ns)
	p.task.engine.publish(ctx, &eventstypes.TaskExit{
		ContainerID: taskID,
		ID:          execID,
		Pid:         uint32(pid),
		ExitStatus:  rec.Status,
		ExitedAt:    timestamppb.New(rec.ExitedAt),
	})

	select {
	case ch <- ex:
	default:
	}
}

// markParentExited marks an exec as stopped when its task exits.
func (p *execProcess) markParentExited() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status == runtime.RunningStatus || p.status == runtime.CreatedStatus {
		p.pidfd = -1
		p.status = runtime.StoppedStatus
	}
}
