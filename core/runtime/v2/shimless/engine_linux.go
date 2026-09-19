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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/v2/core/events/exchange"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	// engineName is the runtime name the engine handles by default. The value
	// in runtime.CreateOpts.Runtime is matched by prefix.
	engineName = "io.containerd.crun.v1"

	defaultCgroupRoot = "/sys/fs/cgroup"

	// Crun annotations in the frozen receiver contract. The receiver socket
	// carries the container init's pidfd; autokill is only requested when
	// Config.Autokill is set and the kernel supports the creator-only v7.3
	// clone3 flags.
	annotationPIDFDReceiver = "run.oci.pidfd_receiver"
	annotationPIDFDAutokill = "run.oci.pidfd_autokill"

	// pidfdReceiverTimeout bounds how long create waits for crun to hand over
	// the pidfd before falling back to pidfd_open.
	pidfdReceiverTimeout = 3 * time.Second
)

// Config configures the shimless engine.
type Config struct {
	// StateDir is TaskManager's state directory, scanned on startup to
	// reconcile tasks left by a previous daemon.
	StateDir string
	// CrunPath is the resolved crun binary. Empty means resolve from PATH.
	CrunPath string
	// CrunRoot is passed to crun as --root. Empty uses crun's default.
	CrunRoot string
	// CgroupRoot is the cgroup v2 mount point. Empty uses /sys/fs/cgroup.
	CgroupRoot string
	// Autokill asks the kernel to kill a task when the daemon releases its
	// pidfd, so a daemon crash tears down the containers it started. Off by
	// default, so tasks survive a daemon restart and are re-adopted.
	Autokill bool
	// RuntimeName is the prefix matched against CreateOpts.Runtime. Empty uses
	// io.containerd.crun.v1.
	RuntimeName string
	// Events receives task lifecycle events. Nil disables event publishing.
	Events *exchange.Exchange
	// Features overrides kernel feature detection. The zero value triggers
	// detection at startup.
	Features Features
	// Logger receives engine logs. Nil uses the containerd global logger.
	Logger *log.Entry
}

// exitTarget is a watched process that can record an observed exit.
type exitTarget interface {
	finish(exitRecord)
}

// Engine is the in-process shimless runtime engine.
type Engine struct {
	cfg      Config
	features Features
	crun     *crunDriver
	watcher  *watcher
	tasks    *runtime.NSMap[*task]
	logger   *log.Entry

	mu      sync.Mutex
	targets map[int]exitTarget

	closed    atomic.Bool
	closeOnce sync.Once
}

// New constructs the engine and reconciles any tasks left on disk.
func New(cfg Config) (*Engine, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.L
	}
	if cfg.StateDir == "" {
		return nil, errors.New("shimless: state dir is required")
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = defaultCgroupRoot
	}
	if cfg.RuntimeName == "" {
		cfg.RuntimeName = engineName
	}
	if cfg.CrunPath == "" {
		path, err := exec.LookPath("crun")
		if err != nil {
			return nil, fmt.Errorf("shimless: crun not found in PATH: %w", err)
		}
		cfg.CrunPath = path
	}
	if _, err := os.Stat(cfg.CrunPath); err != nil {
		return nil, fmt.Errorf("shimless: crun binary %s: %w", cfg.CrunPath, err)
	}
	if !cfg.Features.PidfdOpen && !cfg.Features.PidfdExitInfo && !cfg.Features.CreatorOnly {
		cfg.Features = Detect()
	}

	e := &Engine{
		cfg:      cfg,
		features: cfg.Features,
		crun:     newCrunDriver(cfg.CrunPath, cfg.CrunRoot, cfg.Logger),
		tasks:    runtime.NewNSMap[*task](),
		logger:   cfg.Logger,
		targets:  make(map[int]exitTarget),
	}
	w, err := newWatcher(e.features, e.onExit)
	if err != nil {
		return nil, err
	}
	e.watcher = w

	if err := e.reconcile(context.Background()); err != nil {
		_ = w.Close()
		return nil, err
	}
	if out, err := e.crun.version(context.Background()); err != nil {
		e.logger.WithError(err).Warn("failed to query crun version")
	} else {
		e.logger.WithField("version", out).Info("shimless engine initialized")
	}
	return e, nil
}

// Supports reports whether runtimeName is handled by this engine.
func (e *Engine) Supports(runtimeName string) bool {
	if runtimeName == e.cfg.RuntimeName {
		return true
	}
	return strings.HasPrefix(runtimeName, e.cfg.RuntimeName+".")
}

// Create creates and registers a container for an activated bundle.
func (e *Engine) Create(ctx context.Context, taskID, bundlePath string, spec typeurl.Any, rootfs []mount.Mount, opts runtime.CreateOpts) (runtime.Task, error) {
	if e.closed.Load() {
		return nil, fmt.Errorf("shimless engine is closed: %w", errdefs.ErrUnavailable)
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	if len(rootfs) > 0 {
		if err := mount.All(rootfs, filepath.Join(bundlePath, "rootfs")); err != nil {
			return nil, fmt.Errorf("mount rootfs for %s: %w", taskID, err)
		}
	}

	var ociSpec *specs.Spec
	if spec != nil && spec.GetValue() != nil {
		var s specs.Spec
		if err := typeurl.UnmarshalTo(spec, &s); err != nil {
			return nil, fmt.Errorf("unmarshal spec for %s: %w", taskID, err)
		}
		ociSpec = &s
	}

	var receiver *pidfdReceiver
	if ociSpec != nil {
		receiver, err = newPidfdReceiver(bundlePath)
		if err != nil {
			return nil, err
		}
		defer receiver.Close()
		if ociSpec.Annotations == nil {
			ociSpec.Annotations = make(map[string]string, 2)
		}
		ociSpec.Annotations[annotationPIDFDReceiver] = receiver.Path()
		if e.features.CreatorOnly && e.cfg.Autokill {
			ociSpec.Annotations[annotationPIDFDAutokill] = "1"
		}
	}

	var cg *cgroup
	if ociSpec != nil {
		cg = e.setupCgroup(ociSpec, ns, taskID)
		if err := e.writeSpec(bundlePath, ociSpec); err != nil {
			return nil, err
		}
	}

	st := &taskState{
		Version:   stateVersion,
		Engine:    e.cfg.RuntimeName,
		Crun:      e.cfg.CrunPath,
		ID:        taskID,
		Namespace: ns,
		Bundle:    bundlePath,
		State:     stateCreated,
		CreatedAt: time.Now().UTC(),
	}
	if cg != nil {
		st.Cgroup = cg.path
	}
	if err := writeState(bundlePath, st); err != nil {
		return nil, err
	}

	pidFile := pidFilePath(bundlePath)
	if err := e.crun.create(ctx, taskID, bundlePath, pidFile, opts.IO); err != nil {
		e.discardCreated(ctx, taskID, bundlePath, cg)
		return nil, err
	}

	pid, err := readPidFile(pidFile)
	if err != nil {
		e.discardCreated(ctx, taskID, bundlePath, cg)
		return nil, fmt.Errorf("read init pid for %s: %w", taskID, err)
	}
	startTime, _ := readStartTime(pid)

	pidfd := -1
	if e.features.PidfdOpen {
		if receiver != nil {
			if fd, rerr := receiver.Receive(pidfdReceiverTimeout); rerr == nil {
				pidfd = fd
			} else {
				e.logger.WithError(rerr).WithField("id", taskID).Debug("no pidfd received from crun, falling back to pidfd_open")
			}
		}
		if pidfd < 0 {
			if fd, oerr := openPidfd(pid); oerr == nil {
				pidfd = fd
			} else {
				e.logger.WithError(oerr).WithField("id", taskID).Warn("failed to open pidfd; exit will be observed via cgroup")
			}
		}
	}

	if cg != nil && pid > 0 {
		if in, cerr := cg.Contains(pid); cerr == nil && !in {
			e.logger.WithFields(log.Fields{"id": taskID, "pid": pid}).Warn("init pid is not a member of the prepared cgroup")
		}
	}

	st.Pid = pid
	st.StartTime = startTime
	t := e.newTask(st, pidfd, cg)
	if err := writeState(bundlePath, st); err != nil {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		e.discardCreated(ctx, taskID, bundlePath, cg)
		return nil, err
	}
	if err := e.tasks.AddWithNamespace(ns, t); err != nil {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		e.discardCreated(ctx, taskID, bundlePath, cg)
		return nil, err
	}
	if pidfd >= 0 {
		if err := e.watch(pidfd, taskID, pid, t); err != nil {
			e.logger.WithError(err).WithField("id", taskID).Warn("failed to register pidfd watcher")
			unix.Close(pidfd)
			t.mu.Lock()
			t.pidfd = -1
			t.mu.Unlock()
		}
	}

	e.publish(ctx, &eventstypes.TaskCreate{
		ContainerID: taskID,
		Bundle:      bundlePath,
		Pid:         uint32(pid),
		IO: &eventstypes.TaskIO{
			Stdin:    opts.IO.Stdin,
			Stdout:   opts.IO.Stdout,
			Stderr:   opts.IO.Stderr,
			Terminal: opts.IO.Terminal,
		},
	})
	return t, nil
}

// Get returns a task by id.
func (e *Engine) Get(ctx context.Context, taskID string) (runtime.Task, error) {
	t, err := e.tasks.Get(ctx, taskID)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Tasks lists tasks, optionally across namespaces.
func (e *Engine) Tasks(ctx context.Context, all bool) ([]runtime.Task, error) {
	ts, err := e.tasks.GetAll(ctx, all)
	if err != nil {
		return nil, err
	}
	out := make([]runtime.Task, len(ts))
	for i, t := range ts {
		out[i] = t
	}
	return out, nil
}

// Delete removes a task and returns its exit.
func (e *Engine) Delete(ctx context.Context, taskID string) (*runtime.Exit, error) {
	t, err := e.tasks.Get(ctx, taskID)
	if err != nil {
		return nil, err
	}
	ex, err := t.remove(ctx)
	if err != nil {
		return nil, err
	}
	e.tasks.Delete(ctx, taskID)
	return ex, nil
}

// Close stops the watcher and releases engine resources. Running containers are
// intentionally left alone: they are reparented and survive a daemon restart.
func (e *Engine) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.closed.Store(true)
		err = e.watcher.Close()
	})
	return err
}

func (e *Engine) onExit(pidfd int, id string, rec exitRecord) {
	e.mu.Lock()
	tgt := e.targets[pidfd]
	delete(e.targets, pidfd)
	e.mu.Unlock()
	if tgt != nil {
		tgt.finish(rec)
	}
}

func (e *Engine) watch(pidfd int, id string, pid int, tgt exitTarget) error {
	e.mu.Lock()
	e.targets[pidfd] = tgt
	e.mu.Unlock()
	if err := e.watcher.Add(pidfd, id, pid); err != nil {
		e.mu.Lock()
		delete(e.targets, pidfd)
		e.mu.Unlock()
		return err
	}
	return nil
}

func (e *Engine) unwatch(pidfd int) {
	e.mu.Lock()
	delete(e.targets, pidfd)
	e.mu.Unlock()
	e.watcher.Remove(pidfd)
}

func (e *Engine) newTask(st *taskState, pidfd int, cg *cgroup) *task {
	return &task{
		engine:    e,
		id:        st.ID,
		namespace: st.Namespace,
		bundle:    st.Bundle,
		pid:       st.Pid,
		pidfd:     pidfd,
		cgroup:    cg,
		status:    runtime.CreatedStatus,
	}
}

func (e *Engine) persistState(t *task, state string) {
	st, err := readState(t.bundle)
	if err != nil {
		e.logger.WithError(err).WithField("id", t.id).Debug("no state file to update")
		return
	}
	st.State = state
	if err := writeState(t.bundle, st); err != nil {
		e.logger.WithError(err).WithField("id", t.id).Warn("failed to persist task state")
	}
}

// setupCgroup prepares the cgroup for the spec, if it can. A failure is not
// fatal: without a cgroup the engine still tracks the task by pidfd, only
// restart liveness detection is degraded.
func (e *Engine) setupCgroup(spec *specs.Spec, ns, taskID string) *cgroup {
	if spec.Linux == nil {
		return nil
	}
	path := spec.Linux.CgroupsPath
	if path == "" {
		path = filepath.Join("shimless", ns, taskID)
	}
	cg := newCgroup(e.cfg.CgroupRoot, path)
	if err := cg.Create(); err != nil {
		e.logger.WithError(err).WithFields(log.Fields{"id": taskID, "cgroup": cg.Path()}).
			Warn("failed to create cgroup; continuing without cgroup tracking")
		return nil
	}
	spec.Linux.CgroupsPath = "/" + cg.path
	return cg
}

func (e *Engine) writeSpec(bundle string, spec *specs.Spec) error {
	if err := writeJSONAtomic(filepath.Join(bundle, "config.json"), spec); err != nil {
		return fmt.Errorf("write bundle spec: %w", err)
	}
	return nil
}

// discardCreated cleans up after a failed create. It is best effort and
// deliberately detached from the caller's context, which may already be
// cancelled.
func (e *Engine) discardCreated(ctx context.Context, taskID, bundle string, cg *cgroup) {
	cctx := context.WithoutCancel(ctx)
	if err := e.crun.delete(cctx, taskID, true); err != nil {
		e.logger.WithError(err).WithField("id", taskID).Debug("failed to delete container after create failure")
	}
	if cg != nil {
		if err := cg.Delete(); err != nil {
			e.logger.WithError(err).Debug("failed to remove cgroup after create failure")
		}
	}
	if err := removeState(bundle); err != nil {
		e.logger.WithError(err).Debug("failed to remove state after create failure")
	}
}

// exitEvent converts a record into an exit event.
func exitEvent(taskID, id string, rec exitRecord) *eventstypes.TaskExit {
	return &eventstypes.TaskExit{
		ContainerID: taskID,
		ID:          id,
		Pid:         rec.Pid,
		ExitStatus:  rec.Status,
		ExitedAt:    timestamppb.New(rec.ExitedAt),
	}
}
