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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Persisted file names inside a task bundle. The bundle directory is owned by
// TaskManager (see NewBundle) and survives daemon restarts, which is what lets
// the engine reconcile state after a crash.
const (
	stateFileName = "shimless.json"
	exitFileName  = "exit.json"
	pidFileName   = "init.pid"

	stateVersion = 1
)

// Task lifecycle states persisted in shimless.json.
const (
	stateCreated = "created"
	stateRunning = "running"
	stateStopped = "stopped"
)

// taskState is the durable record of a shimless task. It is written before
// crun create so that a crash mid-create can still be reconciled, and it is
// updated on start and on exit.
type taskState struct {
	Version   int       `json:"v"`
	Engine    string    `json:"engine"`
	Crun      string    `json:"crun"`
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Bundle    string    `json:"bundle"`
	Pid       int       `json:"pid"`
	StartTime uint64    `json:"starttime"`
	Cgroup    string    `json:"cgroup,omitempty"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
}

// exitState is the durable record of how a task exited. It is written by the
// pidfd watcher the moment an exit is observed, and by Delete, so a later
// reconcile can recover the exit even if the daemon was down when it happened.
type exitState struct {
	Pid      uint32    `json:"pid"`
	Status   uint32    `json:"status"`
	Signal   uint32    `json:"signal,omitempty"`
	ExitedAt time.Time `json:"exitedAt"`
	Source   string    `json:"source"`
}

func statePath(bundle string) string { return filepath.Join(bundle, stateFileName) }

func exitStatePath(bundle string) string { return filepath.Join(bundle, exitFileName) }

func pidFilePath(bundle string) string { return filepath.Join(bundle, pidFileName) }

// writeState atomically persists st to bundle/shimless.json.
func writeState(bundle string, st *taskState) error {
	if st.Version == 0 {
		st.Version = stateVersion
	}
	return writeJSONAtomic(statePath(bundle), st)
}

// readState loads bundle/shimless.json.
func readState(bundle string) (*taskState, error) {
	var st taskState
	if err := readJSON(statePath(bundle), &st); err != nil {
		return nil, err
	}
	if st.Bundle == "" {
		st.Bundle = bundle
	}
	return &st, nil
}

// writeExit atomically persists ex to bundle/exit.json.
func writeExit(bundle string, ex *exitState) error {
	return writeJSONAtomic(exitStatePath(bundle), ex)
}

// readExit loads bundle/exit.json. It returns (nil, nil) when absent so
// callers can treat "no recorded exit" as a normal reconcile outcome.
func readExit(bundle string) (*exitState, error) {
	var ex exitState
	err := readJSON(exitStatePath(bundle), &ex)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ex, nil
}

// removeState deletes the engine's state files from a bundle. A missing file
// is not an error.
func removeState(bundle string) error {
	for _, name := range []string{stateFileName, exitFileName, pidFileName} {
		if err := os.Remove(filepath.Join(bundle, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// scanStateDir walks stateDir and loads every shimless.json it finds, in the
// <state>/<namespace>/<task-id>/ layout used by TaskManager.
func scanStateDir(stateDir string) ([]*taskState, error) {
	var states []*taskState
	err := filepath.WalkDir(stateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || d.Name() != stateFileName {
			return nil
		}
		st, err := readState(filepath.Dir(path))
		if err != nil {
			// A partially written or corrupt record must not prevent the
			// rest of the daemon from starting.
			return nil
		}
		states = append(states, st)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan state dir %s: %w", stateDir, err)
	}
	return states, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return nil
}

// writeJSONAtomic writes v as JSON to path using a temporary file in the same
// directory followed by rename, so a reader never observes a partial record.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	tmp = ""
	return nil
}
