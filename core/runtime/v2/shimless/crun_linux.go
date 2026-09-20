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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/log"
)

// crunDriver runs the crun CLI. crun owns the container stdio and the init
// process; the engine only asks it to create/start/stop containers and reads
// the pid it writes.
type crunDriver struct {
	path   string
	root   string
	logger *log.Entry
}

// crunState mirrors the subset of `crun state` output the engine uses.
type crunState struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Pid         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations"`
}

func newCrunDriver(path, root string, logger *log.Entry) *crunDriver {
	return &crunDriver{path: path, root: root, logger: logger}
}

// version runs `crun --version`, used to validate the configured binary.
func (d *crunDriver) version(ctx context.Context) (string, error) {
	out, err := d.run(ctx, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (d *crunDriver) command(ctx context.Context, args ...string) *exec.Cmd {
	if d.root != "" {
		args = append([]string{"--root", d.root}, args...)
	}
	return exec.CommandContext(ctx, d.path, args...)
}

// run executes crun and returns stdout, enriching the error with stderr.
func (d *crunDriver) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := d.command(ctx, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return stdout.Bytes(), fmt.Errorf("crun %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return stdout.Bytes(), fmt.Errorf("crun %s: %w", strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}

// create creates the container without starting its user process. crun writes
// the init pid to pidFile. The container's stdio is supplied by the caller's
// stdioConfig: terminal processes get a --console-socket so crun hands the pty
// master back to the engine, non-terminal processes get real fds (never a
// typed-nil) so the container always has open fd 0/1/2.
func (d *crunDriver) create(ctx context.Context, id, bundle, pidFile string, stdio *stdioConfig) error {
	args := []string{"create", "--bundle", bundle, "--pid-file", pidFile}
	if stdio != nil && stdio.terminal && stdio.consoleSocket != nil {
		args = append(args, "--console-socket", stdio.consoleSocket.Path())
	}
	args = append(args, id)
	cmd := d.command(ctx, args...)
	stdio.apply(cmd)
	// Use a file, not a pipe: the unstarted init inherits crun's stderr write
	// end, so a bytes.Buffer would block Run until the container exits. A
	// terminal process has no cmd.Stderr yet, so this also captures crun's own
	// diagnostics.
	var diag *os.File
	if cmd.Stderr == nil {
		f, ferr := os.CreateTemp("", "shimless-crun-stderr-")
		if ferr == nil {
			diag = f
			defer func() {
				name := f.Name()
				f.Close()
				os.Remove(name)
			}()
			cmd.Stderr = f
		}
	}
	if err := cmd.Run(); err != nil {
		if rerr := d.getLastRuntimeError(bundle); rerr != nil {
			return fmt.Errorf("crun create %s: %w (runtime: %v)", id, err, rerr)
		}
		msg := ""
		if diag != nil {
			if b, rerr := os.ReadFile(diag.Name()); rerr == nil {
				msg = strings.TrimSpace(string(b))
			}
		}
		if msg != "" {
			return fmt.Errorf("crun create %s: %w: %s", id, err, msg)
		}
		return fmt.Errorf("crun create %s: %w", id, err)
	}
	return nil
}

func (d *crunDriver) start(ctx context.Context, id string) error {
	_, err := d.run(ctx, "start", id)
	if err != nil {
		return fmt.Errorf("start %s: %w", id, err)
	}
	return nil
}

func (d *crunDriver) state(ctx context.Context, id string) (*crunState, error) {
	out, err := d.run(ctx, "state", id)
	if err != nil {
		return nil, err
	}
	var st crunState
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("parse crun state for %s: %w", id, err)
	}
	return &st, nil
}

func (d *crunDriver) kill(ctx context.Context, id string, signal uint32, all bool) error {
	args := []string{"kill"}
	if all {
		args = append(args, "--all")
	}
	args = append(args, id, strconv.FormatUint(uint64(signal), 10))
	_, err := d.run(ctx, args...)
	if err != nil {
		return fmt.Errorf("kill %s: %w", id, err)
	}
	return nil
}

func (d *crunDriver) delete(ctx context.Context, id string, force bool) error {
	args := []string{"delete"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)
	_, err := d.run(ctx, args...)
	if err != nil {
		return fmt.Errorf("delete %s: %w", id, err)
	}
	return nil
}

func (d *crunDriver) pause(ctx context.Context, id string) error {
	_, err := d.run(ctx, "pause", id)
	if err != nil {
		return fmt.Errorf("pause %s: %w", id, err)
	}
	return nil
}

func (d *crunDriver) resume(ctx context.Context, id string) error {
	_, err := d.run(ctx, "resume", id)
	if err != nil {
		return fmt.Errorf("resume %s: %w", id, err)
	}
	return nil
}

// execProcess runs a detached exec process and writes its pid to pidFile. The
// process spec must already be written to a file on disk. A terminal exec gets
// a --console-socket so crun hands the pty master back to the engine.
func (d *crunDriver) execProcess(ctx context.Context, id, processFile, pidFile string, stdio *stdioConfig) error {
	args := []string{"exec", "--process", processFile, "--detach", "--pid-file", pidFile}
	if stdio != nil && stdio.terminal {
		args = append(args, "--tty")
		if stdio.consoleSocket != nil {
			args = append(args, "--console-socket", stdio.consoleSocket.Path())
		}
	}
	args = append(args, id)
	cmd := d.command(ctx, args...)
	stdio.apply(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crun exec %s: %w", id, err)
	}
	return nil
}

// ps returns the pids inside the container.
func (d *crunDriver) ps(ctx context.Context, id string) ([]int, error) {
	out, err := d.run(ctx, "ps", "--format", "json", id)
	if err != nil {
		return nil, err
	}
	var pids []int
	if err := json.Unmarshal(out, &pids); err != nil {
		return nil, fmt.Errorf("parse crun ps for %s: %w", id, err)
	}
	return pids, nil
}

// getLastRuntimeError returns the last error crun recorded in the bundle's
// log.json, if the runtime wrote one. crun on this host reports to stderr, so
// a missing log.json is normal and not an error.
func (d *crunDriver) getLastRuntimeError(bundle string) error {
	b, err := os.ReadFile(filepath.Join(bundle, "log.json"))
	if err != nil {
		return nil
	}
	var rec struct {
		Msg   string `json:"msg"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(b), &rec); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	switch {
	case rec.Error != "":
		return errors.New(rec.Error)
	case rec.Msg != "":
		return errors.New(rec.Msg)
	default:
		return nil
	}
}
