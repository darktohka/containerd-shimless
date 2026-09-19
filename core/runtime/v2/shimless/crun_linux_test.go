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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/runtime"
)

func crunPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("crun")
	if err != nil {
		t.Skip("crun is not installed")
	}
	return path
}

func TestCrunDriverVersion(t *testing.T) {
	d := newCrunDriver(crunPath(t), "", nil)
	out, err := d.version(context.Background())
	if err != nil {
		t.Fatalf("crun --version: %v", err)
	}
	if !strings.Contains(out, "crun") {
		t.Fatalf("crun --version output = %q, want it to mention crun", out)
	}
}

func TestCrunDriverStateMissing(t *testing.T) {
	d := newCrunDriver(crunPath(t), t.TempDir(), nil)
	if _, err := d.state(context.Background(), "shimless-does-not-exist"); err == nil {
		t.Fatal("crun state for a missing container succeeded, want error")
	}
}

func TestGetLastRuntimeError(t *testing.T) {
	bundle := t.TempDir()
	d := newCrunDriver("/usr/bin/crun", "", nil)

	if err := d.getLastRuntimeError(bundle); err != nil {
		t.Fatalf("missing log.json should not error, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "log.json"), []byte(`{"msg":"boom","level":"error"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := d.getLastRuntimeError(bundle)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("getLastRuntimeError = %v, want it to mention boom", err)
	}
}

func TestOpenContainerIOMissingPaths(t *testing.T) {
	stdin, stdout, stderr, cleanup := openContainerIO(runtime.IO{})
	defer cleanup()
	if stdin != nil || stdout != nil || stderr != nil {
		t.Fatalf("empty IO should leave all files nil, got %v %v %v", stdin, stdout, stderr)
	}
}
