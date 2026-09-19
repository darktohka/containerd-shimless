//go:build !windows && !darwin

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

package v2

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// setupAbsoluteShimPath creates a temporary directory in $PATH with an empty
// shim executable file in it to test the exec.LookPath branch of resolveRuntimePath
func setupAbsoluteShimPath(t *testing.T) (string, error) {
	tempShimDir := t.TempDir()

	_, err := os.Create(tempShimDir + "/containerd-shim-runc-v2")
	if err != nil {
		return "", err
	}

	t.Setenv("PATH", tempShimDir+":"+os.Getenv("PATH"))
	absoluteShimPath := tempShimDir + "/containerd-shim-runc-v2"

	err = os.Chmod(absoluteShimPath, 0777)
	if err != nil {
		return "", err
	}

	return absoluteShimPath, nil
}

func TestResolveRuntimePath(t *testing.T) {
	sm := &ShimManager{}
	absoluteShimPath, err := setupAbsoluteShimPath(t)
	if err != nil {
		t.Errorf("Failed to create temporary shim path: %q", err)
	}

	tests := []struct {
		runtime string
		want    string
	}{
		{ // Absolute path
			runtime: absoluteShimPath,
			want:    absoluteShimPath,
		},
		{ // Binary name
			runtime: "io.containerd.runc.v2",
			want:    absoluteShimPath,
		},
		{ // Invalid absolute path
			runtime: "/fake/abs/path",
			want:    "",
		},
		{ // No name
			runtime: "",
			want:    "",
		},
		{ // Relative Path
			runtime: "./containerd-shim-runc-v2",
			want:    "",
		},
		{
			runtime: "fake/containerd-shim-runc-v2",
			want:    "",
		},
		{
			runtime: "./fake/containerd-shim-runc-v2",
			want:    "",
		},
		{ // Relative Path or Bad Binary Name
			runtime: ".io.containerd.runc.v2",
			want:    "",
		},
	}

	for _, c := range tests {
		have, _ := sm.resolveRuntimePath(c.runtime)
		if have != c.want {
			t.Errorf("Expected %q, got %q", c.want, have)
		}
	}
}

type fakeEngine struct {
	deleted   []string
	deleteErr error
}

var _ taskEngine = (*fakeEngine)(nil)

func (f *fakeEngine) Supports(string) bool { return true }

func (f *fakeEngine) Create(context.Context, string, string, typeurl.Any, []mount.Mount, runtime.CreateOpts) (runtime.Task, error) {
	return nil, nil
}

func (f *fakeEngine) Get(context.Context, string) (runtime.Task, error) {
	return nil, errdefs.ErrNotFound
}

func (f *fakeEngine) Tasks(context.Context, bool) ([]runtime.Task, error) { return nil, nil }

func (f *fakeEngine) Delete(_ context.Context, taskID string) (*runtime.Exit, error) {
	f.deleted = append(f.deleted, taskID)
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &runtime.Exit{}, nil
}

func (f *fakeEngine) Close() error { return nil }

func TestTaskManagerDeleteEngineRemovesBundle(t *testing.T) {
	state := t.TempDir()
	ctx := namespaces.WithNamespace(context.Background(), "test")

	bundlePath := filepath.Join(state, "test", "task")
	require.NoError(t, os.MkdirAll(filepath.Join(bundlePath, "rootfs"), 0700))

	eng := &fakeEngine{}
	tm := &TaskManager{
		state:      state,
		taskMounts: &taskMountController{},
		engine:     eng,
	}

	_, err := tm.Delete(ctx, "task")
	require.NoError(t, err)
	assert.Equal(t, []string{"task"}, eng.deleted)

	_, err = os.Stat(bundlePath)
	assert.True(t, os.IsNotExist(err), "bundle directory must be removed for engine tasks")
}
