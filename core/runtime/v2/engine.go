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

	"github.com/containerd/typeurl/v2"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/runtime"
)

// taskEngine is an in-process alternative to the shim path. It is selected by
// TaskManager when an implementation reports Supports for the task's runtime
// name, and is otherwise never consulted, so the default shim behavior is
// unchanged.
//
// This interface is intentionally small and frozen: implementations live
// outside this package (see core/runtime/v2/shimless) and must not require
// changes to ShimManager, local.go, or the runtime.Task/PlatformRuntime public
// API.
type taskEngine interface {
	// Supports reports whether this engine handles the given runtime name.
	// The name is the value from runtime.CreateOpts.Runtime, for example
	// "io.containerd.crun.v1".
	Supports(runtimeName string) bool

	// Create creates a task for an already prepared bundle. The bundle and
	// its mounts have been activated by TaskManager; rootfs is the residual
	// set of mounts the engine is still responsible for performing.
	Create(ctx context.Context, taskID, bundlePath string, spec typeurl.Any, rootfs []mount.Mount, opts runtime.CreateOpts) (runtime.Task, error)

	// Get returns a task previously created by this engine.
	Get(ctx context.Context, taskID string) (runtime.Task, error)

	// Tasks returns all tasks, optionally across all namespaces.
	Tasks(ctx context.Context, all bool) ([]runtime.Task, error)

	// Delete removes a task and returns its exit information.
	Delete(ctx context.Context, taskID string) (*runtime.Exit, error)

	// Close releases engine-wide resources.
	Close() error
}
