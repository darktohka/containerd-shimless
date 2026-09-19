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

	"github.com/containerd/containerd/v2/core/runtime"
)

// publish emits ev on the configured exchange. A nil exchange is allowed: the
// engine still works with events disabled, which keeps unit tests free of a
// live event bus. Failures are logged, never fatal, because an event must not
// fail a task operation that already succeeded.
func (e *Engine) publish(ctx context.Context, ev any) {
	if e.cfg.Events == nil {
		return
	}
	topic := runtime.GetTopic(ev)
	if err := e.cfg.Events.Publish(ctx, topic, ev); err != nil {
		e.logger.WithError(err).WithField("topic", topic).Warn("failed to publish task event")
	}
}
