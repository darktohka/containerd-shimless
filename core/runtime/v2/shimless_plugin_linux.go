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

package v2

import (
	"fmt"

	"github.com/containerd/log"
	"github.com/containerd/plugin"

	"github.com/containerd/containerd/v2/core/events/exchange"
	"github.com/containerd/containerd/v2/core/runtime/v2/shimless"
	"github.com/containerd/containerd/v2/plugins"
)

// The engine is compiled in but inert unless TaskConfig.Shimless.Enabled is
// set, so the default shim path is unchanged.
var _ taskEngine = (*shimless.Engine)(nil)

func newShimlessEngine(ic *plugin.InitContext, config *TaskConfig, state string) (taskEngine, error) {
	if !config.Shimless.Enabled {
		return nil, nil
	}
	ep, err := ic.GetByID(plugins.EventPlugin, "exchange")
	if err != nil {
		return nil, fmt.Errorf("shimless: event exchange: %w", err)
	}
	events, ok := ep.(*exchange.Exchange)
	if !ok {
		return nil, fmt.Errorf("shimless: unexpected event plugin type %T", ep)
	}
	eng, err := shimless.New(shimless.Config{
		StateDir:    state,
		CrunPath:    config.Shimless.CrunPath,
		CrunRoot:    config.Shimless.CrunRoot,
		CgroupRoot:  config.Shimless.CgroupRoot,
		RuntimeName: config.Shimless.RuntimeName,
		Autokill:    config.Shimless.Autokill,
		Events:      events,
		Logger:      log.G(ic.Context),
	})
	if err != nil {
		return nil, fmt.Errorf("shimless engine: %w", err)
	}
	return eng, nil
}
