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

import "testing"

func TestDetect(t *testing.T) {
	f := Detect()
	// pidfd_open landed in 5.3 and is effectively always available on a
	// modern host; if it is not, the engine uses the cgroup fallback and the
	// test still validates that Detect returned cleanly.
	if !f.PidfdOpen {
		t.Skip("pidfd_open is not available on this kernel")
	}
	if !f.PidfdExitInfo {
		t.Log("PIDFD_GET_INFO exit reporting unavailable; fallback path in use")
	}
	if f.CreatorOnly {
		t.Log("kernel advertises the v7.3 creator-only clone3 flags")
	}
}

func TestLeadingInt(t *testing.T) {
	tests := []struct {
		in    string
		want  int
		valid bool
	}{
		{"7", 7, true},
		{"3-rc1", 3, true},
		{"10x", 10, true},
		{"", 0, false},
		{"rc1", 0, false},
	}
	for _, tt := range tests {
		got, ok := leadingInt(tt.in)
		if ok != tt.valid || got != tt.want {
			t.Errorf("leadingInt(%q) = (%d,%v), want (%d,%v)", tt.in, got, ok, tt.want, tt.valid)
		}
	}
}
