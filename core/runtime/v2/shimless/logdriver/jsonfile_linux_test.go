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

package logdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type decodedJSONEntry struct {
	Log    string    `json:"log"`
	Stream string    `json:"stream"`
	Time   time.Time `json:"time"`
}

func decodeFirstEntry(t *testing.T, path string) decodedJSONEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var e decodedJSONEntry
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&e); err != nil {
		t.Fatalf("decode %s (%q): %v", path, raw, err)
	}
	return e
}

func TestJSONFilePathAndEncode(t *testing.T) {
	dataStore := t.TempDir()
	cfg := Config{Driver: driverJSONFile}

	s, err := Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.WriteLine(streamStdout, "<hello>"); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := jsonPath(dataStore, "ns", "id")
	want := filepath.Join(dataStore, "containers", "ns", "id", "id-json.log")
	if path != want {
		t.Fatalf("jsonPath = %q, want %q", path, want)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// json.Encoder's default HTML escaping must be preserved for parity.
	if !strings.Contains(string(raw), `\u003c`) {
		t.Fatalf("expected HTML-escaped '<' in %q", raw)
	}

	e := decodeFirstEntry(t, path)
	if e.Log != "<hello>" {
		t.Fatalf("log = %q, want %q", e.Log, "<hello>")
	}
	if e.Stream != streamStdout {
		t.Fatalf("stream = %q, want %q", e.Stream, streamStdout)
	}
	if e.Time.IsZero() {
		t.Fatal("time is zero")
	}
	if e.Time.Location() != time.UTC {
		t.Fatalf("time location = %v, want UTC", e.Time.Location())
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Fatalf("log file mode = %o, want 0600", got)
	}
}

func TestJSONFileLogPathOptionOverridesPath(t *testing.T) {
	dataStore := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.log")
	cfg := Config{Driver: driverJSONFile, Opts: map[string]string{optLogPath: custom}}

	s, err := Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.WriteLine(streamStderr, "oops"); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e := decodeFirstEntry(t, custom)
	if e.Log != "oops" || e.Stream != streamStderr {
		t.Fatalf("entry = %+v, want log=oops stream=stderr", e)
	}

	if _, err := os.Stat(jsonPath(dataStore, "ns", "id")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("default log path should not exist, got err=%v", err)
	}
}

func TestJSONFileRotation(t *testing.T) {
	dataStore := t.TempDir()
	cfg := Config{Driver: driverJSONFile, Opts: map[string]string{optMaxSize: "200"}}

	s, err := Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	line := strings.Repeat("x", 60)
	for i := 0; i < 3; i++ {
		if err := s.WriteLine(streamStdout, line); err != nil {
			t.Fatalf("WriteLine %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	base := jsonPath(dataStore, "ns", "id")
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("base log file missing after rotation: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("base log file is empty after rotation")
	}
	if _, err := os.Stat(base + ".1"); err != nil {
		t.Fatalf("expected rotation backup %s.1: %v", base, err)
	}
}

func TestJSONFileMaxSizeAndMaxFileValidation(t *testing.T) {
	dataStore := t.TempDir()
	if _, err := Open(dataStore, "ns", "id", Config{Driver: driverJSONFile, Opts: map[string]string{optMaxSize: "0"}}, true); err == nil {
		t.Fatal("expected error for max-size=0")
	}
	if _, err := Open(dataStore, "ns", "id", Config{Driver: driverJSONFile, Opts: map[string]string{optMaxFile: "0"}}, true); err == nil {
		t.Fatal("expected error for max-file=0")
	}
}
