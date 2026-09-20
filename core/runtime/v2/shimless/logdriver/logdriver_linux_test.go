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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupported(t *testing.T) {
	for _, d := range []string{driverJSONFile, driverNone, driverJournald, driverSyslog} {
		if !Supported(d) {
			t.Errorf("Supported(%q) = false, want true", d)
		}
	}
	for _, d := range []string{"fluentd", "", "unknown"} {
		if Supported(d) {
			t.Errorf("Supported(%q) = true, want false", d)
		}
	}
}

func TestOpenDispatch(t *testing.T) {
	t.Run("fluentd-unsupported", func(t *testing.T) {
		_, err := Open(t.TempDir(), "ns", "id", Config{Driver: "fluentd"}, true)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Open(fluentd) error = %v, want ErrUnsupported", err)
		}
	})

	t.Run("none", func(t *testing.T) {
		s, err := Open(t.TempDir(), "ns", "id", Config{Driver: driverNone}, true)
		if err != nil {
			t.Fatalf("Open(none): %v", err)
		}
		if err := s.WriteLine(streamStdout, "ignored"); err != nil {
			t.Fatalf("WriteLine: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("json-file", func(t *testing.T) {
		s, err := Open(t.TempDir(), "ns", "id", Config{Driver: driverJSONFile}, true)
		if err != nil {
			t.Fatalf("Open(json-file): %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

func TestNoneSinkDiscardsOutput(t *testing.T) {
	s := noneSink{}
	if err := s.WriteLine(streamStdout, "hello"); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := s.WriteLine(streamStderr, "world"); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestOpenExclusiveLock(t *testing.T) {
	dataStore := t.TempDir()
	cfg := Config{Driver: driverNone}

	first, err := Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	if _, err := Open(dataStore, "ns", "id", cfg, true); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open error = %v, want ErrLocked", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Once released the lock can be re-acquired.
	second, err := Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpenDoesNotLeakLockOnFailure(t *testing.T) {
	dataStore := t.TempDir()

	// An invalid option makes sink construction fail after the lock is taken.
	if _, err := Open(dataStore, "ns", "id", Config{
		Driver: driverJSONFile,
		Opts:   map[string]string{optMaxSize: "not-a-size"},
	}, true); err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("Open with invalid max-size error = %v, want a construction error", err)
	}

	s, err := Open(dataStore, "ns", "id", Config{Driver: driverNone}, true)
	if err != nil {
		t.Fatalf("lock leaked after failed Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestConfigPathAndLoadConfig(t *testing.T) {
	dataStore := t.TempDir()
	path := ConfigPath(dataStore, "ns", "id")
	want := filepath.Join(dataStore, "containers", "ns", "id", "log-config.json")
	if path != want {
		t.Fatalf("ConfigPath = %q, want %q", path, want)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := `{"driver":"json-file","opts":{"max-size":"10"},"address":"unix:///run/foo.sock"}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(dataStore, "ns", "id")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Driver != driverJSONFile || cfg.Opts[optMaxSize] != "10" || cfg.Address != "unix:///run/foo.sock" {
		t.Fatalf("LoadConfig = %+v", cfg)
	}
}

func TestJournaldIdentifier(t *testing.T) {
	id, err := journaldIdentifier(nil, "ns", "0123456789abcdef")
	if err != nil {
		t.Fatalf("journaldIdentifier: %v", err)
	}
	if id != "0123456789ab" {
		t.Fatalf("default identifier = %q, want %q", id, "0123456789ab")
	}

	id, err = journaldIdentifier(map[string]string{optTag: "{{.Namespace}}/{{.ID}}"}, "ns", "0123456789abcdef")
	if err != nil {
		t.Fatalf("journaldIdentifier: %v", err)
	}
	if id != "ns/0123456789ab" {
		t.Fatalf("templated identifier = %q, want %q", id, "ns/0123456789ab")
	}
}

func TestJournaldDatagramEncoding(t *testing.T) {
	got := string(encodeJournaldDatagram(streamStdout, "line1\nline2", "ident", "0123456789abcdef"))
	want := "MESSAGE=line1\nline2\n" +
		"PRIORITY=6\n" +
		"SYSLOG_IDENTIFIER=ident\n" +
		"CONTAINER_TAG=ident\n" +
		"CONTAINER_ID=0123456789ab\n" +
		"CONTAINER_ID_FULL=0123456789abcdef\n"
	if got != want {
		t.Fatalf("datagram =\n%q\nwant\n%q", got, want)
	}

	stderr := string(encodeJournaldDatagram(streamStderr, "boom", "ident", "0123456789abcdef"))
	if !strings.Contains(stderr, "PRIORITY=3\n") {
		t.Fatalf("stderr datagram missing PRIORITY=3: %q", stderr)
	}
}
