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
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/runtime/v2/shimless/logdriver"
)

// writeSinkLogConfig writes the nerdctl log-config.json a startInProcessLog
// call reads.
func writeSinkLogConfig(t *testing.T, dataStore, ns, id, driver string) {
	t.Helper()
	path := logdriver.ConfigPath(dataStore, ns, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create log config dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"driver":"`+driver+`","address":""}`), 0o600); err != nil {
		t.Fatalf("write log config: %v", err)
	}
}

func TestNerdctlLogDataStore(t *testing.T) {
	u, err := url.Parse("binary:///usr/bin/nerdctl?_NERDCTL_INTERNAL_LOGGING=/var/lib/nerdctl/store")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dataStore, ok := nerdctlLogDataStore(u)
	if !ok || dataStore != "/var/lib/nerdctl/store" {
		t.Fatalf("nerdctlLogDataStore = (%q, %v), want store path", dataStore, ok)
	}

	plain, err := url.Parse("binary:///usr/bin/logger")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if dataStore, ok := nerdctlLogDataStore(plain); ok {
		t.Fatalf("plain binary URI detected as nerdctl logging URI: %q", dataStore)
	}

	empty, err := url.Parse("binary:///usr/bin/nerdctl?_NERDCTL_INTERNAL_LOGGING=")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := nerdctlLogDataStore(empty); ok {
		t.Fatal("empty datastore query value must not be treated as a nerdctl logging URI")
	}

	if _, ok := nerdctlLogDataStore(nil); ok {
		t.Fatal("nil URL must not be treated as a nerdctl logging URI")
	}
}

func TestStartInProcessLogUnsupported(t *testing.T) {
	dataStore := t.TempDir()
	writeSinkLogConfig(t, dataStore, "ns", "id", "fluentd")
	if _, _, _, err := startInProcessLog(dataStore, "id", "ns", t.TempDir(), true); !errors.Is(err, logdriver.ErrUnsupported) {
		t.Fatalf("fluentd error = %v, want ErrUnsupported", err)
	}

	writeSinkLogConfig(t, dataStore, "ns", "id", "json-file")
	if _, _, _, err := startInProcessLog(dataStore, "id", "ns", "", true); !errors.Is(err, logdriver.ErrUnsupported) {
		t.Fatalf("empty bundle error = %v, want ErrUnsupported", err)
	}
}

func TestOpenContainerOutputsFallsBackForUnsupportedDriver(t *testing.T) {
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true binary available: %v", err)
	}
	dataStore := t.TempDir()
	writeSinkLogConfig(t, dataStore, "ns", "id", "fluentd")

	uri := "binary://" + truePath + "?_NERDCTL_INTERNAL_LOGGING=" + url.QueryEscape(dataStore)
	s := &stdioConfig{id: "id", ns: "ns", bundle: t.TempDir()}
	stdout, stderr, logger, plog, err := s.openContainerOutputs(context.Background(), uri, uri)
	if err != nil {
		t.Fatalf("openContainerOutputs: %v", err)
	}
	defer func() {
		closeAll(stdout, stderr)
		_ = stopLogger(logger)
	}()

	if plog != nil {
		t.Fatal("in-process log created for an unsupported driver")
	}
	if logger == nil {
		t.Fatal("expected fallback to the external logger")
	}
}

func TestStartInProcessLogCreatesFIFOsAndReleasesLock(t *testing.T) {
	dataStore := t.TempDir()
	writeSinkLogConfig(t, dataStore, "ns", "id", "json-file")
	bundle := t.TempDir()

	l, stdout, stderr, err := startInProcessLog(dataStore, "id", "ns", bundle, true)
	if err != nil {
		t.Fatalf("startInProcessLog: %v", err)
	}

	outPath, errPath := fifoPaths(bundle, "id")
	for _, path := range []string{outPath, errPath} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat fifo %s: %v", path, err)
		}
		if fi.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("%s is not a FIFO (mode %v)", path, fi.Mode())
		}
	}
	for name, f := range map[string]*os.File{"stdout": stdout, "stderr": stderr} {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			t.Fatalf("%s fcntl: %v", name, err)
		}
		if flags&unix.O_ACCMODE != unix.O_RDWR {
			t.Fatalf("%s fifo flags = %#x, want O_RDWR", name, flags)
		}
	}

	cfg := logdriver.Config{Driver: "json-file"}
	if _, err := logdriver.Open(dataStore, "ns", "id", cfg, true); !errors.Is(err, logdriver.ErrLocked) {
		t.Fatalf("Open while in-process log is active = %v, want ErrLocked", err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sink, err := logdriver.Open(dataStore, "ns", "id", cfg, true)
	if err != nil {
		t.Fatalf("Open after Close: %v (logger lock was not released)", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestReattachBinaryStdioInProcess(t *testing.T) {
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true binary available: %v", err)
	}
	dataStore := t.TempDir()
	writeSinkLogConfig(t, dataStore, "ns", "id", "json-file")
	uri := "binary://" + truePath + "?_NERDCTL_INTERNAL_LOGGING=" + url.QueryEscape(dataStore)

	st := &taskState{
		ID:        "id",
		Namespace: "ns",
		Bundle:    t.TempDir(),
		Stdio:     &stdioState{Stdout: uri, Stderr: uri},
	}
	cfg, err := reattachBinaryStdio(st)
	if err != nil {
		t.Fatalf("reattachBinaryStdio: %v", err)
	}
	if cfg == nil || cfg.log == nil {
		t.Fatalf("expected in-process reattach, got %+v", cfg)
	}
	if cfg.logger != nil {
		t.Fatal("external logger must not be started for a supported driver")
	}
	if err := cfg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// While another writer holds the lock, re-attach must decline.
	holder, err := logdriver.Open(dataStore, "ns", "id", logdriver.Config{Driver: "json-file"}, true)
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer holder.Close()

	st2 := &taskState{
		ID:        "id",
		Namespace: "ns",
		Bundle:    t.TempDir(),
		Stdio:     &stdioState{Stdout: uri, Stderr: uri},
	}
	if cfg, err := reattachBinaryStdio(st2); err != nil || cfg != nil {
		t.Fatalf("reattach while locked = (%v, %v), want (nil, nil)", cfg, err)
	}
}

func TestInProcessLogReaderExitsOnFdClose(t *testing.T) {
	dataStore := t.TempDir()
	writeSinkLogConfig(t, dataStore, "ns", "id", "json-file")
	bundle := t.TempDir()

	l, stdout, stderr, err := startInProcessLog(dataStore, "id", "ns", bundle, true)
	if err != nil {
		t.Fatalf("startInProcessLog: %v", err)
	}
	defer closeAll(stdout, stderr)

	if _, err := stdout.Write([]byte("hello\nworld")); err != nil {
		t.Fatalf("write to stdout fifo: %v", err)
	}

	drained := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(drained)
	}()

	// Closing the reader descriptors must unblock the reader goroutines.
	for _, r := range l.readers {
		_ = r.Close()
	}

	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("reader goroutines did not exit after the FIFO fds were closed")
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
