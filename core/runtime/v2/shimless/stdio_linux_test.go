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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/runtime"
)

func TestParseStdioURLSchemelessIsFifo(t *testing.T) {
	u, err := parseStdioURL("/run/containerd/io/stdout")
	if err != nil {
		t.Fatalf("parseStdioURL: %v", err)
	}
	if u.Scheme != "fifo" {
		t.Fatalf("scheme = %q, want fifo", u.Scheme)
	}
	if u.Path != "/run/containerd/io/stdout" {
		t.Fatalf("path = %q, want the original path", u.Path)
	}
}

func TestParseStdioURLKeepsExplicitSchemes(t *testing.T) {
	for _, tc := range []struct {
		path   string
		scheme string
	}{
		{"file:///var/log/ctr.log", "file"},
		{"binary:///usr/bin/nerdctl?_NERDCTL_INTERNAL_LOGGING=/var/lib/nerdctl", "binary"},
		{"binary-v2:///usr/bin/nerdctl", "binary-v2"},
		{"fifo:///run/io/stdout", "fifo"},
	} {
		u, err := parseStdioURL(tc.path)
		if err != nil {
			t.Fatalf("parseStdioURL(%q): %v", tc.path, err)
		}
		if u.Scheme != tc.scheme {
			t.Errorf("parseStdioURL(%q).Scheme = %q, want %q", tc.path, u.Scheme, tc.scheme)
		}
	}
}

func TestNewBinaryCmdArgsAndEnv(t *testing.T) {
	uri, err := url.Parse("binary:///usr/bin/nerdctl?_NERDCTL_INTERNAL_LOGGING=/var/lib/nerdctl&flag=1")
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	cmd := newBinaryCmd(uri, "container-1", "default")

	if cmd.Path != "/usr/bin/nerdctl" {
		t.Fatalf("cmd.Path = %q, want /usr/bin/nerdctl", cmd.Path)
	}
	args := map[string]string{}
	for i := 1; i+1 < len(cmd.Args); i += 2 {
		args[cmd.Args[i]] = cmd.Args[i+1]
	}
	if args["_NERDCTL_INTERNAL_LOGGING"] != "/var/lib/nerdctl" {
		t.Errorf("args = %v, want _NERDCTL_INTERNAL_LOGGING=/var/lib/nerdctl", args)
	}
	if args["flag"] != "1" {
		t.Errorf("args = %v, want flag=1", args)
	}
	env := map[string]bool{}
	for _, e := range cmd.Env {
		env[e] = true
	}
	if !env["CONTAINER_ID=container-1"] || !env["CONTAINER_NAMESPACE=default"] {
		t.Errorf("cmd.Env = %v, want CONTAINER_ID and CONTAINER_NAMESPACE", cmd.Env)
	}
}

func TestNewStdioConfigEmptyIOOpensNullForEveryStream(t *testing.T) {
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	defer s.Close()

	stdin, stdout, stderr := s.containerFiles()
	for name, f := range map[string]*os.File{"stdin": stdin, "stdout": stdout, "stderr": stderr} {
		if f == nil {
			t.Fatalf("%s is nil; the container would start with a closed fd", name)
		}
		if f.Name() != os.DevNull {
			t.Errorf("%s opened %q, want %q", name, f.Name(), os.DevNull)
		}
	}
}

func TestStdioConfigApplyNeverAssignsTypedNil(t *testing.T) {
	cmd := exec.Command("/bin/true")
	(&stdioConfig{}).apply(cmd)
	if cmd.Stdin != nil {
		t.Errorf("cmd.Stdin = %#v, want nil (a typed-nil file would close fd 0)", cmd.Stdin)
	}
	if cmd.Stdout != nil {
		t.Errorf("cmd.Stdout = %#v, want nil", cmd.Stdout)
	}
	if cmd.Stderr != nil {
		t.Errorf("cmd.Stderr = %#v, want nil", cmd.Stderr)
	}
}

func TestStdioConfigApplyAssignsRealFiles(t *testing.T) {
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	defer s.Close()

	cmd := exec.Command("/bin/true")
	s.apply(cmd)
	stdin, ok := cmd.Stdin.(*os.File)
	if !ok || stdin == nil {
		t.Fatalf("cmd.Stdin = %#v, want a non-nil *os.File", cmd.Stdin)
	}
	stdout, ok := cmd.Stdout.(*os.File)
	if !ok || stdout == nil {
		t.Fatalf("cmd.Stdout = %#v, want a non-nil *os.File", cmd.Stdout)
	}
	stderr, ok := cmd.Stderr.(*os.File)
	if !ok || stderr == nil {
		t.Fatalf("cmd.Stderr = %#v, want a non-nil *os.File", cmd.Stderr)
	}
}

func TestStdioConfigFileScheme(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "container.log")
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{
		Stdout: "file://" + path,
		Stderr: "file://" + path,
	})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	_, stdout, stderr := s.containerFiles()
	if _, err := stdout.WriteString("out\n"); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if _, err := stderr.WriteString("err\n"); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if string(b) != "out\nerr\n" && string(b) != "err\nout\n" {
		t.Fatalf("log file = %q, want both streams written", b)
	}
}

func TestStdioConfigSchemelessFifoOutput(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "stdout")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{Stdout: fifoPath})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	defer s.Close()
	_, stdout, _ := s.containerFiles()
	if stdout == nil {
		t.Fatal("schemeless fifo stdout was not opened")
	}
}

func TestStdioConfigRejectsUnknownScheme(t *testing.T) {
	_, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{Stdout: "ttrpc+unix:///tmp/stream"})
	if err == nil {
		t.Fatal("unknown stdio scheme should be rejected, not silently degraded")
	}
}

func TestStdioConfigBinaryStartFailureIsSurfaced(t *testing.T) {
	_, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{
		Stdout: "binary:///nonexistent/shimless-logging-binary?_X=y",
	})
	if err == nil {
		t.Fatal("a logging binary that cannot start must fail the create")
	}
}

func TestStdioConfigTerminalCreatesConsoleSocket(t *testing.T) {
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{Terminal: true})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	defer s.Close()

	if !s.terminal {
		t.Fatal("terminal flag not recorded")
	}
	if s.consoleSocket == nil || s.consoleSocket.Path() == "" {
		t.Fatal("terminal stdio has no console socket; crun cannot hand over the pty")
	}
	if s.console != nil {
		t.Fatal("console should not be set before finish receives the master")
	}
	stdin, stdout, stderr := s.containerFiles()
	if stdin != nil || stdout != nil || stderr != nil {
		t.Fatalf("terminal stdio must not hand fds to crun, got %v %v %v", stdin, stdout, stderr)
	}
	cmd := exec.Command("/bin/true")
	s.apply(cmd)
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatalf("terminal apply set stdio: %v %v %v", cmd.Stdin, cmd.Stdout, cmd.Stderr)
	}
}

func TestStdioConfigResizeIsNilSafe(t *testing.T) {
	var nilConfig *stdioConfig
	if err := nilConfig.Resize(runtime.ConsoleSize{Width: 80, Height: 24}); err != nil {
		t.Fatalf("nil Resize = %v, want nil", err)
	}

	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	defer s.Close()
	if err := s.Resize(runtime.ConsoleSize{Width: 80, Height: 24}); err != nil {
		t.Fatalf("non-terminal Resize = %v, want nil no-op", err)
	}
}

func TestStdioConfigCloseIsIdempotent(t *testing.T) {
	s, err := newStdioConfig(context.Background(), "id", "ns", runtime.IO{})
	if err != nil {
		t.Fatalf("newStdioConfig: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
