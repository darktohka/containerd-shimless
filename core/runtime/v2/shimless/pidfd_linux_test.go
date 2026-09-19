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
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPidfdReceiverTransfer(t *testing.T) {
	if !Detect().PidfdOpen {
		t.Skip("pidfd_open is not supported on this kernel")
	}
	bundle := t.TempDir()
	r, err := newPidfdReceiver(bundle)
	if err != nil {
		t.Fatalf("newPidfdReceiver: %v", err)
	}
	defer r.Close()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	pidfd, err := openPidfd(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("openPidfd: %v", err)
	}
	defer unix.Close(pidfd)

	// Act as crun: connect to the advertised path and send the pidfd over
	// SCM_RIGHTS. The sender must not block; the receiver is already listening.
	client, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer unix.Close(client)
	if err := unix.Connect(client, &unix.SockaddrUnix{Name: r.Path()}); err != nil {
		t.Fatalf("connect to receiver: %v", err)
	}
	if err := unix.Sendmsg(client, []byte{0}, unix.UnixRights(pidfd), nil, 0); err != nil {
		t.Fatalf("send pidfd: %v", err)
	}

	got, err := r.Receive(2 * time.Second)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	defer unix.Close(got)
	if got < 0 {
		t.Fatalf("received invalid fd %d", got)
	}
	// Signal 0 validates that the received descriptor is a live pidfd for a
	// running process.
	if err := unix.PidfdSendSignal(got, 0, nil, 0); err != nil {
		t.Fatalf("received fd is not a usable pidfd: %v", err)
	}
}
