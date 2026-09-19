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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/log"
	"golang.org/x/sys/unix"
)

// exitRecord is the engine-internal description of a process exit.
type exitRecord struct {
	Pid      uint32
	Status   uint32
	Signal   uint32
	ExitedAt time.Time
	Source   string
}

// exitHandler is invoked once per watched process when it exits. It may be
// called from a separate goroutine, so implementations must tolerate concurrent
// invocation. The pidfd identifies the entry unambiguously (task ids are only
// unique within a namespace).
type exitHandler func(pidfd int, id string, rec exitRecord)

type watchEntry struct {
	id  string
	pid int
}

// watcher is the single daemon-wide epoll loop that observes container exits.
// One epoll fd and one eventfd serve every task; each task contributes a single
// pidfd, so the fd cost is O(tasks) + 2.
//
// The watcher owns each registered pidfd: it closes the fd after the exit
// handler returns, or when Remove is called. Callers must not close it again.
type watcher struct {
	epfd     int
	efd      int
	features Features
	handler  exitHandler

	mu      sync.Mutex
	entries map[int]*watchEntry

	done      chan struct{}
	closeOnce sync.Once
}

// newWatcher creates the epoll loop and starts it.
func newWatcher(features Features, handler exitHandler) (*watcher, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(epfd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, efd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(efd),
	}); err != nil {
		unix.Close(efd)
		unix.Close(epfd)
		return nil, fmt.Errorf("epoll_ctl add eventfd: %w", err)
	}
	w := &watcher{
		epfd:     epfd,
		efd:      efd,
		features: features,
		handler:  handler,
		entries:  make(map[int]*watchEntry),
		done:     make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

// Add registers pidfd for id and its process pid.
func (w *watcher) Add(pidfd int, id string, pid int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.entries[pidfd]; ok {
		return fmt.Errorf("pidfd %d already watched", pidfd)
	}
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, pidfd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(pidfd),
	}); err != nil {
		return fmt.Errorf("epoll_ctl add pidfd %d: %w", pidfd, err)
	}
	w.entries[pidfd] = &watchEntry{id: id, pid: pid}
	return nil
}

// Remove stops watching pidfd and closes it if it was still registered. It is
// safe to call after the watcher already handled the exit.
func (w *watcher) Remove(pidfd int) {
	w.mu.Lock()
	_, ok := w.entries[pidfd]
	if ok {
		delete(w.entries, pidfd)
	}
	w.mu.Unlock()
	if !ok {
		return
	}
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, pidfd, nil); err != nil && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.ENOENT) {
		log.L.WithError(err).WithField("pidfd", pidfd).Warn("failed to remove pidfd from epoll")
	}
	unix.Close(pidfd)
}

// Close stops the loop and releases the epoll and event fds.
func (w *watcher) Close() error {
	w.closeOnce.Do(func() {
		var buf [8]byte
		buf[0] = 1
		if _, err := unix.Write(w.efd, buf[:]); err != nil && !errors.Is(err, unix.EAGAIN) {
			log.L.WithError(err).Debug("failed to signal watcher shutdown")
		}
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			log.L.Warn("timed out waiting for pidfd watcher to stop")
		}
		unix.Close(w.efd)
		unix.Close(w.epfd)
	})
	return nil
}

func (w *watcher) loop() {
	defer close(w.done)
	events := make([]unix.EpollEvent, 64)
	for {
		n, err := unix.EpollWait(w.epfd, events, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			log.L.WithError(err).Debug("pidfd watcher stopped")
			return
		}
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			if fd == w.efd {
				return
			}
			w.handle(fd)
		}
	}
}

// handle reports the exit of a single process. The pidfd is removed from the
// map before the handler runs so a concurrent Remove never double-closes it.
func (w *watcher) handle(pidfd int) {
	w.mu.Lock()
	e, ok := w.entries[pidfd]
	if ok {
		delete(w.entries, pidfd)
	}
	w.mu.Unlock()
	if !ok {
		return
	}
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, pidfd, nil); err != nil && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.ENOENT) {
		log.L.WithError(err).WithField("pidfd", pidfd).Warn("failed to remove exited pidfd from epoll")
	}

	rec := exitRecord{Pid: uint32(e.pid), ExitedAt: time.Now(), Status: 255, Source: "synthesize"}
	if !w.features.PidfdExitInfo {
		w.handler(pidfd, e.id, rec)
		unix.Close(pidfd)
		return
	}
	if ws, ok := readPidfdExit(pidfd); ok {
		rec.Status, rec.Signal = decodeWaitStatus(ws)
		rec.Source = "pidfd_info"
		w.handler(pidfd, e.id, rec)
		unix.Close(pidfd)
		return
	}
	// Offload the wait so one slow exit cannot stall the loop.
	id, pid := e.id, e.pid
	go func() {
		r := exitRecord{Pid: uint32(pid), ExitedAt: time.Now(), Status: 255, Source: "synthesize"}
		if ws, ok := waitPidfdExit(pidfd, 2*time.Second); ok {
			r.Status, r.Signal = decodeWaitStatus(ws)
			r.Source = "pidfd_info"
		}
		w.handler(pidfd, id, r)
		unix.Close(pidfd)
	}()
}
