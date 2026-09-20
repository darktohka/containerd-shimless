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

// Package logdriver implements the log-consumer side that nerdctl used to run
// as an external process ("nerdctl _NERDCTL_INTERNAL_LOGGING <datastore>").
//
// It writes the same on-disk artifacts as nerdctl so that "nerdctl logs"
// keeps working unchanged:
//
//   - <dataStore>/containers/<ns>/<id>/log-config.json selects the driver.
//   - <dataStore>/containers/<ns>/<id>/logger-lock is held with an exclusive
//     flock for the whole logging lifetime, so log viewers can block on it to
//     learn when the writer has finished.
//   - json-file entries are appended to <id>-json.log (or opts["log-path"]).
package logdriver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	driverJSONFile = "json-file"
	driverNone     = "none"
	driverJournald = "journald"
	driverSyslog   = "syslog"

	streamStdout = "stdout"
	streamStderr = "stderr"

	// shortIDLen mirrors nerdctl's use of id[:12] for container IDs.
	shortIDLen = 12

	lockFileName = "logger-lock"
)

var (
	// ErrUnsupported is returned when a driver (e.g. fluentd) or a driver
	// option cannot be served in-process. The caller may fall back to the
	// out-of-process logger.
	ErrUnsupported = errors.New("logdriver: unsupported logging driver or option")

	// ErrLocked is returned by Open with tryLock enabled when another writer
	// already holds the container's logger-lock.
	ErrLocked = errors.New("logdriver: logger lock is held by another writer")

	// errSinkClosed is returned when a write races with Close.
	errSinkClosed = errors.New("logdriver: sink is closed")
)

// Config mirrors nerdctl's log-config.json.
type Config struct {
	Driver  string            `json:"driver"`
	Opts    map[string]string `json:"opts,omitempty"`
	Address string            `json:"address"`
}

// Sink consumes already-framed log lines.
//
// WriteLine must be safe for concurrent use by the stdout and stderr
// goroutines. Close must be idempotent and, for json-file, release any
// resources associated with the log file.
type Sink interface {
	WriteLine(stream, line string) error
	Close() error
}

// ConfigPath returns the path of the per-container log-config.json.
func ConfigPath(dataStore, ns, id string) string {
	return filepath.Join(dataStore, "containers", ns, id, "log-config.json")
}

// LoadConfig reads and decodes the log-config.json written for the container.
func LoadConfig(dataStore, ns, id string) (Config, error) {
	path := ConfigPath(dataStore, ns, id)
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read log config file %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to load JSON logging config file %q: %w", path, err)
	}
	return cfg, nil
}

// Supported reports whether driver can be served in-process.
func Supported(driver string) bool {
	switch driver {
	case driverJSONFile, driverNone, driverJournald, driverSyslog:
		return true
	default:
		return false
	}
}

// Open selects a driver described by cfg and acquires the container's
// exclusive logger-lock. tryLock selects LOCK_EX|LOCK_NB and returns ErrLocked
// when another writer already holds the lock.
//
// The returned Sink owns the lock: Close releases it even if closing the
// driver fails. On any error the lock is not leaked.
func Open(dataStore, ns, id string, cfg Config, tryLock bool) (Sink, error) {
	if !Supported(cfg.Driver) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, cfg.Driver)
	}

	lock, err := acquireLock(lockPath(dataStore, ns, id), tryLock)
	if err != nil {
		return nil, err
	}

	sink, err := newSink(dataStore, ns, id, cfg)
	if err != nil {
		// Do not leak the lock if the driver could not be initialised.
		_ = lock.release()
		return nil, err
	}
	return &lockedSink{sink: sink, lock: lock}, nil
}

// newSink constructs the driver-specific sink. It does not touch the lock.
func newSink(dataStore, ns, id string, cfg Config) (Sink, error) {
	switch cfg.Driver {
	case driverJSONFile:
		return newJSONSink(dataStore, ns, id, cfg.Opts)
	case driverNone:
		return noneSink{}, nil
	case driverJournald:
		return newJournaldSink(ns, id, cfg.Opts)
	case driverSyslog:
		return newSyslogSink(id, cfg.Opts)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, cfg.Driver)
	}
}

func lockPath(dataStore, ns, id string) string {
	return filepath.Join(dataStore, "containers", ns, id, lockFileName)
}

// shortID truncates a container ID to the 12 characters nerdctl uses for
// journald metadata, tolerating IDs shorter than that.
func shortID(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}
	return id
}

// lockedSink ties the driver sink to the process-wide exclusive logger-lock.
type lockedSink struct {
	sink Sink
	lock *fileLock

	mu     sync.Mutex
	closed bool
}

func (s *lockedSink) WriteLine(stream, line string) error {
	return s.sink.WriteLine(stream, line)
}

// Close closes the driver and releases the lock. It is idempotent and always
// releases the lock, even when closing the driver fails.
func (s *lockedSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	sinkErr := s.sink.Close()
	lockErr := s.lock.release()
	if sinkErr != nil {
		return sinkErr
	}
	return lockErr
}

// fileLock is an exclusive flock(2) held for the lifetime of a logging session.
type fileLock struct {
	f *os.File

	mu     sync.Mutex
	closed bool
}

// acquireLock opens (creating if needed) path and takes an exclusive flock on
// it. When try is true the lock is non-blocking and ErrLocked is returned if
// the lock is already held.
func acquireLock(path string, try bool) (*fileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to create logger lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open logger lock %q: %w", path, err)
	}
	how := unix.LOCK_EX
	if try {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %q", ErrLocked, path)
		}
		return nil, fmt.Errorf("failed to lock logger lock %q: %w", path, err)
	}
	return &fileLock{f: f}, nil
}

// release unlocks and closes the lock file. It is idempotent.
func (l *fileLock) release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	unlockErr := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	closeErr := l.f.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
