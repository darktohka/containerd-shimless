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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-units"
)

const (
	optLogPath = "log-path"
	optMaxSize = "max-size"
	optMaxFile = "max-file"

	// defaultMaxSize mirrors github.com/fahedouch/go-logrotate's default of
	// 100 MiB (defaultMaxSize * megabyte).
	defaultMaxSize = int64(100 * (1 << 20))
)

// jsonLogEntry is compatible with Docker's "json-file" log format.
type jsonLogEntry struct {
	Log    string    `json:"log,omitempty"`    // line, including "\r\n"
	Stream string    `json:"stream,omitempty"` // "stdout" or "stderr"
	Time   time.Time `json:"time"`             // e.g. "2020-12-11T20:29:41.939902251Z"
}

// jsonPath returns the default json-file log path for a container.
func jsonPath(dataStore, ns, id string) string {
	// the file name corresponds to Docker
	return filepath.Join(dataStore, "containers", ns, id, id+"-json.log")
}

// jsonSink writes Docker-compatible json-file entries, rotating the file the
// same way nerdctl's github.com/fahedouch/go-logrotate dependency does.
//
// WriteLine is safe for concurrent use and writes each entry under a mutex so
// a single encoded JSON document is never interleaved.
type jsonSink struct {
	mu sync.Mutex

	file *os.File
	path string
	size int64

	max        int64
	maxBackups int
	order      int

	closed bool
}

// newJSONSink initialises the log file/directory and opens the sink for
// appending. It mirrors nerdctl's JSONLogger.Init: the directory is created
// with mode 0700 and the file with mode 0600 when missing.
func newJSONSink(dataStore, ns, id string, opts map[string]string) (*jsonSink, error) {
	path := jsonPath(dataStore, ns, id)
	if logPath, ok := opts[optLogPath]; ok {
		path = logPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return nil, createErr
		}
		if createErr == nil {
			if err := f.Close(); err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}

	maxBytes := defaultMaxSize
	if capacity, ok := opts[optMaxSize]; ok {
		capVal, err := units.FromHumanSize(capacity)
		if err != nil {
			return nil, err
		}
		if capVal <= 0 {
			return nil, errors.New("max-size must be a positive number")
		}
		maxBytes = capVal
	}

	maxFile := 1
	if maxFileString, ok := opts[optMaxFile]; ok {
		n, err := strconv.Atoi(maxFileString)
		if err != nil {
			return nil, err
		}
		if n < 1 {
			return nil, errors.New("max-file cannot be less than 1")
		}
		maxFile = n
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &jsonSink{
		file:       f,
		path:       path,
		size:       fi.Size(),
		max:        maxBytes,
		maxBackups: maxFile - 1,
	}, nil
}

// WriteLine encodes a single entry with json.Encoder (default HTML escaping,
// newline-terminated) and appends it, rotating first when the write would
// exceed max-size.
func (s *jsonSink) WriteLine(stream, line string) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&jsonLogEntry{
		Log:    line,
		Stream: stream,
		Time:   time.Now().UTC(),
	}); err != nil {
		return err
	}
	entry := buf.Bytes()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if s.size+int64(len(entry)) > s.max {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.file.Write(entry)
	s.size += int64(n)
	return err
}

// Close closes the current log file. It is idempotent.
func (s *jsonSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// rotate closes the current file, renames it to the next free <base>.<N>
// backup, creates a fresh base file and prunes old backups.
func (s *jsonSink) rotate() error {
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return err
		}
		s.file = nil
	}
	if _, err := os.Stat(s.path); err == nil {
		if err := os.Rename(s.path, s.nextBackupName()); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	s.file = f
	s.size = 0
	return s.prune()
}

// nextBackupName returns the next free "<base>.<N>" path. This mirrors the
// logrotate library's "%s%s.%d" naming with an empty extension and a filename
// prefix, while additionally avoiding clobbering an existing backup.
func (s *jsonSink) nextBackupName() string {
	dir := filepath.Dir(s.path)
	base := filepath.Base(s.path)
	for {
		s.order++
		name := filepath.Join(dir, fmt.Sprintf("%s.%d", base, s.order))
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			return name
		}
	}
}

// prune deletes the oldest backups so that at most maxBackups remain. When
// maxBackups is 0 no backups are pruned, matching the logrotate library.
func (s *jsonSink) prune() error {
	if s.maxBackups <= 0 {
		return nil
	}
	dir := filepath.Dir(s.path)
	prefix := filepath.Base(s.path) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type backup struct {
		order int
		name  string
	}
	var backups []backup
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), prefix))
		if err != nil {
			continue
		}
		backups = append(backups, backup{order: n, name: e.Name()})
	}
	if len(backups) <= s.maxBackups {
		return nil
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].order < backups[j].order })
	for _, b := range backups[:len(backups)-s.maxBackups] {
		if err := os.Remove(filepath.Join(dir, b.name)); err != nil {
			return err
		}
	}
	return nil
}
