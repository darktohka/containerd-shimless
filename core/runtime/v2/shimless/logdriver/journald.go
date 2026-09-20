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
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"text/template"
)

// journalSocketPath is systemd-journald's native datagram socket.
const journalSocketPath = "/run/systemd/journal/socket"

// journaldIdentifierVars are the template variables available in
// opts["tag"], matching nerdctl's identifier struct.
type journaldIdentifierVars struct {
	ID        string
	FullID    string
	Namespace string
}

// journaldSink writes entries to the local systemd journal over its native
// UNIX datagram socket. It is a dependency-free replacement for
// github.com/coreos/go-systemd/v22/journal and mirrors nerdctl's journald
// metadata.
type journaldSink struct {
	mu         sync.Mutex
	conn       *net.UnixConn
	identifier string
	id         string
	closed     bool
}

// newJournaldSink probes the journal socket and connects to it. It fails when
// the socket is absent or is not a unix socket, so the caller can fall back.
func newJournaldSink(ns, id string, opts map[string]string) (*journaldSink, error) {
	fi, err := os.Stat(journalSocketPath)
	if err != nil {
		return nil, fmt.Errorf("the local systemd journal is not available for logging: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("the local systemd journal is not available for logging: %s is not a socket", journalSocketPath)
	}

	identifier, err := journaldIdentifier(opts, ns, id)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: journalSocketPath, Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the systemd journal: %w", err)
	}
	return &journaldSink{conn: conn, identifier: identifier, id: id}, nil
}

// journaldIdentifier resolves opts["tag"] against {{.ID}}, {{.FullID}} and
// {{.Namespace}}, defaulting to the short container ID.
func journaldIdentifier(opts map[string]string, ns, id string) (string, error) {
	tag, ok := opts[optTag]
	if !ok {
		return shortID(id), nil
	}
	tmpl, err := template.New("tag").Parse(tag)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, journaldIdentifierVars{
		ID:        shortID(id),
		FullID:    id,
		Namespace: ns,
	}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// WriteLine sends one datagram for the line. The whole datagram is written in
// a single send so journald sees it as one entry.
func (s *journaldSink) WriteLine(stream, line string) error {
	data := encodeJournaldDatagram(stream, line, s.identifier, s.id)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	_, err := s.conn.Write(data)
	return err
}

// Close closes the journal connection. It is idempotent.
func (s *journaldSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// encodeJournaldDatagram builds a native journal datagram. Each field is
// "NAME=value\n"; a value containing newlines is encoded as a first
// "NAME=first" line followed by continuation lines (without a "NAME=" prefix),
// exactly as the native protocol documents.
func encodeJournaldDatagram(stream, line, identifier, id string) []byte {
	priority := 6 // LOG_INFO
	if stream == streamStderr {
		priority = 3 // LOG_ERR
	}

	var buf bytes.Buffer
	writeJournalField(&buf, "MESSAGE", line)
	writeJournalField(&buf, "PRIORITY", strconv.Itoa(priority))
	writeJournalField(&buf, "SYSLOG_IDENTIFIER", identifier)
	writeJournalField(&buf, "CONTAINER_TAG", identifier)
	writeJournalField(&buf, "CONTAINER_ID", shortID(id))
	writeJournalField(&buf, "CONTAINER_ID_FULL", id)
	return buf.Bytes()
}

// writeJournalField writes "name=value\n". Newlines embedded in value are the
// documented continuation encoding: each subsequent line carries no "name="
// prefix, so a raw "\n" cannot be mistaken for a field break.
func writeJournalField(buf *bytes.Buffer, name, value string) {
	buf.WriteString(name)
	buf.WriteByte('=')
	buf.WriteString(value)
	buf.WriteByte('\n')
}
