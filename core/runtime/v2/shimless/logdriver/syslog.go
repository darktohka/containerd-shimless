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
	"fmt"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	optSyslogAddress  = "syslog-address"
	optSyslogFacility = "syslog-facility"
	optSyslogFormat   = "syslog-format"
	optTag            = "tag"

	// syslogTLSPrefix covers syslog-tls-ca-cert, syslog-tls-cert,
	// syslog-tls-key and syslog-tls-skip-verify.
	syslogTLSPrefix = "syslog-tls-"

	syslogSecureProto = "tcp+tls"
	syslogDefaultPort = "514"
)

// syslogFacilities mirrors nerdctl's facility names. The standard library's
// log/syslog priorities are numerically identical to srslog's.
var syslogFacilities = map[string]syslog.Priority{
	"kern":     syslog.LOG_KERN,
	"user":     syslog.LOG_USER,
	"mail":     syslog.LOG_MAIL,
	"daemon":   syslog.LOG_DAEMON,
	"auth":     syslog.LOG_AUTH,
	"syslog":   syslog.LOG_SYSLOG,
	"lpr":      syslog.LOG_LPR,
	"news":     syslog.LOG_NEWS,
	"uucp":     syslog.LOG_UUCP,
	"cron":     syslog.LOG_CRON,
	"authpriv": syslog.LOG_AUTHPRIV,
	"ftp":      syslog.LOG_FTP,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

// syslogSink forwards container output to a syslog daemon using the standard
// library. It is a deliberately simple port of nerdctl's srslog-based driver;
// options it cannot honour (TLS, explicit formats) yield ErrUnsupported so the
// caller can fall back to the external logger.
type syslogSink struct {
	mu     sync.Mutex
	writer *syslog.Writer
	closed bool
}

// newSyslogSink dials the configured syslog endpoint. tag defaults to the
// short container ID and can be overridden with opts["tag"].
func newSyslogSink(id string, opts map[string]string) (*syslogSink, error) {
	for k := range opts {
		if k == optSyslogFormat || strings.HasPrefix(k, syslogTLSPrefix) {
			return nil, fmt.Errorf("%w: syslog option %q", ErrUnsupported, k)
		}
	}

	proto, address, err := parseSyslogAddress(opts[optSyslogAddress])
	if err != nil {
		return nil, err
	}
	facility, err := parseSyslogFacility(opts[optSyslogFacility])
	if err != nil {
		return nil, err
	}

	tag := shortID(id)
	if cfgTag, ok := opts[optTag]; ok {
		tag = cfgTag
	}

	writer, err := syslog.Dial(proto, address, facility, tag)
	if err != nil {
		return nil, err
	}
	return &syslogSink{writer: writer}, nil
}

// WriteLine maps stdout to Info and stderr to Err, mirroring nerdctl.
func (s *syslogSink) WriteLine(stream, line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if stream == streamStderr {
		return s.writer.Err(line)
	}
	return s.writer.Info(line)
}

// Close closes the syslog connection. It is idempotent.
func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.writer == nil {
		return nil
	}
	return s.writer.Close()
}

// parseSyslogAddress mirrors nerdctl's parseSyslogAddress. An empty address
// returns empty network/address, which makes the standard library connect to
// the local syslog server. tcp+tls cannot be honoured and yields
// ErrUnsupported.
func parseSyslogAddress(address string) (string, string, error) {
	if address == "" {
		// Docker-compatible fallback to the local syslog socket is handled
		// by log/syslog when the network is empty.
		return "", "", nil
	}
	addr, err := url.Parse(address)
	if err != nil {
		return "", "", err
	}

	if addr.Scheme == "unix" || addr.Scheme == "unixgram" {
		if _, err := os.Stat(addr.Path); err != nil {
			return "", "", err
		}
		return addr.Scheme, addr.Path, nil
	}
	if addr.Scheme == syslogSecureProto {
		return "", "", fmt.Errorf("%w: syslog scheme %q", ErrUnsupported, addr.Scheme)
	}
	if addr.Scheme != "udp" && addr.Scheme != "tcp" {
		return "", "", fmt.Errorf("unsupported scheme: '%s'", addr.Scheme)
	}

	host := addr.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", "", err
		}
		host = net.JoinHostPort(host, syslogDefaultPort)
	}
	return addr.Scheme, host, nil
}

// parseSyslogFacility mirrors nerdctl's parseSyslogFacility: default LOG_DAEMON,
// named facilities, or a decimal number in [0,23].
func parseSyslogFacility(facility string) (syslog.Priority, error) {
	if facility == "" {
		return syslog.LOG_DAEMON, nil
	}
	if f, ok := syslogFacilities[facility]; ok {
		return f, nil
	}
	fInt, err := strconv.Atoi(facility)
	if err == nil && fInt >= 0 && fInt <= 23 {
		return syslog.Priority(fInt << 3), nil
	}
	return syslog.Priority(0), errors.New("invalid syslog facility")
}
