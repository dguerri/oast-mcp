// Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package audit provides structured audit logging for security-relevant events.
package audit

import (
	"encoding/json"
	"io"
	"time"
)

// Event represents a single auditable action.
type Event struct {
	Time          time.Time `json:"time"`
	TenantID      string    `json:"tenant_id,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource,omitempty"`
	Outcome       string    `json:"outcome"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	XForwardedFor string    `json:"x_forwarded_for,omitempty"`
	Detail        any       `json:"detail,omitempty"`
}

// Logger writes newline-delimited JSON audit events to w.
type Logger struct {
	enc *json.Encoder
}

// New creates a Logger that writes to w.
func New(w io.Writer) *Logger {
	return &Logger{enc: json.NewEncoder(w)}
}

// Log writes ev as a JSON line. If Time is zero it is set to now.
func (l *Logger) Log(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	_ = l.enc.Encode(ev) // best-effort; write errors are intentionally ignored
}
