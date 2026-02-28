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

// Package oast implements the out-of-band DNS and HTTP listeners that receive
// and record callback events from injection payloads.
package oast

import (
	"context"
	"github.com/dguerri/oast-mcp/internal/store"
)

// Endpoints holds the callback URLs for a new OAST session.
type Endpoints struct {
	CorrelationID string
	DNS           string // <corrID>.oast.example.com
	HTTP          string // http://<corrID>.oast.example.com
	HTTPS         string // https://<corrID>.oast.example.com
}

// Interacter is the interface the MCP server uses to create sessions and receive callbacks.
type Interacter interface {
	// NewSession registers a new correlation ID and returns callback endpoints.
	NewSession(ctx context.Context, sessionID, tenantID string) (*Endpoints, error)
	// StartPolling begins background polling for interactions. Blocks until ctx is cancelled.
	StartPolling(ctx context.Context) error
	// Stop terminates polling.
	Stop()
}

// sessionMeta maps a correlationID prefix to an MCP session.
type sessionMeta struct {
	sessionID string
	tenantID  string
}

// EventSink is implemented by the store — used by the adapter to persist incoming events.
// This keeps the adapter decoupled from the full store.Store interface.
type EventSink interface {
	SaveEvent(ctx context.Context, e *store.Event) error
}
