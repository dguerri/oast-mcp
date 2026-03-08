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

// Package store defines the persistent storage layer for sessions, events,
// agents, tasks, and token revocations.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by store methods when the requested record does not exist.
var ErrNotFound = errors.New("not found")

// DefaultTaskTimeoutSecs is the fallback task timeout (10 minutes) used when
// the caller does not specify a timeout.
const DefaultTaskTimeoutSecs = 600

// SessionRef carries the minimal session fields needed to rebuild the OAST
// in-memory corrID→session map after a restart. It contains no tenant-secret
// data beyond what is already recorded against the corrID in DNS/HTTP logs.
type SessionRef struct {
	CorrelationID string
	SessionID     string
	TenantID      string
}

type Session struct {
	SessionID     string
	TenantID      string
	CorrelationID string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ClosedAt      *time.Time
	Cursor        string
	Tags          []string
}

type Event struct {
	EventID    string
	SessionID  string
	TenantID   string
	ReceivedAt time.Time
	Protocol   string
	SrcIP      string
	Data       map[string]any
}

type Agent struct {
	AgentID      string
	TenantID     string
	Name         string
	RegisteredAt time.Time
	LastSeenAt   *time.Time
	Capabilities []string
	Status       string // online|offline
}

type Task struct {
	TaskID      string
	AgentID     string
	TenantID    string
	ScheduledBy string
	Capability  string
	Params      map[string]any
	Status      string // pending|running|done|error
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	TimeoutAt   *time.Time
	TimeoutSecs int // 0 means use default
	Result      map[string]any
	Err         string
}

type Store interface {
	// Sessions (all tenant-scoped)
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, sessionID, tenantID string) (*Session, error)
	ListSessions(ctx context.Context, tenantID string) ([]*Session, error)
	UpdateSessionCursor(ctx context.Context, sessionID, tenantID, cursor string) error
	CloseSession(ctx context.Context, sessionID, tenantID string) error

	// Events
	SaveEvent(ctx context.Context, e *Event) error
	PollEvents(ctx context.Context, sessionID, tenantID, cursor string, limit int) ([]*Event, string, error)

	// Token revocation
	RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	PruneRevocations(ctx context.Context) error

	// Agents (tenant-scoped)
	UpsertAgent(ctx context.Context, a *Agent) error
	GetAgent(ctx context.Context, agentID, tenantID string) (*Agent, error)
	ListAgents(ctx context.Context, tenantID string) ([]*Agent, error)
	UpdateAgentStatus(ctx context.Context, agentID, tenantID, status string, lastSeen time.Time) error
	MarkAllAgentsOffline(ctx context.Context) error

	// Tasks (tenant-scoped)
	EnqueueTask(ctx context.Context, t *Task) error
	DequeueTask(ctx context.Context, agentID, tenantID string) (*Task, error) // claims oldest pending; returns nil if none
	UpdateTask(ctx context.Context, t *Task) error
	GetTask(ctx context.Context, taskID, tenantID string) (*Task, error)
	ListTasks(ctx context.Context, agentID, tenantID string) ([]*Task, error)
	// CancelTask transitions a pending or running task to error("cancelled").
	// Returns ErrNotFound if the task does not exist or is already terminal.
	CancelTask(ctx context.Context, taskID, tenantID string) error
	// TimeoutStaleTasks marks all pending/running tasks whose timeout_at has
	// passed as error("task timed out"). Returns the number of tasks updated.
	TimeoutStaleTasks(ctx context.Context, now time.Time) (int, error)

	// Maintenance
	PurgeExpired(ctx context.Context, sessionTTL, eventTTL time.Duration) error
	Close() error
}
