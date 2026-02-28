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

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/store"
)

var ctx = context.Background()

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeSession(id, tenant string) *store.Session {
	now := time.Now().UTC().Truncate(time.Second)
	return &store.Session{
		SessionID:     id,
		TenantID:      tenant,
		CorrelationID: "corr-" + id,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		Tags:          []string{"ssrf"},
	}
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func TestSession_CreateAndGet(t *testing.T) {
	s := newStore(t)
	sess := makeSession("s1", "alice")
	require.NoError(t, s.CreateSession(ctx, sess))

	got, err := s.GetSession(ctx, "s1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "s1", got.SessionID)
	assert.Equal(t, "alice", got.TenantID)
	assert.Equal(t, []string{"ssrf"}, got.Tags)
	assert.Equal(t, "corr-s1", got.CorrelationID)
}

func TestSession_TenantIsolation(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateSession(ctx, makeSession("s1", "alice")))
	require.NoError(t, s.CreateSession(ctx, makeSession("s2", "bob")))

	// alice cannot see bob's session
	_, err := s.GetSession(ctx, "s2", "alice")
	assert.ErrorIs(t, err, store.ErrNotFound)

	// list is scoped per tenant
	aliceSessions, err := s.ListSessions(ctx, "alice")
	require.NoError(t, err)
	assert.Len(t, aliceSessions, 1)

	bobSessions, err := s.ListSessions(ctx, "bob")
	require.NoError(t, err)
	assert.Len(t, bobSessions, 1)
}

func TestSession_Close(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateSession(ctx, makeSession("s1", "alice")))
	require.NoError(t, s.CloseSession(ctx, "s1", "alice"))

	got, err := s.GetSession(ctx, "s1", "alice")
	require.NoError(t, err)
	assert.NotNil(t, got.ClosedAt)
}

func TestSession_CloseWrongTenant(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateSession(ctx, makeSession("s1", "alice")))
	err := s.CloseSession(ctx, "s1", "bob")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

// ── Events ────────────────────────────────────────────────────────────────────

func insertEvents(t *testing.T, s store.Store, sessionID, tenantID string, n int) {
	t.Helper()
	base := time.Now().UTC()
	for i := 0; i < n; i++ {
		ev := &store.Event{
			EventID:    fmt.Sprintf("ev-%s-%02d", sessionID, i),
			SessionID:  sessionID,
			TenantID:   tenantID,
			ReceivedAt: base.Add(time.Duration(i) * time.Millisecond),
			Protocol:   "dns",
			SrcIP:      "1.2.3.4",
			Data:       map[string]any{"qname": fmt.Sprintf("q%d.oast.example.com", i)},
		}
		require.NoError(t, s.SaveEvent(ctx, ev))
	}
}

func TestEvents_CursorPagination(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateSession(ctx, makeSession("s1", "alice")))
	insertEvents(t, s, "s1", "alice", 5)

	// first page: 3 events
	page1, cursor1, err := s.PollEvents(ctx, "s1", "alice", "", 3)
	require.NoError(t, err)
	assert.Len(t, page1, 3)
	assert.NotEmpty(t, cursor1)

	// second page: remaining 2
	page2, cursor2, err := s.PollEvents(ctx, "s1", "alice", cursor1, 3)
	require.NoError(t, err)
	assert.Len(t, page2, 2)
	assert.Empty(t, cursor2)

	// no duplicates across pages
	seen := map[string]bool{}
	for _, e := range append(page1, page2...) {
		assert.False(t, seen[e.EventID], "duplicate event %s", e.EventID)
		seen[e.EventID] = true
	}
	assert.Len(t, seen, 5)
}

func TestEvents_TenantIsolation(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateSession(ctx, makeSession("sa", "alice")))
	require.NoError(t, s.CreateSession(ctx, makeSession("sb", "bob")))
	insertEvents(t, s, "sa", "alice", 2)

	// bob cannot poll alice's session
	_, _, err := s.PollEvents(ctx, "sa", "bob", "", 10)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

// ── Token revocation ──────────────────────────────────────────────────────────

func TestTokenRevocation(t *testing.T) {
	s := newStore(t)
	exp := time.Now().Add(time.Hour)

	require.NoError(t, s.RevokeToken(ctx, "jti-1", exp))

	revoked, err := s.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)

	revoked, err = s.IsRevoked(ctx, "unknown-jti")
	require.NoError(t, err)
	assert.False(t, revoked)
}

// ── Agents ────────────────────────────────────────────────────────────────────

func TestAgents_TenantIsolation(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	agentA := &store.Agent{
		AgentID:      "agent-a",
		TenantID:     "alice",
		Name:         "Alice Agent",
		RegisteredAt: now,
		Capabilities: []string{"system_info"},
		Status:       "online",
	}
	require.NoError(t, s.UpsertAgent(ctx, agentA))

	// alice can get her agent
	got, err := s.GetAgent(ctx, "agent-a", "alice")
	require.NoError(t, err)
	assert.Equal(t, "agent-a", got.AgentID)

	// bob cannot
	_, err = s.GetAgent(ctx, "agent-a", "bob")
	assert.ErrorIs(t, err, store.ErrNotFound)

	// list scoped
	aliceAgents, err := s.ListAgents(ctx, "alice")
	require.NoError(t, err)
	assert.Len(t, aliceAgents, 1)

	bobAgents, err := s.ListAgents(ctx, "bob")
	require.NoError(t, err)
	assert.Len(t, bobAgents, 0)
}

// ── Tasks ─────────────────────────────────────────────────────────────────────

func TestTasks_EnqueueDequeue(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "agent-1", TenantID: "alice", Name: "A1",
		RegisteredAt: now, Capabilities: []string{"exec"}, Status: "online",
	}))

	task := &store.Task{
		TaskID:      "task-1",
		AgentID:     "agent-1",
		TenantID:    "alice",
		ScheduledBy: "alice",
		Capability:  "exec",
		Params:      map[string]any{"cmd": "/usr/bin/id"},
		Status:      "pending",
		CreatedAt:   now,
	}
	require.NoError(t, s.EnqueueTask(ctx, task))

	dequeued, err := s.DequeueTask(ctx, "agent-1", "alice")
	require.NoError(t, err)
	require.NotNil(t, dequeued)
	assert.Equal(t, "task-1", dequeued.TaskID)
	assert.Equal(t, "running", dequeued.Status)

	// second dequeue returns nil (no more pending tasks)
	dequeued2, err := s.DequeueTask(ctx, "agent-1", "alice")
	require.NoError(t, err)
	assert.Nil(t, dequeued2)
}

// TestTasks_DequeueTask_TenantIsolation verifies that an agent cannot dequeue
// tasks that belong to a different tenant, even if the agent_id matches.
func TestTasks_DequeueTask_TenantIsolation(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	// Register "agent-x" for two different tenants.
	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "agent-x", TenantID: "alice", Name: "Alice agent-x",
		RegisteredAt: now, Capabilities: []string{"exec"}, Status: "online",
	}))
	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "agent-x", TenantID: "bob", Name: "Bob agent-x",
		RegisteredAt: now, Capabilities: []string{"exec"}, Status: "online",
	}))

	// Enqueue a task for alice's agent-x.
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "task-alice", AgentID: "agent-x", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	// Bob's agent-x must NOT dequeue alice's task.
	got, err := s.DequeueTask(ctx, "agent-x", "bob")
	require.NoError(t, err)
	assert.Nil(t, got, "bob's agent must not dequeue alice's task")

	// Alice's agent-x must dequeue her own task.
	got, err = s.DequeueTask(ctx, "agent-x", "alice")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "task-alice", got.TaskID)
}

func TestTasks_TenantIsolation(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "agent-1", TenantID: "alice", Name: "A1",
		RegisteredAt: now, Capabilities: []string{"exec"}, Status: "online",
	}))
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "t1", AgentID: "agent-1", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	// alice can get her task
	got, err := s.GetTask(ctx, "t1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "t1", got.TaskID)

	// bob cannot
	_, err = s.GetTask(ctx, "t1", "bob")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

