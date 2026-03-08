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

	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestCancelTask_Pending verifies that cancelling a pending task transitions it
// to error("cancelled").
func TestCancelTask_Pending(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "ct-1", AgentID: "agent-1", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	require.NoError(t, s.CancelTask(ctx, "ct-1", "alice"))

	got, err := s.GetTask(ctx, "ct-1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "error", got.Status)
	assert.Equal(t, "cancelled", got.Err)
	assert.NotNil(t, got.CompletedAt)
}

// TestCancelTask_AlreadyTerminal verifies that cancelling a terminal (done) task
// returns ErrNotFound (no transition performed).
func TestCancelTask_AlreadyTerminal(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "ct-2", AgentID: "agent-1", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))
	done := now.Add(time.Second)
	require.NoError(t, s.UpdateTask(ctx, &store.Task{
		TaskID: "ct-2", TenantID: "alice",
		Status: "done", CompletedAt: &done,
	}))

	err := s.CancelTask(ctx, "ct-2", "alice")
	assert.ErrorIs(t, err, store.ErrNotFound, "cancelling a done task must be a no-op")
}

// TestCancelTask_WrongTenant verifies that cancelling another tenant's task returns ErrNotFound.
func TestCancelTask_WrongTenant(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "ct-3", AgentID: "agent-1", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	err := s.CancelTask(ctx, "ct-3", "bob")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

// TestTimeoutStaleTasks verifies that tasks whose timeout_at has passed are marked
// as error("task timed out") and that tasks with a future timeout_at are unaffected.
func TestTimeoutStaleTasks(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	pastTimeout := now.Add(-time.Second) // already expired
	futureTimeout := now.Add(time.Hour)  // not yet expired

	// Task 1: pending, expired timeout → should be timed out.
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "tst-1", AgentID: "ag", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
		TimeoutAt: &pastTimeout, TimeoutSecs: 1,
	}))

	// Task 2: running, expired timeout → should be timed out.
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "tst-2", AgentID: "ag", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
		TimeoutAt: &pastTimeout, TimeoutSecs: 1,
	}))
	started := now
	require.NoError(t, s.UpdateTask(ctx, &store.Task{
		TaskID: "tst-2", TenantID: "alice", Status: "running", StartedAt: &started,
	}))

	// Task 3: pending, future timeout → must NOT be touched.
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "tst-3", AgentID: "ag", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
		TimeoutAt: &futureTimeout, TimeoutSecs: 3600,
	}))

	// Task 4: done, expired timeout → must NOT be touched (already terminal).
	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "tst-4", AgentID: "ag", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
		TimeoutAt: &pastTimeout, TimeoutSecs: 1,
	}))
	done := now.Add(time.Millisecond)
	require.NoError(t, s.UpdateTask(ctx, &store.Task{
		TaskID: "tst-4", TenantID: "alice", Status: "done", CompletedAt: &done,
	}))

	n, err := s.TimeoutStaleTasks(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "exactly two tasks should have been timed out")

	t1, err := s.GetTask(ctx, "tst-1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "error", t1.Status)
	assert.Equal(t, "task timed out", t1.Err)

	t2, err := s.GetTask(ctx, "tst-2", "alice")
	require.NoError(t, err)
	assert.Equal(t, "error", t2.Status)
	assert.Equal(t, "task timed out", t2.Err)

	t3, err := s.GetTask(ctx, "tst-3", "alice")
	require.NoError(t, err)
	assert.Equal(t, "pending", t3.Status, "future-timeout task must remain pending")

	t4, err := s.GetTask(ctx, "tst-4", "alice")
	require.NoError(t, err)
	assert.Equal(t, "done", t4.Status, "terminal task must not be touched")
}

// TestTasks_TimeoutFieldsPersisted verifies that TimeoutAt and TimeoutSecs are
// stored and retrieved correctly.
func TestTasks_TimeoutFieldsPersisted(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	timeoutAt := now.Add(10 * time.Minute)

	require.NoError(t, s.EnqueueTask(ctx, &store.Task{
		TaskID: "tf-1", AgentID: "ag", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
		TimeoutSecs: 600, TimeoutAt: &timeoutAt,
	}))

	got, err := s.GetTask(ctx, "tf-1", "alice")
	require.NoError(t, err)
	assert.Equal(t, 600, got.TimeoutSecs)
	require.NotNil(t, got.TimeoutAt)
	assert.WithinDuration(t, timeoutAt, *got.TimeoutAt, time.Second)
}

// TestMarkAllAgentsOffline verifies that all agents are set to "offline" and
// last_seen_at is updated.
func TestMarkAllAgentsOffline(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()

	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "a1", TenantID: "alice", Name: "A1",
		RegisteredAt: now, Capabilities: []string{"exec"},
		Status: "online", LastSeenAt: &now,
	}))
	require.NoError(t, s.UpsertAgent(ctx, &store.Agent{
		AgentID: "a2", TenantID: "bob", Name: "A2",
		RegisteredAt: now, Capabilities: []string{"exec"},
		Status: "online", LastSeenAt: &now,
	}))

	require.NoError(t, s.MarkAllAgentsOffline(ctx))

	a1, err := s.GetAgent(ctx, "a1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "offline", a1.Status)

	a2, err := s.GetAgent(ctx, "a2", "bob")
	require.NoError(t, err)
	assert.Equal(t, "offline", a2.Status)
}
