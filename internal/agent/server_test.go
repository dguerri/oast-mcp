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

package agent_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/store"
)

func setupServer(t *testing.T) (*agent.Server, *auth.Auth, store.Store) {
	t.Helper()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, t.TempDir())
	return srv, a, st
}

// connectAgent starts a test HTTP server, dials a WS connection, and sends a
// register message. Returns the WS connection and the test server.
func connectAgent(t *testing.T, srv *agent.Server, token, agentID string, caps []string) (*websocket.Conn, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	err = conn.WriteJSON(map[string]any{
		"type":         "register",
		"agent_id":     agentID,
		"name":         "Test Agent",
		"capabilities": caps,
		"token":        token,
	})
	require.NoError(t, err)
	return conn, ts
}

// TestAgentRegister_MissingAgentIDClaim verifies that a token minted without
// an embedded agent_id (i.e. via Issue rather than IssueAgent) is rejected.
func TestAgentRegister_MissingAgentIDClaim(t *testing.T) {
	srv, a, _ := setupServer(t)

	// Issue a plain operator token — no "aid" claim.
	token, err := a.Issue("alice", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	require.NoError(t, conn.WriteJSON(map[string]any{
		"type":     "register",
		"agent_id": "some-agent", // server must ignore this
		"token":    token,
	}))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	var resp map[string]any
	require.NoError(t, conn.ReadJSON(&resp))
	assert.Equal(t, "error", resp["type"])
	assert.Contains(t, resp["message"], "token missing agent_id claim")
}

// TestAgentRegister_TenantScoped verifies that after a successful register
// the agent record appears in the store under the correct tenant.
func TestAgentRegister_TenantScoped(t *testing.T) {
	srv, a, st := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-alice-1", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	connectAgent(t, srv, token, "agent-alice-1", []string{"read_file", "exec"})

	// Give the server goroutine time to process the register message.
	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-alice-1", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond, "agent should appear in store")

	ag, err := st.GetAgent(context.Background(), "agent-alice-1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", ag.TenantID)
	assert.Equal(t, "online", ag.Status)
}

// TestAgentRegister_WrongScope verifies that a token lacking agent:connect
// is rejected with an error message.
func TestAgentRegister_WrongScope(t *testing.T) {
	srv, a, _ := setupServer(t)

	ts := httptest.NewServer(srv)
	defer ts.Close()

	token, err := a.Issue("alice", []string{"oast:read"}, time.Hour)
	require.NoError(t, err)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.WriteJSON(map[string]any{
		"type":     "register",
		"agent_id": "bad-agent",
		"token":    token,
	}))

	var resp map[string]any
	require.NoError(t, conn.ReadJSON(&resp))
	assert.Equal(t, "error", resp["type"])
	assert.Contains(t, resp["message"], "insufficient scope")
}

// TestAgentTask_Dispatch_E2E enqueues a task directly in the store, verifies
// the connected agent receives it over the WebSocket, then sends back a result.
// The test then checks the task is marked "done" in the store.
func TestAgentTask_Dispatch_E2E(t *testing.T) {
	srv, a, st := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-alice-e2e", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	conn, _ := connectAgent(t, srv, token, "agent-alice-e2e", []string{"exec"})

	// Wait for registration to complete.
	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-alice-e2e", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

	// Enqueue a task.
	now := time.Now().UTC()
	task := &store.Task{
		TaskID:     "task-e2e-1",
		AgentID:    "agent-alice-e2e",
		TenantID:   "alice",
		Capability: "exec",
		Params:     map[string]any{"cmd": "id"},
		Status:     "pending",
		CreatedAt:  now,
	}
	require.NoError(t, st.EnqueueTask(context.Background(), task))

	// The dispatch loop sends the task within 2 seconds.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var taskMsg map[string]any
	require.NoError(t, conn.ReadJSON(&taskMsg), "agent should receive the task message")
	assert.Equal(t, "task", taskMsg["type"])
	assert.Equal(t, "task-e2e-1", taskMsg["task_id"])
	assert.Equal(t, "exec", taskMsg["capability"])

	// Agent sends a result back.
	require.NoError(t, conn.WriteJSON(map[string]any{
		"type":    "result",
		"task_id": "task-e2e-1",
		"ok":      true,
		"data":    map[string]any{"output": "uid=0(root)"},
	}))

	// Verify the task is marked done in the store.
	require.Eventually(t, func() bool {
		t2, err := st.GetTask(context.Background(), "task-e2e-1", "alice")
		return err == nil && t2.Status == "done"
	}, 2*time.Second, 50*time.Millisecond, "task should be marked done")

	t2, err := st.GetTask(context.Background(), "task-e2e-1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "done", t2.Status)
	assert.Equal(t, "uid=0(root)", t2.Result["output"])
}

// TestAgentTask_TenantIsolation verifies that alice's agent only receives tasks
// enqueued for her tenant, not tasks for bob's agent.
func TestAgentTask_TenantIsolation(t *testing.T) {
	srv, a, st := setupServer(t)

	aliceToken, err := a.IssueAgent("alice", "agent-alice-iso", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	aliceConn, _ := connectAgent(t, srv, aliceToken, "agent-alice-iso", []string{"exec"})

	// Wait for alice's agent to register.
	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-alice-iso", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

	// Enqueue a task for a different agent (bob's) — alice should not receive it.
	bobTask := &store.Task{
		TaskID:     "task-bob-1",
		AgentID:    "agent-bob-iso",
		TenantID:   "bob",
		Capability: "exec",
		Params:     map[string]any{"cmd": "whoami"},
		Status:     "pending",
		CreatedAt:  time.Now().UTC(),
	}
	require.NoError(t, st.EnqueueTask(context.Background(), bobTask))

	// Enqueue a task for alice's agent so the connection stays warm.
	aliceTask := &store.Task{
		TaskID:     "task-alice-iso",
		AgentID:    "agent-alice-iso",
		TenantID:   "alice",
		Capability: "exec",
		Params:     map[string]any{"cmd": "id"},
		Status:     "pending",
		CreatedAt:  time.Now().UTC(),
	}
	require.NoError(t, st.EnqueueTask(context.Background(), aliceTask))

	// Alice's connection should receive exactly her task, not bob's.
	require.NoError(t, aliceConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var msg map[string]any
	require.NoError(t, aliceConn.ReadJSON(&msg))
	assert.Equal(t, "task-alice-iso", msg["task_id"],
		"alice's agent must only receive her own tasks")
}

// TestHandleConn_ExpiredToken verifies that a token that has already expired
// is rejected with a "token_expired" error message, not the generic "unauthorized".
func TestHandleConn_ExpiredToken(t *testing.T) {
	srv, a, _ := setupServer(t)

	// Issue a token with a negative TTL so it is already expired.
	token, err := a.IssueAgent("alice", "agent-expired", []string{"agent:connect"}, -time.Second)
	require.NoError(t, err)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	require.NoError(t, conn.WriteJSON(map[string]any{
		"type":     "register",
		"agent_id": "agent-expired",
		"token":    token,
	}))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	var resp map[string]any
	require.NoError(t, conn.ReadJSON(&resp))
	assert.Equal(t, "error", resp["type"])
	assert.Equal(t, "token_expired", resp["message"])
}

