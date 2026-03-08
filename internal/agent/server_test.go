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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupServer(t *testing.T) (*agent.Server, *auth.Auth, store.Store) {
	t.Helper()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, t.TempDir())
	srv.PingInterval = 500 * time.Millisecond
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
	t.Cleanup(func() { _ = conn.Close() })

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

// readNonPing reads the next JSON message from the WebSocket, skipping any
// server-initiated ping messages. Tests that expect a specific message type
// should use this instead of conn.ReadJSON to avoid flakes from interleaved
// heartbeat pings.
func readNonPing(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	for {
		var msg map[string]any
		require.NoError(t, conn.ReadJSON(&msg))
		if msg["type"] != "ping" {
			return msg
		}
	}
}

// TestAgentRegister_MissingAgentIDClaim verifies that a token minted without
// an embedded agent_id (i.e. via Issue rather than IssueAgent) is rejected.
func TestAgentRegister_MissingAgentIDClaim(t *testing.T) {
	srv, a, _ := setupServer(t)

	token, err := a.Issue("alice", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

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
	defer func() { _ = conn.Close() }()

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

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-alice-e2e", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

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

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	taskMsg := readNonPing(t, conn)
	assert.Equal(t, "task", taskMsg["type"])
	assert.Equal(t, "task-e2e-1", taskMsg["task_id"])
	assert.Equal(t, "exec", taskMsg["capability"])

	require.NoError(t, conn.WriteJSON(map[string]any{
		"type":    "result",
		"task_id": "task-e2e-1",
		"ok":      true,
		"data":    map[string]any{"output": "uid=0(root)"},
	}))

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

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-alice-iso", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

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

	require.NoError(t, aliceConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	msg := readNonPing(t, aliceConn)
	assert.Equal(t, "task-alice-iso", msg["task_id"],
		"alice's agent must only receive her own tasks")
}

// TestAgentTask_CancelForwarded_E2E verifies that when SendCancel is called on
// the server while an agent is connected, a cancel message is forwarded to the
// agent over WebSocket.
func TestAgentTask_CancelForwarded_E2E(t *testing.T) {
	srv, a, st := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-cancel-fwd", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	conn, _ := connectAgent(t, srv, token, "agent-cancel-fwd", []string{"exec"})

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-cancel-fwd", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

	now := time.Now().UTC()
	timeoutAt := now.Add(10 * time.Minute)
	task := &store.Task{
		TaskID:      "task-cancel-fwd",
		AgentID:     "agent-cancel-fwd",
		TenantID:    "alice",
		Capability:  "exec",
		Params:      map[string]any{"cmd": "sleep 60"},
		Status:      "pending",
		CreatedAt:   now,
		TimeoutSecs: 600,
		TimeoutAt:   &timeoutAt,
	}
	require.NoError(t, st.EnqueueTask(context.Background(), task))

	require.Eventually(t, func() bool {
		t, err := st.GetTask(context.Background(), "task-cancel-fwd", "alice")
		return err == nil && t.Status == "running"
	}, 5*time.Second, 50*time.Millisecond, "task should be claimed as running")

	require.NoError(t, srv.SendCancel(context.Background(), "task-cancel-fwd", "agent-cancel-fwd", "alice"))

	t2, err := st.GetTask(context.Background(), "task-cancel-fwd", "alice")
	require.NoError(t, err)
	assert.Equal(t, "error", t2.Status)
	assert.Equal(t, "cancelled", t2.Err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		var msg map[string]any
		require.NoError(t, conn.ReadJSON(&msg), "expected cancel message")
		if msg["type"] == "cancel" {
			assert.Equal(t, "task-cancel-fwd", msg["task_id"])
			break
		}
	}
}

// TestAgentHeartbeat_UpdatesLastSeen verifies that the server sends periodic
// pings and that each pong updates last_seen_at in the store.
func TestAgentHeartbeat_UpdatesLastSeen(t *testing.T) {
	srv, a, st := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-hb", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	conn, _ := connectAgent(t, srv, token, "agent-hb", []string{"exec"})

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-hb", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

	initialAgent, err := st.GetAgent(context.Background(), "agent-hb", "alice")
	require.NoError(t, err)
	initialLastSeen := *initialAgent.LastSeenAt

	// Read the server-initiated ping.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var msg map[string]any
	require.NoError(t, conn.ReadJSON(&msg))
	assert.Equal(t, "ping", msg["type"])

	// Respond with pong.
	require.NoError(t, conn.WriteJSON(map[string]any{"type": "pong"}))

	// last_seen_at should advance.
	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-hb", "alice")
		return err == nil && ag.LastSeenAt != nil && ag.LastSeenAt.After(initialLastSeen)
	}, 3*time.Second, 50*time.Millisecond, "last_seen_at should be updated after pong")
}

// TestAgentRegister_SetsExpiresAt verifies that the agent's expires_at is set
// from the JWT token expiry at registration time.
func TestAgentRegister_SetsExpiresAt(t *testing.T) {
	srv, a, st := setupServer(t)

	ttl := 2 * time.Hour
	token, err := a.IssueAgent("alice", "agent-exp", []string{"agent:connect"}, ttl)
	require.NoError(t, err)

	connectAgent(t, srv, token, "agent-exp", []string{"exec"})

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-exp", "alice")
		return err == nil && ag != nil
	}, 2*time.Second, 50*time.Millisecond)

	ag, err := st.GetAgent(context.Background(), "agent-exp", "alice")
	require.NoError(t, err)
	require.NotNil(t, ag.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(ttl), *ag.ExpiresAt, 5*time.Second)
}

// TestAgentDisconnect_MarksOffline verifies that when an agent's WebSocket
// connection is closed, the server marks the agent as offline in the store.
// This also tests that the cleanup defer uses a fresh context (not the
// cancelled connection context).
func TestAgentDisconnect_MarksOffline(t *testing.T) {
	srv, a, st := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-disconnect", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	conn, _ := connectAgent(t, srv, token, "agent-disconnect", []string{"exec"})

	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-disconnect", "alice")
		return err == nil && ag != nil && ag.Status == "online"
	}, 2*time.Second, 50*time.Millisecond, "agent should be online")

	// Close the WebSocket connection.
	require.NoError(t, conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	))

	// Agent should transition to offline.
	require.Eventually(t, func() bool {
		ag, err := st.GetAgent(context.Background(), "agent-disconnect", "alice")
		return err == nil && ag.Status == "offline"
	}, 3*time.Second, 50*time.Millisecond, "agent should be marked offline after disconnect")
}

// TestHandleConn_ExpiredToken verifies that a token that has already expired
// is rejected with a "token_expired" error message, not the generic "unauthorized".
func TestHandleConn_ExpiredToken(t *testing.T) {
	srv, a, _ := setupServer(t)

	token, err := a.IssueAgent("alice", "agent-expired", []string{"agent:connect"}, -time.Second)
	require.NoError(t, err)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

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

// TestHealthEndpoints verifies that GET /health and GET /healthz return 200 OK.
func TestHealthEndpoints(t *testing.T) {
	srv, _, _ := setupServer(t)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	for _, path := range []string{"/health", "/healthz"} {
		t.Run(path, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + path)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestWSUpgradeFailed(t *testing.T) {
	srv, _, _ := setupServer(t)
	srv.WebSocketUpgrader = &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return false },
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	t.Run("/ws-ftw", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws-ftw"
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if resp != nil {
			defer func() { _ = resp.Body.Close() }()
		}
		require.Error(t, err)
		assert.ErrorContains(t, err, "websocket: bad handshake")
	})
}

// TestDownloadLoader_PublicEndpoint verifies that a loader binary can be
// downloaded without authentication and returns 200 OK.
func TestDownloadLoader_PublicEndpoint(t *testing.T) {
	_, _, dir, ts := newHTTPTestServer(t)

	// Create a fake loader binary in the known bin directory.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "loader-linux-amd64"), []byte("fake-binary"), 0o644))

	resp, err := ts.Client().Get(ts.URL + "/dl/loader-linux-amd64")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestDownloadLoader_NotFound verifies that requesting a non-existent loader binary returns 404.
func TestDownloadLoader_NotFound(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, dir)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	resp, err := ts.Client().Get(ts.URL + "/dl/loader-darwin-arm64")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDownloadSecondStage_NoAuth verifies that GET /dl/second-stage/linux/amd64
// without an Authorization header returns 401.
func TestDownloadSecondStage_NoAuth(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, dir)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	resp, err := ts.Client().Get(ts.URL + "/dl/second-stage/linux/amd64")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDownloadSecondStage_TokenExpired verifies that GET /dl/second-stage/linux/amd64
// with an expired token returns 401.
func TestDownloadSecondStage_InvalidToken(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, dir)

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest("GET", ts.URL+"/dl/second-stage/linux/amd64", nil)
	req.Header.Add("Authorization", "Bearer A.B.C")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// newHTTPTestServer creates a Server with a known binDir for HTTP-only tests.
func newHTTPTestServer(t *testing.T) (*agent.Server, *auth.Auth, string, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := agent.NewServer(a, st, logger, dir)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, a, dir, ts
}

// TestDownloadSecondStage_ValidToken_BinaryMissing verifies that a valid
// agent:connect token + missing binary → 404.
func TestDownloadSecondStage_ValidToken_BinaryMissing(t *testing.T) {
	_, a, _, ts := newHTTPTestServer(t)

	token, err := a.IssueAgent("alice", "agent-dl-miss", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/dl/second-stage/linux/amd64", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDownloadSecondStage_ValidToken_BinaryPresent verifies that a valid
// agent:connect token + existing binary → 200.
func TestDownloadSecondStage_ValidToken_BinaryPresent(t *testing.T) {
	_, a, dir, ts := newHTTPTestServer(t)

	// The server maps /dl/second-stage/linux/amd64 to binDir/agent-linux/amd64.
	// That path contains a slash (subdirectory), so create the directory first.
	agentBinPath := filepath.Join(dir, "agent-linux", "amd64")
	require.NoError(t, os.MkdirAll(filepath.Dir(agentBinPath), 0o755))
	require.NoError(t, os.WriteFile(agentBinPath, []byte("fake-agent"), 0o644))

	token, err := a.IssueAgent("alice", "agent-dl-ok", []string{"agent:connect"}, time.Hour)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/dl/second-stage/linux/amd64", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
