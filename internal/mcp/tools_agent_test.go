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

package mcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mcpsrv "github.com/dguerri/oast-mcp/internal/mcp"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
)

// TestAgentList_Empty verifies that listing agents for a tenant with no agents
// returns an empty array.
func TestAgentList_Empty(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_list", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	items := extractJSONArray(t, result)
	assert.Empty(t, items)
}

// TestAgentList_TenantIsolation verifies that each tenant sees only their own agents.
func TestAgentList_TenantIsolation(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "alice-agent",
		TenantID:     "alice",
		Name:         "Alice's Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "bob-agent",
		TenantID:     "bob",
		Name:         "Bob's Agent",
		RegisteredAt: now,
		Capabilities: []string{"read_file"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_list", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	items := extractJSONArray(t, result)
	require.Len(t, items, 1, "alice should see only her agent")
	first := items[0].(map[string]any)
	assert.Equal(t, "alice-agent", first["agent_id"])
}

// TestAgentList_InsufficientScope verifies that a token without agent:admin
// is rejected.
func TestAgentList_InsufficientScope(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:read"})

	result, err := srv.CallTool(ctx, "agent_list", nil)
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "agent:admin")
}

// TestAgentTaskSchedule_Success verifies that scheduling a task for an existing
// agent returns a task_id and stores the task.
func TestAgentTaskSchedule_Success(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-1",
		TenantID:     "alice",
		Name:         "Agent 1",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":   "agent-1",
		"capability": "exec",
		"params":     map[string]any{"cmd": "whoami"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	taskID := extractField(t, result, "task_id")
	require.NotEmpty(t, taskID)

	// Verify the task was actually stored.
	task, err := st.GetTask(context.Background(), taskID, "alice")
	require.NoError(t, err)
	assert.Equal(t, "pending", task.Status)
	assert.Equal(t, "exec", task.Capability)
	assert.Equal(t, "agent-1", task.AgentID)
}

// TestAgentTaskSchedule_AgentNotFound verifies that scheduling a task for
// a non-existent agent returns an error.
func TestAgentTaskSchedule_AgentNotFound(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_task_schedule", map[string]any{
		"agent_id":   "ghost-agent",
		"capability": "exec",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "agent not found")
}

// TestAgentTaskSchedule_WrongTenant verifies that bob cannot schedule a task
// on alice's agent.
func TestAgentTaskSchedule_WrongTenant(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "alice-agent",
		TenantID:     "alice",
		Name:         "Alice's Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	bobCtx := makeCtx(t, a, "bob", []string{"agent:admin"})
	result, err := srv.CallTool(bobCtx, "agent_task_schedule", map[string]any{
		"agent_id":   "alice-agent",
		"capability": "exec",
	})
	require.NoError(t, err)
	require.True(t, result.IsError, "bob must not be able to schedule on alice's agent")
	assert.Contains(t, getResultText(t, result), "agent not found")
}

// TestAgentTaskStatus_ReturnsStatusAndResult verifies that task_status returns
// the current status and the result map when the task is done.
func TestAgentTaskStatus_ReturnsStatusAndResult(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	done := now.Add(time.Second)
	task := &store.Task{
		TaskID:      "task-status-1",
		AgentID:     "agent-x",
		TenantID:    "alice",
		Capability:  "exec",
		Status:      "done",
		CreatedAt:   now,
		CompletedAt: &done,
		Result:      map[string]any{"output": "root"},
	}
	require.NoError(t, st.EnqueueTask(context.Background(), task))
	// Update to done state.
	require.NoError(t, st.UpdateTask(context.Background(), task))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id": "task-status-1",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "done", resp["status"])
	resultMap, ok := resp["result"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "root", resultMap["output"])
}

// TestAgentTaskStatus_WrongTenant verifies that bob cannot see alice's task.
func TestAgentTaskStatus_WrongTenant(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "task-alice-2",
		AgentID:    "agent-alice",
		TenantID:   "alice",
		Capability: "exec",
		Status:     "pending",
		CreatedAt:  time.Now().UTC(),
	}))

	bobCtx := makeCtx(t, a, "bob", []string{"agent:admin"})
	result, err := srv.CallTool(bobCtx, "agent_task_status", map[string]any{
		"task_id": "task-alice-2",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "task not found")
}


// newDropperServer creates an MCP server whose binDir contains a stub loader
// binary for "linux-amd64". Use this for agent_dropper_generate tests.
func newDropperServer(t *testing.T) (*mcpsrv.Server, *auth.Auth) {
	t.Helper()
	keyBytes := make([]byte, 32)
	a := auth.New(keyBytes)
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	mock := oast.NewMock(st, "oast.example.com")
	rl := ratelimit.New(100, 100)
	al := audit.New(io.Discard)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	binDir := t.TempDir()
	// Write a stub loader binary so the handler can read it.
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "loader-linux-amd64"), []byte("stub"), 0600))

	srv := mcpsrv.NewServer(a, st, mock, rl, al, logger, "oast.example.com", "mcp.example.com", "agent.example.com", binDir)
	return srv, a
}

// TestAgentDropperGenerate_URLDelivery verifies the default (url) delivery mode:
// returns URL/curl/wget fields and no b64 payload.
func TestAgentDropperGenerate_URLDelivery(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "1h",
		// delivery defaults to "url"
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))

	assert.Equal(t, "web-01", resp["agent_id"])
	assert.Equal(t, "linux-amd64", resp["os_arch"])
	assert.Equal(t, "url", resp["delivery"])
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["expires_at"])
	assert.Contains(t, resp["download_url"], "loader-linux-amd64")
	assert.Contains(t, resp["curl_cmd"], "web-01")
	assert.Contains(t, resp["wget_cmd"], "web-01")
	assert.Nil(t, resp["b64"])
	assert.Nil(t, resp["b64_cmd"])
}

// TestAgentDropperGenerate_InlineDelivery verifies that delivery=inline returns
// b64_cmd with the loader embedded and no URL fields.
func TestAgentDropperGenerate_InlineDelivery(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "1h",
		"delivery": "inline",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))

	assert.Equal(t, "inline", resp["delivery"])
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["b64_cmd"])
	assert.Nil(t, resp["download_url"])
	assert.Nil(t, resp["curl_cmd"])
	assert.Nil(t, resp["wget_cmd"])

	// b64_cmd must embed the stub bytes (base64-encoded).
	assert.Contains(t, resp["b64_cmd"], base64.StdEncoding.EncodeToString([]byte("stub")))
}

// TestAgentDropperGenerate_UnknownTarget verifies that requesting an
// unavailable os_arch returns a clear error.
func TestAgentDropperGenerate_UnknownTarget(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "plan9-mips",
		"ttl":      "1h",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "no loader available")
}

// TestAgentDropperGenerate_TTLTooLong verifies that a TTL > 168h is rejected.
func TestAgentDropperGenerate_TTLTooLong(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "200h",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "168h")
}

// TestAgentDropperGenerate_InsufficientScope verifies that a token without
// agent:admin is rejected.
func TestAgentDropperGenerate_InsufficientScope(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:read"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "1h",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "insufficient scope")
}

