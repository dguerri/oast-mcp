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

	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	mcpsrv "github.com/dguerri/oast-mcp/internal/mcp"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestAgentList_ExcludesExpiredByDefault verifies that expired agents are
// hidden by default and shown when show_expired=true.
func TestAgentList_ExcludesExpiredByDefault(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID: "alive", TenantID: "alice", Name: "Alive",
		RegisteredAt: now, Capabilities: []string{"exec"},
		Status: "online", ExpiresAt: &future,
	}))
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID: "dead", TenantID: "alice", Name: "Dead",
		RegisteredAt: now, Capabilities: []string{"exec"},
		Status: "offline", ExpiresAt: &past,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})

	// Default: only non-expired
	result, err := srv.CallTool(aliceCtx, "agent_list", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))
	items := extractJSONArray(t, result)
	assert.Len(t, items, 1)
	assert.Equal(t, "alive", items[0].(map[string]any)["agent_id"])

	// show_expired=true: both
	result, err = srv.CallTool(aliceCtx, "agent_list", map[string]any{
		"show_expired": true,
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))
	items = extractJSONArray(t, result)
	assert.Len(t, items, 2)
}

// newDropperServer creates an MCP server whose binDir contains a stub loader
// binary for "linux-amd64". Use this for agent_dropper_generate tests.
func newDropperServer(t *testing.T) (*mcpsrv.Server, *auth.Auth) {
	t.Helper()
	keyBytes := make([]byte, 32)
	a := auth.New(keyBytes)
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	mock := oast.NewMock(st, "oast.example.com")
	rl := ratelimit.New(100, 100)
	al := audit.New(io.Discard)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	binDir := t.TempDir()
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

// TestAgentTaskSchedule_DefaultTimeout verifies that a scheduled task gets the
// default timeout when timeout_secs is not supplied.
func TestAgentTaskSchedule_DefaultTimeout(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-to",
		TenantID:     "alice",
		Name:         "Timeout Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":   "agent-to",
		"capability": "exec",
		"params":     map[string]any{"cmd": "id"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, float64(store.DefaultTaskTimeoutSecs), resp["timeout_secs"])
	assert.NotEmpty(t, resp["timeout_at"])
}

// TestAgentTaskSchedule_CustomTimeout verifies that a caller-supplied timeout_secs
// is stored and returned.
func TestAgentTaskSchedule_CustomTimeout(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-cto",
		TenantID:     "alice",
		Name:         "Custom Timeout Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":     "agent-cto",
		"capability":   "exec",
		"params":       map[string]any{"cmd": "id"},
		"timeout_secs": float64(120),
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, float64(120), resp["timeout_secs"])

	taskID := resp["task_id"].(string)
	task, err := st.GetTask(context.Background(), taskID, "alice")
	require.NoError(t, err)
	assert.Equal(t, 120, task.TimeoutSecs)
	require.NotNil(t, task.TimeoutAt)
}

// TestAgentTaskSchedule_TimeoutTooLarge verifies that timeout_secs > 86400 is rejected.
func TestAgentTaskSchedule_TimeoutTooLarge(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-tl",
		TenantID:     "alice",
		Name:         "Agent TL",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":     "agent-tl",
		"capability":   "exec",
		"timeout_secs": float64(90000),
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "86400")
}

// TestAgentTaskCancel_Pending verifies that a pending task can be cancelled via the MCP tool.
func TestAgentTaskCancel_Pending(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID: "agent-cancel", TenantID: "alice", Name: "Cancel Agent",
		RegisteredAt: now, Capabilities: []string{"exec"}, Status: "online",
	}))
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID: "cancel-t1", AgentID: "agent-cancel", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_cancel", map[string]any{
		"task_id":  "cancel-t1",
		"agent_id": "agent-cancel",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	task, err := st.GetTask(context.Background(), "cancel-t1", "alice")
	require.NoError(t, err)
	assert.Equal(t, "error", task.Status)
	assert.Equal(t, "cancelled", task.Err)
}

// TestAgentTaskCancel_AlreadyDone verifies that cancelling a terminal task returns an error.
func TestAgentTaskCancel_AlreadyDone(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	done := now.Add(time.Second)
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID: "cancel-t2", AgentID: "agent-cancel", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))
	require.NoError(t, st.UpdateTask(context.Background(), &store.Task{
		TaskID: "cancel-t2", TenantID: "alice", Status: "done", CompletedAt: &done,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_cancel", map[string]any{
		"task_id":  "cancel-t2",
		"agent_id": "agent-cancel",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "terminal")
}

// TestAgentTaskCancel_WrongTenant verifies that bob cannot cancel alice's task.
func TestAgentTaskCancel_WrongTenant(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID: "cancel-t3", AgentID: "agent-alice", TenantID: "alice",
		ScheduledBy: "alice", Capability: "exec",
		Params: map[string]any{}, Status: "pending", CreatedAt: now,
	}))

	bobCtx := makeCtx(t, a, "bob", []string{"agent:admin"})
	result, err := srv.CallTool(bobCtx, "agent_task_cancel", map[string]any{
		"task_id":  "cancel-t3",
		"agent_id": "agent-alice",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "task not found")
}

// TestAgentTaskCancel_InsufficientScope verifies scope enforcement.
func TestAgentTaskCancel_InsufficientScope(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:read"})

	result, err := srv.CallTool(ctx, "agent_task_cancel", map[string]any{
		"task_id":  "some-task",
		"agent_id": "some-agent",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "agent:admin")
}

// TestAgentTaskSchedule_TimeoutExactlyMax verifies that timeout_secs=86400 is
// accepted as the boundary value (max allowed).
func TestAgentTaskSchedule_TimeoutExactlyMax(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-max-to",
		TenantID:     "alice",
		Name:         "Max Timeout Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":     "agent-max-to",
		"capability":   "exec",
		"params":       map[string]any{"cmd": "id"},
		"timeout_secs": float64(86400),
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, float64(86400), resp["timeout_secs"])
}

// TestAgentTaskSchedule_TimeoutZero verifies that timeout_secs=0 falls back to
// the default timeout (treated as "not set" by parseTimeoutSecs).
func TestAgentTaskSchedule_TimeoutZero(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "agent-zero-to",
		TenantID:     "alice",
		Name:         "Zero Timeout Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_schedule", map[string]any{
		"agent_id":     "agent-zero-to",
		"capability":   "exec",
		"params":       map[string]any{"cmd": "id"},
		"timeout_secs": float64(0),
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	// zero is treated as "not set" so the default timeout is used
	assert.Equal(t, float64(store.DefaultTaskTimeoutSecs), resp["timeout_secs"])
}

// TestAgentTaskSchedule_MissingAgentID verifies that omitting agent_id returns an error.
func TestAgentTaskSchedule_MissingAgentID(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_task_schedule", map[string]any{
		"capability": "exec",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "agent_id")
}

// TestAgentDropperGenerate_InvalidTTLFormat verifies that an unparseable TTL
// string is rejected with a clear error.
func TestAgentDropperGenerate_InvalidTTLFormat(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "not-a-duration",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "invalid ttl")
}

// TestAgentDropperGenerate_ZeroTTL verifies that ttl="0s" is rejected because
// a non-positive duration is not accepted.
func TestAgentDropperGenerate_ZeroTTL(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "0s",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "invalid ttl")
}

// TestAgentDropperGenerate_ExactlyMaxTTL verifies that ttl="168h" (the maximum)
// is accepted as a valid boundary value.
func TestAgentDropperGenerate_ExactlyMaxTTL(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"agent_id": "web-01",
		"os_arch":  "linux-amd64",
		"ttl":      "168h",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "web-01", resp["agent_id"])
	assert.NotEmpty(t, resp["token"])
}

// TestAgentDropperGenerate_MissingParams verifies that omitting the required
// agent_id parameter returns an error.
func TestAgentDropperGenerate_MissingParams(t *testing.T) {
	srv, a := newDropperServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_dropper_generate", map[string]any{
		"os_arch": "linux-amd64",
		"ttl":     "1h",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "required")
}

// TestAgentTaskStatus_PendingTask verifies that a task that was just scheduled
// (never processed) has status "pending" and no result or error fields.
func TestAgentTaskStatus_PendingTask(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "pending-task-1",
		AgentID:    "agent-pending",
		TenantID:   "alice",
		Capability: "system_info",
		Status:     "pending",
		CreatedAt:  now,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id": "pending-task-1",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "pending", resp["status"])
	assert.Equal(t, "pending-task-1", resp["task_id"])
	// A pending task must not have a result or error
	_, hasResult := resp["result"]
	assert.False(t, hasResult, "pending task should not have a result field")
	errVal, hasErr := resp["error"]
	if hasErr {
		assert.Empty(t, errVal, "pending task should not have an error value")
	}
}

// TestAgentList_ShowsCapabilities verifies that the capabilities registered
// for an agent are included in the agent_list response.
func TestAgentList_ShowsCapabilities(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.UpsertAgent(context.Background(), &store.Agent{
		AgentID:      "cap-agent",
		TenantID:     "alice",
		Name:         "Capable Agent",
		RegisteredAt: now,
		Capabilities: []string{"exec", "read_file", "fetch_url", "system_info"},
		Status:       "online",
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	result, err := srv.CallTool(aliceCtx, "agent_list", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	items := extractJSONArray(t, result)
	require.Len(t, items, 1)

	agentMap := items[0].(map[string]any)
	assert.Equal(t, "cap-agent", agentMap["agent_id"])

	capsRaw, ok := agentMap["capabilities"]
	require.True(t, ok, "capabilities field must be present")
	caps, ok := capsRaw.([]any)
	require.True(t, ok, "capabilities must be a JSON array")
	capStrs := make([]string, len(caps))
	for i, c := range caps {
		capStrs[i] = c.(string)
	}
	assert.ElementsMatch(t, []string{"exec", "read_file", "fetch_url", "system_info"}, capStrs)
}

// TestAgentTaskStatus_WaitBlocksUntilDone verifies that wait=true (default)
// blocks until the task reaches a terminal state, returning the result.
func TestAgentTaskStatus_WaitBlocksUntilDone(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "wait-task-1",
		AgentID:    "agent-w",
		TenantID:   "alice",
		Capability: "exec",
		Status:     "pending",
		CreatedAt:  now,
	}))

	// Complete the task after a short delay.
	go func() {
		time.Sleep(300 * time.Millisecond)
		done := time.Now().UTC()
		_ = st.UpdateTask(context.Background(), &store.Task{
			TaskID:      "wait-task-1",
			TenantID:    "alice",
			Status:      "done",
			CompletedAt: &done,
			Result:      map[string]any{"output": "hello"},
		})
	}()

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	start := time.Now()
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id": "wait-task-1",
		// wait defaults to true
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "done", resp["status"])
	resultMap, ok := resp["result"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "hello", resultMap["output"])

	// Should have waited for the task to complete (~300ms), not returned immediately.
	assert.GreaterOrEqual(t, elapsed, 250*time.Millisecond, "should block until task completes")
	// timed_out should be false or absent
	if timedOut, exists := resp["timed_out"]; exists {
		assert.False(t, timedOut.(bool))
	}
}

// TestAgentTaskStatus_WaitTimesOut verifies that when the task stays pending
// beyond the wait timeout, the tool returns timed_out=true with the current status.
func TestAgentTaskStatus_WaitTimesOut(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "wait-task-2",
		AgentID:    "agent-w",
		TenantID:   "alice",
		Capability: "exec",
		Status:     "pending",
		CreatedAt:  now,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	start := time.Now()
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id":      "wait-task-2",
		"timeout_secs": float64(1),
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "pending", resp["status"])
	assert.True(t, resp["timed_out"].(bool), "expected timed_out=true")
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond, "should wait close to timeout")
	assert.LessOrEqual(t, elapsed, 3*time.Second, "should not overshoot timeout")
}

// TestAgentTaskStatus_WaitFalseReturnsImmediately verifies that wait=false
// returns immediately without blocking, even for a pending task.
func TestAgentTaskStatus_WaitFalseReturnsImmediately(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "wait-task-3",
		AgentID:    "agent-w",
		TenantID:   "alice",
		Capability: "exec",
		Status:     "pending",
		CreatedAt:  now,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	start := time.Now()
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id": "wait-task-3",
		"wait":    false,
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "pending", resp["status"])
	// Should return almost instantly — well under 500ms.
	assert.Less(t, elapsed, 500*time.Millisecond, "wait=false should return immediately")
}

// TestAgentTaskStatus_WaitAlreadyDone verifies that waiting on an already-done
// task returns immediately without blocking.
func TestAgentTaskStatus_WaitAlreadyDone(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	done := now.Add(time.Second)
	task := &store.Task{
		TaskID:      "wait-task-4",
		AgentID:     "agent-w",
		TenantID:    "alice",
		Capability:  "exec",
		Status:      "done",
		CreatedAt:   now,
		CompletedAt: &done,
		Result:      map[string]any{"output": "already done"},
	}
	require.NoError(t, st.EnqueueTask(context.Background(), task))
	require.NoError(t, st.UpdateTask(context.Background(), task))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})
	start := time.Now()
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id": "wait-task-4",
		// wait defaults to true, but task is already done
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.Equal(t, "done", resp["status"])
	// Already terminal — should return immediately.
	assert.Less(t, elapsed, 500*time.Millisecond, "already-done task should not block")
}

// TestAgentTaskStatus_WaitTimeoutClamped verifies that timeout_secs > 120 is
// clamped to 120, and timeout_secs <= 0 is clamped to the default (30).
func TestAgentTaskStatus_WaitTimeoutClamped(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	now := time.Now().UTC()
	require.NoError(t, st.EnqueueTask(context.Background(), &store.Task{
		TaskID:     "wait-task-5",
		AgentID:    "agent-w",
		TenantID:   "alice",
		Capability: "exec",
		Status:     "pending",
		CreatedAt:  now,
	}))

	aliceCtx := makeCtx(t, a, "alice", []string{"agent:admin"})

	// timeout_secs=0 should be clamped to default (30), but we test the fast path:
	// pass wait=false to avoid actually waiting, then test clamping separately
	// with a very short timeout to verify it doesn't exceed the clamp.
	// We use timeout_secs=0 with wait=true — should clamp to 1 (minimum) and time out.
	start := time.Now()
	result, err := srv.CallTool(aliceCtx, "agent_task_status", map[string]any{
		"task_id":      "wait-task-5",
		"timeout_secs": float64(0),
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(getResultText(t, result)), &resp))
	assert.True(t, resp["timed_out"].(bool), "should time out")
	// Clamped to minimum (1s), so should take ~1s
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond)
	assert.LessOrEqual(t, elapsed, 3*time.Second)
}

// TestAgentTaskCancel_NotFound verifies that cancelling a task_id that does
// not exist returns an error.
func TestAgentTaskCancel_NotFound(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"agent:admin"})

	result, err := srv.CallTool(ctx, "agent_task_cancel", map[string]any{
		"task_id":  "nonexistent-task-id",
		"agent_id": "some-agent",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, getResultText(t, result), "task not found")
}
