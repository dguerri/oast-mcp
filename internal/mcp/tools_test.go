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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	mcpsrv "github.com/dguerri/oast-mcp/internal/mcp"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
)

func newTestServer(t *testing.T) (*mcpsrv.Server, *auth.Auth, store.Store, *oast.Mock) {
	t.Helper()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	mock := oast.NewMock(st, "oast.example.com")
	rl := ratelimit.New(100, 100)
	al := audit.New(io.Discard)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := mcpsrv.NewServer(a, st, mock, rl, al, logger, "oast.example.com", "mcp.example.com", "agent.example.com", t.TempDir())
	return srv, a, st, mock
}

// newTestServerWithAuditBuf is like newTestServer but writes audit events to
// the returned buffer so tests can inspect them.
func newTestServerWithAuditBuf(t *testing.T) (*mcpsrv.Server, *auth.Auth, store.Store, *oast.Mock, *bytes.Buffer) {
	t.Helper()
	key := make([]byte, 32)
	a := auth.New(key)
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	mock := oast.NewMock(st, "oast.example.com")
	rl := ratelimit.New(100, 100)
	var buf bytes.Buffer
	al := audit.New(&buf)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := mcpsrv.NewServer(a, st, mock, rl, al, logger, "oast.example.com", "mcp.example.com", "agent.example.com", t.TempDir())
	return srv, a, st, mock, &buf
}

// makeCtx creates a context with the given claims injected directly using
// the exported ContextWithClaims helper so the server can find them.
func makeCtx(t *testing.T, a *auth.Auth, subject string, scopes []string) context.Context {
	t.Helper()
	token, err := a.Issue(subject, scopes, time.Hour)
	require.NoError(t, err)
	claims, err := a.Validate(token)
	require.NoError(t, err)
	return mcpsrv.ContextWithClaims(context.Background(), claims)
}

// makeCtxWithRequestInfo creates a context with both claims and client network
// info, simulating a request that came through the HTTP middleware.
func makeCtxWithRequestInfo(t *testing.T, a *auth.Auth, subject string, scopes []string, remoteAddr, xForwardedFor string) context.Context {
	t.Helper()
	ctx := makeCtx(t, a, subject, scopes)
	return mcpsrv.ContextWithRequestInfo(ctx, remoteAddr, xForwardedFor)
}

// parseAuditLines parses newline-delimited JSON audit events from a buffer.
func parseAuditLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &ev))
		events = append(events, ev)
	}
	return events
}

// TestCreateSession_ReturnsEndpoints verifies that creating a session returns
// a session_id, endpoints with DNS/HTTP/HTTPS URLs, and timing fields.
func TestCreateSession_ReturnsEndpoints(t *testing.T) {
	srv, a, _, _ := newTestServer(t)

	aliceCtx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	result, err := srv.CallTool(aliceCtx, "oast_create_session", map[string]any{
		"ttl_seconds": float64(3600),
		"tags":        []any{"test", "milestone7"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, "expected success, got error: %v", getResultText(t, result))

	text := getResultText(t, result)
	require.NotEmpty(t, text)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.NotEmpty(t, resp["session_id"], "session_id should be present")
	endpoints, ok := resp["endpoints"].(map[string]any)
	require.True(t, ok, "endpoints should be an object")
	assert.NotEmpty(t, endpoints["dns"], "dns endpoint should be present")
	assert.NotEmpty(t, endpoints["http"], "http endpoint should be present")
	assert.NotEmpty(t, endpoints["https"], "https endpoint should be present")
	assert.NotEmpty(t, resp["created_at"], "created_at should be present")
	assert.NotEmpty(t, resp["expires_at"], "expires_at should be present")
}

// TestListSessions_TenantIsolation verifies that alice sees only her sessions
// and bob sees only his sessions.
func TestListSessions_TenantIsolation(t *testing.T) {
	srv, a, _, _ := newTestServer(t)

	aliceCtx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})
	bobCtx := makeCtx(t, a, "bob", []string{"oast:write", "oast:read"})

	// Alice creates 2 sessions
	for i := 0; i < 2; i++ {
		result, err := srv.CallTool(aliceCtx, "oast_create_session", nil)
		require.NoError(t, err)
		require.False(t, result.IsError, "alice create session %d failed: %s", i, getResultText(t, result))
	}

	// Bob creates 1 session
	result, err := srv.CallTool(bobCtx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, "bob create session failed: %s", getResultText(t, result))

	// List alice's sessions
	aliceListResult, err := srv.CallTool(aliceCtx, "oast_list_sessions", nil)
	require.NoError(t, err)
	require.False(t, aliceListResult.IsError, "alice list failed: %s", getResultText(t, aliceListResult))

	aliceSessions := extractJSONArray(t, aliceListResult)
	assert.Len(t, aliceSessions, 2, "alice should see exactly 2 sessions")

	// List bob's sessions
	bobListResult, err := srv.CallTool(bobCtx, "oast_list_sessions", nil)
	require.NoError(t, err)
	require.False(t, bobListResult.IsError, "bob list failed: %s", getResultText(t, bobListResult))

	bobSessions := extractJSONArray(t, bobListResult)
	assert.Len(t, bobSessions, 1, "bob should see exactly 1 session")
}

// TestPollEvents_ReturnsEvents verifies that events injected via the mock
// are returned when polling.
func TestPollEvents_ReturnsEvents(t *testing.T) {
	srv, a, st, mock := newTestServer(t)

	aliceCtx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	// Create a session
	createResult, err := srv.CallTool(aliceCtx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, createResult.IsError, "create failed: %s", getResultText(t, createResult))

	sessionID := extractField(t, createResult, "session_id")

	// Get the session from store to find the correlationID
	sess, err := st.GetSession(context.Background(), sessionID, "alice")
	require.NoError(t, err)

	// Inject an event via the mock
	ev := &store.Event{
		EventID:    "test-event-1",
		SessionID:  sessionID,
		TenantID:   "alice",
		ReceivedAt: time.Now().UTC(),
		Protocol:   "dns",
		SrcIP:      "1.2.3.4",
		Data: map[string]any{
			"query": sess.CorrelationID + ".oast.example.com",
		},
	}
	require.NoError(t, mock.InjectEvent(context.Background(), ev))

	// Poll events
	pollResult, err := srv.CallTool(aliceCtx, "oast_list_events", map[string]any{
		"session_id": sessionID,
	})
	require.NoError(t, err)
	require.False(t, pollResult.IsError, "poll should succeed: %s", getResultText(t, pollResult))

	text := getResultText(t, pollResult)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	events, ok := resp["events"].([]any)
	require.True(t, ok, "events should be an array")
	assert.Len(t, events, 1, "should have 1 event")

	firstEvent, ok := events[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "dns", firstEvent["protocol"])
	assert.Equal(t, "1.2.3.4", firstEvent["src_ip"])
}

// TestPollEvents_WrongTenant verifies that a different tenant cannot poll
// another tenant's session.
func TestPollEvents_WrongTenant(t *testing.T) {
	srv, a, _, _ := newTestServer(t)

	aliceCtx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})
	bobCtx := makeCtx(t, a, "bob", []string{"oast:write", "oast:read"})

	// Alice creates a session
	createResult, err := srv.CallTool(aliceCtx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, createResult.IsError)

	sessionID := extractField(t, createResult, "session_id")

	// Bob tries to poll Alice's session
	pollResult, err := srv.CallTool(bobCtx, "oast_list_events", map[string]any{
		"session_id": sessionID,
	})
	require.NoError(t, err)
	require.True(t, pollResult.IsError, "bob should not be able to poll alice's session")

	errText := getResultText(t, pollResult)
	assert.Contains(t, errText, "session not found")
}

// TestCloseSession_WrongTenant verifies that a different tenant cannot close
// another tenant's session.
func TestCloseSession_WrongTenant(t *testing.T) {
	srv, a, _, _ := newTestServer(t)

	aliceCtx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})
	bobCtx := makeCtx(t, a, "bob", []string{"oast:write", "oast:read"})

	// Alice creates a session
	createResult, err := srv.CallTool(aliceCtx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, createResult.IsError)

	sessionID := extractField(t, createResult, "session_id")

	// Bob tries to close Alice's session
	closeResult, err := srv.CallTool(bobCtx, "oast_close_session", map[string]any{
		"session_id": sessionID,
	})
	require.NoError(t, err)
	require.True(t, closeResult.IsError, "bob should not be able to close alice's session")

	errText := getResultText(t, closeResult)
	assert.Contains(t, errText, "session not found")
}

// TestWaitForEvent_TimesOut verifies the tool returns timed_out=true when no
// event arrives before the deadline.
func TestWaitForEvent_TimesOut(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	start := time.Now()
	waitResult, err := srv.CallTool(ctx, "oast_wait_for_event", map[string]any{
		"session_id":      sessionID,
		"timeout_seconds": float64(1),
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.False(t, waitResult.IsError)

	text := getResultText(t, waitResult)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.True(t, resp["timed_out"].(bool), "expected timed_out=true")
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond, "should wait close to the timeout")
	assert.LessOrEqual(t, elapsed, 2*time.Second, "should not wait more than 2× the timeout")
}

// TestWaitForEvent_ReturnsEvent verifies the tool wakes up and returns as soon
// as an event is injected, without waiting for the full timeout.
func TestWaitForEvent_ReturnsEvent(t *testing.T) {
	srv, a, st, mock := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	// Fetch the session before launching the goroutine so require.NoError is safe.
	sess, err := st.GetSession(context.Background(), sessionID, "alice")
	require.NoError(t, err)

	// Inject an event after a short delay so the tool has to actually poll.
	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := mock.InjectEvent(context.Background(), &store.Event{
			EventID:    "wait-ev-1",
			SessionID:  sessionID,
			TenantID:   "alice",
			ReceivedAt: time.Now().UTC(),
			Protocol:   "http",
			SrcIP:      "5.6.7.8",
			Data:       map[string]any{"path": "/" + sess.CorrelationID},
		}); err != nil {
			t.Errorf("InjectEvent failed: %v", err)
		}
	}()

	waitResult, err := srv.CallTool(ctx, "oast_wait_for_event", map[string]any{
		"session_id":      sessionID,
		"timeout_seconds": float64(5),
	})
	require.NoError(t, err)
	require.False(t, waitResult.IsError)

	text := getResultText(t, waitResult)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.False(t, resp["timed_out"].(bool), "expected timed_out=false")
	events, ok := resp["events"].([]any)
	require.True(t, ok)
	assert.Len(t, events, 1)
	first := events[0].(map[string]any)
	assert.Equal(t, "http", first["protocol"])
	assert.Equal(t, "5.6.7.8", first["src_ip"])

	// Verify the session cursor was persisted after the wait returned events.
	updatedSess, err := st.GetSession(context.Background(), sessionID, "alice")
	require.NoError(t, err)
	nextCursorFromResp, _ := resp["next_cursor"].(string)
	assert.Equal(t, nextCursorFromResp, updatedSess.Cursor, "session cursor should be persisted after wait returns events")
}

// TestGeneratePayload_URL verifies basic URL-type payload generation.
func TestGeneratePayload_URL(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	genResult, err := srv.CallTool(ctx, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "url",
	})
	require.NoError(t, err)
	require.False(t, genResult.IsError, getResultText(t, genResult))

	text := getResultText(t, genResult)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	dnsHostname, ok := resp["dns_hostname"].(string)
	require.True(t, ok, "dns_hostname should be a string")
	assert.Contains(t, dnsHostname, "oast.example.com")

	httpURL, ok := resp["http_url"].(string)
	require.True(t, ok, "http_url should be a string")
	assert.Contains(t, httpURL, "http://")

	httpsURL, ok := resp["https_url"].(string)
	require.True(t, ok, "https_url should be a string")
	assert.Contains(t, httpsURL, "https://")

	payload, ok := resp["payload"].(string)
	require.True(t, ok, "payload should be a string")
	assert.Equal(t, httpsURL, payload, "payload should equal https_url for type=url")
}

// TestGeneratePayload_Label_InSubdomain verifies the label appears in the callback URLs.
func TestGeneratePayload_Label_InSubdomain(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	genResult, err := srv.CallTool(ctx, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "url",
		"label":      "login-form",
	})
	require.NoError(t, err)
	require.False(t, genResult.IsError, getResultText(t, genResult))

	text := getResultText(t, genResult)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	dnsHostname, ok := resp["dns_hostname"].(string)
	require.True(t, ok, "dns_hostname should be a string")
	assert.Contains(t, dnsHostname, "login-form")

	httpURL, ok := resp["http_url"].(string)
	require.True(t, ok, "http_url should be a string")
	assert.Contains(t, httpURL, "login-form")

	httpsURL, ok := resp["https_url"].(string)
	require.True(t, ok, "https_url should be a string")
	assert.Contains(t, httpsURL, "login-form")
}

// TestGeneratePayload_Log4j verifies the Log4Shell JNDI payload format.
func TestGeneratePayload_Log4j(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	genResult, err := srv.CallTool(ctx, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "log4j",
	})
	require.NoError(t, err)
	require.False(t, genResult.IsError, getResultText(t, genResult))

	payload := extractField(t, genResult, "payload")
	assert.Contains(t, payload, "${jndi:ldap://")
	assert.Contains(t, payload, "oast.example.com")
}

// TestGeneratePayload_UnknownType verifies an error is returned for unknown types.
func TestGeneratePayload_UnknownType(t *testing.T) {
	srv, a, _, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	genResult, err := srv.CallTool(ctx, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "totally-unknown",
	})
	require.NoError(t, err)
	assert.True(t, genResult.IsError)
	assert.Contains(t, getResultText(t, genResult), "unknown payload type")
}

// TestExpiredSession_ListEvents verifies that oast_list_events returns
// "session expired" for a session whose ExpiresAt is in the past.
func TestExpiredSession_ListEvents(t *testing.T) {
	srv, a, st, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	sessID := insertExpiredSession(t, st, "alice")

	result, err := srv.CallTool(ctx, "oast_list_events", map[string]any{
		"session_id": sessID,
	})
	require.NoError(t, err)
	require.True(t, result.IsError, "expected error for expired session")
	assert.Contains(t, getResultText(t, result), "session expired")
}

// TestExpiredSession_WaitForEvent verifies that oast_wait_for_event returns
// "session expired" immediately rather than polling until timeout.
func TestExpiredSession_WaitForEvent(t *testing.T) {
	srv, a, st, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	sessID := insertExpiredSession(t, st, "alice")

	start := time.Now()
	result, err := srv.CallTool(ctx, "oast_wait_for_event", map[string]any{
		"session_id":      sessID,
		"timeout_seconds": float64(10),
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.True(t, result.IsError, "expected error for expired session")
	assert.Contains(t, getResultText(t, result), "session expired")
	// Should fail fast, not wait the full 10 s.
	assert.Less(t, elapsed, 2*time.Second, "should fail fast, not poll until timeout")
}

// TestExpiredSession_GeneratePayload verifies that oast_generate_payload
// returns "session expired" for a session whose ExpiresAt is in the past.
func TestExpiredSession_GeneratePayload(t *testing.T) {
	srv, a, st, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	sessID := insertExpiredSession(t, st, "alice")

	result, err := srv.CallTool(ctx, "oast_generate_payload", map[string]any{
		"session_id": sessID,
		"type":       "url",
	})
	require.NoError(t, err)
	require.True(t, result.IsError, "expected error for expired session")
	assert.Contains(t, getResultText(t, result), "session expired")
}

// TestExpiredSession_CloseSession verifies that oast_close_session still
// succeeds on an expired (but not yet purged) session, so clients can clean up.
func TestExpiredSession_CloseSession(t *testing.T) {
	srv, a, st, _ := newTestServer(t)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	sessID := insertExpiredSession(t, st, "alice")

	result, err := srv.CallTool(ctx, "oast_close_session", map[string]any{
		"session_id": sessID,
	})
	require.NoError(t, err)
	require.False(t, result.IsError, "close should succeed on an expired session: %s", getResultText(t, result))
}

// TestRevokedToken_Rejected verifies that a valid but revoked JWT is rejected
// by the HTTP middleware with HTTP 401.
func TestRevokedToken_Rejected(t *testing.T) {
	srv, a, st, _ := newTestServer(t)

	// Issue a token for alice.
	token, err := a.Issue("alice", []string{"oast:read", "oast:write"}, time.Hour)
	require.NoError(t, err)

	// Extract claims to get the JTI and ExpiresAt.
	claims, err := a.Validate(token)
	require.NoError(t, err)

	// Revoke the token.
	require.NoError(t, st.RevokeToken(context.Background(), claims.JTI, claims.ExpiresAt))

	// Make an HTTP GET to /sse with the revoked token.
	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "revoked token should be rejected with 401")
}

// insertExpiredSession creates a session directly in the store with ExpiresAt
// one hour in the past and returns its session_id.  This bypasses the MCP
// layer so we can set an arbitrary expiry without waiting.
func insertExpiredSession(t *testing.T, st store.Store, tenantID string) string {
	t.Helper()
	now := time.Now().UTC()
	sessID := "expired-session-" + tenantID
	err := st.CreateSession(context.Background(), &store.Session{
		SessionID:     sessID,
		TenantID:      tenantID,
		CorrelationID: "deadbeef",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour), // expired 1 hour ago
		Tags:          nil,
	})
	require.NoError(t, err)
	return sessID
}

// ── Audit logging tests ───────────────────────────────────────────────────────

// TestAuditEvent_IncludesRemoteAddr verifies that audit events emitted by MCP
// tools include remote_addr and x_forwarded_for when requestInfo is in context.
func TestAuditEvent_IncludesRemoteAddr(t *testing.T) {
	srv, a, _, _, buf := newTestServerWithAuditBuf(t)
	ctx := makeCtxWithRequestInfo(t, a, "alice", []string{"oast:write", "oast:read"},
		"10.0.0.1:12345", "203.0.113.42")

	result, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	events := parseAuditLines(t, buf)
	require.NotEmpty(t, events, "should have at least one audit event")

	// Find the session.create/ok event
	var found bool
	for _, ev := range events {
		if ev["action"] == "session.create" && ev["outcome"] == "ok" {
			assert.Equal(t, "10.0.0.1:12345", ev["remote_addr"])
			assert.Equal(t, "203.0.113.42", ev["x_forwarded_for"])
			assert.Equal(t, "alice", ev["tenant_id"])
			found = true
			break
		}
	}
	assert.True(t, found, "session.create/ok audit event not found")
}

// TestAuditEvent_DeniedIncludesRemoteAddr verifies that denied audit events
// also include remote_addr and x_forwarded_for.
func TestAuditEvent_DeniedIncludesRemoteAddr(t *testing.T) {
	srv, a, _, _, buf := newTestServerWithAuditBuf(t)
	// Use oast:read scope only — session.create requires oast:write
	ctx := makeCtxWithRequestInfo(t, a, "alice", []string{"oast:read"},
		"192.168.1.100:9999", "198.51.100.5")

	result, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	require.True(t, result.IsError, "should be denied without oast:write scope")

	events := parseAuditLines(t, buf)
	require.NotEmpty(t, events)

	var found bool
	for _, ev := range events {
		if ev["action"] == "session.create" && ev["outcome"] == "denied" {
			assert.Equal(t, "192.168.1.100:9999", ev["remote_addr"])
			assert.Equal(t, "198.51.100.5", ev["x_forwarded_for"])
			found = true
			break
		}
	}
	assert.True(t, found, "session.create/denied audit event not found")
}

// TestAuditEvent_EmptyWithoutRequestInfo verifies that audit events have empty
// remote_addr and x_forwarded_for when no requestInfo is in context.
func TestAuditEvent_EmptyWithoutRequestInfo(t *testing.T) {
	srv, a, _, _, buf := newTestServerWithAuditBuf(t)
	// Use makeCtx (no requestInfo)
	ctx := makeCtx(t, a, "alice", []string{"oast:write", "oast:read"})

	result, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	events := parseAuditLines(t, buf)
	require.NotEmpty(t, events)

	for _, ev := range events {
		if ev["action"] == "session.create" && ev["outcome"] == "ok" {
			// remote_addr and x_forwarded_for should be omitted (omitempty)
			assert.Nil(t, ev["remote_addr"], "remote_addr should be omitted when empty")
			assert.Nil(t, ev["x_forwarded_for"], "x_forwarded_for should be omitted when empty")
			return
		}
	}
	t.Fatal("session.create/ok audit event not found")
}

// TestAuditEvent_AgentToolIncludesRemoteAddr verifies that agent tools also
// include remote_addr in audit events.
func TestAuditEvent_AgentToolIncludesRemoteAddr(t *testing.T) {
	srv, a, _, _, buf := newTestServerWithAuditBuf(t)
	ctx := makeCtxWithRequestInfo(t, a, "alice", []string{"agent:admin"},
		"172.16.0.5:54321", "10.10.10.1, 203.0.113.99")

	result, err := srv.CallTool(ctx, "agent_list", nil)
	require.NoError(t, err)
	require.False(t, result.IsError, getResultText(t, result))

	events := parseAuditLines(t, buf)
	require.NotEmpty(t, events)

	var found bool
	for _, ev := range events {
		if ev["action"] == "agent.list" && ev["outcome"] == "ok" {
			assert.Equal(t, "172.16.0.5:54321", ev["remote_addr"])
			assert.Equal(t, "10.10.10.1, 203.0.113.99", ev["x_forwarded_for"])
			found = true
			break
		}
	}
	assert.True(t, found, "agent.list/ok audit event not found")
}

// TestAuditEvent_WaitForEventIncludesRemoteAddr verifies that the deferred
// audit event in oast_wait_for_event also includes request info.
func TestAuditEvent_WaitForEventIncludesRemoteAddr(t *testing.T) {
	srv, a, _, _, buf := newTestServerWithAuditBuf(t)
	ctx := makeCtxWithRequestInfo(t, a, "alice", []string{"oast:write", "oast:read"},
		"10.0.0.2:8080", "203.0.113.50")

	createResult, err := srv.CallTool(ctx, "oast_create_session", nil)
	require.NoError(t, err)
	sessionID := extractField(t, createResult, "session_id")

	// Clear buffer so we only see wait events
	buf.Reset()

	_, err = srv.CallTool(ctx, "oast_wait_for_event", map[string]any{
		"session_id":      sessionID,
		"timeout_seconds": float64(1),
	})
	require.NoError(t, err)

	events := parseAuditLines(t, buf)
	require.NotEmpty(t, events)

	var found bool
	for _, ev := range events {
		if ev["action"] == "session.wait" {
			assert.Equal(t, "10.0.0.2:8080", ev["remote_addr"])
			assert.Equal(t, "203.0.113.50", ev["x_forwarded_for"])
			assert.Equal(t, sessionID, ev["resource"])
			found = true
			break
		}
	}
	assert.True(t, found, "session.wait audit event not found")
}

// --- helpers ---

// getResultText marshals the CallToolResult and extracts the text field.
func getResultText(t *testing.T, result any) string {
	t.Helper()
	b, err := json.Marshal(result)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))

	content, ok := m["content"].([]any)
	if !ok || len(content) == 0 {
		return ""
	}

	first, ok := content[0].(map[string]any)
	if !ok {
		return ""
	}

	text, _ := first["text"].(string)
	return text
}

// extractJSONArray extracts the JSON array from a tool result's text content.
func extractJSONArray(t *testing.T, result any) []any {
	t.Helper()
	text := getResultText(t, result)
	require.NotEmpty(t, text, "result text should not be empty")

	var arr []any
	require.NoError(t, json.Unmarshal([]byte(text), &arr))
	return arr
}

// extractField extracts a string field from a JSON object in the tool result.
func extractField(t *testing.T, result any, field string) string {
	t.Helper()
	text := getResultText(t, result)
	require.NotEmpty(t, text, "result text should not be empty")

	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &obj))

	val, ok := obj[field].(string)
	require.True(t, ok, "field %q should be a string, got: %v", field, obj[field])
	return val
}
