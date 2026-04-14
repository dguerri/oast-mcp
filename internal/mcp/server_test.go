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

// Package mcp — internal tests for server.go (Handler middleware and scanLoaderTargets).
// Uses package mcp (not mcp_test) so that the unexported scanLoaderTargets function
// is accessible.
package mcp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHandlerTestServer builds a minimal Server for HTTP-handler tests.
func newHandlerTestServer(t *testing.T) (*Server, *auth.Auth, store.Store) {
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
	srv := NewServer(a, st, mock, rl, al, logger, "oast.example.com", "mcp.example.com", "agent.example.com", t.TempDir())
	return srv, a, st
}

// ── Handler middleware tests ──────────────────────────────────────────────────

// TestHandler_MissingAuthHeader verifies that a request with no Authorization
// header is rejected with HTTP 401.
func TestHandler_MissingAuthHeader(t *testing.T) {
	srv, _, _ := newHandlerTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "missing Authorization header")
}

// TestHandler_InvalidToken verifies that a request with a garbage token is
// rejected with HTTP 401.
func TestHandler_InvalidToken(t *testing.T) {
	srv, _, _ := newHandlerTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-valid-jwt")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
}

// TestHandler_RevokedToken verifies that a validly-signed but revoked JWT is
// rejected with HTTP 401.
func TestHandler_RevokedToken(t *testing.T) {
	srv, a, st := newHandlerTestServer(t)

	token, err := a.Issue("alice", []string{"oast:read", "oast:write"}, time.Hour)
	require.NoError(t, err)

	claims, err := a.Validate(token)
	require.NoError(t, err)

	require.NoError(t, st.RevokeToken(context.Background(), claims.JTI, claims.ExpiresAt))

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
}

// TestHandler_ValidToken_SSE verifies that a request with a valid, non-revoked JWT
// is forwarded to the underlying SSE handler at /sse (i.e., does not return 401).
// Because the SSE handler keeps the connection open indefinitely, we cancel
// the request context after a short delay and inspect what was written so far.
func TestHandler_ValidToken_SSE(t *testing.T) {
	srv, a, _ := newHandlerTestServer(t)

	token, err := a.Issue("alice", []string{"oast:read", "oast:write"}, time.Hour)
	require.NoError(t, err)

	// Use a context that we cancel quickly so the SSE goroutine exits.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/sse", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// ServeHTTP blocks until the context is cancelled; that's expected.
	srv.Handler().ServeHTTP(w, req)

	// The auth middleware must NOT have written a 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"valid token should not be rejected; got status %d body: %s", w.Code, w.Body.String())
}

// TestHandler_ValidToken_StreamableHTTP verifies that a valid JWT reaches the
// Streamable HTTP handler at /mcp without being rejected by the auth middleware.
func TestHandler_ValidToken_StreamableHTTP(t *testing.T) {
	srv, a, _ := newHandlerTestServer(t)

	token, err := a.Issue("alice", []string{"oast:read", "oast:write"}, time.Hour)
	require.NoError(t, err)

	// POST an MCP initialize request to /mcp.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	// The auth middleware must NOT have written a 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"valid token should not be rejected at /mcp; got status %d body: %s", w.Code, w.Body.String())
}

// ── scanLoaderTargets tests ───────────────────────────────────────────────────

// TestScanLoaderTargets_Empty verifies that an empty directory returns nil/empty.
func TestScanLoaderTargets_Empty(t *testing.T) {
	dir := t.TempDir()
	result := scanLoaderTargets(dir)
	assert.Empty(t, result)
}

// TestScanLoaderTargets_LoaderFiles verifies that files named loader-<os>-<arch>
// are detected and their os-arch suffix is returned.
func TestScanLoaderTargets_LoaderFiles(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"loader-linux-amd64", "loader-darwin-arm64"} {
		f, err := os.Create(filepath.Join(dir, name))
		require.NoError(t, err)
		_ = f.Close()
	}

	result := scanLoaderTargets(dir)
	sort.Strings(result)

	assert.Equal(t, []string{"darwin-arm64", "linux-amd64"}, result)
}

// TestScanLoaderTargets_IgnoresNonLoaderFiles verifies that files whose names
// do not start with "loader-" are not included in the result.
func TestScanLoaderTargets_IgnoresNonLoaderFiles(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"agent-linux-amd64", "README.md", "config.yaml", "notloader-linux-amd64"} {
		f, err := os.Create(filepath.Join(dir, name))
		require.NoError(t, err)
		_ = f.Close()
	}

	result := scanLoaderTargets(dir)
	assert.Empty(t, result)
}

// TestScanLoaderTargets_WindowsExeStripped verifies that the .exe suffix is
// stripped from Windows loader binaries.
func TestScanLoaderTargets_WindowsExeStripped(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "loader-windows-amd64.exe"))
	require.NoError(t, err)
	_ = f.Close()

	result := scanLoaderTargets(dir)
	require.Len(t, result, 1)
	assert.Equal(t, "windows-amd64", result[0])
}
