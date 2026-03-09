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

package oast

// Handler-level unit tests that exercise handleHTTP, buildHTTPData,
// canonicalHost, collectHTTPHeaders, extractCorrID, and addHTTPBody
// without binding any network sockets. Safe for t.Parallel().

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dguerri/oast-mcp/internal/store"
)

// testNativeNoNetwork returns a *Native with sessions pre-registered but no
// servers started. Suitable for calling handleHTTP directly.
func testNativeNoNetwork(t *testing.T) (*Native, *store.SQLiteStore) {
	t.Helper()
	st, err := store.NewSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	n := NewNative("oast.example.com", "1.2.3.4", "", "", 0, 0, "", "", "", st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Pre-parse ip4 so handleHTTP/handleDNS don't panic.
	n.ip4 = []byte{1, 2, 3, 4}
	return n, st
}

// --- canonicalHost ---

func TestCanonicalHost_WithPort(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "example.com", canonicalHost("example.com:8080"))
}

func TestCanonicalHost_WithoutPort(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "example.com", canonicalHost("Example.COM"))
}

func TestCanonicalHost_Empty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", canonicalHost(""))
}

// --- extractCorrID ---

func TestExtractCorrID_Plain(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	corrID := n.extractCorrID("abcdef0123456789abcd.oast.example.com")
	assert.Equal(t, "abcdef0123456789abcd", corrID)
}

func TestExtractCorrID_WithLabel(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	corrID := n.extractCorrID("abcdef0123456789abcd-login.oast.example.com")
	assert.Equal(t, "abcdef0123456789abcd", corrID)
}

func TestExtractCorrID_WithPrefix(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	corrID := n.extractCorrID("something.abcdef0123456789abcd.oast.example.com")
	assert.Equal(t, "abcdef0123456789abcd", corrID)
}

func TestExtractCorrID_ZoneApex(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	assert.Equal(t, "", n.extractCorrID("oast.example.com"))
}

func TestExtractCorrID_WrongZone(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	assert.Equal(t, "", n.extractCorrID("foo.other.com"))
}

// --- buildHTTPData ---

func TestBuildHTTPData_Basic(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://test.oast.example.com/path?q=1", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	srcIP, data := buildHTTPData(req, "test.oast.example.com")
	assert.Equal(t, "10.0.0.1:54321", srcIP)
	assert.Equal(t, "GET", data["method"])
	assert.Equal(t, "/path", data["path"])
	assert.Equal(t, "q=1", data["query_string"])
	assert.Equal(t, "test.oast.example.com", data["host"])
}

func TestBuildHTTPData_XForwardedFor(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "http://test/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	srcIP, data := buildHTTPData(req, "test")
	assert.Equal(t, "10.0.0.1", srcIP, "should use last XFF entry")
	assert.Equal(t, "203.0.113.5, 10.0.0.1", data["x_forwarded_for"])
}

func TestBuildHTTPData_UserAgentAndContentType(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("User-Agent", "MyBot/1.0")
	req.Header.Set("Content-Type", "application/json")
	_, data := buildHTTPData(req, "test")
	assert.Equal(t, "MyBot/1.0", data["user_agent"])
	assert.Equal(t, "application/json", data["content_type"])
}

// --- collectHTTPHeaders ---

func TestCollectHTTPHeaders_FiltersHopByHop(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Custom", "value")
	hdrs := collectHTTPHeaders(req)
	_, hasConn := hdrs["Connection"]
	assert.False(t, hasConn, "hop-by-hop header should be excluded")
	assert.Equal(t, "value", hdrs["X-Custom"])
}

// --- addHTTPBody ---

func TestAddHTTPBody_UTF8(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "http://test/", strings.NewReader("hello world"))
	data := map[string]any{}
	addHTTPBody(req, data)
	assert.Equal(t, "hello world", data["body"])
	assert.Equal(t, false, data["body_truncated"])
}

func TestAddHTTPBody_NilBody(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://test/", nil)
	data := map[string]any{}
	addHTTPBody(req, data)
	_, hasBody := data["body"]
	assert.False(t, hasBody)
}

// --- handleHTTP (full handler, no network) ---

func TestHandleHTTP_UnknownHost_Returns200(t *testing.T) {
	t.Parallel()
	n, _ := testNativeNoNetwork(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://unknown.other.com/", nil)
	req.Host = "unknown.other.com"
	n.handleHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleHTTP_KnownSession_RecordsEvent(t *testing.T) {
	t.Parallel()
	n, st := testNativeNoNetwork(t)
	ctx := context.Background()

	// Create a session via the public API to get a real corrID.
	ep, err := n.NewSession(ctx, "sess-handler", "alice")
	require.NoError(t, err)

	// Create the session in the store so saveEvent can persist.
	require.NoError(t, st.CreateSession(ctx, &store.Session{
		SessionID:     "sess-handler",
		TenantID:      "alice",
		CorrelationID: ep.CorrelationID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+ep.DNS+"/test", nil)
	req.Host = ep.DNS
	n.handleHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	events, _, err := st.PollEvents(ctx, "sess-handler", "alice", "", 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "http", events[0].Protocol)
	assert.Equal(t, "sess-handler", events[0].SessionID)
}
