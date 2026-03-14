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

//go:build smoke

package smoke_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	mcpsrv "github.com/dguerri/oast-mcp/internal/mcp"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
)

// Package-level test infrastructure.
var (
	testAuth     *auth.Auth
	testStore    *store.SQLiteStore
	nativeOAST   *oast.Native
	agentSrv     *agent.Server
	mcpSrv       *mcpsrv.Server
	agentWSURL   string // e.g. "https://127.0.0.1:PORT"
	agentBinary  string
	oastDNSPort  int
	oastHTTPPort int
	testCtx      context.Context
	tenantID     = "smoke-tenant"
	logger       *slog.Logger
	tsAgent      *httptest.Server // agent WebSocket test server
)

func TestMain(m *testing.M) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Auth
	key := make([]byte, 32) // 32 zero bytes
	testAuth = auth.New(key)

	// 2. SQLite store
	var err error
	testStore, err = store.NewSQLite(":memory:")
	if err != nil {
		logger.Error("failed to create store", "err", err)
		os.Exit(1)
	}

	// 3. Native OAST responder on random ports
	nativeOAST = oast.NewNative(
		"oast.test",   // zone
		"127.0.0.1",   // publicIP
		"127.0.0.1",   // dnsBindAddr
		"127.0.0.1",   // httpBindAddr
		0,             // dnsPort (random)
		0,             // httpPort (random)
		"",            // tsigKeyName
		"",            // tsigKeyHex
		"",            // tsigAllowedAddr
		testStore,     // EventSink
		logger,
	)
	ctx := context.Background()
	if err := nativeOAST.StartPolling(ctx); err != nil {
		logger.Error("failed to start native OAST", "err", err)
		os.Exit(1)
	}
	oastDNSPort = nativeOAST.DNSPort()
	oastHTTPPort = nativeOAST.HTTPPort()
	logger.Info("OAST responder started", "dns_port", oastDNSPort, "http_port", oastHTTPPort)

	// 4. Agent server
	binDir, err := os.MkdirTemp("", "smoke-bin-*")
	if err != nil {
		logger.Error("failed to create temp dir", "err", err)
		os.Exit(1)
	}
	agentSrv = agent.NewServer(testAuth, testStore, logger, binDir)

	// 5. Agent WebSocket server (TLS so the agent can connect with -k)
	tsAgent = httptest.NewTLSServer(agentSrv)
	agentWSURL = tsAgent.URL // e.g. "https://127.0.0.1:PORT"
	logger.Info("agent WebSocket server started", "url", agentWSURL)

	// 6. MCP server
	rl := ratelimit.New(1000, 1000) // generous rate limit for tests
	al := audit.New(io.Discard)
	mcpSrv = mcpsrv.NewServer(testAuth, testStore, nativeOAST, rl, al, logger, "oast.test", "mcp.test", agentWSURL, binDir)

	// 7. Wire agent server
	mcpSrv.SetAgentServer(agentSrv)

	// 8. Agent binary
	agentBinary = os.Getenv("AGENT_BINARY")

	// 9. Tenant context with JWT claims
	token, err := testAuth.Issue(tenantID, []string{"oast:read", "oast:write", "agent:admin"}, time.Hour)
	if err != nil {
		logger.Error("failed to issue token", "err", err)
		os.Exit(1)
	}
	claims, err := testAuth.Validate(token)
	if err != nil {
		logger.Error("failed to validate token", "err", err)
		os.Exit(1)
	}
	testCtx = mcpsrv.ContextWithClaims(context.Background(), claims)

	// Run tests
	code := m.Run()

	// Cleanup
	tsAgent.Close()
	nativeOAST.Stop()
	_ = testStore.Close()
	_ = os.RemoveAll(binDir)

	os.Exit(code)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// callTool calls the named MCP tool with the given args and returns the
// parsed JSON result map. Fails the test on error or if the tool reports
// an error.
func callTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	result, err := mcpSrv.CallTool(testCtx, name, args)
	require.NoError(t, err, "CallTool(%s) returned error", name)
	require.NotNil(t, result, "CallTool(%s) returned nil", name)

	text := getResultText(t, result)
	require.False(t, result.IsError, "CallTool(%s) reported error: %s", name, text)

	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &m), "failed to parse result JSON for %s: %s", name, text)
	return m
}

// callToolExpectError calls the named MCP tool and expects an error result.
// Returns the error text.
func callToolExpectError(t *testing.T, name string, args map[string]any) string {
	t.Helper()
	result, err := mcpSrv.CallTool(testCtx, name, args)
	require.NoError(t, err, "CallTool(%s) returned Go error", name)
	require.NotNil(t, result, "CallTool(%s) returned nil", name)
	require.True(t, result.IsError, "CallTool(%s) expected error but got success", name)
	return getResultText(t, result)
}

// getResultText extracts the text content from a CallToolResult.
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

// startAgent launches the agent binary as a subprocess and waits until it
// appears online in the agent list.
func startAgent(t *testing.T, agentID string) {
	t.Helper()
	if agentBinary == "" {
		t.Skip("AGENT_BINARY not set, skipping agent test")
	}

	token, err := testAuth.IssueAgent(tenantID, agentID, []string{"agent:connect"}, 5*time.Minute)
	require.NoError(t, err)

	cmd := exec.Command(agentBinary, "-url", agentWSURL, "-token", token, "-id", agentID, "-k")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "failed to start agent binary")

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Poll agent_list until the agent appears online.
	require.Eventually(t, func() bool {
		result, err := mcpSrv.CallTool(testCtx, "agent_list", nil)
		if err != nil || result == nil || result.IsError {
			return false
		}
		text := getResultText(t, result)
		var agents []map[string]any
		if err := json.Unmarshal([]byte(text), &agents); err != nil {
			return false
		}
		for _, a := range agents {
			if a["agent_id"] == agentID && a["status"] == "online" {
				return true
			}
		}
		return false
	}, 10*time.Second, 500*time.Millisecond, "agent %s did not come online within 10s", agentID)
}

// ── OAST Tests ────────────────────────────────────────────────────────────────

func TestSmoke_OAST_DNS(t *testing.T) {
	// 1. Create session
	sess := callTool(t, "oast_create_session", map[string]any{
		"tags": []any{"smoke-dns"},
	})
	sessionID, ok := sess["session_id"].(string)
	require.True(t, ok, "session_id should be a string")

	// 2. Generate payload
	gen := callTool(t, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "url",
		"label":      "dns-probe",
	})
	dnsHostname, ok := gen["dns_hostname"].(string)
	require.True(t, ok, "dns_hostname should be a string, got: %v", gen)
	t.Logf("DNS hostname: %s", dnsHostname)

	// 3. Send DNS query to our native responder
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", fmt.Sprintf("127.0.0.1:%d", oastDNSPort))
		},
	}
	resolveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := resolver.LookupHost(resolveCtx, dnsHostname)
	require.NoError(t, err, "DNS lookup failed")
	require.NotEmpty(t, addrs, "DNS lookup returned no addresses")
	t.Logf("DNS resolved: %v", addrs)

	// 4. Wait for event
	waitResp := callTool(t, "oast_wait_for_event", map[string]any{
		"session_id":      sessionID,
		"timeout_seconds": float64(10),
	})
	require.Equal(t, false, waitResp["timed_out"], "should not time out")
	evList2, ok := waitResp["events"].([]any)
	require.True(t, ok, "events should be an array")
	require.NotEmpty(t, evList2, "should have at least one event")
	ev := evList2[0].(map[string]any)
	require.Equal(t, "dns", ev["protocol"], "expected dns event")
	data, ok := ev["data"].(map[string]any)
	require.True(t, ok, "event data should be a map")
	qname, _ := data["qname"].(string)
	assert.Contains(t, qname, "dns-probe", "qname should contain label")

	// 5. List events
	events := callTool(t, "oast_list_events", map[string]any{
		"session_id": sessionID,
	})
	evList, ok := events["events"].([]any)
	require.True(t, ok, "events should be an array")
	require.NotEmpty(t, evList, "should have at least one event")

	// 6. Close session
	callTool(t, "oast_close_session", map[string]any{
		"session_id": sessionID,
	})
}

func TestSmoke_OAST_HTTP(t *testing.T) {
	// 1. Create session
	sess := callTool(t, "oast_create_session", map[string]any{
		"tags": []any{"smoke-http"},
	})
	sessionID, ok := sess["session_id"].(string)
	require.True(t, ok, "session_id should be a string")

	// 2. Generate payload
	gen := callTool(t, "oast_generate_payload", map[string]any{
		"session_id": sessionID,
		"type":       "url",
		"label":      "http-probe",
	})
	dnsHostname, ok := gen["dns_hostname"].(string)
	require.True(t, ok, "dns_hostname should be a string, got: %v", gen)

	// 3. Send HTTP request with correct Host header
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", oastHTTPPort), nil)
	require.NoError(t, err)
	req.Host = dnsHostname
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// 4. Wait for event
	waitResp := callTool(t, "oast_wait_for_event", map[string]any{
		"session_id":      sessionID,
		"timeout_seconds": float64(10),
	})
	require.Equal(t, false, waitResp["timed_out"], "should not time out")
	httpEvents, ok := waitResp["events"].([]any)
	require.True(t, ok, "events should be an array")
	require.NotEmpty(t, httpEvents)
	httpEv := httpEvents[0].(map[string]any)
	require.Equal(t, "http", httpEv["protocol"], "expected http event")

	// 5. Close session
	callTool(t, "oast_close_session", map[string]any{
		"session_id": sessionID,
	})
}

// ── Agent Tests ───────────────────────────────────────────────────────────────

func TestSmoke_Agent_Lifecycle(t *testing.T) {
	startAgent(t, "smoke-agent")

	// system_info
	t.Run("system_info", func(t *testing.T) {
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "system_info",
			"params":     map[string]any{},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result, ok := status["result"].(map[string]any)
		require.True(t, ok, "result should be a map")
		assert.NotEmpty(t, result["hostname"], "hostname should not be empty")
		assert.Equal(t, "linux", result["os"])
		assert.Equal(t, "amd64", result["arch"])
	})

	// exec
	t.Run("exec", func(t *testing.T) {
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "exec",
			"params":     map[string]any{"cmd": "echo hello"},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result := status["result"].(map[string]any)
		output, _ := result["output"].(string)
		assert.Equal(t, "hello", output)
		exitCode, _ := result["exit_code"].(float64)
		assert.Equal(t, float64(0), exitCode)
	})

	// read_file
	t.Run("read_file", func(t *testing.T) {
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "read_file",
			"params":     map[string]any{"path": "/etc/hostname"},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result := status["result"].(map[string]any)
		content, _ := result["content"].(string)
		// content should be base64-encoded
		decoded, err := base64.StdEncoding.DecodeString(content)
		require.NoError(t, err, "content should be valid base64")
		assert.NotEmpty(t, decoded, "decoded content should not be empty")
	})

	// write_file
	t.Run("write_file", func(t *testing.T) {
		contentB64 := base64.StdEncoding.EncodeToString([]byte("smoke-test\n"))
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "write_file",
			"params": map[string]any{
				"path":       "/tmp/smoke.txt",
				"content_b64": contentB64,
				"mode":       "0644",
			},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result := status["result"].(map[string]any)
		bytesWritten, _ := result["bytes_written"].(float64)
		assert.Equal(t, float64(11), bytesWritten)
	})

	// read back written file
	t.Run("read_written_file", func(t *testing.T) {
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "read_file",
			"params":     map[string]any{"path": "/tmp/smoke.txt"},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result := status["result"].(map[string]any)
		content, _ := result["content"].(string)
		decoded, err := base64.StdEncoding.DecodeString(content)
		require.NoError(t, err)
		assert.Equal(t, "smoke-test\n", string(decoded))
	})

	// fetch_url
	t.Run("fetch_url", func(t *testing.T) {
		sched := callTool(t, "agent_task_schedule", map[string]any{
			"agent_id":   "smoke-agent",
			"capability": "fetch_url",
			"params":     map[string]any{"url": fmt.Sprintf("http://127.0.0.1:%d/", oastHTTPPort)},
		})
		taskID := sched["task_id"].(string)

		status := waitForTask(t, taskID, 15*time.Second)
		require.Equal(t, "done", status["status"])
		result := status["result"].(map[string]any)
		statusCode, _ := result["status"].(float64)
		assert.Equal(t, float64(200), statusCode)
	})
}

func TestSmoke_Agent_InteractiveExec(t *testing.T) {
	startAgent(t, "interactive-agent")

	// Schedule interactive_exec with bash
	sched := callTool(t, "agent_task_schedule", map[string]any{
		"agent_id":   "interactive-agent",
		"capability": "interactive_exec",
		"params":        map[string]any{"command": "bash"},
		"timeout_secs":  float64(30),
	})
	taskID := sched["task_id"].(string)

	// Wait for the task to start running
	time.Sleep(2 * time.Second)

	// Read initial prompt — PTY typically shows a prompt
	interact1 := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   true,
	})
	stdout1, _ := interact1["stdout"].(string)
	t.Logf("initial stdout: %q", stdout1)

	// Send "id\n" — backslash-n is unescaped by the server to a real newline
	callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"stdin":  "id\\n",
		"wait":   false,
	})

	// Give the command time to execute, then drain output
	time.Sleep(1 * time.Second)
	interact2 := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   true,
	})
	stdout2, _ := interact2["stdout"].(string)
	t.Logf("after 'id' stdout: %q", stdout2)
	// PTY echoes the command and shows output; uid= should appear
	assert.Contains(t, stdout2, "uid=", "should contain uid= from id command")

	// Send "exit\n"
	callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"stdin":  "exit\\n",
		"wait":   true,
	})

	// Drain and check completion
	time.Sleep(1 * time.Second)
	interact4 := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   false,
	})
	running, _ := interact4["running"].(bool)
	assert.False(t, running, "process should have exited")
	if ec, ok := interact4["exit_code"].(float64); ok {
		assert.Equal(t, float64(0), ec)
	}
}

func TestSmoke_Agent_Cancel(t *testing.T) {
	startAgent(t, "cancel-agent")

	// Schedule a long-running interactive process
	sched := callTool(t, "agent_task_schedule", map[string]any{
		"agent_id":   "cancel-agent",
		"capability": "interactive_exec",
		"params":        map[string]any{"command": "sleep 300"},
		"timeout_secs":  float64(60),
	})
	taskID := sched["task_id"].(string)

	// Wait briefly for the task to start
	time.Sleep(2 * time.Second)

	// Confirm it's running
	interact := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   false,
	})
	running, _ := interact["running"].(bool)
	assert.True(t, running, "task should be running")

	// Cancel the task
	callTool(t, "agent_task_cancel", map[string]any{
		"task_id":  taskID,
		"agent_id": "cancel-agent",
	})

	// Check status — should be done or error
	time.Sleep(1 * time.Second)
	status := callTool(t, "agent_task_status", map[string]any{
		"task_id": taskID,
		"wait":   false,
	})
	st, _ := status["status"].(string)
	assert.Contains(t, []string{"done", "error"}, st, "task should be done or error after cancel")
}

func TestSmoke_Agent_StdinEscapes(t *testing.T) {
	startAgent(t, "stdin-escape-agent")

	// Schedule cat (reads stdin, writes to stdout)
	sched := callTool(t, "agent_task_schedule", map[string]any{
		"agent_id":   "stdin-escape-agent",
		"capability": "interactive_exec",
		"params":        map[string]any{"command": "cat"},
		"timeout_secs":  float64(10),
	})
	taskID := sched["task_id"].(string)

	// Wait for the task to start
	time.Sleep(2 * time.Second)

	// Send "hello\nworld\n" — literal backslash-n, server unescapes to newlines
	callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"stdin":  "hello\\nworld\\n",
		"wait":   false,
	})

	// Read output
	time.Sleep(1 * time.Second)
	interact := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   true,
	})
	stdout, _ := interact["stdout"].(string)
	t.Logf("cat stdout: %q", stdout)
	assert.Contains(t, stdout, "hello", "should contain hello")
	assert.Contains(t, stdout, "world", "should contain world")

	// Send Ctrl-D to close cat's stdin
	callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"stdin":  "\\x04",
		"wait":   false,
	})

	// Wait for process to exit
	time.Sleep(2 * time.Second)
	interact2 := callTool(t, "agent_task_interact", map[string]any{
		"task_id": taskID,
		"wait":   false,
	})
	running, _ := interact2["running"].(bool)
	assert.False(t, running, "cat should have exited after Ctrl-D")
}

// ── Test utilities ────────────────────────────────────────────────────────────

// waitForTask polls agent_task_status until the task reaches a terminal state
// or the timeout expires.
func waitForTask(t *testing.T, taskID string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, err := mcpSrv.CallTool(testCtx, "agent_task_status", map[string]any{
			"task_id": taskID,
			"wait":   false,
		})
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		text := getResultText(t, result)
		if text == "" {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		st, _ := m["status"].(string)
		if st == "done" || st == "error" {
			return m
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("task %s did not complete within %s", taskID, timeout)
	return nil
}

// Verify that callToolExpectError is usable (compilation check).
var _ = callToolExpectError
var _ = strings.Contains
