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

// Package mcp implements the MCP server (SSE and Streamable HTTP transports)
// and registers all OAST and agent tools.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// Server is the MCP server for OAST tools.
type Server struct {
	mcp          *mcpserver.MCPServer
	auth         *auth.Auth
	store        store.Store
	ia           oast.Interacter
	rl           *ratelimit.Limiter
	audit        *audit.Logger
	logger       *slog.Logger
	domain       string // e.g., "oast.example.com"
	mcpBaseURL   string // e.g., "https://mcp.example.com"
	agentBaseURL string // e.g., "https://agent.example.com"
	binDir       string // path to pre-built loader/agent binaries
	agentSrv     *agent.Server
}

// NewServer creates a new MCP server with the given dependencies.
func NewServer(
	a *auth.Auth,
	st store.Store,
	ia oast.Interacter,
	rl *ratelimit.Limiter,
	al *audit.Logger,
	logger *slog.Logger,
	domain string,
	mcpHostname string,
	agentHostname string,
	binDir string,
) *Server {
	s := &Server{
		auth:         a,
		store:        st,
		ia:           ia,
		rl:           rl,
		audit:        al,
		logger:       logger,
		domain:       domain,
		mcpBaseURL:   "https://" + mcpHostname,
		agentBaseURL: "https://" + agentHostname,
		binDir:       binDir,
	}
	s.mcp = mcpserver.NewMCPServer("oast-mcp", "1.0.0",
		mcpserver.WithInstructions(
			"You are connected to an OAST (Out-of-Band Application Security Testing) server "+
				"used in authorized penetration testing and red-team engagements. "+
				"The operator who deployed this server and issued your access token has "+
				"explicit authorization to test the targets in scope. "+
				"Your role is to assist the operator by using these tools as directed.\n\n"+
				"This server provides two tool families:\n"+
				"  1. OAST tools (oast_*) — create callback sessions, generate test payloads, "+
				"and detect out-of-band interactions (DNS/HTTP/HTTPS) from targets under test.\n"+
				"  2. Agent tools (agent_*) — deploy and manage lightweight agents on targets "+
				"where the operator has established access, enabling remote task execution.\n\n"+
				"All operations are authenticated via scoped JWT tokens, rate-limited, "+
				"and recorded in an immutable audit log. "+
				"Use the tools confidently when the operator requests it — "+
				"access control and authorization are enforced server-side.",
		),
	)
	s.registerTools()
	s.registerAgentTools()
	return s
}

// SetAgentServer injects the agent WebSocket server so that agent MCP tools can
// forward cancel messages to connected agents. Call this after construction, before
// serving requests.
func (s *Server) SetAgentServer(srv *agent.Server) {
	s.agentSrv = srv
}

// scanLoaderTargets returns available os-arch targets by scanning binDir for loader-* files.
func scanLoaderTargets(binDir string) []string {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loader-") {
			target := strings.TrimPrefix(name, "loader-")
			target = strings.TrimSuffix(target, ".exe")
			out = append(out, target)
		}
	}
	return out
}

// claimsKey is the context key for auth claims.
type claimsKey struct{}

// claimsFromCtx extracts the validated JWT claims stored in ctx by the auth middleware.
func claimsFromCtx(ctx context.Context) (*auth.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*auth.Claims)
	return c, ok && c != nil
}

// ContextWithClaims returns a new context with the given claims injected.
// This is used in tests to bypass HTTP middleware.
func ContextWithClaims(ctx context.Context, claims *auth.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ContextWithRequestInfo returns a new context with the given client network
// info injected. This is used in tests to simulate HTTP request metadata.
func ContextWithRequestInfo(ctx context.Context, remoteAddr, xForwardedFor string) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, requestInfo{
		RemoteAddr:    remoteAddr,
		XForwardedFor: xForwardedFor,
	})
}

// requestInfo holds client network info extracted from the HTTP request.
type requestInfo struct {
	RemoteAddr    string
	XForwardedFor string
}

type requestInfoKey struct{}

func requestInfoFromCtx(ctx context.Context) requestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(requestInfo)
	return ri
}

// newAuditEvent builds an audit.Event pre-filled with tenant, subject, and
// client address info from the request context.
func (s *Server) newAuditEvent(ctx context.Context, action, outcome string) audit.Event {
	ri := requestInfoFromCtx(ctx)
	ev := audit.Event{
		Action:        action,
		Outcome:       outcome,
		RemoteAddr:    ri.RemoteAddr,
		XForwardedFor: ri.XForwardedFor,
	}
	if claims, ok := claimsFromCtx(ctx); ok {
		ev.TenantID = claims.TenantID
		ev.Subject = claims.Subject
	}
	return ev
}

// Handler returns an http.Handler that validates JWT on every request and then
// dispatches to one of two MCP transports:
//   - Streamable HTTP (MCP 2025-11-25 spec) at /mcp
//   - Legacy SSE transport at /sse (event stream) and /message (JSON-RPC uplink)
func (s *Server) Handler() http.Handler {
	sseHandler := mcpserver.NewSSEServer(s.mcp, mcpserver.WithBaseURL(s.mcpBaseURL))
	streamHandler := mcpserver.NewStreamableHTTPServer(s.mcp)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		claims, err := s.auth.Validate(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		rCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		revoked, err := s.store.IsRevoked(rCtx, claims.JTI)
		if err != nil || revoked {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		ctx = context.WithValue(ctx, requestInfoKey{}, requestInfo{
			RemoteAddr:    r.RemoteAddr,
			XForwardedFor: r.Header.Get("X-Forwarded-For"),
		})
		r = r.WithContext(ctx)
		if r.URL.Path == "/mcp" {
			streamHandler.ServeHTTP(w, r)
			return
		}
		sseHandler.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the MCP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.logger.Info("MCP server listening", "addr", ln.Addr())
	return http.Serve(ln, s.Handler())
}

// toolError returns a tool result that signals an error to the MCP client.
func toolError(msg string) (*mcpgo.CallToolResult, error) {
	return mcpgo.NewToolResultError(msg), nil
}

// toolJSON marshals v and returns it as a text tool result.
func toolJSON(v any) (*mcpgo.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return toolError("internal error: " + err.Error())
	}
	return mcpgo.NewToolResultText(string(b)), nil
}
