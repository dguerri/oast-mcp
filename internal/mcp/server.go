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

// Package mcp implements the MCP SSE server and registers all OAST and agent tools.
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

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
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
	s.mcp = mcpserver.NewMCPServer("oast-mcp", "1.0.0")
	s.registerTools()
	s.registerAgentTools()
	return s
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

// Handler returns an http.Handler that validates JWT on every SSE/message request.
func (s *Server) Handler() http.Handler {
	sseHandler := mcpserver.NewSSEServer(s.mcp, mcpserver.WithBaseURL(s.mcpBaseURL))
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
		sseHandler.ServeHTTP(w, r.WithContext(ctx))
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
