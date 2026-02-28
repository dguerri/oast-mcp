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

// Package agent implements the WebSocket server that manages agent connections,
// dispatches tasks, and serves loader and agent binaries.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/store"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type inMsg struct {
	Type         string         `json:"type"`
	AgentID      string         `json:"agent_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Token        string         `json:"token,omitempty"`
	TaskID       string         `json:"task_id,omitempty"`
	Ok           bool           `json:"ok,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
	Error        string         `json:"error,omitempty"`
}

type outMsg struct {
	Type       string         `json:"type"`
	TaskID     string         `json:"task_id,omitempty"`
	Capability string         `json:"capability,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
	Message    string         `json:"message,omitempty"`
}

// Server manages WebSocket connections from agents.
type Server struct {
	auth   *auth.Auth
	store  store.Store
	logger *slog.Logger
	binDir string

	mu    sync.RWMutex
	conns map[string]*agentConn // "tenantID/agentID" → connection
}

// connKey returns the compound map key for a connection.
func connKey(tenantID, agentID string) string { return tenantID + "/" + agentID }

type agentConn struct {
	agentID  string
	tenantID string
	ws       *websocket.Conn
	send     chan outMsg
}

// NewServer creates an agent WebSocket server backed by the given auth, store, and binary directory.
func NewServer(a *auth.Auth, st store.Store, logger *slog.Logger, binDir string) *Server {
	return &Server{
		auth:   a,
		store:  st,
		logger: logger,
		binDir: binDir,
		conns:  make(map[string]*agentConn),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/dl/") {
		s.handleDownload(w, r)
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Non-WebSocket clients (health probes, scanners) hit this path.
		// Treat as a client error (WARN), not a server error.
		s.logger.Warn("ws upgrade", "remote_addr", r.RemoteAddr, "user_agent", r.UserAgent(), "err", err)
		return
	}
	// Use Background context: r.Context() is cancelled when ServeHTTP returns,
	// but the WebSocket connection outlives the HTTP request.
	go s.handleConn(context.Background(), ws)
}

// handleDownload serves binary downloads.
// GET /dl/loader-{os}-{arch}       — public, serves the loader binary
// GET /dl/second-stage/{os}-{arch} — requires valid agent:connect token
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/dl/")

	var filename string
	switch {
	case strings.HasPrefix(path, "loader-"):
		filename = path // e.g. "loader-linux-amd64"

	case strings.HasPrefix(path, "second-stage/"):
		tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tokenStr == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		claims, err := s.auth.Validate(tokenStr)
		if err != nil {
			if errors.Is(err, auth.ErrExpired) {
				http.Error(w, "token expired", http.StatusUnauthorized)
			} else {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
			return
		}
		if authErr := auth.RequireScope(claims, "agent:connect"); authErr != nil {
			http.Error(w, "insufficient scope", http.StatusForbidden)
			return
		}
		osArch := strings.TrimPrefix(path, "second-stage/")
		filename = "agent-" + osArch

	default:
		http.NotFound(w, r)
		return
	}

	fullPath := filepath.Join(s.binDir, filename)
	f, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			s.logger.Error("open binary", "path", fullPath, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeContent(w, r, filename, time.Time{}, f)
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.logger.Info("agent server listening", "addr", ln.Addr())
	return http.Serve(ln, s)
}

func (s *Server) handleConn(ctx context.Context, ws *websocket.Conn) {
	defer ws.Close()

	// First message must be "register"
	var reg inMsg
	if err := ws.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return
	}
	if err := ws.ReadJSON(&reg); err != nil || reg.Type != "register" {
		_ = ws.WriteJSON(outMsg{Type: "error", Message: "expected register message"})
		return
	}
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	claims, err := s.auth.Validate(reg.Token)
	if err != nil {
		if errors.Is(err, auth.ErrExpired) {
			_ = ws.WriteJSON(outMsg{Type: "error", Message: "token_expired"})
		} else {
			_ = ws.WriteJSON(outMsg{Type: "error", Message: "unauthorized"})
		}
		return
	}
	if authErr := auth.RequireScope(claims, "agent:connect"); authErr != nil {
		_ = ws.WriteJSON(outMsg{Type: "error", Message: "insufficient scope"})
		return
	}

	// The agent_id is baked into the JWT by IssueAgent — we never trust the
	// client-supplied reg.AgentID. This prevents a rogue client from claiming
	// any agent_id it likes (including one belonging to another tenant).
	agentID := claims.AgentID
	if agentID == "" {
		_ = ws.WriteJSON(outMsg{Type: "error", Message: "token missing agent_id claim"})
		return
	}

	now := time.Now().UTC()
	a := &store.Agent{
		AgentID:      agentID,
		TenantID:     claims.TenantID,
		Name:         reg.Name,
		RegisteredAt: now,
		LastSeenAt:   &now,
		Capabilities: reg.Capabilities,
		Status:       "online",
	}
	if err := s.store.UpsertAgent(ctx, a); err != nil {
		s.logger.Error("upsert agent", "err", err)
		_ = ws.WriteJSON(outMsg{Type: "error", Message: "internal error"})
		return
	}

	conn := &agentConn{agentID: agentID, tenantID: claims.TenantID, ws: ws, send: make(chan outMsg, 16)}
	s.mu.Lock()
	s.conns[connKey(claims.TenantID, agentID)] = conn
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, connKey(conn.tenantID, agentID))
		s.mu.Unlock()
		if err := s.store.UpdateAgentStatus(ctx, agentID, conn.tenantID, "offline", time.Now().UTC()); err != nil {
			s.logger.Warn("failed to mark agent offline", "agent_id", agentID, "err", err)
		}
	}()

	// Start task dispatcher and writer goroutines
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.dispatchLoop(ctx, conn)
	go s.writeLoop(ctx, conn)
	s.readLoop(ctx, conn)
}

// dispatchLoop polls the store for pending tasks and sends them to the agent.
func (s *Server) dispatchLoop(ctx context.Context, conn *agentConn) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			task, err := s.store.DequeueTask(ctx, conn.agentID, conn.tenantID)
			if err != nil || task == nil {
				continue
			}
			conn.send <- outMsg{
				Type:       "task",
				TaskID:     task.TaskID,
				Capability: task.Capability,
				Params:     task.Params,
			}
		}
	}
}

// writeLoop drains the send channel and writes to the WebSocket.
func (s *Server) writeLoop(ctx context.Context, conn *agentConn) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-conn.send:
			if err := conn.ws.WriteJSON(msg); err != nil {
				s.logger.Debug("ws write", "agentID", conn.agentID, "err", err)
				return
			}
		}
	}
}

// readLoop processes incoming messages from the agent.
func (s *Server) readLoop(ctx context.Context, conn *agentConn) {
	for {
		var msg inMsg
		if err := conn.ws.ReadJSON(&msg); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.logger.Debug("ws read", "agentID", conn.agentID, "err", err)
			}
			return
		}
		switch msg.Type {
		case "ping":
			conn.send <- outMsg{Type: "pong"}
		case "result":
			s.handleResult(ctx, conn, msg)
		default:
			s.logger.Warn("unknown message type", "type", msg.Type, "agentID", conn.agentID)
		}
	}
}

func (s *Server) handleResult(ctx context.Context, conn *agentConn, msg inMsg) {
	now := time.Now().UTC()
	task := &store.Task{
		TaskID:      msg.TaskID,
		AgentID:     conn.agentID,
		TenantID:    conn.tenantID,
		CompletedAt: &now,
	}
	if msg.Ok {
		task.Status = "done"
		task.Result = msg.Data
	} else {
		task.Status = "error"
		task.Err = msg.Error
	}
	if err := s.store.UpdateTask(ctx, task); err != nil {
		s.logger.Error("update task", "taskID", msg.TaskID, "err", err)
	}
}

