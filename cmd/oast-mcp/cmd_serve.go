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

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/audit"
	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/config"
	mcpsrv "github.com/dguerri/oast-mcp/internal/mcp"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
	"github.com/dguerri/oast-mcp/internal/store"
)

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yml", "path to config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config %q: %v\n", *cfgPath, err)
		os.Exit(1)
	}

	// --- JWT signing key ---
	keyBytes, err := hex.DecodeString(cfg.Auth.JWTSigningKeyHex)
	if err != nil || len(keyBytes) != 32 {
		fmt.Fprintln(os.Stderr, "error: auth.jwt_signing_key_hex must be exactly 64 hex chars (32 bytes)")
		os.Exit(1)
	}

	// --- Logger (structured JSON to stdout) ---
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// --- SQLite store ---
	st, err := store.NewSQLite(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to open database", "path", cfg.Database.Path, "error", err)
		os.Exit(1)
	}
	defer st.Close()

	// --- Auth ---
	a := auth.New(keyBytes)

	// --- Native DNS+HTTP OAST responder ---
	ia := oast.NewNative(
		cfg.Domain.OASTZone,
		cfg.Responder.PublicIP,
		cfg.Responder.DNSBindAddr,
		cfg.Responder.HTTPBindAddr,
		cfg.Responder.DNSPort,
		cfg.Responder.HTTPPort,
		cfg.Auth.TSIGKeyName,
		cfg.Auth.TSIGKeyHex,
		cfg.Auth.TSIGAllowedAddr,
		st,
		logger,
	)

	// --- Rate limiter: 10 req/s burst 30 per tenant ---
	rl := ratelimit.New(10, 30)

	// --- Audit log (NDJSON to stdout, captured by systemd journal) ---
	al := audit.New(os.Stdout)

	// --- MCP server ---
	mcp := mcpsrv.NewServer(a, st, ia, rl, al, logger, cfg.Domain.OASTZone, cfg.Domain.MCPHostname, cfg.Domain.AgentHostname, cfg.Agent.BinDir)

	// --- Agent WebSocket server ---
	agentSrv := agent.NewServer(a, st, logger, cfg.Agent.BinDir)

	// --- Background context + signal handling ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// --- Restore in-memory corrID→session map from durable store ---
	// Native stores sessions in RAM only; a restart loses the map. Read all
	// active (non-closed, non-expired) sessions back from SQLite so that
	// callbacks arriving for pre-restart sessions are still attributed correctly.
	refs, err := st.RestoreOASTSessions(ctx)
	if err != nil {
		logger.Warn("failed to restore oast sessions", "error", err)
	} else {
		for _, ref := range refs {
			ia.RestoreSession(ref.CorrelationID, ref.SessionID, ref.TenantID)
		}
		logger.Info("restored oast sessions", "count", len(refs))
	}

	// --- Start OAST polling ---
	if err := ia.StartPolling(ctx); err != nil {
		logger.Error("failed to start oast polling", "error", err)
		os.Exit(1)
	}

	// --- Start MCP server ---
	mcpAddr := fmt.Sprintf("%s:%d", cfg.Server.BindAddr, cfg.Server.MCPPort)
	go func() {
		logger.Info("starting MCP server", "addr", mcpAddr)
		if err := mcp.ListenAndServe(mcpAddr); err != nil {
			logger.Error("MCP server error", "error", err)
		}
	}()

	// --- Start agent WebSocket server ---
	agentAddr := fmt.Sprintf("%s:%d", cfg.Server.BindAddr, cfg.Server.AgentPort)
	go func() {
		logger.Info("starting agent server", "addr", agentAddr)
		if err := agentSrv.ListenAndServe(agentAddr); err != nil {
			logger.Error("agent server error", "error", err)
		}
	}()

	// --- Retention ticker (runs every 24 h) ---
	sessionTTL := time.Duration(cfg.Retention.SessionTTLDays) * 24 * time.Hour
	eventTTL := time.Duration(cfg.Retention.EventTTLDays) * 24 * time.Hour
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := st.PurgeExpired(ctx, sessionTTL, eventTTL); err != nil {
					logger.Warn("purge expired records failed", "error", err)
				}
				if err := st.PruneRevocations(ctx); err != nil {
					logger.Warn("prune revocations failed", "error", err)
				}
			}
		}
	}()

	logger.Info("oast-mcp running", "mcp_addr", mcpAddr, "agent_addr", agentAddr)

	// --- Await shutdown signal ---
	sig := <-sigs
	logger.Info("shutting down", "signal", sig.String())
	cancel()
	ia.Stop()

	// Give goroutines a moment to finish in-flight work.
	time.Sleep(500 * time.Millisecond)
}
