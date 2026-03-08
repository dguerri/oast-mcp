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
	"os"

	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/config"
	"github.com/dguerri/oast-mcp/internal/store"
)

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yml", "path to config file")
	tokenStr := fs.String("token", "", "JWT token to revoke (required)")
	_ = fs.Parse(args)

	if *tokenStr == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		os.Exit(1)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config %q: %v\n", *cfgPath, err)
		os.Exit(1)
	}

	keyBytes, err := hex.DecodeString(cfg.Auth.JWTSigningKeyHex)
	if err != nil || len(keyBytes) != 32 {
		fmt.Fprintln(os.Stderr, "error: auth.jwt_signing_key_hex must be exactly 64 hex chars (32 bytes)")
		os.Exit(1)
	}

	a := auth.New(keyBytes)
	claims, err := a.ParseClaims(*tokenStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing token: %v\n", err)
		os.Exit(1)
	}

	st, err := store.NewSQLite(cfg.Database.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database %q: %v\n", cfg.Database.Path, err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	if err := st.RevokeToken(ctx, claims.JTI, claims.ExpiresAt); err != nil {
		fmt.Fprintf(os.Stderr, "error revoking token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Token revoked: jti=%s expires=%s\n", claims.JTI, claims.ExpiresAt.Format("2006-01-02T15:04:05Z"))
}
