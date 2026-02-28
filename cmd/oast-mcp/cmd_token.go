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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dguerri/oast-mcp/internal/auth"
	"github.com/dguerri/oast-mcp/internal/config"
)

func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	sub := fs.String("sub", "", "token subject / tenant ID (required)")
	scopeStr := fs.String("scope", "oast:read", "comma-separated scopes")
	ttlStr := fs.String("ttl", "24h", "token TTL (e.g. 24h, 168h)")
	cfgPath := fs.String("config", "config.yml", "path to config file")
	_ = fs.Parse(args)

	if *sub == "" {
		fmt.Fprintln(os.Stderr, "error: --sub is required")
		os.Exit(1)
	}

	ttl, err := time.ParseDuration(*ttlStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ttl %q: %v\n", *ttlStr, err)
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

	var scopes []string
	for _, s := range strings.Split(*scopeStr, ",") {
		if t := strings.TrimSpace(s); t != "" {
			scopes = append(scopes, t)
		}
	}
	if len(scopes) == 0 {
		fmt.Fprintln(os.Stderr, "error: --scope must not be empty")
		os.Exit(1)
	}
	tok, err := auth.New(keyBytes).Issue(*sub, scopes, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error issuing token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(tok)
}
