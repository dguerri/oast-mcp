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

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/config"
)

func TestLoad_Valid(t *testing.T) {
	cfg, err := config.Load("testdata/valid.yml")
	require.NoError(t, err)
	assert.Equal(t, "oast.example.com", cfg.Domain.OASTZone)
	assert.Equal(t, "mcp.oast.example.com", cfg.Domain.MCPHostname)
	assert.Equal(t, "agent.oast.example.com", cfg.Domain.AgentHostname)
	assert.Equal(t, 8080, cfg.Server.MCPPort)
	assert.Equal(t, 8081, cfg.Server.AgentPort)
	assert.Equal(t, "127.0.0.1", cfg.Server.BindAddr)
	assert.Equal(t, "1.2.3.4", cfg.Responder.PublicIP)
	assert.Equal(t, 5353, cfg.Responder.DNSPort)
	assert.Equal(t, 9090, cfg.Responder.HTTPPort)
	assert.Equal(t, "/tmp/test.db", cfg.Database.Path)
	assert.Equal(t, 7, cfg.Retention.SessionTTLDays)
	assert.Equal(t, 14, cfg.Retention.EventTTLDays)
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("domain:\n  oast_zone: \"oast.example.com\"\n"))
	require.NoError(t, err)
	assert.Equal(t, 8080, cfg.Server.MCPPort)
	assert.Equal(t, 8081, cfg.Server.AgentPort)
	assert.Equal(t, "127.0.0.1", cfg.Server.BindAddr)
	assert.Equal(t, 53, cfg.Responder.DNSPort)
	assert.Equal(t, 9090, cfg.Responder.HTTPPort)
	assert.Equal(t, "/var/lib/oast-mcp/oast.db", cfg.Database.Path)
	assert.Equal(t, 7, cfg.Retention.SessionTTLDays)
	assert.Equal(t, 14, cfg.Retention.EventTTLDays)
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("testdata/nonexistent.yml")
	assert.Error(t, err)
}
