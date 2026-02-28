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

// Package config loads and validates the oast-mcp server configuration from YAML.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain     DomainConfig     `yaml:"domain"`
	Server     ServerConfig     `yaml:"server"`
	Responder ResponderConfig `yaml:"responder"`
	Auth       AuthConfig       `yaml:"auth"`
	Database   DatabaseConfig   `yaml:"database"`
	Retention  RetentionConfig  `yaml:"retention"`
	Agent      AgentConfig      `yaml:"agent"`
}

type DomainConfig struct {
	OASTZone      string `yaml:"oast_zone"`
	MCPHostname   string `yaml:"mcp_hostname"`
	AgentHostname string `yaml:"agent_hostname"`
}

type ServerConfig struct {
	MCPPort   int    `yaml:"mcp_port"`
	AgentPort int    `yaml:"agent_port"`
	BindAddr  string `yaml:"bind_addr"`
}

type ResponderConfig struct {
	PublicIP     string `yaml:"public_ip"`
	DNSBindAddr  string `yaml:"dns_bind_addr"`  // IP to bind DNS on; empty = all interfaces
	HTTPBindAddr string `yaml:"http_bind_addr"` // IP to bind HTTP callback server on
	DNSPort      int    `yaml:"dns_port"`
	HTTPPort     int    `yaml:"http_port"`
}

type AuthConfig struct {
	// Hex-encoded 32-byte HMAC-SHA256 key. Generate: openssl rand -hex 32
	JWTSigningKeyHex string `yaml:"jwt_signing_key_hex"`
	// TSIG key for RFC 2136 DNS updates (used by Caddy for ACME DNS-01).
	// Hex-encoded 32-byte secret. Generate: openssl rand -hex 32
	// Leave empty to disable RFC 2136 UPDATE support entirely.
	TSIGKeyName    string `yaml:"tsig_key_name"`     // e.g. "caddy."
	TSIGKeyHex     string `yaml:"tsig_key_hex"`
	TSIGAllowedAddr string `yaml:"tsig_allowed_addr"` // source IP allowed to send RFC 2136 UPDATEs; empty = any
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type RetentionConfig struct {
	SessionTTLDays int `yaml:"session_ttl_days"`
	EventTTLDays   int `yaml:"event_ttl_days"`
}

type AgentConfig struct {
	// age X25519 recipient public key. Generate: oast-mcp keygen
	OperatorPublicKey string   `yaml:"operator_public_key"`
	ExecLabMode       bool     `yaml:"exec_lab_mode"`
	ExecAllowlist     []string `yaml:"exec_allowlist"`
	BinDir            string   `yaml:"bin_dir"`
}

// applyDefaults fills in zero-value fields with their built-in defaults.
func applyDefaults(c *Config) {
	if c.Server.MCPPort == 0 {
		c.Server.MCPPort = 8080
	}
	if c.Server.AgentPort == 0 {
		c.Server.AgentPort = 8081
	}
	if c.Server.BindAddr == "" {
		c.Server.BindAddr = "127.0.0.1"
	}
	if c.Responder.DNSPort == 0 {
		c.Responder.DNSPort = 53
	}
	if c.Responder.HTTPPort == 0 {
		c.Responder.HTTPPort = 9090
	}
	if c.Responder.HTTPBindAddr == "" {
		c.Responder.HTTPBindAddr = "127.0.0.1"
	}
	if c.Database.Path == "" {
		c.Database.Path = "/var/lib/oast-mcp/oast.db"
	}
	if c.Retention.SessionTTLDays == 0 {
		c.Retention.SessionTTLDays = 7
	}
	if c.Retention.EventTTLDays == 0 {
		c.Retention.EventTTLDays = 14
	}
	if c.Agent.BinDir == "" {
		c.Agent.BinDir = "/var/lib/oast-mcp/bin"
	}
}

// LoadBytes parses YAML config from data and applies defaults.
func LoadBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

// Load reads the YAML config file at path and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(data)
}
