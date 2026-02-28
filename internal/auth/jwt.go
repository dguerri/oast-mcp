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

// Package auth issues and validates HMAC-SHA256 signed JWT tokens for tenants and agents.
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrExpired           = errors.New("token expired")
	ErrInvalid           = errors.New("invalid token")
	ErrInsufficientScope = errors.New("insufficient scope")
)

// Claims holds the validated, parsed token claims.
type Claims struct {
	Subject   string
	TenantID  string // always equals Subject; kept separate for clarity at call sites
	AgentID   string // non-empty only for agent:connect tokens minted by IssueAgent
	Scopes    []string
	JTI       string
	ExpiresAt time.Time
}

type rawClaims struct {
	jwt.RegisteredClaims
	Scopes   []string `json:"scp"`
	TenantID string   `json:"tid"`
	AgentID  string   `json:"aid,omitempty"`
}

// Auth issues and validates JWT tokens signed with HMAC-SHA256.
type Auth struct{ key []byte }

func New(key []byte) *Auth { return &Auth{key: key} }

// Issue mints a signed JWT for the given subject with the requested scopes and TTL.
func (a *Auth) Issue(sub string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()
	rc := rawClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{"oast-mcp"},
		},
		Scopes:   scopes,
		TenantID: sub,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, rc).SignedString(a.key)
}

// IssueAgent mints a short-lived agent:connect token that embeds both the
// tenantID and the agentID. The agent server uses these claims as the sole
// source of identity — the agent does not need to supply its own agent_id.
func (a *Auth) IssueAgent(tenantID, agentID string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()
	rc := rawClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   tenantID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{"oast-mcp"},
		},
		Scopes:   scopes,
		TenantID: tenantID,
		AgentID:  agentID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, rc).SignedString(a.key)
}

// Validate parses tokenStr, checks the signature, audience, and expiry, and returns the claims.
func (a *Auth) Validate(tokenStr string) (*Claims, error) {
	var rc rawClaims
	_, err := jwt.ParseWithClaims(tokenStr, &rc,
		func(*jwt.Token) (any, error) { return a.key, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience("oast-mcp"),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		return nil, ErrInvalid
	}
	c := &Claims{
		Subject:  rc.Subject,
		TenantID: rc.TenantID,
		AgentID:  rc.AgentID,
		Scopes:   rc.Scopes,
		JTI:      rc.ID,
	}
	if rc.ExpiresAt != nil {
		c.ExpiresAt = rc.ExpiresAt.Time
	}
	return c, nil
}

// ParseClaims parses and signature-validates a token without requiring it to
// be non-expired. Use this only for administrative operations (e.g. revocation)
// where the caller needs the JTI and ExpiresAt of an already-expired token.
func (a *Auth) ParseClaims(tokenStr string) (*Claims, error) {
	var rc rawClaims
	_, err := jwt.ParseWithClaims(tokenStr, &rc,
		func(*jwt.Token) (any, error) { return a.key, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience("oast-mcp"),
	)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrInvalid
	}
	exp := time.Time{}
	if rc.ExpiresAt != nil {
		exp = rc.ExpiresAt.Time
	}
	return &Claims{
		Subject:   rc.Subject,
		TenantID:  rc.TenantID,
		AgentID:   rc.AgentID,
		Scopes:    rc.Scopes,
		JTI:       rc.ID,
		ExpiresAt: exp,
	}, nil
}

// RequireScope returns ErrInsufficientScope if c is nil or does not contain scope.
func RequireScope(c *Claims, scope string) error {
	if c == nil {
		return ErrInsufficientScope
	}
	for _, s := range c.Scopes {
		if s == scope {
			return nil
		}
	}
	return ErrInsufficientScope
}
