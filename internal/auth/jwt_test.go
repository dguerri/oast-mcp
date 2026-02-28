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

package auth_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/auth"
)

func newKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

func TestIssueAndValidate(t *testing.T) {
	a := auth.New(newKey())
	tok, err := a.Issue("alice", []string{"oast:read", "oast:write"}, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, tok)

	claims, err := a.Validate(tok)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject)
	assert.Equal(t, "alice", claims.TenantID)
	assert.Equal(t, []string{"oast:read", "oast:write"}, claims.Scopes)
	assert.NotEmpty(t, claims.JTI)
}

func TestValidate_Expired(t *testing.T) {
	a := auth.New(newKey())
	tok, err := a.Issue("alice", []string{"oast:read"}, -time.Minute)
	require.NoError(t, err)
	_, err = a.Validate(tok)
	assert.ErrorIs(t, err, auth.ErrExpired)
}

func TestValidate_WrongKey(t *testing.T) {
	a1 := auth.New(newKey())
	a2 := auth.New(newKey())
	tok, err := a1.Issue("alice", []string{"oast:read"}, time.Hour)
	require.NoError(t, err)
	_, err = a2.Validate(tok)
	assert.ErrorIs(t, err, auth.ErrInvalid)
}

func TestValidate_Tampered(t *testing.T) {
	a := auth.New(newKey())
	tok, err := a.Issue("alice", []string{"oast:read"}, time.Hour)
	require.NoError(t, err)
	tampered := tok[:len(tok)-4] + "XXXX"
	_, err = a.Validate(tampered)
	assert.ErrorIs(t, err, auth.ErrInvalid)
}

func TestRequireScope(t *testing.T) {
	claims := &auth.Claims{Scopes: []string{"oast:read"}}
	assert.NoError(t, auth.RequireScope(claims, "oast:read"))
	assert.ErrorIs(t, auth.RequireScope(claims, "oast:write"), auth.ErrInsufficientScope)
	assert.ErrorIs(t, auth.RequireScope(claims, "agent:admin"), auth.ErrInsufficientScope)
}

func TestIssue_DifferentSubjectsGetDifferentTenantIDs(t *testing.T) {
	a := auth.New(newKey())
	tokA, _ := a.Issue("alice", []string{"oast:read"}, time.Hour)
	tokB, _ := a.Issue("bob", []string{"oast:read"}, time.Hour)
	claimsA, _ := a.Validate(tokA)
	claimsB, _ := a.Validate(tokB)
	assert.NotEqual(t, claimsA.TenantID, claimsB.TenantID)
	assert.Equal(t, "alice", claimsA.TenantID)
	assert.Equal(t, "bob", claimsB.TenantID)
}

func TestParseClaims_ValidToken(t *testing.T) {
	a := auth.New(newKey())
	token, err := a.Issue("alice", []string{"oast:read"}, time.Hour)
	require.NoError(t, err)

	claims, err := a.ParseClaims(token)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject)
	assert.NotEmpty(t, claims.JTI)
	assert.False(t, claims.ExpiresAt.IsZero())
	assert.WithinDuration(t, time.Now().Add(time.Hour), claims.ExpiresAt, 5*time.Second)
}

func TestParseClaims_ExpiredToken(t *testing.T) {
	a := auth.New(newKey())
	// Negative TTL = already expired
	token, err := a.Issue("alice", []string{"oast:read"}, -time.Second)
	require.NoError(t, err)

	// Must succeed despite expiry — ParseClaims tolerates expired tokens
	claims, err := a.ParseClaims(token)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject)
	assert.NotEmpty(t, claims.JTI)
	assert.False(t, claims.ExpiresAt.IsZero())
	assert.True(t, claims.ExpiresAt.Before(time.Now()))
}

func TestParseClaims_TamperedToken(t *testing.T) {
	a := auth.New(newKey())
	token, err := a.Issue("alice", []string{"oast:read"}, time.Hour)
	require.NoError(t, err)

	// Tamper the token by appending a character
	tampered := token + "X"
	_, err = a.ParseClaims(tampered)
	assert.ErrorIs(t, err, auth.ErrInvalid)
}
