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

package agent_test

import (
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := agent.GenerateKeyPair()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(priv, "AGE-SECRET-KEY-"), "private key must start with AGE-SECRET-KEY-")
	assert.True(t, strings.HasPrefix(pub, "age1"), "public key must start with age1")
}

// TestGenerateKeyPair_Uniqueness verifies that two calls produce different key pairs.
func TestGenerateKeyPair_Uniqueness(t *testing.T) {
	priv1, pub1, err := agent.GenerateKeyPair()
	require.NoError(t, err)

	priv2, pub2, err := agent.GenerateKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, priv1, priv2, "two private keys must differ")
	assert.NotEqual(t, pub1, pub2, "two public keys must differ")
}

// TestGenerateKeyPair_ValidKeyPair verifies that the generated private key can
// decrypt data encrypted with the corresponding public key using the age package.
func TestGenerateKeyPair_ValidKeyPair(t *testing.T) {
	privStr, pubStr, err := agent.GenerateKeyPair()
	require.NoError(t, err)

	// Parse the recipient (public key).
	recipients, err := age.ParseRecipients(strings.NewReader(pubStr))
	require.NoError(t, err)
	require.Len(t, recipients, 1)

	// Encrypt a small message with the public key.
	plaintext := []byte("hello, age encryption")
	var cipherBuf strings.Builder
	w, err := age.Encrypt(&cipherBuf, recipients...)
	require.NoError(t, err)
	_, err = w.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Parse the identity (private key).
	identities, err := age.ParseIdentities(strings.NewReader(privStr))
	require.NoError(t, err)
	require.Len(t, identities, 1)

	// Decrypt and verify round-trip.
	r, err := age.Decrypt(strings.NewReader(cipherBuf.String()), identities...)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
