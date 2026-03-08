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
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func MockGenerateX25519Identity_Valid() (*age.X25519Identity, error) {
	return age.ParseX25519Identity("AGE-SECRET-KEY-1FZNP6JXTE7YLQV3FMDQVKZ4UFFM7KRE7C07FXVPK3XSY5VSPWFS0H60GW")
}

func MockGenerateX25519Identity_Error() (*age.X25519Identity, error) {
	return nil, errors.New("test error")
}

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := agent.GenerateKeyPair()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(priv, "AGE-SECRET-KEY-"), "private key must start with AGE-SECRET-KEY-")
	assert.True(t, strings.HasPrefix(pub, "age1"), "public key must start with age1")
}

func TestGenerateKeyPair_Error(t *testing.T) {
	_, _, err := agent.GenerateKeyPairWith(func() (*age.X25519Identity, error) {
		return nil, errors.New("rng broken")
	})
	require.EqualError(t, err, "rng broken")
}
