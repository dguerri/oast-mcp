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

package ratelimit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/dguerri/oast-mcp/internal/ratelimit"
)

func TestAllow_BurstExhausted(t *testing.T) {
	// burst=3, rps=0 (no refill during test)
	lim := ratelimit.New(0, 3)

	assert.True(t, lim.Allow("tenant-a"))
	assert.True(t, lim.Allow("tenant-a"))
	assert.True(t, lim.Allow("tenant-a"))
	assert.False(t, lim.Allow("tenant-a")) // burst exhausted
}

func TestAllow_TenantsAreIsolated(t *testing.T) {
	lim := ratelimit.New(0, 2)

	assert.True(t, lim.Allow("alice"))
	assert.True(t, lim.Allow("alice"))
	assert.False(t, lim.Allow("alice")) // alice exhausted

	// bob has independent bucket
	assert.True(t, lim.Allow("bob"))
	assert.True(t, lim.Allow("bob"))
	assert.False(t, lim.Allow("bob"))
}

func TestNew_CreatesIndependentLimiters(t *testing.T) {
	// Two separate Limiter instances don't share state
	lim1 := ratelimit.New(0, 1)
	lim2 := ratelimit.New(0, 1)
	assert.True(t, lim1.Allow("alice"))
	assert.True(t, lim2.Allow("alice")) // different instance, independent
}
