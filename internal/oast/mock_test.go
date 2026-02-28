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

package oast_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/oast"
	"github.com/dguerri/oast-mcp/internal/store"
)

// testSink is a simple in-memory EventSink for testing.
type testSink struct {
	mu     sync.Mutex
	events []*store.Event
}

func (s *testSink) SaveEvent(_ context.Context, e *store.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Len returns the number of saved events (thread-safe).
func (s *testSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Events returns a copy of saved events (thread-safe).
func (s *testSink) Events() []*store.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*store.Event, len(s.events))
	copy(cp, s.events)
	return cp
}

func TestMock_NewSession_UniqueCorrelationIDs(t *testing.T) {
	sink := &testSink{}
	m := oast.NewMock(sink, "oast.example.com")
	ctx := context.Background()

	ep1, err := m.NewSession(ctx, "sess-1", "alice")
	require.NoError(t, err)
	ep2, err := m.NewSession(ctx, "sess-2", "alice")
	require.NoError(t, err)

	assert.NotEqual(t, ep1.CorrelationID, ep2.CorrelationID)
	assert.Contains(t, ep1.DNS, "oast.example.com")
	assert.Contains(t, ep1.HTTP, "http://")
	assert.Contains(t, ep1.HTTPS, "https://")
}

func TestMock_InjectEvent(t *testing.T) {
	sink := &testSink{}
	m := oast.NewMock(sink, "oast.example.com")
	ctx := context.Background()

	ev := &store.Event{
		EventID:    "ev-1",
		SessionID:  "sess-1",
		TenantID:   "alice",
		ReceivedAt: time.Now().UTC(),
		Protocol:   "dns",
		SrcIP:      "1.2.3.4",
		Data:       map[string]any{"qname": "test.oast.example.com"},
	}
	require.NoError(t, m.InjectEvent(ctx, ev))
	assert.Equal(t, 1, sink.Len())
	assert.Equal(t, "ev-1", sink.Events()[0].EventID)
}

func TestMock_StartPolling_NoError(t *testing.T) {
	sink := &testSink{}
	m := oast.NewMock(sink, "oast.example.com")
	ctx := context.Background()
	assert.NoError(t, m.StartPolling(ctx))
	m.Stop() // must not panic
}
