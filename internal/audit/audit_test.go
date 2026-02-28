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

package audit_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/audit"
)

func TestLog_WritesJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.New(&buf)

	logger.Log(audit.Event{
		TenantID: "alice",
		Subject:  "alice",
		Action:   "session.create",
		Resource: "sess-123",
		Outcome:  "ok",
	})

	var got map[string]any
	require.NoError(t, json.NewDecoder(&buf).Decode(&got))
	assert.Equal(t, "alice", got["tenant_id"])
	assert.Equal(t, "session.create", got["action"])
	assert.Equal(t, "sess-123", got["resource"])
	assert.Equal(t, "ok", got["outcome"])
	assert.NotEmpty(t, got["time"]) // auto-filled
}

func TestLog_AutoFillsTime(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.New(&buf)
	before := time.Now()

	logger.Log(audit.Event{Action: "test", Outcome: "ok"})

	after := time.Now()
	var got map[string]any
	require.NoError(t, json.NewDecoder(&buf).Decode(&got))
	timeStr, ok := got["time"].(string)
	require.True(t, ok)
	ts, err := time.Parse(time.RFC3339, timeStr)
	require.NoError(t, err)
	assert.True(t, !ts.Before(before) && !ts.After(after))
}

func TestLog_WithDetail(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.New(&buf)

	logger.Log(audit.Event{
		Action:  "session.poll",
		Outcome: "ok",
		Detail:  map[string]any{"events_returned": 5, "cursor": "abc"},
	})

	var got map[string]any
	require.NoError(t, json.NewDecoder(&buf).Decode(&got))
	detail, ok := got["detail"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(5), detail["events_returned"])
}

func TestLog_MultipleEventsAreNewlineDelimited(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.New(&buf)
	logger.Log(audit.Event{Action: "a", Outcome: "ok"})
	logger.Log(audit.Event{Action: "b", Outcome: "ok"})

	dec := json.NewDecoder(&buf)
	var e1, e2 map[string]any
	require.NoError(t, dec.Decode(&e1))
	require.NoError(t, dec.Decode(&e2))
	assert.Equal(t, "a", e1["action"])
	assert.Equal(t, "b", e2["action"])
}
