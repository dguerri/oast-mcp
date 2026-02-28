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

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    closed_at  TEXT,
    cursor     TEXT NOT NULL DEFAULT '',
    tags_json  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sess_tenant ON sessions(tenant_id);

CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    received_at TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    src_ip      TEXT NOT NULL DEFAULT '',
    data_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ev_session ON events(session_id, received_at, event_id);

CREATE TABLE IF NOT EXISTS token_revocations (
    jti        TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- NOTE: existing databases must recreate this table to change the primary key.
-- SQLite does not support ALTER TABLE ... DROP CONSTRAINT / ADD PRIMARY KEY.
-- Migration: rename old table, create new, copy data, drop old.
CREATE TABLE IF NOT EXISTS agents (
    agent_id          TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    name              TEXT NOT NULL,
    registered_at     TEXT NOT NULL,
    last_seen_at      TEXT,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    status            TEXT NOT NULL DEFAULT 'offline',
    PRIMARY KEY (agent_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_tenant ON agents(tenant_id);

CREATE TABLE IF NOT EXISTS tasks (
    task_id      TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    scheduled_by TEXT NOT NULL,
    capability   TEXT NOT NULL,
    params_json  TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    completed_at TEXT,
    result_json  TEXT,
    error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_task_agent_status ON tasks(agent_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_task_tenant ON tasks(tenant_id);

`

// SQLiteStore is a multi-tenant SQLite-backed implementation of Store.
type SQLiteStore struct {
	db *sql.DB
}

// addPragmas appends WAL and foreign-key PRAGMA parameters to the DSN so that
// every new connection opened by the driver has the correct settings.
func addPragmas(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
}

// NewSQLite opens (or creates) a SQLite database at the given DSN and applies the schema.
func NewSQLite(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", addPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single writer to avoid SQLITE_BUSY with WAL.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func marshalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalJSON(raw string, dst any) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), dst)
}

func timeToStr(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func strToTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func nullTimeToStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := timeToStr(*t)
	return &s
}

func strToNullTime(s *string) (*time.Time, error) {
	if s == nil {
		return nil, nil
	}
	t, err := strToTime(*s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateSession(ctx context.Context, sess *Session) error {
	tagsJSON, err := marshalJSON(sess.Tags)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions
			(session_id, tenant_id, correlation_id, created_at, expires_at, closed_at, cursor, tags_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.SessionID,
		sess.TenantID,
		sess.CorrelationID,
		timeToStr(sess.CreatedAt),
		timeToStr(sess.ExpiresAt),
		nullTimeToStr(sess.ClosedAt),
		sess.Cursor,
		tagsJSON,
	)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, sessionID, tenantID string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT session_id, tenant_id, correlation_id,
		       created_at, expires_at, closed_at, cursor, tags_json
		FROM sessions
		WHERE session_id = ? AND tenant_id = ?`,
		sessionID, tenantID,
	)
	return scanSession(row)
}

func (s *SQLiteStore) ListSessions(ctx context.Context, tenantID string) ([]*Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, tenant_id, correlation_id,
		       created_at, expires_at, closed_at, cursor, tags_json
		FROM sessions
		WHERE tenant_id = ?
		ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateSessionCursor(ctx context.Context, sessionID, tenantID, cursor string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET cursor = ?
		WHERE session_id = ? AND tenant_id = ?`,
		cursor, sessionID, tenantID,
	)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *SQLiteStore) CloseSession(ctx context.Context, sessionID, tenantID string) error {
	now := timeToStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET closed_at = ?
		WHERE session_id = ? AND tenant_id = ? AND closed_at IS NULL`,
		now, sessionID, tenantID,
	)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// scanSession works with both *sql.Row and *sql.Rows via the scanner interface.
type scanner interface {
	Scan(dest ...any) error
}

func scanSession(row scanner) (*Session, error) {
	var (
		sess       Session
		closedAtS  *string
		createdAtS string
		expiresAtS string
		tagsJSON   string
	)
	err := row.Scan(
		&sess.SessionID,
		&sess.TenantID,
		&sess.CorrelationID,
		&createdAtS,
		&expiresAtS,
		&closedAtS,
		&sess.Cursor,
		&tagsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sess.CreatedAt, err = strToTime(createdAtS); err != nil {
		return nil, err
	}
	if sess.ExpiresAt, err = strToTime(expiresAtS); err != nil {
		return nil, err
	}
	if sess.ClosedAt, err = strToNullTime(closedAtS); err != nil {
		return nil, err
	}
	if tagsJSON != "" {
		if err = unmarshalJSON(tagsJSON, &sess.Tags); err != nil {
			return nil, err
		}
	}
	return &sess, nil
}

// ── Events ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveEvent(ctx context.Context, ev *Event) error {
	dataJSON, err := marshalJSON(ev.Data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events
			(event_id, session_id, tenant_id, received_at, protocol, src_ip, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.EventID,
		ev.SessionID,
		ev.TenantID,
		timeToStr(ev.ReceivedAt),
		ev.Protocol,
		ev.SrcIP,
		dataJSON,
	)
	return err
}

func (s *SQLiteStore) PollEvents(ctx context.Context, sessionID, tenantID, cursor string, limit int) ([]*Event, string, error) {
	// Verify session belongs to this tenant.
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE session_id = ? AND tenant_id = ?`,
		sessionID, tenantID,
	).Scan(&count)
	if err != nil {
		return nil, "", err
	}
	if count == 0 {
		return nil, "", ErrNotFound
	}

	// cursor format: received_at_rfc3339nano + "_" + event_id
	// Use string comparison on (received_at || '_' || event_id).
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, session_id, tenant_id, received_at, protocol, src_ip, data_json
		FROM events
		WHERE session_id = ? AND tenant_id = ?
		  AND (received_at || '_' || event_id) > ?
		ORDER BY received_at ASC, event_id ASC
		LIMIT ?`,
		sessionID, tenantID, cursor, limit,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, "", err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	var nextCursor string
	if len(events) == limit {
		last := events[len(events)-1]
		nextCursor = timeToStr(last.ReceivedAt) + "_" + last.EventID
	}
	return events, nextCursor, nil
}

func scanEvent(row scanner) (*Event, error) {
	var (
		ev          Event
		receivedAtS string
		dataJSON    string
	)
	err := row.Scan(
		&ev.EventID,
		&ev.SessionID,
		&ev.TenantID,
		&receivedAtS,
		&ev.Protocol,
		&ev.SrcIP,
		&dataJSON,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ev.ReceivedAt, err = strToTime(receivedAtS); err != nil {
		return nil, err
	}
	if dataJSON != "" {
		if err = unmarshalJSON(dataJSON, &ev.Data); err != nil {
			return nil, err
		}
	}
	return &ev, nil
}

// ── Token revocation ──────────────────────────────────────────────────────────

func (s *SQLiteStore) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO token_revocations (jti, revoked_at, expires_at)
		VALUES (?, ?, ?)`,
		jti,
		timeToStr(time.Now().UTC()),
		timeToStr(expiresAt),
	)
	return err
}

func (s *SQLiteStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM token_revocations WHERE jti = ?`, jti,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLiteStore) PruneRevocations(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM token_revocations WHERE expires_at <= ?`,
		timeToStr(time.Now().UTC()),
	)
	return err
}

// ── Agents ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) UpsertAgent(ctx context.Context, a *Agent) error {
	capsJSON, err := marshalJSON(a.Capabilities)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO agents
			(agent_id, tenant_id, name, registered_at, last_seen_at, capabilities_json, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.AgentID,
		a.TenantID,
		a.Name,
		timeToStr(a.RegisteredAt),
		nullTimeToStr(a.LastSeenAt),
		capsJSON,
		a.Status,
	)
	return err
}

func (s *SQLiteStore) GetAgent(ctx context.Context, agentID, tenantID string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT agent_id, tenant_id, name, registered_at, last_seen_at, capabilities_json, status
		FROM agents
		WHERE agent_id = ? AND tenant_id = ?`,
		agentID, tenantID,
	)
	return scanAgent(row)
}

func (s *SQLiteStore) ListAgents(ctx context.Context, tenantID string) ([]*Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT agent_id, tenant_id, name, registered_at, last_seen_at, capabilities_json, status
		FROM agents
		WHERE tenant_id = ?
		ORDER BY registered_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateAgentStatus(ctx context.Context, agentID, tenantID, status string, lastSeen time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE agents SET status = ?, last_seen_at = ?
		WHERE agent_id = ? AND tenant_id = ?`,
		status, timeToStr(lastSeen), agentID, tenantID,
	)
	return err
}

func scanAgent(row scanner) (*Agent, error) {
	var (
		a             Agent
		registeredAtS string
		lastSeenAtS   *string
		capsJSON      string
	)
	err := row.Scan(
		&a.AgentID,
		&a.TenantID,
		&a.Name,
		&registeredAtS,
		&lastSeenAtS,
		&capsJSON,
		&a.Status,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if a.RegisteredAt, err = strToTime(registeredAtS); err != nil {
		return nil, err
	}
	if a.LastSeenAt, err = strToNullTime(lastSeenAtS); err != nil {
		return nil, err
	}
	if capsJSON != "" {
		if err = unmarshalJSON(capsJSON, &a.Capabilities); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

// ── Tasks ─────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) EnqueueTask(ctx context.Context, t *Task) error {
	paramsJSON, err := marshalJSON(t.Params)
	if err != nil {
		return err
	}
	var resultJSON *string
	if t.Result != nil {
		rj, err := marshalJSON(t.Result)
		if err != nil {
			return err
		}
		resultJSON = &rj
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tasks
			(task_id, agent_id, tenant_id, scheduled_by, capability,
			 params_json, status, created_at, started_at, completed_at, result_json, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.TaskID,
		t.AgentID,
		t.TenantID,
		t.ScheduledBy,
		t.Capability,
		paramsJSON,
		t.Status,
		timeToStr(t.CreatedAt),
		nullTimeToStr(t.StartedAt),
		nullTimeToStr(t.CompletedAt),
		resultJSON,
		t.Err,
	)
	return err
}

func (s *SQLiteStore) DequeueTask(ctx context.Context, agentID, tenantID string) (*Task, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Find oldest pending task for this agent, scoped to its tenant.
	var taskID string
	err = tx.QueryRowContext(ctx, `
		SELECT task_id FROM tasks
		WHERE agent_id = ? AND tenant_id = ? AND status = 'pending'
		ORDER BY created_at ASC
		LIMIT 1`,
		agentID, tenantID,
	).Scan(&taskID)
	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Claim it.
	now := timeToStr(time.Now().UTC())
	_, err = tx.ExecContext(ctx, `
		UPDATE tasks SET status = 'running', started_at = ?
		WHERE task_id = ? AND status = 'pending'`,
		now, taskID,
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Re-read the updated task, scoped to both task_id and agent_id so that
	// no cross-agent (and therefore no cross-tenant) row can be returned.
	row := s.db.QueryRowContext(ctx, `
		SELECT task_id, agent_id, tenant_id, scheduled_by, capability,
		       params_json, status, created_at, started_at, completed_at, result_json, error
		FROM tasks
		WHERE task_id = ? AND agent_id = ?`,
		taskID, agentID,
	)
	return scanTask(row)
}

func (s *SQLiteStore) UpdateTask(ctx context.Context, t *Task) error {
	paramsJSON, err := marshalJSON(t.Params)
	if err != nil {
		return err
	}
	var resultJSON *string
	if t.Result != nil {
		rj, err := marshalJSON(t.Result)
		if err != nil {
			return err
		}
		resultJSON = &rj
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tasks
		SET status = ?, started_at = ?, completed_at = ?,
		    result_json = ?, error = ?, params_json = ?
		WHERE task_id = ? AND tenant_id = ?`,
		t.Status,
		nullTimeToStr(t.StartedAt),
		nullTimeToStr(t.CompletedAt),
		resultJSON,
		t.Err,
		paramsJSON,
		t.TaskID,
		t.TenantID,
	)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *SQLiteStore) GetTask(ctx context.Context, taskID, tenantID string) (*Task, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT task_id, agent_id, tenant_id, scheduled_by, capability,
		       params_json, status, created_at, started_at, completed_at, result_json, error
		FROM tasks
		WHERE task_id = ? AND tenant_id = ?`,
		taskID, tenantID,
	)
	return scanTask(row)
}

func (s *SQLiteStore) ListTasks(ctx context.Context, agentID, tenantID string) ([]*Task, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT task_id, agent_id, tenant_id, scheduled_by, capability,
		       params_json, status, created_at, started_at, completed_at, result_json, error
		FROM tasks
		WHERE agent_id = ? AND tenant_id = ?
		ORDER BY created_at DESC`,
		agentID, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanTask(row scanner) (*Task, error) {
	var (
		t            Task
		createdAtS   string
		startedAtS   *string
		completedAtS *string
		paramsJSON   string
		resultJSON   *string
	)
	err := row.Scan(
		&t.TaskID,
		&t.AgentID,
		&t.TenantID,
		&t.ScheduledBy,
		&t.Capability,
		&paramsJSON,
		&t.Status,
		&createdAtS,
		&startedAtS,
		&completedAtS,
		&resultJSON,
		&t.Err,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.CreatedAt, err = strToTime(createdAtS); err != nil {
		return nil, err
	}
	if t.StartedAt, err = strToNullTime(startedAtS); err != nil {
		return nil, err
	}
	if t.CompletedAt, err = strToNullTime(completedAtS); err != nil {
		return nil, err
	}
	if paramsJSON != "" {
		if err = unmarshalJSON(paramsJSON, &t.Params); err != nil {
			return nil, err
		}
	}
	if resultJSON != nil && *resultJSON != "" {
		if err = unmarshalJSON(*resultJSON, &t.Result); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

// ── OAST session restore ──────────────────────────────────────────────────────

// RestoreOASTSessions returns the minimal corrID→session mapping for all
// sessions that are not yet closed and not yet expired. It is intentionally
// NOT on the Store interface — it is a privileged infrastructure operation
// called only by the server process at startup to repopulate the in-memory
// Native.sessions map after a restart.
func (s *SQLiteStore) RestoreOASTSessions(ctx context.Context) ([]SessionRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT correlation_id, session_id, tenant_id
		FROM sessions
		WHERE closed_at IS NULL
		  AND expires_at > ?`,
		timeToStr(time.Now().UTC()),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionRef
	for rows.Next() {
		var ref SessionRef
		if err := rows.Scan(&ref.CorrelationID, &ref.SessionID, &ref.TenantID); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// ── Maintenance ───────────────────────────────────────────────────────────────

func (s *SQLiteStore) PurgeExpired(ctx context.Context, sessionTTL, eventTTL time.Duration) error {
	now := time.Now().UTC()
	eventCutoff := timeToStr(now.Add(-eventTTL))

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM sessions WHERE expires_at < ?`,
		timeToStr(now),
	); err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM events WHERE received_at < ?`,
		eventCutoff,
	); err != nil {
		return err
	}

	return nil
}

// ── requireAffected ───────────────────────────────────────────────────────────

func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
