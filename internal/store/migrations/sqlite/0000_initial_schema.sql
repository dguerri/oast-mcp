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
