ALTER TABLE tasks ADD COLUMN timeout_at TEXT;
ALTER TABLE tasks ADD COLUMN timeout_secs INTEGER NOT NULL DEFAULT 600;
CREATE INDEX IF NOT EXISTS idx_task_timeout ON tasks(timeout_at) WHERE status IN ('pending','running');
