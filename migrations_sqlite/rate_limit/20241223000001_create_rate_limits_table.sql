-- Rate limits table for distributed rate limiting
-- Used by SqliteRateLimitStore when rate_limit + sqlx_sqlite features are enabled

CREATE TABLE rate_limits (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 1,
    reset_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Index for cleanup of expired entries
CREATE INDEX idx_rate_limits_reset_at ON rate_limits(reset_at);
