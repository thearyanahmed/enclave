-- Rate limits table for distributed rate limiting
-- Used by PostgresRateLimitStore when rate_limit + sqlx_postgres features are enabled

CREATE TABLE IF NOT EXISTS rate_limits (
    key VARCHAR(255) PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 1,
    reset_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for cleanup of expired entries
CREATE INDEX idx_rate_limits_reset_at ON rate_limits(reset_at);

-- Comment for documentation
COMMENT ON TABLE rate_limits IS 'Rate limit tracking for distributed rate limiting';
COMMENT ON COLUMN rate_limits.key IS 'Rate limit key (e.g., "api:192.168.1.1" or "login:user@example.com")';
COMMENT ON COLUMN rate_limits.attempts IS 'Number of attempts in the current window';
COMMENT ON COLUMN rate_limits.reset_at IS 'When the current rate limit window expires';
