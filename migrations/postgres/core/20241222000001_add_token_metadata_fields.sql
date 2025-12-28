-- Add Sanctum-like fields to access_tokens
ALTER TABLE access_tokens ADD COLUMN name VARCHAR(255);
ALTER TABLE access_tokens ADD COLUMN abilities JSONB NOT NULL DEFAULT '["*"]';
ALTER TABLE access_tokens ADD COLUMN last_used_at TIMESTAMPTZ;

-- Index for pruning expired tokens
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);
