CREATE TABLE email_verification_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_verification_tokens_token_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
