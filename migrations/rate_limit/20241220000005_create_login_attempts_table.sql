CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_email ON login_attempts(email);
CREATE INDEX idx_login_attempts_attempted_at ON login_attempts(attempted_at);
