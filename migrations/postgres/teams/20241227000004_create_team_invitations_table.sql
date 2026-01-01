CREATE TABLE team_invitations (
    id BIGSERIAL PRIMARY KEY,
    team_id BIGINT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email VARCHAR(254) NOT NULL,
    role VARCHAR(50) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    invited_by BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_team_invitations_team_id ON team_invitations(team_id);
CREATE INDEX idx_team_invitations_email ON team_invitations(email);
CREATE INDEX idx_team_invitations_token_hash ON team_invitations(token_hash);
