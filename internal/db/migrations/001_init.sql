CREATE TABLE IF NOT EXISTS auth_events (
    id         BIGSERIAL PRIMARY KEY,
    user_id    TEXT        NOT NULL,
    ip_address INET        NOT NULL,
    event_type TEXT        NOT NULL,
    status     TEXT        NOT NULL,
    user_agent TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_events_ip_address ON auth_events (ip_address);
CREATE INDEX idx_auth_events_user_id    ON auth_events (user_id);
CREATE INDEX idx_auth_events_created_at ON auth_events (created_at DESC);

-- Composite index for the suspicious IP query (failed logins by IP in a time window)
CREATE INDEX idx_auth_events_status_ip_created
    ON auth_events (status, ip_address, created_at DESC);
