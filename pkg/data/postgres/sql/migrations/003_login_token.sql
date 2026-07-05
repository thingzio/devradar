-- Magic-link login tokens. A short-TTL, single-use token emailed to a would-be
-- tenant; consuming it authenticates them and mints a session. Only the SHA-256
-- hash is stored (like sessions and API tokens) — the raw token lives only in
-- the emailed link. Rows are deleted on consume and expire by TTL.
CREATE TABLE IF NOT EXISTS devradar_login_token (
    id          TEXT PRIMARY KEY,                      -- hex SHA-256 of the raw token
    email       TEXT NOT NULL,                         -- the address the link was sent to
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devradar_login_token_expires ON devradar_login_token(expires_at);
