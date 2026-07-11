-- One-time flash storage for a freshly-minted API token.
--
-- The raw API token is shown to the user exactly once, right after creation.
-- Previously it was passed back in a redirect URL (/tokens?new=<token>), which
-- leaks the secret into browser history, the Referer header, access logs, and
-- observability tooling. Instead we stash it server-side keyed to the tenant,
-- redirect to a clean /tokens, and the page reads-and-deletes it on render.
--
-- Single-use and short-lived: the row is deleted when read (delete-and-return)
-- and expires after a couple of minutes regardless, so an unread flash cannot
-- linger. One outstanding flash per tenant (PK on tenant_id): creating a new
-- token overwrites any prior unread flash, which is the desired behavior.
-- Idempotent.
CREATE TABLE IF NOT EXISTS devradar_token_flash (
    tenant_id  UUID PRIMARY KEY REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    value      TEXT NOT NULL,                    -- the raw "dr_..." token, shown once
    expires_at TIMESTAMPTZ NOT NULL
);
