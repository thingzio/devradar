-- External sign-in identities. A tenant's identity is still a verified email
-- (devradar_tenant.email), but that email can be proven by more than one method:
-- the magic-link flow ('magiclink') or an OAuth provider ('github', later
-- 'google', ...). This table maps a provider's stable per-user subject to a
-- tenant so the same person resolves to one tenant regardless of how they signed
-- in. There is deliberately NO account-linking UI in v1: two providers reporting
-- two different verified emails yield two tenants (the email is the join key).
--
-- subject is the provider's immutable user id:
--   magiclink → the verified email (email IS the subject)
--   github    → the numeric GitHub user id as text (NOT the login/username,
--               which is renamable and reusable)
CREATE TABLE IF NOT EXISTS devradar_identity (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,                          -- 'magiclink' | 'github'
    subject    TEXT NOT NULL,                          -- provider's stable user id
    email      TEXT NOT NULL,                          -- verified email at link time (audit/display)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_devradar_identity_tenant ON devradar_identity(tenant_id);

-- Backfill: every existing tenant reached DevRadar via the magic-link flow, so
-- model that as a magiclink identity keyed on their email. Idempotent.
INSERT INTO devradar_identity (tenant_id, provider, subject, email)
SELECT id, 'magiclink', email, email FROM devradar_tenant
ON CONFLICT (provider, subject) DO NOTHING;
