-- Optional profile avatar for the tenant, captured from an OAuth provider at
-- sign-in (GitHub's avatar_url). Purely cosmetic (the nav shows it instead of
-- the email initial); NULL for email-only tenants, so the UI falls back to the
-- initial. Refreshed on each OAuth sign-in since the provider avatar can change.
ALTER TABLE devradar_tenant
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;
