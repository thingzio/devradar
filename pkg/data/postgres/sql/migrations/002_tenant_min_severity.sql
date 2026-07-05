-- Per-tenant minimum severity of interest. Drives the default severity filter on
-- the read API (and, post-MVP, alerting). Findings are always stored at every
-- severity; this is a view/policy knob, not a write-time filter. 'unknown' is
-- always included regardless of this setting (an unrated CVE could be anything).
ALTER TABLE devradar_tenant
    ADD COLUMN IF NOT EXISTS min_severity TEXT NOT NULL DEFAULT 'medium';
