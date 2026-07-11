-- Per-SBOM severity rollup: a derived cache that collapses "aggregate the
-- tenant's entire finding set on every dashboard load" into "sum a handful of
-- rows". The dashboard/fleet-stats read paths re-counted devradar_finding
-- (tens of thousands of rows for a large tenant) on every request; pagination
-- capped the output rows, not the aggregation. This table holds one row per
-- SBOM with RAW counts (no VEX suppression), maintained inside ApplyScan's
-- transaction so it can never diverge from devradar_finding on a crash.
--
-- Counts are cross-scanner-deduped: a CVE found by both grype and trivy shares
-- one finding_id and counts once (COUNT(DISTINCT finding_id) scoped to the
-- SBOM). VEX suppression is NOT baked in — it is applied at read time only for
-- the rare tenants that have suppressing statements, so this table never goes
-- stale on a VEX upload. Archived SBOMs keep their row; every read path filters
-- devradar_sbom.status = 'active', so a stale row is harmless. A hard delete
-- cascades via the FK.
CREATE TABLE IF NOT EXISTS devradar_sbom_rollup (
    sbom_id      TEXT PRIMARY KEY REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    critical     INT NOT NULL DEFAULT 0,
    high         INT NOT NULL DEFAULT 0,
    medium       INT NOT NULL DEFAULT 0,
    low          INT NOT NULL DEFAULT 0,
    negligible   INT NOT NULL DEFAULT 0,
    unknown      INT NOT NULL DEFAULT 0,
    total        INT NOT NULL DEFAULT 0,
    fixable      INT NOT NULL DEFAULT 0,
    fix_critical INT NOT NULL DEFAULT 0,
    fix_high     INT NOT NULL DEFAULT 0,
    fix_medium   INT NOT NULL DEFAULT 0,
    fix_low      INT NOT NULL DEFAULT 0,
    kev          INT NOT NULL DEFAULT 0,               -- distinct KEV CVEs (raw, no VEX)
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time backfill: aggregate every existing SBOM's findings. Same expression
-- as the ApplyScan maintenance path, grouped. Runs cross-tenant under the
-- migration advisory lock. SBOMs with zero findings get no row — the read paths
-- LEFT JOIN + COALESCE, so a missing row reads as zero. ON CONFLICT DO NOTHING
-- so a scan that races ahead of this backfill (writing via DO UPDATE) wins.
INSERT INTO devradar_sbom_rollup (
    sbom_id, critical, high, medium, low, negligible, unknown, total,
    fixable, fix_critical, fix_high, fix_medium, fix_low, kev, updated_at)
SELECT
    f.sbom_id,
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'critical'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'high'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'medium'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'low'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'negligible'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'unknown'),
    COUNT(DISTINCT f.finding_id),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'critical'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'high'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'medium'),
    COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'low'),
    COUNT(DISTINCT f.exposure) FILTER (WHERE e.kev),
    now()
FROM devradar_finding f
LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
GROUP BY f.sbom_id
ON CONFLICT (sbom_id) DO NOTHING;

-- Fast gate for the read-time VEX branch: "does this tenant have any suppressing
-- statement?". Suppressing statuses only (not_affected|fixed) — an affected or
-- under_investigation statement doesn't hide a finding, so it stays on the
-- rollup fast path. A partial index makes the EXISTS check sub-millisecond.
CREATE INDEX IF NOT EXISTS idx_devradar_vex_stmt_suppressing
    ON devradar_vex_statement(tenant_id)
    WHERE status IN ('not_affected', 'fixed');
