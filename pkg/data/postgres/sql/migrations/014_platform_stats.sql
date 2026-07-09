-- Daily platform snapshot backing the admin dashboard's DoD/WoW/MoM deltas.
-- One row per UTC date, written on each dashboard visit and once per scan-job
-- run (UPSERT — last write of the day wins). This is what makes point-in-time
-- deltas honest: metrics like "open findings" cannot be reconstructed from
-- current state after the fact (devradar_finding is UPSERT-only, no history),
-- so we record the actual value each day and compare snapshots. Cumulative
-- metrics (tenants, SBOMs) could be derived live, but keeping them here too
-- means the dashboard reads one row per comparison point instead of many
-- aggregates. Additive and reversible: dropping this table only removes deltas.
CREATE TABLE IF NOT EXISTS devradar_platform_stats (
    snapshot_date   DATE PRIMARY KEY,                 -- UTC date; one row/day
    tenants         INT NOT NULL DEFAULT 0,
    sboms_active    INT NOT NULL DEFAULT 0,
    unique_digests  INT NOT NULL DEFAULT 0,
    open_findings   INT NOT NULL DEFAULT 0,
    critical_open   INT NOT NULL DEFAULT 0,
    high_open       INT NOT NULL DEFAULT 0,
    vex_statements  INT NOT NULL DEFAULT 0,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now() -- last write within the day
);
