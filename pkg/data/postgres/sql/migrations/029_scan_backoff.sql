-- Per-(SBOM, scanner) failure backoff state. Without this, a scanner that
-- persistently fails on one SBOM (a poison/pathological input, or a converter
-- regression) is retried on EVERY scheduler tick — every ~15 min, forever — and
-- because work selection is per-SBOM, the healthy scanner is re-run alongside it
-- each time too. This table records consecutive failures and a next-attempt time
-- so a failing (SBOM, scanner) pair backs off exponentially and is quarantined
-- after a threshold, while a success clears the row (deleted) so the steady state
-- carries no rows at all.
CREATE TABLE IF NOT EXISTS devradar_scan_attempt (
    sbom_id         TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner         TEXT NOT NULL,
    fail_count      INTEGER NOT NULL DEFAULT 0,   -- consecutive failures
    quarantined     BOOLEAN NOT NULL DEFAULT false, -- past the threshold: stop auto-retrying
    last_error      TEXT,                          -- most recent failure summary
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- earliest time to retry
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sbom_id, scanner)
);

-- Cheap lookup of "is this pair currently backing off?" during the scan loop.
CREATE INDEX IF NOT EXISTS idx_devradar_scan_attempt_next
    ON devradar_scan_attempt (sbom_id, scanner, next_attempt_at);
