-- CVE risk enrichment: EPSS (exploit probability) + CISA KEV (known-exploited).
-- CVE-keyed reference data, shared across every finding that references the CVE —
-- an OVERLAY joined at read time, never written into devradar_finding, so the
-- deterministic scan pipeline (same SBOM + same DB -> same findings) is untouched.
-- Refreshed daily by the scan job from authoritative public feeds.
CREATE TABLE IF NOT EXISTS devradar_cve_enrichment (
    cve             TEXT PRIMARY KEY,                    -- e.g. CVE-2025-68121
    epss_score      REAL,                                -- [0,1] 30-day exploit probability (FIRST.org)
    epss_percentile REAL,                                -- [0,1] percentile among all CVEs
    kev             BOOLEAN NOT NULL DEFAULT false,      -- present in CISA KEV catalog
    kev_added       DATE,                                -- CISA date_added
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index: the dashboard/fleet "any KEV?" checks only care about the true rows.
CREATE INDEX IF NOT EXISTS idx_devradar_cve_enrichment_kev
    ON devradar_cve_enrichment(cve) WHERE kev;
