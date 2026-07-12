-- Hot-path indexes surfaced by the 2026-07-12 review (B2, B3).
--
-- B2: failure counts are computed as a per-row correlated subquery keyed on
-- sbom_id in the busiest list queries (ListImages, ListRepoImages, FleetStats),
-- and FailuresBySBOM filters sbom_id directly — but the only index on
-- devradar_scan_failure was on occurred_at. Each dashboard/image-list load did N
-- sequential scans of a forever-growing table.
CREATE INDEX IF NOT EXISTS idx_devradar_scan_failure_sbom
    ON devradar_scan_failure (sbom_id);

-- B3: EventsBySBOM filters devradar_finding_event by sbom_id ordered by
-- (occurred_at DESC, id DESC), but every existing index on the partitioned event
-- log leads with tenant_id / occurred_at / cause — none with sbom_id. The
-- per-SBOM /events endpoint therefore scanned every monthly partition (retained
-- forever) plus a sort. This composite serves both the filter and the sort, and
-- PostgreSQL propagates it to each partition.
CREATE INDEX IF NOT EXISTS idx_devradar_fe_sbom_time
    ON devradar_finding_event (sbom_id, occurred_at DESC, id DESC);

-- C6: optional API-token expiry. Nullable so existing tokens (and tokens minted
-- without a TTL) never expire — this is a non-breaking opt-in. ValidateAPIToken
-- rejects a token once expires_at has passed.
ALTER TABLE devradar_api_token
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
