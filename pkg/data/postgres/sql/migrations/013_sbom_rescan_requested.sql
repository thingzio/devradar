-- Operator-requested rescan marker. The scan job's work selection
-- (ListScannableSBOMs) normally makes an SBOM due only when its most recent
-- scan_run is older than the staleness window. The admin console's "force
-- rescan" sets this to now(); ListScannableSBOMs also treats a non-NULL marker
-- as due, so the SBOM is picked up on the next scheduler tick regardless of how
-- recently it was scanned. ApplyScan clears it after a successful run, so the
-- override fires exactly once (no cross-process job invocation from the serve
-- image, which carries no scanner binaries).
ALTER TABLE devradar_sbom
    ADD COLUMN IF NOT EXISTS rescan_requested_at TIMESTAMPTZ;
