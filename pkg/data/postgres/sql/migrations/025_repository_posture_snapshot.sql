-- Daily repository posture snapshots retain observed per-repository debt without
-- reconstructing history from mutable current findings.
CREATE TABLE IF NOT EXISTS devradar_repository_posture_snapshot (
    tenant_id          UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    repository         TEXT NOT NULL,
    snapshot_date      DATE NOT NULL,
    images             INT NOT NULL DEFAULT 1,
    relevant_findings  INT NOT NULL DEFAULT 0,
    critical           INT NOT NULL DEFAULT 0,
    high               INT NOT NULL DEFAULT 0,
    medium             INT NOT NULL DEFAULT 0,
    low                INT NOT NULL DEFAULT 0,
    fixable             INT NOT NULL DEFAULT 0,
    kev                 INT NOT NULL DEFAULT 0,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, repository, snapshot_date)
);
