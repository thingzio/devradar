-- Daily tenant posture snapshots preserve exact vulnerability debt over time.
-- Current findings are mutable, so historical fleet posture cannot be derived
-- after the fact. One row per tenant and date makes same-day retries idempotent.
CREATE TABLE IF NOT EXISTS devradar_tenant_posture_snapshot (
    tenant_id          UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    snapshot_date      DATE NOT NULL,
    images             INT NOT NULL DEFAULT 0,
    relevant_findings  INT NOT NULL DEFAULT 0,
    critical           INT NOT NULL DEFAULT 0,
    high               INT NOT NULL DEFAULT 0,
    medium             INT NOT NULL DEFAULT 0,
    low                INT NOT NULL DEFAULT 0,
    fixable             INT NOT NULL DEFAULT 0,
    kev                 INT NOT NULL DEFAULT 0,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, snapshot_date)
);
