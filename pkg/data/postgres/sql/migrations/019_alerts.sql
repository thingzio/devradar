-- Tenant-scoped browser alert policy. One policy per tenant in the first
-- release; future delivery channels consume the alerts this policy creates.
CREATE TABLE IF NOT EXISTS devradar_alert_policy (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL UNIQUE REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    enabled             BOOLEAN NOT NULL DEFAULT false,
    min_severity        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'negligible')),
    alert_kev           BOOLEAN NOT NULL DEFAULT true,
    alert_fix_available BOOLEAN NOT NULL DEFAULT true,
    include_image       BOOLEAN NOT NULL DEFAULT true,
    include_db          BOOLEAN NOT NULL DEFAULT true,
    labels              TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Channel-neutral alert facts. event_occurred_at is retained with event_id
-- because the source event table is range-partitioned by occurred_at.
CREATE TABLE IF NOT EXISTS devradar_alert (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    policy_id         UUID NOT NULL REFERENCES devradar_alert_policy(id) ON DELETE CASCADE,
    event_id          BIGINT NOT NULL,
    event_occurred_at TIMESTAMPTZ NOT NULL,
    alert_kind        TEXT NOT NULL
                      CHECK (alert_kind IN ('new_kev', 'new_finding', 'fix_available', 'posture_regression')),
    sbom_id           TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    repository        TEXT NOT NULL,
    digest            TEXT NOT NULL,
    finding_id        TEXT NOT NULL,
    exposure          TEXT NOT NULL,
    package           TEXT NOT NULL,
    version           TEXT NOT NULL,
    severity          TEXT NOT NULL,
    score             REAL NOT NULL,
    cause             TEXT NOT NULL CHECK (cause IN ('image', 'db')),
    read_at           TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, policy_id, event_id, event_occurred_at, alert_kind)
);
CREATE INDEX IF NOT EXISTS idx_devradar_alert_tenant_time
    ON devradar_alert (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_devradar_alert_tenant_unread
    ON devradar_alert (tenant_id, created_at DESC) WHERE read_at IS NULL;

-- Global consumer cursor over the append-only finding event stream. The tuple
-- ordering is stable when multiple events share one scan timestamp.
CREATE TABLE IF NOT EXISTS devradar_alert_cursor (
    consumer         TEXT PRIMARY KEY,
    last_occurred_at TIMESTAMPTZ NOT NULL,
    last_event_id    BIGINT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A malformed source event is isolated and recorded instead of wedging the
-- cursor. The natural key makes retrying the same batch idempotent.
CREATE TABLE IF NOT EXISTS devradar_alert_failure (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    consumer          TEXT NOT NULL,
    event_id          BIGINT NOT NULL,
    event_occurred_at TIMESTAMPTZ NOT NULL,
    error             TEXT NOT NULL,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (consumer, event_id, event_occurred_at)
);
