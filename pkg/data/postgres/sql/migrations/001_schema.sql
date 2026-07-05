-- DevRadar schema (squashed). All statements are idempotent (IF NOT EXISTS) so
-- the migration runner can re-apply safely. Every object is prefixed devradar_
-- (indexes idx_devradar_*) so nothing collides with devpulse_* / devtrace_* in
-- the shared `thingz` database. Tenant isolation is application-level
-- (WHERE tenant_id = $1); there is deliberately no RLS.

CREATE TABLE IF NOT EXISTS devradar_schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Identity & auth ───────────────────────────────────────────────────────────

-- A tenant is a GitHub identity. Owns SBOMs, API tokens, and alert routing.
CREATE TABLE IF NOT EXISTS devradar_tenant (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id       BIGINT NOT NULL UNIQUE,
    username        TEXT NOT NULL,
    email           TEXT,                              -- alert destination
    avatar_url      TEXT,
    plan            TEXT NOT NULL DEFAULT 'free',
    status          TEXT NOT NULL DEFAULT 'active',    -- active | suspended
    tos_accepted_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devradar_tenant_username ON devradar_tenant(username);

-- Browser sessions minted by the UI after GitHub OAuth. id = hex SHA-256(token).
CREATE TABLE IF NOT EXISTS devradar_session (
    id         TEXT PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devradar_session_tenant ON devradar_session(tenant_id);
CREATE INDEX IF NOT EXISTS idx_devradar_session_expires ON devradar_session(expires_at);

-- API tokens minted in the UI, used by CI to submit SBOMs. Only the hash stored.
CREATE TABLE IF NOT EXISTS devradar_api_token (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,                        -- human label, e.g. "ci-prod"
    token_hash   TEXT NOT NULL UNIQUE,                 -- hex SHA-256 of the "dr_..." token
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devradar_api_token_tenant ON devradar_api_token(tenant_id);

-- ── Core domain ───────────────────────────────────────────────────────────────

-- One row per unique submitted SBOM. Content-addressed (id = sha256 of bytes),
-- digest-pinned, immutable. Bytes live in GCS; this is the index over them.
CREATE TABLE IF NOT EXISTS devradar_sbom (
    id                  TEXT PRIMARY KEY,              -- sha256 of raw bytes
    tenant_id           UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    image_ref           TEXT NOT NULL,                 -- may be a private registry
    digest              TEXT NOT NULL,                 -- sha256:...
    format              TEXT NOT NULL,                 -- cyclonedx | spdx
    spec_version        TEXT NOT NULL DEFAULT '',
    tool                TEXT,                          -- generator, e.g. "syft"
    tool_version        TEXT,                          -- bounds cataloging freshness
    package_count       INT NOT NULL DEFAULT 0,        -- for the zero-findings tripwire
    object_path         TEXT NOT NULL,                 -- gs://.../{tenant}/{id}
    verification_status TEXT NOT NULL DEFAULT 'unverified', -- unverified | attested
    status              TEXT NOT NULL DEFAULT 'active',     -- active | archived
    generated_at        TIMESTAMPTZ,                   -- from SBOM; NULL → see submitted_at
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, digest, format)
);
CREATE INDEX IF NOT EXISTS idx_devradar_sbom_active ON devradar_sbom(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_devradar_sbom_image_ref ON devradar_sbom(tenant_id, image_ref);

-- One row per SBOM per scanner per run. Records all four version axes that
-- determine a finding set, so every result is reproducible and every change is
-- attributable to exactly one cause.
CREATE TABLE IF NOT EXISTS devradar_scan_run (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id               TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner               TEXT NOT NULL,               -- grype | trivy
    db_version            TEXT NOT NULL,               -- vuln DB snapshot (changes ~daily)
    scanner_version       TEXT NOT NULL,               -- scanner binary (matcher logic)
    canonicalizer_version TEXT NOT NULL,               -- SPDX->CDX converter identity
    scanned_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    finding_count  INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count     INT NOT NULL DEFAULT 0,
    medium_count   INT NOT NULL DEFAULT 0,
    low_count      INT NOT NULL DEFAULT 0,
    UNIQUE (sbom_id, scanner, db_version, scanner_version, scanned_at)
);
CREATE INDEX IF NOT EXISTS idx_devradar_scan_run_sbom ON devradar_scan_run(sbom_id, scanner, scanned_at DESC);

-- CURRENT state: one row per unique finding per (sbom, scanner). UPSERT target.
-- Bounded — it only ever holds the latest known findings, never history.
CREATE TABLE IF NOT EXISTS devradar_finding (
    sbom_id     TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner     TEXT NOT NULL,
    finding_id  TEXT NOT NULL,                         -- data.Vulnerability.GetID()
    exposure    TEXT NOT NULL,                         -- CVE-...
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    score       REAL NOT NULL,
    is_fixed    BOOLEAN NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sbom_id, scanner, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_devradar_finding_exposure ON devradar_finding(exposure);
CREATE INDEX IF NOT EXISTS idx_devradar_finding_severity ON devradar_finding(severity);

-- APPEND-ONLY change log. The delta history and the alert source. A row exists
-- ONLY when a finding changed. Partitioned monthly by occurred_at, retained
-- forever. Each event carries the cause (image|db|tooling) and the version axes
-- that produced it.
CREATE TABLE IF NOT EXISTS devradar_finding_event (
    id              BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id       UUID NOT NULL,                     -- denormalized for per-tenant queries + alerting
    sbom_id         TEXT NOT NULL,
    scanner         TEXT NOT NULL,
    finding_id      TEXT NOT NULL,
    event_type      TEXT NOT NULL,                     -- added | resolved | rerated | fixed
    exposure        TEXT NOT NULL,
    package         TEXT NOT NULL,
    version         TEXT NOT NULL,
    severity        TEXT NOT NULL,                     -- severity at event time
    score           REAL NOT NULL,
    prev_severity   TEXT,                              -- for rerated
    prev_score      REAL,
    cause           TEXT NOT NULL,                     -- image | db | tooling
    db_version      TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    scan_run_id     UUID NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (sbom_id, scanner, finding_id, event_type, db_version, scanner_version, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Initial monthly partitions. A scheduled job (or pg_partman) creates future
-- ones ahead of time; a DEFAULT partition catches anything that slips through.
CREATE TABLE IF NOT EXISTS devradar_finding_event_2026_07 PARTITION OF devradar_finding_event
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS devradar_finding_event_2026_08 PARTITION OF devradar_finding_event
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS devradar_finding_event_default PARTITION OF devradar_finding_event DEFAULT;

CREATE INDEX IF NOT EXISTS idx_devradar_fe_tenant_time
    ON devradar_finding_event(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_devradar_fe_alerting
    ON devradar_finding_event(tenant_id, event_type, severity, occurred_at DESC)
    WHERE cause IN ('image', 'db');

-- Failure surface: per-SBOM/per-scanner errors, not swallowed. Drives ops alerts.
CREATE TABLE IF NOT EXISTS devradar_scan_failure (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sbom_id     TEXT NOT NULL,
    scanner     TEXT,
    stage       TEXT NOT NULL,                         -- download|canonicalize|scan|parse|detect|convert|zero-findings|persist
    error       TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devradar_scan_failure_time ON devradar_scan_failure(occurred_at DESC);
