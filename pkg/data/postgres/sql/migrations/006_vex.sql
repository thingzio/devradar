-- VEX (Vulnerability Exploitability eXchange) ingestion. Tenants post OpenVEX
-- documents asserting whether a present CVE actually affects a given image
-- version. This is an OVERLAY: findings are never mutated; suppression is applied
-- by joining the latest statement at read time. A tenant's VEX is their
-- assertion (unverified, like the SBOM) — DevRadar records it, never blesses it.
CREATE TABLE IF NOT EXISTS devradar_vex_document (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    author     TEXT,
    statements INT NOT NULL DEFAULT 0,          -- count parsed from the doc
    matched    INT NOT NULL DEFAULT 0,          -- statements that hit a known finding
    document   JSONB NOT NULL,                  -- raw OpenVEX, for round-trip/download
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devradar_vex_statement (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    document_id      UUID NOT NULL REFERENCES devradar_vex_document(id) ON DELETE CASCADE,
    product_digest   TEXT NOT NULL,             -- sha256:...; scopes to one image version
    vulnerability    TEXT NOT NULL,             -- CVE id
    subcomponent     TEXT,                      -- purl; NULL = whole product (v1 matches at product+cve)
    status           TEXT NOT NULL,             -- not_affected | affected | fixed | under_investigation
    justification    TEXT,                      -- required by spec when not_affected
    impact_statement TEXT,
    timestamp        TIMESTAMPTZ,               -- statement timestamp from the doc, if present
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The suppression join keys on (tenant, digest, cve); newest statement wins.
CREATE INDEX IF NOT EXISTS idx_devradar_vex_stmt_lookup
    ON devradar_vex_statement(tenant_id, product_digest, vulnerability, created_at DESC);
