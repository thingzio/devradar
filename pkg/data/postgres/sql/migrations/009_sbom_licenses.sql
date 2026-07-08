-- License inventory + compliance policy. Licenses are a property of an SBOM's
-- FROZEN per-digest inventory (immutable once submitted), not of the daily
-- scanner delta — so they are captured once at ingest and never flow through
-- ApplyScan. Classification into categories (permissive/copyleft/…) and policy
-- evaluation happen in Go at READ time over the raw IDs stored here, so a
-- taxonomy or policy change re-applies instantly without touching frozen data.
-- All statements idempotent (mirrors 005/008).

-- One row per catalogued package per SBOM. Written once at ingest (inventory is
-- immutable), so the natural key is (sbom_id, package, version). The full license
-- set is preserved as an array — multi-license packages and SPDX expressions are
-- kept verbatim; DevRadar never collapses to a single "winner".
CREATE TABLE IF NOT EXISTS devradar_sbom_package (
    sbom_id  TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    package  TEXT NOT NULL,
    version  TEXT NOT NULL DEFAULT '',
    purl     TEXT NOT NULL DEFAULT '',
    licenses TEXT[] NOT NULL DEFAULT '{}',   -- raw SPDX IDs / names / expressions
    PRIMARY KEY (sbom_id, package, version)
);
-- Serves the per-SBOM license read and (joined to devradar_sbom) the fleet
-- rollup; GIN over the array makes "images that use license X" cheap later.
CREATE INDEX IF NOT EXISTS idx_devradar_sbom_package_licenses
    ON devradar_sbom_package USING GIN (licenses);

-- Per-tenant compliance policy. Opt-in: a tenant with no row (or an all-empty
-- row) denies nothing — DevRadar is descriptive by default. denied_categories
-- names LicenseCategory values (permissive|weak-copyleft|strong-copyleft|
-- proprietary|unknown); the exception arrays carry specific license IDs that
-- override the category decision either way.
CREATE TABLE IF NOT EXISTS devradar_license_policy (
    tenant_id         UUID PRIMARY KEY REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    denied_categories TEXT[] NOT NULL DEFAULT '{}',
    allow_exceptions  TEXT[] NOT NULL DEFAULT '{}',  -- license IDs permitted despite denied category
    deny_exceptions   TEXT[] NOT NULL DEFAULT '{}',  -- license IDs always flagged
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
