-- Cryptographic attestation-verification evidence. When a tenant submits an
-- SBOM together with a sigstore/cosign attestation, DevRadar verifies the
-- signature (keyless via Fulcio identity/issuer + Rekor, or a configured public
-- key) and binds it to the SBOM's subject digest. Unlike VEX, this is a
-- DevRadar-performed cryptographic check, not a tenant assertion: the row is the
-- durable, auditable evidence for every verification decision (an expanded
-- status flag alone is insufficient). devradar_sbom.verification_status carries
-- the denormalized outcome (unverified | verified | failed) as a fast path.
CREATE TABLE IF NOT EXISTS devradar_sbom_attestation (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id              TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    tenant_id            UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    result               TEXT NOT NULL CHECK (result IN ('verified', 'failed')),
    mode                 TEXT NOT NULL CHECK (mode IN ('keyless', 'key')),
    binding              TEXT NOT NULL CHECK (binding IN ('sbom-bytes', 'image-digest')),
    subject_digest       TEXT NOT NULL,             -- digest that was cryptographically bound
    predicate_type       TEXT,                      -- observed in-toto predicate type
    cert_identity        TEXT,                      -- Fulcio SAN (keyless)
    oidc_issuer          TEXT,                      -- OIDC issuer (keyless)
    key_id               TEXT,                      -- public-key fingerprint (key mode)
    transparency_log_ref TEXT,                      -- Rekor log index / entry UUID
    verifier_version     TEXT NOT NULL,             -- sigstore-go version applied
    policy_version       TEXT NOT NULL,             -- hash of the trust policy applied
    failure_reason       TEXT,                      -- populated when result = 'failed'
    envelope             JSONB NOT NULL,            -- raw bundle, round-trippable for audit
    verified_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Re-submitting the same SBOM + attestation under the same policy is a no-op.
    UNIQUE (sbom_id, subject_digest, policy_version)
);

CREATE INDEX IF NOT EXISTS idx_devradar_sbom_attestation_sbom
    ON devradar_sbom_attestation(tenant_id, sbom_id, verified_at DESC);
