-- Repository-scoped VEX. Real-world OpenVEX often scopes a statement to a
-- product by name/PURL with no digest (e.g. pkg:oci/aicr) — asserting
-- not_affected across ALL versions of an image, which is the natural granularity
-- for a "vulnerable code not in execute path" justification. v1 required a
-- digest; this adds a repository key so digest-less statements match every
-- version of the repository, while digest-pinned statements stay precise.
ALTER TABLE devradar_vex_statement
    ADD COLUMN IF NOT EXISTS product_repo TEXT;   -- last path segment of the VEX product (e.g. "aicr")

-- A statement now scopes by digest OR repo; digest may be absent.
ALTER TABLE devradar_vex_statement
    ALTER COLUMN product_digest DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devradar_vex_stmt_repo
    ON devradar_vex_statement(tenant_id, product_repo, vulnerability, created_at DESC)
    WHERE product_repo IS NOT NULL;
