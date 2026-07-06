-- Image identity split out of image_ref. image_ref was doing double duty as both
-- a human label and the cross-digest grouping key; once submitters pin to
-- repo@digest, every digest becomes a distinct image_ref and "track one image
-- over time" breaks. Model the three axes explicitly:
--   repository — registry/path, no tag/digest (the stable image identity)
--   version    — the tag, e.g. "v1.20.2" (nullable; absent on digest-only submits)
--   digest     — already stored (the immutable pin)
ALTER TABLE devradar_sbom
    ADD COLUMN IF NOT EXISTS repository TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS version    TEXT;

-- Backfill repository from existing image_ref: drop an @sha256:... digest, then a
-- trailing :tag. A registry port survives because it only ever appears as
-- host:port/path (colon followed by more path), so it is never the trailing
-- ':segment' the second regexp removes.
UPDATE devradar_sbom
SET repository = regexp_replace(
                     regexp_replace(image_ref, '@sha256:[0-9a-f]+$', ''),
                     ':[^/]+$', '')
WHERE repository = '';

CREATE INDEX IF NOT EXISTS idx_devradar_sbom_repository
    ON devradar_sbom(tenant_id, repository, status);
