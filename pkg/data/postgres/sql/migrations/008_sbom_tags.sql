-- Free-form tenant tags on an SBOM, set at submission (e.g. "team-x", "prod",
-- "edge"). Tags let a tenant group images: an image (repository) is considered
-- to carry a tag when any of its SBOMs do. Stored as an array on the row (small,
-- read-mostly); a GIN index makes the ?tag= filter cheap.
ALTER TABLE devradar_sbom
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_devradar_sbom_tags
    ON devradar_sbom USING GIN (tags);
