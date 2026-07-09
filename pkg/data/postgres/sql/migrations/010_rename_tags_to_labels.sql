-- Rename the SBOM grouping field from "tags" to "labels" to avoid confusion with
-- the image tag (which DevRadar records as `version`). "tag" was overloaded: the
-- image's :v1.2.3 tag AND the tenant's free-form grouping labels. Labels is the
-- grouping concept; version is the image tag. Idempotent: guarded so re-apply is
-- a no-op whether or not the rename already happened.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devradar_sbom' AND column_name = 'tags'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devradar_sbom' AND column_name = 'labels'
    ) THEN
        ALTER TABLE devradar_sbom RENAME COLUMN tags TO labels;
    END IF;
END $$;

ALTER INDEX IF EXISTS idx_devradar_sbom_tags RENAME TO idx_devradar_sbom_labels;

-- Safety net: ensure the column + index exist after the rename (covers a fresh
-- DB where 008 already created `tags` and this rename applied, and a re-run).
ALTER TABLE devradar_sbom
    ADD COLUMN IF NOT EXISTS labels TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_devradar_sbom_labels
    ON devradar_sbom USING GIN (labels);
