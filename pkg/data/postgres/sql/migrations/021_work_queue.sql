-- Supports the tenant-scoped first-seen aggregation used by the remediation
-- work queue. PostgreSQL creates a matching index on each event partition.
CREATE INDEX IF NOT EXISTS idx_devradar_fe_tenant_finding_added
    ON devradar_finding_event (tenant_id, finding_id, event_type, occurred_at)
    WHERE event_type = 'added';
