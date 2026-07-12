-- Give pending alert work explicit tenant ownership so a hard tenant delete
-- cannot leave invisible queue rows inflating the evaluator backlog. This only
-- annotates rows already in the prospective queue; it never backfills source
-- events that were not queued by ApplyScan.
ALTER TABLE devradar_alert_event_queue
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE devradar_alert_event_queue q
SET tenant_id = e.tenant_id
FROM devradar_finding_event e
WHERE q.tenant_id IS NULL
  AND e.occurred_at = q.event_occurred_at
  AND e.id = q.event_id;

-- A queue row without a source event or live tenant cannot be evaluated. Drop
-- it before enforcing ownership so upgrades converge instead of failing.
DELETE FROM devradar_alert_event_queue q
WHERE q.tenant_id IS NULL
   OR NOT EXISTS (
       SELECT 1 FROM devradar_tenant t WHERE t.id = q.tenant_id
   );

ALTER TABLE devradar_alert_event_queue
    ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'devradar_alert_event_queue'::regclass
          AND conname = 'fk_devradar_alert_event_queue_tenant'
    ) THEN
        ALTER TABLE devradar_alert_event_queue
            ADD CONSTRAINT fk_devradar_alert_event_queue_tenant
            FOREIGN KEY (tenant_id) REFERENCES devradar_tenant(id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_devradar_alert_event_queue_tenant
    ON devradar_alert_event_queue (tenant_id);
