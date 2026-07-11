-- Snapshot the existing event tail before the scan runner can create new
-- events. This makes browser alerts prospective from deployment: the first
-- post-deploy scan is eligible, while historical events are not backfilled.
WITH tail AS (
    SELECT occurred_at, id
    FROM devradar_finding_event
    ORDER BY occurred_at DESC, id DESC
    LIMIT 1
)
INSERT INTO devradar_alert_cursor (consumer, last_occurred_at, last_event_id)
SELECT
    'browser-alerts-v1',
    COALESCE((SELECT occurred_at FROM tail), 'epoch'::timestamptz),
    COALESCE((SELECT id FROM tail), 0)
ON CONFLICT (consumer) DO NOTHING;
