-- Transactional outbox for alert evaluation. ApplyScan inserts a queue row in
-- the same transaction as each actionable finding event, so PostgreSQL commit
-- visibility rather than event tuple order determines when work becomes ready.
-- Deliberately no historical backfill: browser alerts remain prospective.
CREATE TABLE IF NOT EXISTS devradar_alert_event_queue (
    consumer          TEXT NOT NULL,
    event_occurred_at TIMESTAMPTZ NOT NULL,
    event_id          BIGINT NOT NULL,
    enqueued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at      TIMESTAMPTZ,
    PRIMARY KEY (consumer, event_occurred_at, event_id)
);

CREATE INDEX IF NOT EXISTS idx_devradar_alert_event_queue_pending
    ON devradar_alert_event_queue (consumer, event_occurred_at, event_id)
    WHERE processed_at IS NULL;

-- Operational indexes for queue/source joins and the product-health windows.
CREATE INDEX IF NOT EXISTS idx_devradar_fe_actionable_position
    ON devradar_finding_event (occurred_at, id)
    WHERE cause IN ('image', 'db');

CREATE INDEX IF NOT EXISTS idx_devradar_alert_created_at
    ON devradar_alert (created_at);

CREATE INDEX IF NOT EXISTS idx_devradar_alert_failure_occurred_at
    ON devradar_alert_failure (occurred_at);
