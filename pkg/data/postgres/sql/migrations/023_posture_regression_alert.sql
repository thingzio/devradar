WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY tenant_id, policy_id, sbom_id, alert_kind
               ORDER BY created_at, id
           ) AS duplicate_rank
    FROM devradar_alert
    WHERE alert_kind = 'posture_regression'
)
DELETE FROM devradar_alert alert
USING ranked
WHERE alert.id = ranked.id
  AND ranked.duplicate_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devradar_alert_one_posture_regression
ON devradar_alert (tenant_id, policy_id, sbom_id, alert_kind)
WHERE alert_kind = 'posture_regression';
