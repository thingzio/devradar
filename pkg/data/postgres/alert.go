package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

const defaultAlertBatchSize = 100

// EnsureAlertPolicy returns the tenant's policy, creating the disabled default
// when the tenant has not configured browser alerts yet.
func (s *Store) EnsureAlertPolicy(ctx context.Context, tenantID string) (*AlertPolicy, error) {
	var p AlertPolicy
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id) VALUES ($1)
		ON CONFLICT (tenant_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
		RETURNING id, tenant_id, enabled, min_severity, alert_kev,
		          alert_fix_available, include_image, include_db, labels,
		          created_at, updated_at`, tenantID).Scan(
		&p.ID, &p.TenantID, &p.Enabled, &p.MinSeverity, &p.AlertKEV,
		&p.AlertFixAvailable, &p.IncludeImage, &p.IncludeDB, pq.Array(&p.Labels),
		&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("ensure alert policy: %w", err)
	}
	return &p, nil
}

// NextAlertEvents returns the next stable event batch. A new consumer starts at
// the current tail so enabling alerts never backfills historical events.
func (s *Store) NextAlertEvents(ctx context.Context, consumer string, limit int) ([]AlertCandidate, AlertPosition, bool, error) {
	if limit <= 0 || limit > maxPageLimit {
		limit = defaultAlertBatchSize
	}
	res, err := s.db.ExecContext(ctx, `
		WITH tail AS (
			SELECT occurred_at, id
			FROM devradar_finding_event
			ORDER BY occurred_at DESC, id DESC
			LIMIT 1
		)
		INSERT INTO devradar_alert_cursor (consumer, last_occurred_at, last_event_id)
		SELECT $1,
		       COALESCE((SELECT occurred_at FROM tail), 'epoch'::timestamptz),
		       COALESCE((SELECT id FROM tail), 0)
		ON CONFLICT (consumer) DO NOTHING`, consumer)
	if err != nil {
		return nil, AlertPosition{}, false, fmt.Errorf("initialize alert cursor: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return nil, AlertPosition{}, false, fmt.Errorf("alert cursor rows affected: %w", err)
	}

	var start AlertPosition
	if err := s.db.QueryRowContext(ctx, `
		SELECT last_occurred_at, last_event_id
		FROM devradar_alert_cursor WHERE consumer=$1`, consumer).
		Scan(&start.OccurredAt, &start.EventID); err != nil {
		return nil, AlertPosition{}, false, fmt.Errorf("read alert cursor: %w", err)
	}
	if inserted == 1 {
		return nil, start, true, nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.occurred_at, e.tenant_id, e.sbom_id,
		       sb.repository, sb.digest, e.finding_id, e.event_type,
		       e.exposure, e.package, e.version, e.severity, e.cause, e.score,
		       COALESCE(en.kev, false), sb.labels,
		       COALESCE(p.id::text, ''), COALESCE(p.enabled, false),
		       COALESCE(p.min_severity, 'medium'), COALESCE(p.alert_kev, true),
		       COALESCE(p.alert_fix_available, true), COALESCE(p.include_image, true),
		       COALESCE(p.include_db, true), COALESCE(p.labels, '{}'),
		       p.created_at, p.updated_at
		FROM devradar_finding_event e
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		LEFT JOIN devradar_cve_enrichment en ON en.cve = e.exposure
		LEFT JOIN devradar_alert_policy p ON p.tenant_id = e.tenant_id
		WHERE (e.occurred_at, e.id) > ($1, $2)
		  AND e.cause IN ('image', 'db')
		ORDER BY e.occurred_at ASC, e.id ASC
		LIMIT $3`, start.OccurredAt, start.EventID, limit)
	if err != nil {
		return nil, AlertPosition{}, false, fmt.Errorf("list alert events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	candidates := make([]AlertCandidate, 0, limit)
	end := start
	for rows.Next() {
		var c AlertCandidate
		var policyCreated, policyUpdated sql.NullTime
		if err := rows.Scan(
			&c.Event.ID, &c.Event.OccurredAt, &c.Event.TenantID, &c.Event.SBOMID,
			&c.Event.Repository, &c.Event.Digest, &c.Event.FindingID, &c.Event.EventType,
			&c.Event.Exposure, &c.Event.Package, &c.Event.Version, &c.Event.Severity,
			&c.Event.Cause, &c.Event.Score, &c.Event.KEV, pq.Array(&c.Event.Labels),
			&c.Policy.ID, &c.Policy.Enabled, &c.Policy.MinSeverity, &c.Policy.AlertKEV,
			&c.Policy.AlertFixAvailable, &c.Policy.IncludeImage, &c.Policy.IncludeDB,
			pq.Array(&c.Policy.Labels), &policyCreated, &policyUpdated); err != nil {
			return nil, AlertPosition{}, false, fmt.Errorf("scan alert event: %w", err)
		}
		c.Policy.TenantID = c.Event.TenantID
		if policyCreated.Valid {
			c.Policy.CreatedAt = policyCreated.Time
		}
		if policyUpdated.Valid {
			c.Policy.UpdatedAt = policyUpdated.Time
		}
		candidates = append(candidates, c)
		end = AlertPosition{OccurredAt: c.Event.OccurredAt, EventID: c.Event.ID}
	}
	if err := rows.Err(); err != nil {
		return nil, AlertPosition{}, false, fmt.Errorf("iterate alert events: %w", err)
	}
	return candidates, end, false, nil
}

// CommitAlertBatch atomically persists all effects and advances the consumer's
// cursor. Conflict guards make retrying a committed batch harmless.
func (s *Store) CommitAlertBatch(ctx context.Context, consumer string, drafts []AlertDraft, failures []AlertFailure, end AlertPosition) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin alert batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, draft := range drafts {
		e := draft.Event
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devradar_alert
			(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
			 repository, digest, finding_id, exposure, package, version, severity, score, cause)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (tenant_id, policy_id, event_id, event_occurred_at, alert_kind)
			DO NOTHING`, e.TenantID, draft.PolicyID, e.ID, e.OccurredAt, draft.Kind,
			e.SBOMID, e.Repository, e.Digest, e.FindingID, e.Exposure, e.Package,
			e.Version, e.Severity, e.Score, e.Cause); err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
	}
	for _, failure := range failures {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devradar_alert_failure
			(consumer, event_id, event_occurred_at, error)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (consumer, event_id, event_occurred_at) DO NOTHING`,
			consumer, failure.Position.EventID, failure.Position.OccurredAt, failure.Error); err != nil {
			return fmt.Errorf("insert alert failure: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_alert_cursor
		SET last_occurred_at=$2, last_event_id=$3, updated_at=now()
		WHERE consumer=$1
		  AND (last_occurred_at, last_event_id) < ($2, $3)`,
		consumer, end.OccurredAt, end.EventID); err != nil {
		return fmt.Errorf("advance alert cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit alert batch: %w", err)
	}
	return nil
}
