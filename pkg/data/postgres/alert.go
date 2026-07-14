package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data"
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

// UpdateAlertPolicy changes only the policy owned by tenantID. Policy ID and
// tenant ID from the input are deliberately ignored.
func (s *Store) UpdateAlertPolicy(ctx context.Context, tenantID string, policy AlertPolicy) error {
	_, err := updateAlertPolicy(ctx, s.db, tenantID, policy)
	return err
}

// UpdateAlertPolicyAudited updates shared alert policy and its attribution in
// one transaction.
func (s *Store) UpdateAlertPolicyAudited(ctx context.Context, tenantID string, policy AlertPolicy, actor account.Actor, requestID string) error {
	return s.WithAudit(ctx, tenantID, actor, AuditEvent{
		Action: "account.alert_policy.update", TargetType: "account", TargetID: tenantID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		changed, err := updateAlertPolicy(ctx, tx, tenantID, policy)
		if err == nil && !changed {
			return errAuditNoMutation
		}
		return err
	})
}

func updateAlertPolicy(ctx context.Context, exec dbtx, tenantID string, policy AlertPolicy) (bool, error) {
	if !data.ValidMinSeverity(policy.MinSeverity) {
		return false, fmt.Errorf("invalid alert minimum severity %q", policy.MinSeverity)
	}
	labels := policy.Labels
	if labels == nil {
		labels = []string{}
	}
	res, err := exec.ExecContext(ctx, `
		UPDATE devradar_alert_policy
		SET enabled=$2, min_severity=$3, alert_kev=$4, alert_fix_available=$5,
		    include_image=$6, include_db=$7, labels=$8, updated_at=now()
		WHERE tenant_id=$1
		  AND ROW(enabled,min_severity,alert_kev,alert_fix_available,include_image,include_db,labels)
		      IS DISTINCT FROM ROW($2,$3,$4,$5,$6,$7,$8::text[])`, tenantID, policy.Enabled, policy.MinSeverity,
		policy.AlertKEV, policy.AlertFixAvailable, policy.IncludeImage,
		policy.IncludeDB, pq.Array(labels))
	if err != nil {
		return false, fmt.Errorf("update alert policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update alert policy rows affected: %w", err)
	}
	if n == 0 {
		var exists bool
		if err := exec.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM devradar_alert_policy WHERE tenant_id=$1)`, tenantID).
			Scan(&exists); err != nil {
			return false, fmt.Errorf("check alert policy target: %w", err)
		}
		if !exists {
			return false, ErrNotFound
		}
	}
	return n > 0, nil
}

const personalAlertSelect = `
	SELECT a.id, a.tenant_id, a.policy_id, a.event_id, a.event_occurred_at,
	       a.alert_kind, a.sbom_id, a.repository, a.digest, a.finding_id,
	       a.exposure, a.package, a.version, a.severity, a.cause, a.score,
	       COALESCE(r.read_at, CASE WHEN u.legacy_tenant_id=a.tenant_id THEN a.read_at END),
	       a.created_at, COALESCE(e.kev, false), e.epss_score
	FROM devradar_alert a
	JOIN devradar_tenant t ON t.id=a.tenant_id AND t.status='active'
	JOIN devradar_account_member m
	  ON m.account_id=a.tenant_id AND m.user_id=$2 AND m.revoked_at IS NULL
	JOIN devradar_user u ON u.id=m.user_id AND u.status='active'
	LEFT JOIN devradar_alert_receipt r
	  ON r.alert_id=a.id AND r.account_id=a.tenant_id AND r.user_id=$2
	LEFT JOIN devradar_cve_enrichment e ON e.cve = a.exposure`

// ListAlerts returns an account member's personal alert history newest first.
func (s *Store) ListAlerts(ctx context.Context, accountID, userID, cursor string, limit int) (items []Alert, next string, err error) {
	eff, fetch := clampLimit(limit)
	cur, hasCur := decodeCursor(cursor)
	args := []any{accountID, userID}
	seek := ""
	if hasCur {
		seek = " AND (a.created_at, a.id) < ($3, $4)"
		args = append(args, cur.TS, cur.ID)
	}
	args = append(args, fetch)
	rows, err := s.db.QueryContext(ctx, personalAlertSelect+fmt.Sprintf(`
		WHERE a.tenant_id=$1%s
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT $%d`, seek, len(args)), args...)
	if err != nil {
		return nil, "", fmt.Errorf("list alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a Alert
		if err := scanAlert(rows, &a); err != nil {
			return nil, "", err
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate alerts: %w", err)
	}
	if len(items) > eff {
		items = items[:eff]
		last := items[eff-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return items, next, nil
}

// UnreadAlerts returns a bounded newest-first personal list for Overview.
func (s *Store) UnreadAlerts(ctx context.Context, accountID, userID string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > maxPageLimit {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx, personalAlertSelect+`
		WHERE a.tenant_id=$1
		  AND COALESCE(r.read_at, CASE WHEN u.legacy_tenant_id=a.tenant_id THEN a.read_at END) IS NULL
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT $3`, accountID, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list unread alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Alert
	for rows.Next() {
		var a Alert
		if err := scanAlert(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unread alerts: %w", err)
	}
	return out, nil
}

// GetAlert returns one alert only when it belongs to the member's account.
func (s *Store) GetAlert(ctx context.Context, accountID, userID, alertID string) (*Alert, error) {
	var a Alert
	err := scanAlert(s.db.QueryRowContext(ctx, personalAlertSelect+`
		WHERE a.tenant_id=$1 AND a.id=$3`, accountID, userID, alertID), &a)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// MarkAlertRead idempotently creates only the specified member's receipt.
func (s *Store) MarkAlertRead(ctx context.Context, accountID, userID, alertID string) error {
	var eligible bool
	err := s.db.QueryRowContext(ctx, `
		WITH eligible AS MATERIALIZED (
			SELECT a.id,a.tenant_id,m.user_id
			FROM devradar_alert a
			JOIN devradar_tenant t ON t.id=a.tenant_id AND t.status='active'
			JOIN devradar_account_member m
			  ON m.account_id=a.tenant_id AND m.user_id=$2 AND m.revoked_at IS NULL
			JOIN devradar_user u ON u.id=m.user_id AND u.status='active'
			WHERE a.tenant_id=$1 AND a.id=$3
		), inserted AS (
			INSERT INTO devradar_alert_receipt (alert_id,account_id,user_id)
			SELECT id,tenant_id,user_id FROM eligible
			ON CONFLICT (alert_id,user_id) DO NOTHING
		)
		SELECT EXISTS(SELECT 1 FROM eligible)`, accountID, userID, alertID).Scan(&eligible)
	if err != nil {
		return fmt.Errorf("mark alert read: %w", err)
	}
	if !eligible {
		return ErrNotFound
	}
	return nil
}

type alertScanner interface {
	Scan(dest ...any) error
}

func scanAlert(row alertScanner, a *Alert) error {
	err := row.Scan(&a.ID, &a.TenantID, &a.PolicyID, &a.EventID, &a.EventOccurredAt,
		&a.Kind, &a.SBOMID, &a.Repository, &a.Digest, &a.FindingID,
		&a.Exposure, &a.Package, &a.Version, &a.Severity, &a.Cause, &a.Score,
		&a.ReadAt, &a.CreatedAt, &a.KEV, &a.EPSS)
	if err != nil {
		return fmt.Errorf("scan alert: %w", err)
	}
	return nil
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
		FROM devradar_alert_event_queue q
		JOIN devradar_finding_event e
		  ON e.occurred_at=q.event_occurred_at AND e.id=q.event_id
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		LEFT JOIN devradar_cve_enrichment en ON en.cve = e.exposure
		LEFT JOIN devradar_alert_policy p ON p.tenant_id = e.tenant_id
		WHERE q.consumer=$1
		  AND q.processed_at IS NULL
		  AND e.cause IN ('image', 'db')
		ORDER BY e.occurred_at ASC, e.id ASC
		LIMIT $2`, consumer, limit)
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
	return candidates, end, inserted == 1 && len(candidates) == 0, nil
}

// CommitAlertBatch atomically persists all effects, marks every examined queue
// position processed, and advances the consumer's cursor as an observability
// high-water. Conflict guards make retrying a committed batch harmless.
func (s *Store) CommitAlertBatch(ctx context.Context, consumer string, drafts []AlertDraft, failures []AlertFailure, processed []AlertPosition, end AlertPosition) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin alert batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, draft := range drafts {
		e := draft.Event
		policyUpdatedAt := sql.NullTime{
			Time:  draft.PolicyUpdatedAt,
			Valid: !draft.PolicyUpdatedAt.IsZero(),
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devradar_alert
			(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
			 repository, digest, finding_id, exposure, package, version, severity, score, cause)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
			FROM devradar_alert_policy p
			WHERE p.id=$2 AND p.tenant_id=$1 AND p.enabled
			  AND ($16::timestamptz IS NULL OR p.updated_at=$16)
			ON CONFLICT DO NOTHING`, e.TenantID, draft.PolicyID, e.ID, e.OccurredAt, draft.Kind,
			e.SBOMID, e.Repository, e.Digest, e.FindingID, e.Exposure, e.Package,
			e.Version, e.Severity, e.Score, e.Cause, policyUpdatedAt); err != nil {
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
	for _, position := range processed {
		if _, err := tx.ExecContext(ctx, `
			UPDATE devradar_alert_event_queue
			SET processed_at=COALESCE(processed_at, now())
			WHERE consumer=$1 AND event_occurred_at=$2 AND event_id=$3`,
			consumer, position.OccurredAt, position.EventID); err != nil {
			return fmt.Errorf("mark alert event processed: %w", err)
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
