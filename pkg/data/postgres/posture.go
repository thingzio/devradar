package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"
)

const (
	maxPostureTrendDays          = 365
	postureSnapshotUnlockTimeout = 5 * time.Second
)

// TenantPosturePoint is one exact daily snapshot of a tenant's active fleet.
// Total is the scanner-deduplicated relevant finding count.
type TenantPosturePoint struct {
	Date       time.Time `json:"date"`
	Images     int       `json:"images"`
	Total      int       `json:"total"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Medium     int       `json:"medium"`
	Low        int       `json:"low"`
	Fixable    int       `json:"fixable"`
	KEV        int       `json:"kev"`
	CapturedAt time.Time `json:"captured_at"`
}

// RepositoryPostureOption is a tenant-owned repository with retained snapshot
// history. CoverageStart is the first observed snapshot; missing days remain
// absent rather than being reconstructed.
type RepositoryPostureOption struct {
	Repository    string
	CoverageStart time.Time
}

// SnapshotTenantPostureStale runs SnapshotTenantPosture only when the newest
// snapshot is older than minInterval (or none exists). The scan job calls this
// every tick, but the projection is an expensive full-fleet scan whose result is
// deduplicated to one row per tenant per day — running it ~96×/day (every 15 min)
// throws away all but the last write. The freshness check is a cheap indexed
// MAX(captured_at) evaluated UNDER the same advisory lock as the projection, so
// two overlapping ticks can never both do the full work. minInterval <= 0
// forces a run (preserves the always-run contract for callers that want it).
func (s *Store) SnapshotTenantPostureStale(ctx context.Context, minInterval time.Duration) (retErr error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant posture connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, `
		SELECT pg_advisory_lock(hashtext('devradar'), hashtext('posture-snapshot'))`); err != nil {
		return fmt.Errorf("lock posture snapshots: %w", err)
	}
	defer func() {
		if err := unlockPostureSnapshots(conn); err != nil && retErr == nil {
			retErr = err
		}
	}()

	if minInterval > 0 {
		var newest sql.NullTime
		if err := conn.QueryRowContext(ctx,
			`SELECT MAX(captured_at) FROM devradar_tenant_posture_snapshot`).Scan(&newest); err != nil {
			return fmt.Errorf("check posture snapshot freshness: %w", err)
		}
		if newest.Valid && time.Since(newest.Time) < minInterval {
			return nil // a recent snapshot already exists; skip the expensive projection
		}
	}
	return s.snapshotTenantPostureLocked(ctx, conn)
}

// SnapshotTenantPosture replaces today's repository and tenant snapshots.
// Findings reported by multiple scanners are collapsed by (sbom_id,
// finding_id), with the worst reported severity and the union of fix/KEV facts.
// All writes share one repeatable-read transaction so fleet and repository
// posture cannot diverge on a partial failure or concurrent source update.
func (s *Store) SnapshotTenantPosture(ctx context.Context) (retErr error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant posture connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Acquire the session lock before beginning the repeatable-read transaction,
	// so a waiting caller establishes its database snapshot only after the prior
	// projection has committed.
	if _, err := conn.ExecContext(ctx, `
		SELECT pg_advisory_lock(hashtext('devradar'), hashtext('posture-snapshot'))`); err != nil {
		return fmt.Errorf("lock posture snapshots: %w", err)
	}
	defer func() {
		if err := unlockPostureSnapshots(conn); err != nil && retErr == nil {
			retErr = err
		}
	}()
	return s.snapshotTenantPostureLocked(ctx, conn)
}

// snapshotTenantPostureLocked performs the projection on a connection that
// already holds the posture-snapshot advisory lock.
func (s *Store) snapshotTenantPostureLocked(ctx context.Context, conn *sql.Conn) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fmt.Errorf("begin tenant posture snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_repository_posture_snapshot
		WHERE snapshot_date = (now() AT TIME ZONE 'UTC')::date`); err != nil {
		return fmt.Errorf("replace repository posture snapshots: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_tenant_posture_snapshot
		WHERE snapshot_date = (now() AT TIME ZONE 'UTC')::date`); err != nil {
		return fmt.Errorf("replace tenant posture snapshots: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		WITH active_repositories AS (
			SELECT DISTINCT sb.tenant_id, sb.repository
			FROM devradar_sbom sb
			JOIN devradar_tenant t ON t.id = sb.tenant_id
			WHERE sb.status = 'active' AND t.status = 'active'
			  AND sb.repository <> ''
		), canonical_findings AS (
			SELECT sb.tenant_id, sb.repository, f.sbom_id, f.finding_id,
			       MIN(CASE f.severity
			             WHEN 'critical' THEN 1
			             WHEN 'high' THEN 2
			             WHEN 'medium' THEN 3
			             WHEN 'low' THEN 4
			             WHEN 'negligible' THEN 5
			             ELSE 6
			           END) AS severity_rank,
			       bool_or(f.is_fixed) AS fixable,
			       COALESCE(bool_or(e.kev), false) AS kev
			FROM devradar_sbom sb
			JOIN devradar_tenant t ON t.id = sb.tenant_id
			JOIN devradar_finding f ON f.sbom_id = sb.id
			LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
			WHERE sb.status = 'active' AND t.status = 'active'
			  AND sb.repository <> ''
			  AND NOT `+vexSuppressedByDigestCVE+`
			GROUP BY sb.tenant_id, sb.repository, f.sbom_id, f.finding_id
		), repository_counts AS (
			SELECT tenant_id, repository,
			       COUNT(*)::int AS relevant_findings,
			       COUNT(*) FILTER (WHERE severity_rank = 1)::int AS critical,
			       COUNT(*) FILTER (WHERE severity_rank = 2)::int AS high,
			       COUNT(*) FILTER (WHERE severity_rank = 3)::int AS medium,
			       COUNT(*) FILTER (WHERE severity_rank = 4)::int AS low,
			       COUNT(*) FILTER (WHERE fixable)::int AS fixable,
			       COUNT(*) FILTER (WHERE kev)::int AS kev
			FROM canonical_findings
			GROUP BY tenant_id, repository
		)
		INSERT INTO devradar_repository_posture_snapshot
			(tenant_id, repository, snapshot_date, images, relevant_findings, critical,
			 high, medium, low, fixable, kev, captured_at)
		SELECT a.tenant_id, a.repository, (now() AT TIME ZONE 'UTC')::date, 1,
		       COALESCE(f.relevant_findings, 0), COALESCE(f.critical, 0),
		       COALESCE(f.high, 0), COALESCE(f.medium, 0), COALESCE(f.low, 0),
		       COALESCE(f.fixable, 0), COALESCE(f.kev, 0), now()
		FROM active_repositories a
		LEFT JOIN repository_counts f
		  ON f.tenant_id = a.tenant_id AND f.repository = a.repository`); err != nil {
		return fmt.Errorf("insert repository posture snapshots: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		WITH active_images AS (
			SELECT sb.id, sb.tenant_id, sb.repository
			FROM devradar_sbom sb
			JOIN devradar_tenant t ON t.id = sb.tenant_id
			WHERE sb.status = 'active' AND t.status = 'active'
		), canonical_findings AS (
			SELECT sb.tenant_id, f.sbom_id, f.finding_id,
			       MIN(CASE f.severity
			             WHEN 'critical' THEN 1
			             WHEN 'high' THEN 2
			             WHEN 'medium' THEN 3
			             WHEN 'low' THEN 4
			             WHEN 'negligible' THEN 5
			             ELSE 6
			           END) AS severity_rank,
			       bool_or(f.is_fixed) AS fixable,
			       COALESCE(bool_or(e.kev), false) AS kev
			FROM devradar_sbom sb
			JOIN devradar_tenant t ON t.id = sb.tenant_id
			JOIN devradar_finding f ON f.sbom_id = sb.id
			LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
			WHERE sb.status = 'active' AND t.status = 'active'
			  AND NOT `+vexSuppressedByDigestCVE+`
			GROUP BY sb.tenant_id, f.sbom_id, f.finding_id
		), image_counts AS (
			SELECT tenant_id, COUNT(DISTINCT repository)::int AS images
			FROM active_images
			GROUP BY tenant_id
		), finding_counts AS (
			SELECT tenant_id,
			       COUNT(*)::int AS relevant_findings,
			       COUNT(*) FILTER (WHERE severity_rank = 1)::int AS critical,
			       COUNT(*) FILTER (WHERE severity_rank = 2)::int AS high,
			       COUNT(*) FILTER (WHERE severity_rank = 3)::int AS medium,
			       COUNT(*) FILTER (WHERE severity_rank = 4)::int AS low,
			       COUNT(*) FILTER (WHERE fixable)::int AS fixable,
			       COUNT(*) FILTER (WHERE kev)::int AS kev
			FROM canonical_findings
			GROUP BY tenant_id
		)
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings, critical,
			 high, medium, low, fixable, kev, captured_at)
		SELECT t.id, (now() AT TIME ZONE 'UTC')::date,
		       COALESCE(i.images, 0), COALESCE(f.relevant_findings, 0),
		       COALESCE(f.critical, 0), COALESCE(f.high, 0),
		       COALESCE(f.medium, 0), COALESCE(f.low, 0),
		       COALESCE(f.fixable, 0), COALESCE(f.kev, 0), now()
		FROM devradar_tenant t
		LEFT JOIN image_counts i ON i.tenant_id = t.id
		LEFT JOIN finding_counts f ON f.tenant_id = t.id
		WHERE t.status = 'active'
		`); err != nil {
		return fmt.Errorf("insert tenant posture snapshots: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant posture snapshots: %w", err)
	}
	return nil
}

func unlockPostureSnapshots(conn *sql.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), postureSnapshotUnlockTimeout)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRowContext(ctx, `
		SELECT pg_advisory_unlock(hashtext('devradar'), hashtext('posture-snapshot'))`).Scan(&unlocked); err != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return fmt.Errorf("unlock posture snapshots: %w", err)
	}
	if !unlocked {
		return fmt.Errorf("unlock posture snapshots: lock not held")
	}
	return nil
}

// TenantPostureTrend returns up to days of one tenant's snapshots in
// chronological order. The requested window is bounded to 1..365 days.
func (s *Store) TenantPostureTrend(ctx context.Context, tenantID string, days int) ([]TenantPosturePoint, error) {
	days = boundedPostureTrendDays(days)

	rows, err := s.db.QueryContext(ctx, `
		SELECT snapshot_date, images, relevant_findings, critical, high,
		       medium, low, fixable, kev, captured_at
		FROM devradar_tenant_posture_snapshot
		WHERE tenant_id = $1
		  AND snapshot_date >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
		  AND snapshot_date <= (now() AT TIME ZONE 'UTC')::date
		ORDER BY snapshot_date ASC`, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("list tenant posture trend: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var points []TenantPosturePoint
	for rows.Next() {
		var point TenantPosturePoint
		if err := rows.Scan(&point.Date, &point.Images, &point.Total,
			&point.Critical, &point.High, &point.Medium, &point.Low,
			&point.Fixable, &point.KEV, &point.CapturedAt); err != nil {
			return nil, fmt.Errorf("scan tenant posture trend: %w", err)
		}
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant posture trend: %w", err)
	}
	return points, nil
}

// RepositoryPostureTrend returns one tenant repository's observed daily
// snapshots in chronological order. Unknown and cross-tenant repositories
// return no points.
func (s *Store) RepositoryPostureTrend(ctx context.Context, tenantID, repository string, days int) ([]TenantPosturePoint, error) {
	days = boundedPostureTrendDays(days)
	rows, err := s.db.QueryContext(ctx, `
		SELECT snapshot_date, images, relevant_findings, critical, high,
		       medium, low, fixable, kev, captured_at
		FROM devradar_repository_posture_snapshot
		WHERE tenant_id = $1 AND repository = $2
		  AND snapshot_date >= (now() AT TIME ZONE 'UTC')::date - ($3::int - 1)
		  AND snapshot_date <= (now() AT TIME ZONE 'UTC')::date
		ORDER BY snapshot_date ASC`, tenantID, repository, days)
	if err != nil {
		return nil, fmt.Errorf("list repository posture trend: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var points []TenantPosturePoint
	for rows.Next() {
		var point TenantPosturePoint
		if err := rows.Scan(&point.Date, &point.Images, &point.Total,
			&point.Critical, &point.High, &point.Medium, &point.Low,
			&point.Fixable, &point.KEV, &point.CapturedAt); err != nil {
			return nil, fmt.Errorf("scan repository posture trend: %w", err)
		}
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repository posture trend: %w", err)
	}
	return points, nil
}

// RepositoryPostureOptions lists tenant-owned repositories with retained
// snapshot coverage, including repositories that are no longer actively
// tracked so their observed history remains accessible.
func (s *Store) RepositoryPostureOptions(ctx context.Context, tenantID string) ([]RepositoryPostureOption, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT repository, MIN(snapshot_date)
		FROM devradar_repository_posture_snapshot
		WHERE tenant_id = $1 AND repository <> ''
		  AND snapshot_date >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
		  AND snapshot_date <= (now() AT TIME ZONE 'UTC')::date
		GROUP BY repository
		ORDER BY repository`, tenantID, maxPostureTrendDays)
	if err != nil {
		return nil, fmt.Errorf("list repository posture options: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var options []RepositoryPostureOption
	for rows.Next() {
		var option RepositoryPostureOption
		if err := rows.Scan(&option.Repository, &option.CoverageStart); err != nil {
			return nil, fmt.Errorf("scan repository posture option: %w", err)
		}
		options = append(options, option)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repository posture options: %w", err)
	}
	return options, nil
}

func boundedPostureTrendDays(days int) int {
	if days < 1 {
		return 1
	}
	if days > maxPostureTrendDays {
		return maxPostureTrendDays
	}
	return days
}

// TenantPostureCoverageStart returns the date of a tenant's first recorded
// posture snapshot. A tenant without historical snapshots returns nil, nil.
func (s *Store) TenantPostureCoverageStart(ctx context.Context, tenantID string) (*time.Time, error) {
	var start sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
		SELECT MIN(snapshot_date)
		FROM devradar_tenant_posture_snapshot
		WHERE tenant_id = $1
		  AND snapshot_date <= (now() AT TIME ZONE 'UTC')::date`, tenantID).Scan(&start); err != nil {
		return nil, fmt.Errorf("get tenant posture coverage start: %w", err)
	}
	if !start.Valid {
		return nil, nil
	}
	return &start.Time, nil
}
