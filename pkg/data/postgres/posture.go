package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const maxPostureTrendDays = 365

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

// SnapshotTenantPosture replaces today's repository and tenant snapshots.
// Findings reported by multiple scanners are collapsed by (sbom_id,
// finding_id), with the worst reported severity and the union of fix/KEV facts.
// All writes share one transaction so fleet and repository posture cannot
// diverge on a partial failure.
func (s *Store) SnapshotTenantPosture(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant posture snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Snapshotting is platform-wide. Overlapping scan jobs must not interleave
	// their delete-and-replace transactions and race on the daily primary keys.
	if _, err := tx.ExecContext(ctx, `
		SELECT pg_advisory_xact_lock(hashtext('devradar'), hashtext('posture-snapshot'))`); err != nil {
		return fmt.Errorf("lock posture snapshots: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_repository_posture_snapshot
		WHERE snapshot_date = CURRENT_DATE`); err != nil {
		return fmt.Errorf("replace repository posture snapshots: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_tenant_posture_snapshot
		WHERE snapshot_date = CURRENT_DATE`); err != nil {
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
		SELECT a.tenant_id, a.repository, CURRENT_DATE, 1,
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
		SELECT t.id, CURRENT_DATE,
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

// TenantPostureTrend returns up to days of one tenant's snapshots in
// chronological order. The requested window is bounded to 1..365 days.
func (s *Store) TenantPostureTrend(ctx context.Context, tenantID string, days int) ([]TenantPosturePoint, error) {
	days = boundedPostureTrendDays(days)

	rows, err := s.db.QueryContext(ctx, `
		SELECT snapshot_date, images, relevant_findings, critical, high,
		       medium, low, fixable, kev, captured_at
		FROM devradar_tenant_posture_snapshot
		WHERE tenant_id = $1
		  AND snapshot_date >= CURRENT_DATE - ($2::int - 1)
		  AND snapshot_date <= CURRENT_DATE
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
		  AND snapshot_date >= CURRENT_DATE - ($3::int - 1)
		  AND snapshot_date <= CURRENT_DATE
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
		  AND snapshot_date <= CURRENT_DATE
		GROUP BY repository
		ORDER BY repository`, tenantID)
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
		  AND snapshot_date <= CURRENT_DATE`, tenantID).Scan(&start); err != nil {
		return nil, fmt.Errorf("get tenant posture coverage start: %w", err)
	}
	if !start.Valid {
		return nil, nil
	}
	return &start.Time, nil
}
