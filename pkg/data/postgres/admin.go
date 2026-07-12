package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// This file holds the operator-console reads and writes. Unlike every other
// method in this package they are DELIBERATELY NOT tenant-scoped: the admin
// console spans all tenants. They are grouped here and Admin-prefixed so the one
// place that legitimately reads across the tenant boundary is auditable in one
// spot. Callers must gate them behind middleware.RequireAdmin.

// PlatformCounts is the live snapshot backing the admin dashboard. Every field
// is computed on demand; the supporting indexes make this cheap. Point-in-time
// deltas (DoD/WoW/MoM) are served separately from devradar_platform_stats — see
// SnapshotPlatformStats / PlatformDeltas.
type PlatformCounts struct {
	Tenants          int
	TenantsActive    int
	TenantsSuspended int
	SBOMsActive      int
	SBOMsArchived    int
	UniqueDigests    int
	OpenFindings     int
	FindingsBySev    map[string]int // severity -> open finding count
	Events24h        int
	EventsByCause24h map[string]int // cause -> event count (last 24h)
	Failures24h      int            // real failures (excludes zero-findings warnings)
	Warnings24h      int            // zero-findings tripwires — informational, not errors
	VEXStatements    int
}

// AdminProductHealth is the aggregate product and pipeline health snapshot for
// the operator console. It deliberately contains no tenant identity or detail
// rows; every field is a bounded set-based count or timestamp.
type AdminProductHealth struct {
	EnabledAlertPolicies        int
	Alerts24h                   int
	UnreadAlerts                int
	EvaluatorBacklog            int
	OldestPendingAt             time.Time
	EvaluatorFailures24h        int
	SnapshotTenantsToday        int
	ActiveSBOMTenants           int
	CanonicalExposures          int
	CanonicalFixableExposures   int
	CanonicalKEVExposures       int
	ComparisonReadyRepositories int
	LicensePoliciesConfigured   int
	LicensePoliciesEnforcing    int
}

// AdminProductHealth computes cross-tenant product and pipeline health for the
// operator console. Each metric group is one bounded aggregate query; failures
// return no partial snapshot.
func (s *Store) AdminProductHealth(ctx context.Context) (*AdminProductHealth, error) {
	health := &AdminProductHealth{}

	if err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM devradar_alert_policy WHERE enabled),
			(SELECT count(*) FROM devradar_alert
			 WHERE created_at > now() - interval '24 hours'),
			(SELECT count(*) FROM devradar_alert WHERE read_at IS NULL),
			(SELECT count(*) FROM devradar_alert_failure
			 WHERE occurred_at > now() - interval '24 hours')`).Scan(
		&health.EnabledAlertPolicies,
		&health.Alerts24h,
		&health.UnreadAlerts,
		&health.EvaluatorFailures24h,
	); err != nil {
		return nil, fmt.Errorf("product health alerts: %w", err)
	}

	var oldestPending sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*), min(event_occurred_at)
		FROM devradar_alert_event_queue
		WHERE consumer=$1 AND processed_at IS NULL`,
		"browser-alerts-v1").Scan(&health.EvaluatorBacklog, &oldestPending); err != nil {
		return nil, fmt.Errorf("product health evaluator backlog: %w", err)
	}
	if oldestPending.Valid {
		health.OldestPendingAt = oldestPending.Time
	}

	if err := s.db.QueryRowContext(ctx, `
		WITH active_tenants AS (
			SELECT DISTINCT tenant_id
			FROM devradar_sbom
			WHERE status = 'active'
		)
		SELECT count(p.tenant_id), count(a.tenant_id)
		FROM active_tenants a
		LEFT JOIN devradar_tenant_posture_snapshot p
		  ON p.tenant_id = a.tenant_id
		 AND p.snapshot_date = (now() AT TIME ZONE 'UTC')::date`).Scan(
		&health.SnapshotTenantsToday,
		&health.ActiveSBOMTenants,
	); err != nil {
		return nil, fmt.Errorf("product health posture coverage: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `
		WITH canonical_findings AS (
			SELECT sb.tenant_id, f.sbom_id, f.finding_id,
			       bool_or(f.is_fixed) AS fixable,
			       COALESCE(bool_or(e.kev), false) AS kev
			FROM devradar_sbom sb
			JOIN devradar_finding f ON f.sbom_id = sb.id
			LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
			WHERE sb.status = 'active'
			  AND NOT `+vexSuppressedByDigestCVE+`
			GROUP BY sb.tenant_id, f.sbom_id, f.finding_id
		)
		SELECT count(*),
		       count(*) FILTER (WHERE fixable),
		       count(*) FILTER (WHERE kev)
		FROM canonical_findings`).Scan(
		&health.CanonicalExposures,
		&health.CanonicalFixableExposures,
		&health.CanonicalKEVExposures,
	); err != nil {
		return nil, fmt.Errorf("product health canonical exposures: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM (
			SELECT tenant_id, repository
			FROM devradar_sbom
			WHERE status = 'active'
			GROUP BY tenant_id, repository
			HAVING count(DISTINCT digest) >= 2
		) ready`).Scan(&health.ComparisonReadyRepositories); err != nil {
		return nil, fmt.Errorf("product health comparison readiness: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (
			   WHERE cardinality(denied_categories) > 0
			      OR cardinality(deny_exceptions) > 0)
		FROM devradar_license_policy`).Scan(
		&health.LicensePoliciesConfigured,
		&health.LicensePoliciesEnforcing,
	); err != nil {
		return nil, fmt.Errorf("product health license policies: %w", err)
	}

	return health, nil
}

// WarningStage is the scan_failure.stage recorded for the zero-findings tripwire.
// It is a heuristic warning (a scanner returned nothing on a non-trivial SBOM,
// usually cross-tool cataloger divergence — e.g. Trivy finds 0 where Grype finds
// some), not a real scan error. Classified at read time so the console can show
// it apart from genuine failures without a schema change.
const WarningStage = "zero-findings"

// AdminPlatformCounts computes the dashboard snapshot across all tenants.
func (s *Store) AdminPlatformCounts(ctx context.Context) (*PlatformCounts, error) {
	pc := &PlatformCounts{
		FindingsBySev:    map[string]int{},
		EventsByCause24h: map[string]int{},
	}

	// Tenants by status (one scan).
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE status = 'active'),
		       count(*) FILTER (WHERE status = 'suspended')
		FROM devradar_tenant`).
		Scan(&pc.Tenants, &pc.TenantsActive, &pc.TenantsSuspended); err != nil {
		return nil, fmt.Errorf("count tenants: %w", err)
	}

	// SBOMs by status + unique digests (one scan).
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status = 'active'),
		       count(*) FILTER (WHERE status = 'archived'),
		       count(DISTINCT digest)
		FROM devradar_sbom`).
		Scan(&pc.SBOMsActive, &pc.SBOMsArchived, &pc.UniqueDigests); err != nil {
		return nil, fmt.Errorf("count sboms: %w", err)
	}

	// Open findings by severity.
	if err := s.groupCount(ctx,
		`SELECT severity, count(*) FROM devradar_finding GROUP BY severity`,
		func(k string, n int) { pc.FindingsBySev[k] = n; pc.OpenFindings += n }); err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}

	// Finding-events in the last 24h, by cause.
	if err := s.groupCount(ctx,
		`SELECT cause, count(*) FROM devradar_finding_event
		 WHERE occurred_at > now() - interval '24 hours' GROUP BY cause`,
		func(k string, n int) { pc.EventsByCause24h[k] = n; pc.Events24h += n }); err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	// Scan failures in the last 24h.
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE stage <> $1),
		       count(*) FILTER (WHERE stage = $1)
		FROM devradar_scan_failure
		WHERE occurred_at > now() - interval '24 hours'`, WarningStage).
		Scan(&pc.Failures24h, &pc.Warnings24h); err != nil {
		return nil, fmt.Errorf("count failures: %w", err)
	}

	// VEX statements (table exists from migration 006).
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_vex_statement`).Scan(&pc.VEXStatements); err != nil {
		return nil, fmt.Errorf("count vex: %w", err)
	}

	return pc, nil
}

// groupCount runs a two-column (text key, int count) GROUP BY query and invokes
// emit for each row. Shared by the dashboard's per-severity and per-cause tallies.
func (s *Store) groupCount(ctx context.Context, query string, emit func(key string, n int)) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return err
		}
		emit(key, n)
	}
	return rows.Err()
}

// AdminScanRun is one recent scan, joined to its SBOM for operator context.
type AdminScanRun struct {
	SBOMID        string
	ImageRef      string
	TenantEmail   string
	Scanner       string
	DBVersion     string
	ScannerVer    string
	Canonicalizer string
	FindingCount  int
	ScannedAt     time.Time
}

// AdminRecentScanRuns returns the most recent scan runs across all tenants.
func (s *Store) AdminRecentScanRuns(ctx context.Context, limit int) ([]AdminScanRun, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sr.sbom_id, sb.image_ref, t.email, sr.scanner, sr.db_version,
		       sr.scanner_version, sr.canonicalizer_version, sr.finding_count, sr.scanned_at
		FROM devradar_scan_run sr
		JOIN devradar_sbom sb ON sb.id = sr.sbom_id
		JOIN devradar_tenant t ON t.id = sb.tenant_id
		ORDER BY sr.scanned_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("recent scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AdminScanRun
	for rows.Next() {
		var r AdminScanRun
		if err := rows.Scan(&r.SBOMID, &r.ImageRef, &r.TenantEmail, &r.Scanner,
			&r.DBVersion, &r.ScannerVer, &r.Canonicalizer, &r.FindingCount, &r.ScannedAt); err != nil {
			return nil, fmt.Errorf("scan run row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScannerFreshness reports the newest vuln-DB snapshot seen per scanner and how
// long ago that scanner last ran — catches a stuck EnsureDB.
type ScannerFreshness struct {
	Scanner     string
	DBVersion   string
	LastScanned time.Time
}

// AdminScannerDBFreshness returns the latest run per scanner.
func (s *Store) AdminScannerDBFreshness(ctx context.Context) ([]ScannerFreshness, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT ON (scanner) scanner, db_version, scanned_at
		FROM devradar_scan_run
		ORDER BY scanner, scanned_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("scanner freshness: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ScannerFreshness
	for rows.Next() {
		var f ScannerFreshness
		if err := rows.Scan(&f.Scanner, &f.DBVersion, &f.LastScanned); err != nil {
			return nil, fmt.Errorf("scan freshness row: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ScanBacklog summarizes the SBOMs currently due for a scan.
type ScanBacklog struct {
	Due       int
	OldestDue time.Time // submitted_at of the oldest due SBOM (zero if none)
}

// AdminScanBacklog counts active SBOMs due for a scan under the given staleness
// window and expected-scanner set (mirrors ListScannableSBOMs work-selection —
// per-scanner freshness plus the force-rescan override), and reports the oldest
// one's submission time. An empty expected set counts every active SBOM.
func (s *Store) AdminScanBacklog(ctx context.Context, maxAge time.Duration, expected []string) (*ScanBacklog, error) {
	var oldest sql.NullTime
	b := &ScanBacklog{}
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*), min(sb.submitted_at)
		FROM devradar_sbom sb
		WHERE sb.status = 'active'
		  AND (sb.rescan_requested_at IS NOT NULL
		    OR EXISTS (
		      SELECT 1 FROM unnest($2::text[]) AS want(scanner)
		      WHERE NOT EXISTS (
		        SELECT 1 FROM devradar_scan_run sr
		        WHERE sr.sbom_id = sb.id
		          AND sr.scanner = want.scanner
		          AND sr.scanned_at > now() - $1::interval)))`,
		fmt.Sprintf("%d seconds", int64(maxAge.Seconds())), pq.Array(expected)).Scan(&b.Due, &oldest)
	if err != nil {
		return nil, fmt.Errorf("scan backlog: %w", err)
	}
	if oldest.Valid {
		b.OldestDue = oldest.Time
	}
	return b, nil
}

// AdminFailure is a scan failure with its SBOM/tenant context.
type AdminFailure struct {
	ID          int64
	SBOMID      string
	ImageRef    string
	TenantEmail string
	Scanner     string
	Stage       string
	Error       string
	OccurredAt  time.Time
}

// IsWarning reports whether this row is the informational zero-findings tripwire
// rather than a genuine scan error (see WarningStage).
func (f AdminFailure) IsWarning() bool { return f.Stage == WarningStage }

// AdminRecentFailures returns recent scan failures across all tenants, newest
// first. A non-empty scanner filters to that scanner.
func (s *Store) AdminRecentFailures(ctx context.Context, scanner string, limit int) ([]AdminFailure, error) {
	where := ""
	args := []any{limit}
	if scanner != "" {
		where = `WHERE sf.scanner = $2`
		args = append(args, scanner)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sf.id, sf.sbom_id, COALESCE(sb.image_ref,''), COALESCE(t.email,''),
		       COALESCE(sf.scanner,''), sf.stage, sf.error, sf.occurred_at
		FROM devradar_scan_failure sf
		LEFT JOIN devradar_sbom sb ON sb.id = sf.sbom_id
		LEFT JOIN devradar_tenant t ON t.id = sb.tenant_id
		`+where+`
		ORDER BY sf.occurred_at DESC
		LIMIT $1`, args...)
	if err != nil {
		return nil, fmt.Errorf("recent failures: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AdminFailure
	for rows.Next() {
		var f AdminFailure
		if err := rows.Scan(&f.ID, &f.SBOMID, &f.ImageRef, &f.TenantEmail,
			&f.Scanner, &f.Stage, &f.Error, &f.OccurredAt); err != nil {
			return nil, fmt.Errorf("failure row: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ScanHistoryPoint is one hourly bucket for the scans-over-time chart.
type ScanHistoryPoint struct {
	Hour     time.Time `json:"hour"`
	Scans    int       `json:"scans"`
	Findings int       `json:"findings"`
}

// AdminScanHistory returns hourly scan/finding totals over the last N hours.
func (s *Store) AdminScanHistory(ctx context.Context, hours int) ([]ScanHistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT date_trunc('hour', scanned_at) AS hour,
		       count(*) AS scans,
		       COALESCE(sum(finding_count), 0) AS findings
		FROM devradar_scan_run
		WHERE scanned_at > now() - ($1 || ' hours')::interval
		GROUP BY hour
		ORDER BY hour`, hours)
	if err != nil {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ScanHistoryPoint
	for rows.Next() {
		var p ScanHistoryPoint
		if err := rows.Scan(&p.Hour, &p.Scans, &p.Findings); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TenantSBOMSummary is the per-tenant rollup shown on the tenant detail page.
type TenantSBOMSummary struct {
	SBOMsActive   int
	SBOMsArchived int
	OpenFindings  int
	LastScannedAt time.Time // zero if never scanned
}

// AdminTenantSBOMSummary rolls up one tenant's SBOM/finding/scan activity.
func (s *Store) AdminTenantSBOMSummary(ctx context.Context, tenantID string) (*TenantSBOMSummary, error) {
	sum := &TenantSBOMSummary{}
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status = 'active'),
		       count(*) FILTER (WHERE status = 'archived')
		FROM devradar_sbom WHERE tenant_id = $1`, tenantID).
		Scan(&sum.SBOMsActive, &sum.SBOMsArchived); err != nil {
		return nil, fmt.Errorf("tenant sbom counts: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id = f.sbom_id
		WHERE sb.tenant_id = $1`, tenantID).Scan(&sum.OpenFindings); err != nil {
		return nil, fmt.Errorf("tenant finding count: %w", err)
	}

	var last sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
		SELECT max(sr.scanned_at)
		FROM devradar_scan_run sr
		JOIN devradar_sbom sb ON sb.id = sr.sbom_id
		WHERE sb.tenant_id = $1`, tenantID).Scan(&last); err != nil {
		return nil, fmt.Errorf("tenant last scan: %w", err)
	}
	if last.Valid {
		sum.LastScannedAt = last.Time
	}
	return sum, nil
}

// AdminResetFailure deletes one scan-failure row (an operator ack that the
// failure has been triaged). Returns sql.ErrNoRows if no such row.
func (s *Store) AdminResetFailure(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_scan_failure WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("reset failure: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// AdminRequestRescan marks an SBOM due for a rescan on the next scheduler tick
// (see migration 013). Returns sql.ErrNoRows if the SBOM does not exist.
func (s *Store) AdminRequestRescan(ctx context.Context, sbomID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devradar_sbom SET rescan_requested_at = now() WHERE id = $1`, sbomID)
	if err != nil {
		return fmt.Errorf("request rescan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ── Platform stats snapshots (devradar_platform_stats, migration 014) ─────────

// PlatformSnapshot is one day's recorded platform state.
type PlatformSnapshot struct {
	Tenants       int
	SBOMsActive   int
	UniqueDigests int
	OpenFindings  int
	CriticalOpen  int
	HighOpen      int
	VEXStatements int
}

// SnapshotPlatformStats computes today's platform state and UPSERTs it into
// devradar_platform_stats keyed by UTC date (last write of the day wins). Called
// on each dashboard visit and once per scan-job run so point-in-time deltas have
// data to compare. Returns the snapshot it wrote.
func (s *Store) SnapshotPlatformStats(ctx context.Context) (*PlatformSnapshot, error) {
	snap := &PlatformSnapshot{}

	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant`).Scan(&snap.Tenants); err != nil {
		return nil, fmt.Errorf("snapshot tenants: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status = 'active'), count(DISTINCT digest)
		FROM devradar_sbom`).Scan(&snap.SBOMsActive, &snap.UniqueDigests); err != nil {
		return nil, fmt.Errorf("snapshot sboms: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE severity = 'critical'),
		       count(*) FILTER (WHERE severity = 'high')
		FROM devradar_finding`).
		Scan(&snap.OpenFindings, &snap.CriticalOpen, &snap.HighOpen); err != nil {
		return nil, fmt.Errorf("snapshot findings: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_vex_statement`).Scan(&snap.VEXStatements); err != nil {
		return nil, fmt.Errorf("snapshot vex: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO devradar_platform_stats
			(snapshot_date, tenants, sboms_active, unique_digests,
			 open_findings, critical_open, high_open, vex_statements, captured_at)
		VALUES ((now() AT TIME ZONE 'UTC')::date, $1,$2,$3,$4,$5,$6,$7, now())
		ON CONFLICT (snapshot_date) DO UPDATE SET
			tenants = EXCLUDED.tenants,
			sboms_active = EXCLUDED.sboms_active,
			unique_digests = EXCLUDED.unique_digests,
			open_findings = EXCLUDED.open_findings,
			critical_open = EXCLUDED.critical_open,
			high_open = EXCLUDED.high_open,
			vex_statements = EXCLUDED.vex_statements,
			captured_at = now()`,
		snap.Tenants, snap.SBOMsActive, snap.UniqueDigests,
		snap.OpenFindings, snap.CriticalOpen, snap.HighOpen, snap.VEXStatements); err != nil {
		return nil, fmt.Errorf("upsert platform stats: %w", err)
	}
	return snap, nil
}

// PlatformDelta pairs a current value with its change vs a prior snapshot. Has
// reports whether a baseline snapshot existed for that horizon (no baseline ⇒
// the UI shows "—" rather than a misleading zero delta).
type PlatformDelta struct {
	Has   bool
	Delta int
}

// PlatformDeltas returns, for each requested look-back in days, the difference
// between the most recent snapshot and the newest snapshot on-or-before that
// horizon, for each tracked metric. Keys of the returned map are the day counts
// passed in (e.g. 1, 7, 30). The newest snapshot is taken as "current" so the
// dashboard reflects the value written on this very visit.
func (s *Store) PlatformDeltas(ctx context.Context, horizonsDays []int) (map[int]map[string]PlatformDelta, error) {
	cur, ok, err := s.latestSnapshot(ctx, 0)
	if err != nil {
		return nil, err
	}
	out := map[int]map[string]PlatformDelta{}
	if !ok {
		return out, nil // no snapshots yet
	}
	for _, d := range horizonsDays {
		prev, had, err := s.latestSnapshot(ctx, d)
		if err != nil {
			return nil, err
		}
		if !had {
			prev = &PlatformSnapshot{} // no baseline: cells report Has=false, Delta unused
		}
		m := map[string]PlatformDelta{}
		for _, f := range []struct {
			key      string
			cur, prv int
		}{
			{"tenants", cur.Tenants, prev.Tenants},
			{"sboms_active", cur.SBOMsActive, prev.SBOMsActive},
			{"unique_digests", cur.UniqueDigests, prev.UniqueDigests},
			{"open_findings", cur.OpenFindings, prev.OpenFindings},
			{"critical_open", cur.CriticalOpen, prev.CriticalOpen},
			{"high_open", cur.HighOpen, prev.HighOpen},
			{"vex_statements", cur.VEXStatements, prev.VEXStatements},
		} {
			m[f.key] = PlatformDelta{Has: had, Delta: f.cur - f.prv}
		}
		out[d] = m
	}
	return out, nil
}

// latestSnapshot returns the newest snapshot on-or-before (today - agoDays).
// agoDays 0 means the newest snapshot overall (the current point).
func (s *Store) latestSnapshot(ctx context.Context, agoDays int) (*PlatformSnapshot, bool, error) {
	snap := &PlatformSnapshot{}
	err := s.db.QueryRowContext(ctx, `
		SELECT tenants, sboms_active, unique_digests, open_findings,
		       critical_open, high_open, vex_statements
		FROM devradar_platform_stats
		WHERE snapshot_date <= (now() AT TIME ZONE 'UTC')::date - ($1 || ' days')::interval
		ORDER BY snapshot_date DESC
		LIMIT 1`, agoDays).
		Scan(&snap.Tenants, &snap.SBOMsActive, &snap.UniqueDigests, &snap.OpenFindings,
			&snap.CriticalOpen, &snap.HighOpen, &snap.VEXStatements)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("latest snapshot: %w", err)
	}
	return snap, true, nil
}
