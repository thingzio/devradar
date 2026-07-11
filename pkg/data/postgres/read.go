package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// SeverityCounts is the per-severity breakdown for an image. Levels below the
// requested threshold are zeroed (unknown is always kept). The per-severity
// buckets use omitempty, so only severities that are at/above the threshold AND
// non-zero appear in the response — a level with nothing to show is dropped
// rather than rendered as 0. Total (all findings) and Relevant (sum of visible
// buckets) are always present, including when Relevant is 0.
type SeverityCounts struct {
	Critical   int `json:"critical,omitempty"`
	High       int `json:"high,omitempty"`
	Medium     int `json:"medium,omitempty"`
	Low        int `json:"low,omitempty"`
	Negligible int `json:"negligible,omitempty"`
	Unknown    int `json:"unknown,omitempty"`
	Total      int `json:"total"`
	Relevant   int `json:"relevant"`
}

// Image is a tenant-facing summary of one tracked image (one SBOM).
type Image struct {
	SBOMID      string         `json:"sbom_id"`
	ImageRef    string         `json:"image_ref"`
	Digest      string         `json:"digest"`
	Format      string         `json:"format"`
	SubmittedAt time.Time      `json:"submitted_at"`
	Counts      SeverityCounts `json:"counts"`
	// Failures is the number of recorded scan failures for this SBOM. Non-zero
	// means at least one scanner errored or returned nothing — the counts above
	// may be from fewer scanners than configured. See GET /v1/sboms/{id}/failures.
	Failures int `json:"failures,omitempty"`
}

// listImagesRollupSQL is the fast path: one rollup row per image, no finding
// aggregation. COALESCE handles a not-yet-scanned SBOM (no rollup row) as zeros.
const listImagesRollupSQL = `
	SELECT sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at,
	       COALESCE(r.critical, 0), COALESCE(r.high, 0), COALESCE(r.medium, 0),
	       COALESCE(r.low, 0), COALESCE(r.negligible, 0), COALESCE(r.unknown, 0),
	       COALESCE(r.total, 0),
	       (SELECT COUNT(*) FROM devradar_scan_failure sf WHERE sf.sbom_id = sb.id) AS failures
	FROM devradar_sbom sb
	LEFT JOIN devradar_sbom_rollup r ON r.sbom_id = sb.id
	WHERE sb.tenant_id = $1 AND sb.status = 'active'
	ORDER BY sb.submitted_at DESC`

// listImagesLiveSQL is the VEX-aware fallback. COUNT(DISTINCT f.finding_id): a
// CVE found by both grype and trivy shares one finding_id; DISTINCT gives a true
// per-image count. VEX-suppressed findings are excluded from the join.
var listImagesLiveSQL = `
	SELECT sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'critical')   AS crit,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'high')       AS high,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'medium')     AS med,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'low')        AS low,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'negligible') AS neg,
	       COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'unknown')    AS unk,
	       COUNT(DISTINCT f.finding_id)                                          AS total,
	       (SELECT COUNT(*) FROM devradar_scan_failure sf WHERE sf.sbom_id = sb.id) AS failures
	FROM devradar_sbom sb
	LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
		AND NOT ` + vexSuppressedByDigestCVE + `
	WHERE sb.tenant_id = $1 AND sb.status = 'active'
	GROUP BY sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at
	ORDER BY sb.submitted_at DESC`

// ListImages returns a tenant's active images. Every tracked image is returned
// (the list is an inventory — images never disappear); minSeverity trims the
// per-severity breakdown to levels at or above the threshold (unknown always
// kept), zeroing the rest. Total still reflects all findings. Tenant-scoped.
func (s *Store) ListImages(ctx context.Context, tenantID, minSeverity string) ([]Image, error) {
	hasVEX, err := s.TenantHasSuppressingVEX(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Counts source: the pre-computed per-SBOM rollup (one row per image, no
	// finding scan) on the fast path, or a live VEX-aware re-aggregation of
	// devradar_finding for tenants with a suppressing VEX statement. Both expose
	// the same crit/high/…/total/failures columns so the scan below is shared.
	// COUNT(DISTINCT f.finding_id) dedups a CVE found by both grype and trivy;
	// the rollup already stores that deduped count per SBOM.
	query := listImagesRollupSQL
	if hasVEX {
		query = listImagesLiveSQL
	}
	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Image
	for rows.Next() {
		var im Image
		var c SeverityCounts
		if err := rows.Scan(&im.SBOMID, &im.ImageRef, &im.Digest, &im.Format, &im.SubmittedAt,
			&c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown, &c.Total, &im.Failures); err != nil {
			return nil, fmt.Errorf("scan image: %w", err)
		}
		im.Counts = applyThreshold(c, minSeverity)
		out = append(out, im)
	}
	return out, rows.Err()
}

// applyThreshold zeroes the per-severity buckets below min (unknown is always
// kept) and sets Relevant to the sum of the visible buckets. Total is left as
// the overall finding count. Uses the shared ordering so it can't drift from the
// row filter on /findings and /events.
func applyThreshold(c SeverityCounts, min string) SeverityCounts {
	buckets := map[string]*int{
		data.SeverityCritical:   &c.Critical,
		data.SeverityHigh:       &c.High,
		data.SeverityMedium:     &c.Medium,
		data.SeverityLow:        &c.Low,
		data.SeverityNegligible: &c.Negligible,
	}
	relevant := c.Unknown // unknown always kept
	for sev, p := range buckets {
		if data.MeetsThreshold(sev, min) {
			relevant += *p
		} else {
			*p = 0 // trim sub-threshold bucket from the breakdown
		}
	}
	c.Relevant = relevant
	return c
}

// Finding is a tenant-facing current finding row. EPSS/KEV are enrichment
// overlays joined from devradar_cve_enrichment (nil/false when no data).
type Finding struct {
	Scanner  string  `json:"scanner"`
	Exposure string  `json:"exposure"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	Severity string  `json:"severity"`
	Score    float32 `json:"score"`
	IsFixed  bool    `json:"is_fixed"`
	// Risk enrichment.
	EPSS    *float32 `json:"epss,omitempty"`     // [0,1] exploit probability
	EPSSPct *float32 `json:"epss_pct,omitempty"` // [0,1] percentile
	KEV     bool     `json:"kev,omitempty"`      // in CISA known-exploited catalog
	// VEXStatus is the tenant's latest VEX assertion for this finding, or "" if
	// none (not_affected/fixed are suppressed by default; shown only when asked).
	VEXStatus string `json:"vex_status,omitempty"`
}

// severityRankSQL orders findings worst-first; shared by the query and the
// keyset predicate so they can't drift.
const severityRankSQL = `CASE severity
	WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	WHEN 'low' THEN 3 WHEN 'negligible' THEN 4 ELSE 5 END`

// severityRankSQLCol is severityRankSQL for a specific column reference (needed
// when a query has multiple tables and the bare column is ambiguous).
func severityRankSQLCol(col string) string {
	return `CASE ` + col + `
		WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 WHEN 'negligible' THEN 4 ELSE 5 END`
}

// findingSortCols is the whitelist of sortable columns for the findings table.
// Each expr is COALESCE'd non-null; finding_id is the unique tiebreak.
var findingSortCols = map[string]sortCol{
	"severity": {expr: severityRankSQL, cast: "double precision", defDesc: false}, // rank asc = worst first
	"cvss":     {expr: "f.score", cast: "double precision", defDesc: true},
	"epss":     {expr: "COALESCE(e.epss_score, -1)", cast: "double precision", defDesc: true},
	"package":  {expr: "f.package", cast: "text", defDesc: false},
	"cve":      {expr: "f.exposure", cast: "text", defDesc: false},
	"scanner":  {expr: "f.scanner", cast: "text", defDesc: false},
	"fixable":  {expr: "f.is_fixed::int", cast: "double precision", defDesc: true},
}

// FindingsBySBOM returns current findings for one SBOM at or above minSeverity
// (unknown always included), keyset-paginated. Sortable by any findingSortCols
// key (default "severity" = worst first); fixableOnly restricts to findings with
// a fix; showSuppressed includes VEX-suppressed findings (hidden by default).
// Tenant-scoped; ErrNotFound if not owned.
func (s *Store) FindingsBySBOM(ctx context.Context, tenantID, sbomID, minSeverity string, fixableOnly, showSuppressed bool, sortKey, sortDir, cursor string, limit int) (items []Finding, next string, err error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, "", err
	}
	eff, fetch := clampLimit(limit)
	sort := resolveSort(sortKey, sortDir, findingSortCols, "severity")
	cur, hasCur := decodeSortCursor(cursor)

	// A CVE found by both grype and trivy yields two devradar_finding rows sharing
	// one finding_id (PK is (sbom_id, scanner, finding_id)). finding_id alone is
	// therefore NOT a unique keyset tiebreak — twins that tie on the sort value
	// would straddle a page boundary and one could be silently dropped by the
	// seek. Use the genuinely-unique composite (finding_id|scanner); finding_id is
	// sha256 hex, so '|' never collides.
	const tiebreak = "(f.finding_id || '|' || f.scanner)"

	args := []any{sbomID, pq.Array(data.AllowedSeverities(minSeverity))}
	conds := ""
	if fixableOnly {
		conds += " AND f.is_fixed"
	}
	if !showSuppressed {
		conds += " AND NOT " + vexSuppressedExpr
	}
	if hasCur {
		conds += " AND " + sort.seek(tiebreak, len(args)+1, len(args)+2)
		args = append(args, cur.Val, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT f.scanner, f.exposure, f.package, f.version, f.severity, f.score, f.is_fixed,
		       %s,
		       e.epss_score, e.epss_percentile, COALESCE(e.kev, false),
		       vex.vex_status,
		       %s
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id = f.sbom_id
		LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure%s
		WHERE f.sbom_id = $1 AND f.severity = ANY($2)%s
		ORDER BY %s
		LIMIT %s`, tiebreak, sort.selectVal(), vexStatusJoin, conds, sort.orderBy(tiebreak), limitPos), args...)
	if err != nil {
		return nil, "", fmt.Errorf("findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type key struct{ val, id string }
	var keys []key
	for rows.Next() {
		var f Finding
		var k key
		var vexStatus *string
		if err := rows.Scan(&f.Scanner, &f.Exposure, &f.Package, &f.Version, &f.Severity, &f.Score, &f.IsFixed,
			&k.id, &f.EPSS, &f.EPSSPct, &f.KEV, &vexStatus, &k.val); err != nil {
			return nil, "", fmt.Errorf("scan finding: %w", err)
		}
		f.VEXStatus = deref(vexStatus)
		items = append(items, f)
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		k := keys[eff-1]
		next = encodeSortCursor(k.val, k.id)
	}
	return items, next, nil
}

// PackageFinding rolls up findings for one package: the count and its worst
// severity, so a long finding list reads as a handful of upgrade decisions.
type PackageFinding struct {
	Package    string `json:"package"`
	Count      int    `json:"count"`
	Fixable    int    `json:"fixable"`
	WorstSev   string `json:"worst_severity"`
	FixablePct int    `json:"-"`
}

// PackageRollup groups an SBOM's findings by package (worst severity first, then
// count), returning the top `limit` packages. Tenant-scoped; ErrNotFound if not
// owned. Not paginated — it's a bounded summary (top N), not a full listing.
func (s *Store) PackageRollup(ctx context.Context, tenantID, sbomID, minSeverity string, limit int) ([]PackageFinding, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT f.package,
		       COUNT(*)                          AS n,
		       COUNT(*) FILTER (WHERE f.is_fixed) AS fixable,
		       MIN(%s)                           AS worst_rank
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id = f.sbom_id
		WHERE f.sbom_id = $1 AND f.severity = ANY($2)
		  AND NOT %s
		GROUP BY f.package
		ORDER BY worst_rank, n DESC, f.package
		LIMIT $3`, severityRankSQL, vexSuppressedByDigestCVE),
		sbomID, pq.Array(data.AllowedSeverities(minSeverity)), limit)
	if err != nil {
		return nil, fmt.Errorf("package rollup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []PackageFinding
	for rows.Next() {
		var p PackageFinding
		var rank int
		if err := rows.Scan(&p.Package, &p.Count, &p.Fixable, &rank); err != nil {
			return nil, fmt.Errorf("scan package rollup: %w", err)
		}
		p.WorstSev = severityForRank(rank)
		if p.Count > 0 {
			p.FixablePct = p.Fixable * 100 / p.Count
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func severityForRank(rank int) string {
	switch rank {
	case 0:
		return "critical"
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	case 4:
		return "negligible"
	default:
		return "unknown"
	}
}

// Event is a tenant-facing change-log row.
type Event struct {
	Scanner    string    `json:"scanner"`
	EventType  string    `json:"event_type"`
	Exposure   string    `json:"exposure"`
	Package    string    `json:"package"`
	Severity   string    `json:"severity"`
	Score      float32   `json:"score"`
	Cause      string    `json:"cause"`
	OccurredAt time.Time `json:"occurred_at"`
}

// EventsBySBOM returns change history for one SBOM at or above minSeverity
// (unknown always included), newest first, keyset-paginated on (occurred_at, id)
// so a long history pages cleanly instead of silently truncating at a fixed cap.
// Tenant-scoped.
func (s *Store) EventsBySBOM(ctx context.Context, tenantID, sbomID, minSeverity, cursor string, limit int) (items []Event, next string, err error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, "", err
	}
	eff, fetch := clampLimit(limit)
	cur, hasCur := decodeCursor(cursor)

	args := []any{sbomID, pq.Array(data.AllowedSeverities(minSeverity))}
	keyset := ""
	if hasCur {
		keyset = ` AND (occurred_at, id) < ($3, $4)`
		args = append(args, cur.TS, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id, scanner, event_type, exposure, package, severity, score, cause, occurred_at
		FROM devradar_finding_event
		WHERE sbom_id = $1 AND severity = ANY($2)%s
		ORDER BY occurred_at DESC, id DESC
		LIMIT %s`, keyset, limitPos), args...)
	if err != nil {
		return nil, "", fmt.Errorf("events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var e Event
		var id int64
		if err := rows.Scan(&id, &e.Scanner, &e.EventType, &e.Exposure, &e.Package,
			&e.Severity, &e.Score, &e.Cause, &e.OccurredAt); err != nil {
			return nil, "", fmt.Errorf("scan event: %w", err)
		}
		items = append(items, e)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeCursor(items[len(items)-1].OccurredAt, strconv.FormatInt(ids[eff-1], 10))
	}
	return items, next, nil
}

// TimelineEvent is one change in an image's history, carrying the digest it
// occurred on so a caller can see the inventory progress across digest changes.
type TimelineEvent struct {
	Digest     string    `json:"digest"`
	SBOMID     string    `json:"sbom_id"`
	Scanner    string    `json:"scanner"`
	EventType  string    `json:"event_type"`
	Exposure   string    `json:"exposure"`
	Package    string    `json:"package"`
	Severity   string    `json:"severity"`
	Score      float32   `json:"score"`
	Cause      string    `json:"cause"`
	OccurredAt time.Time `json:"occurred_at"`
}

// ImageTimeline returns the change history for an image ref across ALL its
// digests — the cross-digest view of how one tracked image evolved. Filtered to
// minSeverity (unknown always included), newest first. Tenant-scoped; returns
// ErrNotFound if the ref is unknown to the tenant (so an empty history and an
// unknown image are distinguishable).
func (s *Store) ImageTimeline(ctx context.Context, tenantID, imageRef, minSeverity string, limit int) ([]TimelineEvent, error) {
	var known bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE tenant_id = $1 AND image_ref = $2)`,
		tenantID, imageRef).Scan(&known); err != nil {
		return nil, fmt.Errorf("check image ref: %w", err)
	}
	if !known {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.digest, e.sbom_id, e.scanner, e.event_type, e.exposure, e.package,
		       e.severity, e.score, e.cause, e.occurred_at
		FROM devradar_finding_event e
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		WHERE e.tenant_id = $1 AND sb.image_ref = $2 AND e.severity = ANY($3)
		ORDER BY e.occurred_at DESC LIMIT $4`,
		tenantID, imageRef, pq.Array(data.AllowedSeverities(minSeverity)), limit)
	if err != nil {
		return nil, fmt.Errorf("image timeline: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []TimelineEvent
	for rows.Next() {
		var t TimelineEvent
		if err := rows.Scan(&t.Digest, &t.SBOMID, &t.Scanner, &t.EventType, &t.Exposure,
			&t.Package, &t.Severity, &t.Score, &t.Cause, &t.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan timeline event: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SBOMDetail is a tenant-facing view of one SBOM's metadata.
type SBOMDetail struct {
	SBOMID      string         `json:"sbom_id"`
	ImageRef    string         `json:"image_ref"`
	Digest      string         `json:"digest"`
	Format      string         `json:"format"`
	SpecVersion string         `json:"spec_version,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	ToolVersion string         `json:"tool_version,omitempty"`
	Status      string         `json:"status"`
	SubmittedAt time.Time      `json:"submitted_at"`
	GeneratedAt *time.Time     `json:"generated_at,omitempty"`
	Labels      []string       `json:"labels,omitempty"`
	Counts      SeverityCounts `json:"counts"`
}

// GetSBOM returns one SBOM's metadata + full severity breakdown, tenant-scoped.
// minSeverity trims the breakdown as in ListImages. ErrNotFound if not owned.
func (s *Store) GetSBOM(ctx context.Context, tenantID, sbomID, minSeverity string) (*SBOMDetail, error) {
	var d SBOMDetail
	var c SeverityCounts
	var tool, toolVer, spec sql.NullString
	var gen sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT sb.id, sb.image_ref, sb.digest, sb.format, sb.spec_version, sb.tool, sb.tool_version,
		       sb.status, sb.submitted_at, sb.generated_at, sb.labels,
		       COUNT(*) FILTER (WHERE f.severity='critical'),
		       COUNT(*) FILTER (WHERE f.severity='high'),
		       COUNT(*) FILTER (WHERE f.severity='medium'),
		       COUNT(*) FILTER (WHERE f.severity='low'),
		       COUNT(*) FILTER (WHERE f.severity='negligible'),
		       COUNT(*) FILTER (WHERE f.severity='unknown'),
		       COUNT(f.finding_id)
		FROM devradar_sbom sb
		LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
			AND NOT `+vexSuppressedByDigestCVE+`
		WHERE sb.id = $1 AND sb.tenant_id = $2
		GROUP BY sb.id`, sbomID, tenantID).Scan(
		&d.SBOMID, &d.ImageRef, &d.Digest, &d.Format, &spec, &tool, &toolVer,
		&d.Status, &d.SubmittedAt, &gen, pq.Array(&d.Labels),
		&c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown, &c.Total)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get sbom: %w", err)
	}
	d.SpecVersion, d.Tool, d.ToolVersion = spec.String, tool.String, toolVer.String
	if gen.Valid {
		d.GeneratedAt = &gen.Time
	}
	d.Counts = applyThreshold(c, minSeverity)
	return &d, nil
}

// ArchiveSBOM marks a tenant's SBOM archived: it drops out of the scan set
// (ListActiveSBOMs) and the images list, and stops accruing findings. Findings
// and event history are retained. Idempotent. ErrNotFound if not owned.
func (s *Store) ArchiveSBOM(ctx context.Context, tenantID, sbomID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devradar_sbom SET status='archived'
		 WHERE id=$1 AND tenant_id=$2 AND status<>'archived'`, sbomID, tenantID)
	if err != nil {
		return fmt.Errorf("archive sbom: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either not owned/absent, or already archived. Distinguish so a repeat
		// archive is idempotent (200) but an unknown id is 404.
		return s.assertSBOMOwner(ctx, tenantID, sbomID)
	}
	return nil
}

// ArchiveRepo archives every active SBOM (all digests/versions) of one image
// (repository) for a tenant — the "stop tracking this image" action. Like
// ArchiveSBOM it is a soft archive: findings and event history are retained, the
// image drops out of the scan set and the dashboard. Returns the number of SBOMs
// archived (0 = unknown/empty image or already fully archived — the caller can
// treat 0 as idempotent success). Tenant-scoped.
func (s *Store) ArchiveRepo(ctx context.Context, tenantID, repository string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devradar_sbom SET status='archived'
		 WHERE tenant_id=$1 AND repository=$2 AND status='active'`, tenantID, repository)
	if err != nil {
		return 0, fmt.Errorf("archive repo: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ErrNotFound is returned when a tenant-scoped resource doesn't exist or isn't
// owned by the tenant (indistinguishable by design).
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func (s *Store) assertSBOMOwner(ctx context.Context, tenantID, sbomID string) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE id = $1 AND tenant_id = $2)`,
		sbomID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("check sbom owner: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

// Failure is a tenant-facing scan-failure row: a scanner/stage that errored or
// returned nothing for one SBOM. Surfaced so a silent scanner (e.g. Trivy
// finding 0 CVEs on an EOL distro it has no advisories for) is visible, not just
// absent from the findings list.
type Failure struct {
	Scanner    string    `json:"scanner,omitempty"`
	Stage      string    `json:"stage"`
	Error      string    `json:"error"`
	OccurredAt time.Time `json:"occurred_at"`
}

// FailuresBySBOM returns recent scan failures for one SBOM, newest first.
// Tenant-scoped via ownership check; ErrNotFound if the SBOM isn't owned.
func (s *Store) FailuresBySBOM(ctx context.Context, tenantID, sbomID string, limit int) ([]Failure, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scanner, stage, error, occurred_at
		FROM devradar_scan_failure
		WHERE sbom_id = $1
		ORDER BY occurred_at DESC
		LIMIT $2`, sbomID, limit)
	if err != nil {
		return nil, fmt.Errorf("failures: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Failure
	for rows.Next() {
		var f Failure
		var scanner sql.NullString
		if err := rows.Scan(&scanner, &f.Stage, &f.Error, &f.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan failure: %w", err)
		}
		f.Scanner = scanner.String
		out = append(out, f)
	}
	return out, rows.Err()
}

// FailuresByRepo returns recent scan failures across all of a repository's
// active SBOMs (newest first) — so the image page can explain a "scan issue"
// flag rather than just showing it. Tenant-scoped via the join to devradar_sbom.
func (s *Store) FailuresByRepo(ctx context.Context, tenantID, repository string, limit int) ([]Failure, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sf.scanner, sf.stage, sf.error, sf.occurred_at
		FROM devradar_scan_failure sf
		JOIN devradar_sbom sb ON sb.id = sf.sbom_id
		WHERE sb.tenant_id = $1 AND sb.repository = $2 AND sb.status = 'active'
		ORDER BY sf.occurred_at DESC
		LIMIT $3`, tenantID, repository, limit)
	if err != nil {
		return nil, fmt.Errorf("repo failures: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Failure
	for rows.Next() {
		var f Failure
		var scanner sql.NullString
		if err := rows.Scan(&scanner, &f.Stage, &f.Error, &f.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan repo failure: %w", err)
		}
		f.Scanner = scanner.String
		out = append(out, f)
	}
	return out, rows.Err()
}
