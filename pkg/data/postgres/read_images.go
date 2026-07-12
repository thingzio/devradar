package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// RepoImage is one tracked image (a repository) in the grouped images view. It
// collapses every SBOM that shares a repository into a single row — the CUJ-1
// unit "an image I track", independent of how many versions/digests it has.
type RepoImage struct {
	Repository  string         `json:"repository"`
	SBOMCount   int            `json:"sbom_count"`
	DigestCount int            `json:"digest_count"`
	Versions    []string       `json:"versions,omitempty"` // distinct image tags/versions seen (may be empty)
	LatestAt    time.Time      `json:"latest_at"`          // newest submission for the repo
	Counts      SeverityCounts `json:"counts"`             // rollup across the repo's findings
	Fixable     int            `json:"fixable"`            // findings with a fix available (any severity)
	Failures    int            `json:"failures,omitempty"`
}

// repoImageSortCols sort against the img-CTE output aliases. Default "risk" is
// the crit→high→total ranking. "repository" alphabetizes; the count columns sort
// by their aggregate.
var repoImageSortCols = map[string]sortCol{
	"risk":       {expr: "risk", cast: "double precision", defDesc: true},
	"repository": {expr: "repository", cast: "text", defDesc: false},
	"total":      {expr: "total", cast: "double precision", defDesc: true},
	"critical":   {expr: "crit", cast: "double precision", defDesc: true},
	"fixable":    {expr: "fixable", cast: "double precision", defDesc: true},
	"sboms":      {expr: "sbom_count", cast: "double precision", defDesc: true},
}

// rollupImgCTE and liveImgCTE are the two interchangeable bodies of the `img`
// CTE in ListRepoImages. They MUST expose identical output columns/aliases so
// the shared outer query, keyset, and row scan don't care which was used.
//
// rollupImgCTE (fast path) sums devradar_sbom_rollup per repository — no finding
// scan. SUM over per-SBOM rollup rows equals COUNT(DISTINCT (sb.id, finding_id))
// because finding_id is unique within a SBOM. COALESCE handles repos whose SBOMs
// have no rollup row yet (freshly submitted, not scanned) as zeros.
const rollupImgCTE = `
	SELECT sb.repository,
	       COUNT(DISTINCT sb.id)                             AS sbom_count,
	       COUNT(DISTINCT sb.digest)                         AS digest_count,
	       COALESCE(array_agg(DISTINCT sb.version) FILTER (WHERE sb.version IS NOT NULL), '{}') AS versions,
	       MAX(sb.submitted_at)                              AS latest_at,
	       COALESCE(SUM(r.critical), 0)                      AS crit,
	       COALESCE(SUM(r.high), 0)                          AS high,
	       COALESCE(SUM(r.medium), 0)                        AS med,
	       COALESCE(SUM(r.low), 0)                           AS low,
	       COALESCE(SUM(r.negligible), 0)                    AS neg,
	       COALESCE(SUM(r.unknown), 0)                       AS unk,
	       COALESCE(SUM(r.total), 0)                         AS total,
	       COALESCE(SUM(r.fixable), 0)                       AS fixable,
	       (SELECT COUNT(*) FROM devradar_scan_failure sf
	          JOIN devradar_sbom sb2 ON sb2.id = sf.sbom_id
	         WHERE sb2.tenant_id = sb.tenant_id AND sb2.repository = sb.repository) AS failures,
	       COALESCE(SUM(r.critical), 0) * 1000000000::bigint
	         + COALESCE(SUM(r.high), 0) * 100000::bigint
	         + COALESCE(SUM(r.total), 0)                     AS risk
	FROM devradar_sbom sb
	LEFT JOIN devradar_sbom_rollup r ON r.sbom_id = sb.id
	WHERE sb.tenant_id = $1 AND sb.status = 'active'
	  AND ($2 = '' OR sb.repository ILIKE '%' || $2 || '%')
	  AND ($3 = '' OR $3 = ANY(sb.labels))
	GROUP BY sb.tenant_id, sb.repository`

// liveImgCTE (VEX fallback) re-aggregates devradar_finding with VEX-suppressed
// findings excluded. Slower, taken only by tenants with a suppressing statement.
var liveImgCTE = `
	SELECT sb.repository,
	       COUNT(DISTINCT sb.id)                             AS sbom_count,
	       COUNT(DISTINCT sb.digest)                         AS digest_count,
	       COALESCE(array_agg(DISTINCT sb.version) FILTER (WHERE sb.version IS NOT NULL), '{}') AS versions,
	       MAX(sb.submitted_at)                              AS latest_at,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'critical')   AS crit,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'high')       AS high,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'medium')     AS med,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'low')        AS low,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'negligible') AS neg,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'unknown')    AS unk,
	       COUNT(DISTINCT (sb.id, f.finding_id))                               AS total,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.is_fixed)     AS fixable,
	       (SELECT COUNT(*) FROM devradar_scan_failure sf
	          JOIN devradar_sbom sb2 ON sb2.id = sf.sbom_id
	         WHERE sb2.tenant_id = sb.tenant_id AND sb2.repository = sb.repository) AS failures,
	       COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'critical') * 1000000000::bigint
	         + COUNT(DISTINCT (sb.id, f.finding_id)) FILTER (WHERE f.severity = 'high') * 100000::bigint
	         + COUNT(DISTINCT (sb.id, f.finding_id))     AS risk
	FROM devradar_sbom sb
	LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
		AND NOT ` + vexSuppressedByDigestCVE + `
	WHERE sb.tenant_id = $1 AND sb.status = 'active'
	  AND ($2 = '' OR sb.repository ILIKE '%' || $2 || '%')
	  AND ($3 = '' OR $3 = ANY(sb.labels))
	GROUP BY sb.tenant_id, sb.repository`

// ListRepoImages returns a tenant's tracked images grouped by repository,
// sorted in SQL (default "risk" = critical → high → total). Sorting in SQL (not
// a Go re-sort) is what makes keyset pagination correct — the DB order is the
// page order. Keyset on (<sort-col>, repository). Every active SBOM contributes;
// counts are the union of findings across the repo's SBOMs, trimmed to
// minSeverity. Risk uses raw (untrimmed) counts, so ranking is threshold-stable.
func (s *Store) ListRepoImages(ctx context.Context, tenantID, minSeverity, nameFilter, labelFilter, sortKey, sortDir, cursor string, limit int) (items []RepoImage, next string, err error) {
	eff, fetch := clampLimit(limit)
	sort := resolveSort(sortKey, sortDir, repoImageSortCols, "risk")
	cur, hasCur := decodeSortCursor(cursor)

	hasVEX, err := s.TenantHasSuppressingVEX(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}

	// $1 tenant, $2 name filter, $3 label filter (empty = no filter); keyset follows.
	args := []any{tenantID, nameFilter, labelFilter}
	keyset := ""
	if hasCur {
		keyset = "WHERE " + sort.seek("repository", 4, 5)
		args = append(args, cur.Val, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	// The per-repo counts come either from the pre-computed per-SBOM rollup (fast
	// path, no VEX) or from a live VEX-aware re-aggregation of devradar_finding.
	// Both expose the same img-CTE aliases (crit/high/…/total/fixable/risk), so the
	// outer query, keyset, and scan below are shared. Summing per-SBOM rollup rows
	// per repo equals COUNT(DISTINCT (sb.id, finding_id)) because finding_id is
	// unique within a SBOM.
	imgCTE := rollupImgCTE
	if hasVEX {
		imgCTE = liveImgCTE
	}

	q := fmt.Sprintf(`
		WITH img AS (%s)
		SELECT repository, sbom_count, digest_count, versions, latest_at,
		       crit, high, med, low, neg, unk, total, fixable, failures, %s
		FROM img
		%s
		ORDER BY %s
		LIMIT %s`, imgCTE, sort.selectVal(), keyset, sort.orderBy("repository"), limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list repo images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vals []string
	for rows.Next() {
		var im RepoImage
		var c SeverityCounts
		var sortval string
		if err := rows.Scan(&im.Repository, &im.SBOMCount, &im.DigestCount, pq.Array(&im.Versions),
			&im.LatestAt, &c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown,
			&c.Total, &im.Fixable, &im.Failures, &sortval); err != nil {
			return nil, "", fmt.Errorf("scan repo image: %w", err)
		}
		im.Counts = applyThreshold(c, minSeverity)
		items = append(items, im)
		vals = append(vals, sortval)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeSortCursor(vals[eff-1], items[len(items)-1].Repository)
	}
	return items, next, nil
}

// SeverityPoint is one day's severity composition for an image (from scan runs).
type SeverityPoint struct {
	Day      string // YYYY-MM-DD
	Critical int
	High     int
	Medium   int
	Low      int
}

// RepoSeverityTimeline returns per-day severity counts for a repository, derived
// from devradar_scan_run (which snapshots counts per scan). Aggregated across the
// repo's SBOMs/scanners by taking the max per day (scanners overlap; max avoids
// double-counting the same findings). Oldest→newest, last `days` days present.
func (s *Store) RepoSeverityTimeline(ctx context.Context, tenantID, repository string, limit int) ([]SeverityPoint, error) {
	if limit <= 0 || limit > 365 {
		limit = 60
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH per_day AS (
			SELECT date_trunc('day', sr.scanned_at)::date AS day,
			       MAX(sr.critical_count) AS crit, MAX(sr.high_count) AS high,
			       MAX(sr.medium_count) AS med, MAX(sr.low_count) AS low
			FROM devradar_scan_run sr
			JOIN devradar_sbom sb ON sb.id = sr.sbom_id
			WHERE sb.tenant_id = $1 AND sb.repository = $2
			GROUP BY 1
			ORDER BY 1 DESC
			LIMIT $3
		)
		SELECT day::text, crit, high, med, low FROM per_day ORDER BY day ASC`,
		tenantID, repository, limit)
	if err != nil {
		return nil, fmt.Errorf("repo severity timeline: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SeverityPoint
	for rows.Next() {
		var p SeverityPoint
		if err := rows.Scan(&p.Day, &p.Critical, &p.High, &p.Medium, &p.Low); err != nil {
			return nil, fmt.Errorf("scan severity point: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TenantLabels returns the distinct grouping labels across a tenant's active
// SBOMs, sorted — the option set for the dashboard label filter.
func (s *Store) TenantLabels(ctx context.Context, tenantID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT unnest(labels) AS label
		FROM devradar_sbom
		WHERE tenant_id = $1 AND status = 'active'
		ORDER BY label`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant labels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return nil, fmt.Errorf("scan label: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// FleetStats is the tenant-wide rollup for the dashboard headline. It is
// deliberately independent of the paginated image list: summing one page would
// undercount once a tenant has more images than fit on a page.
type FleetStats struct {
	Images   int `json:"images"`
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Fixable  int `json:"fixable"`
	// Fixable-now counts per severity — the actionable subset the remediation
	// chart contrasts against each severity's total.
	FixCritical int `json:"fix_critical"`
	FixHigh     int `json:"fix_high"`
	FixMedium   int `json:"fix_medium"`
	FixLow      int `json:"fix_low"`
	KEV         int `json:"kev"` // distinct known-exploited CVEs across the fleet
	Failures    int `json:"failures"`
	// LastScanAt is the most recent scan across the tenant's active SBOMs (nil if
	// nothing has been scanned yet). Surfaces the daily/periodic scan heartbeat so
	// a freshly-submitted SBOM shows "scan pending" rather than looking broken.
	LastScanAt *time.Time `json:"last_scan_at,omitempty"`
}

// FleetStats returns tenant-wide finding totals across all active images,
// including a count of distinct known-exploited (KEV) CVEs — the strongest
// "patch now" signal in the fleet.
//
// Fast path: when the tenant has no suppressing VEX statement (the common case),
// the finding totals are summed from the pre-computed devradar_sbom_rollup —
// hundreds of rows instead of re-aggregating the whole finding set. A tenant
// that does have suppressing VEX falls back to the live VEX-aware query, which
// is the reference for correctness (so the two paths agree exactly when no VEX
// applies).
func (s *Store) FleetStats(ctx context.Context, tenantID string) (FleetStats, error) {
	hasVEX, err := s.TenantHasSuppressingVEX(ctx, tenantID)
	if err != nil {
		return FleetStats{}, err
	}
	if hasVEX {
		return s.fleetStatsLive(ctx, tenantID)
	}
	return s.fleetStatsRollup(ctx, tenantID)
}

// fleetStatsRollup sums the per-SBOM rollup for the fast (no-VEX) path. The
// finding totals come from devradar_sbom_rollup; Images/Failures/LastScanAt are
// the same cheap sub-selects as the live path.
func (s *Store) fleetStatsRollup(ctx context.Context, tenantID string) (FleetStats, error) {
	var fs FleetStats
	var lastScan sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT repository) FROM devradar_sbom
			   WHERE tenant_id = $1 AND status = 'active'),
			COALESCE(SUM(r.total), 0),
			COALESCE(SUM(r.critical), 0),
			COALESCE(SUM(r.high), 0),
			COALESCE(SUM(r.medium), 0),
			COALESCE(SUM(r.low), 0),
			COALESCE(SUM(r.fixable), 0),
			COALESCE(SUM(r.fix_critical), 0),
			COALESCE(SUM(r.fix_high), 0),
			COALESCE(SUM(r.fix_medium), 0),
			COALESCE(SUM(r.fix_low), 0),
			-- KEV is a DISTINCT-across-fleet count: a known-exploited CVE present in
			-- several images must count once, so it can't be SUM'd from the per-SBOM
			-- rollup (that double-counts). Compute it directly; the partial KEV index
			-- keeps it cheap (few CVEs are KEV-flagged).
			(SELECT COUNT(DISTINCT f.exposure)
			   FROM devradar_finding f
			   JOIN devradar_sbom sk ON sk.id = f.sbom_id
			   JOIN devradar_cve_enrichment e ON e.cve = f.exposure AND e.kev
			  WHERE sk.tenant_id = $1 AND sk.status = 'active'),
			(SELECT COUNT(*) FROM devradar_scan_failure sf
			   JOIN devradar_sbom s2 ON s2.id = sf.sbom_id
			  WHERE s2.tenant_id = $1),
			(SELECT MAX(sr.scanned_at) FROM devradar_scan_run sr
			   JOIN devradar_sbom s3 ON s3.id = sr.sbom_id
			  WHERE s3.tenant_id = $1 AND s3.status = 'active')
		FROM devradar_sbom sb
		LEFT JOIN devradar_sbom_rollup r ON r.sbom_id = sb.id
		WHERE sb.tenant_id = $1 AND sb.status = 'active'`,
		tenantID).Scan(&fs.Images, &fs.Total, &fs.Critical, &fs.High, &fs.Medium, &fs.Low, &fs.Fixable,
		&fs.FixCritical, &fs.FixHigh, &fs.FixMedium, &fs.FixLow, &fs.KEV, &fs.Failures, &lastScan)
	if err != nil {
		return FleetStats{}, fmt.Errorf("fleet stats (rollup): %w", err)
	}
	if lastScan.Valid {
		fs.LastScanAt = &lastScan.Time
	}
	return fs, nil
}

// fleetStatsLive is the VEX-aware fallback: it re-aggregates devradar_finding
// with VEX-suppressed findings excluded. Slower, but only tenants with a
// suppressing VEX statement take this path. KEV here excludes suppressed CVEs
// (it hangs off the same VEX-filtered finding join); the rollup fast path
// computes an equivalent distinct-KEV count over the unsuppressed set, so the
// two paths agree for a tenant with no suppressing VEX.
func (s *Store) fleetStatsLive(ctx context.Context, tenantID string) (FleetStats, error) {
	var fs FleetStats
	var lastScan sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT repository) FROM devradar_sbom
			   WHERE tenant_id = $1 AND status = 'active'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.severity = 'critical'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.severity = 'high'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.severity = 'medium'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.severity = 'low'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.is_fixed),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.is_fixed AND f.severity = 'critical'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.is_fixed AND f.severity = 'high'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.is_fixed AND f.severity = 'medium'),
			COUNT(DISTINCT (f.sbom_id, f.finding_id)) FILTER (WHERE f.is_fixed AND f.severity = 'low'),
			COUNT(DISTINCT f.exposure) FILTER (WHERE e.kev),
			(SELECT COUNT(*) FROM devradar_scan_failure sf
			   JOIN devradar_sbom s2 ON s2.id = sf.sbom_id
			  WHERE s2.tenant_id = $1),
			(SELECT MAX(sr.scanned_at) FROM devradar_scan_run sr
			   JOIN devradar_sbom s3 ON s3.id = sr.sbom_id
			  WHERE s3.tenant_id = $1 AND s3.status = 'active')
		FROM devradar_sbom sb
		LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
			AND NOT `+vexSuppressedByDigestCVE+`
		LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
		WHERE sb.tenant_id = $1 AND sb.status = 'active'`,
		tenantID).Scan(&fs.Images, &fs.Total, &fs.Critical, &fs.High, &fs.Medium, &fs.Low, &fs.Fixable,
		&fs.FixCritical, &fs.FixHigh, &fs.FixMedium, &fs.FixLow, &fs.KEV, &fs.Failures, &lastScan)
	if err != nil {
		return FleetStats{}, fmt.Errorf("fleet stats: %w", err)
	}
	if lastScan.Valid {
		fs.LastScanAt = &lastScan.Time
	}
	return fs, nil
}

// RepoSummary is the header rollup for one image: authoritative totals that
// don't depend on how the SBOM list is paginated.
type RepoSummary struct {
	SBOMCount   int
	DigestCount int
	Versions    []string
	Labels      []string // distinct grouping labels across the image's active SBOMs
}

// RepoSummary returns totals for one repository. ErrNotFound if unknown.
func (s *Store) RepoSummary(ctx context.Context, tenantID, repository string) (RepoSummary, error) {
	var rs RepoSummary
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT id), COUNT(DISTINCT digest),
		       COALESCE(array_agg(DISTINCT version) FILTER (WHERE version IS NOT NULL), '{}'),
		       COALESCE((SELECT array_agg(DISTINCT l ORDER BY l)
		                 FROM devradar_sbom s2, unnest(s2.labels) l
		                 WHERE s2.tenant_id = $1 AND s2.repository = $2 AND s2.status = 'active'), '{}')
		FROM devradar_sbom
		WHERE tenant_id = $1 AND repository = $2 AND status = 'active'`,
		tenantID, repository).Scan(&rs.SBOMCount, &rs.DigestCount, pq.Array(&rs.Versions), pq.Array(&rs.Labels))
	if err != nil {
		return RepoSummary{}, fmt.Errorf("repo summary: %w", err)
	}
	if rs.SBOMCount == 0 {
		return RepoSummary{}, ErrNotFound
	}
	return rs, nil
}

// SBOMsForRepo returns the SBOMs tracked for one repository, newest generation
// first (falling back to submission time when a generator omitted generated_at),
// keyset-paginated. This is CUJ-2: "the versions/digests I have for this image".
// repoSBOMSortCols: default "generated" (newest first). "version" sorts by the
// tag; "packages" by catalogued package count.
var repoSBOMSortCols = map[string]sortCol{
	"generated": {expr: "COALESCE(generated_at, submitted_at)", cast: "timestamptz", defDesc: true},
	"version":   {expr: "COALESCE(version, '')", cast: "text", defDesc: false},
	"packages":  {expr: "package_count", cast: "double precision", defDesc: true},
}

func (s *Store) SBOMsForRepo(ctx context.Context, tenantID, repository, sortKey, sortDir, cursor string, limit int) (items []RepoSBOM, next string, err error) {
	// Ownership/existence: distinguish "no such image" (404) from "empty page".
	var known bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE tenant_id = $1 AND repository = $2)`,
		tenantID, repository).Scan(&known); err != nil {
		return nil, "", fmt.Errorf("check repository: %w", err)
	}
	if !known {
		return nil, "", ErrNotFound
	}

	eff, fetch := clampLimit(limit)
	sort := resolveSort(sortKey, sortDir, repoSBOMSortCols, "generated")
	cur, hasCur := decodeSortCursor(cursor)

	where := `WHERE tenant_id = $1 AND repository = $2 AND status = 'active'`
	args := []any{tenantID, repository}
	if hasCur {
		where += " AND " + sort.seek("id", 3, 4)
		args = append(args, cur.Val, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		SELECT id, digest, version, format, tool, tool_version, package_count,
		       COALESCE(generated_at, submitted_at) AS effective_at, submitted_at,
		       %s
		FROM devradar_sbom
		%s
		ORDER BY %s
		LIMIT %s`, sort.selectVal(), where, sort.orderBy("id"), limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("sboms for repo: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vals []string
	for rows.Next() {
		var it RepoSBOM
		var version, tool, toolVer *string
		var sortval string
		if err := rows.Scan(&it.SBOMID, &it.Digest, &version, &it.Format, &tool, &toolVer,
			&it.PackageCount, &it.EffectiveAt, &it.SubmittedAt, &sortval); err != nil {
			return nil, "", fmt.Errorf("scan repo sbom: %w", err)
		}
		it.Version = deref(version)
		it.Tool = deref(tool)
		it.ToolVersion = deref(toolVer)
		items = append(items, it)
		vals = append(vals, sortval)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeSortCursor(vals[eff-1], items[len(items)-1].SBOMID)
	}
	return items, next, nil
}

// RepoSBOM is one SBOM in the per-image list.
type RepoSBOM struct {
	SBOMID       string    `json:"sbom_id"`
	Digest       string    `json:"digest"`
	Version      string    `json:"version,omitempty"`
	Format       string    `json:"format"`
	Tool         string    `json:"tool,omitempty"`
	ToolVersion  string    `json:"tool_version,omitempty"`
	PackageCount int       `json:"package_count"`
	EffectiveAt  time.Time `json:"generated_at"` // COALESCE(generated_at, submitted_at)
	SubmittedAt  time.Time `json:"submitted_at"`
}

// repoTimelineSortCols: default "occurred" (newest change first). "severity"
// worst-first, "cause"/"cve" alphabetical. Tiebreak is the event id.
var repoTimelineSortCols = map[string]sortCol{
	"occurred": {expr: "e.occurred_at", cast: "timestamptz", defDesc: true},
	"severity": {expr: severityRankSQLCol("e.severity"), cast: "double precision", defDesc: false},
	"cause":    {expr: "e.cause", cast: "text", defDesc: false},
	"cve":      {expr: "e.exposure", cast: "text", defDesc: false},
}

// RepoTimeline returns the change history for a repository across ALL its
// digests (CUJ-3), sortable (default "occurred" = newest first), keyset-
// paginated on the chosen column + event id.
func (s *Store) RepoTimeline(ctx context.Context, tenantID, repository, minSeverity string, includeUnknown bool, sortKey, sortDir, cursor string, limit int) (items []TimelineEvent, next string, err error) {
	var known bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE tenant_id = $1 AND repository = $2)`,
		tenantID, repository).Scan(&known); err != nil {
		return nil, "", fmt.Errorf("check repository: %w", err)
	}
	if !known {
		return nil, "", ErrNotFound
	}

	eff, fetch := clampLimit(limit)
	sort := resolveSort(sortKey, sortDir, repoTimelineSortCols, "occurred")
	cur, hasCur := decodeSortCursor(cursor)

	// includeUnknown false ⇒ the severity filter is exact (no forced unrated
	// rows), so the UI change log's dropdown does what it says.
	allowed := data.AllowedSeverities(minSeverity)
	if !includeUnknown {
		allowed = data.AllowedSeveritiesStrict(minSeverity)
	}
	args := []any{tenantID, repository, pq.Array(allowed)}
	keyset := ""
	if hasCur {
		keyset = " AND " + sort.seek("e.id::text", 4, 5)
		args = append(args, cur.Val, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		SELECT e.id, sb.digest, e.sbom_id, e.scanner, e.event_type, e.exposure, e.package,
		       e.severity, e.score, e.cause, e.occurred_at, %s
		FROM devradar_finding_event e
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		WHERE e.tenant_id = $1 AND sb.repository = $2 AND e.severity = ANY($3)%s
		ORDER BY %s
		LIMIT %s`, sort.selectVal(), keyset, sort.orderBy("e.id::text"), limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("repo timeline: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vals []string
	var ids []int64
	for rows.Next() {
		var t TimelineEvent
		var id int64
		var sortval string
		if err := rows.Scan(&id, &t.Digest, &t.SBOMID, &t.Scanner, &t.EventType, &t.Exposure,
			&t.Package, &t.Severity, &t.Score, &t.Cause, &t.OccurredAt, &sortval); err != nil {
			return nil, "", fmt.Errorf("scan timeline event: %w", err)
		}
		items = append(items, t)
		vals = append(vals, sortval)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeSortCursor(vals[eff-1], strconv.FormatInt(ids[eff-1], 10))
	}
	return items, next, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
