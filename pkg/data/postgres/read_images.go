package postgres

import (
	"context"
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
	Versions    []string       `json:"versions,omitempty"` // distinct tags seen (may be empty)
	LatestAt    time.Time      `json:"latest_at"`          // newest submission for the repo
	Counts      SeverityCounts `json:"counts"`             // rollup across the repo's findings
	Fixable     int            `json:"fixable"`            // findings with a fix available (any severity)
	Failures    int            `json:"failures,omitempty"`
}

// ListRepoImages returns a tenant's tracked images grouped by repository,
// **risk-ranked in SQL** (critical, then high, then total finding count), so the
// database order is the display order — which is what makes keyset pagination
// correct (no re-sort in Go could reorder across pages). Keyset on
// (risk_score DESC, repository DESC). Every active SBOM contributes; counts are
// the union of findings across the repo's SBOMs, trimmed to minSeverity like the
// per-SBOM views. Risk uses the raw (untrimmed) severity counts, so ranking is a
// stable property of the image, independent of the viewer's threshold.
func (s *Store) ListRepoImages(ctx context.Context, tenantID, minSeverity, cursor string, limit int) (items []RepoImage, next string, err error) {
	eff, fetch := clampLimit(limit)
	cur, hasCur := decodeCursor(cursor)

	// Rank in a CTE so `risk` is a real column usable in both ORDER BY and the
	// keyset predicate. risk = crit*1e9 + high*1e5 + total (bounded fields;
	// wide multipliers keep the tiers from colliding at realistic corpus sizes).
	args := []any{tenantID}
	keyset := ""
	if hasCur {
		keyset = "WHERE (risk, repository) < ($2, $3)"
		args = append(args, cur.N, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		WITH img AS (
			SELECT sb.repository,
			       COUNT(DISTINCT sb.id)                             AS sbom_count,
			       COUNT(DISTINCT sb.digest)                         AS digest_count,
			       COALESCE(array_agg(DISTINCT sb.version) FILTER (WHERE sb.version IS NOT NULL), '{}') AS versions,
			       MAX(sb.submitted_at)                              AS latest_at,
			       COUNT(*) FILTER (WHERE f.severity = 'critical')   AS crit,
			       COUNT(*) FILTER (WHERE f.severity = 'high')       AS high,
			       COUNT(*) FILTER (WHERE f.severity = 'medium')     AS med,
			       COUNT(*) FILTER (WHERE f.severity = 'low')        AS low,
			       COUNT(*) FILTER (WHERE f.severity = 'negligible') AS neg,
			       COUNT(*) FILTER (WHERE f.severity = 'unknown')    AS unk,
			       COUNT(f.finding_id)                               AS total,
			       COUNT(*) FILTER (WHERE f.is_fixed)                AS fixable,
			       (SELECT COUNT(*) FROM devradar_scan_failure sf
			          JOIN devradar_sbom sb2 ON sb2.id = sf.sbom_id
			         WHERE sb2.tenant_id = sb.tenant_id AND sb2.repository = sb.repository) AS failures,
			       COUNT(*) FILTER (WHERE f.severity = 'critical') * 1000000000::bigint
			         + COUNT(*) FILTER (WHERE f.severity = 'high') * 100000::bigint
			         + COUNT(f.finding_id)                         AS risk
			FROM devradar_sbom sb
			LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
			WHERE sb.tenant_id = $1 AND sb.status = 'active'
			GROUP BY sb.tenant_id, sb.repository
		)
		SELECT repository, sbom_count, digest_count, versions, latest_at,
		       crit, high, med, low, neg, unk, total, fixable, failures, risk
		FROM img
		%s
		ORDER BY risk DESC, repository DESC
		LIMIT %s`, keyset, limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list repo images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var risks []int64
	for rows.Next() {
		var im RepoImage
		var c SeverityCounts
		var risk int64
		if err := rows.Scan(&im.Repository, &im.SBOMCount, &im.DigestCount, pq.Array(&im.Versions),
			&im.LatestAt, &c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown,
			&c.Total, &im.Fixable, &im.Failures, &risk); err != nil {
			return nil, "", fmt.Errorf("scan repo image: %w", err)
		}
		im.Counts = applyThreshold(c, minSeverity)
		items = append(items, im)
		risks = append(risks, risk)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		last := items[len(items)-1]
		next = encodeCursorN(risks[eff-1], last.Repository)
	}
	return items, next, nil
}

// FleetStats is the tenant-wide rollup for the dashboard headline. It is
// deliberately independent of the paginated image list: summing one page would
// undercount once a tenant has more images than fit on a page.
type FleetStats struct {
	Images   int `json:"images"`
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Fixable  int `json:"fixable"`
	Failures int `json:"failures"`
}

// FleetStats returns tenant-wide finding totals across all active images.
func (s *Store) FleetStats(ctx context.Context, tenantID string) (FleetStats, error) {
	var fs FleetStats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT repository) FROM devradar_sbom
			   WHERE tenant_id = $1 AND status = 'active'),
			COUNT(f.finding_id),
			COUNT(*) FILTER (WHERE f.severity = 'critical'),
			COUNT(*) FILTER (WHERE f.severity = 'high'),
			COUNT(*) FILTER (WHERE f.is_fixed),
			(SELECT COUNT(*) FROM devradar_scan_failure sf
			   JOIN devradar_sbom s2 ON s2.id = sf.sbom_id
			  WHERE s2.tenant_id = $1)
		FROM devradar_sbom sb
		LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
		WHERE sb.tenant_id = $1 AND sb.status = 'active'`,
		tenantID).Scan(&fs.Images, &fs.Total, &fs.Critical, &fs.High, &fs.Fixable, &fs.Failures)
	if err != nil {
		return FleetStats{}, fmt.Errorf("fleet stats: %w", err)
	}
	return fs, nil
}

// RepoSummary is the header rollup for one image: authoritative totals that
// don't depend on how the SBOM list is paginated.
type RepoSummary struct {
	SBOMCount   int
	DigestCount int
	Versions    []string
}

// RepoSummary returns totals for one repository. ErrNotFound if unknown.
func (s *Store) RepoSummary(ctx context.Context, tenantID, repository string) (RepoSummary, error) {
	var rs RepoSummary
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT id), COUNT(DISTINCT digest),
		       COALESCE(array_agg(DISTINCT version) FILTER (WHERE version IS NOT NULL), '{}')
		FROM devradar_sbom
		WHERE tenant_id = $1 AND repository = $2 AND status = 'active'`,
		tenantID, repository).Scan(&rs.SBOMCount, &rs.DigestCount, pq.Array(&rs.Versions))
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
func (s *Store) SBOMsForRepo(ctx context.Context, tenantID, repository, cursor string, limit int) (items []RepoSBOM, next string, err error) {
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
	cur, hasCur := decodeCursor(cursor)

	// Order by effective generation time = COALESCE(generated_at, submitted_at),
	// id as the unique tiebreaker for a stable keyset.
	where := `WHERE tenant_id = $1 AND repository = $2 AND status = 'active'`
	args := []any{tenantID, repository}
	if hasCur {
		where += ` AND (COALESCE(generated_at, submitted_at), id) < ($3, $4)`
		args = append(args, cur.TS, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		SELECT id, digest, version, format, tool, tool_version, package_count,
		       COALESCE(generated_at, submitted_at) AS effective_at, submitted_at
		FROM devradar_sbom
		%s
		ORDER BY COALESCE(generated_at, submitted_at) DESC, id DESC
		LIMIT %s`, where, limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("sboms for repo: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var it RepoSBOM
		var version, tool, toolVer *string
		if err := rows.Scan(&it.SBOMID, &it.Digest, &version, &it.Format, &tool, &toolVer,
			&it.PackageCount, &it.EffectiveAt, &it.SubmittedAt); err != nil {
			return nil, "", fmt.Errorf("scan repo sbom: %w", err)
		}
		it.Version = deref(version)
		it.Tool = deref(tool)
		it.ToolVersion = deref(toolVer)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		last := items[len(items)-1]
		next = encodeCursor(last.EffectiveAt, last.SBOMID)
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

// RepoTimeline returns the change history for a repository across ALL its
// digests, newest first, keyset-paginated on (occurred_at, id). This is CUJ-3:
// "how this image's vulnerabilities changed over time", spanning every version.
func (s *Store) RepoTimeline(ctx context.Context, tenantID, repository, minSeverity, cursor string, limit int) (items []TimelineEvent, next string, err error) {
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
	cur, hasCur := decodeCursor(cursor)

	args := []any{tenantID, repository, pq.Array(data.AllowedSeverities(minSeverity))}
	keyset := ""
	if hasCur {
		keyset = ` AND (e.occurred_at, e.id) < ($4, $5)`
		args = append(args, cur.TS, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		SELECT e.id, sb.digest, e.sbom_id, e.scanner, e.event_type, e.exposure, e.package,
		       e.severity, e.score, e.cause, e.occurred_at
		FROM devradar_finding_event e
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		WHERE e.tenant_id = $1 AND sb.repository = $2 AND e.severity = ANY($3)%s
		ORDER BY e.occurred_at DESC, e.id DESC
		LIMIT %s`, keyset, limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("repo timeline: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64 // event id per item, for the keyset cursor tiebreaker
	for rows.Next() {
		var t TimelineEvent
		var id int64
		if err := rows.Scan(&id, &t.Digest, &t.SBOMID, &t.Scanner, &t.EventType, &t.Exposure,
			&t.Package, &t.Severity, &t.Score, &t.Cause, &t.OccurredAt); err != nil {
			return nil, "", fmt.Errorf("scan timeline event: %w", err)
		}
		items = append(items, t)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		last := items[len(items)-1]
		next = encodeCursor(last.OccurredAt, strconv.FormatInt(ids[eff-1], 10))
	}
	return items, next, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
