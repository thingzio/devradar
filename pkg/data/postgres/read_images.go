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
	Failures    int            `json:"failures,omitempty"`
}

// ListRepoImages returns a tenant's tracked images grouped by repository, newest
// activity first, keyset-paginated on (latest_at, repository). Every active SBOM
// contributes; counts are the union of findings across the repo's SBOMs, trimmed
// to minSeverity like the per-SBOM views.
func (s *Store) ListRepoImages(ctx context.Context, tenantID, minSeverity, cursor string, limit int) (items []RepoImage, next string, err error) {
	eff, fetch := clampLimit(limit)
	cur, hasCur := decodeCursor(cursor)

	// Keyset predicate: rows strictly "older" than the cursor in the
	// (latest_at DESC, repository DESC) ordering.
	where := ""
	args := []any{tenantID}
	if hasCur {
		where = `HAVING (MAX(sb.submitted_at), sb.repository) < ($2, $3)`
		args = append(args, cur.TS, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	q := fmt.Sprintf(`
		SELECT sb.repository,
		       COUNT(DISTINCT sb.id)                                        AS sbom_count,
		       COUNT(DISTINCT sb.digest)                                    AS digest_count,
		       COALESCE(array_agg(DISTINCT sb.version) FILTER (WHERE sb.version IS NOT NULL), '{}') AS versions,
		       MAX(sb.submitted_at)                                         AS latest_at,
		       COUNT(*) FILTER (WHERE f.severity = 'critical')              AS crit,
		       COUNT(*) FILTER (WHERE f.severity = 'high')                  AS high,
		       COUNT(*) FILTER (WHERE f.severity = 'medium')                AS med,
		       COUNT(*) FILTER (WHERE f.severity = 'low')                   AS low,
		       COUNT(*) FILTER (WHERE f.severity = 'negligible')            AS neg,
		       COUNT(*) FILTER (WHERE f.severity = 'unknown')               AS unk,
		       COUNT(f.finding_id)                                          AS total,
		       (SELECT COUNT(*) FROM devradar_scan_failure sf
		          JOIN devradar_sbom sb2 ON sb2.id = sf.sbom_id
		         WHERE sb2.tenant_id = sb.tenant_id AND sb2.repository = sb.repository) AS failures
		FROM devradar_sbom sb
		LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
		WHERE sb.tenant_id = $1 AND sb.status = 'active'
		GROUP BY sb.tenant_id, sb.repository
		%s
		ORDER BY latest_at DESC, sb.repository DESC
		LIMIT %s`, where, limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list repo images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var im RepoImage
		var c SeverityCounts
		if err := rows.Scan(&im.Repository, &im.SBOMCount, &im.DigestCount, pq.Array(&im.Versions),
			&im.LatestAt, &c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown,
			&c.Total, &im.Failures); err != nil {
			return nil, "", fmt.Errorf("scan repo image: %w", err)
		}
		im.Counts = applyThreshold(c, minSeverity)
		items = append(items, im)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	items, next = paginateRepoImages(items, eff)
	return items, next, nil
}

func paginateRepoImages(items []RepoImage, eff int) ([]RepoImage, string) {
	if len(items) <= eff {
		return items, ""
	}
	items = items[:eff]
	last := items[len(items)-1]
	return items, encodeCursor(last.LatestAt, last.Repository)
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
