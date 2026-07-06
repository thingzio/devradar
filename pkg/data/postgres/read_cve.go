package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// FleetCVE is one vulnerability's blast radius across a tenant's images: how many
// distinct images it affects, plus its risk context. This is the "which CVE
// should I fix first, fleet-wide" view.
type FleetCVE struct {
	CVE          string   `json:"cve"`
	WorstSev     string   `json:"worst_severity"`
	MaxScore     float32  `json:"max_score"`
	ImageCount   int      `json:"image_count"`   // distinct repositories affected
	FindingCount int      `json:"finding_count"` // total findings across all images/versions
	Fixable      bool     `json:"fixable"`       // a fix exists in at least one occurrence
	KEV          bool     `json:"kev"`
	EPSS         *float32 `json:"epss,omitempty"`
	Repositories []string `json:"repositories,omitempty"` // sample of affected repos
}

// FleetCVEs lists a tenant's vulnerabilities grouped by CVE, ranked by blast
// radius and exploit risk: KEV first, then severity, then EPSS, then image
// count. Ranked in SQL so page order is global order; keyset-paginated on
// (risk, cve). minSeverity trims which findings count toward a CVE's presence.
func (s *Store) FleetCVEs(ctx context.Context, tenantID, minSeverity, cursor string, limit int) (items []FleetCVE, next string, err error) {
	eff, fetch := clampLimit(limit)
	cur, hasCur := decodeCursor(cursor)

	args := []any{tenantID, pq.Array(data.AllowedSeverities(minSeverity))}
	keyset := ""
	if hasCur {
		keyset = "WHERE (risk, cve) < ($3, $4)"
		args = append(args, cur.N, cur.ID)
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	// risk = KEV(1e18) + worst-severity-rank(1e15..) + image_count(1e9) +
	// EPSS-scaled + finding_count. Wide multipliers keep tiers from colliding.
	// Severity rank is inverted (critical highest) via (5 - min(rank)).
	q := fmt.Sprintf(`
		WITH cve AS (
			SELECT f.exposure AS cve,
			       MIN(%s)                                   AS best_rank,
			       MAX(f.score)                              AS max_score,
			       COUNT(DISTINCT sb.repository)             AS image_count,
			       COUNT(*)                                  AS finding_count,
			       bool_or(f.is_fixed)                       AS fixable,
			       COALESCE(bool_or(e.kev), false)           AS kev,
			       MAX(e.epss_score)                         AS epss,
			       (array_agg(DISTINCT sb.repository))[1:3]  AS repos
			FROM devradar_finding f
			JOIN devradar_sbom sb ON sb.id = f.sbom_id
			LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
			WHERE sb.tenant_id = $1 AND sb.status = 'active' AND f.severity = ANY($2)
			GROUP BY f.exposure
		), ranked AS (
			SELECT *,
			       (CASE WHEN kev THEN 1000000000000000000::bigint ELSE 0 END)
			       + (5 - best_rank) * 1000000000000::bigint
			       + LEAST(image_count, 100000) * 1000000::bigint
			       + LEAST((COALESCE(epss,0) * 1000)::bigint, 1000) * 1000
			       + LEAST(finding_count, 999)                       AS risk
			FROM cve
		)
		SELECT cve, best_rank, max_score, image_count, finding_count, fixable, kev, epss, repos, risk
		FROM ranked
		%s
		ORDER BY risk DESC, cve DESC
		LIMIT %s`, severityRankSQL, keyset, limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("fleet cves: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var risks []int64
	for rows.Next() {
		var c FleetCVE
		var rank int
		var risk int64
		if err := rows.Scan(&c.CVE, &rank, &c.MaxScore, &c.ImageCount, &c.FindingCount,
			&c.Fixable, &c.KEV, &c.EPSS, pq.Array(&c.Repositories), &risk); err != nil {
			return nil, "", fmt.Errorf("scan fleet cve: %w", err)
		}
		c.WorstSev = severityForRank(rank)
		items = append(items, c)
		risks = append(risks, risk)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeCursorN(risks[eff-1], items[len(items)-1].CVE)
	}
	return items, next, nil
}

// CVEOccurrence is one image/version affected by a specific CVE.
type CVEOccurrence struct {
	Repository string  `json:"repository"`
	SBOMID     string  `json:"sbom_id"`
	Digest     string  `json:"digest"`
	Version    string  `json:"version,omitempty"`
	Package    string  `json:"package"`
	PkgVersion string  `json:"pkg_version"`
	Severity   string  `json:"severity"`
	Score      float32 `json:"score"`
	IsFixed    bool    `json:"is_fixed"`
	Scanner    string  `json:"scanner"`
}

// CVEDetail is one CVE's fleet-wide context plus every place it occurs.
type CVEDetail struct {
	CVE         string          `json:"cve"`
	KEV         bool            `json:"kev"`
	KEVAdded    string          `json:"kev_added,omitempty"`
	EPSS        *float32        `json:"epss,omitempty"`
	EPSSPct     *float32        `json:"epss_pct,omitempty"`
	Occurrences []CVEOccurrence `json:"occurrences"`
}

// CVEDetail returns the enrichment context for a CVE and every occurrence across
// the tenant's active images. Tenant-scoped; ErrNotFound if the CVE isn't
// present in any of the tenant's findings.
func (s *Store) CVEDetail(ctx context.Context, tenantID, cve string) (*CVEDetail, error) {
	d := &CVEDetail{CVE: cve}

	// Enrichment (may be absent).
	var kevAdded *string
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(kev, false), kev_added, epss_score, epss_percentile
		 FROM devradar_cve_enrichment WHERE cve = $1`, cve).
		Scan(&d.KEV, &kevAdded, &d.EPSS, &d.EPSSPct)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("cve enrichment: %w", err)
	}
	if kevAdded != nil {
		d.KEVAdded = *kevAdded
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.repository, f.sbom_id, sb.digest, sb.version,
		       f.package, f.version, f.severity, f.score, f.is_fixed, f.scanner
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id = f.sbom_id
		WHERE sb.tenant_id = $1 AND sb.status = 'active' AND f.exposure = $2
		ORDER BY sb.repository, sb.digest, f.scanner`,
		tenantID, cve)
	if err != nil {
		return nil, fmt.Errorf("cve occurrences: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var o CVEOccurrence
		var version *string
		if err := rows.Scan(&o.Repository, &o.SBOMID, &o.Digest, &version,
			&o.Package, &o.PkgVersion, &o.Severity, &o.Score, &o.IsFixed, &o.Scanner); err != nil {
			return nil, fmt.Errorf("scan occurrence: %w", err)
		}
		o.Version = deref(version)
		d.Occurrences = append(d.Occurrences, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(d.Occurrences) == 0 {
		return nil, ErrNotFound
	}
	return d, nil
}
