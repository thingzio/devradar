package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

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
	// VEX context (aggregated across the CVE's occurrences). VEXStatus is the
	// tenant's assertion where one applies to every occurrence ("" if none, or if
	// the CVE is only partially VEX'd). Suppressed is true when VEXStatus is
	// not_affected/fixed — such CVEs are shown but de-emphasized in the UI.
	VEXStatus     string `json:"vex_status,omitempty"`
	Justification string `json:"justification,omitempty"`
	Impact        string `json:"impact_statement,omitempty"`
	Suppressed    bool   `json:"suppressed,omitempty"`
}

// FleetCVEFilter narrows the fleet CVE list. Zero value = no filtering.
type FleetCVEFilter struct {
	VEXState      string // "", "vexed" (any statement), "not_vexed", or a specific status
	Justification string // OpenVEX justification, e.g. vulnerable_code_not_in_execute_path
	KEVOnly       bool
	FixableOnly   bool
}

// fleetCVESortCols sort against the outer-query column aliases. Default "risk"
// is the blast-radius/exploit ranking (KEV → severity → reach → EPSS).
var fleetCVESortCols = map[string]sortCol{
	"risk":     {expr: "risk", cast: "double precision", defDesc: true},
	"severity": {expr: "best_rank", cast: "double precision", defDesc: false}, // rank asc = worst first
	"images":   {expr: "image_count", cast: "double precision", defDesc: true},
	"findings": {expr: "finding_count", cast: "double precision", defDesc: true},
	"cvss":     {expr: "max_score", cast: "double precision", defDesc: true},
	"epss":     {expr: "COALESCE(epss, -1)", cast: "double precision", defDesc: true},
	"cve":      {expr: "cve", cast: "text", defDesc: false},
}

// FleetCVEs lists a tenant's vulnerabilities grouped by CVE. Default ranking is
// blast radius + exploit risk (KEV → severity → EPSS → reach), sortable by any
// fleetCVESortCols key. VEX'd CVEs are INCLUDED (annotated with status/impact,
// de-emphasized in the UI) — the filter narrows the set. Ranked/sorted in SQL so
// page order is global order; keyset-paginated. minSeverity trims which findings
// count toward a CVE.
func (s *Store) FleetCVEs(ctx context.Context, tenantID, minSeverity string, filter FleetCVEFilter, sortKey, sortDir, cursor string, limit int) (items []FleetCVE, next string, err error) {
	eff, fetch := clampLimit(limit)
	sort := resolveSort(sortKey, sortDir, fleetCVESortCols, "risk")
	cur, hasCur := decodeSortCursor(cursor)

	args := []any{tenantID, pq.Array(data.AllowedSeverities(minSeverity))}

	// Post-aggregation filters live in the outer WHERE (they reference computed
	// columns). Build them with positional args after the fixed two.
	conds := []string{}
	if filter.KEVOnly {
		conds = append(conds, "kev")
	}
	if filter.FixableOnly {
		conds = append(conds, "fixable")
	}
	switch filter.VEXState {
	case "vexed":
		conds = append(conds, "vex_status IS NOT NULL")
	case "not_vexed":
		conds = append(conds, "vex_status IS NULL")
	case "not_affected", "affected", "fixed", "under_investigation":
		args = append(args, filter.VEXState)
		conds = append(conds, fmt.Sprintf("vex_status = $%d", len(args)))
	}
	if filter.Justification != "" {
		args = append(args, filter.Justification)
		conds = append(conds, fmt.Sprintf("vex_just = $%d", len(args)))
	}
	if hasCur {
		args = append(args, cur.Val, cur.ID)
		conds = append(conds, sort.seek("cve", len(args)-1, len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, fetch)
	limitPos := fmt.Sprintf("$%d", len(args))

	// risk = KEV(1e18) + worst-severity-rank(1e15..) + image_count(1e9) +
	// EPSS-scaled + finding_count. Wide multipliers keep tiers from colliding.
	// vex_* aggregate the tenant's statements for the CVE: a status is attributed
	// to the CVE only when it applies to EVERY occurrence (bool_and), so a
	// partially-VEX'd CVE still reads as open.
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
			       (array_agg(DISTINCT sb.repository))[1:3]  AS repos,
			       bool_and(vex.vex_status IS NOT NULL)      AS all_vexed,
			       (array_agg(vex.vex_status)   FILTER (WHERE vex.vex_status IS NOT NULL))[1] AS a_status,
			       (array_agg(vex.vex_just)     FILTER (WHERE vex.vex_just IS NOT NULL))[1]   AS a_just,
			       (array_agg(vex.vex_impact)   FILTER (WHERE vex.vex_impact IS NOT NULL))[1] AS a_impact
			FROM devradar_finding f
			JOIN devradar_sbom sb ON sb.id = f.sbom_id
			LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure%s
			WHERE sb.tenant_id = $1 AND sb.status = 'active' AND f.severity = ANY($2)
			GROUP BY f.exposure
		), agg AS (
			SELECT cve, best_rank, max_score, image_count, finding_count, fixable, kev, epss, repos,
			       CASE WHEN all_vexed THEN a_status ELSE NULL END AS vex_status,
			       CASE WHEN all_vexed THEN a_just   ELSE NULL END AS vex_just,
			       CASE WHEN all_vexed THEN a_impact ELSE NULL END AS vex_impact
			FROM cve
		), ranked AS (
			SELECT *,
			       (CASE WHEN kev THEN 1000000000000000000::bigint ELSE 0 END)
			       + (5 - best_rank) * 1000000000000::bigint
			       + LEAST(image_count, 100000) * 1000000::bigint
			       + LEAST((COALESCE(epss,0) * 1000)::bigint, 1000) * 1000
			       + LEAST(finding_count, 999)                       AS risk
			FROM agg
		)
		SELECT cve, best_rank, max_score, image_count, finding_count, fixable, kev, epss, repos,
		       vex_status, vex_just, vex_impact, %s
		FROM ranked
		%s
		ORDER BY %s
		LIMIT %s`, severityRankSQL, vexStatusJoin, sort.selectVal(), where, sort.orderBy("cve"), limitPos)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("fleet cves: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vals []string
	for rows.Next() {
		var c FleetCVE
		var rank int
		var sortval string
		var vstatus, vjust, vimpact *string
		if err := rows.Scan(&c.CVE, &rank, &c.MaxScore, &c.ImageCount, &c.FindingCount,
			&c.Fixable, &c.KEV, &c.EPSS, pq.Array(&c.Repositories),
			&vstatus, &vjust, &vimpact, &sortval); err != nil {
			return nil, "", fmt.Errorf("scan fleet cve: %w", err)
		}
		c.VEXStatus, c.Justification, c.Impact = deref(vstatus), deref(vjust), deref(vimpact)
		c.Suppressed = c.VEXStatus == "not_affected" || c.VEXStatus == "fixed"
		c.WorstSev = severityForRank(rank)
		items = append(items, c)
		vals = append(vals, sortval)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > eff {
		items = items[:eff]
		next = encodeSortCursor(vals[eff-1], items[len(items)-1].CVE)
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
