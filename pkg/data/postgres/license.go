package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// UpsertSBOMPackages records the per-package license inventory extracted from an
// SBOM at ingest. The inventory is immutable (frozen per digest), so conflicts on
// the natural key (sbom_id, package, version) are ignored — the first write is
// canonical. Called once, only for a newly-inserted SBOM; a no-op for an empty
// list. Batched in one transaction.
func (s *Store) UpsertSBOMPackages(ctx context.Context, sbomID string, pkgs []data.PackageLicense) error {
	if len(pkgs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin packages tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO devradar_sbom_package (sbom_id, package, version, purl, licenses)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (sbom_id, package, version) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("prepare package insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, p := range pkgs {
		lics := p.Licenses
		if lics == nil {
			lics = []string{} // pq.Array(nil) sends NULL; the column is NOT NULL
		}
		if _, err := stmt.ExecContext(ctx, sbomID, p.Package, p.Version, p.PURL, pq.Array(lics)); err != nil {
			return fmt.Errorf("insert package %s: %w", p.Package, err)
		}
	}
	return tx.Commit()
}

// HasSBOMPackages reports whether the license inventory for an SBOM has already
// been captured. Used by the scan job's backfill to skip SBOMs ingested before
// license capture existed without re-extracting the whole fleet every run. Cheap
// (PK-covered EXISTS). Not tenant-scoped — the scan job is cross-tenant by design
// and the sbomID is already authoritative.
func (s *Store) HasSBOMPackages(ctx context.Context, sbomID string) (bool, error) {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom_package WHERE sbom_id = $1)`,
		sbomID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check sbom packages: %w", err)
	}
	return exists, nil
}

// PackageLicenseRow is a tenant-facing package/license row with its derived
// category and (when a policy is active) a compliance verdict.
type PackageLicenseRow struct {
	Package   string   `json:"package"`
	Version   string   `json:"version,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	Licenses  []string `json:"licenses"`
	Category  string   `json:"category"`            // worst category across the package's licenses
	Violation bool     `json:"violation,omitempty"` // fails the tenant's policy
	Reason    string   `json:"reason,omitempty"`
}

// ListSBOMPackages returns the license inventory for one SBOM, classified and
// evaluated against the tenant's policy in Go (never in SQL). Tenant-scoped;
// ErrNotFound if the SBOM isn't owned. Ordered violations-first, then by package.
func (s *Store) ListSBOMPackages(ctx context.Context, tenantID, sbomID string, policy data.LicensePolicy) ([]PackageLicenseRow, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT package, version, purl, licenses
		FROM devradar_sbom_package
		WHERE sbom_id = $1
		ORDER BY package, version`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("list sbom packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []PackageLicenseRow
	for rows.Next() {
		var r PackageLicenseRow
		if err := rows.Scan(&r.Package, &r.Version, &r.PURL, pq.Array(&r.Licenses)); err != nil {
			return nil, fmt.Errorf("scan sbom package: %w", err)
		}
		pkg := data.PackageLicense{Package: r.Package, Version: r.Version, PURL: r.PURL, Licenses: r.Licenses}
		r.Category = string(worstCategory(r.Licenses))
		r.Violation, r.Reason = policy.Evaluate(pkg)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortViolationsFirst(out)
	return out, nil
}

// PackagesByRepo returns the deduped license inventory across all of a
// repository's active SBOMs, classified + policy-evaluated in Go, violations
// first. The distinct-package identity is (package, version) with licenses
// merged across the repo's digests, so a dependency common to several versions
// appears once. Tenant-scoped via the join to devradar_sbom.
func (s *Store) PackagesByRepo(ctx context.Context, tenantID, repository string, policy data.LicensePolicy) ([]PackageLicenseRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.package, p.version,
		       COALESCE(array_agg(DISTINCT lic) FILTER (WHERE lic IS NOT NULL), '{}')
		FROM devradar_sbom_package p
		JOIN devradar_sbom sb ON sb.id = p.sbom_id
		LEFT JOIN LATERAL unnest(p.licenses) AS lic ON true
		WHERE sb.tenant_id = $1 AND sb.repository = $2 AND sb.status = 'active'
		GROUP BY p.package, p.version
		ORDER BY p.package, p.version`, tenantID, repository)
	if err != nil {
		return nil, fmt.Errorf("repo packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []PackageLicenseRow
	for rows.Next() {
		var r PackageLicenseRow
		if err := rows.Scan(&r.Package, &r.Version, pq.Array(&r.Licenses)); err != nil {
			return nil, fmt.Errorf("scan repo package: %w", err)
		}
		pkg := data.PackageLicense{Package: r.Package, Version: r.Version, Licenses: r.Licenses}
		r.Category = string(worstCategory(r.Licenses))
		r.Violation, r.Reason = policy.Evaluate(pkg)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortViolationsFirst(out)
	return out, nil
}

// LicenseCount is one distribution bucket: a license family or category and the
// number of distinct packages it covers across the tenant's active fleet.
type LicenseCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// FleetLicenseStats is the tenant-wide license landscape.
type FleetLicenseStats struct {
	// Families is the distinct-package count per license family (MIT, GPL, …),
	// worst→best-effort ordered by count desc. Powers the donut + treemap.
	Families []LicenseCount `json:"families"`
	// Categories is the distinct-package count per obligation category.
	Categories []LicenseCount `json:"categories"`
	// Packages is the total distinct packages with at least one license.
	Packages int `json:"packages"`
	// Unlicensed is the count of distinct packages with no resolvable license.
	Unlicensed int `json:"unlicensed"`
	// Violations is the number of distinct packages failing the tenant's policy.
	Violations int `json:"violations"`
}

// FleetLicenseStats aggregates the tenant's active-SBOM license inventory into a
// per-family and per-category distribution, plus a policy violation count. The
// distinct-package identity is (package, version) so the same dependency shared
// across images counts once. Aggregation of raw license IDs happens in SQL; all
// classification and policy evaluation happen in Go.
func (s *Store) FleetLicenseStats(ctx context.Context, tenantID string, policy data.LicensePolicy) (FleetLicenseStats, error) {
	// One row per distinct (package, version) with its merged license set across
	// the tenant's active SBOMs. array_agg(DISTINCT lic) folds a dependency that
	// appears in many images into a single package with the union of its licenses.
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.package, p.version,
		       COALESCE(array_agg(DISTINCT lic) FILTER (WHERE lic IS NOT NULL), '{}')
		FROM devradar_sbom_package p
		JOIN devradar_sbom sb ON sb.id = p.sbom_id
		LEFT JOIN LATERAL unnest(p.licenses) AS lic ON true
		WHERE sb.tenant_id = $1 AND sb.status = 'active'
		GROUP BY p.package, p.version`, tenantID)
	if err != nil {
		return FleetLicenseStats{}, fmt.Errorf("fleet license stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	famCount := map[string]int{}
	catCount := map[string]int{}
	var fs FleetLicenseStats
	for rows.Next() {
		var pkgName, version string
		var lics []string
		if err := rows.Scan(&pkgName, &version, pq.Array(&lics)); err != nil {
			return FleetLicenseStats{}, fmt.Errorf("scan fleet license row: %w", err)
		}
		fs.Packages++
		if len(lics) == 0 {
			fs.Unlicensed++
			catCount[string(data.CategoryUnknown)]++
			famCount["unknown"]++
		} else {
			// A package counts once per distinct family/category it carries.
			seenFam := map[string]struct{}{}
			seenCat := map[string]struct{}{}
			for _, id := range lics {
				for _, single := range data.ParseExpression(id) {
					if f := data.LicenseFamily(single); f != "" {
						seenFam[f] = struct{}{}
					}
					seenCat[string(data.Classify(single))] = struct{}{}
				}
			}
			for f := range seenFam {
				famCount[f]++
			}
			for c := range seenCat {
				catCount[c]++
			}
		}
		if vio, _ := policy.Evaluate(data.PackageLicense{Package: pkgName, Version: version, Licenses: lics}); vio {
			fs.Violations++
		}
	}
	if err := rows.Err(); err != nil {
		return FleetLicenseStats{}, err
	}
	fs.Families = topCounts(famCount, 12)
	fs.Categories = orderedCategoryCounts(catCount)
	return fs, nil
}

// GetLicensePolicy returns the tenant's compliance policy, or an empty policy
// (deny nothing) if none is set.
func (s *Store) GetLicensePolicy(ctx context.Context, tenantID string) (data.LicensePolicy, error) {
	var p data.LicensePolicy
	var denied, allow, deny []string
	err := s.db.QueryRowContext(ctx, `
		SELECT denied_categories, allow_exceptions, deny_exceptions
		FROM devradar_license_policy
		WHERE tenant_id = $1`, tenantID).Scan(pq.Array(&denied), pq.Array(&allow), pq.Array(&deny))
	if errors.Is(err, sql.ErrNoRows) {
		return data.LicensePolicy{}, nil
	}
	if err != nil {
		return data.LicensePolicy{}, fmt.Errorf("get license policy: %w", err)
	}
	for _, c := range denied {
		p.DeniedCategories = append(p.DeniedCategories, data.LicenseCategory(c))
	}
	p.AllowExceptions, p.DenyExceptions = allow, deny
	return p, nil
}

// SetLicensePolicy upserts the tenant's compliance policy.
func (s *Store) SetLicensePolicy(ctx context.Context, tenantID string, p data.LicensePolicy) error {
	denied := make([]string, 0, len(p.DeniedCategories))
	for _, c := range p.DeniedCategories {
		denied = append(denied, string(c))
	}
	allow, deny := p.AllowExceptions, p.DenyExceptions
	if allow == nil {
		allow = []string{}
	}
	if deny == nil {
		deny = []string{}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO devradar_license_policy (tenant_id, denied_categories, allow_exceptions, deny_exceptions, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
			denied_categories = EXCLUDED.denied_categories,
			allow_exceptions  = EXCLUDED.allow_exceptions,
			deny_exceptions   = EXCLUDED.deny_exceptions,
			updated_at        = now()`,
		tenantID, pq.Array(denied), pq.Array(allow), pq.Array(deny))
	if err != nil {
		return fmt.Errorf("set license policy: %w", err)
	}
	return nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

// categoryRank orders categories worst (most restrictive) → best for display and
// for choosing a package's representative category.
var categoryRank = map[data.LicenseCategory]int{
	data.CategoryProprietary:    0,
	data.CategoryStrongCopyleft: 1,
	data.CategoryWeakCopyleft:   2,
	data.CategoryUnknown:        3,
	data.CategoryPermissive:     4,
}

// worstCategory returns the most restrictive category among a package's licenses
// — the one a reviewer cares about first. Empty license set ⇒ unknown.
func worstCategory(licenses []string) data.LicenseCategory {
	if len(licenses) == 0 {
		return data.CategoryUnknown
	}
	worst := data.CategoryPermissive
	worstR := categoryRank[worst]
	for _, id := range licenses {
		for _, single := range data.ParseExpression(id) {
			c := data.Classify(single)
			if r := categoryRank[c]; r < worstR {
				worst, worstR = c, r
			}
		}
	}
	return worst
}

// sortViolationsFirst orders rows violations-first, then by package/version, so
// the compliance-relevant rows lead the list. Stable and deterministic.
func sortViolationsFirst(rows []PackageLicenseRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Violation != rows[j].Violation {
			return rows[i].Violation // true sorts first
		}
		if rows[i].Package != rows[j].Package {
			return rows[i].Package < rows[j].Package
		}
		return rows[i].Version < rows[j].Version
	})
}

// topCounts returns the top-n buckets by count (desc, ties broken by key), and
// folds the remainder into a single "others" bucket — the disco donut pattern,
// but computed here rather than in fragile SQL.
func topCounts(m map[string]int, n int) []LicenseCount {
	all := make([]LicenseCount, 0, len(m))
	for k, v := range m {
		all = append(all, LicenseCount{Key: k, Count: v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		return all[i].Key < all[j].Key
	})
	if len(all) <= n {
		return all
	}
	others := 0
	for _, c := range all[n:] {
		others += c.Count
	}
	out := append([]LicenseCount(nil), all[:n]...)
	if others > 0 {
		out = append(out, LicenseCount{Key: "others", Count: others})
	}
	return out
}

// orderedCategoryCounts returns category buckets in the fixed worst→best display
// order, omitting empty ones.
func orderedCategoryCounts(m map[string]int) []LicenseCount {
	order := []data.LicenseCategory{
		data.CategoryProprietary, data.CategoryStrongCopyleft, data.CategoryWeakCopyleft,
		data.CategoryPermissive, data.CategoryUnknown,
	}
	var out []LicenseCount
	for _, c := range order {
		if n := m[string(c)]; n > 0 {
			out = append(out, LicenseCount{Key: string(c), Count: n})
		}
	}
	return out
}
