package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/lib/pq"
)

const (
	PostureImproves  = "improves"
	PostureRegresses = "regresses"
	PostureUnchanged = "unchanged"
)

var ErrInvalidComparison = errors.New("invalid SBOM comparison")

type PostureCounts struct {
	KEV, Critical, High, Medium, Low, Total int
}

type ComparisonSide struct {
	SBOMID, Repository, Version, Digest string
	Counts                              PostureCounts
}

type ComparisonFinding struct {
	FindingID, Exposure, Package, Version string
	Severity                              string
	Score                                 float32
	Fixed                                 bool
	PreviousSeverity                      string
	PreviousScore                         float32
}

type ComparisonPackage struct {
	Package, Version string
	Licenses         []string
}

type ComparisonLicenseChange struct {
	Package, Version string
	From, To         []string
}

type SBOMComparison struct {
	From, To                       ComparisonSide
	Verdict                        string
	Added, Resolved                []ComparisonFinding
	Rerated, NewlyFixable          []ComparisonFinding
	PackagesAdded, PackagesRemoved []ComparisonPackage
	LicenseChanges                 []ComparisonLicenseChange
}

type comparisonFindingState struct {
	ComparisonFinding
	KEV bool
}

// CompareSBOMs compares immutable evidence for two tenant-owned SBOMs in the
// same repository. Scanner twins are collapsed by finding_id.
func (s *Store) CompareSBOMs(ctx context.Context, tenantID, fromID, toID string) (*SBOMComparison, error) {
	if fromID == toID {
		return nil, ErrInvalidComparison
	}
	from, err := s.comparisonSide(ctx, tenantID, fromID)
	if err != nil {
		return nil, err
	}
	to, err := s.comparisonSide(ctx, tenantID, toID)
	if err != nil {
		return nil, err
	}
	if from.Repository != to.Repository {
		return nil, ErrInvalidComparison
	}

	fromFindings, err := s.comparisonFindings(ctx, fromID)
	if err != nil {
		return nil, err
	}
	toFindings, err := s.comparisonFindings(ctx, toID)
	if err != nil {
		return nil, err
	}
	from.Counts = comparisonCounts(fromFindings)
	to.Counts = comparisonCounts(toFindings)
	out := &SBOMComparison{From: from, To: to, Verdict: comparePosture(from.Counts, to.Counts)}

	for id, before := range fromFindings {
		after, ok := toFindings[id]
		if !ok {
			out.Resolved = append(out.Resolved, before.ComparisonFinding)
			continue
		}
		if before.Severity != after.Severity || before.Score != after.Score {
			changed := after.ComparisonFinding
			changed.PreviousSeverity, changed.PreviousScore = before.Severity, before.Score
			out.Rerated = append(out.Rerated, changed)
		}
		if !before.Fixed && after.Fixed {
			out.NewlyFixable = append(out.NewlyFixable, after.ComparisonFinding)
		}
	}
	for id, after := range toFindings {
		if _, ok := fromFindings[id]; !ok {
			out.Added = append(out.Added, after.ComparisonFinding)
		}
	}
	sortFindings(out.Added)
	sortFindings(out.Resolved)
	sortFindings(out.Rerated)
	sortFindings(out.NewlyFixable)

	fromPackages, err := s.comparisonPackages(ctx, fromID)
	if err != nil {
		return nil, err
	}
	toPackages, err := s.comparisonPackages(ctx, toID)
	if err != nil {
		return nil, err
	}
	for key, before := range fromPackages {
		after, ok := toPackages[key]
		if !ok {
			out.PackagesRemoved = append(out.PackagesRemoved, before)
			continue
		}
		if !slices.Equal(before.Licenses, after.Licenses) {
			out.LicenseChanges = append(out.LicenseChanges, ComparisonLicenseChange{
				Package: before.Package, Version: before.Version, From: before.Licenses, To: after.Licenses,
			})
		}
	}
	for key, after := range toPackages {
		if _, ok := fromPackages[key]; !ok {
			out.PackagesAdded = append(out.PackagesAdded, after)
		}
	}
	sortPackages(out.PackagesAdded)
	sortPackages(out.PackagesRemoved)
	sort.Slice(out.LicenseChanges, func(i, j int) bool {
		return out.LicenseChanges[i].Package+out.LicenseChanges[i].Version < out.LicenseChanges[j].Package+out.LicenseChanges[j].Version
	})
	return out, nil
}

func (s *Store) comparisonSide(ctx context.Context, tenantID, sbomID string) (ComparisonSide, error) {
	var side ComparisonSide
	err := s.db.QueryRowContext(ctx, `
		SELECT id, repository, COALESCE(version,''), digest
		FROM devradar_sbom WHERE tenant_id=$1 AND id=$2 AND status='active'`, tenantID, sbomID).
		Scan(&side.SBOMID, &side.Repository, &side.Version, &side.Digest)
	if errors.Is(err, sql.ErrNoRows) {
		return ComparisonSide{}, ErrNotFound
	}
	if err != nil {
		return ComparisonSide{}, fmt.Errorf("load comparison SBOM: %w", err)
	}
	return side, nil
}

func (s *Store) comparisonFindings(ctx context.Context, sbomID string) (map[string]comparisonFindingState, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT f.finding_id, MIN(f.exposure), MIN(f.package), MIN(f.version),
		       (array_agg(f.severity ORDER BY %s))[1], MAX(f.score), bool_or(f.is_fixed),
		       COALESCE(bool_or(e.kev), false)
		FROM devradar_finding f
		LEFT JOIN devradar_cve_enrichment e ON e.cve=f.exposure
		WHERE f.sbom_id=$1
		GROUP BY f.finding_id`, severityRankSQLCol("f.severity")), sbomID)
	if err != nil {
		return nil, fmt.Errorf("load comparison findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]comparisonFindingState{}
	for rows.Next() {
		var state comparisonFindingState
		if err := rows.Scan(&state.FindingID, &state.Exposure, &state.Package, &state.Version,
			&state.Severity, &state.Score, &state.Fixed, &state.KEV); err != nil {
			return nil, fmt.Errorf("scan comparison finding: %w", err)
		}
		out[state.FindingID] = state
	}
	return out, rows.Err()
}

func (s *Store) comparisonPackages(ctx context.Context, sbomID string) (map[string]ComparisonPackage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT package, version, licenses FROM devradar_sbom_package
		WHERE sbom_id=$1 ORDER BY package, version`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("load comparison packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ComparisonPackage{}
	for rows.Next() {
		var p ComparisonPackage
		if err := rows.Scan(&p.Package, &p.Version, pq.Array(&p.Licenses)); err != nil {
			return nil, fmt.Errorf("scan comparison package: %w", err)
		}
		slices.Sort(p.Licenses)
		out[p.Package+"\x00"+p.Version] = p
	}
	return out, rows.Err()
}

func comparisonCounts(findings map[string]comparisonFindingState) PostureCounts {
	var c PostureCounts
	for _, finding := range findings {
		c.Total++
		if finding.KEV {
			c.KEV++
		}
		switch finding.Severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		}
	}
	return c
}

func comparePosture(from, to PostureCounts) string {
	a := []int{from.KEV, from.Critical, from.High, from.Medium, from.Low, from.Total}
	b := []int{to.KEV, to.Critical, to.High, to.Medium, to.Low, to.Total}
	for i := range a {
		if b[i] < a[i] {
			return PostureImproves
		}
		if b[i] > a[i] {
			return PostureRegresses
		}
	}
	return PostureUnchanged
}

func sortFindings(items []ComparisonFinding) {
	sort.Slice(items, func(i, j int) bool { return items[i].Exposure < items[j].Exposure })
}

func sortPackages(items []ComparisonPackage) {
	sort.Slice(items, func(i, j int) bool { return items[i].Package+items[i].Version < items[j].Package+items[j].Version })
}
