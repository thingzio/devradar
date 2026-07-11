package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
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

type ComparisonLicensePolicyRegression struct {
	Package, Version string
	From, To         []string
	Reason           string
}

type SBOMComparison struct {
	From, To                       ComparisonSide
	Verdict                        string
	Added, Resolved                []ComparisonFinding
	Rerated, NewlyFixable          []ComparisonFinding
	PackagesAdded, PackagesRemoved []ComparisonPackage
	LicenseChanges                 []ComparisonLicenseChange
	LicensePolicyRegressions       []ComparisonLicensePolicyRegression
}

type UpgradeRecommendation struct {
	Baseline, Candidate ComparisonSide
	Comparison          *SBOMComparison
}

type comparisonFindingState struct {
	ComparisonFinding
	KEV bool
}

func (s *Store) ComparisonReadyRepositoryCount(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM (
			SELECT repository
			FROM devradar_sbom
			WHERE tenant_id=$1 AND status='active'
			GROUP BY repository
			HAVING count(DISTINCT digest) >= 2
		) ready`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count comparison-ready repositories: %w", err)
	}
	return count, nil
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

	fromFindings, err := s.comparisonFindings(ctx, tenantID, fromID)
	if err != nil {
		return nil, err
	}
	toFindings, err := s.comparisonFindings(ctx, tenantID, toID)
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

	fromPackages, err := s.comparisonPackages(ctx, tenantID, fromID)
	if err != nil {
		return nil, err
	}
	toPackages, err := s.comparisonPackages(ctx, tenantID, toID)
	if err != nil {
		return nil, err
	}
	policy, err := s.GetLicensePolicy(ctx, tenantID)
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
		beforeViolation, _ := policy.Evaluate(comparisonPackageLicense(before))
		afterViolation, reason := policy.Evaluate(comparisonPackageLicense(after))
		if !beforeViolation && afterViolation {
			out.LicensePolicyRegressions = append(out.LicensePolicyRegressions, ComparisonLicensePolicyRegression{
				Package: after.Package, Version: after.Version, From: before.Licenses, To: after.Licenses, Reason: reason,
			})
		}
	}
	for key, after := range toPackages {
		if _, ok := fromPackages[key]; !ok {
			out.PackagesAdded = append(out.PackagesAdded, after)
			if violation, reason := policy.Evaluate(comparisonPackageLicense(after)); violation {
				out.LicensePolicyRegressions = append(out.LicensePolicyRegressions, ComparisonLicensePolicyRegression{
					Package: after.Package, Version: after.Version, To: after.Licenses, Reason: reason,
				})
			}
		}
	}
	sortPackages(out.PackagesAdded)
	sortPackages(out.PackagesRemoved)
	sort.Slice(out.LicenseChanges, func(i, j int) bool {
		return packageVersionLess(out.LicenseChanges[i].Package, out.LicenseChanges[i].Version,
			out.LicenseChanges[j].Package, out.LicenseChanges[j].Version)
	})
	sort.Slice(out.LicensePolicyRegressions, func(i, j int) bool {
		return packageVersionLess(out.LicensePolicyRegressions[i].Package, out.LicensePolicyRegressions[i].Version,
			out.LicensePolicyRegressions[j].Package, out.LicensePolicyRegressions[j].Version)
	})
	return out, nil
}

// RecommendUpgrade finds the newest active generation after baseline whose
// comparison verdict strictly improves. Generation order uses the SBOM's
// effective timestamp and SBOM ID as a deterministic tie-break.
func (s *Store) RecommendUpgrade(ctx context.Context, tenantID, baselineID string) (*UpgradeRecommendation, error) {
	if _, err := s.comparisonSide(ctx, tenantID, baselineID); err != nil {
		return nil, err
	}
	var candidateID string
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(`
		WITH baseline AS (
			SELECT id, tenant_id, repository,
			       COALESCE(generated_at,submitted_at) AS effective_at
			FROM devradar_sbom
			WHERE tenant_id=$1 AND id=$2 AND status='active'
		), candidates AS (
			SELECT candidate.id,
			       COALESCE(candidate.generated_at,candidate.submitted_at) AS effective_at
			FROM baseline
			JOIN devradar_sbom candidate
			  ON candidate.tenant_id=baseline.tenant_id
			 AND candidate.repository=baseline.repository
			WHERE candidate.status='active'
			  AND (COALESCE(candidate.generated_at,candidate.submitted_at), candidate.id) >
			      (baseline.effective_at, baseline.id)
		), comparison_scope AS (
			SELECT id FROM baseline
			UNION ALL
			SELECT id FROM candidates
		), deduplicated_findings AS (
			SELECT sb.id AS sbom_id, f.finding_id,
			       (array_agg(f.severity ORDER BY %s))[1] AS severity,
			       COALESCE(bool_or(e.kev),false) AS kev
			FROM comparison_scope scope
			JOIN devradar_sbom sb ON sb.id=scope.id AND sb.tenant_id=$1
			JOIN devradar_finding f ON f.sbom_id=sb.id
			LEFT JOIN devradar_cve_enrichment e ON e.cve=f.exposure
			%s
			WHERE NOT %s
			GROUP BY sb.id, f.finding_id
		), posture_counts AS (
			SELECT scope.id,
			       COUNT(f.finding_id) FILTER (WHERE f.kev) AS kev,
			       COUNT(f.finding_id) FILTER (WHERE f.severity='critical') AS critical,
			       COUNT(f.finding_id) FILTER (WHERE f.severity='high') AS high,
			       COUNT(f.finding_id) FILTER (WHERE f.severity='medium') AS medium,
			       COUNT(f.finding_id) FILTER (WHERE f.severity='low') AS low,
			       COUNT(f.finding_id) AS total
			FROM comparison_scope scope
			LEFT JOIN deduplicated_findings f ON f.sbom_id=scope.id
			GROUP BY scope.id
		), baseline_counts AS (
			SELECT counts.*
			FROM posture_counts counts
			JOIN baseline ON baseline.id=counts.id
		)
		SELECT candidate.id
		FROM candidates candidate
		JOIN posture_counts counts ON counts.id=candidate.id
		CROSS JOIN baseline_counts baseline
		WHERE counts.total < baseline.total
		  AND (counts.kev, counts.critical, counts.high, counts.medium, counts.low, counts.total) <
		      (baseline.kev, baseline.critical, baseline.high, baseline.medium, baseline.low, baseline.total)
		ORDER BY candidate.effective_at DESC, candidate.id DESC
		LIMIT 1`, severityRankSQLCol("f.severity"), vexStatusJoin, vexSuppressedExpr),
		tenantID, baselineID).Scan(&candidateID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select upgrade candidate: %w", err)
	}
	comparison, err := s.CompareSBOMs(ctx, tenantID, baselineID, candidateID)
	if err != nil {
		return nil, err
	}
	return &UpgradeRecommendation{
		Baseline: comparison.From, Candidate: comparison.To, Comparison: comparison,
	}, nil
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

func (s *Store) comparisonFindings(ctx context.Context, tenantID, sbomID string) (map[string]comparisonFindingState, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT f.finding_id, MIN(f.exposure), MIN(f.package), MIN(f.version),
		       (array_agg(f.severity ORDER BY %s))[1], MAX(f.score), bool_or(f.is_fixed),
		       COALESCE(bool_or(e.kev), false)
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id=f.sbom_id
		LEFT JOIN devradar_cve_enrichment e ON e.cve=f.exposure
		%s
		WHERE sb.tenant_id=$1 AND sb.id=$2 AND sb.status='active'
		  AND NOT %s
		GROUP BY f.finding_id`, severityRankSQLCol("f.severity"), vexStatusJoin, vexSuppressedExpr), tenantID, sbomID)
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

func (s *Store) comparisonPackages(ctx context.Context, tenantID, sbomID string) (map[string]ComparisonPackage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.package, p.version, p.licenses
		FROM devradar_sbom_package p
		JOIN devradar_sbom sb ON sb.id=p.sbom_id
		WHERE sb.tenant_id=$1 AND sb.id=$2 AND sb.status='active'
		ORDER BY p.package, p.version`, tenantID, sbomID)
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

func comparisonPackageLicense(p ComparisonPackage) data.PackageLicense {
	return data.PackageLicense{Package: p.Package, Version: p.Version, Licenses: p.Licenses}
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
	sort.Slice(items, func(i, j int) bool {
		return packageVersionLess(items[i].Package, items[i].Version, items[j].Package, items[j].Version)
	})
}

func packageVersionLess(leftPackage, leftVersion, rightPackage, rightVersion string) bool {
	if leftPackage != rightPackage {
		return leftPackage < rightPackage
	}
	return leftVersion < rightVersion
}
