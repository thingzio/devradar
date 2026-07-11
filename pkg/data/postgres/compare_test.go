package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestComparisonReadyRepositoryCount_DistinctActiveDigestsAndTenantIsolation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, first := seedTenantAndSBOM(t, st)
	readyRepository := "registry.test/comparison-ready-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, first.ID, readyRepository); err != nil {
		t.Fatal(err)
	}

	duplicateDigest := *first
	duplicateDigest.ID = randID(t) + randID(t)
	duplicateDigest.Repository = readyRepository
	duplicateDigest.Format = "spdx"
	duplicateDigest.ObjectPath += "/spdx"
	if _, _, _, err := st.UpsertSBOM(ctx, &duplicateDigest); err != nil {
		t.Fatalf("seed duplicate digest: %v", err)
	}
	if got, err := st.ComparisonReadyRepositoryCount(ctx, tenantID); err != nil {
		t.Fatal(err)
	} else if got != 0 {
		t.Fatalf("duplicate-only comparison-ready repository count = %d, want 0", got)
	}
	secondDigest := comparisonSBOM(t, tenantID, readyRepository, "v2", time.Now().UTC())
	if _, _, _, err := st.UpsertSBOM(ctx, secondDigest); err != nil {
		t.Fatalf("seed second digest: %v", err)
	}

	singleRepository := "registry.test/comparison-single-" + randID(t)[:8]
	single := comparisonSBOM(t, tenantID, singleRepository, "v1", time.Now().UTC())
	if _, _, _, err := st.UpsertSBOM(ctx, single); err != nil {
		t.Fatalf("seed single-digest repository: %v", err)
	}
	archived := comparisonSBOM(t, tenantID, singleRepository, "archived", time.Now().UTC())
	archived.Status = "archived"
	if _, _, _, err := st.UpsertSBOM(ctx, archived); err != nil {
		t.Fatalf("seed archived digest: %v", err)
	}

	foreignTenantID, foreignFirst := seedTenantAndSBOM(t, st)
	foreignRepository := "registry.test/comparison-foreign-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, foreignFirst.ID, foreignRepository); err != nil {
		t.Fatal(err)
	}
	foreignSecond := comparisonSBOM(t, foreignTenantID, foreignRepository, "v2", time.Now().UTC())
	if _, _, _, err := st.UpsertSBOM(ctx, foreignSecond); err != nil {
		t.Fatalf("seed foreign second digest: %v", err)
	}

	var emptyTenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"empty-"+randID(t)[:8]+"@example.com").Scan(&emptyTenantID); err != nil {
		t.Fatalf("seed empty tenant: %v", err)
	}

	for _, tc := range []struct {
		name     string
		tenantID string
		want     int
	}{
		{name: "tenant", tenantID: tenantID, want: 1},
		{name: "foreign tenant", tenantID: foreignTenantID, want: 1},
		{name: "empty tenant", tenantID: emptyTenantID, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.ComparisonReadyRepositoryCount(ctx, tc.tenantID)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("comparison-ready repository count = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCompareSBOMs_ExcludesVEXSuppressedFindings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, from := seedTenantAndSBOM(t, st)
	from.Repository = "registry.test/vex-compare"
	if _, err := st.DB().ExecContext(ctx, `UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, from.ID, from.Repository); err != nil {
		t.Fatal(err)
	}
	to := comparisonSBOM(t, tenantID, from.Repository, "v2", time.Now().UTC())
	if _, _, _, err := st.UpsertSBOM(ctx, to); err != nil {
		t.Fatal(err)
	}

	insertComparisonFinding(t, st, from.ID, "grype", "digest-hidden", "CVE-2026-8001", "critical", false)
	insertComparisonFinding(t, st, from.ID, "grype", "repo-hidden", "CVE-2026-8002", "critical", false)
	insertComparisonFinding(t, st, from.ID, "grype", "restored", "CVE-2026-8003", "high", false)
	insertComparisonFinding(t, st, from.ID, "trivy", "restored", "CVE-2026-8003", "high", false)
	insertComparisonFinding(t, st, from.ID, "grype", "foreign-vex", "CVE-2026-8004", "medium", false)
	insertComparisonVEX(t, st, tenantID, from.Digest, "", "CVE-2026-8001", "fixed", time.Now().Add(-time.Hour))
	insertComparisonVEX(t, st, tenantID, "", "vex-compare", "CVE-2026-8002", "not_affected", time.Now())
	insertComparisonVEX(t, st, tenantID, from.Digest, "", "CVE-2026-8003", "fixed", time.Now().Add(-time.Hour))
	insertComparisonVEX(t, st, tenantID, from.Digest, "", "CVE-2026-8003", "affected", time.Now())
	otherTenantID, _ := seedTenantAndSBOM(t, st)
	insertComparisonVEX(t, st, otherTenantID, from.Digest, "", "CVE-2026-8004", "fixed", time.Now())

	got, err := st.CompareSBOMs(ctx, tenantID, from.ID, to.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.From.Counts.Total != 2 || len(got.Resolved) != 2 {
		t.Fatalf("VEX-aware comparison counts/resolved = %+v", got)
	}
	if got.Resolved[0].Exposure != "CVE-2026-8003" || got.Resolved[1].Exposure != "CVE-2026-8004" {
		t.Fatalf("resolved findings = %+v", got.Resolved)
	}
}

func TestCompareSBOMs_LicensePolicyRegressionsAreReadTime(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, from := seedTenantAndSBOM(t, st)
	from.Repository = "registry.test/license-compare"
	if _, err := st.DB().ExecContext(ctx, `UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, from.ID, from.Repository); err != nil {
		t.Fatal(err)
	}
	to := comparisonSBOM(t, tenantID, from.Repository, "v2", time.Now().UTC())
	if _, _, _, err := st.UpsertSBOM(ctx, to); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSBOMPackages(ctx, from.ID, []data.PackageLicense{
		{Package: "changed", Version: "1", Licenses: []string{"MIT"}},
		{Package: "already-denied", Version: "1", Licenses: []string{"GPL-3.0"}},
		{Package: "a", Version: "z", Licenses: []string{"MIT"}},
		{Package: "aa", Version: "a", Licenses: []string{"MIT"}},
		{Package: "or-allowed", Version: "1", Licenses: []string{"MIT"}},
		{Package: "and-denied", Version: "1", Licenses: []string{"MIT"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSBOMPackages(ctx, to.ID, []data.PackageLicense{
		{Package: "changed", Version: "1", Licenses: []string{"GPL-3.0"}},
		{Package: "already-denied", Version: "1", Licenses: []string{"GPL-3.0"}},
		{Package: "new-denied", Version: "1", Licenses: []string{"AGPL-3.0"}},
		{Package: "new-allowed", Version: "1", Licenses: []string{"Apache-2.0"}},
		{Package: "a", Version: "z", Licenses: []string{"GPL-3.0"}},
		{Package: "aa", Version: "a", Licenses: []string{"GPL-3.0"}},
		{Package: "or-allowed", Version: "1", Licenses: []string{"MIT OR GPL-3.0"}},
		{Package: "and-denied", Version: "1", Licenses: []string{"MIT AND GPL-3.0"}},
	}); err != nil {
		t.Fatal(err)
	}

	before, err := st.CompareSBOMs(ctx, tenantID, from.ID, to.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.LicensePolicyRegressions) != 0 {
		t.Fatalf("regressions under empty policy = %+v", before.LicensePolicyRegressions)
	}
	if err := st.SetLicensePolicy(ctx, tenantID, data.LicensePolicy{
		DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := st.CompareSBOMs(ctx, tenantID, from.ID, to.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.LicensePolicyRegressions) != 5 {
		t.Fatalf("license-policy regressions = %+v", after.LicensePolicyRegressions)
	}
	got := comparisonLicensePolicyRegressionKeys(after.LicensePolicyRegressions)
	if !slices.Equal(got, []string{"a@z", "aa@a", "and-denied@1", "changed@1", "new-denied@1"}) {
		t.Fatalf("license-policy regression packages = %v", got)
	}
	if got := comparisonLicenseChangeKeys(after.LicenseChanges); !slices.Equal(got,
		[]string{"a@z", "aa@a", "and-denied@1", "changed@1", "or-allowed@1"}) {
		t.Fatalf("license change order = %v", got)
	}
	for _, regression := range after.LicensePolicyRegressions {
		if regression.Reason == "" {
			t.Fatalf("license-policy regression reason = %+v", regression)
		}
	}

	rows, err := st.ListSBOMPackages(ctx, tenantID, from.ID, data.LicensePolicy{})
	if err != nil || packageLicenses(rows, "changed") != "MIT" || packageLicenses(rows, "or-allowed") != "MIT" ||
		packageLicenses(rows, "and-denied") != "MIT" {
		t.Fatalf("frozen from inventory changed: rows=%+v err=%v", rows, err)
	}
}

func TestRecommendUpgrade_SelectsNewestImprovementAndPreservesIsolation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, baseline := seedTenantAndSBOM(t, st)
	baseline.Repository = "registry.test/upgrade"
	baseTime := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2, generated_at=$3 WHERE id=$1`, baseline.ID, baseline.Repository, baseTime); err != nil {
		t.Fatal(err)
	}
	insertComparisonFinding(t, st, baseline.ID, "grype", "base-1", "CVE-2026-8101", "critical", false)
	insertComparisonFinding(t, st, baseline.ID, "grype", "base-2", "CVE-2026-8102", "critical", false)

	older := comparisonSBOM(t, tenantID, baseline.Repository, "older", baseTime.Add(-time.Hour))
	qualifyingOlder := comparisonSBOM(t, tenantID, baseline.Repository, "qualifying-older", baseTime.Add(time.Hour))
	qualifyingNewest := comparisonSBOM(t, tenantID, baseline.Repository, "qualifying-newest", baseTime.Add(2*time.Hour))
	tiePrefix := randID(t) + randID(t)
	qualifyingOlder.GeneratedAt = qualifyingNewest.GeneratedAt
	qualifyingOlder.ID, qualifyingOlder.Digest = tiePrefix[:63]+"0", "sha256:"+tiePrefix[:63]+"0"
	qualifyingNewest.ID, qualifyingNewest.Digest = tiePrefix[:63]+"f", "sha256:"+tiePrefix[:63]+"f"
	equalTotalImprovement := comparisonSBOM(t, tenantID, baseline.Repository, "equal-total", baseTime.Add(3*time.Hour))
	for _, sb := range []*postgres.SBOM{older, qualifyingOlder, qualifyingNewest, equalTotalImprovement} {
		if _, _, _, err := st.UpsertSBOM(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	insertComparisonFinding(t, st, qualifyingOlder.ID, "grype", "qualifying-older", "CVE-2026-8111", "high", false)
	insertComparisonFinding(t, st, qualifyingNewest.ID, "grype", "qualifying-newest", "CVE-2026-8121", "medium", false)
	insertComparisonFinding(t, st, qualifyingNewest.ID, "trivy", "qualifying-newest", "CVE-2026-8121", "medium", false)
	insertComparisonFinding(t, st, qualifyingNewest.ID, "grype", "qualifying-vex-hidden", "CVE-2026-8122", "critical", false)
	insertComparisonVEX(t, st, tenantID, qualifyingNewest.Digest, "", "CVE-2026-8122", "fixed", time.Now())
	insertComparisonFinding(t, st, equalTotalImprovement.ID, "grype", "equal-total-1", "CVE-2026-8131", "high", false)
	insertComparisonFinding(t, st, equalTotalImprovement.ID, "grype", "equal-total-2", "CVE-2026-8132", "high", false)

	var latest *postgres.SBOM
	for i := 0; i < 16; i++ {
		candidate := comparisonSBOM(t, tenantID, baseline.Repository, fmt.Sprintf("non-improving-%02d", i), baseTime.Add(time.Duration(i+4)*time.Hour))
		if _, _, _, err := st.UpsertSBOM(ctx, candidate); err != nil {
			t.Fatal(err)
		}
		insertComparisonFinding(t, st, candidate.ID, "grype", fmt.Sprintf("same-%02d-1", i), fmt.Sprintf("CVE-2026-82%02d", i*2), "critical", false)
		insertComparisonFinding(t, st, candidate.ID, "grype", fmt.Sprintf("same-%02d-2", i), fmt.Sprintf("CVE-2026-82%02d", i*2+1), "critical", false)
		latest = candidate
	}

	otherTenantID, _ := seedTenantAndSBOM(t, st)
	foreign := comparisonSBOM(t, otherTenantID, baseline.Repository, "foreign", baseTime.Add(30*time.Hour))
	if _, _, _, err := st.UpsertSBOM(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	recommendation, err := st.RecommendUpgrade(ctx, tenantID, baseline.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recommendation == nil || recommendation.Candidate.SBOMID != qualifyingNewest.ID {
		t.Fatalf("upgrade recommendation = %+v, want newest lower-total candidate %s", recommendation, qualifyingNewest.ID)
	}
	if recommendation.Comparison.To.Counts.Total >= recommendation.Comparison.From.Counts.Total {
		t.Fatalf("recommendation did not reduce total findings: %+v", recommendation.Comparison)
	}
	if recommendation.Comparison.Verdict != postgres.PostureImproves {
		t.Fatalf("recommendation verdict = %q", recommendation.Comparison.Verdict)
	}
	if got, err := st.RecommendUpgrade(ctx, tenantID, latest.ID); err != nil || got != nil {
		t.Fatalf("newest baseline recommendation = %+v, %v", got, err)
	}
	if _, err := st.RecommendUpgrade(ctx, tenantID, foreign.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("foreign baseline error = %v", err)
	}
}

func comparisonLicensePolicyRegressionKeys(items []postgres.ComparisonLicensePolicyRegression) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Package+"@"+item.Version)
	}
	return out
}

func comparisonLicenseChangeKeys(items []postgres.ComparisonLicenseChange) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Package+"@"+item.Version)
	}
	return out
}

func packageLicenses(rows []postgres.PackageLicenseRow, name string) string {
	for _, row := range rows {
		if row.Package == name && len(row.Licenses) > 0 {
			return row.Licenses[0]
		}
	}
	return ""
}

func TestCompareSBOMs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, from := seedTenantAndSBOM(t, st)
	to := &postgres.SBOM{
		ID: randID(t) + randID(t), TenantID: tenantID, ImageRef: "registry.test/app:v2",
		Repository: from.Repository, Version: "v2", Digest: "sha256:" + randID(t) + randID(t),
		Format: "cyclonedx", PackageCount: 100, ObjectPath: "gs://test/to", Status: "active",
	}
	if _, _, _, err := st.UpsertSBOM(ctx, to); err != nil {
		t.Fatal(err)
	}
	insertComparisonFinding(t, st, from.ID, "grype", "shared", "CVE-2026-6001", "high", false)
	insertComparisonFinding(t, st, from.ID, "grype", "removed", "CVE-2026-6002", "medium", false)
	insertComparisonFinding(t, st, to.ID, "grype", "shared", "CVE-2026-6001", "critical", true)
	insertComparisonFinding(t, st, to.ID, "trivy", "shared", "CVE-2026-6001", "critical", true)
	insertComparisonFinding(t, st, to.ID, "grype", "added", "CVE-2026-6003", "low", false)

	if err := st.UpsertSBOMPackages(ctx, from.ID, []data.PackageLicense{
		{Package: "openssl", Version: "1", Licenses: []string{"MIT"}},
		{Package: "curl", Version: "1", Licenses: []string{"MIT"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSBOMPackages(ctx, to.ID, []data.PackageLicense{
		{Package: "openssl", Version: "1", Licenses: []string{"Apache-2.0"}},
		{Package: "zlib", Version: "2", Licenses: []string{"Zlib"}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.CompareSBOMs(ctx, tenantID, from.ID, to.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != postgres.PostureRegresses || got.From.Counts.Total != 2 || got.To.Counts.Total != 2 {
		t.Fatalf("comparison verdict/counts = %+v", got)
	}
	if len(got.Added) != 1 || got.Added[0].Exposure != "CVE-2026-6003" ||
		len(got.Resolved) != 1 || got.Resolved[0].Exposure != "CVE-2026-6002" ||
		len(got.Rerated) != 1 || len(got.NewlyFixable) != 1 {
		t.Fatalf("finding changes = %+v", got)
	}
	if len(got.PackagesAdded) != 1 || got.PackagesAdded[0].Package != "zlib" ||
		len(got.PackagesRemoved) != 1 || got.PackagesRemoved[0].Package != "curl" ||
		len(got.LicenseChanges) != 1 || got.LicenseChanges[0].Package != "openssl" {
		t.Fatalf("package changes = %+v", got)
	}

	if _, err := st.CompareSBOMs(ctx, tenantID, from.ID, from.ID); !errors.Is(err, postgres.ErrInvalidComparison) {
		t.Fatalf("same digest error = %v", err)
	}
	otherTenant, other := seedTenantAndSBOM(t, st)
	if _, err := st.CompareSBOMs(ctx, tenantID, from.ID, other.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-tenant error = %v", err)
	}
	_ = otherTenant
}

func insertComparisonFinding(t *testing.T, st *postgres.Store, sbomID, scanner, findingID, cve, severity string, fixed bool) {
	t.Helper()
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,$2,$3,$4,'pkg','1',$5,7,$6)`, sbomID, scanner, findingID, cve, severity, fixed); err != nil {
		t.Fatal(err)
	}
}

func comparisonSBOM(t *testing.T, tenantID, repository, version string, generatedAt time.Time) *postgres.SBOM {
	t.Helper()
	id := randID(t) + randID(t)
	return &postgres.SBOM{
		ID: id, TenantID: tenantID, ImageRef: repository + ":" + version,
		Repository: repository, Version: version, Digest: "sha256:" + id,
		Format: "cyclonedx", PackageCount: 100, ObjectPath: "gs://test/" + id,
		Status: "active", GeneratedAt: generatedAt,
	}
}

func insertComparisonVEX(t *testing.T, st *postgres.Store, tenantID, digest, repository, cve, status string, createdAt time.Time) {
	t.Helper()
	var documentID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_vex_document (tenant_id, document) VALUES ($1, '{}') RETURNING id`, tenantID).Scan(&documentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_vex_statement
		(tenant_id, document_id, product_digest, product_repo, vulnerability, status, created_at)
		VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,$7)`,
		tenantID, documentID, digest, repository, cve, status, createdAt); err != nil {
		t.Fatal(err)
	}
}
