package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

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
