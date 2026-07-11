package postgres_test

import (
	"context"
	"testing"
)

func TestSnapshotTenantPosture_DeduplicatesAndIsolates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	repository := "registry.test/posture-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, sb.ID, repository); err != nil {
		t.Fatal(err)
	}
	sb.Repository = repository

	// A second active generation in the same repository is still one image in
	// the FleetStats/UI sense.
	second := *sb
	second.ID = randID(t) + randID(t)
	second.Digest = "sha256:" + randID(t) + randID(t)
	second.ImageRef = repository + ":v2"
	second.Version = "v2"
	second.ObjectPath += "/v2"
	if _, _, _, err := st.UpsertSBOM(ctx, &second); err != nil {
		t.Fatalf("seed second generation: %v", err)
	}

	// Scanner twins disagree: canonical posture uses the worst severity and the
	// union of fix availability, while counting the finding once.
	for _, finding := range []struct {
		scanner, severity string
		fixed             bool
	}{
		{scanner: "grype", severity: "high", fixed: true},
		{scanner: "trivy", severity: "critical", fixed: false},
	} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding
			(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,$2,'same','CVE-2026-8001','pkg','1',$3,9.8,$4)`,
			sb.ID, finding.scanner, finding.severity, finding.fixed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, kev)
		VALUES ('CVE-2026-8001', true)
		ON CONFLICT (cve) DO UPDATE SET kev=true`); err != nil {
		t.Fatalf("seed KEV: %v", err)
	}

	// An archived SBOM in a different repository and its finding are excluded.
	archived := *sb
	archived.ID = randID(t) + randID(t)
	archived.Digest = "sha256:" + randID(t) + randID(t)
	archived.Repository += "/archived"
	archived.ImageRef = archived.Repository
	archived.ObjectPath += "/archived"
	archived.Status = "archived"
	if _, _, _, err := st.UpsertSBOM(ctx, &archived); err != nil {
		t.Fatalf("seed archived SBOM: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','archived','CVE-2026-8002','pkg','1','low',3,true)`, archived.ID); err != nil {
		t.Fatal(err)
	}

	otherTenantID, otherSB := seedTenantAndSBOM(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','other','CVE-2026-8999','pkg','1','high',8,false)`, otherSB.ID); err != nil {
		t.Fatal(err)
	}

	suspendedTenantID, _ := seedTenantAndSBOM(t, st)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, suspendedTenantID); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}

	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatalf("idempotent snapshot: %v", err)
	}
	trend, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trend) != 1 || trend[0].Total != 1 || trend[0].Critical != 1 ||
		trend[0].High != 0 || trend[0].Fixable != 1 || trend[0].KEV != 1 || trend[0].Images != 1 {
		t.Fatalf("tenant trend = %+v", trend)
	}
	other, err := st.TenantPostureTrend(ctx, otherTenantID, 30)
	if err != nil || len(other) != 1 || other[0].Total != 1 || other[0].High != 1 {
		t.Fatalf("other tenant trend = %+v error=%v", other, err)
	}
	suspended, err := st.TenantPostureTrend(ctx, suspendedTenantID, 30)
	if err != nil || len(suspended) != 0 {
		t.Fatalf("suspended tenant trend = %+v error=%v", suspended, err)
	}
}

func TestSnapshotTenantPosture_ExcludesVEXSuppressedFindings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','suppressed','CVE-2026-8111','pkg','1','critical',9.8,true)`, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, kev)
		VALUES ('CVE-2026-8111', true)
		ON CONFLICT (cve) DO UPDATE SET kev=true`); err != nil {
		t.Fatal(err)
	}
	var documentID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_vex_document (tenant_id, document)
		VALUES ($1, '{}'::jsonb) RETURNING id`, tenantID).Scan(&documentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_vex_statement
		(tenant_id, document_id, product_digest, vulnerability, status)
		VALUES ($1,$2,$3,'CVE-2026-8111','not_affected')`, tenantID, documentID, sb.Digest); err != nil {
		t.Fatal(err)
	}

	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	trend, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trend) != 1 || trend[0].Images != 1 || trend[0].Total != 0 ||
		trend[0].Critical != 0 || trend[0].Fixable != 0 || trend[0].KEV != 0 {
		t.Fatalf("VEX-suppressed tenant trend = %+v", trend)
	}
}

func TestTenantPostureTrend_ExcludesFutureSnapshots(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
		(tenant_id, snapshot_date, images, relevant_findings)
		VALUES ($1, CURRENT_DATE + 1, 99, 99)`, tenantID); err != nil {
		t.Fatal(err)
	}

	trend, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trend) != 1 || trend[0].Images != 1 {
		t.Fatalf("trend includes future snapshot: %+v", trend)
	}
}
