package postgres_test

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
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

func TestSnapshotTenantPosture_LatestVEXStatementRestoresExposure(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','latest-vex','CVE-2026-8112','pkg','1','critical',9.8,true)`, sb.ID); err != nil {
		t.Fatal(err)
	}
	var documentID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_vex_document (tenant_id, document)
		VALUES ($1, '{}'::jsonb) RETURNING id`, tenantID).Scan(&documentID); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_vex_statement
		(tenant_id, document_id, product_digest, vulnerability, status, created_at)
		VALUES ($1,$2,$3,'CVE-2026-8112','not_affected',$4)`, tenantID, documentID, sb.Digest, base); err != nil {
		t.Fatal(err)
	}

	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trend, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil || len(trend) != 1 || trend[0].Total != 0 {
		t.Fatalf("suppressed trend = %+v error=%v", trend, err)
	}

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_vex_statement
		(tenant_id, document_id, product_digest, vulnerability, status, created_at)
		VALUES ($1,$2,$3,'CVE-2026-8112','affected',$4)`, tenantID, documentID, sb.Digest, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trend, err = st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil || len(trend) != 1 || trend[0].Total != 1 || trend[0].Critical != 1 || trend[0].Fixable != 1 {
		t.Fatalf("restored trend = %+v error=%v", trend, err)
	}
	if after.CanonicalExposures != before.CanonicalExposures+1 ||
		after.CanonicalFixableExposures != before.CanonicalFixableExposures+1 {
		t.Fatalf("admin exposure was not restored: before=%+v after=%+v", before, after)
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

func TestTenantPostureTrend_BoundsOrdersAndIsolates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)
	otherTenantID, _ := seedTenantAndSBOM(t, st)

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings)
		VALUES
			($1, CURRENT_DATE - 365, 1, 365),
			($1, CURRENT_DATE - 364, 1, 364),
			($1, CURRENT_DATE - 2, 1, 2),
			($1, CURRENT_DATE - 1, 1, 1),
			($1, CURRENT_DATE, 1, 0),
			($2, CURRENT_DATE, 9, 999)`, tenantID, otherTenantID); err != nil {
		t.Fatal(err)
	}

	oneDay, err := st.TenantPostureTrend(ctx, tenantID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(oneDay) != 1 || oneDay[0].Total != 0 {
		t.Fatalf("zero-day request was not clamped to one day: %+v", oneDay)
	}

	maximum, err := st.TenantPostureTrend(ctx, tenantID, 999)
	if err != nil {
		t.Fatal(err)
	}
	wantTotals := []int{364, 2, 1, 0}
	if len(maximum) != len(wantTotals) {
		t.Fatalf("maximum bounded trend length = %d, want %d: %+v", len(maximum), len(wantTotals), maximum)
	}
	for i, want := range wantTotals {
		if maximum[i].Total != want {
			t.Fatalf("trend[%d].Total = %d, want %d: %+v", i, maximum[i].Total, want, maximum)
		}
		if i > 0 && !maximum[i-1].Date.Before(maximum[i].Date) {
			t.Fatalf("trend is not chronological: %+v", maximum)
		}
	}

	other, err := st.TenantPostureTrend(ctx, otherTenantID, 365)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 1 || other[0].Total != 999 {
		t.Fatalf("other tenant trend = %+v", other)
	}
}

func TestTenantPostureCoverageStart_IsolatesAndReturnsNilWithoutSnapshots(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)
	otherTenantID, _ := seedTenantAndSBOM(t, st)
	emptyTenantID, _ := seedTenantAndSBOM(t, st)

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings)
		VALUES
			($1, CURRENT_DATE - 400, 1, 40),
			($1, CURRENT_DATE - 5, 1, 5),
			($2, CURRENT_DATE - 600, 1, 60),
			($3, CURRENT_DATE + 1, 1, 99)`, tenantID, otherTenantID, emptyTenantID); err != nil {
		t.Fatal(err)
	}
	var want string
	if err := st.DB().QueryRowContext(ctx, `SELECT to_char(CURRENT_DATE - 400, 'YYYY-MM-DD')`).Scan(&want); err != nil {
		t.Fatal(err)
	}

	start, err := st.TenantPostureCoverageStart(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if start == nil || start.Format(time.DateOnly) != want {
		t.Fatalf("tenant coverage start = %v, want %s", start, want)
	}

	empty, err := st.TenantPostureCoverageStart(ctx, emptyTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if empty != nil {
		t.Fatalf("empty tenant coverage start = %v, want nil", empty)
	}
}

func TestSnapshotTenantPosture_RepositorySnapshotsReplaceTodayAndRespectVEX(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, first := seedTenantAndSBOM(t, st)
	first.Repository = "registry.test/repository-posture-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, first.ID, first.Repository); err != nil {
		t.Fatal(err)
	}
	second := &postgres.SBOM{
		ID: randID(t) + randID(t), TenantID: tenantID,
		ImageRef: "registry.test/quiet:v1", Repository: "registry.test/quiet-" + randID(t)[:8],
		Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
		PackageCount: 10, ObjectPath: "gs://test/quiet", Status: "active",
	}
	if _, _, _, err := st.UpsertSBOM(ctx, second); err != nil {
		t.Fatal(err)
	}
	for _, scanner := range []string{"grype", "trivy"} {
		severity, fixed := "high", false
		if scanner == "trivy" {
			severity, fixed = "critical", true
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding
			(sbom_id,scanner,finding_id,exposure,package,version,severity,score,is_fixed)
			VALUES ($1,$2,'canonical','CVE-2026-8251','pkg','1',$3,9.8,$4)`,
			first.ID, scanner, severity, fixed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id,scanner,finding_id,exposure,package,version,severity,score,is_fixed)
		VALUES ($1,'grype','suppressed','CVE-2026-8252','pkg','1','high',8,true)`, second.ID); err != nil {
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
		(tenant_id,document_id,product_digest,vulnerability,status)
		VALUES ($1,$2,$3,'CVE-2026-8252','not_affected')`, tenantID, documentID, second.Digest); err != nil {
		t.Fatal(err)
	}

	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	firstTrend, err := st.RepositoryPostureTrend(ctx, tenantID, first.Repository, 30)
	if err != nil || len(firstTrend) != 1 || firstTrend[0].Images != 1 || firstTrend[0].Total != 1 ||
		firstTrend[0].Critical != 1 || firstTrend[0].High != 0 || firstTrend[0].Fixable != 1 {
		t.Fatalf("first repository trend = %+v error=%v", firstTrend, err)
	}
	secondTrend, err := st.RepositoryPostureTrend(ctx, tenantID, second.Repository, 30)
	if err != nil || len(secondTrend) != 1 || secondTrend[0].Images != 1 || secondTrend[0].Total != 0 {
		t.Fatalf("VEX-aware repository trend = %+v error=%v", secondTrend, err)
	}
	options, err := st.RepositoryPostureOptions(ctx, tenantID)
	if err != nil || len(options) != 2 {
		t.Fatalf("repository options = %+v error=%v", options, err)
	}
	otherTenantID, _ := seedTenantAndSBOM(t, st)
	foreign, err := st.RepositoryPostureTrend(ctx, otherTenantID, first.Repository, 30)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("cross-tenant repository trend = %+v error=%v", foreign, err)
	}

	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET status='archived' WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	secondTrend, err = st.RepositoryPostureTrend(ctx, tenantID, second.Repository, 30)
	if err != nil || len(secondTrend) != 0 {
		t.Fatalf("same-day repository replacement retained archived repository: trend=%+v error=%v", secondTrend, err)
	}
	fleet, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil || len(fleet) != 1 || fleet[0].Images != 1 || fleet[0].Total != 1 {
		t.Fatalf("fleet snapshot did not converge with repository rows: trend=%+v error=%v", fleet, err)
	}
}

func TestPostureDatesUseUTCUnderNonUTCSession(t *testing.T) {
	st := testStore(t)
	st.DB().SetMaxOpenConns(1)
	st.DB().SetMaxIdleConns(1)
	ctx := context.Background()

	timezone := "Etc/GMT+12"
	if time.Now().UTC().Hour() >= 12 {
		timezone = "Etc/GMT-14"
	}
	var configuredTimezone string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT set_config('TimeZone', $1, false)`, timezone).Scan(&configuredTimezone); err != nil {
		t.Fatalf("set session timezone: %v", err)
	}
	var sessionDate, utcDate time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT CURRENT_DATE, (now() AT TIME ZONE 'UTC')::date`).Scan(&sessionDate, &utcDate); err != nil {
		t.Fatalf("read session and UTC dates: %v", err)
	}
	if sessionDate.Equal(utcDate) {
		t.Fatalf("test timezone %q did not shift the session date from UTC", configuredTimezone)
	}

	tenantID, sb := seedTenantAndSBOM(t, st)
	repository := "registry.test/utc-current-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, sb.ID, repository); err != nil {
		t.Fatalf("set repository: %v", err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatalf("snapshot posture: %v", err)
	}

	var tenantDate, repositoryDate time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT t.snapshot_date, r.snapshot_date
		FROM devradar_tenant_posture_snapshot t
		JOIN devradar_repository_posture_snapshot r
		  ON r.tenant_id=t.tenant_id
		WHERE t.tenant_id=$1 AND r.repository=$2`, tenantID, repository).
		Scan(&tenantDate, &repositoryDate); err != nil {
		t.Fatalf("read posture snapshot keys: %v", err)
	}
	if !tenantDate.Equal(utcDate) || !repositoryDate.Equal(utcDate) {
		t.Fatalf("snapshot dates = tenant:%s repository:%s, want UTC %s",
			tenantDate.Format(time.DateOnly), repositoryDate.Format(time.DateOnly), utcDate.Format(time.DateOnly))
	}

	tenantTrend, err := st.TenantPostureTrend(ctx, tenantID, 1)
	if err != nil || len(tenantTrend) != 1 || !tenantTrend[0].Date.Equal(utcDate) {
		t.Fatalf("UTC tenant trend = %+v error=%v", tenantTrend, err)
	}
	repositoryTrend, err := st.RepositoryPostureTrend(ctx, tenantID, repository, 1)
	if err != nil || len(repositoryTrend) != 1 || !repositoryTrend[0].Date.Equal(utcDate) {
		t.Fatalf("UTC repository trend = %+v error=%v", repositoryTrend, err)
	}

	boundaryRepository := "registry.test/utc-boundary-" + randID(t)[:8]
	boundaryDate := utcDate.AddDate(0, 0, -364)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_repository_posture_snapshot
			(tenant_id, repository, snapshot_date, images, relevant_findings)
		VALUES ($1,$2,$3,1,0)`, tenantID, boundaryRepository, boundaryDate); err != nil {
		t.Fatalf("insert UTC boundary snapshot: %v", err)
	}
	options, err := st.RepositoryPostureOptions(ctx, tenantID)
	if err != nil {
		t.Fatalf("list UTC repository options: %v", err)
	}
	coverage := make(map[string]time.Time, len(options))
	for _, option := range options {
		coverage[option.Repository] = option.CoverageStart
	}
	if !coverage[repository].Equal(utcDate) || !coverage[boundaryRepository].Equal(boundaryDate) {
		t.Fatalf("UTC repository options = %+v, want current %s and boundary %s",
			options, utcDate.Format(time.DateOnly), boundaryDate.Format(time.DateOnly))
	}
}

func TestRepositoryPostureTrend_BoundsObservedPointsAndOptions(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)
	otherTenantID, _ := seedTenantAndSBOM(t, st)
	repositoryA := "registry.test/a-" + randID(t)[:8]
	repositoryB := "registry.test/b-" + randID(t)[:8]
	repositoryOutsideWindow := "registry.test/old-" + randID(t)[:8]
	foreignRepository := "registry.test/foreign-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_repository_posture_snapshot
			(tenant_id,repository,snapshot_date,images,relevant_findings)
		VALUES
			($1,$2,CURRENT_DATE - 365,1,365),
			($1,$2,CURRENT_DATE - 364,1,364),
			($1,$2,CURRENT_DATE - 2,1,2),
			($1,$2,CURRENT_DATE,1,0),
			($1,$3,CURRENT_DATE - 20,1,20),
			($4,$2,CURRENT_DATE,1,999),
			($1,$5,CURRENT_DATE - 365,1,365),
			($4,$6,CURRENT_DATE,1,999)`,
		tenantID, repositoryA, repositoryB, otherTenantID, repositoryOutsideWindow, foreignRepository); err != nil {
		t.Fatal(err)
	}

	oneDay, err := st.RepositoryPostureTrend(ctx, tenantID, repositoryA, 0)
	if err != nil || len(oneDay) != 1 || oneDay[0].Total != 0 {
		t.Fatalf("one-day repository trend = %+v error=%v", oneDay, err)
	}
	maximum, err := st.RepositoryPostureTrend(ctx, tenantID, repositoryA, 999)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{364, 2, 0}
	if len(maximum) != len(want) {
		t.Fatalf("bounded repository trend = %+v, want totals %v", maximum, want)
	}
	for i, total := range want {
		if maximum[i].Total != total {
			t.Fatalf("repository trend[%d] = %+v, want total %d", i, maximum[i], total)
		}
		if i > 0 && !maximum[i-1].Date.Before(maximum[i].Date) {
			t.Fatalf("repository trend is not chronological: %+v", maximum)
		}
	}
	options, err := st.RepositoryPostureOptions(ctx, tenantID)
	if err != nil || len(options) != 2 || options[0].Repository != repositoryA || options[1].Repository != repositoryB {
		t.Fatalf("repository options = %+v error=%v", options, err)
	}
	var coverageA, coverageB string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT to_char(CURRENT_DATE - 364,'YYYY-MM-DD'),
		       to_char(CURRENT_DATE - 20,'YYYY-MM-DD')`).Scan(&coverageA, &coverageB); err != nil {
		t.Fatal(err)
	}
	if got := options[0].CoverageStart.Format(time.DateOnly); got != coverageA {
		t.Errorf("repository A coverage = %s, want %s", got, coverageA)
	}
	if got := options[1].CoverageStart.Format(time.DateOnly); got != coverageB {
		t.Errorf("repository B coverage = %s, want %s", got, coverageB)
	}
	unknown, err := st.RepositoryPostureTrend(ctx, tenantID, fmt.Sprintf("foreign-%s", repositoryA), 365)
	if err != nil || len(unknown) != 0 {
		t.Fatalf("unknown repository trend = %+v error=%v", unknown, err)
	}
}

func TestSnapshotTenantPosture_ReplacesRowsForSuspendedTenant(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	repository := "registry.test/suspended-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, sb.ID, repository); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	fleet, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil || len(fleet) != 0 {
		t.Fatalf("suspended tenant snapshot retained: trend=%+v error=%v", fleet, err)
	}
	repositoryTrend, err := st.RepositoryPostureTrend(ctx, tenantID, repository, 30)
	if err != nil || len(repositoryTrend) != 0 {
		t.Fatalf("suspended repository snapshot retained: trend=%+v error=%v", repositoryTrend, err)
	}
}

func TestSnapshotTenantPosture_SkipsEmptyRepositoryKeys(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}
	fleet, err := st.TenantPostureTrend(ctx, tenantID, 30)
	if err != nil || len(fleet) != 1 || fleet[0].Images != 1 {
		t.Fatalf("fleet snapshot lost legacy empty-repository image: trend=%+v error=%v", fleet, err)
	}
	var repositoryRows int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM devradar_repository_posture_snapshot
		WHERE tenant_id=$1`, tenantID).Scan(&repositoryRows); err != nil {
		t.Fatal(err)
	}
	if repositoryRows != 0 {
		t.Fatalf("empty repository produced %d repository snapshots", repositoryRows)
	}
}

func TestSnapshotTenantPosture_ConcurrentRetries(t *testing.T) {
	// SnapshotTenantPosture does a global DELETE-then-INSERT of today's rows for
	// all active tenants (no ON CONFLICT), serialized in production by a global
	// advisory lock. A private schema keeps this test's writes from colliding
	// with concurrent package tests that insert directly into the posture
	// snapshot tables on the shared DB under `go test -race ./...`.
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	repository := "registry.test/concurrent-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, sb.ID, repository); err != nil {
		t.Fatal(err)
	}
	if err := st.SnapshotTenantPosture(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := randID(t)
	functionName := "delay_repository_snapshot_" + suffix
	triggerName := "delay_repository_snapshot_" + suffix
	if _, err := st.DB().ExecContext(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.tenant_id = '%s'::uuid THEN
				PERFORM pg_sleep(0.2);
			END IF;
			RETURN OLD;
		END $$;
		CREATE TRIGGER %s BEFORE DELETE ON devradar_repository_posture_snapshot
		FOR EACH ROW EXECUTE FUNCTION %s()`, functionName, tenantID, triggerName, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().ExecContext(context.Background(), fmt.Sprintf(
			`DROP TRIGGER IF EXISTS %s ON devradar_repository_posture_snapshot; DROP FUNCTION IF EXISTS %s()`,
			triggerName, functionName))
	})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- st.SnapshotTenantPosture(ctx)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent posture snapshot: %v", err)
		}
	}
}

func TestSnapshotTenantPosture_UsesOneSourceSnapshotAcrossProjections(t *testing.T) {
	// SnapshotTenantPosture rewrites every active tenant's snapshot for today
	// (a global DELETE + INSERT). A private schema keeps a concurrent package
	// test's snapshot on the shared DB from racing this test's projection reads
	// under `go test -race ./...`.
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	repository := "registry.test/interleaved-" + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=$1`, sb.ID, repository); err != nil {
		t.Fatal(err)
	}
	sb.Repository = repository

	lockKey, err := strconv.ParseInt(randID(t)[:15], 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	suffix := randID(t)
	functionName := "block_repository_snapshot_" + suffix
	triggerName := "block_repository_snapshot_" + suffix
	if _, err := st.DB().ExecContext(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid THEN
				PERFORM pg_advisory_xact_lock(%d);
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s AFTER INSERT ON devradar_repository_posture_snapshot
		FOR EACH ROW EXECUTE FUNCTION %s()`, functionName, tenantID, lockKey, triggerName, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().ExecContext(context.Background(), fmt.Sprintf(
			`DROP TRIGGER IF EXISTS %s ON devradar_repository_posture_snapshot; DROP FUNCTION IF EXISTS %s()`,
			triggerName, functionName))
	})

	blocker, err := st.DB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Close() })
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
	})
	var blockerPID int
	if err := blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}

	snapshotErr := make(chan error, 1)
	go func() { snapshotErr <- st.SnapshotTenantPosture(ctx) }()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		var snapshotBlocked bool
		if err := st.DB().QueryRowContext(waitCtx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE $1 = ANY(pg_blocking_pids(pid))
			)`, blockerPID).Scan(&snapshotBlocked); err != nil {
			t.Fatal(err)
		}
		if snapshotBlocked {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatal(waitCtx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	if err := st.ArchiveSBOM(ctx, tenantID, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}
	if err := <-snapshotErr; err != nil {
		t.Fatal(err)
	}

	repositoryTrend, err := st.RepositoryPostureTrend(ctx, tenantID, repository, 1)
	if err != nil {
		t.Fatal(err)
	}
	fleetTrend, err := st.TenantPostureTrend(ctx, tenantID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(repositoryTrend) != 1 || len(fleetTrend) != 1 {
		t.Fatalf("repository trend=%+v fleet trend=%+v", repositoryTrend, fleetTrend)
	}
	if repositoryTrend[0].Images != fleetTrend[0].Images || repositoryTrend[0].Total != fleetTrend[0].Total {
		t.Fatalf("repository/fleet snapshots diverged across interleaved archive: repository=%+v fleet=%+v",
			repositoryTrend[0], fleetTrend[0])
	}
}
