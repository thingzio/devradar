package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	alertengine "github.com/thingzio/devradar/pkg/alert"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAlertMigration_DefaultsAndConstraints(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	var policyID, gotTenantID, minSeverity string
	var enabled, alertKEV, alertFixAvailable, includeImage, includeDB bool
	var labels []string
	var createdAt, updatedAt time.Time
	err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id) VALUES ($1)
		RETURNING id, tenant_id, enabled, min_severity, alert_kev,
		          alert_fix_available, include_image, include_db, labels,
		          created_at, updated_at`, tenantID).Scan(
		&policyID, &gotTenantID, &enabled, &minSeverity, &alertKEV,
		&alertFixAvailable, &includeImage, &includeDB, pq.Array(&labels),
		&createdAt, &updatedAt)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	if gotTenantID != tenantID || enabled || minSeverity != data.SeverityMedium || !alertKEV ||
		!alertFixAvailable || !includeImage || !includeDB || len(labels) != 0 ||
		createdAt.IsZero() || updatedAt.IsZero() {
		t.Fatal("unexpected policy defaults")
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_alert_policy (tenant_id) VALUES ($1)`, tenantID); err == nil {
		t.Fatal("second tenant policy should violate uniqueness")
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_alert
		(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
		 repository, digest, finding_id, exposure, package, version, severity, score, cause)
		VALUES ($1,$2,1,now(),'new_finding',$3,'registry.test/app','sha256:x',
		        'finding','CVE-1','pkg','1','high',7.5,'tooling')`,
		tenantID, policyID, sb.ID); err == nil {
		t.Fatal("tooling-caused alert should violate cause check")
	}
}

func TestAlertTenantStore_IsolationPaginationAndReadState(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenant1, sb1 := seedTenantAndSBOM(t, st)
	tenant2, sb2 := seedTenantAndSBOM(t, st)
	p1, err := st.EnsureAlertPolicy(ctx, tenant1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := st.EnsureAlertPolicy(ctx, tenant2)
	if err != nil {
		t.Fatal(err)
	}

	p1.Enabled = true
	p1.MinSeverity = data.SeverityHigh
	p1.IncludeDB = false
	p1.Labels = []string{"prod"}
	if err := st.UpdateAlertPolicy(ctx, tenant1, *p1); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	gotPolicy, err := st.EnsureAlertPolicy(ctx, tenant1)
	if err != nil {
		t.Fatal(err)
	}
	if !gotPolicy.Enabled || gotPolicy.MinSeverity != data.SeverityHigh || gotPolicy.IncludeDB ||
		len(gotPolicy.Labels) != 1 || gotPolicy.Labels[0] != "prod" {
		t.Fatalf("updated policy = %+v", gotPolicy)
	}
	unchangedP2, err := st.EnsureAlertPolicy(ctx, tenant2)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedP2.Enabled || unchangedP2.ID != p2.ID {
		t.Fatalf("tenant 2 policy changed: %+v", unchangedP2)
	}

	base := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	ids := []string{
		seedAlertRow(t, st, tenant1, p1.ID, sb1, 101, base, "CVE-2026-0101"),
		seedAlertRow(t, st, tenant1, p1.ID, sb1, 102, base.Add(time.Minute), "CVE-2026-0102"),
		seedAlertRow(t, st, tenant1, p1.ID, sb1, 103, base.Add(2*time.Minute), "CVE-2026-0103"),
	}
	otherID := seedAlertRow(t, st, tenant2, p2.ID, sb2, 201, base.Add(3*time.Minute), "CVE-2026-0201")

	page1, next, err := st.ListAlerts(ctx, tenant1, "", 2)
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(page1) != 2 || next == "" || page1[0].Exposure != "CVE-2026-0103" || page1[1].Exposure != "CVE-2026-0102" {
		t.Fatalf("page 1 = %+v next=%q", page1, next)
	}
	page2, next2, err := st.ListAlerts(ctx, tenant1, next, 2)
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page2) != 1 || next2 != "" || page2[0].Exposure != "CVE-2026-0101" {
		t.Fatalf("page 2 = %+v next=%q", page2, next2)
	}

	if _, err := st.GetAlert(ctx, tenant1, otherID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-tenant GetAlert error = %v, want ErrNotFound", err)
	}
	if err := st.MarkAlertRead(ctx, tenant1, otherID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-tenant MarkAlertRead error = %v, want ErrNotFound", err)
	}
	if err := st.MarkAlertRead(ctx, tenant1, ids[2]); err != nil {
		t.Fatalf("mark read: %v", err)
	}
	if err := st.MarkAlertRead(ctx, tenant1, ids[2]); err != nil {
		t.Fatalf("retry mark read: %v", err)
	}
	unread, err := st.UnreadAlerts(ctx, tenant1, 10)
	if err != nil {
		t.Fatalf("unread alerts: %v", err)
	}
	if len(unread) != 2 {
		t.Fatalf("unread alerts = %d, want 2", len(unread))
	}
	got, err := st.GetAlert(ctx, tenant1, ids[2])
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.ReadAt == nil || got.Exposure != "CVE-2026-0103" {
		t.Fatalf("alert after read = %+v", got)
	}
}

func TestAlertTenantStore_RejectsInvalidSeverity(t *testing.T) {
	st := testStore(t)
	tenantID, _ := seedTenantAndSBOM(t, st)
	p, err := st.EnsureAlertPolicy(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	p.MinSeverity = "mystery"
	if err := st.UpdateAlertPolicy(context.Background(), tenantID, *p); err == nil {
		t.Fatal("invalid severity should fail")
	}
}

func seedAlertRow(t *testing.T, st *postgres.Store, tenantID, policyID string, sb *postgres.SBOM, eventID int64, created time.Time, cve string) string {
	t.Helper()
	var id string
	err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_alert
		(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
		 repository, digest, finding_id, exposure, package, version, severity, score, cause, created_at)
		VALUES ($1,$2,$3,$4,'new_finding',$5,$6,$7,$8,$9,'pkg','1.0','high',8.0,'db',$4)
		RETURNING id`, tenantID, policyID, eventID, created, sb.ID, sb.Repository, sb.Digest,
		fmt.Sprintf("finding-%d", eventID), cve).Scan(&id)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

func TestAlertMigration_DefaultConsumerCursorExists(t *testing.T) {
	st := testStore(t)
	var position postgres.AlertPosition
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT last_occurred_at, last_event_id
		FROM devradar_alert_cursor
		WHERE consumer='browser-alerts-v1'`).Scan(&position.OccurredAt, &position.EventID); err != nil {
		t.Fatalf("default alert cursor: %v", err)
	}
	if position.OccurredAt.IsZero() {
		t.Fatal("default alert cursor has zero timestamp")
	}
}

func TestAlertEvaluatorStore_ProspectiveAndIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	consumer := "test-" + randID(t)

	policy, err := st.EnsureAlertPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("ensure policy: %v", err)
	}
	if policy.Enabled {
		t.Fatal("new policy should be disabled")
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_alert_policy SET enabled=true WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatalf("enable policy: %v", err)
	}

	v1 := postgres.Versions{DBVersion: "alert-db-1", ScannerVersion: "grype-test", CanonicalizerVersion: "test"}
	first := vuln("CVE-2026-1001", "openssl", "1.0.0", data.SeverityHigh, 8.1, false)
	if err := st.ApplyScan(ctx, sb, "grype", v1, []data.Vulnerability{first}); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	candidates, initializedAt, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("initialize cursor: %v", err)
	}
	if !initialized || len(candidates) != 0 || initializedAt.EventID == 0 {
		t.Fatalf("initialization = candidates:%d position:%+v initialized:%v", len(candidates), initializedAt, initialized)
	}

	v2 := postgres.Versions{DBVersion: "alert-db-2", ScannerVersion: "grype-test", CanonicalizerVersion: "test"}
	second := vuln("CVE-2026-1002", "zlib", "2.0.0", data.SeverityCritical, 9.8, false)
	if err := st.ApplyScan(ctx, sb, "grype", v2, []data.Vulnerability{first, second}); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	candidates, end, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("next events: %v", err)
	}
	if initialized || len(candidates) != 1 {
		t.Fatalf("next = candidates:%d initialized:%v, want 1/false", len(candidates), initialized)
	}
	if candidates[0].Event.Exposure != second.Exposure || !candidates[0].Policy.Enabled {
		t.Fatalf("candidate = %+v", candidates[0])
	}
	drafts, err := alertengine.Match(candidates[0].Policy, candidates[0].Event)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(drafts) != 1 {
		t.Fatalf("drafts = %d, want 1", len(drafts))
	}
	if err := st.CommitAlertBatch(ctx, consumer, drafts, nil, end); err != nil {
		t.Fatalf("commit batch: %v", err)
	}
	if err := st.CommitAlertBatch(ctx, consumer, drafts, nil, end); err != nil {
		t.Fatalf("retry batch: %v", err)
	}

	var alertCount int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_alert WHERE tenant_id=$1`, tenantID).Scan(&alertCount); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alertCount != 1 {
		t.Fatalf("alerts = %d, want 1", alertCount)
	}

	if err := st.CommitAlertBatch(ctx, consumer, nil, nil, initializedAt); err != nil {
		t.Fatalf("older cursor commit: %v", err)
	}
	var cursor postgres.AlertPosition
	if err := st.DB().QueryRowContext(ctx, `
		SELECT last_occurred_at, last_event_id FROM devradar_alert_cursor WHERE consumer=$1`, consumer).
		Scan(&cursor.OccurredAt, &cursor.EventID); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	if cursor != end {
		t.Fatalf("cursor moved backward: got %+v, want %+v", cursor, end)
	}

	candidates, _, initialized, err = st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("events after commit: %v", err)
	}
	if initialized || len(candidates) != 0 {
		t.Fatalf("events after commit = %d initialized=%v", len(candidates), initialized)
	}
}

func TestAlertEvaluatorStore_PostureRegressionIsIdempotentPerSBOM(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	var duplicateGroups int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM (
			SELECT tenant_id, policy_id, sbom_id, alert_kind
			FROM devradar_alert
			WHERE alert_kind='posture_regression'
			GROUP BY tenant_id, policy_id, sbom_id, alert_kind
			HAVING COUNT(*) > 1
		) duplicates`).Scan(&duplicateGroups); err != nil {
		t.Fatalf("count duplicate posture regression groups: %v", err)
	}
	if duplicateGroups != 0 {
		t.Fatalf("duplicate posture regression groups = %d, want 0", duplicateGroups)
	}
	tenantID, sb := seedTenantAndSBOM(t, st)
	policy, err := st.EnsureAlertPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("ensure policy: %v", err)
	}
	base := time.Now().UTC()
	drafts := []postgres.AlertDraft{
		{PolicyID: policy.ID, Kind: alertengine.KindPostureRegression, Event: postgres.AlertEvent{
			ID: 501, OccurredAt: base, TenantID: tenantID, SBOMID: sb.ID,
			Repository: sb.Repository, Digest: sb.Digest, FindingID: "finding-501",
			Exposure: "CVE-2026-9501", Package: "pkg", Version: "1", Severity: data.SeverityHigh,
			Cause: data.CauseImage, Score: 8,
		}},
		{PolicyID: policy.ID, Kind: alertengine.KindPostureRegression, Event: postgres.AlertEvent{
			ID: 502, OccurredAt: base.Add(time.Second), TenantID: tenantID, SBOMID: sb.ID,
			Repository: sb.Repository, Digest: sb.Digest, FindingID: "finding-502",
			Exposure: "CVE-2026-9502", Package: "pkg", Version: "1", Severity: data.SeverityCritical,
			Cause: data.CauseImage, Score: 9,
		}},
	}
	if err := st.CommitAlertBatch(ctx, "posture-test", drafts, nil, postgres.AlertPosition{}); err != nil {
		t.Fatalf("commit posture regression drafts: %v", err)
	}
	if err := st.CommitAlertBatch(ctx, "posture-test", drafts, nil, postgres.AlertPosition{}); err != nil {
		t.Fatalf("retry posture regression drafts: %v", err)
	}
	var count int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM devradar_alert
		WHERE tenant_id=$1 AND policy_id=$2 AND sbom_id=$3 AND alert_kind='posture_regression'`,
		tenantID, policy.ID, sb.ID).Scan(&count); err != nil {
		t.Fatalf("count posture regression alerts: %v", err)
	}
	if count != 1 {
		t.Fatalf("posture regression alerts = %d, want 1", count)
	}
}
