package postgres_test

import (
	"context"
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
