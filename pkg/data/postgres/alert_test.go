package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	alertengine "github.com/thingzio/devradar/pkg/alert"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/tenant"
)

func TestAlertEvaluatorStore_ReverseCommitDoesNotLoseEarlierEvent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	consumer := "reverse-commit-" + randID(t)

	if _, err := st.EnsureAlertPolicy(ctx, tenantID); err != nil {
		t.Fatalf("ensure policy: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_alert_policy SET enabled=true WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatalf("enable policy: %v", err)
	}

	_, initializedAt, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("initialize consumer: %v", err)
	}
	if !initialized {
		t.Fatal("new consumer was not initialized prospectively")
	}

	var queueExists bool
	if err := st.DB().QueryRowContext(ctx,
		`SELECT to_regclass('devradar_alert_event_queue') IS NOT NULL`).Scan(&queueExists); err != nil {
		t.Fatalf("check queue migration: %v", err)
	}

	insert := func(tx *sql.Tx, occurredAt time.Time, exposure string) postgres.AlertPosition {
		t.Helper()
		var id int64
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO devradar_finding_event
				(tenant_id, sbom_id, scanner, finding_id, event_type, exposure,
				 package, version, severity, score, cause, db_version,
				 scanner_version, scan_run_id, occurred_at)
			VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1','high',8.0,'db',
			        'db','scanner',gen_random_uuid(),$5)
			RETURNING id`, tenantID, sb.ID, "finding-"+exposure, exposure, occurredAt).Scan(&id); err != nil {
			t.Fatalf("insert source event: %v", err)
		}
		if queueExists {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO devradar_alert_event_queue
					(consumer, tenant_id, event_occurred_at, event_id)
				VALUES ($1,$2,$3,$4)`, consumer, tenantID, occurredAt, id); err != nil {
				t.Fatalf("insert queued event: %v", err)
			}
		}
		return postgres.AlertPosition{OccurredAt: occurredAt, EventID: id}
	}

	txA, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin transaction A: %v", err)
	}
	t.Cleanup(func() { _ = txA.Rollback() })
	earlier := insert(txA, initializedAt.OccurredAt.Add(time.Minute), "CVE-2026-7001")

	txB, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin transaction B: %v", err)
	}
	later := insert(txB, initializedAt.OccurredAt.Add(2*time.Minute), "CVE-2026-7002")
	if err := txB.Commit(); err != nil {
		t.Fatalf("commit transaction B: %v", err)
	}

	result, err := (alertengine.Evaluator{Store: st, Consumer: consumer, BatchSize: 100}).Evaluate(ctx)
	if err != nil {
		t.Fatalf("evaluate later committed event: %v", err)
	}
	if result.Examined != 1 || result.Matched != 1 || result.Failures != 0 {
		t.Fatalf("later evaluation = %+v, want one examined/matched event", result)
	}
	if queueExists {
		var processedAt sql.NullTime
		if err := st.DB().QueryRowContext(ctx, `
			SELECT processed_at FROM devradar_alert_event_queue
			WHERE consumer=$1 AND event_occurred_at=$2 AND event_id=$3`,
			consumer, later.OccurredAt, later.EventID).Scan(&processedAt); err != nil {
			t.Fatalf("read later queue state: %v", err)
		}
		if !processedAt.Valid {
			t.Fatal("later queue row was not marked processed")
		}
	}

	if err := txA.Commit(); err != nil {
		t.Fatalf("commit transaction A: %v", err)
	}
	candidates, _, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("read earlier event after commit: %v", err)
	}
	if initialized || len(candidates) != 1 || candidates[0].Event.ID != earlier.EventID {
		t.Fatalf("second visible batch = %+v initialized=%v, want earlier event %d", candidates, initialized, earlier.EventID)
	}
}

func TestAlertEvaluatorStore_NewCursorDoesNotSkipQueuedProspectiveEvent(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	if _, err := st.EnsureAlertPolicy(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_alert_policy SET enabled=true WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyScan(ctx, sb, "grype", postgres.Versions{
		DBVersion: "cursor-db", ScannerVersion: "cursor-scanner", CanonicalizerVersion: "cursor-canon",
	}, []data.Vulnerability{vuln("CVE-2026-7003", "pkg", "1", data.SeverityHigh, 8, false)}); err != nil {
		t.Fatal(err)
	}
	consumer := "cursor-observability-" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_alert_event_queue SET consumer=$1
		WHERE consumer=$2`, consumer, alertengine.DefaultConsumer); err != nil {
		t.Fatal(err)
	}

	candidates, _, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatal(err)
	}
	if initialized || len(candidates) != 1 || candidates[0].Event.Exposure != "CVE-2026-7003" {
		t.Fatalf("first queued read = candidates:%+v initialized:%v, want prospective event", candidates, initialized)
	}
}

func TestAlertEventQueue_TenantDeletionCascadesPendingRows(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	if err := st.ApplyScan(ctx, sb, "grype", postgres.Versions{
		DBVersion: "delete-db", ScannerVersion: "delete-scanner", CanonicalizerVersion: "delete-canon",
	}, []data.Vulnerability{vuln("CVE-2026-7004", "pkg", "1", data.SeverityHigh, 8, false)}); err != nil {
		t.Fatal(err)
	}
	before, err := st.AdminProductHealth(ctx)
	if err != nil || before.EvaluatorBacklog != 1 {
		t.Fatalf("backlog before tenant deletion = %+v error=%v", before, err)
	}

	if err := tenant.DeleteTenant(ctx, st.DB(), tenantID); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_alert_event_queue
		WHERE consumer=$1 AND processed_at IS NULL`, alertengine.DefaultConsumer).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	after, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 || after.EvaluatorBacklog != 0 || !after.OldestPendingAt.IsZero() {
		t.Fatalf("queue after tenant deletion = pending:%d health:%+v", pending, after)
	}
}

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

func TestAlertEventQueueMigration_IsProspectiveAndIndexed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	var eventID int64
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_finding_event
			(tenant_id, sbom_id, scanner, finding_id, event_type, exposure,
			 package, version, severity, score, cause, db_version,
			 scanner_version, scan_run_id, occurred_at)
		VALUES ($1,$2,'grype','historical','added','CVE-2026-7999','pkg','1',
		        'high',8.0,'db','db','scanner',gen_random_uuid(),now())
		RETURNING id`, tenantID, sb.ID).Scan(&eventID); err != nil {
		t.Fatalf("seed source-only event: %v", err)
	}
	var queued int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_alert_event_queue WHERE event_id=$1`, eventID).Scan(&queued); err != nil {
		t.Fatalf("count source-only queue rows: %v", err)
	}
	if queued != 0 {
		t.Fatalf("source-only historical event was backfilled into queue: %d rows", queued)
	}

	wantIndexes := []string{
		"idx_devradar_alert_event_queue_pending",
		"idx_devradar_alert_event_queue_tenant",
		"idx_devradar_fe_actionable_position",
		"idx_devradar_alert_created_at",
		"idx_devradar_alert_failure_occurred_at",
	}
	for _, name := range wantIndexes {
		var exists bool
		if err := st.DB().QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_indexes
				WHERE schemaname=current_schema() AND indexname=$1)`, name).Scan(&exists); err != nil {
			t.Fatalf("check index %s: %v", name, err)
		}
		if !exists {
			t.Errorf("index %s does not exist", name)
		}
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
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_alert_event_queue (consumer, tenant_id, event_occurred_at, event_id)
		SELECT $1, tenant_id, occurred_at, id
		FROM devradar_finding_event
		WHERE sbom_id=$2 AND event_type='added' AND exposure=$3`,
		consumer, sb.ID, second.Exposure); err != nil {
		t.Fatalf("enqueue custom consumer event: %v", err)
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
	processed := alertCandidatePositions(candidates)
	if err := st.CommitAlertBatch(ctx, consumer, drafts, nil, processed, end); err != nil {
		t.Fatalf("commit batch: %v", err)
	}
	if err := st.CommitAlertBatch(ctx, consumer, drafts, nil, processed, end); err != nil {
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

	if err := st.CommitAlertBatch(ctx, consumer, nil, nil, nil, initializedAt); err != nil {
		t.Fatalf("older cursor commit: %v", err)
	}
	var cursor postgres.AlertPosition
	if err := st.DB().QueryRowContext(ctx, `
		SELECT last_occurred_at, last_event_id FROM devradar_alert_cursor WHERE consumer=$1`, consumer).
		Scan(&cursor.OccurredAt, &cursor.EventID); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	wantCursor := maxAlertPosition(initializedAt, end)
	if cursor != wantCursor {
		t.Fatalf("cursor high-water = %+v, want %+v", cursor, wantCursor)
	}

	candidates, _, initialized, err = st.NextAlertEvents(ctx, consumer, 100)
	if err != nil {
		t.Fatalf("events after commit: %v", err)
	}
	if initialized || len(candidates) != 0 {
		t.Fatalf("events after commit = %d initialized=%v", len(candidates), initialized)
	}
}

func TestAlertEvaluatorStore_StalePolicyDraftIsSkippedAndProcessed(t *testing.T) {
	tests := []struct {
		name   string
		mutate string
	}{
		{name: "disabled at same version", mutate: `UPDATE devradar_alert_policy SET enabled=false WHERE tenant_id=$1`},
		{name: "updated while enabled", mutate: `UPDATE devradar_alert_policy SET min_severity='critical', updated_at=updated_at + interval '1 second' WHERE tenant_id=$1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			tenantID, sb := seedTenantAndSBOM(t, st)
			consumer := "stale-policy-" + randID(t)

			if _, err := st.EnsureAlertPolicy(ctx, tenantID); err != nil {
				t.Fatalf("ensure policy: %v", err)
			}
			if _, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_alert_policy SET enabled=true WHERE tenant_id=$1`, tenantID); err != nil {
				t.Fatalf("enable policy: %v", err)
			}
			policy, err := st.EnsureAlertPolicy(ctx, tenantID)
			if err != nil {
				t.Fatalf("read enabled policy: %v", err)
			}
			if _, _, initialized, err := st.NextAlertEvents(ctx, consumer, 100); err != nil {
				t.Fatalf("initialize consumer: %v", err)
			} else if !initialized {
				t.Fatal("new consumer was not initialized prospectively")
			}

			occurredAt := policy.UpdatedAt.Add(time.Second)
			var eventID int64
			if err := st.DB().QueryRowContext(ctx, `
				INSERT INTO devradar_finding_event
					(tenant_id, sbom_id, scanner, finding_id, event_type, exposure,
					 package, version, severity, score, cause, db_version,
					 scanner_version, scan_run_id, occurred_at)
				VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1','high',8.0,'db',
				        'db','scanner',gen_random_uuid(),$5)
				RETURNING id`, tenantID, sb.ID, "finding-"+randID(t), "CVE-2026-"+randID(t)[:4], occurredAt).Scan(&eventID); err != nil {
				t.Fatalf("insert source event: %v", err)
			}
			if _, err := st.DB().ExecContext(ctx, `
				INSERT INTO devradar_alert_event_queue (consumer, tenant_id, event_occurred_at, event_id)
				VALUES ($1,$2,$3,$4)`, consumer, tenantID, occurredAt, eventID); err != nil {
				t.Fatalf("enqueue event: %v", err)
			}

			candidates, end, initialized, err := st.NextAlertEvents(ctx, consumer, 100)
			if err != nil {
				t.Fatalf("read candidate: %v", err)
			}
			if initialized || len(candidates) != 1 {
				t.Fatalf("candidates=%d initialized=%v, want 1/false", len(candidates), initialized)
			}
			drafts, err := alertengine.Match(candidates[0].Policy, candidates[0].Event)
			if err != nil {
				t.Fatalf("match candidate: %v", err)
			}
			if len(drafts) != 1 || drafts[0].PolicyUpdatedAt.IsZero() {
				t.Fatalf("drafts = %+v, want one versioned draft", drafts)
			}

			if _, err := st.DB().ExecContext(ctx, tt.mutate, tenantID); err != nil {
				t.Fatalf("mutate policy: %v", err)
			}
			processed := alertCandidatePositions(candidates)
			if err := st.CommitAlertBatch(ctx, consumer, drafts, nil, processed, end); err != nil {
				t.Fatalf("commit stale draft: %v", err)
			}

			var alertCount int
			if err := st.DB().QueryRowContext(ctx, `
				SELECT COUNT(*) FROM devradar_alert
				WHERE tenant_id=$1 AND event_id=$2 AND event_occurred_at=$3`,
				tenantID, eventID, occurredAt).Scan(&alertCount); err != nil {
				t.Fatalf("count stale alerts: %v", err)
			}
			if alertCount != 0 {
				t.Fatalf("stale alerts = %d, want 0", alertCount)
			}
			var processedAt sql.NullTime
			if err := st.DB().QueryRowContext(ctx, `
				SELECT processed_at FROM devradar_alert_event_queue
				WHERE consumer=$1 AND event_occurred_at=$2 AND event_id=$3`,
				consumer, occurredAt, eventID).Scan(&processedAt); err != nil {
				t.Fatalf("read queue state: %v", err)
			}
			if !processedAt.Valid {
				t.Fatal("stale draft queue row was not processed")
			}
		})
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
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_alert_policy SET enabled=true WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatalf("enable policy: %v", err)
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
	if err := st.CommitAlertBatch(ctx, "posture-test", drafts, nil, nil, postgres.AlertPosition{}); err != nil {
		t.Fatalf("commit posture regression drafts: %v", err)
	}
	if err := st.CommitAlertBatch(ctx, "posture-test", drafts, nil, nil, postgres.AlertPosition{}); err != nil {
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

func alertCandidatePositions(candidates []postgres.AlertCandidate) []postgres.AlertPosition {
	positions := make([]postgres.AlertPosition, len(candidates))
	for i, candidate := range candidates {
		positions[i] = postgres.AlertPosition{
			OccurredAt: candidate.Event.OccurredAt,
			EventID:    candidate.Event.ID,
		}
	}
	return positions
}

func maxAlertPosition(a, b postgres.AlertPosition) postgres.AlertPosition {
	if a.OccurredAt.After(b.OccurredAt) || (a.OccurredAt.Equal(b.OccurredAt) && a.EventID > b.EventID) {
		return a
	}
	return b
}
