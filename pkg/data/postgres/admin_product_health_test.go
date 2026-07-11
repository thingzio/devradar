package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAdminProductHealth(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	db := st.DB()

	baseline, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatalf("baseline product health: %v", err)
	}

	typ := reflect.TypeOf(postgres.AdminProductHealth{})
	for _, forbidden := range []string{"TenantID", "Email"} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("AdminProductHealth must not expose %s", forbidden)
		}
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type.Kind() != reflect.Int && field.Type != reflect.TypeFor[time.Time]() {
			t.Fatalf("AdminProductHealth.%s has non-aggregate type %s", field.Name, field.Type)
		}
	}

	const consumer = "browser-alerts-v1"
	var previousCursorAt time.Time
	var previousCursorID int64
	previousCursorExists := true
	if err := db.QueryRowContext(ctx, `
		SELECT last_occurred_at, last_event_id
		FROM devradar_alert_cursor
		WHERE consumer=$1`, consumer).Scan(&previousCursorAt, &previousCursorID); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("read previous alert cursor: %v", err)
		}
		previousCursorExists = false
	}

	var tenantIDs []string
	var eventIDs []int64
	var failureIDs []int64
	var enrichmentCVEs []string
	t.Cleanup(func() {
		for _, id := range failureIDs {
			_, _ = db.ExecContext(ctx, `DELETE FROM devradar_alert_failure WHERE id=$1`, id)
		}
		for _, id := range eventIDs {
			_, _ = db.ExecContext(ctx, `DELETE FROM devradar_finding_event WHERE id=$1`, id)
		}
		for _, id := range tenantIDs {
			_, _ = db.ExecContext(ctx, `DELETE FROM devradar_tenant WHERE id=$1`, id)
		}
		for _, cve := range enrichmentCVEs {
			_, _ = db.ExecContext(ctx, `DELETE FROM devradar_cve_enrichment WHERE cve=$1`, cve)
		}
		if previousCursorExists {
			_, _ = db.ExecContext(ctx, `
				INSERT INTO devradar_alert_cursor
					(consumer, last_occurred_at, last_event_id, updated_at)
				VALUES ($1,$2,$3,now())
				ON CONFLICT (consumer) DO UPDATE SET
					last_occurred_at=EXCLUDED.last_occurred_at,
					last_event_id=EXCLUDED.last_event_id,
					updated_at=now()`, consumer, previousCursorAt, previousCursorID)
		} else {
			_, _ = db.ExecContext(ctx, `DELETE FROM devradar_alert_cursor WHERE consumer=$1`, consumer)
		}
	})

	tenantA, sbomA := seedTenantAndSBOM(t, st)
	tenantB, sbomB := seedTenantAndSBOM(t, st)
	foreignTenant, foreignSBOM := seedTenantAndSBOM(t, st)
	tenantIDs = append(tenantIDs, tenantA, tenantB, foreignTenant)

	repositoryA := "registry.test/product-health-ready-" + randID(t)[:8]
	repositoryB := "registry.test/product-health-single-" + randID(t)[:8]
	foreignRepository := "registry.test/product-health-foreign-" + randID(t)[:8]
	for _, update := range []struct {
		id, repository, status string
	}{
		{sbomA.ID, repositoryA, "active"},
		{sbomB.ID, repositoryB, "active"},
		{foreignSBOM.ID, foreignRepository, "archived"},
	} {
		if _, err := db.ExecContext(ctx,
			`UPDATE devradar_sbom SET repository=$2, status=$3 WHERE id=$1`,
			update.id, update.repository, update.status); err != nil {
			t.Fatalf("update seeded SBOM: %v", err)
		}
	}
	sbomA.Repository = repositoryA
	sbomB.Repository = repositoryB
	foreignSBOM.Repository = foreignRepository
	foreignSBOM.Status = "archived"

	secondA := *sbomA
	secondA.ID = randID(t) + randID(t)
	secondA.Digest = "sha256:" + randID(t) + randID(t)
	secondA.ImageRef = repositoryA + ":v2"
	secondA.ObjectPath += "/v2"
	if _, _, _, err := st.UpsertSBOM(ctx, &secondA); err != nil {
		t.Fatalf("seed comparison-ready generation: %v", err)
	}

	duplicateB := *sbomB
	duplicateB.ID = randID(t) + randID(t)
	duplicateB.Format = "spdx"
	duplicateB.ObjectPath += "/spdx"
	if _, _, _, err := st.UpsertSBOM(ctx, &duplicateB); err != nil {
		t.Fatalf("seed duplicate-digest generation: %v", err)
	}

	foreignSecond := *foreignSBOM
	foreignSecond.ID = randID(t) + randID(t)
	foreignSecond.Digest = "sha256:" + randID(t) + randID(t)
	foreignSecond.Format = "spdx"
	foreignSecond.ObjectPath += "/archived"
	if _, _, _, err := st.UpsertSBOM(ctx, &foreignSecond); err != nil {
		t.Fatalf("seed archived foreign generation: %v", err)
	}

	canonicalCVE := "CVE-2099-" + randID(t)[:8]
	suppressedCVE := "CVE-2098-" + randID(t)[:8]
	foreignCVE := "CVE-2097-" + randID(t)[:8]
	enrichmentCVEs = append(enrichmentCVEs, canonicalCVE, suppressedCVE, foreignCVE)
	for _, finding := range []struct {
		sbomID, scanner, findingID, exposure string
		fixed                                bool
	}{
		{sbomA.ID, "grype", "canonical", canonicalCVE, false},
		{sbomA.ID, "trivy", "canonical", canonicalCVE, true},
		{sbomA.ID, "grype", "suppressed", suppressedCVE, true},
		{foreignSBOM.ID, "grype", "foreign", foreignCVE, true},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO devradar_finding
				(sbom_id, scanner, finding_id, exposure, package, version,
				 severity, score, is_fixed)
			VALUES ($1,$2,$3,$4,'pkg','1','high',8.0,$5)`,
			finding.sbomID, finding.scanner, finding.findingID,
			finding.exposure, finding.fixed); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, kev)
		VALUES ($1,true),($2,true),($3,true)
		ON CONFLICT (cve) DO UPDATE SET kev=EXCLUDED.kev`,
		canonicalCVE, suppressedCVE, foreignCVE); err != nil {
		t.Fatalf("seed KEV enrichment: %v", err)
	}
	var vexDocumentID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO devradar_vex_document (tenant_id, document)
		VALUES ($1,'{}'::jsonb)
		RETURNING id`, tenantA).Scan(&vexDocumentID); err != nil {
		t.Fatalf("seed VEX document: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_vex_statement
			(tenant_id, document_id, product_digest, vulnerability, status)
		VALUES ($1,$2,$3,$4,'not_affected')`,
		tenantA, vexDocumentID, sbomA.Digest, suppressedCVE); err != nil {
		t.Fatalf("seed VEX suppression: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings)
		VALUES
			($1,(now() AT TIME ZONE 'UTC')::date,1,1),
			($2,(now() AT TIME ZONE 'UTC')::date,1,99)`,
		tenantA, foreignTenant); err != nil {
		t.Fatalf("seed posture snapshots: %v", err)
	}

	var policyA, policyB string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id, enabled)
		VALUES ($1,true) RETURNING id`, tenantA).Scan(&policyA); err != nil {
		t.Fatalf("seed enabled alert policy: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id, enabled)
		VALUES ($1,false) RETURNING id`, tenantB).Scan(&policyB); err != nil {
		t.Fatalf("seed disabled alert policy: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_license_policy
			(tenant_id, denied_categories, allow_exceptions, deny_exceptions)
		VALUES
			($1,ARRAY['strong-copyleft'],ARRAY[]::text[],ARRAY[]::text[]),
			($2,ARRAY[]::text[],ARRAY[]::text[],ARRAY['LicenseRef-denied']),
			($3,ARRAY[]::text[],ARRAY['MIT'],ARRAY[]::text[])`,
		tenantA, tenantB, foreignTenant); err != nil {
		t.Fatalf("seed license policies: %v", err)
	}

	cursorAt := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	insertEvent := func(cause string, at time.Time) int64 {
		t.Helper()
		var id int64
		if err := db.QueryRowContext(ctx, `
			INSERT INTO devradar_finding_event
				(tenant_id, sbom_id, scanner, finding_id, event_type, exposure,
				 package, version, severity, score, cause, db_version,
				 scanner_version, scan_run_id, occurred_at)
			VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1','high',8.0,$5,
			        'db','scanner',gen_random_uuid(),$6)
			RETURNING id`, tenantA, sbomA.ID, randID(t), canonicalCVE, cause, at).Scan(&id); err != nil {
			t.Fatalf("seed finding event: %v", err)
		}
		eventIDs = append(eventIDs, id)
		return id
	}
	cursorEventID := insertEvent("image", cursorAt)
	pendingAtCursorID := insertEvent("db", cursorAt)
	pendingLaterAt := cursorAt.Add(time.Minute)
	pendingLaterID := insertEvent("image", pendingLaterAt)
	_ = insertEvent("tooling", cursorAt.Add(2*time.Minute))
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_alert_cursor
			(consumer, last_occurred_at, last_event_id, updated_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (consumer) DO UPDATE SET
			last_occurred_at=EXCLUDED.last_occurred_at,
			last_event_id=EXCLUDED.last_event_id,
			updated_at=now()`, consumer, cursorAt, cursorEventID); err != nil {
		t.Fatalf("set alert cursor: %v", err)
	}

	for i, alert := range []struct {
		eventID int64
		at      time.Time
		read    bool
	}{
		{pendingAtCursorID, cursorAt, false},
		{pendingLaterID, pendingLaterAt, true},
	} {
		readAt := any(nil)
		if alert.read {
			readAt = time.Now().UTC()
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO devradar_alert
				(tenant_id, policy_id, event_id, event_occurred_at, alert_kind,
				 sbom_id, repository, digest, finding_id, exposure, package,
				 version, severity, score, cause, read_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pkg','1','high',8.0,
			        'image',$11,now())`,
			tenantA, policyA, alert.eventID, alert.at,
			[]string{"new_finding", "fix_available"}[i], sbomA.ID,
			repositoryA, sbomA.Digest, fmt.Sprintf("alert-%d", i), canonicalCVE,
			readAt); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}

	for _, failure := range []struct {
		eventID int64
		at      time.Time
	}{
		{pendingAtCursorID, time.Now().UTC()},
		{pendingLaterID, time.Now().UTC().Add(-25 * time.Hour)},
	} {
		var id int64
		if err := db.QueryRowContext(ctx, `
			INSERT INTO devradar_alert_failure
				(consumer, event_id, event_occurred_at, error, occurred_at)
			VALUES ($1,$2,$3,'test failure',$4)
			RETURNING id`, consumer, failure.eventID, cursorAt, failure.at).Scan(&id); err != nil {
			t.Fatalf("seed alert evaluator failure: %v", err)
		}
		failureIDs = append(failureIDs, id)
	}

	got, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatalf("admin product health: %v", err)
	}

	wantDeltas := map[string]struct{ got, base, delta int }{
		"enabled alert policies":      {got.EnabledAlertPolicies, baseline.EnabledAlertPolicies, 1},
		"alerts in 24h":               {got.Alerts24h, baseline.Alerts24h, 2},
		"unread alerts":               {got.UnreadAlerts, baseline.UnreadAlerts, 1},
		"evaluator failures in 24h":   {got.EvaluatorFailures24h, baseline.EvaluatorFailures24h, 1},
		"snapshot tenants today":      {got.SnapshotTenantsToday, baseline.SnapshotTenantsToday, 1},
		"active SBOM tenants":         {got.ActiveSBOMTenants, baseline.ActiveSBOMTenants, 2},
		"canonical exposures":         {got.CanonicalExposures, baseline.CanonicalExposures, 1},
		"canonical fixable exposures": {got.CanonicalFixableExposures, baseline.CanonicalFixableExposures, 1},
		"canonical KEV exposures":     {got.CanonicalKEVExposures, baseline.CanonicalKEVExposures, 1},
		"comparison-ready repositories": {got.ComparisonReadyRepositories,
			baseline.ComparisonReadyRepositories, 1},
		"license policies configured": {got.LicensePoliciesConfigured, baseline.LicensePoliciesConfigured, 3},
		"license policies enforcing":  {got.LicensePoliciesEnforcing, baseline.LicensePoliciesEnforcing, 2},
	}
	for name, metric := range wantDeltas {
		if metric.got != metric.base+metric.delta {
			t.Errorf("%s = %d, want baseline %d + %d", name, metric.got, metric.base, metric.delta)
		}
	}
	if got.EvaluatorBacklog != 2 {
		t.Errorf("evaluator backlog = %d, want 2", got.EvaluatorBacklog)
	}
	if !got.OldestPendingAt.Equal(cursorAt) {
		t.Errorf("oldest pending at = %s, want %s", got.OldestPendingAt, cursorAt)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), tenantA) {
		t.Fatal("aggregate unexpectedly contains tenant identity")
	}
}
