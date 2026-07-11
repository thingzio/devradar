package postgres_test

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAdminProductHealth(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	db := st.DB()

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

	tenantA, sbomA := seedTenantAndSBOM(t, st)
	tenantB, sbomB := seedTenantAndSBOM(t, st)
	foreignTenant, foreignSBOM := seedTenantAndSBOM(t, st)

	repositoryA := "registry.test/product-health-ready"
	repositoryB := "registry.test/product-health-single"
	foreignRepository := "registry.test/product-health-foreign"
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

	canonicalKEVCVE := "CVE-2099-0001"
	canonicalNonKEVCVE := "CVE-2099-0002"
	suppressedCVE := "CVE-2099-0003"
	foreignCVE := "CVE-2099-0004"
	for _, finding := range []struct {
		sbomID, scanner, findingID, exposure string
		fixed                                bool
	}{
		// Deliberately use one canonical finding ID with different scanner
		// exposures. Only one exposure is KEV and only one row is fixed, so the
		// aggregate must use bool_or for both facts rather than bool_and.
		{sbomA.ID, "grype", "canonical", canonicalNonKEVCVE, false},
		{sbomA.ID, "trivy", "canonical", canonicalKEVCVE, true},
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
		VALUES ($1,true),($2,false),($3,true),($4,true)`,
		canonicalKEVCVE, canonicalNonKEVCVE, suppressedCVE, foreignCVE); err != nil {
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
			($2,(now() AT TIME ZONE 'UTC')::date - 1,1,88),
			($3,(now() AT TIME ZONE 'UTC')::date,1,99)`,
		tenantA, tenantB, foreignTenant); err != nil {
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
			RETURNING id`, tenantA, sbomA.ID, randID(t), canonicalKEVCVE, cause, at).Scan(&id); err != nil {
			t.Fatalf("seed finding event: %v", err)
		}
		if cause == "image" || cause == "db" {
			if _, err := db.ExecContext(ctx, `
					INSERT INTO devradar_alert_event_queue
						(consumer, tenant_id, event_occurred_at, event_id)
					VALUES ('browser-alerts-v1',$1,$2,$3)`, tenantA, at, id); err != nil {
				t.Fatalf("enqueue finding event: %v", err)
			}
		}
		return id
	}
	cursorEventID := insertEvent("image", cursorAt)
	pendingAtCursorID := insertEvent("db", cursorAt)
	pendingLaterAt := cursorAt.Add(time.Minute)
	pendingLaterID := insertEvent("image", pendingLaterAt)
	toolingAt := cursorAt.Add(2 * time.Minute)
	toolingID := insertEvent("tooling", toolingAt)
	if _, err := db.ExecContext(ctx, `
			UPDATE devradar_alert_event_queue
			SET processed_at=now()
			WHERE consumer='browser-alerts-v1' AND event_occurred_at=$1 AND event_id=$2`,
		cursorAt, cursorEventID); err != nil {
		t.Fatalf("mark cursor event processed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
			UPDATE devradar_alert_cursor
			SET last_occurred_at=$2, last_event_id=$3, updated_at=now()
			WHERE consumer=$1`, "browser-alerts-v1", toolingAt, toolingID); err != nil {
		t.Fatalf("set alert cursor: %v", err)
	}

	for i, alert := range []struct {
		eventID int64
		at      time.Time
		read    bool
		created time.Time
	}{
		{pendingAtCursorID, cursorAt, false, time.Now().UTC()},
		{pendingLaterID, pendingLaterAt, true, time.Now().UTC()},
		{cursorEventID, cursorAt, false, time.Now().UTC().Add(-25 * time.Hour)},
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
			VALUES ($1,$2,$3,$4,'new_finding',$5,$6,$7,$8,$9,'pkg','1',
			        'high',8.0,'image',$10,$11)`,
			tenantA, policyA, alert.eventID, alert.at, sbomA.ID,
			repositoryA, sbomA.Digest, fmt.Sprintf("alert-%d", i),
			canonicalKEVCVE, readAt, alert.created); err != nil {
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
		if _, err := db.ExecContext(ctx, `
			INSERT INTO devradar_alert_failure
				(consumer, event_id, event_occurred_at, error, occurred_at)
			VALUES ('browser-alerts-v1',$1,$2,'test failure',$3)`,
			failure.eventID, cursorAt, failure.at); err != nil {
			t.Fatalf("seed alert evaluator failure: %v", err)
		}
	}

	got, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatalf("admin product health: %v", err)
	}

	want := map[string]struct{ got, want int }{
		"enabled alert policies":        {got.EnabledAlertPolicies, 1},
		"alerts in 24h":                 {got.Alerts24h, 2},
		"unread alerts":                 {got.UnreadAlerts, 2},
		"evaluator backlog":             {got.EvaluatorBacklog, 2},
		"evaluator failures in 24h":     {got.EvaluatorFailures24h, 1},
		"snapshot tenants today":        {got.SnapshotTenantsToday, 1},
		"active SBOM tenants":           {got.ActiveSBOMTenants, 2},
		"canonical exposures":           {got.CanonicalExposures, 1},
		"canonical fixable exposures":   {got.CanonicalFixableExposures, 1},
		"canonical KEV exposures":       {got.CanonicalKEVExposures, 1},
		"comparison-ready repositories": {got.ComparisonReadyRepositories, 1},
		"license policies configured":   {got.LicensePoliciesConfigured, 3},
		"license policies enforcing":    {got.LicensePoliciesEnforcing, 2},
	}
	for name, metric := range want {
		if metric.got != metric.want {
			t.Errorf("%s = %d, want %d", name, metric.got, metric.want)
		}
	}
	if !got.OldestPendingAt.Equal(cursorAt) {
		t.Errorf("oldest pending at = %s, want %s", got.OldestPendingAt, cursorAt)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), tenantA) {
		t.Fatal("aggregate unexpectedly contains tenant identity")
	}

	if _, err := db.ExecContext(ctx,
		`DELETE FROM devradar_alert_cursor WHERE consumer='browser-alerts-v1'`); err != nil {
		t.Fatalf("delete alert cursor: %v", err)
	}
	withoutCursor, err := st.AdminProductHealth(ctx)
	if err != nil {
		t.Fatalf("admin product health without cursor: %v", err)
	}
	if withoutCursor.EvaluatorBacklog != 2 {
		t.Errorf("cursor-independent evaluator backlog = %d, want 2", withoutCursor.EvaluatorBacklog)
	}
	if !withoutCursor.OldestPendingAt.Equal(cursorAt) {
		t.Errorf("cursor-independent oldest pending at = %s, want %s",
			withoutCursor.OldestPendingAt, cursorAt)
	}
}

func isolatedAdminProductHealthStore(t *testing.T) *postgres.Store {
	t.Helper()
	ctx := context.Background()
	base := testStore(t)
	schema := "devradar_product_health_" + randID(t)
	quotedSchema := pq.QuoteIdentifier(schema)
	if _, err := base.DB().ExecContext(ctx, `CREATE SCHEMA `+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}

	var isolated *postgres.Store
	t.Cleanup(func() {
		if isolated != nil {
			_ = isolated.Close()
		}
		_, _ = base.DB().ExecContext(ctx, `DROP SCHEMA IF EXISTS `+quotedSchema+` CASCADE`)
	})

	if _, err := base.DB().ExecContext(ctx, `
		CREATE TABLE `+quotedSchema+`.devradar_schema_version (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("precreate isolated schema version table: %v", err)
	}

	dsn, err := databaseURLWithSearchPath(config.DatabaseURL(), schema)
	if err != nil {
		t.Fatalf("set isolated search_path: %v", err)
	}
	isolated, err = postgres.New(ctx, dsn, postgres.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("open isolated store: %v", err)
	}
	return isolated
}

func databaseURLWithSearchPath(dsn, schema string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("parse URI DSN: %w", err)
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		return u.String(), nil
	}
	if strings.TrimSpace(dsn) == "" {
		return "", fmt.Errorf("DATABASE_URL is empty")
	}
	return strings.TrimSpace(dsn) + " search_path=" + schema, nil
}

func TestAdminProductHealth_DatabaseURLWithSearchPath(t *testing.T) {
	for _, tc := range []struct {
		name, dsn string
		check     func(*testing.T, string)
	}{
		{
			name: "URI",
			dsn:  "postgres://user:pass@localhost/db?sslmode=disable",
			check: func(t *testing.T, got string) {
				u, err := url.Parse(got)
				if err != nil {
					t.Fatal(err)
				}
				if value := u.Query().Get("search_path"); value != "isolated" {
					t.Fatalf("URI search_path = %q, want isolated", value)
				}
			},
		},
		{
			name: "keyword",
			dsn:  "host=localhost dbname=devradar sslmode=disable",
			check: func(t *testing.T, got string) {
				if !strings.HasSuffix(got, " search_path=isolated") {
					t.Fatalf("keyword DSN = %q, want appended search_path", got)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := databaseURLWithSearchPath(tc.dsn, "isolated")
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, got)
		})
	}
}
