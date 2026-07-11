package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
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
