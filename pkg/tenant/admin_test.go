package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/tenant"
)

func adminTestDB(t *testing.T) *postgres.Store {
	t.Helper()
	return testDB(t)
}

// TestAdminListTenants_SearchAndPage covers the operator tenant list: a substring
// search matches by email and the total count reflects the filter.
func TestAdminListTenants_SearchAndPage(t *testing.T) {
	st := adminTestDB(t)
	ctx := context.Background()
	db := st.DB()

	// A uniquely-tagged email so the search is deterministic against a shared DB.
	uniq := "zzsearch-" + randEmail()
	if _, err := tenant.UpsertTenantByEmail(ctx, db, uniq); err != nil {
		t.Fatalf("seed: %v", err)
	}

	list, total, err := tenant.AdminListTenants(ctx, db, uniq, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].Email != uniq {
		t.Fatalf("search %q: got %d rows (total %d), want exactly our tenant", uniq, len(list), total)
	}
}

// TestAdminListTenantsWithStats covers the enriched operator list: a brand-new
// tenant has never logged in (nil LastLoginAt) and tracks zero images.
func TestAdminListTenantsWithStats(t *testing.T) {
	st := adminTestDB(t)
	ctx := context.Background()
	db := st.DB()

	uniq := "zzstats-" + randEmail()
	if _, err := tenant.UpsertTenantByEmail(ctx, db, uniq); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, total, err := tenant.AdminListTenantsWithStats(ctx, db, uniq, 10, 0)
	if err != nil {
		t.Fatalf("list with stats: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("search %q: got %d rows (total %d), want 1", uniq, len(rows), total)
	}
	r := rows[0]
	if r.Email != uniq {
		t.Errorf("email = %q, want %q", r.Email, uniq)
	}
	if r.LastLoginAt != nil {
		t.Errorf("LastLoginAt = %v, want nil (never signed in)", r.LastLoginAt)
	}
	if r.ImageCount != 0 {
		t.Errorf("ImageCount = %d, want 0 (no SBOMs)", r.ImageCount)
	}
}

// TestDeleteTenant_Cascades verifies deleting a tenant removes it (and, by the
// schema's ON DELETE CASCADE, its children — asserted here via a token).
func TestDeleteTenant_Cascades(t *testing.T) {
	st := adminTestDB(t)
	ctx := context.Background()
	db := st.DB()

	tn, err := tenant.UpsertTenantByEmail(ctx, db, "del-"+randEmail())
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'t',$2)`, tn.ID, "cascade-"+randEmail()); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := tenant.DeleteTenant(ctx, db, tn.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := tenant.GetTenant(ctx, db, tn.ID); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("get after delete: err = %v, want ErrNotFound", err)
	}
	var tokens int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1`, tn.ID).Scan(&tokens); err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("tokens after tenant delete = %d, want 0 (cascade)", tokens)
	}

	// Deleting a non-existent tenant is a not-found, not a silent success.
	if err := tenant.DeleteTenant(ctx, db, tn.ID); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: err = %v, want ErrNotFound", err)
	}
}

// TestValidPlan guards the plan allowlist.
func TestValidPlan(t *testing.T) {
	for _, p := range tenant.Plans {
		if !tenant.ValidPlan(p) {
			t.Errorf("ValidPlan(%q) = false, want true", p)
		}
	}
	if tenant.ValidPlan("enterprise-unlimited") {
		t.Error("ValidPlan should reject an unknown plan")
	}
}
