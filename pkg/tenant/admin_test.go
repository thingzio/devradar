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
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
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
	if _, err := tenant.CreateAPIToken(ctx, db, tn.ID, "t"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := tenant.DeleteTenant(ctx, db, tn.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := tenant.GetTenant(ctx, db, tn.ID); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("get after delete: err = %v, want ErrNotFound", err)
	}
	toks, err := tenant.ListAPITokens(ctx, db, tn.ID)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(toks) != 0 {
		t.Errorf("tokens after tenant delete = %d, want 0 (cascade)", len(toks))
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
