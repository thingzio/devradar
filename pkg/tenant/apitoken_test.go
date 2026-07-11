package tenant_test

import (
	"context"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/tenant"
)

// seedTenant creates a fresh tenant row and returns its id.
func seedTenant(t *testing.T, st *postgres.Store) string {
	t.Helper()
	var id string
	if err := st.DB().QueryRowContext(context.Background(),
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`, randEmail()).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

// TestValidateAPIToken_CoarsenedLastUsed verifies that rapid re-validation
// authenticates every time but bumps last_used_at at most once per coarsening
// window (killing the per-request write amplification without losing the token).
func TestValidateAPIToken_CoarsenedLastUsed(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()
	tenantID := seedTenant(t, st)

	raw, err := tenant.CreateAPIToken(ctx, db, tenantID, "ci")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	lastUsed := func() *time.Time {
		var lu *time.Time
		if err := db.QueryRowContext(ctx,
			`SELECT last_used_at FROM devradar_api_token WHERE tenant_id=$1`, tenantID).Scan(&lu); err != nil {
			t.Fatalf("read last_used_at: %v", err)
		}
		return lu
	}

	// First validation authenticates and sets last_used_at.
	if tn, err := tenant.ValidateAPIToken(ctx, db, raw); err != nil || tn.ID != tenantID {
		t.Fatalf("first validate: tn=%v err=%v", tn, err)
	}
	first := lastUsed()
	if first == nil {
		t.Fatal("last_used_at should be set after first validate")
	}

	// Immediate second validation still authenticates, but must NOT bump
	// last_used_at again (within the coarsening window).
	if tn, err := tenant.ValidateAPIToken(ctx, db, raw); err != nil || tn.ID != tenantID {
		t.Fatalf("second validate: tn=%v err=%v", tn, err)
	}
	second := lastUsed()
	if !second.Equal(*first) {
		t.Errorf("last_used_at bumped on rapid re-validate: %v -> %v (want unchanged)", first, second)
	}
}

// TestValidateAPIToken_Invalid rejects an unknown token.
func TestValidateAPIToken_Invalid(t *testing.T) {
	st := testDB(t)
	if _, err := tenant.ValidateAPIToken(context.Background(), st.DB(), "dr_nonexistent"); err == nil {
		t.Error("unknown token should be rejected")
	}
}

// TestCountAPITokens counts a tenant's tokens.
func TestCountAPITokens(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	tenantID := seedTenant(t, st)

	if n, _ := tenant.CountAPITokens(ctx, st.DB(), tenantID); n != 0 {
		t.Errorf("fresh tenant token count = %d, want 0", n)
	}
	for range 3 {
		if _, err := tenant.CreateAPIToken(ctx, st.DB(), tenantID, "x"); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if n, _ := tenant.CountAPITokens(ctx, st.DB(), tenantID); n != 3 {
		t.Errorf("token count = %d, want 3", n)
	}
}
