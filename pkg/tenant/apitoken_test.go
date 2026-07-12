package tenant_test

import (
	"context"
	"errors"
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

	raw, err := tenant.CreateAPIToken(ctx, db, tenantID, "ci", 0)
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

// TestValidateAPIToken_Expiry: a token minted with a TTL authenticates while
// valid and is rejected once expired; a token minted with ttl<=0 never expires.
func TestValidateAPIToken_Expiry(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()
	tenantID := seedTenant(t, st)

	// Non-expiring token (ttl 0) authenticates.
	forever, err := tenant.CreateAPIToken(ctx, db, tenantID, "forever", 0)
	if err != nil {
		t.Fatalf("create non-expiring: %v", err)
	}
	if _, err := tenant.ValidateAPIToken(ctx, db, forever); err != nil {
		t.Fatalf("non-expiring token should authenticate: %v", err)
	}

	// Expiring token: valid now, then force it into the past and confirm rejection.
	expiring, err := tenant.CreateAPIToken(ctx, db, tenantID, "expiring", time.Hour)
	if err != nil {
		t.Fatalf("create expiring: %v", err)
	}
	if _, err := tenant.ValidateAPIToken(ctx, db, expiring); err != nil {
		t.Fatalf("unexpired token should authenticate: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE devradar_api_token SET expires_at = now() - interval '1 minute'
		 WHERE token_hash = $1`, tenant.HashToken(expiring)); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	if _, err := tenant.ValidateAPIToken(ctx, db, expiring); err == nil {
		t.Fatal("expired token must be rejected")
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
		if _, err := tenant.CreateAPIToken(ctx, st.DB(), tenantID, "x", 0); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if n, _ := tenant.CountAPITokens(ctx, st.DB(), tenantID); n != 3 {
		t.Errorf("token count = %d, want 3", n)
	}
}

// TestCreateAPITokenWithLimit_Cap verifies the atomic per-tenant token cap:
// tokens mint up to the cap, the next is rejected with ErrTokenLimit, and a cap
// of 0 disables enforcement.
func TestCreateAPITokenWithLimit_Cap(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	tenantID := seedTenant(t, st)

	const cap = 2
	for i := range cap {
		if _, err := tenant.CreateAPITokenWithLimit(ctx, st.DB(), tenantID, "x", 0, cap); err != nil {
			t.Fatalf("mint %d under cap: %v", i, err)
		}
	}
	if _, err := tenant.CreateAPITokenWithLimit(ctx, st.DB(), tenantID, "over", 0, cap); !errors.Is(err, tenant.ErrTokenLimit) {
		t.Fatalf("over-cap mint: err = %v, want ErrTokenLimit", err)
	}
	// Cap disabled (0) still mints.
	if _, err := tenant.CreateAPITokenWithLimit(ctx, st.DB(), tenantID, "unbounded", 0, 0); err != nil {
		t.Fatalf("cap disabled: %v", err)
	}
}
