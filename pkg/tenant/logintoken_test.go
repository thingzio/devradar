package tenant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/tenant"
)

func testDB(t *testing.T) *postgres.Store {
	t.Helper()
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestLoginToken_Lifecycle(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()
	email := "magic-" + tenant.NormalizeEmail(randEmail())

	// Issue a token, consume it → creates + verifies the tenant.
	raw, err := tenant.CreateLoginToken(ctx, db, email, 15*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tn, err := tenant.ConsumeLoginToken(ctx, db, raw)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if tn.Email != email {
		t.Errorf("email = %q, want %q", tn.Email, email)
	}
	if tn.EmailVerifiedAt == nil {
		t.Errorf("email_verified_at should be set after consume")
	}

	// Single-use: the same token cannot be consumed twice.
	if _, err := tenant.ConsumeLoginToken(ctx, db, raw); !errors.Is(err, tenant.ErrLoginTokenInvalid) {
		t.Errorf("second consume: err = %v, want ErrLoginTokenInvalid", err)
	}

	// A second link for the same email logs into the SAME tenant.
	raw2, _ := tenant.CreateLoginToken(ctx, db, email, 15*time.Minute)
	tn2, err := tenant.ConsumeLoginToken(ctx, db, raw2)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if tn2.ID != tn.ID {
		t.Errorf("same email should map to same tenant: %s vs %s", tn2.ID, tn.ID)
	}
}

func TestLoginToken_Expired(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()

	// Negative TTL → already expired; consume must reject.
	raw, err := tenant.CreateLoginToken(ctx, db, randEmail(), -1*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tenant.ConsumeLoginToken(ctx, db, raw); !errors.Is(err, tenant.ErrLoginTokenInvalid) {
		t.Errorf("expired consume: err = %v, want ErrLoginTokenInvalid", err)
	}
}

func TestLoginToken_UnknownRejected(t *testing.T) {
	st := testDB(t)
	if _, err := tenant.ConsumeLoginToken(context.Background(), st.DB(), "not-a-real-token"); !errors.Is(err, tenant.ErrLoginTokenInvalid) {
		t.Errorf("unknown token: err = %v, want ErrLoginTokenInvalid", err)
	}
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  Foo@Example.COM ": "foo@example.com",
		"a@b.co":             "a@b.co",
	} {
		if got := tenant.NormalizeEmail(in); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
