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

	// Negative TTL → already expired; consume must reject with the EXPIRED error
	// (distinct from invalid/used, so the UI can say "request a new one").
	raw, err := tenant.CreateLoginToken(ctx, db, randEmail(), -1*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tenant.ConsumeLoginToken(ctx, db, raw); !errors.Is(err, tenant.ErrLoginTokenExpired) {
		t.Errorf("expired consume: err = %v, want ErrLoginTokenExpired", err)
	}
}

// TestPeekLoginToken_DoesNotConsume is the anti-prefetch guarantee: peeking a
// valid token (what GET /auth/verify does) must NOT consume it, so a subsequent
// consume (the human's POST) still succeeds. This is the fix for email-security
// scanners burning single-use links before the user clicks.
func TestPeekLoginToken_DoesNotConsume(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()
	email := "peek-" + tenant.NormalizeEmail(randEmail())

	raw, err := tenant.CreateLoginToken(ctx, db, email, 15*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Peek twice (as a scanner + then the page render might) — still valid.
	for i := range 2 {
		got, err := tenant.PeekLoginToken(ctx, db, raw)
		if err != nil {
			t.Fatalf("peek %d: %v", i, err)
		}
		if got != email {
			t.Errorf("peek email = %q, want %q", got, email)
		}
	}

	// The human's POST still consumes successfully after the peeks.
	tn, err := tenant.ConsumeLoginToken(ctx, db, raw)
	if err != nil {
		t.Fatalf("consume after peek: %v", err)
	}
	if tn.Email != email {
		t.Errorf("email = %q, want %q", tn.Email, email)
	}
	// And now it's gone (single-use holds).
	if _, err := tenant.ConsumeLoginToken(ctx, db, raw); !errors.Is(err, tenant.ErrLoginTokenInvalid) {
		t.Errorf("second consume: err = %v, want ErrLoginTokenInvalid", err)
	}
}

func TestPeekLoginToken_ExpiredAndUnknown(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	db := st.DB()

	raw, err := tenant.CreateLoginToken(ctx, db, randEmail(), -1*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tenant.PeekLoginToken(ctx, db, raw); !errors.Is(err, tenant.ErrLoginTokenExpired) {
		t.Errorf("peek expired: err = %v, want ErrLoginTokenExpired", err)
	}
	if _, err := tenant.PeekLoginToken(ctx, db, "no-such-token"); !errors.Is(err, tenant.ErrLoginTokenInvalid) {
		t.Errorf("peek unknown: err = %v, want ErrLoginTokenInvalid", err)
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
