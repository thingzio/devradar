package ratelimit_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/ratelimit"
)

func testDB(t *testing.T) *postgres.Store {
	t.Helper()
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		if os.Getenv("DATABASE_URL") != "" {
			t.Fatalf("connect configured integration database: %v", err)
		}
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func randKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "test:" + hex.EncodeToString(b)
}

// TestAllow_WithinAndOverLimit: the first `limit` hits are allowed, the next is
// rejected, all within one window.
func TestAllow_WithinAndOverLimit(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	key := randKey(t)
	const limit = 3

	for i := 1; i <= limit; i++ {
		ok, err := ratelimit.Allow(ctx, st.DB(), key, limit, time.Hour)
		if err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
		if !ok {
			t.Errorf("hit %d should be allowed (limit %d)", i, limit)
		}
	}
	// One past the limit → rejected.
	ok, err := ratelimit.Allow(ctx, st.DB(), key, limit, time.Hour)
	if err != nil {
		t.Fatalf("over-limit hit: %v", err)
	}
	if ok {
		t.Errorf("hit %d should be rejected (over limit %d)", limit+1, limit)
	}
}

// TestAllow_SeparateKeysIndependent: different keys don't share a budget.
func TestAllow_SeparateKeysIndependent(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	a, b := randKey(t), randKey(t)

	if ok, _ := ratelimit.Allow(ctx, st.DB(), a, 1, time.Hour); !ok {
		t.Fatal("first hit on key a should be allowed")
	}
	if ok, _ := ratelimit.Allow(ctx, st.DB(), a, 1, time.Hour); ok {
		t.Fatal("second hit on key a should be rejected")
	}
	// Key b is unaffected.
	if ok, _ := ratelimit.Allow(ctx, st.DB(), b, 1, time.Hour); !ok {
		t.Error("first hit on key b should be allowed (independent budget)")
	}
}

// TestAllow_ZeroLimitDisabled: a zero limit means "no limit" — always allowed.
func TestAllow_ZeroLimitDisabled(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	key := randKey(t)
	for i := range 5 {
		if ok, err := ratelimit.Allow(ctx, st.DB(), key, 0, time.Hour); err != nil || !ok {
			t.Fatalf("zero-limit hit %d: ok=%v err=%v, want allowed", i, ok, err)
		}
	}
}

func TestAllow_TransactionRollbackDoesNotConsumeQuota(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	key := randKey(t)
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ratelimit.Allow(ctx, tx, key, 1, time.Hour)
	if err != nil || !allowed {
		_ = tx.Rollback()
		t.Fatalf("transactional allowance = %t, %v", allowed, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	allowed, err = ratelimit.Allow(ctx, st.DB(), key, 1, time.Hour)
	if err != nil || !allowed {
		t.Fatalf("allowance after rollback = %t, %v, want available", allowed, err)
	}
}

// TestAllow_WindowResets: with a sub-second window, a new window restores the
// budget.
func TestAllow_WindowResets(t *testing.T) {
	st := testDB(t)
	ctx := context.Background()
	key := randKey(t)

	if ok, _ := ratelimit.Allow(ctx, st.DB(), key, 1, time.Second); !ok {
		t.Fatal("first hit should be allowed")
	}
	if ok, _ := ratelimit.Allow(ctx, st.DB(), key, 1, time.Second); ok {
		t.Fatal("second hit in same 1s window should be rejected")
	}
	// Cross into the next window.
	time.Sleep(1100 * time.Millisecond)
	if ok, _ := ratelimit.Allow(ctx, st.DB(), key, 1, time.Second); !ok {
		t.Error("hit in the next window should be allowed again")
	}
}
