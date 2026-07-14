package tenant_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
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

// randEmail returns a unique test email so parallel/repeated runs don't collide
// on the tenant email UNIQUE constraint.
func randEmail() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "@example.com"
}
