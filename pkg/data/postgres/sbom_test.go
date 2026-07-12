package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

// TestUpsertSBOMWithLimit_ActiveCap verifies the per-tenant active-SBOM cap:
// distinct digests are admitted up to the cap, a brand-new digest past it is
// rejected with ErrSBOMLimit, and a re-submit of an existing digest is always
// admitted (even at the cap) since it is an update, not growth.
func TestUpsertSBOMWithLimit_ActiveCap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"cap-"+randID(t)[:8]+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const cap = 3
	mk := func() *postgres.SBOM {
		return &postgres.SBOM{
			ID:         randID(t) + randID(t),
			TenantID:   tenantID,
			ImageRef:   "registry.test/app",
			Repository: "registry.test/app",
			Digest:     "sha256:" + randID(t) + randID(t),
			Format:     "cyclonedx",
			ObjectPath: "gs://test/" + tenantID + "/" + randID(t),
			Status:     "active",
		}
	}

	// Fill to the cap with distinct digests.
	var lastDigest, lastFormat string
	for i := range cap {
		sb := mk()
		lastDigest, lastFormat = sb.Digest, sb.Format
		if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, sb, cap); err != nil || !inserted {
			t.Fatalf("submit %d under cap: inserted=%v err=%v", i, inserted, err)
		}
	}

	// A brand-new digest past the cap is rejected.
	if _, _, _, err := st.UpsertSBOMWithLimit(ctx, mk(), cap); !errors.Is(err, postgres.ErrSBOMLimit) {
		t.Fatalf("over-cap submit: err = %v, want ErrSBOMLimit", err)
	}

	// A re-submit of an EXISTING digest is still admitted at the cap (update, not
	// growth) — resolves to the existing row (inserted=false), no error.
	resub := mk()
	resub.Digest, resub.Format = lastDigest, lastFormat
	if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, resub, cap); err != nil || inserted {
		t.Fatalf("re-submit at cap: inserted=%v err=%v, want inserted=false nil", inserted, err)
	}

	// A cap of 0 disables enforcement.
	if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, mk(), 0); err != nil || !inserted {
		t.Fatalf("cap disabled: inserted=%v err=%v", inserted, err)
	}
}
