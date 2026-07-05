package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

// TestListImages_ThresholdTrimsBreakdown verifies that ListImages keeps every
// image but trims sub-threshold buckets to zero, keeps unknown, leaves Total as
// the overall count, and sets Relevant to the sum of visible buckets.
func TestListImages_ThresholdTrimsBreakdown(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	// Isolated tenant + one SBOM with one finding per severity.
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	var gh int64
	for _, c := range b {
		gh = gh<<8 | int64(c)
	}
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (github_id, username) VALUES ($1,$2) RETURNING id`,
		gh, "img-"+hex.EncodeToString(b)).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "img-" + hex.EncodeToString(b)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
		VALUES ($1,$2,'img','sha256:x','cyclonedx','gs://x')`, sbomID, tenantID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg','1.0',$4,1.0,false)`,
			sbomID, "f-"+sev, "CVE-"+sev, sev); err != nil {
			t.Fatalf("seed finding %s: %v", sev, err)
		}
	}

	get := func(min string) postgres.SeverityCounts {
		imgs, err := st.ListImages(ctx, tenantID, min)
		if err != nil {
			t.Fatalf("ListImages(%s): %v", min, err)
		}
		if len(imgs) != 1 {
			t.Fatalf("ListImages(%s): %d images, want 1 (image must never disappear)", min, len(imgs))
		}
		return imgs[0].Counts
	}

	// critical: only critical + unknown visible; med/high/low/neg zeroed.
	c := get("critical")
	if c.Critical != 1 || c.High != 0 || c.Medium != 0 || c.Low != 0 || c.Negligible != 0 {
		t.Errorf("critical: buckets = %+v, want only critical=1", c)
	}
	if c.Unknown != 1 {
		t.Errorf("critical: unknown = %d, want 1 (always kept)", c.Unknown)
	}
	if c.Total != 6 {
		t.Errorf("critical: total = %d, want 6 (overall, not trimmed)", c.Total)
	}
	if c.Relevant != 2 { // critical + unknown
		t.Errorf("critical: relevant = %d, want 2", c.Relevant)
	}

	// medium (default): critical+high+medium+unknown; low/neg zeroed.
	c = get("medium")
	if c.Low != 0 || c.Negligible != 0 {
		t.Errorf("medium: low/neg should be zeroed, got low=%d neg=%d", c.Low, c.Negligible)
	}
	if c.Critical != 1 || c.High != 1 || c.Medium != 1 {
		t.Errorf("medium: crit/high/med should be visible, got %+v", c)
	}
	if c.Relevant != 4 { // crit+high+med+unknown
		t.Errorf("medium: relevant = %d, want 4", c.Relevant)
	}

	// negligible: everything visible.
	c = get("negligible")
	if c.Relevant != 6 || c.Total != 6 {
		t.Errorf("negligible: relevant=%d total=%d, want 6/6", c.Relevant, c.Total)
	}
}
