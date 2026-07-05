package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

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
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"img-"+hex.EncodeToString(b)+"@example.com").Scan(&tenantID); err != nil {
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

// TestImageTimeline_AcrossDigests verifies the cross-digest history: two SBOMs
// sharing one image_ref (an image whose digest changed) produce a merged,
// severity-filtered, newest-first timeline; an unknown ref is 404; and the
// timeline is tenant-scoped.
func TestImageTimeline_AcrossDigests(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"tl-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	imageRef := "example.com/app-" + suffix

	// Two digests of the same image_ref, each with one added event at a distinct
	// severity and time.
	seed := func(digest, sev string, when time.Time) {
		sbomID := digest
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
			VALUES ($1,$2,$3,$4,'cyclonedx','gs://x')`, sbomID, tenantID, imageRef, digest); err != nil {
			t.Fatalf("seed sbom: %v", err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding_event
				(tenant_id, sbom_id, scanner, finding_id, event_type, exposure, package, version,
				 severity, score, cause, db_version, scanner_version, scan_run_id, occurred_at)
			VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1.0',$5,1.0,'image','db-1','grype-1',
				gen_random_uuid(),$6)`,
			tenantID, sbomID, "f-"+digest, "CVE-"+sev, sev, when); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC().Add(-1 * time.Hour)
	seed("sha256:aaa"+suffix, "high", old)
	seed("sha256:bbb"+suffix, "low", recent)

	// Full history (negligible threshold → both events), newest first.
	all, err := st.ImageTimeline(ctx, tenantID, imageRef, "negligible", 100)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("timeline len = %d, want 2", len(all))
	}
	if !all[0].OccurredAt.After(all[1].OccurredAt) {
		t.Errorf("timeline not newest-first: %v then %v", all[0].OccurredAt, all[1].OccurredAt)
	}
	if all[0].Digest == all[1].Digest {
		t.Errorf("expected events from two distinct digests, both %s", all[0].Digest)
	}

	// medium threshold drops the 'low' event, keeps 'high'.
	hi, err := st.ImageTimeline(ctx, tenantID, imageRef, "medium", 100)
	if err != nil {
		t.Fatalf("timeline (medium): %v", err)
	}
	if len(hi) != 1 || hi[0].Severity != "high" {
		t.Errorf("medium threshold: got %d events (want 1 high): %+v", len(hi), hi)
	}

	// Unknown ref → ErrNotFound.
	if _, err := st.ImageTimeline(ctx, tenantID, "example.com/nope", "medium", 100); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown ref: err = %v, want ErrNotFound", err)
	}

	// Another tenant sees nothing for this ref → ErrNotFound (isolation).
	var otherID string
	_ = st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"other-"+suffix+"@example.com").Scan(&otherID)
	if _, err := st.ImageTimeline(ctx, otherID, imageRef, "medium", 100); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("cross-tenant timeline: err = %v, want ErrNotFound", err)
	}
}
