package postgres_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

// TestListScannableSBOMs_StalenessFilter verifies work selection: a never-scanned
// SBOM is always due; a freshly-scanned one is excluded within the window; a
// zero window disables the filter (every active SBOM returned).
func TestListScannableSBOMs_StalenessFilter(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Two SBOMs under one tenant: one we'll scan, one we leave untouched.
	tenantID, scanned := seedTenantAndSBOM(t, st)
	fresh := &postgres.SBOM{
		ID: randID(t) + randID(t), TenantID: tenantID, ImageRef: "registry.test/app2",
		Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
		PackageCount: 10, ObjectPath: "gs://test/" + tenantID + "/2", Status: "active",
	}
	if _, _, _, err := st.UpsertSBOM(ctx, fresh); err != nil {
		t.Fatalf("seed second sbom: %v", err)
	}

	// Record a scan on the first (writes a scan_run with scanned_at = now()).
	ver := postgres.Versions{DBVersion: "db1", ScannerVersion: "g1", CanonicalizerVersion: "c1"}
	if err := st.ApplyScan(ctx, scanned, "grype", ver,
		[]data.Vulnerability{vuln("CVE-1", "openssl", "3.0", "high", 7.5, false)}); err != nil {
		t.Fatalf("apply scan: %v", err)
	}

	ids := func(sbs []*postgres.SBOM) []string {
		out := make([]string, len(sbs))
		for i, s := range sbs {
			out[i] = s.ID
		}
		return out
	}

	// Expected set is just grype (the only scanner we recorded a run for), so the
	// scanned SBOM counts as fully fresh. With a 12h window: the just-scanned SBOM
	// is excluded, the never-scanned one due.
	grypeOnly := []string{"grype"}
	due, err := st.ListScannableSBOMs(ctx, 12*time.Hour, grypeOnly)
	if err != nil {
		t.Fatalf("list scannable (12h): %v", err)
	}
	dueIDs := ids(due)
	if slices.Contains(dueIDs, scanned.ID) {
		t.Errorf("freshly-scanned SBOM %s should be excluded within 12h window", scanned.ID)
	}
	if !slices.Contains(dueIDs, fresh.ID) {
		t.Errorf("never-scanned SBOM %s should be due", fresh.ID)
	}

	// With a zero window: filter disabled, both returned (legacy full-pass).
	all, err := st.ListScannableSBOMs(ctx, 0, grypeOnly)
	if err != nil {
		t.Fatalf("list scannable (0): %v", err)
	}
	allIDs := ids(all)
	if !slices.Contains(allIDs, scanned.ID) || !slices.Contains(allIDs, fresh.ID) {
		t.Errorf("zero window should return all active SBOMs; got %v", allIDs)
	}

	// A tiny window (1ns) makes even the just-scanned SBOM due again.
	dueTiny, err := st.ListScannableSBOMs(ctx, time.Nanosecond, grypeOnly)
	if err != nil {
		t.Fatalf("list scannable (1ns): %v", err)
	}
	if !slices.Contains(ids(dueTiny), scanned.ID) {
		t.Errorf("with a 1ns window the scanned SBOM should be due again")
	}
}

// TestListScannableSBOMs_PerScannerFreshness verifies freshness is evaluated per
// scanner: an SBOM scanned by grype but not trivy stays due (so trivy runs),
// and only when BOTH scanners have a recent run does it drop out. This is the
// fix for one scanner's success masking another's absence.
func TestListScannableSBOMs_PerScannerFreshness(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tenantID, sb := seedTenantAndSBOM(t, st)
	both := []string{"grype", "trivy"}
	ver := postgres.Versions{DBVersion: "db1", ScannerVersion: "v1", CanonicalizerVersion: "c1"}

	contains := func(sbs []*postgres.SBOM, id string) bool {
		return slices.ContainsFunc(sbs, func(s *postgres.SBOM) bool { return s.ID == id })
	}

	// Only grype has run → still due (trivy missing).
	if err := st.ApplyScan(ctx, sb, "grype", ver,
		[]data.Vulnerability{vuln("CVE-1", "openssl", "3.0", "high", 7.5, false)}); err != nil {
		t.Fatalf("apply grype: %v", err)
	}
	due, err := st.ListScannableSBOMs(ctx, 12*time.Hour, both)
	if err != nil {
		t.Fatalf("list (grype only): %v", err)
	}
	if !contains(due, sb.ID) {
		t.Errorf("SBOM scanned by grype only should still be due (trivy never ran)")
	}

	// Now trivy has also run → no longer due.
	if err := st.ApplyScan(ctx, sb, "trivy", ver,
		[]data.Vulnerability{vuln("CVE-1", "openssl", "3.0", "high", 7.5, false)}); err != nil {
		t.Fatalf("apply trivy: %v", err)
	}
	due, err = st.ListScannableSBOMs(ctx, 12*time.Hour, both)
	if err != nil {
		t.Fatalf("list (both): %v", err)
	}
	if contains(due, sb.ID) {
		t.Errorf("SBOM scanned by both grype and trivy should not be due within window")
	}
	_ = tenantID
}

// TestListScannableSBOMs_RescanClearedAfterAllScanners verifies a force-rescan
// marker keeps the SBOM due until every expected scanner has run, then
// ClearRescanRequested consumes it.
func TestListScannableSBOMs_RescanClearedAfterAllScanners(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_, sb := seedTenantAndSBOM(t, st)
	both := []string{"grype", "trivy"}
	ver := postgres.Versions{DBVersion: "db1", ScannerVersion: "v1", CanonicalizerVersion: "c1"}

	// Scan with both so freshness alone would exclude it.
	for _, sc := range both {
		if err := st.ApplyScan(ctx, sb, sc, ver, nil); err != nil {
			t.Fatalf("apply %s: %v", sc, err)
		}
	}
	// Force a rescan.
	if err := st.AdminRequestRescan(ctx, sb.ID); err != nil {
		t.Fatalf("request rescan: %v", err)
	}
	due, err := st.ListScannableSBOMs(ctx, 12*time.Hour, both)
	if err != nil {
		t.Fatalf("list after rescan request: %v", err)
	}
	if !slices.ContainsFunc(due, func(s *postgres.SBOM) bool { return s.ID == sb.ID }) {
		t.Errorf("force-rescan should make the SBOM due regardless of freshness")
	}
	// Clear the marker (as scanOne does after all scanners) → no longer due.
	if err := st.ClearRescanRequested(ctx, sb.ID); err != nil {
		t.Fatalf("clear rescan: %v", err)
	}
	due, err = st.ListScannableSBOMs(ctx, 12*time.Hour, both)
	if err != nil {
		t.Fatalf("list after clear: %v", err)
	}
	if slices.ContainsFunc(due, func(s *postgres.SBOM) bool { return s.ID == sb.ID }) {
		t.Errorf("after clearing the rescan marker the fresh SBOM should not be due")
	}
}
