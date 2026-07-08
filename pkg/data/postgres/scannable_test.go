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
		PackageCount: 10, ObjectPath: "gs://test/" + tenantID + "/2",
	}
	if _, _, err := st.UpsertSBOM(ctx, fresh); err != nil {
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

	// With a 12h window: the just-scanned SBOM is excluded, the never-scanned one due.
	due, err := st.ListScannableSBOMs(ctx, 12*time.Hour)
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
	all, err := st.ListScannableSBOMs(ctx, 0)
	if err != nil {
		t.Fatalf("list scannable (0): %v", err)
	}
	allIDs := ids(all)
	if !slices.Contains(allIDs, scanned.ID) || !slices.Contains(allIDs, fresh.ID) {
		t.Errorf("zero window should return all active SBOMs; got %v", allIDs)
	}

	// A tiny window (1ns) makes even the just-scanned SBOM due again.
	dueTiny, err := st.ListScannableSBOMs(ctx, time.Nanosecond)
	if err != nil {
		t.Fatalf("list scannable (1ns): %v", err)
	}
	if !slices.Contains(ids(dueTiny), scanned.ID) {
		t.Errorf("with a 1ns window the scanned SBOM should be due again")
	}
}
