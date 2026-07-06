package scan

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/converter"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/sbom"
	"github.com/thingzio/devradar/pkg/scanner"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeStore struct {
	sboms      []*postgres.SBOM
	applied    int
	appliedIDs []string // SBOM ids that reached ApplyScan
	failures   []string // "stage" per recorded failure
	failedIDs  []string // SBOM ids that recorded a failure
}

func (f *fakeStore) ListActiveSBOMs(context.Context) ([]*postgres.SBOM, error) { return f.sboms, nil }
func (f *fakeStore) ApplyScan(_ context.Context, sb *postgres.SBOM, _ string, _ postgres.Versions, _ []data.Vulnerability) error {
	f.applied++
	f.appliedIDs = append(f.appliedIDs, sb.ID)
	return nil
}
func (f *fakeStore) RecordScanFailure(_ context.Context, sbomID, _, stage string, _ error) {
	f.failures = append(f.failures, stage)
	f.failedIDs = append(f.failedIDs, sbomID)
}

type fakeFetcher struct {
	data []byte
	err  error
}

func (f fakeFetcher) Fetch(context.Context, string) ([]byte, error) { return f.data, f.err }

// ── tests ─────────────────────────────────────────────────────────────────────

// A minimal valid grype document the real converter recognizes.
const grypeDoc = `{"descriptor":{"name":"grype"},"matches":[
  {"vulnerability":{"id":"CVE-1","severity":"High","fix":{"state":"not-fixed"}},
   "artifact":{"name":"openssl","version":"1.1.1"}}]}`

func TestRunner_ScansAndApplies(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{
		{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
	}}
	// One scanner whose "output" is the fixed grype doc; converter registry has grype.
	sc := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if store.applied != 1 {
		t.Errorf("ApplyScan calls = %d, want 1", store.applied)
	}
	if len(store.failures) != 0 {
		t.Errorf("unexpected failures: %v", store.failures)
	}
}

func TestRunner_ZeroFindingsTripwire(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{
		{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 500, ObjectPath: "x"},
	}}
	// grype doc with an empty matches array → 0 findings on a 500-pkg SBOM.
	sc := &fakeScanner{name: "grype", out: `{"descriptor":{"name":"grype"},"matches":[]}`}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if store.applied != 0 {
		t.Errorf("ApplyScan should not run on tripwire, got %d", store.applied)
	}
	if len(store.failures) != 1 || store.failures[0] != "zero-findings" {
		t.Errorf("want one zero-findings failure, got %v", store.failures)
	}
}

func TestRunner_FetchFailureRecorded(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{{ID: "s1", Format: "cyclonedx", ObjectPath: "x"}}}
	sc := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{err: errors.New("boom")},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(store.failures) != 1 || store.failures[0] != "download" {
		t.Errorf("want one download failure, got %v", store.failures)
	}
}

// TestRunner_PanicIsolation is the "one bad apple" guarantee: a scanner that
// panics on a single SBOM must not abort the daily batch. The panic is recorded
// as a panic-stage failure and every other SBOM still scans.
func TestRunner_PanicIsolation(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{
		{ID: "good1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
		{ID: "poison", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
		{ID: "good2", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
	}}
	// Scanner panics only for the SBOM whose id ("poison") lands in the temp path.
	sc := &fakeScanner{name: "grype", out: grypeDoc, panicOn: "poison"}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), DefaultOptions())

	// The run itself must not error — a per-SBOM panic is contained.
	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run returned error, want batch to survive panic: %v", err)
	}
	// Both good SBOMs scanned despite the poison one in the middle.
	if store.applied != 2 {
		t.Errorf("ApplyScan calls = %d, want 2 (good1, good2)", store.applied)
	}
	for _, want := range []string{"good1", "good2"} {
		if !slices.Contains(store.appliedIDs, want) {
			t.Errorf("%s should have scanned; applied = %v", want, store.appliedIDs)
		}
	}
	// The poison SBOM recorded a panic-stage failure.
	if len(store.failures) != 1 || store.failures[0] != "panic" {
		t.Errorf("want one panic failure, got %v", store.failures)
	}
	if len(store.failedIDs) != 1 || store.failedIDs[0] != "poison" {
		t.Errorf("panic should be attributed to poison, got %v", store.failedIDs)
	}
}

// ── fake scanner plumbing ─────────────────────────────────────────────────────

type fakeScanner struct {
	name    string
	out     string
	panicOn string // if non-empty, ScanSBOM panics when the SBOM's id appears in the temp path
}

func (f *fakeScanner) Name() string                                  { return f.name }
func (f *fakeScanner) Version() string                               { return "test-1.0" }
func (f *fakeScanner) DBVersion() string                             { return "db-test" }
func (f *fakeScanner) EnsureDB(context.Context, time.Duration) error { return nil }
func (f *fakeScanner) IsAvailable() bool                             { return true }
func (f *fakeScanner) ConverterName() string                         { return f.name }
func (f *fakeScanner) ScanSBOM(_ context.Context, sbomPath, outPath string) error {
	// writeTemp names the file "devradar-sbom-<id>-*.json", so the poison SBOM's
	// id shows up in the path — match on it to simulate a scanner faulting on one
	// specific untrusted input.
	if f.panicOn != "" && strings.Contains(sbomPath, f.panicOn) {
		panic("boom: poison SBOM")
	}
	return os.WriteFile(outPath, []byte(f.out), 0o600)
}
