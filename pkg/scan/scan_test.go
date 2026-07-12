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
	"github.com/thingzio/devradar/pkg/enrich"
	"github.com/thingzio/devradar/pkg/sbom"
	"github.com/thingzio/devradar/pkg/scanner"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeStore struct {
	sboms      []*postgres.SBOM
	applied    int
	appliedIDs []string        // SBOM ids that reached ApplyScan
	failures   []string        // "stage" per recorded failure
	failedIDs  []string        // SBOM ids that recorded a failure
	hasPkgs    map[string]bool // SBOM ids already carrying a license inventory
	backfilled []string        // SBOM ids that reached UpsertSBOMPackages
	scanMaxAge time.Duration   // staleness window passed to ListScannableSBOMs
	expected   []string        // expected-scanner set passed to ListScannableSBOMs
	cleared    []string        // SBOM ids that reached ClearRescanRequested
}

func (f *fakeStore) ListActiveSBOMs(context.Context) ([]*postgres.SBOM, error) { return f.sboms, nil }
func (f *fakeStore) ListScannableSBOMs(_ context.Context, maxAge time.Duration, expected []string) ([]*postgres.SBOM, error) {
	f.scanMaxAge = maxAge
	f.expected = expected
	return f.sboms, nil
}
func (f *fakeStore) ClearRescanRequested(_ context.Context, sbomID string) error {
	f.cleared = append(f.cleared, sbomID)
	return nil
}
func (f *fakeStore) ApplyScan(_ context.Context, sb *postgres.SBOM, _ string, _ postgres.Versions, _ []data.Vulnerability) error {
	f.applied++
	f.appliedIDs = append(f.appliedIDs, sb.ID)
	return nil
}
func (f *fakeStore) RecordScanFailure(_ context.Context, sbomID, _, stage string, _ error) {
	f.failures = append(f.failures, stage)
	f.failedIDs = append(f.failedIDs, sbomID)
}
func (f *fakeStore) DistinctActiveCVEs(context.Context) ([]string, error)       { return nil, nil }
func (f *fakeStore) UpsertCVEEnrichment(context.Context, []enrich.Record, bool) error { return nil }
func (f *fakeStore) HasSBOMPackages(_ context.Context, sbomID string) (bool, error) {
	return f.hasPkgs[sbomID], nil
}
func (f *fakeStore) UpsertSBOMPackages(_ context.Context, sbomID string, _ []data.PackageLicense) error {
	f.backfilled = append(f.backfilled, sbomID)
	return nil
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
		converter.DefaultRegistry(), nil, DefaultOptions())

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

func TestRunner_AlertEvaluationIsBestEffort(t *testing.T) {
	store := &alertingFakeStore{fakeStore: fakeStore{}, nextErr: errors.New("alert read failed")}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{&fakeScanner{name: "grype", out: grypeDoc}},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("alert evaluation must not fail the scan run: %v", err)
	}
	if store.nextCalls != 1 {
		t.Fatalf("NextAlertEvents calls = %d, want 1", store.nextCalls)
	}
}

func TestRunner_PostureSnapshotRunsAfterAlertsAndIsBestEffort(t *testing.T) {
	store := &postureSnapshotFakeStore{snapshotErr: errors.New("posture snapshot failed")}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{&fakeScanner{name: "grype", out: grypeDoc}},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("posture snapshot must not fail the scan run: %v", err)
	}
	if !slices.Equal(store.steps, []string{"alerts", "posture"}) {
		t.Fatalf("lifecycle steps = %v, want [alerts posture]", store.steps)
	}
}

type postureSnapshotFakeStore struct {
	fakeStore
	steps       []string
	snapshotErr error
}

func (f *postureSnapshotFakeStore) NextAlertEvents(context.Context, string, int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error) {
	f.steps = append(f.steps, "alerts")
	return nil, postgres.AlertPosition{}, true, nil
}

func (f *postureSnapshotFakeStore) CommitAlertBatch(context.Context, string, []postgres.AlertDraft, []postgres.AlertFailure, []postgres.AlertPosition, postgres.AlertPosition) error {
	return nil
}

func (f *postureSnapshotFakeStore) SnapshotTenantPostureStale(context.Context, time.Duration) error {
	f.steps = append(f.steps, "posture")
	return f.snapshotErr
}

type alertingFakeStore struct {
	fakeStore
	nextErr   error
	nextCalls int
}

func (f *alertingFakeStore) NextAlertEvents(context.Context, string, int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error) {
	f.nextCalls++
	return nil, postgres.AlertPosition{}, false, f.nextErr
}

func (f *alertingFakeStore) CommitAlertBatch(context.Context, string, []postgres.AlertDraft, []postgres.AlertFailure, []postgres.AlertPosition, postgres.AlertPosition) error {
	return nil
}

// A minimal CycloneDX SBOM carrying one licensed component, for backfill tests.
const cdxWithLicense = `{"bomFormat":"CycloneDX","components":[
  {"type":"library","name":"openssl","version":"3.0","licenses":[{"license":{"id":"Apache-2.0"}}]}]}`

func TestRunner_BackfillsLicensesWhenAbsent(t *testing.T) {
	store := &fakeStore{
		sboms:   []*postgres.SBOM{{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"}},
		hasPkgs: map[string]bool{}, // nothing captured yet → backfill should run
	}
	sc := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{data: []byte(cdxWithLicense)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(store.backfilled) != 1 || store.backfilled[0] != "s1" {
		t.Errorf("expected s1 to be backfilled, got %v", store.backfilled)
	}
	if len(store.failures) != 0 {
		t.Errorf("backfill should not record failures, got %v", store.failures)
	}
}

func TestRunner_SkipsBackfillWhenPresent(t *testing.T) {
	store := &fakeStore{
		sboms:   []*postgres.SBOM{{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"}},
		hasPkgs: map[string]bool{"s1": true}, // already captured at ingest
	}
	sc := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{data: []byte(cdxWithLicense)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(store.backfilled) != 0 {
		t.Errorf("backfill should be skipped when inventory exists, got %v", store.backfilled)
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
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// The zero-finding anomaly is RECORDED for ops visibility...
	if len(store.failures) != 1 || store.failures[0] != "zero-findings" {
		t.Errorf("want one zero-findings failure, got %v", store.failures)
	}
	// ...but the scan STILL persists (a clean result is valid). Suppressing
	// ApplyScan here left no scan_run, so the SBOM never converged and re-scanned
	// every tick forever — the bug this asserts against.
	if store.applied != 1 {
		t.Errorf("ApplyScan must still run so the SBOM converges, got %d", store.applied)
	}
}

func TestRunner_FetchFailureRecorded(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{{ID: "s1", Format: "cyclonedx", ObjectPath: "x"}}}
	sc := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{err: errors.New("boom")},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), nil, DefaultOptions())

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
		converter.DefaultRegistry(), nil, DefaultOptions())

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

// TestRunner_EnsureDBFailureDropsScanner: a scanner whose DB refresh fails is
// dropped for the run (recorded as an ensure-db failure), and the healthy
// scanner still scans the whole corpus. The run must not abort.
func TestRunner_EnsureDBFailureDropsScanner(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{
		{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
	}}
	bad := &fakeScanner{name: "trivy", out: grypeDoc, ensureErr: errors.New("db download timeout")}
	good := &fakeScanner{name: "grype", out: grypeDoc}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{bad, good},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run must survive one scanner's db failure: %v", err)
	}
	// Healthy scanner scanned the SBOM; failed scanner did not.
	if store.applied != 1 {
		t.Errorf("ApplyScan calls = %d, want 1 (only the healthy scanner)", store.applied)
	}
	if len(store.failures) != 1 || store.failures[0] != "ensure-db" {
		t.Errorf("want one ensure-db failure, got %v", store.failures)
	}
	if len(store.failedIDs) != 1 || store.failedIDs[0] != runFailureSentinel {
		t.Errorf("ensure-db failure should record the run sentinel, got %v", store.failedIDs)
	}
}

// TestRunner_AllScannersFailDBAborts: if every scanner's DB refresh fails, there
// is nothing to scan and Execute returns an error (a genuine whole-run failure).
func TestRunner_AllScannersFailDBAborts(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{{ID: "s1", Format: "cyclonedx", ObjectPath: "x"}}}
	bad := &fakeScanner{name: "grype", ensureErr: errors.New("boom")}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{bad},
		converter.DefaultRegistry(), nil, DefaultOptions())

	if err := r.Execute(context.Background()); err == nil {
		t.Fatal("want error when no scanner survives db refresh")
	}
	if store.applied != 0 {
		t.Errorf("nothing should scan, got %d applied", store.applied)
	}
}

// TestRunner_ScanTimeoutRecorded: a scan that outlives the per-scan budget is
// killed via context and recorded as a scan failure; the batch advances.
func TestRunner_ScanTimeoutRecorded(t *testing.T) {
	store := &fakeStore{sboms: []*postgres.SBOM{
		{ID: "s1", TenantID: "t1", Format: "cyclonedx", PackageCount: 50, ObjectPath: "x"},
	}}
	sc := &fakeScanner{name: "grype", out: grypeDoc, hang: true}
	opts := Options{DBMaxAge: 24 * time.Hour, ScanTimeout: 50 * time.Millisecond}
	r := NewRunner(store, fakeFetcher{data: []byte(`{"bomFormat":"CycloneDX"}`)},
		sbom.NewPassthroughCanonicalizer(), []scanner.Scanner{sc},
		converter.DefaultRegistry(), nil, opts)

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if store.applied != 0 {
		t.Errorf("a timed-out scan must not persist, got %d applied", store.applied)
	}
	if len(store.failures) != 1 || store.failures[0] != "scan" {
		t.Errorf("want one scan failure from timeout, got %v", store.failures)
	}
}

// TestRunner_EnrichmentRefresh verifies the post-scan enrichment step calls the
// enricher with the store's distinct CVEs and upserts what it returns; and that a
// nil enricher (disabled) is a no-op.
func TestRunner_EnrichmentRefresh(t *testing.T) {
	store := &enrichStore{cves: []string{"CVE-2025-1", "CVE-2025-2"}}
	en := &fakeEnricher{recs: []enrich.Record{{CVE: "CVE-2025-1", KEV: true}}, kevAuthoritative: true}
	r := NewRunner(store, fakeFetcher{}, sbom.NewPassthroughCanonicalizer(),
		[]scanner.Scanner{&fakeScanner{name: "grype", out: grypeDoc}},
		converter.DefaultRegistry(), en, DefaultOptions())
	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(en.gotCVEs) != 2 {
		t.Errorf("enricher got %d cves, want 2", len(en.gotCVEs))
	}
	if store.upserted != 1 {
		t.Errorf("upserted %d records, want 1", store.upserted)
	}
	if !store.lastKEVAuthoritative {
		t.Error("kevAuthoritative should propagate true to the store")
	}

	// KEV feed outage (kevAuthoritative=false) must still upsert, but signal the
	// store to preserve KEV flags rather than clear them.
	store3 := &enrichStore{cves: []string{"CVE-2025-1"}}
	en3 := &fakeEnricher{recs: []enrich.Record{{CVE: "CVE-2025-1"}}, kevAuthoritative: false}
	r3 := NewRunner(store3, fakeFetcher{}, sbom.NewPassthroughCanonicalizer(),
		[]scanner.Scanner{&fakeScanner{name: "grype", out: grypeDoc}},
		converter.DefaultRegistry(), en3, DefaultOptions())
	if err := r3.Execute(context.Background()); err != nil {
		t.Fatalf("run (kev outage): %v", err)
	}
	if store3.lastKEVAuthoritative {
		t.Error("a KEV outage must propagate kevAuthoritative=false so flags are preserved")
	}

	// Nil enricher: enrichment skipped, no calls.
	store2 := &enrichStore{cves: []string{"CVE-2025-1"}}
	r2 := NewRunner(store2, fakeFetcher{}, sbom.NewPassthroughCanonicalizer(),
		[]scanner.Scanner{&fakeScanner{name: "grype", out: grypeDoc}},
		converter.DefaultRegistry(), nil, DefaultOptions())
	if err := r2.Execute(context.Background()); err != nil {
		t.Fatalf("run (nil enricher): %v", err)
	}
	if store2.upserted != 0 {
		t.Errorf("nil enricher should not upsert, got %d", store2.upserted)
	}
}

type enrichStore struct {
	cves         []string
	upserted     int
	lastKEVAuthoritative bool // captured from the most recent UpsertCVEEnrichment
}

func (s *enrichStore) ListActiveSBOMs(context.Context) ([]*postgres.SBOM, error) { return nil, nil }
func (s *enrichStore) ListScannableSBOMs(context.Context, time.Duration, []string) ([]*postgres.SBOM, error) {
	return nil, nil
}
func (s *enrichStore) ApplyScan(context.Context, *postgres.SBOM, string, postgres.Versions, []data.Vulnerability) error {
	return nil
}
func (s *enrichStore) ClearRescanRequested(context.Context, string) error               { return nil }
func (s *enrichStore) RecordScanFailure(context.Context, string, string, string, error) {}
func (s *enrichStore) HasSBOMPackages(context.Context, string) (bool, error)            { return true, nil }
func (s *enrichStore) UpsertSBOMPackages(context.Context, string, []data.PackageLicense) error {
	return nil
}
func (s *enrichStore) DistinctActiveCVEs(context.Context) ([]string, error) { return s.cves, nil }
func (s *enrichStore) UpsertCVEEnrichment(_ context.Context, recs []enrich.Record, kevAuthoritative bool) error {
	s.upserted += len(recs)
	s.lastKEVAuthoritative = kevAuthoritative
	return nil
}

type fakeEnricher struct {
	recs             []enrich.Record
	gotCVEs          []string
	kevAuthoritative bool
}

func (f *fakeEnricher) Fetch(_ context.Context, cves []string) ([]enrich.Record, bool, error) {
	f.gotCVEs = cves
	return f.recs, f.kevAuthoritative, nil
}

// ── fake scanner plumbing ─────────────────────────────────────────────────────

type fakeScanner struct {
	name      string
	out       string
	panicOn   string // if non-empty, ScanSBOM panics when the SBOM's id appears in the temp path
	ensureErr error  // if non-nil, EnsureDB fails (simulates a DB-refresh outage)
	hang      bool   // if true, ScanSBOM blocks until ctx is cancelled (simulates a hung scan)
}

func (f *fakeScanner) Name() string      { return f.name }
func (f *fakeScanner) Version() string   { return "test-1.0" }
func (f *fakeScanner) DBVersion() string { return "db-test" }
func (f *fakeScanner) EnsureDB(context.Context, time.Duration) error {
	return f.ensureErr
}
func (f *fakeScanner) IsAvailable() bool     { return true }
func (f *fakeScanner) ConverterName() string { return f.name }
func (f *fakeScanner) ScanSBOM(ctx context.Context, sbomPath, outPath string) error {
	// writeTemp names the file "devradar-sbom-<id>-*.json", so the poison SBOM's
	// id shows up in the path — match on it to simulate a scanner faulting on one
	// specific untrusted input.
	if f.panicOn != "" && strings.Contains(sbomPath, f.panicOn) {
		panic("boom: poison SBOM")
	}
	if f.hang {
		<-ctx.Done() // block until the per-scan timeout fires
		return ctx.Err()
	}
	return os.WriteFile(outPath, []byte(f.out), 0o600)
}
