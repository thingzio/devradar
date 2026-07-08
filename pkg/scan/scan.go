// Package scan is the daily scan job's core loop: for each active SBOM,
// canonicalize to CycloneDX, run each scanner, normalize, and apply the delta.
// It is factored out of cmd/devradar-scan so it can be unit-tested with injected
// fakes (fetcher, scanners, store) rather than only end-to-end.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/converter"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/enrich"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/sbom"
	"github.com/thingzio/devradar/pkg/scanner"
)

// zeroFindingFloor is the package count above which a scanner returning zero
// findings is treated as a failure (a conversion/DB regression), not a clean
// image. Below it, a genuinely tiny image can legitimately have no CVEs.
const zeroFindingFloor = 5

// Fetcher retrieves the raw SBOM bytes for a stored SBOM (GCS in production).
type Fetcher interface {
	Fetch(ctx context.Context, objectPath string) ([]byte, error)
}

// Store is the subset of the postgres store the scan loop needs.
type Store interface {
	ListActiveSBOMs(ctx context.Context) ([]*postgres.SBOM, error)
	// ListScannableSBOMs returns active SBOMs due for a scan given a staleness
	// window (never-scanned or last-scanned older than maxAge). maxAge 0 = all.
	ListScannableSBOMs(ctx context.Context, maxAge time.Duration) ([]*postgres.SBOM, error)
	ApplyScan(ctx context.Context, sb *postgres.SBOM, scanner string, ver postgres.Versions, vulns []data.Vulnerability) error
	RecordScanFailure(ctx context.Context, sbomID, scanner, stage string, cause error)
	DistinctActiveCVEs(ctx context.Context) ([]string, error)
	UpsertCVEEnrichment(ctx context.Context, recs []enrich.Record) error
	// License-inventory backfill: HasSBOMPackages gates re-extraction so SBOMs
	// ingested before license capture existed are populated once, on their next
	// scan, without re-extracting the whole fleet nightly.
	HasSBOMPackages(ctx context.Context, sbomID string) (bool, error)
	UpsertSBOMPackages(ctx context.Context, sbomID string, pkgs []data.PackageLicense) error
}

// Enricher fetches CVE risk context (EPSS + KEV). Injectable so the scan loop is
// testable without live feeds.
type Enricher interface {
	Fetch(ctx context.Context, cves []string) ([]enrich.Record, error)
}

// Options configures a scan run.
type Options struct {
	DBMaxAge    time.Duration // refresh a scanner DB older than this at job start
	ScanTimeout time.Duration // per-SBOM-per-scanner wall-clock budget; 0 = no limit
	// ScanMaxAge is the staleness window for work selection: an SBOM is scanned
	// only if it has never been scanned or its last scan is older than this. It
	// lets the scheduler run frequently (low submission-to-result latency) while
	// each SBOM is scanned at most a bounded number of times per day. 0 disables
	// the filter (every active SBOM every run — the legacy daily-full-pass).
	ScanMaxAge time.Duration
}

// DefaultOptions returns sensible defaults. ScanTimeout bounds a single
// SBOM×scanner invocation so one hung/pathological scan converts to a recorded
// failure and the batch advances, rather than starving every later SBOM until
// the whole job's Cloud Run timeout expires. ScanMaxAge (12h) pairs with a
// frequent scheduler (every ~15 min): new SBOMs are picked up on the next run,
// but a given SBOM is rescanned at most ~twice a day.
func DefaultOptions() Options {
	return Options{DBMaxAge: 24 * time.Hour, ScanTimeout: 10 * time.Minute, ScanMaxAge: 12 * time.Hour}
}

// runFailureSentinel is the sbom_id recorded for whole-run (not per-SBOM)
// failures such as a scanner's DB refresh failing at job start. devradar_scan_failure.sbom_id
// is NOT NULL, so run-level failures need a stable non-empty marker to stay queryable.
const runFailureSentinel = "-"

// readyScanner is a scanner that passed EnsureDB, paired with the version axes
// captured once at job start. The DB is frozen for the run, so these values are
// constant across every SBOM — capturing them here avoids re-shelling out
// (grype db status / trivy version) for every SBOM×scanner.
type readyScanner struct {
	scanner.Scanner
	ver postgres.Versions
}

// Runner ties the pieces together.
type Runner struct {
	store    Store
	fetch    Fetcher
	canon    sbom.Canonicalizer
	scanners []scanner.Scanner
	convs    *converter.Registry
	enricher Enricher // nil disables enrichment
	opts     Options
}

// NewRunner builds a Runner. scanners should be the *available* set. enricher may
// be nil to skip CVE risk enrichment.
func NewRunner(store Store, fetch Fetcher, canon sbom.Canonicalizer, scanners []scanner.Scanner, convs *converter.Registry, enricher Enricher, opts Options) *Runner {
	return &Runner{store: store, fetch: fetch, canon: canon, scanners: scanners, convs: convs, enricher: enricher, opts: opts}
}

// Run is the entry point for the scan binary: it wires the store, blob fetcher,
// scanners, and canonicalizer from the environment, then executes one scan pass.
// cmd/devradar-scan is a thin shell around this.
func Run(ctx context.Context, opts Options) error {
	store, err := postgres.New(ctx, config.DatabaseURL(), postgres.ScanPoolConfig())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = store.Close() }()

	blobs, err := gcs.FromEnv(ctx)
	if err != nil {
		return fmt.Errorf("blob store: %w", err)
	}
	defer func() { _ = blobs.Close() }()

	scanners := scanner.DefaultRegistry().Available()
	if len(scanners) == 0 {
		slog.Warn("no scanners available on PATH; nothing to do")
		return nil
	}

	// Prefer the syft-backed canonicalizer (SPDX -> CycloneDX); fall back to
	// pass-through (CycloneDX-only) if syft isn't installed.
	var canon sbom.Canonicalizer
	if sc, ok := sbom.NewSyftCanonicalizer(); ok {
		slog.Info("canonicalizer ready", "backend", sc.Version())
		canon = sc
	} else {
		slog.Warn("syft not found; canonicalizer is pass-through (SPDX SBOMs will fail to scan)")
		canon = sbom.NewPassthroughCanonicalizer()
	}

	var enricher Enricher
	if config.EnrichEnabled() {
		enricher = enrich.New()
	}

	return NewRunner(store, blobs, canon, scanners, converter.DefaultRegistry(), enricher, opts).Execute(ctx)
}

// Execute runs one full pass over all active SBOMs. It returns an error only for
// whole-run failures (DB prep for ALL scanners, listing); per-SBOM and
// per-scanner failures are recorded to the failure surface and do not abort the
// run.
func (r *Runner) Execute(ctx context.Context) error {
	// Freeze each scanner's DB once, up front: refresh if stale, then every scan
	// in this run shares that version — which is what keeps cause attribution
	// honest (no DB drift mid-run). A scanner whose DB refresh fails (e.g. a
	// transient network blip) is DROPPED for this run, not fatal: the healthy
	// scanner(s) still scan the whole corpus. We abort only if none survive.
	canonVer := r.canon.Version()
	ready := make([]readyScanner, 0, len(r.scanners))
	for _, sc := range r.scanners {
		if err := sc.EnsureDB(ctx, r.opts.DBMaxAge); err != nil {
			// Record it against the run sentinel so it's queryable, then continue.
			r.recordFailure(ctx, runFailureSentinel, sc.Name(), "ensure-db", err)
			continue
		}
		// Capture the version axes once: the DB is now frozen, so these are
		// constant for the run — no need to re-probe per SBOM.
		rs := readyScanner{Scanner: sc, ver: postgres.Versions{
			DBVersion:            sc.DBVersion(),
			ScannerVersion:       sc.Version(),
			CanonicalizerVersion: canonVer,
		}}
		ready = append(ready, rs)
		slog.Info("scanner ready", "scanner", sc.Name(),
			"version", rs.ver.ScannerVersion, "db_version", rs.ver.DBVersion)
	}
	if len(ready) == 0 {
		return fmt.Errorf("no scanners available after db refresh (%d attempted)", len(r.scanners))
	}

	sboms, err := r.store.ListScannableSBOMs(ctx, r.opts.ScanMaxAge)
	if err != nil {
		return fmt.Errorf("list scannable sboms: %w", err)
	}
	slog.Info("scan run starting", "sbom_count", len(sboms), "scanners", len(ready),
		"scan_max_age", r.opts.ScanMaxAge)

	scanned := 0
	for _, sb := range sboms {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.scanOne(ctx, sb, ready)
		scanned++
	}
	slog.Info("scan run complete", "scanned", scanned)

	// Refresh CVE risk enrichment (EPSS + KEV) after findings are written, so the
	// distinct-CVE target set includes anything this run just discovered. Additive
	// overlay: a failure here degrades context, never the scan — log and move on.
	r.refreshEnrichment(ctx)
	return nil
}

// refreshEnrichment pulls EPSS + KEV for the CVEs currently in findings and
// upserts them. Best-effort: enrichment is a read-time overlay, so a feed outage
// leaves prior (possibly stale) data in place rather than failing the run.
func (r *Runner) refreshEnrichment(ctx context.Context) {
	if r.enricher == nil {
		return
	}
	cves, err := r.store.DistinctActiveCVEs(ctx)
	if err != nil {
		slog.Warn("enrichment skipped: list cves", "error", err)
		return
	}
	if len(cves) == 0 {
		return
	}
	recs, err := r.enricher.Fetch(ctx, cves)
	if err != nil {
		slog.Warn("enrichment fetch failed", "error", err)
		return
	}
	if err := r.store.UpsertCVEEnrichment(ctx, recs); err != nil {
		slog.Warn("enrichment upsert failed", "error", err)
		return
	}
	kev := 0
	for _, x := range recs {
		if x.KEV {
			kev++
		}
	}
	slog.Info("enrichment refreshed", "cves", len(cves), "records", len(recs), "kev", kev)
}

// scanOne processes a single SBOM across all scanners. All failures are recorded
// and swallowed so one bad SBOM never stops the batch. The deferred recover is
// the batch-level guarantee: the SBOM is attacker-controllable untrusted input,
// so a panic (nil deref, a gabs edge case, a malformed document) is turned into
// a recorded panic-stage failure rather than unwinding through the run loop and
// crashing the whole daily job — which would then retry onto the same poison
// SBOM. Per-scanner panics are recovered separately in scanWith so one scanner
// faulting still lets the other run on the same SBOM.
func (r *Runner) scanOne(ctx context.Context, sb *postgres.SBOM, ready []readyScanner) {
	defer func() {
		if rec := recover(); rec != nil {
			r.recordFailure(ctx, sb.ID, "", "panic", fmt.Errorf("panic: %v", rec))
		}
	}()

	raw, err := r.fetch.Fetch(ctx, sb.ObjectPath)
	if err != nil {
		r.recordFailure(ctx, sb.ID, "", "download", err)
		return
	}

	// Backfill the license inventory for SBOMs ingested before license capture
	// existed. Runs off the ORIGINAL bytes (ExtractPackages reads both formats
	// natively — no canonicalization needed) and only when nothing is stored yet,
	// so it's a one-time write per SBOM that converges after the first post-deploy
	// run. Best-effort and fully isolated: a failure here is a recorded
	// license-extract failure that never touches the vulnerability scan below.
	r.backfillLicenses(ctx, sb, raw)

	// Canonicalize to CycloneDX so every scanner sees a format it reads reliably.
	cdx, err := r.canon.Canonicalize(ctx, raw, sbom.Format(sb.Format))
	if err != nil {
		r.recordFailure(ctx, sb.ID, "", "canonicalize", err)
		return
	}
	local, cleanup, err := writeTemp(sb.ID, cdx)
	if err != nil {
		r.recordFailure(ctx, sb.ID, "", "canonicalize", err)
		return
	}
	defer cleanup()

	for _, sc := range ready {
		r.scanWith(ctx, sb, sc, local)
	}
}

// backfillLicenses captures the per-package license inventory for an SBOM that
// predates license capture. It is a one-time, idempotent write: HasSBOMPackages
// gates it so the extraction runs only until the inventory exists, and
// UpsertSBOMPackages is ON CONFLICT DO NOTHING besides. Best-effort — every
// failure path (existence check, extraction yielding nothing, upsert) is a
// recorded license-extract failure or a silent skip, never affecting the scan.
func (r *Runner) backfillLicenses(ctx context.Context, sb *postgres.SBOM, raw []byte) {
	has, err := r.store.HasSBOMPackages(ctx, sb.ID)
	if err != nil {
		r.recordFailure(ctx, sb.ID, "", "license-extract", err)
		return
	}
	if has {
		return // already captured (at ingest, or a prior run)
	}
	pkgs := sbom.ExtractPackages(raw)
	if len(pkgs) == 0 {
		return // nothing to store (no components, or unparseable license data)
	}
	if err := r.store.UpsertSBOMPackages(ctx, sb.ID, pkgs); err != nil {
		r.recordFailure(ctx, sb.ID, "", "license-extract", err)
		return
	}
	slog.Info("license inventory backfilled", "sbom_id", sb.ID, "packages", len(pkgs))
}

func (r *Runner) scanWith(ctx context.Context, sb *postgres.SBOM, sc readyScanner, sbomPath string) {
	// Recover per-scanner so a fault in one scanner (or its converter) is a
	// recorded failure that still lets the other scanner run on this SBOM.
	defer func() {
		if rec := recover(); rec != nil {
			r.recordFailure(ctx, sb.ID, sc.Name(), "panic", fmt.Errorf("panic: %v", rec))
		}
	}()

	// Bound this single scan: a hung/pathological scanner invocation on one
	// untrusted SBOM must not starve every SBOM after it. On timeout, ScanSBOM's
	// exec is killed via ctx and this becomes a recorded "scan" failure.
	scanCtx := ctx
	if r.opts.ScanTimeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, r.opts.ScanTimeout)
		defer cancel()
	}

	out, cleanup, err := tempOut(sb.ID, sc.Name())
	if err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	defer cleanup()

	if err := sc.ScanSBOM(scanCtx, sbomPath, out); err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	doc, err := gabs.ParseJSONFile(out)
	if err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "parse", err)
		return
	}
	conv, err := r.convs.Detect(doc)
	if err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "detect", err)
		return
	}
	vulns, err := conv.Convert(scanCtx, doc)
	if err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "convert", err)
		return
	}

	// Tripwire: zero findings on a non-trivial SBOM signals a conversion/DB
	// regression (e.g. Trivy on un-canonicalized SPDX, or a missing DB), not a
	// clean image. Record it rather than writing a misleading "all resolved".
	if len(vulns) == 0 && sb.PackageCount > zeroFindingFloor {
		r.recordFailure(ctx, sb.ID, sc.Name(), "zero-findings",
			fmt.Errorf("0 findings on sbom with %d packages", sb.PackageCount))
		return
	}

	// ver was captured once at job start (DB is frozen for the run).
	if err := r.store.ApplyScan(ctx, sb, sc.Name(), sc.ver, vulns); err != nil {
		r.recordFailure(ctx, sb.ID, sc.Name(), "persist", err)
	}
}

// recordFailure persists a per-SBOM/per-scanner failure to the queryable failure
// surface AND emits a warning to the job log. Failures are otherwise invisible
// (no stdout, table-only), so a scanner silently returning nothing — e.g. Trivy
// finding 0 CVEs on an EOL distro it has no advisories for — would vanish from
// ops view. The log line makes it visible in Cloud Run; the table row makes it
// queryable per-SBOM via GET /v1/sboms/{id}/failures.
func (r *Runner) recordFailure(ctx context.Context, sbomID, scanner, stage string, cause error) {
	slog.Warn("scan failure",
		"sbom_id", sbomID, "scanner", scanner, "stage", stage, "error", cause)
	r.store.RecordScanFailure(ctx, sbomID, scanner, stage, cause)
}

// writeTemp writes b to a temp file and returns its path + a cleanup func.
func writeTemp(id string, b []byte) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "devradar-sbom-"+safe(id)+"-*.json")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// tempOut returns a path for scanner output + a cleanup func.
func tempOut(id, scanner string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "devradar-out-"+safe(id)+"-"+scanner+"-*.json")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	_ = f.Close()
	return name, func() { _ = os.Remove(name) }, nil
}

// safe strips path separators from an id used in a temp filename.
func safe(s string) string {
	return filepath.Base(s)
}
