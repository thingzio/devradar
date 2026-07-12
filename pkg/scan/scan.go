// Package scan is the daily scan job's core loop: for each active SBOM,
// canonicalize to CycloneDX, run each scanner, normalize, and apply the delta.
// It is factored out of cmd/devradar-scan so it can be unit-tested with injected
// fakes (fetcher, scanners, store) rather than only end-to-end.
package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/alert"
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

// maxScannerOutputBytes bounds how much scanner-report JSON we read into memory
// before parsing. Finding volume scales with the untrusted SBOM's package count,
// so a hostile SBOM could drive an arbitrarily large report and OOM the job (on
// Cloud Run, /tmp is tmpfs, so the file itself is already in memory). 256 MiB is
// far above any legitimate grype/trivy report yet caps the blast radius.
const maxScannerOutputBytes = 256 << 20

// Fetcher retrieves the raw SBOM bytes for a stored SBOM (GCS in production).
type Fetcher interface {
	Fetch(ctx context.Context, objectPath string) ([]byte, error)
}

// Store is the subset of the postgres store the scan loop needs.
type Store interface {
	ListActiveSBOMs(ctx context.Context) ([]*postgres.SBOM, error)
	// ListScannableSBOMs returns active SBOMs due for a scan given a staleness
	// window and the set of expected scanners. An SBOM is due if any expected
	// scanner lacks a run within maxAge (per-scanner freshness), or a rescan was
	// requested. maxAge 0 or empty expected = every active SBOM.
	ListScannableSBOMs(ctx context.Context, maxAge time.Duration, expected []string) ([]*postgres.SBOM, error)
	ApplyScan(ctx context.Context, sb *postgres.SBOM, scanner string, ver postgres.Versions, vulns []data.Vulnerability) error
	// ClearRescanRequested consumes an operator force-rescan marker once the
	// whole SBOM has been scanned by every expected scanner.
	ClearRescanRequested(ctx context.Context, sbomID string) error
	RecordScanFailure(ctx context.Context, sbomID, scanner, stage string, cause error)
	// Per-(SBOM, scanner) failure backoff: ScannerAttemptDue gates whether a pair
	// may be scanned this tick; RecordScannerAttemptFailure schedules the next
	// attempt with exponential backoff (and quarantines past a threshold);
	// ClearScannerAttempt resets the state after a success.
	ScannerAttemptDue(ctx context.Context, sbomID, scanner string) (bool, error)
	RecordScannerAttemptFailure(ctx context.Context, sbomID, scanner, errMsg string) error
	ClearScannerAttempt(ctx context.Context, sbomID, scanner string) error
	DistinctActiveCVEs(ctx context.Context) ([]string, error)
	// EnrichmentFreshWithin reports whether any enrichment row was updated within
	// the window — the cadence gate so the daily-updating EPSS/KEV feeds are not
	// re-fetched on every ~15-min scan tick.
	EnrichmentFreshWithin(ctx context.Context, within time.Duration) (bool, error)
	// UpsertCVEEnrichment writes enrichment records. kevAuthoritative gates whether
	// a KEV=false in a record may clear a stored KEV flag — false (a KEV feed
	// outage) preserves existing flags rather than wiping them.
	UpsertCVEEnrichment(ctx context.Context, recs []enrich.Record, kevAuthoritative bool) error
	// License-inventory backfill: HasSBOMPackages gates re-extraction so SBOMs
	// ingested before license capture existed are populated once, on their next
	// scan, without re-extracting the whole fleet nightly.
	HasSBOMPackages(ctx context.Context, sbomID string) (bool, error)
	UpsertSBOMPackages(ctx context.Context, sbomID string, pkgs []data.PackageLicense) error
}

// Enricher fetches CVE risk context (EPSS + KEV). Injectable so the scan loop is
// testable without live feeds.
type Enricher interface {
	Fetch(ctx context.Context, cves []string) (recs []enrich.Record, kevAuthoritative bool, err error)
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
	if err := config.Validate(); err != nil {
		return err
	}
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
		// FAIL LOUDLY, not nil. A scan job with no scanner binary on PATH is a
		// broken deploy (bad image, PATH misconfig), not "nothing to do" — returning
		// nil exits 0 and the Cloud Run Job reports success, masking the outage.
		// An error surfaces it in job status and ops alerting.
		return fmt.Errorf("no scanners available on PATH (expected grype and/or trivy); check the scan-job image")
	}

	// Prefer the syft-backed canonicalizer (SPDX -> CycloneDX); fall back to
	// pass-through (CycloneDX-only) if syft isn't installed.
	var canon sbom.Canonicalizer
	syftCanon, syftOK := sbom.NewSyftCanonicalizer()
	if syftOK {
		slog.Info("canonicalizer ready", "backend", syftCanon.Version())
		canon = syftCanon
	} else {
		slog.Warn("syft not found; canonicalizer is pass-through (SPDX SBOMs will fail to scan)")
		canon = sbom.NewPassthroughCanonicalizer()
	}

	// Complete-toolchain gate (opt-in, for production). A partial toolchain scans
	// but silently under-covers: one scanner loses the cross-check, and a missing
	// syft makes every SPDX SBOM fail. When required, refuse to start on anything
	// less than grype + trivy + syft, so a mis-provisioned image fails loudly at
	// boot instead of quietly degrading. Default off keeps local/dev flexible.
	if config.RequireCompleteToolchain() {
		if err := requireCompleteToolchain(scanners, syftOK); err != nil {
			return err
		}
	}

	var enricher Enricher
	if config.EnrichEnabled() {
		enricher = enrich.New()
	}

	return NewRunner(store, blobs, canon, scanners, converter.DefaultRegistry(), enricher, opts).Execute(ctx)
}

// requireCompleteToolchain returns an error unless the full pinned toolchain is
// present: both grype and trivy (running two is what gives the cross-scanner
// cataloger-disagreement signal) and a working syft canonicalizer (SPDX support).
// It reports every missing component in one error so an operator fixes the image
// in a single pass.
func requireCompleteToolchain(available []scanner.Scanner, syftOK bool) error {
	have := make(map[string]bool, len(available))
	for _, sc := range available {
		have[sc.Name()] = true
	}
	var missing []string
	for _, want := range []string{"grype", "trivy"} {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	if !syftOK {
		missing = append(missing, "syft")
	}
	if len(missing) > 0 {
		return fmt.Errorf("incomplete scanner toolchain: missing %v "+
			"(DEVRADAR_REQUIRE_COMPLETE_TOOLCHAIN is set); check the scan-job image", missing)
	}
	return nil
}

// scanDue refreshes each scanner's vuln DB and scans the due SBOMs. It is called
// only when the cheap pre-check found work, so the expensive DB refresh never
// runs on an idle tick. `pending` is the work list computed with the full scanner
// name set; `allNames` is that set.
//
// Freezing each scanner's DB once, up front, is what keeps cause attribution
// honest (no DB drift mid-run). A scanner whose DB refresh fails (a transient
// blip) is DROPPED for this run, not fatal: the healthy scanner(s) still scan the
// whole corpus. We abort only if none survive.
func (r *Runner) scanDue(ctx context.Context, pending []*postgres.SBOM, allNames []string) error {
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

	// The pre-check used the full name set. If every configured scanner became
	// ready, that work list is exactly right. If a scanner DROPPED at EnsureDB, the
	// due set may have shrunk (an SBOM held due only for the now-absent scanner is
	// no longer expected this run), so re-list with the precise ready set to keep
	// per-scanner freshness exact. Only pay the extra query on the (rare) drop path.
	sboms := pending
	if len(ready) < len(allNames) {
		expected := make([]string, len(ready))
		for i, sc := range ready {
			expected[i] = sc.Name()
		}
		var err error
		if sboms, err = r.store.ListScannableSBOMs(ctx, r.opts.ScanMaxAge, expected); err != nil {
			return fmt.Errorf("list scannable sboms: %w", err)
		}
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
	return nil
}

// Execute runs one full pass over all active SBOMs. It returns an error only for
// whole-run failures (DB prep for ALL scanners, listing); per-SBOM and
// per-scanner failures are recorded to the failure surface and do not abort the
// run.
func (r *Runner) Execute(ctx context.Context) error {
	// Cheap pre-check BEFORE touching any scanner DB: is anything due for ANY
	// configured scanner? This uses only scanner NAMES (no EnsureDB), so on an idle
	// tick we skip the expensive vulnerability-DB refresh (grype+trivy each pull a
	// large DB) entirely. The scheduler fires ~96×/day but few ticks have work;
	// downloading the DBs only when there is actual work removes almost all of that
	// egress and startup cost. Safe because ListScannableSBOMs is monotonic in the
	// expected set — an SBOM is due if ANY expected scanner lacks a recent run — so
	// the full-name set is a SUPERSET of what any ready subset would return: empty
	// here means empty for certain. (GCS-cached DBs are a possible later upgrade.)
	allNames := make([]string, len(r.scanners))
	for i, sc := range r.scanners {
		allNames[i] = sc.Name()
	}
	pending, err := r.store.ListScannableSBOMs(ctx, r.opts.ScanMaxAge, allNames)
	if err != nil {
		return fmt.Errorf("list scannable sboms: %w", err)
	}

	if len(pending) > 0 {
		if err := r.scanDue(ctx, pending, allNames); err != nil {
			return err
		}
	} else {
		slog.Info("scan run: no SBOMs due; skipping vulnerability DB refresh")
	}

	// Fleet-wide maintenance runs every tick regardless of scan work — each has its
	// own cadence gate where relevant (enrichment is daily-gated; posture snapshots
	// are interval-gated). These are cheap and do not download scanner DBs, so they
	// stay on every tick even when nothing was scanned.

	// Refresh CVE risk enrichment (EPSS + KEV) after findings are written, so the
	// distinct-CVE target set includes anything this run just discovered. Additive
	// overlay: a failure here degrades context, never the scan — log and move on.
	r.refreshEnrichment(ctx)

	// Browser alerts consume the committed event stream after enrichment so KEV
	// matching sees the freshest available overlay. This boundary is optional for
	// focused scan fakes and strictly best-effort: alert failures never change the
	// scan result or couple notification concerns to ApplyScan.
	if alertStore, ok := r.store.(alert.Store); ok {
		result, err := (alert.Evaluator{Store: alertStore}).Evaluate(ctx)
		if err != nil {
			slog.Warn("alert evaluation failed", "error", err)
		} else {
			slog.Info("alert evaluation complete", "examined", result.Examined,
				"matched", result.Matched, "failures", result.Failures)
		}
	}

	// Capture exact daily tenant vulnerability debt after findings, enrichment,
	// and alerts have converged. Gated to at most once per
	// PostureSnapshotMinInterval: the projection is a full-fleet scan whose result
	// is deduplicated to one row per tenant per day, so recomputing it every tick
	// is wasted work. The optional boundary keeps focused scan fakes small;
	// snapshot failure is best-effort and never changes the scan result.
	if snapshotter, ok := r.store.(interface {
		SnapshotTenantPostureStale(context.Context, time.Duration) error
	}); ok {
		if err := snapshotter.SnapshotTenantPostureStale(ctx, config.PostureSnapshotMinInterval()); err != nil {
			slog.Warn("tenant posture snapshot failed", "error", err)
		}
	}

	// Record a daily platform snapshot for the admin dashboard's trend deltas, so
	// they accrue even on days with no dashboard visit. Best-effort and optional:
	// only the concrete postgres store implements it, and a failure never affects
	// the scan outcome.
	if snapshotter, ok := r.store.(interface {
		SnapshotPlatformStats(context.Context) (*postgres.PlatformSnapshot, error)
	}); ok {
		if _, err := snapshotter.SnapshotPlatformStats(ctx); err != nil {
			slog.Warn("platform stats snapshot failed", "error", err)
		}
	}

	// Reclaim dead ephemeral auth rows (expired login tokens + sessions). There is
	// no cron, so the frequent scan job is the natural home for this bounded
	// housekeeping. Optional boundary + best-effort: expired rows are already
	// rejected at read time, so a failure here only defers reclamation and never
	// affects auth correctness or the scan outcome.
	if purger, ok := r.store.(interface {
		PurgeExpiredAuth(context.Context) error
	}); ok {
		if err := purger.PurgeExpiredAuth(ctx); err != nil {
			slog.Warn("purge expired auth rows failed", "error", err)
		}
	}
	return nil
}

// refreshEnrichment pulls EPSS + KEV for the CVEs currently in findings and
// upserts them. Best-effort: enrichment is a read-time overlay, so a feed outage
// leaves prior (possibly stale) data in place rather than failing the run.
func (r *Runner) refreshEnrichment(ctx context.Context) {
	if r.enricher == nil {
		return
	}
	// Cadence gate: EPSS and KEV publish about once a day, but the scan job runs
	// every ~15 min. Re-fetching the whole fleet's enrichment every tick is wasted
	// work and needless feed load, so skip when enrichment was refreshed within the
	// min-interval. Mirrors the posture-snapshot gate. 0 disables the gate.
	if iv := config.EnrichMinInterval(); iv > 0 {
		fresh, err := r.store.EnrichmentFreshWithin(ctx, iv)
		if err != nil {
			slog.Warn("enrichment freshness check failed; refreshing anyway", "error", err)
		} else if fresh {
			return // refreshed recently enough
		}
	}
	cves, err := r.store.DistinctActiveCVEs(ctx)
	if err != nil {
		slog.Warn("enrichment skipped: list cves", "error", err)
		return
	}
	if len(cves) == 0 {
		return
	}
	recs, kevAuthoritative, err := r.enricher.Fetch(ctx, cves)
	if err != nil {
		slog.Warn("enrichment fetch failed", "error", err)
		return
	}
	if !kevAuthoritative {
		slog.Warn("enrichment: KEV feed unavailable this run; preserving existing KEV flags")
	}
	if err := r.store.UpsertCVEEnrichment(ctx, recs, kevAuthoritative); err != nil {
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
	// The syft-backed canonicalizer shells out to `syft convert` on the SAME
	// attacker-controlled bytes the scanners see, so it gets the SAME per-SBOM
	// timeout as scanWith — otherwise a crafted SPDX that hangs `syft convert`
	// stalls the entire sequential batch until the whole-job Cloud Run timeout,
	// re-opening the batch-starvation hole the scanner timeout closes. On timeout
	// the exec is killed via ctx and this becomes a recorded canonicalize failure.
	canonCtx := ctx
	if r.opts.ScanTimeout > 0 {
		var cancel context.CancelFunc
		canonCtx, cancel = context.WithTimeout(ctx, r.opts.ScanTimeout)
		defer cancel()
	}
	cdx, err := r.canon.Canonicalize(canonCtx, raw, sbom.Format(sb.Format))
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

	// Consume any operator "force rescan" marker only after every scanner has been
	// attempted, so a forced rescan covers the whole SBOM (all scanners) before the
	// override is cleared — not just the first scanner in the loop. Best-effort: a
	// failed clear leaves the marker set, so the SBOM is picked up again next run
	// (at worst one extra rescan), which is safe.
	if err := r.store.ClearRescanRequested(ctx, sb.ID); err != nil {
		slog.Warn("clear rescan marker", "sbom_id", sb.ID, "error", err)
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
	// Skip a pair that is currently backing off (recent repeated failures) or
	// quarantined. This is the fix for the retry storm: a persistently-failing
	// (SBOM, scanner) pair would otherwise be re-attempted every ~15-min tick
	// forever — and drag the healthy scanner along, since work selection is
	// per-SBOM. On a DB error we fail OPEN (attempt anyway): backoff is an
	// optimization, never a correctness gate.
	if due, err := r.store.ScannerAttemptDue(ctx, sb.ID, sc.Name()); err != nil {
		slog.Warn("scanner backoff check failed; attempting anyway",
			"sbom_id", sb.ID, "scanner", sc.Name(), "error", err)
	} else if !due {
		slog.Debug("scanner skipped (backing off)", "sbom_id", sb.ID, "scanner", sc.Name())
		return
	}

	// Recover per-scanner so a fault in one scanner (or its converter) is a
	// recorded failure that still lets the other scanner run on this SBOM. A panic
	// also counts as a failure for backoff.
	defer func() {
		if rec := recover(); rec != nil {
			r.recordScannerFailure(ctx, sb.ID, sc.Name(), "panic", fmt.Errorf("panic: %v", rec))
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
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	defer cleanup()

	if err := sc.ScanSBOM(scanCtx, sbomPath, out); err != nil {
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	doc, err := parseJSONBounded(out, maxScannerOutputBytes)
	if err != nil {
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "parse", err)
		return
	}
	conv, err := r.convs.Detect(doc)
	if err != nil {
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "detect", err)
		return
	}
	vulns, err := conv.Convert(scanCtx, doc)
	if err != nil {
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "convert", err)
		return
	}

	// Tripwire: zero findings on a non-trivial SBOM is WORTH SURFACING — it can
	// signal a conversion/DB regression (e.g. Trivy on un-canonicalized SPDX, or a
	// missing DB). But it can equally be a genuinely clean image (distroless,
	// minimal, well-patched bases routinely carry >5 packages and 0 CVEs). So we
	// record the anomaly for ops visibility but STILL persist the scan below —
	// a clean result is a valid result. NOTE: this is NOT counted as a backoff
	// failure (it does not gate retries) — a clean image must keep converging.
	if len(vulns) == 0 && sb.PackageCount > zeroFindingFloor {
		r.recordFailure(ctx, sb.ID, sc.Name(), "zero-findings",
			fmt.Errorf("0 findings on sbom with %d packages (recorded; may be a clean image)", sb.PackageCount))
	}

	// ver was captured once at job start (DB is frozen for the run).
	if err := r.store.ApplyScan(ctx, sb, sc.Name(), sc.ver, vulns); err != nil {
		r.recordScannerFailure(ctx, sb.ID, sc.Name(), "persist", err)
		return
	}

	// Success: clear any backoff state so a recovered pair returns to the normal
	// cadence immediately. Best-effort.
	if err := r.store.ClearScannerAttempt(ctx, sb.ID, sc.Name()); err != nil {
		slog.Warn("clear scanner backoff", "sbom_id", sb.ID, "scanner", sc.Name(), "error", err)
	}
}

// recordScannerFailure records a per-scanner failure to BOTH the queryable
// failure log (recordFailure) and the backoff state machine, so a persistently
// failing (SBOM, scanner) pair backs off and eventually quarantines instead of
// being retried every tick.
func (r *Runner) recordScannerFailure(ctx context.Context, sbomID, scanner, stage string, cause error) {
	r.recordFailure(ctx, sbomID, scanner, stage, cause)
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	if err := r.store.RecordScannerAttemptFailure(ctx, sbomID, scanner, stage+": "+msg); err != nil {
		slog.Warn("record scanner backoff", "sbom_id", sbomID, "scanner", scanner, "error", err)
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

// parseJSONBounded reads a scanner-output file through a size-bounded reader
// (rejecting anything over max) before parsing it with gabs, so an untrusted
// SBOM cannot drive an unbounded allocation via a huge scanner report.
func parseJSONBounded(path string, max int64) (*gabs.Container, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("scanner output exceeds %d bytes", max)
	}
	return gabs.ParseJSON(data)
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
