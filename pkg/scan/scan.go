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
	"github.com/thingzio/devradar/pkg/converter"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
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
	ApplyScan(ctx context.Context, sb *postgres.SBOM, scanner string, ver postgres.Versions, vulns []data.Vulnerability) error
	RecordScanFailure(ctx context.Context, sbomID, scanner, stage string, cause error)
}

// Options configures a scan run.
type Options struct {
	DBMaxAge time.Duration // refresh a scanner DB older than this at job start
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{DBMaxAge: 24 * time.Hour}
}

// Runner ties the pieces together.
type Runner struct {
	store    Store
	fetch    Fetcher
	canon    sbom.Canonicalizer
	scanners []scanner.Scanner
	convs    *converter.Registry
	opts     Options
}

// NewRunner builds a Runner. scanners should be the *available* set.
func NewRunner(store Store, fetch Fetcher, canon sbom.Canonicalizer, scanners []scanner.Scanner, convs *converter.Registry, opts Options) *Runner {
	return &Runner{store: store, fetch: fetch, canon: canon, scanners: scanners, convs: convs, opts: opts}
}

// Run executes one full pass over all active SBOMs. It returns an error only for
// whole-run failures (DB prep, listing); per-SBOM and per-scanner failures are
// recorded to the failure surface and do not abort the run.
func (r *Runner) Run(ctx context.Context) error {
	// Freeze each scanner's DB once, up front: refresh if stale, then every scan
	// in this run shares that version — which is what keeps cause attribution
	// honest (no DB drift mid-run).
	for _, sc := range r.scanners {
		if err := sc.EnsureDB(ctx, r.opts.DBMaxAge); err != nil {
			return fmt.Errorf("ensure db for %s: %w", sc.Name(), err)
		}
		slog.Info("scanner ready", "scanner", sc.Name(),
			"version", sc.Version(), "db_version", sc.DBVersion())
	}

	sboms, err := r.store.ListActiveSBOMs(ctx)
	if err != nil {
		return fmt.Errorf("list active sboms: %w", err)
	}
	slog.Info("scan run starting", "sbom_count", len(sboms), "scanners", len(r.scanners))

	scanned := 0
	for _, sb := range sboms {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.scanOne(ctx, sb)
		scanned++
	}
	slog.Info("scan run complete", "scanned", scanned)
	return nil
}

// scanOne processes a single SBOM across all scanners. All failures are recorded
// and swallowed so one bad SBOM never stops the batch.
func (r *Runner) scanOne(ctx context.Context, sb *postgres.SBOM) {
	raw, err := r.fetch.Fetch(ctx, sb.ObjectPath)
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, "", "download", err)
		return
	}

	// Canonicalize to CycloneDX so every scanner sees a format it reads reliably.
	cdx, err := r.canon.Canonicalize(ctx, raw, sbom.Format(sb.Format))
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, "", "canonicalize", err)
		return
	}
	local, cleanup, err := writeTemp(sb.ID, cdx)
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, "", "canonicalize", err)
		return
	}
	defer cleanup()

	for _, sc := range r.scanners {
		r.scanWith(ctx, sb, sc, local)
	}
}

func (r *Runner) scanWith(ctx context.Context, sb *postgres.SBOM, sc scanner.Scanner, sbomPath string) {
	out, cleanup, err := tempOut(sb.ID, sc.Name())
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	defer cleanup()

	if err := sc.ScanSBOM(ctx, sbomPath, out); err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "scan", err)
		return
	}
	doc, err := gabs.ParseJSONFile(out)
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "parse", err)
		return
	}
	conv, err := r.convs.Detect(doc)
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "detect", err)
		return
	}
	vulns, err := conv.Convert(ctx, doc)
	if err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "convert", err)
		return
	}

	// Tripwire: zero findings on a non-trivial SBOM signals a conversion/DB
	// regression (e.g. Trivy on un-canonicalized SPDX, or a missing DB), not a
	// clean image. Record it rather than writing a misleading "all resolved".
	if len(vulns) == 0 && sb.PackageCount > zeroFindingFloor {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "zero-findings",
			fmt.Errorf("0 findings on sbom with %d packages", sb.PackageCount))
		return
	}

	ver := postgres.Versions{
		DBVersion:            sc.DBVersion(),
		ScannerVersion:       sc.Version(),
		CanonicalizerVersion: r.canon.Version(),
	}
	if err := r.store.ApplyScan(ctx, sb, sc.Name(), ver, vulns); err != nil {
		r.store.RecordScanFailure(ctx, sb.ID, sc.Name(), "persist", err)
	}
}

// writeTemp writes b to a temp file and returns its path + a cleanup func.
func writeTemp(id string, b []byte) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "devradar-sbom-"+safe(id)+"-*.json")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", func() {}, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// tempOut returns a path for scanner output + a cleanup func.
func tempOut(id, scanner string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "devradar-out-"+safe(id)+"-"+scanner+"-*.json")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	f.Close()
	return name, func() { os.Remove(name) }, nil
}

// safe strips path separators from an id used in a temp filename.
func safe(s string) string {
	return filepath.Base(s)
}
