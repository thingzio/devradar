// Command devradar-scan is the daily Cloud Run Job. It rescans every active
// SBOM with the available scanners and records current state + change events.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/converter"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/logging"
	"github.com/thingzio/devradar/pkg/sbom"
	"github.com/thingzio/devradar/pkg/scan"
	"github.com/thingzio/devradar/pkg/scanner"
)

// Injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logging.Setup(version, "scan")
	slog.Info("devradar-scan starting", "commit", commit, "date", date)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		slog.Error("scan job failed", "error", err)
		os.Exit(1)
	}
	slog.Info("devradar-scan done")
}

func run(ctx context.Context) error {
	store, err := postgres.New(ctx, config.DatabaseURL(), postgres.ScanPoolConfig())
	if err != nil {
		return err
	}
	defer store.Close()

	fetcher, closeFetcher, err := newFetcher(ctx)
	if err != nil {
		return err
	}
	defer closeFetcher()

	scanners := scanner.DefaultRegistry().Available()
	if len(scanners) == 0 {
		slog.Warn("no scanners available on PATH; nothing to do")
		return nil
	}

	runner := scan.NewRunner(
		store,
		fetcher,
		// v1 canonicalizer is pass-through (CycloneDX-only). The SPDX->CDX
		// backend replaces this without touching the loop.
		sbom.NewPassthroughCanonicalizer(),
		scanners,
		converter.DefaultRegistry(),
		scan.DefaultOptions(),
	)
	return runner.Run(ctx)
}

// newFetcher returns the SBOM byte source. Production uses GCS; setting
// DEVRADAR_LOCAL_SBOMS=1 uses the local filesystem (object_path is a file path)
// for development against docker-compose Postgres.
func newFetcher(ctx context.Context) (scan.Fetcher, func(), error) {
	if config.GetEnvBool("DEVRADAR_LOCAL_SBOMS") {
		slog.Info("using local filesystem SBOM fetcher")
		return gcs.LocalFetcher{}, func() {}, nil
	}
	c, err := gcs.New(ctx)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { _ = c.Close() }, nil
}
