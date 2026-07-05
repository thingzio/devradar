// Command devradar-serve is the Cloud Run service: the SBOM ingest API, the
// tenant-scoped read API, and a minimal GitHub-OAuth UI for minting API tokens.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/logging"
	"github.com/thingzio/devradar/pkg/server"
)

// Injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logging.Setup(version, "serve")
	slog.Info("devradar-serve starting", "commit", commit, "date", date)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		slog.Error("serve failed", "error", err)
		os.Exit(1)
	}
	slog.Info("devradar-serve stopped")
}

func run(ctx context.Context) error {
	store, err := postgres.New(ctx, config.DatabaseURL(), postgres.DefaultPoolConfig())
	if err != nil {
		return err
	}
	defer store.Close()

	blobs, closeBlobs, err := newBlobStore(ctx)
	if err != nil {
		return err
	}
	defer closeBlobs()

	oauthCfg := server.NewOAuthConfigFromEnv()
	if oauthCfg == nil {
		slog.Warn("GitHub OAuth not configured; UI disabled, API-only")
	}

	srv := server.New(store, blobs, oauthCfg, server.Options{
		Version: version, Commit: commit, Date: date,
	})
	return srv.Run(ctx)
}

// newBlobStore returns the SBOM byte store. Production uses GCS; setting
// DEVRADAR_LOCAL_SBOMS=1 uses a local directory (DEVRADAR_LOCAL_SBOM_DIR, default
// ./.sboms) for development against docker-compose Postgres.
func newBlobStore(ctx context.Context) (server.BlobStore, func(), error) {
	if config.GetEnvBool("DEVRADAR_LOCAL_SBOMS") {
		dir := config.GetEnv("DEVRADAR_LOCAL_SBOM_DIR", ".sboms")
		slog.Info("using local filesystem SBOM store", "dir", dir)
		return gcs.LocalStore{Dir: dir}, func() {}, nil
	}
	c, err := gcs.New(ctx)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { _ = c.Close() }, nil
}
