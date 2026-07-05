// Command devradar-serve is the Cloud Run service: the SBOM ingest API, the
// tenant-scoped read API, and the magic-link UI for minting API tokens. It is a
// thin entry point — all wiring and logic live in pkg/server.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, server.Options{Version: version, Commit: commit, Date: date}); err != nil {
		slog.Error("serve failed", "error", err)
		return 1
	}
	slog.Info("devradar-serve stopped")
	return 0
}
