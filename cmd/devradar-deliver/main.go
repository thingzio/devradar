// Command devradar-deliver is the scheduled Cloud Run Job that processes one
// bounded batch of transactional email outbox rows.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/thingzio/devradar/pkg/delivery"
	"github.com/thingzio/devradar/pkg/logging"
)

// Injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logging.Setup(version, "deliver")
	slog.Info("devradar-deliver starting", "commit", commit, "date", date)
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := delivery.Run(ctx, delivery.Options{Version: version, Commit: commit, Date: date}); err != nil {
		slog.Error("delivery job failed", "error", err)
		return 1
	}
	slog.Info("devradar-deliver done")
	return 0
}
