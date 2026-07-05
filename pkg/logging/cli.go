// Package logging configures the process-wide structured logger. Output is JSON
// on stderr (captured by Cloud Run), tagged with version and source, matching
// the DevPulse/DevTrace convention.
package logging

import (
	"log/slog"
	"os"

	"github.com/thingzio/devradar/pkg/config"
)

// Setup installs the default slog logger. version and source (e.g. "serve",
// "scan") are attached to every entry when non-empty. Level is Debug when
// DEVRADAR_DEBUG is set, else Info.
func Setup(version, source string) {
	level := slog.LevelInfo
	if config.DebugEnabled() {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if version != "" {
		logger = logger.With("version", version)
	}
	if source != "" {
		logger = logger.With("source", source)
	}
	slog.SetDefault(logger)
}
