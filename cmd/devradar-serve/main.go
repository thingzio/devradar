// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
