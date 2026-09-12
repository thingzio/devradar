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
