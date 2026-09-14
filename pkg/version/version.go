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

// Package version reports the build identity of the running binary.
//
// Release binaries are stamped by goreleaser through -ldflags. Container
// images are built by ko, which passes no ldflags, so those fall back to the
// VCS metadata the Go toolchain stamps into every build. Nothing is read from
// the environment on purpose: a deploy-time value is a claim about the binary
// rather than a property of it, and can drift from the artifact it describes.
package version

import (
	"regexp"
	"runtime/debug"
)

// Injected via -ldflags by goreleaser. Empty in ko-built container images.
var (
	version string
	commit  string
	date    string
)

// releaseTag matches a version worth showing a user. pseudoVersion excludes
// the vX.Y.Z-<timestamp>-<sha> form the toolchain synthesizes for any build
// that is not sitting on a tag, which releaseTag would otherwise accept.
var (
	releaseTag    = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	pseudoVersion = regexp.MustCompile(`-\d{14}-[0-9a-f]{12}$`)
)

const shortCommitLen = 7

// Info is the build identity of the running binary. Any field may be empty,
// and callers must render accordingly.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Get resolves the build identity, preferring ldflags when they were injected.
func Get() Info {
	if version != "" {
		return Info{Version: version, Commit: commit, Date: date}
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Info{}
	}
	return fromBuildInfo(bi)
}

// fromBuildInfo is split out from Get because debug.ReadBuildInfo cannot be
// faked in-process, and every interesting case here is a parsing decision.
func fromBuildInfo(bi *debug.BuildInfo) Info {
	var out Info
	if releaseTag.MatchString(bi.Main.Version) && !pseudoVersion.MatchString(bi.Main.Version) {
		out.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.Commit = s.Value
			if len(out.Commit) > shortCommitLen {
				out.Commit = out.Commit[:shortCommitLen]
			}
		case "vcs.time":
			out.Date = s.Value
		}
	}
	return out
}
