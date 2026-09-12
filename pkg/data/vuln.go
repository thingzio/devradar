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

// Package data holds the scanner-agnostic vulnerability type that every scanner
// converter normalizes into. It is deliberately the lowest common denominator
// across scanners so no single tool's idiosyncrasies leak into the schema — the
// same design lesson proven in vimp, reimplemented natively here (no dependency
// on that project).
package data

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Severity levels, lowercased to a single scale across scanners.
const (
	SeverityCritical   = "critical"
	SeverityHigh       = "high"
	SeverityMedium     = "medium"
	SeverityLow        = "low"
	SeverityNegligible = "negligible"
	SeverityUnknown    = "unknown"
)

// Finding-event types recorded in the change log.
const (
	EventAdded    = "added"    // finding not previously present
	EventResolved = "resolved" // finding no longer present
	EventRerated  = "rerated"  // severity/score changed
	EventFixed    = "fixed"    // a fix became available
)

// Event cause: which version axis changed to produce a finding event. Alerting
// acts only on image/db; tooling changes are recorded but never alerted.
const (
	CauseImage   = "image"   // a new SBOM (new digest)
	CauseDB      = "db"      // same SBOM, new vulnerability DB
	CauseTooling = "tooling" // same SBOM & DB, new scanner/canonicalizer
)

// Vulnerability is a normalized finding, independent of which scanner produced
// it. Converters map Grype/Trivy output into this shape.
type Vulnerability struct {
	// Exposure is the vulnerability ID, e.g. "CVE-2024-1234".
	Exposure string `json:"exposure"`
	// Package is the affected package name.
	Package string `json:"package"`
	// Version is the installed package version.
	Version string `json:"version"`
	// Severity is the lowercased severity (see the Severity* constants).
	Severity string `json:"severity"`
	// Score is the CVSS base score, resolved by source precedence (V3 over V2).
	Score float32 `json:"score"`
	// IsFixed reports whether a fixed version is available.
	IsFixed bool `json:"is_fixed"`
}

// GetID is the natural identity of a finding within a scan: the tuple
// (exposure, package, version). It is the dedup key and the join key the delta
// engine uses to diff one scan against the previous one. The same (exposure,
// package, version) from two scanners is intentionally the same ID — findings
// are keyed by (sbom, scanner, GetID) at the storage layer.
func (v Vulnerability) GetID() string {
	s := v.Exposure + "/" + v.Package + "/" + v.Version
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

// NormalizeSeverity maps an arbitrary scanner severity string onto the common
// scale, defaulting to SeverityUnknown.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible", "none":
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}
