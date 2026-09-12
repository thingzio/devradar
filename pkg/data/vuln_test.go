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

package data

import "testing"

func TestGetID_StableAndDistinct(t *testing.T) {
	a := Vulnerability{Exposure: "CVE-2024-1", Package: "openssl", Version: "1.1.1"}
	b := Vulnerability{Exposure: "CVE-2024-1", Package: "openssl", Version: "1.1.1"}
	c := Vulnerability{Exposure: "CVE-2024-1", Package: "openssl", Version: "1.1.2"}

	// Identity depends only on (exposure, package, version) — severity/score/fix
	// are mutable attributes, not part of the key.
	a.Severity, a.Score, a.IsFixed = "high", 7.5, false
	b.Severity, b.Score, b.IsFixed = "critical", 9.8, true

	if a.GetID() != b.GetID() {
		t.Errorf("same (exposure,package,version) must share an ID")
	}
	if a.GetID() == c.GetID() {
		t.Errorf("different version must produce a different ID")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": SeverityCritical,
		"High":     SeverityHigh,
		"moderate": SeverityMedium,
		"Low":      SeverityLow,
		"None":     SeverityNegligible,
		"weird":    SeverityUnknown,
		"":         SeverityUnknown,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
