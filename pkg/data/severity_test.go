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

import (
	"slices"
	"testing"
)

func TestMeetsThreshold(t *testing.T) {
	cases := []struct {
		sev, min string
		want     bool
	}{
		{SeverityCritical, SeverityMedium, true},
		{SeverityHigh, SeverityMedium, true},
		{SeverityMedium, SeverityMedium, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityNegligible, SeverityMedium, false},
		{SeverityUnknown, SeverityMedium, true},   // unknown always surfaces
		{SeverityUnknown, SeverityCritical, true}, // even at the strictest threshold
		{SeverityLow, SeverityLow, true},
		{SeverityNegligible, SeverityNegligible, true},
		{"garbage", SeverityCritical, true}, // unrecognized → surface, don't hide
	}
	for _, c := range cases {
		if got := MeetsThreshold(c.sev, c.min); got != c.want {
			t.Errorf("MeetsThreshold(%q,%q) = %v, want %v", c.sev, c.min, got, c.want)
		}
	}
}

func TestAllowedSeverities(t *testing.T) {
	got := AllowedSeverities(SeverityHigh)
	// high threshold → critical, high, and always unknown; not medium/low/neg.
	for _, want := range []string{SeverityCritical, SeverityHigh, SeverityUnknown} {
		if !slices.Contains(got, want) {
			t.Errorf("AllowedSeverities(high) missing %q: %v", want, got)
		}
	}
	for _, notWant := range []string{SeverityMedium, SeverityLow, SeverityNegligible} {
		if slices.Contains(got, notWant) {
			t.Errorf("AllowedSeverities(high) should not contain %q: %v", notWant, got)
		}
	}
}

func TestValidMinSeverity(t *testing.T) {
	for _, ok := range []string{"critical", "high", "medium", "low", "negligible"} {
		if !ValidMinSeverity(ok) {
			t.Errorf("ValidMinSeverity(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"unknown", "", "HIGH", "nope"} {
		if ValidMinSeverity(bad) {
			t.Errorf("ValidMinSeverity(%q) = true, want false", bad)
		}
	}
}

func TestAllowedSeverities_StrictVsUnknown(t *testing.T) {
	def := AllowedSeverities("high")
	strict := AllowedSeveritiesStrict("high")
	if !slices.Contains(def, SeverityUnknown) {
		t.Errorf("AllowedSeverities(high) should include unknown: %v", def)
	}
	if slices.Contains(strict, SeverityUnknown) {
		t.Errorf("AllowedSeveritiesStrict(high) must NOT include unknown: %v", strict)
	}
	// Both exclude below-threshold ranked severities.
	for _, below := range []string{SeverityMedium, SeverityLow, SeverityNegligible} {
		if slices.Contains(def, below) || slices.Contains(strict, below) {
			t.Errorf("high threshold must exclude %q", below)
		}
	}
	// Both include at-or-above ranked severities.
	for _, at := range []string{SeverityHigh, SeverityCritical} {
		if !slices.Contains(strict, at) {
			t.Errorf("high threshold must include %q: %v", at, strict)
		}
	}
}
