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

package converter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/data"
)

// Fixtures are real grype/trivy output produced by scanning the redis SBOM
// (pkg/converter/testdata). They exercise the converters against actual scanner
// shapes, not hand-written approximations.

func parseFixture(t *testing.T, name string) *gabs.Container {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	c, err := gabs.ParseJSON(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return c
}

func TestGrypeConverter(t *testing.T) {
	c := parseFixture(t, "redis.grype.json")
	conv := NewGrype()

	if !conv.CanHandle(c) {
		t.Fatal("grype converter should handle grype output")
	}
	vulns, err := conv.Convert(context.Background(), c)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	assertNormalized(t, vulns, "grype")
}

func TestTrivyConverter(t *testing.T) {
	c := parseFixture(t, "redis.trivy.json")
	conv := NewTrivy()

	if !conv.CanHandle(c) {
		t.Fatal("trivy converter should handle trivy output")
	}
	vulns, err := conv.Convert(context.Background(), c)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	assertNormalized(t, vulns, "trivy")
}

// assertNormalized checks the invariants every converter must uphold.
func assertNormalized(t *testing.T, vulns []data.Vulnerability, who string) {
	t.Helper()
	if len(vulns) == 0 {
		t.Fatalf("%s: expected findings, got none", who)
	}

	scored, validSeverity := 0, 0
	validSeverities := map[string]bool{
		data.SeverityCritical: true, data.SeverityHigh: true, data.SeverityMedium: true,
		data.SeverityLow: true, data.SeverityNegligible: true, data.SeverityUnknown: true,
	}
	for _, v := range vulns {
		if v.Exposure == "" {
			t.Errorf("%s: finding with empty exposure: %+v", who, v)
		}
		if v.Package == "" {
			t.Errorf("%s: finding with empty package: %+v", who, v)
		}
		if !validSeverities[v.Severity] {
			t.Errorf("%s: finding with unnormalized severity %q", who, v.Severity)
		} else {
			validSeverity++
		}
		if v.Score > 0 {
			scored++
		}
		// GetID must be stable and non-empty.
		if v.GetID() == "" {
			t.Errorf("%s: empty GetID", who)
		}
	}
	if validSeverity != len(vulns) {
		t.Errorf("%s: %d/%d findings had valid severities", who, validSeverity, len(vulns))
	}
	// The CVSS-source-precedence logic must resolve a real score for at least
	// some findings — this is the regression guard for the "silently 0.0" bug.
	if scored == 0 {
		t.Errorf("%s: no findings had a CVSS score > 0 — source precedence likely broken", who)
	}
	t.Logf("%s: %d findings, %d with a CVSS score", who, len(vulns), scored)
}

func TestRegistry_Detect(t *testing.T) {
	r := DefaultRegistry()

	g, err := r.Detect(parseFixture(t, "redis.grype.json"))
	if err != nil || g.Name() != "grype" {
		t.Errorf("detect grype: got %v, %v", g, err)
	}
	tv, err := r.Detect(parseFixture(t, "redis.trivy.json"))
	if err != nil || tv.Name() != "trivy" {
		t.Errorf("detect trivy: got %v, %v", tv, err)
	}

	unknown, _ := gabs.ParseJSON([]byte(`{"foo":"bar"}`))
	if _, err := r.Detect(unknown); !errors.Is(err, ErrNoConverter) {
		t.Errorf("detect unknown: want ErrNoConverter, got %v", err)
	}
}
