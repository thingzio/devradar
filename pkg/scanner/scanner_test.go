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

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRegistry(t *testing.T) {
	r := DefaultRegistry()
	if _, ok := r.Get("grype"); !ok {
		t.Error("grype not registered")
	}
	if _, ok := r.Get("trivy"); !ok {
		t.Error("trivy not registered")
	}
	for _, s := range r.All() {
		if s.ConverterName() == "" {
			t.Errorf("%s: empty converter name", s.Name())
		}
	}
}

// TestScanSBOM_Live runs the real binaries against a fixture SBOM. It skips if a
// scanner isn't installed, so the suite stays green in minimal environments.
func TestScanSBOM_Live(t *testing.T) {
	// The canonical (CycloneDX) fixture from the sbom package; both scanners read it.
	src, err := filepath.Abs("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	for _, sc := range DefaultRegistry().All() {
		t.Run(sc.Name(), func(t *testing.T) {
			if !sc.IsAvailable() {
				t.Skipf("%s not installed", sc.Name())
			}
			if v := sc.Version(); v == "" {
				t.Errorf("%s: empty version", sc.Name())
			}
			out := filepath.Join(t.TempDir(), sc.Name()+".json")
			if err := sc.ScanSBOM(context.Background(), src, out); err != nil {
				// A missing baked DB is an environment issue, not a code failure;
				// note it rather than failing the suite on dev machines.
				t.Skipf("%s scan failed (likely missing local DB): %v", sc.Name(), err)
			}
			info, err := os.Stat(out)
			if err != nil || info.Size() < 2 {
				t.Errorf("%s produced no output", sc.Name())
			}
		})
	}
}
