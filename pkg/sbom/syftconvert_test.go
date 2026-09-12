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

package sbom

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSyftCanonicalizer_SPDXtoCDX(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed")
	}
	c, ok := NewSyftCanonicalizer()
	if !ok {
		t.Fatal("expected syft canonicalizer available")
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "redis.syft.spdx.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cdx, err := c.Canonicalize(context.Background(), raw, FormatSPDX)
	if err != nil {
		t.Fatalf("canonicalize spdx: %v", err)
	}
	// Result must be resolvable CycloneDX with the same digest as the source.
	subj, err := Resolve(cdx)
	if err != nil {
		t.Fatalf("resolve converted: %v", err)
	}
	if subj.Format != FormatCycloneDX {
		t.Errorf("converted format = %s, want cyclonedx", subj.Format)
	}
	if subj.Digest != redisDigest {
		t.Errorf("converted digest = %s, want %s", subj.Digest, redisDigest)
	}
}

func TestSyftCanonicalizer_CDXPassthrough(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed")
	}
	c, _ := NewSyftCanonicalizer()
	raw, _ := os.ReadFile(filepath.Join("testdata", "redis.syft.cdx.json"))
	out, err := c.Canonicalize(context.Background(), raw, FormatCycloneDX)
	if err != nil {
		t.Fatalf("passthrough: %v", err)
	}
	if len(out) != len(raw) {
		t.Errorf("cyclonedx passthrough should return input unchanged")
	}
}
