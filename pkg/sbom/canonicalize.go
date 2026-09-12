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

import "context"

// Canonicalizer converts an SBOM to the canonical scanning format (CycloneDX).
//
// This is a seam, not an implementation. The spike showed that scanning is not
// format-neutral — Trivy returns zero findings on Syft-generated SPDX but works
// on the same content as CycloneDX — so every SBOM is canonicalized to CycloneDX
// before it reaches the scanners. Canonicalization runs in the scan job, not at
// ingest, so a flaky or experimental converter can never fail a submission; a
// conversion failure becomes a recorded scan failure instead.
//
// The concrete backend is deliberately undecided here. Candidates:
//
//   - shell out to `syft convert` (proven in the spike, but flagged experimental)
//   - the CycloneDX/SPDX Go libraries in-process (needs its own fidelity check)
//
// Whichever is chosen implements this interface; callers depend only on it.
type Canonicalizer interface {
	// Canonicalize returns CycloneDX JSON for the given raw SBOM of the stated
	// format. For a document already in CycloneDX it is a validated pass-through.
	// Version reports the converter identity (e.g. "syft-1.46.0") for the same
	// reproducibility reason db_version is recorded per scan run.
	Canonicalize(ctx context.Context, raw []byte, format Format) (cyclonedx []byte, err error)
	Version() string
}

// passthroughCanonicalizer is a minimal Canonicalizer that accepts CycloneDX
// as-is and refuses anything else. It exists so the pipeline compiles and can be
// exercised end-to-end on CycloneDX fixtures before the SPDX converter backend
// is chosen and wired in. Replace it — do not extend it into the real converter.
type passthroughCanonicalizer struct{}

// NewPassthroughCanonicalizer returns a Canonicalizer that only handles input
// already in CycloneDX. SPDX input returns ErrUnknownFormat until a real
// converter backend replaces it.
func NewPassthroughCanonicalizer() Canonicalizer { return passthroughCanonicalizer{} }

func (passthroughCanonicalizer) Canonicalize(_ context.Context, raw []byte, format Format) ([]byte, error) {
	if format == FormatCycloneDX {
		return raw, nil
	}
	return nil, ErrUnknownFormat
}

func (passthroughCanonicalizer) Version() string { return "passthrough" }
