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

// Package sbom parses submitted Software Bills of Materials, extracts the
// subject image (digest, reference), generation time, and generator tool, and
// canonicalizes any supported format to CycloneDX for scanning.
//
// Two formats are accepted at ingest: CycloneDX and SPDX. The spike in
// pkg/sbom/testdata established that the subject digest, generation timestamp,
// and generator tool all extract reliably from both formats as produced by
// both Syft and Trivy — so submission requires only the SBOM bytes.
//
// Scanning, however, is not format-neutral: Trivy cannot read Syft-generated
// SPDX (it reports no OS packages and returns zero findings), while it reads
// the same content fine as CycloneDX. Canonicalize therefore converts SPDX to
// CycloneDX before the SBOM reaches the scanners, giving even coverage across
// scanners regardless of the submitted format. Extraction runs on the raw
// bytes at ingest (so ingest can fail closed on "no digest"); canonicalization
// runs later, in the scan job.
package sbom
