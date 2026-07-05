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
