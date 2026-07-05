package sbom

import (
	"errors"
	"time"
)

// Format is a supported SBOM document format.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// ErrNoDigest is returned when no image digest can be resolved from an SBOM.
// Ingest fails closed on this: an SBOM with no digest cannot participate in
// digest-boundary delta causality, which is the whole point of the pipeline.
var ErrNoDigest = errors.New("sbom: no image digest resolvable from document")

// ErrUnknownFormat is returned when the bytes are neither CycloneDX nor SPDX.
var ErrUnknownFormat = errors.New("sbom: unrecognized document format")

// Subject is what an SBOM describes plus the provenance needed to reason about
// its freshness. All fields except Digest are best-effort; Digest is required
// (its absence is ErrNoDigest).
type Subject struct {
	// ImageRef is the image reference the SBOM claims (may be weak or absent —
	// Syft SPDX reports just "nginx"; Trivy embeds the full registry path).
	// A caller-supplied override, when present, takes precedence.
	ImageRef string

	// Digest is the image manifest digest, e.g. "sha256:5825bde...". Required.
	Digest string

	// Format is the detected document format.
	Format Format

	// SpecVersion is the format's spec version, e.g. "1.7" or "SPDX-2.3".
	SpecVersion string

	// Tool is the generator name from document metadata, e.g. "syft" or "trivy".
	Tool string

	// ToolVersion is the generator version. Together with Tool it bounds the
	// cataloging freshness (see the accuracy discussion in the design docs).
	ToolVersion string

	// GeneratedAt is the document's stated creation time. Zero if the document
	// omitted it; callers fall back to ingest-receive time in that case.
	GeneratedAt time.Time
}
