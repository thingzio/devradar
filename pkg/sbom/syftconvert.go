package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// SyftCanonicalizer converts SPDX to CycloneDX by shelling out to the pinned
// `syft convert` binary (spike-proven lossless: OS metadata, package set, and
// the image digest all survive). CycloneDX input is validated and passed
// through. This runs in the scan job, never at ingest, so a conversion failure
// is a recorded scan failure rather than a rejected submission.
//
// syft convert reads a file argument (not stdin) and writes to stdout, so the
// input is staged to a temp file.
type SyftCanonicalizer struct {
	version string // cached `syft version`, e.g. "syft-1.46.0"
}

// NewSyftCanonicalizer returns a syft-backed canonicalizer, or (nil,false) if
// the syft binary is not on PATH — callers fall back to passthrough.
func NewSyftCanonicalizer() (*SyftCanonicalizer, bool) {
	if _, err := exec.LookPath("syft"); err != nil {
		return nil, false
	}
	return &SyftCanonicalizer{version: syftVersion()}, true
}

// Canonicalize returns CycloneDX JSON. CycloneDX input is validated and returned
// as-is; SPDX input is converted via `syft convert`.
func (c *SyftCanonicalizer) Canonicalize(ctx context.Context, raw []byte, format Format) ([]byte, error) {
	switch format {
	case FormatCycloneDX:
		if !json.Valid(raw) {
			return nil, fmt.Errorf("cyclonedx input is not valid JSON")
		}
		return raw, nil
	case FormatSPDX:
		return c.convert(ctx, raw)
	default:
		return nil, ErrUnknownFormat
	}
}

// Version reports the converter identity, recorded per scan run for
// reproducibility (alongside db_version and scanner_version).
func (c *SyftCanonicalizer) Version() string {
	if c.version == "" {
		return "syft-unknown"
	}
	return c.version
}

func (c *SyftCanonicalizer) convert(ctx context.Context, raw []byte) ([]byte, error) {
	f, err := os.CreateTemp("", "devradar-spdx-*.json")
	if err != nil {
		return nil, fmt.Errorf("stage spdx: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write spdx: %w", err)
	}
	_ = f.Close()

	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "syft", "convert", f.Name(), "-q", "-o", "cyclonedx-json")
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft convert: %w (%s)", err, truncate(errb.String(), 300))
	}
	if !json.Valid(out.Bytes()) {
		return nil, fmt.Errorf("syft convert produced invalid JSON")
	}
	return out.Bytes(), nil
}

func syftVersion() string {
	var out bytes.Buffer
	cmd := exec.Command("syft", "version", "-o", "json")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(out.Bytes(), &v) == nil && v.Version != "" {
		return "syft-" + v.Version
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
