package scanner

import (
	"context"
	"encoding/json"
	"os/exec"
)

type trivyScanner struct{}

// NewTrivy returns an exec-based Trivy scanner.
func NewTrivy() Scanner { return &trivyScanner{} }

func (t *trivyScanner) Name() string          { return "trivy" }
func (t *trivyScanner) ConverterName() string { return "trivy" }
func (t *trivyScanner) IsAvailable() bool     { return isInstalled("trivy") }

// Version returns the trivy binary version, e.g. "0.72.0".
func (t *trivyScanner) Version() string {
	out := captureVersion("trivy", "version", "-f", "json")
	if out == "" {
		return ""
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return ""
	}
	return v.Version
}

// ScanSBOM scans the SBOM directly. --skip-db-update: the pinned DB is baked
// into the job image. Input must be CycloneDX (the canonical form) — trivy does
// not reliably read Syft-generated SPDX, which is why the scan job canonicalizes
// before calling any scanner.
func (t *trivyScanner) ScanSBOM(ctx context.Context, sbomPath, outPath string) error {
	cmd := exec.CommandContext(ctx, "trivy", "sbom",
		"--quiet",
		"--scanners", "vuln",
		"--format", "json",
		"--skip-db-update",
		"--output", outPath,
		sbomPath,
	)
	return runCmd(ctx, cmd, outPath)
}
