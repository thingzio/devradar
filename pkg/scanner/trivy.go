package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
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

// trivyVersionInfo mirrors the fields of `trivy version -f json` we use.
type trivyVersionInfo struct {
	Version         string `json:"Version"`
	VulnerabilityDB struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	} `json:"VulnerabilityDB"`
}

func (t *trivyScanner) versionInfo() (trivyVersionInfo, bool) {
	out := captureVersion("trivy", "version", "-f", "json")
	if out == "" {
		return trivyVersionInfo{}, false
	}
	var v trivyVersionInfo
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return trivyVersionInfo{}, false
	}
	return v, true
}

// DBVersion returns the trivy vulnerability DB UpdatedAt timestamp. Call after
// EnsureDB.
func (t *trivyScanner) DBVersion() string {
	v, ok := t.versionInfo()
	if !ok || v.VulnerabilityDB.UpdatedAt.IsZero() {
		return ""
	}
	return v.VulnerabilityDB.UpdatedAt.UTC().Format(time.RFC3339)
}

// EnsureDB downloads/updates the trivy DB if missing or older than maxAge, then
// leaves it frozen (scans use --skip-db-update). Runs once at job start.
func (t *trivyScanner) EnsureDB(ctx context.Context, maxAge time.Duration) error {
	if v, ok := t.versionInfo(); ok && !v.VulnerabilityDB.UpdatedAt.IsZero() &&
		time.Since(v.VulnerabilityDB.UpdatedAt) <= maxAge {
		return nil
	}
	cmd := exec.CommandContext(ctx, "trivy", "image", "--download-db-only", "--quiet")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy db download: %w (%s)", err, truncate(string(out), 300))
	}
	return nil
}

// ScanSBOM scans the SBOM directly. --skip-db-update so the run uses the frozen
// DB from EnsureDB. Input must be CycloneDX (the canonical form) — trivy does
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
