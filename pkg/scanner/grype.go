package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

type grypeScanner struct{}

// NewGrype returns an exec-based Grype scanner.
func NewGrype() Scanner { return &grypeScanner{} }

func (g *grypeScanner) Name() string          { return "grype" }
func (g *grypeScanner) ConverterName() string { return "grype" }
func (g *grypeScanner) IsAvailable() bool     { return isInstalled("grype") }

// Version returns the grype binary version, e.g. "0.115.0".
func (g *grypeScanner) Version() string {
	out := captureVersion("grype", "version", "-o", "json")
	if out == "" {
		return ""
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return ""
	}
	return v.Version
}

// DBVersion returns the grype DB build timestamp (RFC3339), read from
// `grype db status -o json`. Call after EnsureDB.
func (g *grypeScanner) DBVersion() string {
	out := captureVersion("grype", "db", "status", "-o", "json")
	if out == "" {
		return ""
	}
	var s struct {
		Built string `json:"built"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return ""
	}
	return s.Built
}

// EnsureDB updates the grype DB if missing or older than maxAge. grype's own
// `db status` reports validity (it enforces a max age); we additionally honor
// the caller's maxAge. Runs once at job start; scans then run frozen.
func (g *grypeScanner) EnsureDB(ctx context.Context, maxAge time.Duration) error {
	if grypeDBFresh(maxAge) {
		return nil
	}
	cmd := exec.CommandContext(ctx, "grype", "db", "update")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("grype db update: %w (%s)", err, truncate(string(out), 300))
	}
	return nil
}

// grypeDBFresh reports whether the installed DB is present, grype-valid, and
// built within maxAge.
func grypeDBFresh(maxAge time.Duration) bool {
	out := captureVersion("grype", "db", "status", "-o", "json")
	if out == "" {
		return false
	}
	var s struct {
		Built string `json:"built"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || !s.Valid {
		return false
	}
	built, err := time.Parse(time.RFC3339, s.Built)
	if err != nil {
		return false
	}
	return time.Since(built) <= maxAge
}

// ScanSBOM scans the SBOM via grype's "sbom:" scheme. No network, no image
// pull; DB auto-update disabled so the run uses the frozen DB from EnsureDB.
func (g *grypeScanner) ScanSBOM(ctx context.Context, sbomPath, outPath string) error {
	cmd := exec.CommandContext(ctx, "grype",
		"sbom:"+sbomPath,
		"-q",
		"-o", "json",
		"--file", outPath,
	)
	cmd.Env = append(cmd.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
	return runCmd(ctx, cmd, outPath)
}
