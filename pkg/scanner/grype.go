package scanner

import (
	"context"
	"encoding/json"
	"os/exec"
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

// ScanSBOM scans the SBOM via grype's "sbom:" scheme. No network, no image
// pull; DB auto-update disabled because the pinned DB is baked into the image.
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
