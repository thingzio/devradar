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
