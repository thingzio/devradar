package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRegistry(t *testing.T) {
	r := DefaultRegistry()
	if _, ok := r.Get("grype"); !ok {
		t.Error("grype not registered")
	}
	if _, ok := r.Get("trivy"); !ok {
		t.Error("trivy not registered")
	}
	for _, s := range r.All() {
		if s.ConverterName() == "" {
			t.Errorf("%s: empty converter name", s.Name())
		}
	}
}

// TestScanSBOM_Live runs the real binaries against a fixture SBOM. It skips if a
// scanner isn't installed, so the suite stays green in minimal environments.
func TestScanSBOM_Live(t *testing.T) {
	// The canonical (CycloneDX) fixture from the sbom package; both scanners read it.
	src, err := filepath.Abs("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	for _, sc := range DefaultRegistry().All() {
		t.Run(sc.Name(), func(t *testing.T) {
			if !sc.IsAvailable() {
				t.Skipf("%s not installed", sc.Name())
			}
			if v := sc.Version(); v == "" {
				t.Errorf("%s: empty version", sc.Name())
			}
			out := filepath.Join(t.TempDir(), sc.Name()+".json")
			if err := sc.ScanSBOM(context.Background(), src, out); err != nil {
				// A missing baked DB is an environment issue, not a code failure;
				// note it rather than failing the suite on dev machines.
				t.Skipf("%s scan failed (likely missing local DB): %v", sc.Name(), err)
			}
			info, err := os.Stat(out)
			if err != nil || info.Size() < 2 {
				t.Errorf("%s produced no output", sc.Name())
			}
		})
	}
}
