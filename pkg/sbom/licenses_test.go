package sbom

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/thingzio/devradar/pkg/data"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// findPackage returns the first extracted package with the given name.
func findPackage(pkgs []data.PackageLicense, name string) (data.PackageLicense, bool) {
	for _, p := range pkgs {
		if p.Package == name {
			return p, true
		}
	}
	return data.PackageLicense{}, false
}

func TestExtractPackagesAllFixtures(t *testing.T) {
	fixtures := []struct {
		name       string
		wantLicick bool // whether this SBOM is known to carry per-package licenses
	}{
		{"nginx.syft.cdx.json", true},
		{"nginx.trivy.cdx.json", true},
		{"nginx.syft.spdx.json", true},
		{"nginx.trivy.spdx.json", true},
		{"redis.syft.cdx.json", true},
		// Trivy's SPDX for a Go binary (prometheus) reports all NOASSERTION — a real
		// license-data-quality gotcha. Packages still extract; licenses are empty.
		{"prometheus.trivy.spdx.json", false},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			pkgs := ExtractPackages(readFixture(t, f.name))
			if len(pkgs) == 0 {
				t.Fatalf("%s: expected packages, got none", f.name)
			}
			for _, p := range pkgs {
				if p.Package == "" {
					t.Fatalf("%s: package with empty name", f.name)
				}
			}
			withLic := 0
			for _, p := range pkgs {
				if len(p.Licenses) > 0 {
					withLic++
				}
			}
			if f.wantLicick && withLic == 0 {
				t.Fatalf("%s: no package carried any license", f.name)
			}
		})
	}
}

func TestExtractCycloneDXSkipsFileComponents(t *testing.T) {
	// Syft CDX for nginx has 152 library + 1 OS + 3225 file components. Files are
	// not packages and must be excluded so the inventory reflects dependencies.
	pkgs := ExtractPackages(readFixture(t, "nginx.syft.cdx.json"))
	if len(pkgs) > 200 {
		t.Fatalf("extracted %d packages; file components should have been skipped (expect ~153)", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Package != "" && p.Package[0] == '/' {
			t.Errorf("file-path component leaked into inventory: %q", p.Package)
		}
	}
}

func TestExtractCycloneDXMultiLicensePreserved(t *testing.T) {
	// Syft CDX lists apt with 5 distinct license entries — none may be collapsed.
	pkgs := ExtractPackages(readFixture(t, "nginx.syft.cdx.json"))
	apt, ok := findPackage(pkgs, "apt")
	if !ok {
		t.Fatal("apt not found in nginx.syft.cdx.json")
	}
	for _, want := range []string{"BSD-3-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "curl", "Expat"} {
		if !slices.Contains(apt.Licenses, want) {
			t.Errorf("apt licenses %v missing %q", apt.Licenses, want)
		}
	}
	if apt.Version != "3.0.3" {
		t.Errorf("apt version = %q, want 3.0.3", apt.Version)
	}
	if apt.PURL == "" {
		t.Error("apt PURL should be captured from CycloneDX")
	}
}

func TestExtractSPDXExpressionPreserved(t *testing.T) {
	// Trivy SPDX joins apt's licenses into one AND expression — kept intact.
	pkgs := ExtractPackages(readFixture(t, "nginx.trivy.spdx.json"))
	apt, ok := findPackage(pkgs, "apt")
	if !ok {
		t.Fatal("apt not found in nginx.trivy.spdx.json")
	}
	if len(apt.Licenses) != 1 {
		t.Fatalf("apt should have 1 SPDX expression entry, got %v", apt.Licenses)
	}
	if !slices.Contains(apt.Licenses, "GPL-2.0-or-later AND curl AND BSD-3-Clause AND MIT AND GPL-2.0-only") {
		t.Errorf("apt SPDX expression not preserved: %v", apt.Licenses)
	}
	if apt.PURL == "" {
		t.Error("apt PURL should be captured from SPDX externalRefs")
	}
}

func TestExtractSkipsRootImage(t *testing.T) {
	// The subject image package must not appear as a dependency.
	pkgs := ExtractPackages(readFixture(t, "nginx.syft.spdx.json"))
	for _, p := range pkgs {
		if p.Package == "nginx" && len(p.Licenses) == 0 && p.Version != "" &&
			len(p.Version) > 6 && p.Version[:7] == "sha256:" {
			t.Errorf("root image package leaked into inventory: %+v", p)
		}
	}
}

func TestExtractDropsPlaceholderLicenses(t *testing.T) {
	// SPDX NOASSERTION must not become a license value.
	pkgs := ExtractPackages(readFixture(t, "nginx.syft.spdx.json"))
	for _, p := range pkgs {
		for _, l := range p.Licenses {
			if l == "NOASSERTION" || l == "NONE" {
				t.Errorf("placeholder license %q leaked on %s", l, p.Package)
			}
		}
	}
}

func TestExtractUnknownFormatEmpty(t *testing.T) {
	if got := ExtractPackages([]byte(`{"not":"an sbom"}`)); got != nil {
		t.Errorf("unknown format should yield nil, got %v", got)
	}
	if got := ExtractPackages([]byte(`not json`)); got != nil {
		t.Errorf("invalid JSON should yield nil, got %v", got)
	}
}
