// Package scanner runs vulnerability scanners against an SBOM file and returns
// the path to their raw JSON output. v1 shells out to pinned scanner binaries
// (grype, trivy) rather than importing them as libraries — see the design docs
// for why (version integrity, dependency isolation, fault isolation on untrusted
// input). The Scanner interface is the seam that keeps an in-process backend
// cheap to add later. (Design from vimp, reimplemented natively.)
package scanner

import "context"

// Scanner runs one vulnerability scanner against an SBOM file.
type Scanner interface {
	// Name is the scanner identifier, e.g. "grype", "trivy".
	Name() string
	// Version returns the scanner binary version (the matcher logic), recorded
	// per scan run so a change in findings is attributable to a scanner upgrade
	// rather than the image or the vuln DB. "" if it cannot be determined.
	Version() string
	// IsAvailable reports whether the scanner binary is installed.
	IsAvailable() bool
	// ScanSBOM scans the SBOM at sbomPath and writes raw JSON to outPath.
	ScanSBOM(ctx context.Context, sbomPath, outPath string) error
	// ConverterName is the converter that normalizes this scanner's output.
	ConverterName() string
}

// Registry holds registered scanners.
type Registry struct {
	scanners []Scanner
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a scanner.
func (r *Registry) Register(s Scanner) { r.scanners = append(r.scanners, s) }

// All returns every registered scanner.
func (r *Registry) All() []Scanner { return r.scanners }

// Available returns only scanners whose binary is installed.
func (r *Registry) Available() []Scanner {
	out := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		if s.IsAvailable() {
			out = append(out, s)
		}
	}
	return out
}

// Get returns a scanner by name.
func (r *Registry) Get(name string) (Scanner, bool) {
	for _, s := range r.scanners {
		if s.Name() == name {
			return s, true
		}
	}
	return nil, false
}

// DefaultRegistry returns the v1 scanner set: grype + trivy, both exec-based.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGrype())
	r.Register(NewTrivy())
	return r
}
