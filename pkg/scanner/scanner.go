// Package scanner runs vulnerability scanners against an SBOM file and returns
// the path to their raw JSON output. v1 shells out to pinned scanner binaries
// (grype, trivy) rather than importing them as libraries — see the design docs
// for why (version integrity, dependency isolation, fault isolation on untrusted
// input). The Scanner interface is the seam that keeps an in-process backend
// cheap to add later. (Design from vimp, reimplemented natively.)
package scanner

import (
	"context"
	"time"
)

// Scanner runs one vulnerability scanner against an SBOM file.
type Scanner interface {
	// Name is the scanner identifier, e.g. "grype", "trivy".
	Name() string
	// Version returns the scanner binary version (the matcher logic), recorded
	// per scan run so a change in findings is attributable to a scanner upgrade
	// rather than the image or the vuln DB. "" if it cannot be determined.
	Version() string
	// DBVersion returns an identifier for the currently-installed vulnerability
	// database (e.g. its build timestamp), recorded per scan run. Call after
	// EnsureDB so the value reflects the DB the run will actually use. "" if it
	// cannot be determined.
	DBVersion() string
	// EnsureDB updates the vulnerability database if it is missing or older than
	// maxAge, then leaves it frozen for the run. The scan job calls this ONCE at
	// startup; per-SBOM scans then run with auto-update disabled so every scan in
	// a run shares one DB version (which keeps cause attribution honest).
	EnsureDB(ctx context.Context, maxAge time.Duration) error
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

// Names returns the names of every registered scanner — the "expected scanner"
// set used for per-scanner work selection (freshness and backlog).
func (r *Registry) Names() []string {
	out := make([]string, len(r.scanners))
	for i, s := range r.scanners {
		out[i] = s.Name()
	}
	return out
}

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
