package converter

import (
	"context"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/parser"
)

// cvssSourcePrecedence is the order trivy CVSS providers are consulted. Trivy
// frequently populates a vendor score (redhat, ghsa) and NOT nvd; hardcoding nvd
// would silently store 0.0 for a large fraction of findings. Walk the list and
// take the first present, V3 over V2.
var cvssSourcePrecedence = []string{"nvd", "redhat", "ghsa", "bitnami", "amazon", "oracle", "photon", "cbl-mariner", "ubuntu"}

// Trivy normalizes Trivy JSON (`trivy ... --format json`).
type Trivy struct{}

// NewTrivy returns a Trivy converter.
func NewTrivy() *Trivy { return &Trivy{} }

// Name implements Converter.
func (t *Trivy) Name() string { return "trivy" }

// CanHandle recognizes Trivy output by its top-level SchemaVersion + Results.
func (t *Trivy) CanHandle(c *gabs.Container) bool {
	if c == nil {
		return false
	}
	return c.Exists("SchemaVersion") && c.Exists("Results")
}

// Convert normalizes the Results[].Vulnerabilities arrays into findings.
func (t *Trivy) Convert(ctx context.Context, c *gabs.Container) ([]data.Vulnerability, error) {
	if c == nil {
		return nil, ErrNoConverter
	}
	out := make([]data.Vulnerability, 0)
	for _, result := range c.Search("Results").Children() {
		for _, vuln := range result.Search("Vulnerabilities").Children() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if v, ok := trivyVuln(vuln); ok {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func trivyVuln(vuln *gabs.Container) (data.Vulnerability, bool) {
	id := parser.String(vuln, "VulnerabilityID")
	if id == "" {
		return data.Vulnerability{}, false
	}
	v := data.Vulnerability{
		Exposure: id,
		Package:  parser.String(vuln, "PkgName"),
		Version:  parser.String(vuln, "InstalledVersion"),
		Severity: data.NormalizeSeverity(parser.String(vuln, "Severity")),
		Score:    trivyScore(vuln.Search("CVSS")),
		IsFixed:  parser.String(vuln, "FixedVersion") != "",
	}
	return v, true
}

// trivyScore resolves the CVSS base score by source precedence, V3 over V2.
func trivyScore(cvss *gabs.Container) float32 {
	if !cvss.Exists() {
		return 0
	}
	for _, src := range cvssSourcePrecedence {
		s := cvss.Search(src)
		if !s.Exists() {
			continue
		}
		if v3 := s.Search("V3Score"); v3.Exists() {
			return parser.ToFloat32(v3.Data())
		}
		if v2 := s.Search("V2Score"); v2.Exists() {
			return parser.ToFloat32(v2.Data())
		}
	}
	return 0
}
