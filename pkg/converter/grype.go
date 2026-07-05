package converter

import (
	"context"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/parser"
)

// Grype normalizes Grype JSON (`grype -o json`).
type Grype struct{}

// NewGrype returns a Grype converter.
func NewGrype() *Grype { return &Grype{} }

// Name implements Converter.
func (g *Grype) Name() string { return "grype" }

// CanHandle recognizes Grype output by its descriptor.name.
func (g *Grype) CanHandle(c *gabs.Container) bool {
	if c == nil {
		return false
	}
	return parser.ToString(c.Search("descriptor", "name").Data()) == "grype"
}

// Convert normalizes the `matches` array into findings.
func (g *Grype) Convert(ctx context.Context, c *gabs.Container) ([]data.Vulnerability, error) {
	if c == nil {
		return nil, ErrNoConverter
	}
	matches := c.Search("matches")
	if !matches.Exists() {
		// A grype doc with no matches array is malformed; an empty image is a
		// present-but-empty array, handled by the loop below.
		return nil, ErrNoConverter
	}

	out := make([]data.Vulnerability, 0, len(matches.Children()))
	for _, m := range matches.Children() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if v, ok := grypeMatch(m); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func grypeMatch(m *gabs.Container) (data.Vulnerability, bool) {
	vuln := m.Search("vulnerability")
	art := m.Search("artifact")
	if !vuln.Exists() || !art.Exists() {
		return data.Vulnerability{}, false
	}

	// relatedVulnerabilities[0] carries the authoritative NVD record when the
	// primary match is a distro advisory; prefer it for id/severity/score.
	rel := m.Search("relatedVulnerabilities").Index(0)

	v := data.Vulnerability{
		Exposure: parser.FirstNonEmpty(rel.Search("id").Data(), vuln.Search("id").Data()),
		Package:  parser.String(art, "name"),
		Version:  parser.String(art, "version"),
		Severity: data.NormalizeSeverity(parser.FirstNonEmpty(
			rel.Search("severity").Data(), vuln.Search("severity").Data())),
		Score:   grypeScore(rel.Search("cvss"), vuln.Search("cvss")),
		IsFixed: parser.ToString(vuln.Search("fix", "state").Data()) == "fixed",
	}
	if v.Exposure == "" {
		return data.Vulnerability{}, false
	}
	return v, true
}

// grypeScore walks the cvss arrays (related first, then primary), preferring the
// highest CVSS v3 base score, falling back to v2. Version is read as a string
// defensively — some grype versions emit it non-string.
func grypeScore(sources ...*gabs.Container) float32 {
	var v2, v3 float32
	for _, src := range sources {
		if !src.Exists() {
			continue
		}
		for _, cvss := range src.Children() {
			score := parser.ToFloat32(cvss.Search("metrics", "baseScore").Data())
			switch parser.ToString(cvss.Search("version").Data()) {
			case "2.0":
				if score > v2 {
					v2 = score
				}
			case "3.0", "3.1":
				if score > v3 {
					v3 = score
				}
			}
		}
	}
	if v3 > 0 {
		return v3
	}
	return v2
}
