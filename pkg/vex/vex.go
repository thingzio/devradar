// Package vex parses and validates OpenVEX documents into the flat
// (product-digest, CVE, status) statements DevRadar overlays onto findings.
//
// OpenVEX spec: https://github.com/openvex/spec. A document has a list of
// statements, each with a vulnerability, one or more products, a status, and
// (when not_affected) a justification. DevRadar correlates on the product's
// image digest and the vulnerability's CVE id.
//
// A tenant's VEX is their assertion — this package validates *shape* (status
// enum, required justification), never the truth of a claim.
package vex

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Valid OpenVEX statuses.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

var validStatus = map[string]bool{
	StatusNotAffected: true, StatusAffected: true,
	StatusFixed: true, StatusUnderInvestigation: true,
}

// digestRE pulls a sha256 digest out of a product identifier, which may be a
// bare digest, a pkg:oci purl, or a ref@sha256:... string.
var digestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// Statement is one flattened (product, vulnerability) assertion. Exactly one of
// ProductDigest (version-precise) or ProductRepo (all versions of an image) is
// set — real OpenVEX often scopes by image name/PURL with no digest.
type Statement struct {
	ProductDigest   string // sha256:...; empty when scoped by repo
	ProductRepo     string // image name key (e.g. "aicr"); empty when digest-pinned
	Vulnerability   string
	Subcomponent    string // purl, may be empty
	Status          string
	Justification   string
	ImpactStatement string
	Timestamp       string
}

// Document is the parsed result: the author, the raw bytes (for round-trip
// storage), and the flattened statements that resolved to a product digest.
type Document struct {
	Author     string
	Raw        json.RawMessage
	Statements []Statement
	// Skipped counts statements dropped for lacking a resolvable digest — surfaced
	// to the submitter so a mis-scoped VEX isn't silently ineffective.
	Skipped int
}

// ── raw OpenVEX shapes (lenient: fields we don't use are ignored) ─────────────

type rawDoc struct {
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Statements []rawStatement `json:"statements"`
}

type rawStatement struct {
	Vulnerability json.RawMessage `json:"vulnerability"` // string or {name,...}
	Products      []rawProduct    `json:"products"`
	Status        string          `json:"status"`
	Justification string          `json:"justification"`
	ImpactState   string          `json:"impact_statement"`
	Timestamp     string          `json:"timestamp"`
}

type rawProduct struct {
	ID            string          `json:"@id"`
	Identifiers   map[string]any  `json:"identifiers"`
	Subcomponents []rawSubcompStr `json:"subcomponents"`
}

// rawSubcompStr accepts a subcomponent as {"@id": "..."} or a bare string.
type rawSubcompStr struct {
	ID string
}

func (s *rawSubcompStr) UnmarshalJSON(b []byte) error {
	var str string
	if json.Unmarshal(b, &str) == nil {
		s.ID = str
		return nil
	}
	var obj struct {
		ID string `json:"@id"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	s.ID = obj.ID
	return nil
}

// Parse reads an OpenVEX document, validates each statement's shape, and returns
// the flattened statements whose product resolves to an image digest.
func Parse(raw []byte) (*Document, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("vex: not valid JSON")
	}
	var d rawDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("vex: parse: %w", err)
	}
	if len(d.Statements) == 0 {
		return nil, fmt.Errorf("vex: document has no statements")
	}

	out := &Document{Author: d.Author, Raw: append(json.RawMessage(nil), raw...)}
	for i, st := range d.Statements {
		status := strings.ToLower(strings.TrimSpace(st.Status))
		if !validStatus[status] {
			return nil, fmt.Errorf("vex: statement %d: invalid status %q", i, st.Status)
		}
		if status == StatusNotAffected && strings.TrimSpace(st.Justification) == "" {
			return nil, fmt.Errorf("vex: statement %d: not_affected requires a justification", i)
		}
		cve := vulnName(st.Vulnerability)
		if cve == "" {
			return nil, fmt.Errorf("vex: statement %d: missing vulnerability name", i)
		}
		ts := st.Timestamp
		if ts == "" {
			ts = d.Timestamp
		}
		for _, p := range st.Products {
			digest := digestOf(p)
			repo := ""
			if digest == "" {
				// No digest: fall back to a repository key (image name), so the
				// statement scopes to every version of that image.
				repo = repoKeyOf(p)
			}
			if digest == "" && repo == "" {
				out.Skipped++
				continue
			}
			sub := ""
			if len(p.Subcomponents) > 0 {
				sub = p.Subcomponents[0].ID
			}
			out.Statements = append(out.Statements, Statement{
				ProductDigest: digest, ProductRepo: repo, Vulnerability: cve, Subcomponent: sub,
				Status: status, Justification: st.Justification,
				ImpactStatement: st.ImpactState, Timestamp: ts,
			})
		}
	}
	if len(out.Statements) == 0 {
		return nil, fmt.Errorf("vex: no statement resolved to an image digest or name")
	}
	return out, nil
}

// vulnName extracts the CVE id from a vulnerability that may be a bare string or
// an object {"name": "CVE-...", ...}.
func vulnName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return strings.TrimSpace(str)
	}
	var obj struct {
		Name string `json:"name"`
		ID   string `json:"@id"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Name != "" {
			return strings.TrimSpace(obj.Name)
		}
		return digestRE.FindString(obj.ID) // unlikely, but be lenient
	}
	return ""
}

// repoKeyOf derives a repository match key (the image name) from a digest-less
// product identifier — e.g. "pkg:oci/aicr" -> "aicr",
// "pkg:oci/ghcr.io/nvidia/aicr" -> "aicr". The key is the last path segment with
// any tag/version stripped, lowercased. The store matches it against the last
// segment of a tracked repository, so registry-prefix differences don't matter.
func repoKeyOf(p rawProduct) string {
	id := p.ID
	if id == "" {
		if purl, ok := p.Identifiers["purl"].(string); ok {
			id = purl
		}
	}
	if id == "" {
		return ""
	}
	// Strip a pkg:oci/ (or any pkg:type/) PURL scheme prefix.
	if i := strings.Index(id, ":"); i >= 0 && strings.HasPrefix(id, "pkg:") {
		if j := strings.Index(id[i:], "/"); j >= 0 {
			id = id[i+j+1:]
		}
	}
	// Drop PURL qualifiers (?...) and version (@... that isn't a digest handled earlier).
	if i := strings.IndexAny(id, "?@"); i >= 0 {
		id = id[:i]
	}
	// Last path segment.
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	// Strip a :tag.
	if i := strings.LastIndex(id, ":"); i >= 0 {
		id = id[:i]
	}
	return strings.ToLower(strings.TrimSpace(id))
}

// digestOf resolves a product's image digest from its @id or identifiers.
func digestOf(p rawProduct) string {
	if d := digestRE.FindString(p.ID); d != "" {
		return d
	}
	for _, v := range p.Identifiers {
		if s, ok := v.(string); ok {
			if d := digestRE.FindString(s); d != "" {
				return d
			}
		}
	}
	return ""
}
