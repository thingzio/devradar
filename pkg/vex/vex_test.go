package vex

import "testing"

const dig = "sha256:6f5a644135887b2aa7d5cc145072fa56421560e3586ff1f184358022d490f4e1"

func TestParse_OpenVEX(t *testing.T) {
	doc := `{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "author": "security@acme.example",
	  "timestamp": "2026-07-01T00:00:00Z",
	  "statements": [
	    {"vulnerability": {"name": "CVE-2025-0001"},
	     "products": [{"@id": "pkg:oci/app@` + dig + `"}],
	     "status": "not_affected",
	     "justification": "vulnerable_code_not_in_execute_path"},
	    {"vulnerability": "CVE-2025-0002",
	     "products": [{"@id": "` + dig + `"}],
	     "status": "under_investigation"}
	  ]
	}`
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Author != "security@acme.example" {
		t.Errorf("author = %q", d.Author)
	}
	if len(d.Statements) != 2 {
		t.Fatalf("statements = %d, want 2", len(d.Statements))
	}
	s0 := d.Statements[0]
	if s0.ProductDigest != dig || s0.Vulnerability != "CVE-2025-0001" || s0.Status != StatusNotAffected {
		t.Errorf("stmt0 = %+v", s0)
	}
	// Bare-string vulnerability form also resolves.
	if d.Statements[1].Vulnerability != "CVE-2025-0002" {
		t.Errorf("stmt1 vuln = %q", d.Statements[1].Vulnerability)
	}
}

func TestParse_Rejections(t *testing.T) {
	cases := map[string]string{
		"not_affected without justification": `{"statements":[{"vulnerability":"CVE-1","products":[{"@id":"` + dig + `"}],"status":"not_affected"}]}`,
		"invalid status":                     `{"statements":[{"vulnerability":"CVE-1","products":[{"@id":"` + dig + `"}],"status":"maybe"}]}`,
		"no statements":                      `{"statements":[]}`,
		"not json":                           `{nope`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParse_SkipsUnresolvableProduct(t *testing.T) {
	// A product with no digest is skipped, not fatal — but if none resolve, error.
	doc := `{"statements":[
	  {"vulnerability":"CVE-1","products":[{"@id":"pkg:oci/app:latest"}],"status":"affected"},
	  {"vulnerability":"CVE-2","products":[{"@id":"` + dig + `"}],"status":"fixed"}]}`
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(d.Statements) != 1 || d.Skipped != 1 {
		t.Errorf("want 1 resolved + 1 skipped, got %d resolved / %d skipped", len(d.Statements), d.Skipped)
	}
}
