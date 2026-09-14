package server

import (
	"bytes"
	"strings"
	"testing"
)

// TestUICopyOmitsReferenceImplementation renders the landing page that used
// to describe DevRadar as a "reference implementation" and asserts the
// phrase is absent from the rendered output. Asserting on rendered output
// (rather than grepping template source) means the phrase still fails this
// test if it moves into a different template landing.html renders.
func TestUICopyOmitsReferenceImplementation(t *testing.T) {
	const forbidden = "reference implementation"

	// Mirrors the data handleLanding passes to render(w, "landing.html", ...)
	// for the signed-out landing page.
	data := map[string]any{
		"Title":       "Continuous SBOM security posture",
		"SignedIn":    false,
		"Error":       "",
		"Sent":        false,
		"GitHubOAuth": false,
		"Version":     "",
	}

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "landing.html", data); err != nil {
		t.Fatalf("render landing.html: %v", err)
	}
	if body := buf.String(); strings.Contains(body, forbidden) {
		t.Errorf("rendered landing.html still contains %q", forbidden)
	}
}
