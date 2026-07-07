package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLanding_RendersMarketing verifies the unauthenticated landing page renders
// its marketing content and the sign-in form, and does not leak the authed nav.
func TestLanding_RendersMarketing(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"SBOM vs Image", // the differentiator
		"Daily rescans",                // feature grid
		"VEX suppression",
		"How it works",
		"coming soon",          // deferred features surfaced
		`action="/auth/login"`, // sign-in form present
		"honest note on trust", // trust-model note
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	if strings.Contains(body, `class="tab `) {
		t.Error("signed-out landing must not render authed nav tabs")
	}
}
