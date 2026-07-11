package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTenantMutations_RequireCSRF verifies every authenticated browser mutation
// rejects a session-only POST that carries no CSRF token (403), closing the gap
// where tenant actions relied on SameSite alone. Each route is checked with a
// valid session cookie but no csrf_token field/cookie.
func TestTenantMutations_RequireCSRF(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	cookie := seedSession(t, st, tenantID)
	h := srv.Handler()

	routes := []struct {
		name, path, body string
	}{
		{"create token", "/tokens", "name=x"},
		{"revoke token", "/tokens/00000000-0000-0000-0000-000000000000/revoke", ""},
		{"min severity", "/settings/min-severity", "min_severity=high"},
		{"alert settings", "/settings/alerts", "enabled=on&min_severity=high"},
		{"mark alert read", "/alerts/00000000-0000-0000-0000-000000000000/read", ""},
		{"license policy", "/settings/license-policy", "denied=strong-copyleft"},
		{"archive sbom", "/sboms/nope/archive", ""},
		{"archive image", "/images/archive", "repo=nginx"},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, rt.path, strings.NewReader(rt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s without CSRF = %d, want 403", rt.name, rec.Code)
			}
		})
	}
}

// TestVEXUpload_RequiresCSRF verifies the multipart VEX upload (which validates
// CSRF via middleware.CheckCSRF, not the wrapper) also rejects a missing token.
func TestVEXUpload_RequiresCSRF(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	cookie := seedSession(t, st, tenantID)
	h := srv.Handler()

	// A well-formed multipart body but no csrf_token field.
	body := "--b\r\nContent-Disposition: form-data; name=\"vex\"; filename=\"v.json\"\r\n" +
		"Content-Type: application/json\r\n\r\n{}\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/vex/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("VEX upload without CSRF = %d, want 403", rec.Code)
	}
}

// TestCreateToken_FlashNotInURL verifies the raw API token is delivered via a
// one-time server-side flash, not the redirect URL: the create response
// redirects to a clean /tokens (no secret in Location), the token appears once
// on the next GET, and is gone on a second GET.
func TestCreateToken_FlashNotInURL(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	cookie := seedSession(t, st, tenantID)
	h := srv.Handler()

	// Create a token (CSRF-protected form).
	csrfCookie, token := csrfFor(t, h, cookie, "/tokens")
	req := httptest.NewRequest(http.MethodPost, "/tokens",
		strings.NewReader("name=ci&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create token = %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/tokens" {
		t.Errorf("redirect Location = %q, want clean /tokens (no secret in URL)", loc)
	}
	if strings.Contains(loc, "dr_") || strings.Contains(loc, "new=") {
		t.Errorf("redirect URL leaks the token: %q", loc)
	}

	// First GET shows the token once (from the flash).
	get := func() string {
		rq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
		rq.AddCookie(cookie)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc.Body.String()
	}
	first := get()
	if !strings.Contains(first, "dr_") {
		t.Fatalf("first /tokens GET should show the new token once")
	}
	// Extract the shown token so we can assert it's absent on the next load.
	i := strings.Index(first, "dr_")
	shown := first[i:]
	if j := strings.IndexByte(shown, '<'); j >= 0 {
		shown = shown[:j]
	}
	// Second GET must not re-show that exact token (single-use flash).
	if second := get(); strings.Contains(second, shown) {
		t.Errorf("second /tokens GET should not re-show the token")
	}
}
