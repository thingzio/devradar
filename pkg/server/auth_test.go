package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/tenant"
)

// The tests below cover the auth REJECTION paths — the security boundary that
// carried 0% coverage. Each drives a real HTTP request through the full
// middleware + tenant-store stack (no mocks).

// TestAPIToken_Revoked401 verifies a revoked API token is rejected.
func TestAPIToken_Revoked401(t *testing.T) {
	srv, st := testServer(t)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()

	// Find and revoke the token we just minted.
	toks, err := tenant.ListAPITokens(ctx, st.DB(), tenantID)
	if err != nil || len(toks) != 1 {
		t.Fatalf("list tokens: %v (n=%d)", err, len(toks))
	}
	if err := tenant.RevokeAPIToken(ctx, st.DB(), tenantID, toks[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: status = %d, want 401", rec.Code)
	}
}

// TestAPIToken_MalformedHeader401 verifies missing/malformed Authorization → 401.
func TestAPIToken_MalformedHeader401(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	for _, hdr := range []string{"", "Basic abc", "Bearer", "Token xyz"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", hdr, rec.Code)
		}
	}
}

// TestAPIToken_SuspendedTenant403 verifies a suspended tenant with a valid token
// is rejected with 403 — the account-enforcement boundary.
func TestAPIToken_SuspendedTenant403(t *testing.T) {
	srv, st := testServer(t)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()

	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_tenant SET status = 'suspended' WHERE id = $1`, tenantID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("suspended tenant: status = %d, want 403", rec.Code)
	}
}

// TestSession_Expired redirects to login (and clears the cookie) — the 7-day TTL
// enforcement. Uses a negative TTL to mint an already-expired session.
func TestSession_Expired(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	h := srv.Handler()

	raw, err := tenant.CreateSession(context.Background(), st.DB(), tenantID, -time.Hour)
	if err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName(), Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expired session: status = %d, want 302 redirect", rec.Code)
	}
}

// TestSession_SuspendedTenant redirects to login with ?error=suspended.
func TestSession_SuspendedTenant(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_tenant SET status = 'suspended' WHERE id = $1`, tenantID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("suspended session: status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=suspended") {
		t.Errorf("redirect = %q, want ?error=suspended", loc)
	}
}

// TestSession_NoCookie redirects UI routes to login.
func TestSession_NoCookie(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("no cookie: status = %d, want 302", rec.Code)
	}
}

// TestRevokeAPIToken_CrossTenant verifies tenant B cannot revoke tenant A's
// token — ownership is enforced in the WHERE clause. A dropped tenant_id
// predicate here would let one tenant disable another's CI.
func TestRevokeAPIToken_CrossTenant(t *testing.T) {
	_, st := testServer(t)
	ctx := context.Background()
	tenantA, tokA := seedTenantToken(t, st)
	tenantB, _ := seedTenantToken(t, st)

	toks, err := tenant.ListAPITokens(ctx, st.DB(), tenantA)
	if err != nil || len(toks) != 1 {
		t.Fatalf("list A tokens: %v", err)
	}
	// B tries to revoke A's token → must error, and A's token must still work.
	if err := tenant.RevokeAPIToken(ctx, st.DB(), tenantB, toks[0].ID); err == nil {
		t.Error("cross-tenant revoke should fail")
	}
	if _, err := tenant.ValidateAPIToken(ctx, st.DB(), tokA); err != nil {
		t.Errorf("A's token must still be valid after B's failed revoke: %v", err)
	}
}

// TestSetMinSeverity_ValidAndInvalid exercises the settings mutation handler:
// a valid threshold persists; an invalid one is rejected 400 and does not change
// the stored value (a bad write would corrupt every later severity filter).
func TestSetMinSeverity_ValidAndInvalid(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)
	ctx := context.Background()

	post := func(val string) int {
		csrfCookie, token := csrfFor(t, h, cookie, "/tokens")
		req := httptest.NewRequest(http.MethodPost, "/settings/min-severity",
			strings.NewReader("min_severity="+val+"&csrf_token="+token))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		req.AddCookie(csrfCookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Valid → persisted (303 redirect back to /tokens).
	if code := post("high"); code != http.StatusSeeOther {
		t.Errorf("valid min_severity: status = %d, want 303", code)
	}
	tn, err := tenant.GetTenant(ctx, st.DB(), tenantID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if tn.MinSeverity != "high" {
		t.Errorf("min_severity = %q, want high", tn.MinSeverity)
	}

	// Invalid → 400, stored value unchanged.
	if code := post("banana"); code != http.StatusBadRequest {
		t.Errorf("invalid min_severity: status = %d, want 400", code)
	}
	tn, _ = tenant.GetTenant(ctx, st.DB(), tenantID)
	if tn.MinSeverity != "high" {
		t.Errorf("min_severity after invalid = %q, want unchanged high", tn.MinSeverity)
	}
}

// TestMagicLink_ConsumeAndSession exercises the two-step magic-link verify: GET
// /auth/verify renders a confirm page WITHOUT consuming the token (defeats
// email-scanner prefetch), and POST /auth/verify consumes it, mints a session,
// and redirects to /overview; reusing the token fails (single-use).
func TestMagicLink_ConsumeAndSession(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	ctx := context.Background()

	raw, err := tenant.CreateLoginToken(ctx, st.DB(), "magic@example.com", 15*time.Minute)
	if err != nil {
		t.Fatalf("create login token: %v", err)
	}

	// GET renders the confirm page and MUST NOT consume the token (email scanners
	// issue GETs). 200, no session cookie.
	getReq := httptest.NewRequest(http.MethodGet, "/auth/verify?token="+raw, nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("verify GET: status = %d, want 200 (confirm page)", getRec.Code)
	}
	if len(getRec.Result().Cookies()) != 0 {
		t.Error("verify GET must not set a session cookie (no consume)")
	}

	// POST consumes the still-valid token and mints a session.
	postReq := httptest.NewRequest(http.MethodPost, "/auth/verify", strings.NewReader("token="+raw))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("verify POST: status = %d, want 302", postRec.Code)
	}
	if loc := postRec.Header().Get("Location"); loc != "/overview" {
		t.Errorf("verify POST redirect = %q, want /overview", loc)
	}
	if len(postRec.Result().Cookies()) == 0 {
		t.Error("verify POST should set a session cookie")
	}

	// Reuse the same token → single-use, must fail to /?error=used.
	reuseReq := httptest.NewRequest(http.MethodPost, "/auth/verify", strings.NewReader("token="+raw))
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRec := httptest.NewRecorder()
	h.ServeHTTP(reuseRec, reuseReq)
	if loc := reuseRec.Header().Get("Location"); !strings.Contains(loc, "error=used") {
		t.Errorf("reused token redirect = %q, want ?error=used", loc)
	}
}
