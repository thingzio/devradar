package server_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateToken_CapEnforced verifies the per-tenant token issuance cap: with
// the cap set to 2, a third create returns 429 and no third token is minted.
func TestCreateToken_CapEnforced(t *testing.T) {
	t.Setenv("DEVRADAR_MAX_TOKENS_PER_TENANT", "2")
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st) // seed already creates 1 token
	cookie := seedSession(t, st, tenantID)
	h := srv.Handler()

	create := func() int {
		csrfCookie, token := csrfFor(t, h, cookie, "/tokens")
		req := httptest.NewRequest(http.MethodPost, "/tokens",
			strings.NewReader("name=x&csrf_token="+token))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		req.AddCookie(csrfCookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Seed made 1; cap is 2 → one more create succeeds (303), then the next 429s.
	if code := create(); code != http.StatusSeeOther {
		t.Fatalf("2nd token create = %d, want 303", code)
	}
	if code := create(); code != http.StatusTooManyRequests {
		t.Errorf("3rd token create = %d, want 429 (cap reached)", code)
	}
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if n != 2 {
		t.Errorf("token count = %d, want 2 (cap held)", n)
	}
}

// TestLogin_RateLimited verifies POST /auth/login is throttled per email: with
// the email limit set to 2, the third request within the window is redirected
// with ?error=ratelimited and mints no additional login token.
func TestLogin_RateLimited(t *testing.T) {
	t.Setenv("DEVRADAR_LOGIN_RATE_EMAIL", "2")
	t.Setenv("DEVRADAR_LOGIN_RATE_IP", "0") // isolate the email limit
	srv, st := testServer(t)
	h := srv.Handler()

	email := "rl-" + hex.EncodeToString(mustRand(t, 6)) + "@example.com"
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/login",
			strings.NewReader("email="+email))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// First two allowed (redirect to ?sent=1).
	for i := range 2 {
		rec := post()
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "sent=1") {
			t.Fatalf("login %d Location = %q, want sent=1", i+1, loc)
		}
	}
	// Third is rate-limited.
	rec := post()
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ratelimited") {
		t.Errorf("3rd login Location = %q, want error=ratelimited", rec.Header().Get("Location"))
	}

	// Only two login tokens were minted for this email.
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_login_token WHERE email=$1`, email).Scan(&n); err != nil {
		t.Fatalf("count login tokens: %v", err)
	}
	if n != 2 {
		t.Errorf("login token rows = %d, want 2 (3rd was rate-limited)", n)
	}
}
