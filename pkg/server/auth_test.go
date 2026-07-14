package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
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
	adminID := seedLegacyUser(t, st, tenantID)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}

	// Find and revoke the token we just minted.
	toks, err := st.ListAPITokens(ctx, tenantID, actor)
	if err != nil || len(toks) != 1 {
		t.Fatalf("list tokens: %v (n=%d)", err, len(toks))
	}
	if err := st.RevokeAPIToken(ctx, tenantID, toks[0].ID, actor, randomHex(t, 16)); err != nil {
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

	userID := seedLegacyUser(t, st, tenantID)
	raw, err := st.CreateSession(context.Background(), userID, &tenantID, -time.Hour)
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

// TestSession_SuspendedAccount redirects to the chooser without clearing the
// authenticated user's session.
func TestSession_SuspendedAccount(t *testing.T) {
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
	if loc := rec.Header().Get("Location"); loc != "/accounts?error=unavailable" {
		t.Errorf("redirect = %q, want unavailable chooser", loc)
	}
	for _, responseCookie := range rec.Result().Cookies() {
		if responseCookie.Name == middleware.SessionCookieName() && responseCookie.MaxAge < 0 {
			t.Fatal("suspended account cleared user session cookie")
		}
	}
	if _, err := st.ValidateSession(context.Background(), cookie.Value); err != nil {
		t.Fatalf("suspended account destroyed user session: %v", err)
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

func TestAccessContextChromeUsesActorAndAccountFields(t *testing.T) {
	srv, st := testServer(t)
	accountID, _ := seedTenantToken(t, st)
	userID := seedLegacyUser(t, st, accountID)
	ctx := context.Background()
	actorEmail := "actor-" + accountID[:8] + "@example.com"
	actorAvatar := "https://avatars.githubusercontent.com/u/12345"
	accountName := "Shared account " + accountID[:8]
	legacyEmail := tenantEmail(t, st, accountID)
	legacyAvatar := "https://avatars.githubusercontent.com/u/67890"
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_user SET email=$2,avatar_url=$3 WHERE id=$1`,
		userID, actorEmail, actorAvatar); err != nil {
		t.Fatalf("set actor profile: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_tenant SET name=$2,avatar_url=$3 WHERE id=$1`,
		accountID, accountName, legacyAvatar); err != nil {
		t.Fatalf("set account chrome fields: %v", err)
	}
	raw, err := st.CreateSession(ctx, userID, &accountID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName(), Value: raw})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{actorEmail, actorAvatar, accountName, "admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview chrome missing %q", want)
		}
	}
	for _, forbidden := range []string{legacyEmail, legacyAvatar} {
		if strings.Contains(body, forbidden) {
			t.Errorf("overview chrome contains legacy account identity %q", forbidden)
		}
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
	adminA := seedLegacyUser(t, st, tenantA)
	adminB := seedLegacyUser(t, st, tenantB)

	toks, err := st.ListAPITokens(ctx, tenantA, account.Actor{Kind: account.ActorUser, UserID: adminA})
	if err != nil || len(toks) != 1 {
		t.Fatalf("list A tokens: %v", err)
	}
	// B tries to revoke A's token → must error, and A's token must still work.
	if err := st.RevokeAPIToken(ctx, tenantB, toks[0].ID,
		account.Actor{Kind: account.ActorUser, UserID: adminB}, randomHex(t, 16)); err == nil {
		t.Error("cross-tenant revoke should fail")
	}
	if _, _, err := st.ValidateAPIToken(ctx, tokA); err != nil {
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

	post := func(val string) *httptest.ResponseRecorder {
		csrfCookie, token := csrfFor(t, h, cookie, "/tokens")
		req := httptest.NewRequest(http.MethodPost, "/settings/min-severity",
			strings.NewReader("min_severity="+val+"&csrf_token="+token))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		req.AddCookie(csrfCookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Valid → persisted (303 redirect back to /tokens).
	validResponse := post("high")
	if code := validResponse.Code; code != http.StatusSeeOther {
		t.Errorf("valid min_severity: status = %d, want 303", code)
	}
	tn, err := tenant.GetTenant(ctx, st.DB(), tenantID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if tn.MinSeverity != "high" {
		t.Errorf("min_severity = %q, want high", tn.MinSeverity)
	}
	var actorKind, actorUserID, requestID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT actor_kind,actor_user_id::text,request_id
		FROM devradar_audit_event
		WHERE account_id=$1 AND action='account.min_severity.update'`, tenantID).
		Scan(&actorKind, &actorUserID, &requestID); err != nil {
		t.Fatalf("read browser setting audit: %v", err)
	}
	if actorKind != "user" || actorUserID == "" || requestID != validResponse.Header().Get("X-Request-ID") {
		t.Fatalf("browser setting attribution = %s/%s/%s, response %s", actorKind,
			actorUserID, requestID, validResponse.Header().Get("X-Request-ID"))
	}

	// Invalid → 400, stored value unchanged.
	if response := post("banana"); response.Code != http.StatusBadRequest {
		t.Errorf("invalid min_severity: status = %d, want 400", response.Code)
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

	raw, err := st.CreateLoginToken(ctx, "magic@example.com", 15*time.Minute)
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
	// The confirm page sets a CSRF cookie and embeds the token, but must NOT set a
	// session cookie (no consume). POST /auth/verify is CSRF-protected (login-CSRF
	// defense), so capture the double-submit pair the confirm page issued.
	var csrfCookie *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		switch c.Name {
		case middleware.SessionCookieName():
			t.Error("verify GET must not set a session cookie (no consume)")
		case middleware.CSRFCookieName():
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("verify GET must set a CSRF cookie for the confirm form")
	}
	csrfTok := scrapeCSRF(t, getRec.Body.String())

	// POST consumes the still-valid token and mints a session.
	postReq := httptest.NewRequest(http.MethodPost, "/auth/verify",
		strings.NewReader("token="+raw+"&csrf_token="+csrfTok))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(csrfCookie)
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

	// Reuse the same token → single-use, must fail to /?error=used. (Still passes
	// CSRF; single-use rejection happens after.)
	reuseReq := httptest.NewRequest(http.MethodPost, "/auth/verify",
		strings.NewReader("token="+raw+"&csrf_token="+csrfTok))
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseReq.AddCookie(csrfCookie)
	reuseRec := httptest.NewRecorder()
	h.ServeHTTP(reuseRec, reuseReq)
	if loc := reuseRec.Header().Get("Location"); !strings.Contains(loc, "error=used") {
		t.Errorf("reused token redirect = %q, want ?error=used", loc)
	}
}

// TestMagicLink_VerifyRequiresCSRF asserts POST /auth/verify is CSRF-protected:
// a forged cross-site POST carrying an attacker-owned magic-link token but no
// double-submit CSRF pair is rejected with 403, so it cannot silently sign a
// victim into the attacker's tenant (login-CSRF). The token is never consumed.
func TestMagicLink_VerifyRequiresCSRF(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	ctx := context.Background()

	raw, err := st.CreateLoginToken(ctx, "csrf-victim@example.com", 15*time.Minute)
	if err != nil {
		t.Fatalf("create login token: %v", err)
	}

	// POST with a valid token but no csrf_token field / cookie → 403, no session.
	req := httptest.NewRequest(http.MethodPost, "/auth/verify", strings.NewReader("token="+raw))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged verify POST: status = %d, want 403", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.SessionCookieName() && c.Value != "" {
			t.Error("forged verify POST must not mint a session cookie")
		}
	}

	// The token must survive (not consumed) — a subsequent legitimate confirm can
	// still peek it. PeekLoginToken succeeds only if the token is still valid.
	if _, err := st.PeekLoginToken(ctx, raw); err != nil {
		t.Errorf("token should be unconsumed after rejected CSRF POST, got: %v", err)
	}
}

func TestMagicLink_MemberlessUserRedirectsToAccounts(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	ctx := context.Background()
	suffix, err := authn.NewToken("")
	if err != nil {
		t.Fatalf("generate email suffix: %v", err)
	}
	email := "memberless-magic-" + suffix[:8] + "@example.com"
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at)
		VALUES ($1,now()) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("seed memberless user: %v", err)
	}
	raw, err := st.CreateLoginToken(ctx, email, 15*time.Minute)
	if err != nil {
		t.Fatalf("create login token: %v", err)
	}
	getReq := httptest.NewRequest(http.MethodGet, "/auth/verify?token="+raw, nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var csrfCookie *http.Cookie
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == middleware.CSRFCookieName() {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("verify GET did not set CSRF cookie")
	}
	csrfToken := scrapeCSRF(t, getRec.Body.String())
	postReq := httptest.NewRequest(http.MethodPost, "/auth/verify",
		strings.NewReader("token="+raw+"&csrf_token="+csrfToken))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(csrfCookie)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if got := postRec.Header().Get("Location"); got != "/accounts" {
		t.Fatalf("memberless verify redirect = %q, want /accounts", got)
	}
	var sessionRaw string
	for _, cookie := range postRec.Result().Cookies() {
		if cookie.Name == middleware.SessionCookieName() {
			sessionRaw = cookie.Value
		}
	}
	if sessionRaw == "" {
		t.Fatal("memberless verify did not create user session")
	}
	session, err := st.ValidateSession(ctx, sessionRaw)
	if err != nil {
		t.Fatalf("validate memberless session: %v", err)
	}
	if session.User.ID != userID || session.ActiveAccountID != nil {
		t.Fatalf("memberless session = %#v, want user %s with nil account", session, userID)
	}
	var accounts int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant WHERE email=$1`, email).Scan(&accounts); err != nil {
		t.Fatalf("count personal accounts: %v", err)
	}
	if accounts != 0 {
		t.Fatalf("memberless login created %d personal accounts, want 0", accounts)
	}
}
