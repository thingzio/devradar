package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/oauth"
	"github.com/thingzio/devradar/pkg/ratelimit"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"list": func(items ...string) []string { return items },
	"sorth": func(label, key, base, qs, activeSort, activeDir string) template.HTML {
		return sortHeader(label, key, base, qs, "sort", "dir", activeSort, activeDir)
	},
	"sorthp": sortHeader, // explicit param-prefix variant (e.g. "sbom_sort"/"sbom_dir")
	"signed": signed,     // format a delta int as "+N" / "-N" / "0"
}).ParseFS(templateFS, "templates/*.html"))

// signed renders a delta as a leading-sign string for trend views.
func signed(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprintf("%d", n)
}

// sortHeader renders a clickable sortable column header (a full <a>). base is the
// page path; qs is a query-string prefix carrying the filters to preserve (e.g.
// "min_severity=high&fixable=true", no leading '?'); sortParam/dirParam are the
// query keys to write (usually "sort"/"dir", but a page with two sortable tables
// uses distinct prefixes). Clicking a column sorts descending; clicking the
// active column flips direction. An arrow shows the active column's direction.
func sortHeader(label, key, base, qs, sortParam, dirParam, activeSort, activeDir string) template.HTML {
	arrow, nextDir, cls := "", "desc", "sorth"
	if key == activeSort {
		cls = "sorth active"
		if activeDir == "asc" {
			arrow, nextDir = " ↑", "desc"
		} else {
			arrow, nextDir = " ↓", "asc"
		}
	}
	sep := "?"
	if qs != "" {
		sep = "?" + qs + "&"
	}
	href := fmt.Sprintf("%s%s%s=%s&%s=%s", base, sep, sortParam, template.URLQueryEscaper(key), dirParam, nextDir)
	return template.HTML(fmt.Sprintf(`<a href="%s" class="%s">%s%s</a>`,
		template.HTMLEscapeString(href), cls, template.HTMLEscapeString(label), arrow))
}

const (
	sessionTTL    = 7 * 24 * time.Hour
	loginTokenTTL = 15 * time.Minute
	loginPath     = "/"
)

// registerUI wires the magic-link sign-in flow and the token-management page.
// Auth is passwordless: enter an email, receive a one-time link, click it to get
// a session, then mint API tokens for CI. If no email sender is configured
// (local dev), the magic link is logged instead of sent.
func (s *Server) registerUI(mux *http.ServeMux) {
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /", s.handleLanding)
	mux.HandleFunc("POST /auth/login", s.handleRequestLink)
	mux.HandleFunc("GET /auth/verify", s.handleVerifyConfirm)
	// POST /auth/verify mints a session for the token's tenant, so it must be
	// bound to our own confirm page — otherwise a cross-site form carrying an
	// attacker-owned magic-link token is a login-CSRF: the victim's browser gets
	// a session cookie for the ATTACKER's tenant. The confirm GET seeds a
	// double-submit CSRF cookie (issueCSRF) that a cross-site page can neither
	// read nor set (SameSite=Strict, __Host-), so the forged POST fails.
	mux.Handle("POST /auth/verify", middleware.ValidateCSRF(http.HandlerFunc(s.handleVerify)))

	// GitHub OAuth sign-in — registered only when configured (see Server.github).
	if s.github != nil {
		mux.HandleFunc("GET /auth/github", s.handleGitHubStart)
		mux.HandleFunc("GET /auth/github/callback", s.handleGitHubCallback)
	}

	// Public API docs: a human-readable reference and the machine-readable spec.
	// The endpoints they document require a token, but the docs themselves are
	// open so DevRadar can be evaluated before signing up.
	mux.HandleFunc("GET /api", s.handleAPIDocs)
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPISpec)

	csrf := middleware.ValidateCSRF
	// Logout is CSRF-protected (double-submit) so a cross-site page can't force a
	// victim's session to be cleared. It intentionally does NOT require an active
	// session (authed) — clearing an already-invalid cookie is harmless and idempotent.
	mux.Handle("POST /auth/logout", csrf(http.HandlerFunc(s.handleLogout)))
	requireUser := middleware.RequireUser(s.store, loginPath)
	mux.Handle("GET /accounts", requireUser(http.HandlerFunc(s.handleAccounts)))
	mux.Handle("POST /accounts/select", requireUser(csrf(http.HandlerFunc(s.handleSelectAccount))))
	mux.Handle("POST /accounts/{id}/leave", requireUser(csrf(http.HandlerFunc(s.handleLeaveAccount))))
	s.registerAccountRoutes(mux)

	s.registerAdmin(mux)
}

// registerAdmin wires the operator console. Every route is gated by RequirePlatformAdmin
// (email allowlist, 404 for non-admins — so the surface stays hidden); mutating
// POSTs are additionally CSRF-validated. See handler_admin.go.
func (s *Server) registerAdmin(mux *http.ServeMux) {
	admin := middleware.RequirePlatformAdmin(s.store)
	csrf := middleware.ValidateCSRF

	mux.Handle("GET /admin", admin(http.HandlerFunc(s.handleAdminDashboard)))
	mux.Handle("GET /admin/scans", admin(http.HandlerFunc(s.handleAdminScans)))
	mux.Handle("GET /admin/scans/history", admin(http.HandlerFunc(s.handleAdminScanHistory)))
	mux.Handle("GET /admin/tenants", admin(http.HandlerFunc(s.handleAdminTenants)))
	mux.Handle("GET /admin/tenant/{id}", admin(http.HandlerFunc(s.handleAdminTenantDetail)))
	mux.Handle("GET /admin/metrics", admin(http.HandlerFunc(s.handleAdminMetrics)))

	mux.Handle("POST /admin/tenant/{id}/plan", admin(csrf(http.HandlerFunc(s.handleAdminSetPlan))))
	mux.Handle("POST /admin/tenant/{id}/status", admin(csrf(http.HandlerFunc(s.handleAdminSetStatus))))
	mux.Handle("POST /admin/tenant/{id}/min-severity", admin(csrf(http.HandlerFunc(s.handleAdminSetMinSeverity))))
	mux.Handle("POST /admin/tenant/{id}/delete", admin(csrf(http.HandlerFunc(s.handleAdminDeleteTenant))))
	mux.Handle("POST /admin/tenant/{id}/token/{tid}/revoke", admin(csrf(http.HandlerFunc(s.handleAdminRevokeToken))))
	mux.Handle("POST /admin/invite", admin(csrf(http.HandlerFunc(s.handleAdminInvite))))
	mux.Handle("POST /admin/scans/reset-failure/{id}", admin(csrf(http.HandlerFunc(s.handleAdminResetFailure))))
	mux.Handle("POST /admin/scans/rescan/{sbomID}", admin(csrf(http.HandlerFunc(s.handleAdminRescan))))
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	// Already signed in → the selected account or account chooser.
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		if session, err := s.store.ValidateSession(r.Context(), c.Value); err == nil && session.User.Status == "active" {
			path := "/accounts"
			if session.ActiveAccountID != nil {
				path = "/overview"
			}
			http.Redirect(w, r, path, http.StatusFound)
			return
		}
	}
	render(w, "landing.html", map[string]any{
		"Title":       "Continuous SBOM security posture",
		"SignedIn":    false,
		"Error":       r.URL.Query().Get("error"),
		"Sent":        r.URL.Query().Get("sent") == "1",
		"GitHubOAuth": s.github != nil,
		"Version":     s.opts.Version,
	})
}

// handleRequestLink issues a magic link for the submitted email and sends (or,
// in dev, logs) it. The response is identical whether or not the email already
// has an account — sign-up and sign-in are one flow, and this avoids leaking
// which addresses are registered.
func (s *Server) handleRequestLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Cap the unauthenticated login body — a magic-link request carries only an
	// email field, so a small ceiling is ample and bounds abuse of a pre-auth
	// endpoint.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	email := authn.NormalizeEmail(r.FormValue("email"))
	if !looksLikeEmail(email) {
		http.Redirect(w, r, loginPath+"?error=email", http.StatusSeeOther)
		return
	}

	// Rate-limit magic-link requests per email and per client IP (each hit mints
	// a token row and, in prod, sends an email). Over-limit → generic error, no
	// token minted, no enumeration signal. A limiter DB error fails OPEN (better
	// to allow than lock everyone out on a transient blip).
	db := s.store.DB()
	if s.overLoginLimit(ctx, db, "login-email:"+email, config.LoginRatePerHourEmail()) ||
		s.overLoginLimit(ctx, db, "login-ip:"+clientIP(r), config.LoginRatePerHourIP()) {
		http.Redirect(w, r, loginPath+"?error=ratelimited", http.StatusSeeOther)
		return
	}

	raw, err := s.store.CreateLoginToken(ctx, email, loginTokenTTL)
	if err != nil {
		slog.Error("create login token", "error", err)
		http.Redirect(w, r, loginPath+"?error=server", http.StatusSeeOther)
		return
	}
	link := config.BaseURL() + "/auth/verify?token=" + raw

	if s.email == nil {
		// Dev: no sender configured — log the link so it's usable locally.
		slog.Info("magic link (email sending disabled)", "email", email, "link", link)
	} else {
		subject := "Your DevRadar sign-in link"
		html := fmt.Sprintf(`<p>Click to sign in to DevRadar:</p><p><a href="%s">%s</a></p>`+
			`<p>This link expires in %d minutes and can be used once.</p>`, link, link, int(loginTokenTTL.Minutes()))
		text := fmt.Sprintf("Sign in to DevRadar:\n%s\n\nExpires in %d minutes; single use.",
			link, int(loginTokenTTL.Minutes()))
		if err := s.email.Send(ctx, email, subject, html, text); err != nil {
			slog.Error("send magic link", "error", err)
			http.Redirect(w, r, loginPath+"?error=server", http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, loginPath+"?sent=1", http.StatusSeeOther)
}

// handleVerifyConfirm renders the sign-in confirmation page for a magic link
// (GET /auth/verify?token=...). It only PEEKS the token — it does NOT consume it
// — so an email-security scanner that pre-fetches the link cannot burn the
// single-use token before the human clicks. Consumption happens on the POST from
// the page's button (handleVerify). An invalid/expired token skips straight to
// the landing page with the right message.
func (s *Server) handleVerifyConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if _, err := s.store.PeekLoginToken(r.Context(), token); err != nil {
		http.Redirect(w, r, loginPath+"?error="+loginErrorCode(err), http.StatusFound)
		return
	}
	render(w, "verify.html", map[string]any{
		"Title":     "Confirm sign-in",
		"Token":     token,
		"CSRFToken": issueCSRF(w),
		"Version":   s.opts.Version,
	})
}

// handleVerify consumes a magic-link token (POST from the confirm page), mints a
// session, and lands the user on the overview. Bots/scanners issue GETs, not
// POSTs, so reaching here means a human clicked the confirm button.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity, err := s.store.ConsumeLoginToken(ctx, r.FormValue("token"))
	if err != nil {
		slog.Info("magic link consume failed", "reason", loginErrorCode(err))
		http.Redirect(w, r, loginPath+"?error="+loginErrorCode(err), http.StatusFound)
		return
	}
	user, acct, err := s.store.ResolveDirectIdentity(ctx, identity)
	if err != nil {
		slog.Error("resolve magic-link identity", "error", err)
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	if user.Status == "suspended" {
		http.Redirect(w, r, loginPath+"?error=suspended", http.StatusFound)
		return
	}
	var activeAccountID *string
	if acct != nil {
		activeAccountID = &acct.ID
	}
	sess, err := s.store.CreateSession(ctx, user.ID, activeAccountID, sessionTTL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetSessionCookie(w, sess, int(sessionTTL.Seconds()))
	path := "/accounts"
	if activeAccountID != nil {
		path = "/overview"
	}
	http.Redirect(w, r, path, http.StatusFound)
}

// loginErrorCode maps a login-token error to the query code the landing page
// renders. "expired" (timed out) and "used" (unknown/already consumed) are
// distinguished so the user gets accurate guidance.
func loginErrorCode(err error) string {
	switch {
	case errors.Is(err, postgres.ErrLoginTokenExpired):
		return "expired"
	case errors.Is(err, postgres.ErrLoginTokenInvalid):
		return "used"
	default:
		return "server"
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		_ = s.store.DestroySession(r.Context(), c.Value)
	}
	middleware.ClearSessionCookie(w)
	http.Redirect(w, r, loginPath, http.StatusFound)
}

// oauthStateTTL bounds how long a started OAuth flow may take to complete. Long
// enough for the user to authorize at GitHub, short enough to limit replay of a
// leaked state cookie.
const oauthStateTTL = 10 * time.Minute

// handleGitHubStart begins the GitHub OAuth flow: it mints a random state,
// binds it to the browser in a short-lived HttpOnly cookie (CSRF defense), and
// redirects to GitHub's authorize URL. The callback re-checks the state.
func (s *Server) handleGitHubStart(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		slog.Error("oauth state generation", "error", err)
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetOAuthStateCookie(w, state, int(oauthStateTTL.Seconds()))
	http.Redirect(w, r, s.github.AuthCodeURL(state), http.StatusFound)
}

// handleGitHubCallback completes the flow. It verifies the state matches the
// cookie (CSRF), exchanges the code for a provider-verified identity, resolves
// (or creates) the tenant by that verified email, and mints a session. An
// unverified provider account is rejected with a specific message.
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// CSRF: the state in the query must match the one we set on the browser, and
	// the cookie is single-use — clear it regardless of outcome.
	c, err := r.Cookie(middleware.OAuthStateCookieName())
	middleware.ClearOAuthStateCookie(w)
	state := r.URL.Query().Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		slog.Warn("oauth state mismatch")
		http.Redirect(w, r, loginPath+"?error=oauth", http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, loginPath+"?error=oauth", http.StatusFound)
		return
	}

	id, err := s.github.Exchange(ctx, code)
	if err != nil {
		if errors.Is(err, oauth.ErrNoVerifiedEmail) {
			http.Redirect(w, r, loginPath+"?error=unverified", http.StatusFound)
			return
		}
		slog.Error("github oauth exchange", "error", err)
		http.Redirect(w, r, loginPath+"?error=oauth", http.StatusFound)
		return
	}

	user, acct, err := s.store.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
		Provider: id.Provider, Subject: id.Subject, Email: id.Email, AvatarURL: id.AvatarURL,
	})
	if err != nil {
		slog.Error("resolve identity", "error", err)
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	if user.Status == "suspended" {
		http.Redirect(w, r, loginPath+"?error=suspended", http.StatusFound)
		return
	}

	var activeAccountID *string
	if acct != nil {
		activeAccountID = &acct.ID
	}
	sess, err := s.store.CreateSession(ctx, user.ID, activeAccountID, sessionTTL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetSessionCookie(w, sess, int(sessionTTL.Seconds()))
	path := "/accounts"
	if activeAccountID != nil {
		path = "/overview"
	}
	http.Redirect(w, r, path, http.StatusFound)
}

// randomState returns a 256-bit URL-safe random string for the OAuth state.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) handleTokensPage(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	tokens, err := s.store.ListAPITokens(r.Context(), access.Account.ID,
		middleware.ActorFromContext(r.Context()))
	if err != nil {
		slog.Error("list api tokens", "account_id", access.Account.ID,
			"user_id", access.Actor.ID, "request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "failed to list tokens", http.StatusInternalServerError)
		return
	}
	// Read-and-delete the one-time token flash (set by handleCreateToken). Shown
	// exactly once, never carried in the URL. A failure to read is non-fatal — the
	// page still renders, just without the banner.
	sessionHash, err := requestSessionHash(r)
	if err != nil {
		logMutationFailure(r, "api_token.flash.consume", access.Account.ID, "", err)
		http.Error(w, "failed to load tokens", http.StatusInternalServerError)
		return
	}
	flashKey, err := config.TokenFlashKey()
	if err != nil {
		logMutationFailure(r, "api_token.flash.consume", access.Account.ID, "", err)
		http.Error(w, "failed to load tokens", http.StatusInternalServerError)
		return
	}
	newToken, err := s.store.ConsumeTokenFlash(r.Context(), sessionHash,
		access.Account.ID, flashKey)
	if err != nil {
		slog.Error("consume token flash", "account_id", access.Account.ID,
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
	}
	alertPolicy, err := s.store.EnsureAlertPolicy(r.Context(), access.Account.ID)
	if err != nil {
		http.Error(w, "failed to load alert settings", http.StatusInternalServerError)
		return
	}
	labels, err := s.store.TenantLabels(r.Context(), access.Account.ID)
	if err != nil {
		http.Error(w, "failed to load alert settings", http.StatusInternalServerError)
		return
	}
	selected := make(map[string]struct{}, len(alertPolicy.Labels))
	for _, label := range alertPolicy.Labels {
		selected[label] = struct{}{}
	}
	labelOptions := make([]alertLabelOption, 0, len(labels))
	for _, label := range labels {
		_, ok := selected[label]
		labelOptions = append(labelOptions, alertLabelOption{Label: label, Selected: ok})
	}
	render(w, "tokens.html", tokensView{
		chromeView:  s.chrome(access, "Tokens & settings", ""),
		Tokens:      tokens,
		NewToken:    newToken,
		CSRFToken:   issueCSRF(w),
		MinSeverity: accountMinSeverity(&access.Account),
		Severities:  []string{"critical", "high", "medium", "low", "negligible"},
		AlertPolicy: alertPolicy,
		AlertLabels: labelOptions,
		AlertsSaved: r.URL.Query().Get("alerts") == "saved",
	})
}

type tokensView struct {
	chromeView
	Tokens      []postgres.APITokenInfo
	NewToken    string
	CSRFToken   string
	MinSeverity string
	Severities  []string
	AlertPolicy *postgres.AlertPolicy
	AlertLabels []alertLabelOption
	AlertsSaved bool
}

type alertLabelOption struct {
	Label    string
	Selected bool
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	name := r.FormValue("name")
	if name == "" {
		name = "api-token"
	}
	// Optional expiry: the form's expires_days field (0/absent ⇒ never expires,
	// the historical default). Bounded to a sane maximum to catch fat-fingering.
	ttl := parseTokenTTL(r.FormValue("expires_days"))
	// Enforce the per-tenant token cap ATOMICALLY inside the insert (0 disables it)
	// so a bug or compromised session can't mint unbounded credentials — the old
	// count-then-create was raceable. ErrTokenLimit → 429.
	sessionHash, err := requestSessionHash(r)
	if err != nil {
		logMutationFailure(r, "api_token.create", access.Account.ID, "", err)
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	flashKey, err := config.TokenFlashKey()
	if err != nil {
		logMutationFailure(r, "api_token.create", access.Account.ID, "", err)
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	_, err = s.store.CreateAPIToken(r.Context(), access.Account.ID, access.Actor.ID,
		sessionHash, name, ttl, config.MaxTokensPerTenant(),
		middleware.RequestIDFromContext(r.Context()), flashKey)
	if errors.Is(err, postgres.ErrAPITokenLimit) {
		logMutationDenied(r, "api_token.create", "token quota reached")
		http.Error(w, fmt.Sprintf("token limit reached (%d per tenant); revoke an unused token first",
			config.MaxTokensPerTenant()), http.StatusTooManyRequests)
		return
	}
	if err != nil {
		logMutationFailure(r, "api_token.create", access.Account.ID, "", err)
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	if err := s.store.RevokeAPIToken(r.Context(), access.Account.ID, r.PathValue("id"),
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "api_token.revoke", access.Account.ID, r.PathValue("id"), err)
		http.Error(w, "failed to revoke token", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func requestSessionHash(r *http.Request) (string, error) {
	cookie, err := r.Cookie(middleware.SessionCookieName())
	if err != nil || cookie.Value == "" {
		return "", fmt.Errorf("active session cookie is unavailable")
	}
	return authn.HashToken(cookie.Value), nil
}

func (s *Server) handleSetMinSeverity(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	sev := r.FormValue("min_severity")
	if !data.ValidMinSeverity(sev) {
		logMutationDenied(r, "account.min_severity.update", "invalid severity")
		http.Error(w, "invalid min_severity", http.StatusBadRequest)
		return
	}
	if err := s.store.SetMinSeverityAudited(r.Context(), access.Account.ID, sev,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "account.min_severity.update", access.Account.ID, access.Account.ID, err)
		http.Error(w, "failed to update setting", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) handleSetAlertPolicy(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		logMutationDenied(r, "account.alert_policy.update", "invalid form")
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	minSeverity := r.FormValue("min_severity")
	if !data.ValidMinSeverity(minSeverity) {
		logMutationDenied(r, "account.alert_policy.update", "invalid severity")
		http.Error(w, "invalid min_severity", http.StatusBadRequest)
		return
	}
	knownLabels, err := s.store.TenantLabels(r.Context(), access.Account.ID)
	if err != nil {
		logMutationFailure(r, "account.alert_policy.update", access.Account.ID, access.Account.ID, err)
		http.Error(w, "failed to update alert settings", http.StatusInternalServerError)
		return
	}
	known := make(map[string]struct{}, len(knownLabels))
	for _, label := range knownLabels {
		known[label] = struct{}{}
	}
	labels := normalizeLabels(r.Form["labels"])
	allowed := labels[:0]
	for _, label := range labels {
		if _, ok := known[label]; ok {
			allowed = append(allowed, label)
		}
	}
	policy := postgres.AlertPolicy{
		Enabled:           r.FormValue("enabled") == "on",
		MinSeverity:       minSeverity,
		AlertKEV:          r.FormValue("alert_kev") == "on",
		AlertFixAvailable: r.FormValue("alert_fix_available") == "on",
		IncludeImage:      r.FormValue("include_image") == "on",
		IncludeDB:         r.FormValue("include_db") == "on",
		Labels:            allowed,
	}
	if err := s.store.UpdateAlertPolicyAudited(r.Context(), access.Account.ID, policy,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "account.alert_policy.update", access.Account.ID, access.Account.ID, err)
		http.Error(w, "failed to update alert settings", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens?alerts=saved", http.StatusSeeOther)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func render(w http.ResponseWriter, name string, dataV any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, dataV); err != nil {
		slog.Error("template render", "template", name, "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// accountMinSeverity resolves an account's effective default threshold, falling
// back to the platform default when unset.
func accountMinSeverity(acct *account.Account) string {
	if acct.MinSeverity == "" {
		return data.DefaultMinSeverity
	}
	return acct.MinSeverity
}

// scanStatus renders the scan heartbeat shown in the UI header: a relative
// "last scan" time plus the cadence, so a freshly-submitted SBOM reads as "scan
// pending, results within ~15 min" rather than looking broken. nil (nothing
// scanned yet) yields the pending message.
func scanStatus(last *time.Time) string {
	const cadence = "scans run every 15 min"
	if last == nil {
		return "No scan yet — " + cadence
	}
	return "Last scan " + humanizeSince(time.Since(*last)) + " · " + cadence
}

// humanizeSince renders a duration as a coarse "N <unit> ago" string. Coarse by
// design — the scan cadence is minutes, so second-level precision is noise.
func humanizeSince(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes())) // "min" reads fine singular/plural
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	default:
		return plural(int(d.Hours()/24), "day") + " ago"
	}
}

func plural(n int, unit string) string {
	s := fmt.Sprintf("%d %s", n, unit)
	if n != 1 {
		s += "s"
	}
	return s
}

// overLoginLimit reports whether key has exceeded limit hits this hour. It
// prunes stale windows opportunistically. Fails OPEN: a limiter DB error logs
// and returns false (allow) rather than locking users out on a transient blip.
func (s *Server) overLoginLimit(ctx context.Context, db *sql.DB, key string, limit int) bool {
	allowed, err := ratelimit.Allow(ctx, db, key, limit, time.Hour)
	if err != nil {
		slog.Error("login rate limit check", "error", err)
		return false
	}
	if allowed {
		// Best-effort housekeeping; keeps the counter table small without a cron.
		if perr := ratelimit.Prune(ctx, db, 24*time.Hour); perr != nil {
			slog.Warn("prune rate events", "error", perr)
		}
	}
	return !allowed
}

// clientIP extracts the caller's IP for rate-limit keying. It reads
// X-Forwarded-For from the RIGHT, not the left: the client controls its own XFF
// header, and infrastructure (Cloud Run's Google front end) only APPENDS the
// hop it observed. So the left-most entries are attacker-spoofable, while the
// entry `trustedProxies` from the right is the address the nearest trusted proxy
// actually saw. With the Cloud Run default of 1 appended hop, that's the last
// entry. Taking the left-most (the old behavior) let a client send
// `X-Forwarded-For: <random>` to mint a fresh rate-limit key per request and
// defeat the per-IP login limiter. Falls back to RemoteAddr host when the header
// is absent (local/dev).
func clientIP(r *http.Request) string {
	trusted := config.TrustedProxyCount()
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && trusted > 0 {
		parts := strings.Split(xff, ",")
		// The right-most `trusted` entries were added by our own proxies; the one
		// just before them is the furthest hop we can still trust.
		// fewer hops than expected → fall back to the left-most present entry.
		idx := max(len(parts)-trusted, 0)
		if ip := strings.TrimSpace(parts[idx]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// parseTokenTTL turns an "expires_days" form value into a token lifetime. An
// empty, zero, negative, or unparseable value yields 0 (never expires — the
// historical default). Bounded to 10 years to catch obvious fat-fingering.
func parseTokenTTL(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days <= 0 {
		return 0
	}
	const maxDays = 3650
	if days > maxDays {
		days = maxDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// looksLikeEmail is a minimal sanity check — real validation is that the link is
// only deliverable to a controllable mailbox.
func looksLikeEmail(s string) bool {
	at := -1
	for i, c := range s {
		if c == '@' {
			if at != -1 {
				return false // more than one @
			}
			at = i
		}
	}
	return at > 0 && at < len(s)-1
}
