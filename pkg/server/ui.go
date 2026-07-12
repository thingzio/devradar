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

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/oauth"
	"github.com/thingzio/devradar/pkg/ratelimit"
	"github.com/thingzio/devradar/pkg/tenant"
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
	tokenFlashTTL = 2 * time.Minute // one-time API-token display window
	loginPath     = "/"
)

// registerUI wires the magic-link sign-in flow and the token-management page.
// Auth is passwordless: enter an email, receive a one-time link, click it to get
// a session, then mint API tokens for CI. If no email sender is configured
// (local dev), the magic link is logged instead of sent.
func (s *Server) registerUI(mux *http.ServeMux, db *sql.DB) {
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

	authed := middleware.RequireAuth(db, loginPath)
	csrf := middleware.ValidateCSRF
	// Logout is CSRF-protected (double-submit) so a cross-site page can't force a
	// victim's session to be cleared. It intentionally does NOT require an active
	// session (authed) — clearing an already-invalid cookie is harmless and idempotent.
	mux.Handle("POST /auth/logout", csrf(http.HandlerFunc(s.handleLogout)))
	mux.Handle("GET /overview", authed(http.HandlerFunc(s.handleOverview)))
	mux.Handle("GET /search", authed(http.HandlerFunc(s.handleSearch)))
	mux.Handle("GET /dashboard", authed(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /trends", authed(http.HandlerFunc(s.handleTrends)))
	mux.Handle("GET /images", authed(http.HandlerFunc(s.handleImageDetail)))
	mux.Handle("GET /compare", authed(http.HandlerFunc(s.handleCompare)))
	mux.Handle("GET /sboms/{id}", authed(http.HandlerFunc(s.handleSBOMDetail)))
	mux.Handle("POST /sboms/{id}/archive", authed(csrf(http.HandlerFunc(s.handleArchiveSBOMUI))))
	mux.Handle("POST /images/archive", authed(csrf(http.HandlerFunc(s.handleArchiveRepoUI))))
	mux.Handle("GET /cves", authed(http.HandlerFunc(s.handleCVEList)))
	mux.Handle("GET /work", authed(http.HandlerFunc(s.handleWorkQueue)))
	mux.Handle("GET /cves/{cve}", authed(http.HandlerFunc(s.handleCVEDetail)))
	mux.Handle("GET /licenses", authed(http.HandlerFunc(s.handleLicensesPage)))
	mux.Handle("GET /licenses/family", authed(http.HandlerFunc(s.handleLicenseFamily)))
	mux.Handle("GET /alerts", authed(http.HandlerFunc(s.handleAlerts)))
	mux.Handle("GET /alerts/{id}", authed(http.HandlerFunc(s.handleAlertDetail)))
	mux.Handle("POST /alerts/{id}/read", authed(csrf(http.HandlerFunc(s.handleMarkAlertRead))))
	mux.Handle("POST /settings/license-policy", authed(csrf(http.HandlerFunc(s.handleSetLicensePolicy))))
	mux.Handle("GET /docs", authed(http.HandlerFunc(s.handleSubmitGuide)))
	// /submit is the historical path — keep it working (bookmarks, older links)
	// by redirecting to the renamed /docs page.
	mux.Handle("GET /submit", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	})))
	// VEX upload is a multipart file POST: it cannot use the ValidateCSRF wrapper
	// (which caps the body at 4KB), so the handler parses its own form and calls
	// middleware.CheckCSRF after ParseMultipartForm.
	mux.Handle("POST /vex/upload", authed(http.HandlerFunc(s.handleUploadVEX)))
	mux.Handle("GET /tokens", authed(http.HandlerFunc(s.handleTokensPage)))
	mux.Handle("POST /tokens", authed(csrf(http.HandlerFunc(s.handleCreateToken))))
	mux.Handle("POST /tokens/{id}/revoke", authed(csrf(http.HandlerFunc(s.handleRevokeToken))))
	mux.Handle("POST /settings/min-severity", authed(csrf(http.HandlerFunc(s.handleSetMinSeverity))))
	mux.Handle("POST /settings/alerts", authed(csrf(http.HandlerFunc(s.handleSetAlertPolicy))))

	s.registerAdmin(mux, db)
}

// registerAdmin wires the operator console. Every route is gated by RequireAdmin
// (email allowlist, 404 for non-admins — so the surface stays hidden); mutating
// POSTs are additionally CSRF-validated. See handler_admin.go.
func (s *Server) registerAdmin(mux *http.ServeMux, db *sql.DB) {
	admin := middleware.RequireAdmin(db)
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
	// Already signed in → straight to the dashboard.
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		if _, err := tenant.ValidateSession(r.Context(), s.store.DB(), c.Value); err == nil {
			http.Redirect(w, r, "/overview", http.StatusFound)
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
	email := tenant.NormalizeEmail(r.FormValue("email"))
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

	raw, err := tenant.CreateLoginToken(ctx, db, email, loginTokenTTL)
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
	if _, err := tenant.PeekLoginToken(r.Context(), s.store.DB(), token); err != nil {
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
	tn, err := tenant.ConsumeLoginToken(ctx, s.store.DB(), r.FormValue("token"))
	if err != nil {
		slog.Info("magic link consume failed", "reason", loginErrorCode(err))
		http.Redirect(w, r, loginPath+"?error="+loginErrorCode(err), http.StatusFound)
		return
	}
	if tn.Status == tenant.StatusSuspended {
		http.Redirect(w, r, loginPath+"?error=suspended", http.StatusFound)
		return
	}
	sess, err := tenant.CreateSession(ctx, s.store.DB(), tn.ID, sessionTTL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetSessionCookie(w, sess, int(sessionTTL.Seconds()))
	http.Redirect(w, r, "/overview", http.StatusFound)
}

// loginErrorCode maps a login-token error to the query code the landing page
// renders. "expired" (timed out) and "used" (unknown/already consumed) are
// distinguished so the user gets accurate guidance.
func loginErrorCode(err error) string {
	switch {
	case errors.Is(err, tenant.ErrLoginTokenExpired):
		return "expired"
	case errors.Is(err, tenant.ErrLoginTokenInvalid):
		return "used"
	default:
		return "server"
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		_ = tenant.DestroySession(r.Context(), s.store.DB(), c.Value)
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

	tn, err := tenant.ResolveByIdentity(ctx, s.store.DB(), tenant.ProviderGitHub, id.Subject, id.Email, id.AvatarURL)
	if err != nil {
		slog.Error("resolve identity", "error", err)
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	if tn.Status == tenant.StatusSuspended {
		http.Redirect(w, r, loginPath+"?error=suspended", http.StatusFound)
		return
	}

	sess, err := tenant.CreateSession(ctx, s.store.DB(), tn.ID, sessionTTL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetSessionCookie(w, sess, int(sessionTTL.Seconds()))
	http.Redirect(w, r, "/overview", http.StatusFound)
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
	tn := middleware.TenantFromContext(r.Context())
	tokens, err := tenant.ListAPITokens(r.Context(), s.store.DB(), tn.ID)
	if err != nil {
		http.Error(w, "failed to list tokens", http.StatusInternalServerError)
		return
	}
	// Read-and-delete the one-time token flash (set by handleCreateToken). Shown
	// exactly once, never carried in the URL. A failure to read is non-fatal — the
	// page still renders, just without the banner.
	newToken, err := tenant.ConsumeTokenFlash(r.Context(), s.store.DB(), tn.ID, config.TokenFlashKey())
	if err != nil {
		slog.Error("consume token flash", "error", err)
	}
	alertPolicy, err := s.store.EnsureAlertPolicy(r.Context(), tn.ID)
	if err != nil {
		http.Error(w, "failed to load alert settings", http.StatusInternalServerError)
		return
	}
	labels, err := s.store.TenantLabels(r.Context(), tn.ID)
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
	render(w, "tokens.html", map[string]any{
		"Title":       "Tokens & settings",
		"SignedIn":    true,
		"Email":       tn.Email,
		"AvatarURL":   tn.AvatarURL,
		"Tokens":      tokens,
		"NewToken":    newToken, // shown once after creation
		"CSRFToken":   issueCSRF(w),
		"MinSeverity": tenantMinSeverity(tn),
		"Severities":  []string{"critical", "high", "medium", "low", "negligible"},
		"AlertPolicy": alertPolicy,
		"AlertLabels": labelOptions,
		"AlertsSaved": r.URL.Query().Get("alerts") == "saved",
		"Version":     s.opts.Version,
	})
}

type alertLabelOption struct {
	Label    string
	Selected bool
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	name := r.FormValue("name")
	if name == "" {
		name = "api-token"
	}
	// Enforce a per-tenant token cap so a bug or a compromised session can't mint
	// unbounded credentials. 0 disables the cap.
	if cap := config.MaxTokensPerTenant(); cap > 0 {
		n, err := tenant.CountAPITokens(r.Context(), s.store.DB(), tn.ID)
		if err != nil {
			http.Error(w, "failed to create token", http.StatusInternalServerError)
			return
		}
		if n >= cap {
			http.Error(w, fmt.Sprintf("token limit reached (%d per tenant); revoke an unused token first", cap),
				http.StatusTooManyRequests)
			return
		}
	}
	// Optional expiry: the form's expires_days field (0/absent ⇒ never expires,
	// the historical default). Bounded to a sane maximum to catch fat-fingering.
	ttl := parseTokenTTL(r.FormValue("expires_days"))
	raw, err := tenant.CreateAPIToken(r.Context(), s.store.DB(), tn.ID, name, ttl)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	// Stash the raw token server-side for one-time display and redirect to a clean
	// URL — never put the secret in the query string (browser history, Referer,
	// logs). The /tokens page reads-and-deletes it once.
	if err := tenant.StashTokenFlash(r.Context(), s.store.DB(), tn.ID, raw, tokenFlashTTL, config.TokenFlashKey()); err != nil {
		slog.Error("stash token flash", "error", err)
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if err := tenant.RevokeAPIToken(r.Context(), s.store.DB(), tn.ID, r.PathValue("id")); err != nil {
		http.Error(w, "failed to revoke token", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) handleSetMinSeverity(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	sev := r.FormValue("min_severity")
	if !data.ValidMinSeverity(sev) {
		http.Error(w, "invalid min_severity", http.StatusBadRequest)
		return
	}
	if err := tenant.SetMinSeverity(r.Context(), s.store.DB(), tn.ID, sev); err != nil {
		http.Error(w, "failed to update setting", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) handleSetAlertPolicy(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	minSeverity := r.FormValue("min_severity")
	if !data.ValidMinSeverity(minSeverity) {
		http.Error(w, "invalid min_severity", http.StatusBadRequest)
		return
	}
	knownLabels, err := s.store.TenantLabels(r.Context(), tn.ID)
	if err != nil {
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
	if err := s.store.UpdateAlertPolicy(r.Context(), tn.ID, policy); err != nil {
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

// tenantMinSeverity resolves a tenant's effective default threshold, falling
// back to the platform default when unset.
func tenantMinSeverity(tn *tenant.Tenant) string {
	if tn.MinSeverity == "" {
		return data.DefaultMinSeverity
	}
	return tn.MinSeverity
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
