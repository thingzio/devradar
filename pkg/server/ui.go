package server

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/oauth"
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
}).ParseFS(templateFS, "templates/*.html"))

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
func (s *Server) registerUI(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /", s.handleLanding)
	mux.HandleFunc("POST /auth/login", s.handleRequestLink)
	mux.HandleFunc("GET /auth/verify", s.handleVerifyConfirm)
	mux.HandleFunc("POST /auth/verify", s.handleVerify)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

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
	mux.Handle("GET /overview", authed(http.HandlerFunc(s.handleOverview)))
	mux.Handle("GET /search", authed(http.HandlerFunc(s.handleSearch)))
	mux.Handle("GET /dashboard", authed(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /images", authed(http.HandlerFunc(s.handleImageDetail)))
	mux.Handle("GET /sboms/{id}", authed(http.HandlerFunc(s.handleSBOMDetail)))
	mux.Handle("GET /cves", authed(http.HandlerFunc(s.handleCVEList)))
	mux.Handle("GET /cves/{cve}", authed(http.HandlerFunc(s.handleCVEDetail)))
	mux.Handle("GET /licenses", authed(http.HandlerFunc(s.handleLicensesPage)))
	mux.Handle("POST /settings/license-policy", authed(http.HandlerFunc(s.handleSetLicensePolicy)))
	mux.Handle("GET /submit", authed(http.HandlerFunc(s.handleSubmitGuide)))
	mux.Handle("POST /vex/upload", authed(http.HandlerFunc(s.handleUploadVEX)))
	mux.Handle("GET /tokens", authed(http.HandlerFunc(s.handleTokensPage)))
	mux.Handle("POST /tokens", authed(http.HandlerFunc(s.handleCreateToken)))
	mux.Handle("POST /tokens/{id}/revoke", authed(http.HandlerFunc(s.handleRevokeToken)))
	mux.Handle("POST /settings/min-severity", authed(http.HandlerFunc(s.handleSetMinSeverity)))
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
		"Title":       "Sign in",
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
	email := tenant.NormalizeEmail(r.FormValue("email"))
	if !looksLikeEmail(email) {
		http.Redirect(w, r, loginPath+"?error=email", http.StatusSeeOther)
		return
	}

	raw, err := tenant.CreateLoginToken(ctx, s.store.DB(), email, loginTokenTTL)
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
		"Title":   "Confirm sign-in",
		"Token":   token,
		"Version": s.opts.Version,
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

	tn, err := tenant.ResolveByIdentity(ctx, s.store.DB(), tenant.ProviderGitHub, id.Subject, id.Email)
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
	render(w, "tokens.html", map[string]any{
		"Title":       "Tokens & settings",
		"SignedIn":    true,
		"Email":       tn.Email,
		"Tokens":      tokens,
		"NewToken":    r.URL.Query().Get("new"), // shown once after creation
		"MinSeverity": tenantMinSeverity(tn),
		"Severities":  []string{"critical", "high", "medium", "low", "negligible"},
		"Version":     s.opts.Version,
	})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	name := r.FormValue("name")
	if name == "" {
		name = "api-token"
	}
	raw, err := tenant.CreateAPIToken(r.Context(), s.store.DB(), tn.ID, name)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens?new="+raw, http.StatusSeeOther)
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
