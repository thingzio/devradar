package server

import (
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/tenant"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"list": func(items ...string) []string { return items },
}).ParseFS(templateFS, "templates/*.html"))

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
	mux.HandleFunc("GET /auth/verify", s.handleVerify)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	authed := middleware.RequireAuth(db, loginPath)
	mux.Handle("GET /dashboard", authed(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /images", authed(http.HandlerFunc(s.handleImageDetail)))
	mux.Handle("GET /sboms/{id}", authed(http.HandlerFunc(s.handleSBOMDetail)))
	mux.Handle("GET /cves", authed(http.HandlerFunc(s.handleCVEList)))
	mux.Handle("GET /cves/{cve}", authed(http.HandlerFunc(s.handleCVEDetail)))
	mux.Handle("GET /tokens", authed(http.HandlerFunc(s.handleTokensPage)))
	mux.Handle("POST /tokens", authed(http.HandlerFunc(s.handleCreateToken)))
	mux.Handle("POST /tokens/{id}/revoke", authed(http.HandlerFunc(s.handleRevokeToken)))
	mux.Handle("POST /settings/min-severity", authed(http.HandlerFunc(s.handleSetMinSeverity)))
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	// Already signed in → straight to the dashboard.
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		if _, err := tenant.ValidateSession(r.Context(), s.store.DB(), c.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}
	render(w, "landing.html", map[string]any{
		"Title":    "Sign in",
		"SignedIn": false,
		"Error":    r.URL.Query().Get("error"),
		"Sent":     r.URL.Query().Get("sent") == "1",
		"Version":  s.opts.Version,
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

// handleVerify consumes a magic-link token, mints a session, and lands the user
// on the tokens page.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tn, err := tenant.ConsumeLoginToken(ctx, s.store.DB(), r.URL.Query().Get("token"))
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=link", http.StatusFound)
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
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		_ = tenant.DestroySession(r.Context(), s.store.DB(), c.Value)
	}
	middleware.ClearSessionCookie(w)
	http.Redirect(w, r, loginPath, http.StatusFound)
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
