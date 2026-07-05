package server

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/oauth"
	"github.com/thingzio/devradar/pkg/tenant"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

const (
	sessionTTL    = 7 * 24 * time.Hour
	oauthStateTTL = 10 * time.Minute
	loginPath     = "/"
)

// OAuthConfig wraps the GitHub OAuth config; nil disables the UI (API-only).
type OAuthConfig struct {
	GitHub *oauth.Config
}

// NewOAuthConfigFromEnv builds OAuth config from env, or nil if unconfigured.
func NewOAuthConfigFromEnv() *OAuthConfig {
	id := config.GetEnv("GITHUB_OAUTH_CLIENT_ID", "")
	secret := config.GetEnv("GITHUB_OAUTH_CLIENT_SECRET", "")
	if id == "" || secret == "" {
		return nil
	}
	return &OAuthConfig{GitHub: &oauth.Config{
		ClientID:     id,
		ClientSecret: secret,
		RedirectURL:  config.BaseURL() + "/auth/github/callback",
	}}
}

// registerUI wires the OAuth login flow and the token-management page. If OAuth
// is unconfigured the UI is disabled and only the JSON API is served.
func (s *Server) registerUI(mux *http.ServeMux, db *sql.DB) {
	if s.oauth == nil || s.oauth.GitHub == nil {
		mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"service": "devradar", "ui": "disabled (OAuth not configured)",
			})
		})
		return
	}

	mux.HandleFunc("GET /", s.handleLanding)
	mux.HandleFunc("GET /auth/github", s.handleLogin)
	mux.HandleFunc("GET /auth/github/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	authed := middleware.RequireAuth(db, loginPath)
	mux.Handle("GET /tokens", authed(http.HandlerFunc(s.handleTokensPage)))
	mux.Handle("POST /tokens", authed(http.HandlerFunc(s.handleCreateToken)))
	mux.Handle("POST /tokens/{id}/revoke", authed(http.HandlerFunc(s.handleRevokeToken)))
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	// If already signed in, go to tokens.
	if c, err := r.Cookie(middleware.SessionCookieName()); err == nil {
		if _, err := tenant.ValidateSession(r.Context(), s.store.DB(), c.Value); err == nil {
			http.Redirect(w, r, "/tokens", http.StatusFound)
			return
		}
	}
	render(w, "landing.html", map[string]any{"Error": r.URL.Query().Get("error")})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()
	http.SetCookie(w, stateCookie(state))
	http.Redirect(w, r, s.oauth.GitHub.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// CSRF: state cookie must match the query param.
	sc, err := r.Cookie("oauth_state")
	if err != nil || sc.Value == "" || sc.Value != r.URL.Query().Get("state") {
		http.Redirect(w, r, loginPath+"?error=state", http.StatusFound)
		return
	}
	token, err := s.oauth.GitHub.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		slog.Warn("oauth exchange failed", "error", err)
		http.Redirect(w, r, loginPath+"?error=oauth", http.StatusFound)
		return
	}
	gu, err := s.oauth.GitHub.User(ctx, token)
	if err != nil {
		slog.Warn("oauth user fetch failed", "error", err)
		http.Redirect(w, r, loginPath+"?error=oauth", http.StatusFound)
		return
	}
	tn, err := tenant.UpsertTenant(ctx, s.store.DB(), gu.ID, gu.Login, gu.Email, gu.AvatarURL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	sess, err := tenant.CreateSession(ctx, s.store.DB(), tn.ID, sessionTTL)
	if err != nil {
		http.Redirect(w, r, loginPath+"?error=server", http.StatusFound)
		return
	}
	middleware.SetSessionCookie(w, sess, int(sessionTTL.Seconds()))
	http.Redirect(w, r, "/tokens", http.StatusFound)
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
		"Username": tn.Username,
		"Tokens":   tokens,
		"NewToken": r.URL.Query().Get("new"), // shown once after creation
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
	// Show the raw token once via a redirect param (it is never stored).
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

// ── helpers ───────────────────────────────────────────────────────────────────

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template render", "template", name, "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func stateCookie(state string) *http.Cookie {
	return &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   int(oauthStateTTL.Seconds()),
		Secure:   config.BaseURL()[:5] == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
