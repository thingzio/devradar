// Package middleware provides HTTP auth and the tenant context. DevRadar has two
// passwordless auth surfaces: API tokens (Bearer) for CI submitting SBOMs, and
// magic-link session cookies for the token-minting UI.
package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/thingzio/devradar/pkg/tenant"
)

type contextKey string

const tenantContextKey contextKey = "tenant"

const (
	cookieSecure = "__Host-session"
	cookiePlain  = "session"
)

var (
	secure     bool
	cookieName string
)

func init() {
	secure = strings.HasPrefix(os.Getenv("BASE_URL"), "https://")
	if secure {
		cookieName = cookieSecure
	} else {
		cookieName = cookiePlain
	}
}

// SessionCookieName returns the scheme-appropriate cookie name.
func SessionCookieName() string { return cookieName }

// RequireAPIToken validates an Authorization: Bearer token. API routes; 401 JSON
// on failure.
func RequireAPIToken(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearer(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}
			tn, err := tenant.ValidateAPIToken(r.Context(), db, token)
			if err != nil {
				slog.Debug("invalid api token", "error", err)
				writeError(w, http.StatusUnauthorized, "invalid api token")
				return
			}
			if tn.Status == tenant.StatusSuspended {
				writeError(w, http.StatusForbidden, "account suspended")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithTenant(r.Context(), tn)))
		})
	}
}

// RequireAuth validates the session cookie. UI routes; redirects to loginURL on
// failure.
func RequireAuth(db *sql.DB, loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
			tn, err := tenant.ValidateSession(r.Context(), db, cookie.Value)
			if err != nil {
				ClearSessionCookie(w)
				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
			if tn.Status == tenant.StatusSuspended {
				ClearSessionCookie(w)
				http.Redirect(w, r, loginURL+"?error=suspended", http.StatusFound)
				return
			}
			// Ensure a CSRF cookie exists on every authenticated page, so the
			// always-present logout form in the nav can carry a double-submit token
			// even on pages whose handler doesn't otherwise issue one. First-party
			// app.js echoes this cookie into the logout form's hidden field.
			if CSRFTokenFromRequest(r) == "" {
				if token, terr := GenerateCSRFToken(); terr == nil {
					SetCSRFCookie(w, token)
				}
			}
			next.ServeHTTP(w, r.WithContext(WithTenant(r.Context(), tn)))
		})
	}
}

// TenantFromContext returns the authenticated tenant, or nil.
func TenantFromContext(ctx context.Context) *tenant.Tenant {
	if t, ok := ctx.Value(tenantContextKey).(*tenant.Tenant); ok {
		return t
	}
	return nil
}

// WithTenant attaches a tenant to a context (exported for tests).
func WithTenant(ctx context.Context, tn *tenant.Tenant) context.Context {
	return context.WithValue(ctx, tenantContextKey, tn)
}

// SetSessionCookie sets the session cookie with the scheme-appropriate flags.
func SetSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is env-driven (BASE_URL scheme)
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter) { SetSessionCookie(w, "", -1) }

const (
	oauthStateSecure = "__Host-oauth_state"
	oauthStatePlain  = "oauth_state"
)

// oauthStateCookieName is the scheme-appropriate name for the OAuth CSRF state
// cookie (the __Host- prefix is only valid over HTTPS with Secure set).
func oauthStateCookieName() string {
	if secure {
		return oauthStateSecure
	}
	return oauthStatePlain
}

// OAuthStateCookieName returns the scheme-appropriate OAuth state cookie name.
func OAuthStateCookieName() string { return oauthStateCookieName() }

// SetOAuthStateCookie sets the short-lived, HttpOnly OAuth CSRF state cookie.
// SameSite=Lax so it survives the top-level GET redirect back from the provider.
func SetOAuthStateCookie(w http.ResponseWriter, state string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is env-driven (BASE_URL scheme)
		Name:     oauthStateCookieName(),
		Value:    state,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearOAuthStateCookie expires the OAuth state cookie (single-use).
func ClearOAuthStateCookie(w http.ResponseWriter) { SetOAuthStateCookie(w, "", -1) }

func bearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
