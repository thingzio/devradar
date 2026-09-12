// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package middleware provides HTTP authentication and typed request access.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

type contextKey uint8

const (
	userContextKey contextKey = iota
	sessionContextKey
	accessContextKey
	accountContextKey
	actorContextKey
)

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
func RequireAPIToken(store *postgres.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearer(r)
			if token == "" {
				slog.Warn("api authentication denied", "reason", "missing bearer token",
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}
			acct, actor, err := store.ValidateAPIToken(r.Context(), token)
			if err != nil {
				slog.Warn("api authentication denied", "reason", "invalid api token",
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()), "error", err)
				writeError(w, http.StatusUnauthorized, "invalid api token")
				return
			}
			if acct.Status == "suspended" {
				slog.Warn("api authentication denied", "reason", "account suspended",
					"account_id", acct.ID, "path", r.URL.Path,
					"request_id", RequestIDFromContext(r.Context()))
				writeError(w, http.StatusForbidden, "account suspended")
				return
			}
			ctx := context.WithValue(r.Context(), accountContextKey, acct)
			ctx = context.WithValue(ctx, actorContextKey, actor)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireUser authenticates a browser user without requiring an active account.
func RequireUser(store *postgres.Store, loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				slog.Warn("browser authentication denied", "reason", "missing session",
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
			session, err := store.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				slog.Warn("browser authentication denied", "reason", "invalid session",
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				ClearSessionCookie(w)
				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
			if session.User.Status != "active" {
				slog.Warn("browser authentication denied", "reason", "user suspended",
					"user_id", session.User.ID, "path", r.URL.Path,
					"request_id", RequestIDFromContext(r.Context()))
				if err := store.DestroySession(r.Context(), cookie.Value); err != nil {
					slog.Error("destroy suspended user session",
						"user_id", session.User.ID, "path", r.URL.Path,
						"request_id", RequestIDFromContext(r.Context()), "error", err)
				}
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
			actor := account.Actor{Kind: account.ActorUser, UserID: session.User.ID}
			ctx := context.WithValue(r.Context(), userContextKey, &session.User)
			ctx = context.WithValue(ctx, sessionContextKey, session)
			ctx = context.WithValue(ctx, actorContextKey, actor)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAccount revalidates the selected active account and membership.
// RequireUser must wrap it so the authenticated session is present in context.
func RequireAccount(store *postgres.Store, accountsURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := r.Context().Value(sessionContextKey).(*account.Session)
			user := UserFromContext(r.Context())
			if session == nil || user == nil {
				slog.Warn("account authorization denied", "reason", "missing user session",
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				http.Redirect(w, r, accountsURL, http.StatusFound)
				return
			}
			if session.ActiveAccountID == nil {
				slog.Warn("account authorization denied", "reason", "no active account",
					"user_id", user.ID, "path", r.URL.Path,
					"request_id", RequestIDFromContext(r.Context()))
				http.Redirect(w, r, accountsURL, http.StatusFound)
				return
			}
			access, err := store.GetAccess(r.Context(), user.ID, *session.ActiveAccountID)
			if errors.Is(err, postgres.ErrNotFound) {
				slog.Warn("account authorization denied", "reason", "account unavailable",
					"user_id", user.ID, "account_id", *session.ActiveAccountID,
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				reconcileErr := store.ReconcileLegacyAccount(r.Context(), *session.ActiveAccountID)
				switch {
				case reconcileErr == nil:
					access, err = store.GetAccess(r.Context(), user.ID, *session.ActiveAccountID)
				case !errors.Is(reconcileErr, postgres.ErrNotFound):
					err = reconcileErr
				}
			}
			if errors.Is(err, postgres.ErrNotFound) {
				http.Redirect(w, r, unavailableAccountURL(accountsURL), http.StatusFound)
				return
			}
			if err != nil {
				slog.Error("load account access", "user_id", user.ID,
					"account_id", *session.ActiveAccountID, "path", r.URL.Path,
					"request_id", RequestIDFromContext(r.Context()), "error", err)
				http.Error(w, "failed to load account", http.StatusInternalServerError)
				return
			}
			actor := account.Actor{Kind: account.ActorUser, UserID: access.Actor.ID}
			ctx := context.WithValue(r.Context(), accessContextKey, access)
			ctx = context.WithValue(ctx, accountContextKey, &access.Account)
			ctx = context.WithValue(ctx, actorContextKey, actor)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCapability authorizes an active account membership.
// RequireAccount must run first so Access is present in the request context.
func RequireCapability(capability account.Capability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			access := AccessFromContext(r.Context())
			if access == nil || !access.Can(capability) {
				slog.Warn("account authorization denied", "capability", capability,
					"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func unavailableAccountURL(accountsURL string) string {
	separator := "?"
	if strings.Contains(accountsURL, "?") {
		separator = "&"
	}
	return accountsURL + separator + "error=unavailable"
}

// UserFromContext returns the authenticated browser user, or nil.
func UserFromContext(ctx context.Context) *account.User {
	if user, ok := ctx.Value(userContextKey).(*account.User); ok {
		return user
	}
	return nil
}

// AccessFromContext returns the active browser account access, or nil.
func AccessFromContext(ctx context.Context) *account.Access {
	if access, ok := ctx.Value(accessContextKey).(*account.Access); ok {
		return access
	}
	return nil
}

// AccountFromContext returns the authenticated API or browser account, or nil.
func AccountFromContext(ctx context.Context) *account.Account {
	if acct, ok := ctx.Value(accountContextKey).(*account.Account); ok {
		return acct
	}
	return nil
}

// ActorFromContext returns the authenticated user or API-token actor.
func ActorFromContext(ctx context.Context) account.Actor {
	actor, _ := ctx.Value(actorContextKey).(account.Actor)
	return actor
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
