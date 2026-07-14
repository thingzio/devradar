package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

const anonymousUser = "<anonymous>"

// IsAdmin reports whether email is on the operator allowlist
// (DEVRADAR_ADMIN_USERS). Comparison is case-insensitive; DevRadar's identity is
// a verified email, so the allowlist is emails, not usernames.
func IsAdmin(email string) bool {
	if email == "" {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(email))
	return slices.Contains(config.AdminUsers(), want)
}

// RequirePlatformAdmin gates the operator console using the actor user's email.
// Any failure — no cookie, invalid session, not an admin — returns 404 (not 403)
// so the console's existence is not disclosed to non-operators. It does not
// require an active account.
func RequirePlatformAdmin(store *postgres.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				slog.Warn("admin access denied", "reason", "missing session", "path", r.URL.Path,
					"request_id", RequestIDFromContext(r.Context()))
				http.NotFound(w, r)
				return
			}
			session, err := store.ValidateSession(r.Context(), cookie.Value)
			if err != nil || session == nil || session.User.Status != "active" || !IsAdmin(session.User.Email) {
				if session != nil && session.User.Status != "active" {
					if destroyErr := store.DestroySession(r.Context(), cookie.Value); destroyErr != nil {
						slog.Error("destroy suspended platform user session",
							"user_id", session.User.ID, "path", r.URL.Path, "error", destroyErr)
					}
					ClearSessionCookie(w)
				}
				slog.Warn("admin access denied",
					"path", r.URL.Path, "remote", r.RemoteAddr, "email", sessionEmail(session),
					"request_id", RequestIDFromContext(r.Context()))
				http.NotFound(w, r)
				return
			}
			actor := account.Actor{Kind: account.ActorPlatform, UserID: session.User.ID}
			ctx := context.WithValue(r.Context(), userContextKey, &session.User)
			ctx = context.WithValue(ctx, actorContextKey, actor)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func sessionEmail(session *account.Session) string {
	if session == nil {
		return anonymousUser
	}
	return session.User.Email
}
