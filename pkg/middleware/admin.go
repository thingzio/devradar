package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/tenant"
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

// RequireAdmin gates the operator console. It layers on the normal session
// cookie: resolve the session, then check the tenant email against the allowlist.
// Any failure — no cookie, invalid session, not an admin — returns 404 (not 403)
// so the console's existence is not disclosed to non-operators. On success the
// tenant is injected into the request context.
func RequireAdmin(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			tn, err := tenant.ValidateSession(r.Context(), db, cookie.Value)
			if err != nil || tn == nil || !IsAdmin(tn.Email) {
				slog.Warn("admin access denied",
					"path", r.URL.Path, "remote", r.RemoteAddr, "email", tenantEmail(tn))
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithTenant(r.Context(), tn)))
		})
	}
}

func tenantEmail(tn *tenant.Tenant) string {
	if tn == nil {
		return anonymousUser
	}
	return tn.Email
}
