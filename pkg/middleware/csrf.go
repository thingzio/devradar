package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
)

const (
	csrfCookieSecure = "__Host-csrf"
	csrfCookiePlain  = "csrf"
	csrfFormField    = "csrf_token"
	csrfTokenBytes   = 32
)

var csrfCookieName string

func init() {
	if secure {
		csrfCookieName = csrfCookieSecure
	} else {
		csrfCookieName = csrfCookiePlain
	}
}

// CSRFCookieName returns the scheme-appropriate CSRF cookie name.
func CSRFCookieName() string { return csrfCookieName }

// GenerateCSRFToken returns a cryptographically random hex-encoded token.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating csrf token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SetCSRFCookie writes the CSRF token cookie.
//
// Path is always "/": under HTTPS the cookie name carries the __Host- prefix,
// which browsers only accept with Path=/ (and Secure, no Domain). A narrower
// path (e.g. "/admin") is silently dropped, so the token never reaches the
// server and every mutating POST fails "missing CSRF token". Validation is a
// double-submit value compare, not path-scoped, so "/" is safe.
//
// HttpOnly is intentionally false — the double-submit pattern needs the
// server-rendered hidden field to echo the cookie back as a form value.
// SameSite=Strict is the security boundary, not HttpOnly.
func SetCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly:false is intentional for double-submit CSRF
		Name:     CSRFCookieName(),
		Value:    token,
		Path:     "/",
		Secure:   secure,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

// CSRFTokenFromRequest reads the CSRF token from the cookie.
func CSRFTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CSRFCookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

// ValidateCSRF rejects mutating requests whose csrf_token form field does not
// match the CSRF cookie (double-submit cookie pattern). GET/HEAD/OPTIONS pass
// through unchanged.
func ValidateCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		cookieToken := CSRFTokenFromRequest(r)
		// Bound the body before parsing the form. Handlers may set their own
		// stricter limit; this is a safe ceiling for the token check.
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		formToken := r.FormValue(csrfFormField)

		if cookieToken == "" || formToken == "" {
			slog.Warn("csrf: missing token",
				"path", r.URL.Path, "remote", r.RemoteAddr,
				"has_cookie", cookieToken != "", "has_form", formToken != "")
			http.Error(w, "Forbidden: missing CSRF token", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) != 1 {
			slog.Warn("csrf: token mismatch", "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "Forbidden: invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
