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
//
// It caps the body at 4096 bytes before parsing the form, so it is suitable
// only for small urlencoded forms. A handler that must read a large body itself
// (e.g. a multipart file upload) should NOT be wrapped in this middleware —
// after parsing its own form it should call CheckCSRF(r) directly.
func ValidateCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// Bound the body before parsing the form. Handlers may set their own
		// stricter limit; this is a safe ceiling for the token check.
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if !CheckCSRF(r) {
			slog.Warn("csrf: rejected", "path", r.URL.Path, "remote", r.RemoteAddr,
				"request_id", RequestIDFromContext(r.Context()))
			http.Error(w, "Forbidden: invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CheckCSRF reports whether the request carries a valid double-submit CSRF
// token: a non-empty csrf_token form value that matches the CSRF cookie in
// constant time. It reads the form value via r.FormValue, so a handler that has
// already parsed a multipart form (file upload) can call it directly instead of
// wrapping the route in ValidateCSRF (which would truncate the upload body).
// Returns false if either token is missing or they differ.
func CheckCSRF(r *http.Request) bool {
	cookieToken := CSRFTokenFromRequest(r)
	formToken := r.FormValue(csrfFormField)
	if cookieToken == "" || formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) == 1
}
