package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// postForm builds an urlencoded POST carrying the given cookie/form token
// (either may be empty to model a missing value).
func postForm(cookieTok, formTok string) *http.Request {
	form := url.Values{}
	if formTok != "" {
		form.Set(csrfFormField, formTok)
	}
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookieTok != "" {
		r.AddCookie(&http.Cookie{Name: CSRFCookieName(), Value: cookieTok})
	}
	return r
}

func TestCheckCSRF(t *testing.T) {
	cases := []struct {
		name         string
		cookie, form string
		want         bool
	}{
		{"match", "tok123", "tok123", true},
		{"mismatch", "tok123", "different", false},
		{"missing cookie", "", "tok123", false},
		{"missing form", "tok123", "", false},
		{"both missing", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckCSRF(postForm(c.cookie, c.form)); got != c.want {
				t.Errorf("CheckCSRF(%q,%q) = %v, want %v", c.cookie, c.form, got, c.want)
			}
		})
	}
}

func TestValidateCSRF(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := ValidateCSRF(ok)

	// GET passes through untouched.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET should pass through, got %d", rec.Code)
	}

	// Valid double-submit → handler runs.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("abc", "abc"))
	if rec.Code != http.StatusOK {
		t.Errorf("valid CSRF POST = %d, want 200", rec.Code)
	}

	// Missing/invalid → 403.
	for _, c := range []struct{ cookie, form string }{{"", ""}, {"abc", ""}, {"abc", "xyz"}} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, postForm(c.cookie, c.form))
		if rec.Code != http.StatusForbidden {
			t.Errorf("CSRF POST cookie=%q form=%q = %d, want 403", c.cookie, c.form, rec.Code)
		}
	}
}
