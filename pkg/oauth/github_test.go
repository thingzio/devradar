package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

// newTestGitHub builds a GitHub provider whose token endpoint and API base both
// point at the given test server, so Exchange runs entirely offline.
func newTestGitHub(base string) *GitHub {
	g := NewGitHub("cid", "secret", base+"/callback")
	g.cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  base + "/login/oauth/authorize",
		TokenURL: base + "/login/oauth/access_token",
	}
	g.apiBase = base
	return g
}

// githubMux serves a canned token exchange plus /user and /user/emails. emails
// is returned verbatim so a test can omit the verified/primary address.
func githubMux(emails string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":424242,"login":"octocat"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emails))
	})
	return mux
}

// TestExchange_PrimaryVerifiedEmail: a primary+verified email is selected and the
// numeric id (not the login) becomes the subject.
func TestExchange_PrimaryVerifiedEmail(t *testing.T) {
	ts := httptest.NewServer(githubMux(`[
		{"email":"other@x.com","primary":false,"verified":true},
		{"email":"mark@chmarny.com","primary":true,"verified":true}
	]`))
	defer ts.Close()

	id, err := newTestGitHub(ts.URL).Exchange(context.Background(), "code123")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Provider != "github" {
		t.Errorf("provider = %q, want github", id.Provider)
	}
	if id.Subject != "424242" {
		t.Errorf("subject = %q, want 424242 (numeric id, not login)", id.Subject)
	}
	if id.Email != "mark@chmarny.com" {
		t.Errorf("email = %q, want mark@chmarny.com", id.Email)
	}
}

// TestExchange_NoVerifiedEmail: an account whose primary email is unverified (or
// has no verified primary) is rejected — the takeover defense.
func TestExchange_NoVerifiedEmail(t *testing.T) {
	ts := httptest.NewServer(githubMux(`[
		{"email":"victim@x.com","primary":true,"verified":false},
		{"email":"side@x.com","primary":false,"verified":true}
	]`))
	defer ts.Close()

	_, err := newTestGitHub(ts.URL).Exchange(context.Background(), "code123")
	if !errors.Is(err, ErrNoVerifiedEmail) {
		t.Fatalf("err = %v, want ErrNoVerifiedEmail", err)
	}
}
