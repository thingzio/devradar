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
		_, _ = w.Write([]byte(`{"id":424242,"login":"octocat","avatar_url":"https://avatars.githubusercontent.com/u/424242?v=4"}`))
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
	if id.AvatarURL != "https://avatars.githubusercontent.com/u/424242?v=4" {
		t.Errorf("avatar = %q, want the /user avatar_url", id.AvatarURL)
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
