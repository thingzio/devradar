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

package server_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/server"
)

// TestLanding_RendersMarketing verifies the unauthenticated landing page renders
// its marketing content and the sign-in form, and does not leak the authed nav.
func TestLanding_RendersMarketing(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Continuous security posture for every image you ship",
		"Submit", "Detect", "Prioritize", "Compare", "Trend",
		"What changed, and why?",
		"What should I fix next?",
		"Is the next tracked digest better?",
		"Is my fleet improving?",
		"Opt-in browser alerts",
		"Grype and Trivy",
		"License policy", "OpenVEX", "account-scoped API",
		"fleet posture trends", "repository change history",
		"filter tracked images and scope browser alerts",
		"identical SBOM inventory", "vulnerability database", "scanner version", "canonicalizer version",
		"does not verify that a submitted SBOM faithfully represents the claimed image",
		"Results reflect the submitted evidence.",
		`aria-labelledby="trust-title"`, `id="trust-title">An honest note on trust`,
		"Passwordless sign-in with GitHub or a one-time email link.",
		`<meta name="description" content="Continuous SBOM security posture for container images — detect change, prioritize remediation, compare digests, and track vulnerability debt.">`,
		`action="/auth/login"`,
		"honest note on trust",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	lowerBody := strings.ToLower(body)
	for _, stale := range []string{
		"coming soon", "push & email alerts", "webhook", "email alert", "email notification",
		"universally safe", "universal safety", "repository trends", "filter image, work",
		"free to start", "no credit card", "later release",
	} {
		if strings.Contains(lowerBody, stale) {
			t.Errorf("landing page contains stale or unsafe claim %q", stale)
		}
	}
	if !strings.Contains(body, "Enter your email") {
		t.Error("landing page must retain sign-in email copy")
	}
	if strings.Contains(body, `class="tab `) {
		t.Error("signed-out landing must not render authed nav tabs")
	}

	start := strings.Index(body, `<ol class="posture-loop">`)
	if start < 0 {
		t.Fatal("landing posture loop must be an ordered list")
	}
	end := strings.Index(body[start:], "</ol>")
	if end < 0 {
		t.Fatal("landing posture ordered list is not closed")
	}
	loop := body[start : start+end]
	if got := strings.Count(loop, "<li>"); got != 5 {
		t.Fatalf("posture loop stages = %d, want 5", got)
	}
	matches := regexp.MustCompile(`<span class="posture-step">([^<]+)</span>`).FindAllStringSubmatch(loop, -1)
	stages := make([]string, 0, len(matches))
	for _, match := range matches {
		stages = append(stages, match[1])
	}
	if got, want := strings.Join(stages, ","), "Submit,Detect,Prioritize,Compare,Trend"; got != want {
		t.Errorf("posture loop order = %q, want %q", got, want)
	}
}

// TestLanding_FooterShowsVersionAndCommit guards against a regression where
// handleLanding's template data carried "Version" but not "Commit", leaving
// the footer's "(<short-sha>)" silently missing on the signed-out landing
// page — the page the footer contract exists for.
func TestLanding_FooterShowsVersionAndCommit(t *testing.T) {
	srv, _ := testServerWithOptions(t, server.Options{Version: "v1.2.3", Commit: "abc1234"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "VERSION v1.2.3") || !strings.Contains(body, "(abc1234)") {
		t.Error("landing footer missing version and/or commit")
	}
}

func TestLanding_RendersAuthStates(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()

	t.Run("error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?error=email", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "Please enter a valid email address.") ||
			!strings.Contains(body, `action="/auth/login"`) {
			t.Fatalf("error landing = %d body=%s", rec.Code, body)
		}
	})

	t.Run("sent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?sent=1", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "Check your email — we sent you a sign-in link.") {
			t.Fatalf("sent landing = %d body=%s", rec.Code, body)
		}
		if strings.Contains(body, `action="/auth/login"`) {
			t.Error("sent landing must hide sign-in forms")
		}
	})
}

func TestLanding_NarrowEmailFormsStack(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/static/css/app.css", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stylesheet status = %d, want 200", rec.Code)
	}
	css := rec.Body.String()
	stackRule := regexp.MustCompile(`(?s)\.landing \.hero-signin form\.row,\s*\.landing \.lp-cta-form\s*\{[^}]*flex-direction:\s*column;[^}]*align-items:\s*stretch;`)
	if !stackRule.MatchString(css) {
		t.Error("landing email forms need a narrow-screen stacking rule")
	}
	inputRule := regexp.MustCompile(`(?s)\.landing \.hero-signin form\.row input,\s*\.landing \.lp-cta-form input\s*\{[^}]*min-width:\s*0;[^}]*width:\s*100%;`)
	if !inputRule.MatchString(css) {
		t.Error("landing email inputs need a narrow-screen overflow guard")
	}
}
