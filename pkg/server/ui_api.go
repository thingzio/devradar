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

package server

import (
	"bytes"
	"net/http"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
)

// handleAPIDocs renders the public REST API reference — a hand-written page in
// the same server-rendered, no-JS style as /submit, plus a link to the
// downloadable OpenAPI spec. Public: the endpoints require a token, but the docs
// are open so DevRadar can be evaluated before sign-up. The nav adapts to
// whether the viewer happens to be signed in.
func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	access := s.currentAccess(r)
	render(w, "api.html", struct {
		chromeView
		BaseURL string
	}{chromeView: s.chrome(access, "API", "api"), BaseURL: config.BaseURL()})
}

// handleOpenAPISpec serves the embedded OpenAPI document at a clean top-level
// path (so users get devradar.thingz.io/openapi.yaml, not a /static/ path). The
// spec ships with a `version: 0.0.0` placeholder that's replaced with the build
// version at serve time, so the published contract is stamped with the running
// release without a build step.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/openapi.yaml")
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	if v := s.opts.Version; v != "" {
		b = bytes.Replace(b, []byte("version: 0.0.0"), []byte("version: "+v), 1)
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(b)
}

// currentAccess returns active browser access for optional public-page chrome.
func (s *Server) currentAccess(r *http.Request) *account.Access {
	c, err := r.Cookie(middleware.SessionCookieName())
	if err != nil {
		return nil
	}
	session, err := s.store.ValidateSession(r.Context(), c.Value)
	if err != nil || session.User.Status != "active" || session.ActiveAccountID == nil {
		return nil
	}
	access, err := s.store.GetAccess(r.Context(), session.User.ID, *session.ActiveAccountID)
	if err != nil {
		return nil
	}
	return access
}
