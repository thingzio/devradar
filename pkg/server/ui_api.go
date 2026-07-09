package server

import (
	"bytes"
	"net/http"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/tenant"
)

// handleAPIDocs renders the public REST API reference — a hand-written page in
// the same server-rendered, no-JS style as /submit, plus a link to the
// downloadable OpenAPI spec. Public: the endpoints require a token, but the docs
// are open so DevRadar can be evaluated before sign-up. The nav adapts to
// whether the viewer happens to be signed in.
func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	render(w, "api.html", map[string]any{
		"Title":    "API",
		"Tab":      "api",
		"SignedIn": s.signedIn(r),
		"BaseURL":  config.BaseURL(),
		"Version":  s.opts.Version,
	})
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

// signedIn reports whether the request carries a valid session — used by public
// pages to render the signed-in nav for logged-in visitors without gating access.
func (s *Server) signedIn(r *http.Request) bool {
	c, err := r.Cookie(middleware.SessionCookieName())
	if err != nil {
		return false
	}
	_, err = tenant.ValidateSession(r.Context(), s.store.DB(), c.Value)
	return err == nil
}
