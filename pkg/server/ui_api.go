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
