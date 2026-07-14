package server

import (
	"net/http"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
)

// handleSubmitGuide renders the Docs page: how DevRadar works (concepts) plus
// the SBOM submission guide — create a token, install syft, generate an SBOM by
// digest, and POST it — all with copy-paste examples targeting this deployment's
// own base URL so a user can paste them verbatim.
func (s *Server) handleSubmitGuide(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	render(w, "submit.html", struct {
		chromeView
		BaseURL string
	}{chromeView: s.chrome(access, "Docs", "docs"), BaseURL: config.BaseURL()})
}
