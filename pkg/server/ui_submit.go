package server

import (
	"net/http"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
)

// handleSubmitGuide renders the "how to submit an SBOM" help page: create a
// token, install syft, generate an SBOM by digest, and POST it — all with
// copy-paste examples targeting this deployment's own base URL so a user can
// paste them verbatim.
func (s *Server) handleSubmitGuide(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	render(w, "submit.html", map[string]any{
		"Title":    "Submit an SBOM",
		"SignedIn": true,
		"Tab":      "submit",
		"Email":    tn.Email,
		"Version":  s.opts.Version,
		"BaseURL":  config.BaseURL(),
	})
}
