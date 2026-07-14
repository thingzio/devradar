package server

import (
	"net/http"

	"github.com/thingzio/devradar/pkg/middleware"
)

// handleSBOMLicenses returns the per-package license inventory for one of the
// tenant's SBOMs, each package classified into a license category and evaluated
// against the tenant's compliance policy (violations sorted first). Tenant-scoped
// via the store's ownership check; 404 if not owned.
func (s *Server) handleSBOMLicenses(w http.ResponseWriter, r *http.Request) {
	acct := middleware.AccountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	policy, err := s.store.GetLicensePolicy(r.Context(), acct.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policy")
		return
	}
	pkgs, err := s.store.ListSBOMPackages(r.Context(), acct.ID, r.PathValue("id"), policy)
	if err != nil {
		writeReadErr(w, err, "failed to load licenses")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": pkgs})
}

// handleFleetLicenses returns the tenant's fleet-wide license landscape:
// distribution by license family and by category, plus unlicensed and policy
// violation counts across all active SBOMs.
func (s *Server) handleFleetLicenses(w http.ResponseWriter, r *http.Request) {
	acct := middleware.AccountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	policy, err := s.store.GetLicensePolicy(r.Context(), acct.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policy")
		return
	}
	stats, err := s.store.FleetLicenseStats(r.Context(), acct.ID, policy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load license stats")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
