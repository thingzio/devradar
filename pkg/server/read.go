package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/tenant"
)

// minSeverity resolves the effective threshold for a request: an explicit,
// valid ?min_severity= query param wins; otherwise the tenant's default; each
// endpoint resolves independently, so /findings and /events can differ.
func minSeverity(r *http.Request, tn *tenant.Tenant) (string, bool) {
	if q := r.URL.Query().Get("min_severity"); q != "" {
		if !data.ValidMinSeverity(q) {
			return "", false
		}
		return q, true
	}
	if tn.MinSeverity != "" {
		return tn.MinSeverity, true
	}
	return data.DefaultMinSeverity, true
}

// handleListImages returns the tenant's tracked images with the full severity
// breakdown; ?min_severity sets which levels count toward "relevant".
func (s *Server) handleListImages(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	min, ok := minSeverity(r, tn)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid min_severity (want critical|high|medium|low|negligible)")
		return
	}
	images, err := s.store.ListImages(r.Context(), tn.ID, min)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list images")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"min_severity": min, "images": images})
}

// handleTimeline returns the change history for an image ref across all its
// digests. The ref is a query param (not a path segment) because image refs
// contain slashes, which a stdlib ServeMux path wildcard can't capture.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing ref query parameter")
		return
	}
	min, ok := minSeverity(r, tn)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid min_severity")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := s.store.ImageTimeline(r.Context(), tn.ID, ref, min, limit)
	if err != nil {
		writeReadErr(w, err, "failed to load timeline")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_ref": ref, "min_severity": min, "timeline": events})
}

// handleGetSBOM returns one SBOM's metadata + severity breakdown.
func (s *Server) handleGetSBOM(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	min, ok := minSeverity(r, tn)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid min_severity")
		return
	}
	sb, err := s.store.GetSBOM(r.Context(), tn.ID, r.PathValue("id"), min)
	if err != nil {
		writeReadErr(w, err, "failed to load sbom")
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

// handleArchiveSBOM stops tracking an SBOM (status='archived'): it drops from
// the scan set and the images list; findings/events are retained. Idempotent.
func (s *Server) handleArchiveSBOM(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if err := s.store.ArchiveSBOM(r.Context(), tn.ID, r.PathValue("id")); err != nil {
		writeReadErr(w, err, "failed to archive sbom")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFindings returns current findings for one of the tenant's SBOMs,
// filtered to ?min_severity (or the tenant default); unknown always included.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	min, ok := minSeverity(r, tn)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid min_severity")
		return
	}
	findings, err := s.store.FindingsBySBOM(r.Context(), tn.ID, r.PathValue("id"), min)
	if err != nil {
		writeReadErr(w, err, "failed to load findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"min_severity": min, "findings": findings})
}

// handleEvents returns the change history for one of the tenant's SBOMs,
// filtered to ?min_severity (or the tenant default); unknown always included.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	min, ok := minSeverity(r, tn)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid min_severity")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := s.store.EventsBySBOM(r.Context(), tn.ID, r.PathValue("id"), min, limit)
	if err != nil {
		writeReadErr(w, err, "failed to load events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"min_severity": min, "events": events})
}

// writeReadErr maps store errors to HTTP status. A not-found (which also covers
// "not owned by this tenant") is 404 — indistinguishable by design.
func writeReadErr(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, postgres.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, msg)
}
