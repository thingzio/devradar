package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

// handleListImages returns the tenant's tracked images with finding counts.
func (s *Server) handleListImages(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	images, err := s.store.ListImages(r.Context(), tn.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list images")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": images})
}

// handleFindings returns current findings for one of the tenant's SBOMs.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	findings, err := s.store.FindingsBySBOM(r.Context(), tn.ID, r.PathValue("id"))
	if err != nil {
		writeReadErr(w, err, "failed to load findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

// handleEvents returns the change history for one of the tenant's SBOMs.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := s.store.EventsBySBOM(r.Context(), tn.ID, r.PathValue("id"), limit)
	if err != nil {
		writeReadErr(w, err, "failed to load events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
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
