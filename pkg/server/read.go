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

// handleListImages returns the tenant's tracked images grouped by repository —
// one row per image (CUJ-1), regardless of how many versions/digests it has —
// with a severity rollup. Paginated (?limit, ?cursor). ?min_severity trims the
// breakdown.
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
	images, next, err := s.store.ListRepoImages(r.Context(), tn.ID, min,
		r.URL.Query().Get("sort"), r.URL.Query().Get("dir"), r.URL.Query().Get("cursor"), pageLimit(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list images")
		return
	}
	writeJSON(w, http.StatusOK, page(map[string]any{"min_severity": min, "images": images}, next))
}

// handleImageSBOMs lists the SBOMs tracked for one repository (CUJ-2), newest
// generation first. The repository is a `repo=` query param (not a path segment)
// because it contains slashes a stdlib ServeMux wildcard can't capture.
func (s *Server) handleImageSBOMs(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		writeError(w, http.StatusBadRequest, "missing repo query parameter")
		return
	}
	q := r.URL.Query()
	sboms, next, err := s.store.SBOMsForRepo(r.Context(), tn.ID, repo,
		q.Get("sort"), q.Get("dir"), q.Get("cursor"), pageLimit(r))
	if err != nil {
		writeReadErr(w, err, "failed to list sboms")
		return
	}
	writeJSON(w, http.StatusOK, page(map[string]any{"repository": repo, "sboms": sboms}, next))
}

// handleTimeline returns the change history for an image across all its digests
// (CUJ-3). The image is a `repo=` query param (its slashes preclude a path
// wildcard); the legacy `ref=` param is still honored for an exact image_ref.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
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

	// Preferred: group by repository across every version/digest.
	if repo := r.URL.Query().Get("repo"); repo != "" {
		events, next, err := s.store.RepoTimeline(r.Context(), tn.ID, repo, min,
			r.URL.Query().Get("sort"), r.URL.Query().Get("dir"), r.URL.Query().Get("cursor"), pageLimit(r))
		if err != nil {
			writeReadErr(w, err, "failed to load timeline")
			return
		}
		writeJSON(w, http.StatusOK, page(map[string]any{"repository": repo, "min_severity": min, "timeline": events}, next))
		return
	}

	// Legacy: exact image_ref match (kept for back-compat; not paginated).
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing repo (or legacy ref) query parameter")
		return
	}
	events, err := s.store.ImageTimeline(r.Context(), tn.ID, ref, min, pageLimit(r))
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
	fixableOnly := r.URL.Query().Get("fixable") == "true"
	showSuppressed := r.URL.Query().Get("suppressed") == "true"
	q := r.URL.Query()
	findings, next, err := s.store.FindingsBySBOM(r.Context(), tn.ID, r.PathValue("id"), min,
		fixableOnly, showSuppressed, q.Get("sort"), q.Get("dir"), q.Get("cursor"), pageLimit(r))
	if err != nil {
		writeReadErr(w, err, "failed to load findings")
		return
	}
	writeJSON(w, http.StatusOK, page(map[string]any{"min_severity": min, "findings": findings}, next))
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
	events, next, err := s.store.EventsBySBOM(r.Context(), tn.ID, r.PathValue("id"), min,
		r.URL.Query().Get("cursor"), pageLimit(r))
	if err != nil {
		writeReadErr(w, err, "failed to load events")
		return
	}
	writeJSON(w, http.StatusOK, page(map[string]any{"min_severity": min, "events": events}, next))
}

// handleFailures returns recent scan failures for one of the tenant's SBOMs
// (newest first). A failure is a scanner/stage that errored or returned nothing
// — e.g. Trivy finding 0 CVEs on an EOL distro it has no advisories for — so a
// silently-absent scanner is visible here rather than just missing from findings.
func (s *Server) handleFailures(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if tn == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	failures, err := s.store.FailuresBySBOM(r.Context(), tn.ID, r.PathValue("id"), limit)
	if err != nil {
		writeReadErr(w, err, "failed to load failures")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"failures": failures})
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

// pageLimit reads ?limit (0 when absent/invalid; the store clamps to its
// default and maximum).
func pageLimit(r *http.Request) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// page attaches next_cursor to a response body when there is a further page.
// Callers pass an opaque cursor ("" when exhausted); an empty cursor is omitted
// so a fully-returned list has no next_cursor field.
func page(body map[string]any, next string) map[string]any {
	if next != "" {
		body["next_cursor"] = next
	}
	return body
}
