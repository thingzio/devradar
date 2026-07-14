package server

import (
	"io"
	"net/http"

	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/vex"
)

// maxVEXBytes caps an uploaded OpenVEX document (untrusted input).
const maxVEXBytes = 5 << 20 // 5 MiB

// handleSubmitVEX ingests an OpenVEX document (raw JSON body). It parses,
// validates shape, persists, and reports how many statements matched a known
// finding — so the submitter learns whether the VEX is actually effective. VEX
// is a tenant assertion (unverified); it suppresses not_affected/fixed findings
// as a read-time overlay, never mutating findings.
func (s *Server) handleSubmitVEX(w http.ResponseWriter, r *http.Request) {
	acct := middleware.AccountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxVEXBytes+1))
	if err != nil || len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty or unreadable body")
		return
	}
	if len(body) > maxVEXBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "vex document too large")
		return
	}

	doc, err := vex.Parse(body)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	id, matched, err := s.store.SaveVEXDocument(r.Context(), acct.ID, doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store VEX document")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"document_id": id,
		"statements":  len(doc.Statements),
		"matched":     matched, // statements that hit an existing finding
		"unmatched":   len(doc.Statements) - matched,
		"skipped":     doc.Skipped, // statements with no resolvable image digest
		"note":        "Matched not_affected/fixed statements now suppress those findings. A new image digest requires a new VEX statement (digest-scoped).",
	})
}

// handleListVEX returns the tenant's submitted VEX documents (metadata only).
func (s *Server) handleListVEX(w http.ResponseWriter, r *http.Request) {
	acct := middleware.AccountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	docs, err := s.store.ListVEXDocuments(r.Context(), acct.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list VEX documents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": docs})
}
