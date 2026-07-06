package postgres

import (
	"context"
	"fmt"

	"github.com/thingzio/devradar/pkg/vex"
)

// vexStatusJoin resolves the latest VEX status for a finding, correlating on the
// finding's SBOM digest + CVE. It expects the outer query to expose the finding
// as alias `f` and its SBOM as `sb`. The LATERAL subquery picks the newest
// statement per (tenant, digest, cve). Produces column `vex_status` (NULL when
// no statement applies).
//
// Suppression: a finding is suppressed when vex_status IN ('not_affected','fixed').
// vexSuppressed is the predicate; vexNotSuppressed its negation-including-null.
const (
	vexStatusJoin = `
		LEFT JOIN LATERAL (
			SELECT vs.status AS vex_status
			FROM devradar_vex_statement vs
			WHERE vs.tenant_id = sb.tenant_id
			  AND vs.product_digest = sb.digest
			  AND vs.vulnerability = f.exposure
			ORDER BY vs.created_at DESC
			LIMIT 1
		) vex ON true`

	// vexSuppressedExpr is true when the resolved status hides the finding.
	// COALESCE makes it NULL-safe: a finding with no VEX statement (vex_status
	// NULL) is NOT suppressed — without the COALESCE, `NOT (NULL IN ...)` is NULL,
	// which a WHERE treats as false and would wrongly drop every un-VEX'd finding.
	vexSuppressedExpr = `COALESCE(vex.vex_status IN ('not_affected','fixed'), false)`

	// vexSuppressedByDigestCVE is an EXISTS predicate for aggregate queries that
	// join finding `f` + sbom `sb` but don't need the exact status value — true if
	// any VEX statement suppresses this (digest, cve). Used as a join condition so
	// suppressed findings drop out of counts while the image row remains. (v1
	// aggregate simplification: "any suppressing statement" rather than
	// latest-wins; the per-finding view uses proper latest-wins.)
	vexSuppressedByDigestCVE = `EXISTS (
		SELECT 1 FROM devradar_vex_statement vs
		WHERE vs.tenant_id = sb.tenant_id AND vs.product_digest = sb.digest
		  AND vs.vulnerability = f.exposure
		  AND vs.status IN ('not_affected','fixed'))`
)

// SaveVEXDocument persists a parsed OpenVEX document and its statements for a
// tenant, returning the document id and how many statements matched an existing
// finding (so the caller can report effectiveness). Matching is at
// (tenant, product_digest, vulnerability) granularity in v1 — subcomponent is
// stored but not used for matching.
func (s *Store) SaveVEXDocument(ctx context.Context, tenantID string, doc *vex.Document) (id string, matched int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("begin vex tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Count how many statements hit a real finding in one of the tenant's SBOMs.
	for _, st := range doc.Statements {
		var hit bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_finding f
				JOIN devradar_sbom sb ON sb.id = f.sbom_id
				WHERE sb.tenant_id = $1 AND sb.digest = $2 AND f.exposure = $3)`,
			tenantID, st.ProductDigest, st.Vulnerability).Scan(&hit); err != nil {
			return "", 0, fmt.Errorf("vex match check: %w", err)
		}
		if hit {
			matched++
		}
	}

	if err := tx.QueryRowContext(ctx, `
		INSERT INTO devradar_vex_document (tenant_id, author, statements, matched, document)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, nullStr(doc.Author), len(doc.Statements), matched, []byte(doc.Raw)).Scan(&id); err != nil {
		return "", 0, fmt.Errorf("insert vex document: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO devradar_vex_statement
			(tenant_id, document_id, product_digest, vulnerability, subcomponent,
			 status, justification, impact_statement, timestamp)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)
	if err != nil {
		return "", 0, fmt.Errorf("prepare vex statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, st := range doc.Statements {
		var ts any
		if st.Timestamp != "" {
			ts = st.Timestamp
		}
		if _, err := stmt.ExecContext(ctx, tenantID, id, st.ProductDigest, st.Vulnerability,
			nullStr(st.Subcomponent), st.Status, nullStr(st.Justification),
			nullStr(st.ImpactStatement), ts); err != nil {
			return "", 0, fmt.Errorf("insert vex statement: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("commit vex: %w", err)
	}
	return id, matched, nil
}

// VEXDocumentRow is a tenant-facing summary of a submitted VEX document.
type VEXDocumentRow struct {
	ID         string `json:"id"`
	Author     string `json:"author,omitempty"`
	Statements int    `json:"statements"`
	Matched    int    `json:"matched"`
	CreatedAt  string `json:"created_at"`
}

// ListVEXDocuments returns a tenant's submitted VEX documents, newest first.
func (s *Store) ListVEXDocuments(ctx context.Context, tenantID string) ([]VEXDocumentRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(author,''), statements, matched, created_at::text
		FROM devradar_vex_document
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 200`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list vex documents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []VEXDocumentRow
	for rows.Next() {
		var d VEXDocumentRow
		if err := rows.Scan(&d.ID, &d.Author, &d.Statements, &d.Matched, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan vex document: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
