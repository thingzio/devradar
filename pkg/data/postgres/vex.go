package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/thingzio/devradar/pkg/account"
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
//
// vexRepoKeyExpr is the LAST path segment of an sbom's repository, lowercased —
// the key a digest-less (repository-scoped) VEX statement matches against.
//
// DELIBERATE TRADE-OFF (do not "fix" to full-path matching): real published
// vendor VEX documents name their product by bare image name — e.g. NVIDIA's
// AICR OpenVEX uses "pkg:oci/aicr", not the full "ghcr.io/nvidia/aicr" pull path
// we track internally. Matching on the last path segment is what lets those
// documents apply drop-in, which is the headline VEX capability. The cost is that
// two of ONE tenant's repositories sharing a last segment (e.g. "a/api" and
// "b/api") would share a repo-scoped statement. That is possible but unlikely
// (a tenant rarely tracks two same-named images from different namespaces), and
// bounded to a single tenant. Precision when it matters is available via a
// digest-scoped statement, which always wins over a repo-scoped one (see
// vexSpecificityOrder). We accept the basename collision to keep vendor docs working.
const vexRepoKeyExpr = `lower(split_part(sb.repository, '/', array_length(string_to_array(sb.repository,'/'),1)))`

// vexSpecificityOrder ranks a digest-pinned statement above a repository-scoped
// one so a precise statement is never overridden by a broad one that merely
// happens to be newer. Applied before recency in every LATERAL/subquery.
const vexSpecificityOrder = `(vs.product_digest IS NOT NULL) DESC, vs.created_at DESC, vs.id DESC`

const (
	vexStatusJoin = `
		LEFT JOIN LATERAL (
			SELECT vs.status AS vex_status, vs.justification AS vex_just,
			       vs.impact_statement AS vex_impact
			FROM devradar_vex_statement vs
			WHERE vs.tenant_id = sb.tenant_id
			  AND vs.vulnerability = f.exposure
			  AND (vs.product_digest = sb.digest
			       OR vs.product_repo = ` + vexRepoKeyExpr + `)
			ORDER BY ` + vexSpecificityOrder + `
			LIMIT 1
		) vex ON true`

	// vexSuppressedExpr is true when the resolved status hides the finding.
	// COALESCE makes it NULL-safe: a finding with no VEX statement (vex_status
	// NULL) is NOT suppressed — without the COALESCE, `NOT (NULL IN ...)` is NULL,
	// which a WHERE treats as false and would wrongly drop every un-VEX'd finding.
	vexSuppressedExpr = `COALESCE(vex.vex_status IN ('not_affected','fixed'), false)`

	// vexSuppressedByDigestCVE resolves the latest matching statement for aggregate
	// queries that expose finding `f` and SBOM `sb`, matching vexStatusJoin semantics.
	vexSuppressedByDigestCVE = `COALESCE((
		SELECT vs.status IN ('not_affected','fixed')
		FROM devradar_vex_statement vs
		WHERE vs.tenant_id = sb.tenant_id
		  AND vs.vulnerability = f.exposure
		  AND (vs.product_digest = sb.digest OR vs.product_repo = ` + vexRepoKeyExpr + `)
		ORDER BY ` + vexSpecificityOrder + `
		LIMIT 1), false)`
)

// SaveVEXDocument persists a parsed OpenVEX document and its statements for a
// tenant, returning the document id and how many statements matched an existing
// finding (so the caller can report effectiveness). Matching is at
// (tenant, product_digest, vulnerability) granularity in v1 — subcomponent is
// stored but not used for matching.
func (s *Store) SaveVEXDocument(ctx context.Context, tenantID string, doc *vex.Document) (id string, matched int, err error) {
	if doc == nil {
		return "", 0, fmt.Errorf("save vex: nil document")
	}
	id, err = newAuditUUID()
	if err != nil {
		return "", 0, fmt.Errorf("generate vex document id: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("begin vex tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	matched, err = saveVEXDocument(ctx, tx, tenantID, id, doc)
	if err != nil {
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("commit vex: %w", err)
	}
	return id, matched, nil
}

// SaveVEXDocumentAudited persists a VEX document and its success attribution
// in one transaction.
func (s *Store) SaveVEXDocumentAudited(ctx context.Context, tenantID string, doc *vex.Document, actor account.Actor, requestID string) (id string, matched int, err error) {
	if doc == nil {
		return "", 0, fmt.Errorf("save vex: nil document")
	}
	id, err = newAuditUUID()
	if err != nil {
		return "", 0, fmt.Errorf("generate vex document id: %w", err)
	}
	err = s.WithAudit(ctx, tenantID, actor, AuditEvent{
		Action: "vex.save", TargetType: "vex_document", TargetID: id,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		var saveErr error
		matched, saveErr = saveVEXDocument(ctx, tx, tenantID, id, doc)
		return saveErr
	})
	if err != nil {
		return "", 0, err
	}
	return id, matched, nil
}

func saveVEXDocument(ctx context.Context, tx *sql.Tx, tenantID, id string, doc *vex.Document) (matched int, err error) {
	// Count how many statements hit a real finding in one of the tenant's SBOMs.
	// A statement matches by exact digest, or (digest-less) by repository key — the
	// last path segment of the tracked repository. Mirrors vexRepoKeyExpr on the
	// read side (see the deliberate basename trade-off documented there).
	for _, st := range doc.Statements {
		var hit bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_finding f
				JOIN devradar_sbom sb ON sb.id = f.sbom_id
				WHERE sb.tenant_id = $1 AND f.exposure = $2
				  AND (($3 <> '' AND sb.digest = $3)
				       OR ($4 <> '' AND lower(split_part(sb.repository, '/', array_length(string_to_array(sb.repository,'/'),1))) = $4)))`,
			tenantID, st.Vulnerability, st.ProductDigest, st.ProductRepo).Scan(&hit); err != nil {
			return 0, fmt.Errorf("vex match check: %w", err)
		}
		if hit {
			matched++
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_vex_document (id,tenant_id,author,statements,matched,document)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		id, tenantID, nullStr(doc.Author), len(doc.Statements), matched, []byte(doc.Raw)); err != nil {
		return 0, fmt.Errorf("insert vex document: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO devradar_vex_statement
			(tenant_id, document_id, product_digest, product_repo, vulnerability, subcomponent,
			 status, justification, impact_statement, timestamp)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`)
	if err != nil {
		return 0, fmt.Errorf("prepare vex statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, st := range doc.Statements {
		var ts any
		if st.Timestamp != "" {
			ts = st.Timestamp
		}
		if _, err := stmt.ExecContext(ctx, tenantID, id, nullStr(st.ProductDigest), nullStr(st.ProductRepo),
			st.Vulnerability, nullStr(st.Subcomponent), st.Status, nullStr(st.Justification),
			nullStr(st.ImpactStatement), ts); err != nil {
			return 0, fmt.Errorf("insert vex statement: %w", err)
		}
	}
	return matched, nil
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

// TenantHasSuppressingVEX reports whether the tenant has any VEX statement that
// hides a finding (status not_affected|fixed). It gates the read-time fast path:
// the per-SBOM rollup stores RAW counts, so a tenant with no suppressing VEX
// (the overwhelming majority) can read the rollup directly, while a tenant that
// does have one falls back to the live VEX-aware aggregation. Backed by the
// partial index idx_devradar_vex_stmt_suppressing, so this is sub-millisecond.
func (s *Store) TenantHasSuppressingVEX(ctx context.Context, tenantID string) (bool, error) {
	var has bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM devradar_vex_statement
			WHERE tenant_id = $1 AND status IN ('not_affected','fixed'))`,
		tenantID).Scan(&has)
	if err != nil {
		return false, fmt.Errorf("tenant has suppressing vex: %w", err)
	}
	return has, nil
}
