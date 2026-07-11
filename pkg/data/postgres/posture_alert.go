package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ComparePreviousSBOM compares an active SBOM with the immediately preceding
// active generation in the same tenant and repository.
func (s *Store) ComparePreviousSBOM(ctx context.Context, tenantID, sbomID string) (*SBOMComparison, error) {
	var previousID string
	err := s.db.QueryRowContext(ctx, `
		WITH target AS (
			SELECT id, tenant_id, repository,
			       COALESCE(generated_at, submitted_at) AS effective_at
			FROM devradar_sbom
			WHERE tenant_id=$1 AND id=$2 AND status='active'
		)
		SELECT previous.id
		FROM target
		JOIN devradar_sbom previous
		  ON previous.tenant_id=target.tenant_id
		 AND previous.repository=target.repository
		WHERE previous.tenant_id=$1
		  AND previous.status='active'
		  AND (COALESCE(previous.generated_at, previous.submitted_at), previous.id) <
		      (target.effective_at, target.id)
		ORDER BY COALESCE(previous.generated_at, previous.submitted_at) DESC, previous.id DESC
		LIMIT 1`, tenantID, sbomID).Scan(&previousID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select previous SBOM: %w", err)
	}
	return s.CompareSBOMs(ctx, tenantID, previousID, sbomID)
}
