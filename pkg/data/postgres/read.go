package postgres

import (
	"context"
	"fmt"
	"time"
)

// Image is a tenant-facing summary of one tracked image (one SBOM), with its
// latest finding counts across scanners.
type Image struct {
	SBOMID       string
	ImageRef     string
	Digest       string
	Format       string
	SubmittedAt  time.Time
	FindingCount int
	Critical     int
	High         int
}

// ListImages returns a tenant's active images with current finding counts.
// Tenant-scoped: the WHERE tenant_id predicate is the isolation boundary.
func (s *Store) ListImages(ctx context.Context, tenantID string) ([]Image, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at,
		       COUNT(f.finding_id) AS findings,
		       COUNT(*) FILTER (WHERE f.severity = 'critical') AS crit,
		       COUNT(*) FILTER (WHERE f.severity = 'high')     AS high
		FROM devradar_sbom sb
		LEFT JOIN devradar_finding f ON f.sbom_id = sb.id
		WHERE sb.tenant_id = $1 AND sb.status = 'active'
		GROUP BY sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at
		ORDER BY sb.submitted_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	defer rows.Close()

	var out []Image
	for rows.Next() {
		var im Image
		if err := rows.Scan(&im.SBOMID, &im.ImageRef, &im.Digest, &im.Format, &im.SubmittedAt,
			&im.FindingCount, &im.Critical, &im.High); err != nil {
			return nil, fmt.Errorf("scan image: %w", err)
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// Finding is a tenant-facing current finding row.
type Finding struct {
	Scanner  string
	Exposure string
	Package  string
	Version  string
	Severity string
	Score    float32
	IsFixed  bool
}

// FindingsBySBOM returns current findings for one SBOM, tenant-scoped (the SBOM
// must belong to the tenant). Returns ErrNotFound if the SBOM isn't theirs.
func (s *Store) FindingsBySBOM(ctx context.Context, tenantID, sbomID string) ([]Finding, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scanner, exposure, package, version, severity, score, is_fixed
		FROM devradar_finding WHERE sbom_id = $1
		ORDER BY CASE severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
			WHEN 'low' THEN 3 WHEN 'negligible' THEN 4 ELSE 5 END, exposure`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("findings: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.Scanner, &f.Exposure, &f.Package, &f.Version, &f.Severity, &f.Score, &f.IsFixed); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Event is a tenant-facing change-log row.
type Event struct {
	Scanner    string
	EventType  string
	Exposure   string
	Package    string
	Severity   string
	Score      float32
	Cause      string
	OccurredAt time.Time
}

// EventsBySBOM returns the change history for one SBOM, newest first, tenant-scoped.
func (s *Store) EventsBySBOM(ctx context.Context, tenantID, sbomID string, limit int) ([]Event, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scanner, event_type, exposure, package, severity, score, cause, occurred_at
		FROM devradar_finding_event WHERE sbom_id = $1
		ORDER BY occurred_at DESC LIMIT $2`, sbomID, limit)
	if err != nil {
		return nil, fmt.Errorf("events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Scanner, &e.EventType, &e.Exposure, &e.Package,
			&e.Severity, &e.Score, &e.Cause, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrNotFound is returned when a tenant-scoped resource doesn't exist or isn't
// owned by the tenant (the two are deliberately indistinguishable to callers).
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func (s *Store) assertSBOMOwner(ctx context.Context, tenantID, sbomID string) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE id = $1 AND tenant_id = $2)`,
		sbomID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("check sbom owner: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}
