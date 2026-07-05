package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// SeverityCounts is the full per-severity breakdown for an image. All levels are
// always returned; callers/UI decide what to emphasize. Relevant is the count at
// or above a supplied threshold (unknown always included).
type SeverityCounts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
	Total      int `json:"total"`
	Relevant   int `json:"relevant"` // >= min_severity (or unknown)
}

// Image is a tenant-facing summary of one tracked image (one SBOM).
type Image struct {
	SBOMID      string         `json:"sbom_id"`
	ImageRef    string         `json:"image_ref"`
	Digest      string         `json:"digest"`
	Format      string         `json:"format"`
	SubmittedAt time.Time      `json:"submitted_at"`
	Counts      SeverityCounts `json:"counts"`
}

// ListImages returns a tenant's active images with the full severity breakdown.
// minSeverity sets which levels count toward Counts.Relevant (unknown always
// counts); it does not hide any level from the breakdown. Tenant-scoped.
func (s *Store) ListImages(ctx context.Context, tenantID, minSeverity string) ([]Image, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.id, sb.image_ref, sb.digest, sb.format, sb.submitted_at,
		       COUNT(*) FILTER (WHERE f.severity = 'critical')   AS crit,
		       COUNT(*) FILTER (WHERE f.severity = 'high')       AS high,
		       COUNT(*) FILTER (WHERE f.severity = 'medium')     AS med,
		       COUNT(*) FILTER (WHERE f.severity = 'low')        AS low,
		       COUNT(*) FILTER (WHERE f.severity = 'negligible') AS neg,
		       COUNT(*) FILTER (WHERE f.severity = 'unknown')    AS unk,
		       COUNT(f.finding_id)                               AS total
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
		var c SeverityCounts
		if err := rows.Scan(&im.SBOMID, &im.ImageRef, &im.Digest, &im.Format, &im.SubmittedAt,
			&c.Critical, &c.High, &c.Medium, &c.Low, &c.Negligible, &c.Unknown, &c.Total); err != nil {
			return nil, fmt.Errorf("scan image: %w", err)
		}
		c.Relevant = relevantCount(c, minSeverity)
		im.Counts = c
		out = append(out, im)
	}
	return out, rows.Err()
}

// relevantCount sums the per-severity counts that meet the threshold (unknown
// always included), using the shared ordering so it can't drift from the filter.
func relevantCount(c SeverityCounts, min string) int {
	n := c.Unknown
	for sev, cnt := range map[string]int{
		data.SeverityCritical:   c.Critical,
		data.SeverityHigh:       c.High,
		data.SeverityMedium:     c.Medium,
		data.SeverityLow:        c.Low,
		data.SeverityNegligible: c.Negligible,
	} {
		if data.MeetsThreshold(sev, min) {
			n += cnt
		}
	}
	return n
}

// Finding is a tenant-facing current finding row.
type Finding struct {
	Scanner  string  `json:"scanner"`
	Exposure string  `json:"exposure"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	Severity string  `json:"severity"`
	Score    float32 `json:"score"`
	IsFixed  bool    `json:"is_fixed"`
}

// FindingsBySBOM returns current findings for one SBOM at or above minSeverity
// (unknown always included). Tenant-scoped; ErrNotFound if not owned.
func (s *Store) FindingsBySBOM(ctx context.Context, tenantID, sbomID, minSeverity string) ([]Finding, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scanner, exposure, package, version, severity, score, is_fixed
		FROM devradar_finding
		WHERE sbom_id = $1 AND severity = ANY($2)
		ORDER BY CASE severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
			WHEN 'low' THEN 3 WHEN 'negligible' THEN 4 ELSE 5 END, exposure`,
		sbomID, pq.Array(data.AllowedSeverities(minSeverity)))
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
	Scanner    string    `json:"scanner"`
	EventType  string    `json:"event_type"`
	Exposure   string    `json:"exposure"`
	Package    string    `json:"package"`
	Severity   string    `json:"severity"`
	Score      float32   `json:"score"`
	Cause      string    `json:"cause"`
	OccurredAt time.Time `json:"occurred_at"`
}

// EventsBySBOM returns change history for one SBOM at or above minSeverity
// (unknown always included), newest first. Tenant-scoped.
func (s *Store) EventsBySBOM(ctx context.Context, tenantID, sbomID, minSeverity string, limit int) ([]Event, error) {
	if err := s.assertSBOMOwner(ctx, tenantID, sbomID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scanner, event_type, exposure, package, severity, score, cause, occurred_at
		FROM devradar_finding_event
		WHERE sbom_id = $1 AND severity = ANY($2)
		ORDER BY occurred_at DESC LIMIT $3`,
		sbomID, pq.Array(data.AllowedSeverities(minSeverity)), limit)
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
// owned by the tenant (indistinguishable by design).
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
