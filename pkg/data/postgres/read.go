package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data"
)

// SeverityCounts is the per-severity breakdown for an image. Levels below the
// requested threshold are zeroed (unknown is always kept). The per-severity
// buckets use omitempty, so only severities that are at/above the threshold AND
// non-zero appear in the response — a level with nothing to show is dropped
// rather than rendered as 0. Total (all findings) and Relevant (sum of visible
// buckets) are always present, including when Relevant is 0.
type SeverityCounts struct {
	Critical   int `json:"critical,omitempty"`
	High       int `json:"high,omitempty"`
	Medium     int `json:"medium,omitempty"`
	Low        int `json:"low,omitempty"`
	Negligible int `json:"negligible,omitempty"`
	Unknown    int `json:"unknown,omitempty"`
	Total      int `json:"total"`
	Relevant   int `json:"relevant"`
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

// ListImages returns a tenant's active images. Every tracked image is returned
// (the list is an inventory — images never disappear); minSeverity trims the
// per-severity breakdown to levels at or above the threshold (unknown always
// kept), zeroing the rest. Total still reflects all findings. Tenant-scoped.
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
		im.Counts = applyThreshold(c, minSeverity)
		out = append(out, im)
	}
	return out, rows.Err()
}

// applyThreshold zeroes the per-severity buckets below min (unknown is always
// kept) and sets Relevant to the sum of the visible buckets. Total is left as
// the overall finding count. Uses the shared ordering so it can't drift from the
// row filter on /findings and /events.
func applyThreshold(c SeverityCounts, min string) SeverityCounts {
	buckets := map[string]*int{
		data.SeverityCritical:   &c.Critical,
		data.SeverityHigh:       &c.High,
		data.SeverityMedium:     &c.Medium,
		data.SeverityLow:        &c.Low,
		data.SeverityNegligible: &c.Negligible,
	}
	relevant := c.Unknown // unknown always kept
	for sev, p := range buckets {
		if data.MeetsThreshold(sev, min) {
			relevant += *p
		} else {
			*p = 0 // trim sub-threshold bucket from the breakdown
		}
	}
	c.Relevant = relevant
	return c
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

// TimelineEvent is one change in an image's history, carrying the digest it
// occurred on so a caller can see the inventory progress across digest changes.
type TimelineEvent struct {
	Digest     string    `json:"digest"`
	SBOMID     string    `json:"sbom_id"`
	Scanner    string    `json:"scanner"`
	EventType  string    `json:"event_type"`
	Exposure   string    `json:"exposure"`
	Package    string    `json:"package"`
	Severity   string    `json:"severity"`
	Score      float32   `json:"score"`
	Cause      string    `json:"cause"`
	OccurredAt time.Time `json:"occurred_at"`
}

// ImageTimeline returns the change history for an image ref across ALL its
// digests — the cross-digest view of how one tracked image evolved. Filtered to
// minSeverity (unknown always included), newest first. Tenant-scoped; returns
// ErrNotFound if the ref is unknown to the tenant (so an empty history and an
// unknown image are distinguishable).
func (s *Store) ImageTimeline(ctx context.Context, tenantID, imageRef, minSeverity string, limit int) ([]TimelineEvent, error) {
	var known bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE tenant_id = $1 AND image_ref = $2)`,
		tenantID, imageRef).Scan(&known); err != nil {
		return nil, fmt.Errorf("check image ref: %w", err)
	}
	if !known {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.digest, e.sbom_id, e.scanner, e.event_type, e.exposure, e.package,
		       e.severity, e.score, e.cause, e.occurred_at
		FROM devradar_finding_event e
		JOIN devradar_sbom sb ON sb.id = e.sbom_id
		WHERE e.tenant_id = $1 AND sb.image_ref = $2 AND e.severity = ANY($3)
		ORDER BY e.occurred_at DESC LIMIT $4`,
		tenantID, imageRef, pq.Array(data.AllowedSeverities(minSeverity)), limit)
	if err != nil {
		return nil, fmt.Errorf("image timeline: %w", err)
	}
	defer rows.Close()

	var out []TimelineEvent
	for rows.Next() {
		var t TimelineEvent
		if err := rows.Scan(&t.Digest, &t.SBOMID, &t.Scanner, &t.EventType, &t.Exposure,
			&t.Package, &t.Severity, &t.Score, &t.Cause, &t.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan timeline event: %w", err)
		}
		out = append(out, t)
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
