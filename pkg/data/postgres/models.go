package postgres

import "time"

// SBOM is a row in devradar_sbom.
type SBOM struct {
	ID                 string
	TenantID           string
	ImageRef           string
	Repository         string // grouping key: registry/path, no tag/digest
	Version            string // the image tag, e.g. "v1.20.2"; empty on digest-only submits
	Digest             string
	Format             string
	SpecVersion        string
	Tool               string
	ToolVersion        string
	PackageCount       int
	ObjectPath         string
	VerificationStatus string
	Status             string
	Labels             []string // tenant grouping labels, set at submission
	GeneratedAt        time.Time
	SubmittedAt        time.Time
}

// Versions carries the three tool-version axes recorded per scan run. Together
// with the SBOM's own digest they fully determine a finding set and let the
// delta engine attribute each change to a single cause.
type Versions struct {
	DBVersion            string
	ScannerVersion       string
	CanonicalizerVersion string
}

// AlertPolicy is the tenant's prospective filter for browser alerts.
type AlertPolicy struct {
	ID                string
	TenantID          string
	Enabled           bool
	MinSeverity       string
	AlertKEV          bool
	AlertFixAvailable bool
	IncludeImage      bool
	IncludeDB         bool
	Labels            []string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AlertEvent is one finding event enriched with the tenant and image context
// needed for policy matching and an immutable alert record.
type AlertEvent struct {
	ID         int64
	OccurredAt time.Time
	TenantID   string
	SBOMID     string
	Repository string
	Digest     string
	FindingID  string
	EventType  string
	Exposure   string
	Package    string
	Version    string
	Severity   string
	Cause      string
	Score      float32
	KEV        bool
	Labels     []string
}

// AlertCandidate pairs an event with the policy effective when it is read.
type AlertCandidate struct {
	Policy AlertPolicy
	Event  AlertEvent
}

// AlertDraft is a matched event ready for idempotent persistence.
type AlertDraft struct {
	PolicyID string
	Kind     string
	Event    AlertEvent
}

// AlertPosition identifies one stable location in the finding-event stream.
type AlertPosition struct {
	OccurredAt time.Time
	EventID    int64
}

// AlertFailure is one source event the evaluator could not classify.
type AlertFailure struct {
	Position AlertPosition
	Error    string
}

// Alert is a durable, channel-neutral tenant notification.
type Alert struct {
	ID              string
	TenantID        string
	PolicyID        string
	EventID         int64
	EventOccurredAt time.Time
	Kind            string
	SBOMID          string
	Repository      string
	Digest          string
	FindingID       string
	Exposure        string
	Package         string
	Version         string
	Severity        string
	Cause           string
	Score           float32
	ReadAt          *time.Time
	CreatedAt       time.Time
}
