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
	PolicyID        string
	PolicyUpdatedAt time.Time
	Kind            string
	Event           AlertEvent
}

// AlertPosition identifies one source event and its stable pending-queue key.
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
	KEV             bool
	EPSS            *float32
	ReadAt          *time.Time
	CreatedAt       time.Time
}

// Attestation is a row in devradar_sbom_attestation: the durable evidence of one
// cryptographic verification decision for an SBOM. Optional fields are empty when
// not applicable to the mode/outcome (e.g. CertIdentity only on keyless).
type Attestation struct {
	ID                 string    `json:"id"`
	SBOMID             string    `json:"sbom_id"`
	Result             string    `json:"result"`  // verified | failed
	Mode               string    `json:"mode"`    // keyless | key
	Binding            string    `json:"binding"` // sbom-bytes | image-digest
	SubjectDigest      string    `json:"subject_digest"`
	PredicateType      string    `json:"predicate_type,omitempty"`
	CertIdentity       string    `json:"cert_identity,omitempty"`
	OIDCIssuer         string    `json:"oidc_issuer,omitempty"`
	KeyID              string    `json:"key_id,omitempty"`
	TransparencyLogRef string    `json:"transparency_log_ref,omitempty"`
	VerifierVersion    string    `json:"verifier_version"`
	PolicyVersion      string    `json:"policy_version"`
	FailureReason      string    `json:"failure_reason,omitempty"`
	VerifiedAt         time.Time `json:"verified_at"`
}
