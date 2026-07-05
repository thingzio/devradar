package postgres

import "time"

// SBOM is a row in devradar_sbom.
type SBOM struct {
	ID                 string
	TenantID           string
	ImageRef           string
	Digest             string
	Format             string
	SpecVersion        string
	Tool               string
	ToolVersion        string
	PackageCount       int
	ObjectPath         string
	VerificationStatus string
	Status             string
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
