// Package config reads all runtime configuration from environment variables.
// There is no config file and no flags: each tunable is a typed accessor with a
// documented default, following the DevPulse/DevTrace convention. Service-scoped
// tunables are prefixed DEVRADAR_; infrastructure vars (DATABASE_URL, PORT,
// BASE_URL, ANTHROPIC_API_KEY) are unprefixed.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// GetEnv returns the value of key, or fallback if unset or empty.
func GetEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// GetEnvAsInt returns key parsed as an int, or fallback if unset/invalid.
func GetEnvAsInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

// GetEnvBool returns true when key is set to a truthy value ("1", "true",
// case-insensitive). Absent or anything else is false.
func GetEnvBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// GetEnvAsDuration returns key parsed as a Go duration, or fallback if
// unset/invalid.
func GetEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return fallback
}

// DatabaseURL returns the Postgres DSN. In production this is the Cloud SQL
// unix-socket DSN delivered via the devradar-saas-database-url secret; the
// default targets a local docker-compose Postgres for development and tests.
func DatabaseURL() string {
	return GetEnv("DATABASE_URL", "postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable")
}

// GCPProjectID returns the GCP project, defaulting to the shared Thingz project.
func GCPProjectID() string {
	return GetEnv("GCP_PROJECT", "thingzio")
}

// SBOMBucket returns the GCS bucket name for stored SBOM bytes.
func SBOMBucket() string {
	return GetEnv("DEVRADAR_SBOM_BUCKET", "devradar-saas-sboms")
}

// BaseURL returns the externally-reachable base URL (used for magic-link URLs
// and the cookie scheme).
func BaseURL() string {
	return GetEnv("BASE_URL", "http://localhost:8080")
}

// sendAPIKeyPlaceholder is the value Terraform seeds into the send-api-key
// secret before a real key is set out-of-band. Treated as "not configured" so
// the service degrades to logging magic links rather than failing to send with
// a bogus key.
const sendAPIKeyPlaceholder = "placeholder-set-real-value-out-of-band"

// SendAPIKey returns the Resend API key for transactional email (magic-link
// sign-in, later alerts), or "" if unset or still the Terraform placeholder.
// Empty disables real sending — the server logs the magic link instead. Shared
// platform secret name: SEND_API_KEY.
func SendAPIKey() string {
	k := GetEnv("SEND_API_KEY", "")
	if k == sendAPIKeyPlaceholder {
		return ""
	}
	return k
}

// EmailFrom returns the From address for outbound email.
func EmailFrom() string {
	return GetEnv("EMAIL_FROM", "DevRadar <no-reply@thingz.io>")
}

// GitHubClientID returns the GitHub OAuth app client id, or "" if unset.
// Unprefixed like the other platform-integration secrets (SEND_API_KEY): it
// names an external app registration, not a DevRadar service tunable.
func GitHubClientID() string {
	return GetEnv("GITHUB_OAUTH_CLIENT_ID", "")
}

// GitHubClientSecret returns the GitHub OAuth app client secret, or "" if unset
// or still the Terraform placeholder (treated as unconfigured, mirroring
// SendAPIKey so the service degrades to email-only sign-in rather than failing).
func GitHubClientSecret() string {
	k := GetEnv("GITHUB_OAUTH_CLIENT_SECRET", "")
	if k == sendAPIKeyPlaceholder {
		return ""
	}
	return k
}

// GitHubOAuthConfigured reports whether GitHub sign-in is enabled — both the
// client id and secret must be set. When false, the server hides the "Continue
// with GitHub" button and does not register the OAuth routes.
func GitHubOAuthConfigured() bool {
	return GitHubClientID() != "" && GitHubClientSecret() != ""
}

// GitHubOAuthRedirectURL is the OAuth callback URL, derived from BASE_URL. Must
// exactly match the callback registered in the GitHub OAuth app.
func GitHubOAuthRedirectURL() string {
	return BaseURL() + "/auth/github/callback"
}

// DebugEnabled reports whether debug-level logging is on (DEVRADAR_DEBUG).
func DebugEnabled() bool {
	return GetEnvBool("DEVRADAR_DEBUG")
}

// EnrichEnabled reports whether the scan job refreshes CVE risk enrichment
// (EPSS + CISA KEV) each run. On by default; set DEVRADAR_ENRICH=false to
// disable (e.g. in an air-gapped run with no feed egress).
func EnrichEnabled() bool {
	return GetEnv("DEVRADAR_ENRICH", "true") != "false"
}

// AdminUsers returns the set of emails authorized for the operator admin console
// (DEVRADAR_ADMIN_USERS, comma-separated), lower-cased and trimmed for
// case-insensitive matching against the verified tenant email. Empty ⇒ nobody is
// an admin and the whole /admin surface returns 404. Adding an admin is a config
// change + redeploy, not a migration (mirrors DevPulse/DevTrace).
func AdminUsers() []string {
	raw := GetEnv("DEVRADAR_ADMIN_USERS", "")
	if raw == "" {
		return nil
	}
	var out []string
	for u := range strings.SplitSeq(raw, ",") {
		if e := strings.ToLower(strings.TrimSpace(u)); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// MaxImagesPerTenant caps how many distinct images (repositories) a tenant may
// track, an abuse/runaway guard on unbounded per-tenant growth (each image
// multiplies scan work, findings, and dashboard aggregation). The cap is on
// NEW repositories only: re-submitting a digest under an already-tracked
// repository always succeeds, so a tenant already over the limit is never locked
// out of updating what they have. 0 disables the cap. Tunable via
// DEVRADAR_MAX_IMAGES_PER_TENANT (default 500).
func MaxImagesPerTenant() int {
	return GetEnvAsInt("DEVRADAR_MAX_IMAGES_PER_TENANT", 500)
}

// ScanMaxAge is the staleness window for scan-job work selection: an SBOM is
// scanned only if never scanned or last scanned longer ago than this. Paired
// with a frequent scheduler, it bounds per-SBOM scan frequency (default 12h ⇒
// at most ~twice a day). Set DEVRADAR_SCAN_MAX_AGE=0 to scan every active SBOM
// every run. Tunable via DEVRADAR_SCAN_MAX_AGE (a Go duration, e.g. "12h").
func ScanMaxAge() time.Duration {
	return GetEnvAsDuration("DEVRADAR_SCAN_MAX_AGE", 12*time.Hour)
}
