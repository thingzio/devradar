// Package config reads all runtime configuration from environment variables.
// There is no config file and no flags: each tunable is a typed accessor with a
// documented default, following the DevPulse/DevTrace convention. Service-scoped
// tunables are prefixed DEVRADAR_; infrastructure vars (DATABASE_URL, PORT,
// BASE_URL, ANTHROPIC_API_KEY) are unprefixed.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/attest"
)

// MaxSBOMBytes caps the size of an SBOM anywhere it crosses a trust boundary:
// the decoded/decompressed ingest body AND every read back from blob storage.
// It is a single shared invariant so a corrupt, manually-replaced, or legacy
// object can never expand past what ingest would have accepted and exhaust
// scanner memory. 20 MiB comfortably fits real all-layers SBOMs.
const MaxSBOMBytes = 20 << 20

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

// TokenFlashKey returns the AES-256 key used to encrypt the one-time API-token
// display flash at rest (DEVRADAR_TOKEN_FLASH_KEY, base64-encoded 32 bytes), or
// nil when unset. When nil the flash is stored as plaintext (acceptable for
// local dev); production should set a key so the live secret is never at rest in
// plaintext even for the 2-minute display window. An invalid/wrong-length value
// returns nil (the caller degrades to plaintext rather than failing).
func TokenFlashKey() []byte {
	raw := GetEnv("DEVRADAR_TOKEN_FLASH_KEY", "")
	if raw == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
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

// DevMode reports whether the service is running in development mode
// (DEVRADAR_DEV_MODE). Dev mode relaxes production guardrails — notably it
// permits logging magic-link sign-in URLs when no email sender is configured. In
// production (DevMode false) an unconfigured sender is a fatal startup error, so
// sign-in links are never written to logs where they could be replayed.
//
// It is deliberately a single explicit flag: it must NOT be inferred from an
// unrelated storage selector like DEVRADAR_LOCAL_SBOMS, so that setting a local
// storage option in a prod-ish environment can never silently downgrade a
// security guardrail. The local dev flow sets DEVRADAR_DEV_MODE explicitly.
func DevMode() bool {
	return GetEnvBool("DEVRADAR_DEV_MODE")
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

// MaxTokensPerTenant caps how many API tokens a tenant may hold at once — a
// guard so a compromised session or a bug can't mint unbounded credentials.
// 0 disables the cap. Tunable via DEVRADAR_MAX_TOKENS_PER_TENANT (default 25).
func MaxTokensPerTenant() int {
	return GetEnvAsInt("DEVRADAR_MAX_TOKENS_PER_TENANT", 25)
}

// MaxSBOMsPerTenant caps how many ACTIVE SBOMs (distinct digests) a tenant may
// track at once. The repository cap (MaxImagesPerTenant) alone leaves a hole: an
// unbounded number of digests can accrue under a single repository (every rebuild
// is a new digest), each multiplying scan work and findings. This bounds the real
// cost driver. Re-submitting an already-stored digest is always allowed (it is an
// update, not growth); only a brand-new digest past the cap is rejected. 0
// disables the cap. Tunable via DEVRADAR_MAX_SBOMS_PER_TENANT (default 5000).
func MaxSBOMsPerTenant() int {
	return GetEnvAsInt("DEVRADAR_MAX_SBOMS_PER_TENANT", 5000)
}

// LoginRatePerHourEmail caps magic-link requests per normalized email per hour
// (unbounded requests mint login-token rows and send emails). 0 disables.
// Tunable via DEVRADAR_LOGIN_RATE_EMAIL (default 5).
func LoginRatePerHourEmail() int {
	return GetEnvAsInt("DEVRADAR_LOGIN_RATE_EMAIL", 5)
}

// LoginRatePerHourIP caps magic-link requests per client IP per hour, a
// coarser guard against a single source enumerating addresses. 0 disables.
// Tunable via DEVRADAR_LOGIN_RATE_IP (default 20).
func LoginRatePerHourIP() int {
	return GetEnvAsInt("DEVRADAR_LOGIN_RATE_IP", 20)
}

// ScanMaxAge is the staleness window for scan-job work selection: an SBOM is
// scanned only if never scanned or last scanned longer ago than this. Paired
// with a frequent scheduler, it bounds per-SBOM scan frequency (default 12h ⇒
// at most ~twice a day). Set DEVRADAR_SCAN_MAX_AGE=0 to scan every active SBOM
// every run. Tunable via DEVRADAR_SCAN_MAX_AGE (a Go duration, e.g. "12h").
func ScanMaxAge() time.Duration {
	return GetEnvAsDuration("DEVRADAR_SCAN_MAX_AGE", 12*time.Hour)
}

// TrustedProxyCount is the number of proxy hops that append to X-Forwarded-For
// in front of the app. The real client IP is read this many entries from the
// RIGHT of XFF (client-supplied left-most entries are spoofable). Cloud Run
// appends exactly one hop, so the default is 1. Set to 0 to ignore XFF entirely
// and always use RemoteAddr. Tunable via DEVRADAR_TRUSTED_PROXY_COUNT.
func TrustedProxyCount() int {
	return GetEnvAsInt("DEVRADAR_TRUSTED_PROXY_COUNT", 1)
}

// PostureSnapshotMinInterval is the minimum age of the newest posture snapshot
// before the scan job recomputes it. The snapshot is an expensive full-fleet
// projection deduplicated to one row per tenant per day, so recomputing it every
// ~15-min scan tick is wasteful — this bounds it to at most one run per interval
// while still capturing a well-converged end-of-day value. Default 12h. Set to 0
// to recompute on every scan run (the legacy behavior). Tunable via
// DEVRADAR_POSTURE_SNAPSHOT_MIN_INTERVAL (a Go duration).
func PostureSnapshotMinInterval() time.Duration {
	return GetEnvAsDuration("DEVRADAR_POSTURE_SNAPSHOT_MIN_INTERVAL", 12*time.Hour)
}

// AttestEnabled reports whether attestation verification is turned on. On by
// default, but the feature still requires trust material (identities or keys) to
// do anything — see AttestConfigured. Set DEVRADAR_ATTEST=false to hard-disable.
func AttestEnabled() bool {
	return GetEnv("DEVRADAR_ATTEST", "true") != "false"
}

// AttestConfigured reports whether the operator has OPTED IN to attestation
// verification (mirrors GitHubOAuthConfigured): enabled AND at least one identity
// or public-key path is present in the environment. It is deliberately based on
// env-var PRESENCE, not on successfully-loaded material, so a typo'd key/root
// path still counts as "configured" — that surfaces the misconfiguration at
// startup (see AttestPolicy) instead of silently disabling verification. When
// false, submitted attestations are ignored and SBOMs stay 'unverified'.
func AttestConfigured() bool {
	if !AttestEnabled() {
		return false
	}
	return len(csvList("DEVRADAR_ATTEST_IDENTITIES")) > 0 ||
		len(csvList("DEVRADAR_ATTEST_PUBLIC_KEYS")) > 0
}

// AttestPolicy assembles the trust policy from the environment:
//   - DEVRADAR_ATTEST_IDENTITIES   comma-separated Fulcio SAN identities (keyless)
//   - DEVRADAR_ATTEST_ISSUERS      comma-separated OIDC issuers (keyless; required
//     when identities are set — an identity must be pinned to an issuer)
//   - DEVRADAR_ATTEST_PUBLIC_KEYS  comma-separated paths to PEM public keys (key mode)
//   - DEVRADAR_ATTEST_PREDICATE_TYPES comma-separated allow-list (empty ⇒ defaults)
//   - DEVRADAR_ATTEST_TRUSTED_ROOT path to a sigstore trusted-root JSON
//   - DEVRADAR_ATTEST_TUF          "true" to allow fetching the public sigstore
//     TUF root when no trusted-root file is set (off by default: ingest stays
//     network-free)
//
// A configured key or trusted-root path that cannot be read returns an ERROR
// rather than being silently skipped: a typo must fail loudly (the caller fails
// closed at startup) instead of silently weakening or disabling a trust policy
// the operator explicitly asked for.
func AttestPolicy() (attest.Policy, error) {
	p := attest.Policy{
		Identities:       csvList("DEVRADAR_ATTEST_IDENTITIES"),
		Issuers:          csvList("DEVRADAR_ATTEST_ISSUERS"),
		PredicateTypes:   csvList("DEVRADAR_ATTEST_PREDICATE_TYPES"),
		TUFEnabled:       GetEnvBool("DEVRADAR_ATTEST_TUF"),
		RequireSBOMBytes: GetEnvBool("DEVRADAR_ATTEST_REQUIRE_SBOM_BYTES"),
	}
	for _, path := range csvList("DEVRADAR_ATTEST_PUBLIC_KEYS") {
		pem, err := os.ReadFile(path)
		if err != nil {
			return attest.Policy{}, fmt.Errorf("read attest public key %q: %w", path, err)
		}
		p.PublicKeys = append(p.PublicKeys, pem)
	}
	if root := GetEnv("DEVRADAR_ATTEST_TRUSTED_ROOT", ""); root != "" {
		data, err := os.ReadFile(root)
		if err != nil {
			return attest.Policy{}, fmt.Errorf("read attest trusted root %q: %w", root, err)
		}
		p.TrustedRoot = data
	}
	return p, nil
}

// csvList splits a comma-separated env var into trimmed, non-empty values.
func csvList(key string) []string {
	raw := GetEnv(key, "")
	if raw == "" {
		return nil
	}
	var out []string
	for v := range strings.SplitSeq(raw, ",") {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}
