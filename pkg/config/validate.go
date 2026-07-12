package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Validate parses and range-checks every tunable that has a bounded domain,
// exactly once at startup, and returns a precise error naming the offending
// variable. It fails closed: a variable that is SET but unparseable or
// out-of-range is a deployment mistake, so the process should refuse to start
// rather than silently fall back to a default (the accessors' lenient behavior,
// kept for the unset case). An UNSET variable is always fine — the documented
// default applies.
//
// Call it at the top of each binary's Run (serve, scan) before wiring anything.
// It reads os.Getenv directly (not the accessors) so it can tell "unset" from
// "set-but-invalid".
func Validate() error {
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// Non-negative counts/quotas (0 has a documented meaning: disable the cap).
	check(validateInt("DEVRADAR_MAX_IMAGES_PER_TENANT", 0, -1))
	check(validateInt("DEVRADAR_MAX_SBOMS_PER_TENANT", 0, -1))
	check(validateInt("DEVRADAR_MAX_TOKENS_PER_TENANT", 0, -1))
	check(validateInt("DEVRADAR_LOGIN_RATE_EMAIL", 0, -1))
	check(validateInt("DEVRADAR_LOGIN_RATE_IP", 0, -1))
	check(validateInt("DB_MAX_OPEN_CONNS", 1, -1))
	check(validateInt("DB_MAX_IDLE_CONNS", 0, -1))
	// Strictly positive: a zero/negative shutdown budget would abort in-flight
	// requests instantly (or hang), never what an operator means.
	check(validateInt("SERVER_SHUTDOWN_TIMEOUT_SEC", 1, -1))
	// PORT, when set, must be a valid TCP port.
	check(validateInt("PORT", 1, 65535))

	// Non-negative durations (0 disables the staleness filter, documented).
	check(validateDuration("DEVRADAR_SCAN_MAX_AGE", 0))
	check(validateDuration("DEVRADAR_POSTURE_SNAPSHOT_MIN_INTERVAL", 0))

	// Trusted-proxy count gates X-Forwarded-For client-IP trust (rate-limit
	// keying), so a bad value is a security-relevant misconfig, not a cosmetic one.
	check(validateInt("DEVRADAR_TRUSTED_PROXY_COUNT", 0, -1))

	// Fail closed on a security-at-rest key: a SET-but-invalid token-flash key
	// silently degrades to plaintext storage of the live API token. Acceptable in
	// dev (unset ⇒ plaintext by design); a deployment mistake in production.
	check(validateTokenFlashKey())

	// Required URLs, when set, must parse with a scheme + host.
	check(validateURL("BASE_URL"))
	check(validateDatabaseURL("DATABASE_URL"))

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return nil
}

// validateInt checks that key, if set, parses as an int in [min, max]. A max < 0
// means "no upper bound". Unset ⇒ nil (default applies).
func validateInt(key string, min, max int) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not an integer", key, v)
	}
	if n < min {
		return fmt.Errorf("%s=%d is below the minimum %d", key, n, min)
	}
	if max >= 0 && n > max {
		return fmt.Errorf("%s=%d is above the maximum %d", key, n, max)
	}
	return nil
}

// validateDuration checks that key, if set, parses as a Go duration >= min.
func validateDuration(key string, min time.Duration) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid duration (e.g. \"12h\")", key, v)
	}
	if d < min {
		return fmt.Errorf("%s=%s is below the minimum %s", key, d, min)
	}
	return nil
}

// validateURL checks that key, if set, is an absolute URL with a scheme + host.
func validateURL(key string) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid URL", key, v)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s=%q must include a scheme and host (e.g. https://devradar.example.com)", key, v)
	}
	return nil
}

// validateTokenFlashKey fails closed on a security-at-rest misconfig: a SET but
// invalid DEVRADAR_TOKEN_FLASH_KEY (not base64, or not 32 bytes) would otherwise
// make TokenFlashKey() return nil and the caller store the one-time API token in
// PLAINTEXT — silently defeating the encryption the operator meant to enable.
// Unset is always fine (dev default is plaintext by design). A set-but-invalid
// key is a hard error outside dev; in DevMode it is downgraded to allow local
// experimentation.
func validateTokenFlashKey() error {
	v, ok := os.LookupEnv("DEVRADAR_TOKEN_FLASH_KEY")
	if !ok || strings.TrimSpace(v) == "" {
		return nil // unset ⇒ documented plaintext-in-dev default
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(key) != 32 {
		if DevMode() {
			return nil
		}
		return fmt.Errorf("DEVRADAR_TOKEN_FLASH_KEY must be base64-encoded 32 bytes " +
			"(set-but-invalid would silently store API tokens in plaintext)")
	}
	return nil
}

// validateDatabaseURL checks that DATABASE_URL, if set, parses as a URL. Cloud
// SQL DSNs use the postgres:// scheme; we don't dial here, only reject a value
// the driver would choke on.
func validateDatabaseURL(key string) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	if _, err := url.Parse(strings.TrimSpace(v)); err != nil {
		return fmt.Errorf("%s is not a parseable connection string: %w", key, err)
	}
	return nil
}
