package config

import (
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
	check(validateInt("DEVRADAR_INVITATION_RATE_ACCOUNT", 0, -1))
	check(validateInt("DEVRADAR_INVITATION_RATE_RECIPIENT", 0, -1))
	check(validateInt("DB_MAX_OPEN_CONNS", 1, -1))
	check(validateInt("DB_MAX_IDLE_CONNS", 0, -1))
	// Strictly positive: a zero/negative shutdown budget would abort in-flight
	// requests instantly (or hang), never what an operator means.
	check(validateInt("SERVER_SHUTDOWN_TIMEOUT_SEC", 1, -1))
	// PORT, when set, must be a valid TCP port.
	check(validateInt("PORT", 1, 65535))
	check(validateInt("DEVRADAR_DELIVERY_BATCH_SIZE", 1, 50))
	check(validateInt("DEVRADAR_DELIVERY_CONCURRENCY", 1, 5))
	check(validateInt("DEVRADAR_DELIVERY_MAX_ATTEMPTS", 1, 8))

	// Non-negative durations (0 disables the staleness filter, documented).
	check(validateDuration("DEVRADAR_SCAN_MAX_AGE", 0))
	check(validateDuration("DEVRADAR_POSTURE_SNAPSHOT_MIN_INTERVAL", 0))
	check(validateDurationRange("DEVRADAR_DELIVERY_REQUEST_DEADLINE", time.Millisecond, 10*time.Second))
	check(validateDurationRange("DEVRADAR_DELIVERY_RETRY_HORIZON", time.Millisecond, 23*time.Hour))
	check(validateBool("DEVRADAR_ACCOUNT_SHARING_ENABLED"))

	// Trusted-proxy count gates X-Forwarded-For client-IP trust (rate-limit
	// keying), so a bad value is a security-relevant misconfig, not a cosmetic one.
	check(validateInt("DEVRADAR_TRUSTED_PROXY_COUNT", 0, -1))

	// Required URLs, when set, must parse with a scheme + host.
	check(validateURL("BASE_URL"))
	check(validateDatabaseURL("DATABASE_URL"))

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return nil
}

// ValidateServer validates shared configuration plus serve-only secrets.
func ValidateServer() error {
	if err := Validate(); err != nil {
		return err
	}
	if err := validateTokenFlashKey(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := validateSendAPIKey(!DevMode()); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if AccountSharingEnabled() {
		if _, err := DeliveryKey(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}
	return nil
}

// ValidateDelivery validates shared configuration plus the durable outbox key
// and production provider credential required by the delivery command.
func ValidateDelivery() error {
	if err := Validate(); err != nil {
		return err
	}
	if _, err := DeliveryKey(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := validateSendAPIKey(!DevMode()); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

func validateSendAPIKey(required bool) error {
	raw, configured := os.LookupEnv("SEND_API_KEY")
	if !configured || raw == "" || raw == sendAPIKeyPlaceholder {
		if required {
			return fmt.Errorf("SEND_API_KEY is required outside development mode")
		}
		return nil
	}
	if raw != strings.TrimSpace(raw) {
		return fmt.Errorf("SEND_API_KEY contains leading or trailing whitespace")
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("SEND_API_KEY contains invalid characters")
		}
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

func validateDurationRange(key string, min, max time.Duration) error {
	if err := validateDuration(key, min); err != nil {
		return err
	}
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	d, _ := time.ParseDuration(strings.TrimSpace(v))
	if d > max {
		return fmt.Errorf("%s=%s is above the maximum %s", key, d, max)
	}
	return nil
}

func validateBool(key string) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "0", "false", "no", "off":
		return nil
	default:
		return fmt.Errorf("%s=%q is not a boolean", key, v)
	}
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

// validateTokenFlashKey rejects missing production configuration and every
// invalid configured value. Development initializes a process-ephemeral key;
// restart loss of an unread two-minute flash is preferable to recoverable raw
// token storage.
func validateTokenFlashKey() error {
	_, err := TokenFlashKey()
	return err
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
