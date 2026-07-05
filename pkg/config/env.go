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

// DebugEnabled reports whether debug-level logging is on (DEVRADAR_DEBUG).
func DebugEnabled() bool {
	return GetEnvBool("DEVRADAR_DEBUG")
}
