package config

import (
	"strings"
	"testing"
)

func TestValidate_OK(t *testing.T) {
	// A fully valid (or entirely unset) environment passes.
	t.Setenv("DEVRADAR_MAX_IMAGES_PER_TENANT", "500")
	t.Setenv("DB_MAX_OPEN_CONNS", "10")
	t.Setenv("SERVER_SHUTDOWN_TIMEOUT_SEC", "5")
	t.Setenv("PORT", "8080")
	t.Setenv("DEVRADAR_SCAN_MAX_AGE", "12h")
	t.Setenv("BASE_URL", "https://devradar.example.com")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	if err := Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidate_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name, key, val, wantSubstr string
	}{
		{"negative image cap", "DEVRADAR_MAX_IMAGES_PER_TENANT", "-1", "DEVRADAR_MAX_IMAGES_PER_TENANT"},
		{"non-numeric image cap", "DEVRADAR_MAX_IMAGES_PER_TENANT", "lots", "not an integer"},
		{"zero pool", "DB_MAX_OPEN_CONNS", "0", "DB_MAX_OPEN_CONNS"},
		{"negative idle", "DB_MAX_IDLE_CONNS", "-3", "DB_MAX_IDLE_CONNS"},
		{"zero shutdown", "SERVER_SHUTDOWN_TIMEOUT_SEC", "0", "SERVER_SHUTDOWN_TIMEOUT_SEC"},
		{"port too high", "PORT", "70000", "PORT"},
		{"negative scan age", "DEVRADAR_SCAN_MAX_AGE", "-5m", "DEVRADAR_SCAN_MAX_AGE"},
		{"bad scan age", "DEVRADAR_SCAN_MAX_AGE", "soon", "not a valid duration"},
		{"schemeless base url", "BASE_URL", "devradar.example.com", "scheme and host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(c.key, c.val)
			err := Validate()
			if err == nil {
				t.Fatalf("expected error for %s=%q", c.key, c.val)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("error %q should mention %q", err.Error(), c.wantSubstr)
			}
		})
	}
}

func TestValidate_UnsetIsFine(t *testing.T) {
	// Explicitly clear the bounded vars: unset must not error (defaults apply).
	for _, k := range []string{
		"DEVRADAR_MAX_IMAGES_PER_TENANT", "DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS",
		"SERVER_SHUTDOWN_TIMEOUT_SEC", "PORT", "DEVRADAR_SCAN_MAX_AGE", "BASE_URL", "DATABASE_URL",
	} {
		t.Setenv(k, "")
	}
	if err := Validate(); err != nil {
		t.Fatalf("unset config should pass, got %v", err)
	}
}
