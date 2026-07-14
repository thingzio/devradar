package config

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestValidate_OK(t *testing.T) {
	// A fully valid (or entirely unset) environment passes. DevMode on so the
	// production-only flash-key requirement doesn't apply here (covered separately).
	t.Setenv("DEVRADAR_DEV_MODE", "true")
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
			t.Setenv("DEVRADAR_DEV_MODE", "true") // isolate to the validator under test
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

func TestValidate_TokenFlashKeyFailsClosed(t *testing.T) {
	// Production requires a configured key. Development uses a process-ephemeral
	// key so a raw token is never stored recoverably.
	t.Run("unset in prod is rejected", func(t *testing.T) {
		t.Setenv("DEVRADAR_DEV_MODE", "false")
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
		if err := ValidateServer(); err == nil {
			t.Fatal("unset flash key must fail startup in prod")
		}
	})
	t.Run("invalid in prod is rejected", func(t *testing.T) {
		t.Setenv("DEVRADAR_DEV_MODE", "false")
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "not-base64-!!") // invalid
		err := ValidateServer()
		if err == nil || !strings.Contains(err.Error(), "DEVRADAR_TOKEN_FLASH_KEY") {
			t.Fatalf("expected token-flash-key error in prod, got %v", err)
		}
	})
	t.Run("wrong length in prod is rejected", func(t *testing.T) {
		t.Setenv("DEVRADAR_DEV_MODE", "false")
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "dG9vc2hvcnQ=") // valid base64, 8 bytes
		if err := ValidateServer(); err == nil {
			t.Fatal("expected error for wrong-length key in prod")
		}
	})
	t.Run("invalid in dev is also rejected", func(t *testing.T) {
		// A set-but-invalid value is unambiguously a mistake, so it is a hard error
		// even in dev (where only an entirely unset key gets an ephemeral fallback).
		t.Setenv("DEVRADAR_DEV_MODE", "true")
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "not-base64-!!")
		if err := ValidateServer(); err == nil {
			t.Fatal("a set-but-invalid key should be rejected even in dev")
		}
	})
	t.Run("unset in dev is fine", func(t *testing.T) {
		t.Setenv("DEVRADAR_DEV_MODE", "true")
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
		if err := ValidateServer(); err != nil {
			t.Fatalf("unset key in dev must pass, got %v", err)
		}
	})
	t.Run("valid 32-byte key passes", func(t *testing.T) {
		t.Setenv("DEVRADAR_DEV_MODE", "false")
		// base64 of 32 zero bytes.
		t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SEND_API_KEY", "re_real")
		if err := ValidateServer(); err != nil {
			t.Fatalf("valid key rejected: %v", err)
		}
	})
}

func TestValidateServerRejectsUnsafeProductionSendAPIKey(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "false")
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	for _, key := range []string{"", "   ", " re_real", "re_real ", "re_real\nheader", sendAPIKeyPlaceholder} {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			t.Setenv("SEND_API_KEY", key)
			err := ValidateServer()
			if err == nil || !strings.Contains(err.Error(), "SEND_API_KEY") {
				t.Fatalf("unsafe server SEND_API_KEY error = %v", err)
			}
			if key != "" && key != "   " && strings.Contains(err.Error(), key) {
				t.Fatalf("server error reflected SEND_API_KEY: %v", err)
			}
		})
	}
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	for _, key := range []string{"", sendAPIKeyPlaceholder} {
		t.Setenv("SEND_API_KEY", key)
		if err := ValidateServer(); err != nil {
			t.Fatalf("development missing/placeholder sender rejected: %v", err)
		}
	}
}

func TestValidateDoesNotRequireServeOnlyTokenFlashKey(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "false")
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
	if err := Validate(); err != nil {
		t.Fatalf("shared scan validation requires serve-only token flash key: %v", err)
	}
}

func TestTokenFlashKeyNeverSilentlyDowngradesInvalidConfiguration(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "not-base64-!!")
	if key, err := TokenFlashKey(); err == nil || key != nil {
		t.Fatalf("TokenFlashKey invalid = %x, %v, want nil/error", key, err)
	}
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
	first, err := TokenFlashKey()
	if err != nil || len(first) != 32 {
		t.Fatalf("TokenFlashKey dev fallback length = %d, %v, want 32/nil", len(first), err)
	}
	second, err := TokenFlashKey()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("TokenFlashKey dev fallback is not process-stable: %x/%x %v", first, second, err)
	}
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if key, err := TokenFlashKey(); err != nil || len(key) != 32 {
		t.Fatalf("TokenFlashKey valid length = %d, %v, want 32/nil", len(key), err)
	}
}

func TestTokenFlashKeyProductionRequiresConfiguration(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "false")
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
	if key, err := TokenFlashKey(); err == nil || key != nil {
		t.Fatalf("TokenFlashKey prod unset = %x, %v, want nil/error", key, err)
	}
}

func TestValidate_UnsetIsFine(t *testing.T) {
	// Explicitly clear the bounded vars: unset must not error (defaults apply).
	// DevMode on so the production-only flash-key requirement doesn't apply (the
	// flash key is unset here, which is the documented dev default).
	t.Setenv("DEVRADAR_DEV_MODE", "true")
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

func TestValidateServerRequiresDeliveryKeyOnlyWhenSharingEnabled(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	t.Setenv("DEVRADAR_TOKEN_FLASH_KEY", "")
	t.Setenv("DEVRADAR_DELIVERY_KEY", "")
	t.Setenv("DEVRADAR_ACCOUNT_SHARING_ENABLED", "false")
	if err := ValidateServer(); err != nil {
		t.Fatalf("disabled sharing required delivery key: %v", err)
	}
	t.Setenv("DEVRADAR_ACCOUNT_SHARING_ENABLED", "true")
	if err := ValidateServer(); err == nil || !strings.Contains(err.Error(), "DEVRADAR_DELIVERY_KEY") {
		t.Fatalf("enabled sharing error = %v", err)
	}
	t.Setenv("DEVRADAR_DELIVERY_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := ValidateServer(); err != nil {
		t.Fatalf("enabled sharing with valid key: %v", err)
	}
}

func TestValidateDeliveryFailsClosed(t *testing.T) {
	t.Setenv("DEVRADAR_DELIVERY_KEY", "")
	t.Setenv("SEND_API_KEY", "")
	t.Setenv("DEVRADAR_DEV_MODE", "false")
	if err := ValidateDelivery(); err == nil || !strings.Contains(err.Error(), "DEVRADAR_DELIVERY_KEY") {
		t.Fatalf("missing delivery key error = %v", err)
	}
	t.Setenv("DEVRADAR_DELIVERY_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := ValidateDelivery(); err == nil || !strings.Contains(err.Error(), "SEND_API_KEY") {
		t.Fatalf("missing production sender error = %v", err)
	}
	t.Setenv("SEND_API_KEY", "re_real")
	if err := ValidateDelivery(); err != nil {
		t.Fatalf("valid production delivery config: %v", err)
	}
	t.Setenv("SEND_API_KEY", "")
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	if err := ValidateDelivery(); err != nil {
		t.Fatalf("development LogSender config: %v", err)
	}
}

func TestValidateDeliveryRejectsUnsafeProductionSendAPIKey(t *testing.T) {
	t.Setenv("DEVRADAR_DEV_MODE", "false")
	t.Setenv("DEVRADAR_DELIVERY_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	for _, key := range []string{
		"   ", " re_real", "re_real ", "re_real\nheader", sendAPIKeyPlaceholder,
	} {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			t.Setenv("SEND_API_KEY", key)
			err := ValidateDelivery()
			if err == nil || !strings.Contains(err.Error(), "SEND_API_KEY") {
				t.Fatalf("unsafe SEND_API_KEY error = %v", err)
			}
			if key != "   " && strings.Contains(err.Error(), key) {
				t.Fatalf("error reflected SEND_API_KEY: %v", err)
			}
		})
	}
}

func TestValidateRejectsInvalidDeliveryTunables(t *testing.T) {
	for key, value := range map[string]string{
		"DEVRADAR_DELIVERY_BATCH_SIZE":       "51",
		"DEVRADAR_DELIVERY_CONCURRENCY":      "6",
		"DEVRADAR_DELIVERY_REQUEST_DEADLINE": "11s",
		"DEVRADAR_DELIVERY_MAX_ATTEMPTS":     "9",
		"DEVRADAR_DELIVERY_RETRY_HORIZON":    "24h",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if err := Validate(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("%s=%s error = %v", key, value, err)
			}
		})
	}
}
