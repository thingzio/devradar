package config

import (
	"testing"
	"time"
)

func TestGetEnv(t *testing.T) {
	t.Setenv("DR_TEST_STR", "val")
	if got := GetEnv("DR_TEST_STR", "def"); got != "val" {
		t.Errorf("GetEnv set = %q, want val", got)
	}
	if got := GetEnv("DR_TEST_UNSET", "def"); got != "def" {
		t.Errorf("GetEnv unset = %q, want def", got)
	}
}

func TestGetEnvAsInt(t *testing.T) {
	t.Setenv("DR_TEST_INT", "42")
	if got := GetEnvAsInt("DR_TEST_INT", 1); got != 42 {
		t.Errorf("GetEnvAsInt = %d, want 42", got)
	}
	t.Setenv("DR_TEST_BAD", "notint")
	if got := GetEnvAsInt("DR_TEST_BAD", 7); got != 7 {
		t.Errorf("GetEnvAsInt(invalid) = %d, want fallback 7", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("DR_TEST_BOOL", v)
		if !GetEnvBool("DR_TEST_BOOL") {
			t.Errorf("GetEnvBool(%q) = false, want true", v)
		}
	}
	t.Setenv("DR_TEST_BOOL", "nope")
	if GetEnvBool("DR_TEST_BOOL") {
		t.Errorf("GetEnvBool(nope) = true, want false")
	}
}

func TestGetEnvAsDuration(t *testing.T) {
	t.Setenv("DR_TEST_DUR", "90m")
	if got := GetEnvAsDuration("DR_TEST_DUR", time.Hour); got != 90*time.Minute {
		t.Errorf("GetEnvAsDuration = %v, want 90m", got)
	}
	if got := GetEnvAsDuration("DR_TEST_DUR_UNSET", time.Hour); got != time.Hour {
		t.Errorf("GetEnvAsDuration(unset) = %v, want 1h", got)
	}
}

func TestSendAPIKey_PlaceholderTreatedAsUnset(t *testing.T) {
	t.Setenv("SEND_API_KEY", sendAPIKeyPlaceholder)
	if got := SendAPIKey(); got != "" {
		t.Errorf("placeholder key should be treated as unset, got %q", got)
	}
	t.Setenv("SEND_API_KEY", "re_realkey")
	if got := SendAPIKey(); got != "re_realkey" {
		t.Errorf("real key = %q, want re_realkey", got)
	}
}

func TestDefaults(t *testing.T) {
	if DatabaseURL() == "" {
		t.Error("DatabaseURL should have a default")
	}
	if GCPProjectID() != "thingzio" {
		t.Errorf("GCPProjectID default = %q, want thingzio", GCPProjectID())
	}
	if SBOMBucket() == "" {
		t.Error("SBOMBucket should have a default")
	}
}
