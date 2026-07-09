package middleware

import (
	"testing"
)

// TestIsAdmin covers the email allowlist: case-insensitive membership, trimming,
// and the empty-env "nobody is admin" default.
func TestIsAdmin(t *testing.T) {
	t.Setenv("DEVRADAR_ADMIN_USERS", " Admin@Example.com , ops@thingz.io ")

	cases := []struct {
		email string
		want  bool
	}{
		{"admin@example.com", true},   // case-insensitive match
		{"ADMIN@EXAMPLE.COM", true},   // caller casing ignored
		{"ops@thingz.io", true},       // trimmed entry
		{"nobody@example.com", false}, // not listed
		{"", false},                   // empty email
		{"admin@example.com ", true},  // caller whitespace trimmed
	}
	for _, c := range cases {
		if got := IsAdmin(c.email); got != c.want {
			t.Errorf("IsAdmin(%q) = %v, want %v", c.email, got, c.want)
		}
	}
}

// TestIsAdmin_EmptyEnv verifies that with no allowlist configured, nobody is an
// admin (the whole /admin surface then 404s).
func TestIsAdmin_EmptyEnv(t *testing.T) {
	t.Setenv("DEVRADAR_ADMIN_USERS", "")
	if IsAdmin("anyone@example.com") {
		t.Error("with no DEVRADAR_ADMIN_USERS set, IsAdmin must be false")
	}
}
