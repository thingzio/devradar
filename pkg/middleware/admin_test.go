// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
