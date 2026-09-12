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

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAttestConfigured_OptInByEnvPresence(t *testing.T) {
	// Not configured: nothing set.
	if AttestConfigured() {
		t.Fatal("no identities/keys → should not be configured")
	}

	// Identities present → configured (even before material is validated), so a
	// misconfiguration surfaces at startup instead of silently disabling.
	t.Setenv("DEVRADAR_ATTEST_IDENTITIES", "https://github.com/acme/ci")
	if !AttestConfigured() {
		t.Fatal("identities set → should be configured")
	}

	// Hard-disable overrides presence.
	t.Setenv("DEVRADAR_ATTEST", "false")
	if AttestConfigured() {
		t.Fatal("DEVRADAR_ATTEST=false must disable regardless of identities")
	}
}

func TestAttestPolicy_UnreadableKeyPathErrors(t *testing.T) {
	// A4 regression: a configured-but-unreadable public-key path must ERROR, not
	// be silently skipped (which would leave an operator believing verification is
	// enforced when it is not).
	t.Setenv("DEVRADAR_ATTEST_PUBLIC_KEYS", filepath.Join(t.TempDir(), "does-not-exist.pem"))
	_, err := AttestPolicy()
	if err == nil {
		t.Fatal("unreadable key path must return an error")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Fatalf("error should name the public key, got: %v", err)
	}
}

func TestAttestPolicy_UnreadableTrustedRootErrors(t *testing.T) {
	t.Setenv("DEVRADAR_ATTEST_TRUSTED_ROOT", filepath.Join(t.TempDir(), "missing-root.json"))
	_, err := AttestPolicy()
	if err == nil {
		t.Fatal("unreadable trusted-root path must return an error")
	}
	if !strings.Contains(err.Error(), "trusted root") {
		t.Fatalf("error should name the trusted root, got: %v", err)
	}
}

func TestAttestPolicy_CleanWhenPathsReadable(t *testing.T) {
	// Identities + issuers, no file paths → policy assembles without error.
	t.Setenv("DEVRADAR_ATTEST_IDENTITIES", "https://github.com/acme/ci")
	t.Setenv("DEVRADAR_ATTEST_ISSUERS", "https://token.actions.githubusercontent.com")
	p, err := AttestPolicy()
	if err != nil {
		t.Fatalf("readable/absent paths should not error: %v", err)
	}
	if len(p.Identities) != 1 || len(p.Issuers) != 1 {
		t.Fatalf("policy did not carry identities/issuers: %+v", p)
	}
}
