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

package attest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/attest"
)

func TestPolicyConfigured(t *testing.T) {
	if (attest.Policy{}).Configured() {
		t.Fatal("empty policy should not be configured")
	}
	if !(attest.Policy{Identities: []string{"id"}}).Configured() {
		t.Fatal("policy with an identity should be configured")
	}
	if !(attest.Policy{PublicKeys: [][]byte{[]byte("pem")}}).Configured() {
		t.Fatal("policy with a public key should be configured")
	}
}

func TestPolicyVersionStableAndOrderIndependent(t *testing.T) {
	a := attest.Policy{Identities: []string{"a", "b"}, Issuers: []string{"x"}}
	b := attest.Policy{Identities: []string{"b", "a"}, Issuers: []string{"x"}}
	if a.Version() != b.Version() {
		t.Fatalf("policy version should be order-independent: %s vs %s", a.Version(), b.Version())
	}
	c := attest.Policy{Identities: []string{"a", "b"}, Issuers: []string{"y"}}
	if a.Version() == c.Version() {
		t.Fatal("policy version should change when trust inputs change")
	}
	if a.Version() == (attest.Policy{}).Version() {
		t.Fatal("configured and empty policies should differ")
	}
	// RequireSBOMBytes changes the verification outcome, so it must change the hash.
	strict := attest.Policy{Identities: []string{"a", "b"}, Issuers: []string{"x"}, RequireSBOMBytes: true}
	if a.Version() == strict.Version() {
		t.Fatal("RequireSBOMBytes should change the policy version")
	}
}

func TestFakeVerifierPaths(t *testing.T) {
	ctx := context.Background()

	// Error path.
	ferr := &attest.Fake{Err: errors.New("boom")}
	if _, err := ferr.Verify(ctx, nil, "sha256:x", nil); err == nil {
		t.Fatal("expected error from fake")
	}

	// Success path fills in the requested digest and records inputs.
	fok := &attest.Fake{Result: &attest.Result{Outcome: attest.ResultVerified, Mode: attest.ModeKeyless}}
	res, err := fok.Verify(ctx, []byte("sbom"), "sha256:abc", []byte("bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if res.SubjectDigest != "sha256:abc" {
		t.Fatalf("fake should copy requested digest, got %q", res.SubjectDigest)
	}
	if fok.Calls != 1 || string(fok.LastBundle) != "bundle" || fok.LastDigest != "sha256:abc" {
		t.Fatalf("fake did not record inputs: %+v", fok)
	}
}
