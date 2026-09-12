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

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// DefaultPredicateTypes are the in-toto predicate types DevRadar accepts as SBOM
// attestations when a tenant does not configure their own allow-list.
var DefaultPredicateTypes = []string{
	"https://cyclonedx.org/bom",
	"https://spdx.dev/Document",
}

// Policy is the trust configuration a verification is evaluated against. An empty
// Policy (no identities and no public keys) means verification cannot be
// performed — New returns a nil Client so callers skip the feature.
type Policy struct {
	// Identities is the allow-list of Fulcio certificate SAN identities accepted
	// for keyless verification (exact match).
	Identities []string
	// Issuers is the allow-list of OIDC issuers accepted for keyless verification.
	Issuers []string
	// PublicKeys are PEM-encoded cosign public keys accepted for key verification.
	PublicKeys [][]byte
	// PredicateTypes is the allow-list of accepted in-toto predicate types.
	// Empty means DefaultPredicateTypes.
	PredicateTypes []string
	// TrustedRoot is a sigstore trusted-root JSON document. When empty, the
	// verifier may fall back to the public sigstore TUF root if TUF is enabled.
	TrustedRoot []byte
	// TUFEnabled allows fetching the public sigstore trust root via TUF when no
	// TrustedRoot is provided. Off by default to keep ingest network-free.
	TUFEnabled bool
	// RequireSBOMBytes, when true, only accepts the strong sbom-bytes binding (the
	// attestation signed the exact stored SBOM bytes) and rejects the weaker
	// image-digest fallback. Off by default: image-digest binding matches common
	// `cosign attest` image flows.
	RequireSBOMBytes bool
}

// Configured reports whether the policy has enough material to verify anything.
func (p Policy) Configured() bool {
	return len(p.Identities) > 0 || len(p.PublicKeys) > 0
}

// predicateTypes returns the effective accepted predicate-type set.
func (p Policy) predicateTypes() []string {
	if len(p.PredicateTypes) == 0 {
		return DefaultPredicateTypes
	}
	return p.PredicateTypes
}

// Version is a stable hash of the policy's trust-relevant inputs. It is recorded
// on every verification result so a stored decision can be compared against the
// current policy (e.g. to decide whether a user-triggered re-verification would
// differ). Order-independent for the list inputs.
func (p Policy) Version() string {
	var buf []byte
	buf = appendSorted(buf, p.Identities)
	buf = appendSorted(buf, p.Issuers)
	buf = appendSorted(buf, p.predicateTypes())
	keys := make([]string, len(p.PublicKeys))
	for i, k := range p.PublicKeys {
		keys[i] = string(k)
	}
	buf = appendSorted(buf, keys)
	if p.TUFEnabled {
		buf = append(buf, "tuf\x00"...)
	}
	if p.RequireSBOMBytes {
		buf = append(buf, "require-sbom-bytes\x00"...)
	}
	// The trusted root affects verification outcome; fold in a digest of it.
	if len(p.TrustedRoot) > 0 {
		rootSum := sha256.Sum256(p.TrustedRoot)
		buf = append(buf, rootSum[:]...)
	}
	sum := sha256.Sum256(buf)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// appendSorted appends an order-independent, NUL-delimited encoding of vals to
// buf, followed by a field separator, so the policy hash is stable regardless of
// slice order.
func appendSorted(buf []byte, vals []string) []byte {
	cp := append([]string(nil), vals...)
	sort.Strings(cp)
	for _, v := range cp {
		buf = append(buf, v...)
		buf = append(buf, 0)
	}
	return append(buf, '\x1e') // record separator between fields
}

// allowsPredicate reports whether a predicate type is accepted by the policy.
func (p Policy) allowsPredicate(predicateType string) bool {
	for _, s := range p.predicateTypes() {
		if strings.EqualFold(s, predicateType) {
			return true
		}
	}
	return false
}
