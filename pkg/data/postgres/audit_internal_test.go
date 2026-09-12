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

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAuditRepositoryTargetPreservesOnlyValidRawValues(t *testing.T) {
	valid := "registry.test/team/app"
	if got := auditRepositoryTarget(valid); got != valid {
		t.Fatalf("valid repository target = %q, want raw %q", got, valid)
	}

	for _, repository := range []string{
		"", " leading", "trailing ", strings.Repeat("界", maxAuditTargetIDChars+1),
	} {
		sum := sha256.Sum256([]byte(repository))
		want := "sha256:" + hex.EncodeToString(sum[:])
		if got := auditRepositoryTarget(repository); got != want {
			t.Fatalf("invalid repository target for %q = %q, want %q", repository, got, want)
		}
	}
}
