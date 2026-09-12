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

package authn_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/authn"
)

func TestNewToken(t *testing.T) {
	raw, err := authn.NewToken("dr_")
	if err != nil || !strings.HasPrefix(raw, "dr_") || len(raw) != 67 {
		t.Fatalf("NewToken() = %q, %v", raw, err)
	}
	if authn.HashToken(raw) == raw {
		t.Fatal("hash must not equal raw token")
	}
	suffix := strings.TrimPrefix(raw, "dr_")
	decoded, err := hex.DecodeString(suffix)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("token suffix = %q, decoded length = %d, err = %v", suffix, len(decoded), err)
	}
	if canonical := hex.EncodeToString(decoded); suffix != canonical {
		t.Fatalf("token suffix = %q, want canonical lowercase hex %q", suffix, canonical)
	}
}

func TestHashToken(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := authn.HashToken("abc"); got != want {
		t.Fatalf("HashToken() = %q, want %q", got, want)
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got, want := authn.NormalizeEmail("  Person@Example.COM\t"), "person@example.com"; got != want {
		t.Fatalf("NormalizeEmail() = %q, want %q", got, want)
	}
}
