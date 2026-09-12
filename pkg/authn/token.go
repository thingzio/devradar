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

// Package authn provides authentication token primitives.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// NewToken returns prefix followed by 256 bits of cryptographic randomness.
func NewToken(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + hex.EncodeToString(random), nil
}

// HashToken returns the lowercase hexadecimal SHA-256 digest of raw.
func HashToken(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// NormalizeEmail trims surrounding whitespace and lowercases email.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
