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
	"encoding/base64"
	"encoding/json"
	"time"
)

// defaultPageLimit / maxPageLimit bound every paginated list endpoint. A caller
// may ask for fewer; anything outside (0, maxPageLimit] snaps to the default.
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// keysetCursor is an opaque continuation token for keyset (seek) pagination. It
// carries the ordering key of the last row returned — a timestamp plus a unique
// tiebreaker id — so the next page seeks past it with a (ts, id) row comparison
// rather than OFFSET (which degrades and can skip/duplicate rows under writes).
type keysetCursor struct {
	TS time.Time `json:"t,omitzero"`
	ID string    `json:"i"`
}

// encodeCursor returns an opaque base64 token for a time-keyed list, or "" when
// there is no next page.
func encodeCursor(ts time.Time, id string) string {
	b, err := json.Marshal(keysetCursor{TS: ts.UTC(), ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses a token from encodeCursor. ok is false for an empty string
// (first page) or a malformed token (treated as first page, never an error).
func decodeCursor(s string) (c keysetCursor, ok bool) {
	if s == "" {
		return keysetCursor{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return keysetCursor{}, false
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return keysetCursor{}, false
	}
	return c, true
}

// clampLimit normalizes a requested page size and asks for one extra row so the
// caller can tell whether a further page exists without a second COUNT query.
func clampLimit(limit int) (effective, fetch int) {
	if limit <= 0 || limit > maxPageLimit {
		limit = defaultPageLimit
	}
	return limit, limit + 1
}
