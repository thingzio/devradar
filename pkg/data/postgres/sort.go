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
	"fmt"
)

// Server-side sorting composed with keyset pagination.
//
// The hard part is that keyset pagination and arbitrary sort must agree: the
// cursor has to carry the active sort column's value, and the seek predicate has
// to compare on that same column + direction. We solve it generically:
//
//   - Each sortable column is a sortCol with a SQL expression (COALESCE'd so it
//     is never NULL — NULL keyset is a correctness minefield) and a cast type.
//   - ORDER BY is always "<expr> <dir>, <tiebreak> <dir>" (tiebreak is a unique
//     id; it shares the primary direction so a single row-comparison works).
//   - The seek predicate is "(<expr>, <tiebreak>) <op> ($val::<cast>, $id)" where
//     op is '<' for DESC, '>' for ASC.
//   - The cursor stores the sort value as text (selected via <expr>::text so it
//     round-trips) plus the tiebreak id.

type sortCol struct {
	expr    string // SQL expression, COALESCE'd to be non-null
	cast    string // cursor value cast: "double precision" | "text" | "timestamptz"
	defDesc bool   // natural default direction when this column is selected
}

// sortSpec is the resolved sort for a request.
type sortSpec struct {
	key  string  // chosen column key (echoed back to the UI)
	col  sortCol // chosen column
	desc bool    // effective direction
}

// resolveSort picks a sort column from a whitelist. An unknown/empty key falls
// back to defKey. dir ("asc"/"desc"/"") overrides the column's natural default.
func resolveSort(key, dir string, cols map[string]sortCol, defKey string) sortSpec {
	c, ok := cols[key]
	if !ok {
		key = defKey
		c = cols[defKey]
	}
	desc := c.defDesc
	switch dir {
	case "asc":
		desc = false
	case "desc":
		desc = true
	}
	return sortSpec{key: key, col: c, desc: desc}
}

// orderBy renders "<expr> DIR, <tiebreak> DIR".
func (s sortSpec) orderBy(tiebreak string) string {
	d := "ASC"
	if s.desc {
		d = "DESC"
	}
	return fmt.Sprintf("%s %s, %s %s", s.col.expr, d, tiebreak, d)
}

// seek renders the keyset predicate and returns it plus the two args (sort value
// cast + tiebreak id) to append. valPos/idPos are the $-positions to use.
func (s sortSpec) seek(tiebreak string, valPos, idPos int) string {
	op := ">"
	if s.desc {
		op = "<"
	}
	return fmt.Sprintf("(%s, %s) %s ($%d::%s, $%d)", s.col.expr, tiebreak, op, valPos, s.col.cast, idPos)
}

// selectVal renders "<expr>::text AS sortval" so the sort value round-trips into
// the cursor regardless of the column's native type.
func (s sortSpec) selectVal() string {
	return s.col.expr + "::text AS sortval"
}

// sortCursor carries a text-encoded sort value + the unique tiebreaker.
type sortCursor struct {
	Val string `json:"v"`
	ID  string `json:"i"`
}

func encodeSortCursor(val, id string) string {
	b, err := json.Marshal(sortCursor{Val: val, ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSortCursor(s string) (c sortCursor, ok bool) {
	if s == "" {
		return sortCursor{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return sortCursor{}, false
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return sortCursor{}, false
	}
	return c, true
}
