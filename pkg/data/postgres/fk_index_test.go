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

package postgres_test

import (
	"context"
	"fmt"
	"testing"
)

// TestForeignKeysHaveCoveringIndexes asserts every devradar foreign key has a
// child-side index whose LEADING column is the FK's first column. PostgreSQL
// indexes only the parent side of a FK, so an uncovered child column turns each
// parent delete or key update into a seq scan of the child while holding a lock
// on the parent row — the cost lands on account and user deletion, which cascade
// through most of this schema.
//
// The leading column is the whole rule: the FK check is
// `WHERE col1 = $1 [AND col2 = $2 ...]`, so an index that starts with col1
// already turns the scan into a lookup, and the remaining columns are a cheap
// filter over the matched rows. Migration 033 closed the 15 gaps a 2026-08-15
// schema review found; this test is what keeps the next table from reopening one.
func TestForeignKeysHaveCoveringIndexes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// conkey is 1-based (conkey[1] is the FK's first column); indkey is an
	// int2vector, so the cast to smallint[] keeps its 0-based lower bound and
	// (indkey)[0] is the index's leading column.
	//
	// A partial index only counts when its predicate is `col IS NOT NULL`: the
	// FK check never matches NULL, so the planner can prove that predicate and
	// use the index. Any other predicate makes the index unusable for the check.
	const q = `
SELECT c.conrelid::regclass::text, c.conname
FROM pg_constraint c
JOIN pg_class t ON t.oid = c.conrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
WHERE c.contype = 'f'
  AND n.nspname = current_schema()
  AND t.relname LIKE 'devradar\_%'
  AND NOT EXISTS (
      SELECT 1
      FROM pg_index i
      WHERE i.indrelid = c.conrelid
        AND i.indisvalid
        AND (i.indkey::smallint[])[0] = c.conkey[1]
        AND (
            i.indpred IS NULL
            OR pg_get_expr(i.indpred, i.indrelid) = format('(%I IS NOT NULL)', a.attname)
        )
  )
ORDER BY 1, 2`

	rows, err := st.DB().QueryContext(ctx, q)
	if err != nil {
		t.Fatalf("query uncovered foreign keys: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var uncovered []string
	for rows.Next() {
		var table, constraint string
		if err := rows.Scan(&table, &constraint); err != nil {
			t.Fatalf("scan: %v", err)
		}
		uncovered = append(uncovered, fmt.Sprintf("%s.%s", table, constraint))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	for _, fk := range uncovered {
		t.Errorf("foreign key has no covering index (add one to the newest migration): %s", fk)
	}
}
