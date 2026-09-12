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

package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestShouldCompensateSBOMActivation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "inactive", err: postgres.ErrAccountInactive, want: true},
		{name: "wrapped inactive", err: fmt.Errorf("activate: %w", postgres.ErrAccountInactive), want: true},
		{name: "missing", err: postgres.ErrNotFound, want: true},
		{name: "wrapped missing", err: fmt.Errorf("activate: %w", postgres.ErrNotFound), want: true},
		{name: "commit outcome unknown", err: errors.New("commit audited SBOM activation: connection reset")},
		{name: "wrapped SQL error", err: fmt.Errorf("activate: %w", errors.New("database unavailable"))},
		{name: "context cancellation", err: fmt.Errorf("activate: %w", context.Canceled)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldCompensateSBOMActivation(tc.err); got != tc.want {
				t.Fatalf("shouldCompensateSBOMActivation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
