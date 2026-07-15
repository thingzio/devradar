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
