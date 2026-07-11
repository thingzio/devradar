package gcs

import (
	"context"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/config"
)

// TestLocalStore_RoundTrip: Put then Fetch returns the same bytes.
func TestLocalStore_RoundTrip(t *testing.T) {
	ls := LocalStore{Dir: t.TempDir()}
	ctx := context.Background()
	path := "gs://bucket/tenant/abc"
	want := []byte(`{"bomFormat":"CycloneDX"}`)

	if err := ls.Put(ctx, path, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := ls.Fetch(ctx, path)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("fetch = %q, want %q", got, want)
	}
}

// TestLocalStore_FetchBounded: an object larger than the SBOM cap is rejected
// rather than read into memory unbounded.
func TestLocalStore_FetchBounded(t *testing.T) {
	ls := LocalStore{Dir: t.TempDir()}
	ctx := context.Background()
	path := "gs://bucket/tenant/huge"

	// One byte over the cap.
	oversized := make([]byte, config.MaxSBOMBytes+1)
	if err := ls.Put(ctx, path, oversized); err != nil {
		t.Fatalf("put oversized: %v", err)
	}
	_, err := ls.Fetch(ctx, path)
	if err == nil {
		t.Fatal("expected Fetch to reject an over-cap object")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error %q should mention the size limit", err.Error())
	}
}

// TestLocalStore_FetchAtCap: an object exactly at the cap is accepted (boundary).
func TestLocalStore_FetchAtCap(t *testing.T) {
	ls := LocalStore{Dir: t.TempDir()}
	ctx := context.Background()
	path := "gs://bucket/tenant/atcap"

	atCap := make([]byte, config.MaxSBOMBytes)
	if err := ls.Put(ctx, path, atCap); err != nil {
		t.Fatalf("put at-cap: %v", err)
	}
	got, err := ls.Fetch(ctx, path)
	if err != nil {
		t.Fatalf("fetch at-cap should succeed: %v", err)
	}
	if len(got) != config.MaxSBOMBytes {
		t.Errorf("fetch at-cap len = %d, want %d", len(got), config.MaxSBOMBytes)
	}
}
