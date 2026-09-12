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

package gcs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/thingzio/devradar/pkg/config"
	"google.golang.org/api/option"
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

func TestLocalStoreDeleteIsExactAndIdempotent(t *testing.T) {
	ls := LocalStore{Dir: t.TempDir()}
	ctx := context.Background()
	target := "gs://bucket/account/target"
	foreign := "gs://bucket/account/foreign"
	for _, path := range []string{target, foreign} {
		if err := ls.Put(ctx, path, []byte(path)); err != nil {
			t.Fatalf("put %s: %v", path, err)
		}
	}
	if err := ls.Delete(ctx, target); err != nil {
		t.Fatalf("delete target: %v", err)
	}
	if err := ls.Delete(ctx, target); err != nil {
		t.Fatalf("repeat delete target: %v", err)
	}
	if _, err := ls.Fetch(ctx, target); err == nil {
		t.Fatal("deleted local object remains readable")
	}
	if got, err := ls.Fetch(ctx, foreign); err != nil || string(got) != foreign {
		t.Fatalf("foreign local object = %q, %v", got, err)
	}
}

func TestLocalStoreObjectURIsDoNotCollide(t *testing.T) {
	ls := LocalStore{Dir: t.TempDir()}
	ctx := context.Background()
	nested := "gs://bucket/a/b"
	flat := "gs://bucket/a_b"

	if err := ls.Put(ctx, nested, []byte("nested")); err != nil {
		t.Fatalf("put nested object: %v", err)
	}
	if err := ls.Put(ctx, flat, []byte("flat")); err != nil {
		t.Fatalf("put flat object: %v", err)
	}
	if err := ls.Delete(ctx, nested); err != nil {
		t.Fatalf("delete nested object: %v", err)
	}
	if _, err := ls.Fetch(ctx, nested); err == nil {
		t.Fatal("deleted nested object remains readable")
	}
	got, err := ls.Fetch(ctx, flat)
	if err != nil {
		t.Fatalf("fetch flat object: %v", err)
	}
	if string(got) != "flat" {
		t.Fatalf("flat object = %q, want flat", got)
	}
}

func TestClientDeleteIsExactAndMissingIsSuccess(t *testing.T) {
	ctx := context.Background()
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		if len(requests) == 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"message":"not found"}}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sc, err := storage.NewClient(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("new storage client: %v", err)
	}
	defer func() { _ = sc.Close() }()
	client := &Client{sc: sc}
	path := "gs://exact-bucket/account/object.json"
	if err := client.Delete(ctx, path); err != nil {
		t.Fatalf("delete GCS object: %v", err)
	}
	if err := client.Delete(ctx, path); err != nil {
		t.Fatalf("delete missing GCS object: %v", err)
	}
	wantSuffix := "/b/" + url.PathEscape("exact-bucket") + "/o/" + url.PathEscape("account/object.json")
	if len(requests) != 2 || !slices.Equal(requests, []string{
		"DELETE " + wantSuffix,
		"DELETE " + wantSuffix,
	}) {
		t.Fatalf("GCS delete requests = %q, want exact object twice", requests)
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
