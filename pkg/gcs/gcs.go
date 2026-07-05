// Package gcs provides SBOM byte retrieval for the scan job. It implements
// scan.Fetcher over Google Cloud Storage, plus a local-filesystem fetcher for
// development and tests.
package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
)

// Client fetches objects from GCS. object paths are full gs:// URIs
// (gs://bucket/key), matching devradar_sbom.object_path.
type Client struct {
	sc *storage.Client
}

// New creates a GCS client using application default credentials.
func New(ctx context.Context) (*Client, error) {
	sc, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs client: %w", err)
	}
	return &Client{sc: sc}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error { return c.sc.Close() }

// Fetch reads the object at a gs://bucket/key URI.
func (c *Client) Fetch(ctx context.Context, objectPath string) ([]byte, error) {
	bucket, key, err := parseGSURI(objectPath)
	if err != nil {
		return nil, err
	}
	r, err := c.sc.Bucket(bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", objectPath, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", objectPath, err)
	}
	return b, nil
}

// Put writes data to a gs://bucket/key URI. Used by the ingest API to store the
// raw SBOM bytes it is handed. Content-addressed writes are effectively
// idempotent (same id → same object), so an overwrite is harmless.
func (c *Client) Put(ctx context.Context, objectPath string, data []byte) error {
	bucket, key, err := parseGSURI(objectPath)
	if err != nil {
		return err
	}
	w := c.sc.Bucket(bucket).Object(key).NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return fmt.Errorf("write %s: %w", objectPath, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close %s: %w", objectPath, err)
	}
	return nil
}

func parseGSURI(uri string) (bucket, key string, err error) {
	rest, ok := strings.CutPrefix(uri, "gs://")
	if !ok {
		return "", "", fmt.Errorf("not a gs:// uri: %q", uri)
	}
	bucket, key, ok = strings.Cut(rest, "/")
	if !ok || bucket == "" || key == "" {
		return "", "", fmt.Errorf("malformed gs:// uri: %q", uri)
	}
	return bucket, key, nil
}

// LocalStore reads and writes SBOM bytes under a base directory, keyed by the
// tail of the gs:// path. For development and tests only — pairs with the scan
// job's LocalFetcher so a full submit→scan loop runs without GCS.
type LocalStore struct{ Dir string }

// Put writes data to Dir/<sanitized objectPath>.
func (l LocalStore) Put(_ context.Context, objectPath string, data []byte) error {
	p := l.pathFor(objectPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// Fetch reads back what Put wrote.
func (l LocalStore) Fetch(_ context.Context, objectPath string) ([]byte, error) {
	return os.ReadFile(l.pathFor(objectPath))
}

func (l LocalStore) pathFor(objectPath string) string {
	safe := strings.NewReplacer("gs://", "", "/", "_", ":", "_").Replace(objectPath)
	return filepath.Join(l.Dir, safe)
}
