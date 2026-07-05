// Package gcs provides SBOM byte retrieval for the scan job. It implements
// scan.Fetcher over Google Cloud Storage, plus a local-filesystem fetcher for
// development and tests.
package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
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

// LocalFetcher reads SBOM bytes from the local filesystem. object_path is
// treated as a file path. For development and tests only.
type LocalFetcher struct{}

// Fetch reads the file at objectPath.
func (LocalFetcher) Fetch(_ context.Context, objectPath string) ([]byte, error) {
	return os.ReadFile(objectPath)
}
