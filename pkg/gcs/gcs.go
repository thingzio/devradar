// Package gcs stores and retrieves SBOM bytes. It provides a GCS-backed store,
// a local-filesystem store for development/tests, and a FromEnv selector so the
// serve and scan binaries share one blob-store wiring.
package gcs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"

	"github.com/thingzio/devradar/pkg/config"
)

// Store reads and writes SBOM bytes. Both *Client (GCS) and LocalStore satisfy it.
type Store interface {
	Put(ctx context.Context, objectPath string, data []byte) error
	Fetch(ctx context.Context, objectPath string) ([]byte, error)
	Delete(ctx context.Context, objectPath string) error
	Close() error
}

// FromEnv returns the blob store selected by env: a local-filesystem store when
// DEVRADAR_LOCAL_SBOMS is set (dev — DEVRADAR_LOCAL_SBOM_DIR, default ./.sboms),
// otherwise GCS. Both the serve and scan binaries use this so a local run shares
// one on-disk store between submit (serve) and scan.
func FromEnv(ctx context.Context) (Store, error) {
	if config.GetEnvBool("DEVRADAR_LOCAL_SBOMS") {
		dir := config.GetEnv("DEVRADAR_LOCAL_SBOM_DIR", ".sboms")
		slog.Info("using local filesystem SBOM store", "dir", dir)
		return LocalStore{Dir: dir}, nil
	}
	return New(ctx)
}

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

// Fetch reads the object at a gs://bucket/key URI, bounded to config.MaxSBOMBytes
// so a corrupt or manually-replaced object can't exhaust scanner memory.
func (c *Client) Fetch(ctx context.Context, objectPath string) ([]byte, error) {
	bucket, key, err := parseGSURI(objectPath)
	if err != nil {
		return nil, err
	}
	r, err := c.sc.Bucket(bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", objectPath, err)
	}
	defer func() { _ = r.Close() }()
	b, err := readBounded(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", objectPath, err)
	}
	return b, nil
}

// readBounded reads at most config.MaxSBOMBytes from r, returning an error if
// the source exceeds the cap. It reads one byte past the limit to distinguish
// "exactly at the cap" (ok) from "over the cap" (rejected). This is the same
// bounded-read invariant ingest applies to untrusted HTTP bodies, enforced here
// at the storage trust boundary for objects that may predate the cap or have
// been replaced out of band.
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, config.MaxSBOMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > config.MaxSBOMBytes {
		return nil, fmt.Errorf("object exceeds %d-byte SBOM limit", config.MaxSBOMBytes)
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

// Delete removes exactly one object. Missing objects are already in the desired
// state and therefore succeed, making account-deletion retries idempotent.
func (c *Client) Delete(ctx context.Context, objectPath string) error {
	bucket, key, err := parseGSURI(objectPath)
	if err != nil {
		return err
	}
	if err := c.sc.Bucket(bucket).Object(key).Delete(ctx); err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil
		}
		return fmt.Errorf("delete %s: %w", objectPath, err)
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

// LocalStore reads and writes SBOM bytes under a base directory, keyed by a
// digest of the complete object URI. For development and tests only — pairs
// with the scan job's LocalFetcher so a full submit→scan loop runs without GCS.
type LocalStore struct{ Dir string }

// Put writes data to Dir/<sha256(objectPath)>.
func (l LocalStore) Put(_ context.Context, objectPath string, data []byte) error {
	p := l.pathFor(objectPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// Fetch reads back what Put wrote, bounded to config.MaxSBOMBytes (same
// invariant as the GCS path) so a manually-replaced local file can't blow up
// the scanner.
func (l LocalStore) Fetch(_ context.Context, objectPath string) ([]byte, error) {
	f, err := os.Open(l.pathFor(objectPath))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readBounded(f)
}

// Delete removes exactly one local object. A missing file is an idempotent
// success, matching the GCS implementation.
func (l LocalStore) Delete(_ context.Context, objectPath string) error {
	if err := os.Remove(l.pathFor(objectPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", objectPath, err)
	}
	return nil
}

// Close is a no-op; LocalStore holds no resources. Present so LocalStore
// satisfies the Store interface.
func (l LocalStore) Close() error { return nil }

func (l LocalStore) pathFor(objectPath string) string {
	digest := sha256.Sum256([]byte(objectPath))
	return filepath.Join(l.Dir, fmt.Sprintf("%x", digest))
}
