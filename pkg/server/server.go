// Package server is DevRadar's HTTP surface: the SBOM ingest API, the
// tenant-scoped read API, a minimal GitHub-OAuth UI for minting API tokens, and
// health. It uses the stdlib ServeMux with method patterns (no third-party
// router), matching the sibling services.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/middleware"
)

// Options configures the server.
type Options struct {
	Version string
	Commit  string
	Date    string
}

// Server holds handler dependencies.
type Server struct {
	store  *postgres.Store
	blobs  BlobStore
	oauth  *OAuthConfig
	opts   Options
	tokens int64 // reserved for future rate limiting
}

// BlobStore persists and retrieves raw SBOM bytes (GCS in production).
type BlobStore interface {
	Put(ctx context.Context, objectPath string, data []byte) error
}

// New builds a Server.
func New(store *postgres.Store, blobs BlobStore, oauth *OAuthConfig, opts Options) *Server {
	return &Server{store: store, blobs: blobs, oauth: oauth, opts: opts}
}

// Handler builds the routed, middleware-wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	db := s.store.DB()

	// Health (unauthenticated; Cloud Run startup probe).
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Ingest + read API — API-token auth.
	apiToken := middleware.RequireAPIToken(db)
	mux.Handle("POST /v1/sboms", apiToken(http.HandlerFunc(s.handleSubmitSBOM)))
	mux.Handle("GET /v1/images", apiToken(http.HandlerFunc(s.handleListImages)))
	mux.Handle("GET /v1/sboms/{id}/findings", apiToken(http.HandlerFunc(s.handleFindings)))
	mux.Handle("GET /v1/sboms/{id}/events", apiToken(http.HandlerFunc(s.handleEvents)))

	// Minimal UI + OAuth (session auth) for minting API tokens.
	s.registerUI(mux, db)

	return recoverPanics(securityHeaders(mux))
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down
// gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              ":" + config.GetEnv("PORT", "8080"),
		Handler:           s.Handler(),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(),
			time.Duration(config.GetEnvAsInt("SERVER_SHUTDOWN_TIMEOUT_SEC", 5))*time.Second)
		defer cancel()
		slog.Info("shutting down http server")
		return srv.Shutdown(shutdownCtx)
	}
}

// ── shared middleware & helpers ───────────────────────────────────────────────

func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				slog.Error("handler panic", "panic", rec, "path", r.URL.Path,
					"method", r.Method, "stack", string(debug.Stack()))
				http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if middleware.SessionCookieName() == "__Host-session" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Compile-time assertion that the GCS client satisfies BlobStore.
var _ BlobStore = (*gcs.Client)(nil)
