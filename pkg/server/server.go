// Package server is DevRadar's HTTP surface: the SBOM ingest API, the
// tenant-scoped read API, a minimal passwordless (magic-link) UI for minting API
// tokens, and health. It uses the stdlib ServeMux with method patterns (no
// third-party router), matching the sibling services.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/middleware"
	drnet "github.com/thingzio/devradar/pkg/net"
	"github.com/thingzio/devradar/pkg/oauth"
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
	email  drnet.Sender  // nil in dev → magic links are logged, not sent
	github OAuthProvider // nil when GitHub OAuth is not configured → button/routes hidden
	opts   Options
}

// BlobStore persists and retrieves raw SBOM bytes (GCS in production).
type BlobStore interface {
	Put(ctx context.Context, objectPath string, data []byte) error
}

// OAuthProvider turns an OAuth authorization code into a proven identity. The
// interface is the test seam: production wires *oauth.GitHub; tests inject a fake
// that returns a canned identity or ErrNoVerifiedEmail without any network.
type OAuthProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth.Identity, error)
}

// New builds a Server. email may be nil (development), in which case magic-link
// URLs are logged instead of emailed. github may be nil, in which case GitHub
// sign-in is disabled (no button, no routes).
func New(store *postgres.Store, blobs BlobStore, email drnet.Sender, github OAuthProvider, opts Options) *Server {
	return &Server{store: store, blobs: blobs, email: email, github: github, opts: opts}
}

// Run is the entry point for the serve binary: it wires the store, blob store,
// and email sender from the environment, then serves until ctx is cancelled.
// cmd/devradar-serve is a thin shell around this.
func Run(ctx context.Context, opts Options) error {
	if err := config.Validate(); err != nil {
		return err
	}
	store, err := postgres.New(ctx, config.DatabaseURL(), postgres.DefaultPoolConfig())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = store.Close() }()

	blobs, err := gcs.FromEnv(ctx)
	if err != nil {
		return fmt.Errorf("blob store: %w", err)
	}
	defer func() { _ = blobs.Close() }()

	// Magic-link email sender. Without SEND_API_KEY the link is logged, not sent.
	var email drnet.Sender
	if key := config.SendAPIKey(); key != "" {
		email = drnet.ResendSender{APIKey: key, From: config.EmailFrom()}
	} else {
		slog.Warn("SEND_API_KEY not set; magic-link URLs will be logged, not emailed")
	}

	// GitHub OAuth sign-in. Optional: without both client id and secret the UI
	// falls back to email-only sign-in (no button, no routes).
	var github OAuthProvider
	if config.GitHubOAuthConfigured() {
		github = oauth.NewGitHub(config.GitHubClientID(), config.GitHubClientSecret(),
			config.GitHubOAuthRedirectURL())
	} else {
		slog.Info("GitHub OAuth not configured; email-only sign-in")
	}

	return New(store, blobs, email, github, opts).Serve(ctx)
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
	mux.Handle("GET /v1/images/timeline", apiToken(http.HandlerFunc(s.handleTimeline)))
	mux.Handle("GET /v1/images/sboms", apiToken(http.HandlerFunc(s.handleImageSBOMs)))
	mux.Handle("GET /v1/sboms/{id}", apiToken(http.HandlerFunc(s.handleGetSBOM)))
	mux.Handle("DELETE /v1/sboms/{id}", apiToken(http.HandlerFunc(s.handleArchiveSBOM)))
	mux.Handle("GET /v1/sboms/{id}/findings", apiToken(http.HandlerFunc(s.handleFindings)))
	mux.Handle("GET /v1/sboms/{id}/events", apiToken(http.HandlerFunc(s.handleEvents)))
	mux.Handle("GET /v1/sboms/{id}/failures", apiToken(http.HandlerFunc(s.handleFailures)))
	mux.Handle("GET /v1/sboms/{id}/licenses", apiToken(http.HandlerFunc(s.handleSBOMLicenses)))
	mux.Handle("GET /v1/licenses", apiToken(http.HandlerFunc(s.handleFleetLicenses)))
	mux.Handle("POST /v1/vex", apiToken(http.HandlerFunc(s.handleSubmitVEX)))
	mux.Handle("GET /v1/vex", apiToken(http.HandlerFunc(s.handleListVEX)))

	// Minimal passwordless UI (session auth) for minting API tokens.
	s.registerUI(mux, db)

	return recoverPanics(securityHeaders(mux))
}

// Serve starts the HTTP server and blocks until ctx is cancelled, then shuts
// down gracefully.
func (s *Server) Serve(ctx context.Context) error {
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
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
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
		// Defense-in-depth behind html/template escaping. Scripts are first-party
		// only (one external app.js — no inline script). Styles allow 'unsafe-inline'
		// for the small number of inline style= attributes; charts are inline SVG
		// markup (not affected by CSP). No plugins, no framing, no <base> hijack.
		// img-src also allows GitHub's avatar CDN so OAuth profile pictures render.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https://avatars.githubusercontent.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
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

// Compile-time assertions that the concrete implementations satisfy the seams.
var (
	_ BlobStore     = (*gcs.Client)(nil)
	_ OAuthProvider = (*oauth.GitHub)(nil)
)
