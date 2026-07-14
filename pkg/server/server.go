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

	"github.com/thingzio/devradar/pkg/attest"
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
	store    *postgres.Store
	blobs    BlobStore
	email    drnet.Sender    // nil in dev → magic links are logged, not sent
	github   OAuthProvider   // nil when GitHub OAuth is not configured → button/routes hidden
	verifier attest.Verifier // nil when attestation verification is not configured → SBOMs stay 'unverified'
	opts     Options
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
// sign-in is disabled (no button, no routes). verifier may be nil, in which case
// submitted attestations are ignored and SBOMs remain 'unverified'.
func New(store *postgres.Store, blobs BlobStore, email drnet.Sender, github OAuthProvider, verifier attest.Verifier, opts Options) *Server {
	return &Server{store: store, blobs: blobs, email: email, github: github, verifier: verifier, opts: opts}
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

	// Magic-link email sender. Without a real SEND_API_KEY the link would be
	// logged instead of sent — acceptable locally, but in production that writes
	// replayable sign-in URLs to the logs, so refuse to start unless dev mode is
	// explicitly enabled.
	var email drnet.Sender
	if key := config.SendAPIKey(); key != "" {
		email = drnet.ResendSender{APIKey: key, From: config.EmailFrom()}
	} else if config.DevMode() {
		slog.Warn("dev mode: SEND_API_KEY not set; magic-link URLs will be logged, not emailed")
	} else {
		return fmt.Errorf("SEND_API_KEY is not configured and DEVRADAR_DEV_MODE is not set: " +
			"refusing to start in production with magic links logged instead of emailed")
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

	// Attestation verification. Opt-in: without any identity/key in the
	// environment the verifier is nil, submitted attestations are ignored, and
	// SBOMs stay 'unverified'. But once an operator HAS opted in
	// (AttestConfigured), a broken trust policy — an unreadable key/root file, a
	// keyless identity with no issuer — is FATAL at startup. Silently disabling
	// verification the operator asked for would leave them believing attestations
	// are enforced when they are not; fail closed instead (mirrors the SEND_API_KEY
	// prod guard above). Verification failures at request time are still
	// best-effort and never block ingest — this guard is only about a trust policy
	// that cannot be assembled at all.
	var verifier attest.Verifier
	if config.AttestConfigured() {
		policy, err := config.AttestPolicy()
		if err != nil {
			return fmt.Errorf("attestation verification is configured but its trust "+
				"material is unusable: %w", err)
		}
		v, err := attest.New(policy)
		if err != nil {
			return fmt.Errorf("attestation verification is configured but the trust "+
				"policy is invalid: %w", err)
		}
		if !v.Available() {
			return fmt.Errorf("attestation verification is configured but produced no " +
				"usable verifier (no trusted root and TUF disabled?)")
		}
		verifier = v
		slog.Info("attestation verification enabled")
	} else {
		slog.Info("attestation verification not configured; SBOMs remain unverified")
	}

	return New(store, blobs, email, github, verifier, opts).Serve(ctx)
}

// Handler builds the routed, middleware-wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	db := s.store.DB()

	// Liveness (unauthenticated): cheap "the process is up" check. Never touches
	// dependencies, so a slow/broken DB can't wedge the liveness signal and cause
	// needless restarts.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Readiness (unauthenticated): verifies the process can actually serve — it
	// pings Postgres with a short timeout. This is the Cloud Run startup probe
	// target, so an instance is not routed traffic until its DB is reachable.
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			slog.Warn("readiness check failed", "error", err)
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Ingest + read API — API-token auth.
	apiToken := middleware.RequireAPIToken(s.store)
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
	s.registerUI(mux)

	return middleware.RequestID(recoverPanics(securityHeaders(mux)))
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
					"method", r.Method, "request_id", middleware.RequestIDFromContext(r.Context()),
					"stack", string(debug.Stack()))
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

func logMutationDenied(r *http.Request, action, reason string) {
	slog.Warn("mutation denied", "action", action, "reason", reason,
		"path", r.URL.Path, "request_id", middleware.RequestIDFromContext(r.Context()))
}

func logMutationFailure(r *http.Request, action, accountID, targetID string, err error) {
	slog.Error("mutation failed", "action", action, "account_id", accountID,
		"target_id", targetID, "path", r.URL.Path,
		"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
}

// Compile-time assertions that the concrete implementations satisfy the seams.
var (
	_ BlobStore     = (*gcs.Client)(nil)
	_ OAuthProvider = (*oauth.GitHub)(nil)
)
