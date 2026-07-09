package claude

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew_NilWithoutKey verifies New returns nil when no API key is set, so the
// feature degrades to absent rather than erroring.
func TestNew_NilWithoutKey(t *testing.T) {
	t.Setenv("DEVRADAR_ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if c := New(); c != nil {
		t.Fatalf("New() = %v, want nil with no key", c)
	}
}

// TestNilClient_Safe verifies a nil client's methods are safe and no-op.
func TestNilClient_Safe(t *testing.T) {
	var c *Client
	if c.Available() {
		t.Error("nil client should not be Available()")
	}
	out, err := c.Summarize(context.Background(), "sys", "content", 128)
	if err != nil || out != "" {
		t.Errorf("nil Summarize() = (%q, %v), want (\"\", nil)", out, err)
	}
}

// TestSummarize_RoundTrip drives Summarize against a stub Anthropic endpoint,
// asserting the request shape and that the response text is returned.
func TestSummarize_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "k" {
			t.Errorf("x-api-key = %q, want k", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"text":"all nominal"}]}`))
	}))
	defer srv.Close()

	c := &Client{apiKey: "k", model: defaultModel, baseURL: srv.URL, http: srv.Client()}
	out, err := c.Summarize(context.Background(), "sys", "metrics", 256)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if out != "all nominal" {
		t.Errorf("Summarize = %q, want %q", out, "all nominal")
	}
}

// TestSummarize_APIError surfaces a non-200 as an error (not silent empty).
func TestSummarize_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	c := &Client{apiKey: "k", model: defaultModel, baseURL: srv.URL, http: srv.Client()}
	if _, err := c.Summarize(context.Background(), "sys", "x", 128); err == nil {
		t.Error("expected error on 429, got nil")
	}
}
