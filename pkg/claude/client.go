// Package claude is a minimal, nil-safe client for the Anthropic Messages API.
// It is hand-rolled (no SDK dependency) to keep DevRadar's module lean and to
// match the sibling services' pattern. Claude is always optional: New returns
// nil when no API key is configured, and every method is nil-safe so callers
// degrade gracefully (the feature is skipped, never fatal). Haiku is the default
// model — these are short, batch-style completions, not interactive chat.
package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseURL   = "https://api.anthropic.com/v1"
	defaultModel     = "claude-haiku-4-5"
	anthropicVersion = "2023-06-01"
	maxResponseBytes = 1 << 16 // 64KB — responses here are short summaries
)

// Client wraps the Anthropic Messages API. Nil-safe: a nil *Client's methods
// return ("", nil) so an unconfigured deployment simply omits AI output.
type Client struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

// New builds a client from the environment: DEVRADAR_ANTHROPIC_API_KEY (service
// tunable) then ANTHROPIC_API_KEY (shared platform secret). Returns nil if
// neither is set, so callers can `if c := claude.New(); c != nil { ... }`.
func New() *Client {
	key := os.Getenv("DEVRADAR_ANTHROPIC_API_KEY")
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}
	if key == "" {
		return nil
	}

	model := os.Getenv("DEVRADAR_ANTHROPIC_MODEL")
	if model == "" {
		model = os.Getenv("ANTHROPIC_MODEL")
	}
	if model == "" {
		model = defaultModel
	}

	baseURL := os.Getenv("ANTHROPIC_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return &Client{
		apiKey:  key,
		model:   model,
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Available reports whether a usable client is configured (nil-safe).
func (c *Client) Available() bool { return c != nil && c.apiKey != "" }

// Summarize sends a system prompt + user content and returns the model's text.
// A nil client returns ("", nil) so the caller can skip the feature silently.
func (c *Client) Summarize(ctx context.Context, system, content string, maxTokens int) (string, error) {
	if !c.Available() {
		return "", nil
	}
	return c.complete(ctx, system, content, maxTokens)
}

// messagesRequest / messagesResponse mirror the minimal Messages API shapes.
type messagesRequest struct {
	Model    string          `json:"model"`
	MaxToks  int             `json:"max_tokens"`
	System   string          `json:"system"`
	Messages []messagesEntry `json:"messages"`
}

type messagesEntry struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (c *Client) complete(ctx context.Context, system, userMessage string, maxTokens int) (string, error) {
	bodyJSON, err := json.Marshal(messagesRequest{
		Model:    c.model,
		MaxToks:  maxTokens,
		System:   system,
		Messages: []messagesEntry{{Role: "user", Content: userMessage}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/messages", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api error: status %d: %s", resp.StatusCode, string(respBody))
	}

	var result messagesResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response content")
	}
	return result.Content[0].Text, nil
}
