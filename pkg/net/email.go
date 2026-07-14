// Package net sends transactional email via the Resend HTTP API (no SDK),
// matching the DevPulse/DevTrace platform pattern. v1 uses it for magic-link
// sign-in; later, for finding alerts. The API key is the shared SEND_API_KEY
// secret.
package net

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	resendAPIURL     = "https://api.resend.com/emails"
	emailSendTimeout = 30 * time.Second
	maxEmailPayload  = 512 << 10
	maxResponseBody  = 16 << 10
)

var emailClient = &http.Client{Timeout: emailSendTimeout}
var providerReceiptIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

var providerErrorNames = map[string]struct{}{
	"application_error":              {},
	"authentication_error":           {},
	"concurrent_idempotent_requests": {},
	"idempotency_key_already_exists": {},
	"internal_server_error":          {},
	"invalid_access":                 {},
	"invalid_api_key":                {},
	"invalid_idempotency_key":        {},
	"invalid_parameter":              {},
	"invalid_recipient":              {},
	"invalid_region":                 {},
	"method_not_allowed":             {},
	"missing_api_key":                {},
	"missing_required_field":         {},
	"not_found":                      {},
	"payload_mismatch":               {},
	"rate_limit_exceeded":            {},
	"restricted_api_key":             {},
	"validation_error":               {},
}

// Message is one transactional email. IdempotencyKey must be stable for the
// logical delivery and contains no recipient secret.
type Message struct {
	To             string
	Subject        string
	HTML           string
	Text           string
	IdempotencyKey string
}

// Receipt identifies the provider-side delivery request.
type Receipt struct {
	ID string
}

// Sender sends transactional email. The interface lets handlers depend on a
// seam (real Resend, a dev logger, or a test fake) rather than a concrete client.
type Sender interface {
	Send(context.Context, Message) (Receipt, error)
}

// LogSender is the explicit development-only sender. It logs the recipient and
// invitation link while preserving the production sender's validation and
// deterministic idempotency semantics.
type LogSender struct {
	Logger *slog.Logger
}

// Send logs one local delivery and returns a stable receipt derived from the
// non-secret idempotency key.
func (s LogSender) Send(ctx context.Context, message Message) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := validateMessage(message); err != nil {
		return Receipt{}, err
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("dev mode: email not sent", "recipient", message.To, "link", firstMessageURL(message))
	digest := sha256.Sum256([]byte(message.IdempotencyKey))
	return Receipt{ID: fmt.Sprintf("local-%x", digest[:12])}, nil
}

func firstMessageURL(message Message) string {
	for _, field := range strings.Fields(message.Text + " " + message.HTML) {
		field = strings.Trim(field, `"'<>(),`)
		if strings.HasPrefix(field, "https://") || strings.HasPrefix(field, "http://") {
			return strings.TrimSuffix(field, `</a></p>`)
		}
	}
	return ""
}

// ResendSender sends via the Resend API.
type ResendSender struct {
	APIKey string
	From   string // e.g. "DevRadar <no-reply@thingz.io>"
}

// Send delivers one email.
func (s ResendSender) Send(ctx context.Context, message Message) (Receipt, error) {
	return sendEmailTo(ctx, emailClient, resendAPIURL, s.APIKey, s.From, message)
}

// sendEmailTo is the inner implementation, parameterized on the URL so tests can
// point at an httptest server.
func sendEmailTo(ctx context.Context, client *http.Client, apiURL, apiKey, from string, message Message) (Receipt, error) {
	if err := validateMessage(message); err != nil {
		return Receipt{}, err
	}
	payload := map[string]any{
		"from":    from,
		"to":      []string{message.To},
		"subject": message.Subject,
		"html":    message.HTML,
		"text":    message.Text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Receipt{}, fmt.Errorf("marshal email payload: %w", err)
	}
	if len(body) > maxEmailPayload {
		return Receipt{}, fmt.Errorf("email payload exceeds %d bytes", maxEmailPayload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("create email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", message.IdempotencyKey)

	resp, err := client.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("send email request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if readErr != nil {
		return Receipt{}, fmt.Errorf("read email provider response: %w", readErr)
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		var response struct {
			ID string `json:"id"`
		}
		if len(rb) > maxResponseBody || json.Unmarshal(rb, &response) != nil {
			return Receipt{}, fmt.Errorf("email provider returned success without a message ID")
		}
		response.ID = strings.TrimSpace(response.ID)
		if !providerReceiptIDRE.MatchString(response.ID) {
			return Receipt{}, fmt.Errorf("email provider returned an invalid message ID")
		}
		return Receipt{ID: response.ID}, nil
	}

	var response struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(rb, &response)
	name := strings.TrimSpace(response.Name)
	if _, recognized := providerErrorNames[name]; !recognized {
		name = "provider_error"
	}
	// Provider messages are attacker-controlled and may reflect the submitted
	// HTML/text, including raw magic-link or invitation tokens. Expose only a
	// fixed message; status and allowlisted error name retain classification.
	return Receipt{}, &ProviderError{StatusCode: resp.StatusCode, Name: name, Message: "provider request failed"}
}

// ProviderError is a bounded, credential-scrubbed Resend API failure.
type ProviderError struct {
	StatusCode int
	Name       string
	Message    string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("email provider returned %d %s: %s", e.StatusCode, e.Name, e.Message)
}

// IsTransientProviderError reports failures safe to retry with the same
// idempotency key.
func IsTransientProviderError(err error) bool {
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) {
		return false
	}
	return providerErr.StatusCode == http.StatusTooManyRequests ||
		providerErr.StatusCode == http.StatusRequestTimeout ||
		providerErr.StatusCode == http.StatusTooEarly ||
		(providerErr.StatusCode >= 500 && providerErr.StatusCode <= 599) ||
		(providerErr.StatusCode == http.StatusConflict && providerErr.Name == "concurrent_idempotent_requests")
}

// IsPermanentProviderError reports provider failures that retry cannot repair.
func IsPermanentProviderError(err error) bool {
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || IsTransientProviderError(err) {
		return false
	}
	return providerErr.StatusCode >= 400 && providerErr.StatusCode < 500
}

// IsPermanentSenderError reports failures that cannot succeed when retried
// unchanged, including provider 4xx responses and locally invalid messages.
func IsPermanentSenderError(err error) bool {
	var invalid *invalidMessageError
	return IsPermanentProviderError(err) || errors.As(err, &invalid)
}

type invalidMessageError struct {
	message string
}

func (e *invalidMessageError) Error() string { return e.message }

func validateMessage(message Message) error {
	var err error
	switch {
	case strings.TrimSpace(message.To) == "":
		err = fmt.Errorf("email recipient is required")
	case len(message.To) > 320:
		err = fmt.Errorf("email recipient exceeds 320 bytes")
	case strings.TrimSpace(message.Subject) == "":
		err = fmt.Errorf("email subject is required")
	case len(message.Subject) > 998:
		err = fmt.Errorf("email subject exceeds 998 bytes")
	case message.HTML == "" && message.Text == "":
		err = fmt.Errorf("email body is required")
	case strings.TrimSpace(message.IdempotencyKey) == "":
		err = fmt.Errorf("email idempotency key is required")
	case len(message.IdempotencyKey) > 256:
		err = fmt.Errorf("email idempotency key exceeds 256 bytes")
	}
	if err != nil {
		return &invalidMessageError{message: err.Error()}
	}
	return nil
}
