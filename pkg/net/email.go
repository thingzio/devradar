// Package net sends transactional email via the Resend HTTP API (no SDK),
// matching the DevPulse/DevTrace platform pattern. v1 uses it for magic-link
// sign-in; later, for finding alerts. The API key is the shared SEND_API_KEY
// secret.
package net

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	resendAPIURL     = "https://api.resend.com/emails"
	emailSendTimeout = 30 * time.Second
)

var emailClient = &http.Client{Timeout: emailSendTimeout}

// Sender sends transactional email. The interface lets handlers depend on a
// seam (real Resend, a dev logger, or a test fake) rather than a concrete client.
type Sender interface {
	Send(ctx context.Context, to, subject, html, text string) error
}

// ResendSender sends via the Resend API.
type ResendSender struct {
	APIKey string
	From   string // e.g. "DevRadar <no-reply@thingz.io>"
}

// Send delivers one email.
func (s ResendSender) Send(ctx context.Context, to, subject, html, text string) error {
	return sendEmailTo(ctx, resendAPIURL, s.APIKey, s.From, to, subject, html, text)
}

// sendEmailTo is the inner implementation, parameterized on the URL so tests can
// point at an httptest server.
func sendEmailTo(ctx context.Context, apiURL, apiKey, from, to, subject, html, text string) error {
	payload := map[string]any{
		"from":    from,
		"to":      []string{to},
		"subject": subject,
		"html":    html,
		"text":    text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := emailClient.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	msg := string(rb)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Errorf("email API returned %d: %s", resp.StatusCode, msg)
}
