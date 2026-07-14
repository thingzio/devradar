package net

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResendSenderUsesIdempotencyKeyAndReturnsReceipt(t *testing.T) {
	var gotAuthorization, gotIdempotency, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotIdempotency = r.Header.Get("Idempotency-Key")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"provider-message-id"}`)
	}))
	defer srv.Close()

	message := Message{
		To: "recipient@example.com", Subject: "subject", HTML: "<p>body</p>", Text: "body",
		IdempotencyKey: "account-invitation/invitation-id/2",
	}
	receipt, err := sendEmailTo(context.Background(), srv.Client(), srv.URL,
		"re_test_secret", "DevRadar <no-reply@example.com>", message)
	if err != nil {
		t.Fatalf("sendEmailTo: %v", err)
	}
	if receipt.ID != "provider-message-id" {
		t.Fatalf("receipt ID = %q", receipt.ID)
	}
	if gotAuthorization != "Bearer re_test_secret" || gotIdempotency != message.IdempotencyKey {
		t.Fatalf("headers authorization=%q idempotency=%q", gotAuthorization, gotIdempotency)
	}
	if !strings.Contains(gotBody, `"to":["recipient@example.com"]`) {
		t.Fatalf("request body missing recipient: %s", gotBody)
	}
}

func TestResendSenderRejectsSuccessWithoutProviderID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":""}`)
	}))
	defer srv.Close()

	_, err := sendEmailTo(context.Background(), srv.Client(), srv.URL, "re_secret", "from@example.com",
		Message{To: "to@example.com", Subject: "s", Text: "body", IdempotencyKey: "key"})
	if err == nil || strings.Contains(err.Error(), "re_secret") || strings.Contains(err.Error(), "to@example.com") {
		t.Fatalf("missing-ID error = %v", err)
	}
}

func TestResendSenderValidatesProviderReceiptID(t *testing.T) {
	tests := []struct {
		name, id, want string
		valid          bool
	}{
		{name: "canonical", id: " 49a8c67d-3f1b-4ec2_a.1 ", want: "49a8c67d-3f1b-4ec2_a.1", valid: true},
		{name: "whitespace", id: "   "},
		{name: "newline", id: "provider\r\nid"},
		{name: "control", id: "provider\x01id"},
		{name: "unicode", id: "provider-界"},
		{name: "oversized", id: strings.Repeat("a", 257)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"id": tt.id})
			}))
			defer srv.Close()
			receipt, err := sendEmailTo(context.Background(), srv.Client(), srv.URL, "re_secret", "from@example.com",
				Message{To: "to@example.com", Subject: "s", Text: "body", IdempotencyKey: "key"})
			if tt.valid {
				if err != nil || receipt.ID != tt.want {
					t.Fatalf("receipt = %#v, %v, want %q", receipt, err, tt.want)
				}
				return
			}
			if err == nil || strings.Contains(err.Error(), tt.id) {
				t.Fatalf("invalid provider ID returned receipt=%#v error=%v", receipt, err)
			}
		})
	}
}

func TestProviderErrorClassificationAndScrubbing(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		transient bool
		permanent bool
	}{
		{name: "rate limit", status: http.StatusTooManyRequests, body: `{"name":"rate_limit_exceeded","message":"later"}`, transient: true},
		{name: "server", status: http.StatusBadGateway, body: `{"name":"internal_server_error","message":"later"}`, transient: true},
		{name: "last server status", status: 599, body: `{"name":"internal_server_error","message":"later"}`, transient: true},
		{name: "outside HTTP status", status: 600, body: `{"name":"internal_server_error","message":"later"}`},
		{name: "concurrent idempotency", status: http.StatusConflict, body: `{"name":"concurrent_idempotent_requests","message":"later"}`, transient: true},
		{name: "idempotency mismatch", status: http.StatusConflict, body: `{"name":"idempotency_key_already_exists","message":"different payload"}`, permanent: true},
		{name: "invalid recipient", status: http.StatusUnprocessableEntity, body: `{"name":"validation_error","message":"recipient is invalid"}`, permanent: true},
		{name: "auth", status: http.StatusUnauthorized, body: `{"name":"authentication_error","message":"bad key"}`, permanent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const apiKey = "re_super_secret"
			const recipient = "private-recipient@example.com"
			const reflectedToken = "token=dr_raw_invitation_secret"
			body := strings.ReplaceAll(tt.body, "later", apiKey+" "+recipient+" aUtHoRiZaTiOn: BeArEr "+apiKey+" "+reflectedToken)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				body = strings.Replace(body, `"}`, strings.Repeat("x", 8192)+`"}`, 1)
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()

			_, err := sendEmailTo(context.Background(), srv.Client(), srv.URL, apiKey, "from@example.com",
				Message{To: recipient, Subject: "s", Text: "body", IdempotencyKey: "key"})
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) {
				t.Fatalf("error type = %T, want *ProviderError: %v", err, err)
			}
			if IsTransientProviderError(err) != tt.transient || IsPermanentProviderError(err) != tt.permanent {
				t.Fatalf("classification transient=%v permanent=%v", IsTransientProviderError(err), IsPermanentProviderError(err))
			}
			if providerErr.StatusCode != tt.status || providerErr.Name == "" {
				t.Fatalf("provider error = %#v", providerErr)
			}
			if strings.Contains(err.Error(), apiKey) || strings.Contains(err.Error(), recipient) ||
				strings.Contains(err.Error(), reflectedToken) ||
				strings.Contains(strings.ToLower(err.Error()), "authorization: bearer") || len(providerErr.Message) > 512 {
				t.Fatalf("provider error was not scrubbed/bounded: %q", err)
			}
		})
	}
}

func TestResendSenderPreservesContextErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sendEmailTo(ctx, http.DefaultClient, "http://127.0.0.1:1", "re_secret", "from@example.com",
		Message{To: "to@example.com", Subject: "s", Text: "body", IdempotencyKey: "key"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestProviderErrorNameDoesNotExposeReflectedSecrets(t *testing.T) {
	for _, secret := range []string{"re_super_secret", "rawinvitationtoken123"} {
		t.Run(secret, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"name":"`+secret+`","message":"ignored"}`)
			}))
			defer srv.Close()
			_, err := sendEmailTo(context.Background(), srv.Client(), srv.URL, "re_super_secret", "from@example.com",
				Message{To: "to@example.com", Subject: "s", Text: "body", IdempotencyKey: "key"})
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Name != "provider_error" || strings.Contains(err.Error(), secret) {
				t.Fatalf("reflected-name error = %#v, %v", providerErr, err)
			}
		})
	}
}
