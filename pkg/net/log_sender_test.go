package net

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogSenderLogsInvitationAndReturnsDeterministicReceipt(t *testing.T) {
	var output strings.Builder
	sender := LogSender{Logger: slog.New(slog.NewTextHandler(&output, nil))}
	message := Message{
		To:             "invitee@example.com",
		Subject:        "You have been invited to DevRadar",
		Text:           "Open https://devradar.example/invitations/raw-token",
		IdempotencyKey: "account-invitation/invitation-id/1",
	}
	first, err := sender.Send(context.Background(), message)
	if err != nil {
		t.Fatalf("first Send: %v", err)
	}
	second, err := sender.Send(context.Background(), message)
	if err != nil {
		t.Fatalf("second Send: %v", err)
	}
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("receipts = %q, %q, want equal nonempty IDs", first.ID, second.ID)
	}
	logged := output.String()
	if !strings.Contains(logged, message.To) || !strings.Contains(logged, "https://devradar.example/invitations/raw-token") {
		t.Fatalf("log output = %q, want recipient and link", logged)
	}
}

func TestLogSenderHonorsCancellationAndValidatesMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (LogSender{}).Send(ctx, Message{To: "invitee@example.com"}); err == nil {
		t.Fatal("canceled invalid send succeeded")
	}
}
