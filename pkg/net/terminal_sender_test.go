// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const terminalInvitationLink = "https://devradar.example/account-invitations/invitation-id#token=raw-token"

func TestTerminalSenderWritesInvitationWithoutLoggingBearer(t *testing.T) {
	var terminal strings.Builder
	var logs strings.Builder
	sender := TerminalSender{
		Writer: &terminal,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	message := Message{
		To:             "invitee@example.com",
		Subject:        "You have been invited to DevRadar",
		Text:           "Open " + terminalInvitationLink,
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
	if got := terminal.String(); strings.Count(got, terminalInvitationLink) != 2 {
		t.Fatalf("terminal output = %q, want exact invitation link twice", got)
	}
	logged := logs.String()
	if !strings.Contains(logged, message.To) || !strings.Contains(logged, message.IdempotencyKey) {
		t.Fatalf("log output = %q, want safe delivery metadata", logged)
	}
	if strings.Contains(logged, "raw-token") || strings.Contains(logged, terminalInvitationLink) {
		t.Fatalf("log output exposed invitation bearer: %q", logged)
	}
}

func TestTerminalSenderFailsClosedWithSanitizedError(t *testing.T) {
	const reflectedSecret = "provider-text-raw-token"
	var logs strings.Builder
	sender := TerminalSender{
		Writer: errorWriter{err: errors.New(reflectedSecret)},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	message := Message{
		To:             "invitee@example.com",
		Subject:        "You have been invited to DevRadar",
		Text:           "Open " + terminalInvitationLink,
		IdempotencyKey: "account-invitation/invitation-id/1",
	}

	_, err := sender.Send(context.Background(), message)
	if !errors.Is(err, ErrTerminalDelivery) {
		t.Fatalf("Send error = %v, want ErrTerminalDelivery", err)
	}
	if strings.Contains(err.Error(), reflectedSecret) || strings.Contains(err.Error(), "raw-token") {
		t.Fatalf("Send error exposed terminal failure details: %v", err)
	}
	if strings.Contains(logs.String(), reflectedSecret) || strings.Contains(logs.String(), "raw-token") {
		t.Fatalf("log output exposed terminal failure details: %q", logs.String())
	}
}

func TestTerminalSenderRequiresWriterAndHonorsCancellation(t *testing.T) {
	message := Message{
		To:             "invitee@example.com",
		Subject:        "You have been invited to DevRadar",
		Text:           "Open " + terminalInvitationLink,
		IdempotencyKey: "account-invitation/invitation-id/1",
	}
	if _, err := (TerminalSender{}).Send(context.Background(), message); !errors.Is(err, ErrTerminalDelivery) {
		t.Fatalf("nil writer error = %v, want ErrTerminalDelivery", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (TerminalSender{Writer: &strings.Builder{}}).Send(ctx, message); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Send error = %v, want context canceled", err)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
