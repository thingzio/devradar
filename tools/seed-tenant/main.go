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

// Command seed-tenant creates a local test tenant and prints an API token, for
// exercising the ingest/read API without the GitHub OAuth UI. Development only.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	store, err := postgres.NewFromEnv(ctx) // runs migrations
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = store.Close() }()

	user, acct, err := store.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
		Provider: "magiclink", Subject: "dev@example.com", Email: "dev@example.com",
	})
	if err != nil {
		return fmt.Errorf("resolve local identity: %w", err)
	}
	if acct == nil {
		return fmt.Errorf("resolve local identity: no active account")
	}
	session, err := store.CreateSession(ctx, user.ID, &acct.ID, time.Hour)
	if err != nil {
		return fmt.Errorf("create local session: %w", err)
	}
	defer func() { _ = store.DestroySession(ctx, session) }()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate local token flash key: %w", err)
	}
	requestID, err := authn.NewToken("")
	if err != nil {
		return fmt.Errorf("generate local request id: %w", err)
	}
	compensationRequestID, err := authn.NewToken("")
	if err != nil {
		return fmt.Errorf("generate local compensation request id: %w", err)
	}
	tokenID, err := store.CreateAPIToken(ctx, acct.ID, user.ID, authn.HashToken(session),
		"local-dev", 0, 0, requestID, key)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	token, err := store.ConsumeTokenFlash(ctx, authn.HashToken(session), acct.ID, key)
	if err != nil {
		revokeErr := store.RevokeAPIToken(ctx, acct.ID, tokenID,
			account.Actor{Kind: account.ActorUser, UserID: user.ID}, compensationRequestID)
		if revokeErr != nil {
			revokeErr = fmt.Errorf("compensate token creation: %w", revokeErr)
		}
		return errors.Join(fmt.Errorf("consume token flash: %w", err), revokeErr)
	}

	fmt.Printf("Account ID: %s\n", acct.ID)
	fmt.Printf("User email: %s\n", user.Email)
	fmt.Printf("API Token: %s\n\n", token)
	fmt.Println("Export it for the curl examples in the README:")
	fmt.Printf("  export DR_TOKEN=%s\n", token)
	return nil
}
