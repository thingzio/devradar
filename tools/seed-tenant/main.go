// Command seed-tenant creates a local test tenant and prints an API token, for
// exercising the ingest/read API without the GitHub OAuth UI. Development only.
package main

import (
	"context"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/tenant"
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

	db := store.DB()
	tn, err := tenant.UpsertTenantByEmail(ctx, db, "dev@example.com")
	if err != nil {
		return fmt.Errorf("upsert tenant: %w", err)
	}
	token, err := tenant.CreateAPIToken(ctx, db, tn.ID, "local-dev")
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}

	fmt.Printf("Tenant ID: %s\n", tn.ID)
	fmt.Printf("Email:     %s\n", tn.Email)
	fmt.Printf("API Token: %s\n\n", token)
	fmt.Println("Export it for the curl examples in the README:")
	fmt.Printf("  export DR_TOKEN=%s\n", token)
	return nil
}
