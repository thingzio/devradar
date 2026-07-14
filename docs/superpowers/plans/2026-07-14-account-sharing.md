# Account Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace person/account tenant conflation with multi-account users and admin/editor/reader memberships, then ship account invitations behind a disabled production feature flag.

**Architecture:** Keep each existing `devradar_tenant.id` as the account ID and preserve every existing account-scoped query, hash, and object path. Add distinct users, memberships, typed request access, transactional audit, personal alert receipts, a durable email outbox, and invitation acceptance through three forward migrations. Deployable slices preserve current single-account behavior until invitations are explicitly enabled.

**Tech Stack:** Go, stdlib `net/http`, `html/template`, `database/sql`, PostgreSQL/libpq, embedded SQL migrations, Resend HTTP API, Cloud Run Jobs, Cloud Scheduler, Terraform, GoReleaser/ko.

**Design:** `docs/superpowers/specs/2026-07-14-account-sharing-design.md`

## Global Constraints

- Work only in the local repository on `main`; make focused signed commits with `git commit -S`.
- Do not push, tag, deploy, run `terraform apply`, enable production sharing, or modify production state.
- Do not add sign-offs, co-author trailers, or generated-by text.
- Keep `DEVRADAR_ACCOUNT_SHARING_ENABLED=false` through implementation and owner testing.
- Preserve every existing tenant UUID as its account UUID; never recompute SBOM IDs or move GCS objects.
- Preserve explicit application-layer account filtering; do not add RLS.
- Keep all new SQL in `pkg/data/postgres`; domain packages contain no SQL.
- Treat membership, role, acceptance, and revocation as strongly consistent PostgreSQL transactions.
- Revalidate membership on every browser request; do not cache authorization.
- Keep API tokens account-scoped and admin-managed.
- Roles are exactly `admin`, `editor`, and `reader`; all admins are equal and the final admin cannot leave, be removed, or be demoted.
- Editors may upload VEX and archive SBOMs/repositories; readers have no shared-state mutations.
- Minimum severity, alert policy, license policy, account name, API tokens, and membership are admin-only.
- Alert read state is personal to each user.
- Invitations expire after seven days; accept one email per action; use limits of 20 attempts/account/hour, five attempts/recipient/hour, and a 60-second resend cooldown.
- Delivery runs every minute with a batch of 50, concurrency five, ten-second request deadlines, eight attempts, and a 23-hour retry horizon.
- Never store raw session, API, or invitation tokens; encrypt pending invitation delivery payloads with a dedicated 32-byte key.
- Never skip or disable tests. Use red-green-refactor and stop after three failed fix attempts to reassess.
- Rehearse migrations against `/Users/mchmarny/dev/thingz/db/thingz-20260714-020645.sql.gz` in isolated local databases.
- Final rollout remains blocked until the owner validates the complete workflow locally and explicitly approves further action.

Before running database-backed tasks, start the local database and define the test DSN:

```bash
make db-up
export DEV_DB='postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable'
```

---

## Planned File Structure

- `pkg/account/account.go`: pure user/account/membership/access/actor vocabulary and capability matrix.
- `pkg/authn/token.go`: pure email normalization, token generation, and hashing.
- `pkg/data/postgres/account.go`: account, user, membership, and reconciliation queries.
- `pkg/data/postgres/auth.go`: verified identity, login token, session, and active-account queries.
- `pkg/data/postgres/audit.go`: transactional audit event insertion and actor attribution.
- `pkg/data/postgres/delivery.go`: outbox leasing and delivery state transitions.
- `pkg/data/postgres/invitation.go`: invitation creation, rotation, acceptance, revocation, and membership activation.
- `pkg/secretbox/secretbox.go`: AES-256-GCM sealing/opening shared by token flash and invitation delivery.
- `pkg/delivery/delivery.go`: bounded delivery worker and retry classification.
- `cmd/devradar-deliver/main.go`: thin delivery-job entrypoint.
- `pkg/middleware/auth.go`: user, account, API-token, and capability middleware plus typed context accessors.
- `pkg/server/routes.go`: centralized browser route-to-capability declarations.
- `pkg/server/view.go`: shared authenticated chrome data derived from typed access.
- `pkg/server/ui_accounts.go`: account list, selection, settings, members, leave, and role management.
- `pkg/server/ui_invitations.go`: invitation management and public confirmation/acceptance.
- `030_account_identity.sql`: user/account/membership expansion and legacy backfill.
- `031_account_state_audit.sql`: audit, personal alert receipts, and session-scoped token flash.
- `032_account_invitations.sql`: invitation and encrypted delivery outbox.

## Phase A: Identity and Authorization Foundation

### Task 1: Add Account Domain Types and Token Primitives

**Files:**
- Create: `pkg/account/account.go`
- Create: `pkg/account/account_test.go`
- Create: `pkg/authn/token.go`
- Create: `pkg/authn/token_test.go`

**Interfaces:**
- Produces: `account.Role`, `account.Capability`, `account.User`, `account.Account`, `account.Membership`, `account.Access`, `account.Actor`, `account.VerifiedIdentity`, `authn.NormalizeEmail`, `authn.HashToken`, and `authn.NewToken`.

- [ ] **Step 1: Write failing capability and token tests**

```go
func TestRoleCapabilities(t *testing.T) {
	tests := []struct {
		role account.Role
		cap  account.Capability
		want bool
	}{
		{account.RoleAdmin, account.ManageMembers, true},
		{account.RoleEditor, account.WriteEvidence, true},
		{account.RoleEditor, account.ManageSettings, false},
		{account.RoleReader, account.ReadAccount, true},
		{account.RoleReader, account.WriteEvidence, false},
	}
	for _, tt := range tests {
		if got := tt.role.Can(tt.cap); got != tt.want {
			t.Fatalf("%s.Can(%s) = %v, want %v", tt.role, tt.cap, got, tt.want)
		}
	}
}

func TestNewToken(t *testing.T) {
	raw, err := authn.NewToken("dr_")
	if err != nil || !strings.HasPrefix(raw, "dr_") || len(raw) != 67 {
		t.Fatalf("NewToken() = %q, %v", raw, err)
	}
	if authn.HashToken(raw) == raw {
		t.Fatal("hash must not equal raw token")
	}
}
```

- [ ] **Step 2: Run the tests and verify the missing packages fail**

Run: `go test ./pkg/account ./pkg/authn`

Expected: FAIL because the packages do not exist.

- [ ] **Step 3: Implement the exact domain vocabulary**

```go
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleReader Role = "reader"
)

type Capability string

const (
	ReadAccount       Capability = "account.read"
	WritePersonal     Capability = "personal.write"
	WriteEvidence     Capability = "evidence.write"
	ManageSettings    Capability = "settings.manage"
	ManageCredentials Capability = "credentials.manage"
	ManageMembers     Capability = "members.manage"
)

func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleEditor || r == RoleReader
}

func (r Role) Can(c Capability) bool {
	switch r {
	case RoleAdmin:
		return c == ReadAccount || c == WritePersonal || c == WriteEvidence ||
			c == ManageSettings || c == ManageCredentials || c == ManageMembers
	case RoleEditor:
		return c == ReadAccount || c == WritePersonal || c == WriteEvidence
	case RoleReader:
		return c == ReadAccount || c == WritePersonal
	default:
		return false
	}
}
```

Define concrete structs with string UUID fields and timestamps matching the design. `Access` contains `Actor User`, `Account Account`, and `Membership Membership`; `Access.Can` delegates to `Membership.Role.Can`. `Actor` contains `Kind`, `UserID`, and `APITokenID`. `VerifiedIdentity` contains `Provider`, `Subject`, `Email`, and `AvatarURL`.

Implement `authn.NewToken(prefix)` with 32 random bytes encoded as lowercase hex, `HashToken` with SHA-256 hex, and `NormalizeEmail` as lowercase trimmed text.

- [ ] **Step 4: Run focused tests**

Run: `go test -race ./pkg/account ./pkg/authn`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/account pkg/authn
git commit -S -m "feat: add account authorization domain"
```

### Task 2: Add the User, Account, and Membership Expansion Migration

**Files:**
- Create: `pkg/data/postgres/sql/migrations/030_account_identity.sql`
- Create: `pkg/data/postgres/account.go`
- Create: `pkg/data/postgres/account_migration_test.go`
- Modify: `pkg/data/postgres/admin_product_health_test.go`

**Interfaces:**
- Consumes: account types from Task 1.
- Produces: `Store.GetAccount`, `Store.GetUser`, `Store.ListUserAccounts`, `Store.GetAccess`, `Store.ReconcileLegacyAccount`, and `Store.ReconcileLegacyAccounts`.

- [ ] **Step 1: Write failing migration and isolation tests**

Test these exact invariants in an isolated schema:

```go
func TestAccountIdentityMigrationBackfill(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	legacyID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")

	var accountID, userID, role string
	err := st.DB().QueryRow(`
		SELECT m.account_id, m.user_id, m.role
		FROM devradar_account_member m
		JOIN devradar_user u ON u.id=m.user_id
		WHERE u.legacy_tenant_id=$1`, legacyID).Scan(&accountID, &userID, &role)
	if err != nil || accountID != legacyID || userID == legacyID || role != "admin" {
		t.Fatalf("backfill = %s %s %s, err=%v", accountID, userID, role, err)
	}
}
```

Also test two accounts with identical display names remain isolated, identities and live sessions receive the correct `user_id`, and account/member foreign-key cascades do not delete a user who remains in another account.

- [ ] **Step 2: Run the migration tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test ./pkg/data/postgres -run 'TestAccountIdentityMigration|TestAccountStore' -count=1 -v`

Expected: FAIL because migration 030 and account store methods do not exist.

- [ ] **Step 3: Add migration 030**

The migration must create `devradar_user`, add `devradar_tenant.name`, create `devradar_account_member`, add nullable `user_id` to identities/sessions, add nullable `active_account_id` to sessions, and add nullable `created_by_user_id` to API tokens. Use these core constraints:

```sql
CREATE TABLE devradar_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE CHECK (email = lower(btrim(email))),
    email_verified_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    avatar_url TEXT,
    tos_accepted_at TIMESTAMPTZ,
    legacy_tenant_id UUID UNIQUE REFERENCES devradar_tenant(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE devradar_tenant ADD COLUMN name TEXT NOT NULL DEFAULT '';
UPDATE devradar_tenant SET name=left(email,80) WHERE name='';

CREATE TABLE devradar_account_member (
    account_id UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES devradar_user(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin','editor','reader')),
    created_by_user_id UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_by_user_id UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,user_id)
);

ALTER TABLE devradar_identity
    ADD COLUMN user_id UUID REFERENCES devradar_user(id) ON DELETE CASCADE,
    ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE devradar_session
    ADD COLUMN user_id UUID REFERENCES devradar_user(id) ON DELETE CASCADE,
    ADD COLUMN active_account_id UUID REFERENCES devradar_tenant(id) ON DELETE SET NULL,
    ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE devradar_api_token
    ADD COLUMN created_by_user_id UUID REFERENCES devradar_user(id) ON DELETE SET NULL;

INSERT INTO devradar_user
    (email,email_verified_at,status,avatar_url,tos_accepted_at,legacy_tenant_id,created_at,updated_at)
SELECT lower(btrim(email)),email_verified_at,'active',avatar_url,tos_accepted_at,id,created_at,updated_at
FROM devradar_tenant
ON CONFLICT (legacy_tenant_id) DO NOTHING;

INSERT INTO devradar_account_member (account_id,user_id,role,accepted_at)
SELECT t.id,u.id,'admin',COALESCE(t.email_verified_at,t.created_at)
FROM devradar_tenant t JOIN devradar_user u ON u.legacy_tenant_id=t.id
ON CONFLICT (account_id,user_id) DO NOTHING;

UPDATE devradar_identity i SET user_id=u.id
FROM devradar_user u WHERE u.legacy_tenant_id=i.tenant_id AND i.user_id IS NULL;
UPDATE devradar_session s SET user_id=u.id,active_account_id=s.tenant_id
FROM devradar_user u WHERE u.legacy_tenant_id=s.tenant_id AND s.user_id IS NULL;
```

Backfill one distinct user and admin membership per tenant; update identity/session user IDs through `legacy_tenant_id`; initialize each live session's active account to its tenant. Add active membership indexes by `(user_id, account_id)` and `(account_id, role)`.

Drop `NOT NULL` from compatibility `devradar_identity.tenant_id` and `devradar_session.tenant_id`: an invitation-created user has no personal account, and a multi-account session may be at the chooser. Old revisions continue inserting non-null values. New sessions dual-write `tenant_id=active_account_id` when an account is selected.

- [ ] **Step 4: Implement account store methods**

Use `devradar_tenant` as the physical account table. Every account method accepts `accountID` first. `GetAccess(ctx,userID,accountID)` must join user, tenant, and an unrevoked membership and return `postgres.ErrNotFound` for any missing/inactive relationship.

`ReconcileLegacyAccount` must run one transaction, lock the tenant row, insert the missing user using `legacy_tenant_id`, insert the admin membership idempotently, fill missing identity/session user IDs, and fill an empty account name. `ReconcileLegacyAccounts` selects every tenant lacking the mapping and invokes the single-account method in stable ID order.

- [ ] **Step 5: Run migration and store tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres -run 'TestAccountIdentityMigration|TestAccountStore|TestMigrate_Idempotent' -count=1 -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/data/postgres/sql/migrations/030_account_identity.sql pkg/data/postgres/account.go pkg/data/postgres/account_migration_test.go pkg/data/postgres/admin_product_health_test.go
git commit -S -m "feat: add account identity schema"
```

### Task 3: Move Verified Identity and Session Resolution into PostgreSQL Store

**Files:**
- Create: `pkg/data/postgres/auth.go`
- Create: `pkg/data/postgres/auth_test.go`
- Modify: `pkg/account/account.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/oauth_test.go`
- Modify: `pkg/server/auth_test.go`
- Modify: `pkg/server/server_test.go`
- Modify: `pkg/data/postgres/housekeeping.go`
- Modify: `pkg/data/postgres/housekeeping_test.go`

**Interfaces:**
- Consumes: `account.VerifiedIdentity`, account store methods, authn token primitives.
- Produces:
  - `Store.ResolveDirectIdentity(ctx, identity) (*account.User, *account.Account, error)`
  - `Store.CreateLoginToken(ctx, email, ttl) (string, error)`
  - `Store.PeekLoginToken(ctx, raw) (string, error)`
  - `Store.ConsumeLoginToken(ctx, raw) (account.VerifiedIdentity, error)`
  - `Store.CreateSession(ctx, userID string, activeAccountID *string, ttl time.Duration) (string, error)`
  - `Store.ValidateSession(ctx, raw) (*account.Session, error)`
  - `Store.SelectSessionAccount(ctx, raw, userID, accountID string) error`
  - `Store.DestroySession(ctx, raw) error`

- [ ] **Step 1: Write failing direct-signup and multi-account session tests**

Cover these cases:

```go
func TestResolveDirectIdentityCreatesOneAccount(t *testing.T) {
	st := testStore(t)
	id := account.VerifiedIdentity{Provider: "magiclink", Subject: "new@example.com", Email: "new@example.com"}
	user, acct, err := st.ResolveDirectIdentity(context.Background(), id)
	if err != nil || user.ID == acct.ID || acct.Name != "new@example.com" {
		t.Fatalf("resolve = %#v %#v %v", user, acct, err)
	}
	_, second, err := st.ResolveDirectIdentity(context.Background(), id)
	if err != nil || second == nil || second.ID != acct.ID {
		t.Fatalf("repeat created another account: %#v %v", second, err)
	}
}
```

Also test provider-subject precedence over a later provider email change, concurrent first login creates one user/account, an existing zero-membership user receives no account, one membership auto-selects, multiple memberships produce a nil active account, expired sessions fail, and legacy null-`user_id` sessions reconcile on first use.

- [ ] **Step 2: Run focused auth tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestResolveDirectIdentity|TestSession|TestMagicLink|TestGitHubOAuth' -count=1`

Expected: FAIL on missing store methods.

- [ ] **Step 3: Implement transactional identity resolution**

`ResolveDirectIdentity` must:

1. normalize the verified email;
2. check `(provider,subject)` first;
3. acquire `pg_advisory_xact_lock(hashtext(normalized_email))` for first linkage;
4. recheck identity, then resolve user by unique email;
5. create a user only when neither exists;
6. create an account plus admin membership only when this normal signup created the user;
7. link the identity and refresh avatar;
8. return the only active account, or nil when zero/multiple memberships exist.

The new account name is the first 80 Unicode code points of the verified email. Account and user UUIDs must be independently generated.

For compatibility, a directly created identity also writes its new account ID to `devradar_identity.tenant_id`; an invitation-created identity leaves that compatibility column null.

Do not use PostgreSQL `xmax` to infer insertion. The advisory lock makes the explicit select/insert decision deterministic and testable.

- [ ] **Step 4: Implement user sessions and update login handlers**

`ValidateSession` returns:

```go
type Session struct {
	User            User
	ActiveAccountID *string
	ExpiresAt       time.Time
}
```

If a session has null `user_id` but a legacy `tenant_id`, reconcile it transactionally before returning. `SelectSessionAccount` must update only when an active membership exists for that session user.

New session inserts set both `active_account_id` and compatibility `tenant_id` to the selected account, or both null at the chooser. Keep the old tenant auth functions until Task 4 has moved middleware; mark them transitional and add no new callers.

Update magic-link and GitHub callbacks to resolve `account.VerifiedIdentity`, create the user session, and redirect to `/overview` only when an account was selected; otherwise redirect to `/accounts`.

- [ ] **Step 5: Move auth housekeeping and remove replaced tenant SQL**

Move purge queries for sessions/login tokens into `pkg/data/postgres/housekeeping.go`. Keep API-token and operator functions in `pkg/tenant` until Tasks 8 and 12 move their callers.

- [ ] **Step 6: Run auth and regression tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server ./pkg/tenant -run 'TestResolveDirectIdentity|TestSession|TestMagicLink|TestGitHubOAuth|TestPurgeExpiredAuth' -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/data/postgres pkg/server pkg/tenant
git commit -S -m "feat: separate user sessions from accounts"
```

### Task 4: Introduce Typed Request Context and Cut Handlers Over to Account IDs

**Files:**
- Modify: `pkg/middleware/auth.go`
- Modify: `pkg/middleware/admin.go`
- Modify: `pkg/middleware/admin_test.go`
- Create: `pkg/server/view.go`
- Modify: `pkg/server/server.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/ui_*.go`
- Modify: `pkg/server/read.go`
- Modify: `pkg/server/read_licenses.go`
- Modify: `pkg/server/ingest.go`
- Modify: `pkg/server/ingest_vex.go`
- Modify: `pkg/server/admin_metrics.go`
- Modify: `pkg/server/handler_admin.go`
- Modify: `pkg/server/templates/_chrome.html`
- Modify: all affected `pkg/server/*_test.go`
- Delete after all callers move: `pkg/tenant/identity.go`, `pkg/tenant/logintoken.go`, `pkg/tenant/session.go`

**Interfaces:**
- Consumes: `Store.ValidateSession`, `Store.GetAccess`, `Store.ReconcileLegacyAccount`.
- Produces: `middleware.UserFromContext`, `middleware.AccessFromContext`, `middleware.AccountFromContext`, `middleware.ActorFromContext`, `RequireUser`, `RequireAccount`, and `RequirePlatformAdmin`.

- [ ] **Step 1: Write failing middleware context tests**

Test a valid browser request exposes different `Actor.ID` and `Account.ID`, a revoked membership redirects to `/accounts?error=unavailable`, suspended user clears the session, suspended account redirects without clearing the user session, and platform admin checks the actor email.

- [ ] **Step 2: Run middleware tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/middleware ./pkg/server -run 'TestAccessContext|TestSession_|TestAdmin_' -count=1`

Expected: FAIL because typed access middleware is missing.

- [ ] **Step 3: Implement typed middleware**

Use distinct context keys and these semantics:

```go
func RequireUser(store *postgres.Store, loginURL string) func(http.Handler) http.Handler
func RequireAccount(store *postgres.Store, accountsURL string) func(http.Handler) http.Handler
func RequirePlatformAdmin(store *postgres.Store) func(http.Handler) http.Handler
func UserFromContext(context.Context) *account.User
func AccessFromContext(context.Context) *account.Access
func AccountFromContext(context.Context) *account.Account
func ActorFromContext(context.Context) account.Actor
```

`RequireUser` authenticates the session only. `RequireAccount` layers on it and loads the active membership/account every request. `RequirePlatformAdmin` authenticates the user and checks `DEVRADAR_ADMIN_USERS` without requiring an active account.

- [ ] **Step 4: Add shared chrome data and refactor every handler**

Create:

```go
type chromeView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	AvatarURL   string
	AccountName string
	AccountRole account.Role
	Version     string
}

func (s *Server) chrome(a *account.Access, title, tab string) chromeView
```

Embed `chromeView` in authenticated view structs. Replace every `TenantFromContext` use with typed access. Store calls continue to receive `access.Account.ID`; actor email/avatar always come from `access.Actor`. API handlers use `AccountFromContext`. Update log keys from ambiguous `tenant_id` to `account_id` where the value is an account.

- [ ] **Step 5: Move API-token validation to account context**

Add `Store.ValidateAPIToken(ctx,raw) (*account.Account, account.Actor, error)` in `pkg/data/postgres/auth.go`. Preserve the coarsened `last_used_at` update. API middleware injects only the owning account and `Actor{Kind: ActorAPIToken, APITokenID: tokenID}`; it never loads human memberships.

- [ ] **Step 6: Run the full server and middleware suites**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/middleware ./pkg/server ./pkg/data/postgres -count=1`

Expected: PASS with unchanged single-account behavior.

- [ ] **Step 7: Commit**

```bash
git add pkg/middleware pkg/server pkg/data/postgres
git commit -S -m "refactor: use typed user and account access"
```

## Phase B: Roles, Audit, and Multi-Account UX

### Task 5: Centralize Route Capabilities and Enforce the Role Matrix

**Files:**
- Create: `pkg/server/routes.go`
- Create: `pkg/server/routes_test.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/middleware/auth.go`
- Modify: `pkg/server/templates/cves.html`
- Modify: `pkg/server/templates/image.html`
- Modify: `pkg/server/templates/sbom.html`
- Modify: `pkg/server/templates/licenses.html`
- Modify: `pkg/server/templates/tokens.html`
- Modify: `pkg/server/*_test.go`

**Interfaces:**
- Produces: `middleware.RequireCapability(cap account.Capability)` and a complete `browserRoutePolicy` used by route registration and tests.

- [ ] **Step 1: Write a failing route inventory and role matrix test**

The inventory must classify every authenticated browser route. Exercise hand-crafted requests as admin/editor/reader and assert:

- all three roles can GET evidence pages and mark personal alert receipts;
- admin/editor can POST VEX and archive;
- only admin can mutate settings, policies, tokens, and members;
- reader/editor receive `403` from admin-only handlers even with valid CSRF.

- [ ] **Step 2: Run the matrix tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/server -run 'TestAuthenticatedRouteInventory|TestRoleMatrix' -count=1 -v`

Expected: FAIL because routes have no capability declarations.

- [ ] **Step 3: Implement centralized route registration**

Use one declaration per account route:

```go
type browserRoute struct {
	Pattern    string
	Capability account.Capability
	CSRF       bool
}

var browserRoutePolicy = []browserRoute{
	{"GET /overview", account.ReadAccount, false},
	{"POST /sboms/{id}/archive", account.WriteEvidence, true},
	{"POST /images/archive", account.WriteEvidence, true},
	{"POST /vex/upload", account.WriteEvidence, false},
	{"POST /alerts/{id}/read", account.WritePersonal, true},
	{"POST /settings/license-policy", account.ManageSettings, true},
	{"POST /settings/min-severity", account.ManageSettings, true},
	{"POST /settings/alerts", account.ManageSettings, true},
	{"GET /account/tokens", account.ManageCredentials, false},
	{"POST /account/tokens", account.ManageCredentials, true},
	{"POST /account/tokens/{id}/revoke", account.ManageCredentials, true},
}
```

Include every existing authenticated route, not only the examples. Route registration must consume this policy so an undeclared account route cannot be wired accidentally.

- [ ] **Step 4: Gate templates with `Access.Can`**

Pass capability booleans through chrome/view data. Omit VEX/archive controls for readers and all settings/token/member controls for editors/readers. Server checks remain authoritative.

- [ ] **Step 5: Run route, CSRF, and server tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/server ./pkg/middleware -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/server pkg/middleware
git commit -S -m "feat: enforce account role capabilities"
```

### Task 6: Add Transactional Audit Attribution

**Files:**
- Create: `pkg/data/postgres/sql/migrations/031_account_state_audit.sql`
- Create: `pkg/data/postgres/audit.go`
- Create: `pkg/data/postgres/audit_test.go`
- Modify: `pkg/data/postgres/read.go`
- Modify: `pkg/data/postgres/vex.go`
- Modify: `pkg/data/postgres/attestation.go`
- Modify: `pkg/data/postgres/sbom.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/license.go`
- Modify: `pkg/server/ingest.go`
- Modify: `pkg/server/ingest_vex.go`
- Modify: `pkg/server/ui_*.go`
- Modify: `pkg/server/read.go`
- Modify: `pkg/server/handler_admin.go`
- Modify: `pkg/server/server.go`

**Interfaces:**
- Consumes: `account.Actor` from typed request context.
- Produces: `Store.WithAudit`, audited mutation methods, and request correlation.

- [ ] **Step 1: Write failing atomicity and attribution tests**

For each mutation family, assert the data change and audit event commit together. Force audit insertion to fail with a test constraint and assert the protected mutation rolls back. Verify user, API token, and platform actor kinds are distinct and raw secrets never appear in metadata.

- [ ] **Step 2: Run audit tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestAudit|Test.*Attribution' -count=1`

Expected: FAIL because migration 031 and audit methods do not exist.

- [ ] **Step 3: Add the audit schema and request IDs**

Create `devradar_audit_event` with account FK, actor kind, nullable user/token FKs using `ON DELETE SET NULL`, action, target type/ID, outcome, request ID, bounded JSONB metadata, and `occurred_at`. Add `(account_id,occurred_at DESC,id DESC)` and actor indexes.

Migration 031 also creates `devradar_alert_receipt` and a new `devradar_session_token_flash` keyed by `(session_id,account_id)`. Retain the legacy `devradar_token_flash` table unchanged so an old revision can still complete a token flow while traffic drains. Backfill personal receipts for each globally read alert to the account's migrated legacy user. Do not clear or drop the compatibility flash table in a schema migration.

Add outer request-ID middleware that generates a random 128-bit hex ID, stores it in context, and returns `X-Request-ID`. Do not trust an arbitrary client-supplied ID as the primary audit correlation value.

- [ ] **Step 4: Implement one transaction helper and audited variants**

```go
type AuditEvent struct {
	Action, TargetType, TargetID, Outcome, RequestID string
	Metadata map[string]string
}

func (s *Store) WithAudit(ctx context.Context, accountID string, actor account.Actor, event AuditEvent, mutate func(*sql.Tx) error) error
```

Refactor SQL bodies to accept a `dbtx` interface so audited methods use one transaction. Cover account/policy changes, token create/revoke, VEX save, archive, attestation save, and activation of a newly submitted SBOM. For ingest, audit in the activation transaction; an audit failure leaves the SBOM pending so the existing retry path can self-heal.

- [ ] **Step 5: Replace handler mutations with audited methods**

Pass `middleware.ActorFromContext` and the generated request ID. Keep authorization denials as structured security logs; successful shared-state mutation must fail if its audit insert fails.

- [ ] **Step 6: Run mutation and full database tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/data/postgres pkg/server
git commit -S -m "feat: audit account mutations"
```

### Task 7: Add Account Switching, Settings, and Membership Lifecycle

**Files:**
- Create: `pkg/server/ui_accounts.go`
- Create: `pkg/server/accounts_test.go`
- Create: `pkg/server/templates/accounts.html`
- Create: `pkg/server/templates/account_settings.html`
- Create: `pkg/server/templates/account_members.html`
- Modify: `pkg/data/postgres/account.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/_chrome.html`
- Modify: `pkg/server/static/css/app.css`
- Modify: `pkg/server/static/js/app.js`

**Interfaces:**
- Produces: `ListMembers`, `UpdateAccountName`, `ChangeMemberRole`, `RevokeMembership`, `LeaveAccount`, account list/selection routes, and the last-admin invariant.

- [ ] **Step 1: Write failing membership concurrency tests**

Test multiple-account listing, CSRF-protected selection, selection denial for unrelated/revoked membership, trimmed 1-80-code-point names, admin equality, editor/reader self-leave, and concurrent demote/remove/leave attempts retaining at least one active admin.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestAccountSwitch|TestMembership|TestLastAdmin' -count=1 -v`

Expected: FAIL on missing lifecycle methods/routes.

- [ ] **Step 3: Implement serialized membership mutations**

Every role/removal/leave transaction must first execute:

```sql
SELECT id FROM devradar_tenant WHERE id=$1 FOR UPDATE;
```

When the target is an active admin, count active admins under that lock and return `postgres.ErrLastAdmin` if the mutation would leave zero. Use one lifecycle membership row; reactivation clears revocation fields and updates role. Append the matching audit event in the same transaction.

- [ ] **Step 4: Add account UX**

Add user-authenticated `/accounts`, `POST /accounts/select`, and `POST /accounts/{id}/leave`. Add admin-only `/account/settings` and `/account/members`. The nav shows current account name/role and links to `/accounts`; switching always redirects to `/overview`. A user with zero memberships sees invitation guidance and no create-account action.

- [ ] **Step 5: Run account and full server tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/data/postgres/account.go pkg/server
git commit -S -m "feat: add multi-account switching"
```

### Task 8: Make Alert Receipts and API-Token Flash User-Safe

**Files:**
- Create: `pkg/secretbox/secretbox.go`
- Create: `pkg/secretbox/secretbox_test.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/alert_test.go`
- Create: `pkg/data/postgres/token.go`
- Create: `pkg/data/postgres/token_test.go`
- Modify: `pkg/server/ui_alerts.go`
- Modify: `pkg/server/ui_overview.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/alerts_test.go`
- Modify: `pkg/server/auth_test.go`
- Delete after callers move: `pkg/tenant/apitoken.go`, `pkg/tenant/flashcrypt.go`, corresponding tests

**Interfaces:**
- Produces user-aware alert reads and Store API-token management keyed by account plus actor/session.

- [ ] **Step 1: Write failing cross-user isolation tests**

Create two users in one account. Mark one alert read as user A and assert user B still sees it unread. Mint tokens from two sessions and assert each session consumes only its own flash. Assert editor/reader cannot list token metadata or invoke management handlers.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server ./pkg/secretbox -run 'TestAlertReceipt|TestTokenFlash|TestAPIToken' -count=1`

Expected: FAIL because receipts, secretbox, and session/account flash keys are missing.

- [ ] **Step 3: Use migration 031 personal-state tables without altering the migration**

Read and write `devradar_alert_receipt` and `devradar_session_token_flash` created in Task 6. Add `Store.PurgeLegacyTokenFlashes(ctx)` for the explicit feature cutover; call it only when account sharing is enabled after reconciliation and old revisions have zero traffic. Never alter migration 031 after its Task 6 commit.

- [ ] **Step 4: Implement personal alert queries**

Change signatures to include user:

```go
func (s *Store) ListAlerts(ctx context.Context, accountID, userID, cursor string, limit int) ([]Alert, string, error)
func (s *Store) UnreadAlerts(ctx context.Context, accountID, userID string, limit int) ([]Alert, error)
func (s *Store) GetAlert(ctx context.Context, accountID, userID, alertID string) (*Alert, error)
func (s *Store) MarkAlertRead(ctx context.Context, accountID, userID, alertID string) error
```

Join the receipt by alert and user; derive unread from receipt absence. Keep `devradar_alert.read_at` untouched until the later contract release.

For rolling compatibility, treat legacy `alert.read_at` as read only for the migrated user whose `legacy_tenant_id` equals the alert account. Other members rely solely on their receipts, so an old revision cannot clear an invitee's personal unread state.

- [ ] **Step 5: Move API-token SQL and flash encryption into Store**

Preserve exact token caps and advisory-lock admission. `CreateAPIToken` accepts account ID, creating user ID, session hash, name, TTL, limit, request ID, and encryption key; token insert, audit insert, and flash insert commit together. Flash consume requires session plus account. `RevokeAPIToken` is account-filtered and audited.

- [ ] **Step 6: Run focused and regression tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/secretbox ./pkg/data/postgres ./pkg/server -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/secretbox pkg/data/postgres pkg/server pkg/tenant
git commit -S -m "feat: isolate personal alert and token state"
```

## Phase C: Durable Delivery and Invitations

### Task 9: Add Idempotent Email Sending and the Durable Outbox

**Files:**
- Modify: `pkg/net/email.go`
- Create: `pkg/net/email_test.go`
- Create: `pkg/data/postgres/sql/migrations/032_account_invitations.sql`
- Create: `pkg/data/postgres/delivery.go`
- Create: `pkg/data/postgres/delivery_test.go`
- Modify: `pkg/config/env.go`
- Modify: `pkg/config/validate.go`
- Modify: `pkg/config/env_test.go`
- Modify: `pkg/config/validate_test.go`

**Interfaces:**
- Produces `net.Message`, `net.Receipt`, idempotent `Sender.Send`, delivery config, and Store outbox leasing/state methods.

- [ ] **Step 1: Write failing sender and lease tests**

Assert Resend requests carry `Idempotency-Key`, parse the returned message ID, classify 429/5xx and concurrent-idempotency 409 as transient, classify invalid-recipient and payload-mismatch errors as permanent, and never include API keys in errors. Test two workers cannot lease the same row and an expired lease is recoverable.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `go test -race ./pkg/net ./pkg/config && DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres -run TestDelivery -count=1`

Expected: FAIL on missing message/receipt and outbox tables.

- [ ] **Step 3: Change the email seam**

```go
type Message struct {
	To, Subject, HTML, Text, IdempotencyKey string
}

type Receipt struct{ ID string }

type Sender interface {
	Send(context.Context, Message) (Receipt, error)
}
```

Update existing magic-link sending to use this interface. Add typed provider errors containing HTTP status and Resend error name but never request authorization.

- [ ] **Step 4: Add invitation/outbox schema**

Migration 032 creates `devradar_account_invitation` and `devradar_delivery_outbox`. Invitations store only token hash/version. Outbox rows store kind, invitation ID/version, recipient, encrypted payload, idempotency key, status, attempt count, next attempt, lease owner/expiry, provider ID, scrubbed error, and timestamps. Add the pending invitation partial unique index and due-work index.

- [ ] **Step 5: Implement leasing without holding network transactions**

`LeaseDeliveries` uses a short transaction with `FOR UPDATE SKIP LOCKED`, updates lease fields, commits, and returns at most the requested limit. `CompleteDelivery`, `RetryDelivery`, and `PermanentlyFailDelivery` require matching lease owner. Final states clear ciphertext.

- [ ] **Step 6: Add fail-closed delivery-key configuration**

Add `DEVRADAR_DELIVERY_KEY`, require base64-encoded 32 bytes whenever account sharing or the delivery command is enabled, and add accessors for batch 50, concurrency five, ten-second deadline, eight attempts, and 23-hour horizon.

- [ ] **Step 7: Run tests and commit**

Run: `go test -race ./pkg/net ./pkg/config && DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres -run TestDelivery -count=1`

Expected: PASS.

```bash
git add pkg/net pkg/config pkg/data/postgres
git commit -S -m "feat: add durable email outbox"
```

### Task 10: Add the Bounded Delivery Job and Local/Cloud Wiring

**Files:**
- Create: `pkg/delivery/delivery.go`
- Create: `pkg/delivery/delivery_test.go`
- Create: `cmd/devradar-deliver/main.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `vendor/`
- Modify: `.goreleaser.yaml`
- Modify: `Makefile`
- Modify: `infra/saas/cloudrun.tf`
- Modify: `infra/saas/scheduler.tf`
- Modify: `infra/saas/iam.tf`
- Modify: `infra/saas/secrets.tf`
- Modify: `.github/workflows/deploy.yaml`
- Modify: `DEPLOYMENT.md`

**Interfaces:**
- Consumes Store delivery leases, `secretbox.Open`, and `net.Sender`.
- Produces `delivery.Run(ctx, Options) error` and a scheduled `devradar-deliver` Cloud Run Job.

- [ ] **Step 1: Write failing worker tests**

Use a fake store and sender to verify max-five concurrency, context cancellation drains work, ten-second child deadlines, transient exponential backoff with jitter bounds, eight-attempt/23-hour terminal failure, stale invitation/version skip, ciphertext scrubbing, and partial batch failure does not stop unrelated deliveries.

- [ ] **Step 2: Run worker tests and verify failure**

Run: `go test -race ./pkg/delivery ./cmd/devradar-deliver`

Expected: FAIL because packages do not exist.

- [ ] **Step 3: Implement the worker**

Use `errgroup.WithContext` plus a semaphore of five. Fetch at most 50 leases, revalidate pending invitation and token version immediately before send, decrypt only inside the worker goroutine, render the fixed invitation template, and zero/discard plaintext after constructing the HTTP request. Return infrastructure errors; persist per-delivery provider errors and continue.

Run `go mod tidy && go mod vendor` so the direct `golang.org/x/sync/errgroup` dependency and vendored metadata remain reproducible.

Add a `net.LogSender` used only when `DEVRADAR_DEV_MODE=true` and no Resend key is present. It logs the recipient/link and returns a deterministic local receipt; production delivery still fails closed without a real sender.

- [ ] **Step 4: Add thin command and local target**

`cmd/devradar-deliver/main.go` mirrors existing serve/scan entrypoints and calls `delivery.Run(ctx, delivery.Options{Version,Commit,Date})`. Add `make deliver` using local DB/dev mode.

- [ ] **Step 5: Add build and infrastructure resources**

Add a pure-Go GoReleaser/ko image for `devradar-deliver`. Add a single-task Cloud Run Job scheduled every minute, a dedicated delivery service account with Cloud SQL/logging plus only database/send/delivery-key secret access, and scheduler invocation permission. Add the delivery job update to the existing deploy workflow, but do not run it.

Create the dedicated delivery key as 32 random bytes in Secret Manager and inject it into serve and delivery. Do not read or modify local `terraform.tfvars`.

- [ ] **Step 6: Validate code and Terraform**

Run:

```bash
go test -race ./pkg/delivery ./cmd/devradar-deliver
go build ./cmd/devradar-deliver
make tf-validate
```

Expected: all commands PASS; Terraform reports valid configuration.

- [ ] **Step 7: Commit**

```bash
git add pkg/delivery cmd/devradar-deliver go.mod go.sum vendor .goreleaser.yaml Makefile infra/saas .github/workflows/deploy.yaml DEPLOYMENT.md
git commit -S -m "feat: add email delivery job"
```

### Task 11: Add Invitation Acceptance and Member Management

**Files:**
- Create: `pkg/data/postgres/invitation.go`
- Create: `pkg/data/postgres/invitation_test.go`
- Create: `pkg/server/ui_invitations.go`
- Create: `pkg/server/invitations_test.go`
- Create: `pkg/server/templates/account_invitation.html`
- Modify: `pkg/server/templates/account_members.html`
- Modify: `pkg/server/ui_accounts.go`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/routes.go`
- Modify: `pkg/config/env.go`
- Modify: `pkg/config/env_test.go`

**Interfaces:**
- Produces create/refresh/resend/revoke/accept invitation methods and feature-gated UI routes.

- [ ] **Step 1: Write failing invitation lifecycle tests**

Cover new and existing users, all three roles, exact signed-in email match, different-email rejection, GET not consuming, CSRF-required POST, seven-day expiry, resend/role-change token rotation, active-member rejection, one pending invitation per account/email, concurrent acceptance idempotency, revoke-before-accept denial, acceptance account selection, reactivation after prior membership revocation, and no account creation for a user first created by acceptance.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestInvitation|TestAccountMembers' -count=1 -v`

Expected: FAIL on missing invitation methods/routes.

- [ ] **Step 3: Implement invitation creation and resend**

`CreateOrRefreshInvitation` validates admin actor/access, takes the account lock, rejects active members, locks an existing pending invite, generates a new 256-bit token, hashes it, increments version, seals the raw token, and inserts one outbox row with idempotency key `account-invitation/<invitation UUID>/<version>`. Invitation, outbox, and audit must commit together.

Use existing `ratelimit.Allow` with fail-closed error handling for invitation limits. Resend within 60 seconds returns `postgres.ErrRateLimited`.

- [ ] **Step 4: Implement scanner-safe acceptance**

GET calls `PeekInvitation` and renders account name, inviter, and role without mutation. POST locks the invitation row, verifies hash/expiry/state/account/user status, resolves or creates the invited-email user without creating an account, links the magic-link identity, creates/reactivates membership, marks accepted, appends audit, and commits. A repeated accept by the same accepted user returns the existing account without another membership or audit event. Create/select the browser session after the membership transaction; if session creation fails, the accepted membership remains valid and the user can sign in normally.

- [ ] **Step 5: Add admin member/invitation UI and flag**

Add admin-only invite form, pending state, resend, revoke, role change, and remove actions. When `DEVRADAR_ACCOUNT_SHARING_ENABLED` is false, invitation routes return `404` and controls are absent; account switching and existing migrated memberships still work.

When the flag is true, startup must run `ReconcileLegacyAccounts`, verify no account/identity/live-session mapping remains missing, then call `PurgeLegacyTokenFlashes` before exposing invitation routes. This flag may be enabled only after old revisions have zero traffic.

- [ ] **Step 6: Run lifecycle, authorization, and race tests**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestInvitation|TestMembership|TestRoleMatrix' -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/data/postgres pkg/server pkg/config
git commit -S -m "feat: add account invitations"
```

## Phase D: Operator Compatibility, Documentation, and Local Release Gate

### Task 12: Adapt the Platform Console and Remove Remaining Person/Tenant Conflation

**Files:**
- Modify: `pkg/data/postgres/admin.go`
- Create: `pkg/data/postgres/admin_account_test.go`
- Modify: `pkg/server/handler_admin.go`
- Modify: `pkg/server/admin_test.go`
- Modify: `pkg/server/templates/admin_tenants.html`
- Modify: `pkg/server/templates/admin_tenant.html`
- Modify: `pkg/server/templates/_admin.html`
- Modify: `README.md`
- Modify: `DEVELOPMENT.md`
- Modify: `DEPLOYMENT.md`
- Delete: remaining `pkg/tenant/*.go` and migrated tests

**Interfaces:**
- Produces account-oriented operator queries and removes the unsafe platform upsert-invite behavior.

- [ ] **Step 1: Write failing platform-console tests**

Assert list/search returns account name, plan, status, member count, and initial admin email; account deletion removes account data/memberships but preserves a multi-account user; operator authorization uses actor email; and `/admin/invite` sends the ordinary verified signup flow without inserting a verified user/account before acceptance.

- [ ] **Step 2: Run admin tests and verify failure**

Run: `DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -run 'TestAdmin.*Account|TestAdminInvite' -count=1`

Expected: FAIL while the console still treats tenant rows as people.

- [ ] **Step 3: Move operator SQL and update UI language**

Replace `tenant.AdminListTenantsWithStats`, `GetTenant`, plan/status/delete, and token admin functions with `postgres.Store` account methods. Search account name and member email. Keep physical `/admin/tenant/{id}` redirects for bookmarks, but render account terminology and canonical `/admin/account/{id}` links.

Replace operator invite upsert with a normal magic-link signup delivery; no database row becomes verified until token consumption.

- [ ] **Step 4: Remove remaining tenant package callers**

Run `rg -n 'pkg/tenant|tenant\.Tenant|TenantFromContext' --glob '*.go'` and migrate every result. Delete `pkg/tenant` only when the search is empty. Do not rename physical `devradar_tenant` or domain `tenant_id` columns in this release.

- [ ] **Step 5: Update documentation**

Document user/account/membership terminology, role matrix, local delivery command, feature flag, migration versions 30-32, delivery secret/job, invitation workflow, immediate revocation semantics, and the no-release owner gate. Do not mark the ROADMAP item shipped before owner validation and an explicit rollout decision.

- [ ] **Step 6: Run focused and full tests**

Run:

```bash
DATABASE_URL="$DEV_DB" go test -race ./pkg/data/postgres ./pkg/server -count=1
rg -n 'pkg/tenant|tenant\.Tenant|TenantFromContext' --glob '*.go'
```

Expected: tests PASS; `rg` returns no matches and exit status 1.

- [ ] **Step 7: Commit**

```bash
git add pkg README.md DEVELOPMENT.md DEPLOYMENT.md
git commit -S -m "docs: finalize account sharing contract"
```

### Task 13: Rehearse the Production Snapshot and Complete Local Validation

**Files:**
- Modify: `DEPLOYMENT.md` only if rehearsal reveals a missing or inaccurate command
- Create locally but do not commit: migration count reports, `EXPLAIN (ANALYZE, BUFFERS)` output, and workflow validation notes outside the repository

**Interfaces:**
- Consumes: completed migrations 30-32 and all application behavior.
- Produces: local validation evidence and an owner-ready handoff; no remote changes.

- [ ] **Step 1: Run all repository gates on a fresh local database**

```bash
make db-up
make qualify
go build ./...
make tf-validate
git diff --check
```

Expected: qualification complete with coverage at or above `.settings.yaml`, build exits 0, Terraform is valid, and diff check prints nothing.

- [ ] **Step 2: Verify and restore the exact production snapshot locally**

```bash
export ADMIN_URL='postgres://devradar:devradar@localhost:5432/postgres?sslmode=disable'
export PRE_DB='devradar_prod_20260714_020645_pre'
export TEST_DB='devradar_prod_20260714_020645_test'
export PRE_URL="postgres://devradar:devradar@localhost:5432/${PRE_DB}?sslmode=disable"
export TEST_URL="postgres://devradar:devradar@localhost:5432/${TEST_DB}?sslmode=disable"
export PROD_BACKUP='/Users/mchmarny/dev/thingz/db/thingz-20260714-020645.sql.gz'

gzip -t "$PROD_BACKUP"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT inet_server_addr(), inet_server_port(), current_database()"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "DO \$\$ BEGIN CREATE ROLE devpulse NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END \$\$; DO \$\$ BEGIN CREATE ROLE cloudsqlsuperuser NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END \$\$;"
createdb --maintenance-db="$ADMIN_URL" --template=template0 "$PRE_DB"
gzip -dc "$PROD_BACKUP" | psql "$PRE_URL" -v ON_ERROR_STOP=1
psql "$PRE_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*), min(version), max(version) FROM devradar_schema_version"
```

Expected: gzip verification succeeds; server is localhost; baseline schema versions are contiguous through 29. If the retained baseline database already exists, verify it and do not recreate or mutate it.

- [ ] **Step 3: Clone, migrate twice, and verify contiguity**

```bash
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "CREATE DATABASE ${TEST_DB} WITH TEMPLATE ${PRE_DB} OWNER devradar"
DATABASE_URL="$TEST_URL" go test ./pkg/data/postgres -run '^TestMigrate_Idempotent$' -count=1 -v
DATABASE_URL="$TEST_URL" go test ./pkg/data/postgres -run '^TestMigrate_Idempotent$' -count=1 -v
psql "$TEST_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*),min(version),max(version),array_agg(version ORDER BY version)=ARRAY(SELECT generate_series(1,32)) AS contiguous FROM devradar_schema_version"
```

Expected: second migration run applies nothing; result is `32 | 1 | 32 | true`.

- [ ] **Step 4: Compare pre-existing table counts and validate account mappings**

Run the existing `DEPLOYMENT.md` count loop for every table present in the baseline. Migration 031 preserves every compatibility table and row. Then run:

```sql
SELECT count(*) FROM devradar_tenant t
LEFT JOIN devradar_user u ON u.legacy_tenant_id=t.id
LEFT JOIN devradar_account_member m
  ON m.account_id=t.id AND m.user_id=u.id AND m.role='admin' AND m.revoked_at IS NULL
WHERE u.id IS NULL OR m.user_id IS NULL OR u.id=t.id OR btrim(t.name)='';

SELECT count(*) FROM devradar_identity WHERE user_id IS NULL;
SELECT count(*) FROM devradar_session WHERE expires_at>now() AND user_id IS NULL;
SELECT count(*) FROM devradar_session_token_flash;
```

Expected: every query returns `0`; every baseline business-table count matches.

- [ ] **Step 5: Measure authorization and account-list query plans**

Use real account/user IDs from the migrated clone and run `EXPLAIN (ANALYZE, BUFFERS)` for `GetAccess`, `ListUserAccounts`, `ListMembers`, personal `UnreadAlerts`, and due-delivery leasing. Record execution time, rows, buffers, scan type, and chosen indexes. Add only a new forward migration if a measured plan is unbounded; never edit migrations 30-32 after rehearsal.

- [ ] **Step 6: Exercise the complete local workflow with sharing enabled only locally**

Generate an ephemeral local key and start serve against the migrated clone. After each invitation is created, run the one-shot delivery command in a second terminal:

```bash
export DEVRADAR_DELIVERY_KEY="$(openssl rand -base64 32)"
DATABASE_URL="$TEST_URL" DEVRADAR_DEV_MODE=true DEVRADAR_ACCOUNT_SHARING_ENABLED=true \
  DEVRADAR_DELIVERY_KEY="$DEVRADAR_DELIVERY_KEY" go run ./cmd/devradar-serve

DATABASE_URL="$TEST_URL" DEVRADAR_DEV_MODE=true \
  DEVRADAR_DELIVERY_KEY="$DEVRADAR_DELIVERY_KEY" go run ./cmd/devradar-deliver
```

Exercise:

1. existing migrated admin sign-in;
2. direct new signup;
3. admin/editor/reader invitations;
4. scanner-safe GET and explicit POST acceptance;
5. account switching;
6. reader mutation denial;
7. editor VEX/archive success and settings denial;
8. admin policy/token/member changes;
9. personal alert read isolation;
10. role change, leave, removal, final-admin denial, revocation, and re-login.

Expected: every behavior matches the approved design and no cross-account data appears.

- [ ] **Step 7: Final signed commit and local-only handoff**

If rehearsal required documentation or a new forward migration, rerun Steps 1-6 and make one focused signed commit. Then verify:

```bash
git status --short
git log --show-signature --format='%h %G? %s' -15
git log --oneline origin/main..HEAD
git remote -v
```

Expected: clean worktree; every implementation commit shows a good signature; no push, tag, deploy, Terraform apply, or production feature enablement occurred.

Stop here. Provide the owner the local commit range, test evidence, migrated clone URL, and exact manual workflow. The owner performs final local validation and decides whether any rollout work may begin.

## Unresolved Questions

None. Production rollout, pushing commits, and enabling account sharing remain explicit owner decisions after local validation.
