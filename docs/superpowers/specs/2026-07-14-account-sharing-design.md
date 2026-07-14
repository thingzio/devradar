# Account Sharing and Multi-User Tenancy Design

**Date:** 2026-07-14

**Status:** Approved in design review; pending review of this written specification

**Scope:** Account sharing only

## Summary

DevRadar will separate authenticated people from the accounts that own product
data. Every current tenant becomes an account with the same UUID, preserving
all tenant-scoped data, content hashes, and object paths. A distinct user is
created for the current person and receives an `admin` membership in that
account.

Users may belong to multiple accounts and switch the active account in their
browser session. Account-wide roles are `admin`, `editor`, and `reader`.
Authorization is enforced through explicit capabilities on every route and is
revalidated from PostgreSQL on every request so role changes and revocations
take effect on the next request.

This design replaces the ROADMAP proposal to keep a tenant as both a person and
an account. That compatibility model is initially cheaper, but it preserves the
identity ambiguity this feature needs to remove and creates unwanted personal
accounts for invitees. The selected design separates the concepts now while
retaining existing physical tenant identifiers and queries during an
expand/contract migration.

## Goals

- Convert each existing tenant into an account without changing its UUID or
  owned evidence.
- Convert the current tenant identity into a distinct user and initial account
  admin.
- Allow a user to belong to multiple accounts and switch between them.
- Support equal `admin`, `editor`, and `reader` account roles.
- Make invitations work for existing and future users without pre-verifying an
  address supplied by an admin.
- Make membership, role changes, and revocation strongly consistent and
  auditable.
- Preserve current single-account behavior throughout the migration.
- Keep the model understandable, testable, and reversible.

## Non-Goals

- Image- or repository-scoped sharing.
- User-created additional accounts after initial direct signup.
- An owner, billing-owner, or hidden account-creator role.
- Self-service account deletion, account transfer, or user deletion.
- Per-user or per-role API tokens.
- SSO, SCIM, domain claiming, or organization discovery.
- Renaming every `tenant_id` column in the account-sharing release.

## Current Constraints

`devradar_tenant` currently combines two domains:

- person fields: email, verification, external identities, avatar, sessions,
  and terms acceptance;
- account fields: plan, status, minimum severity, policies, API tokens, alerts,
  SBOMs, findings, and every other owned product record.

Browser sessions and external identities resolve directly to a tenant. API
tokens also resolve directly to a tenant. Request handlers receive that tenant
through context and pass its ID to explicitly tenant-filtered store methods.

This is a strong account data boundary, but it cannot identify the person who
acted in an account or represent one person in multiple accounts. The existing
tenant UUID is also part of SBOM content identity and GCS object paths, so it
must remain the account identifier.

## Operating Assumptions

- Workload remains approximately 80% reads and 20% writes.
- Deployment remains single-region and multi-AZ.
- Authorization-backed reads target p99 below 100 ms.
- Membership and authorization state is strongly consistent in PostgreSQL.
- Email delivery is asynchronous and at-least-once internally, with provider
  idempotency preventing duplicate recipient-visible sends.
- Authorization is not cached in the first release.
- An in-flight request may finish after revocation; the next request must fail.

## Domain Model

### Account

An account owns all current tenant-scoped product data and policy:

- SBOMs, findings, events, scans, failures, attestations, and VEX;
- alerts, work, comparisons, trends, and posture snapshots;
- minimum severity, alert policy, and license policy;
- API tokens, plan, status, and account name.

During expansion, `devradar_tenant` remains the physical account table. Its ID
and every existing domain `tenant_id` remain unchanged. Application types and
new code use `Account` and `AccountID` terminology even while compatibility
table and column names remain.

Account names are trimmed, contain 1-80 Unicode code points, and are not unique.
Existing and directly created accounts initially use the verified signup email
as their name. An admin can edit the name.

### User

A user is an authenticated person with:

- a new UUID independent of every account UUID;
- one normalized, unique email and its verification timestamp;
- zero or more external identities;
- status, avatar, and terms acceptance;
- zero or more browser sessions;
- zero or more account memberships.

Existing users receive new UUIDs rather than reusing the account UUID. Keeping
the values distinct exposes actor/account mistakes in tests and code review.
A user cannot authenticate until the email or external identity is verified.
A user may temporarily have no memberships after leaving their last non-admin
membership. That state shows an empty account chooser and does not implicitly
create another account.

### Membership

A membership connects one user to one account. There is one lifecycle row per
`(account_id, user_id)` with:

- role: `admin`, `editor`, or `reader`;
- acceptance and creation attribution;
- active or revoked state;
- role-change and revocation timestamps and attribution.

Re-invitation reactivates the existing lifecycle row with the accepted role.
Immutable audit events preserve prior membership and role history.

All admins are equal. The original account creator has no hidden privilege.
Every operation that could remove the final admin is rejected.

## Schema Direction

Final migration names will follow existing repository conventions. The required
logical changes are:

| Table or change | Purpose |
|---|---|
| `devradar_user` | Person identity, verified email, status, avatar, terms, and transitional `legacy_tenant_id` backfill key |
| `devradar_tenant.name` | Transitional physical account name |
| `devradar_account_member` | User-to-account role and lifecycle |
| `devradar_account_invitation` | Pending invitation, role, hashed token, expiry, acceptance, and revocation |
| `devradar_identity.user_id` | External identity resolves to a user |
| `devradar_session.user_id` | Session authenticates a user |
| `devradar_session.active_account_id` | Session-selected account; nullable at the account chooser |
| `devradar_api_token.created_by_user_id` | Optional creator attribution; legacy tokens remain null |
| `devradar_token_flash` | Rekey one-time token display by session and account |
| `devradar_alert_receipt` | Per-user read state for an account alert |
| `devradar_audit_event` | Append-only account mutation attribution |
| `devradar_delivery_outbox` | Durable, encrypted transactional email delivery |

Required database constraints include:

- unique normalized user email;
- unique external `(provider, subject)` identity;
- unique `(account_id, user_id)` membership;
- role checks on memberships and invitations;
- one unaccepted, unrevoked invitation per `(account_id, normalized_email)`;
- unique invitation token hash;
- unique delivery idempotency key;
- indexes for active memberships by user and account;
- indexes for active admins by account;
- indexes for due delivery work and user alert receipts.

Expired invitations retain their pending row until revoked, accepted, or
refreshed. Resend refreshes that row, rotates its token, and advances its token
version. This makes the active-invitation uniqueness constraint independent of
database-clock expressions in partial indexes.

## Authentication and Active Account

Browser sessions authenticate a user, not an account. A session stores an
optional active account ID.

On sign-in:

1. Resolve or create the user from a verified magic-link or GitHub identity.
2. Load active memberships.
3. Select the only account automatically when exactly one exists.
4. Show the account chooser when more than one exists.
5. Show the empty membership state when none exists.

Account selection is a CSRF-protected POST. It verifies active membership,
updates the session, and redirects to the selected account overview. It does not
redirect to an account-scoped resource from the previous account.

Every authenticated browser request loads one typed access context:

- `Actor`: authenticated user and verified identity;
- `Account`: active owner of the requested data and policy;
- `Access`: active membership role and derived capabilities.

The lookup validates that the user, account, and membership are active. A
revoked or suspended selection redirects to the account chooser with an
unavailable message. It never silently selects another account.

Platform-operator authorization uses the actor user's verified email, never an
account's legacy email or an account's initial admin.

## Roles and Capabilities

Handlers and templates use named capabilities, not numeric role ordering.

| Capability | Admin | Editor | Reader |
|---|---:|---:|---:|
| Read account evidence, CVEs, work, trends, and alerts | Yes | Yes | Yes |
| Update personal alert receipts | Yes | Yes | Yes |
| Upload VEX | Yes | Yes | No |
| Archive SBOMs and repositories | Yes | Yes | No |
| Change account name and global policies | Yes | No | No |
| Create and revoke API tokens | Yes | No | No |
| Invite, remove, or change member roles | Yes | No | No |
| Leave the account | Yes, unless final admin | Yes | Yes |

Global policies include minimum severity, browser alert policy, and license
policy. API-token and member metadata are admin-only surfaces rather than
general read-only account data.

Account deletion, account suspension, and plan changes remain platform-operator
operations. They are not granted to account admins in this release.

Every authenticated route declares its required capability. UI controls are
derived from the same access object, but server-side checks remain authoritative.
Unknown or cross-account resources return `404`. A known member attempting a
known account operation without the required capability receives `403`.

## Direct Signup

A normal first signup performs one transaction:

1. Resolve or create the user from the verified identity.
2. If the user row was created by this normal signup, create one account.
3. Create an active admin membership.
4. Create the session with that account selected.

Existing users never receive another account by signing in again, including an
existing user with zero memberships. A user who first joins through an
invitation receives no personal account. If a future
invitee deliberately signs up through the normal landing flow before accepting
the invitation, that direct signup creates an account; accepting the invitation
later adds the second membership.

## Invitation Flow

The first release accepts one recipient per admin action. Bulk invitation is
deferred.

1. The admin submits one email and one role.
2. The server normalizes the email, rejects active members, and rate-limits the
   account and recipient.
3. In one transaction, create or refresh the pending invitation, rotate a
   256-bit token, store only its hash on the invitation, and enqueue encrypted
   delivery with a stable idempotency key.
4. The delivery worker sends a recipient-specific confirmation link.
5. GET validates enough state to render confirmation but never consumes the
   token, protecting against email-security scanners.
6. The confirmation page seeds CSRF protection and requires an explicit POST.
7. POST locks and validates the invitation, token, expiry, account, user status,
   and state.
8. If a session exists, its verified email must exactly match the invitation.
   A different signed-in user fails closed.
9. If no session exists, the invitation token itself proves control of the
   invited email, resolves or creates that user, links the magic-link identity,
   and creates a session.
10. Create or reactivate the membership with the invited role, consume the
    invitation, select the account, and append audit events transactionally.

Invitations expire after seven days. Resend rotates the token and expiry;
changing the pending role also rotates the token. Accepted, revoked, expired,
or superseded tokens cannot grant access.

The invitation list shows recipient, role, inviter, expiry, and delivery state.
Admins may resend or revoke a pending invitation. Existing members are managed
through their membership rather than reinvited.

Invitation creation and resend are limited to 20 attempts per account per hour,
five attempts per recipient per hour, and a 60-second resend cooldown. These
limits use the existing durable rate-limiter pattern.

## Membership Changes

Membership and role mutations lock the account row, serializing the small set
of changes that affect the last-admin invariant. A removal, leave, or demotion
of an active admin counts active admins while holding that lock and fails with a
conflict if it would leave zero.

Admins may change or remove any admin, including the account's original admin,
subject only to that invariant. Editors and readers may leave their accounts.
An admin may leave only when another active admin remains.

Invitation accept/revoke operations lock the invitation row. Once revocation
commits, a stale acceptance attempt cannot reactivate access. Concurrent repeat
acceptance by the same recipient is idempotent.

## API Tokens and Token Flash

API tokens remain account credentials. Token validation resolves exactly one
account and does not inherit any browser user's memberships. Existing API
capabilities remain unchanged; per-token scopes are outside this release.

Only admins may list token metadata, create tokens, or revoke tokens. New tokens
record the creating user. Legacy tokens keep null creator attribution.
API-originated audit events identify the token as the actor; they do not pretend
that the creating admin performed every later API request.

The one-time token flash is keyed by browser session and account. Existing
tenant-keyed flashes are deleted during cutover because they live for only two
minutes and cannot be safely assigned to a migrated session. This prefers
secret isolation over preserving an unread ephemeral display.

## Personal Alert State

Alert facts remain account-owned. Read/unread state moves to
`devradar_alert_receipt(alert_id, account_id, user_id, read_at)`.

Readers, editors, and admins may update their own receipts. One user's action
never changes another user's unread count. Existing globally read alerts are
backfilled as receipts for the migrated initial admin. The old `read_at` column
is retained through the compatibility period and removed only in a contract
migration.

## Audit Model

Shared-state mutations append an audit event in the same database transaction
as the mutation. Audited actions include:

- invitation creation, resend, revocation, and acceptance;
- membership activation, removal, leave, and role change;
- account-name and global-policy changes;
- API-token creation and revocation;
- API-token-authenticated SBOM and attestation submission;
- VEX submission;
- SBOM and repository archival.

Events record account, actor kind, actor user or token when applicable, action,
target type and stable identifier, outcome, timestamp, and request correlation.
Raw session tokens, API tokens, invitation tokens, and encrypted delivery
payloads are never copied into audit data.

Successful database mutations and their successful audit events are atomic.
Authorization denials and failures before a transaction are emitted as
structured security logs with request correlation; inability to write a
required success audit event fails and rolls back the mutation.

## Email Delivery

Account sharing depends on a reusable transactional email-delivery substrate
rather than synchronous network calls in an HTTP mutation.

The invitation transaction stores an outbox row containing template metadata
and an encrypted recipient-specific token payload. Encryption uses a dedicated
Secret Manager-backed delivery key. The plaintext token exists only during
request construction and worker delivery, then is discarded. Delivered,
permanently failed, revoked, or expired payloads are scrubbed after their audit
retention metadata is recorded.

A thin `devradar-deliver` command runs as a scheduled Cloud Run Job every minute.
Each execution:

- leases at most 50 due rows with `FOR UPDATE SKIP LOCKED`;
- processes at most five deliveries concurrently;
- applies a ten-second per-request deadline;
- uses bounded exponential backoff with jitter;
- treats rate limits and server errors as transient;
- treats invalid recipients and other non-rate-limit client errors as permanent;
- stops after eight attempts, a 23-hour retry horizon, or invitation expiry;
- uses `invitation_id:token_version` as the provider idempotency key;
- records the provider message ID and scrubbed final status.

The email sender seam must accept the idempotency key and return a provider
message ID. The 23-hour retry horizon stays inside Resend's 24-hour idempotency
retention window. Before sending, the worker revalidates that the invitation is
pending and that the leased delivery still matches its current token version.
Local development logs the link while preserving the same outbox state
transitions. Delivery failure never grants access and remains visible to the
inviting admin.

## Account Management UX

The authenticated navigation shows the active account name, role, and account
switcher.

The account list shows all active memberships and supports switching and
leaving. It does not offer new-account creation. A user with no memberships sees
instructions to obtain an invitation.

Admin surfaces are split into:

- account settings: name and global policies;
- API tokens;
- members and pending invitations.

Editors and readers can see their membership and leave action but cannot see
admin-only token, policy, or membership data. Reader templates omit VEX and
archive controls. Editor templates include VEX and archive controls but omit all
global administration. Existing `/tokens` links redirect to the new token
surface during migration.

The platform operator console lists accounts rather than treating account rows
as people. It displays account name, plan, status, member count, and an initial
admin contact. Operator authorization still uses the signed-in user. The
existing `/admin/invite` behavior must not pre-create a verified account; it is
replaced with delivery of the existing magic-link signup flow, which creates the
user, account, and admin membership only after email proof.

## Failure and Error Semantics

- Missing or expired browser authentication redirects to sign-in.
- A session without a selected account redirects to the account chooser.
- A revoked or suspended active selection redirects to the chooser and exposes
  no account data.
- Unknown and unauthorized resource identifiers return `404`.
- Missing capabilities on an otherwise known account operation return `403`.
- Last-admin violations return `409` with corrective guidance.
- Repeat invitation creation returns the current pending invitation without
  creating another membership or unbounded delivery work.
- Email failure leaves a visible, retryable pending invitation.
- Database failure rolls back the membership, role, settings, or invitation
  mutation and its audit event.

## Migration and Rollout

### Phase 1: Expand and Backfill

- Add the user, membership, invitation, receipt, audit, and outbox tables.
- Add account name and additive auth/account columns.
- Create one distinct user per existing tenant using a unique transitional
  `legacy_tenant_id` mapping.
- Move person fields into the user and retain compatibility copies.
- Backfill all identities and sessions with the user ID.
- Set existing sessions' active account to their existing tenant ID.
- Create one active admin membership per existing tenant.
- Backfill personal receipts for the initial admin from globally read alerts.
- Leave legacy API-token creator attribution null.
- Delete short-lived legacy token flashes.

The migration is forward-only, transactional, idempotent, and safe under the
existing migration advisory lock. Old application revisions continue operating
because their columns and constraints remain available.

An old revision can create a tenant, identity, or session after the initial
backfill but before traffic fully moves to the user-aware revision. New auth
code therefore upgrades such legacy rows transactionally on first use. Before
sharing is enabled, a reconciliation pass repeats the backfill and the rollout
asserts that no tenant, identity, or live session lacks its user and admin
membership mapping.

### Phase 2: Authorization Foundation

- Introduce `User`, `Account`, `Membership`, and typed request access objects.
- Make new code dual-write compatibility auth columns.
- Classify every authenticated route by capability.
- Switch existing mutation attribution to durable audit events.
- Keep account sharing disabled. Every existing user remains behaviorally an
  admin of one account.

### Phase 3: Multi-Account UX

- Enable user-backed sign-in and active-account selection.
- Add account list, switcher, settings split, and personal alert receipts.
- Preserve all existing account-filtered store calls by passing `AccountID`.
- Validate single-account behavior before invitations exist.

### Phase 4: Invitation Beta

- Deploy the delivery job and invitation lifecycle behind
  `DEVRADAR_ACCOUNT_SHARING_ENABLED=false`.
- Validate invite, accept, switch, read, edit, role change, leave, revoke, and
  re-login using internal accounts in local and staging environments.
- Route 100% of service traffic to the user-aware revision before enabling
  sharing. Old revisions must never serve multi-user sessions.
- Enable production sharing only with explicit owner approval.

### Phase 5: Contract

After at least one stable release, remove person fields and compatibility auth
columns from `devradar_tenant`, make user references non-null, retire global
alert `read_at`, and rename physical tenant terminology to account terminology.
This cleanup is not required to enable account sharing.

## Verification

### Migration

- Every existing tenant retains its exact account ID and owned row counts.
- Every account receives exactly one distinct user and active admin membership.
- Multiple identities for one old tenant resolve to the same migrated user.
- Session, receipt, and account-name backfills are correct and idempotent.
- Concurrent startup cannot partially apply the migration.
- Tenant/account deletion still cascades owned data and memberships without
  deleting users who belong to other accounts.

### Authorization

- A route inventory test requires every authenticated route to declare a
  capability.
- The full admin/editor/reader matrix covers every browser mutation and read.
- Hand-crafted requests cannot bypass hidden UI controls.
- Platform-admin allowlisting uses the actor user.
- Suspended users, suspended accounts, revoked members, and unrelated users
  fail closed.
- Identical repository strings in different accounts never cross-authorize.

### Concurrency and Lifecycle

- Concurrent demote, remove, and leave operations cannot remove the last admin.
- Accept versus revoke cannot resurrect a revoked invitation.
- Repeat and concurrent acceptance is idempotent.
- Token rotation invalidates every prior invitation link.
- Revocation and role changes affect the next request.
- A user can belong to, switch among, and leave multiple accounts correctly.
- An invitation-created user receives no unwanted account.

### Isolation and Attribution

- One member cannot consume another member's API-token flash.
- Alert receipts and unread counts are personal.
- Account API tokens never inherit a human user's other memberships.
- Every shared-state mutation records the correct user or API-token actor.
- Audit-write failure rolls back the protected mutation.

### Delivery and Operations

- Outbox insertion is atomic with invitation state.
- Retry uses the same provider idempotency key and does not duplicate email.
- Lease expiry recovers abandoned work.
- Batch size, concurrency, attempt count, and deadlines remain bounded.
- Delivery status exposes partial and permanent failure without exposing tokens.
- Authorization queries retain indexed, bounded plans at production-shaped
  membership cardinality.

### Release Gates

- Run `make qualify` and `go build ./...`.
- Rehearse migrations against an isolated production database restore.
- Validate application behavior and authorization query plans on the restore.
- Validate documented rollback and feature-disable procedures.
- Have the owner exercise the complete workflow locally before beta or release.

## Rejected Alternatives

### Keep tenant as both person and account

This minimizes the first migration but leaves actor/account semantics ambiguous,
creates automatic personal accounts for invitees, and makes a later split more
expensive after multi-account behavior ships.

### Rename every tenant table and column immediately

This produces clean physical naming but couples authorization work to a broad
data migration, complicates rolling compatibility, and adds risk without
changing account-sharing behavior.

### Copy data into each member's tenant

Copies would duplicate scans and alerts, break tenant-scoped content identity,
complicate revocation, and let evidence and policy diverge.

### Add PostgreSQL RLS for account sharing

The repository consistently uses explicit account-first store methods. Adding
RLS only for this feature would create two authorization systems without
removing the need for application-level capability checks.

## Exit Criteria

- Existing users retain all current data and behavior as account admins.
- A direct signup creates exactly one account and admin membership.
- An invited existing or future user joins without receiving an unwanted
  account.
- Users can switch among multiple accounts and always see the selected account's
  complete data.
- Admin, editor, and reader capabilities match the approved matrix.
- No action can leave an account without an admin.
- Revocation applies on the next request and is attributable.
- Alert state is personal, while evidence and policy remain account-owned.
- No SBOM, finding, event, blob, scan, alert, or policy data is copied.

## Unresolved Questions

None for the account-sharing implementation plan. Image-scoped sharing remains
a separate future design.
