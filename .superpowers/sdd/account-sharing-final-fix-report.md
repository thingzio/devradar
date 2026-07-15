# Account Sharing Final Fix Report

Date: 2026-07-14
Base: `8e40cddf3a5cf21fc925ea530284833536389f06`
Branch: local `main`

## Result

Resolved all six findings in the final fix brief:

1. Hard account deletion detaches authoritative identity/session compatibility fields before deleting the tenant. Modern identities and sessions survive, the deleted selection clears, and the same session can select another account.
2. Pending invitations expose only `queued`, `sent`, `retrying`, or `failed` for the current account/id/version outbox row. Permanent failure renders safe resend guidance without provider errors, payloads, tokens, hashes, or provider IDs.
3. Exact duplicate invitation creates are no-ops. Different-role creates rotate with `invitation.role_change`; explicit resend and role-change paths retain their behavior. Verified HTTP duplicate no-ops bypass delivery rate charging.
4. GitHub WIF is bound to `repo:thingzio/devradar:environment:saas`. Artifact Registry writer is repository-scoped. Cloud Run admin is scoped to the serve service and scan/delivery jobs. Scheduler and service-account-user grants are unchanged.
5. Every active account and admin top-navigation tab renders exactly one `aria-current="page"`.
6. Escape closes the account menu and restores toggle focus; click-outside and toggle-click closure do not steal focus.

No migration was added. Migration inventory remains exactly 001–032, with account-sharing migrations 030–032.

## Root causes

- Migration 030 made legacy tenant compatibility columns nullable but retained migration 001/011 cascade FKs. Deleting the tenant therefore cascaded authoritative rows unless those columns were cleared first.
- `ListInvitations` did not join the current outbox version, and the template hard-coded `Pending`.
- `CreateOrRefreshInvitation` rotated every existing pending grant and labeled different-role duplicate creates as `invitation.refresh`. The HTTP rate limiter ran before duplicate detection.
- WIF trusted the repository-wide principal set, while deployer Artifact Registry and Cloud Run roles were project-wide.
- Only Trends had `aria-current`.
- Escape and click-outside shared a close function with no focus-restoration distinction.

## RED/GREEN evidence

### Authoritative identity and session preservation

RED, with the corrected authoritative-identity fixture and the fix temporarily removed:

```text
$ go test -race ./pkg/data/postgres -run '^TestAdminDeleteAccountPreservesAuthoritativeIdentityAndSession$' -count=1
--- FAIL: TestAdminDeleteAccountPreservesAuthoritativeIdentityAndSession (0.35s)
    admin_account_test.go:148: row count = 0, want 1
FAIL
FAIL github.com/thingzio/devradar/pkg/data/postgres 0.869s
exit 1
```

GREEN:

```text
$ go test -race ./pkg/data/postgres -run '^TestAdminDeleteAccountPreservesAuthoritativeIdentityAndSession$' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 1.777s
exit 0
```

Fixture correction: the first test draft used `seedAuditAccount`, which creates a modern user/membership but no post-migration identity row. The fixture was corrected to insert an authoritative GitHub identity, then RED was re-proven by removing only the production fix.

### Duplicate create and role-change semantics

Store RED:

```text
$ go test -race ./pkg/data/postgres -run '^TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange$' -count=1
--- FAIL: TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange (0.36s)
    invitation_test.go:164: duplicate invitation changed: ... TokenVersion:1 ... duplicate=... TokenVersion:2 ...
FAIL
FAIL github.com/thingzio/devradar/pkg/data/postgres 0.857s
exit 1
```

Store GREEN:

```text
$ go test -race ./pkg/data/postgres -run '^TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange$' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 1.900s
exit 0
```

HTTP rate-charge RED:

```text
$ go test -race ./pkg/server -run '^TestInvitationManagementRequiresAdminAndRateLimitDoesNotMutate$' -count=1
--- FAIL: TestInvitationManagementRequiresAdminAndRateLimitDoesNotMutate (0.10s)
    invitations_test.go:416: duplicate limited invitation = 429 location "": Invitation sending is temporarily unavailable. Try again later.
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.746s
exit 1
```

HTTP rate-charge GREEN:

```text
$ go test -race ./pkg/server -run '^TestInvitationManagementRequiresAdminAndRateLimitDoesNotMutate$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.783s
exit 0
```

Different-role HTTP RED, with only the duplicate-create audit action reverted:

```text
$ go test -race ./pkg/server -run '^TestInvitationCreateWithDifferentRoleUsesRoleChange$' -count=1
--- FAIL: TestInvitationCreateWithDifferentRoleUsesRoleChange (0.10s)
    invitations_test.go:161: different-role create role/version/action = editor/2/invitation.refresh
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.776s
exit 1
```

Different-role HTTP GREEN:

```text
$ go test -race ./pkg/server -run '^TestInvitationCreateWithDifferentRoleUsesRoleChange$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.767s
exit 0
```

Test correction: the first store RED query compared a text audit target to UUID without a cast. It was corrected to `i.id::text` before accepting the behavioral RED. The first temporary HTTP regression toggle changed the explicit role endpoint branch; it was moved to the duplicate-create branch before accepting RED.

### Safe current delivery state

Store RED:

```text
$ go test -race ./pkg/data/postgres -run '^TestListInvitationsReportsSafeCurrentDeliveryState$' -count=1
pkg/data/postgres/invitation_test.go:258:37: undefined: postgres.InvitationDeliveryState
pkg/data/postgres/invitation_test.go:260:41: invitation.DeliveryState undefined
pkg/data/postgres/invitation_test.go:263:28: undefined: postgres.InvitationDeliveryQueued
pkg/data/postgres/invitation_test.go:264:28: undefined: postgres.InvitationDeliveryRetrying
pkg/data/postgres/invitation_test.go:265:28: undefined: postgres.InvitationDeliveryFailed
pkg/data/postgres/invitation_test.go:266:28: undefined: postgres.InvitationDeliverySent
FAIL github.com/thingzio/devradar/pkg/data/postgres [build failed]
exit 1
```

Store GREEN:

```text
$ go test -race ./pkg/data/postgres -run '^TestListInvitationsReportsSafeCurrentDeliveryState$' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 2.082s
exit 0
```

Template RED:

```text
$ go test -race ./pkg/server -run '^TestAccountMembersShowsSafeInvitationDeliveryFailure$' -count=1
--- FAIL: TestAccountMembersShowsSafeInvitationDeliveryFailure (0.08s)
    invitations_test.go:416: failed invitation state = 200: ... <span class="access-state">Pending</span> ...
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.747s
exit 1
```

Template GREEN:

```text
$ go test -race ./pkg/server -run '^TestAccountMembersShowsSafeInvitationDeliveryFailure$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.759s
exit 0
```

### Navigation current-page semantics

RED:

```text
$ go test -race ./pkg/server -run '^(TestTopNavigationMarksOnlyActiveTabCurrent|TestDocsPage)$' -count=1
--- FAIL: TestDocsPage (0.09s)
    ui_docs_licenses_test.go:38: docs page missing "class=\"tab active\" aria-current=\"page\">Docs"
--- FAIL: TestTopNavigationMarksOnlyActiveTabCurrent (0.00s)
    --- FAIL: .../account_overview
    --- FAIL: .../account_images
    --- FAIL: .../account_work
    --- FAIL: .../account_cves
    --- FAIL: .../account_alerts
    --- FAIL: .../account_licenses
    --- FAIL: .../account_docs
    --- FAIL: .../account_api
    --- FAIL: .../admin_dashboard
    --- FAIL: .../admin_scans
    --- FAIL: .../admin_accounts
    --- FAIL: .../admin_metrics
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.770s
exit 1
```

Trends was the sole passing account-tab subtest before the fix.

GREEN:

```text
$ go test -race ./pkg/server -run '^(TestTopNavigationMarksOnlyActiveTabCurrent|TestDocsPage)$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.786s
exit 0
```

### Account-menu focus restoration

RED:

```text
$ go test -race ./pkg/server -run '^TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot$' -count=1
--- FAIL: TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot (0.00s)
    static_test.go:22: account menu script missing "function close(restoreFocus)"
    static_test.go:22: account menu script missing "if (restoreFocus) toggle.focus();"
    static_test.go:22: account menu script missing "!menu.contains(e.target) && e.target !== toggle) close(false);"
    static_test.go:22: account menu script missing "if (e.key === \"Escape\" && !menu.hidden) close(true);"
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.696s
exit 1
```

GREEN:

```text
$ go test -race ./pkg/server -run '^TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.692s
exit 0
```

## Terraform and workflow validation

Before IAM edits:

```text
$ make tf-validate
terraform -chdir=infra/saas init -backend=false >/dev/null && terraform -chdir=infra/saas validate
Success! The configuration is valid.
exit 0
```

After IAM edits and at final state:

```text
$ make tf-validate
terraform -chdir=infra/saas init -backend=false >/dev/null && terraform -chdir=infra/saas validate
Success! The configuration is valid.
exit 0
```

Command/permission review:

- Release uses only image push and `gcloud artifacts docker images describe` in `devradar-saas-images`; repository-scoped writer covers that repository.
- Deploy updates only `devradar-saas-serve`, `devradar-saas-scan`, and `devradar-saas-deliver`; resource-scoped Run admin covers those targets.
- Deploy pauses/resumes only `devradar-saas-deliver-scheduled`; the existing conditioned custom role is unchanged.
- Both release and deploy jobs retain `environment: saas`.
- Both runtime service-account-user grants are unchanged.

Plain `actionlint` initially exposed an existing SC2046 in the reusable test workflow:

```text
.github/workflows/test-on-call.yaml:78:9: shellcheck reported issue in this script: SC2046: Quote this to prevent word splitting
exit 1
```

The formatting command now uses NUL-delimited tracked paths and an excluded vendor pathspec. `actionlint`, targeted `yamllint`, and the command itself then returned exit 0.

## Final verification

Focused behavioral race tests:

```text
$ go test -race ./pkg/data/postgres -run '^(TestAdminDeleteAccountPreservesAuthoritativeIdentityAndSession|TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange|TestListInvitationsReportsSafeCurrentDeliveryState)$' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 2.862s

$ go test -race ./pkg/server -run '^(TestInvitationCreateWithDifferentRoleUsesRoleChange|TestAccountMembersShowsSafeInvitationDeliveryFailure|TestInvitationManagementRequiresAdminAndRateLimitDoesNotMutate|TestTopNavigationMarksOnlyActiveTabCurrent|TestDocsPage|TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot)$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.971s
```

Full changed-package race tests:

```text
$ go test -race ./pkg/data/postgres ./pkg/server -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 78.083s
ok github.com/thingzio/devradar/pkg/server 35.216s
exit 0
```

Final repository gates:

```text
$ make qualify
ok github.com/thingzio/devradar/pkg/data/postgres 79.501s coverage: 69.3% of statements
ok github.com/thingzio/devradar/pkg/server 33.766s coverage: 61.5% of statements
total: (statements) 67.0%
Coverage: 67.0% (threshold: 45%)
Coverage check passed
go vet ./...
golangci-lint run --timeout=5m
0 issues.
deploy workflow check: PASS (safe-prefix forward=660s/30m)
Qualification complete
exit 0

$ go build ./...
exit 0

$ make tf-validate
Success! The configuration is valid.
exit 0

$ actionlint
exit 0

$ yamllint .
exit 0

$ git diff --check
exit 0
```

## Self-review

- Account isolation: all new invitation/outbox reads filter `account_id`; delivery state additionally filters invitation ID and current token version and selects at most one row. Hard deletion touches only rows referencing the exact deleted account.
- Secrets: the exported invitation type contains only the four-state enum. No provider error, ciphertext, raw token, token hash, idempotency key, or provider ID is selected into UI data or rendered. HTTP regression checks provider error, raw token, and ciphertext absence.
- Authorization: invitation management remains behind authenticated account selection, `ManageMembers`, and CSRF middleware. Direct `CreateOrRefreshInvitation` calls still verify active-account admin membership under transaction lock before returning an exact duplicate.
- Accessibility: every account/admin tab has exactly one current-page marker; Escape focus restoration is guarded by the menu being open; pointer closure never focuses the toggle.
- IAM: exact environment subject, repository-only Artifact Registry writer, and only three Run resources. Scheduler and service-account impersonation scope are preserved.
- Migration scope: no SQL migration changes; latest migration remains 032.
- External state: no push, tag, deploy, Terraform plan/apply, feature enablement, or production/external mutation. `infra/saas/terraform.tfvars` was not read or modified.

## Changed files

- IAM/workflow: `infra/saas/iam.tf`, `.github/workflows/test-on-call.yaml`
- Store behavior/tests: `pkg/data/postgres/admin.go`, `admin_account_test.go`, `invitation.go`, `invitation_test.go`
- HTTP/UI/tests: `pkg/server/ui_invitations.go`, `invitations_test.go`, `static/js/app.js`, `static_test.go`, `template_capabilities_test.go`, `ui_docs_licenses_test.go`, and the three affected templates
- Evidence: this report

## Concerns

None outstanding. Terraform plan/apply and all production actions remain explicit owner steps. Account sharing remains disabled.

---

## Final Re-review Correction — 2026-07-14

Base: `c979252930bd0333e5e2e773682e634ed71a1ef0`

### Root causes and design

- The HTTP create path performed duplicate detection, account quota charging, recipient quota charging, and store mutation as separate transactions. The preflight could race, and recipient denial left both durable counters incremented.
- The corrected create path acquires the account row lock, revalidates active-admin authorization, resolves the pending invitation and outcome, reserves both quotas, and persists invitation/outbox/audit state in one transaction. Exact duplicates commit unchanged before quota reservation. Any denial or later mutation error rolls back all quota and invitation state.
- `ratelimit.Allow` now accepts the shared `QueryRowContext` contract implemented by both `*sql.DB` and `*sql.Tx`; its SQL is unchanged.
- The store returns only `unchanged`, `created`, or `role_changed`. HTTP redirects render “Invitation is already pending.” for an exact duplicate. The unlocked `PendingInvitationMatchesRole` API was deleted.
- Resource-scoped Cloud Run administration cannot authorize reads of the location-scoped long-running operation. A one-permission project custom role now grants only `run.operations.get` to the deployer.

### RED/GREEN evidence

Transactional limiter RED:

```text
$ go test -race ./pkg/ratelimit -run '^TestAllow_TransactionRollbackDoesNotConsumeQuota$' -count=1
pkg/ratelimit/ratelimit_test.go:100:39: cannot use tx (variable of type *sql.Tx) as *sql.DB value in argument to ratelimit.Allow
FAIL github.com/thingzio/devradar/pkg/ratelimit [build failed]
exit 1
```

Transactional limiter GREEN:

```text
$ go test -race ./pkg/ratelimit -run '^TestAllow_TransactionRollbackDoesNotConsumeQuota$' -count=1
ok github.com/thingzio/devradar/pkg/ratelimit 1.692s
exit 0
```

Bounded outcome RED:

```text
$ go test -race ./pkg/data/postgres -run '^TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange$' -count=1
pkg/data/postgres/invitation_test.go:41:28: st.CreateInvitation undefined
pkg/data/postgres/invitation_test.go:42:45: undefined: postgres.InvitationRateLimits
pkg/data/postgres/invitation_test.go:46:25: undefined: postgres.InvitationCreateCreated
pkg/data/postgres/invitation_test.go:165:25: undefined: postgres.InvitationCreateUnchanged
pkg/data/postgres/invitation_test.go:184:25: undefined: postgres.InvitationCreateRoleChanged
FAIL github.com/thingzio/devradar/pkg/data/postgres [build failed]
exit 1
```

Bounded outcome GREEN:

```text
$ go test -race ./pkg/data/postgres -run '^TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange$' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 1.999s
exit 0
```

Concurrent HTTP and rollback RED:

```text
$ go test -race ./pkg/server -run '^(TestConcurrentIdenticalInvitationCreatesShareMutationAndQuota|TestInvitationRecipientQuotaDenialRollsBackAccountQuota)$' -count=1
--- FAIL: TestConcurrentIdenticalInvitationCreatesShareMutationAndQuota (0.13s)
    invitations_test.go:227: both creates did not reach the account-lock barrier: statuses=429/303
--- FAIL: TestInvitationRecipientQuotaDenialRollsBackAccountQuota (0.07s)
    invitations_test.go:288: account/recipient quota after denial = 1/2, want 0/1
FAIL
FAIL github.com/thingzio/devradar/pkg/server 0.946s
exit 1
```

Concurrent HTTP and rollback GREEN:

```text
$ go test -race ./pkg/server -run '^(TestConcurrentIdenticalInvitationCreatesShareMutationAndQuota|TestInvitationRecipientQuotaDenialRollsBackAccountQuota)$' -count=1
ok github.com/thingzio/devradar/pkg/server 1.871s
exit 0
```

The first GREEN attempt returned two correct 303 responses but the barrier probe counted only direct blockers of the holder. PostgreSQL queue-blocked the second waiter behind the first. The probe was corrected to count both blocked account-lock queries; production behavior was unchanged.

IAM RED:

```text
$ go test ./infra/saas -run '^TestDeployerOperationPollingIAMIsLeastPrivilege$' -count=1
--- FAIL: TestDeployerOperationPollingIAMIsLeastPrivilege (0.00s)
    iam_test.go:17: missing Terraform resource google_project_iam_custom_role.cloud_run_operation_viewer
FAIL
FAIL github.com/thingzio/devradar/infra/saas 0.304s
exit 1
```

IAM GREEN and Terraform validation:

```text
$ go test ./infra/saas -run '^TestDeployerOperationPollingIAMIsLeastPrivilege$' -count=1
ok github.com/thingzio/devradar/infra/saas 0.244s

$ make tf-validate
Success! The configuration is valid.
exit 0
```

### Official Cloud Run permission evidence

Google Cloud’s official [Cloud Run IAM roles documentation](https://docs.cloud.google.com/run/docs/reference/iam/roles#click-to-view-the-required-roles-for-deploying-a-container) states that deploying services requires `run.services.get` and `run.operations.get` “to read the status of the service.” The official REST reference identifies the polled resource as [`projects.locations.operations.get`](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.operations/get), separate from service/job resources. This supports the one-permission project custom role while preserving resource-scoped Run administration.

### Final verification

Focused suites:

```text
$ go test -race ./pkg/ratelimit -count=1
ok github.com/thingzio/devradar/pkg/ratelimit 2.994s

$ go test -race ./pkg/data/postgres -run 'Invitation' -count=1
ok github.com/thingzio/devradar/pkg/data/postgres 6.170s

$ go test -race ./pkg/server -run 'Invitation' -count=1
ok github.com/thingzio/devradar/pkg/server 2.594s

$ go test ./infra/saas -count=1
ok github.com/thingzio/devradar/infra/saas 0.312s
```

Full changed-package races:

```text
$ go test -race ./pkg/ratelimit ./pkg/data/postgres ./pkg/server ./infra/saas -count=1
ok github.com/thingzio/devradar/pkg/ratelimit 2.864s
ok github.com/thingzio/devradar/pkg/data/postgres 77.362s
ok github.com/thingzio/devradar/pkg/server 34.911s
ok github.com/thingzio/devradar/infra/saas 1.542s
exit 0
```

Repository gates:

```text
$ make qualify
ok github.com/thingzio/devradar/infra/saas 1.314s
ok github.com/thingzio/devradar/pkg/data/postgres 79.545s coverage: 69.5% of statements
ok github.com/thingzio/devradar/pkg/ratelimit 4.346s coverage: 47.1% of statements
ok github.com/thingzio/devradar/pkg/server 33.595s coverage: 61.5% of statements
Coverage: 67.1% (threshold: 45%)
Coverage check passed
go vet ./...
golangci-lint run --timeout=5m
0 issues.
deploy workflow check: PASS (safe-prefix forward=660s/30m)
Qualification complete
exit 0

$ go build ./...
exit 0

$ make tf-validate
Success! The configuration is valid.
exit 0

$ actionlint
exit 0

$ yamllint .
exit 0

$ git diff --check
exit 0
```

### Self-review

- Transaction isolation: the account lock serializes create outcomes before either quota key is touched. Cross-account requests for one recipient serialize on the recipient quota row. No network I/O occurs in the transaction.
- Rollback: recipient denial and every later error roll back the account counter, recipient counter, invitation, token rotation, outbox, and audit event. Exact duplicates reserve neither counter.
- Authorization and isolation: active account and admin membership are revalidated under the same transaction; all invitation reads remain explicitly account-filtered.
- Secrets: outcomes and redirect messages expose no bearer, token hash, ciphertext, provider error, or delivery identifier.
- IAM: the new role contains exactly `run.operations.get`, has exactly one project binding to the deployer, and broad project `roles/run.admin`/`roles/artifactregistry.writer` remain absent. Existing exact WIF, repository writer, three resource Run grants, scheduler grant, and service-account-user grants remain.
- Scope: no workflow change, migration 033, production feature enablement, push, tag, deploy, plan/apply, or external mutation. `infra/saas/terraform.tfvars` was not accessed.

### Re-review concerns

None outstanding.
