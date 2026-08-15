-- Covering indexes for every devradar foreign key that had none (2026-08-15
-- schema review of the shared `thingz` instance).
--
-- PostgreSQL indexes the referenced (parent) side of a FK automatically — the
-- PK/unique constraint it points at — but never the referencing (child) side.
-- Without a child index whose LEADING column is the FK column, every parent
-- delete/key-update seq-scans the child to enforce the constraint, holding a
-- row lock on the parent for the duration. Account deletion (which cascades
-- through most of this schema) and user deletion are the operations that pay.
--
-- These tables are small today, so plain CREATE INDEX is correct: the ACCESS
-- EXCLUSIVE lock is momentary. CONCURRENTLY is not an option here anyway —
-- the migration runner applies each file inside a transaction (see applyOne),
-- and CREATE INDEX CONCURRENTLY cannot run in one.
--
-- Sparse nullable attribution columns (who invited / created / revoked) get a
-- partial index. A FK check is `WHERE col = $1`, which never matches NULL, so
-- the planner can prove `col IS NOT NULL` and use the partial index — same as
-- the existing devradar_audit_event actor indexes, at a fraction of the size.

-- ── Sessions ─────────────────────────────────────────────────────────────────
-- Highest-churn table in the schema: a row per browser session, deleted in bulk
-- when a user is removed and on every account delete.
CREATE INDEX IF NOT EXISTS idx_devradar_session_user
    ON devradar_session(user_id);
CREATE INDEX IF NOT EXISTS idx_devradar_session_active_account
    ON devradar_session(active_account_id);

-- ── Alerts ───────────────────────────────────────────────────────────────────
-- Both FKs cascade: deleting a policy or an SBOM must find its alerts, and the
-- alert table grows with every actionable finding event.
CREATE INDEX IF NOT EXISTS idx_devradar_alert_policy
    ON devradar_alert(policy_id);
CREATE INDEX IF NOT EXISTS idx_devradar_alert_sbom
    ON devradar_alert(sbom_id);

-- idx_devradar_alert_receipt_user_account leads with user_id, so account
-- deletion had no usable path into the receipts.
CREATE INDEX IF NOT EXISTS idx_devradar_alert_receipt_account
    ON devradar_alert_receipt(account_id);

-- ── VEX ──────────────────────────────────────────────────────────────────────
-- Statements cascade from their document; documents cascade from the account.
-- Both statement indexes lead with tenant_id, so neither serves document_id.
CREATE INDEX IF NOT EXISTS idx_devradar_vex_document_tenant
    ON devradar_vex_document(tenant_id);
CREATE INDEX IF NOT EXISTS idx_devradar_vex_stmt_document
    ON devradar_vex_statement(document_id);

-- ── Identity ─────────────────────────────────────────────────────────────────
-- Backfilled for every pre-account-model row, so a plain index is the right
-- shape (the column is nullable but densely populated).
CREATE INDEX IF NOT EXISTS idx_devradar_identity_user
    ON devradar_identity(user_id);

-- The session-scoped flash PK is (session_id,account_id); account_id trails.
CREATE INDEX IF NOT EXISTS idx_devradar_session_token_flash_account
    ON devradar_session_token_flash(account_id);

-- ── Membership ───────────────────────────────────────────────────────────────
-- account_id leads the primary key, but user_id is served only by
-- idx_devradar_account_member_user_active, which is partial on
-- `revoked_at IS NULL`. The FK check cannot prove that predicate — a revoked
-- membership is exactly the row the check must still find — so deleting a user
-- seq-scanned the table. Unconditional, unlike the attribution indexes below.
CREATE INDEX IF NOT EXISTS idx_devradar_account_member_user
    ON devradar_account_member(user_id);

-- ── Attribution (sparse, partial) ────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_devradar_account_invitation_invited_by
    ON devradar_account_invitation(invited_by_user_id)
    WHERE invited_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devradar_account_invitation_accepted_by
    ON devradar_account_invitation(accepted_by_user_id)
    WHERE accepted_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devradar_account_invitation_revoked_by
    ON devradar_account_invitation(revoked_by_user_id)
    WHERE revoked_by_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devradar_account_member_created_by
    ON devradar_account_member(created_by_user_id)
    WHERE created_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devradar_account_member_revoked_by
    ON devradar_account_member(revoked_by_user_id)
    WHERE revoked_by_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devradar_api_token_created_by
    ON devradar_api_token(created_by_user_id)
    WHERE created_by_user_id IS NOT NULL;
