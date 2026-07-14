-- Durable attribution for account-owned mutations. Audit strings are bounded to
-- keep every row readable and index-safe: actions 96 chars, target kinds 64,
-- target identifiers 512, outcomes 32, request correlation 128, and metadata
-- JSON 4096 bytes. Metadata is an object so callers cannot hide unstructured
-- payloads in an array or scalar.
--
-- Account deletion retains the existing hard-delete lifecycle: audit rows
-- cascade with their account, so the platform delete operation is never blocked.
-- Actor references are nullable and SET NULL because users and credentials have
-- independent deletion lifecycles; actor_kind remains the durable attribution.
CREATE TABLE IF NOT EXISTS devradar_audit_event (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id         UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    actor_kind         TEXT NOT NULL CHECK (actor_kind IN ('user','api_token','platform')),
    actor_user_id      UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    actor_api_token_id UUID REFERENCES devradar_api_token(id) ON DELETE SET NULL,
    CONSTRAINT devradar_audit_event_actor_shape CHECK (
        (actor_kind='user' AND actor_api_token_id IS NULL) OR
        (actor_kind='api_token' AND actor_user_id IS NULL) OR
        (actor_kind='platform' AND actor_api_token_id IS NULL)
    ),
    action             TEXT NOT NULL CHECK (
        action=btrim(action) AND char_length(action) BETWEEN 1 AND 96
    ),
    target_type        TEXT NOT NULL CHECK (
        target_type=btrim(target_type) AND char_length(target_type) BETWEEN 1 AND 64
    ),
    target_id          TEXT NOT NULL CHECK (
        target_id=btrim(target_id) AND char_length(target_id) BETWEEN 1 AND 512
    ),
    outcome            TEXT NOT NULL CHECK (
        outcome=btrim(outcome) AND char_length(outcome) BETWEEN 1 AND 32
    ),
    request_id         TEXT NOT NULL CHECK (
        request_id=btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128
    ),
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(metadata)='object' AND octet_length(metadata::text) <= 4096
    ),
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devradar_audit_event_account_time
    ON devradar_audit_event(account_id,occurred_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_devradar_audit_event_actor_user
    ON devradar_audit_event(actor_user_id,occurred_at DESC,id DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devradar_audit_event_actor_token
    ON devradar_audit_event(actor_api_token_id,occurred_at DESC,id DESC)
    WHERE actor_api_token_id IS NOT NULL;

-- Audit rows are append-only except for referential actions initiated by the
-- database itself. Actor deletion may only clear its nullable FK; account
-- deletion retains the table's explicit ON DELETE CASCADE lifecycle.
CREATE OR REPLACE FUNCTION devradar_protect_audit_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF pg_trigger_depth() > 1
           AND NEW.id IS NOT DISTINCT FROM OLD.id
           AND NEW.account_id IS NOT DISTINCT FROM OLD.account_id
           AND NEW.actor_kind IS NOT DISTINCT FROM OLD.actor_kind
           AND (
               NEW.actor_user_id IS NOT DISTINCT FROM OLD.actor_user_id OR
               (OLD.actor_user_id IS NOT NULL AND NEW.actor_user_id IS NULL)
           )
           AND (
               NEW.actor_api_token_id IS NOT DISTINCT FROM OLD.actor_api_token_id OR
               (OLD.actor_api_token_id IS NOT NULL AND NEW.actor_api_token_id IS NULL)
           )
           AND NEW.action IS NOT DISTINCT FROM OLD.action
           AND NEW.target_type IS NOT DISTINCT FROM OLD.target_type
           AND NEW.target_id IS NOT DISTINCT FROM OLD.target_id
           AND NEW.outcome IS NOT DISTINCT FROM OLD.outcome
           AND NEW.request_id IS NOT DISTINCT FROM OLD.request_id
           AND NEW.metadata IS NOT DISTINCT FROM OLD.metadata
           AND NEW.occurred_at IS NOT DISTINCT FROM OLD.occurred_at
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'devradar_audit_event rows are append-only';
    END IF;

    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'devradar_audit_event rows are append-only';
END;
$$;

DROP TRIGGER IF EXISTS devradar_audit_event_append_only ON devradar_audit_event;
CREATE TRIGGER devradar_audit_event_append_only
BEFORE UPDATE OR DELETE ON devradar_audit_event
FOR EACH ROW EXECUTE FUNCTION devradar_protect_audit_event();

-- Personal presentation state. The compatibility devradar_alert.read_at column
-- remains authoritative until the later alert-receipt cutover.
CREATE TABLE IF NOT EXISTS devradar_alert_receipt (
    alert_id   UUID NOT NULL REFERENCES devradar_alert(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES devradar_user(id) ON DELETE CASCADE,
    read_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (alert_id,user_id)
);

CREATE INDEX IF NOT EXISTS idx_devradar_alert_receipt_user_account
    ON devradar_alert_receipt(user_id,account_id,read_at DESC);

-- Backfill only the globally-read compatibility rows, and only for the one
-- legacy user migrated from that account. Invitation-created users have no
-- legacy_tenant_id and therefore receive no historical read state.
INSERT INTO devradar_alert_receipt (alert_id,account_id,user_id,read_at)
SELECT a.id,a.tenant_id,u.id,a.read_at
FROM devradar_alert a
JOIN devradar_user u ON u.legacy_tenant_id=a.tenant_id
WHERE a.read_at IS NOT NULL
ON CONFLICT (alert_id,user_id) DO NOTHING;

-- Session-scoped successor to devradar_token_flash. Keep the legacy table and
-- rows unchanged while old revisions drain; the later cutover moves callers.
CREATE TABLE IF NOT EXISTS devradar_session_token_flash (
    session_id TEXT NOT NULL REFERENCES devradar_session(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    value      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id,account_id)
);

CREATE INDEX IF NOT EXISTS idx_devradar_session_token_flash_expires
    ON devradar_session_token_flash(expires_at);
