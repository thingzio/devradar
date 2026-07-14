-- Account invitations retain lifecycle history while allowing only one
-- unaccepted, unrevoked row for an account and normalized recipient. Expiry is
-- intentionally not part of the partial uniqueness predicate: an expired row
-- remains pending until it is refreshed, accepted, or explicitly revoked.
CREATE TABLE IF NOT EXISTS devradar_account_invitation (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    normalized_email    TEXT NOT NULL CHECK (
        normalized_email=lower(btrim(normalized_email)) AND
        char_length(normalized_email) BETWEEN 3 AND 320
    ),
    role                TEXT NOT NULL CHECK (role IN ('admin','editor','reader')),
    invited_by_user_id  UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    token_hash          TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    token_version       INTEGER NOT NULL CHECK (token_version BETWEEN 1 AND 2147483647),
    expires_at          TIMESTAMPTZ NOT NULL,
    accepted_at         TIMESTAMPTZ,
    accepted_by_user_id UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_by_user_id  UUID REFERENCES devradar_user(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT devradar_account_invitation_terminal_state CHECK (
        accepted_at IS NULL OR revoked_at IS NULL
    ),
    CONSTRAINT devradar_account_invitation_time_order CHECK (
        expires_at>created_at AND updated_at>=created_at AND
        (accepted_at IS NULL OR accepted_at>=created_at) AND
        (revoked_at IS NULL OR revoked_at>=created_at)
    ),
    CONSTRAINT devradar_account_invitation_id_account_unique UNIQUE (id,account_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_devradar_account_invitation_pending
    ON devradar_account_invitation(account_id,normalized_email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_devradar_account_invitation_account_created
    ON devradar_account_invitation(account_id,created_at DESC,id DESC);

-- Delivery attempts are at-least-once internally. A provider-stable
-- idempotency key prevents duplicate recipient-visible sends. Only the token
-- payload is encrypted; recipient and lifecycle metadata remain queryable for
-- delivery and administration. Terminal rows retain bounded metadata but
-- permanently scrub ciphertext.
CREATE TABLE IF NOT EXISTS devradar_delivery_outbox (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    kind                    TEXT NOT NULL CHECK (kind IN ('account_invitation')),
    invitation_id           UUID NOT NULL,
    invitation_version      INTEGER NOT NULL CHECK (invitation_version BETWEEN 1 AND 2147483647),
    recipient               TEXT NOT NULL CHECK (
        recipient=lower(btrim(recipient)) AND char_length(recipient) BETWEEN 3 AND 320
    ),
    encrypted_payload       TEXT NOT NULL CHECK (char_length(encrypted_payload)<=4096),
    idempotency_key         TEXT NOT NULL UNIQUE CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
    ),
    status                  TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','leased','delivered','permanently_failed','canceled')
    ),
    attempt_count           INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 10000),
    first_attempt_at        TIMESTAMPTZ,
    next_attempt_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner             TEXT CHECK (
        lease_owner IS NULL OR (lease_owner=btrim(lease_owner) AND char_length(lease_owner) BETWEEN 1 AND 128)
    ),
    lease_expires_at        TIMESTAMPTZ,
    provider_id             TEXT CHECK (
        provider_id IS NULL OR (provider_id=btrim(provider_id) AND char_length(provider_id) BETWEEN 1 AND 256)
    ),
    last_error              TEXT CHECK (last_error IS NULL OR char_length(last_error)<=512),
    delivered_at            TIMESTAMPTZ,
    permanently_failed_at   TIMESTAMPTZ,
    canceled_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT devradar_delivery_outbox_invitation_account_fk
        FOREIGN KEY (invitation_id,account_id)
        REFERENCES devradar_account_invitation(id,account_id) ON DELETE CASCADE,
    CONSTRAINT devradar_delivery_outbox_attempt_shape CHECK (
        (attempt_count=0 AND first_attempt_at IS NULL) OR
        (attempt_count>0 AND first_attempt_at IS NOT NULL)
    ),
    CONSTRAINT devradar_delivery_outbox_state_shape CHECK (
        (status='pending' AND lease_owner IS NULL AND lease_expires_at IS NULL AND
            delivered_at IS NULL AND permanently_failed_at IS NULL AND canceled_at IS NULL AND
            encrypted_payload LIKE 'enc:%') OR
        (status='leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND
            delivered_at IS NULL AND permanently_failed_at IS NULL AND canceled_at IS NULL AND
            encrypted_payload LIKE 'enc:%') OR
        (status='delivered' AND lease_owner IS NULL AND lease_expires_at IS NULL AND
            delivered_at IS NOT NULL AND permanently_failed_at IS NULL AND canceled_at IS NULL AND
            provider_id IS NOT NULL AND encrypted_payload='') OR
        (status='permanently_failed' AND lease_owner IS NULL AND lease_expires_at IS NULL AND
            delivered_at IS NULL AND permanently_failed_at IS NOT NULL AND canceled_at IS NULL AND
            encrypted_payload='') OR
        (status='canceled' AND lease_owner IS NULL AND lease_expires_at IS NULL AND
            delivered_at IS NULL AND permanently_failed_at IS NULL AND canceled_at IS NOT NULL AND
            encrypted_payload='')
    ),
    CONSTRAINT devradar_delivery_outbox_time_order CHECK (
        updated_at>=created_at AND
        (first_attempt_at IS NULL OR first_attempt_at>=created_at) AND
        (delivered_at IS NULL OR delivered_at>=created_at) AND
        (permanently_failed_at IS NULL OR permanently_failed_at>=created_at) AND
        (canceled_at IS NULL OR canceled_at>=created_at)
    )
);

-- Outbox identity is fixed at enqueue. Later invitation rotation intentionally
-- leaves the old row intact so the worker can observe it as stale and scrub it;
-- state transitions therefore validate identity only when inserting and forbid
-- identity rewrites afterward.
CREATE OR REPLACE FUNCTION devradar_validate_delivery_outbox_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.id,NEW.account_id,NEW.kind,NEW.invitation_id,NEW.invitation_version,
               NEW.recipient,NEW.idempotency_key,NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id,OLD.account_id,OLD.kind,OLD.invitation_id,OLD.invitation_version,
               OLD.recipient,OLD.idempotency_key,OLD.created_at)
        THEN
            RAISE EXCEPTION 'delivery outbox identity is immutable'
                USING ERRCODE='check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM devradar_account_invitation i
        WHERE i.id=NEW.invitation_id
          AND i.account_id=NEW.account_id
          AND i.token_version=NEW.invitation_version
          AND i.normalized_email=NEW.recipient
          AND i.accepted_at IS NULL
          AND i.revoked_at IS NULL
          AND i.expires_at>clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'delivery outbox invitation identity is not current'
            USING ERRCODE='check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS devradar_delivery_outbox_identity ON devradar_delivery_outbox;
CREATE TRIGGER devradar_delivery_outbox_identity
BEFORE INSERT OR UPDATE ON devradar_delivery_outbox
FOR EACH ROW EXECUTE FUNCTION devradar_validate_delivery_outbox_identity();

CREATE INDEX IF NOT EXISTS idx_devradar_delivery_outbox_due
    ON devradar_delivery_outbox(next_attempt_at,created_at,id)
    WHERE status='pending';
CREATE INDEX IF NOT EXISTS idx_devradar_delivery_outbox_expired_lease
    ON devradar_delivery_outbox(lease_expires_at,created_at,id)
    WHERE status='leased';
CREATE INDEX IF NOT EXISTS idx_devradar_delivery_outbox_invitation_version
    ON devradar_delivery_outbox(invitation_id,invitation_version,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_devradar_delivery_outbox_account_created
    ON devradar_delivery_outbox(account_id,created_at DESC,id DESC);
