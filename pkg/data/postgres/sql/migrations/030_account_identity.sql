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
UPDATE devradar_tenant SET name=left(btrim(email),80) WHERE name='';
ALTER TABLE devradar_tenant ADD CONSTRAINT devradar_tenant_name_valid CHECK (
    name='' OR (name=btrim(name) AND char_length(name) BETWEEN 1 AND 80)
);

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

CREATE INDEX idx_devradar_account_member_user_active
    ON devradar_account_member(user_id,account_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_devradar_account_member_account_role_active
    ON devradar_account_member(account_id,role)
    WHERE revoked_at IS NULL;

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
