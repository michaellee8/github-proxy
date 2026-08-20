CREATE TABLE IF NOT EXISTS pgh_schema_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pgh_credentials (
    id text PRIMARY KEY,
    name text NOT NULL UNIQUE,
    upstream_host text NOT NULL,
    api_base_url text NOT NULL,
    api_version text NOT NULL,
    repository_resolution text NOT NULL,
    encryption_key_id text NOT NULL,
    token_nonce bytea NOT NULL,
    token_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (name <> ''),
    CHECK (upstream_host <> ''),
    CHECK (repository_resolution IN ('numeric-id', 'owner-name'))
);

CREATE TABLE IF NOT EXISTS pgh_repositories (
    credential_id text NOT NULL REFERENCES pgh_credentials(id),
    id bigint NOT NULL,
    owner_name text NOT NULL,
    repository_name text NOT NULL,
    default_branch text NOT NULL,
    etag text NOT NULL DEFAULT '',
    validated_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (owner_name <> ''),
    CHECK (repository_name <> ''),
    CHECK (default_branch <> ''),
    PRIMARY KEY (credential_id, id)
);

CREATE TABLE IF NOT EXISTS pgh_capabilities (
    id text PRIMARY KEY,
    selector text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    credential_id text NOT NULL REFERENCES pgh_credentials(id),
    repository_id bigint NOT NULL,
    policy_name text NOT NULL,
    policy_version integer NOT NULL,
    policy_revision bigint NOT NULL DEFAULT 1,
    policy_grants jsonb NOT NULL DEFAULT '{}'::jsonb,
    git_push text NOT NULL DEFAULT 'none',
    git_tags boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    policy_updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(secret_hash) = 32),
    CHECK (policy_version > 0),
    CHECK (policy_revision > 0),
    CHECK (git_push IN ('none', 'non-default', 'all')),
    FOREIGN KEY (credential_id, repository_id)
        REFERENCES pgh_repositories(credential_id, id)
);

CREATE INDEX IF NOT EXISTS pgh_capabilities_active_selector_idx
    ON pgh_capabilities(selector)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS pgh_capability_policy_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    capability_id text NOT NULL REFERENCES pgh_capabilities(id),
    repository_id bigint NOT NULL,
    before_revision bigint NOT NULL,
    after_revision bigint NOT NULL,
    before_policy jsonb NOT NULL,
    after_policy jsonb NOT NULL,
    direction text NOT NULL,
    reason text NOT NULL,
    actor text,
    CHECK (repository_id > 0),
    CHECK (before_revision > 0),
    CHECK (after_revision = before_revision + 1),
    CHECK (direction IN ('broadened', 'narrowed', 'mixed')),
    CHECK (reason <> ''),
    CHECK (octet_length(reason) <= 512),
    CHECK (actor IS NULL OR (actor <> '' AND octet_length(actor) <= 128))
);

CREATE INDEX IF NOT EXISTS pgh_capability_policy_events_capability_idx
    ON pgh_capability_policy_events(capability_id, after_revision DESC, id DESC);

CREATE TABLE IF NOT EXISTS pgh_audit_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    request_id text NOT NULL,
    phase text NOT NULL,
    capability_id text NOT NULL,
    policy_revision bigint NOT NULL,
    repository_id bigint NOT NULL,
    method text NOT NULL,
    request_path text NOT NULL,
    mutation boolean NOT NULL,
    status integer NOT NULL DEFAULT 0,
    duration_ms bigint NOT NULL DEFAULT 0,
    CHECK (request_id <> ''),
    CHECK (phase IN ('preflight', 'result')),
    CHECK (capability_id <> ''),
    CHECK (policy_revision > 0),
    CHECK (repository_id > 0),
    CHECK (method <> ''),
    CHECK (request_path <> ''),
    CHECK (status >= 0),
    CHECK (duration_ms >= 0)
);

CREATE INDEX IF NOT EXISTS pgh_audit_events_occurred_at_idx
    ON pgh_audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS pgh_audit_events_capability_idx
    ON pgh_audit_events(capability_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS pgh_audit_events_repository_idx
    ON pgh_audit_events(repository_id, occurred_at DESC);
