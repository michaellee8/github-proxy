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
    encryption_key_id text NOT NULL,
    token_nonce bytea NOT NULL,
    token_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (name <> ''),
    CHECK (upstream_host <> '')
);

CREATE TABLE IF NOT EXISTS pgh_repositories (
    id bigint PRIMARY KEY,
    owner_name text NOT NULL,
    repository_name text NOT NULL,
    default_branch text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_name, repository_name)
);

CREATE TABLE IF NOT EXISTS pgh_capabilities (
    id text PRIMARY KEY,
    selector text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    credential_id text NOT NULL REFERENCES pgh_credentials(id),
    repository_id bigint NOT NULL REFERENCES pgh_repositories(id),
    policy_name text NOT NULL,
    policy_version integer NOT NULL,
    policy_grants jsonb NOT NULL DEFAULT '{}'::jsonb,
    git_push text NOT NULL DEFAULT 'none',
    git_tags boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(secret_hash) = 32),
    CHECK (policy_version > 0),
    CHECK (git_push IN ('none', 'non-default', 'all'))
);

CREATE INDEX IF NOT EXISTS pgh_capabilities_active_selector_idx
    ON pgh_capabilities(selector)
    WHERE revoked_at IS NULL;
