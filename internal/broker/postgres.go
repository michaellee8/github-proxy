package broker

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// PostgresStore persists credentials and capabilities in PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Migrate applies embedded, append-only schema migrations transactionally.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("PostgreSQL pool is required")
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS pgh_schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("initialize schema migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var applied bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pgh_schema_migrations WHERE name = $1)`, entry.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if applied {
			continue
		}
		sql, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pgh_schema_migrations(name) VALUES ($1)`, entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// PutCredential creates or rotates a named encrypted Upstream Credential.
func (s *PostgresStore) PutCredential(ctx context.Context, credential StoredCredential) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL store is unavailable")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO pgh_credentials (
    id, name, upstream_host, api_base_url, api_version,
    encryption_key_id, token_nonce, token_ciphertext
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (name) DO UPDATE SET
    upstream_host = EXCLUDED.upstream_host,
    api_base_url = EXCLUDED.api_base_url,
    api_version = EXCLUDED.api_version,
    encryption_key_id = EXCLUDED.encryption_key_id,
    token_nonce = EXCLUDED.token_nonce,
    token_ciphertext = EXCLUDED.token_ciphertext,
    updated_at = now()`,
		credential.ID, credential.Name, credential.UpstreamHost, credential.APIBaseURL, credential.APIVersion,
		credential.Token.KeyID, credential.Token.Nonce, credential.Token.Ciphertext,
	)
	if err != nil {
		return fmt.Errorf("store upstream credential: %w", err)
	}
	return nil
}

func (s *PostgresStore) CredentialByName(ctx context.Context, name string) (StoredCredential, error) {
	var credential StoredCredential
	err := s.pool.QueryRow(ctx, `
SELECT id, name, upstream_host, api_base_url, api_version,
       encryption_key_id, token_nonce, token_ciphertext
FROM pgh_credentials
WHERE name = $1`, name).Scan(
		&credential.ID, &credential.Name, &credential.UpstreamHost, &credential.APIBaseURL, &credential.APIVersion,
		&credential.Token.KeyID, &credential.Token.Nonce, &credential.Token.Ciphertext,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCredential{}, ErrCredentialNotFound
	}
	if err != nil {
		return StoredCredential{}, fmt.Errorf("load upstream credential: %w", err)
	}
	return credential, nil
}

func (s *PostgresStore) CreateCapability(ctx context.Context, capability StoredCapability) error {
	grants, err := json.Marshal(capability.Policy.Grants)
	if err != nil {
		return fmt.Errorf("encode policy grants: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin capability issue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO pgh_repositories (id, owner_name, repository_name, default_branch)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
    owner_name = EXCLUDED.owner_name,
    repository_name = EXCLUDED.repository_name,
    default_branch = EXCLUDED.default_branch,
    updated_at = now()`,
		capability.Repository.ID, capability.Repository.Owner, capability.Repository.Name, capability.Repository.DefaultBranch,
	); err != nil {
		return fmt.Errorf("store target repository: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO pgh_capabilities (
    id, selector, secret_hash, credential_id, repository_id,
    policy_name, policy_version, policy_grants, git_push, git_tags, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		capability.ID, capability.Selector, capability.SecretHash, capability.CredentialID, capability.Repository.ID,
		capability.Policy.Name, capability.Policy.Version, grants, capability.Policy.Git.Push, capability.Policy.Git.Tags, capability.ExpiresAt,
	); err != nil {
		return fmt.Errorf("store repository capability: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit repository capability: %w", err)
	}
	return nil
}

func (s *PostgresStore) CapabilityBySelector(ctx context.Context, selector string) (StoredCapability, error) {
	var capability StoredCapability
	var grants []byte
	err := s.pool.QueryRow(ctx, `
SELECT c.id, c.selector, c.secret_hash, c.credential_id,
       r.id, r.owner_name, r.repository_name, r.default_branch,
       c.policy_name, c.policy_version, c.policy_grants, c.git_push, c.git_tags, c.expires_at, c.revoked_at,
       u.id, u.name, u.upstream_host, u.api_base_url, u.api_version,
       u.encryption_key_id, u.token_nonce, u.token_ciphertext
FROM pgh_capabilities c
JOIN pgh_repositories r ON r.id = c.repository_id
JOIN pgh_credentials u ON u.id = c.credential_id
WHERE c.selector = $1`, selector).Scan(
		&capability.ID, &capability.Selector, &capability.SecretHash, &capability.CredentialID,
		&capability.Repository.ID, &capability.Repository.Owner, &capability.Repository.Name, &capability.Repository.DefaultBranch,
		&capability.Policy.Name, &capability.Policy.Version, &grants, &capability.Policy.Git.Push, &capability.Policy.Git.Tags, &capability.ExpiresAt, &capability.RevokedAt,
		&capability.Credential.ID, &capability.Credential.Name, &capability.Credential.UpstreamHost,
		&capability.Credential.APIBaseURL, &capability.Credential.APIVersion,
		&capability.Credential.Token.KeyID, &capability.Credential.Token.Nonce, &capability.Credential.Token.Ciphertext,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCapability{}, ErrCapabilityNotFound
	}
	if err != nil {
		return StoredCapability{}, fmt.Errorf("load repository capability: %w", err)
	}
	if err := json.Unmarshal(grants, &capability.Policy.Grants); err != nil {
		return StoredCapability{}, fmt.Errorf("decode policy grants: %w", err)
	}
	return capability, nil
}

// RevokeCapability prevents all future uses of a Capability Token.
func (s *PostgresStore) RevokeCapability(ctx context.Context, id string, at time.Time) error {
	result, err := s.pool.Exec(ctx, `UPDATE pgh_capabilities SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	if err != nil {
		return fmt.Errorf("revoke capability: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrCapabilityNotFound
	}
	return nil
}

var _ CapabilityStore = (*PostgresStore)(nil)
