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

// NewPostgresStore constructs a store over an initialized PostgreSQL pool.
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
    id, name, upstream_host, api_base_url, api_version, repository_resolution,
    encryption_key_id, token_nonce, token_ciphertext
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (name) DO UPDATE SET
    upstream_host = EXCLUDED.upstream_host,
    api_base_url = EXCLUDED.api_base_url,
    api_version = EXCLUDED.api_version,
    repository_resolution = EXCLUDED.repository_resolution,
    encryption_key_id = EXCLUDED.encryption_key_id,
    token_nonce = EXCLUDED.token_nonce,
    token_ciphertext = EXCLUDED.token_ciphertext,
    updated_at = now()`,
		credential.ID, credential.Name, credential.UpstreamHost, credential.APIBaseURL, credential.APIVersion, credential.RepositoryResolution,
		credential.Token.KeyID, credential.Token.Nonce, credential.Token.Ciphertext,
	)
	if err != nil {
		return fmt.Errorf("store upstream credential: %w", err)
	}
	return nil
}

// CredentialByName loads a named encrypted Upstream Credential.
func (s *PostgresStore) CredentialByName(ctx context.Context, name string) (StoredCredential, error) {
	var credential StoredCredential
	err := s.pool.QueryRow(ctx, `
SELECT id, name, upstream_host, api_base_url, api_version, repository_resolution,
       encryption_key_id, token_nonce, token_ciphertext
FROM pgh_credentials
WHERE name = $1`, name).Scan(
		&credential.ID, &credential.Name, &credential.UpstreamHost, &credential.APIBaseURL, &credential.APIVersion, &credential.RepositoryResolution,
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

// CreateCapability stores a capability without changing existing repository bindings.
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
INSERT INTO pgh_repositories (credential_id, id, owner_name, repository_name, default_branch, etag, validated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (credential_id, id) DO UPDATE SET
    owner_name = EXCLUDED.owner_name,
    repository_name = EXCLUDED.repository_name,
    default_branch = EXCLUDED.default_branch,
    etag = EXCLUDED.etag,
    validated_at = EXCLUDED.validated_at,
    updated_at = now()`,
		capability.CredentialID, capability.Repository.ID, capability.Repository.Owner, capability.Repository.Name, capability.Repository.DefaultBranch,
		capability.Repository.ETag, capability.Repository.ValidatedAt,
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

// CapabilityBySelector loads the capability material needed for authentication.
func (s *PostgresStore) CapabilityBySelector(ctx context.Context, selector string) (StoredCapability, error) {
	var capability StoredCapability
	var grants []byte
	err := s.pool.QueryRow(ctx, `
SELECT c.id, c.selector, c.secret_hash, c.credential_id,
       r.id, r.owner_name, r.repository_name, r.default_branch, r.etag, r.validated_at,
       c.policy_name, c.policy_version, c.policy_grants, c.git_push, c.git_tags, c.expires_at, c.revoked_at,
       u.id, u.name, u.upstream_host, u.api_base_url, u.api_version, u.repository_resolution,
       u.encryption_key_id, u.token_nonce, u.token_ciphertext
FROM pgh_capabilities c
JOIN pgh_repositories r ON r.credential_id = c.credential_id AND r.id = c.repository_id
JOIN pgh_credentials u ON u.id = c.credential_id
WHERE c.selector = $1`, selector).Scan(
		&capability.ID, &capability.Selector, &capability.SecretHash, &capability.CredentialID,
		&capability.Repository.ID, &capability.Repository.Owner, &capability.Repository.Name, &capability.Repository.DefaultBranch,
		&capability.Repository.ETag, &capability.Repository.ValidatedAt,
		&capability.Policy.Name, &capability.Policy.Version, &grants, &capability.Policy.Git.Push, &capability.Policy.Git.Tags, &capability.ExpiresAt, &capability.RevokedAt,
		&capability.Credential.ID, &capability.Credential.Name, &capability.Credential.UpstreamHost,
		&capability.Credential.APIBaseURL, &capability.Credential.APIVersion, &capability.Credential.RepositoryResolution,
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

// UpdateRepositoryObservation persists canonical mutable metadata after identity verification.
func (s *PostgresStore) UpdateRepositoryObservation(ctx context.Context, credentialID string, repository Repository) error {
	result, err := s.pool.Exec(ctx, `
UPDATE pgh_repositories
SET owner_name = $3, repository_name = $4, default_branch = $5,
    etag = $6, validated_at = $7, updated_at = now()
WHERE credential_id = $1 AND id = $2`, credentialID, repository.ID, repository.Owner, repository.Name, repository.DefaultBranch, repository.ETag, repository.ValidatedAt)
	if err != nil {
		return fmt.Errorf("update repository observation: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrRepositoryIdentity
	}
	return nil
}

// RecordAuditEvent appends one redacted Broker request event.
func (s *PostgresStore) RecordAuditEvent(ctx context.Context, event AuditEvent) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL store is unavailable")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO pgh_audit_events (
    occurred_at, request_id, phase, capability_id, repository_id,
    method, request_path, mutation, status, duration_ms
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		event.OccurredAt, event.RequestID, event.Phase, event.CapabilityID, event.RepositoryID,
		event.Method, event.Path, event.Mutation, event.Status, event.DurationMS,
	)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns newest-first audit records for offline inspection.
func (s *PostgresStore) ListAuditEvents(ctx context.Context, query AuditQuery) ([]AuditEvent, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("PostgreSQL store is unavailable")
	}
	if query.Limit <= 0 || query.Limit > 1000 {
		return nil, errors.New("audit query limit must be between 1 and 1000")
	}
	var repositoryID any
	if query.RepositoryID != nil {
		repositoryID = *query.RepositoryID
	}
	var since any
	if query.Since != nil {
		since = *query.Since
	}
	rows, err := s.pool.Query(ctx, `
SELECT occurred_at, request_id, phase, capability_id, repository_id,
       method, request_path, mutation, status, duration_ms
FROM pgh_audit_events
WHERE ($1::text = '' OR capability_id = $1)
  AND ($2::bigint IS NULL OR repository_id = $2)
  AND ($3::timestamptz IS NULL OR occurred_at >= $3)
ORDER BY occurred_at DESC, id DESC
LIMIT $4`, query.CapabilityID, repositoryID, since, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	events := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(
			&event.OccurredAt, &event.RequestID, &event.Phase, &event.CapabilityID, &event.RepositoryID,
			&event.Method, &event.Path, &event.Mutation, &event.Status, &event.DurationMS,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		event.Event = "broker_request"
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit events: %w", err)
	}
	return events, nil
}

// DeleteAuditEventsBefore applies the configured audit retention cutoff.
func (s *PostgresStore) DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("PostgreSQL store is unavailable")
	}
	result, err := s.pool.Exec(ctx, `DELETE FROM pgh_audit_events WHERE occurred_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired audit events: %w", err)
	}
	return result.RowsAffected(), nil
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
var _ AuditArchive = (*PostgresStore)(nil)
