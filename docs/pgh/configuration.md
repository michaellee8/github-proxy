# Configuration and key rotation

## Broker environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `PGH_DATABASE_URL` | yes | PostgreSQL connection URL. Missing `sslmode` defaults to `verify-full`; all weaker modes are rejected unless the development override is enabled. |
| `PGH_ENCRYPTION_KEYS` | yes | Comma-separated `key-id:base64` entries. Every decoded key must be exactly 32 bytes. |
| `PGH_ACTIVE_KEY_ID` | yes | Key used to encrypt new or replaced Upstream Credentials. It must exist in the keyring. |
| `PGH_LISTEN_ADDR` | no | HTTP address, default `127.0.0.1:8080`. The container and Helm chart set `0.0.0.0:8080` inside their network boundary. |
| `PGH_REPOSITORY_CACHE_TTL` | no | Successful read-observation lifetime, default `30s` and capped at `5m`. Mutations always revalidate. |
| `PGH_AUDIT_RETENTION` | no | PostgreSQL audit retention, default `2160h` (90 days). Serving deletes expired events automatically. |
| `PGH_ALLOW_INSECURE_DATABASE` | no | Set to exactly `true` only for a local development database that cannot use `verify-full`. |

The process validates and connects to PostgreSQL, then applies embedded
migrations before listening. Configuration errors fail startup.

Each replica admits at most 300 reads and 60 mutations per capability per
minute, with eight concurrent requests. Configure deployment-wide limits and
request duration at the reverse proxy.

Kubernetes Ingress annotations are controller-specific, so the chart does not
invent portable settings for them. Before exposing the Service, configure the
selected reverse proxy with header, idle, and total-duration limits plus a
deployment-wide request rate. Restrict its frontend to the approved Agent Host
network; in the NetBird deployment shape, the Broker hostname must not be
reachable outside approved NetBird peers.

Do not place PATs in these variables. Add or replace an Upstream Credential with
`pgh-broker credential put`; the command reads exactly one non-empty token from
standard input. Compose expects deployment secrets in the operator environment.
The Helm chart expects existing Kubernetes Secret references and does not render
secret values into a release manifest.

Credentials use immutable numeric repository lookup by default. For a GitHub
Enterprise host that does not support `/repositories/ID`, explicitly select the
weaker compatibility mode with `credential put --repository-resolution
owner-name`. The Broker still checks the returned ID and accepts at most one
same-authority permanent redirect.

## Agent Host environment

| Variable | Meaning |
| --- | --- |
| `PGH_HOST` | Broker TLS hostname without a scheme or port. Direct GitHub hosts are rejected. |
| `PGH_TOKEN` | Capability Token. This takes precedence over `GH_TOKEN`. |
| `PGH_CONFIG_DIR` | Optional isolated pgh configuration directory. |

`GH_HOST` and `GH_TOKEN` are compatibility fallbacks. Prefer the `PGH_*` names so
an existing `gh` login cannot be confused with a Broker capability.

## Rotate an encryption key

Key rotation has two phases because existing rows retain the key ID that sealed
them.

1. Add a new 32-byte key to `PGH_ENCRYPTION_KEYS` while retaining every old key.
2. Set `PGH_ACTIVE_KEY_ID` to the new key and restart all Broker instances.
3. Re-run `credential put --name NAME` for every stored credential. The upsert
   encrypts the replacement PAT with the active key without invalidating issued
   capabilities that reference the credential name.
4. Verify that no `pgh_credentials.encryption_key_id` row references the old key.
5. Remove the old key from all Broker instances and restart them together.

Never remove an old key before every credential has been re-encrypted. The
Broker intentionally fails capability resolution when the row's key ID is not
available.

## Inspect request audits

Audit records contain method, path, repository and capability IDs, result
status, and timing. They never contain headers, query strings, request bodies,
or credentials.

```bash
pgh-broker audit list --capability cap_SELECTOR --since 2026-08-01T00:00:00Z --limit 100
```

## Rotate an Upstream Credential

Run `credential put` again with the same `--name`. New requests for every linked
capability use the replacement token. Revoke the old PAT at GitHub after a
successful Broker request confirms the replacement works.

## Backup and restore

Back up PostgreSQL and the encryption keyring separately. A database backup
without its referenced keys cannot recover Upstream Credentials; possession of
both has the same sensitivity as the stored PATs. Test restores in an isolated
network and keep the Broker stopped until the keyring is present.
