# Quickstart

This starts PostgreSQL and the Broker as loopback-only containers. It is suited
to operator evaluation, not direct `pgh` use: `pgh` expects its Broker host on
HTTPS port 443, so add a trusted TLS reverse proxy before connecting an Agent
Host.

## Start the Broker

Generate deployment secrets in the operator shell. Do not add them to `.env` or
commit them.

```bash
export PGH_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export PGH_ACTIVE_KEY_ID="key-2026-08"
export PGH_ENCRYPTION_KEYS="${PGH_ACTIVE_KEY_ID}:$(openssl rand -base64 32)"

docker compose up --build -d
curl --fail http://127.0.0.1:8080/healthz
```

Migrations run automatically before the Broker starts listening.

## Store an Upstream Credential

Run this only on the trusted operator machine. The PAT is read from standard
input and is never placed in Compose configuration.

```bash
read -rsp "GitHub PAT: " PGH_OPERATOR_PAT
printf '\n'
printf '%s\n' "$PGH_OPERATOR_PAT" |
  docker compose exec -T pgh-broker pgh-broker credential put \
    --name operator-github \
    --host github.com
unset PGH_OPERATOR_PAT
```

The Upstream Credential must already have every GitHub permission that an
issued capability may need. The Broker can reduce that authority but cannot add
permissions missing from the PAT.

## Issue one repository capability

Obtain the immutable repository ID and default branch on the trusted operator
machine, then issue a short-lived token:

```bash
docker compose exec pgh-broker pgh-broker capability issue \
  --credential operator-github \
  --repo OWNER/REPO \
  --repository-id REPOSITORY_ID \
  --default-branch main \
  --policy developer \
  --policy-version 1 \
  --git-push non-default \
  --expires-in 8h
```

The command prints the Capability Token once. Deliver it through your secret
manager, then set these values on the Agent Host:

```bash
export PGH_HOST=broker.example.internal
export PGH_TOKEN='pgh_pat_...'
pgh repo view OWNER/REPO
```

`PGH_HOST` is a hostname, not a URL, and must resolve to the TLS ingress on port
443. `pgh` keeps its configuration separate from `gh` under the pgh config
directory.

For Git HTTPS, use the same hostname and token:

```bash
git clone https://pgh:${PGH_TOKEN}@broker.example.internal/OWNER/REPO.git
```

Avoid embedding the token in a persistent remote URL. Configure a credential
helper or inject the credential for each agent job.

## Revoke a capability

For a token shaped as `pgh_pat_SELECTOR.SECRET`, its administrative ID is
`cap_SELECTOR`:

```bash
docker compose exec pgh-broker pgh-broker capability revoke cap_SELECTOR
```

Destroy the local stack with `docker compose down`. Add `--volumes` only when
you intentionally want to erase the local PostgreSQL data.

## Install the Helm chart

The chart references existing Secrets. Prepare three files that contain exactly
one value each, without a trailing newline:

- `database-url` with the production PostgreSQL URL;
- `encryption-keys` with the complete `key-id:base64` keyring; and
- `active-key-id` with the active key ID.

Create the Secrets and install an image built from `Dockerfile.pgh-broker`:

```bash
kubectl create secret generic pgh-broker-database \
  --from-file=url=/secure/path/database-url
kubectl create secret generic pgh-broker-encryption \
  --from-file=keys=/secure/path/encryption-keys \
  --from-file=active-key-id=/secure/path/active-key-id

helm upgrade --install pgh-broker deploy/helm/pgh-broker \
  --set image.repository=REGISTRY/pgh-broker \
  --set image.tag=IMAGE_TAG
```

The chart creates a private `ClusterIP` Service and does not create an ingress.
Configure your platform's TLS ingress or gateway separately, and restrict its
clients to approved Agent Hosts.
