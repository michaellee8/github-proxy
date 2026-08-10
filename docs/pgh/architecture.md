# Architecture and threat model

## Trust boundary

The Agent Host is untrusted. It receives only a Capability Token and never
receives the GitHub PAT. `pgh` prevents accidental direct GitHub access, but it
is not the authorization boundary. The Broker and its PostgreSQL database are
trusted and must run outside the Agent Host.

The Broker guarantees direct containment: it forwards authenticated requests
only to the Target Repository. GitHub-side effects caused by permitted work,
including notifications, Actions, integrations, and other repository
automation, are outside that containment guarantee.

```text
Agent Host               Trusted network                  GitHub

pgh / git  -- TLS -->  ingress  -- HTTP -->  Broker  -- TLS --> API / Git / LFS
    |                                           |
Capability Token                            PostgreSQL
                                           encrypted PAT
```

Administrative commands run through the `pgh-broker` binary and connect
directly to PostgreSQL. There is no administrative HTTP API.

## Enforced controls

- A Capability Token resolves to one immutable GitHub repository ID, canonical
  owner/name, one stored Upstream Credential, and one versioned Policy Profile.
  Issuing another capability cannot change an existing repository row.
- Only a SHA-256 hash of the capability secret is stored. Tokens can expire and
  can be revoked immediately.
- Upstream Credentials are encrypted with AES-256-GCM and a named key before
  storage. The ciphertext is authenticated against the credential ID and
  upstream destination metadata. Plaintext is recovered only for an authorized
  upstream request.
- Target Repository identity is revalidated before every mutation. Reads use a
  short successful-observation cache, never stale data after a refresh error.
- REST requests must use a registered method and repository-relative path. The
  Broker rebuilds the upstream URL from trusted repository data and replaces
  client authorization headers. REST Git-ref writes use the same branch and tag
  policy as Git smart HTTP, ref deletion is never registered, and pull request
  heads cannot name another repository.
- GraphQL documents are parsed with size and token limits. Only registered
  operation families rooted at the Target Repository are accepted, and trusted
  owner/name variables replace client values. Nested selections must also use a
  reviewed field allowlist. Author, owner, assignee, and review-request paths
  enter a restricted identity projection that blocks traversal back into the
  wider GitHub graph. One exact, variable-free `Release_fields` schema probe is
  allowed for pinned `gh` feature detection; all other introspection is denied.
- Git smart HTTP is bound to the Target Repository. Push authorization parses
  receive-pack ref commands, rejects ref deletion, and applies branch and tag
  policy before streaming pack data.
- Git LFS operations use the same repository binding and Git write policy.
- Redacted request audits go to PostgreSQL and structured JSON logs. A mutation
  is denied unless its preflight event is durable; a read may continue during a
  database audit outage only after its structured event is emitted.
- Every replica applies separate per-capability read and mutation rates plus a
  concurrency ceiling. The reverse proxy owns deployment-wide limits and
  request duration.
- `pgh` sends capability-bearing HTTP only over HTTPS to the exact configured
  broker authority. Alternate ports, redirects to another authority, and direct
  GitHub destinations fail closed.
- `pgh` disables upstream telemetry, rejects the hidden `send-telemetry`
  command, and places extension data and state beneath `PGH_CONFIG_DIR`. This
  prevents direct telemetry egress and prevents `pgh extension` commands from
  reading or modifying the user's original `gh` extensions.

## Deliberate limits

The Broker limits where an agent can exercise the Upstream Identity. It does not
make autonomous code changes safe by itself.

- REST authorization evaluates registered methods and normalized paths, plus
  ref-bearing bodies for workflow dispatch, content writes, deployments, and
  releases, REST Git-ref paths and bodies, and pull request heads. It does not
  model every field or query parameter accepted by every GitHub endpoint.
- GraphQL is intentionally incomplete. Unregistered operation names, global
  node lookups, mutations, and newly used fields fail closed until their scope
  and identifier provenance are reviewed.
- Git pack contents are not inspected. A permitted push can change any file,
  including workflow files, and GitHub decides whether an update is fast-forward
  and whether branch rules allow it.
- The `developer` profile permits issue, pull request, label, and milestone
  mutations. Agent actions can still notify people, trigger automation, consume
  quotas, or disclose repository data through permitted channels.
- The Broker does not provide semantic commit quarantine. A permitted Git push
  is treated as workflow-capable regardless of which files it changes.
- `/healthz` proves that the process is serving HTTP. It does not continuously
  test PostgreSQL or GitHub connectivity.

Treat a compromised Capability Token as access to every operation in its Policy
Profile until it expires or is revoked. Prefer short expiration times, a
dedicated Upstream Credential, restrictive Git push settings, GitHub branch
protection, and network egress controls on the Agent Host.

## Network requirements

The Broker serves HTTP and does not terminate TLS. Put an authenticated network
boundary and TLS ingress in front of it. Agent Hosts must use a broker DNS name
whose certificate is trusted by `pgh` and Git. Do not expose PostgreSQL or the
Broker's plain HTTP port to Agent Hosts or the public Internet.
