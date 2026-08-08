# Existing GitHub credential broker research

Date: 2026-08-07

## Target capability

The target is an off-machine credential broker that holds a broad GitHub PAT and
issues opaque, independently revocable capabilities to long-running coding-agent
machines. Each capability must expose only an explicitly authorized repository
through Git smart HTTP, GitHub REST, and a constrained subset of GitHub GraphQL.
Installing a GitHub App or creating another GitHub account is not available.

No reviewed project provides that complete combination.

## Candidates

### Infisical Agent Vault

Agent Vault is the strongest base candidate. It is a Go credential broker aimed
at remote coding agents and already provides short-lived sessions, hashed opaque
tokens, PostgreSQL storage, audit events, strict-deny operation, credential
injection, and remote/Kubernetes deployment patterns.

Its current service matcher is limited to host, port, and path patterns. It does
not match HTTP method, headers, query parameters, or bodies. That is insufficient
for GitHub because REST can use different methods on the same path and GraphQL
puts all operations behind `POST /graphql`. An open method-restriction change
addresses the REST-method problem, but not GraphQL document authorization. Agent
Vault also does not parse Git receive-pack commands to enforce branch/ref policy.

Verdict: fork it only if the intended product is a general multi-provider agent
credential vault. For a focused GitHub broker, it brings a larger product and
trusted-code surface than required.

Sources:

- [Architecture and features](https://github.com/Infisical/agent-vault/blob/10743832e3dd362afd30c6e9b26b1732ed0d2766/README.md#L24-L63)
- [Service matching limitations](https://github.com/Infisical/agent-vault/blob/10743832e3dd362afd30c6e9b26b1732ed0d2766/docs/learn/services.mdx#L263-L293)
- [Hashed token storage](https://github.com/Infisical/agent-vault/blob/10743832e3dd362afd30c6e9b26b1732ed0d2766/internal/store/sql_store.go#L23-L35)
- [Method-restriction pull request](https://github.com/Infisical/agent-vault/pull/324)

### GitHub Agent Access Broker

`gh-agent-broker` is the closest GitHub-specific design reference. It has
deny-by-default repository, operation, and branch policies; typed REST routes;
limited server-owned GraphQL operations; Git smart HTTP; stable policy errors;
and auditing. Its receive-pack handler parses the command prefix, checks every
ref update, rejects deletion, verifies the old SHA, and streams the pack without
performing full object inspection.

It uses GitHub App installation tokens, static agent credentials, and a narrow
custom CLI. It is not GHES-compatible, does not pursue upstream `gh` parity, and
does not use the desired PostgreSQL capability model.

Verdict: the best donor for Git receive-pack/ref-policy code and tests, but not a
good project base under the no-GitHub-App constraint.

Source: [GitHub Agent Access Broker](https://github.com/grubbyhacker/gh-agent-broker)

### Airlock

Airlock is a small Go reverse proxy for AI-agent egress. It provides an implicit
deny firewall based on method and path, PAT injection, rate limits, telemetry,
timeouts, redaction, and path-normalization tests. It includes a GitHub Git smart
HTTP example covering `info/refs`, `git-upload-pack`, and `git-receive-pack`.

It lacks multi-capability lifecycle and PostgreSQL storage, semantic GraphQL
authorization, repository claim binding, and receive-pack ref parsing.

Verdict: useful source material for request normalization and generic proxy
controls, but not a sufficient broker base.

Source: [Airlock](https://github.com/realugbun/airlock)

### Dependabot Proxy

Dependabot Proxy is designed to inject credentials into trusted, isolated
Dependabot jobs, not to act as an authorization boundary against an autonomous
client. Its GitHub API handler only accepts `GET` and `HEAD`, and its repository
recognition is limited to `/repos/{owner}/{repo}` paths. Its Git handler routes
credentials and forwards Git traffic but does not enforce receive-pack ref
policy. Configuration can also fall back to broader credentials for unmatched
repositories.

Verdict: do not fork it. At most, reuse isolated Git credential-routing ideas or
tests after verifying their assumptions.

Sources:

- [GitHub API method handling](https://github.com/dependabot/proxy/blob/570209bcb7d677efe113afa9f0688bf7a7de94d8/internal/handlers/github_api.go#L127-L129)
- [Repository path extraction](https://github.com/dependabot/proxy/blob/570209bcb7d677efe113afa9f0688bf7a7de94d8/internal/handlers/github_api.go#L165-L172)
- [Credential fallback](https://github.com/dependabot/proxy/blob/570209bcb7d677efe113afa9f0688bf7a7de94d8/internal/handlers/git_server.go#L336-L353)

### FINOS GitProxy

FINOS GitProxy is a mature Git-only policy gateway. It buffers and parses pushes,
creates a temporary clone, and runs pre-receive inspection before forwarding.
That is useful evidence for what semantic commit/file policy requires. It does
not broker GitHub API access, does not hide a server-held PAT, and is written in
TypeScript rather than Go.

Verdict: architecture reference for a future quarantine/semantic inspection
tier, not reusable as the selected transparent ref-only broker.

Source: [GitProxy push parsing](https://github.com/finos/git-proxy/blob/d68c99ad6070798fcbb494990237f43d5ed1dd35/src/proxy/processors/pre-processor/parsePush.ts#L57-L139)

## Excluded approaches

GitHub App token brokers such as Octo STS, Claw, and smaller `gh-token-broker`
projects can mint genuinely repository-scoped GitHub credentials, but require the
App to be installed on the organization or repository. That is the unavailable
permission this broker is intended to replace.

Generic credential injectors such as CyberArk Secretless Broker solve secret
delivery but not GitHub repository authorization, GraphQL operation control, or
Git receive-pack policy.

## Recommendation

Build the focused GitHub broker rather than basing it on Dependabot Proxy. Reuse
selectively:

- Agent Vault's opaque-token, PostgreSQL, session, and audit design patterns.
- `gh-agent-broker`'s receive-pack prefix parser, old-SHA preflight, ref policy,
  and related tests.
- Airlock's request normalization, deny rules, rate limiting, and telemetry
  patterns.
- A pinned upstream `gh` fork for `pgh`, preserving CLI compatibility while
  forcing all destinations through the broker.

Fork Agent Vault instead only if supporting credentials beyond GitHub is a near-
term product requirement. Either route still requires a purpose-built GitHub
policy engine: typed REST route authorization, exact repository binding,
registered GraphQL operation/AST validation, and Git receive-pack ref checks.
