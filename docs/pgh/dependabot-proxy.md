# Dependabot Proxy reuse decision

The Broker does not fork or deploy
[`dependabot/proxy`](https://github.com/dependabot/proxy).

Dependabot Proxy injects credentials into trusted, isolated dependency update
jobs. This Broker assumes the client may be an autonomous, long-running Agent
Host and must itself enforce repository and operation scope.

Dependabot Proxy is useful reference code for Git credential routing and
streaming behavior, but its security contract is insufficient here:

- its GitHub API handler is oriented around read-only `GET` and `HEAD` traffic;
- repository extraction does not provide the full REST, GraphQL, Git, and LFS
  Compatibility Operation model;
- Git forwarding does not enforce receive-pack branch and tag policy; and
- credential fallback behavior is unsuitable for a deny-by-default capability
  boundary.

Selective reuse must stay small, attributed, and testable at the Broker's public
request interface. The architecture remains a purpose-built GitHub Broker with
opaque capabilities, exact Target Repository binding, parsed GraphQL operation
families, and Git ref authorization.

The broader candidate review is recorded in
[`docs/research/existing-github-credential-brokers.md`](../research/existing-github-credential-brokers.md).
