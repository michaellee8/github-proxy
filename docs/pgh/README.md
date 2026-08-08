# pgh operator guide

`pgh` is a pinned fork of GitHub CLI that addresses only a repository access
Broker. The Broker holds an encrypted Upstream Credential and issues opaque,
revocable Capability Tokens for one Target Repository and Policy Profile.

- [Architecture and threat model](architecture.md)
- [Quickstart](quickstart.md)
- [Configuration and key rotation](configuration.md)
- [Policy and compatibility matrix](compatibility.md)
- [Upgrading the upstream gh release](upgrading.md)
- [Why this does not use Dependabot Proxy](dependabot-proxy.md)
