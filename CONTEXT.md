# Repository Access Broker

This context describes repository-scoped authority for GitHub tooling used by
long-running coding agents.

## Language

**Agent Host**:
An untrusted machine that runs autonomous coding agents and holds only Broker-issued credentials.
_Avoid_: Sandbox, devbox, trusted client

**pgh**:
The agent-facing GitHub CLI that preserves supported `gh` behavior while addressing only a Broker.
_Avoid_: gh wrapper, security boundary

**Broker**:
The trusted authority that holds Upstream Credentials and enforces repository and operation scope.
_Avoid_: Proxy, gateway, token forwarder

**Upstream Identity**:
The GitHub user whose authority the Broker exercises through an Upstream Credential.
_Avoid_: Agent user, capability owner

**Upstream Credential**:
An encrypted GitHub PAT held by the Broker and never disclosed to an Agent Host.
_Avoid_: Capability Token, client token

**Capability Token**:
An opaque, revocable bearer credential that grants one Agent Host a defined Repository Capability.
_Avoid_: GitHub PAT, upstream token

**Target Repository**:
The immutable GitHub repository identity bound to a Repository Capability. Its
canonical owner/name and default branch are mutable Repository Observations.
_Avoid_: Requested repository, current repo

**Repository Observation**:
Broker-verified mutable metadata for a Target Repository, including its canonical
owner/name and default branch at a recorded validation time.
_Avoid_: Repository identity, operator-supplied repository metadata

**Repository Capability**:
The association of one Capability Token with one Target Repository, one Upstream
Credential, and one Policy Profile. The repository and credential bindings,
profile name and version, token secret, and expiration are fixed after issue.
Policy replacement does not alter revocation. An operator may replace the
capability's additional grants and Git ref authority while it is active.
_Avoid_: Login, session, GitHub scope

**Policy Profile**:
A versioned set of permitted Compatibility Operations and configurable Git ref
authority. A Repository Capability fixes the profile name and version at issue
time, while its assignment of additional grants and Git controls may change.
_Avoid_: Route list, GitHub scope

**Policy Revision**:
A monotonically increasing number that identifies the exact policy assignment
resolved for a request. A Repository Capability starts at revision 1 and gains
a new revision after each effective policy replacement.
_Avoid_: Policy Profile version, token version

**Compatibility Operation**:
A recognized `pgh`, REST, GraphQL, Git, or LFS behavior that the Broker can authorize as one operation.
_Avoid_: Arbitrary request, endpoint passthrough

**Direct Containment**:
The guarantee that the Broker exercises an Upstream Credential directly against
only the Target Repository. Effects caused by repository-owned workflows,
webhooks, or other automation are outside this guarantee.
_Avoid_: Sandbox, effect containment, workflow isolation

**Audit Event**:
A redacted record of a Broker authorization decision and its upstream outcome,
attributable to a Repository Capability without containing credential material.
_Avoid_: Request log, token log, request-body archive

**Administrative Event**:
A permanent, append-only record of an effective operator change to a Repository
Capability's policy assignment, including its before and after Policy Revisions
and policies, direction, reason, optional actor label, and timestamp.
_Avoid_: Audit Event, request log
