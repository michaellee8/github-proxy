# Policy and compatibility matrix

This matrix describes Policy Profile `developer` version 1. Compatibility is
deny-by-default: an unlisted REST path, GraphQL operation name, Git service, or
LFS operation is rejected before reaching GitHub.

The rows below summarize individually registered method/path patterns. They do
not grant every current or future endpoint beneath a resource prefix.

## Capability policy assignment

The Policy Profile name and version are fixed when a Repository Capability is
issued. An offline operator may replace the active capability's complete set of
additional grants, Git push tier, and tag authority without replacing its
Capability Token. Repository and Upstream Credential bindings, token material,
expiration, and revocation state remain unchanged by policy replacement.

Each effective replacement increments the Policy Revision and appends a
permanent Administrative Event. An identical replacement does neither. Changes
use serialized, last-write-wins transactions and apply when a request resolves
after commit. A request that already resolved may complete under the earlier
policy and records that Policy Revision in both request-audit phases. Expired
and revoked capabilities may be inspected but cannot be changed.

## REST API

| Resource under `/repos/OWNER/REPO` | Read | Default mutation | Additional grant | Notes |
| --- | --- | --- | --- | --- |
| repository metadata | yes | no | none | Repository root accepts `GET` and `HEAD` only. |
| issues, pulls, labels, milestones | yes | registered create/update routes | `pulls.merge` for merge, `pulls.review.dismiss` for review dismissal, and `objects.delete` for registered `DELETE` routes | Issue transfer, sub-issue/dependency relationships, pull update-branch, and unregistered routes are denied. Pull request heads must belong to the Target Repository. |
| Actions | yes | no | `actions.write` | Secrets and variables remain hard denied. |
| check runs, check suites, statuses | yes | no | `checks.write` | |
| commits, contents, Git data | yes | no | `contents.write` | Content branch fields and REST Git-ref writes are checked against Git push policy. Only branch and tag refs are accepted, and REST ref deletion is always denied. |
| deployments | yes | no | `deployments.write` | Deployment refs are checked against Git push policy. |
| releases | yes | no | `releases.write` | Creating a release, or editing its tag or target, also requires tag authority and ref-policy approval. |
| traffic | yes | no | none | |
| collaborators, environments, hooks, invitations, keys, rulesets, security administration | no | no | none | Hard denied. |
| account, organization, search, and other global routes | no | no | none | Requests must be rooted at the Target Repository. |

Known grant names are `actions.write`, `checks.write`, `contents.write`,
`deployments.write`, `objects.delete`, `pulls.merge`,
`pulls.review.dismiss`, and `releases.write`.
Every `DELETE` request also requires `objects.delete`, even when its resource
has a separate write grant. This grant never enables an unregistered route or
Git-ref deletion.

## GraphQL API

The registered query families are `RepositoryInfo`, `IssueList`,
`IssueByNumber`, `IssueNodeID`, `IssueRepositoryInfo`, `IssueTemplates`,
`LabelList`, `PullRequestList`, `PullRequestByNumber`,
`PullRequestForBranch`, `PullRequestTemplates`, `RepositoryIssueTypes`,
`RepositoryLabelList`, `RepositoryMilestoneList`, and
`RepositoryReleaseList`. Each document must contain one named repository-root
query with the variables registered for that family. The Broker replaces
repository variables with the Target Repository.

The only allowed introspection is the exact variable-free `Release_fields`
feature probe emitted by the pinned `gh` release:
`Release: __type(name: "Release") { fields { name } }`. Altered aliases,
directives, variables, or additional selections on that probe are denied.

Nested selections use a recursive field allowlist. This prevents traversal from
the repository into owner repositories, parent or fork repositories,
collaborators, environments, rules, security administration, and other global
graph data. Other introspection, anonymous operations, multiple operations,
mutations, search, global node access, unregistered names, and unreviewed fields
are denied.

Many upstream `gh` commands use other GraphQL shapes, especially global node
lookups and mutations. Those commands
currently fail closed with `PGH_OPERATION_UNKNOWN`; upstream command presence in
`pgh --help` does not imply Broker compatibility. Register and test each
additional family before marking its command compatible.

## Git smart HTTP and LFS

| Operation | `git-push=none` | `git-push=non-default` | `git-push=all` |
| --- | --- | --- | --- |
| fetch/clone | yes | yes | yes |
| push default branch | no | no | yes |
| push other branch | no | yes | yes |
| delete any ref | no | no | no |
| create/update tag | only with `--git-tags` | only with `--git-tags` | only with `--git-tags` |
| LFS download/read locks | yes | yes | yes |
| LFS upload/write lock | no | yes | yes |
| LFS delete lock | no | no | no |

GitHub remains responsible for fast-forward checks, branch protection, object
validity, and workflow side effects. The Broker does not inspect pack contents.
Enabling `--git-tags` also counts as Git write authority for LFS upload and lock
creation, even when `--git-push=none`.

## pgh command status

The REST and GraphQL tables above describe authorization policy, not blanket CLI
compatibility.

The pinned `gh` v2.97.0 tree contains 247 registered command paths: 210 are
runnable and 37 are structural groups or help topics. Every runnable path has
exactly one case in the live command audit. The source-derived manifest in
`internal/pghcmd/testdata/runnable-command-audit.txt` is checked against both the
Cobra tree and the audit tables, so adding or removing an upstream command fails
CI until its outcome is reviewed.

Audit outcomes distinguish:

- successful repository reads forwarded to real `api.github.com`;
- expected Broker policy or operation-registration denials;
- commands that reject the Broker host because upstream supports GitHub.com only;
- local configuration, filesystem, external-process, and noninteractive outcomes.

The command audit is deliberately read-only at the GitHub boundary. Its Broker
uses the configured `GH_TOKEN` for real `GET`, `HEAD`, and registered GraphQL
queries, but a final transport rejects REST mutations before they reach GitHub.
Thus all mutation commands have tested CLI and Broker outcomes without implying
live mutation compatibility or changing repository state. `pgh send-telemetry`
is rejected because upstream creates an HTTP client outside the Broker transport.

Only the following command shapes are currently declared live-endpoint
compatible. Each row runs through the real `pgh` command tree and Broker against
`api.github.com` in `internal/pghcmd/live_integration_test.go`.

| Command shape | Live result |
| --- | --- |
| `pgh repo view OWNER/REPO` | pass |
| `pgh repo view OWNER/REPO --json nameWithOwner` | pass |
| `pgh api repos/OWNER/REPO` | pass |
| `pgh api graphql` with one registered query family | pass; every registered family is forwarded live, with expected GitHub not-found errors accepted only for missing fixture numbers |
| `pgh issue list --repo OWNER/REPO --json number,title` | pass |
| `pgh pr list --repo OWNER/REPO --json number,title` | pass |
| `pgh label list --repo OWNER/REPO --json name` | pass |
| `pgh release list --repo OWNER/REPO --json name,tagName` | pass |
| `pgh workflow list --repo OWNER/REPO --json id,name,path,state` | pass |
| `pgh run list --repo OWNER/REPO --json databaseId,workflowName,status` | pass |
| commands that use an unregistered GraphQL operation | denied |
| account, auth mutation, org, gist, project, codespace, SSH/GPG key, secret, variable, and extension network workflows | denied or unsupported |
| non-HTTPS, alternate-port, arbitrary `--hostname`, redirect, or direct GitHub destination | rejected by the pgh client transport |

Git HTTPS live checks run real `git ls-remote`, shallow clone, and fetch through
the Broker. Explicitly enabled write checks create and remove a non-default
branch and a tag through GitHub's receive-pack endpoint, then verify that deletion
through the Broker is denied. The write opt-in also exercises reversible REST
lifecycles for labels, milestones, issues, comments, reactions, branches, pull
requests, and draft releases. LFS policy has unit coverage but is not yet
declared live-endpoint compatible.

Run the read-only matrix with `script/test-pgh-live.sh`. Temporary-ref tests
require both `PGH_LIVE_ALLOW_WRITES=1` and `PGH_LIVE_DEFAULT_BRANCH`, and first
verify that the configured default branch ref exists. Keep these tests tied to
the pinned `gh` release: a new upstream release can change an internal command
from REST to GraphQL without changing its CLI syntax.
