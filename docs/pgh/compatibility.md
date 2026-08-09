# Policy and compatibility matrix

This matrix describes Policy Profile `developer` version 1. Compatibility is
deny-by-default: an unlisted REST path, GraphQL operation name, Git service, or
LFS operation is rejected before reaching GitHub.

The rows below summarize individually registered method/path patterns. They do
not grant every current or future endpoint beneath a resource prefix.

## REST API

| Resource under `/repos/OWNER/REPO` | Read | Default mutation | Additional grant | Notes |
| --- | --- | --- | --- | --- |
| repository metadata | yes | no | none | Repository root accepts `GET` and `HEAD` only. |
| issues, pulls, labels, milestones | yes | registered create/update routes | `objects.delete` for registered `DELETE` routes | Includes pull request merge routes. Issue transfer, sub-issue/dependency relationships, pull update-branch, and unregistered routes are denied. Pull request heads must belong to the Target Repository. |
| Actions | yes | no | `actions.write` | Secrets and variables remain hard denied. |
| check runs, check suites, statuses | yes | no | `checks.write` | |
| commits, contents, Git data | yes | no | `contents.write` | Content branch fields and REST Git-ref writes are checked against Git push policy. Only branch and tag refs are accepted, and REST ref deletion is always denied. |
| deployments | yes | no | `deployments.write` | Deployment refs are checked against Git push policy. |
| releases | yes | no | `releases.write` | Creating a release, or editing its tag or target, also requires tag authority and ref-policy approval. |
| traffic | yes | no | none | |
| collaborators, environments, hooks, invitations, keys, rulesets, security administration | no | no | none | Hard denied. |
| account, organization, search, and other global routes | no | no | none | Requests must be rooted at the Target Repository. |

Known grant names are `actions.write`, `checks.write`, `contents.write`,
`deployments.write`, `objects.delete`, and `releases.write`.
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
compatibility. Only the following pinned `gh` v2.97.0 command shapes are declared
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
through the Broker is denied. LFS policy has unit coverage but is not yet declared
live-endpoint compatible.

Run the read-only matrix with `scripts/test-pgh-live.sh`. Temporary-ref tests
require both `PGH_LIVE_ALLOW_WRITES=1` and `PGH_LIVE_DEFAULT_BRANCH`, and first
verify that the configured default branch ref exists. Keep these tests tied to
the pinned `gh` release: a new upstream release can change an internal command
from REST to GraphQL without changing its CLI syntax.
