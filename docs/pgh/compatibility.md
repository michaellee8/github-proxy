# Policy and compatibility matrix

This matrix describes Policy Profile `developer` version 1. Compatibility is
deny-by-default: an unlisted REST path, GraphQL operation name, Git service, or
LFS operation is rejected before reaching GitHub.

## REST API

| Resource under `/repos/OWNER/REPO` | Read | Default mutation | Additional grant | Notes |
| --- | --- | --- | --- | --- |
| repository metadata | yes | no | none | Repository root accepts `GET` and `HEAD` only. |
| issues, pulls, labels, milestones | yes | create/update | `objects.delete` for `DELETE` | Includes pull request merge routes. |
| Actions | yes | no | `actions.write` | Secrets and variables remain hard denied. |
| check runs, check suites, statuses | yes | no | `checks.write` | |
| commits, contents, Git data | yes | no | `contents.write` | Content branch fields are checked against Git push policy. |
| deployments | yes | no | `deployments.write` | Deployment refs are checked against Git push policy. |
| releases | yes | no | `releases.write` | Creating a release also requires tag authority. |
| traffic | yes | no | none | |
| collaborators, environments, hooks, invitations, keys, rulesets, security administration | no | no | none | Hard denied. |
| account, organization, search, and other global routes | no | no | none | Requests must be rooted at the Target Repository. |

Known grant names are `actions.write`, `checks.write`, `contents.write`,
`deployments.write`, `objects.delete`, and `releases.write`.
Every `DELETE` request also requires `objects.delete`, even when its resource
has a separate write grant.

## GraphQL API

The registered query families are `RepositoryInfo`, `IssueList`,
`IssueByNumber`, `IssueNodeID`, `IssueRepositoryInfo`, `IssueTemplates`,
`LabelList`, `PullRequestList`, `PullRequestByNumber`,
`PullRequestForBranch`, `PullRequestTemplates`, `RepositoryIssueTypes`,
`RepositoryLabelList`, and `RepositoryMilestoneList`. Each document must
contain one named repository-root query with the variables registered for that
family. The Broker replaces repository variables with the Target Repository.

Nested selections use a recursive field allowlist. This prevents traversal from
the repository into owner repositories, parent or fork repositories,
collaborators, environments, rules, security administration, and other global
graph data. Introspection, anonymous operations, multiple operations,
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

| Command shape | Status |
| --- | --- |
| `pgh api repos/OWNER/REPO/...` using a listed REST operation | supported |
| `pgh api graphql` with a registered repository-read family | supported |
| issue/PR commands that use only listed REST routes | expected to work, verify per command |
| commands that use an unregistered GraphQL operation | denied |
| account, auth mutation, org, gist, project, codespace, SSH/GPG key, secret, variable, and extension network workflows | denied or unsupported |
| arbitrary `--hostname` or direct GitHub destination | rejected by the pgh client transport |

Keep live compatibility tests tied to the pinned `gh` release. A new upstream
release can change an internal command from REST to GraphQL without changing its
CLI syntax.
