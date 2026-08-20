# Allow operator-managed capability policy changes

An offline operator may broaden or narrow an active Repository Capability's
additional grants, Git push tier, and tag authority without replacing its
Capability Token. The Target Repository, Upstream Credential, token material,
Policy Profile name and version, and expiration are fixed after issue. Policy
replacement does not alter revocation.

Each Repository Capability starts at Policy Revision 1. An effective
replacement locks the capability row, replaces every mutable policy control,
increments the revision, and appends a permanent Administrative Event in one
transaction. Identical replacements are no-ops. Concurrent replacements are
serialized with last-write-wins behavior; revisions are observable and are not
update preconditions.

The new policy applies to requests that resolve after the transaction commits.
A request that already resolved a Session may finish under its recorded earlier
Policy Revision. Both phases of request auditing record that revision, while
Administrative Events remain outside request-audit retention. Expired and
revoked capabilities remain inspectable but reject replacement.
