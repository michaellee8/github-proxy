# Revalidate repository identity before use

The Broker resolves a Target Repository by numeric GitHub ID before every
mutation and caches successful Repository Observations for reads for a
configurable 30-second default, bounded to five minutes, without stale-on-error
behavior. Numeric resolution is the default because owner/name can be reused;
an operator may explicitly configure documented owner/name resolution for an
upstream that does not support numeric lookup, and the Broker still requires the
returned ID to match. Resolution mode belongs to the Upstream Credential because
it is a property of the upstream host. Capabilities follow renames and transfers
when the resolved numeric repository ID is unchanged. This accepts an
undocumented GitHub.com dependency in the strong mode while keeping a deliberate
compatibility mode for other upstreams.

Capability issuance accepts owner/name, derives the numeric ID, canonical name,
and default branch from the selected Upstream Credential, and optionally checks
an operator-supplied expected repository ID. Operator-supplied repository
metadata is never treated as authoritative.
