# Make the Broker the authorization boundary

The Agent Host and `pgh` are untrusted; only the off-host Broker enforces
repository and operation authority. Capability Tokens bind an immutable
repository identity to a versioned policy, while broad Upstream Credentials are
encrypted in PostgreSQL. Client-side denials improve usability but never replace
Broker enforcement.
