# Register GraphQL operation families

The Broker accepts only parsed GraphQL operation families derived from the
pinned `gh` release, validates selected fields and identifier provenance, and
rebuilds the upstream operation with trusted repository variables. Literal
query hashes would break dynamic `--json` selections, while arbitrary GraphQL
would make repository-scoped authorization indefensible.
