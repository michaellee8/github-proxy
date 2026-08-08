# Upgrade the pinned gh release

This repository imported upstream `cli/cli` release `v2.97.0` at the root and
retains the upstream module path. `pgh` is a forked binary, not a wrapper around
an installed `gh` binary.

Use one reviewed upstream release at a time:

1. Read the upstream release notes and security notices. Prioritize GitHub CLI
   security releases.
2. Fetch the immutable release tag from the `upstream-gh` remote and verify the
   tag or release artifact according to upstream's provenance instructions.
3. Merge the release into a dedicated upgrade branch. Preserve `cmd/pgh`,
   `internal/pghcmd`, Broker packages, deployment files, and the pgh section of
   the root README while resolving upstream changes.
4. Build both `cmd/gh` and `cmd/pgh`. The original `gh` binary must remain an
   upstream-compatible command and `pgh` must retain its separate identity,
   config directory, token variables, and destination guard.
5. Inventory every REST route and GraphQL operation used by the commands in the
   compatibility matrix. Add Broker authorization and public-interface tests
   before enabling a changed or new operation family.
6. Run focused pgh/Broker tests, `go test ./...`, `make lint`, container build,
   Compose validation, Helm lint, and live compatibility tests against a
   disposable repository capability.
7. Update this document, chart `appVersion`, image tags, and release notes with
   the new upstream pin and any compatibility changes.

Do not turn unknown upstream API traffic into a generic pass-through to make an
upgrade green. A failed-closed command is preferable to silently broadening a
Repository Capability.
