# Fork gh at the repository root

We maintain `pgh` as a pinned-release fork of `cli/cli` at the repository root,
retain the upstream module path and history, and add the Broker alongside it.
This costs periodic rebase work but preserves command parsing and presentation
behavior that would be expensive and brittle to reproduce in a wrapper.
