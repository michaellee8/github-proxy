# Stream Git with ref policy

The Broker parses Git receive-pack ref commands and streams pack data without a
bare mirror or object quarantine. This preserves Git protocol compatibility and
operational simplicity, but deliberately leaves non-fast-forward decisions,
branch rules, pushed file paths, and workflow side effects to GitHub. Semantic
pack inspection can be added later as a distinct validating tier.
