# Require durable mutation audit events

The Broker writes redacted Audit Events to PostgreSQL and structured logs, with
configurable retention defaulting to 90 days and automatic expiry. A mutation
is denied when its preflight event cannot be stored, while a read may continue
when database auditing is unavailable only after its structured event is
emitted. This favors accountability over mutation availability without making
read access depend entirely on the audit database.
