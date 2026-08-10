# Allow operator-managed capability lifetimes

Capability expiration is optional and has no Broker-enforced maximum so an
operator can authorize a long-running Agent Host without an automated renewal
channel. A capability without an expiration remains valid until revoked; the
wizard should make that consequence explicit, while short expirations remain
available and preferred for temporary sessions.
