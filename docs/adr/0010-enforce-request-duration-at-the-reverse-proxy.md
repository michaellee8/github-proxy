# Enforce request duration at the reverse proxy

The Broker does not impose a whole-request duration limit because Git and LFS
transfers can legitimately be long-lived. Deployments must enforce header,
idle, and total-duration limits at the required reverse proxy, while the Broker
uses per-capability concurrency and rate limits to bound its own request slots.
