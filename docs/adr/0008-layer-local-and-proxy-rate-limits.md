# Layer local and reverse-proxy rate limits

Each Broker replica applies per-capability limits of 300 reads per minute, 60
mutations per minute, and eight concurrent requests, while the deployment's
reverse proxy supplies deployment-wide controls. Coordinating every request
through PostgreSQL would make the database a hot-path bottleneck; local limits
bound one replica and the proxy prevents additional replicas from multiplying
the externally permitted load.
