# Examples

These Compose examples show Docker Permission Proxy profiles for common clients.
They are intentionally minimal: add restart policies, logging limits, TLS, and
networking details to match your deployment.

- [`traefik`](traefik/docker-compose.yml): expose a Unix DPP socket to Traefik's Docker provider.
- [`mysql-exec`](mysql-exec/docker-compose.yml): allow exec into MySQL, but not inspect.
- [`nginx-restart`](nginx-restart/docker-compose.yml): allow only restarts for nginx.
- [`log-reader`](log-reader/docker-compose.yml): provide a logs-only Docker API socket to a collector.

All examples default to deny. A rule grants only the listed `ACTION` values for
containers selected by name, label, image, or ID.

The container-specific examples prefer `dpp.rule.*` labels. Those labels are
evaluated only on the target container, so the container opts in to the narrow
operations allowed for itself. The Traefik example keeps environment rules
because Traefik also needs list and network access, which is not scoped to one
target container.

Run an example from this directory with:

```bash
docker compose -f <example>/docker-compose.yml up
```
