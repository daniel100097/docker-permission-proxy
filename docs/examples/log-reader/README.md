# Log Reader Access

This example exposes a DPP Unix socket for a log collector that should only read
container logs.

The app container opts in with container-local DPP labels:

```text
dpp.rule.logs.action=logs
dpp.rule.logs.match=*
```

The proxy rules allow:

- `logs` for this app container

The rules do not allow inspect, exec, restart, stop, remove, image changes,
volume changes, or other Docker API actions.

The DPP service only sets `DPP_LISTEN` and `DPP_DEFAULT`; the permission rule is
declared on the app container itself.

The `collector` service receives this Docker host:

```text
unix:///var/run/docker-permission-proxy/socket.sock
```

Run it with:

```bash
docker compose up
```

Replace the `user` group ID with your host Docker socket group ID:

```bash
stat -c '%g' /var/run/docker.sock
```
