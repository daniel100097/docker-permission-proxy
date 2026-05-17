# Nginx Logs And Restart Access

This example exposes a DPP Unix socket for clients that should only be able to
read nginx container output and restart the nginx container.

The nginx container opts in with container-local DPP labels:

```text
dpp.rule.self.action=logs,restart
dpp.rule.self.match=*
```

The proxy rules allow:

- `logs` for this nginx container's output
- `restart` for this nginx container

The rules do not allow inspect, exec, start, stop, remove, image changes, or
other Docker API actions.

The DPP service only sets `DPP_LISTEN` and `DPP_DEFAULT`; the permission rule is
declared on the nginx container itself.

Run it with:

```bash
docker compose up
```

Replace the `user` group ID with your host Docker socket group ID:

```bash
stat -c '%g' /var/run/docker.sock
```
