# Traefik Docker Provider

This example runs Traefik with Docker provider access through Docker Permission
Proxy instead of mounting `/var/run/docker.sock` into Traefik.

Traefik connects to this proxied Unix socket:

```text
unix:///var/run/traefik-docker-permission-proxy/socket.sock
```

The proxy rules allow Traefik to:

- list and inspect containers
- list and inspect networks

The rules do not allow container lifecycle operations, exec, logs, image changes,
volume changes, or container removal.

Run it with:

```bash
docker compose up
```

Replace the `user` group ID with your host Docker socket group ID:

```bash
stat -c '%g' /var/run/docker.sock
```
