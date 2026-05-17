# MySQL Exec Access

This example exposes a DPP Unix socket for clients that need to run `exec` in a
MySQL container without also granting `inspect`.

The MySQL container opts in with container-local DPP labels:

```text
dpp.rule.self.action=exec
dpp.rule.self.match=*
dpp.rule.self.exec-user-allow=mysql,1000
```

The proxy rules allow:

- `exec` into this MySQL container
- exec users `mysql` and `1000`
- omitted exec users when Docker inspect reports the container default user as `mysql`
- follow-up exec start, resize, and inspect calls for exec sessions created by DPP

The rules do not allow Docker container inspect, logs, restart, stop, remove, or
other Docker API actions.

The DPP service only sets `DPP_LISTEN` and `DPP_DEFAULT`; the permission rule is
declared on the MySQL container itself.

The MySQL service sets `user: mysql`, so Docker inspect exposes a non-root
default user. That lets clients run `docker compose exec mysql sh` without `-u`.
If a container has no configured default user, DPP still rejects exec requests
that omit `User` because Docker would run them as root.

Run it with:

```bash
docker compose up
```

The Docker CLI may perform its own container inspect before exec. Direct Docker
API clients can call the exec endpoints without granting inspect through DPP.

Replace the `user` group ID with your host Docker socket group ID:

```bash
stat -c '%g' /var/run/docker.sock
```
