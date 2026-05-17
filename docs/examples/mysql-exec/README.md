# MySQL Exec Access

This example exposes a DPP Unix socket for clients that need to run `exec` in a
MySQL container without also granting `inspect`.

The MySQL container opts in with container-local DPP labels:

```text
dpp.rule.exec.action=exec
dpp.rule.exec.match=*
dpp.rule.exec.exec-user-allow=mysql,1000
```

The proxy rules allow:

- `exec` into this MySQL container
- exec users `mysql` and `1000`
- follow-up exec start, resize, and inspect calls for exec sessions created by DPP

The rules do not allow Docker container inspect, logs, restart, stop, remove, or
other Docker API actions.

The DPP service only sets `DPP_LISTEN` and `DPP_DEFAULT`; the permission rule is
declared on the MySQL container itself.

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
