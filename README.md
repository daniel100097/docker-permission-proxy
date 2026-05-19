# Docker Permission Proxy (DPP)

Docker Permission Proxy is a Docker socket proxy written in Go. It accepts Docker
HTTP API requests, classifies each request into an action and target, evaluates
environment-variable rules, and only forwards allowed requests to the upstream
Docker daemon.

It is intended for cases where a tool needs limited Docker API access, but a raw
`/var/run/docker.sock` mount would be too broad.

## Features

- Rule-based access control via `DPP_RULE_*` environment variables
- Per-rule decisions: `allow`, `deny`, or desktop-confirmed `ask`
- Desktop confirmation dialogs through `kdialog` or `zenity`
- Traefik-style rule naming: `DPP_RULE_<name>_<field>`
- Container selectors for labels, name, image, and ID prefix
- Container-local rules declared directly on Docker container labels
- Glob matching with `*`, `?`, and character classes
- Exec user enforcement with root user/group protection
- Exec-ID tracking for follow-up `exec.start`, `exec.resize`, and `exec.inspect`
- Container metadata cache and bounded exec-ID cache
- TCP and Unix listener support
- Unix and HTTP upstream support, with HTTP used by tests
- Static Go binary with a non-root container image
- GitHub Actions CI and GHCR image publishing

## Quick Start

Build and run locally:

```bash
go build -o dpp ./cmd/dsp

DPP_LISTEN="tcp://127.0.0.1:2375" \
DPP_UPSTREAM="unix:///var/run/docker.sock" \
DPP_DEFAULT="deny" \
DPP_RULE_readall_ACTION="list,inspect,logs" \
DPP_RULE_readall_TARGET="container" \
DPP_RULE_readall_MATCH="*" \
./dpp
```

Point a Docker client at the proxy:

```bash
DOCKER_HOST=tcp://127.0.0.1:2375 docker ps
DOCKER_HOST=tcp://127.0.0.1:2375 docker logs my-container
```

Build the container image:

```bash
docker build -t docker-permission-proxy .
```

Run with Docker:

```bash
docker run --rm \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e DPP_LISTEN=tcp://0.0.0.0:2375 \
  -e DPP_DEFAULT=deny \
  -e DPP_RULE_readall_ACTION=list,inspect \
  -e DPP_RULE_readall_TARGET=container \
  -e DPP_RULE_readall_MATCH='*' \
  docker-permission-proxy
```

## Configuration

### Global Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DPP_LISTEN` | `tcp://127.0.0.1:2375` | Proxy listener. Supports `tcp://host:port`, `host:port`, or `unix:///path`. |
| `DPP_UPSTREAM` | `unix:///var/run/docker.sock` | Upstream Docker daemon endpoint. Usually `unix:///var/run/docker.sock`. |
| `DPP_DEFAULT` | `deny` | Default policy for recognized, non-exec requests without a matching rule. Must be `deny` or `allow`. |
| `DPP_CONFIRM_SOCKET` | unset | Optional Unix socket for an external `DECISION=ask` helper. If unset, DPP opens `kdialog` or `zenity` directly in the proxy container. |
| `DPP_CONFIRM_TIMEOUT` | `30s` | Maximum time to wait for the dialog or external helper response. Uses Go duration syntax. |

Unknown Docker API endpoints are always denied, even with `DPP_DEFAULT=allow`.
Exec requests are never allowed by default policy; they require an explicit exec
rule with user restrictions.

### Rule Grammar

Rules use this environment variable pattern:

```text
DPP_RULE_<name>_<field>=<value>
```

Example:

```bash
DPP_RULE_devexec_ACTION=exec
DPP_RULE_devexec_MATCH_LABEL_team=dev
DPP_RULE_devexec_EXEC_USER_ALLOW=1000,deploy
```

Important parser details:

- Rule names currently cannot contain underscores. Use `devexec`, not `dev_exec`.
- Unknown fields are startup errors, so typos fail closed.
- `ACTION` is required. A rule without `ACTION` is ignored.
- `DECISION` defaults to `allow`. Set it to `deny` to block a matching request or `ask` to require desktop confirmation.
- `TARGET` defaults to `container` if omitted.
- Among evaluated matching rules, decisions are combined fail-closed: `deny` wins over `ask`, and `ask` wins over `allow`.
- Selectors in one rule are ANDed, except `MATCH=*`, which is an explicit match-all selector.
- Avoid combining `MATCH=*` with more specific selectors; `MATCH=*` makes the rule unscoped.

Rules can also be declared on a container with Docker labels. Label-defined rules
are evaluated only for the container that carries those labels, so they are useful
when the container owner should opt in to specific operations for that container.

### Rule Fields

| Field | Description |
|-------|-------------|
| `ACTION` | Required CSV of action names. |
| `DECISION` | `allow`, `deny`, or `ask`. Defaults to `allow`. |
| `TARGET` | CSV of target names. Defaults to `container`. |
| `MATCH` | Set to `*` to match any target for the action and target. |
| `MATCH_LABEL_<key>` | Match a container label value with a glob. Label key case is preserved. |
| `MATCH_NAME` | Match a container name with a glob. |
| `MATCH_IMAGE` | Match a container image or create body image with a glob. |
| `MATCH_ID` | Match a container ID prefix. |
| `EXEC_USER` | Exact Docker exec `User` value required. |
| `EXEC_USER_ALLOW` | CSV whitelist of allowed Docker exec users or UIDs. |

`MATCH_LABEL_<key>` is convenient for simple labels like `team` or `env`. Docker
labels commonly contain dots and slashes, such as `com.docker.compose.project`.
Those are awkward to express in shell environment variable names. Prefer compose
YAML or another environment injection mechanism if you need such keys.

### Container Label Rules

Container labels use this pattern:

```text
dpp.rule.<name>.<field>=<value>
```

Example:

```yaml
services:
  app:
    labels:
      dpp.rule.self.action: "restart,logs"
      dpp.rule.self.match: "*"
```

Supported label fields map to the environment rule fields:

| Label field | Environment field |
|-------------|-------------------|
| `action` | `ACTION` |
| `decision` | `DECISION` |
| `target` | `TARGET` |
| `match` | `MATCH` |
| `match-label.<key>` | `MATCH_LABEL_<key>` |
| `match-name` | `MATCH_NAME` |
| `match-image` | `MATCH_IMAGE` |
| `match-id` | `MATCH_ID` |
| `exec-user` | `EXEC_USER` |
| `exec-user-allow` | `EXEC_USER_ALLOW` |

Label-defined rules still use the same action, target, selector, glob, and exec
user rules as environment-defined rules. They cannot grant access to other
containers because DPP parses them from the inspected target container only.

### Glob Matching

Glob patterns are full-string, case-sensitive matches:

- `*` matches any sequence, including `/`
- `?` matches one character
- character classes like `[abc]` are supported
- malformed patterns fail closed

Examples:

| Pattern | Value | Match |
|---------|-------|-------|
| `registry.acme.io/*` | `registry.acme.io/app:latest` | yes |
| `registry.acme.io/*` | `registry.acme.io/team/app:latest` | yes |
| `worker-??` | `worker-01` | yes |
| `worker-??` | `worker-001` | no |

## Actions And Targets

The proxy classifies Docker endpoints into action and target names. Rule actions
must use these names.

### Container Actions

| Action | Docker API examples |
|--------|---------------------|
| `list` | `GET /containers/json` |
| `inspect` | `GET /containers/{id}/json`, `top`, `stats` |
| `logs` | `GET /containers/{id}/logs` |
| `changes` | `GET /containers/{id}/changes` |
| `export` | `GET /containers/{id}/export` |
| `archive.read` | `GET /containers/{id}/archive` |
| `archive.write` | `PUT /containers/{id}/archive` |
| `archive.stat` | `HEAD /containers/{id}/archive` |
| `exec` | `POST /containers/{id}/exec` |
| `exec.start` | `POST /exec/{id}/start`, resolved through the exec cache |
| `exec.resize` | `POST /exec/{id}/resize`, resolved through the exec cache |
| `exec.inspect` | `GET /exec/{id}/json`, resolved through the exec cache |
| `attach` | `POST /containers/{id}/attach`, `GET /containers/{id}/attach/ws` |
| `resize` | `POST /containers/{id}/resize` |
| `start`, `stop`, `restart`, `kill` | container lifecycle endpoints |
| `pause`, `unpause`, `wait`, `rename`, `update` | container lifecycle/update endpoints |
| `create` | `POST /containers/create` |
| `remove` | `DELETE /containers/{id}` |
| `prune` | `POST /containers/prune` |

### Image Actions

| Action | Docker API examples |
|--------|---------------------|
| `list` | `GET /images/json` |
| `inspect` | `GET /images/{id}/json` |
| `image.history` | `GET /images/{id}/history` |
| `image.search` | `GET /images/search` |
| `image.save` | `GET /images/get`, `GET /images/{id}/get` |
| `image.load` | `POST /images/load` |
| `pull` | `POST /images/create` |
| `push` | `POST /images/{id}/push` |
| `tag` | `POST /images/{id}/tag` |
| `remove` | `DELETE /images/{id}` |
| `prune` | `POST /images/prune` |
| `build` | `POST /build` |
| `commit` | `POST /commit` |

### Network And Volume Actions

| Target | Actions |
|--------|---------|
| `network` | `list`, `inspect`, `network.create`, `network.remove`, `network.connect`, `network.disconnect`, `prune` |
| `volume` | `list`, `inspect`, `volume.create`, `volume.remove`, `prune` |

### Swarm And Other Targets

| Target | Actions |
|--------|---------|
| `swarm` | `inspect`, `swarm.init`, `swarm.join`, `swarm.leave`, `swarm.update`, `swarm.unlock`, `swarm.unlockkey` |
| `service` | `list`, `inspect`, `service.create`, `service.update`, `service.remove`, `service.logs` |
| `task` | `list`, `inspect`, `task.logs` |
| `node` | `list`, `inspect`, `node.update`, `node.remove` |
| `secret` | `list`, `inspect`, `secret.create`, `secret.update`, `secret.remove` |
| `config` | `list`, `inspect`, `config.create`, `config.update`, `config.remove` |
| `plugin` | `list`, `inspect`, `plugin.pull`, `plugin.enable`, `plugin.disable`, `plugin.remove` |
| `distribution` | `distribution.inspect` |
| `build` | `session` |

### Always-Allowed System Endpoints

These system endpoints are always allowed:

- `GET` or `HEAD /_ping`
- `GET /version`
- `GET /info`
- `GET /events`
- `GET /system/df`

`/info`, `/events`, and `/system/df` can expose operational metadata such as
container names, image names, labels, event streams, and disk usage. Bind the
proxy only to trusted networks, or put authentication/TLS in front of it.

## Exec User Enforcement

Exec is intentionally stricter than other actions:

- `exec` always requires an explicit matching rule.
- `DPP_DEFAULT=allow` does not allow exec.
- Missing or empty Docker exec `User` inherits the container's configured
  `Config.User` from inspect only when that value is explicit and non-root.
- If the container has no configured default user, missing or empty Docker exec
  `User` is rejected because Docker would run the exec as root.
- `root`, `0`, `root:*`, `0:*`, `*:root`, and `*:0` are rejected.
- `EXEC_USER` requires the full `User` string to match exactly.
- `EXEC_USER_ALLOW` checks the user component before `:` and still rejects root user/group.

Examples:

```bash
# Allow shell access on dev containers for numeric users 1000 and 1001.
DPP_RULE_devexec_ACTION=exec
DPP_RULE_devexec_MATCH_LABEL_team=dev
DPP_RULE_devexec_EXEC_USER_ALLOW=1000,1001

# Require an exact user string.
DPP_RULE_deployexec_ACTION=exec
DPP_RULE_deployexec_MATCH_NAME=deploy-*
DPP_RULE_deployexec_EXEC_USER=deploy
```

With an image or Compose service that sets `USER node` / `user: "1000:1000"`,
`docker compose exec api sh` can pass the same rule as `docker compose exec -u
1000:1000 api sh`. Images that leave `Config.User` empty still require `-u`.

Allowed follow-up requests (`exec.start`, `exec.resize`, `exec.inspect`) are
resolved through the exec-ID cache populated by the original `exec` create
response.

## Example Rules

### Read-Only Container Access

```bash
DPP_RULE_readcontainers_ACTION=list,inspect,logs
DPP_RULE_readcontainers_TARGET=container
DPP_RULE_readcontainers_MATCH=*
```

This allows `docker ps`, `docker inspect`, and `docker logs` for containers.

### Read Images

```bash
DPP_RULE_readimages_ACTION=list,inspect,image.history
DPP_RULE_readimages_TARGET=image
DPP_RULE_readimages_MATCH=*
```

Non-container targets usually need `TARGET` and `MATCH=*` because container
metadata selectors only apply to containers.

### Restart Production Containers

```bash
DPP_RULE_prodctl_ACTION=start,stop,restart
DPP_RULE_prodctl_TARGET=container
DPP_RULE_prodctl_MATCH_LABEL_env=prod
```

### Ask Before Restarting Production Containers

For the main proxy container to open the dialog directly, run it as the logged-in
desktop user and mount that user's desktop runtime directory:

```yaml
services:
  docker-proxy:
    image: ghcr.io/daniel100097/docker-permission-proxy:main
    user: "1000:1000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /run/user/1000:/run/user/1000
      - /tmp/.X11-unix:/tmp/.X11-unix:ro
    environment:
      XDG_RUNTIME_DIR: "/run/user/1000"
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus"
      DISPLAY: "${DISPLAY:-}"
      WAYLAND_DISPLAY: "${WAYLAND_DISPLAY:-wayland-0}"
      DPP_RULE_prodask_ACTION: "restart"
      DPP_RULE_prodask_DECISION: "ask"
      DPP_RULE_prodask_MATCH_LABEL_env: "prod"
```

The image includes `zenity`. If `kdialog` or `zenity` is available in the
container, DPP opens a question dialog with the matching rule, Docker API
request, action, target, and an approximate Docker command such as
`docker container restart prod-app`. If the dialog command is unavailable, times
out, or the dialog is rejected, the Docker request is denied.

The `user: "1000:1000"` setting matters because `/run/user/1000` is normally
private to UID 1000. Change the UID/GID if your desktop session uses a different
account. If Docker socket access then fails, add the host Docker socket group
with `group_add`.

If you prefer an external helper instead of mounting the desktop session into the
main proxy container, set `DPP_CONFIRM_SOCKET`. The socket protocol is one
newline-terminated JSON request and one JSON response:

```json
{"id":"abc","rule":"prodask","action":"restart","target":"container","resource_id":"prod-app","method":"POST","path":"/containers/prod-app/restart","command":"docker container restart prod-app","message":"..."}
{"allow":true}
```

This makes it possible to replace `cmd/dpp-confirm` with another host daemon if
you want a different desktop integration or audit flow.

### Container-Local Restart Opt-In

```yaml
services:
  worker:
    labels:
      dpp.rule.self.action: "restart"
      dpp.rule.self.match: "*"
```

This allows `restart` only for this `worker` container. Other containers need
their own labels or an environment-defined rule.

### Allow Logs By Name

```bash
DPP_RULE_workerlogs_ACTION=logs
DPP_RULE_workerlogs_TARGET=container
DPP_RULE_workerlogs_MATCH_NAME=worker-*
```

### Allow Pulls From Any Registry

```bash
DPP_RULE_pull_ACTION=pull
DPP_RULE_pull_TARGET=image
DPP_RULE_pull_MATCH=*
```

### Allow Docker CP Read But Not Write

```bash
DPP_RULE_copyread_ACTION=archive.read,archive.stat
DPP_RULE_copyread_TARGET=container
DPP_RULE_copyread_MATCH_LABEL_team=dev
```

### BuildKit Session

```bash
DPP_RULE_buildsession_ACTION=session
DPP_RULE_buildsession_TARGET=build
DPP_RULE_buildsession_MATCH=*
```

Build sessions can be sensitive. Do not allow `session`, `build`, or `commit`
unless the client is trusted to run builds on that Docker daemon.

## Container Create Caveat

`create` rules currently match the request body `Image` and labels. They do not
yet validate dangerous `HostConfig` fields such as:

- `Privileged`
- bind mounts like `/:/host` or `/var/run/docker.sock`
- `NetworkMode=host`
- `PidMode=host`
- added capabilities
- devices

For production, keep `create` denied unless callers are trusted or you add an
additional policy layer that validates Docker create options.

Example image-restricted create rule:

```bash
DPP_RULE_cicreate_ACTION=create
DPP_RULE_cicreate_TARGET=container
DPP_RULE_cicreate_MATCH_IMAGE=registry.acme.io/*
```

## Docker Compose

See [`docker-compose.yml`](docker-compose.yml) for a local build example.
See [`docs/examples`](docs/examples) for focused Compose examples, including
Traefik, exec-only, restart-only, and logs-only proxy profiles.

Two deployment notes matter:

- A read-only bind mount of `/var/run/docker.sock` does not make Docker API access read-only. The socket still accepts mutating API calls if rules allow them.
- The image runs as non-root. The container user must still be able to open the host Docker socket. On many Linux hosts this means adding the container to the host Docker socket group.

Find the Docker socket group ID:

```bash
stat -c '%g' /var/run/docker.sock
```

Then set `group_add` in Compose:

```yaml
services:
  docker-proxy:
    image: ghcr.io/danielvolz/docker-permission-proxy:main
    group_add:
      - "999" # replace with: stat -c '%g' /var/run/docker.sock
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "127.0.0.1:2375:2375"
```

Avoid attaching untrusted containers to the same Docker network as a TCP DPP
listener. If possible, prefer binding to localhost or using a Unix listener.

## CI/CD And Images

The GitHub Actions workflow runs:

- `go mod download`
- `go mod verify`
- `go build ./...`
- `go vet ./...`
- `go test -race -count=1 ./...`
- Docker build and push to GHCR for non-PR pushes

Published image:

```text
ghcr.io/daniel100097/docker-permission-proxy
```

Container package URL:

```text
https://github.com/daniel100097/docker-permission-proxy/pkgs/container/docker-permission-proxy
```

Pull the branch image:

```bash
docker pull ghcr.io/daniel100097/docker-permission-proxy:main
```

The workflow publishes branch, semantic-version tag, and SHA tags. Prefer pinned
version or SHA tags for production.

## Architecture

```text
Client request
    |
    v
HTTP listener (TCP or Unix)
    |
    v
Classifier: method + path -> action, target, ID
    |
    v
Authorizer: rules + optional container inspect metadata + exec user checks
    |
    v
Reverse proxy / upgrade tunnel
    |
    v
Docker daemon socket
```

Container metadata is cached for a short TTL to reduce Docker inspect calls.
Exec IDs are cached after successful exec creation so follow-up exec operations
can be mapped back to the original container.

## Development

```bash
go test ./...
go test -race -count=1 ./...
go vet ./...
```

The test suite includes unit coverage for config parsing, request classification,
authorization, cache behavior, and proxy integration against a mock Docker server.
