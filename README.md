# Docker Permission Proxy (DSP)

A configurable Docker socket proxy written in Go that enforces fine-grained
access control rules via environment variables using a Traefik-style naming
convention.

## Features

- **Rule-based access control** — define granular permission rules via `DPP_RULE_*` env vars
- **Selector matching** — match containers by labels, name, image, or ID (glob patterns supported)
- **Exec user enforcement** — restrict exec commands to specific users/UIDs
- **Container metadata caching** — TTL-based cache avoids repeated Docker API calls
- **Exec-ID tracking** — automatically maps exec IDs to containers for follow-up authorization
- **Flexible listener** — supports TCP and Unix socket listeners
- **Zero dependencies** — pure Go, single static binary

## Quick Start

```bash
# Build
go build -o dsp ./cmd/dsp

# Run with minimal config
DPP_LISTEN="tcp://127.0.0.1:2375" \
DPP_UPSTREAM="unix:///var/run/docker.sock" \
DPP_DEFAULT="deny" \
DPP_RULE_readonly_ACTION="list,inspect,logs" \
DPP_RULE_readonly_TARGET="container,image,network,volume" \
DPP_RULE_readonly_MATCH="*" \
./dsp
```

## Configuration

### Global Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DPP_LISTEN` | `tcp://127.0.0.1:2375` | Listen address (`tcp://host:port` or `unix:///path`) |
| `DPP_UPSTREAM` | `unix:///var/run/docker.sock` | Upstream Docker socket |
| `DPP_DEFAULT` | `deny` | Default policy when no rules match |

### Rule Grammar

Rules are defined via environment variables following this pattern:

```
DPP_RULE_<name>_<field>=<value>
```

| Field | Description |
|-------|-------------|
| `ACTION` | **(required)** CSV of allowed verbs |
| `TARGET` | CSV of resource types (default: `container`) |
| `MATCH` | Set to `*` to match any target |
| `MATCH_LABEL_<key>` | Match container label `key` to value/glob |
| `MATCH_NAME` | Glob pattern for container name |
| `MATCH_IMAGE` | Glob pattern for image |
| `MATCH_ID` | SHA prefix match |
| `EXEC_USER` | Required exact UID/username for exec |
| `EXEC_USER_ALLOW` | CSV whitelist of UIDs/usernames for exec |

A rule is only valid if `ACTION` is present. All `MATCH_*` selectors within a rule
are ANDed. Rules are ORed across — any matching rule grants access.

### Available Actions

| Action | Description |
|--------|-------------|
| `list` | List resources |
| `inspect` | Inspect/get resource details |
| `logs` | Container logs |
| `exec` | Execute command in container |
| `attach` | Attach to container |
| `start` | Start container |
| `stop` | Stop container |
| `restart` | Restart container |
| `kill` | Kill container |
| `pause` | Pause container |
| `unpause` | Unpause container |
| `create` | Create resource |
| `remove` | Remove resource |
| `pull` | Pull image |
| `push` | Push image |
| `build` | Build image |
| `network.create` | Create network |
| `network.remove` | Remove network |
| `volume.create` | Create volume |
| `volume.remove` | Remove volume |
| `prune` | Prune resources |

### Available Targets

`container`, `image`, `network`, `volume`, `system`

System endpoints (`_ping`, `version`, `info`, `events`, `df`) are always allowed.

## Exec User Enforcement

The exec action has special handling. When a rule allows exec, it also validates
the `User` field in the exec create request body:

1. If `EXEC_USER` is set: body `.User` must match exactly
2. If `EXEC_USER_ALLOW` is set: body `.User` must be in the whitelist
3. If neither is set: exec is denied (safer default)
4. Empty/missing `User` field is always rejected (prevents inheriting container default, usually root)

## Example Configuration

```bash
# Allow exec on dev containers, restrict to specific users
DPP_RULE_devexec_ACTION=exec
DPP_RULE_devexec_MATCH_LABEL_team=dev
DPP_RULE_devexec_EXEC_USER_ALLOW=1000,1001,deploy

# Allow lifecycle operations on production containers
DPP_RULE_opsctl_ACTION=start,stop,restart,kill
DPP_RULE_opsctl_MATCH_LABEL_env=prod

# Allow creating containers only from our registry
DPP_RULE_cicreate_ACTION=create
DPP_RULE_cicreate_MATCH_IMAGE=registry.acme.io/*

# Allow read-only operations on everything
DPP_RULE_readall_ACTION=list,inspect,logs
DPP_RULE_readall_TARGET=container,image,network,volume
DPP_RULE_readall_MATCH=*
```

## Docker Compose

See [docker-compose.yml](docker-compose.yml) for a complete example.

## Building

```bash
# Local build
go build -o dsp ./cmd/dsp

# Docker build
docker build -t docker-permission-proxy .
```

## Architecture

```
Request → Classifier → Authorizer → Proxy → Docker Socket
              ↓              ↓
        action/target    rule matching
        identification   + exec user check
                              ↓
                        metadata cache
                        (container inspect)
```

The proxy classifies each incoming request into an action + target + resource ID,
finds applicable rules, fetches container metadata (cached), evaluates rule selectors,
and either forwards the request or returns 403.
