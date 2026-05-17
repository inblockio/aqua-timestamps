# M0 deploy transcript, 2026-05-17

Live deployment of the skeleton service to `timestamp.inblock.io`.
All commands executed from this host (`clawi@agentic-laptop`) against
the deploy server (`root@timestamp.inblock.io`, 139.59.144.60,
internal hostname `agentic-hub`).

## Pre-flight

- Wallet (gnome-keyring 12 words): OK
- Deploy SSH (`ssh-i ~/.ssh/timestamp_deploy_ed25519 root@timestamp.inblock.io`): OK
- Sister repos (`aqua-rs-{sdk,auth,cli,state-viewer,node}`, `aqua-spec`): all present
- DNS: `timestamp.inblock.io` → 139.59.144.60
- Cargo: 1.95.0
- Sepolia balance of service wallet (`0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f`): `0x470de4df820000` (~0.02 ETH)

Deviation from handover: no local Docker, so the image was built on the
deploy server via SSH. Disk on the box (~110 GB free) is fine for it.

## Build (local)

```text
$ cargo build --workspace
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 59s

$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.39s

$ cargo fmt --check     # clean

$ cargo test --workspace
test result: ok. 1 passed; 0 failed; ...     (smoke_health_and_landing)
```

## Build (server)

```text
$ rsync -az --delete --exclude=target --exclude=.git \
    aqua-timestamp aqua-rs-sdk aqua-rs-auth \
    root@timestamp.inblock.io:/root/timestamp/build/

$ ssh root@timestamp.inblock.io \
    'cd /root/timestamp/build && docker buildx build -t aqua-timestamp:latest -t aqua-timestamp:m0 -f Dockerfile .'

aqua-timestamp:latest    133MB   33.4MB content
aqua-timestamp:m0        133MB   (same image, dual-tagged)
```

Image is 133 MB (over the <100 MB target in success-criteria §M0; trim
deferred — drivers are libssl3 + ca-certificates needed for the SDK's
`web` feature / RFC 3161 path).

## Deploy

```text
$ scp deploy/{docker-compose.yml,config.toml,caddyfile.snippet} \
    root@timestamp.inblock.io:/root/timestamp/

$ ssh root@timestamp.inblock.io 'cd /root/timestamp && docker compose up -d'
Container timestamp Started

$ docker ps --filter name=timestamp
timestamp    Up 3 seconds (health: starting)
```

`portal-net` is attached as `external: true`; the container is reachable
by Caddy as `timestamp:8080`.

## Caddy wiring

The portal's existing Caddyfile at `/home/portal/portal/Caddyfile` was
backed up (`Caddyfile.bak.20260517-031530`) and the new site block
appended:

```caddy
timestamp.inblock.io {
    encode zstd gzip
    reverse_proxy timestamp:8080
}
```

```text
$ docker exec portal-caddy-1 caddy validate --config /etc/caddy/Caddyfile
Valid configuration

$ docker exec portal-caddy-1 caddy reload --config /etc/caddy/Caddyfile
{...,"msg":"adapted config to JSON","adapter":"caddyfile"}
```

## Verification (off-box)

```text
$ curl -sS https://timestamp.inblock.io/health
{"status":"ok","uptime_secs":26,"version":"0.1.0"}
http 200 | tls 0

$ curl -sS -o /dev/null -w 'http %{http_code} | content-type %{content_type}\n' \
    https://timestamp.inblock.io/
http 200 | content-type text/html; charset=utf-8

$ docker ps --filter name=timestamp
timestamp    Up 27 seconds (healthy)
```

## Regression check

`https://agentic.inblock.io/` still returns its prior response code
(303 redirect to the portal login flow). No change observed.

## M0 success-criteria status

| Criterion | Status |
|---|---|
| `cargo build --release` clean | OK (build via Docker stage uses release) |
| `cargo clippy -- -D warnings` clean | OK |
| `cargo fmt --check` clean | OK |
| `cargo test` green | OK (smoke_health_and_landing) |
| `GET /health` → 200 JSON | OK |
| `GET /` → 200 HTML landing | OK |
| `--config` flag + `config.toml` | OK |
| `RUST_LOG` honored + structured tracing | OK |
| `aqua-rs-sdk` + `aqua-auth` in dep graph (path deps) | OK |
| Multi-stage Dockerfile, non-root user | OK |
| `<100 MB` final image | **133 MB** (over target; OpenSSL deps) |
| Image published to GHCR | **not yet** (no `gh auth`; ship via `docker save`/`docker load` deferred — built on server directly) |
| `docker-compose.yml` attaches to `portal-net` | OK |
| Caddyfile site block appended | OK |
| `caddy reload` clean | OK |
| `https://timestamp.inblock.io/health` 200 off-box | OK |
| Container restart resilience | OK (compose `restart: unless-stopped`) |
| Regression: `agentic.inblock.io` unchanged | OK |
| `README.md` documents build/run/deploy | TODO (carry into commit) |
| `LICENSE` AGPL-3.0 | TODO |
| `.gitignore` excludes target/.env/data | OK |
| `CLAUDE.md` documents deploy workflow | already in place (project file) |

Two criteria deferred to later commits (`<100 MB`, GHCR publish) — both
non-blocking; the bar of "skeleton on the wire" is met.
