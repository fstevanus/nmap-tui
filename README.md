# nmap-web

A full-featured **nmap web UI** that runs locally in Docker/Podman. On Linux
it uses **host networking** so scans see the host's network exactly as if nmap
ran on the host itself; on macOS/Windows it uses a port-mapped, capability-
scoped setup (containers run in a VM there — see [Quick start](#quick-start)).
Beautiful dark UI, live scan progress, parsed results, scan history.

![license](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Full nmap power** — every major option group is exposed in a clean UI:
  scan techniques (SYN/connect/UDP/ACK/Window/Maimon/FIN/Xmas/NULL/SCTP),
  port selection, host discovery, service/version & OS detection, NSE scripts,
  timing templates & rate controls, firewall/IDS evasion, output flags —
  plus a raw **extra arguments** field for anything else nmap supports.
- **Zenmap-style presets** — Quick, Intense, Ping sweep, Full port, Vuln scan,
  Slow comprehensive, etc., with a Custom mode for full control.
- **Live progress** — WebSocket stream of nmap's stats lines, % complete,
  progress bar, colorized terminal log, cancel anytime.
- **Parsed results** — hosts, ports with service/version banners, NSE script
  output, OS detection with accuracy, traceroute, summary stats.
- **History** — scans persisted across restarts; export raw XML or plain-text
  output; re-open any past scan.
- **Runs anywhere** — on Linux, host networking + root gives the full nmap
  experience (SYN scans, ARP discovery, OS detection); on macOS/Windows or
  rootless Podman, a port-mapped container with `NET_RAW`/`NET_ADMIN` caps
  still does SYN scans and OS detection against the LAN.
- **Local-first security** — binds to `127.0.0.1` by default; optional bearer
  token if you must expose it further.

## Quick start

> **Which path am I on?** Docker Desktop and Podman on **macOS/Windows** run
> containers inside a Linux VM: `--network host` gives the container the
> **VM's** network, *not* your Mac's LAN, and VM ports aren't auto-forwarded.
> Use the **port-mapped variant** there. On a **Linux** host with a rootful
> engine, use **host networking** for the full nmap experience.

### macOS / Windows / rootless Podman — port-mapped + capabilities

```bash
# --format docker so the Dockerfile HEALTHCHECK is kept (podman's default
# OCI format would drop it)
podman build --format docker -t nmap-web .
podman run -d --name nmap-web \
  -p 127.0.0.1:8787:8787 \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -e NMAP_UI_HOST=0.0.0.0 \
  -v nmap-web-data:/data \
  nmap-web
```

Open **http://127.0.0.1:8787**. The `NET_RAW`/`NET_ADMIN` caps are granted
inside the container's own network namespace, so SYN scans and OS detection
work against LAN targets over slirp4netns/passt. Two caveats: there is no L2
(no ARP/MAC discovery), and **"the host itself" is not `127.0.0.1` here** —
that's the container's own loopback. Scan the Mac via its **LAN IP** or
`host.containers.internal` instead. (If your `podman` CLI talks to a **remote**
host — check `podman system connection list` — the published port binds on
that machine; reach it with an SSH tunnel: `ssh -L 8787:127.0.0.1:8787 <host>`.)

Compose equivalent (needs `docker compose` or a `podman compose` provider
installed):

```bash
docker compose -f docker-compose.rootless.yml up -d --build
# or: podman compose -f docker-compose.rootless.yml up -d --build
```

### Linux (rootful) — host networking

```bash
docker compose up -d --build
# or: podman compose up -d --build
```

Open **http://127.0.0.1:8787**. This is `docker-compose.yml`: host networking
+ root, so scans see the real network topology (ARP, MAC vendors, link-layer
discovery) exactly as on the host. Manual equivalent:

```bash
podman run -d --name nmap-web --network host \
  -e NMAP_UI_HOST=127.0.0.1 -e NMAP_UI_PORT=8787 \
  -v nmap-web-data:/data \
  nmap-web
```

## Host networking — why and how

nmap needs raw sockets (SYN scans, OS fingerprinting, ARP discovery) and must
see the real network topology. The container therefore runs:

- **`--network host`** — the container shares the host's network stack. Scanning
  `192.168.1.0/24` inside the container is identical to running nmap on the host.
- **as root** — required for raw packet handling (Docker's default caps include
  `NET_RAW`).

> **macOS / Windows note:** Docker Desktop and Podman run inside a Linux VM.
> Host networking gives the container the **VM's** network stack — it does
> **not** reach your Mac's LAN the way it would on Linux, and ports bound
> inside the VM aren't forwarded to your Mac automatically. Don't use host
> networking there; use the port-mapped variant from
> [Quick start](#quick-start). On a Linux host, host networking is literal.
> Alternatively run the app natively (see [Local development](#local-development)).

### Rootless Podman caveat

If your Podman is **rootless** (the default for many Linux distros, e.g. via
`systemctl --user`), the container cannot open raw sockets inside the *host*
network namespace even with `--network host` — the `NET_RAW` capability simply
doesn't exist in the host's initial user namespace, so SYN scans fail with
`Couldn't open a raw socket`. Two options:

1. **Run rootful** (`sudo podman ...` or a rootful Docker daemon) — then host
   networking + the default image give the complete nmap experience (ARP, MAC
   vendors, link-layer discovery). This is the recommended setup on Linux.
2. **Use the port-mapped variant** `docker-compose.rootless.yml` — default
   (slirp4netns/passt) network with `cap_add: [NET_RAW, NET_ADMIN]`. SYN scans
   and OS detection work against the LAN; you lose L2 discovery (no ARP/MAC
   info), and the host itself must be addressed by its LAN IP (or
   `host.containers.internal`). This is also the correct setup on
   **macOS/Windows** — see [Quick start](#quick-start).

Quick self-test once the container is up:

```bash
# host networking (rootful Linux): scan your own loopback with SYN
podman exec nmap-web nmap -sS -F 127.0.0.1
```

If you see `Couldn't open a raw socket. Error: Operation not permitted`,
you're on a rootless setup — switch to the port-mapped variant
(`docker-compose.rootless.yml`), which grants `NET_RAW`/`NET_ADMIN` inside the
container's own network namespace.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `NMAP_UI_HOST` | `127.0.0.1` | Bind address. Keep localhost unless you set a token. |
| `NMAP_UI_PORT` | `8787` | HTTP port. |
| `NMAP_UI_DATA_DIR` | `./data` (`/data` in image) | Where scan history + output files live. Mount a volume. |
| `NMAP_UI_CONCURRENCY` | `2` | Max simultaneous nmap processes. |
| `NMAP_UI_HISTORY` | `200` | Max kept scan records. |
| `NMAP_UI_TOKEN` | *(empty)* | Optional auth token. Sent as `X-Auth-Token` header (API) / `?token=` (WS). |

## Local development (no container)

Requires Node.js ≥ 20 and a local `nmap` (`brew install nmap`, `apt install nmap`).

```bash
npm install
npm start          # http://127.0.0.1:8787
npm run dev        # auto-restart on changes
```

Run as root (or `sudo`) if you need raw-socket scan types (`-sS`, `-O`, …);
TCP connect scans (`-sT`) work unprivileged.

## Architecture

```
server.js          HTTP server + REST API + WebSocket hub (no framework)
lib/args.js        scan request → nmap argv builder (presets + all options)
lib/scanner.js     process manager: queue, concurrency, live events, cancel
lib/parse.js       nmap XML (-oX) → normalized JSON results
lib/store.js       JSON-file scan history persistence
public/            static UI (vanilla JS, zero external assets)
```

Each scan runs `nmap -oX -` (XML to stdout, parsed into structured results),
`-oN <file>` (human output kept for download) and `--stats-every 1s`
(progress lines streamed over WebSocket). See
[`docs/frontend-contract.md`](docs/frontend-contract.md) for the full API.

## Security notes

- **Scan only networks you own or are authorized to test.** nmap-web is a
  tool for network admins, pentesters and homelab owners — with host networking
  it is as powerful as running nmap directly on the machine.
- By default the UI binds to `127.0.0.1` and is only reachable from the local
  machine. If you bind `0.0.0.0` (e.g. to reach it from another machine),
  **always set `NMAP_UI_TOKEN`**. Consider putting it behind a reverse proxy
  with TLS and real auth.
- There is deliberately no built-in "sudo" abstraction: the container runs as
  root because raw sockets need it.

## License

MIT
