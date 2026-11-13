# Frontend ↔ Backend contract

The backend (Node.js, `server.js`) serves the static UI from `public/` and exposes
this REST + WebSocket API. The frontend is vanilla JS (no build step, no CDN —
must work fully offline inside the container).

## Base URL
Same origin. If an auth token is configured (`NMAP_UI_TOKEN`), every API request
must include header `X-Auth-Token: <token>` and the WS URL must carry
`?token=<token>`.

## REST

### GET /api/health
```json
{ "ok": true, "nmapVersion": "Nmap version 7.94 ( https://nmap.org )" }
```
`nmapVersion` is `null` when the `nmap` binary is not on PATH (the server
logs a warning and still serves; scans will fail until nmap is installed).

### GET /api/presets
```json
{ "presets": [ { "id": "quick", "label": "Quick scan", "desc": "..." }, ... ] }
```
ids: regular, quick, quickPlus, pingSweep, quickTraceroute, intense, intenseUdp,
intenseAllTcp, intenseAllPlusUdp, intenseNoPing, fullPortSyn, vuln,
slowComprehensive, custom

### POST /api/scan
Request:
```json
{
  "targets": "192.168.1.1\n192.168.1.0/24\nexample.com",
  "name": "optional label",
  "profile": "intense",
  "options": {
    "scanType": "syn | connect | udp | ack | window | maimon | fin | xmas | null | sctpInit | sctpCookie | pingSweep | list | none",
    "ports": "default | all | fast | top | list",
    "topPorts": 100,
    "portList": "22,80,443,8000-9000",
    "ping": { "skip": false, "synPorts": "", "ackPorts": "", "udpPorts": "", "icmpEcho": false, "icmpTimestamp": false, "icmpNetmask": false, "disableArp": false, "dns": "default | always | never" },
    "service": { "version": false, "intensity": 7, "light": false, "all": false },
    "os": { "detect": false, "guess": false },
    "aggressive": false,
    "scripts": { "defaults": false, "list": "", "args": "", "trace": false },
    "timing": { "template": 3, "minRate": "", "maxRate": "", "hostTimeout": "", "scanDelay": "", "maxRetries": "" },
    "firewall": { "fragment": false, "mtu": "", "decoys": "", "spoofSource": "", "sourcePort": "", "dataLength": "", "ttl": "", "spoofMac": "", "badsum": false, "interface": "" },
    "output": { "verbose": 0, "reason": false, "openOnly": false, "packetTrace": false, "traceroute": false, "ipv6": false },
    "extraArgs": ""
  }
}
```
Response 201: `{ "id": "a1b2c3d4e5f6", "status": "queued" }`
Response 400: `{ "error": "Targets are required." }`

### GET /api/scans
```json
{ "scans": [ { "id": "...", "name": null, "targets": "...", "profile": "intense",
  "command": "nmap -T4 -A -v ...", "status": "queued|running|done|error|cancelled",
  "exitCode": 0, "error": null, "stderrTail": ["line", "..."] | null, "createdAt": "ISO", "queuedAt": "ISO|null",
  "startedAt": "ISO|null", "finishedAt": "ISO|null", "durationMs": 1234,
  "summary": null } ] }
```
`stderrTail` (error scans only): up to 40 lines of nmap stderr, as an array.
`summary` (when done): `{ "hostsUp": n, "hostsDown": n, "openPorts": n, "closedPorts": n, "filteredPorts": n, "services": { "http": 3 }, "elapsed": "2.01", "exit": "success" }` — note `closedPorts`/`filteredPorts` include nmap's `<extraports>` counts.

### GET /api/scans/:id
```json
{ "scan": { ...meta as above..., "options": {...}, "result": {...}|null } }
```

### DELETE /api/scans/:id
Active scan → `{ "id": "...", "status": "cancelling" }`; finished → `{ "id": "...", "status": "deleted" }`

### POST /api/scans/:id/cancel → `{ "id": "...", "status": "cancelling" }`
Inactive/finished scan → `409 { "error": "Scan is not active" }`

### GET /api/scans/:id/output.xml  /  output.txt  → file download
(`HEAD` is also supported and returns the same headers without a body.)

## WebSocket: /ws/scan/:id  (+ ?token=)

Server sends JSON events:
```json
{ "type": "queued",   "position": 1 }
{ "type": "started",  "command": "nmap -T4 -A ...", "pid": 42, "startedAt": "ISO" }
{ "type": "log",      "line": "Stats: 0:01:02 elapsed; ...", "ts": 123456 }
{ "type": "progress", "percent": 42.1, "stats": "SYN Stealth Scan Timing: About 42.10% done" }
{ "type": "done",     "result": {...}, "summary": {...}, "exitCode": 0, "durationMs": 1234, "finishedAt": "ISO" }
{ "type": "error",    "message": "...", "stderrTail": ["..."] }
{ "type": "cancelled","exitCode": null }
```
(`exitCode` may be omitted when a queued scan is cancelled before it starts.)
On connect the server replays a snapshot event matching current status
(queued/started/done/cancelled/error), then streams live events. Reconnect with
exponential backoff on close.

## result object (from GET /api/scans/:id or the `done` event)

```json
{
  "scanner": { "name": "nmap", "version": "7.94", "args": "...", "startstr": "..." },
  "scanInfo": [ { "type": "syn", "protocol": "tcp", "numservices": "1000", "services": "1-1024,..." } ],
  "verbose": "0",
  "debugging": "0",
  "hosts": [
    {
      "address": "192.168.1.1",
      "type": "ipv4",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "Acme Corp",
      "hostnames": ["router.lan"],
      "state": "up | down | unknown",
      "status": { "state": "up", "reason": "syn-ack", "reason_ttl": "64" },
      "ports": [
        {
          "portid": "80",
          "protocol": "tcp",
          "state": "open | closed | filtered | unfiltered | open|filtered | closed|filtered",
          "reason": "syn-ack",
          "reason_ttl": "64",
          "service": { "name": "http", "product": "nginx", "version": "1.18.0",
                        "extrainfo": "Ubuntu", "ostype": "", "method": "probed", "conf": "10",
                        "cpe": ["cpe:/a:nginx:nginx:1.18.0"] },
          "scripts": [ { "id": "http-title", "output": "Welcome to nginx!", "text": "Welcome to nginx!\ntitle:\n  value: Welcome" } ],
          "owner": ""
        }
      ],
      "os": {
        "portsUsed": [ { "state": "open", "proto": "tcp", "portid": "80" } ],
        "matches": [
          { "name": "Linux 5.x", "accuracy": "98", "line": "123",
            "cpe": [], "classes": [ { "type": "general purpose", "vendor": "Linux",
            "osfamily": "Linux", "osgen": "5.X", "accuracy": "98", "cpe": [] } ] }
        ]
      },
      "traceroute": [ { "port": "80", "protocol": "tcp", "hops": [ { "ttl": "1", "ipaddr": "192.168.1.1", "rtt": "0.42", "host": "router.lan" } ] } ],
      "hostScripts": [ { "id": "ip-forwarding", "output": "1", "text": "1" } ],
      "uptime": { "seconds": "123456", "lastboot": "..." },
      "distance": { "value": "1" },
      "times": { "srtt": "123", "rttvar": "100", "to": "100000" }
    }
  ],
  "runStats": {
    "finished": { "time": "2", "timestr": "...", "summary": "Nmap done at ...; 1 IP address (1 host up) scanned in 2.01 seconds", "elapsed": "2.01", "exit": "success", "errormsg": "" },
    "hosts": { "up": "1", "down": "0", "total": "1" }
  },
  "summary": { "hostsUp": 1, "hostsDown": 0, "openPorts": 1, "closedPorts": 0,
               "filteredPorts": 0, "services": { "http": 1 }, "elapsed": "2.01", "exit": "success", "errormsg": "" }
}
```

Notes:
- `summary.exit` may be `"error"` (e.g. raw sockets unavailable in the container);
  show `summary.errormsg` / `runStats.finished.errormsg` as a prominent warning
  banner in the results view.
- All `service` fields except `name` may be empty strings; `service` may be null.
- `scripts[].text` is the full readable output (tables serialized); `output` is the raw
  attribute. Prefer `text`.
- `os.matches[].accuracy` is a string "0"–"100" → render as accuracy bar.
- Port state chips: open=green, open|filtered=amber, filtered=orange, closed=gray,
  closed|filtered=gray, unfiltered=blue, unknown=dim.
- Guard every field — a bare `-sn` scan has no `ports`, no `os`, no `traceroute`.
