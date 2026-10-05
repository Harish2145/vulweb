# Local Pentest Lab — Nginx (CDN/Cache/WAF/Reverse Proxy) + Vulnerable Flask App

**For isolated local/offline use only. Never expose to the internet or a
shared network.** This app has no real security boundaries by design.

## Architecture

```
            ┌────────────────────────┐
  :8080 --> │  nginx (reverse proxy, │
            │  edge cache, toggle-   │
            │  able naive WAF)       │──────┐
            └───────────┬────────────┘      │ internal docker network
                         │                   │
                ┌────────▼─────────┐   ┌─────▼──────┐
                │  web (Flask app) │   │  metadata  │
                │  frontend+API    │   │  (fake SSRF│
                │  ~25 intentional │   │  target,   │
                │  vulns)          │   │  not on    │
                └──────────────────┘   │  host port)│
                                        └────────────┘
```

## Run it

```bash
cd pentestlab
docker compose up --build
```

App is reachable at **http://localhost:8080** (through nginx). The Flask
container itself is not published to the host — everything goes through
the proxy, as in a real deployment.

## Toggle the WAF

Edit `WAF_MODE` in `docker-compose.yml` (`on` or `off`), then:

```bash
docker compose up -d --build nginx
```

- `off` — pure reverse proxy + cache, nothing blocked (default; good for
  first learning each vuln clean).
- `on` — a naive regex "WAF" blocks obvious payloads (`UNION SELECT`,
  `<script`, `../`, known scanner user-agents). Good for practicing
  **WAF bypass** technique (encoding, case variation, comment injection,
  alternate payloads). See CHEATSHEET.md's "WAF Bypass" section.

## Reset the lab

```bash
docker compose down -v   # wipes the sqlite db + uploaded files
docker compose up --build
```

## What's inside

- `nginx/` — reverse proxy, edge cache (`proxy_cache`), toggleable WAF.
- `web/` — the vulnerable Flask application (frontend templates + JSON API).
- `metadata/` — a fake cloud instance-metadata endpoint, reachable only
  from the internal docker network, used as an SSRF target.
- `CHEATSHEET.md` — every vulnerability, its location, a PoC, and the fix.

## Scope note

Everything here runs on your own machine, in containers you control. The
same techniques must not be used against systems you don't have explicit
written authorization to test.
