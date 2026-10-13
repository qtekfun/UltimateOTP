# Deploying the UltimateOTP server

The server is one small container (`api`) plus a one-shot `migrate`, built from
`server/Dockerfile` and run with `server/compose.yaml`. It stores only ciphertext, wrapped keys
and public keys (design §4.2): losing it never loses a secret, and a dump of it reveals none
without the master password or the recovery key. The homelab layout below mirrors UltimateTunes
(`stacks/media/ultimatetunes/` in the homelab repository): Cloudflare Tunnel -> Traefik v3 -> a
dedicated proxy network -> the api.

## 1. Files

| File | What |
|---|---|
| `server/Dockerfile` | Python 3.13 slim, pinned by digest; uv-locked dependencies; non-root uid 10001; migrations in `/app/migrations` |
| `server/compose.yaml` | `migrate` then `api`; read-only root, `cap_drop: ALL`, `no-new-privileges`, pids/memory/CPU/file limits; data in the `data` volume; port on loopback only |
| `server/deploy/traefik.override.yaml` | the Traefik labels, the dedicated `otp-proxy` network, the LAN-only enrollment routes |

Build: `docker build -f server/Dockerfile -t ultimateotp-server:0.1.0 .` from the repository root.

## 2. Settings (`UOTP_*`, all optional unless stated)

| Variable | Default | Meaning |
|---|---|---|
| `UOTP_TRUSTED_PROXIES` | empty | CIDRs whose `X-Forwarded-For` is believed (Traefik's pinned address, cloudflared). Empty: none |
| `UOTP_ENROLLMENT_SCOPE` | `lan` | `lan` or `anywhere`: where the enrollment surface answers (decision 4) |
| `UOTP_LAN_NETWORKS` | `127.0.0.0/8,::1/128,192.168.0.0/16,fd00::/8` | the owner's LAN/tailnet; **narrow it to your /24 and never include a Docker range** |
| `UOTP_DENIED_NETWORKS` | empty | never LAN, whatever the above says (put the proxy subnet here) |
| `UOTP_METRICS_NETWORKS` | loopback | who may read `/metrics` |
| `UOTP_SIGNATURE_MAX_SKEW_S` | 60 | request timestamp window |
| `UOTP_ENROLLMENT_TOKEN_TTL_S`, `UOTP_PAIRING_TTL_S` | 600 | lifetimes |
| `UOTP_RECOVERY_FETCH_LIMIT` | 5 | wrap fetches per enrollment token |
| `UOTP_MAX_BODY_BYTES` / `UOTP_MAX_ITEMS` | 4 MiB / 2000 | request and vault size caps |
| `UOTP_SSE_KEEPALIVE_S` / `UOTP_SSE_MAX_AGE_S` / `UOTP_SSE_MAX_STREAMS_PER_DEVICE` | 15 / 3600 / 3 | live sync (docs/sync.md) |
| `UOTP_RATELIMIT_ENABLED` and `UOTP_*_RATE_PER_S` / `UOTP_*_BURST` | on | in-app limits per client (`enroll`, `auth_failure`) and per device (`mint`, `write`) |
| `UOTP_LOG_LEVEL` | `INFO` | JSON logs on stdout |

There are no secrets to configure: the server holds no key of its own.

## 3. Homelab: Cloudflare Tunnel -> Traefik (dedicated network)

Same reasoning as UltimateTunes' approach A: the api trusts `X-Forwarded-For` only from Traefik's
pinned address, so it must not sit on the shared `traefik` network where any neighbour could reach
it or spoof that address. It joins a small bridge shared only with Traefik.

1. **Network** (once, on the host):
   ```sh
   docker network create --subnet 10.213.49.0/24 --ip-range 10.213.49.128/25 otp-proxy
   ```
   `.2` is kept for Traefik's pin (10.213.44-48 are taken by UltimateTunes).
2. **Traefik joins `otp-proxy`** with `ipv4_address: 10.213.49.2` (stack
   `stacks/networking/traefik/compose.yml`). This recreates Traefik: a few seconds of downtime.
3. **Stack** `stacks/security/ultimateotp/`: copy `server/compose.yaml` as `compose.yml` and
   `server/deploy/traefik.override.yaml` as `compose.override.yml`; `.env`:
   ```sh
   UOTP_VERSION=0.1.0
   UOTP_PUBLIC_HOST=otp.example.org
   # Traefik's pinned otp-proxy address and cloudflared's address on the traefik network.
   UOTP_TRUSTED_PROXIES=10.213.49.2/32,172.31.0.250/32
   # LAN /24 + tailnet. NEVER 172.16.0.0/12 or any Docker range.
   UOTP_LAN_NETWORKS=192.168.88.0/24,100.64.0.0/10,fd7a:115c:a1e0::/48
   UOTP_PROXY_SUBNET=10.213.49.0/24
   ```
4. **Cloudflare**: public hostname `otp.example.org` -> `https://traefik:443`, origin server name
   set, cache bypassed for the whole hostname. Cloudflare gives up on an origin that stays silent
   for about 100 s; the 15 s keepalive comment of the event stream keeps it well below that.
5. **Start**: `docker compose config --quiet && docker compose up -d`.
6. **First device**: on the host, `docker compose exec api ultimateotp account-create
   --server-url https://otp.example.org`, then enroll the phone **on the home Wi-Fi** with the
   printed token (valid 10 minutes, single use). The printed `uotp://enroll?server=...&token=...`
   link is a proposal for the app to scan as a QR code; the app may ignore it.
7. **Verify from outside** (mobile data): `https://otp.example.org/otp/v1/server-info` answers;
   `/healthz`, `/readyz`, `/metrics` give 404 (no router); `POST /otp/v1/enroll` gives 403 at
   Traefik. Commits and the event stream work.

### Routers (`server/deploy/traefik.override.yaml`)

| Router | Rule | Middlewares | Why |
|---|---|---|---|
| `otp-enroll` (300) | `/otp/v1/enroll`, `/otp/v1/recovery/keys`, `/otp/v1/pairings/*/join`, `/otp/v1/pairings/*/result` | `local-ip-whitelist@file`, 1 r/s burst 5, inflight 4, body limit | the only routes reachable without a device key; `recovery/keys` returns what an offline password guess needs |
| `otp-events` (250) | `GET /otp/v1/events` | 6 r/min burst 10, inflight 8, **no buffering** | SSE must stream |
| `otp-write` (200) | non-GET `/otp/v1/*` | 5 r/s burst 20, inflight 8, body <= 4.5 MB | commits, rotation, revocation |
| `otp-client` (100) | `/otp/v1/*` | 10 r/s burst 50, inflight 8 | reads |

No Authelia on API routes: native app with signed requests. There is **no admin web page**: the
admin surface is the CLI inside the container (`docker compose exec api ultimateotp ...`), so it is
reachable only by whoever controls the host. Rate limits exist twice: per client at Traefik, and in
the api (per resolved client on enrollment and on authentication failures, per device on writes).

### Allowing enrollment from outside the LAN (decision 4, still open)

Two switches, both needed: remove `local-ip-whitelist@file` from the `otp-enroll` router, and set
`UOTP_ENROLLMENT_SCOPE=anywhere`. Consequence: whoever holds a fresh enrollment token can then
fetch the password wraps from anywhere (at most 5 times per token) and try passwords offline. The
token is single-use, short-lived and minted only by the CLI or an enrolled device, so the risk is a
leaked token, but the Argon2id cost and the password strength become the only barrier. Flip it back
after travelling.

## 4. Backups and restore

The database is one SQLite file in the `data` volume. Its content is already end-to-end
encrypted; backups still deserve encryption because they reveal metadata (number of items,
device labels, timing).

Online, consistent copy (SQLite backup API, safe while the api writes):

```sh
docker compose exec -T api ultimateotp backup /data/backup.db
docker compose cp api:/data/backup.db ./ultimateotp-$(date +%F).db
docker compose exec -T api python -c "import os; os.remove('/data/backup.db')"
age -r <offline age recipient> -o ultimateotp-$(date +%F).db.age ultimateotp-$(date +%F).db
shred -u ultimateotp-$(date +%F).db
```

Nightly to the NAS, 30 daily and 12 monthly copies (design §4.6). Test a restore monthly:
`sqlite3 restored.db 'PRAGMA integrity_check'` and start a throwaway stack on it.

**Restoring is a rollback by design.** Devices remember the highest vault version they accepted
and refuse an older signed head (anti-rollback, design §4.4). After a restore, the app must
offer "the server lost data: upload my copy", which commits the device's full state on top of the
restored version (the device trusts its own state). Until then, devices keep working offline.
Prefer the devices' own encrypted exports when the backup is old.

Housekeeping: `docker compose exec api ultimateotp purge` deletes expired tokens, finished
pairings and old nonces (cron it weekly; nothing breaks if you never do).

## 5. Health, metrics, logs

- `GET /healthz`: the process answers. `GET /readyz`: database present and fully migrated (503
  otherwise); used by the compose healthcheck. Neither is routed by Traefik.
- `GET /metrics` (Prometheus text) for `UOTP_METRICS_NETWORKS` only: `uotp_events_total{event}`
  (enrollments, commits, conflicts, rejected heads, revocations, wrap fetches, auth failures,
  rate-limit hits), `uotp_problems_total{code}`, `uotp_sse_streams`. To scrape from another
  container, add that container's single address to `UOTP_METRICS_NETWORKS`.
- An external uptime check can use `https://otp.example.org/otp/v1/server-info`.
- Logs: one JSON object per line on stdout. Security events on the `ultimateotp.security`
  logger with a stable `event`: `auth.failure` (with `reason`), `ratelimit.hit`,
  `enroll.success`, `enroll.denied_network`, `enroll.token_created`, `recovery.keys_fetched`,
  `pairing.created|joined|rejected`, `device.revoked`, `vault.commit`, `vault.conflict`,
  `vault.head_rejected`, `vault.rotated`, `keys.updated`, `sse.open`. Requests are logged as
  `http.request` with the resolved client address and the path without query string. Bodies,
  headers, tokens and blobs are never logged, and a redaction filter removes tokens, bearer
  values, signatures and long base64 runs as a second line of defence.
- Worth an ntfy alert (CrowdSec or a log shipper): `enroll.success`, `device.revoked`,
  `recovery.keys_fetched`, `vault.rotated`, and bursts of `auth.failure` or `vault.head_rejected`.

## 6. Operating limits

- One api process only (in-memory live-sync broker, docs/sync.md). Do not scale the service.
- uvicorn has no request-header timeout: never expose the api port directly, keep Traefik in
  front.
- A request through Docker's port publishing from the host itself arrives from the bridge
  gateway (e.g. `172.19.0.1`), which is not in the LAN list: enrollment from the host fails
  closed (403). That is intended; enroll from a phone on the LAN through Traefik.
