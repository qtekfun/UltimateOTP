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
| `UOTP_ENROLLMENT_SCOPE` | `anywhere` | where password login (email code + SRP) and sign-up answer (decision 6) |
| `UOTP_PAIRING_SCOPE` | `lan` | where enrollment tokens (bootstrap, CLI) and device pairing answer |
| `UOTP_SIGNUP` | `disabled` | public sign-up from the app (`POST /otp/v1/signup`); open it only to create your account (§3 step 6), otherwise accounts come from `ultimateotp account-create` (decision 8) |
| `UOTP_EMAIL_VERIFICATION` | `enabled` | emailed login codes (decision 13); `disabled` only for development |
| `UOTP_SMTP_HOST` / `_PORT` / `_USER` / `_FROM` | `smtp.resend.com` / 587 / `resend` / required | STARTTLS relay; the password is the Docker secret `uotp_smtp_password` (the Resend API key) |
| `UOTP_SMTP_CA_FILE` | empty | extra CA bundle for a private relay |
| `UOTP_EMAIL_CODE_TTL_S` / `_MAX_ATTEMPTS` | 600 / 5 | login codes |
| `UOTP_SRP_LOCKOUT_THRESHOLD` / `_BASE_S` / `_MAX_S` | 5 / 60 / 86400 | per-account lockout after consecutive wrong passwords, doubling |
| `UOTP_NTFY_URL` | empty | ntfy topic URL for notifications (decision 7); token in the Docker secret `uotp_ntfy_token` |
| `UOTP_LAN_NETWORKS` | `127.0.0.0/8,::1/128,192.168.0.0/16,fd00::/8` | the owner's LAN/tailnet; **narrow it to your /24 and never include a Docker range** |
| `UOTP_DENIED_NETWORKS` | empty | never LAN, whatever the above says (put the proxy subnet here) |
| `UOTP_METRICS_NETWORKS` | loopback | who may read `/metrics` |
| `UOTP_SIGNATURE_MAX_SKEW_S` | 60 | request timestamp window |
| `UOTP_ENROLLMENT_TOKEN_TTL_S`, `UOTP_PAIRING_TTL_S` | 600 | lifetimes |
| `UOTP_RECOVERY_FETCH_LIMIT` | 5 | wrap fetches per enrollment token |
| `UOTP_MAX_BODY_BYTES` / `UOTP_MAX_ITEMS` | 4 MiB / 2000 | request and vault size caps |
| `UOTP_SSE_KEEPALIVE_S` / `UOTP_SSE_MAX_AGE_S` / `UOTP_SSE_MAX_STREAMS_PER_DEVICE` | 15 / 3600 / 3 | live sync (docs/sync.md) |
| `UOTP_RATELIMIT_ENABLED` and `UOTP_*_RATE_PER_S` / `UOTP_*_BURST` | on | in-app limits per client (`enroll`, `auth_failure`) and per device (`mint`, `write`) |
| `UOTP_IP_SECRET` | empty | optional Docker secret `uotp_ip_secret` (32+ random characters): the secret of the daily client-id salts (§6). Empty: the server makes one and keeps it in the database |
| `UOTP_BLOCK_ENABLED` | `true` | temporary blocking of clients that keep failing (§6); `false` is the off switch |
| `UOTP_BLOCK_THRESHOLD` / `_WINDOW_S` | 20 / 600 | failed or abusive attempts of one client within the window that start a block |
| `UOTP_BLOCK_DURATIONS_S` | `900,3600,86400` | 1st, 2nd, 3rd... block of a client (the last repeats): 15 min, 1 h, 24 h |
| `UOTP_BLOCK_DECAY_S` | 86400 | a client quiet this long after its block ended starts again at the first length |
| `UOTP_BLOCK_PERSIST` | `true` | keep active blocks in SQLite so a restart does not wipe a 24 h block |
| `UOTP_HISTORY_RETENTION_DAYS` | 30 | how long previous vault versions (the app's trash and undo) are kept; `0` turns history off (§8) |
| `UOTP_HISTORY_MAX_VERSIONS` / `_MAX_BYTES` | 1000 / 33554432 | per account: retained versions and bytes of previous blobs |
| `UOTP_TOMBSTONE_RETENTION_DAYS` | 0 | delete tombstones older than this (0: keep forever). Clients behind a compacted tombstone are sent the full set (§8) |
| `UOTP_MAINTENANCE_INTERVAL_S` | 3600 | background housekeeping: history, tombstones, expired codes, block rows |
| `UOTP_ACCOUNT_ACTION_PER_HOUR` / `_BURST` | 10 / 5 | per account: re-authentication codes and proofs, account deletion, email change (§7) |
| `UOTP_EXPORT_PER_HOUR` / `_BURST` | 6 / 3 | full account exports per device |
| `UOTP_HISTORY_RATE_PER_S` / `_BURST` | 2 / 30 | history and trash reads per device |
| `UOTP_LOG_LEVEL` | `INFO` | JSON logs on stdout |

Secrets (Docker secrets, never environment variables or logs): `uotp_smtp_password` (the Resend
API key, required while email verification is on), `uotp_ntfy_token` (optional) and
`uotp_ip_secret` (optional, §6). The server holds no key that decrypts anything.

**Startup rule (decision 13):** the api, and the CLI commands that may send mail
(`account-create`, `token-create`, `device-revoke`), refuse to start when email verification is
on and `UOTP_SMTP_HOST`, `UOTP_SMTP_FROM` or the secret is missing. `migrate`, `backup` and the
read-only commands never need SMTP.

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
   UOTP_SMTP_FROM=UltimateOTP <otp@example.org>   # a sender of your Resend domain
   UOTP_NTFY_URL=https://ntfy.example.org/ultimateotp   # optional
   ```
   and `secrets/resend_api_key` (and `secrets/ntfy_token`, uncommenting its lines in
   `compose.yml`), folder `700`, files `644` (the container runs as uid 10001).
4. **Cloudflare**: public hostname `otp.example.org` -> `https://traefik:443`, origin server name
   set, cache bypassed for the whole hostname. Cloudflare gives up on an origin that stays silent
   for about 100 s; the 15 s keepalive comment of the event stream keeps it well below that.
5. **Start**: `docker compose config --quiet && docker compose up -d`.
6. **First device: sign up from the app** (like Ente Auth). Open sign-up for the few minutes it
   takes, then close it again:
   1. set `UOTP_SIGNUP=enabled` in `.env` and `docker compose up -d` (recreates the api);
   2. in the app, choose **Create account** on the first screen (or Settings → Sync → Create
      account): server URL, email, the 6-digit code from the email, a password (it encrypts
      everything and cannot be reset; the app shows a strength hint), then write down the 24-word
      recovery key and confirm it. Since 1.3.0 the first step stops at once (`409 email_taken`, or
      `403 signup_disabled`, before any email) when the address already has an account or sign-up is
      closed; this is the only place where an address's existence is told, and only while sign-up is open.
      The app creates the account with `POST /otp/v1/signup`, and the
      codes already on the phone become the account's first entries;
   3. set `UOTP_SIGNUP=disabled` again and `docker compose up -d`.

   Every later device chooses **Log in** (email code + password, SRP) from anywhere, or pairs by
   QR on the LAN. While sign-up is open, anyone who can reach the server and receive email can
   create an account on it, which is why it stays closed by default (decision 8).

   *Alternative, sign-up kept closed (CLI token, LAN only):* on the host,
   `docker compose exec api ultimateotp account-create --email you@example.org --server-url
   https://otp.example.org`. The address gets a 6-digit code; in the app choose **Advanced:
   enrollment token or pairing** and enroll the phone **on the home Wi-Fi** with the printed token
   (valid 10 minutes, single use) and that code, which verifies the address once. The printed
   `uotp://enroll?server=...&token=...` link is a proposal for the app to scan as a QR code; the
   app may ignore it.
7. **Verify from outside** (mobile data): `https://otp.example.org/otp/v1/server-info` answers;
   `/healthz`, `/readyz`, `/metrics` give 404 (no router); `POST /otp/v1/enroll` gives 403 at
   Traefik; `POST /otp/v1/srp/attributes` answers (password login is public). Commits and the
   event stream work. Send a test login to check that the code email arrives through Resend.

### Routers (`server/deploy/traefik.override.yaml`)

| Router | Rule | Middlewares | Why |
|---|---|---|---|
| `otp-login` (300) | `POST /otp/v1/srp/{attributes,session,verify}`, `/otp/v1/login/email-code`, `/otp/v1/signup` | 6 r/min burst 8, inflight 4, body limit; **public** | password login from anywhere (decision 6); the api adds per-client and per-address email limits and the per-account SRP lockout |
| `otp-enroll` (300) | `/otp/v1/enroll`, `/otp/v1/recovery/keys`, `/otp/v1/pairings/*/join`, `/otp/v1/pairings/*/result` | `local-ip-whitelist@file`, 1 r/s burst 5, inflight 4, body limit | enrollment tokens and pairing stay on the LAN; `recovery/keys` returns what an offline password guess needs |
| `otp-events` (250) | `GET /otp/v1/events` | 6 r/min burst 10, inflight 8, **no buffering** | SSE must stream |
| `otp-write` (200) | non-GET `/otp/v1/*` | 5 r/s burst 20, inflight 8, body <= 4.5 MB | commits, rotation, revocation |
| `otp-client` (100) | `/otp/v1/*` | 10 r/s burst 50, inflight 8 | reads |

No Authelia on API routes: native app with signed requests. There is **no admin web page** (decision 8): the
admin surface is the CLI inside the container (`docker compose exec api ultimateotp ...`:
`account-create --email`, `account-email-check ACCOUNT on|off`, `token-create`, `accounts`,
`devices`, `device-revoke`, `backup`, `purge`), so it is reachable only by whoever controls the host. Rate limits exist twice: per client at Traefik, and in
the api (per resolved client on enrollment and on authentication failures, per device on writes).

### Logging in from anywhere (decisions 6 and 13) and what stays on the LAN

Password login is public, like Ente's: emailed 6-digit code (10 min, single use, 5 tries), then an
SRP-6a proof (RFC 5054 4096-bit group, SHA-256). The server stores only the SRP verifier and salt,
releases the password-wrapped vault key only after a valid proof, and registers the device's key in
the same request. Defences, outermost first: Cloudflare/CrowdSec, the `otp-login` Traefik limit,
the api's per-client limits (`srp`, `email_ip`) and per-destination email limit
(`email_address`), the per-code attempt limit, and the per-account exponential lockout. Unknown
addresses get decoy answers and no email, so the routes do not reveal who has an account.

Still LAN-only by default: the bootstrap enrollment token, CLI- or device-minted tokens, the
token-based wrap fetch (recovery-key path) and pairing. To open them while travelling, remove
`local-ip-whitelist@file` from `otp-enroll` and set `UOTP_PAIRING_SCOPE=anywhere`; then a leaked
token alone would let someone fetch the wraps and guess passwords offline, so flip it back.

Recovery with the 24-word key (decision 10) is a client feature on top of that path: a CLI token
(LAN), `GET /otp/v1/recovery/keys`, unwrap locally with the recovery key, enroll, then set a new
password (`PUT /otp/v1/account/keys` with new wraps and a new `srp` record). The server sees only
opaque wraps.

### Email (Resend) and ntfy

- Mail leaves through one background worker: SMTP to `UOTP_SMTP_HOST:UOTP_SMTP_PORT`, STARTTLS
  required (a relay that does not offer it gets neither the key nor the message), then AUTH with
  `UOTP_SMTP_USER` and the secret. Sent: login codes, account-verification codes, and notices for
  recovery-data fetches and vault-key rotations.
- ntfy (optional): a `POST` to `UOTP_NTFY_URL` with `Title`, `Tags`, `Priority` and, when the
  secret exists, `Authorization: Bearer`. Sent on: a device login or enrollment (any path), a
  revocation, a recovery-data fetch, a rotation, and an SRP lockout (repeated wrong passwords).
- Messages contain event names, device labels, client addresses and times, never a token, key,
  wrap or password. A failed delivery is logged and never fails the API request.
- The api needs outbound access to the relay and the ntfy server (its default network).

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
- `GET /metrics` (Prometheus text) for `UOTP_METRICS_NETWORKS` only (loopback by default, never
  routed by Traefik). The families, with no personal label (never an account, device, client or
  address), and how to scrape them are in §9.
- An external uptime check can use `https://otp.example.org/otp/v1/server-info`.
- Logs: one JSON object per line on stdout. **A client address never appears in them**: requests
  and events carry `client_id`, the anonymized id of §6. Security events on the
  `ultimateotp.security` logger with a stable `event`: `auth.failure` (with `reason`),
  `ratelimit.hit`, `enroll.success`, `enroll.denied_network`, `enroll.token_created`,
  `recovery.keys_fetched`, `pairing.created|joined|rejected`, `device.revoked`, `vault.commit`,
  `vault.conflict`, `vault.head_rejected`, `vault.rotated`, `keys.updated`, `sse.open`. Requests are
  logged as `http.request` with the anonymized client id and the path without query string.
  Bodies, headers, tokens and blobs are never logged, and a redaction filter removes tokens,
  bearer values, signatures, long base64 runs and, as a last line of defence, anything that looks
  like an IPv4 or IPv6 address.
- Events of 1.1.0: `srp.session`, `srp.success`, `srp.failure` (with `failures`), `srp.lockout`
  (with `locked_for_s`), `srp.locked`, `email.code_requested`, `email.code_failure`,
  `signup.success`, `account.email_check`.
- Events of 1.2.0: `client.blocked` (`client_id`, `block_level`, `duration_s`, `reason`),
  `login.unknown_account` (`stage`), `account.reauth_code_requested`,
  `account.reauth_srp_started`, `account.deleted`, `account.email_change_requested`,
  `account.email_changed`, `devices.revoked_others`, `account.exported`. Account events keep the
  `account_id` and `device_id` (opaque server ids) for the audit trail.
- The server sends ntfy itself (above); `auth.failure` and `vault.head_rejected` bursts are still
  worth a log-based alert. The CrowdSec parser and scenarios are in §6.

## 6. Anonymized client addresses and temporary blocking

### 6.1 No client IP in logs, metrics, notices, the database or rate-limit keys

A client address (after `X-Forwarded-For` has been resolved, §2 `UOTP_TRUSTED_PROXIES`) lives only
in the memory of the request that carries it, where the LAN checks need it. Everywhere else the
server uses an **anonymized client id**:

```
daily_salt = HMAC-SHA256(server_secret, "uotp-client-salt-v1|" + UTC date)
client_id  = "c_" + hex(HMAC-SHA256(daily_salt, address))[:12]      (IPv6: the /64 is hashed)
```

"Many attempts from the same address within one day" stays visible; the address cannot be
recovered from the id, and the ids of two different days cannot be linked by anyone who does not
hold the secret. It is used in the access log, every security event, ntfy and email notices, the
per-client rate-limit buckets, the block table and the `last_ip` of the active-sessions list
(which therefore shows an opaque id, stable for one UTC day, instead of an address; 1.1.0 stored
raw addresses and migration 0002 erases them). Metrics never carry a client label at all.

- **Secret.** `UOTP_IP_SECRET` (Docker secret `uotp_ip_secret`) if set, else 32 random bytes the
  server creates once in the `server_secrets` table, so ids survive restarts. It is never logged.
  Only today's salt is cached; no old salt is kept anywhere, and ids rotate at 00:00 UTC.
- **One deliberate exception: blocks.** A block set at 23:00 for 24 h must hold after midnight, so
  the block list also checks the *previous* day's id of the caller (derived on demand, not stored)
  and a back-off level carries over one midnight. A client that stays away for two UTC days starts
  fresh. Nothing older than yesterday is ever linked.
- **What this does not hide.** Whoever holds the secret (the host, a database backup) can test a
  guessed address against an id; IPv4 is small enough to enumerate. The protection is against
  people who read *logs*, log shippers and CrowdSec, not against the host owner, who sees the
  real addresses at the proxy anyway. Traefik's own access log and Cloudflare keep real addresses:
  the rule above applies to the api only. Treat database backups as sensitive (they hold the
  secret). To rotate it, delete the `client-id-secret` row (or change `uotp_ip_secret`) and restart:
  all ids change and active blocks end.
- The `last_ip` column keeps its name for contract stability; its content is the id.

### 6.2 Temporary blocking with a growing back-off

On top of the per-route token buckets (Traefik and the api) and the per-account SRP lockout, the
api counts **failed or abusive attempts per client id, across all routes**: wrong SRP proofs and
unknown or expired handshakes, wrong email codes, unknown-account probes (a code or handshake for
an address nobody has), signature failures (unknown device, bad signature, replay, bad token),
knocking on a locked account, refused vault heads, enrollment from outside the LAN, and rate-limit
hits. A request counts once however many events it logs. At `UOTP_BLOCK_THRESHOLD` (20) within
`UOTP_BLOCK_WINDOW_S` (10 min) the client is blocked: every `/otp/v1` request answers
`429 client_blocked` with `Retry-After` for 15 min; the next block of the same client lasts 1 h,
then 24 h (the last length repeats). A client quiet for `UOTP_BLOCK_DECAY_S` (24 h) after its
block ended starts again at 15 min.

- **A successful login does not erase a block or a count.** A guesser that found the password is
  not rewarded, and a block is not something the blocked party can lift. Requests during a block
  are refused before routing and do not extend it.
- **The owner's LAN is exempt** (`UOTP_LAN_NETWORKS`, minus `UOTP_DENIED_NETWORKS`; a request that
  came through an untrusted proxy is never LAN). Keep that list narrow: a wide one exempts
  strangers. If `UOTP_TRUSTED_PROXIES` is wrong every client looks like the proxy and one bad
  client blocks everyone: the `UltimateOTPBlockedClientsNow` alert and
  `/otp/v1/server-info` from outside tell you.
- **State** is in memory, mirrored to the `client_blocks` table when `UOTP_BLOCK_PERSIST` is on
  (default), so a restart does not wipe an active 24 h block. Counts are not persisted.
  `UOTP_BLOCK_ENABLED=false` switches everything off.
- **CLI** (`docker compose exec api ultimateotp ...`):
  ```sh
  ultimateotp blocks list                  # id, level, remaining seconds, last reason
  ultimateotp blocks clear c_0123456789ab  # lift one block and its back-off level
  ultimateotp blocks clear --all
  ```
  The api re-reads the table every 5 s while it holds a block, so a clear takes effect within
  seconds. With persistence off the CLI sees nothing (it is another process).
- **Event for CrowdSec**: when a block starts the api logs, on `ultimateotp.security`:
  ```json
  {"time": "...", "level": "WARNING", "logger": "ultimateotp.security", "message": "client.blocked",
   "event": "client.blocked", "client_id": "c_0123456789ab", "block_level": 1,
   "duration_s": 900, "reason": "srp.failure"}
  ```
  and fires ntfy at the longest level. Metrics: `uotp_blocks_total`, `uotp_blocked_clients`.

### 6.3 CrowdSec: parser and scenarios (not validated here)

The api cannot hand CrowdSec an address on purpose, so a decision on a `client_id` is a record
and an alert (`cscli alerts list`, the notification plugins), **not** something a firewall bouncer
can enforce: the enforcement is the api's own block above, and the real addresses stay in the
Traefik access log that the Traefik bouncer already reads. What CrowdSec adds is correlation and
notification across your other services. The files below are a ready starting point; they were
written against the documented parser/scenario syntax and **could not be run in the environment
this was written in**. Check them with `cscli explain` on a sample line before relying on them.

Acquisition (`/etc/crowdsec/acquis.d/ultimateotp.yaml`):

```yaml
source: docker
container_name:
  - ultimateotp-api-1
labels:
  type: ultimateotp
```

Parser (`/etc/crowdsec/parsers/s01-parse/ultimateotp-logs.yaml`):

```yaml
onsuccess: next_stage
name: local/ultimateotp-logs
description: UltimateOTP api JSON security events (anonymized client ids)
filter: "evt.Line.Labels.type == 'ultimateotp'"
statics:
  - parsed: otp_json_status
    expression: "UnmarshalJSON(evt.Line.Raw, evt.Unmarshaled, 'otp')"
  - meta: log_type
    value: ultimateotp_security
  - meta: otp_event
    expression: "evt.Unmarshaled.otp.event"
  - meta: client_id
    expression: "evt.Unmarshaled.otp.client_id"
  - meta: reason
    expression: "evt.Unmarshaled.otp.reason"
  - meta: service
    value: ultimateotp
```

Scenarios (`/etc/crowdsec/scenarios/ultimateotp-*.yaml`):

```yaml
type: leaky
name: local/ultimateotp-password-guessing
description: Many wrong passwords or email codes from one anonymized client in a day
filter: >-
  evt.Meta.log_type == 'ultimateotp_security' &&
  evt.Meta.otp_event in ['srp.failure', 'email.code_failure']
groupby: evt.Meta.client_id
capacity: 15
leakspeed: 10m
blackhole: 1h
labels:
  service: ultimateotp
  type: bruteforce
  remediation: false
---
type: trigger
name: local/ultimateotp-client-blocked
description: The UltimateOTP api blocked a client
filter: >-
  evt.Meta.log_type == 'ultimateotp_security' && evt.Meta.otp_event == 'client.blocked'
groupby: evt.Meta.client_id
labels:
  service: ultimateotp
  type: bruteforce
  remediation: false
```

`cscli explain --file sample.log --type ultimateotp` with one `client.blocked` line from your logs
shows whether the parser fills `otp_event` and `client_id`.

## 7. Account management routes: flows and threat models

All are signed requests like the rest (`docs/crypto-format.md` is unchanged), limited per account
(`UOTP_ACCOUNT_ACTION_*`), audited as security events and announced by ntfy and, where it matters,
by email in the account's language. They sit behind the ordinary `otp-write` / `otp-client`
routers. The baseline threat is **a stolen, unlocked phone**: it holds the device key, so it
passes the signature check, but it does not hold the password, the mailbox or the other devices.

**Re-authentication.** The two dangerous actions (delete, change email) need a fresh proof next to
the signature: the 6-digit code emailed to the account's *current* address
(`POST /account/reauth/email-code`, 10 min, single use, 5 tries), or the SRP proof of the password
(`POST /account/reauth/srp` then the proof in the action; a handshake of this kind is bound to the
caller's account, single use, and can never register a device). Wrong proofs count toward the
account lockout and the client block, so the route is not a free password oracle. While the account
is locked the emailed code still works for the owner. An account without an email on file can only
use the password proof; one without a password record only the code.

| Action | Route | Needs | Effect | What it defends against |
|---|---|---|---|---|
| Delete the account | `POST /account/delete` | signature + reauth | one transaction removes the account, devices, wraps, items, tombstones, history, tokens, pairings, pending codes; open streams get `account_deleted`; the answer counts what went; the old address is mailed and ntfy fires | a thief wiping the owner's server copy. Without the mailbox or the password the phone cannot. The owner's other devices keep their local copies, and so does an export |
| Change email | `POST /account/email/change`, then `/confirm` | signature + reauth; then a code sent to the **new** address | the login address switches; both addresses are told | takeover of the account's recovery channel. The old address is warned at once and can react; the new address must be read by the requester. Always `202`, and a taken address sends nothing, so the route is not a directory of who has an account |
| Sign out every other device | `POST /devices/revoke-others` | signature | others are revoked at once, their key wraps deleted, `rotation_required` set, streams told | a thief (or an old tablet) is expelled by the owner holding any one device. A thief could also use it against the owner; the revoked devices come back by password login |
| Export | `GET /account/export` | signature, 6/hour per device | one JSON: encrypted vault and tombstones, key bundle, sealed key of this device, device list, history | the file is ciphertext plus the password and recovery wraps, which any device could already fetch. It never holds the SRP verifier, tokens or nonces. The owner is notified, so an unexpected export is visible |

Residual risks. A thief with the unlocked phone *and* the mailbox (a phone with mail logged in)
defeats the emailed code: prefer the password proof in the app for deletion. Deleting the account
does not touch server backups (§4) taken earlier; they hold the ciphertext until you rotate them.
Revoke-others asks for no extra proof by design (it is the panic button); the vault key rotation
that must follow is done by the surviving device.

## 8. Vault history and trash

The server keeps every previous committed vault version as ciphertext, so the app can offer a
30-day trash and undo. On each commit that replaces or deletes an item, the item's previous blob
goes to `item_history` with the version that superseded it, and the commit's signed head goes to
`vault_versions`. Routes: `GET /vault/history` (versions and what each changed),
`GET /vault/history/{version}` (the whole vault as it was, with that commit's signed head, which
the client can verify by recomputing the manifest, or one `item_id`), `GET /vault/trash` (items
deleted within the retention, with their last blob). Restoring is an ordinary commit: decrypt the
old blob with the version it carried (the version is part of its authenticated data) and upsert it
again; the server never opens a blob.

- **Retention**: `UOTP_HISTORY_RETENTION_DAYS` (30) by age, `UOTP_HISTORY_MAX_VERSIONS` (1000)
  and `UOTP_HISTORY_MAX_BYTES` (32 MiB) per account, whichever bites first, oldest first. Pruning
  runs inside each commit and in the background task (`UOTP_MAINTENANCE_INTERVAL_S`). `0` days
  turns history and trash off and clears what was kept.
- **Tombstones**: an entry deleted less than the retention ago is recoverable *whether or not its
  tombstone still exists*: its last blob is in the history, not in the tombstone. With
  `UOTP_TOMBSTONE_RETENTION_DAYS` > 0 old tombstones are compacted; a client whose `since` is older
  than a compacted tombstone gets the full live set with `full: true` instead of a delta, and drops
  what is missing. The default (0) keeps tombstones forever, the 1.1.0 behaviour.
- **Key rotation clears the history** (and the trash): ciphertext under an older vault key must not
  outlive the rotation that exists to retire that key. A revoked device that knew it could
  otherwise read the old blobs from a database leak. The 30-day undo therefore restarts after a
  rotation; the app should say so.
- **Storage**: roughly the size of the blobs you edit or delete in 30 days; entries are a few
  hundred bytes to a few KiB. `uotp_history_bytes` shows it. Backups carry the history (it is
  ciphertext). Metadata it adds: ids of changed items and commit times.
- **Upgrade**: a 1.1.0 database starts with an empty history (the old blobs were overwritten in
  place); migration 0002 is additive and tested from a 1.1.0 fixture.

## 9. Monitoring: Prometheus and Grafana

Files in `docs/monitoring/`: `grafana-ultimateotp.json` (dashboard), `alerts.yml` (Prometheus
rules), `alerts.test.yml` (promtool unit tests of the rules). Check them with:

```sh
cd docs/monitoring
docker run --rm --entrypoint promtool -v "$PWD":/m:ro quay.io/prometheus/prometheus:v3.15.0 check rules /m/alerts.yml
docker run --rm --entrypoint promtool -v "$PWD":/m:ro quay.io/prometheus/prometheus:v3.15.0 test rules /m/alerts.test.yml
```

Metric families (`/metrics`, text format; labels are fixed low-cardinality strings only):

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `uotp_signups_total` | counter | | accounts created from the app |
| `uotp_logins_total` | counter | `result` = success, srp_failure, email_code_failure, locked | password logins |
| `uotp_blocks_total` / `uotp_blocked_clients` | counter / gauge | | client blocks started / active now |
| `uotp_lockouts_total` | counter | | per-account SRP lockouts |
| `uotp_commits_total`, `uotp_rotations_total` | counter | | accepted commits, key rotations |
| `uotp_conflicts_total` | counter | `reason` = version, key_epoch | refused commits |
| `uotp_sse_streams` / `uotp_sse_connections_total` | gauge / counter | | live-sync streams open / opened |
| `uotp_emails_total`, `uotp_notifications_total` | counter | `result` = sent, failed | SMTP relay and ntfy |
| `uotp_account_actions_total` | counter | `action` | delete, email change, revoke-others, export |
| `uotp_events_total` | counter | `event` | every security event by name |
| `uotp_problems_total` | counter | `code` | problem responses |
| `uotp_http_request_duration_seconds` | histogram | `method`, `route` (template), `status` (2xx...) | latency; the stream route is excluded |
| `uotp_accounts`, `uotp_devices_active`, `uotp_vault_items` | gauge | | totals |
| `uotp_history_versions`, `uotp_history_items`, `uotp_history_bytes` | gauge | | retained history |
| `uotp_database_bytes` | gauge | | SQLite file + WAL |
| `uotp_build_info` | gauge | `version` | always 1 |

Gauges that scan tables are cached for 30 s. Alerts: server down or not scraped, 5xx, slow p95,
auth-failure spike (wrong passwords, codes, locked), signature-failure spike, many blocks, many
blocked clients at once, emails failing, ntfy failing, database doubling or heading past 1 GB,
history near its cap. They assume the scrape job is named `ultimateotp`.

**How the homelab Prometheus reaches it.** The api only sits on the `otp-proxy` network (shared
with Traefik) and its compose default network, and `/metrics` is never routed by Traefik, so a
Prometheus on another network cannot see it. Proposal, with no change to the homelab repository
made here: attach Prometheus to `otp-proxy` with a fixed address outside the dynamic range and
allow exactly that address.

```yaml
# stacks/monitoring/prometheus/compose.yml (excerpt, proposal)
services:
  prometheus:
    networks:
      default: {}
      otp-proxy:
        ipv4_address: 10.213.49.3        # .2 is Traefik's pin; the dynamic range is .128/25
networks:
  otp-proxy: {external: true}
```

```yaml
# stacks/security/ultimateotp/.env
UOTP_METRICS_NETWORKS=127.0.0.0/8,::1/128,10.213.49.3/32
```

```yaml
# prometheus.yml (excerpt)
rule_files:
  - /etc/prometheus/rules/ultimateotp-alerts.yml      # docs/monitoring/alerts.yml
scrape_configs:
  - job_name: ultimateotp
    scrape_interval: 30s
    metrics_path: /metrics
    static_configs:
      - targets: ["ultimateotp-api-1:8047"]            # container name on otp-proxy
```

`UOTP_TRUSTED_PROXIES` must not contain the Prometheus address (it would let it spoof
`X-Forwarded-For`), and nothing else on `otp-proxy` should be allowed. Alternatives: publish the
port on the host and put the *bridge gateway address* in `UOTP_METRICS_NETWORKS` (any container
on that host then reads the metrics), or run a small `node_exporter`-style relay on the network.
Dashboard: Grafana, Dashboards, New, Import, upload `grafana-ultimateotp.json`, pick the
Prometheus data source (it asks for `DS_PROMETHEUS`); the `job` variable filters on the scrape job.

## 10. Localized emails

Login, sign-up and account-action emails are sent in `es` or `en`. The language is, in order: the
`lang` field of `/login/email-code`, `/signup` and `/account/email/change`; the best language of
`Accept-Language` (by quality, `es-MX` counts as `es`); the language last used by a signed device
of the account (kept as `accounts.lang`; only signed requests update it, so a stranger cannot
change it); `en`. The text lives in plain files, `server/src/ultimateotp/templates/<lang>/<name>.txt`
(`Subject: ...`, a blank line, the body with `$placeholders`), with no new dependency. The test
suite checks that both languages have every template with the same placeholders. To add a
language, add the folder and its code to `i18n.SUPPORTED`. ntfy notices to the owner and API
problem texts stay English. `ultimateotp account-create --lang es` sets the language of the first
code.

## 11. Operating limits

- One api process only (in-memory live-sync broker, docs/sync.md). Do not scale the service.
- uvicorn has no request-header timeout: never expose the api port directly, keep Traefik in
  front.
- A request through Docker's port publishing from the host itself arrives from the bridge
  gateway (e.g. `172.19.0.1`), which is not in the LAN list: enrollment from the host fails
  closed (403). That is intended; enroll from a phone on the LAN through Traefik.
