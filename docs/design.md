# UltimateOTP: design and feasibility (draft for review)

Status: design only, nothing built. Date: 2026-10-13. Working name "UltimateOTP" (Ultimate family).
Scope: the Android app (Kotlin + Compose, F-Droid) and the Python backend are designed in full.
Other clients (Linux desktop/CLI, web, iOS) are later milestones; the API and crypto are chosen
so they are not locked out (§4.7).

**TL;DR.** Feasible, about 10-14 person-weeks to an MVP the owner would trust with real 2FA secrets,
and roughly 14-20 with a Linux CLI and desktop client. The hard part is not TOTP or the blob store; it is the
key management, recovery and the review effort it needs. The MinIO problem does not need this
project: it can be removed this week (§6a). Recommended path in §7.

---

## 1. Goals, non-goals, requirements

### Goals
| # | Requirement | Notes |
|---|---|---|
| G1 | Offline-first codes | TOTP (RFC 6238) and HOTP (RFC 4226); SHA1/256/512; 6/8 digits (accept 5-10); any period; Steam Guard (5 chars, custom alphabet; cheap, ~0.5 day) |
| G2 | E2EE sync across devices | Server stores opaque ciphertext only; never secrets, issuers, labels, icons or counts beyond "N blobs of size S" |
| G3 | Import | Ente Auth export (plain text `otpauth://` list and the encrypted export), single `otpauth://` URI, `otpauth-migration://` (Google), QR via camera and from an image file. Aegis JSON (plain/encrypted) as a stretch |
| G4 | Encrypted export and backup | Portable encrypted file (age-compatible or own format, §3.5); scheduled local backups to a SAF folder; server-side backups of ciphertext |
| G5 | Recovery with all devices lost | Master password + recovery key (printed / password manager); server or offline backup supplies ciphertext |
| G6 | Multi-device enrollment | Several Android devices first; add/revoke devices; new device gets the vault key without the server learning it |

### Non-goals (MVP)
- Multi-user / sharing / families. Single owner; the server may support several accounts later but MVP has one.
- Push notification approvals, WebAuthn/passkeys, password manager features.
- Play Store, Google services (no FCM). F-Droid only, like the other Ultimate apps.
- iOS, desktop, web clients (later milestones, §5).
- Server-side code generation (that is 2FAuth's model, and it violates G2).

### Non-functional
- Codes must work with no network, no server, forever. The server is a convenience, not a dependency.
- Losing the server (or the homelab) must never lose secrets: every device has the full vault.
- Reproducible build; dependencies few and well-known; GPL-3.0-or-later like the family.

---

## 2. Threat model

Assets: TOTP seeds (and their labels, which reveal which services the owner uses), master
password, recovery key, device keys, auth tokens.

| Adversary / event | Protected? | How / residual risk |
|---|---|---|
| **Server compromise** (container RCE, DB dump, NAS backup read) | Yes for confidentiality | Server holds only XChaCha20-Poly1305 ciphertext + wrapped keys. Offline brute-force of the master password is possible from the stored KEK params: mitigated by Argon2id (high cost) and by **not storing anything password-derived that a recovery key alone does not also protect**; recommend a long passphrase. Residual: attacker can delete data or serve **rollback/old blobs** (mitigated: signed monotonic vault version kept on each device, §4.4) and can see metadata (number of items if per-item blobs, timing, IPs). |
| **Malicious server serving a different key/device list** | Partly | Device list is signed by an existing device key; clients pin the set of device public keys they have seen and warn on unexpected additions. |
| **Cloudflare / tunnel compromise** (TLS terminated at Cloudflare) | Yes for secrets | Same as server compromise: CF sees ciphertext and bearer tokens. Tokens are device-bound (request signing with the device Ed25519 key, §4.3) so a stolen token alone cannot write. Residual: CF can block/replay reads; can see traffic patterns. Option: pair new devices on LAN only, bypassing CF. |
| **Lost/stolen phone, locked** | Yes | Vault key wrapped by an Android Keystore key (StrongBox when available) that requires user auth (biometric/PIN) per session; app lock; device revoked from another device, which **rotates the vault key** (§3.6). |
| **Lost phone, unlocked and app open** | No | Attacker can read codes. Mitigation only: short app-lock timeout, FLAG_SECURE, no codes in notifications. |
| **Malicious app update** (compromised signing key, F-Droid build server, or owner's own supply chain) | Not by design | An app update runs with full access to decrypted secrets; no client crypto stops it. Mitigations: reproducible builds on F-Droid with the developer signature (F-Droid publishes dev-signed APK only if the build matches), signing key offline, pinned dependency hashes (Gradle verification-metadata), minimal dependencies, Renovate PRs reviewed. Same residual as Aegis/Ente. |
| **Malicious server update** (own image) | Yes for secrets | Server code never sees plaintext; worst case is DoS/rollback as above. |
| **Backup theft** (NAS, exported file, cloud copy) | Yes if password strong | Backups contain ciphertext only; export files are Argon2id-protected; brute force is the only attack. |
| **Recovery key theft** | No | The recovery key alone decrypts the vault (by design). Store it offline (printed + password manager). |
| **Coercion, malware with root/accessibility on device** | No | Out of scope; true of every authenticator. |
| **Owner forgets password AND loses recovery key AND all devices** | No | Data is gone; that is the price of E2EE. Encrypted export with a different password reduces this. |

What the design does **not** protect: metadata (when you sync, from where, how many items),
availability (server can refuse service; codes still work offline), and a compromised client.

---

## 3. Crypto design

**Rule: no custom primitives, no custom constructions beyond key wrapping with standard AEAD.**
Use libsodium (Android: Lazysodium-android or the Tink equivalents; Python: PyNaCl, only for
tests/tools, the server never decrypts). libsodium is chosen over Tink because it exists on
every later client (libsodium.js / sodium-native for web/desktop, swift-sodium for iOS, PyNaCl for a
Python CLI) with bit-identical formats; it is also what Ente Auth uses, so its export format can be
read with the same library. Before committing, verify Lazysodium is still maintained; if not, the
fallback is Tink (AEAD XChaCha20-Poly1305 exists in Tink) + Bouncy Castle Argon2, keeping the same
wire formats (formats are libsodium-compatible regardless of which library produces them).

### 3.1 Primitives
| Use | Primitive (libsodium name) |
|---|---|
| Password KDF | Argon2id, `crypto_pwhash` (MODERATE or higher: ops=3, mem=256 MiB; calibrated per device, params stored with the salt) |
| Symmetric AEAD | XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf`), random 192-bit nonces |
| Device key agreement | X25519 sealed boxes (`crypto_box_seal`) for handing the vault key to a device |
| Signatures | Ed25519 (`crypto_sign`) for device identity, request signing and signed vault-head |
| Key derivation from a key | `crypto_kdf` (BLAKE2b) with fixed context strings |
| Fingerprints / pairing codes | BLAKE2b-256 of public keys, shown as 6 words or a 2x6 digit SAS |
| Local at-rest wrap | Android Keystore AES-256-GCM key (hardware-backed, `setUserAuthenticationRequired`) |

### 3.2 Key hierarchy
```
master password --Argon2id(salt_pw)--> KEK_pw  --wraps--> VK (vault key, 256-bit random)
recovery key (256-bit random, shown once as 24 words / base32) --wraps--> VK
device_i: X25519/Ed25519 keypair (generated on device, private part wrapped by Keystore)
          VK sealed to device_i public key   (stored server-side, per device)
items: AEAD(VK, random nonce)    exports: own password, independent of VK (§3.5)
```
- **VK** encrypts every item. Rotating VK = re-encrypt all items (cheap: a few hundred KB).
- **Master password vs recovery key:** both wrap the same VK independently. Password is for
  everyday "new device" enrollment without another device; recovery key is for when the
  password is forgotten. Either one alone + the ciphertext = full access. Keep both strong.
- Option (recommended for the paranoid setting): disable password-wrapped VK on the server and
  rely only on device-to-device enrollment + recovery key. Then a server dump is not
  brute-forceable at all (only the 256-bit recovery-key wrap exists).

### 3.3 Server authentication (separate from encryption)
- No password-derived auth key is sent to the server. Each device authenticates with its **Ed25519 device key**: request signature over
  `method | path | timestamp | body-hash`, server verifies against the registered device public
  key, 60 s skew window, nonce cache against replay. No passwords ever reach the server.
- Bootstrap of the first device and of password-only enrollment: an **enrollment token**
  (random, single-use, 10 min) shown in the LAN-only admin page or created by an existing device.
- This avoids SRP/OPAQUE (complex, few audited Kotlin/Python libs). Rolling your own PAKE
  would be the most dangerous part of the whole project; this design does not need one.

### 3.4 New device enrollment (Android to Android)
1. New device generates its keypair, requests an enrollment session (needs an enrollment token).
2. Existing device scans a QR shown by the new device: `{session_id, new_pubkey_fpr}`; both
   show a 6-word SAS derived from both public keys; user confirms they match.
3. Existing device signs the new device's public key into the device list, uploads
   `crypto_box_seal(VK, new_pubkey)`. Server sees only the sealed box.
4. Fallback with no device available: master password (or recovery key) unwraps VK from the
   server-stored wrap, then the device registers itself (still needs an enrollment token).

### 3.5 Vault item, export and backup formats
- Item plaintext: JSON `{type, secret_b32, algo, digits, period|counter, issuer, label, icon,
  tags, notes, created, updated}`, padded to 256-byte buckets (hides length of labels).
- Item ciphertext: `v1 | nonce(24) | AEAD(VK, plaintext, ad = item_id || vault_id || version)`.
- **Export file:** age v1 format with scrypt recipient is the most portable choice (age has Go,
  Rust, Python, JS, Kotlin-compatible implementations and an audited spec), but age uses scrypt,
  not Argon2id. Alternative: own container `UOTP-EXPORT-1 | argon2id params | salt | nonce |
  AEAD(...)` built only from libsodium calls. **Decision for review: prefer age** (standard,
  decryptable with the `age` CLI in an emergency without this app) unless Argon2id is a hard
  requirement. Also offer plain `otpauth://` text export behind a warning, for migration out.
- HOTP counters: counter is in the item; increments are item updates (conflict rule in §4.4).

### 3.6 Revocation and rotation
Revoking a device: an existing device generates VK', re-encrypts all items, re-wraps VK' to
remaining devices, password and recovery key (needs the password to re-derive KEK_pw, or the
password wrap is dropped until next unlock), bumps `key_epoch`. Server deletes the revoked
device's key. Old ciphertext in old backups stays decryptable by the old VK: acceptable, the
TOTP seeds themselves are what matters, and the owner should re-key the services if the device
was really compromised.

### 3.7 Where hand-rolled crypto would be dangerous
| Temptation | Why not | Do instead |
|---|---|---|
| Own password protocol / PAKE | Subtle; offline-guessing leaks | Device-key signatures + enrollment tokens |
| AES-CBC/CTR + HMAC by hand, nonce counters | Nonce reuse, padding oracles | XChaCha20-Poly1305 with random nonces |
| PBKDF2 or a fast hash for the password | GPU brute force | Argon2id with stored, calibrated params |
| Inventing a sync "merkle" signature scheme | Easy to get rollback/fork wrong | Simple signed monotonic head (§4.4), reviewed |
| Own QR pairing without SAS confirmation | MITM by the server | SAS words compared by the user |
| Storing VK in SharedPreferences "encrypted" with a hardcoded key | Trivially extractable | Android Keystore-wrapped |

Budget an **external review** of §3 + the implementation (even an informal one by a
crypto-literate friend) before trusting real secrets. This is the biggest risk item.

---

## 4. Architecture

### 4.1 Android app (Kotlin, Compose, Hilt, Room 3; mirrors UltimatePhone/UltimateTunes layout)
| Module | Responsibility |
|---|---|
| `:app` | Compose UI (code list, search, tags, add/scan, settings, devices, import/export), navigation, app lock, FLAG_SECURE |
| `:core:otp` | Pure Kotlin TOTP/HOTP/Steam generation + `otpauth://` and `otpauth-migration://` parsing. No Android deps; RFC test vectors; 100 % branch coverage |
| `:core:crypto` | Thin wrapper over libsodium + Keystore; the **only** module that touches keys; small API (`seal`, `open`, `wrapVk`, `deriveKek`, `sign`) |
| `:core:vault` | Room DB of encrypted items (ciphertext at rest, decrypted only in memory for display), vault head, local backups |
| `:core:sync` | WorkManager periodic + on-change sync, HTTP client (OkHttp/Ktor), request signing, conflict merge |
| `:core:import` | Ente (plain + encrypted export), Aegis JSON, Google migration, image QR decode (ZXing core, no Play Services ML Kit) |
| `:core:designsystem` | Shared theme from the family |
Permissions: CAMERA (scan), INTERNET (sync; app fully works if denied by firewall). No
analytics, no Play Services. `android:allowBackup="false"` (Keystore keys do not survive it).

### 4.2 Backend (Python 3.13, uv, FastAPI, pydantic v2, SQLite WAL, plain SQL migrations; as UltimateTunes)
- **One service** (`api`) + `migrate` one-shot; same hardening anchor as UltimateTunes
  (`read_only`, `cap_drop: ALL`, `no-new-privileges`, pids limit, non-root).
- **Storage: SQLite** (single user, tiny data; one file to back up, `sqlite3 .backup` for
  consistent snapshots). Portable SQL so Postgres remains possible, as in UltimateTunes. **No S3.**
- The server is a **dumb, versioned, encrypted-blob store**: it never parses item contents.
- Admin page (enrollment tokens, device list, revoke): LAN-only + Authelia, same as `ut-admin`.
- Deps: fastapi, uvicorn, pydantic(-settings), PyNaCl (Ed25519 verify only). Nothing else.

Tables (sketch): `accounts(id, created)`, `devices(id, account_id, ed25519_pub, x25519_pub,
name, added_by_sig, created, revoked_at)`, `vault_head(account_id, version, key_epoch,
head_sig, updated)`, `items(account_id, item_id, version, deleted, blob, updated)`,
`key_wraps(account_id, kind{password,recovery,device}, device_id, key_epoch, blob, params)`,
`enroll_tokens(hash, expires, used)`, `nonces(device_id, nonce, ts)`.

### 4.3 API contract sketch (`/otp/v1`, OpenAPI in `contracts/`, JSON, blobs base64url)
| Method & path | Purpose | Auth |
|---|---|---|
| `POST /otp/v1/enroll` | Register a device pubkey with an enrollment token; first device also uploads password/recovery wraps | enrollment token |
| `GET /otp/v1/keys` | My sealed VK + wraps for current epoch | device sig |
| `GET /otp/v1/devices` / `POST .../devices/{id}/revoke` | List / revoke (revoke also needs a rotation commit) | device sig |
| `GET /otp/v1/vault?since={version}` | Head + items changed since version (incl. tombstones) | device sig |
| `POST /otp/v1/vault/commit` | `{base_version, new_head_sig, upserts[], deletes[]}`; atomic; 409 if `base_version != head` | device sig |
| `POST /otp/v1/vault/rotate` | Full re-encryption commit with new `key_epoch` + new wraps | device sig |
| `GET /otp/v1/recovery/wraps` | Password/recovery wraps + KDF params (rate-limited hard) | enrollment token |
| `GET /healthz`, `/readyz` | Probes (not routed by Traefik) | none |
Limits: blob ≤ 64 KiB, ≤ 2000 items, body ≤ 1 MiB.

### 4.4 Sync and conflict resolution
- Server keeps a single monotonic `version` per vault. Each commit is optimistic: send
  `base_version`; on 409 the client pulls, merges, retries.
- **Merge is client-side, per item**: item ids are random UUIDs, so concurrent adds never
  collide. Same item edited on two devices: last-writer-wins on the decrypted `updated` field,
  keeping the losing version as an "archived conflict" copy for 30 days (cheap, safe).
  Delete vs edit: edit wins (never lose a secret silently). HOTP counter: `max(a, b)`.
- **Rollback protection:** each commit carries `head_sig = Ed25519(device, vault_id || version
  || key_epoch || hash(sorted item_id:version list))`. Devices store the highest version seen and
  refuse a head that is lower or not signed by a known device.
- Offline: all edits go to a local outbox; codes never wait for sync.

### 4.5 Deployment (homelab stack `stacks/security/ultimateotp/`)
- Internet → Cloudflare Tunnel → Traefik v3 → `api` on a **dedicated `otp-proxy` network**
  (pattern of `ut-proxy`); CrowdSec bouncer and security headers from the entrypoint.
- Routers (Host `otp-api.<domain>`), mirroring UltimateTunes:
  | Router | Rule | Middlewares |
  |---|---|---|
  | `otp-admin` | `/admin` | `local-ip-whitelist@file`, `authelia-auth@file`, ratelimit |
  | `otp-enroll` | `POST /otp/v1/enroll`, `/recovery/*` | **LAN-only by default** (toggle for travel), 1 r/s burst 5, inflight 4 |
  | `otp-write` | non-GET `/otp/v1/*` | ratelimit 5 r/s burst 20, body limit 1 MB, inflight |
  | `otp-client` | GET `/otp/v1/*` | ratelimit 10 r/s burst 50, inflight 8 |
  Client IP from `X-Forwarded-For` depth 1, IPv6 /64, as in `compose.override.yml`.
- No Authelia on API routes (native app). Registration closed after the first device:
  enrollment needs a token minted on the LAN admin page or by an existing device.

### 4.6 Backups and monitoring
- Nightly `sqlite3 .backup` → age-encrypted (to an offline age key) → NAS, 30 daily / 12 monthly.
  Content is already E2EE; the extra age layer hides metadata. Restore test monthly (script).
- On devices: scheduled encrypted export to a SAF folder (e.g. Syncthing-shared) — this is the
  "server is gone" path.
- Monitoring: JSON logs to stdout with security events (`auth.failure`, `enroll.*`,
  `device.revoked`, `vault.rollback_rejected`), as in UltimateTunes; Uptime check on `/healthz`
  via the existing stack; ntfy alerts on: new device enrolled, device revoked, recovery wraps
  fetched, >N signature failures/hour, backup job failed.

### 4.7 Later clients (not MVP) and what keeps the door open
| Client | Needs | Already enabled by |
|---|---|---|
| Linux CLI (Python) | PyNaCl + `age`; reuse `core:otp` logic in Python | libsodium formats, OpenAPI contract, device-key auth (no browser flow) |
| Desktop GUI (Linux) | Kotlin Compose Multiplatform could reuse `:core:otp`, `:core:crypto` (JVM) | Pure-Kotlin core modules, keep them KMP-ready (no Android types) |
| Web | libsodium.js; WebCrypto for at-rest; session-only keys; serve from a separate origin | Same formats; CORS policy decided later. Highest risk (code served by the same server it should not trust): last |
| iOS | swift-sodium, Keychain/Secure Enclave for device key wrap | Same formats; X25519/Ed25519 keys, not Android-specific Keystore formats on the wire |
Rule: nothing Android-specific goes over the wire; every format is versioned (`v1` prefix).

---

## 5. MVP scope vs later, with effort

Estimates assume one experienced developer working like on UltimateTunes (Claude-assisted,
tests + CI + F-Droid packaging included). Ranges, not promises.

| Milestone | Content | Person-weeks |
|---|---|---|
| M0 Spike | libsodium on Android (Lazysodium vs Tink) decision; Ente encrypted export decode; Keystore wrap; threat model sign-off | 1 |
| M1 Offline app | `:core:otp` (TOTP/HOTP/Steam), QR scan + image, `otpauth` parsing, Ente/Google/Aegis import, encrypted local vault, app lock, encrypted export/backup to SAF. **Usable alone, like Aegis** | 3-4 |
| M2 Server | FastAPI blob store, migrations, device-sig auth, enrollment tokens, admin page, OpenAPI contract, compose + Traefik stack, backups, ntfy | 2-3 |
| M3 Sync + enrollment | Key hierarchy, recovery key, device pairing with SAS, commit/merge, rollback protection, revocation + rotation | 3-4 |
| M4 Hardening + review | Fuzz/property tests, external crypto review, F-Droid reproducible build, docs (SECURITY.md, recovery runbook), migration from Ente | 1-2 |
| **MVP total** | M0-M4 | **10-14** |
| Later L1 | Linux CLI (Python) | 1-2 |
| Later L2 | Desktop GUI (Compose Multiplatform) | 3-4 |
| Later L3 | Web client | 3-5 |
| Later L4 | iOS | 6-8 (new platform for the owner) |
| Ongoing | Dependency bumps, Android API changes, F-Droid | ~0.5 week / quarter |

Note M1 alone is a working authenticator: the project can stop there and still be useful.

---

## 6. Alternatives (checked 2026-10-13)

### a. Keep Ente museum, remove MinIO
- MinIO community edition: stopped publishing images Oct 2025, repo in maintenance mode then
  archived (Feb 2026). Sources: https://github.com/minio/minio/issues/21714,
  https://news.ycombinator.com/item?id=45665452, https://www.answeroverflow.com/m/1477287829926055996
- **Ente Auth data lives in Postgres** (`authenticator_entity` table), S3 is for Photos files:
  https://github.com/ente-io/ente/issues/9462 (references `authenticator_entity.updated_at`),
  https://github.com/ente/ente/blob/main/docs/docs/self-hosting/administration/object-storage.md
  ("S3 ... for storing files (photos, thumbnails and videos)"). A community user reports running
  Auth without the MinIO container (snippet of the Ente Discord thread above). **Must be tested**:
  museum may still require an `s3` config block to start; point it at a dummy endpoint.
- Drop-in S3 replacements if needed: **pgsty/minio ("Silo")**, community fork with images
  (https://github.com/pgsty/silo, https://hub.docker.com/r/pgsty/minio); **Garage** v2.3.0,
  active (https://apps.truenas.com/catalog/garage_community/); **RustFS** 1.0 GA Sep 2026, young
  (https://linuxiac.com/rustfs-1-0-s3-compatible-object-storage-reaches-ga/).
- Effort: 0.5-1 day. Risk: museum is a large Go server built for Photos; Ente's self-host story
  keeps shifting (org rename broke image paths, see stack README gotcha #2).

### b. Aegis + encrypted backups synced by Syncthing/Nextcloud
- Active: v3.4.3, Sep 2026; AES-256-GCM vault, scrypt password, automatic backups to a chosen
  folder, HOTP/TOTP/Steam, imports many formats (https://github.com/beemdevelopment/Aegis).
  Ente import via the plain-text `otpauth` export (https://github.com/beemdevelopment/Aegis/issues/1405).
- Multi-device is **manual** (import a backup on the second phone; no live sync, edits on two
  phones diverge). No server at all, nothing to expose. Linux: decrypt backups with Aegis's
  documented format/scripts, no official desktop app.

### c. Server-side / password-manager options
- **2FAuth**: active (v8.0.0, Jul 2026, https://github.com/Bubka/2FAuth/releases) but a web app
  that **generates codes on the server** (https://github.com/Bubka/2FAuth/discussions/309):
  server holds plaintext-usable secrets → fails G2.
- **Vaultwarden TOTP**: E2EE, already a mature self-host pattern; but puts the 2FA secrets next
  to passwords (both factors in one vault), and the official Bitwarden apps gate TOTP code
  display behind premium license checks per some reports; Bitwarden Authenticator sync is
  documented only for Bitwarden accounts (https://bitwarden.com/help/totp-sync/,
  https://mustafa.net/2026/08/18/switching-to-vaultwarden-from-bitwarden-what-changed-for-me/).
- **Proton Pass**: E2EE, but a third-party cloud: not self-hosted, contradicts the goal.

### d. Ente Auth offline mode, no server
- Supported: "Use without backups", local vault key in OS secure storage, automatic local
  encrypted backups and encrypted exports (https://ente.com/help/auth/features/offline-mode).
- No sync; same manual multi-device story as Aegis but keeps the current app and UX.

### Comparison (Android-first)
| Option | E2EE | Multi-device sync | Self-hosted | Ops burden | Build effort | Long-term risk |
|---|---|---|---|---|---|---|
| a. museum without MinIO / with fork | Yes | Yes (live) | Yes | Medium (big Go server, SMTP) | 0.5-1 day | Upstream changes, S3 assumptions |
| b. Aegis + Syncthing | Yes | Manual (backup import) | No server | Low | 0.5 day | Very low; mature app |
| c. 2FAuth | **No** | Yes | Yes | Low | 1 day | Secrets server-side |
| c. Vaultwarden TOTP | Yes | Yes | Yes | Low (if already run) | 1 day | Mixes factors; client licensing quirks |
| d. Ente offline | Yes | Manual | No server | None | 0 | Low |
| Custom UltimateOTP | Yes | Yes | Yes | Low (one small container) | 10-14 pw | **Own crypto integration and maintenance** |

---

## 7. Verdict

**Probable? Yes.** The pieces are well understood (RFC algorithms, libsodium, a blob store),
and the owner already ships Kotlin apps on F-Droid and a hardened FastAPI service. **Worth it?
Only as a deliberate project, not as a MinIO fix.** The MinIO problem is a one-day job.

Main risks of building it:
1. Crypto/key-management bugs in a security-critical app with one maintainer and no audit (biggest).
2. Recovery path untested until it is needed; a bug here loses every 2FA secret.
3. Maintenance forever (Android changes, deps) for a problem Aegis/Ente already solve well.
4. Scope creep (desktop/web/iOS) multiplies the attack surface; the web client especially.

### Recommended path
| When | Step |
|---|---|
| **This week** | 1) Take an **encrypted Ente export** and a plain `otpauth` export kept offline. 2) In a throwaway copy of the stack, start museum **without MinIO** (dummy `s3` block); confirm login + Auth sync from a second Android device. If it works, delete MinIO from `stacks/security/ente-auth`. If not, swap the image to `pgsty/minio` (same data dir) or Garage. 3) Enable Ente's automatic local backups on each phone to a Syncthing folder. |
| Next month | Back up the Ente Postgres DB to the NAS (no MinIO volume needed if step 2 worked); add an ntfy alert on museum health. Decide on the custom project with this document. |
| If going ahead | Build **M1 (offline app) first**: it is useful on its own (it replaces Aegis/Ente offline) and de-risks crypto, import and Keystore. Run it beside Ente for a few weeks. Only then M2-M3 (server + sync), then external review (M4) before deleting Ente. |
| If not | Stay on Ente (museum without MinIO) or move to Aegis + Syncthing if live sync is not needed. |

Open questions for the owner: is live sync really needed (vs Aegis-style backup sync)? Is the
password-wrapped VK on the server acceptable, or device-pairing + recovery key only? age vs
Argon2id export format? Enrollment from outside the LAN (travel) allowed?
