<!-- SPDX-FileCopyrightText: 2026 UltimateOTP contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# UltimateOTP crypto format, version 1

Status: **normative for v1** (2026-10-13). Owner: the Android client (`feat/android`). The backend
never decrypts anything, but it stores, validates the size of, and in a few places verifies
(Ed25519 only) the structures below; §12 lists exactly what the server must do.

This document refines `design.md` §3 with the owner's decisions (`decisions.md`): live sync,
password-wrapped vault key on the server (decrypted only on clients), Argon2id + XChaCha20-Poly1305
secretstream exports (no age). Where this document and `design.md` differ, this document wins;
the differences are listed in §14.

Reference implementation and test vectors: [`crypto-vectors/generate_vectors.py`](crypto-vectors/generate_vectors.py)
produces [`crypto-vectors/vectors.json`](crypto-vectors/vectors.json) with **PyNaCl 1.6.2 (reference
libsodium)**. Every client must reproduce the deterministic vectors byte for byte and open the
randomized ones (§13).

---

## 1. Library choice

All primitives are **libsodium** functions (the names below are libsodium's). No primitive or
mode is implemented by hand in any client.

| Client | Binding | Notes |
|---|---|---|
| Android (Kotlin) | `com.ionspin.kotlin:multiplatform-crypto-libsodium-bindings:0.9.5` (Apache-2.0) | libsodium 1.0.20 on Android, 1.0.19 in the JVM unit tests |
| Python (server tests, future CLI) | PyNaCl (Apache-2.0) | used to generate the vectors |
| Web / desktop / iOS (later) | libsodium.js, sodium-native, swift-sodium | same functions, so the same bytes |

### 1.1 Why not Lazysodium (checked 2026-10-13)

`design.md` asked to verify Lazysodium for Android before committing to it. Result: **not
maintained enough to hold vault keys**.

- Last release `v5.2.0` on 2025-05-30, last commit 2025-05-31 ("Fix sample app"); nothing since
  (https://github.com/terl/lazysodium-android/releases, Maven Central `lastUpdated 20250531`).
- Open and unanswered: #68 (2026-03-05) *"SecretStream.State JNA auto-write silently destroys
  secretstream state on first push/pull"*, a correctness bug in exactly the API our export and the
  Ente import need; #70 (2026-07-28) *"Please update included libsodium"*; #38 *"LazySodium
  compilation from scratch for F-Droid"* open since 2020
  (https://github.com/terl/lazysodium-android/issues).
- JVM unit tests need a second artifact (`lazysodium-java`) that duplicates the Android classes.

### 1.2 Why not Tink + Bouncy Castle (the design's fallback)

- Neither implements `crypto_secretstream_xchacha20poly1305` (needed by our export **and** by the
  Ente Auth encrypted export we must import) nor `crypto_box_seal`. We would have to build those
  constructions from ChaCha20/Poly1305/HChaCha20 by hand, which the design forbids (§3.7).
- Bouncy Castle's Argon2 runs on the Java heap. The owner requires libsodium's *sensitive* limit
  (1 GiB) for exports, and Ente desktop writes exports with 1 GiB; that does not fit in an
  Android app heap (typically 256-512 MiB with `largeHeap`). libsodium allocates natively.

### 1.3 Why ionspin `kotlin-multiplatform-libsodium`

- Maintained: release `0.9.5` (Maven Central, 2025-11-22), commits until 2026-06-09, maintainer
  answering issues in 2025-10 (https://github.com/ionspin/kotlin-multiplatform-libsodium).
  Apache-2.0. A third-party review of 0.9.2 exists
  (https://reneevandervelde.com/publications/expect-fun/audit-ionspin-kmp-libsodium.html).
- It is a thin JNA wrapper over **upstream libsodium**, built from the libsodium submodule with
  libsodium's own `dist-build` scripts. The Android `.so` files are 16 KB page aligned (checked with
  `readelf`: `LOAD` alignment `0x4000`).
- The Kotlin Multiplatform metadata gives a JVM variant (bundled `libsodium` for Linux, macOS,
  Windows) and an Android variant from the same coordinate, so the same code runs in JVM unit
  tests and on the device.
- It exposes everything we need: `crypto_pwhash`, `crypto_aead_xchacha20poly1305_ietf_*`,
  `crypto_secretstream_xchacha20poly1305_*`, `crypto_box_seal*`, `crypto_sign_*`,
  `crypto_generichash`, `crypto_kdf_derive_from_key`, `sodium_pad`, `randombytes_buf`.

Caveats, handled in code:

- The project labels itself "experimental". We only call one libsodium function per wrapper
  call, the wrapper is isolated in `:core:crypto` (the only module that touches keys) and every
  call is pinned by the vectors in §13, so a later swap to another binding does not change a byte.
- **Bug found while writing this spec:** `PasswordHash.pwhash(…, password: String, …)` passes
  `String.length` (UTF-16 code units) as the password length while JNA encodes the string as
  UTF-8, so any non-ASCII password is truncated. `:core:crypto` therefore calls `crypto_pwhash`
  through the already loaded native library with the UTF-8 bytes and their real length. The
  vector `password_kdf[1]` (non-ASCII password) catches a regression. To be reported upstream.
- F-Droid: the AAR carries prebuilt `libsodium.so` and JNA's `libjnidispatch.so` from Maven
  Central. F-Droid accepts Maven Central dependencies; the build stays reproducible because every
  artifact is pinned by hash (`gradle/verification-metadata.xml`). If F-Droid ever requires
  native code built from source, libsodium can be built in the F-Droid recipe (`srclibs`) with
  the same `dist-build/android-*.sh` scripts, without changing any format.

---

## 2. Conventions

- `||` concatenation. `u8`, `u32be`, `u64be`: unsigned integers, **big-endian**, of 1, 4, 8 bytes.
- `"text"`: the ASCII bytes of the string, no terminator, no length prefix.
- `b64u`: base64url without padding (RFC 4648 §5). All binary values in JSON / HTTP use `b64u`
  unless stated otherwise (Ente's format uses standard base64, §11).
- UUIDs (`vault_id`, `item_id`) are random version-4 UUIDs. Their text form is the lowercase
  canonical `8-4-4-4-12`; their binary form (16 bytes, RFC 9562 byte order) goes into every
  associated data / signed body.
- Every binary format starts with a version byte or a magic string. A reader rejects versions it
  does not know; it never guesses.
- `AEAD(k, n, m, ad)` = `crypto_aead_xchacha20poly1305_ietf_encrypt` (32-byte key, 24-byte random
  nonce from `randombytes_buf`, 16-byte tag appended). Nonces are random, never counters.
- `H(m)` = `crypto_generichash(32, m)` (BLAKE2b-256, unkeyed). `MAC(k, m)` = `crypto_generichash(32, m, k)`.
- `KDF(k, id, ctx)` = `crypto_kdf_derive_from_key(32, id, ctx, k)`; `ctx` is exactly 8 ASCII bytes.
- `SIGN(sk, m)` = `crypto_sign_detached` (Ed25519, 64 bytes).
- Passwords: Unicode **NFC** normalization, then UTF-8. No trimming. (Ente imports use the raw
  UTF-8 of what was typed, then NFC as a retry, §11.)

---

## 3. Key hierarchy

```
master password ──Argon2id(salt)──▶ KEK_pw ──AEAD wraps──▶ VK_e          (kind 1, server)
                                      └──────AEAD wraps──▶ KEK_rk        (kind 3, server)
recovery key RK (256 bit, 24 words) ──KDF──▶ KEK_rk ──AEAD wraps──▶ VK_e  (kind 2, server)

VK_e (vault key of key epoch e, 256-bit random)
 ├─ KDF(VK_e, 1, "uotpitem") = K_item   encrypts every item blob (§6)
 └─ KDF(VK_e, 2, "uotpcert") = K_cert   MACs device certificates (§5.2)

device d: Ed25519 sign keypair + X25519 box keypair, generated on the device
          (private parts wrapped by the Android Keystore, never leave the device)
          VK_e sealed to the box public key by another device (grant, §5.3)
exports:  own password, Argon2id + secretstream, independent of VK (§10)
```

- `VK` never leaves a client in clear. The server stores only wraps and sealed grants.
- `key_epoch` (u32, starts at 1) increases by one at every rotation (§8).
- Why the extra *kind 3* wrap: rotation (after revoking a device) must re-wrap the new `VK` for
  the recovery key, but devices never store `RK`. With `KEK_rk` wrapped under the password, a
  device that knows the password can re-create the recovery wrap. This exposes nothing new:
  the password alone already unwraps `VK`. All three wraps are symmetric AEADs, so the server
  cannot forge any of them (a sealed box to a recovery public key could be forged by the server).

---

## 4. Password key derivation and wraps

### 4.1 Argon2id parameters

`KEK_pw = crypto_pwhash(32, NFC_UTF8(password), salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13)`

- `salt`: 16 random bytes, new for every password set or change.
- **Writer parameters**: libsodium *sensitive* limits, `opslimit = 4`, `memlimit = 1073741824`
  (1 GiB). If the device cannot allocate that much native memory, the writer halves memory and
  doubles operations (Ente's `deriveSensitiveKey` strategy, which keeps the total work equal):
  `(4, 1 GiB)` → `(8, 512 MiB)` → `(16, 256 MiB)`. Below 256 MiB the writer fails; it never
  silently weakens further. The parameters actually used are stored next to the salt.
- **Reader limits**: `1 <= opslimit <= 4096`, `8192 <= memlimit <= 1073741824`. Anything else is
  rejected before deriving (protects against a server that sends absurd parameters).
- The KDF only runs when a device enrolls with the password, the password changes, or the vault
  key rotates: day-to-day unlock uses the Android Keystore (§9), so the cost does not hit every
  app start.

KDF parameters as JSON (`kdf` object in the API):

```json
{"alg": "argon2id13", "opslimit": 4, "memlimit": 1073741824, "salt": "<b64u 16 bytes>"}
```

and as bytes, the `params_block` bound into wraps:
`params_block = u8 2 (ALG_ARGON2ID13) || u32be opslimit || u64be memlimit || salt[16]` (29 bytes).

### 4.2 Wrap record

```
wrap  = u8 0x01 || nonce[24] || AEAD(K, nonce, payload, AD)
AD    = "uotp/wrap/v1" || u8 kind || vault_id[16] || u32be key_epoch || params
```

| kind | name | K | payload | key_epoch | params | size |
|---|---|---|---|---|---|---|
| 1 | password | `KEK_pw` | `VK_e` (32) | `e` | `params_block` | 73 bytes |
| 2 | recovery | `KEK_rk` | `VK_e` (32) | `e` | empty | 73 bytes |
| 3 | recovery-kek | `KEK_pw` | `KEK_rk` (32) | `0` | `params_block` | 73 bytes |

A wrap whose AEAD fails is reported as "wrong password / wrong recovery key"; nothing else is
said (no oracle beyond what the AEAD tag gives).

The paranoid option from `design.md` §3.2 (no password wrap on the server) is supported: kinds 1
and 3 are simply not uploaded; then rotation needs the recovery key to re-create kind 2.

### 4.3 Recovery key

- `RK` = 32 random bytes, shown **once** as 24 words of the BIP-39 English list (256 bits of
  entropy + 8-bit SHA-256 checksum, exactly BIP-39's encoding; no BIP-39 seed derivation or
  passphrase). The list is `crypto-vectors/bip39-english.txt`, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` (from
  https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt). A wrong checksum is
  reported as a typo before any network call.
- `KEK_rk = KDF(RK, 1, "uotprcvy")`.

---

## 5. Devices

### 5.1 Device keys and id

- Each device generates `(sign_pk, sign_sk)` with `crypto_sign_keypair` and, independently,
  `(box_pk, box_sk)` with `crypto_box_keypair`. No Ed25519→X25519 conversion.
- `fpr = H("uotp/device/v1" || sign_pk || box_pk)` (32 bytes).
- `device_id = b64u(fpr[0..16])` (22 characters). Deterministic, so the server can recompute it
  from the public keys and reject a mismatch.

### 5.2 Device certificate

```
cert_body  = "uotp/devcert/v1" || vault_id[16] || sign_pk[32] || box_pk[32] || u64be created_unix_s
self_sig   = SIGN(sign_sk_of_that_device, cert_body)          proof of possession; server verifies
vk_mac[e]  = MAC(K_cert(VK_e), u32be e || cert_body)           proof of VK knowledge; clients verify
```

- A device creates its own certificate as soon as it holds `VK` (after pairing, password or
  recovery enrollment) and uploads it. The server stores `cert_body`, `self_sig` and the map
  `epoch -> vk_mac`; it cannot create a `vk_mac`, so it cannot add a device that clients trust.
- At rotation the rotating device adds `vk_mac[e+1]` for every device that stays (it knows the
  new `VK`); devices without a `vk_mac` for the current epoch are revoked.
- **Pinning**: a client trusts a device's keys only after verifying `self_sig` and `vk_mac` for
  an epoch whose `VK` it holds. It keeps the trusted set locally and shows a warning when the
  server lists a device it cannot verify.

### 5.3 Vault key grant (to a device)

```
grant_plain = "uotp/grant/v1" || vault_id[16] || u32be key_epoch || VK_e[32]
sealed      = crypto_box_seal(grant_plain, recipient.box_pk)          (65 + 48 = 113 bytes)
grant_sig   = SIGN(granter.sign_sk, "uotp/grantsig/v1" || recipient.fpr || sealed)
```

A sealed box is anonymous (anyone, including the server, can seal to a public key), so the
recipient accepts a grant only if `grant_sig` verifies with a **pinned** device key (or the
pairing partner confirmed by the SAS, §5.4) and the `vault_id`/`key_epoch` inside match.

### 5.4 Pairing a new device (QR + 6 words)

1. New device **N** generates its keys and opens an enrollment session on the server with an
   enrollment token (API: `contracts/openapi.yaml`). The server returns `session_id`.
2. N shows a QR code: `uotp://pair?v=1&sid=<session_id>&fpr=<b64u fpr_N>&srv=<server base URL>`.
3. Existing device **E** scans it, fetches the session's public keys from the server and checks
   `fpr(sign_pk, box_pk) == fpr_N` from the QR (the QR is out of band, so the server cannot swap
   N's keys). E posts its own public keys to the session.
4. Both show 6 words: `sas = H("uotp/sas/v1" || fpr_E || fpr_N)`; the first 66 bits (big-endian
   bit order) are split into 6 groups of 11 bits, each an index into the BIP-39 list. N computes
   the same with E's keys from the session. The user confirms they match on both screens: this
   is what proves to **N** that it talks to E and not to the server.
5. E uploads to the session:
   ```
   bundle       = JSON {"v":1,"vault_id":…,"key_epoch":e,"vk":b64u,"head_version":n,"items_digest":b64u}
   sealed       = crypto_box_seal("uotp/pair/v1" || bundle, N.box_pk)
   bundle_sig   = SIGN(E.sign_sk, "uotp/pairsig/v1" || session_id (UTF-8) || fpr_N || sealed)
   ```
6. N verifies `bundle_sig` with E's SAS-confirmed key, opens the box, checks the prefix, adopts
   `VK`, pins E, pins `head_version`/`items_digest` as its rollback floor, creates its own
   certificate (§5.2) and registers.

If no other device is available, N enrolls with the master password (kind 1 wrap) or the
recovery key (kind 2 wrap) instead; it still needs an enrollment token.

---

## 6. Vault items

### 6.1 Plaintext

UTF-8 JSON object, keys in any order; unknown keys **must be preserved** on rewrite (forward
compatibility). Version 1 fields:

| field | type | notes |
|---|---|---|
| `v` | int | `1` |
| `type` | string | `totp`, `hotp`, `steam` |
| `secret` | string | RFC 4648 base32, upper case, no padding |
| `algorithm` | string | `SHA1`, `SHA256`, `SHA512` |
| `digits` | int | 5-10 (`steam`: 5) |
| `period` | int | seconds, TOTP/Steam |
| `counter` | int | HOTP |
| `issuer`, `label` | string | label = account name |
| `icon` | string? | icon key, not image data |
| `tags` | string[] | |
| `notes` | string | |
| `favorite` | bool | |
| `created`, `updated` | int | ms since the Unix epoch |
| `updated_by` | string | `device_id` of the last writer (merge tie-breaker) |

Before encryption the JSON is padded with `sodium_pad(…, 256)` (ISO/IEC 7816-4: `0x80` then
zeros up to the next multiple of 256), so the server only learns the length in 256-byte buckets.
Maximum padded plaintext: 60 KiB.

### 6.2 Blob

```
blob = u8 0x01 || u32be key_epoch || nonce[24] || AEAD(K_item(VK_key_epoch), nonce, padded, AD)
AD   = "uotp/item/v1" || vault_id[16] || item_id[16] || u64be item_version || u32be key_epoch
```

- `item_id`: random UUIDv4 chosen by the creating client.
- `item_version`: per-item revision chosen by the client: 1 on creation, +1 on every change,
  including the deletion (tombstone) and re-encryption at rotation. The server must require it
  to increase strictly per item.
- Binding `vault_id`, `item_id`, `item_version` and `key_epoch` means the server can neither
  move a blob to another item or vault nor present it under another version: decryption fails.
- Blob size: 1 + 4 + 24 + padded + 16 bytes; at most 61 485 bytes (< 64 KiB).
- A **tombstone** is the pair `(item_id, item_version)` with no blob.

The same blob format is used in the local Room database and on the server, so sync uploads the
stored bytes as they are.

---

## 7. Vault head: signed version numbers (rollback protection)

```
entry(i)     = item_id[16] || u64be item_version || u8 state || blob_hash[32]
               state 0 = live, blob_hash = H(blob);  state 1 = tombstone, blob_hash = 32 zero bytes
items_digest = H(entry(i1) || entry(i2) || …)   entries sorted by item_id bytes, ascending
               (empty vault: H(empty string))
head_body    = "uotp/head/v1" || vault_id[16] || u64be head_version || u32be key_epoch || items_digest[32]
head_sig     = SIGN(signer.sign_sk, head_body)
```

- The server keeps one monotonic `head_version` per vault. A commit is optimistic: the client
  sends `base_version` and the signed head for `head_version = base_version + 1`, computed over
  the full item set **after** its changes. The server accepts the commit only if
  `base_version` equals the current version (else 409, the client pulls, merges, re-signs).
- The server stores `head_body` fields, `head_sig` and the signer's `device_id`, and returns them
  with every pull.
- A client accepts a pulled state only if: the signer is a pinned, non-revoked device; the
  signature verifies; recomputing `items_digest` over its merged local state gives the signed
  value; and `head_version` ≥ the highest version it has seen (equal versions must have equal
  digests). Otherwise it refuses the state and reports `vault.rollback_rejected`.
- Tombstones stay in the digest (they are small); purging them needs a rotation-style commit.

---

## 8. Rotation (after revoking a device)

1. The rotating device asks for the master password (or the recovery key in paranoid mode).
2. It generates `VK_{e+1}`, re-encrypts every item (new nonce, `item_version + 1`,
   `key_epoch = e+1`), seals grants (§5.3) for every remaining pinned device, adds
   `vk_mac[e+1]` to their certificates, writes new kind-1 and kind-2 wraps (`KEK_rk` from the
   kind-3 wrap) and signs the new head.
3. Everything goes in one atomic commit; the server deletes the revoked device's grants.

Old blobs kept in old backups stay readable with the old `VK` (accepted in `design.md` §3.6).

---

## 9. Local storage on Android (not on the wire)

- `VK` and the device private keys are stored encrypted by an Android Keystore AES-256-GCM key
  (StrongBox when available) that requires user authentication (biometric or device
  credential). The app lock is the Keystore authentication itself, not a UI-only gate.
- The Room database stores item blobs in the §6.2 format (ciphertext), item ids and versions,
  the pinned head and the outbox. Plaintext exists only in memory while the vault is unlocked.
- `android:allowBackup="false"`; the window uses `FLAG_SECURE`.

---

## 10. Export file (`.uotp`)

Password-protected, independent of `VK`, made only of libsodium calls
(`crypto_pwhash` + `crypto_secretstream_xchacha20poly1305`), the same primitives as Ente's export.

```
header = "UOTPEXP1"                (8)
       || u8 2                     (alg = crypto_pwhash_ALG_ARGON2ID13)
       || u32be opslimit || u64be memlimit || salt[16]
       || u32be chunk_size         (plaintext bytes per chunk, writer uses 65536; reader accepts 1..1048576)
       || ss_header[24]            (crypto_secretstream_xchacha20poly1305_init_push)
                                   = 65 bytes
key    = crypto_pwhash(32, NFC_UTF8(password), salt, opslimit, memlimit, ARGON2ID13)
body   = c_1 || c_2 || … || c_n,  c_i = crypto_secretstream_xchacha20poly1305_push(m_i, ad = header, tag)
```

- The plaintext is split into chunks of exactly `chunk_size` bytes, the last one shorter or equal
  (possibly empty); every chunk carries `TAG_MESSAGE` except the last, which carries
  `TAG_FINAL`. Each ciphertext chunk is `len(m_i) + 17` bytes.
- Every chunk authenticates the whole `header` as associated data, so the KDF parameters cannot
  be altered.
- The reader rejects: unknown magic or alg, parameters outside §4.1's reader limits, a
  `TAG_FINAL` before the end of the file, end of file without `TAG_FINAL` (truncation), any
  `TAG_PUSH`/`TAG_REKEY`, trailing bytes.
- Writer parameters: the sensitive limits with the fallback ladder of §4.1.
- Plaintext: UTF-8 JSON `{"format":"uotp-export","version":1,"exported_at":<ms>,"items":[<item plaintext §6.1>…]}`.
- Why not age (`design.md` §3.5): age's password recipient is scrypt; the owner chose Argon2id
  with the sensitive limits for every password-derived key. This format can still be opened in
  an emergency with ~40 lines of PyNaCl (`generate_vectors.py` shows the writer).
- A plain export (`otpauth://` URIs, one per line, like Ente's plain export) is also offered,
  behind an explicit warning.

---

## 11. Ente Auth export (import only)

Sources: Ente's help page https://ente.com/help/auth/migration/export, and the app code
`mobile/apps/auth/lib/ui/settings/data/export_widget.dart` (`_getAuthDataForExport`, encrypted
branch) and `…/import/encrypted_ente_import.dart` in https://github.com/ente-io/ente (main,
read 2026-10-13); an independent reimplementation documents the same:
https://github.com/muquit/twofa-rescue/blob/main/docs/ente-auth-export-encryption-algorithm-claude.md.

- **Plain export**: UTF-8 text, one `otpauth://` URI per line (Ente's `rawData`), with
  `algorithm=Algorithm.sha1` rewritten to `algorithm=sha1` and `,` escaped as `%2C`. Lines may
  carry Ente's own `codeDisplay` query parameter (JSON with pinned/trashed/tags), which is read
  for tags and otherwise ignored. Ente uses `otpauth://steam/…` for Steam (5 digits).
- **Encrypted export**: JSON
  `{"version":1,"kdfParams":{"memLimit":<bytes>,"opsLimit":<n>,"salt":"<base64>"},"encryptedData":"<base64>","encryptionNonce":"<base64>"}`,
  standard base64 with padding.
  `key = crypto_pwhash(32, UTF8(password), salt, opsLimit, memLimit, ARGON2ID13)`;
  `encryptionNonce` is **not** an AEAD nonce but the 24-byte `crypto_secretstream_xchacha20poly1305`
  header; `encryptedData` is a single secretstream chunk with `TAG_FINAL` and no associated data;
  the plaintext is the plain export above. Ente writes with its own sensitive-with-fallback
  limits (up to 1 GiB), which is why native Argon2id is required.

---

## 12. What the server must do (and must not)

- Treat every blob, wrap, sealed grant and pairing bundle as opaque bytes (`b64u` in JSON).
  Validate sizes only: wraps 73 bytes; grants 113 bytes; item blobs 1 + 4 + 24 + 16 + k·256 bytes
  with 1 ≤ k ≤ 240 (so ≤ 61 485); head signature 64 bytes.
- Recompute `device_id` from `sign_pk || box_pk` (§5.1) and verify `self_sig` on `cert_body`
  with PyNaCl (`VerifyKey(sign_pk).verify(cert_body, self_sig)`), rejecting a mismatch.
- Verify request signatures (§12.1) with the registered `sign_pk`.
- Optionally verify `head_sig` with the signer's `sign_pk` (cheap, catches buggy clients). It
  cannot check `items_digest` semantics beyond recomputing it from the stored blobs, which it may
  also do (all inputs are ciphertext and versions).
- Enforce `head_version = base_version + 1`, strictly increasing `item_version` per item, and
  atomic commits.
- Never receive or log a password, a KEK, `VK` or a recovery key; never try to derive anything
  from wraps. Rate-limit the endpoint that returns wraps and KDF parameters (offline brute force
  needs them).

### 12.1 Request signing (proposal; `contracts/openapi.yaml` is authoritative for header names)

```
string_to_sign = "uotp/req/v1" "\n" METHOD "\n" PATH_AND_QUERY "\n" TIMESTAMP "\n" NONCE "\n" hex(SHA-256(body))
headers: X-UOTP-Device: <device_id>
         X-UOTP-Timestamp: <unix seconds, decimal>
         X-UOTP-Nonce: <b64u of 16 random bytes>
         X-UOTP-Signature: <b64u SIGN(sign_sk, string_to_sign)>
```

`METHOD` upper case; `PATH_AND_QUERY` exactly as sent on the wire (percent-encoding kept, no
scheme/host); empty body hashes the empty string. The server accepts ±60 s of skew and keeps
nonces for 120 s per device to reject replays.

---

## 13. Test vectors

[`crypto-vectors/vectors.json`](crypto-vectors/vectors.json), regenerated with:

```sh
cd docs/crypto-vectors
uv run --no-project --with pynacl==1.6.2 python generate_vectors.py > vectors.json
```

| Vector | Kind | Covers |
|---|---|---|
| `password_kdf[*]` | deterministic | NFC + UTF-8 + Argon2id; `[1]` is non-ASCII (NFC changes it) |
| `wraps.*` | deterministic | kinds 1, 2, 3; BIP-39 words of `RK`; `KEK_rk` |
| `subkeys` | deterministic | `K_item`, `K_cert` via `crypto_kdf` |
| `item` | deterministic | padding, AD, blob |
| `devices` | deterministic | fingerprints, `device_id`, SAS words, certificate, `self_sig`, `vk_mac` |
| `head` | deterministic | `items_digest` with a tombstone, empty digest, head signature |
| `request_signature` | deterministic | canonical string and signature |
| `grant`, `pairing` | decrypt-only | sealed boxes (random ephemeral key) and their signatures |
| `export` | decrypt-only | `.uotp` file with 64-byte chunks (several chunks) |
| `ente_encrypted_export` | decrypt-only | Ente's JSON format |

The vectors use cheap Argon2id parameters (`opslimit = 2`, `memlimit = 16 MiB`) so tests stay
fast; they are inside the reader limits. Ed25519 keys are derived from fixed 32-byte seeds
(`crypto_sign_seed_keypair`) and X25519 secret keys are fixed bytes.

The Android unit tests (`:core:crypto`) load this file and check every vector.

---

## 14. Deviations from `design.md`

| design.md | here | why |
|---|---|---|
| Lazysodium or Tink + Bouncy Castle | ionspin libsodium bindings | §1 |
| Argon2id MODERATE (ops 3, 256 MiB) | sensitive (ops 4, 1 GiB) with fallback ladder down to (16, 256 MiB) | owner decision 3 for exports; the vault KEK gets the same since it is brute-forceable from a server dump |
| Export: age preferred | own `.uotp` container (Argon2id + secretstream) | owner decision 3 |
| Recovery key wraps VK (rotation unclear) | kind 2 wrap + kind 3 (`KEK_rk` under the password) | lets rotation re-create the recovery wrap without the recovery key, all wraps stay server-unforgeable |
| Device list signed by an existing device | every device self-certifies, trusted by `vk_mac` (needs `VK`) | also covers devices enrolled by password/recovery, where no other device signs |
| AD = item_id ‖ vault_id ‖ version | adds `key_epoch` and a label; `item_version` is per item | binds the key epoch; per-item versions can be bound before the commit is accepted |
| `head_sig` over `hash(sorted item_id:version)` | over item ids, versions, tombstone flag and blob hashes | also detects a swapped blob with the same version |
