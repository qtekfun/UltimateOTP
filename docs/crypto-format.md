<!-- SPDX-FileCopyrightText: 2026 UltimateOTP contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# UltimateOTP crypto format, version 1

Status: **normative for v1** (2026-10-13). Owner: the Android client (`feat/android`). The backend
never decrypts anything. The **signed statements** (request, head, seal and device signatures)
are defined by the API contract `contracts/openapi.yaml` (owned by `feat/server`), which the
server verifies; this document repeats them in §7 and §12 so that one place lists every byte a
client produces, and the vectors cover them. If the two ever differ, the contract wins for those
four statements and this document wins for everything encrypted.

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
- `item_id` is a random version-4 UUID. Its text form (API, manifest) is the lowercase canonical
  `8-4-4-4-12`; its binary form (16 bytes, RFC 9562 byte order) goes into associated data.
- `lines(a, b, …)`: the contract's signed statements, the UTF-8 of the arguments (integers in
  decimal) joined by `"\n"`, no trailing newline.
- Every binary format starts with a version byte or a magic string. A reader rejects versions it
  does not know; it never guesses.
- `AEAD(k, n, m, ad)` = `crypto_aead_xchacha20poly1305_ietf_encrypt` (32-byte key, 24-byte random
  nonce from `randombytes_buf`, 16-byte tag appended). Nonces are random, never counters.
- `H(m)` = `crypto_generichash(32, m)` (BLAKE2b-256, unkeyed). `SHA-256` = `crypto_hash_sha256`
  (used where the contract chose it, so servers need only the standard library).
- `KDF(k, id, ctx)` = `crypto_kdf_derive_from_key(32, id, ctx, k)`; `ctx` is exactly 8 ASCII bytes.
- `SIGN(sk, m)` = `crypto_sign_detached` (Ed25519, 64 bytes).
- Passwords: Unicode **NFC** normalization, then UTF-8. No trimming. (Ente imports use the raw
  UTF-8 of what was typed, then NFC as a retry, §11.)

---

## 3. Key hierarchy

```
master password ──Argon2id(salt)──▶ KEK_pw ──AEAD wraps──▶ VK_e          (kind 1)
                                      └──────AEAD wraps──▶ KEK_rk        (kind 3)
recovery key RK (256 bit, 24 words) ──KDF──▶ KEK_rk ──AEAD wraps──▶ VK_e  (kind 2)

VK_e (vault key of key epoch e, 256-bit random)
 └─ KDF(VK_e, 1, "uotpitem") = K_item   encrypts every item blob (§6)

device d: Ed25519 sign keypair + X25519 box keypair, generated on the device
          (private parts wrapped by the Android Keystore, never leave the device)
          VK_e sealed to the X25519 key by another device, signed by it (§5.3)
exports:  own password, Argon2id + secretstream, independent of VK (§10)
```

- `VK` never leaves a client in clear. The server stores only wraps and sealed keys.
- `key_epoch` (u32, starts at 1) increases by one at every rotation (§8).
- Why the extra *kind 3* wrap: rotation (after revoking a device) must re-wrap the new `VK` for
  the recovery key, but devices never store `RK`. With `KEK_rk` wrapped under the password, a
  device that knows the password can re-create the recovery wrap. This exposes nothing new: the
  password alone already unwraps `VK`. All three wraps are symmetric AEADs, so the server cannot
  forge any of them (a sealed box to a "recovery public key" could be forged by the server).
- A device that works **offline only** (milestone M1) has a `VK` too, kept in the Keystore, and no
  account: its items use the empty account id in their associated data (§6.2). When it creates or
  joins an account its items are re-encrypted for the account.

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
wrap  = u8 0x01 || nonce[24] || AEAD(K, nonce, payload, AD)          (73 bytes)
AD    = "UOTP-WRAP-v1" || u8 kind || u32be key_epoch || params
```

| kind | name | K | payload | key_epoch | params |
|---|---|---|---|---|---|
| 1 | password | `KEK_pw` | `VK_e` (32) | `e` | `params_block` |
| 2 | recovery | `KEK_rk` | `VK_e` (32) | `e` | empty |
| 3 | recovery-kek | `KEK_pw` | `KEK_rk` (32) | `0` | `params_block` |

Mapping onto the contract's `KeyBundle` (all base64url, opaque to the server):

| API field | content | bytes |
|---|---|---|
| `password_kdf` | `params_block` | 29 |
| `password_wrap` | kind 1 wrap `||` kind 3 wrap | 146 |
| `recovery_wrap` | kind 2 wrap | 73 |

The account id is **not** in the wrap AD: the bootstrap device builds the wraps before the server
assigns the account id (`POST /otp/v1/enroll`), and moving a wrap to another account gains
nothing (it still needs that account's password or recovery key).

A wrap whose AEAD fails is reported as "wrong password / wrong recovery key"; nothing else is
said. The paranoid option of `design.md` §3.2 (no password path on the server) omits
`password_wrap` and `password_kdf`; rotation then asks for the recovery key to re-create kind 2.

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

- Each device generates `(ed25519_pk, ed25519_sk)` with `crypto_sign_keypair` and, independently,
  `(x25519_pk, x25519_sk)` with `crypto_box_keypair`. No Ed25519→X25519 conversion.
- `device_id` (`dev_` + 22 characters) and `account_id` (`acc_` + 22) are assigned by the server.

### 5.2 Device certificate and trust (contract: `Device.added_by_signature`)

```
device_certificate = Ed25519(approver, lines("UOTP-DEVICE-v1", account_id, device_id,
                                              b64u(ed25519_pk), b64u(x25519_pk)))
```

Each client keeps a **pinned device set** (device id → Ed25519 key) and only accepts heads and
sealed keys signed by a pinned, non-revoked device:

- the device pins itself; the bootstrap device starts the set;
- a device added by pairing is pinned when its certificate verifies with a pinned approver;
- the joining device pins the approver whose key it read from the QR code (§5.4);
- devices with `enrolled_via` `token` or `bootstrap` that no pinned device vouched for are shown
  with a warning and pinned only after the user confirms them on this device (the server could
  otherwise inject a device of its own). A device enrolled by password or recovery key trusts the
  device list it finds at enrollment and flags it the same way (trust on first use).

### 5.3 Sealed vault key (contract: `SealedVaultKey`)

```
grant_plain      = "UOTP-GRANT-v1" || u32be key_epoch || VK_e[32] || UTF8(account_id)
sealed_vault_key = crypto_box_seal(grant_plain, recipient.x25519_pk)      (75 + 48 = 123 bytes)
seal_signature   = Ed25519(sealer, lines("UOTP-SEAL-v1", account_id, key_epoch,
                                          recipient_device_id, b64u(SHA-256(sealed_vault_key))))
```

A sealed box is anonymous (anyone, the server included, can seal to a public key), so the
recipient opens it only if `seal_signature` verifies with a **pinned** device key, and accepts the
key only if the `key_epoch` and `account_id` inside match.

### 5.4 Pairing a new device (QR + 6 words; contract: `/otp/v1/pairings`)

1. Existing device **A** calls `POST /otp/v1/pairings` and shows a QR code:
   `uotp://pair?v=1&s=<server base URL, percent-encoded>&p=<pairing_id>&k=<pairing secret>&a=<b64u A.ed25519_pk>`.
   The QR carries A's whole public key (43 characters), not a shortened fingerprint.
2. New device **B** scans it, generates its keys and calls `.../join`. It immediately shows the
   six SAS words.
3. A gets the `pairing` event, reads B's keys with `GET /otp/v1/pairings/{id}` and shows the six
   words too:
   ```
   sas   = BLAKE2b-256("UOTP-SAS-v1" || A.ed25519_pk || B.ed25519_pk || B.x25519_pk)
   words = the first 66 bits of sas (big-endian bit order), 6 groups of 11 bits, each an index
           into the BIP-39 English list
   ```
   B takes `A.ed25519_pk` from the QR code (out of band), A takes B's keys from the server. If the
   server swapped B's keys, the words differ: the user compares them on both screens and A
   approves only if they match.
4. A calls `.../approve` with B's device certificate (§5.2) and `VK` sealed to B (§5.3).
5. B polls `.../result`, checks that `approver.ed25519_public_key` equals the key in the QR,
   verifies the certificate and the seal signature with it, opens the seal, pins A, pulls the
   vault and verifies its head (signed by a pinned device) before trusting any item.

Without another device, B enrolls with an enrollment token and the master password (kind 1) or
the recovery key (kind 2) from `GET /otp/v1/recovery/keys`.

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
| `updated_by` | string | `device_id` of the last writer, `local` offline (merge tie-breaker) |

Before encryption the JSON is padded with `sodium_pad(…, 256)` (ISO/IEC 7816-4: `0x80` then
zeros up to the next multiple of 256), so the server only learns the length in 256-byte buckets.
Maximum padded plaintext: 60 KiB.

### 6.2 Blob

```
blob = u8 0x01 || u32be key_epoch || nonce[24] || AEAD(K_item(VK_key_epoch), nonce, padded, AD)
AD   = "UOTP-ITEM-v1" || u8 len(account_id) || UTF8(account_id) || item_id[16]
       || u64be item_version || u32be key_epoch
```

- `item_id`: random UUIDv4 chosen by the creating client (16 bytes here, canonical lower-case text
  in the API).
- `item_version`: the contract's item `version`, i.e. **the vault version of the commit that writes
  the item**. A commit always lands at `base_version + 1`, so the client encrypts with that value;
  after a `409 version_conflict` it re-encrypts with the new one (cheap). Offline-only vaults use
  `account_id = ""` and a local per-item counter.
- Binding `account_id`, `item_id`, `item_version` and `key_epoch` means the server can neither
  move a blob to another item or account nor present it under another version: decryption fails.
- Blob size: 1 + 4 + 24 + padded + 16 bytes; at most 61 485 bytes (< 64 KiB, the contract limit).
- A deletion is a tombstone (`deleted: true`, no blob).

The same blob format is used in the local Room database and on the server, so a synced item is
uploaded as stored.

## 7. Vault head: signed version numbers (rollback protection; contract "Vault model")

```
manifest  = concatenation over every LIVE item after the commit, sorted by item_id text, of
            item_id ":" item_version ":" b64u(SHA-256(blob)) "\n"          (empty vault: "")
signature = Ed25519(signer, lines("UOTP-HEAD-v1", account_id, version, key_epoch,
                                   signed_by_device_id, b64u(SHA-256(manifest))))
```

- The server keeps one monotonic `version` per vault. A commit sends `base_version` and the
  signed head for `version = base_version + 1`, computed over the full item set **after** its
  changes; the server recomputes the manifest, verifies the signature and applies the commit only
  if `base_version` is current (else `409`: pull, merge, re-encrypt, re-sign).
- A client accepts a pulled state only if: the signer is a pinned, non-revoked device (§5.2); the
  signature verifies; the manifest recomputed from its merged local items matches; and `version`
  is at least the highest version it has accepted (equal versions must have equal manifests).
  Otherwise it keeps its local state and reports `vault.rollback_rejected`. Version 0 (empty vault,
  unsigned) is accepted only on a device that has never accepted a version.

## 8. Rotation (after revoking a device; contract: `POST /otp/v1/vault/rotate`)

1. The rotating device asks for the master password (or the recovery key in paranoid mode).
2. It generates `VK_{e+1}`, re-encrypts every live item for `version = base + 1` and
   `key_epoch = e+1`, seals `VK_{e+1}` to every active device (§5.3), re-creates the kind 1, 2, 3
   wraps (`KEK_rk` from the kind 3 wrap) and signs the new head.
3. Everything goes in one atomic request; the server deletes older wraps and sealed keys.

Old blobs kept in old backups stay readable with the old `VK` (accepted in `design.md` §3.6).

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

- Treat every blob, wrap, sealed key and KDF parameter set as opaque bytes (base64url). Validate
  sizes only: `password_kdf` 29 bytes; `password_wrap` 73 or 146; `recovery_wrap` 73; sealed
  vault keys 123; item blobs 1 + 4 + 24 + 16 + k·256 bytes with 1 ≤ k ≤ 240 (≤ 61 485).
- Verify the four signed statements of the contract (request, head, seal, device certificate).
- Never receive or log a password, a KEK, `VK` or a recovery key; never try to derive anything
  from wraps. Rate-limit `GET /otp/v1/recovery/keys` hard (offline brute force needs it).

### 12.1 Request signing (contract "Authentication")

```
message = lines("UOTP-REQ-v1", METHOD, path_and_query, device_id_or_"pending",
                timestamp, nonce_b64u, b64u(SHA-256(body)))
headers: X-UOTP-Device, X-UOTP-Timestamp (Unix seconds), X-UOTP-Nonce (16-32 random bytes,
         b64u), X-UOTP-Signature (b64u Ed25519 of message)
```

`path_and_query` is the path exactly as sent plus `?` and the raw query when there is one; an
empty body hashes the empty string. The server accepts ±60 s of skew (`stale_request` carries
`server_time`, which the client uses to correct its clock offset) and rejects replayed nonces.

## 13. Test vectors

[`crypto-vectors/vectors.json`](crypto-vectors/vectors.json), regenerated with:

```sh
cd docs/crypto-vectors
uv run --no-project --with pynacl==1.6.2 python generate_vectors.py > vectors.json
```

| Vector | Kind | Covers |
|---|---|---|
| `password_kdf[*]` | deterministic | NFC + UTF-8 + Argon2id; `[1]` is non-ASCII (NFC changes it) |
| `wraps.*` | deterministic | kinds 1, 2, 3, their API encoding; BIP-39 words of `RK`; `KEK_rk` |
| `item` | deterministic | `K_item`, padding, AD (account and offline), blob |
| `devices` | deterministic | SAS words, device certificate |
| `head` | deterministic | manifest, head message and signature |
| `request_signature` | deterministic | canonical request and signature |
| `sealed_vault_key` | decrypt-only | sealed box (random ephemeral key) and seal signature |
| `export` | decrypt-only | `.uotp` file with 64-byte chunks (several chunks) |
| `ente_encrypted_export` | decrypt-only | Ente's JSON format |

The vectors use cheap Argon2id parameters (`opslimit = 2`, `memlimit = 16 MiB`) so tests stay
fast; they are inside the reader limits. Ed25519 keys come from fixed 32-byte seeds
(`crypto_sign_seed_keypair`), X25519 secret keys are fixed bytes. The signed-statement vectors
were also checked with the server's own `server/src/ultimateotp/signing.py` (branch `feat/server`).

The Android unit tests (`:core:crypto`) load this file and check every vector.

## 14. Deviations from `design.md`

| design.md | here | why |
|---|---|---|
| Lazysodium or Tink + Bouncy Castle | ionspin libsodium bindings | §1 |
| Argon2id MODERATE (ops 3, 256 MiB) | sensitive (ops 4, 1 GiB) with a fallback ladder down to (16, 256 MiB) | owner decision 3 for exports; the vault KEK gets the same since it is brute-forceable from a server dump |
| Export: age preferred | own `.uotp` container (Argon2id + secretstream) | owner decision 3 |
| Recovery key wraps VK (rotation unclear) | kind 2 wrap + kind 3 (`KEK_rk` under the password) inside `password_wrap` | rotation re-creates the recovery wrap without the recovery key; all wraps stay server-unforgeable |
| New device shows the QR, existing device scans | existing device shows the QR (pairing session of the contract) | the contract's flow; the QR carries A's full public key and the SAS still protects B's keys |
| AD = item_id ‖ vault_id ‖ version | adds `key_epoch`, a label, and uses the commit version and `account_id` of the contract | binds the key epoch; ids as the API defines them |
| `head_sig` over `hash(sorted item_id:version)` | the contract's manifest (ids, versions and SHA-256 of each blob) | also detects a swapped blob with the same version |
