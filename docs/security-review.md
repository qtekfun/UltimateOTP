<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Security review package

For an external reviewer (a firm or a volunteer). Version of this document: written against `master` at
tag `v0.1.2` plus the 0.2.0 changes; crypto format 1.1, API contract 1.1.0. Facts below were read from the
repository on the date of writing; where something was not verified it says so.

Status of the project: early development, **never reviewed by anyone outside the project**. One
maintainer, written with an AI coding assistant. That is the reason for this document.

Reading order: this file, then [crypto-format.md](crypto-format.md) (normative, byte level),
[design.md](design.md) section 2 and 3 (threat model, design rationale; where it differs from the format
document, the format document wins, see its section 14), [decisions.md](decisions.md), the OpenAPI
contract [`contracts/openapi.yaml`](../contracts/openapi.yaml), then the code.

## 1. What the product is

A self-hosted, end-to-end encrypted authenticator. An Android app generates TOTP/HOTP/Steam codes and
works fully offline. Optionally it syncs through a server the user hosts, which stores only ciphertext,
wrapped keys and public keys. Login on a new device follows Ente Auth: emailed one-time code plus an
SRP-6a proof of the password. There is no hosted service and no telemetry.

## 2. Scope: what to review, in priority order

| # | Area | Where | Question for the reviewer |
|---|---|---|---|
| 1 | SRP-6a, client | `android/core/crypto/.../Srp.kt`, `PasswordKdf.kt` | Does it follow RFC 5054 (group, `k`, `x`, `u`, `S`) and RFC 2945 (`M1`, `M2`, with `K = H(PAD(S))`) as written in crypto-format 4.4? Checks on `B`, `u`; timing (`BigInteger.modPow` is not constant time); handling of the login subkey. |
| 2 | SRP-6a, server | `server/src/ultimateotp/srp.py`, `login.py` | Same RFCs. Validation of `A`, session lifetime (5 minutes), single use, lockout and backoff, decoy responses for unknown emails, constant-time compares. |
| 3 | Key hierarchy and wrapping | crypto-format 3, 4; `KeyWraps.kt`, `ItemCipher.kt`, `SealedVaultKey.kt`, `Aead.kt` | Domain separation (AD labels, `kind`, `key_epoch`), nonce handling (random 192-bit), the kind 3 "recovery-kek" wrap, Argon2id parameters and reader limits, password normalisation (NFC). |
| 4 | Request signing and replay protection | crypto-format 12.1; contract "Authentication"; `server/.../signing.py`, `auth.py`, `Statements.kt` | Canonical string unambiguity, what is bound (method, path and query, device, time, nonce, body hash), ±60 s window, nonce cache lifetime vs window, behaviour across restarts and with several workers. |
| 5 | Pairing | crypto-format 5.4; `server/.../service.py` pairing parts; sync client | Strength of the six-word SAS (66 bits) against a malicious server, what the QR carries, pairing session lifetime and single use, who can approve. |
| 6 | Revocation, rotation, signed heads | crypto-format 7, 8 | Rollback and fork protection by the signed head, behaviour of a client that was offline, rotation atomicity, what a revoked device can still do or keep. |
| 7 | Export formats and imports | crypto-format 10, 11; `ExportFile.kt`, `SecretStreamCodec.kt`, `EnteExport.kt`, `core:otp` parsers | Container authentication (header as AD, truncation, `TAG_FINAL`), reader limits against hostile files, parsers for `otpauth://`, `otpauth-migration://` and lists (resource exhaustion, injection into the UI). |
| 8 | Android storage and lock | `KeystoreSecretStore.kt`, `core:vault`, `AutoLock.kt`, `MainActivity.kt` | Keystore key parameters (AES-256-GCM, StrongBox when present, user authentication validity of 30 s, not invalidated by new biometrics), where plaintext can exist, `FLAG_SECURE`, backup exclusion, what the lock actually protects (see 7). |
| 9 | libsodium binding workarounds | `PasswordKdf.kt`, `Sodium.kt`, `proguard-rules.pro` | The direct `crypto_pwhash` call over JNA with UTF-8 bytes and `NativeLong` instead of the bindings' `String` API; memory zeroing; R8 keep rules. |
| 10 | Server data handling and deployment | `server/`, `docs/deploy.md`, `server/Dockerfile`, `server/compose.yaml` | No plaintext or secrets in logs, hardening of the container, defaults of `UOTP_*` settings, enrollment scope, email and ntfy secrets handling. |
| 11 | Build and release integrity | `.github/workflows/release.yml`, `android/gradle/verification-metadata.xml`, [reproducible-builds.md](reproducible-builds.md) | Dependency pinning, signing, what F-Droid and a user can verify. |

Out of scope: Android itself and the Keystore implementations of vendors, libsodium's own internals
(already widely reviewed), the user's reverse proxy.

## 3. Threat model summary

Full table: [design.md](design.md) section 2. Summary of what the design claims:

| Adversary | Claim |
|---|---|
| Server operator or intruder (DB dump, RCE) | Cannot read secrets, labels or the vault key. Can delete data, refuse service, show old data (rollback is detected by clients that saw a newer signed head), see metadata (IPs, timing, item count, device names, account email) and brute-force the password from the stored SRP verifier and password wrap, slowed by Argon2id (sensitive limits, up to 1 GiB). |
| Malicious server substituting devices or keys | Clients pin device keys; new devices are shown for confirmation; pairing uses a six-word SAS compared on both screens; sealed keys must be signed by a pinned device. A device enrolled by password trusts the device list on first use. |
| Network attacker | TLS is the user's reverse proxy's job; requests are also signed and replay-protected; blobs are authenticated. |
| Lost or stolen locked phone | Secrets are wrapped by a Keystore key that needs the device credential or biometrics. |
| Lost phone, unlocked, app open | Not protected. |
| Compromised app update or build | Not protected by crypto; mitigations are reproducible builds, hash-pinned dependencies and a signing key kept off the CI except as a secret. |
| Malware or root on the phone, coercion | Out of scope. |
| Stolen export file | Protected by the export password (Argon2id, sensitive limits). |
| Recovery key theft | Equals vault access, by design. |

Trust assumptions the reviewer should challenge: that email is an acceptable second step (the mailbox is
a root of trust for login on a new device only; the password and the SRP proof are still required);
that a 24-word BIP-39 encoding of 256 random bits is a sensible recovery key; that storing a
password-wrapped vault key on the server is acceptable (owner decision 2).

## 4. Cryptographic inventory

Versions are those pinned in `android/gradle/libs.versions.toml`, `android/gradle/verification-metadata.xml`
and `server/uv.lock` at the time of writing.

### 4.1 Primitives

| Use | Primitive | Provided by | Where used |
|---|---|---|---|
| Password KDF | Argon2id (`crypto_pwhash`, sensitive limits 4 ops, 1 GiB, with a fallback ladder to 16 ops, 256 MiB) | libsodium | vault password wrap, export, Ente import |
| Symmetric AEAD | XChaCha20-Poly1305-IETF, random 24-byte nonce | libsodium | items, wraps |
| Streaming AEAD | `crypto_secretstream_xchacha20poly1305` | libsodium | `.uotp` export, Ente export import |
| Key agreement for key transfer | `crypto_box_seal` (X25519, XSalsa20-Poly1305) | libsodium | sealed vault key to a device |
| Signatures | Ed25519 (`crypto_sign_detached`) | libsodium (app), PyNaCl (server verify) | requests, heads, seals, device certificates |
| Key derivation | `crypto_kdf_derive_from_key` (BLAKE2b) | libsodium | item key, `KEK_rk`, login subkey |
| Hashing | BLAKE2b-256 (`crypto_generichash`), SHA-256 | libsodium; JDK `MessageDigest` and Python `hashlib` for SRP | manifests, SAS, SRP |
| Padding | `sodium_pad` (ISO/IEC 7816-4, 256-byte blocks) | libsodium | item plaintext |
| Password authentication | SRP-6a, RFC 5054 4096-bit group (RFC 3526), SHA-256, own implementation | `java.math.BigInteger` (app), Python integers (server) | login from a new device |
| Recovery key encoding | BIP-39 English word list, 256 bits plus 8-bit checksum | own code, list checked by SHA-256 | recovery key, SAS words |
| Local secret wrapping | AES-256-GCM in the Android Keystore, StrongBox when available, user authentication required | Android Keystore | vault key and device private keys at rest |
| Random numbers | `randombytes_buf` (libsodium); `secrets` (Python server) | libsodium, CPython | nonces, salts, SRP ephemerals, ids, codes |
| Emailed codes | 6 digits, SHA-256 with a per-code salt, constant-time compare | `hashlib`, `hmac` | server login |

### 4.2 Libraries

| Component | Version | Role | Licence | Native code |
|---|---|---|---|---|
| libsodium | 1.0.20 on Android (version string read from the `libsodium.so` in the AAR); 1.0.19 in the JVM unit tests (from the bindings' JVM artifact, per crypto-format 1) | all primitives above | ISC | yes, prebuilt inside the bindings' AAR |
| `com.ionspin.kotlin:multiplatform-crypto-libsodium-bindings` | 0.9.5 | Kotlin bindings over JNA; labels itself experimental | Apache-2.0 | `libsodium.so` for arm64-v8a, armeabi-v7a, x86, x86_64 |
| JNA (`net.java.dev.jna:jna`) | 5.18.1 AAR at runtime (what the bindings depend on); 5.19.1 is compile-only for `PasswordKdf` | calls libsodium | Apache-2.0 or LGPL-2.1+ | `libjnidispatch.so` (ABIs armeabi, mips and mips64 are excluded in `app/build.gradle.kts`) |
| ZXing core | 3.5.4 | QR decoding | Apache-2.0 | no |
| CameraX | 1.6.2 | camera frames | Apache-2.0 | no |
| Room (androidx.room3) | 3.0.3 | local database of ciphertext | Apache-2.0 | no |
| AndroidX Biometric | 1.1.0 | authentication prompt | Apache-2.0 | no |
| OkHttp | 5.5.0 | HTTP, SSE | Apache-2.0 | no |
| kotlinx.serialization | 1.11.0 | JSON | Apache-2.0 | no |
| Kotlin / AGP / Gradle | 2.4.21 / 9.4.1 / 9.8.1 | build | Apache-2.0 | no |
| Python | 3.13 (image `python:3.13-slim`, pinned by digest) | server | PSF | |
| FastAPI / Starlette / Pydantic / Uvicorn | 0.143.0 / 1.8.0 / 2.14.1 / 0.54.0 (`server/uv.lock`) | server | MIT / BSD | no |
| PyNaCl | 1.6.2 (`server/uv.lock`) | Ed25519 verification on the server; generates the test vectors | Apache-2.0 | yes (bundles libsodium; the bundled version was not checked) |

The complete, hash-pinned list of build dependencies is `android/gradle/verification-metadata.xml`.

## 5. Test vectors and where they live

| Artifact | Location | Produced by | Checked by |
|---|---|---|---|
| Vectors for every format (KDF, wraps, items, devices, heads, request signature, sealed key, export, Ente export, SRP) | `docs/crypto-vectors/vectors.json` (copy in `server/tests/vectors/crypto-v1.json`) | `docs/crypto-vectors/generate_vectors.py` with PyNaCl 1.6.2 (reference libsodium) | Android `CryptoVectorsTest.kt`; server `tests/test_crypto_vectors.py` |
| RFC 5054 Appendix B (1024-bit group, SHA-1) | `docs/crypto-vectors/rfc5054.json` | RFC text | Android `SrpTest.kt`; server `tests/test_srp.py` (`test_rfc5054_appendix_b`) |
| BIP-39 English word list | `docs/crypto-vectors/bip39-english.txt` (SHA-256 `2f5eed53...dbda`, shipped in the app as a resource) | bitcoin/bips | `CryptoResourcesTest` (on the fix branch) and the vectors |
| Round trips and negative cases | `android/core/crypto/src/test/`, `core/sync/src/test/`, `core/vault/src/test/` | | `./gradlew check` |
| OTP RFC vectors (RFC 4226, RFC 6238) | `android/core/otp/src/test/` | | `./gradlew check` |
| Server behaviour: signatures, replay, enrollment, pairing, revocation, SRP login, lockout, email codes, plaintext scan of the database, contract conformance | `server/tests/` | | `uv run pytest` in `server/` |

Regenerate the vectors with the command in crypto-format 13. The vectors use cheap Argon2id parameters
(2 ops, 16 MiB); the production parameters are not exercised by a vector.

## 6. How to build, run and test

- App: `cd android && ./gradlew check assembleRelease` (JDK 21, Android SDK). Unsigned without the
  `UOTP_*` signing variables. See [reproducible-builds.md](reproducible-builds.md).
- Server: `cd server && uv sync && uv run pytest`. Deployment: [deploy.md](deploy.md).
- Everything uses invented data. No test needs a device.

## 7. Known limitations

State them plainly; a reviewer should not have to discover them.

1. **Hand-written SRP.** No audited library was used on either side. Client: about 150 lines over
   `BigInteger`; server: about 175 lines over Python integers. Pinned by RFC 5054 Appendix B (1024-bit,
   SHA-1) and by self-generated vectors for the production group (4096-bit, SHA-256, `K = H(PAD(S))`),
   which are not an independent third-party reference. Compatibility with Ente's SRP library is not
   claimed. `BigInteger.modPow` and Python's `pow` are not constant time.
2. **Experimental libsodium bindings.** The ionspin library describes itself as experimental, and a
   bug in its `pwhash` (UTF-16 length used as the byte length, 64-bit `memlimit` for a C `size_t`) is
   worked around by calling `crypto_pwhash` directly (not yet reported upstream, per crypto-format 1.3).
   The prebuilt `libsodium.so` and `libjnidispatch.so` come from Maven Central AARs and are not built in
   this project's CI. The bindings' API was used with one libsodium call per wrapper call, and pinned by
   vectors, so replacing them does not change a byte.
3. **No UI or on-device tests so far.** Unit tests run on the JVM (with Robolectric for Android types).
   The release build (R8, resource shrinking) is not exercised by tests, which is how the
   resource-path crash of 0.1.2 reached a release (see [CHANGELOG.md](../CHANGELOG.md)). No automated test exercises the Keystore
   path, the biometric prompts or the StrongBox fallbacks.
4. **App lock semantics.** The Keystore key requires authentication within the last 30 seconds; after
   that window the app asks again. Whether this is the right model for an unlocked phone, and the
   behaviour on devices without a secure lock screen (the key is then created without authentication
   requirement), should be examined.
5. **Not memory-hardened on the JVM.** Secrets exist as `ByteArray`/`String` on the heap for as long
   as the GC leaves them; zeroing is best effort.
6. **Email as a factor.** A compromised mailbox plus a stolen password is enough to log in on a new
   device; a compromised mailbox alone is not. The six-digit code is stored salted and SHA-256 hashed,
   short-lived (10 minutes, 5 attempts).
7. **Metadata is plaintext on the server**: account email, device names, last seen and last IP, item
   count and sizes in 256-byte buckets, timing. This is an owner decision (decisions.md 9).
8. **Password-wrapped vault key on the server** makes offline guessing against a server dump possible;
   the cost is Argon2id with 1 GiB memory per guess. The "paranoid" mode of design.md 3.2 (no
   password wrap) is specified in the format, but whether and how the app offers it was not checked
   for this document.
9. **Old backups stay readable with the old vault key** after a rotation (accepted, design.md 3.6).
10. **Single maintainer, AI-assisted code.** Review should assume that plausible-looking code can be
    wrong in subtle ways, and that tests were written by the same process as the code.
11. **Server rate limiting** assumes a reverse proxy supplying a trustworthy client IP
    (`X-Forwarded-For` depth is configurable); behind a misconfigured proxy all clients share a bucket.

## 8. Reporting and reviewer logistics

- Vulnerabilities: GitHub private vulnerability reporting, see [../SECURITY.md](../SECURITY.md).
- Questions and non-sensitive findings: public issues are fine.
- The maintainer can provide a test server, test accounts, a debug APK and the exact commit; ask in
  the engagement request.
- The report can be published; say so in the request if the reviewer's own policy needs it.

## 9. Before calling it 1.0

All of the following, in order of importance:

- [ ] External review of areas 1 to 8 of section 2 done, findings fixed or accepted in writing, and the
      report (or a summary) linked from the README.
- [ ] Independent SRP check: an audited library or a third-party interoperability test for the 4096-bit
      SHA-256 group, or a documented decision to keep the own implementation with the reviewer's sign-off.
- [ ] The bindings workaround reported upstream, or the bindings replaced or vendored; decision recorded
      about the prebuilt native libraries (see [fdroid/README.md](fdroid/README.md)).
- [ ] Instrumented tests on a device or emulator, running the release (R8) build: onboarding, sign-up,
      login, pairing, export and import, lock and unlock, Keystore invalidation, rotation.
- [ ] A test that the release APK contains every resource the code reads by name (the 0.1.2 class of
      bug) and a smoke test of the minified build in CI.
- [ ] Recovery drills written down and run: lost phone with another device, all devices lost with the
      recovery key, forgotten password with the recovery key, server restored from backup.
- [ ] Property and fuzz tests for the parsers (`otpauth`, migration, export container, Ente import) and
      for the request-signing canonicalisation.
- [ ] Reproducible build confirmed by F-Droid's verification for at least one release (the app signed by
      this project's key, F-Droid's build identical).
- [ ] Gradle dependency verification and the server lock file enforced in CI, with a documented update
      process.
- [ ] Format stability: crypto format and contract frozen as v1, migration path for v2 written.
- [ ] Server hardening reviewed against the default deployment (compose file, headers, logging of
      secrets, backup and restore).
- [ ] A privacy statement (what the server stores, what is logged, retention).
- [ ] Threat model re-read against what was built, design.md updated to match crypto-format.

## 10. Who could review

No prices or availability are stated here: I could not verify them. Ask for quotes, state the scope of
section 2, and say that it is a GPL project with a single maintainer and a small budget.

Organisations that do security audits of free software (non-exhaustive, check that each currently
accepts such work):

- Cure53 (Berlin), which has published audits of many open source privacy projects.
- Radically Open Security (Netherlands, non-profit), which does reviews of free software and works with
  the NLnet and NGI funding programmes.
- Include Security, Trail of Bits, Quarkslab and X41 D-Sec have published open source audits too.
- Open Source Technology Improvement Fund (OSTIF), which brokers and co-funds audits of open source
  projects; it can be approached when a project has users.

Funding routes that have paid for audits of free software: NLnet / NGI Zero grants (which can include
an audit), the Sovereign Tech Fund, and OSTIF. Check each programme's current rules and eligibility.

Community review options, cheaper and less complete, useful before a paid audit:

- A focused review request for the SRP code and the key hierarchy on Cryptography Stack Exchange or a
  cryptography mailing list, pointing at crypto-format.md and the test vectors.
- Asking maintainers of similar projects (Aegis, Ente Auth, 2FAuth) or cryptography-literate F-Droid
  contributors for a read-through of the parts that overlap with their work.
- Android security researchers for the Keystore and lock model (area 8).
- Automated aids that do not replace review: static analysis (Android lint, detekt, Semgrep,
  CodeQL for Kotlin and Python), `pip-audit` for the server lock file, and dependency scanners on
  the verification metadata.
