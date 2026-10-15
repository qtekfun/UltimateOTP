<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org). Before 1.0.0 the app and the server are in
early development: anything may change, and nothing here has been externally audited.

Android `versionCode` of each release is given next to it (see RELEASING.md); the server and the API
contract (`contracts/openapi.yaml`) have their own version numbers and are mentioned when they change.

## [Unreleased]

## [0.2.1] - 2026-10-15

Android `versionCode` 5. Tag `v0.2.1`. No server change (API contract 1.2.0, image `0.2.1` is the same code as `0.2.0`).

### Added

- Settings > Account > **New recovery key**: after the current password, makes 24 new words and replaces
  the recovery wrap. The old words stop working; the password and the vault do not change.
- The next code is shown on every TOTP and Steam card from the start of the period (it was shown only in
  the last 5 seconds).

### Changed

- A server problem the app has no text for now names its problem code instead of a generic message.
- Lint no longer fails the build when a newer version of a library is published.

## [0.2.0] - 2026-10-14

Android `versionCode` 4. Tag `v0.2.0`. Server API contract 1.2.0 (server image `0.2.0`). The first version meant
for F-Droid: 0.1.2 crashes on sign-up. Upgrade note: server migration `0002` erases the client addresses
stored by 1.1.0 and cannot be undone; back up `ultimateotp.db` first.

### Features

- New design: green, dark-first theme, logo and adaptive icon, issuer logos, cards with the next code and
  a countdown ring, a two-pane layout on foldables, Spanish translation and a language setting.
- Import from Aegis, 2FAS, andOTP, Raivo and Bitwarden/Proton; trash with undo and 30-day retention (and
  recovery from the server history); manual ordering; Autofill; configurable inactivity lock; local
  exportable error log; account management (delete account, change email, sign out other devices, export).
- Server: anonymised client addresses (daily salted hash), temporary blocks with growing back-off,
  vault history, Spanish and English emails, Prometheus metrics, Grafana dashboard and alert rules.

### Known issues

- KB-6: a 32-bit process may be unable to allocate the 1 GiB Argon2id needs when creating an account
  (see docs/testing.md).
- Autofill, biometric prompts and the Keystore timing were not exercised on real hardware by the
  automated tests.

### Fixed

- Creating an account from the app crashed in release builds with
  `IllegalArgumentException: Required value was null` (in the SRP group loader), and showing the 24-word
  recovery key would have crashed right after. Every other use of the SRP group (log in on a new device,
  password change) goes through the same loader and is expected to be affected too; only the use of the
  app without a server was unaffected. The RFC 5054 group and the BIP-39 word list were read
  with a resource name relative to a class's package; R8 renames and repackages classes in the minified
  release build, so the lookup returned `null`. Debug builds and every unit test were unaffected, which
  is why the test suite stayed green. The files are now read with an absolute path through one helper
  (`CryptoResources`), and a test fails the build if any main source reads a resource relative to a
  class. Branch `fix/release-resources`, commit `b64e84e`.

### Added

- Show/hide toggle on the password fields and a button to copy the 24 recovery words. Branch
  `feat/show-password`, commit `3d0a989`.

### Changed

- Release builds are reproducible across machines: the prebuilt native libraries are packaged unstripped,
  so the APK no longer depends on whether the build machine has an NDK (the stripped and unstripped
  builds differed in every `.so`). The APK is about 190 KB larger. See docs/reproducible-builds.md.
- Gradle dependency verification: `android/gradle/verification-metadata.xml` pins the SHA-256 of every
  dependency and plugin; builds fail on an unknown or changed artifact.
- Dependabot for Gradle, uv, Docker and GitHub Actions; F-Droid store texts (English, Spanish),
  `SECURITY.md`, a security review package (docs/security-review.md) and a draft F-Droid recipe
  (docs/fdroid/).

## [0.1.2] - 2026-10-13

Android `versionCode` 3. Tag `v0.1.2`.

### Added

- Sign-up from the app, like Ente Auth: a first-run choice between **Create account** (email, emailed
  code, password and a 24-word recovery key), **Log in** and **Use without a server**. The server side is
  `POST /otp/v1/signup`, closed by default (`UOTP_SIGNUP=disabled`).
- Deployment guide: opening sign-up, creating the account from the app and closing it again.

### Known issues

- Create account crashes in the release APK (fixed in the next version, see Unreleased), and the other
  SRP flows are expected to as well. Using the app without a server works.

## [0.1.1] - 2026-10-13

Android `versionCode` 2. Tag `v0.1.1`. No change in the app.

### Changed

- The release workflow also builds the server image for amd64 and arm64 and publishes it to GHCR as
  `ghcr.io/qtekfun/ultimateotp-server:<version>`, with provenance and SBOM attestations, and the
  release notes carry its digest.

## [0.1.0] - 2026-10-13

Android `versionCode` 1. Tag `v0.1.0`. First tagged version; API contract 1.1.0, crypto format 1.1.

### Added

- Android app (Kotlin, Jetpack Compose): TOTP, HOTP and Steam codes, SHA-1/256/512; QR scanning with
  CameraX and ZXing (no Google services); `otpauth://` links; edit, tags, favourites, search.
- Offline vault: items encrypted with XChaCha20-Poly1305 and kept in an encrypted Room database; the
  secrets protecting it live in the Android Keystore (StrongBox when available) behind the device
  credential or biometrics; app lock; `FLAG_SECURE`; no Android backup.
- Import from Ente Auth (plain and encrypted), Google Authenticator migration codes and `otpauth://`
  lists; encrypted export to a `.uotp` file (Argon2id and XChaCha20-Poly1305 secretstream) and a plain
  export behind a warning.
- Sync with your own server: device keys and signed requests, vault key wrapped by the password and by a
  24-word recovery key, pairing by QR with six confirmation words, device revocation with key rotation,
  signed vault heads against rollback, live updates over SSE, password and recovery re-keying.
- Login from anywhere like Ente: emailed one-time code and an SRP-6a proof of the password (RFC 5054,
  4096-bit group, SHA-256).
- Server (Python, FastAPI, SQLite): a blob store that never sees plaintext; enrollment tokens, signed
  requests with replay protection, SRP login with lockout and rate limits, emailed codes over SMTP
  STARTTLS, ntfy and email alerts, session list, admin CLI, Docker image and Traefik deployment guide.
- Crypto format and test vectors generated with PyNaCl (`docs/crypto-format.md`,
  `docs/crypto-vectors/`), checked by both the Android and the server tests.
- GPL-3.0-or-later license; release workflow that builds and signs the APK from a `v*` tag.

[Unreleased]: https://github.com/qtekfun/UltimateOTP/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/qtekfun/UltimateOTP/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/qtekfun/UltimateOTP/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/qtekfun/UltimateOTP/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/qtekfun/UltimateOTP/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/qtekfun/UltimateOTP/releases/tag/v0.1.0
