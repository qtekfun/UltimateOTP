# Roadmap and status

Written 2026-10-14. See `decisions.md` for why, `testing.md` for what is verified, `security-review.md` for the review plan.

## Done

- Offline authenticator: TOTP, HOTP and Steam, otpauth and QR import, Ente, Google, Aegis, 2FAS, andOTP, Raivo, Bitwarden and Proton importers, encrypted export.
- Sync: SRP-6a login with emailed codes, device signing, optimistic commits, live events (SSE), pairing, revocation, rotation, history and trash, account deletion and export.
- Server hardening: anonymised client ids, growing blocks, localized emails, metrics, Grafana dashboard.
- Release pipeline: signed APK and multi-arch server image from a `v*` tag; reproducible build.
- Test suite and CI: minified build under test, real-server contract tests, emulator journeys, coverage floors.

## Not verified on a real device

Nothing below has been run on a phone. Each item needs a person with a device before 1.0:

- The Keystore authentication prompt (BiometricPrompt, device credential) and the 30 s window.
- The Autofill service in Chrome, Firefox and real apps.
- Animations, haptics, predictive back, themed icon, per-app language.
- Key derivation memory use on low-RAM and 32-bit ARM phones.
- Sharing and saving the error log, and the import file picker.

## Open

- **External security review** of the hand-written SRP (Kotlin and Python), the key hierarchy and the Android storage. It is a precondition of 1.0 and of storing real secrets.
- **SRP library:** replace the hand-written SRP with a maintained one if a suitable one appears.
- **F-Droid submission:** recipe drafted in `fdroid/`; waits for a release that carries the fixes, icons and screenshots.
- **Lost Keystore key:** a guarded "start over" action.
- **Real-device Autofill matching** for OTP fields that are not annotated.
- **Server upgrade 1.1 to 1.2:** migration `0002` erases stored client addresses and is not reversible; back up `ultimateotp.db` first.
