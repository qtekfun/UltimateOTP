# Owner decisions (2026-10-13)

These answer the open questions in `design.md` §7 and override it where they differ.

1. **Live sync is required in the MVP.** Changes on one device must reach the others without a manual export/import.
2. **Password-wrapped vault key on the server, like Ente Auth.** The server stores the vault key encrypted under a key derived from the user's password (Argon2id). It is fetched by new or reinstalled devices and decrypted only on the client. The server never sees the password, the derived key or the plaintext vault key. A recovery key wraps the vault key too.
3. **Export format: the most secure option.** Password-protected exports use Argon2id (libsodium "sensitive" limits) and XChaCha20-Poly1305 secretstream, the same primitives as the vault, and not age/scrypt. Document the parameters and the reasoning in `docs/crypto-format.md`.
4. **Device enrollment from outside the LAN: allowed, the way Ente Auth does it** (decided 2026-10-13, see 6).
5. **Scope:** an Android app (Kotlin + Jetpack Compose, F-Droid) and a Python backend at least. Other clients (CLI, desktop, web, iOS) are later milestones, but the API and crypto formats must not lock them out.

## Round 2 (2026-10-13): "as close to Ente Auth as possible"

Guiding rule from the owner: when in doubt, behave like Ente Auth. These decisions answer the backend's open questions and override `design.md` where they differ.

6. **Login from anywhere with the password, like Ente (SRP).** A new or reinstalled device can sign in from outside the LAN with username + password. The server releases the password-wrapped vault key (and key attributes) only after an SRP-6a proof of the password: RFC 5054, 4096-bit group and SHA-256, as Ente uses. The server stores only the SRP verifier, never the password or a password hash usable to log in.
   - The SRP password input is derived client-side from the same Argon2id output as the KEK. Use a separate subkey via a libsodium KDF context, so the verifier never reveals the KEK. Ente does the same, with a login subkey from the KEK.
   - After a successful SRP login, the device registers its Ed25519 key in the same flow and from then on signs every request, as designed.
   - Pairing by QR from an existing device (the current flow) stays as an alternative, and LAN-only enrollment tokens stay for the first device or account bootstrap.
   - `UOTP_ENROLLMENT_SCOPE` defaults to `anywhere` for SRP login. Pairing and bootstrap-token routes keep their own setting, default `lan`.
   - Strong per-account and per-IP rate limits on the SRP routes, a lockout with exponential backoff, and CrowdSec-friendly security events in the logs.
7. **New-login notifications, like Ente's login emails, sent via ntfy.** The server sends an ntfy message when:
   - a device logs in or is enrolled;
   - a device is revoked;
   - the recovery key is used;
   - the vault key is rotated;
   - SRP login fails repeatedly for an account.

   Configured with `UOTP_NTFY_URL` plus a token from a Docker secret. Optional: when unset, the events are only logged.
8. **Administration: CLI only, like a self-hosted Ente museum.** No admin web page.
   - Accounts are created with the CLI.
   - Public sign-up is disabled by default (`UOTP_SIGNUP=disabled`), like `internal.disable-registration` in museum.
9. **Device labels and session metadata stay in plaintext on the server**, like Ente's active-sessions list (device name, app version, last seen, last IP). The app shows an "Active sessions" screen where any device can revoke another. OTP data, labels of OTP entries, issuers and tags stay end-to-end encrypted.
10. **Recovery key: 24 words, like Ente.** The recovery key is shown once as a 24-word BIP-39 mnemonic of 256-bit entropy. It is stored by the user and wraps the vault key; the server keeps only that wrapped copy.
11. **Export compatible in spirit with Ente's encrypted export.** Argon2id plus XChaCha20-Poly1305 secretstream with the KDF params in the header, as in 3. Import of Ente's plain and encrypted exports remains in scope.
12. **Server backups and rollback:** documented as the backend says. Restoring an old server backup looks like a rollback to devices; the app offers "upload my local copy" to re-seed the server from a device after a restore.
