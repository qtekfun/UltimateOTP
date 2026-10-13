# Owner decisions (2026-10-13)

These answer the open questions in `design.md` §7 and override it where they differ.

1. **Live sync is required in the MVP.** Changes on one device must reach the others without a manual export/import.
2. **Password-wrapped vault key on the server, like Ente Auth.** The server stores the vault key encrypted under a key derived from the user's password (Argon2id). It is fetched by new or reinstalled devices and decrypted only on the client. The server never sees the password, the derived key or the plaintext vault key. A recovery key wraps the vault key too.
3. **Export format: the most secure option.** Password-protected exports use Argon2id (libsodium "sensitive" limits) and XChaCha20-Poly1305 secretstream, the same primitives as the vault, and not age/scrypt. Document the parameters and the reasoning in `docs/crypto-format.md`.
4. **Device enrollment from outside the LAN: still open.** Implement the design's default (LAN-only for the admin and enrollment routes) behind a setting, so it can change without a redesign.
5. **Scope:** an Android app (Kotlin + Jetpack Compose, F-Droid) and a Python backend at least. Other clients (CLI, desktop, web, iOS) are later milestones, but the API and crypto formats must not lock them out.
