# UltimateOTP

Self-hosted, end-to-end encrypted OTP authenticator: Android app + Python backend.

Like Ente Auth, the app starts with a choice: **Create account** (email, emailed code, password
and a 24-word recovery key, on a server where the owner opened sign-up with
`UOTP_SIGNUP=enabled`), **Log in** (email, code, password) or **Use without a server**. An
enrollment token from the server's CLI and QR pairing remain available as advanced options. See
[docs/deploy.md](docs/deploy.md) §3 step 6 for setting up the first device.

- Design: [docs/design.md](docs/design.md)
- Owner decisions: [docs/decisions.md](docs/decisions.md)
- Import from other apps: [docs/import-formats.md](docs/import-formats.md); autofill: [docs/autofill.md](docs/autofill.md); error log: [docs/diagnostics.md](docs/diagnostics.md)
- `server/`: backend (Python, FastAPI, SQLite); deployment in [docs/deploy.md](docs/deploy.md), live sync in [docs/sync.md](docs/sync.md)
- `android/`: Android app (Kotlin, Jetpack Compose)
- `contracts/`: HTTP API contract (OpenAPI)
- Releases: built and signed by GitHub Actions on a `v*` tag, see [RELEASING.md](RELEASING.md)

## Status

Early development. Not audited: do not trust it with real 2FA secrets yet.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
