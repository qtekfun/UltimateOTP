# UltimateOTP

Self-hosted, end-to-end encrypted OTP authenticator: Android app + Python backend.

- Design: [docs/design.md](docs/design.md)
- Owner decisions: [docs/decisions.md](docs/decisions.md)
- `server/`: backend (Python, FastAPI, SQLite); deployment in [docs/deploy.md](docs/deploy.md), live sync in [docs/sync.md](docs/sync.md)
- `android/`: Android app (Kotlin, Jetpack Compose)
- `contracts/`: HTTP API contract (OpenAPI)

## Status

Early development. Not audited: do not trust it with real 2FA secrets yet.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
