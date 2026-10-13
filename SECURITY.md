<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Security policy

## Status

UltimateOTP is in early development (0.x) and **has not been audited**. Do not make it the only copy of
the 2FA secrets of accounts you cannot afford to lose; keep an encrypted export somewhere safe. What is
known to be missing is listed in [docs/security-review.md](docs/security-review.md) (section 7) and the
conditions for calling it 1.0 are in section 9 there.

## Reporting a vulnerability

Please report privately through GitHub's private vulnerability reporting: on the repository page, go to
**Security**, then **Report a vulnerability**
(<https://github.com/qtekfun/UltimateOTP/security/advisories/new>). Do not open a public issue or a pull
request for a vulnerability.

Useful in a report: the affected component (Android app, server, crypto format, contract), the version or
commit, what an attacker needs (network position, a stolen phone, a server dump, a malicious server), and
the steps or a test that shows it. Use invented data; never send real secrets.

What to expect: this is a one-person hobby project, so there are no guaranteed response times. I will try to
acknowledge a report within a week, to work on a fix privately, and to credit you in the advisory and the
changelog unless you prefer otherwise. Coordinated disclosure is welcome: please give me a reasonable
time to release a fix before publishing details.

## Supported versions

Only the latest release is supported, and, before 1.0, fixes may require a new key epoch or a format
change that needs a manual migration (announced in the changelog).

## Scope

In scope:

- The Android app (`android/`): key handling, vault storage, app lock, import and export, sync client.
- The server (`server/`): authentication, SRP login, signed requests, replay protection, rate limits,
  data handling, deployment defaults.
- The formats and protocol: `docs/crypto-format.md` and `contracts/openapi.yaml`.
- Build and release integrity: the release workflow, dependency pinning, reproducibility.

Out of scope:

- A compromised or rooted device, malware with accessibility rights, or an unlocked phone in the
  attacker's hands (see the threat model in [docs/design.md](docs/design.md) section 2).
- Vulnerabilities in third-party libraries that are not reachable through this project; report those
  upstream (libsodium, JNA, ionspin bindings, FastAPI, PyNaCl, AndroidX).
- Denial of service against a server you run yourself without the recommended reverse proxy limits.
- Weak passwords chosen by users.

## For reviewers

[docs/security-review.md](docs/security-review.md) is the package for an external review: scope, threat
model, a table of every primitive and library with versions, test vectors, known limitations and a
suggested reading order.
