# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""`ultimateotp` command: the api, the migrator and the admin CLI.

Admin commands run inside the container (`docker compose exec api ultimateotp ...`), so they are
reachable only by whoever controls the host: that is the LAN-only admin surface of the MVP.
They print enrollment tokens on stdout on purpose (the owner types or scans them into the app);
tokens are single-use and expire after `UOTP_ENROLLMENT_TOKEN_TTL_S` (10 min).
"""

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ultimateotp import __version__, db
from ultimateotp.clock import SystemClock
from ultimateotp.errors import ApiError
from ultimateotp.events import Broker
from ultimateotp.logging import configure_logging
from ultimateotp.metrics import Metrics
from ultimateotp.service import Service
from ultimateotp.settings import Settings

log = logging.getLogger("ultimateotp")


def _service(settings: Settings) -> Service:
    return Service(
        db.Database(settings.database_file), settings, SystemClock(), Broker(), Metrics()
    )


def _print(value: Any) -> None:
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_api(settings: Settings) -> int:
    import uvicorn  # noqa: PLC0415 - only the api role needs the server

    from ultimateotp.app import create_app  # noqa: PLC0415

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        # One process: the live-sync broker is in memory (docs/sync.md).
        workers=1,
        log_config=None,
        access_log=False,
        # Client addresses behind a proxy come from forwarded.py (UOTP_TRUSTED_PROXIES).
        proxy_headers=False,
        server_header=False,
        limit_concurrency=settings.limit_concurrency,
        timeout_keep_alive=settings.keepalive_timeout_s,
        timeout_graceful_shutdown=settings.shutdown_timeout_s,
    )
    return 0


def _enroll_uri(server_url: str | None, token: str) -> str | None:
    if not server_url:
        return None
    return f"uotp://enroll?server={quote(server_url, safe='')}&token={token}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ultimateotp", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("api", help="serve the /otp/v1 api")
    sub.add_parser("migrate", help="apply the database migrations")
    create = sub.add_parser("account-create", help="new account + bootstrap enrollment token")
    create.add_argument("--server-url", help="public URL, to print an enrollment link")
    token = sub.add_parser("token-create", help="enrollment token for an existing account")
    token.add_argument("account_id")
    token.add_argument("--server-url", help="public URL, to print an enrollment link")
    sub.add_parser("accounts", help="list accounts (vault head, device count)")
    devices = sub.add_parser("devices", help="list the devices of an account")
    devices.add_argument("account_id")
    revoke = sub.add_parser("device-revoke", help="revoke a device now")
    revoke.add_argument("device_id")
    backup = sub.add_parser("backup", help="consistent online copy of the database")
    backup.add_argument("destination", type=Path)
    sub.add_parser("purge", help="delete expired tokens, pairings and nonces")
    args = parser.parse_args(argv)

    settings = Settings()
    configure_logging(
        settings.log_level, sys.stdout if args.command in ("api", "migrate") else sys.stderr
    )
    try:
        if args.command == "api":
            return run_api(settings)
        if args.command == "migrate":
            applied = db.migrate(settings.database_file, settings.migrations_dir)
            log.info(
                "migrate: %d migration(s) applied: %s", len(applied), [m.name for m in applied]
            )
            return 0
        service = _service(settings)
        if args.command == "account-create":
            account_id, tok, expires = service.create_account()
            _print(
                {
                    "account_id": account_id,
                    "enrollment_token": tok,
                    "expires_at": expires,
                    "enroll_uri": _enroll_uri(args.server_url, tok),
                }
            )
        elif args.command == "token-create":
            tok, expires = service.create_token(args.account_id)
            _print(
                {
                    "enrollment_token": tok,
                    "expires_at": expires,
                    "enroll_uri": _enroll_uri(args.server_url, tok),
                }
            )
        elif args.command == "accounts":
            _print(service.list_accounts())
        elif args.command == "devices":
            _print(service.admin_devices(args.account_id))
        elif args.command == "device-revoke":
            _print(service.revoke_device(args.device_id, None))
        elif args.command == "backup":
            db.backup(settings.database_file, args.destination)
            log.info("backup written to %s", args.destination)
        elif args.command == "purge":
            _print(service.purge())
    except ApiError as error:
        sys.stderr.write(f"error: {error.code} {error.detail}\n")
        return 1
    return 0
