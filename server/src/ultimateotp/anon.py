# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Anonymized client addresses (owner decision of 2026-10-13, docs/deploy.md §6).

A client IP never reaches a log line, a metric label, a notice, the database or a rate-limit key.
What does: `c_` + 12 hex characters, `HMAC-SHA256(daily_salt, address)` truncated, where

    daily_salt = HMAC-SHA256(server_secret, "uotp-client-salt-v1|" + UTC date)

so "many attempts from the same address within one day" is visible, the address cannot be
recovered from the id, and ids of different days cannot be linked by anyone without the secret.
IPv6 is masked to its /64 first (one subscriber, not one privacy address). The real address
lives only in the ASGI scope for the duration of the request (the LAN checks need it).

The salt of a day is derived on demand and only today's is cached; nothing about earlier days is
kept. The one deliberate exception is the block list: a block that spans UTC midnight is honoured
through the previous day's id (`ClientContext.previous_id`), so a 24 h block really lasts 24 h.
"""

import contextvars
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from starlette.types import ASGIApp, Receive, Scope, Send

from ultimateotp.clock import Clock
from ultimateotp.db import Database
from ultimateotp.forwarded import client_host, from_networks
from ultimateotp.netaddr import IpNetwork, parse_ip
from ultimateotp.settings import Settings

CLIENT_ID_PREFIX = "c_"
CLIENT_ID_HEX = 12
SECRET_NAME = "client-id-secret"  # noqa: S105 - the row name, not a secret
SALT_LABEL = b"uotp-client-salt-v1|"
UNKNOWN_HOST = "unknown"
SCOPE_KEY = "uotp.client"


@dataclass(frozen=True)
class ClientContext:
    """What the rest of the server may know about the caller."""

    client_id: str
    previous_id: str
    # On the owner's LAN: never blocked (UOTP_LAN_NETWORKS, minus UOTP_DENIED_NETWORKS).
    exempt: bool = False
    accept_language: str | None = None
    # Abuse events seen in this request: a request is one attempt, however many events it logs
    # (a wrong code is both `email.code_failure` and `auth.failure`).
    counted: list[str] = field(default_factory=list, compare=False, hash=False)


_current: contextvars.ContextVar[ClientContext | None] = contextvars.ContextVar(
    "uotp_client", default=None
)


def current() -> ClientContext | None:
    """The caller of the request being handled (threads started by the framework inherit it)."""
    return _current.get()


def set_current(context: ClientContext | None) -> contextvars.Token[ClientContext | None]:
    return _current.set(context)


def reset_current(token: contextvars.Token[ClientContext | None]) -> None:
    _current.reset(token)


def mask(host: str | None) -> str:
    """The text that gets hashed: IPv4 as is, IPv6 as its /64, anything else as `unknown`."""
    address = parse_ip(host)
    if address is None:
        return UNKNOWN_HOST
    if isinstance(address, ipaddress.IPv6Address):
        network = ipaddress.ip_network(f"{address}/64", strict=False)
        return f"{network.network_address}/64"
    return str(address)


class ClientIds:
    def __init__(self, secret: bytes, clock: Clock) -> None:
        if len(secret) < 16:  # noqa: PLR2004
            raise ValueError("the client-id secret is too short")
        self._secret = secret
        self._clock = clock
        self._cached: tuple[date, bytes] | None = None

    def _today(self) -> date:
        return datetime.fromtimestamp(self._clock.now(), UTC).date()

    def _salt(self, day: date) -> bytes:
        cached = self._cached
        today = self._today()
        if cached is not None and cached[0] == day:
            return cached[1]
        salt = hmac.new(
            self._secret, SALT_LABEL + day.isoformat().encode(), hashlib.sha256
        ).digest()
        if day == today:
            self._cached = (day, salt)
        return salt

    def _id(self, host: str | None, day: date) -> str:
        digest = hmac.new(self._salt(day), mask(host).encode(), hashlib.sha256).hexdigest()
        return CLIENT_ID_PREFIX + digest[:CLIENT_ID_HEX]

    def client_id(self, host: str | None) -> str:
        return self._id(host, self._today())

    def previous_id(self, host: str | None) -> str:
        return self._id(host, self._today() - timedelta(days=1))


def load_secret(db: Database, settings: Settings, clock: Clock) -> bytes:
    """The server secret of the daily salts: the optional Docker secret, else a random one kept
    in `server_secrets` (so ids survive restarts and are never derived from anything public)."""
    if settings.ip_secret is not None:
        return hashlib.sha256(settings.ip_secret.get_secret_value().encode()).digest()
    with db.write() as conn:
        row = conn.execute(
            "SELECT secret FROM server_secrets WHERE name = ?", (SECRET_NAME,)
        ).fetchone()
        if row is not None:
            return bytes.fromhex(row["secret"])
        secret = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO server_secrets (name, secret, created_at) VALUES (?, ?, ?)",
            (SECRET_NAME, secret.hex(), clock.now()),
        )
        return secret


class ClientIdentity:
    """Plain ASGI middleware, inside `ClientAddress`: resolves the anonymized id, the LAN
    exemption and the language header once per request, and publishes them in a context
    variable and in the scope. Everything downstream logs and keys on the id, never the address."""

    def __init__(
        self,
        app: ASGIApp,
        ids: ClientIds,
        lan: tuple[IpNetwork, ...],
        denied: tuple[IpNetwork, ...],
    ) -> None:
        self._app = app
        self._ids = ids
        self._lan = lan
        self._denied = denied

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        host = client_host(scope)
        language = None
        for name, value in scope.get("headers", []):
            if name == b"accept-language":
                language = value.decode("latin-1")[:256]
                break
        context = ClientContext(
            client_id=self._ids.client_id(host),
            previous_id=self._ids.previous_id(host),
            exempt=from_networks(scope, self._lan, self._denied),
            accept_language=language,
        )
        scope[SCOPE_KEY] = context
        token = set_current(context)
        try:
            await self._app(scope, receive, send)
        finally:
            reset_current(token)


def context_of(scope: Scope) -> ClientContext:
    """The context of a request (an unknown caller when the middleware did not run)."""
    context = scope.get(SCOPE_KEY)
    if isinstance(context, ClientContext):
        return context
    return ClientContext(client_id="c_unknown", previous_id="c_unknown")
