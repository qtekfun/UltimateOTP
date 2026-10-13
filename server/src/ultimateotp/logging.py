# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""JSON logs on stdout, secrets redacted before anything is written.

Nothing secret should ever reach a log call (handlers log ids, codes and reasons only, never a
body, a header value, a token or a blob); the redaction filter is the second line of defence:
tokens (`uoe_`, `uop_`), bearer values, the signature header and any long base64url run (a blob
or a key) are replaced by `[REDACTED]`.

`security_event` writes one line on the `ultimateotp.security` logger with a stable `event`
name (`auth.failure`, `enroll.success`, `device.revoked`, `vault.conflict`, ...) and flat fields,
for CrowdSec or a SIEM. `AccessLog` logs every request with the anonymized client id (never an
address, anon.py), the method, the route template's path without the query string, the status and
the duration, and feeds the latency histogram.
"""

import json
import logging
import re
import sys
import time
from datetime import UTC, datetime
from typing import Any, TextIO, override

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ultimateotp.anon import SCOPE_KEY, ClientContext
from ultimateotp.metrics import Metrics

REDACTED = "[REDACTED]"
FIELDS_ATTR = "uotp_fields"
SECURITY_LOGGER = "ultimateotp.security"
ACCESS_LOGGER = "ultimateotp.access"
MAX_FIELD_CHARS = 256
# A stream that lives for an hour has no meaningful latency (uotp_sse_connections_total counts it).
EVENTS_ROUTE = "/otp/v1/events"

_TOKEN = re.compile(r"\buo[ep]_[A-Za-z0-9_-]{20,}")
_BEARER = re.compile(r"(?i)\b(bearer\s+)[^\s,;\"']+")
_SIG_HEADER = re.compile(r"(?i)(x-uotp-signature[\"']?\s*[:=,]\s*[\"']?)[^\s,;\"')]+")
# 40+ base64url characters in a row: a key, a signature, a wrap or a blob. Ids (22 chars after
# their prefix) stay readable.
_LONG_B64 = re.compile(r"[A-Za-z0-9_-]{40,}")
_SECRET_KEY = re.compile(
    r"token|secret|password|authorization|signature|blob|wrap|kdf|sealed|nonce", re.IGNORECASE
)


# Defence in depth for the anonymization rule (anon.py): no log line carries a client address.
# The callers never pass one; this catches one that slipped into a message or an exception.
_IPV4 = re.compile(r"(?<![\w.])(?!0\.0\.0\.0(?![\w.]))(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(
    r"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"(?=[0-9A-Fa-f]|\b))(?![\w:])"
)
ADDRESS_MASK = "[ip]"


def scrub_addresses(text: str) -> str:
    text = _IPV4.sub(ADDRESS_MASK, text)
    return _IPV6.sub(lambda m: m.group(0) if m.group(0) == "::" else ADDRESS_MASK, text)


def redact(text: str) -> str:
    text = scrub_addresses(text)
    text = _TOKEN.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _SIG_HEADER.sub(lambda m: m.group(1) + REDACTED, text)
    return _LONG_B64.sub(REDACTED, text)


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return redact(value[:MAX_FIELD_CHARS])
    if isinstance(value, dict):
        return {
            k: REDACTED if isinstance(k, str) and _SECRET_KEY.search(k) else _redact_value(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    return value


class RedactingFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if isinstance(record.args, dict):
            record.args = _redact_value(record.args)  # type: ignore[assignment]
        elif record.args:
            record.args = tuple(_redact_value(a) for a in record.args)
        return True


class JsonFormatter(logging.Formatter):
    @override
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        fields = getattr(record, FIELDS_ATTR, None)
        if isinstance(fields, dict):
            for name, value in fields.items():
                key = str(name)
                entry.setdefault(key, REDACTED if _SECRET_KEY.search(key) else _redact_value(value))
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(level: str, stream: TextIO | None = None) -> None:
    """JSON lines on `stream` (stdout for the api; the admin CLI passes stderr so its own
    output on stdout stays machine-readable)."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True


_security_log = logging.getLogger(SECURITY_LOGGER)


def security_event(
    event: str, *, level: int = logging.INFO, **fields: str | int | bool | None
) -> None:
    """One structured security event. Callers pass ids, codes and reasons only."""
    _security_log.log(level, event, extra={FIELDS_ATTR: {"event": event, **fields}})


class AccessLog:
    """Plain ASGI middleware, inside `ClientIdentity` so it sees the anonymized client."""

    def __init__(self, app: ASGIApp, metrics: Metrics | None = None) -> None:
        self._app = app
        self._metrics = metrics
        self._log = logging.getLogger(ACCESS_LOGGER)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        start = time.monotonic()
        status = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            elapsed = time.monotonic() - start
            path = str(scope.get("path", ""))
            level = logging.DEBUG if path in ("/healthz", "/readyz", "/metrics") else logging.INFO
            context = scope.get(SCOPE_KEY)
            self._log.log(
                level,
                "request",
                extra={
                    FIELDS_ATTR: {
                        "event": "http.request",
                        "method": scope.get("method"),
                        "path": path[:MAX_FIELD_CHARS],
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 1),
                        "client_id": context.client_id
                        if isinstance(context, ClientContext)
                        else None,
                    }
                },
            )
            route = scope.get("route")
            template = getattr(route, "path", None)
            if self._metrics is not None and template != EVENTS_ROUTE:
                self._metrics.observe(
                    "uotp_http_request_duration_seconds",
                    elapsed,
                    method=str(scope.get("method", "GET")),
                    route=template if isinstance(template, str) else "unmatched",
                    status=f"{status // 100}xx",
                )
