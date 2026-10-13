# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The FastAPI application.

Middleware order, outermost first: `ClientAddress` (decides the client behind the proxy),
`AccessLog`, `BodyLimit`, then FastAPI. No CORS: native apps only (a web client is a later
milestone with its own origin policy, design §4.7). No OpenAPI UI: the contract is the file.
"""

from fastapi import FastAPI
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ultimateotp import __version__, errors
from ultimateotp.alerts import Alerts
from ultimateotp.clock import Clock, SystemClock
from ultimateotp.db import Database
from ultimateotp.events import Broker
from ultimateotp.forwarded import ClientAddress
from ultimateotp.logging import AccessLog
from ultimateotp.metrics import Metrics
from ultimateotp.ratelimit import Limit, NoRateLimit, RateLimiter, TokenBucketLimiter
from ultimateotp.routes import probes, router
from ultimateotp.service import Service
from ultimateotp.settings import Settings


class _TooLargeError(Exception):
    pass


class BodyLimit:
    """Refuses request bodies over `max_bytes` (declared or streamed) with 413."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self._app = app
        self._max = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length" and (not value.isdigit() or int(value) > self._max):
                await self._reject(scope, receive, send)
                return
        seen = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self._max:
                    raise _TooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracking_send)
        except _TooLargeError:
            if started:
                raise
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        response = errors.problem_response(413, "body_too_large", "", str(scope.get("path", "")))
        await response(scope, receive, send)


def build_limiter(settings: Settings, clock: Clock) -> RateLimiter:
    if not settings.ratelimit_enabled:
        return NoRateLimit()
    return TokenBucketLimiter(
        {
            "enroll": Limit(settings.enroll_rate_per_s, settings.enroll_burst),
            "auth_failure": Limit(settings.auth_failure_rate_per_s, settings.auth_failure_burst),
            "mint": Limit(settings.mint_rate_per_s, settings.mint_burst),
            "write": Limit(settings.write_rate_per_s, settings.write_burst),
            "srp": Limit(settings.srp_rate_per_s, settings.srp_burst),
            "email_ip": Limit(settings.email_ip_per_hour / 3600, settings.email_ip_burst),
            "email_address": Limit(
                settings.email_address_per_hour / 3600, settings.email_address_burst
            ),
        },
        clock,
    )


def create_app(
    settings: Settings,
    clock: Clock | None = None,
    limiter: RateLimiter | None = None,
    alerts: Alerts | None = None,
) -> ASGIApp:
    clock = clock or SystemClock()
    metrics = Metrics()
    broker = Broker()
    metrics.gauge("uotp_sse_streams", lambda: float(broker.count()))
    service = Service(
        Database(settings.database_file),
        settings,
        clock,
        broker,
        metrics,
        alerts or Alerts(settings),
    )

    app = FastAPI(
        title="UltimateOTP",
        version=__version__,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.service = service
    app.state.limiter = limiter or build_limiter(settings, clock)
    errors.install(app, metrics)
    app.include_router(router)
    app.include_router(probes)

    asgi: ASGIApp = BodyLimit(app, settings.max_body_bytes)
    asgi = AccessLog(asgi)
    asgi = ClientAddress(asgi, settings.proxy_networks)
    # Tests reach the FastAPI object (state, service) through this attribute.
    asgi.fastapi = app  # type: ignore[attr-defined]
    return asgi
