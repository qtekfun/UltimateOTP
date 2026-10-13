# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""FastAPI dependencies: device signatures, the LAN gate of the enrollment surface, rate limits."""

import logging
import re

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from ultimateotp.errors import ApiError
from ultimateotp.forwarded import client_host, from_networks
from ultimateotp.ratelimit import RateLimiter
from ultimateotp.service import DeviceAuth, Service, SignedRequest
from ultimateotp.settings import Settings


def service_of(request: Request) -> Service:
    service: Service = request.app.state.service
    return service


def limiter_of(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.limiter
    return limiter


def client_key(request: Request) -> str:
    return client_host(request.scope) or "unknown"


def rate_limit(request: Request, bucket: str, key: str) -> None:
    retry = limiter_of(request).hit(bucket, key)
    if retry is not None:
        service_of(request).event(
            "ratelimit.hit", level=logging.WARNING, bucket=bucket, client_ip=client_key(request)
        )
        raise ApiError(429, "rate_limited", retry_after=max(1, int(retry + 0.999)))


def target_of(request: Request) -> str:
    """The request target as the client sent it: raw path plus `?query`."""
    raw = request.scope.get("raw_path") or request.scope["path"].encode()
    target = raw.decode("latin-1")
    query = request.scope.get("query_string", b"")
    return f"{target}?{query.decode('latin-1')}" if query else target


_APP_VERSION = re.compile(r"^[\x21-\x7e]{1,64}$")


async def signed_request(request: Request) -> SignedRequest:
    headers = request.headers
    app_version = headers.get("x-uotp-app-version")
    return SignedRequest(
        method=request.method,
        target=target_of(request),
        device=headers.get("x-uotp-device"),
        timestamp=headers.get("x-uotp-timestamp"),
        nonce=headers.get("x-uotp-nonce"),
        signature=headers.get("x-uotp-signature"),
        body=await request.body(),
        client_ip=client_host(request.scope),
        app_version=app_version if app_version and _APP_VERSION.match(app_version) else None,
    )


def auth_failed(request: Request, error: ApiError) -> ApiError:
    """Logs the failure and turns it into 429 when this client fails too often."""
    service_of(request).event(
        "auth.failure",
        level=logging.WARNING,
        reason=error.code,
        client_ip=client_key(request),
        path=request.url.path,
    )
    retry = limiter_of(request).hit("auth_failure", client_key(request))
    if retry is not None:
        return ApiError(429, "rate_limited", retry_after=max(1, int(retry + 0.999)))
    return error


async def device_auth(request: Request) -> DeviceAuth:
    """A registered device's signed request (contract: "Authentication")."""
    signed = await signed_request(request)
    try:
        return await run_in_threadpool(service_of(request).authenticate, signed)
    except ApiError as error:
        raise auth_failed(request, error) from None


def bearer(request: Request) -> str | None:
    value = request.headers.get("authorization", "")
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def _scope_gate(request: Request, scope: str, setting: str) -> None:
    settings: Settings = request.app.state.settings
    if scope == "lan" and not from_networks(
        request.scope, settings.lan_network_list, settings.denied_network_list
    ):
        service_of(request).event(
            "enroll.denied_network",
            level=logging.WARNING,
            client_ip=client_key(request),
            path=request.url.path,
            setting=setting,
        )
        raise ApiError(403, "enrollment_network_denied", "this route is allowed from the LAN only")


def pairing_gate(request: Request) -> None:
    """Enrollment tokens and pairing: LAN-only unless `UOTP_PAIRING_SCOPE=anywhere`
    (decision 6), rate-limited per client either way."""
    settings: Settings = request.app.state.settings
    _scope_gate(request, settings.pairing_scope, "UOTP_PAIRING_SCOPE")
    rate_limit(request, "enroll", client_key(request))


def login_gate(request: Request) -> None:
    """Password login (email code + SRP) and sign-up: anywhere by default
    (`UOTP_ENROLLMENT_SCOPE`, decision 6), strict per-client limits."""
    settings: Settings = request.app.state.settings
    _scope_gate(request, settings.enrollment_scope, "UOTP_ENROLLMENT_SCOPE")
    rate_limit(request, "srp", client_key(request))
