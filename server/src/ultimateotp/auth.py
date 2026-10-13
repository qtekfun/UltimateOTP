# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""FastAPI dependencies: device signatures, the LAN gate of the enrollment surface, rate limits."""

import logging

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


async def signed_request(request: Request) -> SignedRequest:
    headers = request.headers
    return SignedRequest(
        method=request.method,
        target=target_of(request),
        device=headers.get("x-uotp-device"),
        timestamp=headers.get("x-uotp-timestamp"),
        nonce=headers.get("x-uotp-nonce"),
        signature=headers.get("x-uotp-signature"),
        body=await request.body(),
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


def enrollment_gate(request: Request) -> None:
    """The enrollment surface: LAN-only unless `UOTP_ENROLLMENT_SCOPE=anywhere`, rate-limited
    per client either way (docs/decisions.md item 4)."""
    settings: Settings = request.app.state.settings
    if settings.enrollment_scope == "lan" and not from_networks(
        request.scope, settings.lan_network_list, settings.denied_network_list
    ):
        service_of(request).event(
            "enroll.denied_network",
            level=logging.WARNING,
            client_ip=client_key(request),
            path=request.url.path,
        )
        raise ApiError(403, "enrollment_network_denied", "enrollment is allowed from the LAN only")
    rate_limit(request, "enroll", client_key(request))
