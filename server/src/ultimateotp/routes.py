# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""`/otp/v1` routes (contracts/openapi.yaml). Thin: the rules live in `service.py`."""

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from ultimateotp import API_VERSION, db
from ultimateotp.auth import (
    auth_failed,
    bearer,
    device_auth,
    enrollment_gate,
    rate_limit,
    service_of,
    signed_request,
)
from ultimateotp.errors import ApiError
from ultimateotp.events import Event
from ultimateotp.forwarded import from_networks
from ultimateotp.models import (
    ApproveRequest,
    CommitRequest,
    EnrollRequest,
    JoinRequest,
    PutKeysRequest,
    RotateRequest,
)
from ultimateotp.service import DeviceAuth, Service, SignedRequest
from ultimateotp.settings import Settings

router = APIRouter(prefix="/otp/v1")

Auth = Annotated[DeviceAuth, Depends(device_auth)]
Signed = Annotated[SignedRequest, Depends(signed_request)]
EnrollmentGate = Depends(enrollment_gate)


def _pending(request: Request, call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Runs an enrollment-surface call; signature and token failures are logged and counted."""
    try:
        return call()
    except ApiError as error:
        if error.status == 401:
            raise auth_failed(request, error) from None
        raise


@router.get("/server-info")
def server_info(request: Request) -> dict[str, Any]:
    return {"api_version": API_VERSION, "server_time": service_of(request).clock.now()}


# ---------------------------------------------------------------- enrollment


@router.post("/enroll", status_code=201, dependencies=[EnrollmentGate])
def enroll(request: Request, body: EnrollRequest, signed: Signed) -> dict[str, Any]:
    service = service_of(request)
    return _pending(request, lambda: service.enroll(bearer(request), body, signed))


@router.get("/recovery/keys", dependencies=[EnrollmentGate])
def recovery_keys(request: Request) -> dict[str, Any]:
    service = service_of(request)
    return _pending(request, lambda: service.recovery_keys(bearer(request)))


@router.post("/enrollment-tokens", status_code=201)
def create_enrollment_token(request: Request, auth: Auth) -> dict[str, Any]:
    rate_limit(request, "mint", auth.device_id)
    token, expires = service_of(request).create_token(auth.account_id, auth.device_id)
    return {"token": token, "expires_at": expires}


# ---------------------------------------------------------------- account and devices


@router.get("/account/keys")
def get_keys(request: Request, auth: Auth) -> dict[str, Any]:
    return service_of(request).get_keys(auth)


@router.put("/account/keys")
def put_keys(request: Request, auth: Auth, body: PutKeysRequest) -> dict[str, Any]:
    rate_limit(request, "write", auth.device_id)
    return service_of(request).put_keys(auth, body)


@router.get("/devices")
def list_devices(request: Request, auth: Auth) -> dict[str, Any]:
    return service_of(request).list_devices(auth)


@router.post("/devices/{device_id}/revoke")
def revoke_device(request: Request, auth: Auth, device_id: str) -> dict[str, Any]:
    return service_of(request).revoke_device(device_id, auth)


# ---------------------------------------------------------------- pairing


@router.post("/pairings", status_code=201)
def create_pairing(request: Request, auth: Auth) -> dict[str, Any]:
    rate_limit(request, "mint", auth.device_id)
    return service_of(request).create_pairing(auth)


@router.get("/pairings/{pairing_id}")
def get_pairing(request: Request, auth: Auth, pairing_id: str) -> dict[str, Any]:
    return service_of(request).get_pairing(auth, pairing_id)


@router.post("/pairings/{pairing_id}/join", dependencies=[EnrollmentGate])
def join_pairing(
    request: Request, pairing_id: str, body: JoinRequest, signed: Signed
) -> dict[str, Any]:
    service = service_of(request)
    return _pending(
        request, lambda: service.join_pairing(pairing_id, bearer(request), body, signed)
    )


@router.post("/pairings/{pairing_id}/approve")
def approve_pairing(
    request: Request, auth: Auth, pairing_id: str, body: ApproveRequest
) -> dict[str, Any]:
    return service_of(request).approve_pairing(auth, pairing_id, body)


@router.post("/pairings/{pairing_id}/reject")
def reject_pairing(request: Request, auth: Auth, pairing_id: str) -> dict[str, Any]:
    return service_of(request).reject_pairing(auth, pairing_id)


@router.get("/pairings/{pairing_id}/result", dependencies=[EnrollmentGate])
def pairing_result(request: Request, pairing_id: str, signed: Signed) -> dict[str, Any]:
    service = service_of(request)
    return _pending(request, lambda: service.pairing_result(pairing_id, bearer(request), signed))


# ---------------------------------------------------------------- vault


@router.get("/vault")
def get_vault(
    request: Request, auth: Auth, since: Annotated[int, Query(ge=0)] = 0
) -> dict[str, Any]:
    return service_of(request).get_vault(auth, since)


@router.post("/vault/commit")
def commit(request: Request, auth: Auth, body: CommitRequest) -> dict[str, Any]:
    rate_limit(request, "write", auth.device_id)
    return service_of(request).commit(auth, body)


@router.post("/vault/rotate")
def rotate(request: Request, auth: Auth, body: RotateRequest) -> dict[str, Any]:
    rate_limit(request, "write", auth.device_id)
    return service_of(request).rotate(auth, body)


# ---------------------------------------------------------------- live sync (docs/sync.md)


def _hello(state: dict[str, Any]) -> Event:
    return Event(
        "hello",
        {k: state[k] for k in ("version", "key_epoch", "devices_revision", "rotation_required")},
    )


async def _stream(service: Service, settings: Settings, auth: DeviceAuth) -> AsyncIterator[str]:
    sub = service.broker.subscribe(auth.account_id, auth.device_id)
    try:
        yield "retry: 5000\n\n"
        state = await run_in_threadpool(service.state, auth.account_id, auth.device_id)
        if state["revoked"]:
            yield Event("revoked", {"device_id": auth.device_id}).encode()
            return
        yield _hello(state).encode()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + settings.sse_max_age_s
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            try:
                async with asyncio.timeout(min(settings.sse_keepalive_s, remaining)):
                    event = await sub.queue.get()
            except TimeoutError:
                # Catch up with changes made outside this process (admin CLI) or dropped.
                fresh = await run_in_threadpool(service.state, auth.account_id, auth.device_id)
                if fresh["revoked"]:
                    yield Event("revoked", {"device_id": auth.device_id}).encode()
                    return
                if fresh["version"] > state["version"]:
                    yield Event(
                        "vault",
                        {
                            "version": fresh["version"],
                            "key_epoch": fresh["key_epoch"],
                            "signed_by": fresh["signed_by"],
                        },
                        event_id=str(fresh["version"]),
                    ).encode()
                if fresh["devices_revision"] != state["devices_revision"]:
                    yield Event("devices", {"devices_revision": fresh["devices_revision"]}).encode()
                state = fresh
                yield ": keepalive\n\n"
                continue
            if event.name == "vault":
                state = {**state, "version": event.data["version"]}
            elif event.name == "devices":
                state = {**state, "devices_revision": event.data["devices_revision"]}
            yield event.encode()
            if event.name == "revoked":
                return
    finally:
        service.broker.unsubscribe(sub)


@router.get("/events")
async def events(request: Request, auth: Auth) -> StreamingResponse:
    service = service_of(request)
    settings: Settings = request.app.state.settings
    if service.broker.count(auth.device_id) >= settings.sse_max_streams_per_device:
        raise ApiError(429, "rate_limited", "too many open streams", retry_after=5)
    service.event("sse.open", device_id=auth.device_id)
    return StreamingResponse(
        _stream(service, settings, auth),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------- probes


probes = APIRouter()


@probes.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@probes.get("/readyz", include_in_schema=False)
def readyz(request: Request) -> JSONResponse:
    settings: Settings = request.app.state.settings
    ready = False
    if settings.database_file.is_file():
        with (
            contextlib.suppress(Exception),
            contextlib.closing(db.connect(settings.database_file, read_only=True)) as conn,
        ):
            ready = not db.pending(conn, settings.migrations_dir)
    return JSONResponse(
        {"status": "ok" if ready else "unavailable"}, status_code=200 if ready else 503
    )


@probes.get("/metrics", include_in_schema=False)
def metrics(request: Request) -> PlainTextResponse:
    settings: Settings = request.app.state.settings
    if not from_networks(request.scope, settings.metrics_network_list):
        raise ApiError(403, "forbidden")
    return PlainTextResponse(service_of(request).metrics.render())
