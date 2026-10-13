# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""RFC 9457 problem responses with the stable `code` of the contract (`Problem`)."""

import json
import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from ultimateotp.metrics import Metrics

PROBLEM_TYPE_BASE = "https://ultimateotp.invalid/problems/"
PROBLEM_MEDIA_TYPE = "application/problem+json"

log = logging.getLogger(__name__)

_TITLES = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    409: "Conflict",
    410: "Gone",
    413: "Request body too large",
    429: "Too many requests",
    500: "Internal error",
}


class ApiError(Exception):
    """An error answered as a problem document."""

    def __init__(self, status: int, code: str, detail: str = "", **extra: Any) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail
        self.extra = extra


def problem_response(
    status: int, code: str, detail: str = "", instance: str = "", **extra: Any
) -> Response:
    body: dict[str, Any] = {
        "type": PROBLEM_TYPE_BASE + code,
        "title": _TITLES.get(status, "Error"),
        "status": status,
        "code": code,
    }
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    body.update(extra)
    headers: dict[str, str] = {}
    if "retry_after" in extra:
        headers["Retry-After"] = str(extra["retry_after"])
    return Response(
        json.dumps(body, ensure_ascii=False),
        status_code=status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


def install(app: FastAPI, metrics: Metrics) -> None:
    def respond(
        request: Request, status: int, code: str, detail: str = "", **extra: Any
    ) -> Response:
        metrics.inc("uotp_problems_total", code)
        return problem_response(status, code, detail, request.url.path, **extra)

    async def handle(request: Request, exc: Exception) -> Response:
        if isinstance(exc, ApiError):
            return respond(request, exc.status, exc.code, exc.detail, **exc.extra)
        if isinstance(exc, RequestValidationError):
            # Field locations only: never echo the refused input (it may be a key or a blob).
            fields = sorted({".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()})
            return respond(request, 400, "invalid_request", "invalid: " + ", ".join(fields)[:500])
        if isinstance(exc, StarletteHTTPException):
            code = "not_found" if exc.status_code == HTTPStatus.NOT_FOUND else "invalid_request"
            return respond(request, exc.status_code, code)
        log.error("unhandled error on %s", request.url.path, exc_info=exc)
        return respond(request, 500, "internal_error")

    for kind in (ApiError, RequestValidationError, StarletteHTTPException, Exception):
        app.add_exception_handler(kind, handle)
