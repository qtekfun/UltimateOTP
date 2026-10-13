# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Structured logs without secrets."""

import io
import json
import logging

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Bootstrapped
from ultimateotp.logging import (
    FIELDS_ATTR,
    REDACTED,
    JsonFormatter,
    RedactingFilter,
    redact,
)

TOKEN = "uoe_" + "x" * 43
SIG = "A" * 86


@pytest.mark.parametrize(
    "text",
    [
        f"token {TOKEN}",
        "Authorization: Bearer abc.def",
        f"x-uotp-signature: {SIG}",
        "blob=" + "Q" * 60,
    ],
)
def test_redact(text: str) -> None:
    assert REDACTED in redact(text)
    assert TOKEN not in redact(text)
    assert SIG not in redact(text)
    assert "abc.def" not in redact(text)


def test_ids_stay_readable() -> None:
    text = "device dev_AAAAAAAAAAAAAAAAAAAAAA of acc_BBBBBBBBBBBBBBBBBBBBBB"
    assert redact(text) == text


def _format(record: logging.LogRecord) -> dict[str, object]:
    RedactingFilter().filter(record)
    result: dict[str, object] = json.loads(JsonFormatter().format(record))
    return result


def test_secret_named_fields_are_redacted() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg %s", (TOKEN,), None)
    setattr(record, FIELDS_ATTR, {"event": "x", "token": "abc", "blob": "zzz", "device_id": "d"})
    entry = _format(record)
    assert entry["message"] == f"msg {REDACTED}"
    assert entry["token"] == REDACTED
    assert entry["blob"] == REDACTED
    assert entry["device_id"] == "d"


def test_requests_and_security_events_are_logged_without_secrets(
    lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        bootstrapped.device.get("/otp/v1/devices")
        lan.get("/otp/v1/devices", headers={"Authorization": f"Bearer {TOKEN}"})
        lan.get(
            f"/otp/v1/recovery/keys?token={TOKEN}", headers={"Authorization": f"Bearer {TOKEN}"}
        )
    finally:
        root.removeHandler(handler)
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    events = [line.get("event") for line in lines]
    assert "http.request" in events
    assert "auth.failure" in events
    access = next(line for line in lines if line.get("event") == "http.request")
    # Never the address: the anonymized id (anon.py).
    assert "client_ip" not in access
    assert str(access["client_id"]).startswith("c_")
    assert "192.168.1.10" not in stream.getvalue()
    assert "?" not in str(access["path"])
    assert TOKEN not in stream.getvalue()
