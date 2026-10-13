# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ed25519 request signatures, the timestamp window and nonce replay protection."""

import json
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from tests.client import Device
from tests.conftest import Bootstrapped, FakeClock, Server
from ultimateotp import b64, signing
from ultimateotp.settings import Settings


def _code(response: object) -> str:
    return str(response.json()["code"])  # type: ignore[attr-defined]


def test_signed_request_is_accepted(bootstrapped: Bootstrapped) -> None:
    response = bootstrapped.device.get("/otp/v1/devices")
    assert response.status_code == 200
    assert response.json()["devices"][0]["device_id"] == bootstrapped.device.device_id


def test_missing_headers_are_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    response = lan.get("/otp/v1/devices")
    assert response.status_code == 401
    assert _code(response) == "invalid_signature"
    assert response.headers["content-type"] == "application/problem+json"


def test_signature_by_another_key_is_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    impostor = Device(lan)
    impostor.device_id = bootstrapped.device.device_id
    response = impostor.get("/otp/v1/devices")
    assert response.status_code == 401
    assert _code(response) == "invalid_signature"


def test_unknown_device_is_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    stranger = Device(lan)
    stranger.device_id = "dev_" + "A" * 22
    assert _code(stranger.get("/otp/v1/devices")) == "invalid_signature"


def test_tampered_body_is_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    dev = bootstrapped.device
    signed_body = json.dumps({"base_version": 0}).encode()
    headers = dev.headers("POST", "/otp/v1/vault/commit", signed_body)
    sent = json.dumps({"base_version": 7}).encode()
    response = lan.post(
        "/otp/v1/vault/commit",
        content=sent,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert _code(response) == "invalid_signature"


def test_signature_is_bound_to_path_and_query(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    dev = bootstrapped.device
    headers = dev.headers("GET", "/otp/v1/vault?since=0", b"")
    response = lan.get("/otp/v1/vault?since=5", headers=headers)
    assert _code(response) == "invalid_signature"
    headers = dev.headers("GET", "/otp/v1/devices", b"")
    assert _code(lan.get("/otp/v1/account/keys", headers=headers)) == "invalid_signature"


def test_signature_is_bound_to_method(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    headers = bootstrapped.device.headers("GET", "/otp/v1/pairings", b"")
    assert _code(lan.post("/otp/v1/pairings", headers=headers)) == "invalid_signature"


def test_replayed_request_is_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    headers = bootstrapped.device.headers("GET", "/otp/v1/devices", b"")
    assert lan.get("/otp/v1/devices", headers=headers).status_code == 200
    replay = lan.get("/otp/v1/devices", headers=headers)
    assert replay.status_code == 401
    assert _code(replay) == "replayed_request"


def test_replayed_write_is_refused_and_has_no_effect(
    lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    body = b""
    headers = bootstrapped.device.headers("POST", "/otp/v1/pairings", body)
    assert lan.post("/otp/v1/pairings", headers=headers).status_code == 201
    assert _code(lan.post("/otp/v1/pairings", headers=headers)) == "replayed_request"


@pytest.mark.parametrize("skew", [-61, 61, 3600])
def test_stale_timestamp_is_refused(lan: TestClient, bootstrapped: Bootstrapped, skew: int) -> None:
    response = bootstrapped.device.get("/otp/v1/devices", timestamp=int(time.time()) + skew)
    assert response.status_code == 401
    assert _code(response) == "stale_request"
    assert abs(response.json()["server_time"] - time.time()) < 5


def test_old_request_cannot_be_replayed_after_the_window(
    lan: TestClient, bootstrapped: Bootstrapped, clock: FakeClock
) -> None:
    """Nonces are forgotten after the window, but by then the timestamp is stale too."""
    headers = bootstrapped.device.headers("GET", "/otp/v1/devices", b"")
    assert lan.get("/otp/v1/devices", headers=headers).status_code == 200
    clock.advance(3 * 60)
    response = lan.get("/otp/v1/devices", headers=headers)
    assert _code(response) == "stale_request"


@pytest.mark.parametrize("nonce", ["short", "", "AAAAAAAAAAAAAAAAAAAAAA==", "A" * 50])
def test_bad_nonce_is_refused(lan: TestClient, bootstrapped: Bootstrapped, nonce: str) -> None:
    headers = bootstrapped.device.headers("GET", "/otp/v1/devices", b"", nonce=nonce or "x")
    if not nonce:
        headers["X-UOTP-Nonce"] = ""
    assert lan.get("/otp/v1/devices", headers=headers).status_code == 401


def test_malformed_timestamp_is_refused(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    headers = bootstrapped.device.headers("GET", "/otp/v1/devices", b"")
    headers["X-UOTP-Timestamp"] = "-5"
    assert _code(lan.get("/otp/v1/devices", headers=headers)) == "invalid_signature"


def test_same_nonce_from_two_devices_is_fine(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    from tests.conftest import second_device  # noqa: PLC0415

    other = second_device(server, lan, bootstrapped)
    nonce = b64.encode(b"\x01" * 16)
    assert bootstrapped.device.get("/otp/v1/devices", nonce=nonce).status_code == 200
    assert other.get("/otp/v1/devices", nonce=nonce).status_code == 200


def test_auth_failures_are_rate_limited(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(ratelimit_enabled=True, auth_failure_burst=3))
    with server.client() as client:
        codes = [client.get("/otp/v1/devices").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3:] == [429, 429]
    assert server.service.metrics.value("uotp_events_total", "auth.failure") == 5


def test_canonical_request_layout() -> None:
    """The exact bytes clients must sign (contract, "Authentication")."""
    message = signing.request_message(
        "post", "/otp/v1/x?a=1", "dev_1", "1700000000", "bm9uY2U", b""
    )
    assert message == (
        b"UOTP-REQ-v1\nPOST\n/otp/v1/x?a=1\ndev_1\n1700000000\nbm9uY2U\n"
        b"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    )


@pytest.mark.parametrize("text", ["AA==", "A", "AB", "a+b/", "ab c"])
def test_base64url_is_strict(text: str) -> None:
    with pytest.raises(b64.InvalidBase64Error):
        b64.decode(text)


def test_base64url_round_trip() -> None:
    for size in range(10):
        data = bytes(range(size))
        assert b64.decode(b64.encode(data)) == data
