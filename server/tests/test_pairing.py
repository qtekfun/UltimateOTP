# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Device-to-device pairing (design §3.4): the server only relays keys and signed seals."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from nacl.public import SealedBox

from tests.client import Device, new_item_id, seal_for
from tests.conftest import PUBLIC_CLIENT, Bootstrapped, FakeClock, Server
from ultimateotp import b64, signing


def _open(a: Device) -> dict[str, Any]:
    response = a.post("/otp/v1/pairings")
    assert response.status_code == 201
    return dict(response.json())


def _join(b: Device, pairing: dict[str, Any]) -> Any:
    return b.post(
        f"/otp/v1/pairings/{pairing['pairing_id']}/join",
        {"ed25519_public_key": b.ed25519, "x25519_public_key": b.x25519, "label": b.label},
        bearer=pairing["secret"],
    )


def _approval(boot: Bootstrapped, device_id: str, pending: dict[str, Any]) -> dict[str, str]:
    a = boot.device
    sealed = seal_for(pending["x25519_public_key"], boot.vault.vault_key)
    cert = signing.device_message(
        boot.account_id, device_id, pending["ed25519_public_key"], pending["x25519_public_key"]
    )
    seal = signing.seal_message(boot.account_id, 1, device_id, sealed)
    return {
        "device_id": device_id,
        "device_signature": a.sign(cert),
        "sealed_vault_key": b64.encode(sealed),
        "seal_signature": a.sign(seal),
    }


def test_full_pairing_flow(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    a = bootstrapped.device
    a.commit(bootstrapped.vault, {new_item_id(): {"issuer": "Example"}})
    pairing = _open(a)
    pid = pairing["pairing_id"]
    assert a.get(f"/otp/v1/pairings/{pid}").json()["status"] == "open"

    b = Device(lan, "Phone B")
    joined = _join(b, pairing)
    assert joined.status_code == 200
    device_id = joined.json()["device_id"]

    # A sees B's keys and would show the SAS here.
    seen = a.get(f"/otp/v1/pairings/{pid}").json()
    assert seen["status"] == "joined"
    assert seen["device"]["ed25519_public_key"] == b.ed25519

    waiting = b.get(f"/otp/v1/pairings/{pid}/result", bearer=pairing["secret"], device=device_id)
    assert waiting.json()["status"] == "joined"
    assert waiting.json()["device_key"] is None

    approved = a.post(
        f"/otp/v1/pairings/{pid}/approve", _approval(bootstrapped, device_id, seen["device"])
    )
    assert approved.status_code == 200
    assert approved.json()["enrolled_via"] == "pairing"
    assert approved.json()["added_by"] == a.device_id

    result = b.get(f"/otp/v1/pairings/{pid}/result", bearer=pairing["secret"], device=device_id)
    data = result.json()
    assert data["status"] == "approved"
    assert data["approver"]["ed25519_public_key"] == a.ed25519
    # B checks both signatures with the approver key (QR fingerprint) and opens the box.
    sealed = b64.decode(data["device_key"]["sealed_vault_key"])
    assert signing.verify(
        a.ed25519,
        signing.seal_message(data["account_id"], 1, device_id, sealed),
        data["device_key"]["seal_signature"],
    )
    assert SealedBox(b.box_key).decrypt(sealed) == bootstrapped.vault.vault_key

    b.device_id = device_id
    assert b.get("/otp/v1/vault").status_code == 200
    keys = b.get("/otp/v1/account/keys").json()
    assert keys["device_key"]["sealed_by"] == a.device_id


def test_join_needs_the_secret_and_proof(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    pairing = _open(bootstrapped.device)
    b = Device(lan)
    wrong = {**pairing, "secret": "uop_" + "A" * 43}
    assert _join(b, wrong).json()["code"] == "invalid_token"
    impostor = Device(lan)
    payload = {"ed25519_public_key": b.ed25519, "x25519_public_key": b.x25519, "label": "x"}
    response = impostor.post(
        f"/otp/v1/pairings/{pairing['pairing_id']}/join", payload, bearer=pairing["secret"]
    )
    assert response.json()["code"] == "invalid_signature"


def test_join_only_once(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    pairing = _open(bootstrapped.device)
    assert _join(Device(lan), pairing).status_code == 200
    second = _join(Device(lan), pairing)
    assert second.status_code == 409
    assert second.json()["code"] == "pairing_state"


def test_join_from_outside_the_lan_is_denied(server: Server, bootstrapped: Bootstrapped) -> None:
    pairing = _open(bootstrapped.device)
    with server.client(PUBLIC_CLIENT) as client:
        response = _join(Device(client), pairing)
    assert response.status_code == 403


def test_result_needs_the_joined_key(lan: TestClient, bootstrapped: Bootstrapped) -> None:
    pairing = _open(bootstrapped.device)
    device_id = _join(Device(lan), pairing).json()["device_id"]
    other = Device(lan)
    response = other.get(
        f"/otp/v1/pairings/{pairing['pairing_id']}/result",
        bearer=pairing["secret"],
        device=device_id,
    )
    assert response.status_code == 401


@pytest.mark.parametrize("bad", ["device_signature", "seal_signature"])
def test_approval_signatures_are_verified(
    lan: TestClient, bootstrapped: Bootstrapped, bad: str
) -> None:
    a = bootstrapped.device
    pairing = _open(a)
    b = Device(lan)
    device_id = _join(b, pairing).json()["device_id"]
    pending = a.get(f"/otp/v1/pairings/{pairing['pairing_id']}").json()["device"]
    approval = _approval(bootstrapped, device_id, pending)
    approval[bad] = b.sign(b"something else")
    response = a.post(f"/otp/v1/pairings/{pairing['pairing_id']}/approve", approval)
    assert response.status_code == 400
    assert response.json()["code"] == f"invalid_{bad}"


def test_only_the_creator_sees_and_decides(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    from tests.conftest import second_device  # noqa: PLC0415

    other = second_device(server, lan, bootstrapped)
    pairing = _open(bootstrapped.device)
    assert other.get(f"/otp/v1/pairings/{pairing['pairing_id']}").status_code == 404
    assert other.post(f"/otp/v1/pairings/{pairing['pairing_id']}/reject").status_code == 404


def test_reject_and_expiry(lan: TestClient, bootstrapped: Bootstrapped, clock: FakeClock) -> None:
    a = bootstrapped.device
    pairing = _open(a)
    rejected = a.post(f"/otp/v1/pairings/{pairing['pairing_id']}/reject")
    assert rejected.json()["status"] == "rejected"
    assert _join(Device(lan), pairing).status_code == 409

    late = _open(a)
    clock.advance(601)
    joiner = Device(lan)
    joiner.clock_offset = clock.offset
    response = _join(joiner, late)
    assert response.status_code == 410
    assert response.json()["code"] == "pairing_expired"
