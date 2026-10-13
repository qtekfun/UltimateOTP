# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Revocation and key rotation (design §3.6)."""

import secrets
from typing import Any

from fastapi.testclient import TestClient
from nacl.public import SealedBox

from tests.client import Device, Vault, new_item_id, seal_for
from tests.conftest import PASSWORD, Bootstrapped, Server, second_device
from ultimateotp import b64, signing

ITEM = {"issuer": "Example", "secret_b32": "JBSWY3DPEHPK3PXP"}


def test_revoked_device_is_locked_out(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a = bootstrapped.device
    b = second_device(server, lan, bootstrapped)
    response = a.post(f"/otp/v1/devices/{b.device_id}/revoke")
    assert response.status_code == 200
    assert response.json()["revoked_at"] is not None
    refused = b.get("/otp/v1/vault")
    assert refused.status_code == 401
    assert refused.json()["code"] == "device_revoked"
    head = a.get("/otp/v1/vault").json()["head"]
    assert head["rotation_required"] is True
    devices = a.get("/otp/v1/devices").json()
    assert devices["devices_revision"] == 3
    # Revoked devices stay listed, so old head signatures can still be checked.
    assert {d["device_id"] for d in devices["devices"]} == {a.device_id, b.device_id}
    # Idempotent.
    assert a.post(f"/otp/v1/devices/{b.device_id}/revoke").status_code == 200


def test_device_can_revoke_itself(bootstrapped: Bootstrapped) -> None:
    dev = bootstrapped.device
    assert dev.post(f"/otp/v1/devices/{dev.device_id}/revoke").status_code == 200
    assert dev.get("/otp/v1/devices").json()["code"] == "device_revoked"


def test_cannot_revoke_another_accounts_device(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    account_id, token, _ = server.service.create_account()
    stranger = Device(lan)
    stranger.enroll(token, Vault(account_id=account_id).key_bundle("x", secrets.token_bytes(32)))
    response = stranger.post(f"/otp/v1/devices/{bootstrapped.device.device_id}/revoke")
    assert response.status_code == 404
    assert bootstrapped.device.get("/otp/v1/devices").status_code == 200


def test_admin_cli_revocation(server: Server, lan: TestClient, bootstrapped: Bootstrapped) -> None:
    b = second_device(server, lan, bootstrapped)
    assert b.device_id is not None
    server.service.revoke_device(b.device_id, None)
    assert b.get("/otp/v1/vault").json()["code"] == "device_revoked"


def _rotation(
    boot: Bootstrapped, devices: list[Device], vault: Vault, new_key: bytes
) -> dict[str, Any]:
    """Re-encrypts every live item under a new vault key and seals it to `devices`."""
    a = boot.device
    rotated = Vault(account_id=vault.account_id, vault_key=new_key, key_epoch=2)
    new_version = vault.version + 1
    upserts, live = [], {}
    for item_id, item in vault.plaintext.items():
        blob = rotated.encrypt_item(item_id, item, new_version)
        live[item_id] = (new_version, blob)
        upserts.append({"item_id": item_id, "blob": b64.encode(blob)})
    device_keys = []
    for dev in devices:
        assert dev.device_id is not None
        sealed = seal_for(dev.x25519, new_key)
        device_keys.append(
            {
                "device_id": dev.device_id,
                "sealed_vault_key": b64.encode(sealed),
                "seal_signature": a.sign(
                    signing.seal_message(vault.account_id, 2, dev.device_id, sealed)
                ),
            }
        )
    return {
        "base_version": vault.version,
        "new_key_epoch": 2,
        "head": {
            "version": new_version,
            "signature": a.head_signature(rotated, new_version, 2, live),
        },
        "upserts": upserts,
        "deletes": [],
        "keys": rotated.key_bundle(PASSWORD, secrets.token_bytes(32)),
        "device_keys": device_keys,
    }


def test_rotation_after_revocation(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    b = second_device(server, lan, bootstrapped)
    c = second_device(server, lan, bootstrapped)
    a.commit(vault, {new_item_id(): ITEM, new_item_id(): ITEM})
    a.post(f"/otp/v1/devices/{c.device_id}/revoke")
    new_key = secrets.token_bytes(32)

    payload = _rotation(bootstrapped, [a, b], vault, new_key)
    response = a.post("/otp/v1/vault/rotate", payload)
    assert response.status_code == 200, response.text
    head = response.json()
    assert head["key_epoch"] == 2
    assert head["rotation_required"] is False
    assert head["version"] == 2

    keys_b = b.get("/otp/v1/account/keys").json()
    assert keys_b["key_epoch"] == 2
    sealed = b64.decode(keys_b["device_key"]["sealed_vault_key"])
    assert SealedBox(b.box_key).decrypt(sealed) == new_key
    items = b.get("/otp/v1/vault?since=0").json()["items"]
    fresh = Vault(account_id=vault.account_id, vault_key=new_key, key_epoch=2)
    assert all(
        fresh.decrypt_item(i["item_id"], b64.decode(i["blob"]), i["version"]) == ITEM for i in items
    )
    # Old-epoch commits are refused from now on.
    assert a.commit(vault, {new_item_id(): ITEM}).json()["code"] in {
        "version_conflict",
        "key_epoch_conflict",
    }


def test_rotation_must_cover_every_active_device(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    second_device(server, lan, bootstrapped)
    a.commit(vault, {new_item_id(): ITEM})
    payload = _rotation(bootstrapped, [a], vault, secrets.token_bytes(32))
    response = a.post("/otp/v1/vault/rotate", payload)
    assert response.json()["code"] == "incomplete_rotation"


def test_rotation_must_reencrypt_every_item(bootstrapped: Bootstrapped) -> None:
    """A correctly signed head that leaves one item under the old key is still refused."""
    a, vault = bootstrapped.device, bootstrapped.vault
    kept, moved = new_item_id(), new_item_id()
    a.commit(vault, {kept: ITEM, moved: ITEM})
    new_key = secrets.token_bytes(32)
    payload = _rotation(bootstrapped, [a], vault, new_key)
    payload["upserts"] = [u for u in payload["upserts"] if u["item_id"] == moved]
    rotated = Vault(account_id=vault.account_id, vault_key=new_key, key_epoch=2)
    live = {kept: vault.blobs[kept], moved: (2, b64.decode(payload["upserts"][0]["blob"]))}
    payload["head"]["signature"] = a.head_signature(rotated, 2, 2, live)
    response = a.post("/otp/v1/vault/rotate", payload)
    assert response.status_code == 400
    assert response.json()["code"] == "incomplete_rotation"


def test_rotation_seals_must_be_signed(bootstrapped: Bootstrapped) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    a.commit(vault, {new_item_id(): ITEM})
    payload = _rotation(bootstrapped, [a], vault, secrets.token_bytes(32))
    payload["device_keys"][0]["seal_signature"] = a.sign(b"nope")
    assert a.post("/otp/v1/vault/rotate", payload).json()["code"] == "invalid_seal_signature"


def test_rotation_epoch_must_be_next(bootstrapped: Bootstrapped) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    a.commit(vault, {new_item_id(): ITEM})
    payload = _rotation(bootstrapped, [a], vault, secrets.token_bytes(32))
    payload["new_key_epoch"] = 3
    assert a.post("/otp/v1/vault/rotate", payload).json()["code"] == "key_epoch_conflict"
