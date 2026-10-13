# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The server never receives, stores or logs plaintext secrets (design G2).

A whole lifecycle runs on real crypto-format v1 ciphertext: bootstrap with a password and a
recovery key, items with recognizable secrets, a second device through the password path, a third
through pairing, an edit, a delete, a revocation and a key rotation. Then every byte the server
received (bodies and headers), every byte of the SQLite files (database, WAL, shared memory) and
every log line are searched for the secrets in raw, hex, base64 and base64url form.
"""

import base64
import io
import logging
import secrets
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.client import Device, Vault, derive_kek, kdf, login_key, new_item_id, seal_for
from tests.conftest import PASSWORD, Server
from ultimateotp import b64, db, signing
from ultimateotp.logging import JsonFormatter, RedactingFilter

SECRETS = {
    "totp seed": b"JBSWY3DPEHPK3PXPZZQQ",
    "issuer": b"Plaintext-Canary-Bank",
    "account label": b"canary.user@example.org",
    "notes": b"recovery codes 1234-5678-canary",
}


class Recorder:
    """ASGI wrapper keeping every request body and header the server receives."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.received = bytearray()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            for name, value in scope.get("headers", []):
                self.received += name + b": " + value + b"\n"
            self.received += scope.get("raw_path", b"") + b"?" + scope.get("query_string", b"")

        async def recording_receive() -> Message:
            message = await receive()
            self.received += message.get("body", b"")
            return message

        await self.app(scope, recording_receive, send)


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    yield stream
    root.removeHandler(handler)
    root.setLevel(previous)


def _forms(value: bytes) -> list[bytes]:
    return [
        value,
        value.hex().encode(),
        base64.b64encode(value).rstrip(b"="),
        b64.encode(value).encode(),
    ]


def test_server_never_sees_plaintext(server: Server, log_output: io.StringIO) -> None:
    recorder = Recorder(server.asgi)
    recovery_key = secrets.token_bytes(32)
    with TestClient(recorder, client=("192.168.1.10", 50000)) as http:
        account_id, token, _ = server.service.create_account()
        vault = Vault(account_id=account_id)
        a = Device(http, "Phone A")
        assert a.enroll(token, vault.key_bundle(PASSWORD, recovery_key)).status_code == 201

        item = {
            "v": 1,
            "type": "totp",
            "secret": SECRETS["totp seed"].decode(),
            "issuer": SECRETS["issuer"].decode(),
            "label": SECRETS["account label"].decode(),
            "notes": SECRETS["notes"].decode(),
        }
        one, two = new_item_id(), new_item_id()
        assert a.commit(vault, {one: item, two: {**item, "issuer": "Other"}}).status_code == 200

        # Second device: token + password path.
        token_b, _ = server.service.create_token(account_id)
        assert (
            http.get(
                "/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token_b}"}
            ).status_code
            == 200
        )
        b = Device(http, "Phone B")
        assert b.enroll(token_b).status_code == 201

        # Third device: pairing.
        pairing = a.post("/otp/v1/pairings").json()
        c = Device(http, "Tablet C")
        joined = c.post(
            f"/otp/v1/pairings/{pairing['pairing_id']}/join",
            {"ed25519_public_key": c.ed25519, "x25519_public_key": c.x25519, "label": c.label},
            bearer=pairing["secret"],
        ).json()
        sealed = seal_for(c.x25519, vault.vault_key, account_id, 1)
        approve = {
            "device_id": joined["device_id"],
            "device_signature": a.sign(
                signing.device_message(account_id, joined["device_id"], c.ed25519, c.x25519)
            ),
            "sealed_vault_key": b64.encode(sealed),
            "seal_signature": a.sign(
                signing.seal_message(account_id, 1, joined["device_id"], sealed)
            ),
        }
        assert (
            a.post(f"/otp/v1/pairings/{pairing['pairing_id']}/approve", approve).status_code == 200
        )

        # Fourth device: password login from anywhere (SRP); the password never travels.
        server.service.set_email_check(account_id, enabled=False)
        with closing(db.connect(server.settings.database_file)) as conn:
            conn.execute(
                "UPDATE accounts SET email = 'canary@example.org' WHERE id = ?", (account_id,)
            )
        d = Device(http, "Laptop D")
        assert d.srp_login("canary@example.org", PASSWORD).status_code == 201

        # Edit, delete, revoke.
        assert a.commit(vault, {one: {**item, "digits": 8}}).status_code == 200
        assert a.commit(vault, deletes=[two]).status_code == 200
        assert a.post(f"/otp/v1/devices/{b.device_id}/revoke").status_code == 200

    db_bytes = b"".join(
        Path(str(server.settings.database_file) + suffix).read_bytes()
        for suffix in ("", "-wal", "-shm")
        if Path(str(server.settings.database_file) + suffix).exists()
    )
    # Positive controls: the scan does find what is there in plain text by design (device
    # labels, ids), so an absence below means something.
    assert b"Tablet C" in db_bytes
    assert b"Phone B" in bytes(recorder.received)
    assert account_id.encode() in db_bytes
    logs = log_output.getvalue().encode()
    assert b"vault.commit" in logs

    salt_free_kek = kdf(recovery_key, 1, "uotprcvy")
    needles = {
        **{name: _forms(value) for name, value in SECRETS.items()},
        "password": [PASSWORD.encode()],
        "vault key": _forms(vault.vault_key),
        "recovery key": _forms(recovery_key),
        "recovery KEK": _forms(salt_free_kek),
    }
    params = b64.decode(_password_kdf(server, account_id))
    kek_pw = derive_kek(PASSWORD, params)
    needles["password KEK"] = _forms(kek_pw)
    needles["SRP login subkey"] = _forms(login_key(kek_pw))

    for where, haystack in (
        ("received by the server", bytes(recorder.received)),
        ("stored in SQLite", db_bytes),
        ("logged", logs),
    ):
        for name, forms in needles.items():
            for form in forms:
                assert form not in haystack, f"{name} {where}"


def _password_kdf(server: Server, account_id: str) -> str:
    with closing(db.connect(server.settings.database_file)) as conn:
        row = conn.execute(
            "SELECT password_kdf FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
    return str(row["password_kdf"])
