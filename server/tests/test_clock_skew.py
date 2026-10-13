# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""A phone whose clock is off by more than 60 s must be able to log in: `stale_request` comes
before anything is consumed or counted, so the retry with a corrected clock succeeds."""

import secrets
import time
from collections.abc import Callable
from typing import Any

from tests.client import Device, Vault
from tests.conftest import LAN_CLIENT, PASSWORD, PUBLIC_CLIENT, Mail, Server
from tests.test_login import EMAIL, _account
from ultimateotp.settings import Settings

SKEW = 3600


def _count(server: Server, sql: str) -> Any:
    with server.service.db.read() as conn:
        return conn.execute(sql).fetchone()[0]


def test_stale_srp_verify_keeps_the_handshake_and_counts_nothing(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(srp_lockout_threshold=2, block_threshold=3))
    with server.client(LAN_CLIENT) as lan:
        _account(server, lan)
    with server.client(PUBLIC_CLIENT) as internet:
        for _ in range(6):  # more than the lockout and block thresholds
            phone = Device(internet, "Skewed phone")
            phone.clock_offset = SKEW
            stale = phone.srp_login(EMAIL, PASSWORD)
            assert stale.status_code == 401
            assert stale.json()["code"] == "stale_request"
            assert "server_time" in stale.json()
        # Nothing consumed against the account, nothing counted against the client.
        assert _count(server, "SELECT srp_failures FROM accounts WHERE email IS NOT NULL") == 0
        assert _count(server, "SELECT srp_locked_until IS NOT NULL FROM accounts") == 0
        assert _count(server, "SELECT COUNT(*) FROM client_blocks") == 0
        metrics = server.service.metrics
        assert metrics.value("uotp_events_total", "srp.failure") == 0
        assert metrics.value("uotp_events_total", "auth.failure") == 0
        assert metrics.value("uotp_logins_total", result="srp_failure") == 0
        assert metrics.value("uotp_blocks_total") == 0
        # The retry with the corrected clock succeeds, with the same handshake.
        phone = Device(internet, "Skewed phone")
        phone.clock_offset = SKEW
        ok = phone.srp_login(EMAIL, PASSWORD, retry_stale=True)
        assert ok.status_code == 201, ok.text
        assert phone.get("/otp/v1/vault").status_code == 200


def test_stale_verify_does_not_burn_the_session(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings())
    with server.client(LAN_CLIENT) as lan:
        _account(server, lan)
        phone = Device(lan, "Skewed phone")
        phone.clock_offset = SKEW
        assert phone.srp_login(EMAIL, PASSWORD).status_code == 401
        # The handshake is still there (it expires on its own).
        assert _count(server, "SELECT COUNT(*) FROM srp_sessions") == 1


def test_stale_signup_keeps_the_emailed_code(make_mail: Callable[..., Mail]) -> None:
    mail: Mail = make_mail(signup="enabled")
    with mail.server.client(PUBLIC_CLIENT) as client:
        client.post("/otp/v1/login/email-code", json={"email": EMAIL})
        mail.flush()
        code = mail.box.code_for(EMAIL)
        vault = Vault(account_id="")
        phone = Device(client, "Skewed phone")
        phone.clock_offset = SKEW
        body = {
            "email": EMAIL,
            "email_code": code,
            "device": {
                "ed25519_public_key": phone.ed25519,
                "x25519_public_key": phone.x25519,
                "label": "Skewed phone",
            },
            "keys": vault.key_bundle(PASSWORD, secrets.token_bytes(32)),
        }
        stale = phone.post("/otp/v1/signup", body)
        assert stale.status_code == 401
        assert stale.json()["code"] == "stale_request"
        phone.clock_offset = int(stale.json()["server_time"]) - int(time.time())
        ok = phone.post("/otp/v1/signup", body)
        assert ok.status_code == 201, ok.text
    assert mail.server.service.metrics.value("uotp_events_total", "email.code_failure") == 0


def test_stale_signed_request_is_not_an_auth_failure(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(block_threshold=3))
    account_id, token, _ = server.service.create_account()
    with server.client(LAN_CLIENT) as lan:
        dev = Device(lan, "Phone")
        keys = Vault(account_id=account_id).key_bundle("p", b"r" * 32)
        assert dev.enroll(token, keys).status_code == 201
    with server.client(PUBLIC_CLIENT) as client:
        dev.http = client
        dev.clock_offset = SKEW
        for _ in range(6):
            response = dev.get("/otp/v1/devices")
            assert response.status_code == 401
            assert response.json()["code"] == "stale_request"
        assert server.service.metrics.value("uotp_events_total", "auth.failure") == 0
        dev.clock_offset = 0
        assert dev.get("/otp/v1/devices").status_code == 200
