# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Emailed one-time codes and notices (decision 13) through a local fake relay that, like
smtp.resend.com:587, requires STARTTLS before AUTH. Nothing is ever sent to Resend."""

import secrets
import sqlite3
from collections.abc import Callable
from contextlib import closing

from fastapi.testclient import TestClient

from tests.client import Device, Vault
from tests.conftest import PASSWORD, PUBLIC_CLIENT, Bootstrapped, FakeClock, Mail
from tests.fakes import SMTP_PASSWORD, SMTP_USER, Mailbox, free_port
from ultimateotp import b64
from ultimateotp.settings import Settings

EMAIL = "owner@example.org"


def _bootstrap(mail: Mail, client: TestClient) -> Bootstrapped:
    account_id, token, _ = mail.server.service.create_account(EMAIL)
    mail.flush()
    code = mail.box.code_for(EMAIL)
    vault = Vault(account_id=account_id)
    device = Device(client, "Phone A")
    recovery_key = secrets.token_bytes(32)
    keys = vault.key_bundle(PASSWORD, recovery_key)
    payload = {
        "ed25519_public_key": device.ed25519,
        "x25519_public_key": device.x25519,
        "label": device.label,
        "keys": keys,
        "email_code": code,
    }
    response = device.post("/otp/v1/enroll", payload, bearer=token)
    assert response.status_code == 201, response.text
    device.device_id = response.json()["device"]["device_id"]
    return Bootstrapped(account_id, device, vault, recovery_key)


def _request_code(client: TestClient, email: str = EMAIL) -> int:
    return client.post("/otp/v1/login/email-code", json={"email": email}).status_code


def test_account_creation_verifies_the_email_once(mail: Mail) -> None:
    with mail.server.client() as lan:
        account_id, token, _ = mail.server.service.create_account(EMAIL)
        mail.flush()
        assert mail.box.wait(1)[0]["To"] == EMAIL
        dev = Device(lan)
        keys = Vault(account_id=account_id).key_bundle(PASSWORD, secrets.token_bytes(32))
        without = dev.enroll(token, keys)
        assert without.status_code == 401
        assert without.json()["code"] == "invalid_email_code"
        # The same token and the mailed code finish the bootstrap and verify the address.
        payload = {
            "ed25519_public_key": dev.ed25519,
            "x25519_public_key": dev.x25519,
            "label": dev.label,
            "keys": keys,
            "email_code": mail.box.code_for(EMAIL),
        }
        assert dev.post("/otp/v1/enroll", payload, bearer=token).status_code == 201
    # STARTTLS was negotiated before AUTH with the Resend-style credentials.
    assert mail.box.logins == [(SMTP_USER, SMTP_PASSWORD)]
    with closing(sqlite3.connect(mail.server.settings.database_file)) as conn:
        assert conn.execute("SELECT email_verified_at FROM accounts").fetchone()[0] is not None


def test_login_needs_the_emailed_code_then_srp(mail: Mail) -> None:
    with mail.server.client() as lan:
        _bootstrap(mail, lan)
    before = len(mail.box.messages)
    with mail.server.client(PUBLIC_CLIENT) as internet:
        attributes = internet.post("/otp/v1/srp/attributes", json={"email": EMAIL}).json()
        assert attributes["email_code_required"] is True
        no_code = Device(internet).srp_login(EMAIL, PASSWORD)
        assert no_code.status_code == 401
        assert no_code.json()["code"] == "invalid_email_code"
        assert _request_code(internet) == 202
        mail.flush()
        mail.box.wait(before + 1)
        code = mail.box.code_for(EMAIL)
        assert Device(internet).srp_login(EMAIL, PASSWORD, code).status_code == 201
        reused = Device(internet).srp_login(EMAIL, PASSWORD, code)
        assert reused.json()["code"] == "invalid_email_code"


def test_code_dies_after_five_wrong_tries(mail: Mail) -> None:
    with mail.server.client() as lan:
        _bootstrap(mail, lan)
        _request_code(lan)
        mail.flush()
        code = mail.box.code_for(EMAIL)
        wrong = f"{(int(code) + 1) % 1_000_000:06d}"
        for _ in range(5):
            assert Device(lan).srp_login(EMAIL, PASSWORD, wrong).status_code == 401
        assert Device(lan).srp_login(EMAIL, PASSWORD, code).status_code == 401


def test_code_expires(mail: Mail, clock: FakeClock) -> None:
    with mail.server.client() as lan:
        _bootstrap(mail, lan)
        _request_code(lan)
        mail.flush()
        code = mail.box.code_for(EMAIL)
        clock.advance(601)
        dev = Device(lan)
        dev.clock_offset = clock.offset
        assert dev.srp_login(EMAIL, PASSWORD, code).json()["code"] == "invalid_email_code"


def test_email_check_can_be_turned_off_per_account(mail: Mail) -> None:
    with mail.server.client() as lan:
        owner = _bootstrap(mail, lan)
        mail.server.service.set_email_check(owner.account_id, enabled=False)
        attributes = lan.post("/otp/v1/srp/attributes", json={"email": EMAIL}).json()
        assert attributes["email_code_required"] is False
        assert Device(lan).srp_login(EMAIL, PASSWORD).status_code == 201


def test_unknown_addresses_get_no_mail(mail: Mail) -> None:
    with mail.server.client() as lan:
        _bootstrap(mail, lan)
        before = len(mail.box.messages)
        assert _request_code(lan, "stranger@example.org") == 202
        mail.flush()
        assert len(mail.box.messages) == before


def test_codes_are_stored_salted_and_hashed(mail: Mail) -> None:
    with mail.server.client() as lan:
        _bootstrap(mail, lan)
        _request_code(lan)
    mail.flush()
    code = mail.box.code_for(EMAIL)
    with closing(sqlite3.connect(mail.server.settings.database_file)) as conn:
        row = conn.execute("SELECT salt, code_hash FROM email_codes").fetchone()
    assert code not in row[0] + row[1]
    assert len(row[0]) == 32
    assert len(row[1]) == 64


def test_send_limits_per_address_and_per_client(make_mail: Callable[..., Mail]) -> None:
    mail = make_mail(ratelimit_enabled=True, email_address_burst=2, email_ip_burst=3)
    with mail.server.client() as lan:
        codes = [_request_code(lan, "a@example.org") for _ in range(3)]
        assert codes == [202, 202, 429]
        assert _request_code(lan, "b@example.org") == 429  # the client's own budget is spent
    with mail.server.client(PUBLIC_CLIENT) as other:
        assert _request_code(other, "b@example.org") == 202


def test_recovery_and_rotation_send_email_notices(mail: Mail) -> None:
    from tests.test_revocation import _rotation  # noqa: PLC0415

    with mail.server.client() as lan:
        owner = _bootstrap(mail, lan)
        token, _ = mail.server.service.create_token(owner.account_id)
        lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
        owner.device.commit(owner.vault, {"00000000-0000-4000-8000-000000000001": {"x": 1}})
        payload = _rotation(owner, [owner.device], owner.vault, secrets.token_bytes(32))
        assert owner.device.post("/otp/v1/vault/rotate", payload).status_code == 200
    mail.flush()
    subjects = [m["Subject"] for m in mail.box.messages]
    assert "UltimateOTP: recovery data fetched" in subjects
    assert "UltimateOTP: vault key rotated" in subjects
    # No secrets in any email: no token, no vault key, no password.
    for message in mail.box.messages:
        body = message.get_payload(decode=True).decode()
        assert "uoe_" not in body
        assert b64.encode(owner.vault.vault_key) not in body
        assert PASSWORD not in body


def test_no_starttls_no_credentials(make_settings: Callable[..., Settings]) -> None:
    """A relay that does not offer STARTTLS gets neither the API key nor the message."""
    from aiosmtpd.controller import Controller  # noqa: PLC0415

    from ultimateotp.alerts import Alerts  # noqa: PLC0415

    box = Mailbox()
    port = free_port()
    controller = Controller(
        box,
        hostname="127.0.0.1",
        port=port,
        authenticator=box.authenticate,
        auth_require_tls=False,
    )
    controller.start()
    try:
        settings = make_settings(
            email_verification="enabled",
            smtp_host="127.0.0.1",
            smtp_port=port,
            smtp_from="otp@example.org",
            smtp_password=SMTP_PASSWORD,
        )
        alerts = Alerts(settings)
        alerts.email(EMAIL, "subject", "body")
        assert alerts.flush()
    finally:
        controller.stop()
    assert box.messages == []
    assert box.logins == []
