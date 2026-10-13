# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Account management (contract 1.2.0): re-authentication, delete, change email, sign out
every other device, export. Local fake SMTP and ntfy only."""

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, Vault, new_item_id
from tests.conftest import PASSWORD, PUBLIC_CLIENT, Bootstrapped, FakeClock, Mail, second_device
from tests.fakes import NtfyInbox, ntfy_server
from tests.test_contract import check
from tests.test_email import EMAIL, _bootstrap
from tests.test_i18n import _text
from ultimateotp import b64, srp

NEW_EMAIL = "new.address@example.org"
ITEM = {"issuer": "Example", "secret_b32": "JBSWY3DPEHPK3PXP"}


@pytest.fixture
def ntfy() -> Iterator[tuple[NtfyInbox, str]]:
    with ntfy_server() as (inbox, url):
        yield inbox, url


@pytest.fixture
def world(
    make_mail: Callable[..., Mail], ntfy: tuple[NtfyInbox, str]
) -> Iterator[tuple[Mail, TestClient, Bootstrapped, NtfyInbox]]:
    inbox, url = ntfy
    mail = make_mail(ntfy_url=url)
    with mail.server.client() as lan:
        boot = _bootstrap(mail, lan)
        mail.box.messages.clear()
        yield mail, lan, boot, inbox


def _rows(mail: Mail, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    with closing(sqlite3.connect(mail.server.settings.database_file)) as conn:
        return conn.execute(sql, args).fetchall()


def _code(mail: Mail, address: str = EMAIL) -> str:
    mail.flush()
    return mail.box.code_for(address)


def _all_account_rows(mail: Mail, account_id: str) -> int:
    total = 0
    for table in (
        "accounts",
        "devices",
        "device_key_wraps",
        "items",
        "enrollment_tokens",
        "pairings",
        "vault_versions",
        "item_history",
        "email_changes",
        "srp_sessions",
    ):
        column = "id" if table == "accounts" else "account_id"
        total += _rows(mail, f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", account_id)[0][0]  # noqa: S608
    return total


# ---------------------------------------------------------------- re-authentication


def test_reauth_code_goes_to_the_account_address_only(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    response = boot.device.post("/otp/v1/account/reauth/email-code")
    assert response.status_code == 202
    check(response.json(), "Accepted")
    mail.flush()
    assert [m["To"] for m in mail.box.messages] == [EMAIL]
    assert "Confirm a sensitive action" in _text(mail.box.messages[0])
    assert "delete your account" in _text(mail.box.messages[0])


def test_reauth_routes_need_a_signature(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, _, _ = world
    for path, body in (
        ("/otp/v1/account/reauth/email-code", None),
        ("/otp/v1/account/reauth/srp", {"srp_a": "A" * 683}),
        ("/otp/v1/account/delete", {"reauth": {"email_code": "123456"}}),
        ("/otp/v1/account/email/change", {"new_email": NEW_EMAIL, "reauth": {"email_code": "1"}}),
        ("/otp/v1/account/email/confirm", {"code": "123456"}),
        ("/otp/v1/devices/revoke-others", None),
    ):
        response = lan.post(path, json=body)
        assert response.status_code == 401, path
    assert lan.get("/otp/v1/account/export").status_code == 401
    mail.flush()
    assert mail.box.messages == []


# ---------------------------------------------------------------- delete


def test_delete_with_an_emailed_code_removes_everything(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, inbox = world
    a, vault = boot.device, boot.vault
    b = second_device(mail.server, lan, boot)
    keep, gone = new_item_id(), new_item_id()
    a.commit(vault, {keep: ITEM, gone: ITEM})
    a.commit(vault, {keep: {**ITEM, "n": 2}}, deletes=[gone])
    a.post("/otp/v1/pairings")
    a.post("/otp/v1/enrollment-tokens")
    assert _all_account_rows(mail, boot.account_id) > 8
    a.post("/otp/v1/account/reauth/email-code")
    code = _code(mail)

    response = a.post("/otp/v1/account/delete", {"reauth": {"email_code": code}})
    assert response.status_code == 200, response.text
    body = response.json()
    check(body, "AccountDeleted")
    assert body["status"] == "deleted"
    assert body["account_id"] == boot.account_id
    assert body["removed"] == {"devices": 2, "items": 2, "history_versions": 2, "history_items": 2}
    # Gone for good: every row, for every device.
    assert _all_account_rows(mail, boot.account_id) == 0
    for dev in (a, b):
        refused = dev.get("/otp/v1/vault")
        assert refused.status_code == 401
        assert refused.json()["code"] == "invalid_signature"
    assert _rows(mail, "SELECT COUNT(*) FROM email_codes WHERE email = ?", EMAIL) == [(0,)]
    assert _rows(mail, "SELECT COUNT(*) FROM request_nonces WHERE signer = ?", a.device_id) == [
        (0,)
    ]
    # No login either: the address is unknown again.
    assert Device(lan).srp_login(EMAIL, PASSWORD).status_code in (401, 429)
    # The owner was told, by email and ntfy; no secret in either.
    mail.flush()
    assert mail.server.service.alerts.flush()
    notice = next(m for m in mail.box.messages if "deleted" in _text(m))
    assert notice["To"] == EMAIL
    assert code not in _text(notice)
    assert any("account deleted" in title.lower() for title in inbox.titles())
    assert mail.server.service.metrics.value("uotp_events_total", "account.deleted") == 1


def test_delete_with_the_password_proof(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    a.commit(boot.vault, {new_item_id(): ITEM})
    start, proof = a.reauth_srp(PASSWORD)
    assert start.status_code == 200
    check(start.json(), "ReauthSrpSession")
    response = a.post("/otp/v1/account/delete", {"reauth": {"srp": proof}})
    assert response.status_code == 200, response.text
    assert response.json()["removed"]["items"] == 1
    assert _all_account_rows(mail, boot.account_id) == 0


def test_wrong_code_wrong_password_and_missing_proof_delete_nothing(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    before = _all_account_rows(mail, boot.account_id)
    # A stolen unlocked device with no proof: refused before anything happens.
    none = a.post("/otp/v1/account/delete", {"reauth": {}})
    assert none.status_code == 400
    both = a.post(
        "/otp/v1/account/delete",
        {
            "reauth": {
                "email_code": "123456",
                "srp": {"session_id": "srp_" + "A" * 22, "srp_m1": "A" * 43},
            }
        },
    )
    assert both.status_code == 400
    assert a.post("/otp/v1/account/delete", {}).status_code == 400
    extra = a.post("/otp/v1/account/delete", {"reauth": {"email_code": "123456"}, "force": True})
    assert extra.status_code == 400
    # A code that was never requested.
    wrong = a.post("/otp/v1/account/delete", {"reauth": {"email_code": "000000"}})
    assert wrong.status_code == 401
    assert wrong.json()["code"] == "invalid_email_code"
    # A wrong password proof.
    _, bad = a.reauth_srp(PASSWORD, tamper=True)
    refused = a.post("/otp/v1/account/delete", {"reauth": {"srp": bad}})
    assert refused.status_code == 401
    assert refused.json()["code"] == "srp_failed"
    # Not a valid handshake at all.
    ghost = a.post(
        "/otp/v1/account/delete",
        {"reauth": {"srp": {"session_id": "srp_" + "B" * 22, "srp_m1": "A" * 43}}},
    )
    assert ghost.status_code == 401
    assert _all_account_rows(mail, boot.account_id) == before


def test_email_code_for_delete_is_single_use_and_limited_to_five_tries(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    a.post("/otp/v1/account/reauth/email-code")
    code = _code(mail)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert (
            a.post("/otp/v1/account/delete", {"reauth": {"email_code": wrong}}).status_code == 401
        )
    # The right code no longer works after 5 wrong tries.
    dead = a.post("/otp/v1/account/delete", {"reauth": {"email_code": code}})
    assert dead.status_code == 401
    assert _all_account_rows(mail, boot.account_id) > 0
    # A fresh one works, once.
    a.post("/otp/v1/account/reauth/email-code")
    fresh = _code(mail)
    assert a.post("/otp/v1/account/delete", {"reauth": {"email_code": fresh}}).status_code == 200


def test_reauth_srp_session_is_single_use_and_bound_to_the_account(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, _ = world
    a = boot.device
    _, proof = a.reauth_srp(PASSWORD)
    # Another account's device cannot spend it.
    other_id, token, _ = mail.server.service.create_account("other@example.org")
    mail.flush()
    other = Device(lan, "Other")
    keys = Vault(account_id=other_id).key_bundle("other password", b"x" * 32)
    payload = {
        "ed25519_public_key": other.ed25519,
        "x25519_public_key": other.x25519,
        "label": "Other",
        "keys": keys,
        "email_code": mail.box.code_for("other@example.org"),
    }
    response = other.post("/otp/v1/enroll", payload, bearer=token)
    assert response.status_code == 201, response.text
    other.device_id = response.json()["device"]["device_id"]
    stolen = other.post("/otp/v1/account/delete", {"reauth": {"srp": proof}})
    assert stolen.status_code == 401
    # It was consumed by that attempt (single use), even for its owner.
    again = a.post("/otp/v1/account/delete", {"reauth": {"srp": proof}})
    assert again.status_code == 401
    assert _all_account_rows(mail, boot.account_id) > 0
    # And the same proof is useless as a login handshake.
    start, fresh = a.reauth_srp(PASSWORD)
    assert start.status_code == 200
    assert fresh is not None
    login = lan.post(
        "/otp/v1/srp/verify",
        json={
            "session_id": fresh["session_id"],
            "srp_m1": fresh["srp_m1"],
            "device": {
                "ed25519_public_key": other.ed25519,
                "x25519_public_key": other.x25519,
                "label": "x",
            },
        },
    )
    assert login.status_code in (400, 401)


def test_reauth_srp_expires(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox], clock: FakeClock
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    _, proof = a.reauth_srp(PASSWORD)
    clock.advance(mail.server.settings.srp_session_ttl_s + 5)
    a.clock_offset = clock.offset
    late = a.post("/otp/v1/account/delete", {"reauth": {"srp": proof}})
    assert late.status_code == 401
    assert _all_account_rows(mail, boot.account_id) > 0


def test_wrong_proofs_count_toward_the_account_lockout(
    make_mail: Callable[..., Mail],
) -> None:
    mail = make_mail(srp_lockout_threshold=3, srp_lockout_base_s=60)
    with mail.server.client() as lan:
        boot = _bootstrap(mail, lan)
        a = boot.device
        for _ in range(3):
            _, bad = a.reauth_srp(PASSWORD, tamper=True)
            assert a.post("/otp/v1/account/delete", {"reauth": {"srp": bad}}).status_code == 401
        locked, none = a.reauth_srp(PASSWORD)
        assert locked.status_code == 429
        assert locked.json()["code"] == "account_locked"
        assert none is None
        # The emailed code is still a way in for the owner while the password path is locked.
        a.post("/otp/v1/account/reauth/email-code")
        code = _code(mail)
        assert a.post("/otp/v1/account/delete", {"reauth": {"email_code": code}}).status_code == 200


def test_no_password_record_means_srp_unavailable(
    make_mail: Callable[..., Mail],
) -> None:
    mail = make_mail()
    with mail.server.client() as lan:
        account_id, token, _ = mail.server.service.create_account(EMAIL)
        mail.flush()
        vault = Vault(account_id=account_id)
        dev = Device(lan)
        keys = vault.key_bundle(PASSWORD, b"r" * 32, with_srp=False)
        keys.pop("password_wrap")
        keys.pop("password_kdf")
        payload = {
            "ed25519_public_key": dev.ed25519,
            "x25519_public_key": dev.x25519,
            "label": "d",
            "keys": keys,
            "email_code": mail.box.code_for(EMAIL),
        }
        response = dev.post("/otp/v1/enroll", payload, bearer=token)
        assert response.status_code == 201, response.text
        dev.device_id = response.json()["device"]["device_id"]
        big_a = b64.encode(
            srp.GROUP_4096.pad(srp.client_public(srp.GROUP_4096, srp.new_ephemeral()))
        )
        refused = dev.post("/otp/v1/account/reauth/srp", {"srp_a": big_a})
        assert refused.status_code == 409
        assert refused.json()["code"] == "srp_unavailable"
        # An invalid public value is refused as a bad request.
        zero = dev.post("/otp/v1/account/reauth/srp", {"srp_a": "A" * 683})
        assert zero.status_code == 400


def test_reauth_actions_are_rate_limited(make_mail: Callable[..., Mail]) -> None:
    mail = make_mail(ratelimit_enabled=True, account_action_burst=3, account_action_per_hour=0.5)
    with mail.server.client() as lan:
        boot = _bootstrap(mail, lan)
        codes = [
            boot.device.post("/otp/v1/account/reauth/email-code").status_code for _ in range(5)
        ]
        assert codes[:3] == [202, 202, 202]
        assert codes[3:] == [429, 429]
        limited = boot.device.post("/otp/v1/account/delete", {"reauth": {"email_code": "000000"}})
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) > 0


# ---------------------------------------------------------------- change email


def _request_change(a: Device, mail: Mail, new: str = NEW_EMAIL, **extra: Any) -> Any:
    a.post("/otp/v1/account/reauth/email-code")
    code = _code(mail)
    response = a.post(
        "/otp/v1/account/email/change",
        {"new_email": new, "reauth": {"email_code": code}, **extra},
    )
    mail.flush()
    return response


def test_change_email_code_to_the_new_address_then_switch(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, inbox = world
    a = boot.device
    response = _request_change(a, mail)
    assert response.status_code == 202, response.text
    check(response.json(), "EmailChangePending")
    mail.flush()
    to_new = [m for m in mail.box.messages if m["To"] == NEW_EMAIL]
    to_old = [m for m in mail.box.messages if m["To"] == EMAIL and "change" in _text(m).lower()]
    assert len(to_new) == 1
    assert "Confirm your new email address" in _text(to_new[0])
    # The old address is warned at once, with the address it would change to.
    assert any(NEW_EMAIL in _text(m) for m in to_old)
    # Nothing changed yet.
    assert _rows(mail, "SELECT email FROM accounts") == [(EMAIL,)]
    code = mail.box.code_for(NEW_EMAIL)

    confirmed = a.post("/otp/v1/account/email/confirm", {"code": code})
    assert confirmed.status_code == 200, confirmed.text
    check(confirmed.json(), "AccountEmail")
    assert confirmed.json()["email"] == NEW_EMAIL
    assert _rows(mail, "SELECT email, email_verified_at IS NOT NULL FROM accounts") == [
        (NEW_EMAIL, 1)
    ]
    assert _rows(mail, "SELECT COUNT(*) FROM email_changes") == [(0,)]
    mail.flush()
    notices = {m["To"]: _text(m) for m in mail.box.messages if "address" in _text(m).lower()}
    assert NEW_EMAIL in notices[EMAIL]  # "your email address was changed"
    assert "signs in to your account" in notices[NEW_EMAIL]
    assert any("email" in title.lower() for title in inbox.titles())
    # Login now works with the new address and codes go there.
    with mail.server.client(PUBLIC_CLIENT) as internet:
        internet.post("/otp/v1/login/email-code", json={"email": NEW_EMAIL})
        mail.flush()
        login_code = mail.box.code_for(NEW_EMAIL)
        newdev = Device(internet, "Laptop")
        assert newdev.srp_login(NEW_EMAIL, PASSWORD, login_code).status_code == 201
        # The old address is just an unknown one now: no code is sent to it.
        count = len(mail.box.messages)
        internet.post("/otp/v1/login/email-code", json={"email": EMAIL})
        mail.flush()
        assert len(mail.box.messages) == count


def test_the_code_is_single_use_and_limited_to_five_tries(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    assert _request_change(a, mail).status_code == 202
    code = mail.box.code_for(NEW_EMAIL)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        refused = a.post("/otp/v1/account/email/confirm", {"code": wrong})
        assert refused.status_code == 401
        assert refused.json()["code"] == "invalid_email_code"
    dead = a.post("/otp/v1/account/email/confirm", {"code": code})
    assert dead.status_code == 401
    assert _rows(mail, "SELECT email FROM accounts") == [(EMAIL,)]
    # A new request replaces the pending change and resets the tries.
    assert _request_change(a, mail).status_code == 202
    fresh = mail.box.code_for(NEW_EMAIL)
    assert a.post("/otp/v1/account/email/confirm", {"code": fresh}).status_code == 200
    assert a.post("/otp/v1/account/email/confirm", {"code": fresh}).status_code == 401


def test_code_expires(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox], clock: FakeClock
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    assert _request_change(a, mail).status_code == 202
    code = mail.box.code_for(NEW_EMAIL)
    clock.advance(mail.server.settings.email_code_ttl_s + 5)
    a.clock_offset = clock.offset
    assert a.post("/otp/v1/account/email/confirm", {"code": code}).status_code == 401
    assert _rows(mail, "SELECT email FROM accounts") == [(EMAIL,)]


def test_confirm_with_nothing_pending_and_without_proof(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    a = boot.device
    assert a.post("/otp/v1/account/email/confirm", {"code": "123456"}).status_code == 401
    # A stolen device cannot even start a change without the proof.
    missing = a.post("/otp/v1/account/email/change", {"new_email": NEW_EMAIL, "reauth": {}})
    assert missing.status_code == 400
    wrong = a.post(
        "/otp/v1/account/email/change",
        {"new_email": NEW_EMAIL, "reauth": {"email_code": "000000"}},
    )
    assert wrong.status_code == 401
    bad = a.post(
        "/otp/v1/account/email/change",
        {"new_email": "not-an-address", "reauth": {"email_code": "1"}},
    )
    assert bad.status_code == 400
    mail.flush()
    assert not [m for m in mail.box.messages if m["To"] == NEW_EMAIL]
    assert _rows(mail, "SELECT COUNT(*) FROM email_changes") == [(0,)]


def test_taken_address_looks_the_same_and_sends_nothing(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    mail.server.service.create_account("taken@example.org")
    mail.flush()
    mail.box.messages.clear()
    response = _request_change(boot.device, mail, "taken@example.org")
    assert response.status_code == 202
    assert response.json()["status"] == "pending"
    mail.flush()
    assert not [m for m in mail.box.messages if m["To"] == "taken@example.org"]
    # No way to confirm anything: it is indistinguishable from a wrong code.
    refused = boot.device.post("/otp/v1/account/email/confirm", {"code": "123456"})
    assert refused.status_code == 401
    assert _rows(mail, "SELECT email FROM accounts WHERE email = 'taken@example.org'") == [
        ("taken@example.org",)
    ]
    # The same address as now is a silent no-op too.
    same = _request_change(boot.device, mail, EMAIL)
    assert same.status_code == 202


def test_race_for_an_address_is_resolved_by_the_database(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, _, boot, _ = world
    assert _request_change(boot.device, mail).status_code == 202
    code = mail.box.code_for(NEW_EMAIL)
    # Somebody else takes the address between the request and the confirmation.
    mail.server.service.create_account(NEW_EMAIL)
    refused = boot.device.post("/otp/v1/account/email/confirm", {"code": code})
    assert refused.status_code == 409
    assert refused.json()["code"] == "email_taken"
    assert _rows(mail, "SELECT email FROM accounts WHERE id = ?", boot.account_id) == [(EMAIL,)]


# ---------------------------------------------------------------- sign out every other device


def test_revoke_others_keeps_only_the_caller(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, inbox = world
    a = boot.device
    b = second_device(mail.server, lan, boot)
    c = second_device(mail.server, lan, boot)
    a.get("/otp/v1/devices", extra_headers={"Accept-Language": "es"})
    response = a.post("/otp/v1/devices/revoke-others")
    assert response.status_code == 200, response.text
    body = response.json()
    check(body, "RevokeOthersResult")
    assert sorted(body["revoked"]) == sorted([b.device_id, c.device_id])
    assert body["rotation_required"] is True
    for other in (b, c):
        assert other.get("/otp/v1/vault").json()["code"] == "device_revoked"
    assert a.get("/otp/v1/vault").status_code == 200
    head = a.get("/otp/v1/vault").json()["head"]
    assert head["rotation_required"] is True
    assert head["devices_revision"] == body["devices_revision"]
    devices = {d["device_id"]: d for d in a.get("/otp/v1/devices").json()["devices"]}
    assert devices[a.device_id]["revoked_at"] is None
    assert devices[b.device_id]["revoked_at"] is not None
    # Idempotent: nobody left to sign out.
    again = a.post("/otp/v1/devices/revoke-others")
    assert again.status_code == 200
    assert again.json()["revoked"] == []
    # Audited, notified in the account's language, and ntfy.
    mail.flush()
    assert mail.server.service.alerts.flush()
    notice = next(m for m in mail.box.messages if "dispositivos" in _text(m))
    assert "2 dispositivo(s)" in _text(notice)
    assert any("signed out" in title for title in inbox.titles())
    assert mail.server.service.metrics.value("uotp_events_total", "devices.revoked_others") == 1


def test_revoke_others_only_touches_the_own_account(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, _ = world
    other_id, token, _ = mail.server.service.create_account()
    stranger = Device(lan, "Stranger")
    stranger.enroll(token, Vault(account_id=other_id).key_bundle("x", b"y" * 32))
    assert stranger.post("/otp/v1/devices/revoke-others").json()["revoked"] == []
    assert boot.device.get("/otp/v1/vault").status_code == 200


# ---------------------------------------------------------------- export


def test_export_has_everything_and_nothing_secret(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, inbox = world
    a, vault = boot.device, boot.vault
    b = second_device(mail.server, lan, boot)
    keep, gone = new_item_id(), new_item_id()
    a.commit(vault, {keep: ITEM, gone: ITEM})
    a.commit(vault, {keep: {**ITEM, "n": 2}}, deletes=[gone])
    a.post("/otp/v1/enrollment-tokens")
    response = a.get("/otp/v1/account/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    doc = response.json()
    check(doc, "AccountExport")
    assert doc["format"] == "ultimateotp-server-export-1"
    assert doc["account"] == {
        "account_id": boot.account_id,
        "email": EMAIL,
        "created_at": doc["account"]["created_at"],
    }
    assert doc["head"]["version"] == 2
    assert {i["item_id"]: i["deleted"] for i in doc["items"]} == {keep: False, gone: True}
    assert {d["device_id"] for d in doc["devices"]} == {a.device_id, b.device_id}
    assert doc["keys"]["password_wrap"]
    assert doc["keys"]["recovery_wrap"]
    assert [v["version"] for v in doc["history"]["versions"]] == [2, 1]
    assert {r["reason"] for r in doc["history"]["items"]} == {"replaced", "deleted"}
    # The client can use it offline: decrypt the live item and the trashed one.
    live = next(i for i in doc["items"] if i["item_id"] == keep)
    assert vault.decrypt_item(keep, b64.decode(live["blob"]), live["version"])["n"] == 2
    trashed = next(r for r in doc["history"]["items"] if r["reason"] == "deleted")
    assert vault.decrypt_item(gone, b64.decode(trashed["blob"]), trashed["version"]) == ITEM
    # Never: the SRP verifier, enrollment tokens, nonces.
    text = response.text
    srp_row = _rows(mail, "SELECT srp_verifier, srp_salt FROM accounts")[0]
    assert srp_row[0] not in text
    assert "srp_verifier" not in text
    assert "uoe_" not in text
    assert "token_hash" not in text
    json.loads(text)
    # Audited and notified.
    mail.flush()
    assert mail.server.service.alerts.flush()
    assert any("exported" in _text(m) for m in mail.box.messages)
    assert any("exported" in title for title in inbox.titles())
    assert mail.server.service.metrics.value("uotp_events_total", "account.exported") == 1


def test_export_is_rate_limited_per_device(make_mail: Callable[..., Mail]) -> None:
    mail = make_mail(ratelimit_enabled=True, export_burst=2, export_per_hour=0.1)
    with mail.server.client() as lan:
        boot = _bootstrap(mail, lan)
        codes = [boot.device.get("/otp/v1/account/export").status_code for _ in range(4)]
        assert codes == [200, 200, 429, 429]


def test_export_of_one_account_never_contains_another(
    world: tuple[Mail, TestClient, Bootstrapped, NtfyInbox],
) -> None:
    mail, lan, boot, _ = world
    other_id, token, _ = mail.server.service.create_account()
    stranger = Device(lan, "Stranger")
    vault = Vault(account_id=other_id)
    stranger.enroll(token, vault.key_bundle("x", b"y" * 32))
    secret_item = new_item_id()
    stranger.commit(vault, {secret_item: {"issuer": "Theirs"}})
    doc = boot.device.get("/otp/v1/account/export").json()
    assert secret_item not in json.dumps(doc)
    assert other_id not in json.dumps(doc)
