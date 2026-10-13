# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Password login from anywhere (SRP-6a), lockout, decoys, scopes, password change, sessions,
sign-up and ntfy notifications (decisions 6-9). Email codes are in tests/test_email.py."""

import secrets
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.client import Device, Vault, unwrap_with_password
from tests.conftest import LAN_CLIENT, PASSWORD, PUBLIC_CLIENT, Bootstrapped, FakeClock, Server
from tests.fakes import NtfyInbox, ntfy_server
from ultimateotp import b64, cli
from ultimateotp.app import create_app
from ultimateotp.settings import Settings

EMAIL = "owner@example.org"


def _account(server: Server, client: TestClient, email: str = EMAIL) -> Bootstrapped:
    account_id, token, _ = server.service.create_account(email)
    vault = Vault(account_id=account_id)
    device = Device(client, "Phone A")
    recovery_key = secrets.token_bytes(32)
    assert device.enroll(token, vault.key_bundle(PASSWORD, recovery_key)).status_code == 201
    return Bootstrapped(account_id, device, vault, recovery_key)


@pytest.fixture
def owner(server: Server, lan: TestClient) -> Bootstrapped:
    return _account(server, lan)


# ---------------------------------------------------------------- settings


def test_refuses_to_start_without_smtp(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    enabled = make_settings(email_verification="enabled")
    with pytest.raises(SystemExit, match="UOTP_EMAIL_VERIFICATION=disabled"):
        create_app(enabled)
    monkeypatch.setenv("UOTP_DATA_DIR", str(enabled.data_dir))
    monkeypatch.setenv("UOTP_MIGRATIONS_DIR", str(enabled.migrations_dir))
    monkeypatch.delenv("UOTP_EMAIL_VERIFICATION", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["account-create", "--email", "a@example.org"])
    # Migrations never need SMTP.
    assert cli.main(["migrate"]) == 0
    assert make_settings(email_verification="disabled").email_enabled is False
    with pytest.raises(ValidationError):
        make_settings(ntfy_url="ftp://example.org/x")
    defaults = make_settings()
    assert defaults.enrollment_scope == "anywhere"
    assert defaults.pairing_scope == "lan"
    assert defaults.signup == "disabled"


# ---------------------------------------------------------------- SRP login


def test_password_login_registers_the_device(
    server: Server, owner: Bootstrapped, clock: FakeClock
) -> None:
    with server.client(PUBLIC_CLIENT) as internet:
        new = Device(internet, "Reinstalled phone")
        response = new.srp_login(EMAIL, PASSWORD)
        assert response.status_code == 201, response.text
        data = response.json()
        assert data["account_id"] == owner.account_id
        assert data["device"]["enrolled_via"] == "password"
        assert data["device"]["app_version"] == "1.0.0-test"
        # The released wrap opens with the password, on the client only.
        bundle = {**data["keys"]}
        assert unwrap_with_password(bundle, PASSWORD) == owner.vault.vault_key
        # The device signs from now on.
        assert new.get("/otp/v1/vault").status_code == 200
    assert server.service.metrics.value("uotp_events_total", "srp.success") == 1


def test_wrong_password_and_single_use_sessions(server: Server, owner: Bootstrapped) -> None:
    with server.client(PUBLIC_CLIENT) as internet:
        wrong = Device(internet).srp_login(EMAIL, "not the password")
        assert wrong.status_code == 401
        assert wrong.json()["code"] == "srp_failed"
        right = Device(internet).srp_login(EMAIL, PASSWORD, tamper=True)
        assert right.json()["code"] == "srp_failed"


def test_lockout_is_exponential(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(make_settings(srp_lockout_threshold=3, srp_lockout_base_s=60))
    with server.client() as lan:
        _account(server, lan)
        codes = [Device(lan).srp_login(EMAIL, "guess").status_code for _ in range(3)]
        assert codes == [401, 401, 401]
        locked = Device(lan).srp_login(EMAIL, PASSWORD)
        assert locked.status_code == 429
        assert locked.json()["code"] == "account_locked"
        assert 55 <= locked.json()["retry_after"] <= 60
        clock.advance(61)
        dev = Device(lan)
        dev.clock_offset = clock.offset
        assert dev.srp_login(EMAIL, "guess").status_code == 401
        again = Device(lan)
        again.clock_offset = clock.offset
        assert 115 <= again.srp_login(EMAIL, PASSWORD).json()["retry_after"] <= 120
        clock.advance(121)
        good = Device(lan)
        good.clock_offset = clock.offset
        assert good.srp_login(EMAIL, PASSWORD).status_code == 201
        # Success resets the counter.
        row = server.service.list_accounts()[0]
        assert row["srp"] is True
    assert server.service.metrics.value("uotp_events_total", "srp.lockout") == 2


def test_unknown_addresses_get_decoys(server: Server, owner: Bootstrapped, lan: TestClient) -> None:
    real = lan.post("/otp/v1/srp/attributes", json={"email": EMAIL}).json()
    ghost = lan.post("/otp/v1/srp/attributes", json={"email": "nobody@example.org"}).json()
    again = lan.post("/otp/v1/srp/attributes", json={"email": "NOBODY@example.org"}).json()
    assert ghost == again
    assert set(ghost) == set(real)
    assert ghost["srp_user_id"] != real["srp_user_id"]
    response = Device(lan).srp_login("nobody@example.org", PASSWORD)
    assert response.status_code == 401
    assert response.json()["code"] == "srp_failed"


def test_bad_srp_values_are_refused(server: Server, owner: Bootstrapped, lan: TestClient) -> None:
    zero = "A" * 683
    response = lan.post("/otp/v1/srp/session", json={"email": EMAIL, "srp_a": zero})
    assert response.status_code == 400
    bad_session = Device(lan).post(
        "/otp/v1/srp/verify",
        {
            "session_id": "srp_" + "A" * 22,
            "srp_m1": "A" * 43,
            "device": {"ed25519_public_key": "A" * 43, "x25519_public_key": "A" * 43, "label": "x"},
        },
    )
    assert bad_session.json()["code"] == "srp_failed"


def test_proof_of_possession_is_required(server: Server, owner: Bootstrapped) -> None:
    """A valid SRP proof alone cannot register someone else's key."""
    with server.client() as lan:
        thief = Device(lan)
        victim = Device(lan)
        original = thief.post

        def post_with_victim_key(target: str, payload: object = None, **kw: object) -> object:
            if isinstance(payload, dict) and "device" in payload:
                payload["device"]["ed25519_public_key"] = victim.ed25519
            return original(target, payload, **kw)  # type: ignore[arg-type]

        thief.post = post_with_victim_key  # type: ignore[method-assign]
        response = thief.srp_login(EMAIL, PASSWORD)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_signature"


# ---------------------------------------------------------------- scopes


def test_login_works_from_anywhere_but_pairing_stays_lan(
    server: Server, owner: Bootstrapped
) -> None:
    token, _ = server.service.create_token(owner.account_id)
    with server.client(PUBLIC_CLIENT) as internet:
        assert Device(internet).srp_login(EMAIL, PASSWORD).status_code == 201
        assert Device(internet).enroll(token).status_code == 403
        assert internet.post(f"/otp/v1/pairings/pair_{'A' * 22}/join", json={}).status_code == 403


def test_enrollment_scope_lan_closes_password_login(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(enrollment_scope="lan"))
    with server.client() as lan:
        _account(server, lan)
    with server.client(PUBLIC_CLIENT) as internet:
        response = internet.post("/otp/v1/srp/attributes", json={"email": EMAIL})
    assert response.status_code == 403


def test_srp_routes_are_rate_limited_per_client(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(ratelimit_enabled=True, srp_burst=3))
    with server.client() as client:
        codes = [
            client.post("/otp/v1/srp/attributes", json={"email": EMAIL}).status_code
            for _ in range(5)
        ]
    assert codes == [200, 200, 200, 429, 429]


# ---------------------------------------------------------------- password change


def test_password_change_replaces_the_srp_record(server: Server, owner: Bootstrapped) -> None:
    dev = owner.device
    new_bundle = owner.vault.key_bundle("new password", owner.recovery_key)
    response = dev.put("/otp/v1/account/keys", {"base_revision": 1, "key_epoch": 1, **new_bundle})
    assert response.status_code == 200
    with server.client() as lan:
        assert Device(lan).srp_login(EMAIL, PASSWORD).status_code == 401
        assert Device(lan).srp_login(EMAIL, "new password").status_code == 201
    # Paranoid mode: no password wrap, no password login (decoy attributes).
    only_recovery = {"recovery_wrap": new_bundle["recovery_wrap"]}
    dev.put("/otp/v1/account/keys", {"base_revision": 2, "key_epoch": 1, **only_recovery})
    with server.client() as lan:
        assert Device(lan).srp_login(EMAIL, "new password").status_code == 401


def test_bad_srp_records_are_refused(owner: Bootstrapped) -> None:
    bundle = owner.vault.key_bundle(PASSWORD, owner.recovery_key)
    bundle["srp"]["srp_verifier"] = "A" * 683
    response = owner.device.put(
        "/otp/v1/account/keys", {"base_revision": 1, "key_epoch": 1, **bundle}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- sessions (decision 9)


def test_sessions_list_and_revocation(server: Server, owner: Bootstrapped) -> None:
    with server.client(PUBLIC_CLIENT) as internet:
        other = Device(internet, "Tablet")
        assert other.srp_login(EMAIL, PASSWORD).status_code == 201
        other.get("/otp/v1/vault", extra_headers={"X-UOTP-App-Version": "1.2.3"})
    listing = owner.device.get(
        "/otp/v1/sessions", extra_headers={"X-UOTP-App-Version": "0.9.0"}
    ).json()["sessions"]
    by_id = {s["device_id"]: s for s in listing}
    mine, theirs = by_id[owner.device.device_id], by_id[other.device_id]
    assert mine["current"] is True
    assert mine["app_version"] == "0.9.0"
    # Never an address: the opaque daily client id (anon.py).
    assert mine["last_ip"].startswith("c_")
    assert LAN_CLIENT[0] not in mine["last_ip"]
    assert theirs["current"] is False
    assert theirs["label"] == "Tablet"
    assert theirs["app_version"] == "1.2.3"
    assert theirs["last_ip"].startswith("c_")
    assert theirs["last_ip"] != mine["last_ip"]
    # Any device revokes another from the list.
    assert owner.device.post(f"/otp/v1/devices/{other.device_id}/revoke").status_code == 200
    with server.client(PUBLIC_CLIENT) as internet:
        other.http = internet
        assert other.get("/otp/v1/vault").json()["code"] == "device_revoked"
    after = {s["device_id"]: s for s in owner.device.get("/otp/v1/sessions").json()["sessions"]}
    assert after[other.device_id]["revoked_at"] is not None


def test_bad_app_version_header_is_ignored(owner: Bootstrapped) -> None:
    owner.device.get("/otp/v1/vault", extra_headers={"X-UOTP-App-Version": "bad value"})
    mine = owner.device.get("/otp/v1/sessions").json()["sessions"][0]
    assert mine["app_version"] is None


# ---------------------------------------------------------------- sign-up (decision 8)


def test_signup_is_disabled_by_default(server: Server, lan: TestClient) -> None:
    dev = Device(lan)
    vault = Vault()
    payload = {
        "email": "new@example.org",
        "device": {
            "ed25519_public_key": dev.ed25519,
            "x25519_public_key": dev.x25519,
            "label": "x",
        },
        "keys": vault.key_bundle(PASSWORD, secrets.token_bytes(32)),
    }
    response = dev.post("/otp/v1/signup", payload)
    assert response.status_code == 403
    assert response.json()["code"] == "signup_disabled"


def test_signup_when_enabled(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(signup="enabled"))
    with server.client(PUBLIC_CLIENT) as internet:
        dev = Device(internet)
        vault = Vault()
        payload = {
            "email": "New@Example.org",
            "device": {
                "ed25519_public_key": dev.ed25519,
                "x25519_public_key": dev.x25519,
                "label": "First phone",
            },
            "keys": vault.key_bundle(PASSWORD, secrets.token_bytes(32)),
        }
        response = dev.post("/otp/v1/signup", payload)
        assert response.status_code == 201, response.text
        assert response.json()["device"]["enrolled_via"] == "signup"
        dup = Device(internet)
        payload["device"]["ed25519_public_key"] = dup.ed25519
        payload["device"]["x25519_public_key"] = dup.x25519
        assert dup.post("/otp/v1/signup", payload).json()["code"] == "email_taken"
        assert Device(internet).srp_login("new@example.org", PASSWORD).status_code == 201


# ---------------------------------------------------------------- ntfy notifications (decision 7)


@pytest.fixture
def ntfy() -> Iterator[tuple[NtfyInbox, str]]:
    with ntfy_server() as fake:
        yield fake


def test_ntfy_notifications(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    ntfy: tuple[NtfyInbox, str],
) -> None:
    inbox, url = ntfy
    server = make_server(
        make_settings(ntfy_url=url, ntfy_token="tk_faketokenfortests", srp_lockout_threshold=2)
    )
    with server.client() as lan:
        owner = _account(server, lan)
        token, _ = server.service.create_token(owner.account_id)
        lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
        other = Device(lan, "Laptop")
        assert other.srp_login(EMAIL, PASSWORD).status_code == 201
        owner.device.post(f"/otp/v1/devices/{other.device_id}/revoke")
        for _ in range(2):
            Device(lan).srp_login(EMAIL, "guess")
    assert server.service.alerts.flush()
    posts = inbox.wait(5)
    titles = inbox.titles()
    assert titles.count("UltimateOTP: new device signed in") == 2
    assert "UltimateOTP: recovery data fetched" in titles
    assert "UltimateOTP: device revoked" in titles
    assert "UltimateOTP: repeated failed logins" in titles
    for headers, body in posts:
        assert headers["Authorization"] == "Bearer tk_faketokenfortests"
        assert "uoe_" not in body
        assert b64.encode(owner.vault.vault_key) not in body
        assert token not in body
    assert any('"Laptop"' in body for _, body in posts)


def test_no_ntfy_without_url(server: Server, owner: Bootstrapped) -> None:
    assert server.service.alerts.ntfy_enabled is False
    assert server.service.alerts.flush()
