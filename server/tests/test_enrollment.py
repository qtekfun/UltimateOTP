# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Account bootstrap, enrollment tokens, the password path, and the LAN-only default."""

import secrets
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, Vault, unwrap_with_password
from tests.conftest import LAN_CLIENT, PASSWORD, PUBLIC_CLIENT, Bootstrapped, FakeClock, Server
from ultimateotp.settings import Settings

TRAEFIK = "10.213.49.2"
CLOUDFLARED = "172.31.0.250"


def _bundle(account_id: str) -> dict[str, str]:
    return Vault(account_id=account_id).key_bundle(PASSWORD, secrets.token_bytes(32))


# ---------------------------------------------------------------- bootstrap and tokens


def test_bootstrap_creates_device_and_stores_opaque_keys(server: Server, lan: TestClient) -> None:
    account_id, token, _ = server.service.create_account()
    keys = _bundle(account_id)
    dev = Device(lan, "Pixel")
    response = dev.enroll(token, keys)
    assert response.status_code == 201
    body = response.json()
    assert body["account_id"] == account_id
    assert body["device"]["enrolled_via"] == "bootstrap"
    assert body["head"]["version"] == 0
    assert body["head"]["key_epoch"] == 1
    stored = dev.get("/otp/v1/account/keys").json()
    wraps = {k: v for k, v in keys.items() if k != "srp"}
    assert {k: stored[k] for k in wraps} == wraps
    # The SRP record is stored but never handed back to devices.
    assert "srp" not in stored
    assert stored["keys_revision"] == 1
    assert stored["device_key"] is None


def test_bootstrap_requires_keys(server: Server, lan: TestClient) -> None:
    _, token, _ = server.service.create_account()
    response = Device(lan).enroll(token)
    assert response.status_code == 400
    assert response.json()["code"] == "keys_required"


def test_token_is_single_use(server: Server, lan: TestClient) -> None:
    account_id, token, _ = server.service.create_account()
    assert Device(lan).enroll(token, _bundle(account_id)).status_code == 201
    again = Device(lan).enroll(token, _bundle(account_id))
    assert again.status_code == 401
    assert again.json()["code"] == "invalid_token"


def test_expired_token_is_refused(server: Server, lan: TestClient, clock: FakeClock) -> None:
    account_id, token, _ = server.service.create_account()
    clock.advance(601)
    # The device signs with the server's (advanced) clock so only the token is at fault.
    dev = Device(lan)
    dev.clock_offset = clock.offset
    assert dev.enroll(token, _bundle(account_id)).json()["code"] == "invalid_token"


@pytest.mark.parametrize("token", [None, "uoe_" + "A" * 43, "garbage"])
def test_bad_token_is_refused(lan: TestClient, server: Server, token: str | None) -> None:
    server.service.create_account()
    dev = Device(lan)
    response = dev.post(
        "/otp/v1/enroll",
        {"ed25519_public_key": dev.ed25519, "x25519_public_key": dev.x25519, "label": "x"},
        bearer=token,
    )
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_enroll_needs_proof_of_possession(server: Server, lan: TestClient) -> None:
    """The body's key must be the one that signed the request."""
    account_id, token, _ = server.service.create_account()
    signer, victim = Device(lan), Device(lan)
    payload = {
        "ed25519_public_key": victim.ed25519,
        "x25519_public_key": victim.x25519,
        "label": "x",
        "keys": _bundle(account_id),
    }
    response = signer.post("/otp/v1/enroll", payload, bearer=token)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_signature"
    # The token survives a failed attempt.
    assert victim.enroll(token, _bundle(account_id)).status_code == 201


def test_same_device_key_cannot_enroll_twice(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    token, _ = server.service.create_token(bootstrapped.account_id)
    dev = bootstrapped.device
    dev_id = dev.device_id
    dev.device_id = None
    response = dev.enroll(token)
    dev.device_id = dev_id
    assert response.status_code == 409
    assert response.json()["code"] == "device_exists"


def test_device_can_mint_a_token(bootstrapped: Bootstrapped, lan: TestClient) -> None:
    response = bootstrapped.device.post("/otp/v1/enrollment-tokens")
    assert response.status_code == 201
    token = response.json()["token"]
    assert token.startswith("uoe_")
    new = Device(lan)
    assert new.enroll(token).status_code == 201
    assert new.get("/otp/v1/account/keys").status_code == 200


def test_password_path_new_device(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    """Design §3.4 step 4: token -> wraps -> unwrap with the password locally -> enroll."""
    token, _ = server.service.create_token(bootstrapped.account_id)
    wraps = lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
    assert wraps.status_code == 200
    assert unwrap_with_password(wraps.json(), PASSWORD) == bootstrapped.vault.vault_key
    new = Device(lan, "Tablet")
    response = new.enroll(token)
    assert response.status_code == 201
    assert response.json()["device"]["enrolled_via"] == "token"
    keys_payload = {"keys": _bundle(bootstrapped.account_id)}
    # A second bootstrap of an account that has keys is refused.
    token2, _ = server.service.create_token(bootstrapped.account_id)
    late = Device(lan)
    late_payload = {
        "ed25519_public_key": late.ed25519,
        "x25519_public_key": late.x25519,
        "label": "x",
        **keys_payload,
    }
    refused = late.post("/otp/v1/enroll", late_payload, bearer=token2)
    assert refused.json()["code"] == "keys_exist"


def test_recovery_fetches_are_limited_per_token(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    token, _ = server.service.create_token(bootstrapped.account_id)
    headers = {"Authorization": f"Bearer {token}"}
    codes = [lan.get("/otp/v1/recovery/keys", headers=headers).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429]


def test_recovery_keys_before_bootstrap_is_not_found(server: Server, lan: TestClient) -> None:
    _, token, _ = server.service.create_account()
    response = lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_put_keys_is_optimistic(bootstrapped: Bootstrapped) -> None:
    dev = bootstrapped.device
    current = dev.get("/otp/v1/account/keys").json()
    new = _bundle(bootstrapped.account_id)
    ok = dev.put("/otp/v1/account/keys", {"base_revision": 1, "key_epoch": 1, **new})
    assert ok.status_code == 200
    assert ok.json()["keys_revision"] == 2
    assert ok.json()["recovery_wrap"] != current["recovery_wrap"]
    stale = dev.put("/otp/v1/account/keys", {"base_revision": 1, "key_epoch": 1, **new})
    assert stale.status_code == 409
    assert stale.json()["code"] == "keys_revision_conflict"
    # Dropping the password path (paranoid setting, design §3.2).
    only_recovery = {"recovery_wrap": new["recovery_wrap"]}
    dropped = dev.put("/otp/v1/account/keys", {"base_revision": 2, "key_epoch": 1, **only_recovery})
    assert dropped.json()["password_wrap"] is None
    half = dev.put(
        "/otp/v1/account/keys",
        {"base_revision": 3, "key_epoch": 1, "password_wrap": "AAAA", **only_recovery},
    )
    assert half.status_code == 400


# ---------------------------------------------------------------- LAN-only by default


def _enroll_from(server: Server, peer: tuple[str, int], headers: dict[str, str]) -> int:
    account_id, token, _ = server.service.create_account()
    with server.client(peer) as client:
        dev = Device(client)
        payload = {
            "ed25519_public_key": dev.ed25519,
            "x25519_public_key": dev.x25519,
            "label": "x",
            "keys": _bundle(account_id),
        }
        response = dev.post("/otp/v1/enroll", payload, bearer=token, extra_headers=headers)
    return response.status_code


def test_enrollment_from_the_internet_is_denied_by_default(server: Server) -> None:
    assert server.settings.pairing_scope == "lan"
    assert _enroll_from(server, PUBLIC_CLIENT, {}) == 403
    assert _enroll_from(server, LAN_CLIENT, {}) == 201
    assert server.service.metrics.value("uotp_events_total", "enroll.denied_network") == 1


def test_lan_gate_covers_every_enrollment_route(server: Server) -> None:
    with server.client(PUBLIC_CLIENT) as client:
        responses = [
            client.post("/otp/v1/enroll", json={}),
            client.get("/otp/v1/recovery/keys"),
            client.post(f"/otp/v1/pairings/pair_{'A' * 22}/join", json={}),
            client.get(f"/otp/v1/pairings/pair_{'A' * 22}/result"),
        ]
    for response in responses:
        assert response.status_code == 403, response.request.url
        assert response.json()["code"] == "enrollment_network_denied"


def test_forwarded_header_from_an_untrusted_peer_is_not_lan(server: Server) -> None:
    """A LAN peer that carries forwarding headers is an unconfigured proxy: fail closed."""
    assert _enroll_from(server, LAN_CLIENT, {"X-Forwarded-For": "192.168.1.20"}) == 403


@pytest.mark.parametrize(
    ("chain", "expected"),
    [
        # Internet client through cloudflared and Traefik: denied.
        (f"198.51.100.4, {CLOUDFLARED}", 403),
        # A forged LAN entry prepended by an Internet client is never read.
        (f"192.168.1.20, 198.51.100.4, {CLOUDFLARED}", 403),
        # A LAN client through Traefik (split DNS): allowed.
        ("192.168.1.20", 201),
        # Only trusted proxies in the chain: unknown client, denied.
        (CLOUDFLARED, 403),
        ("not-an-ip", 403),
    ],
)
def test_client_address_behind_trusted_proxies(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    chain: str,
    expected: int,
) -> None:
    server = make_server(
        make_settings(
            trusted_proxies=f"{TRAEFIK}/32,{CLOUDFLARED}/32", lan_networks="192.168.1.0/24"
        )
    )
    assert _enroll_from(server, (TRAEFIK, 4000), {"X-Forwarded-For": chain}) == expected


def test_denied_networks_win(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(
        make_settings(lan_networks="192.168.0.0/16", denied_networks="192.168.1.0/24")
    )
    assert _enroll_from(server, LAN_CLIENT, {}) == 403


def test_pairing_scope_anywhere_opens_it(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(pairing_scope="anywhere"))
    assert _enroll_from(server, PUBLIC_CLIENT, {}) == 201


def test_regular_routes_work_from_anywhere(server: Server, bootstrapped: Bootstrapped) -> None:
    with server.client(PUBLIC_CLIENT) as client:
        bootstrapped.device.http = client
        assert bootstrapped.device.get("/otp/v1/devices").status_code == 200


def test_enrollment_is_rate_limited_per_client(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(ratelimit_enabled=True, enroll_burst=2))
    with server.client() as client:
        codes = [client.get("/otp/v1/recovery/keys").status_code for _ in range(4)]
    assert codes == [401, 401, 429, 429]
