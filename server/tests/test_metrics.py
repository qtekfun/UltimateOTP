# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prometheus metrics: the names docs/monitoring relies on, and no personal labels."""

import re
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, Vault, new_item_id
from tests.conftest import LAN_CLIENT, PASSWORD, Bootstrapped, Mail, Server
from tests.test_blocking import PUBLIC, _probe
from tests.test_login import EMAIL, _account
from ultimateotp.metrics import LATENCY_BUCKETS, Metrics
from ultimateotp.settings import Settings

EXPECTED_FAMILIES = [
    "uotp_signups_total",
    "uotp_logins_total",
    "uotp_blocks_total",
    "uotp_lockouts_total",
    "uotp_commits_total",
    "uotp_conflicts_total",
    "uotp_sse_connections_total",
    "uotp_emails_total",
    "uotp_notifications_total",
    "uotp_events_total",
    "uotp_problems_total",
    "uotp_http_request_duration_seconds",
    "uotp_sse_streams",
    "uotp_blocked_clients",
    "uotp_accounts",
    "uotp_devices_active",
    "uotp_vault_items",
    "uotp_history_versions",
    "uotp_history_items",
    "uotp_history_bytes",
    "uotp_database_bytes",
    "uotp_build_info",
]


def _scrape(server: Server) -> str:
    with server.client(("127.0.0.1", 9)) as local:
        response = local.get("/metrics")
    assert response.status_code == 200
    return response.text


def _value(text: str, series: str) -> float:
    match = re.search(rf"^{re.escape(series)} (\S+)$", text, re.MULTILINE)
    assert match, f"{series} not exposed"
    return float(match.group(1))


def test_registry_text_format() -> None:
    metrics = Metrics()
    metrics.inc("uotp_events_total", 'we"ird\nname')
    metrics.inc("uotp_logins_total", result="success", amount=3)
    metrics.observe(
        "uotp_http_request_duration_seconds", 0.03, method="GET", route="/x", status="2xx"
    )
    metrics.observe(
        "uotp_http_request_duration_seconds", 20.0, method="GET", route="/x", status="2xx"
    )
    metrics.gauge("uotp_build_info", lambda: 1.0, version="1.2.3")
    text = metrics.render()
    assert 'uotp_events_total{event="we\\"ird\\nname"} 1' in text
    assert 'uotp_logins_total{result="success"} 3' in text
    assert 'uotp_logins_total{result="srp_failure"} 0' in text  # declared at zero
    assert 'uotp_build_info{version="1.2.3"} 1.0' in text
    series = 'uotp_http_request_duration_seconds_bucket{method="GET",route="/x",status="2xx",le="'
    assert f'{series}0.05"}} 1' in text
    assert f'{series}10"}} 1' in text
    assert f'{series}+Inf"}} 2' in text
    assert (
        'uotp_http_request_duration_seconds_count{method="GET",route="/x",status="2xx"} 2' in text
    )
    assert len(LATENCY_BUCKETS) == 11
    # Every sample line is `name{labels} number`.
    for line in text.splitlines():
        if line and not line.startswith("#"):
            assert re.fullmatch(r"[a-z_]+(\{.*\})? \S+", line), line


def test_all_families_are_exposed(server: Server, bootstrapped: Bootstrapped) -> None:
    bootstrapped.device.commit(bootstrapped.vault, {new_item_id(): {"x": 1}})
    assert bootstrapped.device.get("/otp/v1/vault/history/99").status_code == 404
    text = _scrape(server)
    for family in EXPECTED_FAMILIES:
        assert f"# TYPE {family} " in text, family
    assert _value(text, "uotp_commits_total") == 1
    assert _value(text, "uotp_accounts") == 1
    assert _value(text, "uotp_devices_active") == 1
    assert _value(text, "uotp_vault_items") == 1
    assert _value(text, "uotp_database_bytes") > 0
    assert 'uotp_build_info{version="0.1.0"} 1' in text


def test_login_signup_conflict_block_and_lockout_counters(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(
        make_settings(signup="disabled", srp_lockout_threshold=2, block_threshold=50)
    )
    with server.client(LAN_CLIENT) as lan:
        owner = _account(server, lan)
        assert Device(lan).srp_login(EMAIL, PASSWORD).status_code == 201
        assert Device(lan).srp_login(EMAIL, "wrong").status_code == 401
        assert Device(lan).srp_login(EMAIL, "wrong").status_code == 401  # locks the account
        assert Device(lan).srp_login(EMAIL, PASSWORD).status_code == 429
        # A conflict: commit on a stale base.
        stale = Vault(account_id=owner.account_id, vault_key=owner.vault.vault_key)
        owner.device.commit(owner.vault, {new_item_id(): {"x": 1}})
        assert owner.device.commit(stale, {new_item_id(): {"x": 2}}).status_code == 409
    text = _scrape(server)
    assert _value(text, 'uotp_logins_total{result="success"}') == 1
    assert _value(text, 'uotp_logins_total{result="srp_failure"}') == 2
    assert _value(text, 'uotp_logins_total{result="locked"}') == 1
    assert _value(text, "uotp_lockouts_total") == 1
    assert _value(text, 'uotp_conflicts_total{reason="version"}') == 1
    assert _value(text, "uotp_commits_total") == 1


def test_blocks_and_signups(
    make_mail: Callable[..., Mail],
) -> None:
    mail: Mail = make_mail(signup="enabled", block_threshold=3)
    import secrets  # noqa: PLC0415

    with mail.server.client(PUBLIC) as client:
        client.post("/otp/v1/login/email-code", json={"email": EMAIL})
        mail.flush()
        vault = Vault(account_id="")
        device = Device(client, "Phone")
        response = device.post(
            "/otp/v1/signup",
            {
                "email": EMAIL,
                "email_code": mail.box.code_for(EMAIL),
                "device": {
                    "ed25519_public_key": device.ed25519,
                    "x25519_public_key": device.x25519,
                    "label": "Phone",
                },
                "keys": vault.key_bundle(PASSWORD, secrets.token_bytes(32)),
            },
        )
        assert response.status_code == 201, response.text
        _probe(client, 3)
        assert client.get("/otp/v1/server-info").status_code == 429
    mail.flush()
    text = _scrape(mail.server)
    assert _value(text, "uotp_signups_total") == 1
    assert _value(text, "uotp_blocks_total") == 1
    assert _value(text, 'uotp_emails_total{result="sent"}') >= 1
    assert _value(text, 'uotp_problems_total{code="client_blocked"}') >= 1


def test_failed_email_delivery_is_counted(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    from tests.fakes import free_port  # noqa: PLC0415

    server = make_server(
        make_settings(
            email_verification="enabled",
            smtp_host="127.0.0.1",
            smtp_port=free_port(),  # nobody listens
            smtp_from="otp@example.org",
            smtp_password="x",
            smtp_timeout_s=1,
        )
    )
    server.service.create_account("a@example.org")
    assert server.service.alerts.flush()
    assert server.service.metrics.value("uotp_emails_total", result="failed") == 1
    assert server.service.metrics.value("uotp_emails_total", result="sent") == 0


def test_latency_histogram_uses_route_templates_and_no_personal_labels(
    server: Server, bootstrapped: Bootstrapped
) -> None:
    a = bootstrapped.device
    item = new_item_id()
    a.commit(bootstrapped.vault, {item: {"x": 1}})
    a.get("/otp/v1/vault/history/1")
    a.get(f"/otp/v1/vault/history/1?item_id={item}")
    a.post(f"/otp/v1/devices/{a.device_id}/revoke")
    with server.client(("203.0.113.9", 1)) as stranger:
        stranger.get("/definitely/not/a/route/user@example.org")
    text = _scrape(server)
    routes = set(re.findall(r'route="([^"]*)"', text))
    assert "/otp/v1/vault/history/{version}" in routes
    assert "/otp/v1/devices/{device_id}/revoke" in routes
    assert "/otp/v1/vault/commit" in routes
    assert "unmatched" in routes
    assert not [r for r in routes if "dev_" in r or "@" in r or "1?item" in r]
    # No account, device, client, address or email anywhere in the exposition.
    assert not re.search(r"acc_[A-Za-z0-9_-]{22}|dev_[A-Za-z0-9_-]{22}|c_[0-9a-f]{12}", text)
    assert "@" not in text
    assert not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text.replace("0.1.0", ""))
    # The stream route is excluded from the latency histogram (an hour is not a latency).
    assert 'route="/otp/v1/events"' not in text


def test_sse_connection_counter(server: Server, bootstrapped: Bootstrapped) -> None:
    from tests.test_events import DEADLINE_S  # noqa: PLC0415

    assert DEADLINE_S > 0
    server.service.metrics.inc("uotp_sse_connections_total")
    assert _value(_scrape(server), "uotp_sse_connections_total") == 1


@pytest.mark.parametrize("path", ["/metrics"])
def test_metrics_stay_private(server: Server, path: str) -> None:
    with server.client(("203.0.113.9", 1)) as stranger:
        assert stranger.get(path).status_code == 403
    with TestClient(server.asgi, client=("192.168.1.10", 1)) as lan:
        assert lan.get(path).status_code == 403
