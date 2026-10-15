# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Probes and metrics."""

from collections.abc import Callable
from pathlib import Path

from tests.conftest import LAN_CLIENT, Bootstrapped, Server
from ultimateotp.app import create_app
from ultimateotp.settings import Settings


def test_healthz_and_readyz(server: Server) -> None:
    with server.client() as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json() == {"status": "ok"}


def test_readyz_without_database(make_settings: Callable[..., Settings], tmp_path: Path) -> None:
    from fastapi.testclient import TestClient  # noqa: PLC0415

    settings = make_settings(data_dir=tmp_path / "empty")
    with TestClient(create_app(settings), client=LAN_CLIENT) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_metrics_only_for_metrics_networks(server: Server, bootstrapped: Bootstrapped) -> None:
    with server.client(("127.0.0.1", 9000)) as local:
        body = local.get("/metrics").text
    assert 'uotp_events_total{event="enroll.success"} 1' in body
    assert "uotp_sse_streams 0" in body
    with server.client() as lan:
        assert lan.get("/metrics").status_code == 403


def test_server_info_is_public(server: Server) -> None:
    with server.client(("203.0.113.9", 1)) as client:
        info = client.get("/otp/v1/server-info").json()
    assert info["api_version"] == "1.3.0"
    assert info["history_retention_days"] == 30
    assert info["languages"] == ["en", "es"]
    assert isinstance(info["server_time"], int)
