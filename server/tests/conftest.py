# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, Vault
from tests.fakes import SMTP_PASSWORD, SMTP_USER, Mailbox, smtp_relay
from ultimateotp import db
from ultimateotp.app import create_app
from ultimateotp.service import Service
from ultimateotp.settings import Settings

MIGRATIONS = Path(__file__).resolve().parents[2] / "contracts" / "db" / "migrations"
LAN_CLIENT = ("192.168.1.10", 51000)
PUBLIC_CLIENT = ("203.0.113.7", 51000)
PASSWORD = "correct horse battery staple"


class FakeClock:
    """Real time plus an adjustable offset (clients sign with the real clock)."""

    def __init__(self) -> None:
        self.offset = 0
        self._mono = 0.0

    def now(self) -> int:
        return int(time.time()) + self.offset

    def monotonic(self) -> float:
        return time.monotonic() + self.offset + self._mono

    def advance(self, seconds: int) -> None:
        self.offset += seconds


@pytest.fixture
def make_settings(tmp_path: Path) -> Callable[..., Settings]:
    def make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "data_dir": tmp_path,
            "migrations_dir": MIGRATIONS,
            "ratelimit_enabled": False,
            # Most tests run without SMTP; tests/test_email.py runs a fake relay.
            "email_verification": "disabled",
            **overrides,
        }
        return Settings(**values)

    return make


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@dataclass
class Server:
    settings: Settings
    clock: FakeClock
    asgi: Any

    @property
    def service(self) -> Service:
        service: Service = self.asgi.fastapi.state.service
        return service

    def client(self, peer: tuple[str, int] = LAN_CLIENT) -> TestClient:
        return TestClient(self.asgi, client=peer)


@pytest.fixture
def make_server(clock: FakeClock) -> Callable[[Settings], Server]:
    def make(settings: Settings) -> Server:
        db.migrate(settings.database_file, settings.migrations_dir)
        return Server(settings, clock, create_app(settings, clock=clock))

    return make


@pytest.fixture
def server(make_server: Callable[[Settings], Server], settings: Settings) -> Server:
    return make_server(settings)


@pytest.fixture
def lan(server: Server) -> Iterator[TestClient]:
    with server.client() as client:
        yield client


@dataclass
class Bootstrapped:
    account_id: str
    device: Device
    vault: Vault
    recovery_key: bytes

    @property
    def trusted(self) -> dict[str, str]:
        assert self.device.device_id is not None
        return {self.device.device_id: self.device.ed25519}


@pytest.fixture
def bootstrapped(server: Server, lan: TestClient) -> Bootstrapped:
    """An account with its first device enrolled (bootstrap) and an empty vault."""
    account_id, token, _ = server.service.create_account()
    device = Device(lan, "Phone A")
    vault = Vault(account_id=account_id)
    recovery_key = secrets.token_bytes(32)
    response = device.enroll(token, vault.key_bundle(PASSWORD, recovery_key))
    assert response.status_code == 201, response.text
    return Bootstrapped(account_id, device, vault, recovery_key)


def second_device(server: Server, client: TestClient, boot: Bootstrapped) -> Device:
    """Enrolls another device through the token + password path."""
    token, _ = server.service.create_token(boot.account_id)
    device = Device(client, "Phone B")
    response = device.enroll(token)
    assert response.status_code == 201, response.text
    return device


@dataclass
class Mail:
    server: Server
    box: Mailbox

    def flush(self) -> None:
        assert self.server.service.alerts.flush()


@pytest.fixture
def make_mail(
    tmp_path: Path,
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
) -> Iterator[Callable[..., Mail]]:
    relays = []

    def make(**overrides: object) -> Mail:
        manager = smtp_relay(tmp_path)
        box, port, cert = manager.__enter__()
        relays.append(manager)
        settings = make_settings(
            email_verification="enabled",
            smtp_host="127.0.0.1",
            smtp_port=port,
            smtp_user=SMTP_USER,
            smtp_from="UltimateOTP <otp@example.org>",
            smtp_password=SMTP_PASSWORD,
            smtp_ca_file=cert,
            **overrides,
        )
        return Mail(make_server(settings), box)

    yield make
    for manager in relays:
        manager.__exit__(None, None, None)


@pytest.fixture
def mail(make_mail: Callable[..., Mail]) -> Mail:
    return make_mail()
