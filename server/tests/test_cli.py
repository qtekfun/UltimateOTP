# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The admin CLI (`ultimateotp ...`), run in-process with the same settings as the api."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from tests.conftest import MIGRATIONS, Server
from ultimateotp import cli


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("UOTP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("UOTP_MIGRATIONS_DIR", str(MIGRATIONS))
    monkeypatch.setenv("UOTP_LOG_LEVEL", "WARNING")
    return tmp_path


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, object]:
    code = cli.main(list(args))
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else None


def test_migrate_then_account_and_token(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "migrate")[0] == 0
    assert run(capsys, "migrate")[0] == 0  # idempotent
    code, created = run(capsys, "account-create", "--server-url", "https://otp.example.org")
    assert code == 0
    assert isinstance(created, dict)
    assert created["enrollment_token"].startswith("uoe_")
    assert created["enroll_uri"].startswith("uotp://enroll?server=https%3A%2F%2Fotp.example.org&")
    code, token = run(capsys, "token-create", created["account_id"])
    assert code == 0
    assert isinstance(token, dict)
    assert token["enroll_uri"] is None
    code, accounts = run(capsys, "accounts")
    assert isinstance(accounts, list)
    assert accounts[0]["account_id"] == created["account_id"]
    assert accounts[0]["active_devices"] == 0
    assert run(capsys, "devices", created["account_id"]) == (0, [])
    _, purged = run(capsys, "purge")
    assert purged == {"enrollment_tokens": 0, "pairings": 0, "request_nonces": 0}


def test_unknown_ids_fail_cleanly(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run(capsys, "migrate")
    assert cli.main(["token-create", "acc_" + "A" * 22]) == 1
    assert cli.main(["device-revoke", "dev_" + "A" * 22]) == 1
    assert "not_found" in capsys.readouterr().err


def test_device_listing_and_revocation(
    server: Server,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    bootstrapped: object,
) -> None:
    monkeypatch.setenv("UOTP_DATA_DIR", str(server.settings.data_dir))
    monkeypatch.setenv("UOTP_MIGRATIONS_DIR", str(MIGRATIONS))
    account_id = bootstrapped.account_id  # type: ignore[attr-defined]
    device_id = bootstrapped.device.device_id  # type: ignore[attr-defined]
    _, devices = run(capsys, "devices", account_id)
    assert isinstance(devices, list)
    assert devices[0]["device_id"] == device_id
    _, revoked = run(capsys, "device-revoke", device_id)
    assert isinstance(revoked, dict)
    assert revoked["revoked_at"] is not None


def test_backup_is_a_consistent_copy(
    server: Server, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bootstrapped: object
) -> None:
    monkeypatch.setenv("UOTP_DATA_DIR", str(server.settings.data_dir))
    destination = tmp_path / "backup" / "copy.db"
    destination.parent.mkdir()
    assert cli.main(["backup", str(destination)]) == 0
    with closing(sqlite3.connect(destination)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    with pytest.raises(FileExistsError):
        cli.main(["backup", str(destination)])
