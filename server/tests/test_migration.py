# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""A deployed 1.1.0 server upgrades without data loss: `tests/fixtures/v1_1_0.sql` is a database
exactly as that server (migration 0001 only) leaves it, built by `fixtures/make_v1_1_0.py`."""

import hashlib
import json
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from tests.client import Device, Vault, new_item_id
from tests.conftest import LAN_CLIENT, MIGRATIONS, PUBLIC_CLIENT, Server
from ultimateotp import b64, db
from ultimateotp.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"
# Migration 0001 is history: a deployed database was built from exactly these bytes.
INIT_SHA256 = "3769beadb95044fe713d4f5169a8e1730bae9695b9a9684741205cb5132d6386"
LEGACY: dict[str, Any] = json.loads((FIXTURES / "v1_1_0.json").read_text(encoding="utf-8"))
ORIGINAL_TABLES = [
    "accounts",
    "devices",
    "device_key_wraps",
    "items",
    "enrollment_tokens",
    "pairings",
    "request_nonces",
    "email_codes",
    "srp_sessions",
    "server_secrets",
]


def _snapshot(path: Path, tables: list[str]) -> dict[str, list[dict[str, Any]]]:
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return {
            table: [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2")]  # noqa: S608
            for table in tables
        }


@pytest.fixture
def legacy_db(settings: Settings) -> Path:
    path = settings.database_file
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript((FIXTURES / "v1_1_0.sql").read_text(encoding="utf-8"))
    with closing(sqlite3.connect(path)) as conn:
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations")]
        columns = [r[1] for r in conn.execute("PRAGMA table_info(accounts)")]
    assert versions == [1]
    assert "lang" not in columns, "the fixture must be a 1.1.0 database"
    return path


def test_migration_0001_is_untouched() -> None:
    digest = hashlib.sha256((MIGRATIONS / "0001_init.sql").read_bytes()).hexdigest()
    assert digest == INIT_SHA256
    names = sorted(p.name for p in MIGRATIONS.glob("*.sql"))
    assert names[:2] == ["0001_init.sql", "0002_hardening.sql"]


def test_upgrade_keeps_every_row_and_scrubs_addresses(settings: Settings, legacy_db: Path) -> None:
    before = _snapshot(legacy_db, ORIGINAL_TABLES)
    assert before["accounts"], "the fixture has an account"
    assert {d["last_ip"] for d in before["devices"]} == {"192.168.1.10", "203.0.113.7"}
    applied = db.migrate(legacy_db, settings.migrations_dir)
    assert [m.name for m in applied] == ["0002_hardening.sql"]
    assert db.migrate(legacy_db, settings.migrations_dir) == []  # idempotent
    after = _snapshot(legacy_db, ORIGINAL_TABLES)
    for table in ORIGINAL_TABLES:
        assert len(after[table]) == len(before[table]), table
        for old, new in zip(before[table], after[table], strict=True):
            kept = {k: v for k, v in new.items() if k in old}
            expected = dict(old)
            if table == "devices":
                expected["last_ip"] = None  # the server no longer keeps client addresses
            if table == "srp_sessions":
                assert new["purpose"] == "login"
            assert kept == expected, table
    for account in after["accounts"]:
        assert account["lang"] is None
        assert account["tombstones_compacted_through"] == 0
    with closing(sqlite3.connect(legacy_db)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        for table in ("vault_versions", "item_history", "client_blocks", "email_changes"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


def _legacy_device(client: TestClient) -> tuple[Device, Vault]:
    device = Device(client, "Legacy phone")
    device.signing_key = SigningKey(bytes.fromhex(LEGACY["ed25519_seed"]))
    device.box_key = PrivateKey(bytes.fromhex(LEGACY["x25519_seed"]))
    device.device_id = LEGACY["device_id"]
    device.account_id = LEGACY["account_id"]
    vault = Vault(
        account_id=LEGACY["account_id"],
        vault_key=bytes.fromhex(LEGACY["vault_key"]),
        key_epoch=LEGACY["key_epoch"],
        version=LEGACY["version"],
    )
    return device, vault


def test_upgraded_server_serves_the_old_data_and_starts_the_history(
    make_server: Callable[[Settings], Server], settings: Settings, legacy_db: Path
) -> None:
    server = make_server(settings)  # make_server migrates
    with server.client(LAN_CLIENT) as client:
        assert client.get("/readyz").status_code == 200
        device, vault = _legacy_device(client)
        # The old device keeps working with its old key, no re-enrollment.
        pulled = device.get("/otp/v1/vault?since=0")
        assert pulled.status_code == 200, pulled.text
        body = pulled.json()
        assert body["full"] is True
        assert body["head"]["version"] == LEGACY["version"]
        live = {i["item_id"]: i for i in body["items"] if not i["deleted"]}
        assert set(live) == set(LEGACY["live_items"])
        for item_id, plain in LEGACY["live_items"].items():
            blob = b64.decode(live[item_id]["blob"])
            assert vault.decrypt_item(item_id, blob, live[item_id]["version"]) == plain
        tombstone = next(i for i in body["items"] if i["deleted"])
        assert tombstone["item_id"] == LEGACY["deleted_item"]
        # No history from before the upgrade: 1.1.0 overwrote in place.
        assert device.get("/otp/v1/vault/history").json()["versions"] == []
        assert device.get("/otp/v1/vault/trash").json()["items"] == []
        # Pull with the client-side checks, then write on top of the old version.
        vault.version = 0  # a client with no local copy: pull everything and verify the head
        device.pull(vault, {LEGACY["device_id"]: device.ed25519})
        assert vault.version == LEGACY["version"]
        item = next(iter(LEGACY["live_items"]))
        assert device.commit(vault, {item: {"issuer": "after upgrade"}}).status_code == 200
        assert device.commit(vault, deletes=[item]).status_code == 200
        listing = device.get("/otp/v1/vault/history").json()["versions"]
        assert [v["version"] for v in listing] == [5, 4]
        trash = device.get("/otp/v1/vault/trash").json()["items"]
        assert [t["item_id"] for t in trash] == [item]
        assert vault.decrypt_item(item, b64.decode(trash[0]["blob"]), trash[0]["version"]) == {
            "issuer": "after upgrade"
        }
        # Sessions: the stored address is gone; the device shows today's opaque id instead.
        sessions = {s["device_id"]: s for s in device.get("/otp/v1/sessions").json()["sessions"]}
        assert sessions[LEGACY["revoked_device_id"]]["last_ip"] is None
        assert sessions[LEGACY["revoked_device_id"]]["revoked_at"] is not None
        assert sessions[LEGACY["device_id"]]["last_ip"].startswith("c_")
        assert "192.168" not in json.dumps(sessions)


def test_password_login_and_account_deletion_work_on_the_upgraded_database(
    make_server: Callable[[Settings], Server], settings: Settings, legacy_db: Path
) -> None:
    server = make_server(settings)
    with server.client(PUBLIC_CLIENT) as internet:
        fresh = Device(internet, "After upgrade")
        login = fresh.srp_login(LEGACY["email"], LEGACY["password"])
        assert login.status_code == 201, login.text
        assert login.json()["head"]["version"] == LEGACY["version"]
        # The new account routes work on legacy rows too: delete with the password proof.
        start, proof = fresh.reauth_srp(LEGACY["password"])
        assert start.status_code == 200
        response = fresh.post("/otp/v1/account/delete", {"reauth": {"srp": proof}})
        assert response.status_code == 200, response.text
        assert response.json()["removed"]["devices"] == 3
        assert response.json()["removed"]["items"] == 3  # two live items and one tombstone
    with closing(sqlite3.connect(legacy_db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


def test_fixture_items_and_ids_are_what_the_sidecar_says(legacy_db: Path) -> None:
    rows = _snapshot(legacy_db, ["items", "accounts"])
    assert {r["item_id"] for r in rows["items"] if not r["deleted"]} == set(LEGACY["live_items"])
    assert rows["accounts"][0]["id"] == LEGACY["account_id"]
    assert new_item_id() not in LEGACY["live_items"]
