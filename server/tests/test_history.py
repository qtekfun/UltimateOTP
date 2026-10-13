# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Vault history and trash (contract 1.2.0): previous versions kept as ciphertext, restore of an
entry deleted less than the retention ago even after its tombstone is compacted, retention and
caps, rotation and the abuse cases."""

import secrets
import sqlite3
from collections.abc import Callable
from contextlib import closing
from typing import Any

import pytest
from fastapi.testclient import TestClient
from nacl.signing import VerifyKey

from tests.client import Device, Vault, new_item_id
from tests.conftest import (
    LAN_CLIENT,
    PASSWORD,
    Bootstrapped,
    FakeClock,
    Server,
    second_device,
)
from tests.test_revocation import _rotation
from ultimateotp import b64, signing
from ultimateotp.settings import Settings

DAY = 86_400


def _boot(server: Server, client: TestClient) -> Bootstrapped:
    account_id, token, _ = server.service.create_account()
    device = Device(client, "Phone A")
    vault = Vault(account_id=account_id)
    recovery_key = secrets.token_bytes(32)
    assert device.enroll(token, vault.key_bundle(PASSWORD, recovery_key)).status_code == 201
    return Bootstrapped(account_id, device, vault, recovery_key)


@pytest.fixture
def make_boot(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> Callable[..., tuple[Server, Bootstrapped, TestClient]]:
    def make(**overrides: Any) -> tuple[Server, Bootstrapped, TestClient]:
        server = make_server(make_settings(**overrides))
        client = TestClient(server.asgi, client=LAN_CLIENT)
        return server, _boot(server, client), client

    return make


def _sync_clock(boot: Bootstrapped, clock: FakeClock) -> None:
    boot.device.clock_offset = clock.offset


def verify_state(boot: Bootstrapped, state: dict[str, Any]) -> None:
    """What a client does with a past state: recompute the manifest and check the head."""
    head = state["head"]
    manifest = signing.manifest(
        (i["item_id"], i["version"], signing.sha256_b64(b64.decode(i["blob"])))
        for i in state["items"]
    )
    message = signing.head_message(
        head["account_id"], head["version"], head["key_epoch"], head["signed_by"], manifest
    )
    VerifyKey(b64.decode(boot.device.ed25519)).verify(message, b64.decode(head["signature"]))


def _item(n: int) -> dict[str, Any]:
    return {"issuer": f"Example {n}", "secret_b32": "JBSWY3DPEHPK3PXP", "n": n}


def test_history_lists_versions_and_rebuilds_each_past_vault(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    _, boot, _ = make_boot()
    a, vault = boot.device, boot.vault
    one, two, three = new_item_id(), new_item_id(), new_item_id()
    assert a.commit(vault, {one: _item(1), two: _item(2)}).status_code == 200  # v1
    assert a.commit(vault, {one: _item(11)}).status_code == 200  # v2: one replaced
    assert a.commit(vault, {three: _item(3)}, deletes=[two]).status_code == 200  # v3
    assert a.commit(vault, deletes=[one]).status_code == 200  # v4

    listing = a.get("/otp/v1/vault/history").json()
    assert listing["retention_days"] == 30
    assert listing["current_version"] == 4
    assert [v["version"] for v in listing["versions"]] == [4, 3, 2, 1]
    by_version = {v["version"]: v for v in listing["versions"]}
    assert by_version[1]["upserted"] == sorted([one, two])
    assert by_version[2]["upserted"] == [one]
    assert by_version[3]["deleted"] == [two]
    assert by_version[4]["deleted"] == [one]
    assert {v["kind"] for v in listing["versions"]} == {"commit"}
    assert all(v["signed_by"] == a.device_id for v in listing["versions"])
    assert listing["next_before"] is None

    expected = {
        1: {one: 1, two: 1},
        2: {one: 2, two: 1},
        3: {one: 2, three: 3},
        4: {three: 3},
    }
    for version, items in expected.items():
        state = a.get(f"/otp/v1/vault/history/{version}").json()
        assert state["complete"] is True
        assert state["head"]["version"] == version
        assert {i["item_id"]: i["version"] for i in state["items"]} == items
        verify_state(boot, state)
    # A past blob decrypts with the version it came with (the version is in its AAD).
    state = a.get("/otp/v1/vault/history/2").json()
    old = next(i for i in state["items"] if i["item_id"] == two)
    assert vault.decrypt_item(two, b64.decode(old["blob"]), old["version"]) == _item(2)
    # The same via `item_id`: only that entry, flagged incomplete.
    one_only = a.get(f"/otp/v1/vault/history/1?item_id={one}").json()
    assert one_only["complete"] is False
    assert [i["item_id"] for i in one_only["items"]] == [one]


def test_pagination(make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]]) -> None:
    _, boot, _ = make_boot()
    for n in range(5):
        assert boot.device.commit(boot.vault, {new_item_id(): _item(n)}).status_code == 200
    page = boot.device.get("/otp/v1/vault/history?limit=2").json()
    assert [v["version"] for v in page["versions"]] == [5, 4]
    assert page["next_before"] == 4
    rest = boot.device.get(f"/otp/v1/vault/history?limit=10&before={page['next_before']}").json()
    assert [v["version"] for v in rest["versions"]] == [3, 2, 1]
    assert rest["next_before"] is None


def test_trash_and_restore(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    _, boot, _ = make_boot()
    a, vault = boot.device, boot.vault
    gone, kept = new_item_id(), new_item_id()
    a.commit(vault, {gone: _item(1), kept: _item(2)})
    a.commit(vault, {gone: _item(10)})  # edited once: the trash holds the last live blob
    deleted = a.commit(vault, deletes=[gone])
    assert deleted.status_code == 200
    trash = a.get("/otp/v1/vault/trash").json()
    assert trash["retention_days"] == 30
    assert [t["item_id"] for t in trash["items"]] == [gone]
    entry = trash["items"][0]
    assert entry["deleted_in_version"] == 3
    assert entry["version"] == 2
    assert entry["key_epoch"] == 1
    assert vault.decrypt_item(gone, b64.decode(entry["blob"]), entry["version"]) == _item(10)
    # Restore = an ordinary upsert, re-encrypted for the next version.
    restored = a.commit(vault, {gone: vault.decrypt_item(gone, b64.decode(entry["blob"]), 2)})
    assert restored.status_code == 200
    assert a.get("/otp/v1/vault/trash").json()["items"] == []
    live = {i["item_id"] for i in a.get("/otp/v1/vault").json()["items"] if not i["deleted"]}
    assert live == {gone, kept}


def test_deleted_twice_shows_the_latest_deletion(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    _, boot, _ = make_boot()
    a, vault = boot.device, boot.vault
    item = new_item_id()
    a.commit(vault, {item: _item(1)})
    a.commit(vault, deletes=[item])
    a.commit(vault, {item: _item(2)})
    a.commit(vault, deletes=[item])
    trash = a.get("/otp/v1/vault/trash").json()["items"]
    assert len(trash) == 1
    assert trash[0]["deleted_in_version"] == 4
    assert vault.decrypt_item(item, b64.decode(trash[0]["blob"]), trash[0]["version"]) == _item(2)


def test_entry_is_recoverable_after_its_tombstone_is_compacted(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
    clock: FakeClock,
) -> None:
    server, boot, _ = make_boot(tombstone_retention_days=1)
    a, vault = boot.device, boot.vault
    gone, kept = new_item_id(), new_item_id()
    a.commit(vault, {gone: _item(1), kept: _item(2)})  # v1
    a.commit(vault, deletes=[gone])  # v2, the tombstone
    clock.advance(2 * DAY)
    _sync_clock(boot, clock)
    result = server.service.maintenance()
    assert result["tombstones"] == 1
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        rows = conn.execute("SELECT item_id FROM items WHERE deleted = 1").fetchall()
    assert rows == []  # compacted away
    # ... and the entry is still there to restore, 2 days after deleting it.
    trash = a.get("/otp/v1/vault/trash").json()["items"]
    assert [t["item_id"] for t in trash] == [gone]
    assert vault.decrypt_item(gone, b64.decode(trash[0]["blob"]), 1) == _item(1)
    # A device that never saw the tombstone is told to take the full set.
    delta = a.get("/otp/v1/vault?since=1").json()
    assert delta["full"] is True
    assert {i["item_id"] for i in delta["items"]} == {kept}
    # One that did see it gets an ordinary delta.
    assert a.get("/otp/v1/vault?since=2").json()["full"] is False
    assert a.get("/otp/v1/vault?since=0").json()["full"] is True


def test_retention_prunes_by_age_exactly(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
    clock: FakeClock,
) -> None:
    server, boot, _ = make_boot(history_retention_days=10)
    a, vault = boot.device, boot.vault
    item, other = new_item_id(), new_item_id()
    a.commit(vault, {item: _item(1), other: _item(0)})  # v1, day 0
    clock.advance(6 * DAY)
    _sync_clock(boot, clock)
    a.commit(vault, {item: _item(2)})  # v2, day 6
    a.commit(vault, deletes=[item])  # v3, day 6
    clock.advance(6 * DAY)  # day 12: v1 is 12 days old, v2 and v3 6
    _sync_clock(boot, clock)
    a.commit(vault, {new_item_id(): _item(3)})  # v4, day 12 (prunes v1 in the same transaction)
    versions = [v["version"] for v in a.get("/otp/v1/vault/history").json()["versions"]]
    assert versions == [4, 3, 2]
    gone = a.get("/otp/v1/vault/history/1")
    assert gone.status_code == 410
    assert gone.json()["code"] == "history_pruned"
    assert a.get("/otp/v1/vault/history/99").status_code == 404
    # What is left rebuilds exactly and still verifies.
    state = a.get("/otp/v1/vault/history/2").json()
    assert {i["item_id"]: i["version"] for i in state["items"]} == {item: 2, other: 1}
    verify_state(boot, state)
    # The trash entry of v3 is within the window.
    assert [t["item_id"] for t in a.get("/otp/v1/vault/trash").json()["items"]] == [item]
    clock.advance(11 * DAY)  # day 23: everything but the current version aged out
    _sync_clock(boot, clock)
    server.service.maintenance()
    assert a.get("/otp/v1/vault/trash").json()["items"] == []
    assert [v["version"] for v in a.get("/otp/v1/vault/history").json()["versions"]] == [4]
    # The current version always answers, from the live rows.
    assert a.get("/otp/v1/vault/history/4").status_code == 200


def test_count_cap_keeps_only_the_latest_and_they_still_verify(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    _, boot, _ = make_boot(history_max_versions=3)
    a, vault = boot.device, boot.vault
    item = new_item_id()
    for n in range(6):
        assert a.commit(vault, {item: _item(n), new_item_id(): _item(100 + n)}).status_code == 200
    versions = [v["version"] for v in a.get("/otp/v1/vault/history").json()["versions"]]
    assert versions == [6, 5, 4]
    for version in versions:
        verify_state(boot, a.get(f"/otp/v1/vault/history/{version}").json())
    assert a.get("/otp/v1/vault/history/3").status_code == 410
    with closing(sqlite3.connect(a.http.app.fastapi.state.settings.database_file)) as conn:
        # Previous blobs of versions that fell out are gone too: nothing grows without bound.
        left = conn.execute("SELECT MIN(superseded_by) FROM item_history").fetchone()[0]
    assert left >= 4


def test_byte_cap(make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]]) -> None:
    server, boot, _ = make_boot(history_max_bytes=1024 * 1024)
    a, vault = boot.device, boot.vault
    item = new_item_id()
    big = "x" * 40_000
    for n in range(40):
        assert a.commit(vault, {item: {"n": n, "pad": big}}).status_code == 200
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        total = conn.execute("SELECT SUM(size) FROM item_history").fetchone()[0]
    assert total <= 1024 * 1024
    versions = [v["version"] for v in a.get("/otp/v1/vault/history").json()["versions"]]
    assert versions[0] == 40
    assert 10 < len(versions) < 40
    verify_state(boot, a.get(f"/otp/v1/vault/history/{versions[-1]}").json())


def test_history_off(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
    clock: FakeClock,
) -> None:
    server, boot, _ = make_boot(history_retention_days=0)
    a, vault = boot.device, boot.vault
    item = new_item_id()
    a.commit(vault, {item: _item(1)})
    a.commit(vault, deletes=[item])
    assert a.get("/otp/v1/vault/history").json()["versions"] == []
    assert a.get("/otp/v1/vault/trash").json()["items"] == []
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM item_history").fetchone()[0] == 0
    info = TestClient(server.asgi, client=LAN_CLIENT).get("/otp/v1/server-info").json()
    assert info["history_retention_days"] == 0


def test_turning_history_off_clears_what_was_kept(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    on = make_server(make_settings())
    client = TestClient(on.asgi, client=LAN_CLIENT)
    boot = _boot(on, client)
    item = new_item_id()
    boot.device.commit(boot.vault, {item: _item(1)})
    boot.device.commit(boot.vault, deletes=[item])
    assert len(boot.device.get("/otp/v1/vault/trash").json()["items"]) == 1
    off = make_server(make_settings(history_retention_days=0))
    off.service.maintenance()
    with closing(sqlite3.connect(off.settings.database_file)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM item_history").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM vault_versions").fetchone()[0] == 0


def test_rotation_clears_the_history(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    server, boot, client = make_boot()
    a, vault = boot.device, boot.vault
    b = second_device(server, client, boot)
    kept, gone = new_item_id(), new_item_id()
    a.commit(vault, {kept: _item(1), gone: _item(2)})
    a.commit(vault, {kept: _item(3)}, deletes=[gone])
    assert a.get("/otp/v1/vault/trash").json()["items"]
    assert a.post(f"/otp/v1/devices/{b.device_id}/revoke").status_code == 200
    payload = _rotation(boot, [a], vault, secrets.token_bytes(32))
    response = a.post("/otp/v1/vault/rotate", payload)
    assert response.status_code == 200, response.text
    # Old-epoch ciphertext does not outlive the rotation.
    assert a.get("/otp/v1/vault/trash").json()["items"] == []
    listing = a.get("/otp/v1/vault/history").json()["versions"]
    assert [(v["version"], v["kind"], v["key_epoch"]) for v in listing] == [(3, "rotate", 2)]
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM item_history").fetchone()[0] == 0
    # The current (rotated) version still answers.
    assert a.get("/otp/v1/vault/history/3").status_code == 200


def test_history_is_per_account_and_needs_a_signature(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    server, boot, client = make_boot()
    item = new_item_id()
    boot.device.commit(boot.vault, {item: _item(1)})
    boot.device.commit(boot.vault, deletes=[item])
    stranger_boot = _boot(server, client)
    stranger = stranger_boot.device
    assert stranger.get("/otp/v1/vault/history").json()["versions"] == []
    assert stranger.get("/otp/v1/vault/trash").json()["items"] == []
    # Version 1 exists for the other account, not for this one: not found, no leak.
    assert stranger.get("/otp/v1/vault/history/1").status_code == 404
    for path in ("/otp/v1/vault/history", "/otp/v1/vault/history/1", "/otp/v1/vault/trash"):
        unsigned = client.get(path)
        assert unsigned.status_code == 401
        assert unsigned.json()["code"] == "invalid_signature"


@pytest.mark.parametrize(
    "path",
    [
        "/otp/v1/vault/history/0",
        "/otp/v1/vault/history/-1",
        "/otp/v1/vault/history/abc",
        "/otp/v1/vault/history/1?item_id=not-a-uuid",
        "/otp/v1/vault/history?limit=0",
        "/otp/v1/vault/history?limit=501",
        "/otp/v1/vault/history?before=0",
        "/otp/v1/vault/history?limit=x",
    ],
)
def test_bad_parameters_are_400(bootstrapped: Bootstrapped, path: str) -> None:
    response = bootstrapped.device.get(path)
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"


def test_history_reads_are_rate_limited(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    _, boot, _ = make_boot(ratelimit_enabled=True, history_burst=3, history_rate_per_s=0.01)
    codes = [boot.device.get("/otp/v1/vault/trash").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_replayed_history_request_is_refused(bootstrapped: Bootstrapped) -> None:
    a = bootstrapped.device
    nonce = b64.encode(secrets.token_bytes(16))
    assert a.get("/otp/v1/vault/history", nonce=nonce).status_code == 200
    replay = a.get("/otp/v1/vault/history", nonce=nonce)
    assert replay.status_code == 401
    assert replay.json()["code"] == "replayed_request"


def test_a_second_device_commit_is_recorded_with_its_signer(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
) -> None:
    server, boot, client = make_boot()
    b = second_device(server, client, boot)
    boot.device.commit(boot.vault, {new_item_id(): _item(1)})
    bvault = Vault(account_id=boot.account_id, vault_key=boot.vault.vault_key)
    b.pull(bvault, boot.trusted)
    assert b.commit(bvault, {new_item_id(): _item(2)}).status_code == 200
    versions = {v["version"]: v for v in b.get("/otp/v1/vault/history").json()["versions"]}
    assert versions[1]["signed_by"] == boot.device.device_id
    assert versions[2]["signed_by"] == b.device_id


def test_background_task_prunes_without_any_request(
    make_boot: Callable[..., tuple[Server, Bootstrapped, TestClient]],
    clock: FakeClock,
) -> None:
    """The app's lifespan runs the housekeeping on its own: no commit, no CLI."""
    import time  # noqa: PLC0415

    server, boot, _ = make_boot(maintenance_interval_s=0.05)
    a, vault = boot.device, boot.vault
    item = new_item_id()
    a.commit(vault, {item: _item(1)})
    a.commit(vault, deletes=[item])
    assert len(a.get("/otp/v1/vault/trash").json()["items"]) == 1
    clock.advance(31 * DAY)
    _sync_clock(boot, clock)
    with TestClient(server.asgi, client=LAN_CLIENT):  # entering runs the lifespan
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with closing(sqlite3.connect(server.settings.database_file)) as conn:
                left = conn.execute("SELECT COUNT(*) FROM item_history").fetchone()[0]
            if left == 0:
                break
            time.sleep(0.05)
        assert left == 0
    assert a.get("/otp/v1/vault/trash").json()["items"] == []
