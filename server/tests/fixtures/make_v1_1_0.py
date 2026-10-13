# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Builds `v1_1_0.sql` and `v1_1_0.json`: a database exactly as the 1.1.0 server (commit d5db3a0,
migration 0001 only) leaves it, with data a deployed server would have.

Run it against a checkout of that commit, never against this tree:

    git archive d5db3a0 server contracts | tar -x -C /tmp/v110
    cd /tmp/v110/server && PYTHONPATH=src:. python /path/to/make_v1_1_0.py OUT_DIR

The test `tests/test_migration.py` loads the SQL, applies the migrations of this tree and checks
that nothing was lost. The JSON holds what a client of that account would have kept (device
keys, vault key, password); it is test data with no value.
"""

import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from tests.client import Device, Vault, new_item_id
from ultimateotp import db
from ultimateotp.app import create_app
from ultimateotp.settings import Settings

PASSWORD = "legacy fixture password"
EMAIL = "legacy@example.org"
RECOVERY_KEY = bytes(range(32))


def main(out: Path) -> None:
    root = Path.cwd().parent
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            data_dir=Path(tmp),
            migrations_dir=root / "contracts" / "db" / "migrations",
            ratelimit_enabled=False,
            email_verification="disabled",
        )
        db.migrate(settings.database_file, settings.migrations_dir)
        app = create_app(settings)
        service = app.fastapi.state.service
        account_id, token, _ = service.create_account(EMAIL, email_check=False)
        lan = TestClient(app, client=("192.168.1.10", 51000))
        device = Device(lan, "Legacy phone")
        vault = Vault(account_id=account_id)
        assert device.enroll(token, vault.key_bundle(PASSWORD, RECOVERY_KEY)).status_code == 201
        keep, edited, deleted = new_item_id(), new_item_id(), new_item_id()
        assert device.commit(vault, {keep: {"issuer": "Keep"}, edited: {"issuer": "v1"}}).is_success
        assert device.commit(
            vault, {edited: {"issuer": "v2"}, deleted: {"issuer": "Gone"}}
        ).is_success
        assert device.commit(vault, deletes=[deleted]).is_success
        public = TestClient(app, client=("203.0.113.7", 51000))
        laptop = Device(public, "Legacy laptop")
        assert laptop.srp_login(EMAIL, PASSWORD).status_code == 201
        assert device.post(f"/otp/v1/devices/{laptop.device_id}/revoke").status_code == 200
        service.create_token(account_id)  # an unused enrollment token
        # Make sure every last_ip carries a raw address, as 1.1.0 stored them.
        with closing(sqlite3.connect(settings.database_file)) as conn:
            conn.execute(
                "UPDATE devices SET last_ip = '192.168.1.10' WHERE id = ?", (device.device_id,)
            )
            conn.execute(
                "UPDATE devices SET last_ip = '203.0.113.7' WHERE id = ?", (laptop.device_id,)
            )
            conn.commit()
            statements = "\n".join(conn.iterdump())
        (out / "v1_1_0.sql").write_text(statements + "\n", encoding="utf-8")
        (out / "v1_1_0.json").write_text(
            json.dumps(
                {
                    "email": EMAIL,
                    "password": PASSWORD,
                    "account_id": account_id,
                    "vault_key": vault.vault_key.hex(),
                    "key_epoch": vault.key_epoch,
                    "version": vault.version,
                    "device_id": device.device_id,
                    "ed25519_seed": bytes(device.signing_key).hex(),
                    "x25519_seed": bytes(device.box_key).hex(),
                    "revoked_device_id": laptop.device_id,
                    "live_items": dict(vault.plaintext),
                    "deleted_item": deleted,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
