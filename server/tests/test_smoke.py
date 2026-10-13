# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from tests.client import new_item_id
from tests.conftest import Bootstrapped


def test_bootstrap_and_commit(bootstrapped: Bootstrapped) -> None:
    dev, vault = bootstrapped.device, bootstrapped.vault
    item = new_item_id()
    response = dev.commit(vault, {item: {"issuer": "Example", "secret_b32": "JBSWY3DPEHPK3PXP"}})
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 1
