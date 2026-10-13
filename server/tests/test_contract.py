# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The implementation matches contracts/openapi.yaml: same routes, and real responses validate
against the contract's schemas."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from openapi_schema_validator import OAS31Validator
from openapi_spec_validator import validate

from tests.client import Device, new_item_id, seal_for
from tests.conftest import Bootstrapped, Server, second_device
from ultimateotp import API_VERSION, b64, routes, signing

CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml"
SPEC: dict[str, Any] = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def check(body: Any, schema: str) -> None:
    validator = OAS31Validator(
        {"$ref": f"#/components/schemas/{schema}", "components": SPEC["components"]}
    )
    errors = [e.message for e in validator.iter_errors(body)]
    assert not errors, (schema, errors)


def test_contract_is_valid_openapi() -> None:
    validate(SPEC)
    assert SPEC["info"]["version"] == API_VERSION


def test_routes_match_the_contract() -> None:
    implemented = {
        (method.lower(), route.path)
        for router in (routes.router, routes.probes)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods
        if method != "HEAD"
    }
    documented = {
        (method, path)
        for path, item in SPEC["paths"].items()
        for method in item
        if method in {"get", "post", "put", "delete", "patch"}
    }
    assert implemented == documented


def test_problem_codes_are_documented() -> None:
    codes = set(SPEC["components"]["schemas"]["Problem"]["properties"]["code"]["enum"])
    source = (Path(__file__).resolve().parents[1] / "src" / "ultimateotp").rglob("*.py")
    import re  # noqa: PLC0415

    used = set()
    for path in source:
        text = path.read_text(encoding="utf-8")
        used |= set(re.findall(r'ApiError\(\s*\d{3},\s*"([a-z_]+)"', text))
        used |= set(re.findall(r'_unauthorized\("([a-z_]+)"', text))
    assert used, "no codes found"
    assert used <= codes, used - codes


def test_responses_validate(server: Server, lan: TestClient, bootstrapped: Bootstrapped) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    check(lan.get("/otp/v1/server-info").json(), "ServerInfo")
    check(a.get("/otp/v1/account/keys").json(), "AccountKeys")
    check(a.get("/otp/v1/devices").json(), "DeviceList")
    check(a.post("/otp/v1/enrollment-tokens").json(), "EnrollmentToken")
    item = new_item_id()
    check(a.commit(vault, {item: {"issuer": "x"}}).json(), "VaultHead")
    check(a.commit(vault, deletes=[item]).json(), "VaultHead")
    check(a.get("/otp/v1/vault?since=0").json(), "VaultChanges")

    token, _ = server.service.create_token(bootstrapped.account_id)
    recovery = lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
    check(recovery.json(), "RecoveryKeys")
    b = Device(lan)
    check(b.enroll(token).json(), "EnrollResponse")

    pairing = a.post("/otp/v1/pairings").json()
    check(pairing, "PairingCreated")
    c = Device(lan)
    joined = c.post(
        f"/otp/v1/pairings/{pairing['pairing_id']}/join",
        {"ed25519_public_key": c.ed25519, "x25519_public_key": c.x25519, "label": "C"},
        bearer=pairing["secret"],
    ).json()
    check(joined, "JoinResponse")
    check(a.get(f"/otp/v1/pairings/{pairing['pairing_id']}").json(), "Pairing")
    result = c.get(
        f"/otp/v1/pairings/{pairing['pairing_id']}/result",
        bearer=pairing["secret"],
        device=joined["device_id"],
    )
    check(result.json(), "PairingResult")
    sealed = seal_for(c.x25519, vault.vault_key, bootstrapped.account_id, 1)
    approved = a.post(
        f"/otp/v1/pairings/{pairing['pairing_id']}/approve",
        {
            "device_id": joined["device_id"],
            "device_signature": a.sign(
                signing.device_message(
                    bootstrapped.account_id, joined["device_id"], c.ed25519, c.x25519
                )
            ),
            "sealed_vault_key": b64.encode(sealed),
            "seal_signature": a.sign(
                signing.seal_message(bootstrapped.account_id, 1, joined["device_id"], sealed)
            ),
        },
    )
    check(approved.json(), "Device")
    result = c.get(
        f"/otp/v1/pairings/{pairing['pairing_id']}/result",
        bearer=pairing["secret"],
        device=joined["device_id"],
    )
    check(result.json(), "PairingResult")
    check(a.post(f"/otp/v1/devices/{b.device_id}/revoke").json(), "Device")
    rejected = a.post("/otp/v1/pairings").json()
    check(a.post(f"/otp/v1/pairings/{rejected['pairing_id']}/reject").json(), "Pairing")


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/otp/v1/devices"), ("post", "/otp/v1/vault/commit"), ("get", "/nope")],
)
def test_problems_validate(lan: TestClient, method: str, path: str) -> None:
    response = lan.request(method.upper(), path)
    assert response.headers["content-type"] == "application/problem+json"
    check(response.json(), "Problem")


def test_conflict_problem_carries_the_head(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    b = second_device(server, lan, bootstrapped)
    from tests.client import Vault  # noqa: PLC0415

    bootstrapped.device.commit(bootstrapped.vault, {new_item_id(): {"x": 1}})
    stale = Vault(account_id=bootstrapped.account_id, vault_key=bootstrapped.vault.vault_key)
    problem = b.commit(stale, {new_item_id(): {"x": 2}}).json()
    check(problem, "Problem")
    check(problem["head"], "VaultHead")
