# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""docs/monitoring: the Grafana dashboard and the Prometheus rules only use metrics the server
exposes, and the dashboard is structurally importable. (promtool itself is run by hand, see
docs/deploy.md §9; these tests need no Docker.)"""

import json
import re
from pathlib import Path
from typing import Any

import yaml

from ultimateotp.metrics import _HELP

MONITORING = Path(__file__).resolve().parents[2] / "docs" / "monitoring"
DASHBOARD: dict[str, Any] = json.loads((MONITORING / "grafana-ultimateotp.json").read_text())
RULES: dict[str, Any] = yaml.safe_load((MONITORING / "alerts.yml").read_text())


def _metric_names(text: str) -> set[str]:
    names = set(re.findall(r"\buotp_[a-z0-9_]+", text))
    return {re.sub(r"_(bucket|count|sum)$", "", n) for n in names}


def _queries() -> list[str]:
    return [t["expr"] for p in DASHBOARD["panels"] for t in p.get("targets", [])]


def test_dashboard_is_importable() -> None:
    assert DASHBOARD["title"] == "UltimateOTP"
    assert DASHBOARD["uid"] == "ultimateotp"
    assert DASHBOARD["schemaVersion"] >= 36
    inputs = {i["name"]: i for i in DASHBOARD["__inputs"]}
    assert inputs["DS_PROMETHEUS"]["pluginId"] == "prometheus"
    ids = [p["id"] for p in DASHBOARD["panels"]]
    assert len(ids) == len(set(ids))
    for panel in DASHBOARD["panels"]:
        grid = panel["gridPos"]
        assert grid["x"] >= 0
        assert grid["x"] + grid["w"] <= 24
        if panel["type"] == "row":
            continue
        assert panel["datasource"]["uid"] == "${DS_PROMETHEUS}"
        for target in panel["targets"]:
            assert target["expr"]
            assert target["datasource"]["uid"] == "${DS_PROMETHEUS}"
    assert len(_queries()) >= 20


def test_dashboard_uses_only_exposed_metrics() -> None:
    used = _metric_names("\n".join(_queries()))
    assert used
    assert used <= set(_HELP), used - set(_HELP)
    # Every panel is scoped by the job variable (the homelab Prometheus holds many jobs).
    assert all("$job" in q for q in _queries())


def test_rules_use_only_exposed_metrics_and_have_the_usual_fields() -> None:
    rules = [r for g in RULES["groups"] for r in g["rules"]]
    assert {r["alert"] for r in rules} >= {
        "UltimateOTPDown",
        "UltimateOTPAuthFailuresSpike",
        "UltimateOTPManyBlocks",
        "UltimateOTPEmailsFailing",
        "UltimateOTPStorageGrowth",
    }
    for rule in rules:
        assert rule["labels"]["severity"] in {"critical", "warning", "info"}
        assert rule["annotations"]["summary"]
        assert rule["annotations"]["description"]
    used = _metric_names("\n".join(r["expr"] for r in rules))
    assert used <= set(_HELP) | {"up"}, used - set(_HELP)


def test_no_personal_label_is_ever_queried() -> None:
    text = "\n".join(_queries()) + json.dumps(RULES)
    for label in ("client_id", "client_ip", "account_id", "device_id", "by (ip"):
        assert label not in text
