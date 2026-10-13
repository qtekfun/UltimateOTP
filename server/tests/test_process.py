# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The real `ultimateotp` process, started the way CI and the Android contract tests start it.

Every other test builds the ASGI app in-process. These start `python -m ultimateotp migrate` and
`api` as separate processes with only `UOTP_*` environment variables, so a broken entry point,
settings parsing or migration path fails here and not in the Android job.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.conftest import MIGRATIONS

STARTUP_S = 20


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _env(tmp_path: Path, port: int, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("UOTP_")}
    env.update(
        UOTP_DATA_DIR=str(tmp_path),
        UOTP_MIGRATIONS_DIR=str(MIGRATIONS),
        UOTP_HOST="127.0.0.1",
        UOTP_PORT=str(port),
        UOTP_LOG_LEVEL="WARNING",
        UOTP_RATELIMIT_ENABLED="false",
        **extra,
    )
    return env


def _get(url: str) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - loopback
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


@pytest.fixture
def api(tmp_path: Path) -> Iterator[tuple[str, subprocess.Popen[bytes]]]:
    port = _free_port()
    env = _env(tmp_path, port, UOTP_SIGNUP="enabled", UOTP_EMAIL_VERIFICATION="disabled")
    subprocess.run(
        [sys.executable, "-m", "ultimateotp", "migrate"], env=env, check=True, timeout=60
    )
    process = subprocess.Popen([sys.executable, "-m", "ultimateotp", "api"], env=env)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + STARTUP_S
        while True:
            assert process.poll() is None, "the api exited during startup"
            try:
                if _get(f"{url}/readyz")[0] == 200:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, "the api did not become ready"
            time.sleep(0.1)
        yield url, process
    finally:
        process.terminate()
        process.wait(timeout=10)


def _contract_version() -> str:
    """`info.version` of contracts/openapi.yaml: the one place the API version is written."""
    text = (Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml").read_text()
    match = re.search(r"^info:\n(?:[ ]+.*\n)*?[ ]+version:\s*['\"]?([0-9][^'\"\s]*)", text, re.M)
    assert match, "no info.version in contracts/openapi.yaml"
    return match.group(1)


def test_api_process_serves_the_contract_routes(api: tuple[str, subprocess.Popen[bytes]]) -> None:
    url, _ = api
    status, info = _get(f"{url}/otp/v1/server-info")
    assert status == 200
    assert info["api_version"] == _contract_version()
    # Unknown account: attributes are a decoy, never a 404 that reveals who has an account.
    request = urllib.request.Request(  # noqa: S310
        f"{url}/otp/v1/srp/attributes",
        data=json.dumps({"email": "nobody@example.org"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        assert response.status == 200
        attributes = json.loads(response.read())
    assert {"srp_user_id", "srp_salt", "password_kdf"} <= set(attributes)
    assert attributes["email_code_required"] is False  # verification is disabled in this process


def test_api_process_stops_on_sigterm(api: tuple[str, subprocess.Popen[bytes]]) -> None:
    _, process = api
    process.terminate()
    # uvicorn finishes its graceful shutdown, then re-raises the signal: -SIGTERM, not -SIGKILL.
    assert process.wait(timeout=10) in (0, -signal.SIGTERM)
