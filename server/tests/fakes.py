# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Local stand-ins for the outside world: an SMTP relay with STARTTLS and AUTH (aiosmtpd, a
self-signed certificate) and an ntfy endpoint (http.server). Nothing leaves the machine."""

import email
import http.server
import re
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, Envelope, LoginPassword, Session

SMTP_USER = "resend"
SMTP_PASSWORD = "re_fake_api_key_for_tests_only"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def self_signed(directory: Path) -> tuple[Path, Path]:
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(  # noqa: S603 - fixed arguments, test only
        [  # noqa: S607
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


@dataclass
class Mailbox:
    messages: list[Message] = field(default_factory=list)
    logins: list[tuple[str, str]] = field(default_factory=list)
    arrived: threading.Condition = field(default_factory=threading.Condition)

    async def handle_DATA(  # noqa: N802 - aiosmtpd hook name
        self, server: Any, session: Session, envelope: Envelope
    ) -> str:
        message = email.message_from_bytes(envelope.content or b"")
        with self.arrived:
            self.messages.append(message)
            self.arrived.notify_all()
        return "250 OK"

    def authenticate(
        self, server: Any, session: Session, envelope: Envelope, mechanism: str, data: Any
    ) -> AuthResult:
        if not isinstance(data, LoginPassword):
            return AuthResult(success=False)
        user, password = data.login.decode(), data.password.decode()
        self.logins.append((user, password))
        return AuthResult(success=(user, password) == (SMTP_USER, SMTP_PASSWORD))

    def wait(self, count: int, timeout: float = 10.0) -> list[Message]:
        with self.arrived:
            self.arrived.wait_for(lambda: len(self.messages) >= count, timeout)
            return list(self.messages)

    def code_for(self, address: str) -> str:
        for message in reversed(self.messages):
            if message["To"] == address:
                match = re.search(r"\b(\d{6})\b", message.get_payload(decode=True).decode())
                if match:
                    return match.group(1)
        raise AssertionError(f"no code mailed to {address}")


@contextmanager
def smtp_relay(directory: Path) -> Iterator[tuple[Mailbox, int, Path]]:
    """STARTTLS required before AUTH, like smtp.resend.com:587."""
    cert, key = self_signed(directory)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    box = Mailbox()
    port = free_port()
    controller = Controller(
        box,
        hostname="127.0.0.1",
        port=port,
        tls_context=context,
        require_starttls=True,
        auth_require_tls=True,
        authenticator=box.authenticate,
        auth_required=True,
    )
    controller.start()
    try:
        yield box, port, cert
    finally:
        controller.stop()


@dataclass
class NtfyInbox:
    posts: list[tuple[dict[str, str], str]] = field(default_factory=list)
    arrived: threading.Condition = field(default_factory=threading.Condition)

    def wait(self, count: int, timeout: float = 10.0) -> list[tuple[dict[str, str], str]]:
        with self.arrived:
            self.arrived.wait_for(lambda: len(self.posts) >= count, timeout)
            return list(self.posts)

    def titles(self) -> list[str]:
        return [headers.get("Title", "") for headers, _ in self.posts]


@contextmanager
def ntfy_server() -> Iterator[tuple[NtfyInbox, str]]:
    inbox = NtfyInbox()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            with inbox.arrived:
                inbox.posts.append((dict(self.headers.items()), body))
                inbox.arrived.notify_all()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield inbox, f"http://127.0.0.1:{server.server_address[1]}/ultimateotp"
    finally:
        server.shutdown()
        server.server_close()
