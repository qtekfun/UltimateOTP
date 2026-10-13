# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Outbound messages: emailed login codes and notices (SMTP, decision 13) and ntfy
notifications (decision 7).

Everything goes through one background worker thread, so a slow relay never delays an API
answer and the timing of a request does not reveal whether an email was sent (which would tell
an attacker whether an address has an account). Messages carry event names, device labels,
client addresses and times only: never a token, a key, a wrap, a blob or a password. The one
secret-like value ever sent is the login code itself, to the account's own address.

SMTP is STARTTLS only (Resend: smtp.resend.com:587, user `resend`, the API key as password from
a Docker secret). A relay that does not offer STARTTLS gets no credentials and no message.
"""

import logging
import queue
import smtplib
import ssl
import threading
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ultimateotp.settings import Settings

log = logging.getLogger(__name__)
_STOP = object()


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    body: str


@dataclass(frozen=True)
class Notice:
    title: str
    body: str
    tags: str = "lock"
    priority: str = "default"


class Outbox:
    """A daemon thread that sends queued messages one by one; failures are logged, not raised."""

    def __init__(self, send: Callable[[object], None]) -> None:
        self._send = send
        self._queue: queue.Queue[object] = queue.Queue(maxsize=1000)
        self._thread = threading.Thread(target=self._run, name="uotp-outbox", daemon=True)
        self._thread.start()

    def put(self, message: object) -> None:
        try:
            self._queue.put_nowait(message)
        except queue.Full:
            log.warning("outbox full: dropped one %s", type(message).__name__)

    def flush(self, timeout: float = 10.0) -> bool:
        """Waits until everything queued so far was handled (tests, the CLI before exiting)."""
        done = threading.Event()
        self.put(done)
        return done.wait(timeout)

    def _run(self) -> None:
        while True:
            message = self._queue.get()
            if isinstance(message, threading.Event):
                message.set()
                continue
            try:
                self._send(message)
            except Exception:
                log.warning("outbound %s failed", type(message).__name__, exc_info=True)


class Alerts:
    """What the service calls. Without SMTP or ntfy configured the events are only logged."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.mail_enabled = bool(settings.smtp_host and settings.smtp_from)
        self.ntfy_enabled = bool(settings.ntfy_url)
        self._outbox = Outbox(self._deliver)

    def email(self, to: str, subject: str, body: str) -> None:
        if self.mail_enabled:
            self._outbox.put(Email(to, subject, body))

    def notify(
        self, title: str, body: str, *, tags: str = "lock", priority: str = "default"
    ) -> None:
        if self.ntfy_enabled:
            self._outbox.put(Notice(title, body, tags, priority))

    def flush(self, timeout: float = 10.0) -> bool:
        return self._outbox.flush(timeout)

    def _deliver(self, message: object) -> None:
        if isinstance(message, Email):
            self._send_email(message)
        elif isinstance(message, Notice):
            self._send_ntfy(message)

    def _send_email(self, message: Email) -> None:
        s = self.settings
        mail = EmailMessage()
        mail["From"] = s.smtp_from
        mail["To"] = message.to
        mail["Subject"] = message.subject
        mail["Date"] = formatdate(localtime=False)
        mail["Message-ID"] = make_msgid(domain=s.smtp_from.rpartition("@")[2] or None)
        mail.set_content(message.body)
        context = ssl.create_default_context(cafile=str(s.smtp_ca_file) if s.smtp_ca_file else None)
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_s) as smtp:
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                raise smtplib.SMTPNotSupportedError("the relay does not offer STARTTLS")
            smtp.starttls(context=context)
            smtp.ehlo()
            if s.smtp_password is not None:
                smtp.login(s.smtp_user, s.smtp_password.get_secret_value())
            smtp.send_message(mail)
        log.info("email sent: %s", message.subject)

    def _send_ntfy(self, message: Notice) -> None:
        s = self.settings
        headers = {
            "Title": message.title,
            "Tags": message.tags,
            "Priority": message.priority,
            "Content-Type": "text/plain; charset=utf-8",
        }
        if s.ntfy_token is not None:
            headers["Authorization"] = "Bearer " + s.ntfy_token.get_secret_value()
        request = urllib.request.Request(  # noqa: S310 - the URL is the owner's, http(s) only
            s.ntfy_url, data=message.body.encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            response.read()
        log.info("ntfy sent: %s", message.title)
