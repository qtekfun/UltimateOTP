# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Password login from anywhere, the Ente way (decisions 6, 8 and 13).

A new device signs in with: (1) a 6-digit code emailed to the account's address, (2) an SRP-6a
proof of the password. Only then does the server release the wrapped vault key and register the
device's Ed25519 key, in the same request. The server stores the SRP verifier, never anything that
logs in by itself; the emailed code is stored as a salted SHA-256.

Unknown addresses get decoy answers (deterministic attributes from a server-side HMAC key, a
handshake that always fails), so the routes do not tell who has an account. Email sending is
asynchronous for the same reason. Lockout: after `UOTP_SRP_LOCKOUT_THRESHOLD` consecutive wrong
proofs the account refuses handshakes for base * 2^(n - threshold) seconds, capped.
"""

import hashlib
import hmac
import logging
import secrets
import sqlite3
from typing import TYPE_CHECKING, Any

from ultimateotp import anon, b64, i18n, ids, srp
from ultimateotp.errors import ApiError
from ultimateotp.models import (
    SignupRequest,
    SrpSessionRequest,
    SrpVerifyRequest,
)

if TYPE_CHECKING:
    from ultimateotp.service import Service, SignedRequest

GROUP = srp.GROUP_4096
SRP_SESSION_PREFIX = "srp_"
DECOY_KEY = "decoy-srp-attributes"
# The decoy KDF parameters: the writer defaults of crypto-format §4.1 (ops 4, 1 GiB).
DECOY_OPSLIMIT = 4
DECOY_MEMLIMIT = 1 << 30
CODE_DIGITS = 6


def hash_code(salt: bytes, code: str) -> str:
    return hashlib.sha256(salt + code.encode("ascii")).hexdigest()


def _int(value_b64: str) -> int:
    return int.from_bytes(b64.decode(value_b64), "big")


class Login:
    def __init__(self, service: "Service") -> None:
        self.service = service
        self.settings = service.settings
        self.clock = service.clock
        self.db = service.db

    # ------------------------------------------------------------ email codes

    def _account_by_email(self, conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = conn.execute(
            "SELECT * FROM accounts WHERE email = ?", (email,)
        ).fetchone()
        return row

    def issue_code(self, conn: sqlite3.Connection, email: str) -> str:
        code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
        salt = secrets.token_bytes(16)
        now = self.clock.now()
        conn.execute("DELETE FROM email_codes WHERE email = ?", (email,))
        conn.execute(
            "INSERT INTO email_codes (email, salt, code_hash, created_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (email, salt.hex(), hash_code(salt, code), now, now + self.settings.email_code_ttl_s),
        )
        return code

    def send_code(
        self, email: str, code: str, lang: str = i18n.DEFAULT, template: str = "login_code"
    ) -> None:
        subject, body = i18n.render(
            lang, template, code=code, minutes=self.settings.email_code_ttl_s // 60
        )
        self.service.alerts.email(email, subject, body)

    def request_code(self, email: str, lang: str | None = None) -> None:
        """Sends a code when the address has an account (or may sign up). Always silent."""
        if not self.settings.email_enabled:
            return
        with self.db.write() as conn:
            account = self._account_by_email(conn, email)
            if account is None and self.settings.signup != "enabled":
                code = None
            else:
                code = self.issue_code(conn, email)
        known = account is not None
        self.service.event("email.code_requested", known=known)
        if account is None and code is None:
            # Asking for a code for an address nobody has: a probe, counted toward a block.
            self.service.event("login.unknown_account", stage="email_code")
        if code is not None:
            stored = account["lang"] if account is not None else None
            self.send_code(email, code, self.service.language(lang, stored))

    def check_code(self, email: str, code: str | None) -> bool:
        """Consumes the code when right; counts a wrong attempt in its own transaction, so the
        count survives the error the caller raises next."""
        now = self.clock.now()
        with self.db.write() as conn:
            row = conn.execute("SELECT * FROM email_codes WHERE email = ?", (email,)).fetchone()
            if row is None or row["expires_at"] < now:
                return False
            if row["attempts"] >= self.settings.email_code_max_attempts or code is None:
                return False
            expected = row["code_hash"]
            if hmac.compare_digest(expected, hash_code(bytes.fromhex(row["salt"]), code)):
                conn.execute("DELETE FROM email_codes WHERE email = ?", (email,))
                return True
            conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE email = ?", (email,))
        return False

    def require_code(self, email: str, code: str | None) -> None:
        if not self.check_code(email, code):
            self.service.event("email.code_failure", level=logging.WARNING)
            self.service.metrics.inc("uotp_logins_total", result="email_code_failure")
            raise ApiError(401, "invalid_email_code", "missing, wrong, used or expired code")

    # ------------------------------------------------------------ SRP

    def _decoy_key(self) -> bytes:
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT secret FROM server_secrets WHERE name = ?", (DECOY_KEY,)
            ).fetchone()
            if row is None:
                secret = secrets.token_bytes(32)
                conn.execute(
                    "INSERT INTO server_secrets (name, secret, created_at) VALUES (?, ?, ?)",
                    (DECOY_KEY, secret.hex(), self.clock.now()),
                )
                return secret
        return bytes.fromhex(row["secret"])

    def _decoy(self, email: str) -> dict[str, Any]:
        digest = hmac.new(self._decoy_key(), email.encode(), hashlib.sha256).digest()
        params = bytes([2]) + DECOY_OPSLIMIT.to_bytes(4, "big") + DECOY_MEMLIMIT.to_bytes(8, "big")
        uid = digest[:16].hex()
        return {
            "srp_user_id": f"{uid[:8]}-{uid[8:12]}-4{uid[13:16]}-8{uid[17:20]}-{uid[20:32]}",
            "srp_salt": b64.encode(digest[16:32]),
            "password_kdf": b64.encode(params + digest[:16]),
            "email_code_required": self.settings.email_enabled,
        }

    def _code_required(self, account: sqlite3.Row) -> bool:
        return self.settings.email_enabled and bool(account["email_check"])

    def attributes(self, email: str) -> dict[str, Any]:
        with self.db.read() as conn:
            account = self._account_by_email(conn, email)
        if account is None or account["srp_verifier"] is None or account["password_kdf"] is None:
            return self._decoy(email)
        return {
            "srp_user_id": account["srp_user_id"],
            "srp_salt": account["srp_salt"],
            "password_kdf": account["password_kdf"],
            "email_code_required": self._code_required(account),
        }

    def start(self, body: SrpSessionRequest) -> dict[str, Any]:
        big_a = _int(body.srp_a)
        if not srp.valid_public(GROUP, big_a):
            raise ApiError(400, "invalid_request", "srp_a out of range")
        now = self.clock.now()
        with self.db.read() as conn:
            account = self._account_by_email(conn, body.email)
        usable = account is not None and account["srp_verifier"] is not None
        if account is not None and (account["srp_locked_until"] or 0) > now:
            retry = int(account["srp_locked_until"] - now)
            self.service.event("srp.locked", level=logging.WARNING, account_id=account["id"])
            self.service.metrics.inc("uotp_logins_total", result="locked")
            raise ApiError(429, "account_locked", "too many failed logins", retry_after=retry)
        need_code = self.settings.email_enabled and (
            account is None or not usable or bool(account["email_check"])
        )
        if need_code:
            self.require_code(body.email, body.email_code)
        elif not usable:
            self.service.event("login.unknown_account", stage="srp_session")
        if usable and account is not None:
            verifier = _int(account["srp_verifier"])
        else:
            verifier = pow(GROUP.g, int.from_bytes(self._decoy_key(), "big"), GROUP.N)
        b = srp.new_ephemeral()
        big_b = srp.server_public(GROUP, verifier, b)
        session_id = SRP_SESSION_PREFIX + b64.encode(secrets.token_bytes(16))
        with self.db.write() as conn:
            conn.execute("DELETE FROM srp_sessions WHERE expires_at < ?", (now,))
            conn.execute(
                "INSERT INTO srp_sessions (id, account_id, email, srp_a, srp_b_secret,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    account["id"] if usable and account is not None else None,
                    body.email,
                    body.srp_a,
                    format(b, "x"),
                    now,
                    now + self.settings.srp_session_ttl_s,
                ),
            )
        self.service.event("srp.session")
        return {"session_id": session_id, "srp_b": b64.encode(GROUP.pad(big_b))}

    def failed(self, account_id: str | None) -> ApiError:
        """Counts a wrong proof and locks the account past the threshold."""
        self.service.metrics.inc("uotp_logins_total", result="srp_failure")
        if account_id is None:
            self.service.event("srp.failure", level=logging.WARNING)
            return ApiError(401, "srp_failed", "wrong email, password or session")
        s = self.settings
        now = self.clock.now()
        with self.db.write() as conn:
            conn.execute(
                "UPDATE accounts SET srp_failures = srp_failures + 1 WHERE id = ?", (account_id,)
            )
            failures = int(
                conn.execute(
                    "SELECT srp_failures FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()[0]
            )
            locked_for = 0
            if failures >= s.srp_lockout_threshold:
                exponent = min(failures - s.srp_lockout_threshold, 32)
                locked_for = min(s.srp_lockout_max_s, s.srp_lockout_base_s * 2**exponent)
                conn.execute(
                    "UPDATE accounts SET srp_locked_until = ? WHERE id = ?",
                    (now + locked_for, account_id),
                )
        self.service.event(
            "srp.failure",
            level=logging.WARNING,
            account_id=account_id,
            failures=failures,
        )
        if locked_for:
            self.service.event(
                "srp.lockout",
                level=logging.WARNING,
                account_id=account_id,
                failures=failures,
                locked_for_s=locked_for,
            )
            self.service.metrics.inc("uotp_lockouts_total")
            client = anon.current()
            self.service.alerts.notify(
                "UltimateOTP: repeated failed logins",
                f"{failures} wrong passwords in a row for account {account_id}, last from "
                f"client {client.client_id if client else 'unknown'}. Logins are locked for "
                f"{locked_for} s.",
                tags="warning",
                priority="high",
            )
        return ApiError(401, "srp_failed", "wrong email, password or session")

    def verify(self, body: SrpVerifyRequest, req: "SignedRequest") -> dict[str, Any]:
        # The timestamp window first: a phone whose clock is off gets `stale_request` with the
        # server time and retries, so the handshake must not be consumed nor counted yet.
        self.service.check_window(req)
        now = self.clock.now()
        with self.db.write() as conn:
            session = conn.execute(
                "SELECT * FROM srp_sessions WHERE id = ?", (body.session_id,)
            ).fetchone()
            conn.execute("DELETE FROM srp_sessions WHERE id = ?", (body.session_id,))
        # A re-authentication handshake (account.py) is never good for registering a device.
        if session is None or session["expires_at"] < now or session["purpose"] != "login":
            raise self.failed(None)
        account_id = session["account_id"]
        with self.db.read() as conn:
            account = (
                conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
                if account_id
                else None
            )
        if account is None or account["srp_verifier"] is None:
            raise self.failed(None)
        m2 = srp.server_verify(
            GROUP,
            account["srp_user_id"].encode("ascii"),
            b64.decode(account["srp_salt"]),
            _int(account["srp_verifier"]),
            _int(session["srp_a"]),
            int(session["srp_b_secret"], 16),
            b64.decode(body.srp_m1),
        )
        if m2 is None:
            raise self.failed(account["id"])
        with self.db.write() as conn:
            conn.execute(
                "UPDATE accounts SET srp_failures = 0, srp_locked_until = NULL WHERE id = ?",
                (account["id"],),
            )
        with self.db.write() as conn:
            result = self.service.register_device(
                account["id"], body.device, req, via="password", conn=conn
            )
        self.service.after_register(account["id"], result, req)
        self.service.event(
            "srp.success", account_id=account["id"], device_id=result["device"]["device_id"]
        )
        self.service.metrics.inc("uotp_logins_total", result="success")
        with self.db.read() as conn:
            keys = self.service.key_attributes(conn, account["id"])
        return {"srp_m2": b64.encode(m2), **result, "keys": keys}

    # ------------------------------------------------------------ sign-up (off by default)

    def signup(self, body: SignupRequest, req: "SignedRequest") -> dict[str, Any]:
        if self.settings.signup != "enabled":
            raise ApiError(403, "signup_disabled", "accounts are created with the admin CLI")
        self.service.check_window(req)  # before the emailed code is consumed
        if body.keys.srp is None or body.keys.password_wrap is None:
            raise ApiError(400, "keys_required", "sign-up needs the password wraps and SRP")
        if self.settings.email_enabled:
            self.require_code(body.email, body.email_code)
        account_id = ids.new_account_id()
        lang = self.service.language(body.lang)
        now = self.clock.now()
        with self.db.write() as conn:
            if self._account_by_email(conn, body.email) is not None:
                raise ApiError(409, "email_taken")
            conn.execute(
                "INSERT INTO accounts (id, created_at, email, email_verified_at, lang)"
                " VALUES (?, ?, ?, ?, ?)",
                (account_id, now, body.email, now if self.settings.email_enabled else None, lang),
            )
            self.service.store_bundle(conn, account_id, body.keys)
            # Same transaction: a bad proof of possession leaves no account behind.
            result = self.service.register_device(
                account_id, body.device, req, via="signup", conn=conn
            )
        self.service.event("signup.success", account_id=account_id)
        self.service.metrics.inc("uotp_signups_total")
        self.service.after_register(account_id, result, req)
        return result
