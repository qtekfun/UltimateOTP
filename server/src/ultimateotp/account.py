# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Account management for a signed-in device (contract 1.2.0, docs/deploy.md §7).

Delete the account, change its email, sign out every other device, export everything. The
dangerous ones (delete, change email) need a fresh proof next to the device signature, so a stolen
unlocked device alone cannot do them: the code emailed to the account's own address, or the SRP
password proof of a handshake for this account. Every action is audited as a security event and
notified by email (in the account's language) and ntfy; none of them ever sees plaintext.
"""

import hmac
import logging
import secrets
import sqlite3
from typing import TYPE_CHECKING, Any

from ultimateotp import b64, srp
from ultimateotp.errors import ApiError
from ultimateotp.events import Event
from ultimateotp.login import GROUP, SRP_SESSION_PREFIX, hash_code
from ultimateotp.models import (
    ChangeEmailRequest,
    ConfirmEmailRequest,
    DeleteAccountRequest,
    Reauth,
    ReauthSrpRequest,
)

if TYPE_CHECKING:
    from ultimateotp.service import DeviceAuth, Service

REAUTH_PURPOSE = "reauth"
EXPORT_FORMAT = "ultimateotp-server-export-1"
CODE_DIGITS = 6
ID_CHUNK = 500


class AccountManager:
    def __init__(self, service: "Service") -> None:
        self.service = service
        self.settings = service.settings
        self.clock = service.clock
        self.db = service.db

    # ------------------------------------------------------------------ re-authentication

    def _row(self, conn: sqlite3.Connection, auth: "DeviceAuth") -> sqlite3.Row:
        return self.service._account(conn, auth.account_id)

    def request_reauth_code(self, auth: "DeviceAuth") -> None:
        """Emails a fresh code to the account's address. Always silent: with no address on file
        (or email verification off) nothing is sent and the proof cannot be given this way."""
        with self.db.write() as conn:
            account = self._row(conn, auth)
            email = account["email"]
            code = None
            if email and self.settings.email_enabled:
                code = self.service.login.issue_code(conn, email)
        self.service.event(
            "account.reauth_code_requested", account_id=auth.account_id, device_id=auth.device_id
        )
        if code is not None:
            self.service.login.send_code(
                email,
                code,
                self.service.language(None, account["lang"]),
                template="reauth_code",
            )

    def reauth_srp_start(self, auth: "DeviceAuth", body: ReauthSrpRequest) -> dict[str, Any]:
        big_a = int.from_bytes(b64.decode(body.srp_a), "big")
        if not srp.valid_public(GROUP, big_a):
            raise ApiError(400, "invalid_request", "srp_a out of range")
        now = self.clock.now()
        with self.db.read() as conn:
            account = self._row(conn, auth)
        if account["srp_verifier"] is None or account["password_kdf"] is None:
            raise ApiError(409, "srp_unavailable", "this account has no password record")
        if (account["srp_locked_until"] or 0) > now:
            self.service.event("srp.locked", level=logging.WARNING, account_id=account["id"])
            self.service.metrics.inc("uotp_logins_total", result="locked")
            raise ApiError(
                429,
                "account_locked",
                "too many failed logins",
                retry_after=int(account["srp_locked_until"] - now),
            )
        b = srp.new_ephemeral()
        big_b = srp.server_public(
            GROUP, int.from_bytes(b64.decode(account["srp_verifier"]), "big"), b
        )
        session_id = SRP_SESSION_PREFIX + b64.encode(secrets.token_bytes(16))
        with self.db.write() as conn:
            conn.execute("DELETE FROM srp_sessions WHERE expires_at < ?", (now,))
            conn.execute(
                "INSERT INTO srp_sessions (id, account_id, email, srp_a, srp_b_secret, created_at,"
                " expires_at, purpose) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    account["id"],
                    account["email"] or "",
                    body.srp_a,
                    format(b, "x"),
                    now,
                    now + self.settings.srp_session_ttl_s,
                    REAUTH_PURPOSE,
                ),
            )
        self.service.event(
            "account.reauth_srp_started", account_id=auth.account_id, device_id=auth.device_id
        )
        return {
            "session_id": session_id,
            "srp_b": b64.encode(GROUP.pad(big_b)),
            "srp_user_id": account["srp_user_id"],
            "srp_salt": account["srp_salt"],
            "password_kdf": account["password_kdf"],
        }

    def verify_reauth(self, auth: "DeviceAuth", reauth: Reauth) -> None:
        """Raises unless `reauth` is a valid fresh proof for this account (single use)."""
        login = self.service.login
        if (reauth.email_code is None) == (reauth.srp is None):
            raise ApiError(400, "invalid_request", "reauth: exactly one of email_code and srp")
        if reauth.email_code is not None:
            with self.db.read() as conn:
                email = self._row(conn, auth)["email"]
            login.require_code(email or "", reauth.email_code)
            return
        proof = reauth.srp
        if proof is None:  # unreachable: exactly one of the two was checked above
            raise ApiError(400, "invalid_request", "reauth: exactly one of email_code and srp")
        now = self.clock.now()
        with self.db.write() as conn:
            session = conn.execute(
                "SELECT * FROM srp_sessions WHERE id = ?", (proof.session_id,)
            ).fetchone()
            conn.execute("DELETE FROM srp_sessions WHERE id = ?", (proof.session_id,))
            account = self.service._account(conn, auth.account_id)
        if (
            session is None
            or session["purpose"] != REAUTH_PURPOSE
            or session["account_id"] != auth.account_id
            or session["expires_at"] < now
            or account["srp_verifier"] is None
        ):
            raise login.failed(None)
        m2 = srp.server_verify(
            GROUP,
            account["srp_user_id"].encode("ascii"),
            b64.decode(account["srp_salt"]),
            int.from_bytes(b64.decode(account["srp_verifier"]), "big"),
            int.from_bytes(b64.decode(session["srp_a"]), "big"),
            int(session["srp_b_secret"], 16),
            b64.decode(proof.srp_m1),
        )
        if m2 is None:
            raise login.failed(account["id"])
        with self.db.write() as conn:
            conn.execute(
                "UPDATE accounts SET srp_failures = 0, srp_locked_until = NULL WHERE id = ?",
                (account["id"],),
            )

    # ------------------------------------------------------------------ delete

    def delete_account(self, auth: "DeviceAuth", body: DeleteAccountRequest) -> dict[str, Any]:
        self.verify_reauth(auth, body.reauth)
        now = self.clock.now()
        with self.db.write() as conn:
            account = self._row(conn, auth)
            email, lang = account["email"], account["lang"]
            devices = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM devices WHERE account_id = ?", (auth.account_id,)
                )
            ]
            removed = {
                "devices": len(devices),
                "items": self._count(conn, "items", auth.account_id),
                "history_versions": self._count(conn, "vault_versions", auth.account_id),
                "history_items": self._count(conn, "item_history", auth.account_id),
            }
            for start in range(0, len(devices), ID_CHUNK):
                chunk = devices[start : start + ID_CHUNK]
                marks = ",".join("?" * len(chunk))
                conn.execute(
                    f"DELETE FROM request_nonces WHERE signer IN ({marks})",  # noqa: S608
                    chunk,
                )
            if email:
                conn.execute("DELETE FROM email_codes WHERE email = ?", (email,))
                conn.execute("DELETE FROM srp_sessions WHERE email = ?", (email,))
            # Foreign keys cascade: devices, wraps, items, history, tokens, pairings, handshakes.
            conn.execute("DELETE FROM accounts WHERE id = ?", (auth.account_id,))
        self.service.event(
            "account.deleted",
            level=logging.WARNING,
            account_id=auth.account_id,
            device_id=auth.device_id,
            **{f"removed_{key}": value for key, value in removed.items()},
        )
        self.service.metrics.inc("uotp_account_actions_total", action="delete")
        self.service.broker.publish(auth.account_id, Event("account_deleted", {}))
        self.service.alerts.notify(
            "UltimateOTP: account deleted",
            f"Account {auth.account_id} and all its data were deleted from device"
            f" {auth.device_id}.",
            tags="warning",
            priority="high",
        )
        if email:
            self.service.notice_to(email, "account_deleted", self.service.language(None, lang))
        return {
            "status": "deleted",
            "account_id": auth.account_id,
            "deleted_at": now,
            "removed": removed,
        }

    @staticmethod
    def _count(conn: sqlite3.Connection, table: str, account_id: str) -> int:
        row = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE account_id = ?", (account_id,))  # noqa: S608 - fixed names
        return int(row.fetchone()[0])

    # ------------------------------------------------------------------ change email

    def change_email(self, auth: "DeviceAuth", body: ChangeEmailRequest) -> dict[str, Any]:
        self.verify_reauth(auth, body.reauth)
        now = self.clock.now()
        expires = now + self.settings.email_code_ttl_s
        new = body.new_email
        code = None
        with self.db.write() as conn:
            account = self._row(conn, auth)
            old = account["email"]
            taken = conn.execute(
                "SELECT 1 FROM accounts WHERE email = ? AND id != ?", (new, auth.account_id)
            ).fetchone()
            if not taken and new != old:
                code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
                salt = secrets.token_bytes(16)
                conn.execute(
                    "INSERT OR REPLACE INTO email_changes (account_id, new_email, salt, code_hash,"
                    " created_at, expires_at, attempts) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (auth.account_id, new, salt.hex(), hash_code(salt, code), now, expires),
                )
        lang = self.service.language(body.lang, account["lang"])
        self.service.event(
            "account.email_change_requested",
            level=logging.WARNING,
            account_id=auth.account_id,
            device_id=auth.device_id,
            sent=code is not None,
        )
        self.service.metrics.inc("uotp_account_actions_total", action="email_change_request")
        if code is not None:
            self.service.login.send_code(new, code, lang, template="email_change_code")
            if old:
                self.service.notice_to(old, "email_change_requested", lang, new_email=new)
            self.service.alerts.notify(
                "UltimateOTP: email change requested",
                f"A change of the login email of account {auth.account_id} was requested"
                f" from device {auth.device_id}.",
                tags="warning",
            )
        return {"status": "pending", "expires_at": expires}

    def confirm_email(self, auth: "DeviceAuth", body: ConfirmEmailRequest) -> dict[str, Any]:
        now = self.clock.now()
        max_attempts = self.settings.email_code_max_attempts
        ok = False
        with self.db.write() as conn:
            account = self._row(conn, auth)
            row = conn.execute(
                "SELECT * FROM email_changes WHERE account_id = ?", (auth.account_id,)
            ).fetchone()
            if row is not None and row["expires_at"] >= now and row["attempts"] < max_attempts:
                expected = row["code_hash"]
                if hmac.compare_digest(expected, hash_code(bytes.fromhex(row["salt"]), body.code)):
                    ok = True
                else:
                    conn.execute(
                        "UPDATE email_changes SET attempts = attempts + 1 WHERE account_id = ?",
                        (auth.account_id,),
                    )
        if not ok or row is None:
            self.service.event("email.code_failure", level=logging.WARNING)
            self.service.metrics.inc("uotp_logins_total", result="email_code_failure")
            raise ApiError(401, "invalid_email_code", "missing, wrong, used or expired code")
        new, old = row["new_email"], account["email"]
        try:
            with self.db.write() as conn:
                conn.execute(
                    "UPDATE accounts SET email = ?, email_verified_at = ? WHERE id = ?",
                    (new, now, auth.account_id),
                )
                conn.execute("DELETE FROM email_changes WHERE account_id = ?", (auth.account_id,))
                if old:
                    conn.execute("DELETE FROM email_codes WHERE email = ?", (old,))
        except sqlite3.IntegrityError:
            raise ApiError(409, "email_taken", "that address is used by another account") from None
        self.service.event(
            "account.email_changed",
            level=logging.WARNING,
            account_id=auth.account_id,
            device_id=auth.device_id,
        )
        self.service.metrics.inc("uotp_account_actions_total", action="email_changed")
        lang = self.service.language(None, account["lang"])
        if old:
            self.service.notice_to(old, "email_changed_old", lang, new_email=new)
        self.service.notice_to(new, "email_changed_new", lang)
        self.service.alerts.notify(
            "UltimateOTP: login email changed",
            f"The login email of account {auth.account_id} was changed from device"
            f" {auth.device_id}.",
            tags="warning",
            priority="high",
        )
        return {"account_id": auth.account_id, "email": new}

    # ------------------------------------------------------------------ sign out others

    def revoke_others(self, auth: "DeviceAuth") -> dict[str, Any]:
        now = self.clock.now()
        with self.db.write() as conn:
            rows = conn.execute(
                "SELECT id, label FROM devices WHERE account_id = ? AND revoked_at IS NULL"
                " AND id != ? ORDER BY created_at, id",
                (auth.account_id, auth.device_id),
            ).fetchall()
            ids_ = [r["id"] for r in rows]
            if ids_:
                marks = ",".join("?" * len(ids_))
                conn.execute(
                    f"UPDATE devices SET revoked_at = ? WHERE id IN ({marks})",  # noqa: S608
                    (now, *ids_),
                )
                conn.execute(
                    f"DELETE FROM device_key_wraps WHERE device_id IN ({marks})",  # noqa: S608
                    ids_,
                )
                conn.execute(
                    "UPDATE accounts SET rotation_required = 1,"
                    " devices_revision = devices_revision + 1 WHERE id = ?",
                    (auth.account_id,),
                )
            account = self._row(conn, auth)
            caller = conn.execute(
                "SELECT label FROM devices WHERE id = ?", (auth.device_id,)
            ).fetchone()
        if ids_:
            self.service.event(
                "devices.revoked_others",
                level=logging.WARNING,
                account_id=auth.account_id,
                device_id=auth.device_id,
                count=len(ids_),
            )
            self.service.metrics.inc("uotp_account_actions_total", action="revoke_others")
            for device_id in ids_:
                self.service.broker.publish(
                    auth.account_id, Event("revoked", {"device_id": device_id}), device_id=device_id
                )
            self.service._publish_devices(account)
            label = caller["label"] if caller else "a device"
            self.service._alert(
                auth.account_id,
                "UltimateOTP: other devices signed out",
                f'{len(ids_)} device(s) were signed out from "{label}".',
                template="sessions_revoked",
                account_lang=account["lang"],
                count=len(ids_),
                device=label,
            )
        return {
            "revoked": ids_,
            "devices_revision": account["devices_revision"],
            "rotation_required": bool(account["rotation_required"]),
        }

    # ------------------------------------------------------------------ export

    def export(self, auth: "DeviceAuth") -> dict[str, Any]:
        service = self.service
        with self.db.read() as conn:
            account = self._row(conn, auth)
            keys = service._keys(conn, auth)
            devices = conn.execute(
                "SELECT * FROM devices WHERE account_id = ? ORDER BY created_at, id",
                (auth.account_id,),
            ).fetchall()
            items = conn.execute(
                "SELECT item_id, version, deleted, blob FROM items WHERE account_id = ?"
                " ORDER BY version, item_id",
                (auth.account_id,),
            ).fetchall()
            history = service.history.export(conn, auth.account_id)
            caller = next((d for d in devices if d["id"] == auth.device_id), None)
        service.event(
            "account.exported",
            level=logging.WARNING,
            account_id=auth.account_id,
            device_id=auth.device_id,
            items=len(items),
        )
        service.metrics.inc("uotp_account_actions_total", action="export")
        label = caller["label"] if caller else "a device"
        service._alert(
            auth.account_id,
            "UltimateOTP: account data exported",
            f'The encrypted data of account {auth.account_id} was exported from "{label}".',
            template="data_exported",
            account_lang=account["lang"],
            device=label,
        )
        return {
            "format": EXPORT_FORMAT,
            "exported_at": self.clock.now(),
            "account": {
                "account_id": account["id"],
                "email": account["email"],
                "created_at": account["created_at"],
            },
            "head": service.head(account),
            "keys": {
                "key_epoch": keys["key_epoch"],
                "keys_revision": keys["keys_revision"],
                "password_wrap": keys["password_wrap"],
                "password_kdf": keys["password_kdf"],
                "recovery_wrap": keys["recovery_wrap"],
            },
            "device_key": keys["device_key"],
            "devices": [service.device_dict(d) for d in devices],
            "items": [
                {
                    "item_id": r["item_id"],
                    "version": r["version"],
                    "deleted": bool(r["deleted"]),
                    "blob": r["blob"],
                }
                for r in items
            ],
            "history": history,
        }
