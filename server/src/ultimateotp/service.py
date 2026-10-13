# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The domain rules of `/otp/v1`, independent of HTTP (the admin CLI reuses them).

The server is a dumb, versioned store of opaque blobs (docs/design.md §4.2). It checks shapes,
sizes, signatures, versions and ownership; it never decrypts, parses or logs a blob, a wrap or a
KDF parameter set.
"""

import hmac
import logging
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ultimateotp import b64, formats, ids, signing, srp
from ultimateotp.alerts import Alerts
from ultimateotp.clock import Clock
from ultimateotp.db import Database
from ultimateotp.errors import ApiError
from ultimateotp.events import Broker, Event
from ultimateotp.logging import security_event
from ultimateotp.login import Login
from ultimateotp.metrics import Metrics
from ultimateotp.models import (
    ApproveRequest,
    CommitRequest,
    EnrollRequest,
    JoinRequest,
    KeyBundle,
    NewDevice,
    PutKeysRequest,
    RotateRequest,
    SrpSetup,
)
from ultimateotp.settings import Settings

PENDING = "pending"
MAX_TIMESTAMP_DIGITS = 12
SRP_SALT_MIN_BYTES = 16
NONCE_PURGE_EVERY_S = 60


@dataclass(frozen=True)
class SignedRequest:
    """What a signature covers, as received."""

    method: str
    target: str
    device: str | None
    timestamp: str | None
    nonce: str | None
    signature: str | None
    body: bytes
    # Not signed: the resolved client address and the optional `X-UOTP-App-Version` header,
    # kept as session metadata (decision 9).
    client_ip: str | None = None
    app_version: str | None = None


@dataclass(frozen=True)
class DeviceAuth:
    device_id: str
    account_id: str


Row = sqlite3.Row


def _unauthorized(code: str = "invalid_signature", **extra: Any) -> ApiError:
    return ApiError(401, code, "", **extra)


class Service:
    def __init__(  # noqa: PLR0913, PLR0917 - the collaborators of the service
        self,
        db: Database,
        settings: Settings,
        clock: Clock,
        broker: Broker,
        metrics: Metrics,
        alerts: Alerts | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.clock = clock
        self.broker = broker
        self.metrics = metrics
        self.alerts = alerts or Alerts(settings)
        self.login = Login(self)
        self._last_nonce_purge = 0

    # ------------------------------------------------------------------ helpers

    def event(self, name: str, *, level: int = logging.INFO, **fields: Any) -> None:
        security_event(name, level=level, **fields)
        self.metrics.inc("uotp_events_total", name)

    def _decode(self, value: str, max_bytes: int, field: str, sizes: tuple[int, ...] = ()) -> bytes:
        """Strict base64url, non-empty, at most `max_bytes`, and one of `sizes` when given
        (crypto-format v1 lengths, `formats.py`)."""
        try:
            data = b64.decode(value)
        except b64.InvalidBase64Error as exc:
            raise ApiError(400, "invalid_request", f"{field}: not base64url") from exc
        if not data or len(data) > max_bytes or (sizes and len(data) not in sizes):
            raise ApiError(400, "invalid_request", f"{field}: bad length")
        return data

    def _check_bundle(self, keys: KeyBundle | PutKeysRequest) -> None:
        if (keys.password_wrap is None) != (keys.password_kdf is None):
            raise ApiError(400, "invalid_request", "password_wrap and password_kdf go together")
        limit = self.settings.max_wrap_bytes
        if keys.password_wrap is not None and keys.password_kdf is not None:
            self._decode(keys.password_wrap, limit, "password_wrap", formats.PASSWORD_WRAP_BYTES)
            self._decode(keys.password_kdf, limit, "password_kdf", formats.KDF_PARAMS_BYTES)
        self._decode(keys.recovery_wrap, limit, "recovery_wrap", formats.RECOVERY_WRAP_BYTES)
        self._check_srp(keys.srp)

    def _sealed(self, value: str) -> bytes:
        return self._decode(
            value, self.settings.max_wrap_bytes, "sealed_vault_key", formats.SEALED_VAULT_KEY_BYTES
        )

    def _blob(self, value: str) -> bytes:
        data = self._decode(value, self.settings.max_blob_bytes, "blob")
        if not formats.valid_blob_size(len(data)):
            raise ApiError(400, "invalid_request", "blob: bad length")
        return data

    @staticmethod
    def _account(conn: sqlite3.Connection, account_id: str) -> Row:
        row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        if row is None:
            raise ApiError(404, "not_found")
        return row

    @staticmethod
    def head(account: Row) -> dict[str, Any]:
        return {
            "account_id": account["id"],
            "version": account["vault_version"],
            "key_epoch": account["key_epoch"],
            "signed_by": account["head_signed_by"],
            "signature": account["head_signature"],
            "updated_at": account["head_updated_at"],
            "rotation_required": bool(account["rotation_required"]),
            "devices_revision": account["devices_revision"],
        }

    @staticmethod
    def device_dict(row: Row) -> dict[str, Any]:
        return {
            "device_id": row["id"],
            "label": row["label"],
            "ed25519_public_key": row["ed25519_public_key"],
            "x25519_public_key": row["x25519_public_key"],
            "enrolled_via": row["enrolled_via"],
            "added_by": row["added_by"],
            "added_by_signature": row["added_by_signature"],
            "created_at": row["created_at"],
            "last_seen_at": row["last_seen_at"],
            "revoked_at": row["revoked_at"],
            "app_version": row["app_version"],
        }

    def _publish_devices(self, account: Row) -> None:
        self.broker.publish(
            account["id"], Event("devices", {"devices_revision": account["devices_revision"]})
        )

    def _publish_vault(self, account: Row) -> None:
        self.broker.publish(
            account["id"],
            Event(
                "vault",
                {
                    "version": account["vault_version"],
                    "key_epoch": account["key_epoch"],
                    "signed_by": account["head_signed_by"],
                },
                event_id=str(account["vault_version"]),
            ),
        )

    # ------------------------------------------------------------------ signatures

    def _check_signed(self, req: SignedRequest) -> tuple[str, str]:
        """Common header checks; returns (nonce, signature)."""
        if not (req.device and req.timestamp and req.nonce and req.signature):
            raise _unauthorized()
        if not req.timestamp.isdecimal() or len(req.timestamp) > MAX_TIMESTAMP_DIGITS:
            raise _unauthorized()
        now = self.clock.now()
        if abs(now - int(req.timestamp)) > self.settings.signature_max_skew_s:
            raise _unauthorized("stale_request", server_time=now)
        try:
            nonce_len = len(b64.decode(req.nonce))
        except b64.InvalidBase64Error as exc:
            raise _unauthorized() from exc
        if not signing.NONCE_MIN_BYTES <= nonce_len <= signing.NONCE_MAX_BYTES:
            raise _unauthorized()
        return req.nonce, req.signature

    def _verify(self, req: SignedRequest, public_key: str, signature: str) -> None:
        message = signing.request_message(
            req.method,
            req.target,
            req.device or "",
            req.timestamp or "",
            req.nonce or "",
            req.body,
        )
        if not signing.verify(public_key, message, signature):
            raise _unauthorized()

    def _consume_nonce(self, conn: sqlite3.Connection, signer: str, nonce: str) -> None:
        now = self.clock.now()
        if now - self._last_nonce_purge >= NONCE_PURGE_EVERY_S:
            conn.execute(
                "DELETE FROM request_nonces WHERE seen_at < ?",
                (now - 2 * self.settings.signature_max_skew_s,),
            )
            self._last_nonce_purge = now
        try:
            conn.execute(
                "INSERT INTO request_nonces (signer, nonce, seen_at) VALUES (?, ?, ?)",
                (signer, nonce, now),
            )
        except sqlite3.IntegrityError as exc:
            raise _unauthorized("replayed_request") from exc

    def authenticate(self, req: SignedRequest) -> DeviceAuth:
        """A registered device's request: signature, window, nonce, not revoked."""
        nonce, signature = self._check_signed(req)
        device_id = req.device or ""
        if not ids.DEVICE_ID.match(device_id):
            raise _unauthorized()
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT id, account_id, ed25519_public_key, revoked_at FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
        if row is None:
            raise _unauthorized()
        self._verify(req, row["ed25519_public_key"], signature)
        if row["revoked_at"] is not None:
            raise _unauthorized("device_revoked")
        with self.db.write() as conn:
            self._consume_nonce(conn, device_id, nonce)
            conn.execute(
                "UPDATE devices SET last_seen_at = ?, last_ip = COALESCE(?, last_ip),"
                " app_version = COALESCE(?, app_version) WHERE id = ?",
                (self.clock.now(), req.client_ip, req.app_version, device_id),
            )
        return DeviceAuth(device_id=device_id, account_id=row["account_id"])

    def verify_pending(
        self, conn: sqlite3.Connection, req: SignedRequest, expected_device: str, public_key: str
    ) -> None:
        """Proof of possession of a new device key (inside the caller's write transaction)."""
        nonce, signature = self._check_signed(req)
        if req.device != expected_device:
            raise _unauthorized()
        self._verify(req, public_key, signature)
        self._consume_nonce(conn, f"{PENDING}:{public_key}", nonce)

    # ------------------------------------------------------------------ admin (CLI)

    def create_account(
        self, email: str | None = None, *, email_check: bool = True
    ) -> tuple[str, str, int]:
        """Account + bootstrap token (admin CLI). With email verification on, the address gets
        a code that the bootstrap enrollment must present once (decision 13)."""
        account_id = ids.new_account_id()
        code = None
        with self.db.write() as conn:
            if (
                email is not None
                and conn.execute("SELECT 1 FROM accounts WHERE email = ?", (email,)).fetchone()
            ):
                raise ApiError(409, "email_taken")
            conn.execute(
                "INSERT INTO accounts (id, created_at, email, email_check) VALUES (?, ?, ?, ?)",
                (account_id, self.clock.now(), email, int(email_check)),
            )
            token, expires = self._insert_token(conn, account_id, None)
            if email is not None and self.settings.email_enabled:
                code = self.login.issue_code(conn, email)
        if email is not None and code is not None:
            self.login.send_code(email, code)
        self.event("account.created", account_id=account_id)
        return account_id, token, expires

    def set_email_check(self, account_id: str, *, enabled: bool) -> None:
        with self.db.write() as conn:
            self._account(conn, account_id)
            conn.execute(
                "UPDATE accounts SET email_check = ? WHERE id = ?", (int(enabled), account_id)
            )
        self.event(
            "account.email_check", level=logging.WARNING, account_id=account_id, enabled=enabled
        )

    def account_email(self, account_id: str) -> str | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT email FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return None if row is None else row["email"]

    def _alert(self, account_id: str, title: str, body: str, *, email_notice: bool = False) -> None:
        """ntfy always (decision 7); an email notice too for recovery and rotation (13)."""
        self.alerts.notify(title, body)
        email = self.account_email(account_id) if email_notice else None
        if email:
            self.alerts.email(
                email,
                title,
                body + "\nIf this was not you, revoke the devices"
                " you do not recognize and change your password.\n",
            )

    def _insert_token(
        self, conn: sqlite3.Connection, account_id: str, created_by: str | None
    ) -> tuple[str, int]:
        token = ids.new_enrollment_token()
        now = self.clock.now()
        expires = now + self.settings.enrollment_token_ttl_s
        conn.execute(
            "INSERT INTO enrollment_tokens (token_hash, account_id, created_by, created_at,"
            " expires_at) VALUES (?, ?, ?, ?, ?)",
            (ids.secret_hash(token), account_id, created_by, now, expires),
        )
        return token, expires

    def create_token(self, account_id: str, created_by: str | None = None) -> tuple[str, int]:
        with self.db.write() as conn:
            self._account(conn, account_id)
            token, expires = self._insert_token(conn, account_id, created_by)
        self.event(
            "enroll.token_created", account_id=account_id, device_id=created_by or "admin-cli"
        )
        return token, expires

    def list_accounts(self) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT a.*, (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id"
                " AND d.revoked_at IS NULL) AS active_devices FROM accounts a ORDER BY created_at"
            ).fetchall()
        return [
            {
                **self.head(r),
                "email": r["email"],
                "email_check": bool(r["email_check"]),
                "srp": r["srp_verifier"] is not None,
                "created_at": r["created_at"],
                "active_devices": r["active_devices"],
            }
            for r in rows
        ]

    def admin_devices(self, account_id: str) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            self._account(conn, account_id)
            rows = conn.execute(
                "SELECT * FROM devices WHERE account_id = ? ORDER BY created_at", (account_id,)
            ).fetchall()
        return [self.device_dict(r) for r in rows]

    def purge(self) -> dict[str, int]:
        """Deletes expired tokens, finished or expired pairings and old nonces."""
        now = self.clock.now()
        with self.db.write() as conn:
            tokens = conn.execute(
                "DELETE FROM enrollment_tokens WHERE expires_at < ?", (now - 86_400,)
            ).rowcount
            pairings = conn.execute(
                "DELETE FROM pairings WHERE expires_at < ?", (now - 86_400,)
            ).rowcount
            nonces = conn.execute(
                "DELETE FROM request_nonces WHERE seen_at < ?",
                (now - 2 * self.settings.signature_max_skew_s,),
            ).rowcount
        return {"enrollment_tokens": tokens, "pairings": pairings, "request_nonces": nonces}

    # ------------------------------------------------------------------ enrollment

    def _valid_token(self, conn: sqlite3.Connection, token: str | None) -> Row:
        if token is None or not ids.ENROLLMENT_TOKEN.match(token):
            raise _unauthorized("invalid_token")
        row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?", (ids.secret_hash(token),)
        ).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] < self.clock.now():
            raise _unauthorized("invalid_token")
        return row

    def store_bundle(self, conn: sqlite3.Connection, account_id: str, keys: KeyBundle) -> None:
        """Stores the wraps. SRP follows the password path: a new `srp` replaces the record,
        none keeps it, and no password wrap at all removes it (no password login)."""
        conn.execute(
            "UPDATE accounts SET password_wrap = ?, password_kdf = ?, recovery_wrap = ?,"
            " keys_revision = keys_revision + 1 WHERE id = ?",
            (keys.password_wrap, keys.password_kdf, keys.recovery_wrap, account_id),
        )
        if keys.password_wrap is None:
            conn.execute(
                "UPDATE accounts SET srp_user_id = NULL, srp_salt = NULL, srp_verifier = NULL"
                " WHERE id = ?",
                (account_id,),
            )
        elif keys.srp is not None:
            conn.execute(
                "UPDATE accounts SET srp_user_id = ?, srp_salt = ?, srp_verifier = ?,"
                " srp_failures = 0, srp_locked_until = NULL WHERE id = ?",
                (keys.srp.srp_user_id, keys.srp.srp_salt, keys.srp.srp_verifier, account_id),
            )

    def _check_srp(self, srp_setup: SrpSetup | None) -> None:
        if srp_setup is None:
            return
        salt = self._decode(srp_setup.srp_salt, 64, "srp_salt")
        verifier = int.from_bytes(self._decode(srp_setup.srp_verifier, 512, "srp_verifier"))
        if len(salt) < SRP_SALT_MIN_BYTES or not srp.valid_public(srp.GROUP_4096, verifier):
            raise ApiError(400, "invalid_request", "srp: bad salt or verifier")

    def _insert_device(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        device: NewDevice | EnrollRequest,
        via: str,
        req: SignedRequest,
    ) -> Row:
        self._decode(device.ed25519_public_key, 32, "ed25519_public_key")
        self._decode(device.x25519_public_key, 32, "x25519_public_key")
        if conn.execute(
            "SELECT 1 FROM devices WHERE ed25519_public_key = ?", (device.ed25519_public_key,)
        ).fetchone():
            raise ApiError(409, "device_exists")
        device_id = ids.new_device_id()
        now = self.clock.now()
        conn.execute(
            "INSERT INTO devices (id, account_id, ed25519_public_key, x25519_public_key, label,"
            " enrolled_via, created_at, last_seen_at, app_version, last_ip)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                device_id,
                account_id,
                device.ed25519_public_key,
                device.x25519_public_key,
                device.label,
                via,
                now,
                now,
                device.app_version or req.app_version,
                req.client_ip,
            ),
        )
        conn.execute(
            "UPDATE accounts SET devices_revision = devices_revision + 1 WHERE id = ?",
            (account_id,),
        )
        row: Row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return row

    def register_device(
        self,
        account_id: str,
        device: NewDevice,
        req: SignedRequest,
        *,
        via: str,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        """Proof of possession of the new key, then the device row (caller's transaction)."""
        self.verify_pending(conn, req, PENDING, device.ed25519_public_key)
        row = self._insert_device(conn, account_id, device, via, req)
        account = self._account(conn, account_id)
        return {
            "account_id": account_id,
            "device": self.device_dict(row),
            "head": self.head(account),
        }

    def after_register(self, account_id: str, result: dict[str, Any], req: SignedRequest) -> None:
        device = result["device"]
        self.event(
            "enroll.success",
            account_id=account_id,
            device_id=device["device_id"],
            via=device["enrolled_via"],
            client_ip=req.client_ip,
        )
        self.broker.publish(
            account_id, Event("devices", {"devices_revision": result["head"]["devices_revision"]})
        )
        self._alert(
            account_id,
            "UltimateOTP: new device signed in",
            f'Device "{device["label"]}" ({device["enrolled_via"]}) was added to your account'
            f" from {req.client_ip or 'an unknown address'}.",
        )

    def key_attributes(self, conn: sqlite3.Connection, account_id: str) -> dict[str, Any]:
        account = self._account(conn, account_id)
        return {
            "key_epoch": account["key_epoch"],
            "keys_revision": account["keys_revision"],
            "password_wrap": account["password_wrap"],
            "password_kdf": account["password_kdf"],
            "recovery_wrap": account["recovery_wrap"],
        }

    def enroll(self, token: str | None, body: EnrollRequest, req: SignedRequest) -> dict[str, Any]:
        if body.keys is not None:
            self._check_bundle(body.keys)
        # Bootstrap of an account whose email is unverified: the code from account-create.
        with self.db.read() as conn:
            token_row = self._valid_token(conn, token)
            account = self._account(conn, token_row["account_id"])
        verify_email = (
            body.keys is not None
            and self.settings.email_enabled
            and account["email"] is not None
            and account["email_verified_at"] is None
        )
        if verify_email:
            self.login.require_code(account["email"], body.email_code, req.client_ip or "unknown")
        now = self.clock.now()
        with self.db.write() as conn:
            token_row = self._valid_token(conn, token)
            self.verify_pending(conn, req, PENDING, body.ed25519_public_key)
            account = self._account(conn, token_row["account_id"])
            has_keys = account["recovery_wrap"] is not None
            if not has_keys and body.keys is None:
                raise ApiError(400, "keys_required", "the account has no key bundle yet")
            if has_keys and body.keys is not None:
                raise ApiError(409, "keys_exist", "the account already has a key bundle")
            via = "bootstrap" if body.keys is not None else "token"
            row = self._insert_device(conn, account["id"], body, via, req)
            if body.keys is not None:
                self.store_bundle(conn, account["id"], body.keys)
            if verify_email:
                conn.execute(
                    "UPDATE accounts SET email_verified_at = ? WHERE id = ?", (now, account["id"])
                )
            conn.execute(
                "UPDATE enrollment_tokens SET used_at = ?, used_by = ? WHERE token_hash = ?",
                (now, row["id"], token_row["token_hash"]),
            )
            account = self._account(conn, account["id"])
        result = {
            "account_id": account["id"],
            "device": self.device_dict(row),
            "head": self.head(account),
        }
        self.after_register(account["id"], result, req)
        return result

    def recovery_keys(self, token: str | None) -> dict[str, Any]:
        with self.db.write() as conn:
            token_row = self._valid_token(conn, token)
            if token_row["recovery_fetches"] >= self.settings.recovery_fetch_limit:
                raise ApiError(429, "rate_limited", "fetch limit of this token", retry_after=600)
            account = self._account(conn, token_row["account_id"])
            if account["recovery_wrap"] is None:
                raise ApiError(404, "not_found", "the account has no key bundle yet")
            conn.execute(
                "UPDATE enrollment_tokens SET recovery_fetches = recovery_fetches + 1"
                " WHERE token_hash = ?",
                (token_row["token_hash"],),
            )
        self.event("recovery.keys_fetched", level=logging.WARNING, account_id=account["id"])
        self._alert(
            account["id"],
            "UltimateOTP: recovery data fetched",
            "A new device fetched your password and recovery-key wraps with an enrollment token"
            " (the password or recovery-key path).",
            email_notice=True,
        )
        return {
            "account_id": account["id"],
            "key_epoch": account["key_epoch"],
            "keys_revision": account["keys_revision"],
            "password_wrap": account["password_wrap"],
            "password_kdf": account["password_kdf"],
            "recovery_wrap": account["recovery_wrap"],
        }

    # ------------------------------------------------------------------ account keys, devices

    def _keys(self, conn: sqlite3.Connection, auth: DeviceAuth) -> dict[str, Any]:
        account = self._account(conn, auth.account_id)
        wrap = conn.execute(
            "SELECT * FROM device_key_wraps WHERE device_id = ? AND key_epoch = ?",
            (auth.device_id, account["key_epoch"]),
        ).fetchone()
        return {
            "account_id": account["id"],
            "key_epoch": account["key_epoch"],
            "keys_revision": account["keys_revision"],
            "password_wrap": account["password_wrap"],
            "password_kdf": account["password_kdf"],
            "recovery_wrap": account["recovery_wrap"],
            "device_key": None
            if wrap is None
            else {
                "key_epoch": wrap["key_epoch"],
                "sealed_vault_key": wrap["sealed_vault_key"],
                "sealed_by": wrap["sealed_by"],
                "seal_signature": wrap["seal_signature"],
            },
        }

    def get_keys(self, auth: DeviceAuth) -> dict[str, Any]:
        with self.db.read() as conn:
            return self._keys(conn, auth)

    def put_keys(self, auth: DeviceAuth, body: PutKeysRequest) -> dict[str, Any]:
        self._check_bundle(body)
        with self.db.write() as conn:
            account = self._account(conn, auth.account_id)
            if body.key_epoch != account["key_epoch"]:
                raise ApiError(409, "key_epoch_conflict", head=self.head(account))
            if body.base_revision != account["keys_revision"]:
                raise ApiError(409, "keys_revision_conflict")
            self.store_bundle(
                conn,
                account["id"],
                KeyBundle(
                    password_wrap=body.password_wrap,
                    password_kdf=body.password_kdf,
                    recovery_wrap=body.recovery_wrap,
                    srp=body.srp,
                ),
            )
            result = self._keys(conn, auth)
        self.event("keys.updated", account_id=auth.account_id, device_id=auth.device_id)
        return result

    def list_devices(self, auth: DeviceAuth) -> dict[str, Any]:
        with self.db.read() as conn:
            account = self._account(conn, auth.account_id)
            rows = conn.execute(
                "SELECT * FROM devices WHERE account_id = ? ORDER BY created_at, id",
                (auth.account_id,),
            ).fetchall()
        return {
            "devices_revision": account["devices_revision"],
            "devices": [self.device_dict(r) for r in rows],
        }

    def sessions(self, auth: DeviceAuth) -> dict[str, Any]:
        """Decision 9: the "Active sessions" list (plain-text metadata, like Ente's)."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM devices WHERE account_id = ? ORDER BY last_seen_at DESC, id",
                (auth.account_id,),
            ).fetchall()
        return {
            "sessions": [
                {
                    "device_id": r["id"],
                    "label": r["label"],
                    "app_version": r["app_version"],
                    "enrolled_via": r["enrolled_via"],
                    "created_at": r["created_at"],
                    "last_seen_at": r["last_seen_at"],
                    "last_ip": r["last_ip"],
                    "revoked_at": r["revoked_at"],
                    "current": r["id"] == auth.device_id,
                }
                for r in rows
            ]
        }

    def revoke_device(self, device_id: str, by: DeviceAuth | None) -> dict[str, Any]:
        """By a device of the same account, or by the admin CLI (`by` None)."""
        now = self.clock.now()
        with self.db.write() as conn:
            row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            if row is None or (by is not None and row["account_id"] != by.account_id):
                raise ApiError(404, "not_found")
            already = row["revoked_at"] is not None
            if not already:
                conn.execute("UPDATE devices SET revoked_at = ? WHERE id = ?", (now, device_id))
                conn.execute("DELETE FROM device_key_wraps WHERE device_id = ?", (device_id,))
                conn.execute(
                    "UPDATE accounts SET rotation_required = 1,"
                    " devices_revision = devices_revision + 1 WHERE id = ?",
                    (row["account_id"],),
                )
            account = self._account(conn, row["account_id"])
            row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not already:
            self.event(
                "device.revoked",
                level=logging.WARNING,
                account_id=account["id"],
                device_id=device_id,
                by=by.device_id if by else "admin-cli",
            )
            self._alert(
                account["id"],
                "UltimateOTP: device revoked",
                f'Device "{row["label"]}" was revoked'
                f" {'by another device' if by else 'from the admin CLI'}.",
            )
            self.broker.publish(
                account["id"], Event("revoked", {"device_id": device_id}), device_id=device_id
            )
            self._publish_devices(account)
        return self.device_dict(row)

    # ------------------------------------------------------------------ pairing

    def create_pairing(self, auth: DeviceAuth) -> dict[str, Any]:
        pairing_id = ids.new_pairing_id()
        secret = ids.new_pairing_secret()
        now = self.clock.now()
        expires = now + self.settings.pairing_ttl_s
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO pairings (id, account_id, created_by, secret_hash, status,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, 'open', ?, ?)",
                (
                    pairing_id,
                    auth.account_id,
                    auth.device_id,
                    ids.secret_hash(secret),
                    now,
                    expires,
                ),
            )
        self.event("pairing.created", account_id=auth.account_id, device_id=auth.device_id)
        return {"pairing_id": pairing_id, "secret": secret, "expires_at": expires}

    def _status(self, row: Row) -> str:
        status = str(row["status"])
        if status in ("open", "joined") and row["expires_at"] < self.clock.now():
            return "expired"
        return status

    def _pairing_dict(self, row: Row) -> dict[str, Any]:
        device = None
        if row["device_id"] is not None:
            device = {
                "device_id": row["device_id"],
                "label": row["label"],
                "ed25519_public_key": row["ed25519_public_key"],
                "x25519_public_key": row["x25519_public_key"],
            }
        return {
            "pairing_id": row["id"],
            "status": self._status(row),
            "expires_at": row["expires_at"],
            "device": device,
        }

    @staticmethod
    def _own_pairing(conn: sqlite3.Connection, auth: DeviceAuth, pairing_id: str) -> Row:
        row = conn.execute("SELECT * FROM pairings WHERE id = ?", (pairing_id,)).fetchone()
        if row is None or row["created_by"] != auth.device_id:
            raise ApiError(404, "not_found")
        return row

    @staticmethod
    def _pairing_by_secret(conn: sqlite3.Connection, pairing_id: str, secret: str | None) -> Row:
        if secret is None or not ids.PAIRING_SECRET.match(secret):
            raise _unauthorized("invalid_token")
        row = conn.execute("SELECT * FROM pairings WHERE id = ?", (pairing_id,)).fetchone()
        if row is None:
            raise _unauthorized("invalid_token")
        if not hmac.compare_digest(row["secret_hash"], ids.secret_hash(secret)):
            raise _unauthorized("invalid_token")
        return row

    def get_pairing(self, auth: DeviceAuth, pairing_id: str) -> dict[str, Any]:
        with self.db.read() as conn:
            return self._pairing_dict(self._own_pairing(conn, auth, pairing_id))

    def join_pairing(
        self, pairing_id: str, secret: str | None, body: JoinRequest, req: SignedRequest
    ) -> dict[str, Any]:
        self._decode(body.ed25519_public_key, 32, "ed25519_public_key")
        self._decode(body.x25519_public_key, 32, "x25519_public_key")
        with self.db.write() as conn:
            row = self._pairing_by_secret(conn, pairing_id, secret)
            self.verify_pending(conn, req, PENDING, body.ed25519_public_key)
            status = self._status(row)
            if status == "expired":
                raise ApiError(410, "pairing_expired")
            if status != "open":
                raise ApiError(409, "pairing_state", f"session is {status}")
            if conn.execute(
                "SELECT 1 FROM devices WHERE ed25519_public_key = ?", (body.ed25519_public_key,)
            ).fetchone():
                raise ApiError(409, "device_exists")
            device_id = ids.new_device_id()
            conn.execute(
                "UPDATE pairings SET status = 'joined', device_id = ?, ed25519_public_key = ?,"
                " x25519_public_key = ?, label = ? WHERE id = ?",
                (
                    device_id,
                    body.ed25519_public_key,
                    body.x25519_public_key,
                    body.label,
                    pairing_id,
                ),
            )
        self.event("pairing.joined", account_id=row["account_id"], pairing_id=pairing_id)
        self.broker.publish(
            row["account_id"],
            Event("pairing", {"pairing_id": pairing_id, "status": "joined"}),
            device_id=row["created_by"],
        )
        return {"pairing_id": pairing_id, "device_id": device_id, "status": "joined"}

    def approve_pairing(
        self, auth: DeviceAuth, pairing_id: str, body: ApproveRequest
    ) -> dict[str, Any]:
        sealed = self._sealed(body.sealed_vault_key)
        now = self.clock.now()
        with self.db.write() as conn:
            row = self._own_pairing(conn, auth, pairing_id)
            status = self._status(row)
            if status == "expired":
                raise ApiError(410, "pairing_expired")
            if status != "joined" or row["device_id"] != body.device_id:
                raise ApiError(409, "pairing_state", f"session is {status}")
            account = self._account(conn, auth.account_id)
            approver = conn.execute(
                "SELECT ed25519_public_key FROM devices WHERE id = ?", (auth.device_id,)
            ).fetchone()
            cert = signing.device_message(
                account["id"], body.device_id, row["ed25519_public_key"], row["x25519_public_key"]
            )
            if not signing.verify(approver["ed25519_public_key"], cert, body.device_signature):
                raise ApiError(400, "invalid_device_signature")
            seal = signing.seal_message(account["id"], account["key_epoch"], body.device_id, sealed)
            if not signing.verify(approver["ed25519_public_key"], seal, body.seal_signature):
                raise ApiError(400, "invalid_seal_signature")
            if conn.execute(
                "SELECT 1 FROM devices WHERE ed25519_public_key = ?", (row["ed25519_public_key"],)
            ).fetchone():
                raise ApiError(409, "device_exists")
            conn.execute(
                "INSERT INTO devices (id, account_id, ed25519_public_key, x25519_public_key,"
                " label, enrolled_via, added_by, added_by_signature, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'pairing', ?, ?, ?)",
                (
                    body.device_id,
                    account["id"],
                    row["ed25519_public_key"],
                    row["x25519_public_key"],
                    row["label"],
                    auth.device_id,
                    body.device_signature,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO device_key_wraps (device_id, key_epoch, account_id, sealed_vault_key,"
                " sealed_by, seal_signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    body.device_id,
                    account["key_epoch"],
                    account["id"],
                    body.sealed_vault_key,
                    auth.device_id,
                    body.seal_signature,
                    now,
                ),
            )
            conn.execute(
                "UPDATE pairings SET status = 'approved', device_signature = ?, decided_at = ?"
                " WHERE id = ?",
                (body.device_signature, now, pairing_id),
            )
            conn.execute(
                "UPDATE accounts SET devices_revision = devices_revision + 1 WHERE id = ?",
                (account["id"],),
            )
            account = self._account(conn, account["id"])
            device = conn.execute(
                "SELECT * FROM devices WHERE id = ?", (body.device_id,)
            ).fetchone()
        self.event(
            "enroll.success",
            account_id=account["id"],
            device_id=body.device_id,
            via="pairing",
            by=auth.device_id,
        )
        self._publish_devices(account)
        self._alert(
            account["id"],
            "UltimateOTP: new device signed in",
            f'Device "{device["label"]}" (pairing) was added to your account by another device.',
        )
        return self.device_dict(device)

    def reject_pairing(self, auth: DeviceAuth, pairing_id: str) -> dict[str, Any]:
        with self.db.write() as conn:
            row = self._own_pairing(conn, auth, pairing_id)
            status = self._status(row)
            if status not in ("open", "joined"):
                raise ApiError(409, "pairing_state", f"session is {status}")
            conn.execute(
                "UPDATE pairings SET status = 'rejected', decided_at = ? WHERE id = ?",
                (self.clock.now(), pairing_id),
            )
            row = self._own_pairing(conn, auth, pairing_id)
        self.event("pairing.rejected", account_id=auth.account_id, pairing_id=pairing_id)
        return self._pairing_dict(row)

    def pairing_result(
        self, pairing_id: str, secret: str | None, req: SignedRequest
    ) -> dict[str, Any]:
        with self.db.write() as conn:
            row = self._pairing_by_secret(conn, pairing_id, secret)
            if row["device_id"] is None:
                raise ApiError(404, "not_found", "nobody joined this session")
            self.verify_pending(conn, req, row["device_id"], row["ed25519_public_key"])
            approver = conn.execute(
                "SELECT id, ed25519_public_key FROM devices WHERE id = ?", (row["created_by"],)
            ).fetchone()
            wrap = None
            if row["status"] == "approved":
                wrap = conn.execute(
                    "SELECT * FROM device_key_wraps WHERE device_id = ?"
                    " ORDER BY key_epoch DESC LIMIT 1",
                    (row["device_id"],),
                ).fetchone()
        return {
            "pairing_id": row["id"],
            "status": self._status(row),
            "device_id": row["device_id"],
            "account_id": row["account_id"],
            "approver": {
                "device_id": approver["id"],
                "ed25519_public_key": approver["ed25519_public_key"],
            },
            "device_signature": row["device_signature"],
            "device_key": None
            if wrap is None
            else {
                "key_epoch": wrap["key_epoch"],
                "sealed_vault_key": wrap["sealed_vault_key"],
                "sealed_by": wrap["sealed_by"],
                "seal_signature": wrap["seal_signature"],
            },
        }

    # ------------------------------------------------------------------ vault

    def get_vault(self, auth: DeviceAuth, since: int) -> dict[str, Any]:
        with self.db.read() as conn:
            account = self._account(conn, auth.account_id)
            rows = conn.execute(
                "SELECT item_id, version, deleted, blob FROM items"
                " WHERE account_id = ? AND version > ? ORDER BY version, item_id",
                (auth.account_id, since),
            ).fetchall()
        return {
            "head": self.head(account),
            "items": [
                {
                    "item_id": r["item_id"],
                    "version": r["version"],
                    "deleted": bool(r["deleted"]),
                    "blob": r["blob"],
                }
                for r in rows
            ],
        }

    def state(self, account_id: str, device_id: str) -> dict[str, Any]:
        """For the SSE stream: account state, plus whether the device is still active."""
        with self.db.read() as conn:
            account = self._account(conn, account_id)
            device = conn.execute(
                "SELECT revoked_at FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
        return {
            "version": account["vault_version"],
            "key_epoch": account["key_epoch"],
            "devices_revision": account["devices_revision"],
            "rotation_required": bool(account["rotation_required"]),
            "signed_by": account["head_signed_by"],
            "revoked": device is None or device["revoked_at"] is not None,
        }

    def _apply(
        self,
        conn: sqlite3.Connection,
        auth: DeviceAuth,
        account: Row,
        body: CommitRequest | RotateRequest,
    ) -> dict[str, tuple[int, str]]:
        """Validates the change set and the signed head, then writes the items and the head.
        Returns the live items after the change: item_id -> (version, blob sha256)."""
        upserts, deletes = body.upserts, body.deletes
        new_version, signature = body.head.version, body.head.signature
        key_epoch = body.new_key_epoch if isinstance(body, RotateRequest) else account["key_epoch"]
        changed = [u.item_id for u in upserts] + list(deletes)
        if len(set(changed)) != len(changed):
            raise ApiError(400, "duplicate_item")
        if not changed:
            raise ApiError(400, "empty_commit")
        blobs = {u.item_id: self._blob(u.blob) for u in upserts}
        existing = {
            r["item_id"]: (r["version"], bool(r["deleted"]), r["blob_sha256"])
            for r in conn.execute(
                "SELECT item_id, version, deleted, blob_sha256 FROM items WHERE account_id = ?",
                (account["id"],),
            )
        }
        for item_id in deletes:
            if item_id not in existing or existing[item_id][1]:
                raise ApiError(400, "unknown_item", "delete of an item that is not live")
        live = {i: (v, h) for i, (v, d, h) in existing.items() if not d}
        for item_id, blob in blobs.items():
            live[item_id] = (new_version, signing.sha256_b64(blob))
        for item_id in deletes:
            del live[item_id]
        if len(live) > self.settings.max_items:
            raise ApiError(400, "too_many_items")
        manifest = signing.manifest((i, v, h) for i, (v, h) in live.items())
        message = signing.head_message(
            account["id"], new_version, key_epoch, auth.device_id, manifest
        )
        signer = conn.execute(
            "SELECT ed25519_public_key FROM devices WHERE id = ?", (auth.device_id,)
        ).fetchone()
        if not signing.verify(signer["ed25519_public_key"], message, signature):
            self.event(
                "vault.head_rejected",
                level=logging.WARNING,
                account_id=account["id"],
                device_id=auth.device_id,
            )
            raise ApiError(400, "invalid_head_signature")
        now = self.clock.now()
        for upsert in upserts:
            conn.execute(
                "INSERT INTO items (account_id, item_id, version, deleted, blob, blob_sha256,"
                " updated_at) VALUES (?, ?, ?, 0, ?, ?, ?)"
                " ON CONFLICT (account_id, item_id) DO UPDATE SET version = excluded.version,"
                " deleted = 0, blob = excluded.blob, blob_sha256 = excluded.blob_sha256,"
                " updated_at = excluded.updated_at",
                (
                    account["id"],
                    upsert.item_id,
                    new_version,
                    upsert.blob,
                    live[upsert.item_id][1],
                    now,
                ),
            )
        for item_id in deletes:
            conn.execute(
                "UPDATE items SET version = ?, deleted = 1, blob = NULL, blob_sha256 = NULL,"
                " updated_at = ? WHERE account_id = ? AND item_id = ?",
                (new_version, now, account["id"], item_id),
            )
        conn.execute(
            "UPDATE accounts SET vault_version = ?, key_epoch = ?, head_signed_by = ?,"
            " head_signature = ?, head_updated_at = ? WHERE id = ?",
            (new_version, key_epoch, auth.device_id, signature, now, account["id"]),
        )
        return live

    def _check_base(self, account: Row, base_version: int, head_version: int) -> None:
        if base_version != account["vault_version"]:
            self.event("vault.conflict", account_id=account["id"], reason="version")
            raise ApiError(
                409, "version_conflict", "pull, merge and retry", head=self.head(account)
            )
        if head_version != base_version + 1:
            raise ApiError(400, "bad_version", "head.version must be base_version + 1")

    def commit(self, auth: DeviceAuth, body: CommitRequest) -> dict[str, Any]:
        with self.db.write() as conn:
            account = self._account(conn, auth.account_id)
            self._check_base(account, body.base_version, body.head.version)
            if body.key_epoch != account["key_epoch"]:
                self.event("vault.conflict", account_id=account["id"], reason="key_epoch")
                raise ApiError(409, "key_epoch_conflict", head=self.head(account))
            self._apply(conn, auth, account, body)
            account = self._account(conn, auth.account_id)
        self.event(
            "vault.commit",
            account_id=account["id"],
            device_id=auth.device_id,
            version=account["vault_version"],
            upserts=len(body.upserts),
            deletes=len(body.deletes),
        )
        self._publish_vault(account)
        return self.head(account)

    def rotate(self, auth: DeviceAuth, body: RotateRequest) -> dict[str, Any]:
        self._check_bundle(body.keys)
        now = self.clock.now()
        with self.db.write() as conn:
            account = self._account(conn, auth.account_id)
            self._check_base(account, body.base_version, body.head.version)
            if body.new_key_epoch != account["key_epoch"] + 1:
                raise ApiError(409, "key_epoch_conflict", head=self.head(account))
            active = {
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM devices WHERE account_id = ? AND revoked_at IS NULL",
                    (account["id"],),
                )
            }
            sealed_for = [k.device_id for k in body.device_keys]
            if len(set(sealed_for)) != len(sealed_for) or set(sealed_for) != active:
                raise ApiError(400, "incomplete_rotation", "one sealed key for every active device")
            signer = conn.execute(
                "SELECT ed25519_public_key FROM devices WHERE id = ?", (auth.device_id,)
            ).fetchone()["ed25519_public_key"]
            for key in body.device_keys:
                sealed = self._sealed(key.sealed_vault_key)
                message = signing.seal_message(
                    account["id"], body.new_key_epoch, key.device_id, sealed
                )
                if not signing.verify(signer, message, key.seal_signature):
                    raise ApiError(400, "invalid_seal_signature")
            live = self._apply(conn, auth, account, body)
            if any(version != body.head.version for version, _ in live.values()):
                raise ApiError(400, "incomplete_rotation", "every live item must be re-encrypted")
            self.store_bundle(conn, account["id"], body.keys)
            conn.execute("UPDATE accounts SET rotation_required = 0 WHERE id = ?", (account["id"],))
            conn.execute("DELETE FROM device_key_wraps WHERE account_id = ?", (account["id"],))
            conn.executemany(
                "INSERT INTO device_key_wraps (device_id, key_epoch, account_id, sealed_vault_key,"
                " sealed_by, seal_signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        k.device_id,
                        body.new_key_epoch,
                        account["id"],
                        k.sealed_vault_key,
                        auth.device_id,
                        k.seal_signature,
                        now,
                    )
                    for k in body.device_keys
                ],
            )
            account = self._account(conn, auth.account_id)
        self.event(
            "vault.rotated",
            level=logging.WARNING,
            account_id=account["id"],
            device_id=auth.device_id,
            key_epoch=account["key_epoch"],
        )
        self._alert(
            account["id"],
            "UltimateOTP: vault key rotated",
            f"The vault key was rotated to epoch {account['key_epoch']}; every device was"
            " re-keyed.",
            email_notice=True,
        )
        self._publish_vault(account)
        return self.head(account)


def live_manifest(items: Iterable[tuple[str, int, bytes]]) -> bytes:
    """Client-side helper (tests, a future CLI): the manifest of `(item_id, version, blob)`."""
    return signing.manifest((i, v, signing.sha256_b64(b)) for i, v, b in items)
