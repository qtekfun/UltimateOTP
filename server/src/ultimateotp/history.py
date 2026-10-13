# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Vault history: previous committed versions, ciphertext only (contract 1.2.0).

Enables the app's 30-day trash and undo. Every commit that replaces or deletes an item first
copies the item's previous blob into `item_history` (with the version that replaced it) and
records the commit's signed head in `vault_versions`. The state of the vault after any retained
commit V is then: the current rows of `items` that did not change after V, plus the history rows
whose lifetime [version, superseded_by) contains V. A deleted entry's last blob stays in
`item_history` whether or not its tombstone still exists in `items`, which is what makes it
recoverable after tombstone compaction.

Retention is by age (`UOTP_HISTORY_RETENTION_DAYS`) and by per-account caps on versions and bytes;
pruning drops the oldest versions first and is exact: a retained version is always reconstructible.
Key rotation clears the account's history: old-epoch ciphertext must not outlive the rotation.
The server never opens a blob; it only moves them.
"""

import json
import sqlite3
from typing import Any

from ultimateotp.settings import Settings

DAY_S = 86_400
Row = sqlite3.Row


class HistoryPrunedError(Exception):
    """The version existed but aged out of the retention window."""


class NoSuchVersionError(Exception):
    """The version does not exist (yet)."""


class History:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return self.settings.history_retention_days > 0

    # ------------------------------------------------------------------ writing

    @staticmethod
    def previous_blobs(
        conn: sqlite3.Connection, account_id: str, item_ids: list[str]
    ) -> dict[str, Row]:
        """The live rows of `item_ids` (the states a commit is about to overwrite)."""
        found: dict[str, Row] = {}
        for start in range(0, len(item_ids), 500):
            chunk = item_ids[start : start + 500]
            marks = ",".join("?" * len(chunk))
            rows = conn.execute(
                "SELECT item_id, version, blob, blob_sha256 FROM items"  # noqa: S608
                f" WHERE account_id = ? AND deleted = 0 AND item_id IN ({marks})",
                (account_id, *chunk),
            )
            found.update({r["item_id"]: r for r in rows})
        return found

    def record(  # noqa: PLR0913 - one commit's facts
        self,
        conn: sqlite3.Connection,
        account_id: str,
        *,
        version: int,
        key_epoch: int,
        kind: str,
        signed_by: str,
        signature: str,
        now: int,
        upserted: list[str],
        deleted: list[str],
        previous: dict[str, Row],
    ) -> None:
        """Called inside the commit's transaction, before the items are overwritten."""
        if not self.enabled:
            return
        replaced = set(upserted)
        rows = []
        for item_id, prior in previous.items():
            if item_id in replaced or item_id in deleted:
                reason = "deleted" if item_id in deleted else "replaced"
                rows.append(
                    (
                        account_id,
                        item_id,
                        prior["version"],
                        version,
                        reason,
                        prior["blob"],
                        prior["blob_sha256"],
                        len(prior["blob"]),
                    )
                )
        conn.executemany(
            "INSERT OR REPLACE INTO item_history (account_id, item_id, version, superseded_by,"
            " reason, blob, blob_sha256, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.execute(
            "INSERT OR REPLACE INTO vault_versions (account_id, version, key_epoch, kind,"
            " signed_by, signature, committed_at, upserted, deleted)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                account_id,
                version,
                key_epoch,
                kind,
                signed_by,
                signature,
                now,
                json.dumps(sorted(upserted)),
                json.dumps(sorted(deleted)),
            ),
        )

    @staticmethod
    def reset(conn: sqlite3.Connection, account_id: str) -> None:
        """Key rotation: nothing encrypted under an older vault key stays on the server."""
        conn.execute("DELETE FROM item_history WHERE account_id = ?", (account_id,))
        conn.execute("DELETE FROM vault_versions WHERE account_id = ?", (account_id,))

    # ------------------------------------------------------------------ pruning

    def prune_account(
        self, conn: sqlite3.Connection, account_id: str, now: int, current_version: int
    ) -> tuple[int, int]:
        """Drops versions older than the retention, beyond the count cap or over the byte cap.
        Returns (versions removed, previous blobs removed). Never removes the current version."""
        s = self.settings
        if not self.enabled:
            floor = current_version
        else:
            row = conn.execute(
                "SELECT MAX(version) FROM vault_versions WHERE account_id = ? AND committed_at < ?",
                (account_id, now - s.history_retention_days * DAY_S),
            ).fetchone()
            floor = max(row[0] or 0, current_version - s.history_max_versions)
            total = conn.execute(
                "SELECT COALESCE(SUM(size), 0) FROM item_history"
                " WHERE account_id = ? AND superseded_by > ?",
                (account_id, floor),
            ).fetchone()[0]
            if total > s.history_max_bytes:
                for superseded_by, size in conn.execute(
                    "SELECT superseded_by, SUM(size) FROM item_history WHERE account_id = ?"
                    " AND superseded_by > ? GROUP BY superseded_by ORDER BY superseded_by",
                    (account_id, floor),
                ).fetchall():
                    if total <= s.history_max_bytes or superseded_by >= current_version:
                        break
                    total -= size
                    floor = superseded_by
        if floor <= 0:
            return 0, 0
        # Previous blobs go with the versions they replaced (a trash entry expires with its
        # deletion). The current version's own record is kept: it is the head.
        blobs = conn.execute(
            "DELETE FROM item_history WHERE account_id = ? AND superseded_by <= ?",
            (account_id, floor),
        ).rowcount
        record_floor = floor if not self.enabled else min(floor, current_version - 1)
        versions = conn.execute(
            "DELETE FROM vault_versions WHERE account_id = ? AND version <= ?",
            (account_id, record_floor),
        ).rowcount
        return versions, blobs

    # ------------------------------------------------------------------ reading

    def list_versions(
        self, conn: sqlite3.Connection, account_id: str, limit: int, before: int | None
    ) -> tuple[list[dict[str, Any]], int | None]:
        rows = conn.execute(
            "SELECT * FROM vault_versions WHERE account_id = ? AND version < ?"
            " ORDER BY version DESC LIMIT ?",
            (account_id, before if before is not None else 1 << 62, limit + 1),
        ).fetchall()
        page = rows[:limit]
        next_before = page[-1]["version"] if len(rows) > limit and page else None
        return [self.version_dict(r) for r in page], next_before

    @staticmethod
    def version_dict(row: Row) -> dict[str, Any]:
        return {
            "version": row["version"],
            "key_epoch": row["key_epoch"],
            "kind": row["kind"],
            "signed_by": row["signed_by"],
            "signature": row["signature"],
            "committed_at": row["committed_at"],
            "upserted": json.loads(row["upserted"]),
            "deleted": json.loads(row["deleted"]),
        }

    def state_at(
        self,
        conn: sqlite3.Connection,
        account: Row,
        version: int,
        item_id: str | None = None,
    ) -> dict[str, Any]:
        """The vault after commit `version`: its signed head and every live item."""
        account_id = account["id"]
        if version > account["vault_version"]:
            raise NoSuchVersionError
        extra, args = ("", ()) if item_id is None else (" AND item_id = ?", (item_id,))
        if version == account["vault_version"]:
            head = {
                "account_id": account_id,
                "version": version,
                "key_epoch": account["key_epoch"],
                "signed_by": account["head_signed_by"],
                "signature": account["head_signature"],
                "updated_at": account["head_updated_at"],
            }
            rows = conn.execute(
                "SELECT item_id, version, blob FROM items WHERE account_id = ? AND deleted = 0"  # noqa: S608
                + extra
                + " ORDER BY item_id",
                (account_id, *args),
            ).fetchall()
        else:
            meta = conn.execute(
                "SELECT * FROM vault_versions WHERE account_id = ? AND version = ?",
                (account_id, version),
            ).fetchone()
            if meta is None:
                raise HistoryPrunedError
            head = {
                "account_id": account_id,
                "version": version,
                "key_epoch": meta["key_epoch"],
                "signed_by": meta["signed_by"],
                "signature": meta["signature"],
                "updated_at": meta["committed_at"],
            }
            rows = conn.execute(
                "SELECT item_id, version, blob FROM items WHERE account_id = ? AND deleted = 0"  # noqa: S608
                " AND version <= ?" + extra + " UNION ALL"
                " SELECT item_id, version, blob FROM item_history WHERE account_id = ?"
                " AND version <= ? AND superseded_by > ?" + extra + " ORDER BY item_id",
                (account_id, version, *args, account_id, version, version, *args),
            ).fetchall()
        return {
            "head": head,
            "complete": item_id is None,
            "items": [
                {"item_id": r["item_id"], "version": r["version"], "blob": r["blob"]} for r in rows
            ],
        }

    def trash(self, conn: sqlite3.Connection, account: Row) -> list[dict[str, Any]]:
        """Items that are deleted now, newest deletion first, with their last live blob."""
        rows = conn.execute(
            "SELECT h.item_id, h.version, h.blob, h.superseded_by,"
            " COALESCE(v.committed_at, 0) AS deleted_at"
            " FROM item_history h"
            " LEFT JOIN vault_versions v ON v.account_id = h.account_id"
            "  AND v.version = h.superseded_by"
            " LEFT JOIN items i ON i.account_id = h.account_id AND i.item_id = h.item_id"
            " WHERE h.account_id = ? AND h.reason = 'deleted'"
            " AND (i.item_id IS NULL OR i.deleted = 1)"
            " AND h.superseded_by = (SELECT MAX(h2.superseded_by) FROM item_history h2"
            "  WHERE h2.account_id = h.account_id AND h2.item_id = h.item_id)"
            " ORDER BY h.superseded_by DESC, h.item_id",
            (account["id"],),
        ).fetchall()
        return [
            {
                "item_id": r["item_id"],
                "version": r["version"],
                "blob": r["blob"],
                "key_epoch": account["key_epoch"],
                "deleted_in_version": r["superseded_by"],
                "deleted_at": r["deleted_at"],
            }
            for r in rows
        ]

    def export(self, conn: sqlite3.Connection, account_id: str) -> dict[str, Any]:
        versions = conn.execute(
            "SELECT * FROM vault_versions WHERE account_id = ? ORDER BY version DESC", (account_id,)
        ).fetchall()
        records = conn.execute(
            "SELECT item_id, version, superseded_by, reason, blob FROM item_history"
            " WHERE account_id = ? ORDER BY superseded_by DESC, item_id",
            (account_id,),
        ).fetchall()
        return {
            "retention_days": self.settings.history_retention_days,
            "versions": [self.version_dict(r) for r in versions],
            "items": [
                {
                    "item_id": r["item_id"],
                    "version": r["version"],
                    "superseded_by_version": r["superseded_by"],
                    "reason": r["reason"],
                    "blob": r["blob"],
                }
                for r in records
            ],
        }

    # ------------------------------------------------------------------ housekeeping

    def compact_tombstones(self, conn: sqlite3.Connection, now: int) -> int:
        """Deletes tombstones older than `tombstone_retention_days`, remembering per account the
        highest version removed so older clients get a full set (VaultChanges.full)."""
        days = self.settings.tombstone_retention_days
        if days <= 0:
            return 0
        cutoff = now - days * DAY_S
        removed = 0
        for row in conn.execute(
            "SELECT account_id, MAX(version) AS top, COUNT(*) AS n FROM items"
            " WHERE deleted = 1 AND updated_at < ? GROUP BY account_id",
            (cutoff,),
        ).fetchall():
            conn.execute(
                "UPDATE accounts SET tombstones_compacted_through ="
                " MAX(tombstones_compacted_through, ?) WHERE id = ?",
                (row["top"], row["account_id"]),
            )
            conn.execute(
                "DELETE FROM items WHERE account_id = ? AND deleted = 1 AND updated_at < ?",
                (row["account_id"], cutoff),
            )
            removed += row["n"]
        return removed
