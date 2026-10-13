# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""SQLite access (WAL) and the plain SQL migrator.

Each request opens its own short-lived connection (SQLite connections are cheap and not
shareable across threads). Writes that read-then-write (commits, enrollment, pairing) run in
`BEGIN IMMEDIATE`, which takes the database write lock up front: the optimistic-concurrency
check and the write it guards can never interleave with another writer.

Migrations: `NNNN_name.sql` files applied in order, one transaction each, recorded in
`schema_migrations` (same rules as UltimateTunes' contracts/db/README.md: a statement ends with
`;` at the end of a line, `--` comments on their own lines).
"""

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from ultimateotp.clock import Clock, SystemClock

BUSY_TIMEOUT_MS = 5000
_NAME = re.compile(r"^(?P<version>\d{4})_[a-z0-9_]+\.sql$")
_STATEMENT_END = re.compile(r";[ \t]*$", re.MULTILINE)


def connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        conn = sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, isolation_level=None, check_same_thread=False
        )
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        with closing(connect(self.path)) as conn:
            yield conn

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """One `BEGIN IMMEDIATE` transaction: committed on success, rolled back on error."""
        with closing(connect(self.path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str


def discover(directory: Path) -> list[Migration]:
    if not directory.is_dir():
        raise FileNotFoundError(f"migrations directory not found: {directory}")
    migrations: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = _NAME.match(path.name)
        if match is None:
            raise ValueError(f"bad migration file name: {path.name}")
        migrations.append(
            Migration(int(match["version"]), path.name, path.read_text(encoding="utf-8"))
        )
    if len({m.version for m in migrations}) != len(migrations):
        raise ValueError("two migrations share a version number")
    return migrations


def split_statements(sql: str) -> list[str]:
    lines = [line for line in sql.splitlines() if not line.lstrip().startswith("--")]
    return [s.strip() for s in _STATEMENT_END.split("\n".join(lines)) if s.strip()]


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if exists is None:
        return set()
    return {int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations")}


def pending(conn: sqlite3.Connection, directory: Path) -> list[Migration]:
    done = applied_versions(conn)
    return [m for m in discover(directory) if m.version not in done]


def migrate(path: Path, directory: Path, clock: Clock | None = None) -> list[Migration]:
    clock = clock or SystemClock()
    applied: list[Migration] = []
    with closing(connect(path)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)"
        )
        for migration in pending(conn, directory):
            conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in split_statements(migration.sql):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (migration.version, migration.name, clock.now()),
                )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
            applied.append(migration)
    return applied


def backup(source: Path, destination: Path) -> None:
    """Consistent online copy with SQLite's backup API (safe while the api writes)."""
    if destination.exists():
        raise FileExistsError(f"backup destination exists: {destination}")
    with (
        closing(connect(source, read_only=True)) as src,
        closing(sqlite3.connect(destination)) as dst,
    ):
        src.backup(dst)
