"""Dedicated SQLite read-only adapter for Legacy data and independent snapshots."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"unsafe SQLite identifier: {value!r}")
    return '"' + value.replace('"', '""') + '"'


@dataclass(frozen=True)
class SQLiteSnapshotIdentity:
    path: str
    size: int
    mtime_ns: int
    inode: int
    device: int
    sha256: str


class LegacySQLiteReader:
    def __init__(self, db_path: Path, connection: sqlite3.Connection, *, independent_snapshot: bool):
        self.db_path = db_path
        self.connection = connection
        self.independent_snapshot = independent_snapshot

    @classmethod
    def open(cls, db_path: Path, *, immutable: bool = False) -> "LegacySQLiteReader":
        path = Path(db_path).expanduser().resolve(strict=False)
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(path)
        if immutable:
            raise ValueError("immutable=1 requires open_snapshot() and an independently materialized snapshot")
        encoded = urllib.parse.quote(str(path), safe="/")
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return cls(path, connection, independent_snapshot=False)

    @classmethod
    def open_snapshot(cls, db_path: Path) -> "LegacySQLiteReader":
        path = Path(db_path).expanduser().resolve(strict=False)
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(path)
        if path.with_name(path.name + "-wal").exists() or path.with_name(path.name + "-shm").exists():
            raise ValueError("independent immutable snapshot must not depend on WAL/SHM sidecars")
        encoded = urllib.parse.quote(str(path), safe="/")
        connection = sqlite3.connect(f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return cls(path, connection, independent_snapshot=True)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "LegacySQLiteReader":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def table_names(self) -> list[str]:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [str(row[0]) for row in rows]

    def schema(self, table: str) -> list[dict[str, Any]]:
        name = _identifier(table)
        return [dict(row) for row in self.connection.execute(f"PRAGMA table_info({name})")]

    def table_count(self, table: str) -> int:
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {_identifier(table)}").fetchone()[0])

    def table_max_integer_key(self, table: str, key_column: str = "id") -> int | None:
        columns = {item["name"]: str(item["type"] or "").upper() for item in self.schema(table)}
        if key_column not in columns or "INT" not in columns[key_column]:
            return None
        value = self.connection.execute(
            f"SELECT MAX({_identifier(key_column)}) FROM {_identifier(table)}"
        ).fetchone()[0]
        return int(value) if value is not None else None

    def iter_table_rows(
        self,
        table: str,
        *,
        key_column: str = "id",
        after_id: int = 0,
        batch_size: int = 1000,
    ) -> Iterator[dict[str, Any]]:
        if batch_size <= 0 or batch_size > 100_000:
            raise ValueError("batch_size must be in 1..100000")
        table_sql = _identifier(table)
        key_sql = _identifier(key_column)
        columns = {item["name"] for item in self.schema(table)}
        if key_column not in columns:
            raise ValueError(f"missing key column {key_column!r} in {table!r}")
        cursor = int(after_id)
        while True:
            rows = self.connection.execute(
                f"SELECT * FROM {table_sql} WHERE {key_sql} > ? ORDER BY {key_sql} LIMIT ?",
                (cursor, batch_size),
            ).fetchall()
            if not rows:
                return
            for row in rows:
                value = dict(row)
                cursor = int(value[key_column])
                yield value

    def snapshot_identity(self) -> SQLiteSnapshotIdentity:
        before = self.db_path.stat()
        digest = hashlib.sha256()
        with self.db_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
        after = self.db_path.stat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        if identity(before) != identity(after):
            raise RuntimeError("SQLite source changed while hashing snapshot identity")
        return SQLiteSnapshotIdentity(
            path=str(self.db_path),
            size=before.st_size,
            mtime_ns=before.st_mtime_ns,
            inode=before.st_ino,
            device=before.st_dev,
            sha256=digest.hexdigest(),
        )
