from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from sitina.journal.model import FrontierRef, canonical_json_bytes

from .runner import ProjectionHandler, ProjectionRunner
from .schema import open_projection


def semantic_checksum(connection: sqlite3.Connection) -> str:
    value = {}
    tables = [
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for table in tables:
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        rows = connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        value[table] = [dict(zip(columns, row, strict=True)) for row in rows]
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class ProjectionGeneration:
    generation_id: str
    database_path: Path
    frontier: FrontierRef
    semantic_checksum: str

    @classmethod
    def build(cls, root: Path, journal, frontier: FrontierRef, handlers: Mapping[str, ProjectionHandler]) -> "ProjectionGeneration":
        root.mkdir(parents=True, exist_ok=True)
        generation_id = "generation-" + uuid.uuid4().hex
        path = root / f"{generation_id}.sqlite"
        connection = open_projection(path)
        try:
            events = tuple(event for event in journal.iter_events(0) if event.position <= frontier.position)
            ProjectionRunner(connection, handlers).apply_batch(events)
            checksum = semantic_checksum(connection)
        finally:
            connection.close()
        return cls(generation_id, path, frontier, checksum)

    def switch(self, root: Path) -> Path:
        pointer = root / "current-generation.json"
        value = canonical_json_bytes(
            {
                "schema": "PROJECTION_GENERATION_POINTER_V1", "generation_id": self.generation_id,
                "database_path": str(self.database_path), "frontier": self.frontier.__dict__,
                "semantic_checksum": self.semantic_checksum,
            }
        )
        temporary = root / f".{pointer.name}.{uuid.uuid4().hex}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, pointer)
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory)
        finally: os.close(directory)
        return pointer
