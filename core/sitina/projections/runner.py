from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping

from sitina.journal.model import EventEnvelope

from .schema import ProjectionError
from .coverage import MissingRequiredProjectionHandler


ProjectionHandler = Callable[[sqlite3.Connection, EventEnvelope], None]


class ProjectionRunner:
    def __init__(
        self,
        connection: sqlite3.Connection,
        handlers: Mapping[str, ProjectionHandler],
        *,
        projection_name: str = "kernel",
        record_failure: Callable[[dict], None] | None = None,
    ):
        self.connection = connection
        self.handlers = dict(handlers)
        self.projection_name = projection_name
        self.record_failure = record_failure
        self._coordinator = threading.Lock()

    @property
    def offset(self) -> int:
        row = self.connection.execute(
            "SELECT last_position FROM projection_offsets WHERE projection_name=?", (self.projection_name,)
        ).fetchone()
        if row is None:
            raise ProjectionError("projection offset row is missing")
        return int(row[0])

    def apply_batch(self, events: Iterable[EventEnvelope], *, segment_id: str = "active", first_frame_offset: int = 0) -> int:
        batch = tuple(events)
        if not batch:
            return self.offset
        with self._coordinator:
            start = self.offset
            expected = list(range(start + 1, start + len(batch) + 1))
            if [event.position for event in batch] != expected:
                raise ProjectionError("projection batch is not a gap-free committed prefix")
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                for index, event in enumerate(batch):
                    handler = self.handlers.get(event.event_type) or self.handlers.get("*")
                    if handler is not None:
                        handler(self.connection, event)
                    self.connection.execute(
                        "INSERT INTO event_catalog(position,event_hash,stream_id,stream_version,event_type,segment_id,frame_offset) VALUES(?,?,?,?,?,?,?)",
                        (event.position, event.event_hash, event.stream_id, event.stream_version, event.event_type, segment_id, first_frame_offset + index),
                    )
                    previous = self.connection.execute(
                        "SELECT last_stream_version FROM stream_heads WHERE stream_id=?", (event.stream_id,)
                    ).fetchone()
                    if previous is not None and int(previous[0]) + 1 != event.stream_version:
                        raise ProjectionError("projection observed a Stream Version gap")
                    self.connection.execute(
                        "INSERT INTO stream_heads(stream_id,last_stream_version,last_position) VALUES(?,?,?) "
                        "ON CONFLICT(stream_id) DO UPDATE SET last_stream_version=excluded.last_stream_version,last_position=excluded.last_position",
                        (event.stream_id, event.stream_version, event.position),
                    )
                self.connection.execute(
                    "UPDATE projection_offsets SET last_position=?,state='RUNNING' WHERE projection_name=?",
                    (batch[-1].position, self.projection_name),
                )
                self.connection.execute("COMMIT")
                return batch[-1].position
            except BaseException as error:
                try:
                    self.connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                state = "DEGRADED" if isinstance(error, MissingRequiredProjectionHandler) else "FAILED"
                self.connection.execute(
                    "UPDATE projection_offsets SET state=? WHERE projection_name=?",
                    (state, self.projection_name),
                )
                if self.record_failure:
                    self.record_failure(
                        {
                            "schema": "PROJECTION_FAILURE_V1", "projection_name": self.projection_name,
                            "from_position": start + 1, "to_position": batch[-1].position,
                            "error_type": type(error).__name__, "blocking": True, "state": state,
                        }
                    )
                raise

    def store_command_outcome(
        self,
        *,
        command_id: str,
        request_hash: str,
        status: str,
        transaction_hash: str | None,
        first_position: int | None,
        last_position: int | None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO command_outcomes(command_id,request_hash,status,transaction_hash,first_position,last_position) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(command_id) DO UPDATE SET request_hash=excluded.request_hash,status=excluded.status,transaction_hash=excluded.transaction_hash,first_position=excluded.first_position,last_position=excluded.last_position",
            (command_id, request_hash, status, transaction_hash, first_position, last_position),
        )
