from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ConsistencyError(RuntimeError):
    pass


class ConsistencyLevel(str, Enum):
    STRONG = "STRONG"
    EVENTUAL = "EVENTUAL"
    STALE = "STALE"


class ProjectorState(str, Enum):
    RUNNING = "RUNNING"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True)
class ReadOptions:
    consistency: ConsistencyLevel
    target_frontier: Mapping[str, int] | None = None
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class ReadMetadata:
    applied_frontier: Mapping[str, int]
    target_frontier: Mapping[str, int]
    lag_events: int
    projector_state: ProjectorState
    stale: bool


class ProjectionTracker:
    def __init__(self, *, applied: Mapping[str, int] | None = None, head: Mapping[str, int] | None = None):
        self.condition = threading.Condition()
        self.applied = dict(applied or {"journal-shadow-1": 0})
        self.head = dict(head or self.applied)
        self.state = ProjectorState.RUNNING

    def update_applied(self, frontier: Mapping[str, int]) -> None:
        with self.condition:
            self.applied.update(frontier); self.condition.notify_all()

    def update_head(self, frontier: Mapping[str, int]) -> None:
        with self.condition:
            self.head.update(frontier); self.condition.notify_all()

    def set_state(self, state: ProjectorState) -> None:
        with self.condition:
            self.state = state; self.condition.notify_all()


def _reached(applied: Mapping[str, int], target: Mapping[str, int]) -> bool:
    return all(applied.get(journal, -1) >= position for journal, position in target.items())


def wait_for_frontier(tracker: ProjectionTracker, options: ReadOptions, *, poll_seconds: float = 0.05) -> ReadMetadata:
    with tracker.condition:
        target = dict(options.target_frontier if options.target_frontier is not None else tracker.head)
    if options.consistency is ConsistencyLevel.STALE:
        applied = dict(tracker.applied)
        return ReadMetadata(applied, target, sum(max(0, target.get(k, 0) - applied.get(k, 0)) for k in target), tracker.state, True)
    if options.consistency is ConsistencyLevel.EVENTUAL:
        applied = dict(tracker.applied)
        return ReadMetadata(applied, target, sum(max(0, target.get(k, 0) - applied.get(k, 0)) for k in target), tracker.state, not _reached(applied, target))
    deadline = time.monotonic() + options.timeout_seconds
    with tracker.condition:
        while not _reached(tracker.applied, target):
            if tracker.state in {ProjectorState.FAILED, ProjectorState.BLOCKED, ProjectorState.INCOMPATIBLE}:
                raise ConsistencyError(f"projector is {tracker.state.value}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConsistencyError("fixed-target projection wait timed out")
            tracker.condition.wait(min(remaining, poll_seconds))
        applied = dict(tracker.applied)
        lag = sum(max(0, tracker.head.get(k, 0) - applied.get(k, 0)) for k in tracker.head)
        return ReadMetadata(applied, target, lag, tracker.state, False)

