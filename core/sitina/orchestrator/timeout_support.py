"""Run-level cancellation, deadline, and terminal-event support.

This module deliberately contains no provider implementation.  It is the
single source of truth for a run's deadline/cancellation state so every agent
call can observe the same budget, including resumed CLI processes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.utils import ensure_dir, iso_now, read_json, write_json


@dataclass(frozen=True)
class ProviderTimeoutConfig:
    """Timeout and retry limits for one provider request and its parent run."""

    connect_timeout: float = 10.0
    read_timeout: float = 120.0
    total_request_timeout: float = 120.0
    retry_backoff_seconds: float = 1.0
    max_retries: int = 1
    run_deadline: float = 600.0

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ProviderTimeoutConfig":
        def positive_float(key: str, default: float) -> float:
            try:
                value = float(config.get(key, default))
            except (TypeError, ValueError):
                return default
            return value if value > 0 else default

        def non_negative_int(key: str, default: int) -> int:
            try:
                return max(0, int(config.get(key, default)))
            except (TypeError, ValueError):
                return default

        read_timeout = positive_float("read_timeout_seconds", 120.0)
        return cls(
            connect_timeout=positive_float("connect_timeout_seconds", 10.0),
            read_timeout=read_timeout,
            total_request_timeout=positive_float("total_request_timeout_seconds", read_timeout),
            retry_backoff_seconds=positive_float("retry_backoff_seconds", 1.0),
            max_retries=non_negative_int("max_provider_retries", 1),
            run_deadline=positive_float("run_deadline_seconds", 600.0),
        )


@dataclass(frozen=True)
class RunDeadline:
    """A wall-clock deadline that can be reconstructed by another process."""

    run_id: str
    started_at: float
    deadline_at: float
    timeout_seconds: float

    @classmethod
    def create(cls, run_id: str, timeout_seconds: float = 600.0) -> "RunDeadline":
        now = time.time()
        return cls(run_id=run_id, started_at=now, deadline_at=now + timeout_seconds, timeout_seconds=timeout_seconds)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunDeadline":
        return cls(
            run_id=str(payload["run_id"]),
            started_at=float(payload["started_at"]),
            deadline_at=float(payload["deadline_at"]),
            timeout_seconds=float(payload["timeout_seconds"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "deadline_at": self.deadline_at,
            "timeout_seconds": self.timeout_seconds,
        }

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_at - time.time())

    def is_exceeded(self) -> bool:
        return self.remaining_seconds() <= 0.0

    def elapsed_seconds(self) -> float:
        return max(0.0, time.time() - self.started_at)


class RunControlStore:
    """Persist cancellation/deadline state without storing any credentials."""

    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.directory = home / "state" / "run_controls"

    def path(self, run_id: str) -> Path:
        return self.directory / f"{run_id}.json"

    def create(self, deadline: RunDeadline) -> dict[str, Any]:
        ensure_dir(self.directory)
        payload = {
            "run_id": deadline.run_id,
            "deadline": deadline.to_dict(),
            "cancel_requested": False,
            "cancel_reason": None,
            "created_at": iso_now(),
            "updated_at": iso_now(),
        }
        write_json(self.path(deadline.run_id), payload)
        return payload

    def get(self, run_id: str) -> dict[str, Any] | None:
        payload = read_json(self.path(run_id), default=None)
        return payload if isinstance(payload, dict) else None

    def deadline(self, run_id: str) -> RunDeadline | None:
        payload = self.get(run_id)
        deadline = payload.get("deadline") if payload else None
        return RunDeadline.from_dict(deadline) if isinstance(deadline, dict) else None

    def request_cancel(self, run_id: str, reason: str = "cancel requested by user") -> dict[str, Any] | None:
        payload = self.get(run_id)
        if not payload:
            return None
        payload["cancel_requested"] = True
        payload["cancel_reason"] = reason[:500]
        payload["updated_at"] = iso_now()
        write_json(self.path(run_id), payload)
        return payload

    def is_cancel_requested(self, run_id: str) -> bool:
        return bool((self.get(run_id) or {}).get("cancel_requested"))

    def cancel_reason(self, run_id: str) -> str:
        return str((self.get(run_id) or {}).get("cancel_reason") or "cancel requested by user")


class TimeoutError(RuntimeError):
    """Raised when a run-level deadline is exhausted before an agent call."""

    def __init__(self, timeout_type: str, message: str):
        super().__init__(message)
        self.timeout_type = timeout_type


class RunCancelledError(RuntimeError):
    pass


TERMINAL_EVENTS = {
    "run_completed",
    "run_failed",
    "run_blocked",
    "run_timeout",
    "run_cancelled",
    "run_paused",
    "run_interrupted",
}


def completion_invariant(ledger: Any, run_id: str) -> tuple[bool, list[str]]:
    """Return whether ledger evidence permits a successful terminal event.

    The invariant is intentionally event based. It catches shortcut completion
    even if a fixture reaches a `done` code path without all required protocol
    records. Task-graph node completeness remains checked by the engine.
    """

    timeline = ledger.timeline(run_id)
    event_types = [str(event.get("event_type")) for event in timeline]
    failures = {
        "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused",
        "provider_connect_timeout", "provider_read_timeout", "run_deadline_exceeded",
        "provider_auth_failed", "provider_permission_denied", "provider_parse_failed",
        "agent_schema_invalid", "checkpoint_failed",
    }
    reasons: list[str] = []
    if any(event in failures for event in event_types):
        reasons.append("terminal or provider failure already recorded")
    if "task_graph_created" not in event_types:
        reasons.append("missing task graph")
    if "proposal_round_opened" in event_types:
        if "proposal_submitted" not in event_types:
            reasons.append("proposal round has no submitted proposal")
        if "proposal_evaluated" not in event_types:
            reasons.append("proposal round has no evaluation")
        if "proposal_selected" not in event_types:
            reasons.append("proposal round has no selection")
    handoffs = [event for event in timeline if event.get("event_type") == "agent_handoff"]
    accepted = {
        str((event.get("payload_json") or {}).get("handoff_id"))
        for event in timeline
        if event.get("event_type") == "handoff_accepted"
    }
    for event in handoffs:
        payload = event.get("payload_json") or {}
        handoff_id = str(payload.get("handoff_id") or "")
        # The initial dispatch is an envelope setup, not a receiver work node.
        if payload.get("from_agent") == "initial" and payload.get("to_agent") == "controller":
            continue
        if handoff_id and handoff_id not in accepted:
            reasons.append(f"unresolved handoff {handoff_id}")
    if "retry_scheduled" in event_types and "retry_exhausted" not in event_types:
        # A completed rework node records its completion; a bare retry is open.
        retry_nodes = [event for event in event_types if event == "rework_node_created"]
        if not retry_nodes:
            reasons.append("pending retry has no rework node")
    return not reasons, reasons


def ensure_terminal_event(ledger: Any, run_id: str, task_type: str, phase: str, reason: str = "no terminal event recorded") -> None:
    """Write exactly one terminal event, refusing incomplete success states."""

    timeline = ledger.timeline(run_id)
    if any(event.get("event_type") in TERMINAL_EVENTS for event in timeline):
        return
    if phase in {"done", "completed"}:
        ok, missing = completion_invariant(ledger, run_id)
        if ok:
            ledger.record("run_completed", run_id=run_id, task_type=task_type, status="ok", reason=reason, payload={"completion_invariant": "passed"})
        else:
            ledger.record(
                "run_failed",
                run_id=run_id,
                task_type=task_type,
                status="failed",
                reason="completion invariant failed: " + "; ".join(missing),
                payload={"completion_invariant": "failed", "missing": missing},
            )
    elif phase == "blocked":
        ledger.record("run_blocked", run_id=run_id, task_type=task_type, status="blocked", reason=reason, payload={})
    elif phase == "timeout":
        ledger.record("run_timeout", run_id=run_id, task_type=task_type, status="failed", reason=reason, payload={})
    elif phase == "cancelled":
        ledger.record("run_cancelled", run_id=run_id, task_type=task_type, status="failed", reason=reason, payload={})
    elif phase == "interrupted":
        ledger.record("run_interrupted", run_id=run_id, task_type=task_type, status="failed", reason=reason, payload={})
    elif phase == "paused":
        ledger.record("run_paused", run_id=run_id, task_type=task_type, status="pending", reason=reason, payload={})
    else:
        ledger.record("run_failed", run_id=run_id, task_type=task_type, status="failed", reason=reason, payload={"phase": phase})


@dataclass(frozen=True)
class CollaborationCheckpoint:
    checkpoint_id: str
    run_id: str
    round_id: str
    phase: str
    completed_proposals: list[str]
    completed_evaluations: list[str]
    selected_proposal_id: str | None
    created_at: str
    resumable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "run_id": self.run_id,
            "round_id": self.round_id,
            "phase": self.phase,
            "completed_proposals": self.completed_proposals,
            "completed_evaluations": self.completed_evaluations,
            "selected_proposal_id": self.selected_proposal_id,
            "created_at": self.created_at,
            "resumable": self.resumable,
        }
