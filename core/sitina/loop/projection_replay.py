from __future__ import annotations

from typing import Any, Callable, Mapping

from sitina.journal.model import EventEnvelope

from .coordinator import LoopBackend
from .model import TaskProjection


class _ReplayReadPorts:
    """The production reducer can only read this authenticated snapshot and CAS."""

    def __init__(self, events: tuple[EventEnvelope, ...], read_document: Callable[..., Mapping[str, Any]]):
        self._events = events
        self._read_document = read_document

    def task_events(self, task_id: str, *, after_position: int = 0) -> tuple[EventEnvelope, ...]:
        return tuple(event for event in self._events
                     if event.stream_id == f"loop-task/{task_id}" and event.position > after_position)

    def read(self, reference: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        return self._read_document(reference, expected_hash=expected_hash)


class _ReadOnlyTaskReplay:
    # Reuse the live reducer and its complete validation dependency closure.
    # No LoopBackend, Host, writer lease, scheduler or execution authority is opened.
    _native_wait_binding_current = LoopBackend._native_wait_binding_current
    _advance_task_cache = LoopBackend._advance_task_cache
    _validate_provider_response_disposition = LoopBackend._validate_provider_response_disposition
    _validate_cancel_reconciliation = LoopBackend._validate_cancel_reconciliation
    _provider_response_disposition_binding = LoopBackend._provider_response_disposition_binding
    _recovery_identity_options = LoopBackend._recovery_identity_options
    _validate_software_update_transition = LoopBackend._validate_software_update_transition
    _operation_dispatch_started = LoopBackend._operation_dispatch_started
    _validate_work_plan_evidence = LoopBackend._validate_work_plan_evidence
    _validate_review_failure_evidence = LoopBackend._validate_review_failure_evidence
    _project = LoopBackend._project

    def __init__(self, events: tuple[EventEnvelope, ...], read_document: Callable[..., Mapping[str, Any]]):
        ports = _ReplayReadPorts(events, read_document)
        self.store = ports
        self.context_memory = ports
        self._task_cache: dict[str, TaskProjection] = {}


def replay_task_projection_read_only(
    task_id: str, events: tuple[EventEnvelope, ...], *, read_document: Callable[..., Mapping[str, Any]],
) -> TaskProjection:
    """Replay already authenticated events with production invariants and read-only ports.

    The caller authenticates one complete Journal snapshot and supplies verified
    CAS reads. The disposable projection cache is private to this single read.
    """
    snapshot = tuple(events)
    task_events = tuple(event for event in snapshot if event.stream_id == f"loop-task/{task_id}")
    return _ReadOnlyTaskReplay(snapshot, read_document)._project(task_id, task_events)

