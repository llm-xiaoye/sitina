from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, Mapping

from sitina.journal.model import domain_hash
from sitina.protocols.tasks import TaskAggregate, TaskAttempt, TaskProtocolError

from .decisions import SchedulerDecision


class DispatchError(RuntimeError):
    pass


class DecisionState(str, Enum):
    AVAILABLE = "AVAILABLE"
    CONSUMED = "CONSUMED"
    EXHAUSTED = "EXHAUSTED"
    INVALIDATED = "INVALIDATED"


@dataclass(frozen=True)
class DispatchState:
    decision: SchedulerDecision
    canonical_decision_ref: str
    state: DecisionState = DecisionState.AVAILABLE
    next_attempt_index: int = 0
    events: tuple[dict, ...] = ()


class FixtureWorker:
    def __init__(self):
        self.received: dict[str, tuple[str, str]] = {}
        self.external_calls = 0

    def receive(self, *, dispatch_key: str, task_id: str, attempt: TaskAttempt) -> None:
        existing = self.received.get(dispatch_key)
        value = (task_id, attempt.fencing_token)
        if existing is not None and existing != value:
            raise DispatchError("fixture worker dispatch key conflict")
        self.received[dispatch_key] = value


def project_outbox(connection: sqlite3.Connection, decision: SchedulerDecision, *, source_position: int) -> None:
    for index, task_id in enumerate(decision.ordered_attempts):
        claim_command_id = f"claim-{domain_hash('DISPATCH_CLAIM_COMMAND', (decision.decision_id + ':' + str(index)).encode())}"
        connection.execute(
            "INSERT OR IGNORE INTO dispatch_outbox(decision_id,attempt_index,task_id,claim_command_id,candidate_state,source_position) VALUES(?,?,?,?,?,?)",
            (decision.decision_id, index, task_id, claim_command_id, "CANDIDATE", source_position),
        )


class Dispatcher:
    def __init__(self):
        self._states: dict[str, DispatchState] = {}

    def register_authoritative_decision(self, decision: SchedulerDecision, *, canonical_decision_ref: str) -> DispatchState:
        if len(canonical_decision_ref) != 64:
            raise DispatchError("SchedulerDecision requires a canonical Journal reference")
        existing = self._states.get(decision.decision_id)
        if existing:
            if existing.decision.commitment != decision.commitment or existing.canonical_decision_ref != canonical_decision_ref:
                raise DispatchError("SchedulerDecision ID integrity conflict")
            return existing
        state = DispatchState(decision, canonical_decision_ref)
        self._states[decision.decision_id] = state
        return state

    def invalidate_by_closing(self, decision_id: str, *, closing_ref: str) -> dict:
        state = self._state(decision_id)
        if state.state is DecisionState.CONSUMED: raise DispatchError("consumed decision cannot be retroactively invalidated")
        event = {"schema": "DECISION_INVALIDATED_BY_CLOSING_V1", "decision_id": decision_id, "closing_ref": closing_ref}
        self._states[decision_id] = replace(state, state=DecisionState.INVALIDATED, events=state.events + (event,))
        return event

    def _state(self, decision_id: str) -> DispatchState:
        try: return self._states[decision_id]
        except KeyError as error: raise DispatchError("SQLite-only outbox row has no authoritative SchedulerDecision") from error

    def dispatch_next(
        self,
        decision_id: str,
        tasks: Mapping[str, TaskAggregate],
        *,
        commit_claim: Callable[[str, dict], str],
        worker: FixtureWorker,
        conflict_policy: str = "NEXT_CANDIDATE",
    ) -> tuple[DispatchState, dict[str, TaskAggregate]]:
        state = self._state(decision_id)
        if state.state is not DecisionState.AVAILABLE: raise DispatchError(f"decision is {state.state.value}")
        mutable = dict(tasks); events = list(state.events)
        for index in range(state.next_attempt_index, len(state.decision.ordered_attempts)):
            task_id = state.decision.ordered_attempts[index]
            try: task = mutable[task_id]
            except KeyError: continue
            claim_command_id = f"claim-{domain_hash('DISPATCH_CLAIM_COMMAND', (state.decision.decision_id + ':' + str(index)).encode())}"
            try:
                claimed, attempt, claim_event = task.claim(claim_command_id=claim_command_id, lease_expires_at="2099-01-01T00:00:00Z")
            except TaskProtocolError as error:
                conflict = {"schema": "DISPATCH_ATTEMPT_CONFLICT_V1", "decision_id": decision_id, "attempt_index": index, "task_id": task_id, "frozen_next_action": conflict_policy, "reason": str(error)}
                events.append(conflict)
                if conflict_policy == "NEXT_CANDIDATE": continue
                exhausted = replace(state, state=DecisionState.EXHAUSTED, next_attempt_index=index + 1, events=tuple(events + [{"schema": "DISPATCH_DECISION_EXHAUSTED_V1", "decision_id": decision_id}]))
                self._states[decision_id] = exhausted
                return exhausted, mutable
            canonical_claim_ref = commit_claim(task_id, claim_event)
            if len(canonical_claim_ref) != 64:
                raise DispatchError("TaskClaimed must be canonically committed before worker dispatch")
            mutable[task_id] = claimed
            dispatch_key = f"{decision_id}:{index}:{claim_command_id}"
            worker.receive(dispatch_key=dispatch_key, task_id=task_id, attempt=attempt)
            consumed_event = {"schema": "DISPATCH_DECISION_CONSUMED_V1", "decision_id": decision_id, "attempt_index": index, "task_id": task_id, "claim_command_id": claim_command_id, "task_claim_ref": canonical_claim_ref, "fencing_token": attempt.fencing_token}
            consumed = replace(state, state=DecisionState.CONSUMED, next_attempt_index=index + 1, events=tuple(events + [consumed_event]))
            self._states[decision_id] = consumed
            return consumed, mutable
        exhausted_event = {"schema": "DISPATCH_DECISION_EXHAUSTED_V1", "decision_id": decision_id}
        exhausted = replace(state, state=DecisionState.EXHAUSTED, next_attempt_index=len(state.decision.ordered_attempts), events=tuple(events + [exhausted_event]))
        self._states[decision_id] = exhausted
        return exhausted, mutable

