from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping

from sitina.commands.model import CommandResult, CommandStatus
from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ProcessError(RuntimeError):
    pass


class ProcessStallDetected(ProcessError):
    def __init__(self, manager: "ProcessManager", fact: dict[str, Any]):
        super().__init__(str(fact))
        self.manager = manager
        self.fact = fact


class ProcessState(str, Enum):
    RUNNING = "RUNNING"
    WAITING_OUTCOME = "WAITING_OUTCOME"
    STALLED = "STALLED"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class DurableStep:
    source_event_hash: str
    step_key: str
    command_id: str
    request_hash: str
    generation: int
    step_number: int
    transition_hash: str
    action: str


@dataclass(frozen=True)
class ProcessManager:
    process_id: str
    definition_hash: str
    generation: int = 1
    step_count: int = 0
    max_steps: int = 100
    state: ProcessState = ProcessState.RUNNING
    visited_transition_hashes: tuple[str, ...] = ()
    pending_step: DurableStep | None = None
    journal_facts: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.process_id, field="process_id")
        if len(self.definition_hash) != 64 or self.max_steps < 1: raise ProcessError("invalid process definition or max steps")

    def plan_step(self, *, source_event_hash: str, action: str, payload: Mapping[str, Any]) -> tuple["ProcessManager", DurableStep, tuple[dict, ...]]:
        if self.state is ProcessState.STALLED or self.state is ProcessState.COMPLETED: raise ProcessError("terminal Process cannot plan a step")
        if len(source_event_hash) != 64: raise ProcessError("invalid Source Event hash")
        step_key = domain_hash("PROCESS_STEP_KEY", canonical_json_bytes({"process_id": self.process_id, "definition_hash": self.definition_hash, "generation": self.generation, "source_event_hash": source_event_hash, "action": action}))
        request_hash = domain_hash("PROCESS_STEP_REQUEST", canonical_json_bytes({"step_key": step_key, "payload": dict(payload)}))
        if self.pending_step:
            if self.pending_step.step_key == step_key and self.pending_step.request_hash == request_hash: return self, self.pending_step, ()
            if self.pending_step.step_key == step_key:
                raise ProcessError("same durable step identity has a different request hash")
            raise ProcessError("Process already has a pending Command outcome")
        command_id = f"process-command-{step_key}"
        transition_hash = domain_hash("PROCESS_TRANSITION", canonical_json_bytes({"process_id": self.process_id, "generation": self.generation, "step": self.step_count + 1, "action": action, "request_hash": request_hash}))
        if transition_hash in self.visited_transition_hashes or self.step_count >= self.max_steps:
            reason = "REPEATED_TRANSITION_HASH" if transition_hash in self.visited_transition_hashes else "MAX_STEPS_EXCEEDED"
            event = {"schema": "PROCESS_STALL_DETECTED_V1", "process_id": self.process_id, "reason": reason, "transition_hash": transition_hash, "max_steps": self.max_steps}
            stalled = replace(self, state=ProcessState.STALLED, journal_facts=self.journal_facts + (event,))
            raise ProcessStallDetected(stalled, event)
        step = DurableStep(source_event_hash, step_key, command_id, request_hash, self.generation, self.step_count + 1, transition_hash, action)
        source_fact = {"schema": "PROCESS_SOURCE_OBSERVED_V1", "process_id": self.process_id, "source_event_hash": source_event_hash, "generation": self.generation}
        step_fact = {"schema": "PROCESS_STEP_PLANNED_V1", "process_id": self.process_id, **step.__dict__}
        updated = replace(self, state=ProcessState.WAITING_OUTCOME, pending_step=step, journal_facts=self.journal_facts + (source_fact, step_fact))
        return updated, step, (source_fact, step_fact)

    def reconcile_outcome(self, query: Callable[[str, str], CommandResult]) -> tuple["ProcessManager", tuple[dict, ...]]:
        if not self.pending_step: return self, ()
        step = self.pending_step; result = query(step.command_id, step.request_hash)
        if result.status in {CommandStatus.UNKNOWN, CommandStatus.RETRYABLE_NOT_ACCEPTED}:
            return self, ()
        outcome = {"schema": "PROCESS_STEP_OUTCOME_V1", "process_id": self.process_id, "step_key": step.step_key, "command_id": step.command_id, "request_hash": step.request_hash, "status": result.status.value, "canonical_outcome_ref": result.canonical_outcome_ref}
        if result.status is CommandStatus.CONFLICT:
            stalled = replace(self, state=ProcessState.STALLED, pending_step=None, journal_facts=self.journal_facts + (outcome,))
            return stalled, (outcome,)
        updated = replace(self, state=ProcessState.RUNNING, step_count=step.step_number, visited_transition_hashes=self.visited_transition_hashes + (step.transition_hash,), pending_step=None, journal_facts=self.journal_facts + (outcome,))
        return updated, (outcome,)

    @classmethod
    def rebuild(cls, process_id: str, definition_hash: str, journal_facts: tuple[dict[str, Any], ...], *, max_steps: int = 100) -> "ProcessManager":
        manager = cls(process_id, definition_hash, max_steps=max_steps)
        pending: DurableStep | None = None; visited: list[str] = []; step_count = 0; state = ProcessState.RUNNING
        for fact in journal_facts:
            if fact.get("process_id") != process_id: continue
            if fact["schema"] == "PROCESS_STEP_PLANNED_V1":
                pending = DurableStep(**{key: fact[key] for key in DurableStep.__dataclass_fields__}); state = ProcessState.WAITING_OUTCOME
            elif fact["schema"] == "PROCESS_STEP_OUTCOME_V1" and pending and fact["step_key"] == pending.step_key:
                if fact["status"] == CommandStatus.CONFLICT.value: state = ProcessState.STALLED
                else: visited.append(pending.transition_hash); step_count = pending.step_number; state = ProcessState.RUNNING
                pending = None
            elif fact["schema"] == "PROCESS_STALL_DETECTED_V1": state = ProcessState.STALLED
        return replace(manager, step_count=step_count, state=state, visited_transition_hashes=tuple(visited), pending_step=pending, journal_facts=journal_facts)
