from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .run import RunAggregate, RunState


class TerminalEligibilityError(RuntimeError):
    pass


class BlockerKind(str, Enum):
    TASK = "TASK"
    PROTOCOL = "PROTOCOL"
    OBLIGATION = "OBLIGATION"
    TIMER = "TIMER"
    MATERIALIZATION = "MATERIALIZATION"
    EFFECT_EXPOSURE = "EFFECT_EXPOSURE"
    MONITORING_TRANSFER = "MONITORING_TRANSFER"
    PROJECTION_LAG = "PROJECTION_LAG"
    OBJECT_INTEGRITY = "OBJECT_INTEGRITY"
    PERMIT = "PERMIT"
    PROCESS = "PROCESS"
    DECISION_OUTBOX = "DECISION_OUTBOX"
    COMMAND = "COMMAND"
    CLAIM_LEASE = "CLAIM_LEASE"
    APPROVAL = "APPROVAL"
    CONFLICT = "CONFLICT"
    EFFECT_PLACEHOLDER = "EFFECT_PLACEHOLDER"
    DEAD_LETTER = "DEAD_LETTER"
    CHECKPOINT = "CHECKPOINT"


@dataclass(frozen=True)
class TerminalEligibilityProjection:
    run_id: str
    counts: Mapping[BlockerKind, int]
    source_position: int

    @classmethod
    def empty(cls, run_id: str) -> "TerminalEligibilityProjection":
        validate_identifier(run_id, field="run_id")
        return cls(run_id, {kind: 0 for kind in BlockerKind}, 0)

    def apply(self, kind: BlockerKind, delta: int, *, source_position: int) -> "TerminalEligibilityProjection":
        if source_position != self.source_position + 1: raise TerminalEligibilityError("terminal projection requires a gap-free source prefix")
        counts = dict(self.counts); value = counts[kind] + delta
        if value < 0: raise TerminalEligibilityError("terminal blocker count cannot be negative")
        counts[kind] = value
        return replace(self, counts=counts, source_position=source_position)

    @property
    def candidate(self) -> bool:
        return all(count == 0 for count in self.counts.values())


@dataclass(frozen=True)
class AuthoritativeTerminalFacts:
    blocker_refs: Mapping[BlockerKind, tuple[str, ...]]
    cancellation_requested_ref: str | None
    failure_refs: tuple[str, ...]
    required_obligations_complete_ref: str | None
    policy_hash: str

    def __post_init__(self) -> None:
        if len(self.policy_hash) != 64: raise TerminalEligibilityError("invalid terminal policy hash")
        for references in self.blocker_refs.values():
            if any(len(reference) != 64 for reference in references): raise TerminalEligibilityError("terminal blocker lacks canonical fact reference")
        outcome_references = (
            *((self.cancellation_requested_ref,) if self.cancellation_requested_ref else ()),
            *self.failure_refs,
            *((self.required_obligations_complete_ref,) if self.required_obligations_complete_ref else ()),
        )
        if any(len(reference) != 64 for reference in outcome_references):
            raise TerminalEligibilityError("terminal outcome lacks canonical fact reference")


@dataclass(frozen=True)
class TerminalDecision:
    command_id: str
    request_hash: str
    terminal_state: RunState
    source_position: int
    authoritative_fact_hash: str


def full_validate(projection: TerminalEligibilityProjection, run: RunAggregate, facts: AuthoritativeTerminalFacts) -> TerminalDecision:
    if not projection.candidate: raise TerminalEligibilityError("Projection is not even a terminal candidate")
    if run.state is not RunState.CLOSING: raise TerminalEligibilityError("authoritative Run is not CLOSING")
    actual_counts = {kind: len(facts.blocker_refs.get(kind, ())) for kind in BlockerKind}
    if any(actual_counts.values()): raise TerminalEligibilityError("authoritative full validation found blockers")
    if facts.cancellation_requested_ref:
        state = RunState.CANCELLED
    elif facts.failure_refs:
        state = RunState.FAILED
    elif facts.required_obligations_complete_ref:
        state = RunState.SUCCEEDED
    else:
        raise TerminalEligibilityError("no authoritative terminal outcome fact")
    fact_value = {
        "run_id": run.run_id, "run_stream_version": run.stream_version, "source_position": projection.source_position,
        "blocker_refs": {kind.value: list(facts.blocker_refs.get(kind, ())) for kind in BlockerKind},
        "cancellation_requested_ref": facts.cancellation_requested_ref, "failure_refs": list(facts.failure_refs),
        "required_obligations_complete_ref": facts.required_obligations_complete_ref, "policy_hash": facts.policy_hash,
        "terminal_state": state.value,
    }
    request_hash = domain_hash("TERMINAL_VALIDATION", canonical_json_bytes(fact_value))
    return TerminalDecision(f"terminal-command-{request_hash}", request_hash, state, projection.source_position, domain_hash("TERMINAL_FACT_SET", canonical_json_bytes(fact_value)))


def apply_terminal_decision(run: RunAggregate, decision: TerminalDecision) -> tuple[RunAggregate, dict]:
    return run.terminal(decision.terminal_state, expected_stream_version=run.stream_version)
