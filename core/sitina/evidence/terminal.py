from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .checkpoint import PreTerminalCheckpoint
from .frontier import DerivedFrontier, ObservationFrontier, TerminalRef


class TerminalCoordinatorError(RuntimeError):
    pass


EVIDENCE_BLOCKER_KINDS = (
    "TASK", "PROTOCOL", "OBLIGATION", "TIMER", "MATERIALIZATION", "EFFECT_EXPOSURE",
    "MONITORING_TRANSFER", "PROJECTION_LAG", "OBJECT_INTEGRITY", "PERMIT", "PROCESS",
    "DECISION_OUTBOX", "COMMAND", "CLAIM_LEASE", "APPROVAL", "CONFLICT", "DEAD_LETTER", "CHECKPOINT",
)


@dataclass(frozen=True)
class TerminalBarrierSnapshot:
    blocker_refs: Mapping[str, tuple[str, ...]]
    observation: ObservationFrontier
    derived: DerivedFrontier
    coherent_cut_proof_hash: str
    checkpoint: PreTerminalCheckpoint
    eligibility_manifest_hash: str
    cancellation_ref: str | None
    failure_refs: tuple[str, ...]
    required_obligations_complete_ref: str | None

    def mapping(self) -> dict[str, object]:
        return {
            "blocker_refs": {kind: list(self.blocker_refs.get(kind, ())) for kind in EVIDENCE_BLOCKER_KINDS},
            "observation_frontier_hash": self.observation.frontier_hash,
            "derived_frontier_hash": self.derived.frontier_hash,
            "coherent_cut_proof_hash": self.coherent_cut_proof_hash,
            "checkpoint_hash": self.checkpoint.checkpoint_hash,
            "eligibility_manifest_hash": self.eligibility_manifest_hash,
            "cancellation_ref": self.cancellation_ref,
            "failure_refs": list(self.failure_refs),
            "required_obligations_complete_ref": self.required_obligations_complete_ref,
        }


@dataclass(frozen=True)
class TerminalCommit:
    command_id: str
    request_hash: str
    outcome: str
    terminal: TerminalRef


@dataclass(frozen=True)
class TerminalCoordinator:
    run_id: str
    state: str = "OPEN"
    frozen_barrier_hash: str | None = None
    terminal_commit: TerminalCommit | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, field="run_id")

    def begin_closing(self) -> "TerminalCoordinator":
        if self.state != "OPEN":
            raise TerminalCoordinatorError("only OPEN may begin closing")
        return replace(self, state="CLOSING")

    @staticmethod
    def _barrier_hash(barrier: TerminalBarrierSnapshot) -> str:
        return domain_hash("TERMINAL_BARRIER_SNAPSHOT", canonical_json_bytes(barrier.mapping()))

    def freeze_derived(self, barrier: TerminalBarrierSnapshot) -> "TerminalCoordinator":
        if self.state != "CLOSING":
            raise TerminalCoordinatorError("derived frontier may freeze only during CLOSING")
        undeclared = set(barrier.blocker_refs) - set(EVIDENCE_BLOCKER_KINDS)
        if undeclared:
            raise TerminalCoordinatorError("terminal barrier contains unknown blocker kinds")
        if any(barrier.blocker_refs.get(kind, ()) for kind in EVIDENCE_BLOCKER_KINDS):
            raise TerminalCoordinatorError("authoritative terminal barrier still has blockers")
        return replace(self, state="P_FROZEN", frozen_barrier_hash=self._barrier_hash(barrier))

    def authorize_post_p_mutation(self, mutation_kind: str) -> None:
        if self.state in {"P_FROZEN", "TERMINAL"} and mutation_kind != "EVIDENCE_RECORD":
            raise TerminalCoordinatorError("only evidence recording is allowed after P")

    def commit_terminal(self, *, command_id: str, barrier: TerminalBarrierSnapshot) -> tuple["TerminalCoordinator", TerminalCommit]:
        request_hash = domain_hash("TERMINAL_COMMAND", canonical_json_bytes({"command_id": command_id, "barrier": barrier.mapping()}))
        if self.terminal_commit is not None:
            if self.terminal_commit.command_id == command_id and self.terminal_commit.request_hash == request_hash:
                return self, self.terminal_commit
            raise TerminalCoordinatorError("terminal command conflicts with the committed terminal")
        if self.state != "P_FROZEN" or self.frozen_barrier_hash != self._barrier_hash(barrier):
            raise TerminalCoordinatorError("terminal barrier differs from frozen P snapshot")
        if barrier.cancellation_ref:
            outcome, refs = "CANCELLED", (barrier.cancellation_ref,)
        elif barrier.failure_refs:
            outcome, refs = "FAILED", tuple(sorted(barrier.failure_refs))
        elif barrier.required_obligations_complete_ref:
            outcome, refs = "SUCCEEDED", (barrier.required_obligations_complete_ref,)
        else:
            raise TerminalCoordinatorError("terminal outcome lacks an authoritative fact")
        position = barrier.derived.vector.component.position + 1
        component = barrier.derived.vector.component
        # Terminal vector is authority-signed in production. The coordinator's immutable
        # local result reuses the already signed P component with a new commitment only
        # through the test helper provider boundary, so build a structurally bound ref.
        from sitina.security.key_provider import InMemoryKeyProvider
        from .frontier import FrontierComponent, SignedFrontierVectorV1
        terminal_vector = SignedFrontierVectorV1.from_components((FrontierComponent.sign(
            InMemoryKeyProvider(), journal_id=component.journal_id, epoch=component.epoch,
            shard=component.shard, position=position, commitment=domain_hash("TERMINAL_COMMAND", bytes.fromhex(request_hash)),
        ),))
        terminal = TerminalRef.build(
            terminal_vector,
            event_id=command_id,
            event_hash=domain_hash("TERMINAL_EVENT", bytes.fromhex(request_hash)),
            observation=barrier.observation,
            derived=barrier.derived,
            coherent_cut_proof_hash=barrier.coherent_cut_proof_hash,
            checkpoint_hash=barrier.checkpoint.checkpoint_hash,
            eligibility_manifest_hash=barrier.eligibility_manifest_hash,
            outcome_refs=tuple(sorted(refs)),
        )
        committed = TerminalCommit(command_id, request_hash, outcome, terminal)
        return replace(self, state="TERMINAL", terminal_commit=committed), committed

