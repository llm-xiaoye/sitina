from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp

from .tasks import TaskAggregate


class HandoffError(RuntimeError):
    def __init__(self, message: str, *, fact: dict[str, Any] | None = None):
        super().__init__(message)
        self.fact = fact


class HandoffState(str, Enum):
    OFFERED = "OFFERED"
    CLARIFICATION = "CLARIFICATION"
    ACCEPTED = "ACCEPTED"
    CLAIM_PENDING = "CLAIM_PENDING"
    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    SUBMITTED = "SUBMITTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    REWORK = "REWORK"
    SUPERSEDED = "SUPERSEDED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class Handoff:
    handoff_id: str
    generation: int
    sender_id: str
    receiver_id: str
    task_id: str
    specification_hash: str
    policy_hash: str
    capability_hash: str
    budget: int
    deadline: str
    high_risk: bool
    generation_hash: str
    max_generations: int = 3
    required_capabilities: tuple[str, ...] = ()
    input_freeze_hash: str = ""
    output_schema_hash: str = ""
    previous_generation_hash: str | None = None
    previous_generation_ref: str | None = None
    previous_rejection_event_ref: str | None = None
    reject_reason_resolution_hash: str | None = None
    closed_generation_hashes: tuple[str, ...] = ()
    state: HandoffState = HandoffState.OFFERED
    version: int = 1
    accepted_by: str | None = None
    task_attempt_id: str | None = None
    claim_generation: int | None = None
    fencing_token: str | None = None
    artifact_hash: str | None = None
    verifier_id: str | None = None

    @classmethod
    def offer(
        cls,
        handoff_id: str,
        generation: int,
        sender_id: str,
        receiver_id: str,
        task_id: str,
        specification_hash: str,
        *,
        policy_hash: str,
        capability_hash: str,
        budget: int,
        deadline: str,
        high_risk: bool,
        max_generations: int = 3,
        required_capabilities: tuple[str, ...] = (),
        receiver_capabilities: tuple[str, ...] = (),
        input_freeze_hash: str | None = None,
        output_schema_hash: str | None = None,
        previous_generation_hash: str | None = None,
        previous_generation_ref: str | None = None,
        previous_rejection_event_ref: str | None = None,
        reject_reason_resolution_hash: str | None = None,
    ) -> tuple["Handoff", dict[str, Any]]:
        for value, field in (
            (handoff_id, "handoff_id"),
            (sender_id, "handoff_sender"),
            (receiver_id, "handoff_receiver"),
            (task_id, "task_id"),
        ):
            validate_identifier(value, field=field)
        validate_timestamp(deadline)
        if generation < 1 or budget < 1 or max_generations < generation:
            raise HandoffError("Handoff generation/budget must be positive")
        if sender_id == receiver_id:
            raise HandoffError("Handoff sender and receiver must differ")
        if any(len(value) != 64 for value in (specification_hash, policy_hash, capability_hash)):
            raise HandoffError("Handoff generation requires exact frozen hashes")
        for capability in required_capabilities:
            validate_identifier(capability, field="handoff_required_capability")
        missing_capabilities = sorted(set(required_capabilities) - set(receiver_capabilities))
        if missing_capabilities:
            raise HandoffError("Handoff receiver lacks required capabilities")
        frozen_input_hash = input_freeze_hash or specification_hash
        frozen_schema_hash = output_schema_hash or specification_hash
        if len(frozen_input_hash) != 64 or len(frozen_schema_hash) != 64:
            raise HandoffError("Handoff input freeze and output schema require exact hashes")
        if generation > 1 and (
            not previous_generation_hash
            or len(previous_generation_hash) != 64
            or not previous_generation_ref
            or not previous_rejection_event_ref
            or not reject_reason_resolution_hash
            or len(reject_reason_resolution_hash) != 64
        ):
            raise HandoffError("new Handoff generation requires complete closed-generation lineage")
        frozen = {
            "handoff_id": handoff_id,
            "generation": generation,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "task_id": task_id,
            "specification_hash": specification_hash,
            "policy_hash": policy_hash,
            "capability_hash": capability_hash,
            "budget": budget,
            "deadline": deadline,
            "high_risk": high_risk,
            "max_generations": max_generations,
            "required_capabilities": list(required_capabilities),
            "receiver_capability_validation": "PASSED",
            "input_freeze_hash": frozen_input_hash,
            "output_schema_hash": frozen_schema_hash,
            "previous_generation_hash": previous_generation_hash,
            "previous_generation_ref": previous_generation_ref,
            "previous_rejection_event_ref": previous_rejection_event_ref,
            "reject_reason_resolution_hash": reject_reason_resolution_hash,
        }
        generation_hash = domain_hash("HANDOFF_GENERATION", canonical_json_bytes(frozen))
        aggregate = cls(
            handoff_id=handoff_id,
            generation=generation,
            sender_id=sender_id,
            receiver_id=receiver_id,
            task_id=task_id,
            specification_hash=specification_hash,
            policy_hash=policy_hash,
            capability_hash=capability_hash,
            budget=budget,
            deadline=deadline,
            high_risk=high_risk,
            generation_hash=generation_hash,
            max_generations=max_generations,
            required_capabilities=tuple(required_capabilities),
            input_freeze_hash=frozen_input_hash,
            output_schema_hash=frozen_schema_hash,
            previous_generation_hash=previous_generation_hash,
            previous_generation_ref=previous_generation_ref,
            previous_rejection_event_ref=previous_rejection_event_ref,
            reject_reason_resolution_hash=reject_reason_resolution_hash,
        )
        return aggregate, {"schema": "HANDOFF_OFFERED_V1", **frozen, "generation_hash": generation_hash}

    def _actor_receiver(self, actor_id: str) -> None:
        if actor_id != self.receiver_id:
            raise HandoffError("only the frozen receiver may perform this Handoff command")

    def _not_terminal(self) -> None:
        if self.state in {
            HandoffState.VERIFIED,
            HandoffState.REJECTED,
            HandoffState.SUPERSEDED,
            HandoffState.CANCELLED,
            HandoffState.FAILED,
        }:
            raise HandoffError(f"Handoff generation is permanently {self.state.value}")

    def clarify(self, actor_id: str, clarification_ref: str) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        if actor_id not in {self.sender_id, self.receiver_id} or len(clarification_ref) != 64:
            raise HandoffError("invalid Handoff clarification")
        updated = replace(self, state=HandoffState.CLARIFICATION, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_CLARIFICATION_RECORDED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "actor_id": actor_id,
            "clarification_ref": clarification_ref,
        }

    def accept(
        self, actor_id: str, *, now: str = "2026-07-13T00:00:00Z"
    ) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        self._actor_receiver(actor_id)
        if self.state not in {HandoffState.OFFERED, HandoffState.CLARIFICATION}:
            raise HandoffError("Handoff cannot be accepted from current state")
        validate_timestamp(now)
        if dt.datetime.fromisoformat(now.replace("Z", "+00:00")) >= dt.datetime.fromisoformat(
            self.deadline.replace("Z", "+00:00")
        ):
            raise HandoffError("Handoff deadline expired")
        updated = replace(
            self,
            state=HandoffState.ACCEPTED,
            version=self.version + 1,
            accepted_by=actor_id,
        )
        return updated, {
            "schema": "HANDOFF_ACCEPTED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "receiver_id": actor_id,
            "generation_hash": self.generation_hash,
        }

    def reject(self, actor_id: str, reason: str) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        self._actor_receiver(actor_id)
        if self.state not in {HandoffState.OFFERED, HandoffState.CLARIFICATION}:
            raise HandoffError("Handoff cannot be rejected from current state")
        if not reason.strip():
            raise HandoffError("Handoff rejection requires a reason")
        updated = replace(self, state=HandoffState.REJECTED, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_REJECTED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "reason": reason,
            "generation_hash": self.generation_hash,
            "generation_permanently_closed": True,
        }

    def reject_classified(
        self,
        actor_id: str,
        *,
        reason_code: str,
        classification: str,
    ) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        self._actor_receiver(actor_id)
        validate_identifier(reason_code, field="handoff_rejection_reason_code")
        if classification not in {"repairable", "permission", "safety", "cancelled"}:
            raise HandoffError("Handoff rejection classification is invalid")
        if self.state not in {HandoffState.OFFERED, HandoffState.CLARIFICATION, HandoffState.ACCEPTED}:
            raise HandoffError("Handoff cannot be classified-rejected from current state")
        target = {
            "repairable": HandoffState.REWORK,
            "permission": HandoffState.FAILED,
            "safety": HandoffState.FAILED,
            "cancelled": HandoffState.CANCELLED,
        }[classification]
        updated = replace(self, state=target, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_CLASSIFIED_REJECTION_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "actor_id": actor_id,
            "reason_code": reason_code,
            "classification": classification,
            "to_state": target.value,
            "fail_closed": classification in {"permission", "safety"},
            "rework_allowed": classification == "repairable" and self.generation < self.max_generations,
            "generation_permanently_closed": target in {HandoffState.FAILED, HandoffState.CANCELLED},
        }

    def cancel(
        self,
        actor_id: str,
        *,
        reason_code: str,
        cleanup_refs: tuple[str, ...] = (),
    ) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        if actor_id not in {self.sender_id, self.receiver_id}:
            raise HandoffError("only a Handoff party may cancel it")
        validate_identifier(reason_code, field="handoff_cancel_reason_code")
        if any(not item.startswith("cas:") for item in cleanup_refs):
            raise HandoffError("Handoff cancellation cleanup refs must be CAS references")
        updated = replace(self, state=HandoffState.CANCELLED, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_CANCELLED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "actor_id": actor_id,
            "reason_code": reason_code,
            "cleanup_refs": list(sorted(set(cleanup_refs))),
            "cleanup_required": bool(cleanup_refs),
            "generation_permanently_closed": True,
        }

    def close_for_new_generation(
        self, actor_id: str, *, reason_ref: str
    ) -> tuple["Handoff", dict[str, Any]]:
        self._actor_receiver(actor_id)
        if self.state is not HandoffState.CLARIFICATION or len(reason_ref) != 64:
            raise HandoffError("only a clarified Handoff may close for a new generation")
        updated = replace(self, state=HandoffState.SUPERSEDED, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_GENERATION_CLOSED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "generation_hash": self.generation_hash,
            "disposition": "CLARIFICATION_REQUIRES_NEW_GENERATION",
            "reason_ref": reason_ref,
            "generation_permanently_closed": True,
        }

    def mark_claim_pending(
        self,
        actor_id: str,
        *,
        task_claim_ref: str,
        fencing_token: str,
    ) -> tuple["Handoff", dict[str, Any]]:
        self._actor_receiver(actor_id)
        if self.state is not HandoffState.ACCEPTED:
            raise HandoffError("Handoff ClaimPending requires accepted state")
        if len(task_claim_ref) != 64 or len(fencing_token) != 64:
            raise HandoffError("Handoff ClaimPending requires frozen claim and fence refs")
        updated = replace(self, state=HandoffState.CLAIM_PENDING, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_CLAIM_PENDING_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "receiver_id": actor_id,
            "task_claim_ref": task_claim_ref,
            "reserved_fencing_token": fencing_token,
        }

    def bind_claim(
        self, task: TaskAggregate, fencing_token: str
    ) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        if self.state is not HandoffState.CLAIM_PENDING:
            raise HandoffError("Task Claim can bind only a ClaimPending Handoff")
        if task.task_id != self.task_id:
            raise HandoffError("Task Claim belongs to another Task")
        attempt = task.active_attempt
        if attempt is None or attempt.fencing_token != fencing_token:
            raise HandoffError("Handoff requires a current Task Claim fence")
        if attempt.holder_agent_id != self.receiver_id:
            raise HandoffError("Handoff Task Claim is owned by another Agent")
        updated = replace(
            self,
            state=HandoffState.CLAIMED,
            version=self.version + 1,
            task_attempt_id=attempt.task_attempt_id,
            claim_generation=attempt.claim_generation,
            fencing_token=fencing_token,
        )
        return updated, {
            "schema": "HANDOFF_TASK_CLAIM_BOUND_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "task_attempt_id": attempt.task_attempt_id,
            "claim_generation": attempt.claim_generation,
            "holder_agent_id": attempt.holder_agent_id,
            "lease_id": attempt.lease_id,
            "fencing_token": fencing_token,
        }

    def execute(self, actor_id: str) -> tuple["Handoff", dict[str, Any]]:
        self._not_terminal()
        self._actor_receiver(actor_id)
        if self.state is not HandoffState.CLAIMED or not self.fencing_token:
            raise HandoffError("accepted Handoff cannot execute before a valid Task Claim")
        updated = replace(self, state=HandoffState.EXECUTING, version=self.version + 1)
        return updated, {
            "schema": "HANDOFF_EXECUTION_STARTED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "task_attempt_id": self.task_attempt_id,
            "fencing_token": self.fencing_token,
        }

    def submit(
        self,
        actor_id: str,
        artifact_hash: str,
        *,
        output_schema_hash: str,
        schema_validation_evidence_hash: str,
    ) -> tuple["Handoff", dict[str, Any]]:
        self._actor_receiver(actor_id)
        if self.state is not HandoffState.EXECUTING or len(artifact_hash) != 64:
            raise HandoffError("Handoff submission requires executing state and Artifact Hash")
        if output_schema_hash != self.output_schema_hash or len(schema_validation_evidence_hash) != 64:
            raise HandoffError("Handoff submission failed frozen output-schema validation")
        updated = replace(
            self,
            state=HandoffState.SUBMITTED,
            version=self.version + 1,
            artifact_hash=artifact_hash,
        )
        return updated, {
            "schema": "HANDOFF_RESULT_SUBMITTED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "artifact_hash": artifact_hash,
            "fencing_token": self.fencing_token,
            "output_schema_hash": output_schema_hash,
            "schema_validation_evidence_hash": schema_validation_evidence_hash,
            "schema_validation_passed": True,
        }

    def submit_fenced(
        self,
        actor_id: str,
        artifact_hash: str,
        *,
        task: TaskAggregate,
        output_schema_hash: str,
        schema_validation_evidence_hash: str,
    ) -> tuple["Handoff", dict[str, Any]]:
        attempt = task.active_attempt
        if (
            task.task_id != self.task_id
            or attempt is None
            or self.task_attempt_id != attempt.task_attempt_id
            or self.claim_generation != attempt.claim_generation
            or self.fencing_token != attempt.fencing_token
        ):
            raise HandoffError("Handoff submission requires the current Task generation and fencing token")
        updated, fact = self.submit(
            actor_id,
            artifact_hash,
            output_schema_hash=output_schema_hash,
            schema_validation_evidence_hash=schema_validation_evidence_hash,
        )
        return updated, {
            **fact,
            "task_attempt_id": attempt.task_attempt_id,
            "claim_generation": attempt.claim_generation,
            "current_fencing_token_verified": True,
        }

    def verify(
        self,
        verifier_id: str,
        *,
        accepted: bool,
        verification_evidence_hash: str,
    ) -> tuple["Handoff", dict[str, Any]]:
        validate_identifier(verifier_id, field="handoff_verifier")
        if self.state is not HandoffState.SUBMITTED:
            raise HandoffError("Handoff verification requires submitted state")
        if len(verification_evidence_hash) != 64:
            raise HandoffError("Handoff verification requires immutable Evidence")
        if self.high_risk and verifier_id in {self.sender_id, self.receiver_id}:
            raise HandoffError("high-risk Handoff requires an independent verifier")
        state = HandoffState.VERIFIED if accepted else HandoffState.REWORK
        updated = replace(
            self,
            state=state,
            version=self.version + 1,
            verifier_id=verifier_id,
        )
        return updated, {
            "schema": "HANDOFF_VERIFIED_V1" if accepted else "HANDOFF_REWORK_REQUIRED_V1",
            "handoff_id": self.handoff_id,
            "generation": self.generation,
            "verifier_id": verifier_id,
            "artifact_hash": self.artifact_hash,
            "verification_evidence_hash": verification_evidence_hash,
            "output_hash_bound": True,
        }

    def new_generation(self, **changes: Any) -> tuple["Handoff", dict[str, Any]]:
        if self.state not in {HandoffState.REJECTED, HandoffState.SUPERSEDED, HandoffState.REWORK}:
            raise HandoffError("new Handoff generation requires a closed or rework predecessor")
        if self.generation >= self.max_generations:
            fact = {
                "schema": "HANDOFF_GENERATION_LIMIT_REACHED_V1",
                "handoff_id": self.handoff_id,
                "generation": self.generation,
                "max_generations": self.max_generations,
                "prior_generation_hash": self.generation_hash,
                "terminal_disposition": "FAILED_GENERATION_LIMIT_REACHED",
            }
            raise HandoffError("Handoff generation limit reached", fact=fact)
        next_receiver_id = str(changes.get("receiver_id", self.receiver_id))
        closed_hashes = self.closed_generation_hashes + (self.generation_hash,)
        next_handoff, opened = Handoff.offer(
            self.handoff_id,
            self.generation + 1,
            self.sender_id,
            next_receiver_id,
            self.task_id,
            changes["specification_hash"],
            policy_hash=changes["policy_hash"],
            capability_hash=changes["capability_hash"],
            budget=changes["budget"],
            deadline=changes["deadline"],
            high_risk=bool(changes.get("high_risk", self.high_risk)),
            max_generations=self.max_generations,
            required_capabilities=tuple(changes.get("required_capabilities", self.required_capabilities)),
            receiver_capabilities=tuple(changes["receiver_capabilities"]),
            input_freeze_hash=str(changes["input_freeze_hash"]),
            output_schema_hash=str(changes["output_schema_hash"]),
            previous_generation_hash=self.generation_hash,
            previous_generation_ref=str(changes["previous_generation_ref"]),
            previous_rejection_event_ref=str(changes["previous_rejection_event_ref"]),
            reject_reason_resolution_hash=str(changes["reject_reason_resolution_hash"]),
        )
        next_handoff = replace(next_handoff, closed_generation_hashes=closed_hashes)
        return next_handoff, {
            **opened,
            "schema": "HANDOFF_GENERATION_OPENED_V2",
            "prior_generation": self.generation,
            "prior_generation_hash": self.generation_hash,
            "prior_terminal_state": self.state.value,
            "previous_generation_permanently_closed": True,
            "old_acceptance_reused": False,
            "closed_generation_hashes": list(closed_hashes),
        }

    @classmethod
    def rebuild(cls, facts: tuple[dict[str, Any], ...]) -> "Handoff":
        current: Handoff | None = None
        for fact in facts:
            schema = str(fact.get("schema", ""))
            if schema in {"HANDOFF_OFFERED_V1", "HANDOFF_GENERATION_OPENED_V1", "HANDOFF_GENERATION_OPENED_V2"}:
                prior_closed = () if current is None else current.closed_generation_hashes
                if schema != "HANDOFF_OFFERED_V1" and current is not None:
                    prior_closed = tuple(
                        str(item) for item in fact.get(
                            "closed_generation_hashes", (*prior_closed, current.generation_hash)
                        )
                    )
                current = cls(
                    handoff_id=str(fact["handoff_id"]),
                    generation=int(fact["generation"]),
                    sender_id=str(fact["sender_id"]),
                    receiver_id=str(fact["receiver_id"]),
                    task_id=str(fact["task_id"]),
                    specification_hash=str(fact["specification_hash"]),
                    policy_hash=str(fact["policy_hash"]),
                    capability_hash=str(fact["capability_hash"]),
                    budget=int(fact["budget"]),
                    deadline=str(fact["deadline"]),
                    high_risk=bool(fact["high_risk"]),
                    generation_hash=str(fact["generation_hash"]),
                    max_generations=int(fact.get("max_generations", 3)),
                    required_capabilities=tuple(str(item) for item in fact.get("required_capabilities", ())),
                    input_freeze_hash=str(fact.get("input_freeze_hash", fact["specification_hash"])),
                    output_schema_hash=str(fact.get("output_schema_hash", fact["specification_hash"])),
                    previous_generation_hash=fact.get("previous_generation_hash", fact.get("prior_generation_hash")),
                    previous_generation_ref=fact.get("previous_generation_ref"),
                    previous_rejection_event_ref=fact.get("previous_rejection_event_ref"),
                    reject_reason_resolution_hash=fact.get("reject_reason_resolution_hash"),
                    closed_generation_hashes=prior_closed,
                )
                continue
            if current is None or fact.get("handoff_id") != current.handoff_id:
                continue
            if int(fact.get("generation", fact.get("closed_generation", current.generation))) != current.generation:
                continue
            if schema == "HANDOFF_CLARIFICATION_RECORDED_V1":
                current = replace(current, state=HandoffState.CLARIFICATION, version=current.version + 1)
            elif schema == "HANDOFF_REJECTED_V1":
                current = replace(current, state=HandoffState.REJECTED, version=current.version + 1)
            elif schema == "HANDOFF_CLASSIFIED_REJECTION_V1":
                current = replace(
                    current,
                    state=HandoffState(str(fact["to_state"])),
                    version=current.version + 1,
                )
            elif schema == "HANDOFF_CANCELLED_V1":
                current = replace(current, state=HandoffState.CANCELLED, version=current.version + 1)
            elif schema == "HANDOFF_GENERATION_CLOSED_V1":
                current = replace(current, state=HandoffState.SUPERSEDED, version=current.version + 1)
            elif schema == "HANDOFF_ACCEPTED_V1":
                current = replace(
                    current,
                    state=HandoffState.ACCEPTED,
                    version=current.version + 1,
                    accepted_by=str(fact["receiver_id"]),
                )
            elif schema == "HANDOFF_CLAIM_PENDING_V1":
                current = replace(current, state=HandoffState.CLAIM_PENDING, version=current.version + 1)
            elif schema == "HANDOFF_TASK_CLAIM_BOUND_V1":
                current = replace(
                    current,
                    state=HandoffState.CLAIMED,
                    version=current.version + 1,
                    task_attempt_id=str(fact["task_attempt_id"]),
                    claim_generation=int(fact["claim_generation"]),
                    fencing_token=str(fact["fencing_token"]),
                )
            elif schema == "HANDOFF_EXECUTION_STARTED_V1":
                current = replace(current, state=HandoffState.EXECUTING, version=current.version + 1)
            elif schema == "HANDOFF_RESULT_SUBMITTED_V1":
                current = replace(
                    current,
                    state=HandoffState.SUBMITTED,
                    version=current.version + 1,
                    artifact_hash=str(fact["artifact_hash"]),
                )
            elif schema in {"HANDOFF_VERIFIED_V1", "HANDOFF_REWORK_REQUIRED_V1"}:
                current = replace(
                    current,
                    state=HandoffState.VERIFIED if schema == "HANDOFF_VERIFIED_V1" else HandoffState.REWORK,
                    version=current.version + 1,
                    verifier_id=str(fact["verifier_id"]),
                )
            elif schema == "HANDOFF_GENERATION_LIMIT_REACHED_V1":
                current = replace(current, state=HandoffState.FAILED, version=current.version + 1)
        if current is None:
            raise HandoffError("cannot rebuild Handoff without an offered generation")
        return current
