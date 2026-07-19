from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class HandoffContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandoffContract:
    handoff_id: str
    generation: int
    sender_id: str
    receiver_id: str
    task_id: str
    objective: str
    scope: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    input_refs: tuple[str, ...]
    input_hashes: tuple[str, ...]
    current_state_ref: str
    output_schema: Mapping[str, Any]
    acceptance_criteria: tuple[str, ...]
    assumptions: tuple[str, ...]
    residual_risks: tuple[str, ...]
    open_questions: tuple[str, ...]
    budget_tokens: int
    deadline: str
    policy_hash: str
    previous_generation_ref: str | None = None
    previous_rejection_event_ref: str | None = None
    reject_reason_resolution_map: Mapping[str, str] = field(default_factory=dict)
    blackboard_version_refs: tuple[str, ...] = ()
    task_claim_ref: str | None = None
    fencing_token: str | None = None
    max_generations: int = 3

    def __post_init__(self) -> None:
        for value, field in (
            (self.handoff_id, "handoff_id"),
            (self.sender_id, "handoff_sender"),
            (self.receiver_id, "handoff_receiver"),
            (self.task_id, "task_id"),
        ):
            validate_identifier(value, field=field)
        for capability in self.required_capabilities:
            validate_identifier(capability, field="handoff_required_capability")
        validate_timestamp(self.deadline)
        if self.generation < 1 or self.budget_tokens < 1 or self.max_generations < self.generation:
            raise HandoffContractError("Handoff contract generation and budget must be positive")
        if self.sender_id == self.receiver_id:
            raise HandoffContractError("Handoff sender and receiver must differ")
        if not self.objective.strip() or not self.scope or not self.acceptance_criteria:
            raise HandoffContractError("Handoff objective, scope, and acceptance criteria are required")
        if len(self.policy_hash) != 64 or len(self.current_state_ref) != 64:
            raise HandoffContractError("Handoff policy/current state references must be hashes")
        if any(len(item) != 64 for item in (*self.input_refs, *self.input_hashes)):
            raise HandoffContractError("Handoff inputs require exact hashes or CAS object IDs")
        if self.generation > 1:
            if not self.previous_generation_ref or not self.previous_rejection_event_ref:
                raise HandoffContractError("new Handoff generation requires prior generation and rejection refs")
            if not self.reject_reason_resolution_map or any(
                not isinstance(reason, str) or not reason.strip()
                or not isinstance(resolution, str) or not resolution.strip()
                for reason, resolution in self.reject_reason_resolution_map.items()
            ):
                raise HandoffContractError("new Handoff generation must resolve every rejection reason")
            if not isinstance(self.task_claim_ref, str) or len(self.task_claim_ref) != 64:
                raise HandoffContractError("new Handoff generation requires a frozen Task Claim ref")
            if not isinstance(self.fencing_token, str) or len(self.fencing_token) != 64:
                raise HandoffContractError("new Handoff generation requires its reserved fencing token")
        if any(not isinstance(item, str) or not item for item in self.blackboard_version_refs):
            raise HandoffContractError("Blackboard version refs must be non-empty strings")
        canonical_json_bytes(dict(self.output_schema))

    @property
    def objective_ref(self) -> str:
        return domain_hash("HANDOFF_OBJECTIVE", canonical_json_bytes({"objective": self.objective}))

    @property
    def scope_ref(self) -> str:
        return domain_hash("HANDOFF_SCOPE", canonical_json_bytes({"scope": list(self.scope)}))

    @property
    def output_schema_hash(self) -> str:
        return domain_hash("HANDOFF_OUTPUT_SCHEMA", canonical_json_bytes(dict(self.output_schema)))

    @property
    def input_freeze_hash(self) -> str:
        return domain_hash(
            "HANDOFF_INPUT_FREEZE",
            canonical_json_bytes(
                {
                    "generation": self.generation,
                    "input_refs": list(self.input_refs),
                    "input_hashes": list(self.input_hashes),
                    "previous_generation_ref": self.previous_generation_ref,
                    "previous_rejection_event_ref": self.previous_rejection_event_ref,
                    "reject_reason_resolution_map": dict(self.reject_reason_resolution_map),
                }
            ),
        )

    def mapping(self) -> dict[str, Any]:
        return {
            **self.__dict__,
            "from_agent": self.sender_id,
            "to_agent": self.receiver_id,
            "objective_ref": self.objective_ref,
            "scope_ref": self.scope_ref,
            "scope": list(self.scope),
            "required_capabilities": list(self.required_capabilities),
            "input_refs": list(self.input_refs),
            "input_hashes": list(self.input_hashes),
            "output_schema": dict(self.output_schema),
            "acceptance_criteria": list(self.acceptance_criteria),
            "assumptions": list(self.assumptions),
            "residual_risks": list(self.residual_risks),
            "open_questions": list(self.open_questions),
            "reject_reason_resolution_map": dict(self.reject_reason_resolution_map),
            "blackboard_version_refs": list(self.blackboard_version_refs),
            "budget": self.budget_tokens,
            "output_schema_hash": self.output_schema_hash,
            "input_freeze_hash": self.input_freeze_hash,
        }

    @property
    def contract_hash(self) -> str:
        return domain_hash("HANDOFF_CONTRACT", canonical_json_bytes(self.mapping()))

    def offered_fact(self, *, contract_object_ref: str) -> dict[str, Any]:
        if not contract_object_ref.startswith("cas:"):
            raise HandoffContractError("Handoff contract must be published to CAS")
        return {
            "schema": "HANDOFF_CONTRACT_FROZEN_V1",
            **self.mapping(),
            "contract_hash": self.contract_hash,
            "contract_object_ref": contract_object_ref,
            "_object_refs": [contract_object_ref],
        }
