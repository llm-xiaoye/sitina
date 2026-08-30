from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp
from sitina.contracts.models import BlackboardDocumentRecord
from sitina.security.redaction import redact_boundary_value


class HandoffContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandoffAcknowledgement:
    handoff_id: str
    generation: int
    receiver_id: str
    contract_hash: str
    status: str
    missing_fields: tuple[str, ...]
    occurred_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.handoff_id, field="handoff_ack_id")
        validate_identifier(self.receiver_id, field="handoff_ack_receiver")
        validate_timestamp(self.occurred_at)
        if self.generation < 1 or len(self.contract_hash) != 64 or self.status not in {"ACCEPTED", "REJECTED"}:
            raise HandoffContractError("Handoff acknowledgement identity or status is invalid")
        if tuple(sorted(set(self.missing_fields))) != self.missing_fields:
            raise HandoffContractError("Handoff acknowledgement missing fields must be unique and sorted")
        if (self.status == "ACCEPTED") == bool(self.missing_fields):
            raise HandoffContractError("Handoff acknowledgement status conflicts with missing fields")


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
    blackboard_documents: tuple[BlackboardDocumentRecord, ...] = ()

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
        document_ids = [item.document_id for item in self.blackboard_documents]
        if len(document_ids) != len(set(document_ids)):
            raise HandoffContractError("Handoff BlackboardDocument bindings contain duplicate document IDs")
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
            "blackboard_documents": [
                item.model_dump(mode="json", by_alias=True) for item in self.blackboard_documents
            ],
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
        # Keep the complete contract under the ordinary fail-closed boundary
        # scan.  Generated task IDs are handled by the scanner's lexical
        # boundary rules; no field-specific allowlist is permitted here.
        boundary = redact_boundary_value(self.mapping(), boundary="handoff")
        if boundary.redacted_paths:
            raise HandoffContractError("Handoff contract contains sensitive content at the persistence boundary")
        return {
            "schema": "HANDOFF_CONTRACT_FROZEN_V1",
            **self.mapping(),
            "contract_hash": self.contract_hash,
            "contract_object_ref": contract_object_ref,
            "_object_refs": [contract_object_ref],
        }

    def acknowledge(
        self,
        *,
        receiver_id: str,
        occurred_at: str,
        expected_contract_hash: str,
        available_capabilities: tuple[str, ...],
        available_input_refs: tuple[str, ...],
        available_blackboard_document_ids: tuple[str, ...],
        accepted_budget_tokens: int,
        verified_objective_ref: str,
        verified_scope_ref: str,
        acceptance_criteria_confirmed: bool,
        verified_policy_hash: str,
        verified_current_state_ref: str,
        verified_output_schema_hash: str,
    ) -> HandoffAcknowledgement:
        validate_identifier(receiver_id, field="handoff_ack_receiver")
        validate_timestamp(occurred_at)
        if receiver_id != self.receiver_id:
            raise HandoffContractError("only the frozen receiver may acknowledge a Handoff")
        missing = []
        if expected_contract_hash != self.contract_hash:
            missing.append("contract_hash")
        missing.extend(
            f"capability:{item}"
            for item in sorted(set(self.required_capabilities) - set(available_capabilities))
        )
        missing.extend(
            f"input_ref:{item}"
            for item in sorted(set(self.input_refs) - set(available_input_refs))
        )
        missing.extend(
            f"blackboard_document:{item}"
            for item in sorted(
                {document.document_id for document in self.blackboard_documents}
                - set(available_blackboard_document_ids)
            )
        )
        if accepted_budget_tokens < self.budget_tokens:
            missing.append("budget_tokens")
        if verified_objective_ref != self.objective_ref:
            missing.append("objective_ref")
        if verified_scope_ref != self.scope_ref:
            missing.append("scope_ref")
        if not acceptance_criteria_confirmed:
            missing.append("acceptance_criteria")
        if verified_policy_hash != self.policy_hash:
            missing.append("policy_hash")
        if verified_current_state_ref != self.current_state_ref:
            missing.append("current_state_ref")
        if verified_output_schema_hash != self.output_schema_hash:
            missing.append("output_schema_hash")
        fields = tuple(sorted(set(missing)))
        return HandoffAcknowledgement(
            self.handoff_id,
            self.generation,
            receiver_id,
            self.contract_hash,
            "REJECTED" if fields else "ACCEPTED",
            fields,
            occurred_at,
        )
