from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class MergeError(RuntimeError):
    pass


class MergeOperationKind(str, Enum):
    COMMUTATIVE = "COMMUTATIVE"
    APPEND_ONLY = "APPEND_ONLY"
    CRDT_COMPATIBLE = "CRDT_COMPATIBLE"
    UNDECLARED = "UNDECLARED"


SAFE_KINDS = frozenset(
    {
        MergeOperationKind.COMMUTATIVE,
        MergeOperationKind.APPEND_ONLY,
        MergeOperationKind.CRDT_COMPATIBLE,
    }
)


class MergeState(str, Enum):
    OPEN = "OPEN"
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    MERGED = "MERGED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


@dataclass(frozen=True)
class MergeOperation:
    json_path: str
    kind: MergeOperationKind
    value_ref: str

    def __post_init__(self) -> None:
        if not self.json_path.startswith("/") or ".." in self.json_path:
            raise MergeError("invalid Merge JSON path")
        if len(self.value_ref) != 64:
            raise MergeError("Merge value requires a canonical reference")


@dataclass(frozen=True)
class MergeProposal:
    proposal_id: str
    operations: tuple[MergeOperation, ...]
    operations_hash: str
    validated: bool = False
    validation_ref: str | None = None


@dataclass(frozen=True)
class MergeProtocol:
    merge_id: str
    document_id: str
    base_version: int
    base_hash: str
    allowed_kinds: tuple[MergeOperationKind, ...]
    state: MergeState = MergeState.OPEN
    version: int = 1
    proposals: tuple[MergeProposal, ...] = ()
    selected_proposal_id: str | None = None
    arbitration_obligation_id: str | None = None

    @classmethod
    def open(
        cls,
        merge_id: str,
        document_id: str,
        base_version: int,
        base_hash: str,
        *,
        allowed_kinds: tuple[MergeOperationKind, ...],
    ) -> tuple["MergeProtocol", dict[str, Any]]:
        validate_identifier(merge_id, field="merge_id")
        validate_identifier(document_id, field="document_id")
        if base_version < 0 or len(base_hash) != 64:
            raise MergeError("invalid Merge base")
        allowed = tuple(sorted(set(allowed_kinds), key=lambda item: item.value))
        if not allowed or any(item not in SAFE_KINDS for item in allowed):
            raise MergeError("Merge policy may declare only safe operation kinds")
        aggregate = cls(merge_id, document_id, base_version, base_hash, allowed)
        return aggregate, {
            "schema": "MERGE_OPENED_V1",
            "merge_id": merge_id,
            "document_id": document_id,
            "base_version": base_version,
            "base_hash": base_hash,
            "allowed_kinds": [item.value for item in allowed],
        }

    def propose(
        self, proposal_id: str, operations: tuple[MergeOperation, ...]
    ) -> tuple["MergeProtocol", dict[str, Any]]:
        if self.state not in {MergeState.OPEN, MergeState.PROPOSED}:
            raise MergeError("Merge does not accept proposals in current state")
        validate_identifier(proposal_id, field="merge_proposal_id")
        if not operations or any(operation.kind not in self.allowed_kinds for operation in operations):
            raise MergeError("operation is not schema-declared as commutative/append-only/CRDT")
        if any(item.proposal_id == proposal_id for item in self.proposals):
            raise MergeError("Merge Proposal ID already exists")
        operation_value = [
            {"json_path": item.json_path, "kind": item.kind.value, "value_ref": item.value_ref}
            for item in operations
        ]
        operations_hash = domain_hash("MERGE_OPERATIONS", canonical_json_bytes(operation_value))
        proposal = MergeProposal(proposal_id, operations, operations_hash)
        updated = replace(
            self,
            state=MergeState.PROPOSED,
            version=self.version + 1,
            proposals=self.proposals + (proposal,),
        )
        return updated, {
            "schema": "MERGE_PROPOSED_V1",
            "merge_id": self.merge_id,
            "proposal_id": proposal_id,
            "operations_hash": operations_hash,
            "operation_count": len(operations),
        }

    def validate(
        self, proposal_id: str, *, schema_valid: bool, evidence_ref: str
    ) -> tuple["MergeProtocol", dict[str, Any]]:
        if self.state is not MergeState.PROPOSED or len(evidence_ref) != 64:
            raise MergeError("Merge validation is not admissible")
        try:
            proposal = next(item for item in self.proposals if item.proposal_id == proposal_id)
        except StopIteration as error:
            raise MergeError("unknown Merge Proposal") from error
        if not schema_valid:
            return self.fail("schema-validation-failed")
        validated = replace(proposal, validated=True, validation_ref=evidence_ref)
        updated = replace(
            self,
            state=MergeState.VALIDATED,
            version=self.version + 1,
            proposals=tuple(validated if item.proposal_id == proposal_id else item for item in self.proposals),
            selected_proposal_id=proposal_id,
        )
        return updated, {
            "schema": "MERGE_VALIDATED_V1",
            "merge_id": self.merge_id,
            "proposal_id": proposal_id,
            "operations_hash": proposal.operations_hash,
            "validation_ref": evidence_ref,
        }

    def merge(self, proposal_id: str) -> tuple["MergeProtocol", dict[str, Any]]:
        if self.state is not MergeState.VALIDATED or self.selected_proposal_id != proposal_id:
            raise MergeError("Merge requires the exact validated Proposal")
        proposal = next(item for item in self.proposals if item.proposal_id == proposal_id)
        if not proposal.validated:
            raise MergeError("Projection selection cannot replace Merge validation")
        result_hash = domain_hash(
            "MERGE_RESULT",
            canonical_json_bytes(
                {
                    "merge_id": self.merge_id,
                    "base_hash": self.base_hash,
                    "operations_hash": proposal.operations_hash,
                }
            ),
        )
        updated = replace(self, state=MergeState.MERGED, version=self.version + 1)
        return updated, {
            "schema": "MERGE_COMPLETED_V1",
            "merge_id": self.merge_id,
            "proposal_id": proposal_id,
            "result_hash": result_hash,
        }

    def fail(self, reason: str) -> tuple["MergeProtocol", dict[str, Any]]:
        if self.state in {MergeState.MERGED, MergeState.ESCALATED}:
            raise MergeError("terminal Merge cannot fail again")
        identity = domain_hash(
            "MERGE_ARBITRATION_OBLIGATION",
            canonical_json_bytes({"merge_id": self.merge_id, "reason": reason, "version": self.version}),
        )
        obligation_id = f"obligation-arbitration-{identity}"
        updated = replace(
            self,
            state=MergeState.ESCALATED,
            version=self.version + 1,
            arbitration_obligation_id=obligation_id,
        )
        return updated, {
            "schema": "MERGE_FAILED_V1",
            "merge_id": self.merge_id,
            "reason": reason,
            "arbitration_obligation_id": obligation_id,
        }
