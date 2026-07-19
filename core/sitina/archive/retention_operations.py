from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .retention import RetentionBlockers


class RetentionOperationError(RuntimeError):
    pass


class OperationState(str, Enum):
    PROPOSED = "PROPOSED"
    ASSESSED = "ASSESSED"
    APPROVED = "APPROVED"
    FENCED = "FENCED"
    EXECUTING = "EXECUTING"
    EXECUTED_DRY_RUN = "EXECUTED_DRY_RUN"
    RECONCILING = "RECONCILING"
    RECONCILED = "RECONCILED"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"
    FAILED_UNKNOWN = "FAILED_UNKNOWN"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class RetentionOperation:
    operation_id: str
    kind: str
    object_ids: tuple[str, ...]
    copy_ids: tuple[str, ...]
    policy_snapshot_hash: str
    catalog_snapshot_hash: str
    frontier_hash: str
    hold_snapshot_hash: str
    approval_quorum: int
    executor_id: str
    deadline: int
    state: OperationState = OperationState.PROPOSED
    approvals: tuple[str, ...] = ()
    fence_token: str | None = None
    destructive_capability_present: bool = False
    reconciliation_evidence_hash: str | None = None
    operation_hash: str = ""

    def __post_init__(self) -> None:
        if not self.operation_hash:
            object.__setattr__(self, "operation_hash", domain_hash("RETENTION_OPERATION", canonical_json_bytes(self.identity_mapping())))

    @property
    def stream_id(self) -> str:
        return f"retention-operation/{self.operation_id}"

    def identity_mapping(self) -> dict[str, object]:
        return {
            "schema": "RETENTION_OPERATION_IDENTITY_V1",
            "operation_id": self.operation_id,
            "kind": self.kind,
            "object_ids": list(self.object_ids),
            "copy_ids": list(self.copy_ids),
            "policy_snapshot_hash": self.policy_snapshot_hash,
            "catalog_snapshot_hash": self.catalog_snapshot_hash,
            "frontier_hash": self.frontier_hash,
            "hold_snapshot_hash": self.hold_snapshot_hash,
            "approval_quorum": self.approval_quorum,
            "executor_id": self.executor_id,
            "deadline": self.deadline,
        }

    @classmethod
    def propose(cls, operation_id: str, **values: object) -> "RetentionOperation":
        validate_identifier(operation_id, field="operation_id")
        return cls(operation_id=operation_id, **values)  # type: ignore[arg-type]

    def assess(
        self,
        *,
        blockers: RetentionBlockers,
        replica_compliant_after: bool,
        current_catalog_hash: str,
        current_hold_hash: str,
    ) -> "RetentionOperation":
        if self.state is not OperationState.PROPOSED:
            raise RetentionOperationError("assessment is out of order")
        if not blockers.clear or not replica_compliant_after:
            raise RetentionOperationError("retention blockers or replica policy prevent assessment")
        if current_catalog_hash != self.catalog_snapshot_hash or current_hold_hash != self.hold_snapshot_hash:
            raise RetentionOperationError("retention snapshots drifted before assessment")
        return replace(self, state=OperationState.ASSESSED)

    def approve(self, approvers: tuple[str, ...], *, now: int) -> "RetentionOperation":
        if self.state is not OperationState.ASSESSED:
            raise RetentionOperationError("approval is out of order")
        unique = tuple(sorted(set(approvers)))
        if len(unique) < self.approval_quorum or now > self.deadline:
            raise RetentionOperationError("approval quorum is insufficient or stale")
        return replace(self, state=OperationState.APPROVED, approvals=unique)

    def fence(self, *, fence: str, current_catalog_hash: str, current_hold_hash: str) -> "RetentionOperation":
        if self.state is not OperationState.APPROVED:
            raise RetentionOperationError("fencing is out of order")
        if current_catalog_hash != self.catalog_snapshot_hash or current_hold_hash != self.hold_snapshot_hash:
            raise RetentionOperationError("retention snapshots drifted at fence")
        return replace(self, state=OperationState.FENCED, fence_token=fence)

    def execute_dry_run(self, *, outcome: str) -> tuple["RetentionOperation", dict[str, object]]:
        if self.state is not OperationState.FENCED:
            raise RetentionOperationError("execution is out of order")
        if outcome not in {"ACKNOWLEDGED", "ACK_LOST"}:
            raise RetentionOperationError("unknown executor disposition")
        state = OperationState.EXECUTED_DRY_RUN if outcome == "ACKNOWLEDGED" else OperationState.RECONCILING
        receipt = {
            "schema": "RETENTION_DRY_RUN_RECEIPT_V1",
            "operation_id": self.operation_id,
            "outcome": outcome,
            "physical_delete_executed": False,
            "destructive_capability_present": False,
        }
        return replace(self, state=state), receipt

    def reconcile(self, *, evidence_hash: str, physical_absence_claimed: bool) -> "RetentionOperation":
        if self.state not in {OperationState.EXECUTED_DRY_RUN, OperationState.RECONCILING}:
            raise RetentionOperationError("reconciliation is out of order")
        if physical_absence_claimed:
            raise RetentionOperationError("dry-run reconciliation cannot claim physical absence")
        return replace(self, state=OperationState.RECONCILED, reconciliation_evidence_hash=evidence_hash)

    def verify(self, *, verifier_id: str, dry_run_verified: bool) -> "RetentionOperation":
        if self.state is not OperationState.RECONCILED or not dry_run_verified:
            raise RetentionOperationError("verified reconciliation evidence is required")
        return replace(self, state=OperationState.VERIFIED)

    def complete(self) -> "RetentionOperation":
        if self.state is not OperationState.VERIFIED:
            raise RetentionOperationError("unknown or unverified operation cannot complete")
        return replace(self, state=OperationState.COMPLETED)
