from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ReworkError(RuntimeError):
    pass


class FailureType(str, Enum):
    SIMPLE_CORRECTION = "SIMPLE_CORRECTION"
    TEST_FAILED = "TEST_FAILED"
    REVIEW_REJECTED = "REVIEW_REJECTED"
    SECURITY_FINDING = "SECURITY_FINDING"
    ACCEPTANCE_CRITERIA_MISSED = "ACCEPTANCE_CRITERIA_MISSED"
    MERGE_CONFLICT = "MERGE_CONFLICT"


class ReworkState(str, Enum):
    OPEN = "OPEN"
    ROUND_ACTIVE = "ROUND_ACTIVE"
    SATISFIED = "SATISFIED"
    SUCCESSOR_REQUIRED = "SUCCESSOR_REQUIRED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class Rework:
    rework_id: str
    task_id: str
    failure_type: FailureType
    acceptance_criteria_hash: str
    max_retries: int
    state: ReworkState = ReworkState.OPEN
    version: int = 1
    retry_count: int = 0
    active_attempt_id: str | None = None
    result_refs: tuple[str, ...] = ()
    successor_obligation_id: str | None = None

    @classmethod
    def open(
        cls,
        rework_id: str,
        task_id: str,
        failure_type: FailureType,
        acceptance_criteria_hash: str,
        *,
        max_retries: int,
    ) -> tuple["Rework", dict[str, Any]]:
        validate_identifier(rework_id, field="rework_id")
        validate_identifier(task_id, field="task_id")
        if len(acceptance_criteria_hash) != 64 or max_retries < 1:
            raise ReworkError("invalid Rework criteria or retry bound")
        aggregate = cls(
            rework_id,
            task_id,
            failure_type,
            acceptance_criteria_hash,
            max_retries,
        )
        return aggregate, {
            "schema": "REWORK_OPENED_V1",
            "rework_id": rework_id,
            "task_id": task_id,
            "failure_type": failure_type.value,
            "acceptance_criteria_hash": acceptance_criteria_hash,
            "max_retries": max_retries,
        }

    @staticmethod
    def route_failure(failure_type: FailureType, *, multi_round_required: bool) -> str:
        if failure_type is FailureType.SIMPLE_CORRECTION and not multi_round_required:
            return "NEW_TASK_ATTEMPT"
        return "REWORK_PROTOCOL"

    def begin_round(self, attempt_id: str) -> tuple["Rework", dict[str, Any]]:
        if self.state is not ReworkState.OPEN:
            raise ReworkError("Rework is not open for a new round")
        validate_identifier(attempt_id, field="rework_attempt_id")
        if self.retry_count >= self.max_retries:
            raise ReworkError("Rework retry bound exhausted")
        updated = replace(
            self,
            state=ReworkState.ROUND_ACTIVE,
            version=self.version + 1,
            retry_count=self.retry_count + 1,
            active_attempt_id=attempt_id,
        )
        return updated, {
            "schema": "REWORK_ROUND_STARTED_V1",
            "rework_id": self.rework_id,
            "round": updated.retry_count,
            "attempt_id": attempt_id,
            "failure_type": self.failure_type.value,
            "acceptance_criteria_hash": self.acceptance_criteria_hash,
        }

    def complete_round(
        self, result_ref: str, *, accepted: bool
    ) -> tuple["Rework", dict[str, Any]]:
        if self.state is not ReworkState.ROUND_ACTIVE or len(result_ref) != 64:
            raise ReworkError("Rework result requires an active round and canonical reference")
        result_refs = self.result_refs + (result_ref,)
        if accepted:
            updated = replace(
                self,
                state=ReworkState.SATISFIED,
                version=self.version + 1,
                active_attempt_id=None,
                result_refs=result_refs,
            )
            return updated, {
                "schema": "REWORK_SATISFIED_V1",
                "rework_id": self.rework_id,
                "round": self.retry_count,
                "result_ref": result_ref,
                "acceptance_criteria_hash": self.acceptance_criteria_hash,
            }
        if self.retry_count >= self.max_retries:
            identity = domain_hash(
                "REWORK_SUCCESSOR_OBLIGATION",
                canonical_json_bytes(
                    {
                        "rework_id": self.rework_id,
                        "retry_count": self.retry_count,
                        "result_refs": list(result_refs),
                    }
                ),
            )
            successor = f"obligation-rework-{identity}"
            updated = replace(
                self,
                state=ReworkState.SUCCESSOR_REQUIRED,
                version=self.version + 1,
                active_attempt_id=None,
                result_refs=result_refs,
                successor_obligation_id=successor,
            )
            return updated, {
                "schema": "REWORK_RETRY_EXHAUSTED_V1",
                "rework_id": self.rework_id,
                "retry_count": self.retry_count,
                "result_ref": result_ref,
                "successor_obligation_id": successor,
            }
        updated = replace(
            self,
            state=ReworkState.OPEN,
            version=self.version + 1,
            active_attempt_id=None,
            result_refs=result_refs,
        )
        return updated, {
            "schema": "REWORK_ROUND_FAILED_V1",
            "rework_id": self.rework_id,
            "round": self.retry_count,
            "result_ref": result_ref,
            "remaining_retries": self.max_retries - self.retry_count,
        }
