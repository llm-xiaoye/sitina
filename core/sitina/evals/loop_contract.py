from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from sitina.loop.model import SPEC_VERSION
from sitina.loop.termination import TERMINATION_CONTRACT_VERSION


class ProgramStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    NOT_RUN = "NOT_RUN"


class ReviewerStatus(str, Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    NOT_RUN = "NOT_RUN"


class EvaluationOutcome(str, Enum):
    CASE_PASS = "CASE_PASS"
    CASE_FAIL = "CASE_FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"


@dataclass(frozen=True)
class AcceptanceCase:
    """Per-task evidence contract; there is intentionally no universal diff/test rule."""

    case_id: str
    task_type: str
    expected_task_statuses: tuple[str, ...]
    spec_version: str = SPEC_VERSION
    required_program_checks: tuple[str, ...] = ()
    required_evidence_kinds: tuple[str, ...] = ()
    independent_review_required: bool = False
    termination_contract_version: str | None = None

    def __post_init__(self) -> None:
        if not self.case_id.strip() or not self.task_type.strip():
            raise ValueError("acceptance case identity and task type are required")
        if not self.expected_task_statuses or len(set(self.expected_task_statuses)) != len(
            self.expected_task_statuses
        ):
            raise ValueError("each case requires explicit unique expected task statuses")
        if len(set(self.required_program_checks)) != len(self.required_program_checks):
            raise ValueError("required program checks must be unique")
        if len(set(self.required_evidence_kinds)) != len(self.required_evidence_kinds):
            raise ValueError("required evidence kinds must be unique")


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    spec_version: str
    actual_task_status: str
    program_checks: Mapping[str, ProgramStatus]
    evidence_refs: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    reviewer_results: tuple[ReviewerStatus, ...] = ()
    termination_contract_version: str | None = None


@dataclass(frozen=True)
class CaseEvaluation:
    case_id: str
    spec_version: str
    actual_task_status: str
    program_status: ProgramStatus
    reviewer_status: ReviewerStatus
    outcome: EvaluationOutcome
    comparable: bool
    reason_codes: tuple[str, ...]
    termination_contract_version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_CASE_EVALUATION_V1",
            "case_id": self.case_id,
            "spec_version": self.spec_version,
            "termination_contract_version": self.termination_contract_version,
            "actual_task_status": self.actual_task_status,
            "program_status": self.program_status.value,
            "reviewer_status": self.reviewer_status.value,
            "outcome": self.outcome.value,
            "comparable": self.comparable,
            "reason_codes": list(self.reason_codes),
        }


class LoopAcceptanceEvaluator:
    """The shared r4 completion contract for daily and benchmark evaluation."""

    def __init__(self, *, mode: str = "daily") -> None:
        if mode not in {"daily", "benchmark"}:
            raise ValueError("evaluation mode must be daily or benchmark")
        self.mode = mode

    @property
    def required_reviewers(self) -> int:
        return 2 if self.mode == "benchmark" else 1

    @staticmethod
    def _program_status(
        case: AcceptanceCase,
        observation: CaseObservation,
        reasons: list[str],
    ) -> ProgramStatus:
        missing_checks = [
            name for name in case.required_program_checks if name not in observation.program_checks
        ]
        not_run = [
            name
            for name in case.required_program_checks
            if observation.program_checks.get(name) is ProgramStatus.NOT_RUN
        ]
        failed = [
            name
            for name in case.required_program_checks
            if observation.program_checks.get(name) is ProgramStatus.FAIL
        ]
        needs_evidence = [
            name
            for name in case.required_program_checks
            if observation.program_checks.get(name) is ProgramStatus.NEEDS_EVIDENCE
        ]
        missing_evidence = [
            kind for kind in case.required_evidence_kinds if not observation.evidence_refs.get(kind)
        ]
        if failed:
            reasons.extend("PROGRAM_FAIL:" + name for name in failed)
            return ProgramStatus.FAIL
        if missing_checks or not_run:
            reasons.extend("PROGRAM_NOT_RUN:" + name for name in (*missing_checks, *not_run))
            return ProgramStatus.NOT_RUN
        if needs_evidence or missing_evidence:
            reasons.extend("PROGRAM_NEEDS_EVIDENCE:" + name for name in needs_evidence)
            reasons.extend("EVIDENCE_MISSING:" + kind for kind in missing_evidence)
            return ProgramStatus.NEEDS_EVIDENCE
        return ProgramStatus.PASS

    def _reviewer_status(
        self,
        case: AcceptanceCase,
        observation: CaseObservation,
        reasons: list[str],
    ) -> ReviewerStatus:
        required = self.required_reviewers if case.independent_review_required else 0
        provided = observation.reviewer_results
        if any(item is ReviewerStatus.BLOCK for item in provided):
            reasons.append("REVIEWER_BLOCK")
            return ReviewerStatus.BLOCK
        if any(item is ReviewerStatus.NEEDS_EVIDENCE for item in provided):
            reasons.append("REVIEWER_NEEDS_EVIDENCE")
            return ReviewerStatus.NEEDS_EVIDENCE
        if len(provided) < required or any(item is ReviewerStatus.NOT_RUN for item in provided):
            reasons.append(f"REVIEWER_NOT_RUN:{len(provided)}/{required}")
            return ReviewerStatus.NOT_RUN
        return ReviewerStatus.PASS

    def evaluate(self, case: AcceptanceCase, observation: CaseObservation) -> CaseEvaluation:
        reasons: list[str] = []
        if case.case_id != observation.case_id:
            reasons.append("CASE_ID_MISMATCH")
        if case.spec_version != SPEC_VERSION or observation.spec_version != case.spec_version:
            reasons.append("SPEC_VERSION_MISMATCH")
        case_termination = case.termination_contract_version
        observed_termination = observation.termination_contract_version
        if (case_termination is None) != (observed_termination is None) or (
            case_termination is not None
            and (
                case_termination != TERMINATION_CONTRACT_VERSION
                or observed_termination != case_termination
            )
        ):
            reasons.append("TERMINATION_CONTRACT_VERSION_MISMATCH")
        if reasons:
            return CaseEvaluation(
                case.case_id,
                observation.spec_version,
                observation.actual_task_status,
                ProgramStatus.NOT_RUN,
                ReviewerStatus.NOT_RUN,
                EvaluationOutcome.CONFIGURATION_ERROR,
                False,
                tuple(reasons),
                observed_termination,
            )

        program = self._program_status(case, observation, reasons)
        reviewer = self._reviewer_status(case, observation, reasons)
        if observation.actual_task_status not in case.expected_task_statuses:
            reasons.append(
                "TASK_STATUS_MISMATCH:"
                + observation.actual_task_status
                + ":expected="
                + ",".join(case.expected_task_statuses)
            )
            program = ProgramStatus.FAIL
        if program is ProgramStatus.FAIL or reviewer is ReviewerStatus.BLOCK:
            outcome = EvaluationOutcome.CASE_FAIL
        elif program is ProgramStatus.PASS and reviewer is ReviewerStatus.PASS:
            outcome = EvaluationOutcome.CASE_PASS
        else:
            outcome = EvaluationOutcome.NEEDS_REVIEW
        return CaseEvaluation(
            case.case_id,
            case.spec_version,
            observation.actual_task_status,
            program,
            reviewer,
            outcome,
            True,
            tuple(reasons),
            case_termination,
        )
