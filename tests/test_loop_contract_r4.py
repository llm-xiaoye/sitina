from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from sitina.evals.loop_contract import (
    AcceptanceCase,
    CaseObservation,
    EvaluationOutcome,
    LoopAcceptanceEvaluator,
    ProgramStatus,
    ReviewerStatus,
)
from sitina.loop import SPEC_VERSION


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/r4_review_calibration.py"
_SCRIPT_SPEC = importlib.util.spec_from_file_location("r4_review_calibration", _SCRIPT_PATH)
assert _SCRIPT_SPEC is not None and _SCRIPT_SPEC.loader is not None
_SCRIPT_MODULE = importlib.util.module_from_spec(_SCRIPT_SPEC)
_SCRIPT_SPEC.loader.exec_module(_SCRIPT_MODULE)
program_check = _SCRIPT_MODULE.program_check


def observation(
    *,
    status: str = "SUCCEEDED",
    program: ProgramStatus = ProgramStatus.PASS,
    reviewers: tuple[ReviewerStatus, ...] = (ReviewerStatus.PASS,),
    spec_version: str = SPEC_VERSION,
) -> CaseObservation:
    return CaseObservation(
        case_id="case-1",
        spec_version=spec_version,
        actual_task_status=status,
        program_checks={"output": program},
        evidence_refs={"artifact": ("cas:artifact",)},
        reviewer_results=reviewers,
    )


def delivery_case(*, review: bool = True) -> AcceptanceCase:
    return AcceptanceCase(
        case_id="case-1",
        task_type="code_change",
        expected_task_statuses=("SUCCEEDED",),
        required_program_checks=("output",),
        required_evidence_kinds=("artifact",),
        independent_review_required=review,
    )


@pytest.mark.parametrize("status", ["FAILED", "CANCELLED", "WAITING_OPERATION"])
def test_non_success_task_state_cannot_become_delivery_pass(status: str) -> None:
    result = LoopAcceptanceEvaluator(mode="daily").evaluate(
        delivery_case(), observation(status=status)
    )
    assert result.actual_task_status == status
    assert result.program_status is ProgramStatus.FAIL
    assert result.outcome is EvaluationOutcome.CASE_FAIL
    assert result.comparable
    assert any(reason.startswith("TASK_STATUS_MISMATCH") for reason in result.reason_codes)


@pytest.mark.parametrize("status", ["WAITING_OPERATION", "CANCELLED"])
def test_special_case_can_explicitly_expect_wait_or_cancel(status: str) -> None:
    case = AcceptanceCase(
        case_id="case-1",
        task_type="control_transition",
        expected_task_statuses=(status,),
        required_program_checks=("output",),
        required_evidence_kinds=("artifact",),
    )
    result = LoopAcceptanceEvaluator().evaluate(case, observation(status=status, reviewers=()))
    assert result.outcome is EvaluationOutcome.CASE_PASS
    assert result.actual_task_status == status


def test_read_only_case_does_not_invent_diff_test_or_review_requirements() -> None:
    case = AcceptanceCase(
        case_id="case-1",
        task_type="read_only",
        expected_task_statuses=("SUCCEEDED",),
        required_program_checks=("output",),
        required_evidence_kinds=("artifact",),
        independent_review_required=False,
    )
    result = LoopAcceptanceEvaluator().evaluate(case, observation(reviewers=()))
    assert result.program_status is ProgramStatus.PASS
    assert result.reviewer_status is ReviewerStatus.PASS
    assert result.outcome is EvaluationOutcome.CASE_PASS


def test_machine_failure_cannot_be_overruled_by_reviewer_pass() -> None:
    result = LoopAcceptanceEvaluator().evaluate(
        delivery_case(), observation(program=ProgramStatus.FAIL)
    )
    assert result.reviewer_status is ReviewerStatus.PASS
    assert result.outcome is EvaluationOutcome.CASE_FAIL


def test_not_run_remains_explicit() -> None:
    result = LoopAcceptanceEvaluator().evaluate(
        delivery_case(), observation(program=ProgramStatus.NOT_RUN)
    )
    assert result.program_status is ProgramStatus.NOT_RUN
    assert result.outcome is EvaluationOutcome.NEEDS_REVIEW


def test_spec_mismatch_is_not_comparable() -> None:
    result = LoopAcceptanceEvaluator().evaluate(
        delivery_case(), observation(spec_version="sitina-loop-v1-r3")
    )
    assert result.outcome is EvaluationOutcome.CONFIGURATION_ERROR
    assert not result.comparable


def test_daily_and_benchmark_share_contract_but_require_one_vs_two_reviewers() -> None:
    case = delivery_case()
    one_review = observation(reviewers=(ReviewerStatus.PASS,))
    assert LoopAcceptanceEvaluator(mode="daily").evaluate(case, one_review).outcome is EvaluationOutcome.CASE_PASS
    benchmark = LoopAcceptanceEvaluator(mode="benchmark").evaluate(case, one_review)
    assert benchmark.reviewer_status is ReviewerStatus.NOT_RUN
    assert benchmark.outcome is EvaluationOutcome.NEEDS_REVIEW
    two_reviews = observation(reviewers=(ReviewerStatus.PASS, ReviewerStatus.PASS))
    assert LoopAcceptanceEvaluator(mode="benchmark").evaluate(case, two_reviews).outcome is EvaluationOutcome.CASE_PASS


def _write_packet(root: Path, *, plotted_values: tuple[float, ...] | None) -> None:
    root.mkdir()
    (root / "requirements.md").write_text("convert mg/L to g/L", encoding="utf-8")
    (root / "chart.png").write_bytes(b"deterministic-placeholder")
    if plotted_values is None:
        return
    source = "time_s,concentration_mg_L\n0,0\n10,25\n20,50\n30,75\n"
    plot = "time_s,concentration_g_L\n" + "\n".join(
        f"{time},{value}" for time, value in zip((0, 10, 20, 30), plotted_values, strict=True)
    ) + "\n"
    (root / "source.csv").write_text(source, encoding="utf-8")
    (root / "plot-data.csv").write_text(plot, encoding="utf-8")
    provenance = {
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "plot_data_sha256": hashlib.sha256(plot.encode()).hexdigest(),
        "transformation": "concentration_g_L = concentration_mg_L / 1000",
    }
    (root / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")


def test_program_calibration_classifies_correct_error_alternative_and_missing(tmp_path: Path) -> None:
    case_1 = tmp_path / "case-001"
    case_2 = tmp_path / "case-002"
    case_3 = tmp_path / "case-003"
    case_4 = tmp_path / "case-004"
    _write_packet(case_1, plotted_values=(0, 0.025, 0.05, 0.075))
    _write_packet(case_2, plotted_values=(0, 25, 50, 75))
    _write_packet(case_3, plotted_values=(0, 0.025, 0.05, 0.075))
    _write_packet(case_4, plotted_values=None)
    assert [program_check(path)["program_status"] for path in (case_1, case_2, case_3, case_4)] == [
        "PASS",
        "FAIL",
        "PASS",
        "NEEDS_EVIDENCE",
    ]


def test_program_calibration_does_not_claim_unimplemented_visual_validation(tmp_path: Path) -> None:
    packet = tmp_path / "packet"
    _write_packet(packet, plotted_values=(0, 0.025, 0.05, 0.075))
    first = program_check(packet)
    (packet / "chart.png").write_bytes(b"a different but still present chart")
    second = program_check(packet)
    assert first["program_status"] == second["program_status"] == "PASS"
    assert first["presentation_attributes_scored"] is False
    assert second["presentation_attributes_scored"] is False
