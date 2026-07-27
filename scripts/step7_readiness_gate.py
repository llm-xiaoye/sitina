#!/usr/bin/env python3
"""Fail-closed validator for the current Step 7 CANARY_READY contract.

This gate is intentionally read-only.  It verifies a candidate and its bound
evidence against the current repository and deployment, but never creates,
copies, quarantines, deletes, deploys, promotes, or enables anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


CANDIDATE_SCHEMA = "SITINA_STEP7_REVIEW_CANDIDATE_V1"
READY_MARKER = "SITINA_STEP7_CANARY_READY_V1"
SUMMARY_MARKER = "SITINA_STEP7_GATE_JSON:"
ENTRY_CANDIDATE_SCHEMA = "SITINA_STEP7_ENTRY_REVIEW_CANDIDATE_V1"
ENTRY_CANDIDATE_SHA256 = "acb33c0cde566339a194d850bd83d6bbebc9679b301a1b5246555772ef93fc56"
POLICY_RELATIVE_PATH = "config/true_multi_agent_policy.json"
SWITCHES = (
    "tool_calls_allowed",
    "external_mutation_allowed",
    "execution_bridge_enabled",
    "execution_handoff_bypass_enabled",
)
REQUIRED_GATES = (
    "minimal_negative_contract",
    "identity_sentinel_directed",
    "execution_activation",
    "step7_readiness_gate",
    "unit_fast",
    "integration_isolated",
    "all_registered_unique",
)
MINIMUM_GATE_COUNTS = {
    "minimal_negative_contract": 8,
    "identity_sentinel_directed": 56,
    "execution_activation": 60,
    "step7_readiness_gate": 1,
    "unit_fast": 208,
    "integration_isolated": 200,
    "all_registered_unique": 980,
}
HISTORICAL_SKIP_IDS = (
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_default_suites_pass_with_zero_external_or_production_access",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_legacy_baseline_reproducible_with_semantics_preserved",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_manifest_promotion_and_pinned_profile",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_plan_inventory_and_incident_recovery_gates",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_source_only_manifest_is_current_and_excludes_runtime",
)
FORBIDDEN_ACTION_FIELDS = (
    "production_canary_run",
    "execution_switch_enabled",
    "production_data_modified",
    "production_data_deleted",
    "baseline_installed_or_promoted",
    "quarantine_or_trash_cleared",
    "unique_or_latest_backup_deleted",
    "reachable_evidence_deleted",
    "historical_baseline_deleted",
    "git_history_rewritten",
    "push_merge_publish_or_external_change",
    "destructive_git_recovery_used",
    "gate_weakened_assertion_removed_or_skip_added",
    "step8_entered",
    "step9_entered",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _safe_regular_file(path_value: Any, errors: list[str], label: str) -> Path | None:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        errors.append(f"{label} path must be absolute")
        return None
    path = Path(path_value)
    try:
        metadata = path.lstat()
    except OSError:
        errors.append(f"{label} file missing: {path}")
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        errors.append(f"{label} must be a regular non-symlink file: {path}")
        return None
    return path


def _verify_file_reference(
    value: Any,
    errors: list[str],
    label: str,
    *,
    require_json_object: bool = True,
) -> tuple[Path | None, dict[str, Any] | None]:
    if not isinstance(value, Mapping):
        errors.append(f"{label} reference must be an object")
        return None, None
    path = _safe_regular_file(value.get("path"), errors, label)
    expected = value.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        errors.append(f"{label} reference requires a SHA-256")
    if path is None:
        return None, None
    actual = _sha256(path)
    if actual != expected:
        errors.append(f"{label} SHA-256 mismatch")
    if not require_json_object:
        return path, None
    try:
        document = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label} is not a JSON object: {type(exc).__name__}")
        document = None
    return path, document


def _git(source_root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        cwd=source_root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def _tracked_files(source_root: Path) -> list[str]:
    raw = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=source_root,
        stderr=subprocess.DEVNULL,
    )
    return [item.decode("utf-8") for item in raw.split(b"\0") if item]


def _verify_source_state(
    candidate: Mapping[str, Any],
    source_root: Path,
    errors: list[str],
) -> dict[str, Any]:
    source = candidate.get("source")
    if not isinstance(source, Mapping):
        errors.append("source state is missing")
        return {}
    try:
        head = _git(source_root, "rev-parse", "HEAD^{commit}")
        tree = _git(source_root, "rev-parse", "HEAD^{tree}")
        status = _git(source_root, "status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, subprocess.CalledProcessError):
        errors.append("source root is not a readable Git worktree")
        return {}
    if source.get("root") != str(source_root):
        errors.append("candidate source root mismatch")
    if source.get("head") != head:
        errors.append("candidate source HEAD mismatch")
    if source.get("tree") != tree:
        errors.append("candidate source tree mismatch")
    if source.get("worktree_clean") is not True or status:
        errors.append("source worktree is not clean")
    changed_files = source.get("changed_files")
    if not isinstance(changed_files, list) or not changed_files:
        errors.append("candidate must list Step7 changed files")
    return {"head": head, "tree": tree, "worktree_clean": not bool(status)}


def _verify_source_deployment(
    source_root: Path,
    deployment_root: Path,
    candidate: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    declared = candidate.get("source_deployment")
    if not isinstance(declared, Mapping):
        errors.append("source_deployment evidence is missing")
        return {}
    if declared.get("source_root") != str(source_root):
        errors.append("source_deployment source root mismatch")
    if declared.get("deployment_root") != str(deployment_root):
        errors.append("source_deployment deployment root mismatch")
    try:
        relative_paths = _tracked_files(source_root)
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        errors.append("unable to enumerate tracked source files")
        return {}
    missing: list[str] = []
    content_mismatches: list[str] = []
    mode_mismatches: list[str] = []
    unsafe: list[str] = []
    for relative in relative_paths:
        source = source_root / relative
        deployment = deployment_root / relative
        try:
            source_stat = source.lstat()
            deployment_stat = deployment.lstat()
        except OSError:
            missing.append(relative)
            continue
        if (
            stat.S_ISLNK(source_stat.st_mode)
            or stat.S_ISLNK(deployment_stat.st_mode)
            or not stat.S_ISREG(source_stat.st_mode)
            or not stat.S_ISREG(deployment_stat.st_mode)
        ):
            unsafe.append(relative)
            continue
        if source_stat.st_size != deployment_stat.st_size or _sha256(source) != _sha256(deployment):
            content_mismatches.append(relative)
        if stat.S_IMODE(source_stat.st_mode) != stat.S_IMODE(deployment_stat.st_mode):
            mode_mismatches.append(relative)
    if missing:
        errors.append(f"deployment missing {len(missing)} tracked files")
    if content_mismatches:
        errors.append(f"source/deployment content mismatch for {len(content_mismatches)} files")
    if mode_mismatches:
        errors.append(f"source/deployment mode mismatch for {len(mode_mismatches)} files")
    if unsafe:
        errors.append(f"source/deployment contains {len(unsafe)} unsafe tracked paths")
    if declared.get("tracked_file_count") != len(relative_paths):
        errors.append("declared tracked-file count mismatch")
    if declared.get("exact_match_count") != len(relative_paths):
        errors.append("declared exact-match count mismatch")
    return {
        "tracked_file_count": len(relative_paths),
        "exact_match_count": len(relative_paths)
        - len(set(missing + content_mismatches + mode_mismatches + unsafe)),
        "missing": missing,
        "content_mismatches": content_mismatches,
        "mode_mismatches": mode_mismatches,
        "unsafe": unsafe,
    }


def _verify_entry_candidate(candidate: Mapping[str, Any], errors: list[str]) -> None:
    reference = candidate.get("step56_entry_candidate")
    _, entry = _verify_file_reference(reference, errors, "Step5/6 entry candidate")
    if isinstance(reference, Mapping) and reference.get("sha256") != ENTRY_CANDIDATE_SHA256:
        errors.append("Step5/6 entry candidate is not the authorized physical artifact")
    if entry is None:
        return
    if entry.get("schema") != ENTRY_CANDIDATE_SCHEMA:
        errors.append("Step5/6 entry candidate schema mismatch")
    if entry.get("verdict") != "READY_FOR_INDEPENDENT_STEP7_ENTRY_REVIEW":
        errors.append("Step5/6 entry candidate is not review-ready")
    if entry.get("scope_completed") != "Sitina Step 5/6 closure":
        errors.append("Step5/6 formal-closure scope is missing")
    if entry.get("step7_entered") is not False:
        errors.append("Step5/6 entry evidence incorrectly entered Step7")
    if candidate.get("step5_step6_formally_accepted") is not True:
        errors.append("candidate does not attest formal Step5/6 acceptance")


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _verify_gates(candidate: Mapping[str, Any], errors: list[str]) -> dict[str, Any]:
    raw_gates = candidate.get("gates")
    if not isinstance(raw_gates, list):
        errors.append("gate evidence must be an array")
        return {}
    gates = {
        item.get("stage"): item
        for item in raw_gates
        if isinstance(item, Mapping) and isinstance(item.get("stage"), str)
    }
    if set(gates) != set(REQUIRED_GATES):
        errors.append("required gate set is incomplete or contains unknown stages")
    summaries: dict[str, Any] = {}
    for stage in REQUIRED_GATES:
        gate = gates.get(stage)
        if not isinstance(gate, Mapping):
            continue
        for field in (
            "collected",
            "executed",
            "passed",
            "failed",
            "errors",
            "skipped",
            "xfail",
            "xpass",
            "warnings",
            "external_attempts",
            "production_attempts",
        ):
            if not _integer(gate.get(field)):
                errors.append(f"{stage} has invalid {field}")
        if gate.get("collection_complete") is not True or gate.get("execution_complete") is not True:
            errors.append(f"{stage} is incomplete")
        if gate.get("control_override_used") is not False or gate.get("live_override_used") is not False:
            errors.append(f"{stage} used an override")
        if all(_integer(gate.get(field)) for field in ("collected", "executed", "passed", "skipped")):
            if gate["collected"] != gate["executed"]:
                errors.append(f"{stage} did not execute every collected test")
            if gate["executed"] < MINIMUM_GATE_COUNTS[stage]:
                errors.append(f"{stage} count fell below its acceptance floor")
            if gate["passed"] + gate["skipped"] != gate["executed"]:
                errors.append(f"{stage} pass/skip accounting is inconsistent")
        for field in (
            "failed",
            "errors",
            "xfail",
            "xpass",
            "warnings",
            "external_attempts",
            "production_attempts",
        ):
            if gate.get(field) != 0:
                errors.append(f"{stage} has non-zero {field}")
        skip_ids = gate.get("skip_ids")
        if stage == "all_registered_unique":
            if gate.get("skipped") != len(HISTORICAL_SKIP_IDS):
                errors.append("registered aggregate does not contain exactly five skips")
            if tuple(skip_ids or ()) != HISTORICAL_SKIP_IDS:
                errors.append("registered aggregate skip allowlist mismatch")
            if gate.get("skip_allowlist_match") is not True:
                errors.append("registered aggregate did not confirm the skip allowlist")
            if gate.get("discovered_test_files") != gate.get("registered_unique_selectors"):
                errors.append("registered aggregate discovery/registration mismatch")
        elif gate.get("skipped") != 0 or skip_ids not in (None, []):
            errors.append(f"{stage} contains an unexpected skip")
        _verify_file_reference(gate.get("evidence"), errors, f"{stage} evidence")
        summaries[stage] = {
            field: gate.get(field)
            for field in (
                "collected",
                "executed",
                "passed",
                "failed",
                "errors",
                "skipped",
                "xfail",
                "xpass",
                "warnings",
            )
        }
    return summaries


def _verify_review(value: Any, errors: list[str], label: str) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} is missing")
        return
    if value.get("provider_mode") != "live":
        errors.append(f"{label} did not use a live provider")
    if value.get("profile") != "deepseek" or value.get("model") != "deepseek-v4-pro":
        errors.append(f"{label} did not use the required DeepSeek profile/model")
    if value.get("verdict") != "PASS":
        errors.append(f"{label} has no valid PASS verdict")
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        if not _integer(value.get(field)) or value.get(field) == 0:
            errors.append(f"{label} has invalid or zero {field}")
    if (
        _integer(value.get("input_tokens"))
        and _integer(value.get("output_tokens"))
        and _integer(value.get("total_tokens"))
        and value["total_tokens"] < value["input_tokens"] + value["output_tokens"]
    ):
        errors.append(f"{label} token accounting is inconsistent")
    if not _integer(value.get("provider_calls")) or value.get("provider_calls") == 0:
        errors.append(f"{label} has no provider call")
    if not isinstance(value.get("started_at_utc"), str) or not isinstance(value.get("ended_at_utc"), str):
        errors.append(f"{label} lacks start/end timestamps")
    if (
        not isinstance(value.get("input_sha256"), str)
        or len(value["input_sha256"]) != 64
        or not isinstance(value.get("output_sha256"), str)
        or len(value["output_sha256"]) != 64
    ):
        errors.append(f"{label} lacks input/output hashes")
    tool_types = value.get("tool_call_types")
    if not isinstance(tool_types, list) or not tool_types or any(item != "read" for item in tool_types):
        errors.append(f"{label} used a non-read tool or omitted tool types")
    if value.get("file_changes") != 0 or value.get("external_changes") != 0:
        errors.append(f"{label} changed files or external state")
    _verify_file_reference(
        value.get("audit"),
        errors,
        f"{label} audit",
        require_json_object=False,
    )


def _verify_cleanup(candidate: Mapping[str, Any], errors: list[str]) -> None:
    cleanup = candidate.get("cleanup")
    if not isinstance(cleanup, Mapping):
        errors.append("cleanup closure is missing")
        return
    _, cleanup_candidate = _verify_file_reference(
        cleanup.get("candidate"), errors, "cleanup candidate"
    )
    _, ledger = _verify_file_reference(cleanup.get("ledger"), errors, "cleanup ledger")
    if cleanup_candidate is not None and not str(cleanup_candidate.get("schema", "")).startswith(
        "SITINA_CLEANUP_CANDIDATE"
    ):
        errors.append("cleanup candidate schema mismatch")
    if ledger is not None:
        if not str(ledger.get("schema", "")).startswith("SITINA_CLEANUP_LEDGER"):
            errors.append("cleanup ledger schema mismatch")
        approved = ledger.get("approved_action_count")
        completed = ledger.get("completed_approved_action_count")
        if not _integer(approved) or not _integer(completed) or approved != completed:
            errors.append("approved cleanup actions are not fully completed")
        if ledger.get("new_actions_performed_during_step7") != 0:
            errors.append("Step7 performed a new cleanup action")
        if ledger.get("permanent_deletion") is not False:
            errors.append("cleanup ledger records permanent deletion")
        if ledger.get("unapproved_actions_performed") != 0:
            errors.append("cleanup ledger records an unapproved action")
    _verify_review(cleanup.get("real_sitina_review"), errors, "cleanup Sitina review")


def _verify_switches(
    candidate: Mapping[str, Any],
    source_root: Path,
    deployment_root: Path,
    errors: list[str],
) -> None:
    declared = candidate.get("execution_switches")
    if not isinstance(declared, Mapping):
        errors.append("execution-switch evidence is missing")
        return
    source_policy = source_root / POLICY_RELATIVE_PATH
    deployment_policy = deployment_root / POLICY_RELATIVE_PATH
    try:
        if source_policy.is_symlink() or deployment_policy.is_symlink():
            raise ValueError("policy file is a symlink")
        source = _load_json(source_policy)
        deployment = _load_json(deployment_policy)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        errors.append("unable to read source/deployment execution policy")
        return
    if _sha256(source_policy) != _sha256(deployment_policy):
        errors.append("source/deployment execution policy differs")
    for field in SWITCHES:
        if declared.get(field) is not False or source.get(field) is not False or deployment.get(field) is not False:
            errors.append(f"execution switch is not false: {field}")


def _verify_sentinel(candidate: Mapping[str, Any], errors: list[str]) -> None:
    sentinel = candidate.get("production_sentinel")
    if not isinstance(sentinel, Mapping):
        errors.append("production sentinel evidence is missing")
        return
    if not isinstance(sentinel.get("goal_id"), str) or not sentinel.get("goal_id"):
        errors.append("production sentinel lacks Goal binding")
    for name in ("base_v2", "mutable_v3"):
        before = sentinel.get(f"{name}_before")
        after = sentinel.get(f"{name}_after")
        if not isinstance(before, str) or len(before) != 64 or before != after:
            errors.append(f"production {name} sentinel changed or is invalid")
    if sentinel.get("production_attempts") != 0:
        errors.append("production sentinel evidence records a production attempt")


def _verify_rollback_and_bound_evidence(
    candidate: Mapping[str, Any],
    errors: list[str],
) -> None:
    rollback = candidate.get("rollback_proof")
    if not isinstance(rollback, Mapping) or rollback.get("verified") is not True:
        errors.append("verified rollback proof is missing")
    else:
        artifacts = rollback.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append("rollback proof has no artifact")
        else:
            for index, artifact in enumerate(artifacts):
                _verify_file_reference(artifact, errors, f"rollback artifact {index}")
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("candidate has no bound evidence list")
    else:
        for index, reference in enumerate(evidence):
            _verify_file_reference(reference, errors, f"bound evidence {index}")


def _verify_boundaries(candidate: Mapping[str, Any], errors: list[str]) -> None:
    forbidden = candidate.get("forbidden_actions")
    if not isinstance(forbidden, Mapping):
        errors.append("forbidden-action ledger is missing")
    else:
        for field in FORBIDDEN_ACTION_FIELDS:
            if forbidden.get(field) is not False:
                errors.append(f"forbidden action is present or unconfirmed: {field}")
    if candidate.get("authorization_to_enter_step8") is not False:
        errors.append("candidate improperly grants Step8 admission")
    risks = candidate.get("remaining_risks")
    if not isinstance(risks, list):
        errors.append("remaining risks must be explicitly listed")
    pending = candidate.get("pending_production_actions")
    if not isinstance(pending, list) or not pending:
        errors.append("pending production actions are missing")
    elif not all(
        isinstance(item, Mapping)
        and item.get("approval_required") is True
        and item.get("status") == "NOT_AUTHORIZED"
        for item in pending
    ):
        errors.append("pending production actions are not all approval-bound and unauthorized")


def validate_step7_candidate(
    candidate: Mapping[str, Any],
    *,
    source_root: Path,
    deployment_root: Path,
) -> dict[str, Any]:
    """Return a machine-readable, fail-closed Step7 validation summary."""

    errors: list[str] = []
    source_root = source_root.expanduser().resolve(strict=True)
    deployment_root = deployment_root.expanduser().resolve(strict=True)
    if candidate.get("schema") != CANDIDATE_SCHEMA:
        errors.append("candidate schema mismatch")
    if candidate.get("marker") != READY_MARKER:
        errors.append("candidate marker mismatch")
    _verify_entry_candidate(candidate, errors)
    source_state = _verify_source_state(candidate, source_root, errors)
    source_deployment = _verify_source_deployment(
        source_root, deployment_root, candidate, errors
    )
    gates = _verify_gates(candidate, errors)
    _verify_cleanup(candidate, errors)
    _verify_review(candidate.get("real_sitina_review"), errors, "Step7 Sitina review")
    _verify_switches(candidate, source_root, deployment_root, errors)
    _verify_sentinel(candidate, errors)
    _verify_rollback_and_bound_evidence(candidate, errors)
    _verify_boundaries(candidate, errors)
    return {
        "schema": "SITINA_STEP7_GATE_RESULT_V1",
        "marker": READY_MARKER,
        "accepted": not errors,
        "error_count": len(errors),
        "errors": errors,
        "source": source_state,
        "source_deployment": source_deployment,
        "gates": gates,
        "execution_switches_false": not any(
            error.startswith("execution switch") for error in errors
        ),
        "step8_admission_granted": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--deployment-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        candidate = _load_json(arguments.candidate.expanduser().resolve(strict=True))
        summary = validate_step7_candidate(
            candidate,
            source_root=arguments.source_root,
            deployment_root=arguments.deployment_root,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        summary = {
            "schema": "SITINA_STEP7_GATE_RESULT_V1",
            "marker": READY_MARKER,
            "accepted": False,
            "error_count": 1,
            "errors": [f"gate input rejected: {type(exc).__name__}"],
            "step8_admission_granted": False,
        }
    print(SUMMARY_MARKER + json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
