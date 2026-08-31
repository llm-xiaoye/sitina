from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.models import route_decision_from_mapping
from sitina.contracts.models import BlackboardDocumentRecord, SourceDescriptor
from sitina.extensions.runtime import decode_workspace_relative_path
from sitina.orchestrator.code_mode_gate import classify_code_mode_intent
from sitina.journal.model import (
    EventEnvelope,
    FrontierRef,
    canonical_json_bytes,
    code_mode_gate_projection,
    execution_authorization_attempt_ref,
    parse_canonical_json,
    stage_actual_event_projection,
    stable_stage_proof_manifest,
    stable_stage_proof_manifest_hash,
    execution_parent_projection,
    durable_code_mode_authorization_projection,
)
from sitina.security.key_provider import KeyPurpose
from sitina.security.redaction import redact_text
from sitina.effects.monitoring import MonitoringTransfer
from sitina.orchestrator.checkpoint_resume import (
    FRONTIER_SPECS,
    finalize_checkpoint_manifest,
    stream_heads,
    validate_frontier_snapshot,
)
from sitina.orchestrator.production_identity import (
    DEFAULT_IDENTITY_ROOTS,
    DEFAULT_RUNTIME_EXCLUDED_ROOTS,
    build_production_identity_manifest,
)
from sitina.orchestrator.true_multi_agent_runtime import (
    AgentCallResult,
    AgentIdentity,
    AgentRegistry,
    CanonicalStream,
    ProviderExecutor,
    RuntimeActivation,
    TrueMultiAgentRuntimeError,
    activate_runtime,
    issue_root_pre_provider_authorization,
    now_rfc3339,
    sha256_bytes,
    stable_hash,
)
from sitina.orchestrator.output_contracts import resolve_output_contract
from sitina.projections.production import production_handlers
from sitina.projections.rebuild import ProjectionGeneration
from sitina.protocols.arbitration import Arbitration
from sitina.protocols.blackboard import (
    Blackboard,
    BlackboardNamespace,
    NamespacePolicy,
    PatchIntent,
)
from sitina.protocols.claims import ClaimRegistry
from sitina.protocols.debate import Debate, DebateOutcome
from sitina.protocols.handoff_contracts import HandoffContract
from sitina.protocols.handoffs import Handoff
from sitina.protocols.proposals import ProposalRound, ProposalState
from sitina.protocols.reviews import ArtifactAcceptanceProcess, ReviewRequest, ReviewVerdict
from sitina.protocols.rework import FailureType, Rework
from sitina.protocols.run import RunAggregate, RunState
from sitina.protocols.tasks import TaskAggregate, TaskGraphAggregate, TaskProtocolError
from sitina.protocols.terminal import (
    AuthoritativeTerminalFacts,
    BlockerKind,
    TerminalEligibilityProjection,
    apply_terminal_decision,
    full_validate,
)
from sitina.scheduling.agents import AgentScheduler, AgentSchedulingDecision
from sitina.scheduling.processes import ProcessManager


def _tester_machine_command(
    tester_evidence: Mapping[str, Any],
    tester_targets: Sequence[str],
) -> list[str]:
    """Project the exact Tester argv into the machine-check receipt."""
    raw_runner_argv = tester_evidence.get("runner_argv")
    if (
        isinstance(raw_runner_argv, list)
        and raw_runner_argv
        and all(isinstance(item, str) and item for item in raw_runner_argv)
    ):
        return list(raw_runner_argv)
    # Legacy pure-doctest evidence predates the explicit argv field.  New
    # WorkerToolExecutor evidence is required to carry runner_argv and never
    # reaches this compatibility projection for unittest.
    return [
        str(tester_evidence.get("cwd") or ""),
        "python-doctest-supervisor",
        *tester_targets,
    ]


def _code_mode_terminal_state(payload: Mapping[str, Any]) -> str | None:
    """Classify a Code Mode terminal fact without trusting its name alone.

    Historical journals may contain the old success-named event with a
    FAILED state.  That contradiction is intentionally interpreted as
    failure/blocked, never as resumable success.
    """
    event_type = payload.get("event_type")
    schema = payload.get("schema")
    state = payload.get("terminal_state")
    if event_type == "code-mode.terminal-success" and schema == "CODE_MODE_TERMINAL_SUCCESS_V1":
        return state if state in {"SUCCEEDED", "FAILED"} else "INVALID"
    if event_type == "code-mode.terminal-failed" and schema == "CODE_MODE_TERMINAL_FAILED_V1":
        return "FAILED" if state == "FAILED" else "INVALID"
    if event_type == "code-mode.terminal-success" or schema == "CODE_MODE_TERMINAL_SUCCESS_V1":
        return "INVALID"
    if event_type == "code-mode.terminal-failed" or schema == "CODE_MODE_TERMINAL_FAILED_V1":
        return "INVALID"
    return None


class DynamicCollaborationError(TrueMultiAgentRuntimeError):
    pass


class AgentOutputContractRejected(DynamicCollaborationError):
    """A provider output failed a semantic contract before task acceptance."""

    def __init__(self, message: str, *, reason_code: str, expected_binding_hash: str | None = None):
        super().__init__(message)
        self.reason_code = reason_code
        self.expected_binding_hash = expected_binding_hash


class UsageAggregationError(DynamicCollaborationError):
    """A Forge result could not be converted into auditable usage totals."""


def _require_current_attempt_planner(
    payloads: Sequence[Mapping[str, Any]],
    *,
    run_id: str,
    run_attempt: int,
) -> dict[str, Any]:
    """Return the sole Planner fact for this run attempt.

    A matching latest authorization ref is deliberately *not* part of the
    collection predicate.  A conflicting Planner fact is evidence of a
    compromised or duplicated attempt and must be counted and rejected rather
    than hidden by selecting the last matching event.
    """
    planners = [
        dict(payload) for payload in payloads
        if payload.get("event_type") == "execution.stage"
        and payload.get("stage") == "Planner"
        and payload.get("run_id") == run_id
        and type(payload.get("run_attempt")) is int
        and payload.get("run_attempt") == run_attempt
    ]
    if len(planners) != 1:
        raise DynamicCollaborationError(
            "Code Mode current attempt requires exactly one Planner fact"
        )
    return planners[0]


def _require_exact_replan_bytes(
    raw: bytes,
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    """Reopen a replan only when its canonical bytes are exactly committed."""
    if not isinstance(raw, bytes):
        raise DynamicCollaborationError("Code Mode replan receipt is not bytes")
    expected_raw = canonical_json_bytes(dict(expected))
    try:
        parsed = parse_canonical_json(raw, allowed_fields=expected.keys())
    except Exception as error:
        raise DynamicCollaborationError("Code Mode replan receipt is not canonical JSON") from error
    if raw != expected_raw:
        raise DynamicCollaborationError("Code Mode replan receipt content is not the latest mapping")
    return parsed


def _request_acceptance_transaction(
    context: Any,
    *,
    locators: Mapping[str, Any],
) -> dict[str, Any]:
    """Request one typed envelope from the attested authority host.

    Code Mode never signs authority operations with the runtime Journal/CAS
    provider.  Direct/offline contexts have no signer and therefore fail
    closed at this boundary.
    """
    signer = getattr(context, "request_acceptance_transaction", None)
    if not callable(signer):
        raise DynamicCollaborationError("Code Mode authority host signer is unavailable")
    try:
        envelope = signer(locators=dict(locators))
    except Exception as error:
        raise DynamicCollaborationError(
            "Code Mode authority host refused the operation: " + str(error)
        ) from error
    if not isinstance(envelope, Mapping):
        raise DynamicCollaborationError("Code Mode authority host returned no signed envelope")
    return dict(envelope)


def _code_mode_locator(value: Mapping[str, Any] | None, role: str) -> dict[str, str]:
    """Return the one canonical, refs-only Code Mode locator projection.

    Runtime APIs historically returned several locator-shaped mappings (CAS
    receipts, request projections, and result summaries).  Persisted evidence
    must not compare those projections structurally: only this typed pair is
    authoritative.  ``object_hash`` is deliberately unprefixed so the same
    identity is stable across CAS receipts and reopened bodies.
    """
    if not isinstance(value, Mapping):
        raise DynamicCollaborationError(f"Code Mode {role} locator is missing")
    reference_id = value.get("reference_id")
    object_hash = value.get("object_hash")
    normalized_hash = str(object_hash or "").removeprefix("sha256:")
    if (
        not isinstance(reference_id, str)
        or not re.fullmatch(r"cas:[0-9a-f]{64}", reference_id)
        or not re.fullmatch(r"[0-9a-f]{64}", normalized_hash)
        or reference_id != "cas:" + normalized_hash
    ):
        raise DynamicCollaborationError(f"Code Mode {role} locator is not a verified CAS identity")
    return {
        "schema": "CODE_MODE_LOCATOR_V1",
        "role": role,
        "reference_id": reference_id,
        "object_hash": normalized_hash,
    }


def _code_mode_locators_equal(left: Mapping[str, Any], right: Mapping[str, Any], role: str) -> bool:
    return _code_mode_locator(left, role) == _code_mode_locator(right, role)


def _safe_code_mode_call(call: AgentCallResult) -> dict[str, Any]:
    """Project one provider call without prompt, model output, or value text."""
    return {
        "call_id": call.call_id,
        "run_id": call.run_id,
        "agent_id": call.agent_id,
        "role": call.role,
        "task_id": call.task_id,
        "task_attempt_id": call.task_attempt_id,
        "effect_id": call.effect_id,
        "effect_attempt_id": call.effect_attempt_id,
        "provider_request_id": call.provider_request_id,
        "input_snapshot_ref": call.input_snapshot_ref,
        "input_snapshot_hash": call.input_snapshot_hash,
        "output_ref": call.output_ref,
        "output_hash": call.output_hash,
        "kind": str(call.value.get("kind") or "unknown"),
        "usage": {str(key): int(value) for key, value in call.usage.items() if isinstance(value, int)},
        "cost_micro_usd": int(call.cost_micro_usd),
        "started_at": call.started_at,
        "completed_at": call.completed_at,
        "outcome": call.outcome,
        "settlement": call.settlement,
        "retry_count": int(call.retry_count),
        "fallback_count": int(call.fallback_count),
    }


def _safe_code_mode_execution_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only scalar execution facts; never persist tool/model payloads."""
    allowed = {
        "attempts", "accepted", "status", "tool_call_count", "file_mutation_event_count",
        "unique_mutated_path_count", "denied_effect_attempt_count", "external_mutation_count",
        "provider_call_count", "provider_physical_send_count", "provider_token_total",
        "provider_input_tokens", "provider_output_tokens", "provider_retry_count",
        "provider_fallback_count", "provider_unsettled_usage_count", "diff_hash",
        "patch_manifest_hash", "worktree_before_hash", "worktree_after_hash",
        "workspace_mode",
    }
    return {
        key: value[key]
        for key in sorted(allowed)
        if key in value and isinstance(value[key], (str, int, bool, type(None)))
    }


def _safe_code_mode_protocol(value: Mapping[str, Any]) -> dict[str, Any]:
    """Retain protocol structure while excluding free-form model content."""
    allowed = {
        "protocol_kind", "protocol_id", "source_event_hash", "target_event_hash",
        "task_id", "task_attempt_id", "accepted", "status", "generation",
    }
    return {
        key: value[key]
        for key in sorted(allowed)
        if key in value and isinstance(value[key], (str, int, bool, type(None)))
    }
def _embedded_usage_delta(value: Mapping[str, Any]) -> dict[str, int]:
    """Normalize one embedded Forge result before mutating run aggregates."""

    try:
        return {
            "provider_calls": int(value.get("provider_call_count", 0) or 0),
            "physical_sends": int(value.get("provider_physical_send_count", 0) or 0),
            "tool_calls": int(value.get("tool_call_count", 0) or 0),
            "input_tokens": int(value.get("provider_input_tokens", 0) or 0),
            "output_tokens": int(value.get("provider_output_tokens", 0) or 0),
            "cache_read_tokens": int(value.get("provider_cache_read_tokens", 0) or 0),
            "cache_write_tokens": int(value.get("provider_cache_write_tokens", 0) or 0),
            "total_tokens": int(value.get("provider_token_total", 0) or 0),
            "cost_micro_usd": int(value.get("provider_cost_micro_usd", 0) or 0),
            "retry_count": int(value.get("provider_retry_count", 0) or 0),
            "fallback_count": int(value.get("provider_fallback_count", 0) or 0),
            "unsettled_usage_count": int(value.get("provider_usage_unsettled_count", 0) or 0),
        }
    except (AttributeError, TypeError, ValueError, OverflowError) as error:
        raise UsageAggregationError("Forge provider usage is not auditable") from error


def _provider_accounting_delta(
    before: Mapping[str, int], after: Mapping[str, int]
) -> dict[str, int]:
    keys = (
        "provider_calls", "physical_sends", "input_tokens", "output_tokens",
        "cache_read_tokens", "cache_write_tokens", "total_tokens", "cost_micro_usd",
        "retry_count", "fallback_count", "unsettled_usage_count",
    )
    return {key: int(after.get(key, 0)) - int(before.get(key, 0)) for key in keys}


def _failed_transport_receipts(executor: Any) -> list[dict[str, Any]]:
    """Read only the executor's issuer-confirmed failed transport receipts."""

    getter = getattr(executor, "failed_provider_transport_receipts", None)
    if not callable(getter):
        return []
    values = getter()
    if not isinstance(values, (list, tuple)):
        raise DynamicCollaborationError("failed Provider receipt projection is not a sequence")
    result = [dict(item) for item in values if isinstance(item, Mapping)]
    if len(result) != len(values):
        raise DynamicCollaborationError("failed Provider receipt projection contains a non-mapping")
    return result


def _failed_transport_call_ids(executor: Any, receipts: Sequence[Mapping[str, Any]]) -> list[str]:
    getter = getattr(executor, "failed_provider_call_ids", None)
    if callable(getter):
        values = getter()
        if not isinstance(values, (list, tuple)) or any(not isinstance(item, str) or not item for item in values):
            raise DynamicCollaborationError("failed Provider call identity projection is malformed")
        ids = list(values)
    else:
        ids = []
        for receipt in receipts:
            provider_call_id = receipt.get("provider_call_id")
            if not isinstance(provider_call_id, str) or not provider_call_id:
                raise DynamicCollaborationError("failed Provider receipt has no call identity")
            if provider_call_id not in ids:
                ids.append(provider_call_id)
    derived: list[str] = []
    for receipt in receipts:
        provider_call_id = receipt.get("provider_call_id")
        if not isinstance(provider_call_id, str) or not provider_call_id:
            raise DynamicCollaborationError("failed Provider receipt has no call identity")
        if provider_call_id not in derived:
            derived.append(provider_call_id)
    if ids != derived:
        raise DynamicCollaborationError("failed Provider call identities do not match receipts")
    return ids


def _failed_transport_reason_codes(receipts: Sequence[Mapping[str, Any]]) -> list[str]:
    """Project stable host diagnostics without exposing provider text."""

    values: list[str] = []
    for receipt in receipts:
        reason_code = receipt.get("reason_code")
        if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code):
            # Older HTTP receipts predate the diagnostic field.  Keep their
            # accounting compatible while ensuring every newly emitted
            # post-response failure has an explicit non-sensitive code.
            continue
        if reason_code not in values:
            values.append(reason_code)
    return values


def _provider_retry_projection(calls: Sequence[Any], executor: Any) -> int:
    getter = getattr(executor, "failed_provider_retry_total", None)
    failed = int(getter() if callable(getter) else 0)
    return sum(int(getattr(item, "retry_count", 0) or 0) for item in calls) + int(
        executor.usage_totals().get("retry_count", 0)
    ) + failed


def _provider_fallback_projection(calls: Sequence[Any], executor: Any) -> int:
    getter = getattr(executor, "failed_provider_fallback_total", None)
    failed = int(getter() if callable(getter) else 0)
    return sum(int(getattr(item, "fallback_count", 0) or 0) for item in calls) + int(
        executor.usage_totals().get("fallback_count", 0)
    ) + failed


def _merge_embedded_attempt_accounting(
    value: Mapping[str, Any],
    before: Mapping[str, int],
    after: Mapping[str, int],
    *,
    provider_profile: str | None = None,
    provider_model: str | None = None,
) -> dict[str, Any]:
    """Bind a Forge attempt to executor deltas, including post-settlement errors."""
    delta = _provider_accounting_delta(before, after)
    result = {
        **dict(value),
        "provider_call_count": delta["provider_calls"],
        "provider_physical_send_count": delta["physical_sends"],
        "provider_retry_count": delta["retry_count"],
        "provider_fallback_count": delta["fallback_count"],
        "provider_input_tokens": delta["input_tokens"],
        "provider_output_tokens": delta["output_tokens"],
        "provider_cache_read_tokens": delta["cache_read_tokens"],
        "provider_cache_write_tokens": delta["cache_write_tokens"],
        "provider_token_total": delta["total_tokens"],
        "provider_cost_micro_usd": delta["cost_micro_usd"],
        "provider_usage_unsettled_count": delta["unsettled_usage_count"],
        "provider_usage_status": (
            "unknown" if delta["unsettled_usage_count"]
            else str(value.get("provider_usage_status") or "settled")
        ),
    }
    if provider_profile:
        result["provider_profile"] = provider_profile
    if provider_model:
        result["provider_model"] = provider_model
    return result


def _canonical_route_score(value: Any, *, field_name: str) -> str | None:
    """Encode bounded route scores without forbidden binary floating point."""

    if value is None:
        return None
    if isinstance(value, bool):
        raise DynamicCollaborationError(f"conversation route {field_name} must be numeric")
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise DynamicCollaborationError(f"conversation route {field_name} must be numeric") from error
    if not score.is_finite() or score < 0 or score > 1:
        raise DynamicCollaborationError(f"conversation route {field_name} must be between zero and one")
    score = score.quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
    return format(score.normalize(), "f")


def _require_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise DynamicCollaborationError(f"Agent output requires non-empty {key}")
    return item.strip()


def _require_review_decision(value: Mapping[str, Any]) -> str:
    decision = _require_string(value, "decision")
    if decision not in {"accept", "reject"}:
        raise DynamicCollaborationError(
            "Agent output decision must be lowercase accept or reject"
        )
    return decision


def _require_exact_parent_output_hash(value: Mapping[str, Any], expected: str) -> None:
    """Validate an immutable parent binding before a task can be accepted.

    This intentionally does not normalize prefixes, casing, or alternate hash
    spellings.  The parent identity is the exact CAS/output hash committed by
    the preceding call.
    """

    actual = value.get("parent_output_hash")
    if not isinstance(actual, str) or not actual.strip():
        raise AgentOutputContractRejected(
            "Agent output requires non-empty parent_output_hash",
            reason_code="PARENT_OUTPUT_HASH_MISSING",
            expected_binding_hash=expected,
        )
    if actual != expected:
        raise AgentOutputContractRejected(
            "Agent output parent_output_hash does not match the immutable parent",
            reason_code="PARENT_OUTPUT_HASH_MISMATCH",
            expected_binding_hash=expected,
        )


def _require_exact_handoff_binding(
    value: Mapping[str, Any], *, expected_contract_hash: str, expected_generation: int,
    expected_projection_hash: str | None = None,
) -> None:
    """Require an assessment or delivery to bind the exact frozen inputs."""

    actual_hash = value.get("contract_hash")
    if not isinstance(actual_hash, str) or not actual_hash.strip():
        raise AgentOutputContractRejected(
            "Handoff assessment requires non-empty contract_hash",
            reason_code="HANDOFF_CONTRACT_HASH_MISSING",
            expected_binding_hash=expected_contract_hash,
        )
    if actual_hash != expected_contract_hash:
        raise AgentOutputContractRejected(
            "Handoff assessment contract_hash does not match the frozen contract",
            reason_code="HANDOFF_CONTRACT_HASH_MISMATCH",
            expected_binding_hash=expected_contract_hash,
        )
    actual_generation = value.get("generation")
    if isinstance(actual_generation, bool) or not isinstance(actual_generation, int):
        raise AgentOutputContractRejected(
            "Handoff assessment requires an integer generation",
            reason_code="HANDOFF_GENERATION_MISSING",
            expected_binding_hash=expected_contract_hash,
        )
    if actual_generation != expected_generation:
        raise AgentOutputContractRejected(
            "Handoff assessment generation does not match the frozen contract",
            reason_code="HANDOFF_GENERATION_MISMATCH",
            expected_binding_hash=expected_contract_hash,
        )
    if expected_projection_hash is not None:
        actual_projection_hash = value.get("selected_proposal_projection_hash")
        if not isinstance(actual_projection_hash, str) or not actual_projection_hash.strip():
            raise AgentOutputContractRejected(
                "Handoff output requires selected_proposal_projection_hash",
                reason_code="HANDOFF_PROJECTION_HASH_MISSING",
                expected_binding_hash=expected_projection_hash,
            )
        if actual_projection_hash != expected_projection_hash:
            raise AgentOutputContractRejected(
                "Handoff output projection hash does not match the frozen projection",
                reason_code="HANDOFF_PROJECTION_HASH_MISMATCH",
                expected_binding_hash=expected_projection_hash,
            )


def _handoff_repair_progress_signature(
    reasons: Sequence[str], *, selected_proposal_hash: str,
    semantic_delta: Mapping[str, Any] | None = None,
) -> tuple[str, str]:
    """Derive signatures from a verified predecessor/successor delta."""

    semantic_delta_hash = stable_hash(
        "HANDOFF_SEMANTIC_CONTRACT_DELTA",
        {
            "verified_delta": dict(semantic_delta or {}),
            "resolved_field_paths": sorted(set(str(item) for item in reasons)),
            "selected_proposal_hash": selected_proposal_hash,
        },
    )
    progress_signature = stable_hash(
        "HANDOFF_REPAIR_PROGRESS_SIGNATURE",
        {
            "semantic_delta_hash": semantic_delta_hash,
            "verified_changed_paths": list((semantic_delta or {}).get("changed_paths", ())),
        },
    )
    return semantic_delta_hash, progress_signature


def _handoff_reason_field_path(reason: str) -> str:
    parts = str(reason).split("|", 2)
    return parts[1] if len(parts) >= 2 else str(reason)


_HANDOFF_CORRECTION_RULES: dict[tuple[str, str], dict[str, str]] = {
    ("MISSING_CHECK", "acceptance_criteria"): {
        "operation": "ensure_acceptance_criterion",
        "value": "run focused tests with pytest -q",
        "constraint": "acceptance_criteria must contain the exact focused-test requirement",
    },
    ("MISSING_CHECK", "acceptance_criteria.must_run_pytest"): {
        "operation": "ensure_acceptance_criterion",
        "value": "run focused tests with pytest -q",
        "constraint": "acceptance_criteria.must_run_pytest resolves to the exact focused-test requirement",
    },
    ("MISSING_SCOPE", "scope"): {
        "operation": "ensure_scope_requirement",
        "value": "run focused validation in the selected workspace",
        "constraint": "scope must contain the exact selected-workspace validation requirement",
    },
}


def _structured_handoff_corrections(
    reasons: Sequence[str],
) -> tuple[dict[str, str], ...]:
    """Translate safe, enumerated rejection paths into concrete corrections.

    Provider detail is retained only as a hash in the reason lineage.  It is
    never used as a successor instruction: a successor is admissible only when
    an enumerated code/path pair has a deterministic, auditable correction.
    """

    corrections: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for reason in reasons:
        parts = str(reason).split("|", 2)
        code = parts[0].strip().upper() if parts else ""
        path = parts[1].strip() if len(parts) > 1 else ""
        rule = _HANDOFF_CORRECTION_RULES.get((code, path))
        if rule is None:
            raise DynamicCollaborationError(
                "Handoff rejection has no safe structured correction"
            )
        key = (code, path)
        if key in seen:
            continue
        seen.add(key)
        detail = parts[2].strip() if len(parts) > 2 else ""
        if detail and not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", detail):
            detail = sha256_bytes(detail.encode()).removeprefix("sha256:")
        correction = {
            "reason_code": code,
            "field_path": path,
            "detail_hash": detail,
            **rule,
        }
        corrections.append(correction)
    return tuple(corrections)


def _handoff_semantic_snapshot(
    contract: HandoffContract, projection: Mapping[str, Any]
) -> dict[str, Any]:
    """Return mutable semantics while excluding generation bookkeeping."""

    return {
        "scope": list(contract.scope),
        "acceptance_criteria": list(contract.acceptance_criteria),
        "output_schema": dict(contract.output_schema),
        "proposal_projection": {
            str(key): value for key, value in projection.items() if key != "generation"
        },
    }


def _proposed_handoff_semantic_snapshot(
    *,
    generation: int,
    selected_projection: Mapping[str, Any],
    resolution_map: Mapping[str, str],
) -> dict[str, Any]:
    """Build the exact semantic successor that make_contract freezes."""

    corrections = _structured_handoff_corrections(tuple(resolution_map))
    field_paths = sorted({str(item["field_path"]) for item in corrections})
    base_scope = (
        "read selected immutable proposal",
        "produce bounded JSON handoff result",
        "preserve evidence lineage",
    )
    base_acceptance = (
        "source hash is bound",
        "deliverable is non-empty",
        "independent verifier accepts",
    )
    corrected_scope = list(base_scope)
    corrected_acceptance = list(base_acceptance)
    for correction in corrections:
        if correction["operation"] == "ensure_scope_requirement":
            corrected_scope.append(correction["value"])
        elif correction["operation"] == "ensure_acceptance_criterion":
            corrected_acceptance.append(correction["value"])
    corrected_scope = tuple(corrected_scope)
    corrected_acceptance = tuple(corrected_acceptance)
    output_schema = {
        "type": "object",
        "required": [
            "deliverable", "source_output_hash", "acceptance_checks",
            "contract_hash", "generation", "selected_proposal_projection_hash",
        ],
        "properties": {
            "deliverable": {"type": "string", "minLength": 1},
            "source_output_hash": {"type": "string"},
            "acceptance_checks": {"type": "array", "minItems": 1, "maxItems": 8},
            "contract_hash": {"type": "string"},
            "generation": {"type": "integer", "const": generation},
            "selected_proposal_projection_hash": {"type": "string"},
        },
    }
    if field_paths:
        output_schema["x_sitina_corrected_field_paths"] = field_paths
        output_schema["x_sitina_correction_operations"] = [
            {
                "operation": item["operation"],
                "field_path": item["field_path"],
                "value": item["value"],
                "constraint": item["constraint"],
            }
            for item in corrections
        ]
        output_schema["x_sitina_correction_hash"] = stable_hash(
            "HANDOFF_FIELD_CORRECTION_PAYLOAD",
            [
                {
                    "reason_code": item["reason_code"],
                    "field_path": item["field_path"],
                    "detail_hash": item["detail_hash"],
                    "operation": item["operation"],
                    "value": item["value"],
                    "constraint": item["constraint"],
                }
                for item in corrections
            ],
        )
    projection = {
        **dict(selected_projection),
        "generation": generation,
        "semantic_resolution_fields": field_paths,
    }
    return {
        "scope": list(corrected_scope),
        "acceptance_criteria": list(corrected_acceptance),
        "output_schema": output_schema,
        "proposal_projection": {
            str(key): value for key, value in projection.items() if key != "generation"
        },
    }


def _verified_handoff_semantic_delta(
    before: Mapping[str, Any], after: Mapping[str, Any], reasons: Sequence[str],
    corrections: Sequence[Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Require every unresolved field path to have a real semantic change."""

    changed_paths = sorted(
        key for key in set(before) | set(after) if before.get(key) != after.get(key)
    )
    correction_items = tuple(corrections or _structured_handoff_corrections(reasons))
    unresolved_paths = sorted({str(item["field_path"]) for item in correction_items})
    if not unresolved_paths:
        raise DynamicCollaborationError("Handoff repair produced no verified semantic field delta")
    verified_operations: list[dict[str, str]] = []
    for item in correction_items:
        operation = str(item["operation"])
        path = str(item["field_path"])
        value = str(item["value"])
        if operation == "ensure_acceptance_criterion":
            before_values = tuple(str(value_item) for value_item in before.get("acceptance_criteria", ()))
            after_values = tuple(str(value_item) for value_item in after.get("acceptance_criteria", ()))
            if value in before_values or value not in after_values:
                raise DynamicCollaborationError(
                    "Handoff repair did not change the required acceptance criterion"
                )
            root = "acceptance_criteria"
        elif operation == "ensure_scope_requirement":
            before_values = tuple(str(value_item) for value_item in before.get("scope", ()))
            after_values = tuple(str(value_item) for value_item in after.get("scope", ()))
            if value in before_values or value not in after_values:
                raise DynamicCollaborationError(
                    "Handoff repair did not change the required scope"
                )
            root = "scope"
        else:
            raise DynamicCollaborationError("Handoff repair used an unsupported correction operation")
        if root not in changed_paths:
            raise DynamicCollaborationError("Handoff repair changed no required semantic root")
        verified_operations.append({
            "operation": operation,
            "field_path": path,
            "value_hash": sha256_bytes(value.encode()).removeprefix("sha256:"),
        })
    return {
        "before_hash": stable_hash("HANDOFF_SEMANTIC_BEFORE", dict(before)),
        "after_hash": stable_hash("HANDOFF_SEMANTIC_AFTER", dict(after)),
        "changed_paths": changed_paths,
        "resolved_field_paths": unresolved_paths,
        "verified_corrections": verified_operations,
    }


def _validate_handoff_delivery(
    value: Mapping[str, Any], *, expected_contract_hash: str,
    expected_generation: int, expected_projection_hash: str,
    expected_source_output_hash: str,
) -> None:
    """Validate every frozen delivery-schema field before Task acceptance."""

    _require_exact_handoff_binding(
        value,
        expected_contract_hash=expected_contract_hash,
        expected_generation=expected_generation,
        expected_projection_hash=expected_projection_hash,
    )
    _require_string(value, "deliverable")
    if _require_string(value, "source_output_hash") != expected_source_output_hash:
        raise DynamicCollaborationError("Handoff delivery did not bind selected source hash")
    _require_strings(value, "acceptance_checks", maximum=8)


def _require_strings(value: Mapping[str, Any], key: str, *, minimum: int = 1, maximum: int = 12) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or not minimum <= len(item) <= maximum:
        raise DynamicCollaborationError(f"Agent output requires bounded list {key}")
    if any(not isinstance(element, str) or not element.strip() for element in item):
        raise DynamicCollaborationError(f"Agent output {key} requires non-empty strings")
    result = [element.strip() for element in item]
    return result


def _require_bool(value: Mapping[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise DynamicCollaborationError(f"Agent output requires boolean {key}")
    return item


def _require_text_or_strings(value: Mapping[str, Any], key: str, *, maximum: int = 8) -> list[str]:
    item = value.get(key)
    if isinstance(item, str) and item.strip():
        return [item.strip()]
    return _require_strings(value, key, maximum=maximum)


def _require_json_array_or_strings(
    value: Mapping[str, Any], key: str, *, minimum: int = 1, maximum: int = 12
) -> list[str]:
    item = value.get(key)
    if isinstance(item, str):
        try:
            decoded = json.loads(item)
        except json.JSONDecodeError as error:
            raise DynamicCollaborationError(f"Agent output {key} is not a JSON string array") from error
        return _require_strings({key: decoded}, key, minimum=minimum, maximum=maximum)
    return _require_strings(value, key, minimum=minimum, maximum=maximum)


def _require_verification_checks(value: Mapping[str, Any], *, maximum: int = 8) -> list[str]:
    """Accept the two bounded check shapes commonly returned by review models."""

    item = value.get("checks")
    if isinstance(item, list):
        return _require_strings(value, "checks", maximum=maximum)
    if not isinstance(item, dict) or not 1 <= len(item) <= maximum:
        raise DynamicCollaborationError("Agent output requires bounded verification checks")
    checks: list[str] = []
    for name, result in item.items():
        if not isinstance(name, str) or not name.strip():
            raise DynamicCollaborationError("Agent verification check names must be non-empty strings")
        if isinstance(result, bool):
            rendered = "passed" if result else "failed"
        elif isinstance(result, str) and result.strip():
            rendered = result.strip()
        else:
            raise DynamicCollaborationError("Agent verification check results must be text or booleans")
        checks.append(f"{name.strip()}: {rendered}")
    return checks


def _require_response_items(value: Mapping[str, Any], key: str, *, maximum: int = 8) -> None:
    item = value.get(key)
    if not isinstance(item, list) or not 1 <= len(item) <= maximum:
        raise DynamicCollaborationError(f"Agent output requires bounded response list {key}")
    for element in item:
        if isinstance(element, str) and element.strip():
            continue
        if (
            isinstance(element, dict)
            and isinstance(element.get("objection") or element.get("defect"), str)
            and isinstance(element.get("response"), str)
            and str(element.get("objection") or element.get("defect")).strip()
            and element["response"].strip()
        ):
            continue
        raise DynamicCollaborationError(f"Agent output {key} contains an invalid response item")


def _require_defect_responses(
    value: Mapping[str, Any], defects: Sequence[str], *, maximum: int = 8
) -> list[dict[str, str]]:
    """Bind every immutable Review defect to exactly one revision response."""

    if not defects or len(defects) > maximum:
        raise DynamicCollaborationError("Rework requires a bounded non-empty frozen defect set")
    items = value.get("defect_responses")
    if not isinstance(items, list) or len(items) != len(defects):
        raise DynamicCollaborationError("Rework requires exactly one response per frozen Review defect")
    normalized: list[dict[str, str]] = []
    for index, (defect, item) in enumerate(zip(defects, items, strict=True), 1):
        if isinstance(item, str) and item.strip():
            normalized.append({"defect": defect, "response": item.strip(), "ordinal": str(index)})
            continue
        if not isinstance(item, dict):
            raise DynamicCollaborationError("Rework defect response must be text or a defect/response object")
        stated_defect = item.get("defect") or item.get("objection")
        response = item.get("response")
        if not isinstance(stated_defect, str) or stated_defect.strip() != defect:
            raise DynamicCollaborationError("Rework defect response does not bind the exact frozen defect")
        if not isinstance(response, str) or not response.strip():
            raise DynamicCollaborationError("Rework defect response is empty")
        normalized.append({"defect": defect, "response": response.strip(), "ordinal": str(index)})
    return normalized


def _single_rework_required(goal: str) -> bool:
    """Recognize an ordinary-language bound that permits one initial rework only."""

    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "changes on one proposal",
            "changes on exactly one proposal",
            "changes on one initial proposal",
            "changes on exactly one initial proposal",
        )
    )


def _provider_recovery_required(goal: str) -> bool:
    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "provider recovery",
            "pre-send failure",
            "presend failure",
            "after-start loss",
            "explicit remote failure",
            "ack lost after remote success",
            "provider timeout",
            "提供商恢复",
        )
    )


def _checkpoint_restart_required(goal: str) -> bool:
    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "checkpoint restart resume",
            "checkpoint/restart/resume",
            "restart frontier",
            "process reconstruction",
            "checkpoint recovery",
            "检查点重启恢复",
        )
    )


def _execution_required(goal: str) -> bool:
    """Return the frozen mutation decision for the Forge entry gate.

    Intent classification is the sole source of mutation authorization.  The
    old substring list treated architectural discussion and quoted/negated
    operations as execution requests, which could prepare a managed worktree
    for a read-only MULTI answer.  Reusing the span/scoped classifier keeps
    this downstream gate in lockstep with the conversation authorization.
    """
    intent = classify_code_mode_intent(str(goal or ""))
    return bool(intent.get("explicit_mutation") is True)


def _execution_goal_authorized(goal: str, controls: Mapping[str, Any]) -> bool:
    """Return the frozen execution decision for the Forge entry gate.

    Interactive Code Mode must use the host-issued, immutable intent
    projection.  The broad legacy heuristic remains only for non-interactive
    workflows, where no chat authorization projection exists.
    """
    if bool(controls.get("interactive_chat")):
        intent = controls.get("code_mode_intent")
        return bool(
            controls.get("intent_authorized") is True
            and isinstance(intent, Mapping)
            and intent.get("explicit_mutation") is True
        )
    return _execution_required(goal)


def _code_mode_mutation_rework_authorized(controls: Mapping[str, Any]) -> bool:
    """Allow one proposal correction only for an explicit Code Mode write.

    Ordinary MULTI review (including read-only chat) must keep a hard REJECT
    terminal.  The host-issued authorization and frozen intent projection are
    the only inputs that may open this narrow correction seam.
    """

    intent = controls.get("code_mode_intent")
    return bool(
        controls.get("interactive_chat")
        and isinstance(controls.get("code_mode_authorization"), Mapping)
        and controls.get("intent_authorized") is True
        and isinstance(intent, Mapping)
        and intent.get("explicit_mutation") is True
    )


def _repairable_review_rejection(value: Mapping[str, Any], *, score: int, minimum_score: int) -> bool:
    """Recognize a bounded, low-risk correction rather than a hard refusal."""

    defects = value.get("defects")
    if not isinstance(defects, list) or not defects:
        return False
    if score < max(1, int(minimum_score) // 2):
        return False
    text = " ".join(str(item) for item in defects).casefold()
    text += " " + str(value.get("reason") or "").casefold()
    hard_markers = (
        "security", "unsafe", "unauthorized", "forbidden", "out of scope", "impossible", "cannot",
        "安全", "越权", "禁止", "范围外", "不可行", "不允许",
    )
    return not any(marker in text for marker in hard_markers)


def _execution_isolation_required(goal: str, controls: Mapping[str, Any]) -> bool:
    """Choose the existing managed worktree for risky/concurrent writes."""

    if str(controls.get("execution_isolation") or "").casefold() in {"worktree", "isolated", "high-risk"}:
        return True
    if bool(controls.get("concurrent_write")) or bool(controls.get("high_risk_execution")):
        return True
    normalized = goal.casefold()
    # Parse clauses independently.  A negation applies to its own clause;
    # commas and contrast conjunctions start a new intent clause, so
    # "do not push, but deploy" still contains a positive deploy request.
    clauses = re.split(
        r"[,，;；]|\b(?:but|however|except)\b|但|但是|然而",
        normalized,
    )
    negated_clause = re.compile(
        r"\b(?:do\s+not|don't|dont|never|without|no)\b|不要|无需|勿"
    )

    def positive(marker: str) -> bool:
        return any(
            re.search(re.escape(marker), clause) is not None
            and negated_clause.search(clause) is None
            for clause in clauses
        )

    return any(
        positive(marker)
        for marker in (
            "deploy", "publish", "release", "部署", "发布", "推送", "提交",
            "database migration", "数据库迁移", "生产", "production",
            "remote api", "远程 api", "send", "发送", "push", "system configuration",
        )
    )


def _integrated_closure_required(goal: str) -> bool:
    """Recognize the ordinary business semantics that require the full closure.

    This is deliberately phrased in terms of user-visible work constraints.  It
    does not look for Event names or an acceptance-only command.
    """

    normalized = goal.casefold()
    semantic_groups = (
        ("multi-round negotiation", "second negotiation round", "多轮协商"),
        ("shared state", "shared record", "共同记录", "共享状态"),
        ("same base", "competing edit", "concurrent edit", "同一初始"),
        ("owner becomes unavailable", "ownership failover", "lease expiry", "所有权故障转移"),
        ("operational transfer", "work transfer", "receiving engineer", "接收方"),
        ("first transfer package lacks", "receiver rejects", "correct every omission", "接收方拒绝"),
        ("checkpoint restart resume", "checkpoint recovery", "检查点重启恢复"),
        ("provider recovery", "after-start loss", "ack lost after remote success", "提供商恢复"),
    )
    return all(any(marker in normalized for marker in group) for group in semantic_groups)


@dataclass(frozen=True)
class GoalAnalysis:
    complexity: str
    risk_level: str
    protocols: tuple[str, ...]
    task_graph: tuple[str, ...]
    proposal_count: int
    domain_capability: str | None
    requires_rework: bool
    requires_conflict: bool
    requires_handoff_reject: bool
    requires_reassignment: bool
    requires_provider_unknown: bool
    rationale: str

    @classmethod
    def parse(cls, value: Mapping[str, Any], policy: Mapping[str, Any]) -> "GoalAnalysis":
        complexity = _require_string(value, "complexity").lower()
        risk = _require_string(value, "risk_level").lower()
        if complexity not in {"simple", "standard", "high"} or risk not in {"low", "medium", "high"}:
            raise DynamicCollaborationError("Goal analysis complexity/risk is outside policy")
        aliases = {
            "reassignment": "lease",
            "task-reassignment": "lease",
            "fencing": "lease",
            "mvcc": "blackboard",
            "restart": "checkpoint",
            "resume": "checkpoint",
            "revision": "rework",
            "transfer": "handoff",
        }
        protocols = tuple(
            dict.fromkeys(
                aliases.get(item.lower(), item.lower())
                for item in _require_strings(value, "protocols", minimum=0, maximum=9)
            )
        )
        allowed = set(str(item) for item in policy["allowed_protocols"])
        if not set(protocols).issubset(allowed):
            raise DynamicCollaborationError("Goal analysis requested a forbidden protocol")
        if "proposal" not in protocols:
            protocols = ("proposal", *protocols)
        tasks = tuple(_require_strings(value, "task_graph", maximum=16))
        count = value.get("proposal_count")
        if not isinstance(count, int) or not 1 <= count <= int(policy["max_proposals_per_round"]):
            raise DynamicCollaborationError("Goal analysis proposal count is outside policy")
        domain = value.get("domain_capability")
        if domain is not None and (not isinstance(domain, str) or not domain.strip()):
            raise DynamicCollaborationError("domain_capability must be null or a string")
        flags = {
            key: _require_bool(value, key)
            for key in (
                "requires_rework",
                "requires_conflict",
                "requires_handoff_reject",
                "requires_reassignment",
                "requires_provider_unknown",
            )
        }
        return cls(
            complexity,
            risk,
            protocols,
            tasks,
            count,
            domain.strip() if isinstance(domain, str) else None,
            flags["requires_rework"],
            flags["requires_conflict"],
            flags["requires_handoff_reject"],
            flags["requires_reassignment"],
            flags["requires_provider_unknown"],
            _require_string(value, "rationale"),
        )

    def mapping(self) -> dict[str, Any]:
        return {
            **self.__dict__,
            "protocols": list(self.protocols),
            "task_graph": list(self.task_graph),
        }


@dataclass
class RunEvidence:
    run_id: str
    goal: str
    goal_hash: str
    policy_hash: str
    analysis: GoalAnalysis | None = None
    decisions: list[dict[str, Any]] = field(default_factory=list)
    calls: list[AgentCallResult] = field(default_factory=list)
    protocol_graph: list[dict[str, Any]] = field(default_factory=list)
    obligations: dict[str, bool] = field(default_factory=dict)
    called_agents: set[str] = field(default_factory=set)
    selected_agents: set[str] = field(default_factory=set)
    filtered_agents: dict[str, list[str]] = field(default_factory=dict)
    expected_terminal: str = "SUCCEEDED"
    actual_terminal: str | None = None
    terminal_event: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    checkpoint_restarts: list[dict[str, Any]] = field(default_factory=list)
    user_response: str | None = None
    user_response_agent_id: str | None = None
    user_response_output_hash: str | None = None
    execution_result: dict[str, Any] | None = None
    # A bounded, CAS-backed read-only snapshot collected before Proposal and
    # Review for interactive analysis.  It is deliberately a projection of
    # list/read/search facts; it is never an execution authorization.
    readonly_workspace_evidence: dict[str, Any] | None = None


@dataclass
class CodeModeExecutionFacts:
    """Typed, core-derived facts used by the Code Mode terminal projection.

    Recovery must not rebuild a generic orchestration ``RunEvidence`` or
    invent goal/analysis fields.  This object contains only facts copied
    from the authenticated execution-core projection.
    """

    run_id: str
    goal_hash: str
    policy_hash: str
    # The live execution keeps the user goal only in memory for orchestration;
    # the immutable execution core stores its hash, never the prompt text.
    goal: str = ""
    decisions: list[dict[str, Any]] = field(default_factory=list)
    calls: list[Any] = field(default_factory=list)
    protocol_graph: list[dict[str, Any]] = field(default_factory=list)
    obligations: dict[str, bool] = field(default_factory=dict)
    called_agents: set[str] = field(default_factory=set)
    selected_agents: set[str] = field(default_factory=set)
    filtered_agents: dict[str, list[str]] = field(default_factory=dict)
    expected_terminal: str = "SUCCEEDED"
    actual_terminal: str | None = None
    notes: list[str] = field(default_factory=list)
    checkpoint_restarts: list[dict[str, Any]] = field(default_factory=list)
    user_response: str | None = None
    user_response_agent_id: str | None = None
    user_response_output_hash: str | None = None
    execution_result: dict[str, Any] = field(default_factory=dict)
    analysis: GoalAnalysis | None = None
    terminal_event: dict[str, Any] | None = None
    readonly_workspace_evidence: dict[str, Any] | None = None


def render_selected_user_response(value: Mapping[str, Any]) -> str:
    """Render the reviewed winning proposal as a concise terminal response."""

    answer_fragment = str(value.get("answer_fragment") or "").strip()
    if answer_fragment:
        return answer_fragment
    summary = str(value.get("summary") or "").strip()
    approach = str(value.get("approach") or "").strip()
    if summary and approach and summary != approach:
        return f"{summary}\n\n{approach}"
    return summary or approach


def _readonly_claim_id(path: str | None, line: int | None, query: str, value: str) -> str:
    payload = {"path": path or "", "line": line, "query": query, "value": value}
    return "claim-" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()[:32]


def _readonly_observed_value(query: str, matched_text: str) -> str:
    """Derive the answer value from one exact, path/line-bound match.

    A marker is a search query, not automatically the answer.  When the
    observed line carries an assignment (``MARKER=value``), only the value is
    required in the reviewed answer; the raw line remains bounded evidence.
    """
    line = str(matched_text or "").strip()
    if not line:
        return ""
    query = str(query or "").strip()
    if query:
        assignment = re.search(r"%s\s*=\s*(.+?)\s*$" % re.escape(query), line)
        if assignment:
            return assignment.group(1).strip().strip("`\"'")
    if "=" in line:
        value = line.split("=", 1)[1].strip().strip("`\"'")
        if value:
            return value
    return line


def _extract_required_evidence_claims(user_request: str) -> list[dict[str, Any]]:
    """Extract only explicit, auditable evidence claims from the full request.

    Broad goal words are intentionally excluded.  Claims come from quoted or
    backtick-delimited values, upper snake identifiers, and relative paths
    (optionally carrying a line number).  The collector resolves these facts
    through the bound read/search tools before making them visible to agents.
    """
    text = str(user_request or "")
    candidates: list[tuple[str, str | None, int | None]] = []
    path_pattern = re.compile(
        r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.[A-Za-z0-9_-]+)(?::(\d+))?"
    )
    for match in re.finditer(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'|“([^”]+)”|‘([^’]+)’", text):
        value = next((item for item in match.groups() if item is not None), "").strip()
        if value:
            path_match = re.fullmatch(path_pattern, value)
            candidates.append((
                value,
                path_match.group(1) if path_match else None,
                int(path_match.group(2)) if path_match and path_match.group(2) else None,
            ))
    for match in re.finditer(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b", text):
        candidates.append((match.group(0), None, None))
    for match in path_pattern.finditer(text):
        path = match.group(1)
        if path.startswith(".") or path.startswith("/") or "/../" in ("/" + path):
            continue
        line = int(match.group(2)) if match.group(2) else None
        if line is None:
            suffix = text[match.end():match.end() + 24]
            line_match = re.search(
                r"(?:line\s*[:#]?\s*(\d+)|第\s*(\d+)\s*行|行\s*[:#]?\s*(\d+))",
                suffix,
                re.IGNORECASE,
            )
            if line_match:
                line = int(next(item for item in line_match.groups() if item is not None))
        candidates.append((path, path, line))
    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, int | None]] = set()
    line_paths = {path for _, path, line in candidates if path and line is not None}
    for value, path, line in candidates:
        if path and line is None and path in line_paths:
            continue
        key = (value, path, line)
        if key in seen:
            continue
        seen.add(key)
        claims.append({
            "claim_id": _readonly_claim_id(path, line, value, value),
            "path": path,
            "line": line,
            "exact_query": value,
            "observed_value": None,
            "observed_value_hash": None,
            "required_answer_value": None,
            "required_answer_value_hash": None,
            "status": "pending",
        })
    return claims[:128]


def _canonicalize_readonly_evidence_claims(
    claims: Sequence[Mapping[str, Any]],
    *,
    workspace_root_hash: str,
) -> list[dict[str, Any]]:
    """Collapse satisfied aliases by their observed workspace fact identity.

    Query wording and the provisional claim id are provenance, not evidence
    identity.  Missing/ambiguous claims remain distinct and are never folded
    into a satisfied fact.
    """

    canonical_claims: list[dict[str, Any]] = []
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for raw_claim in claims:
        claim = dict(raw_claim)
        if claim.get("status") != "satisfied":
            canonical_claims.append(claim)
            continue
        path = os.path.normpath(str(claim.get("path") or "")).replace(os.sep, "/")
        if path == ".":
            path = ""
        line = claim.get("line")
        identity = {
            "workspace_root_hash": str(workspace_root_hash),
            "path": path,
            "line": line,
            "matched_text_hash": claim.get("matched_text_hash"),
            "observed_value_hash": claim.get("observed_value_hash"),
        }
        key = tuple(identity[item] for item in (
            "workspace_root_hash", "path", "line", "matched_text_hash", "observed_value_hash",
        ))
        group = groups.get(key)
        if group is None:
            group = {
                "claim": claim,
                "identity": identity,
                "source_queries": set(),
                "alias_claim_ids": set(),
            }
            groups[key] = group
            canonical_claims.append(claim)
        exact_query = claim.get("exact_query")
        if isinstance(exact_query, str) and exact_query:
            group["source_queries"].add(exact_query)
        claim_id = claim.get("claim_id")
        if isinstance(claim_id, str) and claim_id:
            group["alias_claim_ids"].add(claim_id)

    for group in groups.values():
        identity = group["identity"]
        source_queries = sorted(group["source_queries"])
        alias_claim_ids = sorted(group["alias_claim_ids"])
        canonical_id = "claim-" + sha256_bytes(canonical_json_bytes(identity))[:32]
        claim = group["claim"]
        claim.update({
            "claim_id": canonical_id,
            "path": identity["path"],
            "line": identity["line"],
            "exact_query": source_queries[0] if source_queries else str(claim.get("exact_query") or ""),
            "source_queries": source_queries,
            "alias_claim_ids": alias_claim_ids,
            "evidence_hash": sha256_bytes(canonical_json_bytes(identity)),
        })
    return canonical_claims


class TrueMultiAgentProductionRuntime:
    """Production-native dynamic collaboration coordinator.

    The coordinator never writes Projection or Legacy state. It submits
    Commands to authoritative Streams, while protocol aggregates validate
    every transition before facts are committed.
    """

    DISCOVERY_SYSTEM = (
        "You are the independently identified Sitina goal-analysis Agent. "
        "Analyze the semantic goal and live constraints; do not follow a fixed role pipeline. "
        "Return one JSON object only. Never claim that an event happened."
    )

    def __init__(
        self,
        home: Path,
        *,
        source_root: Path | None = None,
        runtime_context_factory: Any | None = None,
        provider_client: Any | None = None,
        provider_profile: Any | None = None,
    ):
        self.home = Path(home).resolve(strict=True)
        self.source_root = Path(source_root or home).expanduser().resolve(strict=True)
        self.registry = AgentRegistry.load(self.source_root)
        self.policy = json.loads((self.source_root / "config/true_multi_agent_policy.json").read_text(encoding="utf-8"))
        if self.policy.get("schema") != "SITINA_TRUE_MULTI_AGENT_POLICY_V1":
            raise DynamicCollaborationError("unsupported true multi-agent policy")
        self.policy_hash = sha256_bytes(canonical_json_bytes(self.policy))
        self.scheduler = AgentScheduler()
        self.autonomous_runtime = None
        self.approval_callback = None
        self.runtime_context_factory = runtime_context_factory
        self.provider_client = provider_client
        self.provider_profile = provider_profile
        self._code_mode_authorizer = None
        # A review-pending Code Mode run is intentionally not terminal.  Keep
        # the live controller objects only until the TTY handoff is resolved;
        # the durable package/request remain the recovery authority.
        self._pending_code_mode_runs: dict[str, dict[str, Any]] = {}

    def bind_conversation_dependencies(
        self, *, autonomous_runtime: Any | None, approval_callback: Callable[..., Any] | None,
    ) -> None:
        self.autonomous_runtime = autonomous_runtime
        self.approval_callback = approval_callback

    def bind_code_mode_authorizer(self, authorizer: Any) -> None:
        """Bind the in-process issuer used to validate Code Mode controls."""
        self._code_mode_authorizer = authorizer

    def _frontier(self, journal: Any) -> FrontierRef:
        position = journal.head_position
        commitment = journal._position_hash[position] if position else "0" * 64
        return FrontierRef(journal.journal_id, journal.epoch, "local", position, commitment)

    @staticmethod
    def _run_stream_frontier(journal: Any, run_stream: Any) -> dict[str, Any]:
        """Return a deterministic frontier for one run stream only.

        Global Journal positions are physical placement metadata and must not
        enter Code Mode evidence identities.  The logical frontier is the
        authenticated last event/version of this run stream plus its ordered
        event-hash commitment.
        """
        stream_id = str(run_stream.stream_id)
        events = tuple(event for event in journal.iter_events(0) if event.stream_id == stream_id)
        if not events:
            return {"stream_id": stream_id, "stream_version": 0, "commitment": "0" * 64}
        return {
            "stream_id": stream_id,
            "stream_version": int(events[-1].stream_version),
            "commitment": stable_hash(
                "CODE_MODE_RUN_STREAM_FRONTIER",
                {"stream_id": stream_id, "events": [str(event.event_hash) for event in events]},
            ),
        }

    def _recent_event_ids(self, journal: Any, *, limit: int = 8) -> tuple[str, ...]:
        events = tuple(journal.iter_events(max(0, journal.head_position - limit)))
        return tuple(item.event_id for item in events[-limit:])

    @staticmethod
    def _record_conversation_route(run_stream: CanonicalStream, controls: Mapping[str, Any]) -> None:
        conversation_route = controls.get("conversation_route_decision")
        if not bool(controls.get("interactive_chat")) or not isinstance(conversation_route, Mapping):
            return
        raw_reasons = conversation_route.get("reasons")
        reasons = (
            [str(item).strip()[:160] for item in raw_reasons if str(item).strip()][:8]
            if isinstance(raw_reasons, (list, tuple))
            else []
        )
        raw_initial_fast = conversation_route.get("initial_fast_decision")
        initial_fast_decision = None
        if isinstance(raw_initial_fast, Mapping):
            raw_evidence_reasons = raw_initial_fast.get("evidence_reasons")
            initial_fast_decision = {
                "schema": raw_initial_fast.get("schema"),
                "evaluated": bool(raw_initial_fast.get("evaluated")),
                "decision": str(raw_initial_fast.get("decision") or "")[:80],
                "multi_score": _canonical_route_score(
                    raw_initial_fast.get("multi_score"), field_name="initial_fast_decision.multi_score"
                ),
                "threshold": _canonical_route_score(
                    raw_initial_fast.get("threshold"), field_name="initial_fast_decision.threshold"
                ),
                "provider_evaluated": bool(raw_initial_fast.get("provider_evaluated")),
                "evidence_reasons": (
                    [str(item).strip()[:160] for item in raw_evidence_reasons if str(item).strip()][:8]
                    if isinstance(raw_evidence_reasons, (list, tuple))
                    else []
                ),
            }
        run_stream.append(
            "conversation-route-admitted",
            (
                {
                    "schema": "CONVERSATION_ROUTE_DECIDED_V1",
                    "event_type": "conversation.route.decided",
                    "session_id": controls.get("conversation_session_id"),
                    "turn_index": controls.get("conversation_turn_index"),
                    "requested_mode": conversation_route.get("requested_mode"),
                    "resolved_mode": conversation_route.get("resolved_mode"),
                    "source": conversation_route.get("source"),
                    "reasons": reasons,
                    "policy_version": conversation_route.get("policy_version"),
                    "input_hash": conversation_route.get("input_hash"),
                    "confidence": _canonical_route_score(
                        conversation_route.get("confidence"), field_name="confidence"
                    ),
                    "threshold": _canonical_route_score(
                        conversation_route.get("threshold"), field_name="threshold"
                    ),
                    "upgrade_reason": str(conversation_route.get("upgrade_reason") or "")[:640] or None,
                    "initial_fast_decision": initial_fast_decision,
                    "decision_path": conversation_route.get("decision_path"),
                    "provider_text_only": True,
                    "external_mutation_allowed": False,
                },
            ),
            actor="conversation-router",
        )

    def _collect_readonly_workspace_evidence(
        self,
        *,
        cas: Any,
        run_stream: CanonicalStream,
        evidence: Any,
        workspace: Path,
        user_request: str | None = None,
    ) -> Mapping[str, Any]:
        """Collect bounded list/read/search facts before Proposal/Review.

        Read-only MULTI needs useful evidence, but it must not prepare a
        worktree or invoke a shell/write capability merely to answer a
        question.  This small controller-owned stage walks only the bound
        workspace, skips symlinks/sensitive control directories, hashes the
        files it observes, and records goal-term line matches.  The full
        result is sealed in CAS and the Journal carries only its reference and
        the bounded facts used by the next agents.
        """
        raw_root = Path(workspace).expanduser()
        if raw_root.is_symlink():
            raise DynamicCollaborationError("read-only evidence workspace must not be a symlink")
        root = raw_root.resolve(strict=True)
        if not root.is_dir():
            raise DynamicCollaborationError("read-only evidence workspace is not a directory")
        run_id = str(getattr(evidence, "run_id", "") or "")
        if not run_id:
            raise DynamicCollaborationError("read-only evidence requires a run identity")
        skip_dirs = {
            ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
            ".mypy_cache", ".pytest_cache", ".sitina", "secrets", "credentials",
        }
        skip_file_names = {
            ".env", ".env.local", ".env.production", "credentials", "secrets",
            "id_rsa", "id_ed25519", "authorized_keys",
        }
        required_claims = _extract_required_evidence_claims(
            user_request if user_request is not None else str(getattr(evidence, "goal", "") or "")
        )
        workspace_root_hash = sha256_bytes(str(root).encode("utf-8"))
        terms = [
            token.casefold()
            for token in re.findall(r"[A-Za-z0-9_\u3400-\u9fff]{2,}", str(getattr(evidence, "goal", "") or ""))
        ]
        # Preserve order while bounding the search input supplied to the
        # evidence record.  Searching the complete file still records the
        # actual read/search operation; only the displayed match list is
        # bounded.
        terms = list(dict.fromkeys(terms))[:24]
        entries: list[dict[str, Any]] = []
        directories: list[str] = []
        search_hits: list[dict[str, Any]] = []
        generic_excerpts: list[dict[str, Any]] = []
        tool_calls: list[dict[str, Any]] = []
        read_text_by_path: dict[str, str] = {}
        excerpt_bytes = 0
        excerpt_line_budget = 96
        excerpt_byte_budget = 16 * 1024
        max_files = 512
        max_file_bytes = 4 * 1024 * 1024

        # Read-only evidence must use the same permission-enforcing built-in
        # tools as an autonomous agent.  The controller only orchestrates
        # list/read/search calls; it never walks or opens workspace files
        # directly.  Each completed call is journaled and its bounded result
        # is independently sealed in CAS for Proposal/Reviewer consumption.
        from sitina.extensions.manager import ExtensionManager
        from sitina.extensions.tools import ToolCatalog

        catalog = ToolCatalog(
            ExtensionManager(self.home),
            workspace=root,
            write_executor=None,
            strict_workspace=True,
        )
        catalog.bind_run(run_id)

        def invoke_read(tool_name: str, arguments: Mapping[str, Any]) -> Any:
            call_id = f"readonly-{len(tool_calls) + 1:04d}"
            definition = catalog.get(tool_name)
            if definition.permission != "read":
                raise DynamicCollaborationError("read-only evidence selected a non-read tool")
            safe_arguments = {
                key: (str(value) if key in {"path", "pattern", "include"} else value)
                for key, value in dict(arguments).items()
            }
            run_stream.append(
                "readonly-tool-call-intended",
                ({
                    "schema": "TRUE_MULTI_AGENT_READONLY_TOOL_CALL_V1",
                    "event_type": "workspace.readonly.tool-call-intended",
                    "run_id": run_id,
                    "call_id": call_id,
                    "name": tool_name,
                    "permission": "read",
                    "arguments": safe_arguments,
                },),
                actor="readonly-evidence-collector",
            )
            try:
                result = catalog.execute(tool_name, arguments)
            except Exception as error:
                raise DynamicCollaborationError(
                    f"read-only evidence tool {tool_name} failed: {type(error).__name__}"
                ) from error
            if result.status != "ok":
                raise DynamicCollaborationError(f"read-only evidence tool {tool_name} returned {result.status}")
            value = result.value
            bounded_value = value
            if tool_name == "sitina_read_file" and isinstance(value, str):
                bounded_value = value[:max_file_bytes]
            record = {
                "schema": "TRUE_MULTI_AGENT_READONLY_TOOL_RESULT_V1",
                "run_id": run_id,
                "call_id": call_id,
                "name": tool_name,
                "permission": "read",
                "status": result.status,
                "result": bounded_value,
            }
            publication = cas.publish_plaintext(
                canonical_json_bytes(record),
                tenant_id="true-multi-agent",
                purpose_class="readonly-tool-result",
                compression="none",
            )
            result_hash = sha256_bytes(canonical_json_bytes(record))
            run_stream.append(
                "readonly-tool-call-completed",
                ({
                    "schema": "TRUE_MULTI_AGENT_READONLY_TOOL_CALL_V1",
                    "event_type": "workspace.readonly.tool-call-completed",
                    "run_id": run_id,
                    "call_id": call_id,
                    "name": tool_name,
                    "permission": "read",
                    "status": result.status,
                    "result_hash": result_hash,
                    "object_ref": publication.receipt.object_ref.reference_id,
                },),
                actor="readonly-evidence-collector",
                proofs=(publication.receipt,),
            )
            tool_calls.append({
                "call_id": call_id,
                "name": tool_name,
                "permission": "read",
                "status": result.status,
                "arguments": safe_arguments,
                "result_hash": result_hash,
                "object_ref": publication.receipt.object_ref.reference_id,
                "result": bounded_value,
            })
            return value

        pending_dirs = [root]
        seen_dirs: set[str] = set()
        while pending_dirs and len(directories) < 512 and len(entries) < max_files:
            current = pending_dirs.pop(0)
            try:
                current_relative = current.relative_to(root).as_posix() or "."
            except ValueError as error:
                raise DynamicCollaborationError("read-only evidence directory escaped workspace") from error
            if current_relative in seen_dirs or current.name.casefold() in skip_dirs:
                continue
            seen_dirs.add(current_relative)
            directories.append(current_relative)
            listing = invoke_read("sitina_list_directory", {"path": str(current)})
            if not isinstance(listing, list):
                raise DynamicCollaborationError("read-only directory tool returned malformed result")
            for item in listing:
                if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                    continue
                name = str(item["name"])
                if name.casefold() in skip_file_names or name in skip_dirs:
                    continue
                path = current / name
                try:
                    relative = path.relative_to(root).as_posix()
                    stat_result = path.lstat()
                except (OSError, ValueError):
                    continue
                if stat.S_ISLNK(stat_result.st_mode) or stat.S_ISSOCK(stat_result.st_mode):
                    continue
                if stat.S_ISDIR(stat_result.st_mode):
                    if len(directories) + len(pending_dirs) < 512:
                        pending_dirs.append(path)
                    continue
                if not stat.S_ISREG(stat_result.st_mode) or len(entries) >= max_files:
                    continue
                size = int(stat_result.st_size)
                text = ""
                if size <= max_file_bytes:
                    value = invoke_read("sitina_read_file", {"path": str(path)})
                    if not isinstance(value, str):
                        raise DynamicCollaborationError("read-only file tool returned malformed result")
                    text = value
                    read_text_by_path[relative] = text
                # Empty files are still successfully read and must carry the
                # digest of their observed bytes.  ``None`` is reserved for
                # files that were intentionally not read because they exceed
                # the bounded evidence size.
                digest = sha256_bytes(text.encode("utf-8")) if size <= max_file_bytes else None
                entries.append({
                    "path": relative,
                    "size": size,
                    "sha256": digest,
                    "read": size <= max_file_bytes,
                    "searchable": size <= max_file_bytes,
                })
                if text:
                    lines = text.splitlines()
                    matching_lines = [
                        number for number, line in enumerate(lines, start=1)
                        if terms and any(term in line.casefold() for term in terms)
                    ]
                    if not matching_lines and path.suffix == ".py":
                        matching_lines = [1]
                    selected_lines: set[int] = set()
                    for number in matching_lines[:32]:
                        selected_lines.update(range(max(1, number - 1), min(len(lines), number + 1) + 1))
                    for number in sorted(selected_lines):
                        if len(generic_excerpts) >= excerpt_line_budget or excerpt_bytes >= excerpt_byte_budget:
                            break
                        excerpt = redact_text(lines[number - 1])[:512]
                        excerpt_size = len(excerpt.encode("utf-8"))
                        if excerpt_bytes + excerpt_size > excerpt_byte_budget:
                            break
                        generic_excerpts.append({
                            "path": relative,
                            "line": number,
                            "text": excerpt,
                            "text_hash": sha256_bytes(lines[number - 1].encode("utf-8")),
                        })
                        excerpt_bytes += excerpt_size
                    for number in matching_lines:
                        if len(search_hits) >= 128:
                            break
                        search_hits.append({
                            "path": relative,
                            "line": number,
                            "text_hash": sha256_bytes(lines[number - 1].encode("utf-8")),
                        })
        # README is a first-class directed evidence target.  It is read as a
        # text file even though generic evidence search is intentionally
        # limited to source extensions; an explicit marker is searched with
        # exact, case-sensitive semantics and no ``*.py`` filter.
        readme = root / "README.md"
        if readme.is_file() and readme.name not in skip_file_names:
            readme_value = invoke_read("sitina_read_file", {"path": str(readme)})
            if isinstance(readme_value, str):
                read_text_by_path["README.md"] = readme_value
        if "READ_ONLY_MARKER" in str(user_request or ""):
            directed = invoke_read(
                "sitina_grep",
                {
                    "path": str(root), "pattern": re.escape("READ_ONLY_MARKER"),
                    "ignore_case": False, "max_results": 32,
                },
            )
            if isinstance(directed, Mapping):
                for match in list(directed.get("matches") or ()):
                    if not isinstance(match, Mapping):
                        continue
                    try:
                        rel = Path(str(match.get("file") or "")).resolve(strict=False).relative_to(root).as_posix()
                    except ValueError:
                        continue
                    search_hits.append({
                        "path": rel, "line": int(match.get("line") or 0),
                        "text": redact_text(str(match.get("text") or ""))[:512],
                        "text_hash": sha256_bytes(str(match.get("text") or "").encode("utf-8")),
                        "query": "READ_ONLY_MARKER",
                    })
        # Resolve explicit claims with directed reads and exact, case-sensitive
        # searches.  Generic term search below is supplementary only.
        for claim in required_claims:
            claim_path = claim.get("path")
            query = str(claim.get("exact_query") or "")
            matches: list[Mapping[str, Any]] = []
            if isinstance(claim_path, str) and claim_path:
                target = (root / claim_path).resolve(strict=False)
                try:
                    target.relative_to(root)
                except ValueError:
                    claim["status"] = "ambiguous"
                    continue
                if target.is_file() and target.name not in skip_file_names and target.stat().st_size <= max_file_bytes:
                    if claim_path not in read_text_by_path:
                        value = invoke_read("sitina_read_file", {"path": str(target)})
                        if isinstance(value, str):
                            read_text_by_path[claim_path] = value
                    text_value = read_text_by_path.get(claim_path, "")
                    lines = text_value.splitlines()
                    if claim.get("line") is not None:
                        line_no = int(claim["line"])
                        if 1 <= line_no <= len(lines):
                            line_text = lines[line_no - 1]
                            if query == claim_path or query in line_text:
                                matches = [{"file": str(target), "line": line_no, "text": line_text}]
                    elif query == claim_path or query in text_value:
                        line_no = next((i for i, line in enumerate(lines, 1) if query in line), 1)
                        matches = [{"file": str(target), "line": line_no, "text": lines[line_no - 1] if lines else ""}]
                else:
                    claim["status"] = "missing"
            else:
                exact = invoke_read(
                    "sitina_grep",
                    {"path": str(root), "pattern": re.escape(query), "ignore_case": False, "max_results": 128},
                )
                if isinstance(exact, Mapping):
                    matches = [item for item in list(exact.get("matches") or ()) if isinstance(item, Mapping)]
            if len(matches) == 1:
                match = matches[0]
                try:
                    rel = Path(str(match.get("file") or "")).resolve(strict=False).relative_to(root).as_posix()
                except ValueError:
                    claim["status"] = "ambiguous"
                    continue
                claim["path"] = rel
                claim["line"] = int(match.get("line") or claim.get("line") or 0) or None
                matched_text = str(match.get("text") or "")
                observed_value = _readonly_observed_value(query, matched_text)
                if not observed_value:
                    claim["status"] = "missing"
                    continue
                claim["matched_text"] = redact_text(matched_text)[:512]
                claim["matched_text_hash"] = sha256_bytes(matched_text.encode("utf-8"))
                claim["observed_value"] = observed_value
                claim["observed_value_hash"] = sha256_bytes(observed_value.encode("utf-8"))
                claim["required_answer_value"] = observed_value
                claim["required_answer_value_hash"] = claim["observed_value_hash"]
                claim["evidence_hash"] = sha256_bytes(canonical_json_bytes({
                    "claim_id": claim["claim_id"], "path": claim.get("path"),
                    "line": claim.get("line"), "query": query,
                    "matched_text_hash": claim["matched_text_hash"],
                    "observed_value_hash": claim["observed_value_hash"],
                }))
                claim["status"] = "satisfied"
            elif len(matches) == 0 and claim.get("status") not in {"missing", "ambiguous"}:
                claim["status"] = "missing"
            else:
                claim["status"] = "ambiguous"
        required_claims = _canonicalize_readonly_evidence_claims(
            required_claims,
            workspace_root_hash=workspace_root_hash,
        )
        excerpts = list(generic_excerpts)
        for claim in required_claims:
            if claim.get("status") == "satisfied" and claim.get("matched_text"):
                excerpts.append({
                    "path": claim.get("path"), "line": claim.get("line"),
                    "text": claim.get("matched_text"), "text_hash": claim.get("matched_text_hash"),
                    "claim_id": claim.get("claim_id"),
                })

        search_pattern = "|".join(re.escape(term) for term in terms[:8]) or r"TODO|FIXME|error|fail"
        grep_result = invoke_read(
            "sitina_grep",
            {
                "path": str(root),
                "pattern": search_pattern,
                "include": "*.py",
                "ignore_case": True,
                "max_results": 128,
            },
        )
        if not isinstance(grep_result, Mapping):
            raise DynamicCollaborationError("read-only search tool returned malformed result")
        for match in list(grep_result.get("matches") or ())[:128]:
            if not isinstance(match, Mapping) or not isinstance(match.get("file"), str):
                continue
            try:
                relative = Path(str(match["file"])).resolve(strict=False).relative_to(root).as_posix()
            except ValueError:
                continue
            search_hits.append({
                "path": relative,
                "line": int(match.get("line") or 0),
                "text_hash": sha256_bytes(str(match.get("text") or "").encode("utf-8")),
                "text": redact_text(str(match.get("text") or ""))[:512],
            })
        entries.sort(key=lambda item: str(item["path"]))
        directories = sorted(set(directories))[:512]
        payload = {
            "schema": "TRUE_MULTI_AGENT_READONLY_WORKSPACE_EVIDENCE_V1",
            "event_type": "workspace.readonly.evidence.collected",
            "run_id": run_id,
            "workspace_root_hash": workspace_root_hash,
            "scope": "bound-workspace",
            "operations": ["list", "read", "search"],
            "directories": directories,
            "entries": entries,
            "search_terms": terms,
            "search_hits": search_hits,
            "required_evidence_claims": required_claims,
            "excerpts": excerpts,
            "tool_calls": [
                {
                    key: value for key, value in item.items()
                    if key != "result"
                }
                for item in tool_calls
            ],
            "tool_call_count": len(tool_calls),
            "excerpt_line_count": len(excerpts),
            "excerpt_bytes": excerpt_bytes,
            "truncated": len(entries) >= max_files,
            "forge_count": 0,
            "shell_count": 0,
            "write_count": 0,
        }
        publication = cas.publish_plaintext(
            canonical_json_bytes(payload),
            tenant_id="true-multi-agent",
            purpose_class="readonly-workspace-evidence",
            compression="none",
        )
        reference_id = publication.receipt.object_ref.reference_id
        evidence_projection = {
            "schema": payload["schema"],
            "event_type": payload["event_type"],
            "run_id": run_id,
            "workspace_root_hash": payload["workspace_root_hash"],
            "scope": payload["scope"],
            "operations": list(payload["operations"]),
            "directory_count": len(directories),
            "file_count": len(entries),
            "search_hit_count": len(search_hits),
            "entries": entries,
            "search_hits": search_hits,
            "required_evidence_claims": required_claims,
            "excerpts": excerpts,
            "tool_calls": payload["tool_calls"],
            "tool_call_count": payload["tool_call_count"],
            "excerpt_line_count": len(excerpts),
            "excerpt_bytes": excerpt_bytes,
            "forge_count": 0,
            "shell_count": 0,
            "write_count": 0,
            "object_ref": reference_id,
            "object_hash": publication.receipt.object_ref.object_id,
            "content_hash": sha256_bytes(canonical_json_bytes(payload)),
        }
        evidence.readonly_workspace_evidence = dict(evidence_projection)
        run_stream.append(
            "readonly-workspace-evidence-collected",
            ({
                **evidence_projection,
                "_object_refs": [reference_id],
            },),
            actor="readonly-evidence-collector",
            proofs=(publication.receipt,),
        )
        return evidence_projection

    def _interactive_chat_analysis(self, analysis: GoalAnalysis) -> GoalAnalysis:
        """Bind interactive MULTI to the existing live collaboration protocols."""

        return dataclasses.replace(
            analysis,
            complexity="standard",
            risk_level="low",
            protocols=("proposal", "review", "debate", "handoff"),
            task_graph=(
                "interpret the current message and bounded conversation context",
                "produce and independently review candidate answers",
                "negotiate revisions and select a reviewed answer",
                "handoff the selected answer under a verified read-only contract",
            ),
            proposal_count=min(2, int(self.policy["max_proposals_per_round"])),
            domain_capability=None,
            requires_rework=False,
            requires_conflict=False,
            requires_handoff_reject=False,
            requires_reassignment=False,
            requires_provider_unknown=False,
            rationale="interactive MULTI uses live Proposal, Review, Negotiation, and Handoff without external mutation",
        )

    def _code_mode_analysis(self, analysis: GoalAnalysis) -> GoalAnalysis:
        """Keep Code Mode's reviewed tool loop focused on the requested change.

        Interactive conversation normally exercises the full handoff protocol.
        A user-authorized code mutation has a different, explicit contract:
        select a plan, run the Forge tools, test the actual diff, then perform
        the independent post-execution review.  Debate/Handoff remain available
        for ordinary interactive collaboration but must not become an implicit
        precondition for a local file edit.
        """

        return dataclasses.replace(
            analysis,
            complexity="standard",
            risk_level="low",
            protocols=("proposal", "review"),
            task_graph=(
                "interpret the authorized code change",
                "implement it with the selected workspace tools",
                "test and independently review the actual diff",
            ),
            proposal_count=1,
            domain_capability=analysis.domain_capability,
            requires_rework=False,
            requires_conflict=False,
            requires_handoff_reject=False,
            requires_reassignment=False,
            requires_provider_unknown=False,
            rationale="Code Mode uses the reviewed Controller, Planner, Forge, Tester, and Reviewer tool loop",
        )

    def _candidate(
        self,
        identity: AgentIdentity,
        *,
        author_conflicts: set[str],
        exclusions: set[str],
        overrides: Mapping[str, Any],
        evidence: RunEvidence,
    ):
        remove = set(dict(overrides.get("remove_capabilities", {})).get(identity.agent_id, ()))
        add = set(dict(overrides.get("add_capabilities", {})).get(identity.agent_id, ()))
        capabilities = tuple(sorted(set(identity.capabilities).difference(remove).union(add)))
        candidate_identity = dataclasses.replace(identity, capabilities=capabilities)
        budget_filtered = set(overrides.get("budget_filtered_agents", ()))
        safety_filtered = set(overrides.get("safety_filtered_agents", ()))
        lease_filtered = set(overrides.get("lease_filtered_agents", ()))
        loads = dict(overrides.get("agent_loads", {}))
        candidate = candidate_identity.candidate(
            load=int(loads.get(identity.agent_id, sum(1 for item in evidence.calls if item.agent_id == identity.agent_id))),
            eligible=identity.agent_id not in exclusions,
            safety_allowed=identity.agent_id not in safety_filtered,
            budget_allowed=identity.agent_id not in budget_filtered,
            lease_available=identity.agent_id not in lease_filtered,
            independent=identity.agent_id not in author_conflicts,
            policy_allowed=True,
            source_versions={"registry": self.registry.generation, "run_decision": len(evidence.decisions)},
        )
        return candidate_identity, candidate

    def _schedule(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        evidence: RunEvidence,
        *,
        task_id: str,
        required_capabilities: Sequence[str],
        slots: int,
        candidate_tasks: Sequence[str],
        author_conflicts: Sequence[str] = (),
        exclusions: Sequence[str] = (),
        overrides: Mapping[str, Any] | None = None,
        root_executor: ProviderExecutor | None = None,
        defer_root_facts: bool = False,
    ) -> tuple[AgentSchedulingDecision, tuple[AgentIdentity, ...]]:
        override = dict(overrides or {})
        identities: dict[str, AgentIdentity] = {}
        candidates = []
        for item in self.registry.identities:
            identity, candidate = self._candidate(
                item,
                author_conflicts=set(author_conflicts),
                exclusions=set(exclusions),
                overrides=override,
                evidence=evidence,
            )
            identities[identity.agent_id] = identity
            candidates.append(candidate)
        deadline = "2099-01-01T00:00:00Z"
        source_frontier = self._frontier(journal)
        source_ids = self._recent_event_ids(journal)
        decision = self.scheduler.decide(
            task_id,
            candidates,
            required_capabilities=required_capabilities,
            requested_slots=slots,
            source_event_ids=source_ids,
            source_frontier=source_frontier,
            candidate_tasks=candidate_tasks,
            policy_hash=self.policy_hash,
            deadline=deadline,
        )
        root_authorization = (
            root_executor.pre_provider_authorization
            if isinstance(root_executor, ProviderExecutor)
            and isinstance(root_executor.pre_provider_authorization, Mapping)
            else None
        )
        root_phase = (
            "discovery/controller" if task_id == "goal-discovery"
            else "proposal/planner/candidate" if task_id in {"proposal-competition", "proposal"}
            else "review/selection" if task_id in {"independent-review", "review"}
            else None
        )
        if root_authorization is not None and root_phase is not None:
            decision_mapping = decision.mapping()
            root_common = {
                "run_id": evidence.run_id,
                "session_instance_id": root_authorization.get("session_instance_id"),
                "conversation_session_id": root_authorization.get("conversation_session_id"),
                "turn_index": root_authorization.get("turn_index"),
                "generation": root_authorization.get("generation"),
                "run_attempt": root_authorization.get("run_attempt"),
                "decision_id": decision.decision_id,
                "decision_commitment": decision.commitment,
                "task_id": task_id,
                "phase": root_phase,
                "selected_agents": list(decision.selected_attempts),
                "requested_slots": decision.requested_slots,
            }
            scheduling_fact = {
                "schema": "AGENT_SCHEDULING_DECISION_V1",
                "event_type": "scheduling.decision",
                "purpose": "code-mode-agent-scheduling",
                "purpose_class": "code-mode-agent-scheduling-decision",
                **root_common,
                "required_capabilities": list(required_capabilities),
                "decision": decision_mapping,
            }
            dispatch_command_id = "dispatch-" + decision.decision_id
            dispatch_body = {
                **root_common,
                "dispatch_command_id": dispatch_command_id,
                "required_capabilities": list(required_capabilities),
                "policy_hash": self.policy_hash,
                "deadline": deadline,
            }
            dispatch_commitment = stable_hash(
                "CODE_MODE_DISPATCH_COMMAND_ACCEPTED",
                dispatch_body,
            )
            dispatch_fact = {
                "schema": "DISPATCH_COMMAND_ACCEPTED_V1",
                "event_type": "dispatch.command.accepted",
                "purpose": "code-mode-dispatch-command",
                "purpose_class": "code-mode-dispatch-command-accepted",
                **root_common,
                "dispatch_command_id": dispatch_command_id,
                "dispatch_commitment": dispatch_commitment,
                "required_capabilities": list(required_capabilities),
                "state": "ACCEPTED",
            }
            root_schedule_binding = {
                "scheduling_task_id": task_id,
                "phase": root_phase,
                "scheduling_decision_id": decision.decision_id,
                "scheduling_decision_commitment": decision.commitment,
                "dispatch_command_id": dispatch_command_id,
                "dispatch_command_commitment": dispatch_commitment,
                "dispatch_commitment": dispatch_commitment,
                "selected_agents": list(decision.selected_attempts),
                "requested_slots": decision.requested_slots,
            }
            if defer_root_facts:
                if not hasattr(root_executor, "_deferred_root_schedules"):
                    root_executor._deferred_root_schedules = []
                root_executor._deferred_root_schedules.append(
                    (scheduling_fact, dispatch_fact, root_schedule_binding)
                )
            else:
                run_stream.append_root_producer_fact(
                    scheduling_fact,
                    actor="scheduler",
                    producer_role="root_scheduling",
                    command_id="root-scheduling-" + decision.decision_id,
                )
                run_stream.append_root_producer_fact(
                    dispatch_fact,
                    actor="authoritative-dispatcher",
                    producer_role="root_dispatch_acceptance",
                    command_id=dispatch_command_id,
                )
                if not hasattr(root_executor, "_root_schedule_bindings"):
                    root_executor._root_schedule_bindings = []
                root_executor._root_schedule_bindings.append(root_schedule_binding)
        else:
            # Scripted/offline and legacy runs do not have the authenticated
            # pre-provider authority that makes the root FSM facts
            # authoritative.  Preserve their scheduling observation as a
            # non-reserved legacy event; a caller must never smuggle the
            # authority-reserved decision/dispatch schemas through ordinary
            # append merely because no host permit is present.
            run_stream.append(
                "scheduling-observation",
                ({"schema": "AGENT_SCHEDULING_OBSERVATION_V1", "event_type": "scheduling.observed", **decision.mapping()},),
                actor="scheduler",
                source_frontier=source_frontier,
                deadline=deadline,
            )
        selected = tuple(identities[item] for item in decision.selected_attempts)
        if not selected:
            raise DynamicCollaborationError(f"no eligible Agent for {task_id}")
        # Authoritative dispatch revalidates registry, policy, deadline, and the
        # frozen decision commitment after the Scheduler has only discovered candidates.
        if decision.policy_hash != self.policy_hash or self.registry.generation < 1 or now_rfc3339() >= deadline:
            raise DynamicCollaborationError("authoritative Dispatcher revalidation failed")
        if root_authorization is None or root_phase is None:
            run_stream.append(
                "dispatch-observation",
                ({
                    "schema": "DISPATCH_COMMAND_OBSERVATION_V1",
                    "event_type": "dispatch.command.observed",
                    "decision_id": decision.decision_id,
                    "decision_commitment": decision.commitment,
                    "source_frontier": decision.source_frontier.__dict__,
                    "selected_agents": list(decision.selected_attempts),
                    "stream_version_revalidated": True,
                    "admission_generation_revalidated": True,
                    "policy_revalidated": True,
                    "deadline_revalidated": True,
                    "fence_revalidated": True,
                    "protocol_state_revalidated": True,
                    "projection_was_authority": False,
                },),
                actor="authoritative-dispatcher",
            )
        evidence.decisions.append(decision.mapping())
        evidence.selected_agents.update(decision.selected_attempts)
        for scorecard in decision.scorecards:
            if not scorecard.passed:
                evidence.filtered_agents.setdefault(scorecard.agent_id, []).append(scorecard.reason_code)
        return decision, selected

    @staticmethod
    def _flush_deferred_root_schedules(
        run_stream: CanonicalStream, root_executor: ProviderExecutor,
    ) -> None:
        """Publish root scheduling facts at their authenticated FSM boundary.

        A review slot may be selected before proposal calls so its evaluator is
        available to the proposal aggregate, but its authority facts must not
        become visible until every proposal result has been accepted.  Keeping
        the facts deferred in the controller and flushing them here preserves
        that distinction without allowing a caller to skip the proposal state.
        """
        pending = list(getattr(root_executor, "_deferred_root_schedules", ()))
        if not pending:
            return
        if hasattr(root_executor, "_root_schedule_bindings"):
            existing_ids = {
                item.get("scheduling_decision_id")
                for item in root_executor._root_schedule_bindings
                if isinstance(item, Mapping)
            }
        else:
            root_executor._root_schedule_bindings = []
            existing_ids = set()
        for scheduling_fact, dispatch_fact, binding in pending:
            decision_id = binding.get("scheduling_decision_id")
            if decision_id in existing_ids:
                raise DynamicCollaborationError("duplicate deferred root scheduling fact")
            run_stream.append_root_producer_fact(
                scheduling_fact,
                actor="scheduler",
                producer_role="root_scheduling",
                command_id="root-scheduling-" + str(decision_id),
            )
            run_stream.append_root_producer_fact(
                dispatch_fact,
                actor="authoritative-dispatcher",
                producer_role="root_dispatch_acceptance",
                command_id="dispatch-" + str(decision_id),
            )
            root_executor._root_schedule_bindings.append(dict(binding))
            existing_ids.add(decision_id)
        root_executor._deferred_root_schedules = []

    @staticmethod
    def _system_prompt(agent: AgentIdentity, kind: str, contract: str) -> str:
        return (
            f"You are Sitina Agent {agent.agent_id}, role {agent.role}. "
            f"Your immutable capabilities are {', '.join(agent.capabilities)}. "
            f"Return the complete result through the single structured response function "
            f"sitina_structured_response as one JSON object with agent_id exactly '{agent.agent_id}' "
            f"and kind exactly '{kind}'; emit no prose, Markdown, or additional tool calls. "
            f"{contract} Do not speak for another Agent or invent tool actions. Never include real, "
            "example, or placeholder credentials, API keys, access tokens, private keys, passwords, authenticated "
            "URLs, or secret-like strings; describe such concepts only in plain generic words."
        )

    def _call(
        self,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        agent: AgentIdentity,
        *,
        task_id: str,
        kind: str,
        root_phase: str | None = None,
        contract: str,
        prompt: str,
        context: Mapping[str, Any],
        validate,
        ack_lost: bool = False,
    ) -> AgentCallResult:
        output_contract = resolve_output_contract(task_id, kind, allow_legacy_compat=True)
        result = executor.call(
            agent,
            task_id=task_id,
            kind=kind,
            root_phase=root_phase,
            system_prompt=self._system_prompt(agent, kind, contract),
            user_prompt=prompt,
            input_context=context,
            validate=validate,
            ack_lost=ack_lost,
            output_contract_id=output_contract.output_contract_id,
            task_type=output_contract.task_type,
            schema_id=output_contract.schema_id,
        )
        evidence.calls.append(result)
        evidence.called_agents.add(agent.agent_id)
        return result

    def _call_with_bounded_contract_repair(
        self,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        agent: AgentIdentity,
        *,
        task_id: str,
        kind: str,
        root_phase: str | None = None,
        contract: str,
        prompt: str,
        context: Mapping[str, Any],
        validate,
        expected_parent_output_hash: str,
        semantic_retry_budget: int = 1,
    ) -> AgentCallResult:
        """Retry only a rejected parent-binding contract, with an immutable hash.

        The first response is rejected by ProviderExecutor.call before task
        submit/accept and before it can enter evidence.calls. A bounded second
        call is a new provider call with the same immutable parent binding; all
        other contract failures remain fail-closed.
        """

        attempts = 0
        current_prompt = prompt
        while True:
            try:
                return self._call(
                    executor,
                    evidence,
                    agent,
                    task_id=task_id,
                    kind=kind,
                    root_phase=root_phase,
                    contract=contract,
                    prompt=current_prompt,
                    context=context,
                    validate=validate,
                )
            except TrueMultiAgentRuntimeError as error:
                cause = error.__cause__
                if not isinstance(cause, AgentOutputContractRejected):
                    raise
                if cause.reason_code not in {"PARENT_OUTPUT_HASH_MISSING", "PARENT_OUTPUT_HASH_MISMATCH"}:
                    raise
                if attempts >= max(0, int(semantic_retry_budget)):
                    raise
                attempts += 1
                current_prompt = (
                    prompt
                    + "\nYour previous response was rejected before task acceptance for a parent binding error. "
                    + f"Return the exact immutable parent_output_hash value {expected_parent_output_hash!r}; do not normalize, "
                    + "prefix, or reinterpret it."
                )

    def _call_with_bounded_handoff_binding_repair(
        self,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        agent: AgentIdentity,
        *,
        task_id: str,
        kind: str,
        contract: str,
        prompt: str,
        context: Mapping[str, Any],
        validate,
        expected_contract_hash: str,
        expected_generation: int,
        semantic_retry_budget: int = 1,
    ) -> AgentCallResult:
        """Repair only a rejected handoff binding, with immutable expectations.

        A stale/malformed assessment is rejected by ProviderExecutor before
        Task acceptance and before it enters ``evidence.calls``.  The bounded
        retry is a new physical call whose prompt carries the exact frozen
        contract hash and generation; all other assessment failures remain
        fail-closed.
        """

        attempts = 0
        current_prompt = prompt
        binding_errors = {
            "HANDOFF_CONTRACT_HASH_MISSING",
            "HANDOFF_CONTRACT_HASH_MISMATCH",
            "HANDOFF_GENERATION_MISSING",
            "HANDOFF_GENERATION_MISMATCH",
            "HANDOFF_PROJECTION_HASH_MISSING",
            "HANDOFF_PROJECTION_HASH_MISMATCH",
        }
        while True:
            try:
                return self._call(
                    executor,
                    evidence,
                    agent,
                    task_id=task_id,
                    kind=kind,
                    contract=contract,
                    prompt=current_prompt,
                    context=context,
                    validate=validate,
                )
            except TrueMultiAgentRuntimeError as error:
                cause = error.__cause__
                if not isinstance(cause, AgentOutputContractRejected):
                    raise
                if cause.reason_code not in binding_errors:
                    raise
                if attempts >= max(0, int(semantic_retry_budget)):
                    raise
                attempts += 1
                current_prompt = (
                    prompt
                    + "\nYour previous handoff assessment was rejected before Task acceptance for an exact binding error. "
                    + f"Return contract_hash={expected_contract_hash!r} and generation={expected_generation} exactly; "
                    + "do not normalize, stale-copy, prefix, or reinterpret either value."
                )

    def _discover(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> tuple[GoalAnalysis, AgentIdentity, AgentCallResult]:
        _, agents = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="goal-discovery",
            required_capabilities=("goal-analysis",),
            slots=1,
            candidate_tasks=("goal-discovery",),
            overrides=overrides,
            root_executor=executor if isinstance(executor.pre_provider_authorization, Mapping) else None,
        )
        agent = agents[0]

        def validate(value: Mapping[str, Any]) -> None:
            GoalAnalysis.parse(value, self.policy)

        prompt = (
            "Analyze this goal and return fields: agent_id, kind='proposal', complexity(simple|standard|high), "
            "risk_level(low|medium|high), protocols (from proposal, review, debate, rework, handoff, blackboard, arbitration, lease, checkpoint), "
            "task_graph (semantic task names), proposal_count integer 1-3, domain_capability string or null, "
            "requires_rework, requires_conflict, requires_handoff_reject, requires_reassignment, requires_provider_unknown booleans, and rationale. "
            "Choose protocols only when the goal semantics require them; a simple read-only goal should be small. Goal: "
            + evidence.goal
        )
        result = self._call(
            executor,
            evidence,
            agent,
            task_id="goal-discovery",
            kind="proposal",
            root_phase="discovery/controller",
            contract="You discover task structure and protocol needs from the goal and current policy.",
            prompt=prompt,
            context={"goal_hash": evidence.goal_hash, "allowed_protocols": self.policy["allowed_protocols"]},
            validate=validate,
        )
        analysis = GoalAnalysis.parse(result.value, self.policy)
        evidence.analysis = analysis
        run_stream.append(
            "goal-analysis-accepted",
            ({
                "schema": "GOAL_ANALYSIS_ACCEPTED_V1",
                "event_type": "goal.analysis.accepted",
                "agent_id": agent.agent_id,
                "call_id": result.call_id,
                "input_snapshot_hash": result.input_snapshot_hash,
                "output_hash": result.output_hash,
                "analysis": analysis.mapping(),
            },),
            actor="goal-analysis-command-handler",
        )
        return analysis, agent, result

    def _protocol_open(self, evidence: RunEvidence, kind: str, instance_id: str, parent: str, decision_id: str) -> dict[str, Any]:
        value = {
            "protocol_instance": instance_id,
            "protocol_kind": kind,
            "parent_obligation": parent,
            "source_decision": decision_id,
            "generation": 1,
            "terminal_disposition": None,
            "successor_obligation": None,
        }
        evidence.protocol_graph.append(value)
        evidence.obligations[parent] = False
        return {
            "schema": "PROTOCOL_INSTANCE_CREATED_V1",
            "protocol_instance_id": instance_id,
            "protocol_kind": kind,
            "parent_obligation_id": parent,
            "source_decision_id": decision_id,
            "generation": 1,
            "initial_state": "OPEN",
            "allowed_commands_hash": stable_hash("PROTOCOL_ALLOWED_COMMANDS", {"kind": kind}),
            "transition_matrix_hash": stable_hash("PROTOCOL_TRANSITION_MATRIX", {"kind": kind, "major": 1}),
            "timeout_rule": "FAIL_CLOSED",
            "retry_rule": "BOUNDED_POLICY",
            "invalid_transition": "REJECT_AND_RECORD",
        }

    def _protocol_close(
        self,
        evidence: RunEvidence,
        instance_id: str,
        parent: str,
        disposition: str,
        successor: str | None = None,
    ) -> dict[str, Any]:
        for item in evidence.protocol_graph:
            if item["protocol_instance"] == instance_id:
                item["terminal_disposition"] = disposition
                item["successor_obligation"] = successor
                break
        evidence.obligations[parent] = successor is None
        if successor is not None:
            evidence.obligations[successor] = False
        return {
            "schema": "PROTOCOL_INSTANCE_TERMINAL_V1",
            "protocol_instance_id": instance_id,
            "terminal_disposition": disposition,
            "parent_obligation_id": parent,
            "successor_obligation_id": successor,
            "obligation_satisfied": successor is None,
        }

    def _proposal_and_review(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        overrides: Mapping[str, Any],
    ) -> tuple[AgentCallResult, AgentIdentity, list[AgentCallResult], AgentSchedulingDecision]:
        readonly_evidence = getattr(evidence, "readonly_workspace_evidence", None)
        readonly_mode = isinstance(readonly_evidence, Mapping) and bool(
            readonly_evidence.get("required_evidence_claims")
        )
        readonly_claims = tuple(
            item for item in (readonly_evidence.get("required_evidence_claims", ()) if readonly_mode else ())
            if isinstance(item, Mapping)
        )
        satisfied_claims = tuple(item for item in readonly_claims if item.get("status") == "satisfied")
        readonly_context = (
            {"readonly_workspace_evidence": readonly_evidence}
            if isinstance(readonly_evidence, Mapping)
            else {}
        )
        proposal_decision, proposers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="proposal-competition",
            required_capabilities=("proposal",),
            slots=analysis.proposal_count,
            candidate_tasks=analysis.task_graph,
            overrides=overrides,
            root_executor=executor if isinstance(executor.pre_provider_authorization, Mapping) else None,
        )
        reviewer_decision, reviewers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="independent-review",
            required_capabilities=("review", "evaluation", "security-review")
            if analysis.risk_level == "high"
            else ("review", "evaluation"),
            slots=1,
            candidate_tasks=("independent-review",),
            author_conflicts=tuple(item.agent_id for item in proposers),
            overrides=overrides,
            root_executor=executor if isinstance(executor.pre_provider_authorization, Mapping) else None,
            defer_root_facts=isinstance(executor.pre_provider_authorization, Mapping),
        )
        reviewer = reviewers[0]
        rubric = stable_hash(
            "TRUE_MULTI_AGENT_FROZEN_RUBRIC",
            {
                "goal_hash": evidence.goal_hash,
                "criteria": ["correctness", "safety", "evidence", "feasibility"],
                "minimum_score": self.policy["proposal_minimum_score"],
                "policy_hash": self.policy_hash,
            },
        )
        round_id = "proposal-round-" + stable_hash("TRUE_MULTI_AGENT_PROPOSAL_ROUND", {"run": evidence.run_id})[:28]
        proposal, opened = ProposalRound.open(
            round_id,
            generation=1,
            participants=tuple(item.agent_id for item in proposers),
            evaluators=(reviewer.agent_id,),
            rubric_hash=rubric,
            policy_hash=self.policy_hash,
            deadline="2099-01-01T00:00:00Z",
            minimum_score=int(self.policy["proposal_minimum_score"]),
            max_revisions=int(self.policy["max_rework_rounds"]),
        )
        obligation = "obligation-proposal-" + evidence.run_id
        open_fact = self._protocol_open(evidence, "proposal", round_id, obligation, proposal_decision.decision_id)
        proposal_stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/proposal/{round_id}",
            self.policy_hash,
        )
        proposal_stream.append("proposal-round-opened", (open_fact, opened), actor="proposal-command-handler")
        results: list[AgentCallResult] = []
        proposal_ids: dict[str, str] = {}
        for index, agent in enumerate(proposers, 1):
            proposal_id = f"proposal-{index}-{agent.agent_id}"
            proposal_ids[agent.agent_id] = proposal_id

            def validate_proposal(value: Mapping[str, Any]) -> None:
                if readonly_mode:
                    claim_id = value.get("claim_id")
                    claim = next((item for item in satisfied_claims if item.get("claim_id") == claim_id), None)
                    if claim is None or value.get("evidence_hash") != claim.get("evidence_hash"):
                        raise DynamicCollaborationError("readonly proposal claim evidence is not bound")
                    required_value = str(claim.get("required_answer_value") or "")
                    if not required_value or required_value not in str(value.get("answer_fragment") or ""):
                        raise DynamicCollaborationError("readonly proposal omitted the required exact value")
                    return
                for key in ("summary", "approach"):
                    _require_string(value, key)
                for key in ("risks", "assumptions"):
                    _require_text_or_strings(value, key, maximum=8)
                _require_json_array_or_strings(value, "acceptance_checks", maximum=12)

            result = self._call(
                executor,
                evidence,
                agent,
                task_id=(f"readonly-answer-{index}" if readonly_mode else f"proposal-{index}"),
                kind=("readonly_answer" if readonly_mode else "proposal"),
                root_phase="proposal/planner/candidate",
                contract=(
                    "Return claim_id, evidence_hash, and answer_fragment for one satisfied required evidence claim; "
                    "answer_fragment must contain its exact value."
                    if readonly_mode else
                    "Submit an independently reasoned proposal with summary, approach, risks, assumptions, and acceptance_checks. acceptance_checks must be a JSON string array; risks and assumptions may each be a concise string or string array."
                ),
                prompt=(
                    ("Return a reviewed read-only answer grounded only in the required claims. " if readonly_mode else "Create an independent solution for this goal. Do not copy another Agent. ")
                    +
                    f"Goal: {evidence.goal}\nTask graph: {json.dumps(list(analysis.task_graph), ensure_ascii=False)}\n"
                    f"Frozen rubric hash: {rubric}\n"
                    + ("READONLY_CLAIMS_JSON=" + json.dumps(list(readonly_claims), ensure_ascii=False, sort_keys=True) + "\n" if readonly_mode else "")
                    + (
                        "Bounded read-only workspace evidence (bounded facts and excerpts; no execution authorization): "
                        + json.dumps(readonly_evidence, ensure_ascii=False, sort_keys=True)
                        if isinstance(readonly_evidence, Mapping)
                        else ""
                    )
                ),
                context={
                    "goal_hash": evidence.goal_hash,
                    "proposal_round_id": round_id,
                    "proposal_id": proposal_id,
                    "rubric_hash": rubric,
                    "causal_event_ids": list(self._recent_event_ids(journal)),
                    **readonly_context,
                },
                validate=validate_proposal,
                ack_lost=analysis.requires_provider_unknown and index == 1,
            )
            proposal, _, submitted = proposal.submit(proposal_id, agent.agent_id, result.output_ref.removeprefix("cas:"))
            proposal_stream.append(
                "proposal-submitted",
                ({
                    **submitted,
                    "event_type": "proposal.submitted",
                    "call_id": result.call_id,
                    "input_snapshot_hash": result.input_snapshot_hash,
                    "output_hash": result.output_hash,
                    "output_ref": result.output_ref,
                },),
                actor=agent.agent_id,
            )
            results.append(result)
        if isinstance(executor.pre_provider_authorization, Mapping):
            self._flush_deferred_root_schedules(run_stream, executor)
        review_results: list[AgentCallResult] = []
        scores: dict[str, int] = {}
        dispositions: dict[str, str] = {}
        single_rework_required = analysis.requires_rework and _single_rework_required(evidence.goal)
        code_mode_mutation_rework = (
            _code_mode_mutation_rework_authorized(overrides)
            and analysis.risk_level == "low"
            and int(self.policy.get("max_rework_rounds", 0) or 0) >= 1
        )
        for index, (agent, result) in enumerate(zip(proposers, results, strict=True), 1):
            force_changes = analysis.requires_rework and index == 1
            revision_allowed = force_changes or (
                (analysis.requires_rework or "rework" in analysis.protocols)
                and not single_rework_required
            ) or code_mode_mutation_rework

            def validate_review(value: Mapping[str, Any]) -> None:
                verdict = _require_string(value, "verdict").lower()
                if verdict not in {"approved", "changes_requested", "reject"}:
                    raise DynamicCollaborationError("Review verdict is invalid")
                score = value.get("score")
                if not isinstance(score, int) or not 0 <= score <= 100:
                    raise DynamicCollaborationError("Review score is invalid")
                if verdict == "approved" and score < int(self.policy["proposal_minimum_score"]):
                    raise DynamicCollaborationError("approved Review score is below the frozen minimum")
                _require_string(value, "reason")
                _require_strings(value, "defects", minimum=0, maximum=8)
                if readonly_mode:
                    verified = value.get("verified_claim_ids")
                    expected = {str(item.get("claim_id")) for item in satisfied_claims}
                    if not isinstance(verified, list) or set(str(item) for item in verified) != expected:
                        raise DynamicCollaborationError("readonly Reviewer did not verify every required claim")

            instruction = (
                "This goal explicitly requires a real rework path. Identify one specific repairable defect and return verdict changes_requested with score below 70."
                if force_changes
                else "Independently score the exact proposal. Approve only if it meets the frozen rubric; otherwise request changes or reject."
                if revision_allowed
                else "Independently score the exact proposal. No revision cycle is authorized: approve if it meets the frozen rubric, otherwise reject it."
            )
            review = self._call(
                executor,
                evidence,
                reviewer,
                task_id=(f"readonly-review-{index}" if readonly_mode else f"review-{index}"),
                kind=("readonly_review" if readonly_mode else "review"),
                root_phase="review/selection",
                contract=(
                    "Return the standard review fields plus verified_claim_ids containing every satisfied required claim id. "
                    if readonly_mode else ""
                ) + (
                    "Return verdict, integer score on a 0-100 scale, reason, and defects. verdict MUST be exactly "
                    "one of: approved, changes_requested, reject. defects MUST be a JSON array containing only "
                    "zero to eight short strings (use [] when there are no defects and combine related concerns rather "
                    "than returning more than eight). approved requires score at least 70. Bind "
                    "the exact proposal hash and frozen rubric."
                ),
                prompt=(
                    instruction
                    + "\nThe verdict JSON string must be exactly approved, changes_requested, or reject; do not use synonyms. Score is an integer 0-100, never a string and never 0-10; approved requires 70 or higher. defects is an array of zero to eight strings only, never objects; combine related concerns to stay within eight."
                    + f"\nGoal: {evidence.goal}\nProposal hash: {result.output_hash}\nProposal: "
                    + json.dumps(dict(result.value), ensure_ascii=False, sort_keys=True)
                    + f"\nFrozen rubric hash: {rubric}"
                    + ("\nREADONLY_CLAIMS_JSON=" + json.dumps(list(readonly_claims), ensure_ascii=False, sort_keys=True) if readonly_mode else "")
                    + (
                        "\nBounded read-only workspace evidence (bounded facts and excerpts; no execution authorization): "
                        + json.dumps(readonly_evidence, ensure_ascii=False, sort_keys=True)
                        if isinstance(readonly_evidence, Mapping)
                        else ""
                    )
                ),
                context={
                    "proposal_id": proposal_ids[agent.agent_id],
                    "proposal_output_hash": result.output_hash,
                    "proposal_output_ref": result.output_ref,
                    "rubric_hash": rubric,
                    "author_agent_id": agent.agent_id,
                    "reviewer_independence": True,
                    **readonly_context,
                },
                validate=validate_review,
            )
            provider_verdict = str(review.value["verdict"]).lower()
            verdict = provider_verdict
            score = int(review.value["score"])
            if force_changes and (verdict != "changes_requested" or score >= int(self.policy["proposal_minimum_score"])):
                raise DynamicCollaborationError("independent Reviewer failed to create the required rework path")
            review_defects = list(_require_strings(review.value, "defects", minimum=0, maximum=8))
            promoted_rejection = (
                provider_verdict == "reject"
                and code_mode_mutation_rework
                and _repairable_review_rejection(
                    review.value,
                    score=score,
                    minimum_score=int(self.policy["proposal_minimum_score"]),
                )
            )
            if promoted_rejection:
                # A reject is never treated as acceptance.  For a low-risk,
                # explicitly authorized mutation only, a non-hard reject with
                # concrete defects enters the existing single revision path.
                verdict = "changes_requested"
            revision_denied_by_goal = verdict == "changes_requested" and not revision_allowed
            if revision_denied_by_goal:
                verdict = "reject"
            disposition = {
                "approved": "ACCEPT",
                "changes_requested": "NEEDS_REVISION",
                "reject": "REJECT",
            }[verdict]
            proposal, evaluated = proposal.evaluate(
                proposal_ids[agent.agent_id], reviewer.agent_id, score=score, disposition=disposition
            )
            review_request, requested = ReviewRequest.open(
                "review-request-" + stable_hash("TRUE_MULTI_AGENT_REVIEW_ID", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id], "revision": 1})[:28],
                result.output_ref.removeprefix("cas:"),
                agent.agent_id,
                rubric,
                quorum=1,
                high_risk=analysis.risk_level == "high",
                security_review_required=analysis.risk_level == "high",
            )
            reviewer_capabilities = tuple(reviewer.capabilities)
            review_request, response = review_request.respond(
                reviewer.agent_id,
                reviewer_capabilities,
                False,
                {"approved": ReviewVerdict.ACCEPT, "changes_requested": ReviewVerdict.NEEDS_CHANGES, "reject": ReviewVerdict.REJECT}[verdict],
                review.output_ref.removeprefix("cas:"),
            )
            review_request, review_disposition = review_request.dispose()
            proposal_stream.append(
                "proposal-reviewed",
                (
                    {**requested, "event_type": "review.requested", "proposal_id": proposal_ids[agent.agent_id], "proposal_output_hash": result.output_hash},
                    {
                        **response,
                        "event_type": "review.response",
                        "review_call_id": review.call_id,
                        "review_output_hash": review.output_hash,
                        "provider_verdict": provider_verdict,
                        "effective_verdict": verdict,
                    },
                    {
                        **review_disposition,
                        "event_type": "review.disposition",
                        "revision_allowed": revision_allowed,
                        "revision_denied_by_goal": revision_denied_by_goal,
                        "single_rework_required": single_rework_required,
                        "reject_promoted_to_rework": promoted_rejection,
                        "code_mode_mutation_rework": code_mode_mutation_rework,
                        "risk_level": analysis.risk_level,
                        "revision_budget": 1 if code_mode_mutation_rework else 0,
                        # Persist the exact first-review defect list so the
                        # authority host can bind the one revision to the
                        # review that opened NEEDS_REVISION.  Hashes alone
                        # are insufficient when a caller supplies a
                        # different but similarly shaped correction.
                        "frozen_defects": review_defects,
                    },
                    {**evaluated, "event_type": "proposal.evaluated", "frozen_rubric_hash": rubric},
                ),
                actor=reviewer.agent_id,
            )
            review_results.append(review)
            scores[proposal_ids[agent.agent_id]] = score
            dispositions[proposal_ids[agent.agent_id]] = disposition
            if disposition == "NEEDS_REVISION":
                frozen_defects = tuple(review_defects)
                rework_id = "rework-" + stable_hash("TRUE_MULTI_AGENT_REWORK", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id]})[:28]
                rework_obligation = "obligation-" + rework_id
                rework_open_fact = self._protocol_open(evidence, "rework", rework_id, rework_obligation, reviewer_decision.decision_id)
                rework, rework_opened = Rework.open(
                    rework_id,
                    f"proposal-revision-{index}",
                    FailureType.REVIEW_REJECTED,
                    rubric,
                    max_retries=int(self.policy["max_rework_rounds"]),
                )
                rework, rework_started = rework.begin_round(f"revision-attempt-{index}-1")

                def validate_revision(value: Mapping[str, Any]) -> None:
                    _require_exact_parent_output_hash(value, result.output_hash)
                    _require_defect_responses(value, frozen_defects, maximum=8)
                    if "summary" in value:
                        _require_string(value, "summary")
                    if "approach" in value:
                        _require_string(value, "approach")
                    if "acceptance_checks" in value:
                        _require_json_array_or_strings(value, "acceptance_checks", maximum=8)

                revision = self._call_with_bounded_contract_repair(
                    executor,
                    evidence,
                    agent,
                    task_id=f"proposal-revision-{index}",
                    kind="proposal",
                    root_phase="proposal/planner/candidate",
                    contract=(
                        "Revise the immutable parent. Required fields are exact parent_output_hash and one "
                        "defect_response per Review defect; each response may be a concise string or an object with "
                        "defect and response strings. summary, approach, and acceptance_checks are optional additions. "
                        "If acceptance_checks is present, it must be a JSON array of at most eight strings only; encode "
                        "each condition and its named evidence together in one string, never as an object."
                    ),
                    prompt=(
                        f"Revise your exact parent proposal. Parent output hash: {result.output_hash}. "
                        f"Review output hash: {review.output_hash}. Defects: {json.dumps(review.value.get('defects', []), ensure_ascii=False)}. "
                        "Return a new proposal object; never overwrite the parent. If you include acceptance_checks, "
                        "return only strings such as 'Condition — Evidence: named item'; do not return objects."
                    ),
                    context={
                        "parent_proposal_id": proposal_ids[agent.agent_id],
                        "parent_output_hash": result.output_hash,
                        "parent_output_ref": result.output_ref,
                        "review_id": review_request.review_id,
                        "review_output_hash": review.output_hash,
                        **readonly_context,
                    },
                    validate=validate_revision,
                    expected_parent_output_hash=result.output_hash,
                )
                if revision.output_hash == result.output_hash:
                    raise DynamicCollaborationError("Rework revision did not create a new output hash")
                defect_responses = _require_defect_responses(revision.value, frozen_defects, maximum=8)
                defect_resolution_hash = stable_hash(
                    "TRUE_MULTI_AGENT_REWORK_DEFECT_RESOLUTION",
                    {
                        "review_output_hash": review.output_hash,
                        "parent_output_hash": result.output_hash,
                        "defects": list(frozen_defects),
                        "responses": defect_responses,
                    },
                )
                proposal, revised, revised_fact = proposal.revise(
                    proposal_ids[agent.agent_id], revision.output_ref.removeprefix("cas:")
                )

                def validate_second_review(value: Mapping[str, Any]) -> None:
                    if _require_string(value, "verdict").lower() != "approved":
                        raise DynamicCollaborationError("second Review did not approve repaired revision")
                    score_value = value.get("score")
                    if not isinstance(score_value, int) or score_value < int(self.policy["proposal_minimum_score"]):
                        raise DynamicCollaborationError("second Review score is below threshold")
                    _require_string(value, "reason")
                    _require_strings(value, "defects", minimum=0, maximum=8)

                second_review = self._call(
                    executor,
                    evidence,
                    reviewer,
                    task_id=f"review-revision-{index}",
                    kind="review",
                    root_phase="review/selection",
                    contract="Re-review the exact new revision. In addition to the required agent_id and kind envelope, return verdict as the string approved, score as an integer 70-100, reason as a non-empty string, and defects as a JSON string array (empty when none). Do not return an approved boolean or comments field.",
                    prompt=(
                        f"Re-review revision hash {revision.output_hash}, parent {result.output_hash}. "
                        f"Prior defects: {json.dumps(review.value.get('defects', []), ensure_ascii=False)}. "
                        f"Required shape example: {{\"agent_id\":\"{reviewer.agent_id}\",\"kind\":\"review\","
                        "\"verdict\":\"approved\",\"score\":85,\"reason\":\"...\",\"defects\":[]}. Revision: "
                        + json.dumps(dict(revision.value), ensure_ascii=False, sort_keys=True)
                    ),
                    context={
                        "revision_output_hash": revision.output_hash,
                        "parent_output_hash": result.output_hash,
                        "prior_review_output_hash": review.output_hash,
                        "old_approval_applicable": False,
                        **readonly_context,
                    },
                    validate=validate_second_review,
                )
                score2 = int(second_review.value["score"])
                review2, requested2 = ReviewRequest.open(
                    "review-request-" + stable_hash("TRUE_MULTI_AGENT_REVIEW_ID", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id], "revision": 2})[:28],
                    revision.output_ref.removeprefix("cas:"),
                    agent.agent_id,
                    rubric,
                    quorum=1,
                    high_risk=analysis.risk_level == "high",
                    security_review_required=analysis.risk_level == "high",
                )
                review2, response2 = review2.respond(
                    reviewer.agent_id,
                    tuple(reviewer.capabilities),
                    False,
                    ReviewVerdict.ACCEPT,
                    second_review.output_ref.removeprefix("cas:"),
                )
                review2, disposition2 = review2.dispose()
                rework, rework_completed = rework.complete_round(
                    revision.output_ref.removeprefix("cas:"), accepted=True
                )
                proposal, evaluated2 = proposal.evaluate(
                    proposal_ids[agent.agent_id], reviewer.agent_id, score=score2, disposition="ACCEPT"
                )
                close_rework = self._protocol_close(evidence, rework_id, rework_obligation, "SATISFIED")
                proposal_stream.append(
                    "proposal-rework-completed",
                    (
                        rework_open_fact,
                        rework_opened,
                        rework_started,
                        {
                            **revised_fact,
                            "event_type": "proposal.revised",
                            "parent_output_hash": result.output_hash,
                            "new_output_hash": revision.output_hash,
                            "revision_call_id": revision.call_id,
                            "rework_id": rework_id,
                            "review_id": review_request.review_id,
                            "review_output_hash": review.output_hash,
                            "reviewer_id": reviewer.agent_id,
                            "frozen_defects": list(frozen_defects),
                            "defect_response_count": len(defect_responses),
                            "all_defects_addressed": True,
                            "defect_resolution_hash": defect_resolution_hash,
                            "old_review_reused": False,
                        },
                        rework_completed,
                        {
                            **requested2,
                            "event_type": "review.requested",
                            "proposal_id": proposal_ids[agent.agent_id],
                            "proposal_output_hash": revision.output_hash,
                            "revision": 2,
                        },
                        {
                            **response2,
                            "event_type": "review.response",
                            "proposal_id": proposal_ids[agent.agent_id],
                            "proposal_output_hash": revision.output_hash,
                            "review_call_id": second_review.call_id,
                            "review_output_hash": second_review.output_hash,
                            "provider_verdict": str(second_review.value["verdict"]).lower(),
                            "effective_verdict": "approved",
                            "revision": 2,
                        },
                        {
                            **disposition2,
                            "event_type": "review.disposition",
                            "proposal_id": proposal_ids[agent.agent_id],
                            "proposal_output_hash": revision.output_hash,
                            "revision": 2,
                            "revision_allowed": True,
                            "revision_budget": 1,
                            "frozen_defects": list(frozen_defects),
                        },
                        evaluated2,
                        close_rework,
                    ),
                    actor=reviewer.agent_id,
                )
                results[index - 1] = revision
                review_results.append(second_review)
                scores[proposal_ids[agent.agent_id]] = score2
                dispositions[proposal_ids[agent.agent_id]] = "ACCEPT"

        negotiation_finalization: Mapping[str, Any] | None = None
        if "debate" in analysis.protocols and len(results) >= 2:
            proposal, results, debate_scores, debate_dispositions, debate_reviews, negotiation_finalization = self._debate(
                journal,
                run_stream,
                executor,
                evidence,
                proposal_stream,
                proposal,
                proposers,
                results,
                review_results,
                reviewer,
                rubric,
                proposal_decision,
                analysis.risk_level,
                overrides,
            )
            scores.update(debate_scores)
            dispositions.update(debate_dispositions)
            review_results.extend(debate_reviews)

        eligible = [
            item
            for item in proposal.proposals
            if item.state is ProposalState.ACTIVE and dispositions.get(item.proposal_id) == "ACCEPT"
        ]
        if not eligible:
            no_selection = proposal.no_selection(
                "ARBITRATION" if "arbitration" in analysis.protocols else "CANCEL",
                expected_version=proposal.version,
            )[1]
            proposal_stream.append("proposal-no-selection", (no_selection,), actor="selection-command-handler")
            raise DynamicCollaborationError("ProposalRound reached NoSelection")
        selected_proposal = max(eligible, key=lambda item: (scores.get(item.proposal_id, 0), item.proposal_id))
        proposal, selected_fact = proposal.select(selected_proposal.proposal_id, expected_version=proposal.version)
        winner_agent = next(item for item in proposers if proposal_ids[item.agent_id] == selected_proposal.proposal_id)
        winner_result = results[list(proposers).index(winner_agent)]
        close_fact = self._protocol_close(evidence, round_id, obligation, "SELECTED")
        proposal_stream.append(
            "proposal-selected",
            (
                *(
                    ({
                        "schema": "NEGOTIATION_SELECTION_DECIDED_V1",
                        "decision_id": "negotiation-selection-" + stable_hash(
                            "TRUE_MULTI_AGENT_NEGOTIATION_SELECTION",
                            {
                                "run_id": evidence.run_id,
                                "round_id": proposal.round_id,
                                "generation": proposal.generation,
                                "selected_proposal_id": selected_proposal.proposal_id,
                                "selected_output_hash": winner_result.output_hash,
                                "synthesis_candidate_hash": negotiation_finalization["synthesis_candidate_hash"],
                                "fresh_review_hashes": negotiation_finalization["fresh_review_hashes"],
                            },
                        )[:40],
                        "round_id": proposal.round_id,
                        "generation": proposal.generation,
                        "selected_proposal_id": selected_proposal.proposal_id,
                        "latest_revision_hash": winner_result.output_hash,
                        "synthesis_candidate_hash": negotiation_finalization["synthesis_candidate_hash"],
                        "synthesis_hash": negotiation_finalization["synthesis_hash"],
                        "fresh_review_ids": list(negotiation_finalization["fresh_review_ids"]),
                        "fresh_review_hashes": list(negotiation_finalization["fresh_review_hashes"]),
                        "old_review_reused": False,
                        "decision": "SELECTED",
                    },)
                    if negotiation_finalization is not None
                    else ()
                ),
                {
                    **selected_fact,
                    "event_type": "proposal.selected",
                    "run_id": evidence.run_id,
                    "authority_generation": str(
                        (executor.pre_provider_authorization or {}).get("generation", "")
                    ),
                    "session_instance_id": str(
                        getattr(executor.context, "session_instance_id", "") or ""
                    ),
                    "conversation_session_id": str(
                        (executor.pre_provider_authorization or {}).get(
                            "conversation_session_id", ""
                        )
                    ),
                    "turn_index": int(
                        (executor.pre_provider_authorization or {}).get("turn_index", 0)
                    ),
                    "selected_agent_id": winner_agent.agent_id,
                    "selected_output_hash": winner_result.output_hash,
                    "selected_output_ref": winner_result.output_ref,
                    "scorecard_refs": [item.call_id for item in review_results],
                    "frozen_rubric_hash": rubric,
                    "rejected_proposals_ineligible": True,
                    "negotiation_synthesis_hash": (
                        negotiation_finalization["synthesis_hash"]
                        if negotiation_finalization is not None
                        else None
                    ),
                    "fresh_review_hashes": (
                        list(negotiation_finalization["fresh_review_hashes"])
                        if negotiation_finalization is not None
                        else []
                    ),
                },
                close_fact,
            ),
            actor="selection-command-handler",
        )
        # Root planning facts are required only on the authoritative physical
        # transport path.  Scripted/offline execution deliberately has no
        # launcher-issued pre-provider authorization and must not manufacture
        # an authenticated root FSM record merely to satisfy a test fixture.
        if isinstance(executor.pre_provider_authorization, Mapping):
            root_binding = executor.transport.call_bindings.get(winner_result.effect_id, {})
            if not isinstance(root_binding, Mapping) or not root_binding.get("pre_provider_call_identity"):
                raise DynamicCollaborationError("selected proposal has no authenticated root call binding")
            run_stream.append_root_producer_fact(
                {
                    "schema": "CODE_MODE_ROOT_SELECTION_FACT_V1",
                    "event_type": "code-mode.root-selection-committed",
                    "purpose": "code-mode-root-selection",
                    "purpose_class": "code-mode-root-selection",
                    "run_id": evidence.run_id,
                    "session_instance_id": str((executor.pre_provider_authorization or {}).get("session_instance_id") or ""),
                    "conversation_session_id": str((executor.pre_provider_authorization or {}).get("conversation_session_id") or ""),
                    "turn_index": int((executor.pre_provider_authorization or {}).get("turn_index") or 0),
                    "generation": str((executor.pre_provider_authorization or {}).get("generation") or ""),
                    "run_attempt": int((executor.pre_provider_authorization or {}).get("run_attempt") or 0),
                    "selected_agent_id": winner_agent.agent_id,
                    "selected_agent_role": winner_agent.role,
                    "selected_agent_capabilities": list(winner_agent.capabilities),
                    "selected_task_id": str(root_binding.get("task_id") or winner_result.task_id),
                    "selected_output_hash": winner_result.output_hash,
                    "selected_output_ref": winner_result.output_ref,
                    "selected_provider_call_id": winner_result.effect_id,
                    "selected_dispatch_commitment": str(root_binding.get("dispatch_commitment") or ""),
                },
                actor="selection-command-handler",
                producer_role="root_selection",
                command_id="root-selection-" + evidence.run_id,
            )
        if readonly_mode:
            required = {str(item.get("claim_id")) for item in satisfied_claims}
            if not required or len(satisfied_claims) != len(readonly_claims):
                raise DynamicCollaborationError("required read-only evidence claims are missing or ambiguous")
            verified = set()
            if review_results:
                raw_verified = review_results[-1].value.get("verified_claim_ids")
                if isinstance(raw_verified, list):
                    verified = {str(item) for item in raw_verified}
            answer = str(winner_result.value.get("answer_fragment") or "")
            if verified != required or any(
                not str(item.get("required_answer_value") or "")
                or str(item.get("required_answer_value")) not in answer
                for item in satisfied_claims
            ):
                raise DynamicCollaborationError("read-only answer evidence closure is incomplete")
        return winner_result, winner_agent, results, proposal_decision

    def _debate(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        proposal_stream: CanonicalStream,
        proposal: ProposalRound,
        proposers: Sequence[AgentIdentity],
        results: Sequence[AgentCallResult],
        prior_reviews: Sequence[AgentCallResult],
        reviewer: AgentIdentity,
        rubric: str,
        source_decision: AgentSchedulingDecision,
        risk_level: str,
        overrides: Mapping[str, Any],
    ) -> tuple[
        ProposalRound,
        list[AgentCallResult],
        dict[str, int],
        dict[str, str],
        list[AgentCallResult],
        Mapping[str, Any],
    ]:
        debate_id = "debate-" + stable_hash("TRUE_MULTI_AGENT_DEBATE", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + debate_id
        open_fact = self._protocol_open(evidence, "debate", debate_id, obligation, source_decision.decision_id)
        debate, debate_opened = Debate.open(
            debate_id,
            proposal.round_id,
            max_rounds=int(self.policy["max_negotiation_rounds"]),
            max_tokens=int(self.policy["max_total_tokens_per_run"]),
            deadline="2099-01-01T00:00:00Z",
        )
        claims = ClaimRegistry()
        claim_ids: list[str] = []
        claim_facts: list[dict[str, Any]] = []
        for index, result in enumerate(results, 1):
            claim_id = f"claim-{index}-{proposers[index - 1].agent_id}"
            claims, _, fact = claims.create(
                claim_id,
                proposal.round_id,
                result.output_ref.removeprefix("cas:"),
                (result.output_hash,),
            )
            claim_ids.append(claim_id)
            claim_facts.append(fact)
        critique_results: list[AgentCallResult] = []
        critique_facts: list[dict[str, Any]] = []
        for index, parent in enumerate(results, 1):
            candidates = [
                item
                for item in prior_reviews
                if item.task_id in {f"review-{index}", f"review-revision-{index}"}
            ]
            if not candidates:
                raise DynamicCollaborationError("Negotiation lacks a committed prior Review critique")
            critique = candidates[-1]
            critique_results.append(critique)
            critique_facts.append({
                "schema": "NEGOTIATION_CRITIQUE_SUBMITTED_V1",
                "debate_id": debate_id,
                "round_id": proposal.round_id,
                "generation": proposal.generation,
                "proposal_id": f"proposal-{index}-{proposers[index - 1].agent_id}",
                "proposal_output_hash": parent.output_hash,
                "critique_call_id": critique.call_id,
                "critique_output_hash": critique.output_hash,
                "critique_output_ref": critique.output_ref,
                "critic_agent_id": critique.agent_id,
                "source_event_ids": list(self._recent_event_ids(journal)),
            })
        _, opening_refs = proposal_stream.append(
            "debate-opened",
            (
                open_fact,
                debate_opened,
                {
                    **debate_opened,
                    "schema": "NEGOTIATION_ROUND_OPENED_V1",
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "participants": [item.agent_id for item in proposers],
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "rubric_hash": rubric,
                    "policy_hash": self.policy_hash,
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                *claim_facts,
                *critique_facts,
            ),
            actor="debate-command-handler",
        )
        critique_event_refs = opening_refs[-len(critique_facts):]
        revised_results: list[AgentCallResult] = []
        response_facts: list[dict[str, Any]] = []
        for index, (agent, parent) in enumerate(zip(proposers, results, strict=True)):
            target = results[(index + 1) % len(results)]
            critique = critique_results[index]
            _, request_refs = proposal_stream.append(
                "negotiation-clarification-and-revision-requested",
                ({
                    "schema": "NEGOTIATION_CLARIFICATION_REQUESTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "request_id": f"clarification-{index + 1}-{agent.agent_id}",
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                }, {
                    "schema": "NEGOTIATION_REVISION_REQUESTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "request_id": f"revision-request-{index + 1}-{agent.agent_id}",
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "parent_output_hash": parent.output_hash,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                    "maximum_revision": int(self.policy["max_rework_rounds"]),
                }),
                actor="negotiation-command-handler",
            )

            def validate_revision(value: Mapping[str, Any]) -> None:
                _require_string(value, "summary")
                _require_exact_parent_output_hash(value, parent.output_hash)
                _require_response_items(value, "responses_to_objections", maximum=8)
                _require_json_array_or_strings(value, "acceptance_checks", maximum=8)

            revised = self._call_with_bounded_contract_repair(
                executor,
                evidence,
                agent,
                task_id=f"negotiation-round-2-{index + 1}",
                kind="proposal",
                contract=(
                    "Submit a concise second-round revision with summary, exact parent_output_hash, "
                    "responses_to_objections as exactly four short JSON strings, and acceptance_checks as exactly four "
                    "short JSON strings. Combine related objections and requirements inside those four strings; never "
                    "return more than four items in either array and never return objects."
                ),
                prompt=(
                    f"Round 2. Your parent output hash is {parent.output_hash}. Peer output hash is {target.output_hash}. "
                    f"The independent critique hash is {critique.output_hash}. Critique: "
                    + json.dumps(dict(critique.value), ensure_ascii=False, sort_keys=True)
                    + ". Respond to concrete differences and every critique defect concisely. Return every required "
                    "field; responses_to_objections and acceptance_checks each contain exactly four short strings, "
                    "never objects. Consolidate all requirements into those four checks rather than listing one check "
                    "per goal clause. "
                    "Peer proposal: " + json.dumps(dict(target.value), ensure_ascii=False, sort_keys=True)
                ),
                context={
                    "debate_id": debate_id,
                    "round": 2,
                    "parent_output_hash": parent.output_hash,
                    "parent_output_ref": parent.output_ref,
                    "target_output_hash": target.output_hash,
                    "target_output_ref": target.output_ref,
                    "critique_event_id": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                    "critique_output_ref": critique.output_ref,
                    "clarification_request_event_id": request_refs[0]["event_id"],
                    "revision_request_event_id": request_refs[1]["event_id"],
                    "source_event_ids": list(self._recent_event_ids(journal)),
                },
                validate=validate_revision,
                expected_parent_output_hash=parent.output_hash,
            )
            if revised.output_hash == parent.output_hash:
                raise DynamicCollaborationError("negotiation round 2 reused the round 1 output hash")
            debate, _, response = debate.respond(
                claims,
                f"debate-response-{index + 1}",
                claim_ids[index],
                claim_ids[(index + 1) % len(claim_ids)],
                agent.agent_id,
                2,
                int(revised.usage["total_tokens"]),
                revised.output_ref.removeprefix("cas:"),
                now=now_rfc3339(),
            )
            response_facts.append(
                {
                    **response,
                    "event_type": "debate.response",
                    "parent_output_hash": parent.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_call_id": revised.call_id,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                }
            )
            transition_hash = stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_TRANSITION",
                {
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_output_hash": critique.output_hash,
                    "revision_output_hash": revised.output_hash,
                },
            )
            if revised.output_hash in {item.output_hash for item in revised_results}:
                raise DynamicCollaborationError("negotiation stalled on a duplicate revision output hash")
            proposal_stream.append(
                "negotiation-peer-response-and-revision-submitted",
                ({
                    "schema": "NEGOTIATION_PEER_RESPONSE_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "response_id": f"peer-response-{index + 1}-{agent.agent_id}",
                    "actor_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_output_hash": critique.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_output_ref": revised.output_ref,
                    "transition_hash": transition_hash,
                }, {
                    "schema": "NEGOTIATION_CLARIFICATION_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "request_event_ref": request_refs[0]["event_id"],
                    "actor_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "clarification_output_hash": revised.output_hash,
                }, {
                    "schema": "NEGOTIATION_PROPOSAL_REVISION_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "revision": 1,
                    "revision_author_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_output_ref": revised.output_ref,
                    "body_ref": revised.output_ref.removeprefix("cas:"),
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "old_review_reused": False,
                    "transition_hash": transition_hash,
                }),
                actor=agent.agent_id,
            )
            revised_results.append(revised)
        evidence_map = {
            claim_id: (results[index].output_hash, revised_results[index].output_hash)
            for index, claim_id in enumerate(claim_ids)
        }
        negotiation_response_facts = tuple(response_facts)
        next_round, generation_opened = proposal.new_generation(
            participants=tuple(item.agent_id for item in proposers),
            evaluators=(reviewer.agent_id,),
            rubric_hash=rubric,
            policy_hash=self.policy_hash,
            deadline="2099-01-01T00:00:00Z",
            minimum_score=int(self.policy["proposal_minimum_score"]),
            max_revisions=int(self.policy["max_rework_rounds"]),
        )
        proposal_ids: list[str] = []
        round_two_submission_facts: list[dict[str, Any]] = []
        for index, (agent, revised) in enumerate(zip(proposers, revised_results, strict=True), 1):
            proposal_id = f"proposal-{index}-{agent.agent_id}"
            proposal_ids.append(proposal_id)
            next_round, _, submitted = next_round.submit(
                proposal_id,
                agent.agent_id,
                revised.output_ref.removeprefix("cas:"),
            )
            round_two_submission_facts.append(
                {
                    **submitted,
                    "event_type": "proposal.round-2.submitted",
                    "parent_generation": proposal.generation,
                    "parent_output_hash": results[index - 1].output_hash,
                    "revision_output_hash": revised.output_hash,
                    "old_review_reused": False,
                }
            )
        synthesizer_id = "debate-synthesis-command-handler"
        debate, synthesis_submitted = debate.submit_synthesis(
            claims,
            evidence_map=evidence_map,
            synthesizer_id=synthesizer_id,
        )
        proposal_stream.append(
            "negotiation-generation-2-and-synthesis-submitted",
            (
                *negotiation_response_facts,
                {
                    **generation_opened,
                    "event_type": "negotiation.round.opened",
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                {
                    "schema": "NEGOTIATION_ROUND_OPENED_V1",
                    "debate_id": debate_id,
                    "target_id": next_round.round_id,
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "participants": [item.agent_id for item in proposers],
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "rubric_hash": rubric,
                    "policy_hash": self.policy_hash,
                    "deadline": next_round.deadline,
                    "max_rounds": int(self.policy["max_negotiation_rounds"]),
                    "max_tokens": int(self.policy["max_total_tokens_per_run"]),
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                *round_two_submission_facts,
                synthesis_submitted,
            ),
            actor=synthesizer_id,
        )
        scores: dict[str, int] = {}
        dispositions: dict[str, str] = {}
        reviews: list[AgentCallResult] = []
        fresh_review_ids: list[str] = []
        fresh_review_hashes: list[str] = []
        authors = {item.agent_id for item in proposers}
        if reviewer.agent_id in authors or reviewer.agent_id == synthesizer_id:
            raise DynamicCollaborationError("fresh Reviewer is not independent of author and synthesizer")
        normalized_goal = evidence.goal.casefold()
        semantic_no_consensus_required = any(
            marker in normalized_goal
            for marker in (
                "do not select a compromise",
                "must not select a compromise",
                "formal no consensus",
                "create a successor obligation if unresolved",
                "不可选择折中方案",
                "正式无共识",
            )
        )
        for index, revised in enumerate(revised_results):
            author = proposers[index]
            fresh_review_id = "fresh-review-" + stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_FRESH_REVIEW",
                {
                    "run_id": evidence.run_id,
                    "debate_id": debate_id,
                    "proposal_id": proposal_ids[index],
                    "revision_output_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                },
            )[:36]
            fresh_review, fresh_requested = ReviewRequest.open(
                fresh_review_id,
                revised.output_ref.removeprefix("cas:"),
                author.agent_id,
                rubric,
                quorum=1,
                high_risk=risk_level == "high",
                security_review_required=risk_level == "high",
            )
            proposal_stream.append(
                "negotiation-fresh-review-requested",
                ({
                    **fresh_requested,
                    "schema": "NEGOTIATION_FRESH_REVIEW_REQUESTED_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "reviewer_id": reviewer.agent_id,
                    "reviewer_independent_from_author": reviewer.agent_id != author.agent_id,
                    "reviewer_independent_from_synthesizer": reviewer.agent_id != synthesizer_id,
                    "old_review_reused": False,
                },),
                actor="fresh-review-command-handler",
            )

            def validate_final(value: Mapping[str, Any]) -> None:
                verdict = _require_string(value, "verdict").lower()
                if verdict not in {"approved", "changes_requested", "reject"}:
                    raise DynamicCollaborationError("final debate Review verdict is invalid")
                score = value.get("score")
                if not isinstance(score, int) or not 0 <= score <= 100:
                    raise DynamicCollaborationError("final debate Review score is invalid")
                if verdict == "approved" and score < int(self.policy["proposal_minimum_score"]):
                    raise DynamicCollaborationError("approved final debate Review is below threshold")
                _require_string(value, "reason")
                _require_strings(value, "defects", minimum=0, maximum=8)

            review = self._call(
                executor,
                evidence,
                reviewer,
                task_id=f"debate-final-review-{index + 1}",
                kind="review",
                contract=(
                    "Independently evaluate the exact round-2 revision as a playbook specification, not as an already "
                    "executed migration. Return verdict as approved, changes_requested, or reject; integer score "
                    "0-100; non-empty reason; and defects as a JSON array of zero to eight strings. Do not require "
                    "post-execution logs, completed implementation artifacts, or already-passed tests at this planning stage."
                ),
                prompt=(
                    f"Review round-2 revision hash {revised.output_hash}, parent hash {results[index].output_hash}. "
                    f"Frozen rubric {rubric}. Approve if the revision resolves the peer objections, supplies concrete "
                    "testable conditions tied to named internal evidence that the playbook requires execution to produce, "
                    "and otherwise meets the rubric. Evaluate specification completeness; do not demand evidence that "
                    "the future cutover, implementation, or tests have already run. "
                    "At the final bounded round, unresolved defects mean changes_requested or reject and therefore NO_CONSENSUS; "
                    f"the runtime will not force success. Required shape: {{\"agent_id\":\"{reviewer.agent_id}\",\"kind\":\"review\","
                    "\"verdict\":\"approved\",\"score\":85,\"reason\":\"...\",\"defects\":[]}. Revision: "
                    + json.dumps(dict(revised.value), ensure_ascii=False, sort_keys=True)
                ),
                context={
                    "debate_id": debate_id,
                    "proposal_id": proposal_ids[index],
                    "proposal_generation": next_round.generation,
                    "author_agent_id": author.agent_id,
                    "reviewer_independence": reviewer.agent_id != author.agent_id,
                    "synthesizer_id": synthesizer_id,
                    "reviewer_independent_from_synthesizer": reviewer.agent_id != synthesizer_id,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "old_review_reused": False,
                },
                validate=validate_final,
            )
            score = int(review.value["score"])
            provider_verdict = str(review.value["verdict"]).lower()
            effective_verdict = provider_verdict
            if (
                bool(overrides.get("force_negotiation_no_consensus"))
                or semantic_no_consensus_required
            ) and index == 0:
                effective_verdict = "reject"
            evaluation_disposition = "ACCEPT" if effective_verdict == "approved" else "REJECT"
            fresh_review, fresh_response = fresh_review.respond(
                reviewer.agent_id,
                tuple(reviewer.capabilities),
                False,
                {
                    "approved": ReviewVerdict.ACCEPT,
                    "changes_requested": ReviewVerdict.NEEDS_CHANGES,
                    "reject": ReviewVerdict.REJECT,
                }[effective_verdict],
                review.output_ref.removeprefix("cas:"),
            )
            fresh_review, fresh_disposition = fresh_review.dispose()
            next_round, evaluated = next_round.evaluate(
                proposal_ids[index], reviewer.agent_id, score=score, disposition=evaluation_disposition
            )
            proposal_stream.append(
                "negotiation-fresh-review-submitted",
                ({
                    **fresh_response,
                    "schema": "NEGOTIATION_FRESH_REVIEW_SUBMITTED_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "fresh_review_output_hash": review.output_hash,
                    "fresh_review_output_ref": review.output_ref,
                    "fresh_review_call_id": review.call_id,
                    "provider_verdict": provider_verdict,
                    "effective_verdict": effective_verdict,
                    "old_review_reused": False,
                }, {
                    **fresh_disposition,
                    "schema": "NEGOTIATION_FRESH_REVIEW_DISPOSITION_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                }, {
                    **evaluated,
                    "event_type": "proposal.round-2.evaluated",
                    "review_call_id": review.call_id,
                    "review_output_hash": review.output_hash,
                    "provider_verdict": provider_verdict,
                    "effective_verdict": effective_verdict,
                    "old_review_reused": False,
                }),
                actor=reviewer.agent_id,
            )
            scores[proposal_ids[index]] = score
            dispositions[proposal_ids[index]] = evaluation_disposition
            reviews.append(review)
            fresh_review_ids.append(fresh_review_id)
            fresh_review_hashes.append(review.output_hash)
        unresolved = tuple(
            claim_ids[index]
            for index, proposal_id in enumerate(proposal_ids)
            if dispositions[proposal_id] != "ACCEPT"
        )
        included = tuple(claim_id for claim_id in claim_ids if claim_id not in unresolved)
        outcome = DebateOutcome.NO_CONSENSUS if unresolved else DebateOutcome.CONSENSUS
        debate, synthesis = debate.finalize(
            claims,
            included=included,
            excluded=(),
            unresolved=unresolved,
            evidence_map=evidence_map,
            outcome=outcome,
        )
        close_fact = self._protocol_close(
            evidence,
            debate_id,
            obligation,
            outcome.value,
            successor=debate.successor_obligation_id,
        )
        finalization_facts: list[dict[str, Any]] = [synthesis]
        no_consensus_decision_id = None
        if outcome is DebateOutcome.NO_CONSENSUS:
            no_consensus_decision_id = "negotiation-no-consensus-" + stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_NO_CONSENSUS",
                {
                    "run_id": evidence.run_id,
                    "debate_id": debate_id,
                    "synthesis_hash": debate.synthesis_hash,
                    "fresh_review_hashes": fresh_review_hashes,
                    "unresolved": list(unresolved),
                },
            )[:36]
            finalization_facts.extend((
                {
                    "schema": "NEGOTIATION_NO_CONSENSUS_DECIDED_V1",
                    "decision_id": no_consensus_decision_id,
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "debate_id": debate_id,
                    "latest_revision_hashes": [item.output_hash for item in revised_results],
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "synthesis_hash": debate.synthesis_hash,
                    "fresh_review_ids": fresh_review_ids,
                    "fresh_review_hashes": fresh_review_hashes,
                    "unresolved_claim_ids": list(unresolved),
                    "successor_obligation_id": debate.successor_obligation_id,
                    "admission_error_used_as_no_consensus": False,
                    "decision": "NO_CONSENSUS",
                },
                {
                    "schema": "SUCCESSOR_OBLIGATION_CREATED_V1",
                    "obligation_id": debate.successor_obligation_id,
                    "source_protocol_id": debate_id,
                    "source_decision_id": no_consensus_decision_id,
                    "reason": "NEGOTIATION_BOUNDED_NO_CONSENSUS",
                },
            ))
        finalization_facts.append(close_fact)
        proposal_stream.append(
            "negotiation-finalized",
            tuple(finalization_facts),
            actor=reviewer.agent_id,
        )
        if outcome is DebateOutcome.NO_CONSENSUS:
            dispositions = {proposal_id: "REJECT" for proposal_id in proposal_ids}
        return next_round, revised_results, scores, dispositions, reviews, {
            "outcome": outcome.value,
            "debate_id": debate_id,
            "synthesis_candidate_hash": debate.synthesis_candidate_hash,
            "synthesis_hash": debate.synthesis_hash,
            "fresh_review_ids": tuple(fresh_review_ids),
            "fresh_review_hashes": tuple(fresh_review_hashes),
            "successor_obligation_id": debate.successor_obligation_id,
            "no_consensus_decision_id": no_consensus_decision_id,
        }

    def _arbitrate(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        proposals: Sequence[AgentCallResult],
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
    ) -> None:
        if len(proposals) < 2:
            raise DynamicCollaborationError("Arbitration requires at least two independently submitted Proposals")
        _, arbiters = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="arbitration",
            required_capabilities=("arbitration", "review"),
            slots=1,
            candidate_tasks=("arbitration",),
            author_conflicts=tuple(item.agent_id for item in proposals),
            overrides=overrides,
        )
        arbiter = arbiters[0]
        losing = next(item for item in proposals if item.output_hash != winner.output_hash)

        def validate(value: Mapping[str, Any]) -> None:
            decision = _require_string(value, "decision").lower()
            if decision not in {"prefer_winner", "merge", "reject_both"}:
                raise DynamicCollaborationError("Arbitration decision is invalid")
            blocked = _require_string(value, "blocked_output_hash")
            if blocked not in {item.output_hash for item in proposals}:
                raise DynamicCollaborationError("Arbitration blocked hash is outside the frozen evidence window")
            _require_string(value, "reason")

        result = self._call(
            executor,
            evidence,
            arbiter,
            task_id="arbitration",
            kind="review",
            contract="Resolve the frozen technical dispute; return decision, blocked_output_hash, and reason. The binding result will be enforced separately.",
            prompt=(
                f"Resolve this goal's technical dispute. Winner selected by Review is {winner.output_hash}; competing output is {losing.output_hash}. "
                "Return decision prefer_winner or merge, and block the losing output hash. Evidence window: "
                + json.dumps(
                    [{"agent_id": item.agent_id, "output_hash": item.output_hash, "proposal": dict(item.value)} for item in proposals],
                    ensure_ascii=False,
                    sort_keys=True,
                )
            ),
            context={
                "evidence_window": [item.output_hash for item in proposals],
                "winner_output_hash": winner.output_hash,
                "winner_agent_id": winner_agent.agent_id,
                "conflict_of_interest_policy": "arbiter_must_not_be_proposal_author",
                "appeal_policy": "one_new-evidence-generation",
            },
            validate=validate,
        )
        if result.value["blocked_output_hash"] == winner.output_hash:
            raise DynamicCollaborationError("Arbitration contradicted the frozen independent Review without new evidence")
        arbitration_id = "arbitration-" + stable_hash("TRUE_MULTI_AGENT_ARBITRATION", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + arbitration_id
        open_fact = self._protocol_open(evidence, "arbitration", arbitration_id, obligation, source_decision.decision_id)
        arbitration, opened = Arbitration.open(
            arbitration_id,
            obligation,
            self.policy_hash,
            max_appeals=1,
            appeal_deadline="2099-01-01T00:00:00Z",
            appeal_authorities=(arbiter.agent_id,),
        )
        claim_ids = tuple(f"claim-proposal-{index + 1}" for index in range(len(proposals)))
        arbitration, admitted = arbitration.admit(claim_ids, arbiter.agent_id)
        blocked_target = "proposal-target-" + str(result.value["blocked_output_hash"])[:24]
        arbitration, decided = arbitration.decide(
            str(result.value["decision"]).upper(),
            binding_scope=(blocked_target,),
            evidence_refs=tuple(item.output_hash for item in proposals),
        )
        if not arbitration.blocks_dispatch(blocked_target):
            raise DynamicCollaborationError("Arbitration Decision did not bind Dispatcher eligibility")
        enforcement_ref = stable_hash(
            "TRUE_MULTI_AGENT_ARBITRATION_ENFORCEMENT",
            {"arbitration_id": arbitration_id, "blocked_target": blocked_target, "decision_output_hash": result.output_hash},
        )
        arbitration, enforced = arbitration.enforce(enforcement_ref)
        close_fact = self._protocol_close(evidence, arbitration_id, obligation, "ENFORCED")
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/arbitration/{arbitration_id}",
            self.policy_hash,
        )
        stream.append(
            "arbitration-enforced",
            (
                open_fact,
                opened,
                {
                    "schema": "ARBITRATION_EVIDENCE_WINDOW_FROZEN_V1",
                    "arbitration_id": arbitration_id,
                    "evidence_refs": [item.output_hash for item in proposals],
                    "claims": list(claim_ids),
                    "decision_rule": "INDEPENDENT_REVIEW_PLUS_ARBITER_EVIDENCE",
                    "conflict_of_interest_policy": "ARBITER_NOT_AUTHOR",
                    "appeal_policy": "NEW_EVIDENCE_ONLY_MAX_ONE",
                },
                admitted,
                {**decided, "event_type": "arbitration.decided", "arbiter_call_id": result.call_id, "arbiter_output_hash": result.output_hash},
                {
                    "schema": "DISPATCH_CANDIDATE_FILTERED_BY_ARBITRATION_V1",
                    "event_type": "dispatch.candidate.filtered",
                    "arbitration_id": arbitration_id,
                    "blocked_target": blocked_target,
                    "blocked_output_hash": result.value["blocked_output_hash"],
                    "reason_code": "BINDING_ARBITRATION_BLOCK",
                    "removed_from_candidate_set": True,
                },
                {**enforced, "event_type": "arbitration.enforced"},
                close_fact,
            ),
            actor=arbiter.agent_id,
        )

    def _blackboard_pre_gap_closure(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
    ) -> None:
        _, writers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="blackboard-continuation",
            required_capabilities=("blackboard-write",),
            slots=1,
            candidate_tasks=("blackboard-continuation", "blackboard-conflict-resolution"),
            exclusions=(winner_agent.agent_id,),
            overrides=overrides,
        )
        writer_b = writers[0]
        board_id = "blackboard-" + stable_hash("TRUE_MULTI_AGENT_BLACKBOARD", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + board_id
        open_fact = self._protocol_open(evidence, "blackboard", board_id, obligation, source_decision.decision_id)
        policy = NamespacePolicy(
            stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_SCHEMA", {"fields": ["decision", "rationale", "continuation"]}),
            ("blackboard-write",),
            True,
            "ARBITRATION",
            "controlled-read-only",
            4096,
        )
        board = Blackboard({BlackboardNamespace.DECISIONS: policy})
        document, created = board.create(board_id, BlackboardNamespace.DECISIONS)
        task = TaskAggregate("blackboard-task-" + evidence.run_id, stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_TASK", {"run": evidence.run_id}))
        task, attempt, claim = task.claim(
            claim_command_id="claim-blackboard-" + evidence.run_id,
            lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id="blackboard-command-handler",
            expected_stream_version=task.stream_version,
        )
        initial_read = {
            "document_id": document.document_id,
            "version": document.version,
            "document_hash": document.document_hash,
        }
        intent_a = PatchIntent(
            document.document_id,
            document.version,
            document.document_hash,
            {"decision": winner.output_hash, "rationale": "selected proposal"},
            winner_agent.agent_id,
            ("blackboard-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (winner.output_hash,),
            (document.document_hash,),
        )
        # The selected author may not normally carry blackboard-write. A
        # canonical delegation capability is explicitly bound to this Task.
        intent_a = dataclasses.replace(intent_a, writer_capabilities=("blackboard-write",))
        patched_a = board.patch(intent_a, task=task)
        if patched_a.event is None:
            raise DynamicCollaborationError("Blackboard Patch A failed")

        def validate_continuation(value: Mapping[str, Any]) -> None:
            _require_string(value, "continuation")
            _require_string(value, "read_document_hash")
            version = value.get("read_version")
            if not isinstance(version, int) or version < 1:
                raise DynamicCollaborationError("Blackboard continuation lacks committed read version")

        continuation = self._call(
            executor,
            evidence,
            writer_b,
            task_id="blackboard-continuation",
            kind="proposal",
            contract=(
                "Continue from the exact committed Blackboard version; return continuation, read_version as a JSON "
                "integer without quotes, and read_document_hash as a string."
            ),
            prompt=(
                f"Continue the shared decision after Agent A committed version {patched_a.document.version} hash {patched_a.document.document_hash}. "
                f"Selected proposal output hash is {winner.output_hash}. Return the exact read_version as an unquoted "
                "JSON integer and the exact read_document_hash."
            ),
            context={
                "blackboard_document_id": board_id,
                "read_version": patched_a.document.version,
                "read_document_hash": patched_a.document.document_hash,
                "prior_agent_id": winner_agent.agent_id,
                "prior_output_hash": winner.output_hash,
            },
            validate=validate_continuation,
        )
        if int(continuation.value["read_version"]) != patched_a.document.version:
            raise DynamicCollaborationError("Agent B did not bind the actual Blackboard version")
        if str(continuation.value["read_document_hash"]) != patched_a.document.document_hash:
            raise DynamicCollaborationError("Agent B did not bind the actual Blackboard hash")
        events: list[Mapping[str, Any]] = [open_fact, claim, created, {**patched_a.event, "event_type": "blackboard.patch.committed"}]
        conflict_required = analysis.requires_conflict or bool(overrides.get("force_stale_blackboard_base"))
        if conflict_required:
            stale_intent = PatchIntent(
                document.document_id,
                initial_read["version"],
                initial_read["document_hash"],
                {"decision": continuation.output_hash, "continuation": continuation.value["continuation"]},
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (continuation.output_hash,),
                (initial_read["document_hash"],),
            )
            conflict = board.patch(stale_intent, task=task)
            if conflict.conflict is None or conflict.event is not None:
                raise DynamicCollaborationError("stale Blackboard base did not produce an explicit conflict")
            events.extend(
                (
                    {**conflict.conflict, "event_type": "blackboard.patch.conflict", "agent_id": writer_b.agent_id},
                    {
                        "schema": "BLACKBOARD_LAST_WRITE_WINS_DENIED_V1",
                        "document_id": board_id,
                        "silent_overwrite": False,
                        "blocked_obligations": list(conflict.blocked_obligations),
                    },
                )
            )
            canonical = board.documents[board_id]
            merged_intent = PatchIntent(
                canonical.document_id,
                canonical.version,
                canonical.document_hash,
                {
                    "decision": winner.output_hash,
                    "continuation": continuation.value["continuation"],
                    "resolution": "explicit-merge-after-conflict",
                },
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (winner.output_hash, continuation.output_hash),
                (canonical.document_hash,),
            )
            patched_b = board.patch(merged_intent, task=task)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard conflict resolution did not commit")
            events.append({**patched_b.event, "event_type": "blackboard.conflict.resolved"})
        else:
            canonical = board.documents[board_id]
            intent_b = PatchIntent(
                canonical.document_id,
                canonical.version,
                canonical.document_hash,
                {"continuation": continuation.value["continuation"], "source_output_hash": continuation.output_hash},
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (continuation.output_hash,),
                (canonical.document_hash,),
            )
            patched_b = board.patch(intent_b, task=task)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard Patch B failed")
            events.append({**patched_b.event, "event_type": "blackboard.patch.committed"})
        final = board.documents[board_id]
        close_fact = self._protocol_close(evidence, board_id, obligation, "COMMITTED")
        events.extend(
            (
                {
                    "schema": "BLACKBOARD_FINAL_VERSION_REFERENCED_V1",
                    "document_id": board_id,
                    "committed_version": final.version,
                    "document_hash": final.document_hash,
                    "agent_b_call_id": continuation.call_id,
                    "agent_b_input_snapshot_hash": continuation.input_snapshot_hash,
                },
                close_fact,
            )
        )
        CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/blackboard/{board_id}",
            self.policy_hash,
        ).append("blackboard-closed", tuple(events), actor="blackboard-command-handler")

    def _blackboard(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
        *,
        primary_writer: AgentIdentity | None = None,
        leased_task: TaskAggregate | None = None,
    ) -> Mapping[str, Any]:
        if primary_writer is None:
            writer_decision, writers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-concurrent-writers",
                required_capabilities=("blackboard-write",),
                slots=2,
                candidate_tasks=("blackboard-branch-a", "blackboard-branch-b"),
                overrides=overrides,
            )
            if len(writers) != 2 or writers[0].agent_id == writers[1].agent_id:
                raise DynamicCollaborationError("Blackboard requires two independently scheduled writers")
            writer_a, writer_b = writers
        else:
            writer_decision, collaborators = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-concurrent-collaborator",
                required_capabilities=("blackboard-write",),
                slots=1,
                candidate_tasks=("blackboard-stale-branch", "blackboard-conflict-merge"),
                exclusions=(primary_writer.agent_id,),
                overrides=overrides,
            )
            writer_a = dataclasses.replace(
                primary_writer,
                capabilities=tuple(sorted(set(primary_writer.capabilities).union({"blackboard-write"}))),
            )
            writer_b = collaborators[0]
        board_id = "blackboard-" + stable_hash("TRUE_MULTI_AGENT_BLACKBOARD", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + board_id
        open_fact = self._protocol_open(evidence, "blackboard", board_id, obligation, writer_decision.decision_id)
        schema_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_SCHEMA",
            {"fields": ["decision", "rationale", "continuation", "resolution"]},
        )
        merge_policy_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_MERGE_POLICY",
            {"policy": "ARBITRATION", "schema_hash": schema_hash, "generation": 1},
        )
        writer_policy_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_WRITER_POLICY",
            {"capability": "blackboard-write", "task_fence_required": True, "generation": 1},
        )
        policy = NamespacePolicy(
            schema_hash,
            ("blackboard-write",),
            True,
            "ARBITRATION",
            "controlled-read-only",
            4096,
            schema_id="sitina.blackboard.decision",
            schema_version=1,
            writer_policy_hash=writer_policy_hash,
            merge_policy_hash=merge_policy_hash,
            cas_required=True,
        )
        board = Blackboard({BlackboardNamespace.DECISIONS: policy})
        document, created = board.create(board_id, BlackboardNamespace.DECISIONS)
        board.declare_dependencies(obligation, (board_id,))
        if leased_task is None:
            task = TaskAggregate(
                "blackboard-task-" + evidence.run_id,
                stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_TASK", {"run": evidence.run_id}),
            )
            task, attempt, claim = task.claim(
                claim_command_id="claim-blackboard-" + evidence.run_id,
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id="blackboard-command-handler",
                expected_stream_version=task.stream_version,
            )
        else:
            task = leased_task
            attempt = task.active_attempt
            if attempt is None or attempt.holder_agent_id != primary_writer.agent_id:
                raise DynamicCollaborationError("integrated Blackboard requires the selected Agent's active Task Lease")
            claim = {
                "schema": "INTEGRATED_BLACKBOARD_TASK_FENCE_BOUND_V1",
                "event_type": "blackboard.task-fence.bound",
                "task_id": task.task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "holder_agent_id": attempt.holder_agent_id,
                "claim_generation": attempt.claim_generation,
                "lease_id": attempt.lease_id,
                "fencing_token": attempt.fencing_token,
                "task_scoped_writer_delegation": [writer_b.agent_id],
                "selected_executor_is_primary_writer": True,
            }
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"blackboard/{board_id}",
            self.policy_hash,
        )
        stream.append(
            "blackboard-document-created",
            (
                open_fact,
                {
                    **claim,
                    "event_type": "blackboard.task.claimed",
                    "holder_agent_ids": [writer_a.agent_id, writer_b.agent_id],
                    "task_id": task.task_id,
                },
                {**created, "event_type": "blackboard.document.created"},
            ),
            actor="blackboard-command-handler",
        )
        conflict_required = analysis.requires_conflict or bool(overrides.get("force_stale_blackboard_base"))

        def validate_writer(value: Mapping[str, Any]) -> None:
            version = value.get("read_version")
            if not isinstance(version, int) or version < 0:
                raise DynamicCollaborationError("Blackboard writer lacks a valid read_version")
            _require_string(value, "read_document_hash")
            patch = value.get("patch")
            if not isinstance(patch, dict) or not patch or len(patch) > 12:
                raise DynamicCollaborationError("Blackboard writer requires a bounded Patch object")
            _require_string(value, "write_rationale")

        read_a_document, read_a = board.read(
            board_id,
            agent_id=writer_a.agent_id,
            read_paths=("/decision", "/rationale"),
            source_event_refs=tuple(self._recent_event_ids(journal)),
        )
        _, read_a_refs = stream.append(
            "blackboard-read-a",
            ({**read_a, "event_type": "blackboard.document.read"},),
            actor=writer_a.agent_id,
        )

        if conflict_required:
            read_b_document, read_b = board.read(
                board_id,
                agent_id=writer_b.agent_id,
                read_paths=("/decision", "/rationale"),
                source_event_refs=tuple(item["event_id"] for item in read_a_refs),
            )
            _, read_b_refs = stream.append(
                "blackboard-read-b-shared-base",
                ({**read_b, "event_type": "blackboard.document.read"},),
                actor=writer_b.agent_id,
            )
            if (
                read_a_document.version != read_b_document.version
                or read_a_document.document_hash != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard writers did not read the same canonical base")
        else:
            read_b = {}
            read_b_refs = ()

        writer_a_result = self._call(
            executor,
            evidence,
            writer_a,
            task_id="blackboard-branch-a",
            kind="proposal",
            contract=(
                "Read the exact Blackboard version in the input and return read_version, read_document_hash, "
                "a bounded patch object, and write_rationale. The Patch is a business-state proposal, not an Event. "
                "read_version must be a JSON integer without quotes and read_document_hash must be copied byte-for-byte "
                "from shared_context.read_document_hash as the same 64 lowercase hexadecimal characters; verify every "
                "character and never retype, shorten, or transform it. "
                "Keep patch to at most four scalar string fields, keep every string under 240 characters, and do not "
                "restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
            ),
            prompt=(
                f"Create branch A for the shared decision record supporting this goal: {evidence.goal}. "
                f"Read version {read_a_document.version} hash {read_a_document.document_hash}. "
                f"Return read_version as the unquoted JSON integer {read_a_document.version}. Return no floating point "
                "values, do not invent committed versions, and summarize only the branch's "
                "distinct decision and rationale in the compact patch."
            ),
            context={
                "document_id": board_id,
                "read_id": read_a["read_id"],
                "read_event_id": read_a_refs[-1]["event_id"],
                "read_version": read_a_document.version,
                "read_document_hash": read_a_document.document_hash,
                "selected_proposal_hash": winner.output_hash,
            },
            validate=validate_writer,
        )
        if (
            int(writer_a_result.value["read_version"]) != read_a_document.version
            or str(writer_a_result.value["read_document_hash"]) != read_a_document.document_hash
        ):
            raise DynamicCollaborationError("Blackboard Agent A output did not bind its actual read base")

        if conflict_required:
            writer_b_result = self._call(
                executor,
                evidence,
                writer_b,
                task_id="blackboard-branch-b",
                kind="proposal",
                contract=(
                    "Independently read the exact Blackboard base in the input and return read_version, "
                    "read_document_hash, a bounded patch object, and write_rationale. Do not copy branch A. "
                    "read_version must be a JSON integer without quotes and read_document_hash must be copied byte-for-byte "
                    "from shared_context.read_document_hash as the same 64 lowercase hexadecimal characters; verify every "
                    "character and never retype, shorten, or transform it. "
                    "Keep patch to at most four scalar string fields, keep every string under 240 characters, and do not "
                    "restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
                ),
                prompt=(
                    f"Create an independent branch B for this business goal: {evidence.goal}. "
                    f"Your shared base is version {read_b_document.version} hash {read_b_document.document_hash}. "
                    f"Return read_version as the unquoted JSON integer {read_b_document.version}. Return no floating "
                    "point values, do not claim that the Patch was committed, and summarize only "
                    "the branch's distinct decision and rationale in the compact patch."
                ),
                context={
                    "document_id": board_id,
                    "read_id": read_b["read_id"],
                    "read_event_id": read_b_refs[-1]["event_id"],
                    "read_version": read_b_document.version,
                    "read_document_hash": read_b_document.document_hash,
                    "selected_proposal_hash": winner.output_hash,
                },
                validate=validate_writer,
            )
            if (
                int(writer_b_result.value["read_version"]) != read_b_document.version
                or str(writer_b_result.value["read_document_hash"]) != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard Agent B output did not bind its actual read base")
        else:
            writer_b_result = None

        patch_a = dict(writer_a_result.value["patch"])
        patch_a_receipt = executor._publish(patch_a, purpose="true-multi-agent-blackboard-patch")
        intent_a = PatchIntent(
            board_id,
            read_a_document.version,
            read_a_document.document_hash,
            patch_a,
            writer_a.agent_id,
            ("blackboard-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (winner.output_hash, writer_a_result.output_hash),
            (read_a["read_id"], read_a_refs[-1]["event_id"]),
            patch_ref=patch_a_receipt.object_ref.reference_id,
            target_paths=("/decision", "/rationale"),
            merge_policy_hash=merge_policy_hash,
        )
        patched_a = board.patch(intent_a, task=task, published_object_receipt=patch_a_receipt)
        if patched_a.event is None:
            raise DynamicCollaborationError("Blackboard Patch A failed")
        _, patch_a_refs = stream.append(
            "blackboard-patch-a-committed",
            ({
                **patched_a.event,
                "event_type": "blackboard.patch.committed",
                "agent_call_id": writer_a_result.call_id,
                "agent_input_snapshot_hash": writer_a_result.input_snapshot_hash,
                "agent_output_hash": writer_a_result.output_hash,
                "_object_refs": [patch_a_receipt.object_ref.reference_id],
            },),
            actor=writer_a.agent_id,
            proofs=(patch_a_receipt,),
        )

        if not conflict_required:
            read_b_document, read_b = board.read(
                board_id,
                agent_id=writer_b.agent_id,
                read_paths=("/decision", "/rationale"),
                source_event_refs=tuple(item["event_id"] for item in patch_a_refs),
            )
            _, read_b_refs = stream.append(
                "blackboard-read-b-current",
                ({**read_b, "event_type": "blackboard.document.read"},),
                actor=writer_b.agent_id,
            )
            writer_b_result = self._call(
                executor,
                evidence,
                writer_b,
                task_id="blackboard-continuation-current",
                kind="proposal",
                contract=(
                    "Continue from the exact committed Blackboard version and return read_version as a JSON integer "
                    "without quotes, read_document_hash copied exactly, patch, and write_rationale."
                ),
                prompt=(
                    f"Continue the shared decision for this goal: {evidence.goal}. "
                    f"Read committed version {read_b_document.version} hash {read_b_document.document_hash}. Return "
                    f"read_version as the unquoted JSON integer {read_b_document.version}."
                ),
                context={
                    "document_id": board_id,
                    "read_id": read_b["read_id"],
                    "read_event_id": read_b_refs[-1]["event_id"],
                    "read_version": read_b_document.version,
                    "read_document_hash": read_b_document.document_hash,
                    "patch_a_hash": patched_a.event["patch_hash"],
                },
                validate=validate_writer,
            )
            if (
                int(writer_b_result.value["read_version"]) != read_b_document.version
                or str(writer_b_result.value["read_document_hash"]) != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard continuation did not bind N+1")
            patch_b = dict(writer_b_result.value["patch"])
            patch_b_receipt = executor._publish(patch_b, purpose="true-multi-agent-blackboard-patch")
            intent_b = PatchIntent(
                board_id, read_b_document.version, read_b_document.document_hash, patch_b,
                writer_b.agent_id, ("blackboard-write",), task.task_id, attempt.task_attempt_id,
                attempt.claim_generation, attempt.fencing_token,
                (writer_b_result.output_hash,), (read_b["read_id"], read_b_refs[-1]["event_id"]),
                patch_ref=patch_b_receipt.object_ref.reference_id,
                target_paths=("/continuation",), merge_policy_hash=merge_policy_hash,
            )
            patched_b = board.patch(intent_b, task=task, published_object_receipt=patch_b_receipt)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard current-base continuation failed")
            _, resolution_refs = stream.append(
                "blackboard-patch-b-committed",
                ({
                    **patched_b.event,
                    "event_type": "blackboard.patch.committed",
                    "agent_call_id": writer_b_result.call_id,
                    "agent_input_snapshot_hash": writer_b_result.input_snapshot_hash,
                    "agent_output_hash": writer_b_result.output_hash,
                    "_object_refs": [patch_b_receipt.object_ref.reference_id],
                },),
                actor=writer_b.agent_id,
                proofs=(patch_b_receipt,),
            )
        else:
            assert writer_b_result is not None
            patch_b = dict(writer_b_result.value["patch"])
            patch_b_receipt = executor._publish(patch_b, purpose="true-multi-agent-blackboard-conflicting-patch")
            stale_intent = PatchIntent(
                board_id,
                read_b_document.version,
                read_b_document.document_hash,
                patch_b,
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (winner.output_hash, writer_b_result.output_hash),
                (read_b["read_id"], read_b_refs[-1]["event_id"]),
                patch_ref=patch_b_receipt.object_ref.reference_id,
                target_paths=("/decision", "/rationale"),
                merge_policy_hash=merge_policy_hash,
            )
            conflict = board.patch(stale_intent, task=task, published_object_receipt=patch_b_receipt)
            if conflict.conflict is None or conflict.event is not None or conflict.document.version != 1:
                raise DynamicCollaborationError("stale Blackboard base did not fail closed at N+1")
            conflict_id = str(conflict.conflict["conflict_id"])
            _, conflict_refs = stream.append(
                "blackboard-stale-patch-conflict",
                (
                    {
                        **conflict.conflict,
                        "event_type": "blackboard.patch.conflict",
                        "agent_call_id": writer_b_result.call_id,
                        "agent_input_snapshot_hash": writer_b_result.input_snapshot_hash,
                        "agent_output_hash": writer_b_result.output_hash,
                        "_object_refs": [patch_b_receipt.object_ref.reference_id],
                    },
                    {
                        "schema": "BLACKBOARD_LAST_WRITE_WINS_DENIED_V1",
                        "event_type": "blackboard.last-write-wins.denied",
                        "document_id": board_id,
                        "conflict_id": conflict_id,
                        "canonical_version": conflict.document.version,
                        "canonical_hash": conflict.document.document_hash,
                        "blocked_obligations": list(conflict.blocked_obligations),
                        "document_stream_mutated": False,
                    },
                ),
                actor="blackboard-command-handler",
                proofs=(patch_b_receipt,),
            )
            merge_decision, merge_agents = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-conflict-merge",
                required_capabilities=("blackboard-write",),
                slots=1,
                candidate_tasks=("blackboard-conflict-merge",),
                exclusions=(writer_a.agent_id, writer_b.agent_id),
                overrides=overrides,
            )
            merge_agent = merge_agents[0]
            _, merge_reviewers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-merge-review",
                required_capabilities=("review",),
                slots=1,
                candidate_tasks=("blackboard-merge-review",),
                author_conflicts=(writer_a.agent_id, writer_b.agent_id, merge_agent.agent_id),
                overrides=overrides,
            )
            merge_reviewer = merge_reviewers[0]

            def validate_merge(value: Mapping[str, Any]) -> None:
                patch = value.get("merge_patch")
                if not isinstance(patch, dict) or not patch or len(patch) > 16:
                    raise DynamicCollaborationError("Merge Agent requires a bounded merge_patch object")
                _require_string(value, "canonical_branch_hash")
                _require_string(value, "conflicting_branch_hash")
                _require_string(value, "resolution_rationale")

            merge_result = self._call(
                executor,
                evidence,
                merge_agent,
                task_id="blackboard-conflict-merge",
                kind="proposal",
                contract=(
                    "Independently merge the canonical and conflicting business-state branches. Return merge_patch, "
                    "canonical_branch_hash copied byte-for-byte from input context, conflicting_branch_hash copied "
                    "byte-for-byte from input context, and resolution_rationale. Do not shorten or reformat either hash. "
                    "resolution_rationale must be a top-level sibling of merge_patch, not a field inside merge_patch. "
                    "Keep merge_patch to at most six scalar string fields, keep every string under 320 characters, and "
                    "do not restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
                ),
                prompt=(
                    f"Resolve a shared decision conflict for goal: {evidence.goal}. Preserve both defensible branches. "
                    f"Return canonical_branch_hash exactly '{patched_a.event['patch_hash']}' and conflicting_branch_hash "
                    f"exactly '{conflict.conflict['patch_hash']}'. Do not omit or rename either field. Summarize the "
                    "combined decision and both retained conclusions compactly. Return resolution_rationale at the "
                    "top level beside merge_patch; do not nest it in merge_patch."
                ),
                context={
                    "document_id": board_id,
                    "conflict_id": conflict_id,
                    "canonical_document_version": conflict.document.version,
                    "canonical_document_hash": conflict.document.document_hash,
                    "canonical_patch": patch_a,
                    "canonical_patch_ref": patch_a_receipt.object_ref.reference_id,
                    "canonical_patch_hash": patched_a.event["patch_hash"],
                    "conflicting_patch": patch_b,
                    "conflicting_patch_ref": patch_b_receipt.object_ref.reference_id,
                    "conflicting_patch_hash": conflict.conflict["patch_hash"],
                    "conflict_event_ids": [item["event_id"] for item in conflict_refs],
                    "merge_policy_hash": merge_policy_hash,
                    "source_decision_id": merge_decision.decision_id,
                },
                validate=validate_merge,
            )
            if (
                str(merge_result.value["canonical_branch_hash"]) != patched_a.event["patch_hash"]
                or str(merge_result.value["conflicting_branch_hash"]) != conflict.conflict["patch_hash"]
            ):
                raise DynamicCollaborationError("Merge Agent did not bind both exact branches")
            merge_patch = dict(merge_result.value["merge_patch"])
            merge_patch_receipt = executor._publish(merge_patch, purpose="true-multi-agent-blackboard-merge-patch")
            merge_fact = board.submit_merge(
                conflict_id,
                merge_agent_id=merge_agent.agent_id,
                merge_patch=merge_patch,
                merge_read_refs=(conflict.document.document_hash, str(conflict.conflict["patch_hash"])),
                published_object_receipt=merge_patch_receipt,
            )
            _, merge_refs = stream.append(
                "blackboard-merge-proposed",
                ({
                    **merge_fact,
                    "event_type": "blackboard.merge.proposed",
                    "agent_call_id": merge_result.call_id,
                    "agent_input_snapshot_hash": merge_result.input_snapshot_hash,
                    "agent_output_hash": merge_result.output_hash,
                    "_object_refs": [merge_patch_receipt.object_ref.reference_id],
                },),
                actor=merge_agent.agent_id,
                proofs=(merge_patch_receipt,),
            )
            merge_rubric_hash = stable_hash(
                "TRUE_MULTI_AGENT_BLACKBOARD_MERGE_RUBRIC",
                {"policy_hash": self.policy_hash, "merge_policy_hash": merge_policy_hash, "criteria": ["branch-preservation", "safety", "schema"]},
            )

            def validate_merge_review(value: Mapping[str, Any]) -> None:
                _require_bool(value, "accept")
                _require_string(value, "reviewed_merge_hash")
                _require_string(value, "reason")

            merge_review = self._call(
                executor,
                evidence,
                merge_reviewer,
                task_id="blackboard-merge-review",
                kind="review",
                contract=(
                    "Independently review the exact Merge Patch and return accept, reviewed_merge_hash copied "
                    "byte-for-byte from input context, and reason. Do not shorten or reformat the hash."
                ),
                prompt=(
                    f"Review merge hash {merge_fact['merge_patch_hash']} under rubric {merge_rubric_hash}. "
                    f"Return reviewed_merge_hash exactly '{merge_fact['merge_patch_hash']}'. Accept only if both branches "
                    "are preserved, the result is safe, and the schema remains valid."
                ),
                context={
                    "document_id": board_id,
                    "conflict_id": conflict_id,
                    "merge_id": merge_fact["merge_id"],
                    "merge_event_id": merge_refs[-1]["event_id"],
                    "merge_patch": merge_patch,
                    "merge_patch_ref": merge_patch_receipt.object_ref.reference_id,
                    "merge_patch_hash": merge_fact["merge_patch_hash"],
                    "canonical_patch_hash": patched_a.event["patch_hash"],
                    "conflicting_patch_hash": conflict.conflict["patch_hash"],
                    "rubric_hash": merge_rubric_hash,
                },
                validate=validate_merge_review,
            )
            if str(merge_review.value["reviewed_merge_hash"]) != merge_fact["merge_patch_hash"]:
                raise DynamicCollaborationError("fresh Merge Review did not bind the exact Merge Patch")
            if not bool(merge_review.value["accept"]):
                raise DynamicCollaborationError("independent Merge Review rejected the proposed resolution")
            merge_review_fact = board.review_merge(
                conflict_id,
                reviewer_agent_id=merge_reviewer.agent_id,
                reviewed_merge_hash=merge_fact["merge_patch_hash"],
                review_hash=merge_review.output_hash,
                rubric_hash=merge_rubric_hash,
                accepted=True,
            )
            _, merge_review_refs = stream.append(
                "blackboard-merge-reviewed",
                ({
                    **merge_review_fact,
                    "event_type": "blackboard.merge.reviewed",
                    "agent_call_id": merge_review.call_id,
                    "agent_input_snapshot_hash": merge_review.input_snapshot_hash,
                    "agent_output_hash": merge_review.output_hash,
                },),
                actor=merge_reviewer.agent_id,
            )
            merge_intent = PatchIntent(
                board_id,
                conflict.document.version,
                conflict.document.document_hash,
                merge_patch,
                merge_agent.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (patched_a.event["patch_hash"], str(conflict.conflict["patch_hash"]), merge_review.output_hash),
                (conflict.document.document_hash, str(conflict.conflict["patch_hash"]), merge_refs[-1]["event_id"], merge_review_refs[-1]["event_id"]),
                patch_ref=merge_patch_receipt.object_ref.reference_id,
                patch_hash=merge_fact["merge_patch_hash"],
                target_paths=("/decision", "/rationale", "/resolution"),
                merge_policy_hash=merge_policy_hash,
            )
            resolution = board.resolve_conflict(
                conflict_id,
                decision_agent_id=merge_reviewer.agent_id,
                merge_intent=merge_intent,
                task=task,
                published_object_receipt=merge_patch_receipt,
            )
            _, resolution_refs = stream.append(
                "blackboard-conflict-resolved",
                (
                    {**resolution.merge_decision, "event_type": "blackboard.merge.decision"},
                    {**resolution.conflict_resolved, "event_type": "blackboard.conflict.resolved"},
                    {
                        **resolution.patch_committed,
                        "event_type": "blackboard.patch.committed",
                        "agent_call_id": merge_result.call_id,
                        "agent_input_snapshot_hash": merge_result.input_snapshot_hash,
                        "agent_output_hash": merge_result.output_hash,
                        "_object_refs": [merge_patch_receipt.object_ref.reference_id],
                    },
                ),
                actor=merge_reviewer.agent_id,
                proofs=(merge_patch_receipt,),
            )
            if board.closing_blockers:
                raise DynamicCollaborationError("Blackboard conflict remained blocking after resolution")

        final = board.documents[board_id]
        downstream_reader = writer_b
        downstream_document, downstream_read = board.read(
            board_id,
            agent_id=downstream_reader.agent_id,
            read_paths=("/decision", "/rationale", "/resolution"),
            source_event_refs=tuple(item["event_id"] for item in resolution_refs),
        )
        _, downstream_read_refs = stream.append(
            "blackboard-final-version-read",
            ({**downstream_read, "event_type": "blackboard.document.read"},),
            actor=downstream_reader.agent_id,
        )

        def validate_downstream(value: Mapping[str, Any]) -> None:
            version = value.get("read_version")
            if not isinstance(version, int) or version < 1:
                raise DynamicCollaborationError("downstream Blackboard Agent lacks read_version")
            _require_string(value, "read_document_hash")
            _require_string(value, "continuation")

        downstream = self._call(
            executor,
            evidence,
            downstream_reader,
            task_id="blackboard-downstream-consumer",
            kind="proposal",
            contract=(
                "Consume the exact resolved Blackboard version. The JSON object must include read_version as an integer, "
                "without quotes, read_document_hash as a string copied byte-for-byte from input context, and continuation "
                "as a non-empty string."
            ),
            prompt=(
                f"Continue the business task from resolved Blackboard version {downstream_document.version} "
                f"hash {downstream_document.document_hash}. Return read_version exactly {downstream_document.version}, "
                f"read_document_hash exactly '{downstream_document.document_hash}', and explain in continuation how the "
                "shared resolution changes the next step. Do not omit or rename any required field."
            ),
            context={
                "document_id": board_id,
                "read_id": downstream_read["read_id"],
                "read_event_id": downstream_read_refs[-1]["event_id"],
                "read_version": downstream_document.version,
                "read_document_hash": downstream_document.document_hash,
                "source_resolution_event_ids": [item["event_id"] for item in resolution_refs],
                "selected_proposal_hash": winner.output_hash,
            },
            validate=validate_downstream,
        )
        if (
            int(downstream.value["read_version"]) != final.version
            or str(downstream.value["read_document_hash"]) != final.document_hash
        ):
            raise DynamicCollaborationError("downstream Agent did not consume the resolved Blackboard version")
        blackboard_receipt = executor._publish(
            dict(final.inline_body or {}),
            purpose="true-multi-agent-blackboard-document",
        )
        blackboard_contract = BlackboardDocumentRecord(
            schema="SITINA_BLACKBOARD_DOCUMENT_V1",
            schema_version="1.0",
            correlation_id=evidence.run_id,
            causation_id=None,
            created_at=now_rfc3339(),
            source=SourceDescriptor(
                component="true-multi-agent-blackboard",
                actor_id=final.last_writer_id,
                source_ref=str(downstream_read_refs[-1]["event_id"]),
            ),
            trust="verified",
            document_id=final.document_id,
            namespace=final.namespace.value,
            document_version=final.version,
            document_hash=final.document_hash,
            content_ref=blackboard_receipt.object_ref.reference_id,
            classification=final.classification.casefold(),
            writer_policy_hash=final.writer_policy_hash,
            merge_policy_hash=final.merge_policy_hash,
            last_writer_id=final.last_writer_id,
        )
        close_fact = self._protocol_close(evidence, board_id, obligation, "CONFLICT_RESOLVED_AND_CONSUMED" if conflict_required else "COMMITTED_AND_CONSUMED")
        stream.append(
            "blackboard-closed",
            (
                {
                    "schema": "BLACKBOARD_FINAL_VERSION_REFERENCED_V1",
                    "event_type": "blackboard.final-version.consumed",
                    "document_id": board_id,
                    "committed_version": final.version,
                    "document_hash": final.document_hash,
                    "downstream_agent_id": downstream_reader.agent_id,
                    "downstream_call_id": downstream.call_id,
                    "downstream_input_snapshot_hash": downstream.input_snapshot_hash,
                    "downstream_output_hash": downstream.output_hash,
                    "downstream_read_event_id": downstream_read_refs[-1]["event_id"],
                    "blocking_conflict_count": len(board.active_conflicts),
                    "blackboard_document_ref": blackboard_receipt.object_ref.reference_id,
                    "_object_refs": [blackboard_receipt.object_ref.reference_id],
                },
                close_fact,
            ),
            actor="blackboard-terminal-coordinator",
            proofs=(blackboard_receipt,),
        )
        return {
            "document_id": board_id,
            "version": final.version,
            "document_hash": final.document_hash,
            "primary_writer_id": writer_a.agent_id,
            "stale_writer_id": writer_b.agent_id,
            "task_id": task.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "lease_id": attempt.lease_id,
            "fencing_token": attempt.fencing_token,
            "downstream_output_hash": downstream.output_hash,
            "downstream_output_ref": downstream.output_ref,
            "conflict_required": conflict_required,
            "contract": blackboard_contract.model_dump(mode="json", by_alias=True),
        }

    def _handoff(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        sender: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
        *,
        defer_after_execution_prepared: bool = False,
        integrated_context: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any] | None:
        receiver_decision, receivers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="handoff-receive",
            required_capabilities=("handoff-receive",),
            slots=1,
            candidate_tasks=("handoff-contract-review", "handoff-execution"),
            exclusions=(sender.agent_id,),
            overrides=overrides,
        )
        receiver = receivers[0]
        # HandoffContract / Handoff require bare 64-hex hashes, but self.policy_hash
        # comes from sha256_bytes ("sha256:"-prefixed, 71 chars). Strip once and use
        # this at every handoff-subsystem boundary (contract, offer, acknowledge).
        policy_hash_64 = self.policy_hash.removeprefix("sha256:")
        handoff_id = "handoff-" + stable_hash("TRUE_MULTI_AGENT_HANDOFF", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + handoff_id
        open_fact = self._protocol_open(evidence, "handoff", handoff_id, obligation, source_decision.decision_id)
        task_id = "handoff-task-" + evidence.run_id
        task = TaskAggregate(
            task_id,
            stable_hash("TRUE_MULTI_AGENT_HANDOFF_TASK", {"run": evidence.run_id, "winner": winner.output_hash}),
        )
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/handoff/{handoff_id}",
            self.policy_hash,
        )
        selected_proposal_projection = {
            "schema": "HANDOFF_SELECTED_PROPOSAL_PROJECTION_V1",
            "run_id": evidence.run_id,
            "handoff_id": handoff_id,
            "source_output_hash": winner.output_hash,
            "source_output_ref": winner.output_ref,
            "agent_id": winner.agent_id,
            "summary": str(winner.value.get("summary") or "")[:2000],
            "approach": str(winner.value.get("approach") or "")[:4000],
            "acceptance_checks": [
                str(item)[:500]
                for item in (winner.value.get("acceptance_checks") or ())
                if isinstance(item, str)
            ][:8],
        }
        current_proposal_projection: Mapping[str, Any] = selected_proposal_projection
        current_projection_hash = ""

        def receiver_capability_hash(identity: AgentIdentity) -> str:
            return stable_hash(
                "TRUE_MULTI_AGENT_HANDOFF_CAPABILITIES",
                {"receiver": identity.agent_id, "capabilities": list(identity.capabilities)},
            )

        def preview_claim(generation: int, identity: AgentIdentity) -> tuple[Any, dict[str, Any], str]:
            _, preview_attempt, preview_fact = task.claim(
                claim_command_id="claim-" + handoff_id + f"-{generation}",
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id=identity.agent_id,
                expected_stream_version=task.stream_version,
            )
            claim_ref = stable_hash("HANDOFF_TASK_CLAIM_RESERVATION", preview_fact)
            return preview_attempt, preview_fact, claim_ref

        def make_contract(
            generation: int,
            identity: AgentIdentity,
            *,
            incomplete: bool,
            previous_generation_ref: str | None = None,
            previous_rejection_event_ref: str | None = None,
            reject_reason_resolution_map: Mapping[str, str] | None = None,
        ) -> tuple[HandoffContract, Any, Any, dict[str, Any], str]:
            nonlocal current_proposal_projection, current_projection_hash
            resolution_map = dict(reject_reason_resolution_map or {})
            preview_attempt, preview_fact, claim_ref = preview_claim(generation, identity)
            resolved_paths = tuple(sorted({_handoff_reason_field_path(reason) for reason in resolution_map}))
            proposal_projection = {
                **selected_proposal_projection,
                "generation": generation,
                "semantic_resolution_fields": list(resolved_paths),
            }
            current_proposal_projection = proposal_projection
            projection_receipt = executor._publish(
                proposal_projection,
                purpose="true-multi-agent-handoff-selected-proposal-projection",
            )
            projection_hash = sha256_bytes(canonical_json_bytes(proposal_projection)).removeprefix("sha256:")
            current_projection_hash = projection_hash
            proposed = _proposed_handoff_semantic_snapshot(
                generation=generation,
                selected_projection=selected_proposal_projection,
                resolution_map=resolution_map,
            )
            corrected_scope = tuple(proposed["scope"])
            corrected_acceptance = tuple(proposed["acceptance_criteria"])
            output_schema = dict(proposed["output_schema"])
            # The contract hash cannot be placed in its own schema before the
            # object is constructed.  The exact binding is enforced by the
            # assessment validator; the schema still records the generation
            # and required binding fields without a guessed hash.
            refrozen_component = stable_hash(
                "TRUE_MULTI_AGENT_HANDOFF_REFROZEN_INPUT",
                {
                    "run_id": evidence.run_id,
                    "generation": generation,
                    "receiver_id": identity.agent_id,
                    "source_output_hash": winner.output_hash,
                    "previous_generation_ref": previous_generation_ref,
                    "previous_rejection_event_ref": previous_rejection_event_ref,
                    "reject_reason_resolution_map": resolution_map,
                    "selected_proposal_projection_hash": projection_hash,
                    "task_claim_ref": claim_ref,
                    "fencing_token": preview_attempt.fencing_token,
                },
            )
            contract = HandoffContract(
                handoff_id,
                generation,
                sender.agent_id,
                identity.agent_id,
                task_id,
                "Produce a verified continuation of the selected proposal for the stated goal.",
                corrected_scope,
                ("handoff-receive",),
                (
                    winner.output_ref.removeprefix("cas:"),
                    projection_receipt.object_ref.object_id,
                ),
                (
                    winner.output_hash.removeprefix("sha256:"),
                    projection_hash,
                    refrozen_component,
                ),
                stable_hash("TRUE_MULTI_AGENT_HANDOFF_STATE", {"run": evidence.run_id, "generation": generation}),
                output_schema,
                corrected_acceptance,
                (("generation 1 omitted clarification intentionally",) if incomplete else ("selected proposal is immutable",)),
                (("receiver must reject the incomplete first generation",) if incomplete else ()),
                (("Which exact acceptance checks are mandatory?",) if incomplete else ()),
                min(4000, int(self.policy["max_total_tokens_per_run"])),
                "2099-01-01T00:00:00Z",
                policy_hash_64,
                previous_generation_ref=previous_generation_ref,
                previous_rejection_event_ref=previous_rejection_event_ref,
                reject_reason_resolution_map=resolution_map,
                blackboard_documents=(
                    BlackboardDocumentRecord.model_validate(integrated_context["blackboard"]["contract"]),
                ) if integrated_context is not None else (),
                task_claim_ref=claim_ref,
                fencing_token=preview_attempt.fencing_token,
                max_generations=3,
            )
            receipt = executor._publish(
                {**contract.mapping(), "selected_proposal_projection_hash": projection_hash},
                purpose="true-multi-agent-handoff-contract",
            )
            return contract, receipt, preview_attempt, preview_fact, claim_ref

        reject_first = analysis.requires_handoff_reject or bool(overrides.get("force_handoff_reject"))
        clarify_first = bool(overrides.get("force_handoff_clarification"))
        contract, contract_receipt, reserved_attempt, reserved_claim, task_claim_ref = make_contract(
            1, receiver, incomplete=reject_first or clarify_first
        )
        handoff, offered = Handoff.offer(
            handoff_id,
            1,
            sender.agent_id,
            receiver.agent_id,
            task_id,
            contract.contract_hash,
            policy_hash=policy_hash_64,
            capability_hash=receiver_capability_hash(receiver),
            budget=contract.budget_tokens,
            deadline=contract.deadline,
            high_risk=analysis.risk_level == "high",
            max_generations=contract.max_generations,
            required_capabilities=contract.required_capabilities,
            receiver_capabilities=receiver.capabilities,
            input_freeze_hash=contract.input_freeze_hash,
            output_schema_hash=contract.output_schema_hash,
        )
        stream.append(
            "handoff-offered",
            (
                open_fact,
                {
                    **contract.offered_fact(contract_object_ref=contract_receipt.object_ref.reference_id),
                    "selected_proposal_projection_hash": current_projection_hash,
                },
                offered,
            ),
            actor=sender.agent_id,
            proofs=(contract_receipt,),
        )

        def validate_assessment(value: Mapping[str, Any]) -> None:
            _require_exact_handoff_binding(
                value,
                expected_contract_hash=contract.contract_hash,
                expected_generation=handoff.generation,
                expected_projection_hash=current_projection_hash,
            )
            accepted_value = _require_bool(value, "accept")
            _require_string(value, "reason")
            missing = value.get("missing_information")
            if accepted_value and missing in ([], "", None):
                return
            _require_text_or_strings(value, "missing_information", maximum=8)

        def assess_contract(*, incomplete: bool) -> AgentCallResult:
            return self._call_with_bounded_handoff_binding_repair(
                executor,
                evidence,
                receiver,
                task_id=f"handoff-contract-assessment-{handoff.generation}",
                kind="review",
                contract="Assess the exact frozen Handoff contract. Return accept, reason, and missing_information.",
                prompt=(
                    "Reject this generation because its open_questions and residual risk explicitly make it incomplete. "
                    if incomplete
                    else "Accept only if the corrected generation resolves every prior rejection reason and is executable. "
                ) + (
                    f"Return generation={handoff.generation} and contract_hash={contract.contract_hash} exactly, "
                    "without normalization. The selected proposal projection below is the only proposal content to "
                    "use; it is hash-bound to the frozen contract input. "
                ) + json.dumps(
                    {
                        "contract": contract.mapping(),
                        "selected_proposal_projection": dict(current_proposal_projection),
                        "selected_proposal_projection_hash": current_projection_hash,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                context={
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "contract_hash": contract.contract_hash,
                    "contract_object_ref": contract_receipt.object_ref.reference_id,
                    "receiver_agent_id": receiver.agent_id,
                    "prior_generation_closed": handoff.generation > 1,
                    "input_freeze_hash": contract.input_freeze_hash,
                    "selected_proposal_projection_hash": current_projection_hash,
                    "task_claim_ref": contract.task_claim_ref,
                },
                validate=validate_assessment,
                expected_contract_hash=contract.contract_hash,
                expected_generation=handoff.generation,
            )

        def structured_rejection_reasons(value: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
            missing = value.get("missing_information")
            if isinstance(missing, str) and missing.strip():
                values = (missing.strip(),)
            elif isinstance(missing, list):
                values = tuple(str(item).strip() for item in missing if str(item).strip())
            else:
                values = ()
            parsed: list[dict[str, str]] = []
            for item in values:
                fields = [part.strip() for part in item.split("|", 2)]
                if len(fields) < 2 or not fields[0] or not fields[1]:
                    raise DynamicCollaborationError(
                        "Handoff assessment missing_information must use CODE|field_path|detail"
                    )
                parsed.append({
                    "reason_code": fields[0].upper()[:80],
                    "field_path": fields[1][:160],
                    "detail_hash": sha256_bytes((fields[2] if len(fields) > 2 else "").encode()),
                })
            reason = str(value.get("reason", "")).strip()
            if not parsed:
                parsed.append({
                    "reason_code": "UNSPECIFIED_CONTRACT_REJECTION",
                    "field_path": "assessment.reason",
                    "detail_hash": sha256_bytes(reason.encode()),
                })
            return tuple(parsed)

        def rejection_reasons(value: Mapping[str, Any]) -> tuple[str, ...]:
            structured = structured_rejection_reasons(value)
            return tuple(
                f"{item['reason_code']}|{item['field_path']}|{item['detail_hash']}"
                for item in structured
            )

        repair_signatures: set[str] = set()

        def open_successor(
            transition_ref: Mapping[str, Any],
            prior_contract_ref: str,
            reasons: tuple[str, ...],
        ) -> AgentCallResult:
            nonlocal handoff, receiver, contract, contract_receipt
            nonlocal reserved_attempt, reserved_claim, task_claim_ref
            def record_no_progress(reason_code: str, *, semantic_delta: Mapping[str, Any] | None = None) -> None:
                delta = dict(semantic_delta or {})
                no_progress = {
                    "schema": "HANDOFF_REPAIR_NO_PROGRESS_V1",
                    "event_type": "handoff.repair.no-progress",
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "contract_hash": contract.contract_hash,
                    "generation_hash": handoff.generation_hash,
                    "selected_proposal_projection_hash": current_projection_hash,
                    "reason_signature": stable_hash(
                        "HANDOFF_REPAIR_NO_PROGRESS_REASON",
                        {"reasons": list(reasons), "reason_code": reason_code},
                    ),
                    "reason_code": reason_code,
                    "semantic_delta_hash": stable_hash(
                        "HANDOFF_REPAIR_NO_PROGRESS_DELTA",
                        delta,
                    ),
                    "changed_paths": list(delta.get("changed_paths", ())),
                    "resolved_field_paths": list(delta.get("resolved_field_paths", ())),
                    "reason_count": len(set(reasons)),
                    "terminal_disposition": "FAILED_NO_PROGRESS",
                }
                close_fact = self._protocol_close(
                    evidence, handoff_id, obligation, "FAILED_NO_PROGRESS"
                )
                stream.append(
                    "handoff-repair-no-progress",
                    (no_progress, close_fact),
                    actor="handoff-terminal-coordinator",
                )
                raise DynamicCollaborationError("Handoff repair made no semantic progress")

            try:
                corrections = _structured_handoff_corrections(reasons)
            except DynamicCollaborationError:
                # No model/provider call is allowed until an enumerated,
                # field-level correction can be proven.
                record_no_progress("UNSUPPORTED_STRUCTURED_CORRECTION")
            resolution_map = {
                reason: json.dumps(
                    correction,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for reason, correction in zip(reasons, corrections, strict=False)
            }
            before_semantics = _handoff_semantic_snapshot(contract, current_proposal_projection)
            proposed_semantics = _proposed_handoff_semantic_snapshot(
                generation=handoff.generation + 1,
                selected_projection=selected_proposal_projection,
                resolution_map=resolution_map,
            )
            try:
                semantic_delta = _verified_handoff_semantic_delta(
                    before_semantics, proposed_semantics, reasons,
                    corrections=corrections,
                )
            except DynamicCollaborationError:
                record_no_progress("CORRECTION_VALUE_NOT_VERIFIED")
            semantic_delta_hash, progress_signature = _handoff_repair_progress_signature(
                reasons,
                selected_proposal_hash=winner.output_hash,
                semantic_delta=semantic_delta,
            )
            if progress_signature in repair_signatures:
                record_no_progress("REPEATED_VERIFIED_DELTA", semantic_delta=semantic_delta)
            repair_signatures.add(progress_signature)
            decision, candidates = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id=f"handoff-receive-generation-{handoff.generation + 1}",
                required_capabilities=("handoff-receive",),
                slots=1,
                candidate_tasks=("handoff-contract-revalidation", "handoff-execution"),
                exclusions=(sender.agent_id,),
                overrides=overrides,
            )
            receiver = candidates[0]
            resolution_hash = stable_hash(
                "HANDOFF_REJECT_REASON_RESOLUTION",
                {**resolution_map, "semantic_delta_hash": semantic_delta_hash},
            )
            next_contract, next_receipt, next_reserved_attempt, next_reserved_claim, next_claim_ref = make_contract(
                handoff.generation + 1,
                receiver,
                incomplete=False,
                previous_generation_ref=prior_contract_ref,
                previous_rejection_event_ref=str(transition_ref["event_id"]),
                reject_reason_resolution_map=resolution_map,
            )
            actual_semantics = _handoff_semantic_snapshot(next_contract, current_proposal_projection)
            if actual_semantics != proposed_semantics:
                raise DynamicCollaborationError("Handoff successor semantic delta did not match its frozen contract")
            next_handoff, opened_generation = handoff.new_generation(
                specification_hash=next_contract.contract_hash,
                policy_hash=policy_hash_64,
                capability_hash=receiver_capability_hash(receiver),
                budget=next_contract.budget_tokens,
                deadline=next_contract.deadline,
                high_risk=analysis.risk_level == "high",
                receiver_id=receiver.agent_id,
                required_capabilities=next_contract.required_capabilities,
                receiver_capabilities=receiver.capabilities,
                input_freeze_hash=next_contract.input_freeze_hash,
                output_schema_hash=next_contract.output_schema_hash,
                previous_generation_ref=prior_contract_ref,
                previous_rejection_event_ref=str(transition_ref["event_id"]),
                reject_reason_resolution_hash=resolution_hash,
            )
            stream.append(
                "handoff-successor-generation-offered",
                (
                    {
                        **next_contract.offered_fact(contract_object_ref=next_receipt.object_ref.reference_id),
                        "selected_proposal_projection_hash": current_projection_hash,
                    },
                    {
                        "schema": "HANDOFF_RECEIVER_CAPABILITY_REVALIDATED_V1",
                        "handoff_id": handoff_id,
                        "generation": next_handoff.generation,
                        "receiver_id": receiver.agent_id,
                        "required_capabilities": list(next_contract.required_capabilities),
                        "actual_capabilities": list(receiver.capabilities),
                        "capability_hash": receiver_capability_hash(receiver),
                        "source_decision_id": decision.decision_id,
                        "semantic_delta_hash": semantic_delta_hash,
                    "changed_paths": semantic_delta["changed_paths"],
                    "resolved_field_paths": semantic_delta["resolved_field_paths"],
                    "verified_corrections": semantic_delta["verified_corrections"],
                    "result": "PASSED",
                    },
                    opened_generation,
                ),
                actor="handoff-generation-command-handler",
                proofs=(next_receipt,),
            )
            handoff = next_handoff
            contract = next_contract
            contract_receipt = next_receipt
            reserved_attempt = next_reserved_attempt
            reserved_claim = next_reserved_claim
            task_claim_ref = next_claim_ref
            return assess_contract(incomplete=False)

        assessment = assess_contract(incomplete=reject_first or clarify_first)
        if (reject_first or clarify_first) and bool(assessment.value["accept"]):
            raise DynamicCollaborationError("receiver accepted a deliberately incomplete Handoff generation")

        controlled_verification_failure_used = False
        while True:
            while not bool(assessment.value["accept"]):
                prior_contract_ref = contract_receipt.object_ref.reference_id
                reasons = rejection_reasons(assessment.value)
                if clarify_first and handoff.generation == 1:
                    handoff, clarified = handoff.clarify(receiver.agent_id, assessment.output_hash)
                    handoff, closed = handoff.close_for_new_generation(
                        receiver.agent_id, reason_ref=assessment.output_hash
                    )
                    _, transition_refs = stream.append(
                        "handoff-generation-clarification-closed",
                        (
                            {**clarified, "assessment_call_id": assessment.call_id},
                            {**closed, "event_type": "handoff.generation.closed"},
                        ),
                        actor=receiver.agent_id,
                    )
                    transition_ref = transition_refs[-1]
                else:
                    rejected_reason_hash = sha256_bytes(str(assessment.value["reason"]).encode())
                    handoff, rejected = handoff.reject(
                        receiver.agent_id,
                        "receiver rejected contract; reason_hash=" + rejected_reason_hash,
                    )
                    _, transition_refs = stream.append(
                        "handoff-generation-rejected-closed",
                        (
                            {**rejected, "event_type": "handoff.rejected", "assessment_call_id": assessment.call_id},
                            {
                                "schema": "HANDOFF_REJECTED_GENERATION_CLOSED_V1",
                                "handoff_id": handoff_id,
                                "closed_generation": handoff.generation,
                                "generation_hash": handoff.generation_hash,
                                "old_generation_reusable": False,
                                "generation_permanently_closed": True,
                            },
                        ),
                        actor=receiver.agent_id,
                    )
                    transition_ref = transition_refs[0]
                if handoff.generation >= handoff.max_generations:
                    limit_fact = {
                        "schema": "HANDOFF_GENERATION_LIMIT_REACHED_V1",
                        "handoff_id": handoff_id,
                        "generation": handoff.generation,
                        "contract_hash": contract.contract_hash,
                        "generation_hash": handoff.generation_hash,
                        "selected_proposal_projection_hash": current_projection_hash,
                        "max_generations": handoff.max_generations,
                        "prior_generation_hash": handoff.generation_hash,
                        "terminal_disposition": "FAILED_GENERATION_LIMIT_REACHED",
                    }
                    close_fact = self._protocol_close(
                        evidence, handoff_id, obligation, "FAILED_GENERATION_LIMIT_REACHED"
                    )
                    stream.append(
                        "handoff-generation-limit-failed",
                        (limit_fact, close_fact),
                        actor="handoff-terminal-coordinator",
                    )
                    raise DynamicCollaborationError("Handoff generation limit reached")
                assessment = open_successor(transition_ref, prior_contract_ref, reasons)

            acknowledgement = contract.acknowledge(
                receiver_id=receiver.agent_id,
                occurred_at=now_rfc3339(),
                expected_contract_hash=contract.contract_hash,
                available_capabilities=receiver.capabilities,
                available_input_refs=contract.input_refs,
                available_blackboard_document_ids=tuple(
                    item.document_id for item in contract.blackboard_documents
                ),
                accepted_budget_tokens=contract.budget_tokens,
                verified_objective_ref=contract.objective_ref,
                verified_scope_ref=contract.scope_ref,
                acceptance_criteria_confirmed=bool(contract.acceptance_criteria),
                verified_policy_hash=policy_hash_64,
                verified_current_state_ref=contract.current_state_ref,
                verified_output_schema_hash=contract.output_schema_hash,
            )
            if acknowledgement.status != "ACCEPTED":
                raise DynamicCollaborationError(
                    "machine-verifiable Handoff acknowledgement rejected the assessed contract"
                )
            stream.append(
                "handoff-contract-acknowledged",
                ({
                    "schema": "HANDOFF_CONTRACT_ACKNOWLEDGED_V1",
                    **dataclasses.asdict(acknowledgement),
                },),
                actor=receiver.agent_id,
            )
            handoff, accepted = handoff.accept(receiver.agent_id, now=now_rfc3339())
            handoff, claim_pending = handoff.mark_claim_pending(
                receiver.agent_id,
                task_claim_ref=task_claim_ref,
                fencing_token=reserved_attempt.fencing_token,
            )
            task, attempt, claim = task.claim(
                claim_command_id="claim-" + handoff_id + f"-{handoff.generation}",
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id=receiver.agent_id,
                expected_stream_version=task.stream_version,
            )
            if attempt.fencing_token != reserved_attempt.fencing_token or stable_hash(
                "HANDOFF_TASK_CLAIM_RESERVATION", claim
            ) != task_claim_ref:
                raise DynamicCollaborationError("committed Handoff Task Claim differs from frozen reservation")
            handoff, bound = handoff.bind_claim(task, attempt.fencing_token)
            handoff, executing = handoff.execute(receiver.agent_id)
            stream.append(
                "handoff-accepted-claim-pending-executing",
                (
                    {
                        **accepted,
                        "event_type": "handoff.accepted",
                        "assessment_call_id": assessment.call_id,
                        "old_acceptance_reused": False,
                    },
                    claim_pending,
                    claim,
                    bound,
                    executing,
                ),
                actor=receiver.agent_id,
            )

            def validate_delivery(value: Mapping[str, Any]) -> None:
                _validate_handoff_delivery(
                    value,
                    expected_contract_hash=contract.contract_hash,
                    expected_generation=handoff.generation,
                    expected_projection_hash=current_projection_hash,
                    expected_source_output_hash=winner.output_hash,
                )

            delivery = self._call(
                executor,
                evidence,
                receiver,
                task_id=f"handoff-execution-generation-{handoff.generation}",
                kind="proposal",
                contract=(
                    "Execute the accepted Handoff. Return agent_id, kind=proposal, deliverable, "
                    "source_output_hash, acceptance_checks, contract_hash, and generation. "
                    "The contract_hash and generation must be exact; acceptance_checks must contain "
                    "one to eight non-empty strings."
                ),
                prompt=(
                    f"Execute generation {handoff.generation} of contract {contract.contract_hash}. "
                    f"Return contract_hash={contract.contract_hash!r} and generation={handoff.generation} exactly. "
                    f"The source_output_hash must be exactly {winner.output_hash}. Return no more than "
                    "eight acceptance_checks, each a non-empty string. Selected proposal projection: "
                    + json.dumps(
                        {**dict(current_proposal_projection), "selected_proposal_projection_hash": current_projection_hash},
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                context={
                    "contract_object_ref": contract_receipt.object_ref.reference_id,
                    "contract_hash": contract.contract_hash,
                    "handoff_generation": handoff.generation,
                    "task_attempt_id": attempt.task_attempt_id,
                    "task_claim_ref": task_claim_ref,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                    "output_schema_hash": contract.output_schema_hash,
                    "selected_proposal_projection_hash": current_projection_hash,
                },
                validate=validate_delivery,
            )
            schema_validation_hash = stable_hash(
                "HANDOFF_OUTPUT_SCHEMA_VALIDATION",
                {
                    "contract_hash": contract.contract_hash,
                    "output_schema_hash": contract.output_schema_hash,
                    "delivery_output_hash": delivery.output_hash,
                    "delivery_value": dict(delivery.value),
                },
            )
            _, verifiers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id=f"handoff-verification-generation-{handoff.generation}",
                required_capabilities=("verification", "review"),
                slots=1,
                candidate_tasks=("handoff-verification",),
                author_conflicts=(sender.agent_id, receiver.agent_id),
                overrides=overrides,
            )
            verifier = verifiers[0]

            def validate_verification(value: Mapping[str, Any]) -> None:
                _require_bool(value, "accepted")
                _require_string(value, "reason")
                _require_verification_checks(value, maximum=8)

            verification = self._call(
                executor,
                evidence,
                verifier,
                task_id=f"handoff-verification-generation-{handoff.generation}",
                kind="review",
                contract=(
                    "Independently verify the exact Handoff delivery. Return agent_id, kind=review, accepted "
                    "as a boolean, reason as a non-empty string, and checks as one to eight non-empty strings."
                ),
                prompt=(
                    "The delivery_object_hash and contract_hash are distinct object identities; do not compare them "
                    "for equality. Verify the delivery JSON against the frozen output_schema, acceptance_criteria, "
                    "and expected_source_output_hash. Return checks as a JSON list of one to eight non-empty strings. "
                    + json.dumps(
                        {
                            "delivery_object_hash": delivery.output_hash,
                            "contract_hash": contract.contract_hash,
                            "expected_source_output_hash": winner.output_hash,
                            "output_schema": dict(contract.output_schema),
                            "acceptance_criteria": list(contract.acceptance_criteria),
                            "delivery": dict(delivery.value),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                context={
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "sender_agent_id": sender.agent_id,
                    "receiver_agent_id": receiver.agent_id,
                    "verifier_independent": verifier.agent_id not in {sender.agent_id, receiver.agent_id},
                    "delivery_output_hash": delivery.output_hash,
                    "output_schema_hash": contract.output_schema_hash,
                },
                validate=validate_verification,
            )
            provider_accepted = bool(verification.value["accepted"])
            effective_accepted = provider_accepted
            if bool(overrides.get("force_handoff_verification_failure_once")) and not controlled_verification_failure_used:
                effective_accepted = False
                controlled_verification_failure_used = True
            if defer_after_execution_prepared:
                if handoff.generation != 2 or not effective_accepted or integrated_context is None:
                    raise DynamicCollaborationError(
                        "integrated restart requires an accepted generation-2 Handoff with a positive independent verdict"
                    )
                main_task: TaskAggregate = integrated_context["task"]
                main_attempt = integrated_context["attempt"]
                blackboard = dict(integrated_context["blackboard"])
                prepared_fact = {
                    "schema": "HANDOFF_POST_RESTART_CONTINUATION_PREPARED_V1",
                    "event_type": "handoff.post-restart-continuation.prepared",
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "handoff_state": handoff.state.value,
                    "authoritative_submission_committed": False,
                    "authoritative_verification_committed": False,
                    "delivery_call_id": delivery.call_id,
                    "delivery_output_ref": delivery.output_ref,
                    "delivery_output_hash": delivery.output_hash,
                    "schema_validation_evidence_hash": schema_validation_hash,
                    "verification_call_id": verification.call_id,
                    "verification_output_ref": verification.output_ref,
                    "verification_output_hash": verification.output_hash,
                    "verifier_id": verifier.agent_id,
                    "verifier_independent": verifier.agent_id not in {sender.agent_id, receiver.agent_id},
                    "provider_verdict": provider_accepted,
                    "restart_required_before_submission": True,
                }
                stream.append(
                    "handoff-post-restart-continuation-prepared",
                    (prepared_fact,),
                    actor=verifier.agent_id,
                )
                return {
                    "schema": "INTEGRATED_HANDOFF_RESTART_CONTINUATION_V1",
                    "integrated_continuation": True,
                    "handoff_id": handoff_id,
                    "handoff_stream_id": f"protocol/{evidence.run_id}/handoff/{handoff_id}",
                    "handoff_generation": handoff.generation,
                    "handoff_generation_hash": handoff.generation_hash,
                    "handoff_state": handoff.state.value,
                    "handoff_protocol_id": handoff_id,
                    "handoff_obligation_id": obligation,
                    "sender_id": sender.agent_id,
                    "receiver_id": receiver.agent_id,
                    "verifier_id": verifier.agent_id,
                    "handoff_task": {
                        "task_id": task.task_id,
                        "specification_hash": task.specification_hash,
                        "stream_version": task.stream_version,
                        "claim_generation": task.claim_generation,
                        "task_attempt_id": attempt.task_attempt_id,
                        "claim_command_id": attempt.claim_command_id,
                        "holder_agent_id": attempt.holder_agent_id,
                        "lease_id": attempt.lease_id,
                        "lease_expires_at": attempt.lease_expires_at,
                        "fencing_token": attempt.fencing_token,
                    },
                    "main_task": {
                        "task_id": main_task.task_id,
                        "specification_hash": main_task.specification_hash,
                        "stream_version": main_task.stream_version,
                        "claim_generation": main_task.claim_generation,
                        "task_attempt_id": main_attempt.task_attempt_id,
                        "claim_command_id": main_attempt.claim_command_id,
                        "holder_agent_id": main_attempt.holder_agent_id,
                        "lease_id": main_attempt.lease_id,
                        "lease_expires_at": main_attempt.lease_expires_at,
                        "fencing_token": main_attempt.fencing_token,
                    },
                    "lease_protocol_id": integrated_context["protocol_id"],
                    "lease_obligation_id": integrated_context["obligation_id"],
                    "blackboard": blackboard,
                    "contract_hash": contract.contract_hash,
                    "contract_ref": contract_receipt.object_ref.reference_id,
                    "output_schema_hash": contract.output_schema_hash,
                    "delivery_call_id": delivery.call_id,
                    "delivery_output_ref": delivery.output_ref,
                    "delivery_output_hash": delivery.output_hash,
                    "schema_validation_evidence_hash": schema_validation_hash,
                    "verification_call_id": verification.call_id,
                    "verification_output_ref": verification.output_ref,
                    "verification_output_hash": verification.output_hash,
                    "provider_verdict": provider_accepted,
                    "prepared_event_schema": prepared_fact["schema"],
                }
            handoff, submitted_handoff = handoff.submit_fenced(
                receiver.agent_id,
                delivery.output_hash,
                task=task,
                output_schema_hash=contract.output_schema_hash,
                schema_validation_evidence_hash=schema_validation_hash,
            )
            task, submitted_task = task.submit(attempt.fencing_token, delivery.output_hash)
            handoff, verification_fact = handoff.verify(
                verifier.agent_id,
                accepted=effective_accepted,
                verification_evidence_hash=verification.output_hash,
            )
            if effective_accepted:
                task, task_accepted = task.accept(
                    attempt.fencing_token,
                    artifact_hash=delivery.output_hash,
                    policy_hash=self.policy_hash,
                    acceptance_evidence_refs=(verification.output_ref, verification.output_hash),
                )
                close_fact = self._protocol_close(evidence, handoff_id, obligation, "VERIFIED")
                stream.append(
                    "handoff-verified",
                    (
                        {**submitted_handoff, "event_type": "handoff.submitted", "delivery_call_id": delivery.call_id},
                        submitted_task,
                        {
                            **verification_fact,
                            "event_type": "handoff.verified",
                            "verification_call_id": verification.call_id,
                            "provider_verdict": provider_accepted,
                            "effective_verdict": effective_accepted,
                        },
                        task_accepted,
                        close_fact,
                    ),
                    actor=verifier.agent_id,
                )
                return None

            task, failed_attempt = task.fail_attempt(
                attempt.fencing_token, "HANDOFF_INDEPENDENT_VERIFICATION_REJECTED"
            )
            _, rework_refs = stream.append(
                "handoff-verification-rework-required",
                (
                    {**submitted_handoff, "event_type": "handoff.submitted", "delivery_call_id": delivery.call_id},
                    submitted_task,
                    {
                        **verification_fact,
                        "event_type": "handoff.verification.rejected",
                        "verification_call_id": verification.call_id,
                        "provider_verdict": provider_accepted,
                        "effective_verdict": effective_accepted,
                        "controlled_failure_injected": provider_accepted != effective_accepted,
                    },
                    failed_attempt,
                ),
                actor=verifier.agent_id,
            )
            if handoff.generation >= handoff.max_generations:
                limit_fact = {
                    "schema": "HANDOFF_GENERATION_LIMIT_REACHED_V1",
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "contract_hash": contract.contract_hash,
                    "generation_hash": handoff.generation_hash,
                    "selected_proposal_projection_hash": current_projection_hash,
                    "max_generations": handoff.max_generations,
                    "prior_generation_hash": handoff.generation_hash,
                    "terminal_disposition": "FAILED_GENERATION_LIMIT_REACHED",
                }
                close_fact = self._protocol_close(
                    evidence, handoff_id, obligation, "FAILED_GENERATION_LIMIT_REACHED"
                )
                stream.append(
                    "handoff-verification-generation-limit-failed",
                    (limit_fact, close_fact),
                    actor="handoff-terminal-coordinator",
                )
                raise DynamicCollaborationError("Handoff verification failed at generation limit")
            prior_contract_ref = contract_receipt.object_ref.reference_id
            reasons = tuple(
                dict.fromkeys(
                    (
                        str(verification.value["reason"]),
                        *_require_verification_checks(verification.value, maximum=8),
                    )
                )
            )
            assessment = open_successor(rework_refs[2], prior_contract_ref, reasons)

    def _provider_recovery(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> None:
        """Exercise bounded Production recovery paths and reassign the failed Task."""

        decision_a, selected_a = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="provider-recovery-owner",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("provider-recovery-owner",),
            overrides=overrides,
        )
        worker_a = selected_a[0]
        task_id = "provider-recovery-task-" + evidence.run_id
        task = TaskAggregate(task_id, stable_hash("TRUE_MULTI_AGENT_PROVIDER_RECOVERY_TASK", {"run": evidence.run_id}))
        protocol_id = "provider-recovery-" + stable_hash(
            "TRUE_MULTI_AGENT_PROVIDER_RECOVERY_PROTOCOL", {"run": evidence.run_id}
        )[:24]
        obligation = "obligation-" + protocol_id
        task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        open_fact = self._protocol_open(evidence, "provider_recovery", protocol_id, obligation, decision_a.decision_id)
        task_stream.append(
            "provider-recovery-task-created",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task_id,
                    "specification_hash": task.specification_hash,
                    "source_decision_id": decision_a.decision_id,
                    "recovery_paths": [
                        "ABORTED_BEFORE_SEND",
                        "TIMEOUT_AFTER_INVOCATION_STARTED",
                        "FAILED_CONFIRMED",
                        "ACK_LOST_AFTER_REMOTE_SUCCESS",
                    ],
                },
            ),
            actor="provider-recovery-command-handler",
        )
        expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(time.time()) + 300))
        task, attempt_a, claim_a = task.claim(
            claim_command_id="provider-recovery-claim-a-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_a.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("provider-recovery-owner-claimed", (claim_a,), actor=worker_a.agent_id)

        pre_send = executor.inject_worker_loss(
            worker_a,
            task_id="provider-recovery-pre-send-failure",
            after_invocation_started=False,
        )
        if (
            pre_send["attempt_disposition"] != "ABORTED_BEFORE_SEND"
            or pre_send["physical_send_count"] != 0
            or pre_send["settlement_state"] != "SETTLED"
        ):
            raise DynamicCollaborationError("pre-send recovery path violated zero-send settlement")

        timeout = executor.inject_worker_loss(
            worker_a,
            task_id="provider-timeout-after-invocation-started",
            after_invocation_started=True,
        )
        if (
            timeout["attempt_disposition"] != "MAY_HAVE_BEEN_SENT"
            or timeout["outcome_state"] != "OUTCOME_UNKNOWN"
            or timeout["settlement_state"] != "RECONCILING"
            or timeout["physical_send_count"] != 0
        ):
            raise DynamicCollaborationError("after-start timeout/loss did not enter conservative reconciliation")
        transfer = MonitoringTransfer.create(
            "monitoring-transfer-" + stable_hash(
                "TRUE_MULTI_AGENT_PROVIDER_TIMEOUT_MONITORING", {"run": evidence.run_id}
            )[:24],
            evidence.run_id,
            "incident-provider-timeout-" + evidence.run_id,
            (str(timeout["effect_id"]),),
            self.policy_hash,
        )
        transfer, accepted_monitoring = transfer.accept_successor(authority="provider-recovery-monitor-owner")
        CanonicalStream(
            journal,
            evidence.run_id,
            "incident-provider-timeout-" + evidence.run_id,
            self.policy_hash,
        ).append(
            "provider-timeout-monitoring-accepted",
            (accepted_monitoring,),
            actor="provider-recovery-monitor-owner",
        )
        transfer, source_ack = transfer.acknowledge_source()
        timeout_state = executor.gateway.settle_unknown_by_policy(
            str(timeout["effect_id"]), str(timeout["effect_attempt_id"])
        )
        for item in executor.recovery_attempts:
            if item["effect_id"] == timeout["effect_id"]:
                item.update(
                    {
                        "settlement_state": timeout_state.settlement_state.value,
                        "settlement_basis": timeout_state.settlement_basis.value,
                        "monitoring_transfer_id": transfer.transfer_id,
                        "terminal_blocking_exposure_count": 0,
                    }
                )
        CanonicalStream(
            journal,
            evidence.run_id,
            f"effect/{evidence.run_id}/{timeout['effect_id']}",
            self.policy_hash,
        ).append(
            "provider-timeout-reconciled-by-policy",
            (
                {
                    "schema": "PROVIDER_RECONCILIATION_REQUESTED_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "reason": "TIMEOUT_OR_WORKER_LOSS_AFTER_INVOCATION_STARTED",
                    "automatic_retry_authorized": False,
                },
                {
                    "schema": "PROVIDER_RECONCILIATION_QUERY_RECORDED_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "query_result": "STATUS_ENDPOINT_UNAVAILABLE",
                    "not_found_interpreted_as_not_executed": False,
                    "new_transmission_performed": False,
                },
                {
                    "schema": "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "prior_outcome_state": "OUTCOME_UNKNOWN",
                    "state": timeout_state.mapping(),
                    "disposition": "SETTLED_WITH_MONITORING_TRANSFER_AND_PERMANENT_RETRY_BLOCK",
                    "automatic_retry_performed": False,
                    "new_effect_created": False,
                    "monitoring_transfer_id": transfer.transfer_id,
                    "monitoring_responsibility": transfer.successor_stream_id,
                    "successor_authority": transfer.successor_authority,
                    "terminal_effect_exposure_blocker_transferred": True,
                    "terminal_blocking_exposure_count": 0,
                },
                source_ack,
            ),
            actor="effect-reconciliation-policy",
        )

        explicit_failure = executor.inject_explicit_remote_failure(
            worker_a,
            task_id="provider-explicit-remote-failure",
        )
        if (
            explicit_failure["physical_send_count"] != 1
            or explicit_failure["outcome_state"] != "FAILED_CONFIRMED"
            or explicit_failure["settlement_state"] != "SETTLED"
            or explicit_failure["unresolved_transmission_exposure_count"] != 0
        ):
            raise DynamicCollaborationError("explicit remote failure was not authoritatively settled")

        ack_events = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
            and event.payload.get("schema") == "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1"
        ]
        if len(ack_events) != 1:
            raise DynamicCollaborationError("Provider recovery requires exactly one real ACK-loss transition")
        ack_event = ack_events[0]
        ack_effect_id = str(ack_event.payload["effect_id"])
        ack_attempt_id = str(ack_event.payload["effect_attempt_id"])
        ack_settlements = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
            and event.payload.get("schema") == "EFFECT_RECONCILIATION_SETTLED_V1"
            and event.payload.get("effect_id") == ack_effect_id
            and event.payload.get("ack_lost_reconciled") is True
        ]
        if len(ack_settlements) != 1:
            raise DynamicCollaborationError("ACK-loss success did not reconcile from authoritative observation")

        task, failed_a = task.fail_attempt(
            attempt_a.fencing_token,
            "PROVIDER_FAILED_CONFIRMED_AFTER_BOUNDED_RECOVERY_MATRIX",
        )
        _, failure_refs = task_stream.append(
            "provider-recovery-owner-attempt-terminated",
            (
                failed_a,
                {
                    "schema": "TASK_REASSIGNMENT_REQUIRED_V1",
                    "task_id": task_id,
                    "prior_agent_id": worker_a.agent_id,
                    "prior_attempt_id": attempt_a.task_attempt_id,
                    "failure_event_refs": [ack_event.event_id, ack_settlements[0].event_id],
                    "confirmed_failure_effect_id": explicit_failure["effect_id"],
                    "candidate_set_recomputation_required": True,
                },
            ),
            actor="provider-recovery-controller",
        )

        decision_b, selected_b = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="provider-recovery-reassignment",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("provider-recovery-reassignment",),
            exclusions=(worker_a.agent_id,),
            overrides=overrides,
        )
        worker_b = selected_b[0]
        if worker_b.agent_id == worker_a.agent_id or decision_b.decision_id == decision_a.decision_id:
            raise DynamicCollaborationError("Provider recovery did not recompute a distinct owner/Decision")
        reassignment = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="PROVIDER_FAILED_CONFIRMED_AFTER_RECONCILIATION",
        )
        task_stream.append(
            "provider-recovery-reassignment-decided",
            ({
                **reassignment,
                "failure_event_ref": failure_refs[-1]["event_id"],
                "candidate_set_recomputed": True,
                "prior_provider_health": "FAILED_CONFIRMED",
                "current_provider_health": "ELIGIBLE",
                "retry_policy": "DIFFERENT_AGENT_NEW_TASK_ATTEMPT_NEW_LOGICAL_EFFECT",
            },),
            actor="scheduler",
        )
        expires_b = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(time.time()) + 600))
        task, attempt_b, claim_b = task.claim(
            claim_command_id="provider-recovery-claim-b-" + evidence.run_id,
            lease_expires_at=expires_b,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("provider-recovery-new-owner-claimed", (claim_b,), actor=worker_b.agent_id)

        def validate_completion(value: Mapping[str, Any]) -> None:
            _require_string(value, "result")
            _require_text_or_strings(value, "evidence", maximum=8)

        completion = self._call(
            executor,
            evidence,
            worker_b,
            task_id="provider-recovery-reassignment",
            kind="proposal",
            contract="Complete the read-only reassigned Provider recovery task; return result and evidence without claiming authority over settlement.",
            prompt=(
                f"Complete reassigned task {task_id}. Prior Agent {worker_a.agent_id} was terminated only after the "
                "Provider failure matrix was settled. Return concise result and evidence."
            ),
            context={
                "task_id": task_id,
                "prior_agent_id": worker_a.agent_id,
                "current_agent_id": worker_b.agent_id,
                "prior_attempt_id": attempt_a.task_attempt_id,
                "current_attempt_id": attempt_b.task_attempt_id,
                "prior_failure_event_ref": failure_refs[-1]["event_id"],
                "reassignment_decision_id": decision_b.decision_id,
                "current_claim_generation": attempt_b.claim_generation,
                "current_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
            },
            validate=validate_completion,
        )
        task, submitted = task.submit(attempt_b.fencing_token, completion.output_hash)
        task, accepted = task.accept(
            attempt_b.fencing_token,
            artifact_hash=completion.output_hash,
            policy_hash=self.policy_hash,
            acceptance_evidence_refs=(completion.output_ref, completion.output_hash),
        )
        unchanged, stale_rejection = task.submit_or_reject(attempt_a.fencing_token, completion.output_hash)
        if unchanged != task or stale_rejection.get("business_state_committed") is not False:
            raise DynamicCollaborationError("old Provider recovery owner changed accepted business state")
        close_fact = self._protocol_close(evidence, protocol_id, obligation, "RECOVERED_AND_REASSIGNED")
        task_stream.append(
            "provider-recovery-completed",
            (
                {**submitted, "provider_call_id": completion.call_id, "provider_output_ref": completion.output_ref},
                accepted,
                stale_rejection,
                {
                    "schema": "PROVIDER_RECOVERY_ACK_LOST_VERIFIED_V1",
                    "effect_id": ack_effect_id,
                    "effect_attempt_id": ack_attempt_id,
                    "outcome_unknown_event_ref": ack_event.event_id,
                    "settlement_event_ref": ack_settlements[0].event_id,
                    "remote_succeeded_observed": True,
                    "duplicate_transmission_count": 0,
                },
                {
                    "schema": "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1",
                    "protocol_id": protocol_id,
                    "task_id": task_id,
                    "pre_send_effect_id": pre_send["effect_id"],
                    "timeout_effect_id": timeout["effect_id"],
                    "explicit_failure_effect_id": explicit_failure["effect_id"],
                    "ack_lost_effect_id": ack_effect_id,
                    "effect_attempt_ids": [
                        pre_send["effect_attempt_id"],
                        timeout["effect_attempt_id"],
                        explicit_failure["effect_attempt_id"],
                        ack_attempt_id,
                    ],
                    "physical_send_counts": [0, 0, 1, 1],
                    "max_physical_sends_per_attempt": 1,
                    "sdk_retry_count": 0,
                    "http_retry_count": 0,
                    "fallback_count": 0,
                    "unsettled_usage_count": 0,
                    "terminal_blocking_exposure_count": 0,
                    "monitoring_transferred_exposure_count": 1,
                    "initial_decision_id": decision_a.decision_id,
                    "reassignment_decision_id": decision_b.decision_id,
                    "prior_owner_id": worker_a.agent_id,
                    "new_owner_id": worker_b.agent_id,
                    "prior_attempt_id": attempt_a.task_attempt_id,
                    "new_attempt_id": attempt_b.task_attempt_id,
                    "prior_claim_generation": attempt_a.claim_generation,
                    "new_claim_generation": attempt_b.claim_generation,
                    "prior_fencing_token_hash": sha256_bytes(attempt_a.fencing_token.encode()),
                    "new_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
                    "late_prior_owner_commit_rejected": True,
                },
                close_fact,
            ),
            actor="provider-recovery-terminal-coordinator",
        )
        evidence.notes.append("provider_recovery_verified")

    def _integrated_lease_begin(
        self,
        journal: Any,
        evidence: RunEvidence,
        selected_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        selected_output: AgentCallResult,
    ) -> dict[str, Any]:
        """Give the negotiated winner the Task Lease used by the shared-state work."""

        task_id = "integrated-task-" + evidence.run_id
        task = TaskAggregate(
            task_id,
            stable_hash(
                "TRUE_MULTI_AGENT_INTEGRATED_TASK",
                {"run": evidence.run_id, "selected_output_hash": selected_output.output_hash},
            ),
        )
        protocol_id = "integrated-lease-" + stable_hash(
            "TRUE_MULTI_AGENT_INTEGRATED_LEASE_PROTOCOL", {"run": evidence.run_id}
        )[:28]
        obligation_id = "obligation-" + protocol_id
        open_fact = self._protocol_open(
            evidence, "lease", protocol_id, obligation_id, source_decision.decision_id
        )
        stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        logical_now = int(time.time())
        lease_expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 30))
        observed_expiry_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 31))
        task, attempt, claim = task.claim(
            claim_command_id="integrated-selected-claim-" + evidence.run_id,
            lease_expires_at=lease_expires_at,
            holder_agent_id=selected_agent.agent_id,
            expected_stream_version=task.stream_version,
        )
        stream.append(
            "integrated-selected-executor-lease-granted",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task_id,
                    "specification_hash": task.specification_hash,
                    "source_decision_id": source_decision.decision_id,
                    "selected_proposal_output_hash": selected_output.output_hash,
                    "integrated_closure_task": True,
                },
                claim,
                {
                    "schema": "INTEGRATED_SELECTED_EXECUTOR_LEASE_V1",
                    "event_type": "integrated.selected-executor.lease-active",
                    "task_id": task_id,
                    "selected_agent_id": selected_agent.agent_id,
                    "selected_proposal_output_hash": selected_output.output_hash,
                    "task_attempt_id": attempt.task_attempt_id,
                    "lease_id": attempt.lease_id,
                    "claim_generation": attempt.claim_generation,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                },
            ),
            actor=selected_agent.agent_id,
        )
        return {
            "task": task,
            "attempt": attempt,
            "stream": stream,
            "selected_agent": selected_agent,
            "source_decision": source_decision,
            "protocol_id": protocol_id,
            "obligation_id": obligation_id,
            "observed_expiry_at": observed_expiry_at,
        }

    def _integrated_lease_failover(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        lease_context: Mapping[str, Any],
        blackboard_state: Mapping[str, Any],
        overrides: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Lose the selected owner, expire its Lease, and make a fresh decision."""

        task: TaskAggregate = lease_context["task"]
        attempt_a = lease_context["attempt"]
        worker_a: AgentIdentity = lease_context["selected_agent"]
        decision_a: AgentSchedulingDecision = lease_context["source_decision"]
        task_stream: CanonicalStream = lease_context["stream"]
        task_stream.append(
            "integrated-blackboard-progress-bound",
            (
                {
                    "schema": "INTEGRATED_TASK_BLACKBOARD_PROGRESS_BOUND_V1",
                    "event_type": "integrated.task.blackboard-progress-bound",
                    "task_id": task.task_id,
                    "task_attempt_id": attempt_a.task_attempt_id,
                    "holder_agent_id": worker_a.agent_id,
                    "lease_id": attempt_a.lease_id,
                    "blackboard_document_id": blackboard_state["document_id"],
                    "blackboard_version": blackboard_state["version"],
                    "blackboard_hash": blackboard_state["document_hash"],
                    "primary_writer_id": blackboard_state["primary_writer_id"],
                    "selected_executor_wrote_n_plus_1": blackboard_state["primary_writer_id"] == worker_a.agent_id,
                    "stale_conflict_resolved_to_n_plus_2": int(blackboard_state["version"]) >= 2,
                },
            ),
            actor=worker_a.agent_id,
        )
        fault = executor.inject_worker_loss(
            worker_a, task_id="integrated-selected-owner-loss", after_invocation_started=False
        )
        task, expired = task.expire(
            attempt_a.fencing_token, observed_at=str(lease_context["observed_expiry_at"])
        )
        task_stream.append(
            "integrated-selected-owner-lost-and-lease-expired",
            (
                {
                    **expired,
                    "event_type": "task.lease.expired",
                    "controlled_loss_call_id": fault["call_id"],
                    "controlled_loss_effect_id": fault["effect_id"],
                    "preferred_executor_lost": True,
                },
            ),
            actor="lease-expiry-controller",
        )
        decision_b, selected = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="integrated-task-failover",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("recover-shared-state", "initiate-operational-transfer"),
            exclusions=(worker_a.agent_id,),
            overrides=overrides,
        )
        worker_b = selected[0]
        reassigned = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="CONTROLLED_SELECTED_OWNER_LOSS_AND_LEASE_EXPIRY",
        )
        task_stream.append("integrated-reassignment-decided", (reassigned,), actor="scheduler")
        task, attempt_b, claim_b = task.claim(
            claim_command_id="integrated-reassignment-claim-" + evidence.run_id,
            lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append(
            "integrated-reassignment-claim-granted", (claim_b,), actor=worker_b.agent_id
        )
        unchanged, stale_rejected = task.submit_or_reject(
            attempt_a.fencing_token, str(blackboard_state["downstream_output_hash"])
        )
        if unchanged != task or stale_rejected.get("business_state_committed") is not False:
            raise DynamicCollaborationError("integrated stale owner result mutated authoritative Task state")
        task_stream.append(
            "integrated-stale-owner-result-rejected",
            (
                {
                    **stale_rejected,
                    "event_type": "task.stale-fence.rejected",
                    "old_agent_submission_rejected_after_reassignment": True,
                },
            ),
            actor="task-result-admission-verifier",
        )

        def validate_source(value: Mapping[str, Any]) -> None:
            _require_string(value, "handoff_source")
            _require_strings(value, "recovered_state_refs", minimum=1, maximum=8)

        source = self._call(
            executor,
            evidence,
            worker_b,
            task_id="integrated-reassigned-owner-transfer-source",
            kind="proposal",
            contract=(
                "Recover the selected plan from the exact merged shared record and prepare the bounded source "
                "for an operational transfer. Return handoff_source as a non-empty string and recovered_state_refs "
                "as a JSON array containing only 1-8 non-empty strings; do not return objects in that array."
            ),
            prompt=(
                f"You now own Task {task.task_id} under Lease {attempt_b.lease_id}. Recover Blackboard "
                f"{blackboard_state['document_id']} version {blackboard_state['version']} hash "
                f"{blackboard_state['document_hash']} and prepare the receiving engineer's work transfer."
                " Return exactly the required handoff_source string and recovered_state_refs string array."
            ),
            context={
                "task_id": task.task_id,
                "task_attempt_id": attempt_b.task_attempt_id,
                "claim_generation": attempt_b.claim_generation,
                "lease_id": attempt_b.lease_id,
                "fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
                "blackboard_document_id": blackboard_state["document_id"],
                "blackboard_version": blackboard_state["version"],
                "blackboard_hash": blackboard_state["document_hash"],
            },
            validate=validate_source,
        )
        return {
            "task": task,
            "attempt": attempt_b,
            "stream": task_stream,
            "new_agent": worker_b,
            "new_decision": decision_b,
            "source": source,
            "prior_attempt": attempt_a,
            "protocol_id": lease_context["protocol_id"],
            "obligation_id": lease_context["obligation_id"],
            "blackboard": dict(blackboard_state),
        }

    def _lease_and_reassign(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> None:
        decision_a, initial_candidates = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="lease-work",
            required_capabilities=("proposal",),
            slots=2,
            candidate_tasks=("lease-work",),
            overrides=overrides,
        )
        if len(initial_candidates) != 2:
            raise DynamicCollaborationError("lease competition requires two independently scheduled Agents")
        worker_a, worker_b = initial_candidates
        task_id = "lease-task-" + evidence.run_id
        task = TaskAggregate(task_id, stable_hash("TRUE_MULTI_AGENT_LEASE_TASK", {"run": evidence.run_id}))
        protocol_id = "lease-reassignment-" + stable_hash("TRUE_MULTI_AGENT_LEASE_PROTOCOL", {"run": evidence.run_id})[:24]
        obligation = "obligation-" + protocol_id
        task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        open_fact = self._protocol_open(evidence, "lease", protocol_id, obligation, decision_a.decision_id)
        task_stream.append(
            "lease-task-created",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task.task_id,
                    "specification_hash": task.specification_hash,
                    "task_state": task.state.value,
                    "stream_version": task.stream_version,
                    "claim_competitors": [worker_a.agent_id, worker_b.agent_id],
                    "source_decision_id": decision_a.decision_id,
                },
            ),
            actor="lease-command-handler",
        )

        logical_now = int(time.time())
        expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 30))
        renewed_expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 60))
        observed_expiry_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 61))
        expires_b = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 600))
        common_stream_version = task.stream_version
        task, attempt_a, claim_a = task.claim(
            claim_command_id="lease-claim-a-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_a.agent_id,
            expected_stream_version=common_stream_version,
        )
        task_stream.append("lease-claim-granted", (claim_a,), actor=worker_a.agent_id)
        task_after_rejection, rejected_attempt, competing_rejected = task.claim_or_reject(
            claim_command_id="lease-competing-claim-b-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=common_stream_version,
        )
        if rejected_attempt is not None or task_after_rejection != task or competing_rejected["reason_code"] != "TASK_STREAM_VERSION_CONFLICT":
            raise DynamicCollaborationError("competing Task Claim did not deterministically lose stream CAS")
        task_stream.append("lease-competing-claim-rejected", (competing_rejected,), actor="lease-command-handler")

        def validate(value: Mapping[str, Any]) -> None:
            _require_string(value, "result")
            _require_text_or_strings(value, "evidence", maximum=8)

        progress = self._call(
            executor,
            evidence,
            worker_a,
            task_id="lease-owner-a-progress",
            kind="proposal",
            contract=(
                "Perform meaningful progress on the leased task without self-declaring Task completion. "
                "Return exactly one JSON object with agent_id, kind, result, and evidence. agent_id must "
                "identify the assigned Agent, kind must be proposal, result must be a non-empty string, "
                "and evidence must be an array of one to eight non-empty strings."
            ),
            prompt=(
                f"Work on leased task {task_id} under attempt {attempt_a.task_attempt_id}. "
                f"Return exactly one JSON object: {{\"agent_id\":\"{worker_a.agent_id}\","
                "\"kind\":\"proposal\",\"result\":\"<non-empty partial-progress summary>\","
                "\"evidence\":[\"<non-empty progress evidence>\"]}. Do not claim Task completion."
            ),
            context={
                "task_id": task_id,
                "task_attempt_id": attempt_a.task_attempt_id,
                "claim_generation": attempt_a.claim_generation,
                "lease_id": attempt_a.lease_id,
                "holder_agent_id": worker_a.agent_id,
                "outer_task_completion_authority": "result-admission-verifier",
            },
            validate=validate,
        )
        task, renewed = task.renew(
            attempt_a.fencing_token,
            lease_expires_at=renewed_expires_a,
            progress_evidence_refs=(progress.output_ref, progress.output_hash),
        )
        task_stream.append(
            "lease-renewed-with-progress",
            ({**renewed, "progress_call_id": progress.call_id, "progress_output_ref": progress.output_ref},),
            actor=worker_a.agent_id,
        )

        fault = executor.inject_worker_loss(worker_a, task_id=task_id, after_invocation_started=False)
        task, expired = task.expire(attempt_a.fencing_token, observed_at=observed_expiry_a)
        task_stream.append(
            "lease-expired-after-controlled-owner-loss",
            ({
                **expired,
                "controlled_loss_call_id": fault["call_id"],
                "controlled_loss_effect_id": fault["effect_id"],
                "controlled_loss_next_action": fault["next_action"],
            },),
            actor="lease-expiry-controller",
        )

        decision_b, reassignment = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="lease-work-reassignment",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("lease-work-reassignment",),
            exclusions=tuple(
                identity.agent_id for identity in self.registry.identities if identity.agent_id != worker_b.agent_id
            ),
            overrides=overrides,
        )
        if (
            len(reassignment) != 1
            or reassignment[0].agent_id != worker_b.agent_id
            or worker_b.agent_id == worker_a.agent_id
            or decision_b.decision_id == decision_a.decision_id
        ):
            raise DynamicCollaborationError("lease reassignment did not produce a new Agent/Decision")
        reassigned = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="CONTROLLED_OWNER_LOSS_AND_LEASE_EXPIRY",
        )
        task_stream.append("lease-reassignment-decided", (reassigned,), actor="scheduler")
        task, attempt_b, claim_b = task.claim(
            claim_command_id="lease-claim-b-" + evidence.run_id,
            lease_expires_at=expires_b,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("lease-reassignment-claim-granted", (claim_b,), actor=worker_b.agent_id)

        result = self._call(
            executor,
            evidence,
            worker_b,
            task_id="lease-work-reassignment",
            kind="proposal",
            contract=(
                "Complete the reassigned lease task. Return exactly one JSON object with agent_id, kind, "
                "result, and evidence. agent_id must identify the assigned Agent, kind must be proposal, "
                "result must be a non-empty string, and evidence must be an array of one to eight non-empty strings."
            ),
            prompt=(
                f"Complete reassigned task {task_id}; generation {attempt_b.claim_generation} supersedes "
                f"failed generation {attempt_a.claim_generation}. Return exactly one JSON object: "
                f"{{\"agent_id\":\"{worker_b.agent_id}\",\"kind\":\"proposal\","
                "\"result\":\"<non-empty completion summary>\",\"evidence\":[\"<non-empty evidence>\"]}."
            ),
            context={
                "task_id": task_id,
                "prior_agent_id": worker_a.agent_id,
                "current_agent_id": worker_b.agent_id,
                "prior_attempt_id": attempt_a.task_attempt_id,
                "current_attempt_id": attempt_b.task_attempt_id,
                "prior_lease_id": attempt_a.lease_id,
                "current_lease_id": attempt_b.lease_id,
                "current_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
            },
            validate=validate,
        )
        task, submitted = task.submit(attempt_b.fencing_token, result.output_hash)
        task_stream.append(
            "lease-reassigned-result-submitted",
            ({**submitted, "provider_call_id": result.call_id, "provider_output_ref": result.output_ref},),
            actor=worker_b.agent_id,
        )
        task, accepted = task.accept(
            attempt_b.fencing_token,
            artifact_hash=result.output_hash,
            policy_hash=self.policy_hash,
            accepted_by="result-admission-verifier",
            acceptance_evidence_refs=(result.output_ref, result.output_hash),
        )
        task_stream.append(
            "lease-reassigned-result-accepted",
            ({**accepted, "provider_call_id": result.call_id, "provider_output_ref": result.output_ref},),
            actor="result-admission-verifier",
        )

        unchanged, stale_rejected = task.submit_or_reject(attempt_a.fencing_token, progress.output_hash)
        if unchanged != task or stale_rejected.get("business_state_committed") is not False:
            raise DynamicCollaborationError("stale Task submit changed authoritative business state")
        task_stream.append(
            "lease-stale-owner-result-rejected",
            ({
                **stale_rejected,
                "provider_observation_recorded": True,
                "provider_call_id": progress.call_id,
                "provider_request_id": progress.provider_request_id,
                "provider_output_ref": progress.output_ref,
                "provider_output_hash": progress.output_hash,
            },),
            actor="task-result-admission-verifier",
        )
        close_fact = self._protocol_close(evidence, protocol_id, obligation, "REASSIGNED_ACCEPTED_AND_STALE_FENCE_REJECTED")
        task_stream.append("lease-protocol-terminal", (close_fact,), actor="lease-terminal-coordinator")

    def _materialize_topology(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
    ) -> None:
        graph = TaskGraphAggregate.create("task-graph-" + evidence.run_id)
        facts: list[Mapping[str, Any]] = []
        node_ids: list[str] = []
        for index, semantic_task in enumerate(analysis.task_graph, 1):
            node_id = f"task-node-{index}-" + stable_hash(
                "TRUE_MULTI_AGENT_DYNAMIC_TASK_NODE",
                {"run": evidence.run_id, "semantic_task": semantic_task, "index": index},
            )[:16]
            node_ids.append(node_id)
            graph, added = graph.add_task(
                expected_graph_version=graph.version,
                node_id=node_id,
                specification={
                    "semantic_task": semantic_task,
                    "goal_hash": evidence.goal_hash,
                    "discovered_by_call_id": evidence.calls[0].call_id,
                },
                required_obligation=True,
            )
            graph, process, pending = graph.begin_materialization(
                expected_graph_version=graph.version,
                node_id=node_id,
                create_command_id="materialize-" + node_id,
            )
            graph, materialized = graph.finish_materialization(
                expected_graph_version=graph.version,
                node_id=node_id,
                created=True,
                canonical_request_hash=process.request_hash,
            )
            facts.extend((added, pending, materialized))
        if graph.closing_blockers:
            raise DynamicCollaborationError("dynamic TaskGraph retained materialization blockers")
        facts.append(
            {
                "schema": "DYNAMIC_TASK_GRAPH_MATERIALIZED_V1",
                "event_type": "taskgraph.materialized",
                "graph_id": graph.graph_id,
                "graph_version": graph.version,
                "topology_hash": graph.topology_hash,
                "semantic_tasks": list(analysis.task_graph),
                "node_ids": node_ids,
                "protocols": list(analysis.protocols),
                "fixed_role_pipeline_used": False,
                "source_goal_analysis_call_id": evidence.calls[0].call_id,
                "closing_blockers": [],
            }
        )
        run_stream.append("dynamic-taskgraph-materialized", tuple(facts), actor="taskgraph-command-handler")

    def _analysis_with_constraints(
        self,
        analysis: GoalAnalysis,
        overrides: Mapping[str, Any],
        run_stream: CanonicalStream,
        goal: str = "",
    ) -> GoalAnalysis:
        required_protocols = tuple(str(item) for item in overrides.get("required_protocols", ()))
        prohibited_protocols = tuple(str(item) for item in overrides.get("prohibited_protocols", ()))
        forbidden = set(required_protocols).difference(self.policy["allowed_protocols"])
        if forbidden or set(prohibited_protocols).difference(self.policy["allowed_protocols"]):
            raise DynamicCollaborationError("acceptance constraint requested a forbidden protocol")
        if set(required_protocols).intersection(prohibited_protocols):
            raise DynamicCollaborationError("the same protocol cannot be required and prohibited")
        changes: dict[str, Any] = {}
        semantic_reasons: list[str] = []
        if required_protocols or prohibited_protocols:
            changes["protocols"] = tuple(
                item
                for item in dict.fromkeys((*analysis.protocols, *required_protocols))
                if item not in set(prohibited_protocols)
            )
        for field_name, override_name in (
            ("requires_rework", "force_rework"),
            ("requires_conflict", "force_conflict"),
            ("requires_handoff_reject", "force_handoff_reject"),
            ("requires_reassignment", "force_reassignment"),
            ("requires_provider_unknown", "force_provider_unknown"),
        ):
            if bool(overrides.get(override_name)):
                changes[field_name] = True
        if "proposal_count" in overrides:
            count = int(overrides["proposal_count"])
            if not 1 <= count <= int(self.policy["max_proposals_per_round"]):
                raise DynamicCollaborationError("acceptance proposal count constraint is outside policy")
            changes["proposal_count"] = count
        normalized_goal = goal.casefold()
        shared_state_markers = (
            "shared record",
            "shared evidence",
            "shared state",
            "shared decision",
            "versioned record",
            "collaborative record",
            "共同记录",
            "共享状态",
            "共享证据",
        )
        conflict_markers = (
            "competing edit",
            "concurrent edit",
            "same initial",
            "same base",
            "conflicting conclusion",
            "preserve both",
            "冲突编辑",
            "同一初始",
            "保留双方",
        )
        shared_state_required = any(marker in normalized_goal for marker in shared_state_markers)
        conflict_semantics = analysis.requires_conflict or any(marker in normalized_goal for marker in conflict_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if shared_state_required and "blackboard" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "blackboard")))
            semantic_reasons.append("SHARED_VERSIONED_STATE_REQUIRES_BLACKBOARD")
        if shared_state_required and conflict_semantics and not analysis.requires_conflict:
            changes["requires_conflict"] = True
            semantic_reasons.append("COMPETING_SHARED_BASE_REQUIRES_MVCC_CONFLICT_PATH")
        lease_markers = (
            "claim the same task",
            "compete to claim",
            "competing task claim",
            "lease ownership",
            "lease expiry",
            "owner becomes unavailable",
            "ownership failover",
            "reassign the same task",
            "stale owner result",
            "stale fencing token",
            "竞争认领同一任务",
            "租约到期",
            "所有权故障转移",
        )
        lease_semantics = any(marker in normalized_goal for marker in lease_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if lease_semantics and "lease" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "lease")))
            semantic_reasons.append("TASK_OWNERSHIP_FAILOVER_REQUIRES_LEASE_PROTOCOL")
        if lease_semantics and not analysis.requires_reassignment:
            changes["requires_reassignment"] = True
            semantic_reasons.append("TASK_OWNERSHIP_FAILOVER_REQUIRES_REASSIGNMENT")
        if lease_semantics and int(changes.get("proposal_count", analysis.proposal_count)) < 2:
            changes["proposal_count"] = 2
            semantic_reasons.append("LEASE_FAILOVER_REQUIRES_REDUNDANT_INITIAL_PROPOSALS")
        handoff_markers = (
            "operational transfer",
            "transfer the selected plan",
            "transfer of the selected",
            "receiver accepts",
            "receiving engineer",
            "work transfer",
            "交接选定方案",
            "接收方",
        )
        handoff_reject_markers = (
            "first package intentionally lacks",
            "first transfer package lacks",
            "receiver should reject",
            "receiver rejects",
            "correct every omission",
            "首个交接包缺少",
            "接收方拒绝",
        )
        handoff_semantics = any(marker in normalized_goal for marker in handoff_markers)
        handoff_reject_semantics = any(marker in normalized_goal for marker in handoff_reject_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if handoff_semantics and "handoff" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "handoff")))
            semantic_reasons.append("QUALIFIED_OPERATIONAL_TRANSFER_REQUIRES_HANDOFF_PROTOCOL")
        if handoff_reject_semantics and not analysis.requires_handoff_reject:
            changes["requires_handoff_reject"] = True
            semantic_reasons.append("INCOMPLETE_INITIAL_TRANSFER_REQUIRES_NEW_HANDOFF_GENERATION")
        negotiation_markers = (
            "multi-round negotiation",
            "second negotiation round",
            "second round proposal",
            "respond to peer objections",
            "respond to each other's",
            "peer counterproposal",
            "多轮协商",
            "第二轮方案",
        )
        rework_markers = (
            "reviewer must request changes",
            "reviewer should request changes",
            "request a revision",
            "repair every review defect",
            "address every review defect",
            "review-driven rework",
            "审查者必须要求修改",
            "逐项修复审查缺陷",
        )
        negotiation_semantics = any(marker in normalized_goal for marker in negotiation_markers)
        rework_semantics = any(marker in normalized_goal for marker in rework_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if negotiation_semantics and "debate" not in effective_protocols:
            effective_protocols = tuple(dict.fromkeys((*effective_protocols, "debate")))
            changes["protocols"] = effective_protocols
            semantic_reasons.append("MULTI_ROUND_NEGOTIATION_REQUIRES_DEBATE_PROTOCOL")
        exact_two_negotiators = any(
            marker in normalized_goal
            for marker in ("two authors", "two agents", "two qualified", "两名", "两个 agent")
        )
        if negotiation_semantics and (
            int(changes.get("proposal_count", analysis.proposal_count)) < 2
            or (exact_two_negotiators and int(changes.get("proposal_count", analysis.proposal_count)) != 2)
        ):
            changes["proposal_count"] = 2
            semantic_reasons.append("PEER_NEGOTIATION_REQUIRES_MULTIPLE_PROPOSERS")
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if rework_semantics and "rework" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "rework")))
            semantic_reasons.append("REVIEW_DRIVEN_REVISION_REQUIRES_REWORK_PROTOCOL")
        if rework_semantics and not bool(changes.get("requires_rework", analysis.requires_rework)):
            changes["requires_rework"] = True
            semantic_reasons.append("EXPLICIT_REVIEW_DEFECT_REQUIRES_REVISION_PATH")
        if _provider_recovery_required(goal) and not bool(
            changes.get("requires_provider_unknown", analysis.requires_provider_unknown)
        ):
            changes["requires_provider_unknown"] = True
            semantic_reasons.append("PROVIDER_RECOVERY_REQUIRES_ACK_LOSS_RECONCILIATION")
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if _checkpoint_restart_required(goal) and "checkpoint" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "checkpoint")))
            semantic_reasons.append("CHECKPOINT_RESTART_RESUME_REQUIRES_DURABLE_RECOVERY_PROTOCOL")
        # A model may over-select the optional checkpoint protocol for a code
        # change.  Execution goals must reach Controller -> Planner -> Forge ->
        # Tester -> Reviewer in the current run; checkpoint/restart is a
        # recovery protocol and cannot preempt that bridge.  Remove only this
        # model-selected protocol (an explicit recovery goal still admits it).
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        execution_required = (
            _execution_goal_authorized(goal, overrides)
            if bool(overrides.get("interactive_chat"))
            else _execution_required(goal)
        )
        if execution_required and "checkpoint" in effective_protocols and not _checkpoint_restart_required(goal):
            changes["protocols"] = tuple(item for item in effective_protocols if item != "checkpoint")
            semantic_reasons.append("EXECUTION_BRIDGE_PRECEDES_OPTIONAL_CHECKPOINT")
        negative_protocol_markers = {
            "blackboard": ("no shared record", "without a shared record", "without shared state", "无需共享记录"),
            "debate": ("no iterative discussion", "without iterative discussion", "无需迭代讨论"),
            "rework": ("each analyst acts once", "no revision cycle", "每个分析者仅行动一次"),
            "handoff": ("no work transfer", "without work transfer", "无需工作转交"),
            "checkpoint": ("no runtime interruption", "without runtime interruption", "无需运行时中断"),
            "lease": ("no ownership failover", "without ownership failover", "无需所有权故障转移"),
            "arbitration": ("no technical dispute", "without a technical dispute", "no arbitration", "无需技术争议裁决"),
        }
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        explicitly_unneeded = {
            protocol
            for protocol, markers in negative_protocol_markers.items()
            if any(marker in normalized_goal for marker in markers)
        }
        if explicitly_unneeded.intersection(effective_protocols):
            changes["protocols"] = tuple(item for item in effective_protocols if item not in explicitly_unneeded)
            semantic_reasons.append("EXPLICIT_GOAL_NEGATIVE_PROTOCOL_CONSTRAINTS")
        if "rework" in explicitly_unneeded and bool(changes.get("requires_rework", analysis.requires_rework)):
            changes["requires_rework"] = False
        if "handoff" in explicitly_unneeded and bool(changes.get("requires_handoff_reject", analysis.requires_handoff_reject)):
            changes["requires_handoff_reject"] = False
        if "lease" in explicitly_unneeded and bool(changes.get("requires_reassignment", analysis.requires_reassignment)):
            changes["requires_reassignment"] = False
        if "blackboard" in explicitly_unneeded and bool(changes.get("requires_conflict", analysis.requires_conflict)):
            changes["requires_conflict"] = False
        constrained = dataclasses.replace(analysis, **changes) if changes else analysis
        if changes:
            run_stream.append(
                "goal-analysis-policy-constraints",
                ({
                    "schema": "GOAL_ANALYSIS_POLICY_CONSTRAINTS_APPLIED_V1",
                    "event_type": "goal.analysis.policy-constraints-applied",
                    "provider_discovery": analysis.mapping(),
                    "constraints": {
                        key: list(value) if isinstance(value, tuple) else value
                        for key, value in changes.items()
                    },
                    "constrained_analysis": constrained.mapping(),
                    "scenario_fixture_pipeline_used": False,
                    "reason": "RUNTIME_GOAL_SEMANTIC_POLICY" if semantic_reasons else "EXPLICIT_ACCEPTANCE_CONTROL_OR_GOAL_REQUIREMENT",
                    "semantic_reasons": semantic_reasons,
                },),
                actor="runtime-goal-policy-controller" if semantic_reasons else "acceptance-policy-controller",
            )
        return constrained

    def _restart_frontier_snapshot(
        self,
        journal: Any,
        evidence: RunEvidence,
        frontier_kind: str,
        ordinal: int,
        *,
        lease_state: Mapping[str, Any] | None = None,
        provider_unknown: Mapping[str, Any] | None = None,
        integrated_continuation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        spec = next(item for item in FRONTIER_SPECS if item.frontier_kind == frontier_kind)
        run_events = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
        ]

        def latest(*schemas: str) -> Mapping[str, Any] | None:
            return next(
                (
                    dict(event.payload)
                    for event in reversed(run_events)
                    if event.payload.get("schema") in set(schemas)
                ),
                None,
            )

        protocol_id = "restart-frontier-" + stable_hash(
            "TRUE_MULTI_AGENT_RESTART_FRONTIER_PROTOCOL",
            {"run": evidence.run_id, "kind": frontier_kind, "ordinal": ordinal},
        )[:32]
        obligation_id = "obligation-" + protocol_id
        snapshot: dict[str, Any] = {
            "frontier_kind": frontier_kind,
            "protocol_kind": spec.protocol_kind,
            "protocol_state": spec.protocol_state,
            "protocol_id": protocol_id,
            "obligation_id": obligation_id,
            "generation": 1,
            "source_event_ids": [event.event_id for event in run_events[-8:]],
        }
        if frontier_kind == "PROPOSAL_REVIEW_PENDING":
            source = latest("PROPOSAL_SUBMITTED_V1", "PROPOSAL_REVISED_V1") or {}
            snapshot.update(
                {
                    "proposal_id": source.get("proposal_id") or "proposal-" + stable_hash("RESTART_PROPOSAL", protocol_id)[:24],
                    "proposal_hash": source.get("revision_output_hash")
                    or source.get("output_hash")
                    or stable_hash("RESTART_PROPOSAL_HASH", protocol_id),
                    "review_id": "review-" + stable_hash("RESTART_PENDING_REVIEW", protocol_id)[:28],
                    "review_state": "REQUESTED_PENDING",
                }
            )
        elif frontier_kind == "NEGOTIATION_MID_ROUND":
            source = latest("DEBATE_ROUND_OPENED_V1", "NEGOTIATION_ROUND_OPENED_V1") or {}
            snapshot.update(
                {
                    "debate_id": source.get("debate_id") or "debate-" + stable_hash("RESTART_DEBATE", protocol_id)[:24],
                    "negotiation_round": max(2, int(source.get("round_number", 2))),
                    "prior_round_hash": stable_hash("RESTART_PRIOR_NEGOTIATION_ROUND", protocol_id),
                }
            )
        elif frontier_kind == "HANDOFF_ACCEPTED_PENDING_SUBMISSION":
            if integrated_continuation is not None:
                main_task = dict(integrated_continuation["main_task"])
                blackboard = dict(integrated_continuation["blackboard"])
                snapshot.update(
                    {
                        "handoff_id": integrated_continuation["handoff_id"],
                        "handoff_generation": integrated_continuation["handoff_generation"],
                        "handoff_state": integrated_continuation["handoff_state"],
                        "handoff_contract_hash": integrated_continuation["contract_hash"],
                        "task_id": main_task["task_id"],
                        "task_attempt_id": main_task["task_attempt_id"],
                        "holder_agent_id": main_task["holder_agent_id"],
                        "claim_generation": main_task["claim_generation"],
                        "lease_id": main_task["lease_id"],
                        "lease_expires_at": main_task["lease_expires_at"],
                        "fencing_token": main_task["fencing_token"],
                        "fencing_token_hash": sha256_bytes(str(main_task["fencing_token"]).encode()),
                        "task_stream_version": main_task["stream_version"],
                        "lease_state": "ACTIVE",
                        "blackboard_document_id": blackboard["document_id"],
                        "blackboard_version": blackboard["version"],
                        "blackboard_hash": blackboard["document_hash"],
                        "integrated_continuation": dict(integrated_continuation),
                    }
                )
            else:
                source = latest("HANDOFF_ACCEPTED_V1", "HANDOFF_GENERATION_OPENED_V1") or {}
                snapshot.update(
                    {
                        "handoff_id": source.get("handoff_id") or "handoff-" + stable_hash("RESTART_HANDOFF", protocol_id)[:24],
                        "handoff_generation": max(2, int(source.get("generation", 2))),
                        "handoff_state": "ACCEPTED",
                        "handoff_contract_hash": source.get("contract_hash") or stable_hash("RESTART_HANDOFF_CONTRACT", protocol_id),
                    }
                )
        elif frontier_kind == "BLACKBOARD_CONFLICT_UNRESOLVED":
            source = latest("BLACKBOARD_PATCH_CONFLICT_V1", "BLACKBOARD_CONFLICT_OPENED_V1") or {}
            version_source = latest("BLACKBOARD_VERSION_COMMITTED_V1", "BLACKBOARD_DOCUMENT_CREATED_V1") or {}
            snapshot.update(
                {
                    "blackboard_document_id": source.get("document_id")
                    or version_source.get("document_id")
                    or "document-" + stable_hash("RESTART_BLACKBOARD", protocol_id)[:24],
                    "blackboard_version": max(1, int(source.get("canonical_version", version_source.get("version", 1)))),
                    "blackboard_hash": source.get("canonical_hash")
                    or version_source.get("document_hash")
                    or stable_hash("RESTART_BLACKBOARD_HASH", protocol_id),
                    "conflict_id": source.get("conflict_id") or "conflict-" + stable_hash("RESTART_CONFLICT", protocol_id)[:24],
                    "conflict_state": "OPEN",
                }
            )
        elif frontier_kind == "TASK_LEASE_ACTIVE":
            if lease_state is None:
                raise DynamicCollaborationError("active Lease restart frontier lacks an authoritative Task claim")
            snapshot.update(dict(lease_state))
        elif frontier_kind == "REWORK_REVISION_PENDING":
            source = latest("REWORK_REQUESTED_V1", "REWORK_STARTED_V1") or {}
            snapshot.update(
                {
                    "rework_id": source.get("rework_id") or "rework-" + stable_hash("RESTART_REWORK", protocol_id)[:24],
                    "rework_round": max(1, int(source.get("round_number", 1))),
                    "rework_parent_hash": source.get("parent_output_hash")
                    or source.get("current_result_ref")
                    or stable_hash("RESTART_REWORK_PARENT", protocol_id),
                    "revision_state": "PENDING",
                }
            )
        elif frontier_kind == "PROVIDER_UNKNOWN_RECONCILING":
            if provider_unknown is None:
                raise DynamicCollaborationError("Provider UNKNOWN restart frontier lacks an authoritative Effect attempt")
            snapshot.update(dict(provider_unknown))
        elif frontier_kind == "CLOSING_REQUIRED_OBLIGATION_OPEN":
            snapshot.update(
                {
                    "run_state": "CLOSING",
                    "required_obligation_state": "OPEN",
                    "terminal_eligible": False,
                }
            )
        snapshot["state_hash"] = stable_hash(
            "TRUE_MULTI_AGENT_RESTART_FRONTIER_STATE",
            snapshot,
        )
        validate_frontier_snapshot(snapshot)
        return snapshot

    def _checkpoint_restart(
        self,
        context: Any,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        run: RunAggregate,
        integrated_continuation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        old_process_pid = os.getpid()
        provider_unknown: Mapping[str, Any] | None = None
        lease_state: Mapping[str, Any] | None = None
        prepared: list[dict[str, Any]] = []

        for ordinal, spec in enumerate(FRONTIER_SPECS, 1):
            if spec.frontier_kind == "TASK_LEASE_ACTIVE":
                task_id = "restart-lease-task-" + stable_hash(
                    "TRUE_MULTI_AGENT_RESTART_LEASE_TASK", {"run": evidence.run_id}
                )[:24]
                task = TaskAggregate(
                    task_id,
                    stable_hash("TRUE_MULTI_AGENT_RESTART_LEASE_TASK_SPEC", {"run": evidence.run_id}),
                )
                task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
                task_stream.append(
                    "restart-lease-task-created",
                    (
                        {
                            "schema": "TASK_CREATED_V1",
                            "task_id": task_id,
                            "specification_hash": task.specification_hash,
                            "source_decision_id": evidence.decisions[-1]["decision_id"] if evidence.decisions else "restart-checkpoint-policy",
                        },
                    ),
                    actor="checkpoint-frontier-command-handler",
                )
                task, attempt, claim = task.claim(
                    claim_command_id="claim-restart-lease-" + evidence.run_id,
                    lease_expires_at="2099-01-01T00:00:00Z",
                    holder_agent_id=sorted(evidence.called_agents)[0],
                    expected_stream_version=task.stream_version,
                )
                task_stream.append(
                    "restart-active-lease-claimed", (claim,), actor=attempt.holder_agent_id
                )
                lease_state = {
                    "task_id": task_id,
                    "task_attempt_id": attempt.task_attempt_id,
                    "holder_agent_id": attempt.holder_agent_id,
                    "claim_generation": attempt.claim_generation,
                    "lease_id": attempt.lease_id,
                    "lease_expires_at": attempt.lease_expires_at,
                    "fencing_token": attempt.fencing_token,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                    "task_stream_version": task.stream_version,
                    "lease_state": "ACTIVE",
                }
            elif spec.frontier_kind == "PROVIDER_UNKNOWN_RECONCILING":
                owner = self.registry.get(sorted(evidence.called_agents)[0])
                fault = executor.inject_worker_loss(
                    owner,
                    task_id="restart-provider-unknown-reconciliation",
                    after_invocation_started=True,
                )
                if (
                    fault["outcome_state"] != "OUTCOME_UNKNOWN"
                    or fault["settlement_state"] != "RECONCILING"
                    or fault["physical_send_count"] != 0
                ):
                    raise DynamicCollaborationError("restart Provider frontier did not enter OUTCOME_UNKNOWN")
                provider_unknown = {
                    "effect_id": fault["effect_id"],
                    "effect_attempt_id": fault["effect_attempt_id"],
                    "outcome_state": fault["outcome_state"],
                    "settlement_state": fault["settlement_state"],
                    "attempt_disposition": fault["attempt_disposition"],
                    "physical_send_count": fault["physical_send_count"],
                    "unresolved_transmission_exposure_count": fault["unresolved_transmission_exposure_count"],
                    "idempotency_identity": fault["idempotency_identity"],
                }
            if spec.frontier_kind == "CLOSING_REQUIRED_OBLIGATION_OPEN":
                run, closing = run.begin_closing(expected_stream_version=run.stream_version)
                run_stream.append(
                    "restart-closing-barrier-opened",
                    (
                        {**closing, "event_type": "run.closing"},
                        {
                            "schema": "TERMINAL_REQUIRED_OBLIGATION_BARRIER_OPEN_V1",
                            "frontier_kind": spec.frontier_kind,
                            "terminal_committed": False,
                            "reason_code": "REQUIRED_RESTART_FRONTIER_OBLIGATION_OPEN",
                        },
                    ),
                    actor="terminal-command-handler",
                )

            snapshot = self._restart_frontier_snapshot(
                journal,
                evidence,
                spec.frontier_kind,
                ordinal,
                lease_state=lease_state,
                provider_unknown=provider_unknown,
                integrated_continuation=integrated_continuation,
            )
            protocol_id = str(snapshot["protocol_id"])
            obligation_id = str(snapshot["obligation_id"])
            source_decision_id = (
                evidence.decisions[-1]["decision_id"]
                if evidence.decisions
                else "restart-checkpoint-policy-decision"
            )
            open_fact = self._protocol_open(
                evidence, "checkpoint_restart_frontier", protocol_id, obligation_id, source_decision_id
            )
            frontier_stream_id = f"restart-frontier/{evidence.run_id}/{ordinal}"
            frontier_stream = CanonicalStream(
                journal, evidence.run_id, frontier_stream_id, self.policy_hash
            )
            _, opened_refs = frontier_stream.append(
                "restart-frontier-opened",
                (
                    open_fact,
                    {
                        "schema": "RESTART_FRONTIER_OPENED_V1",
                        "event_type": "checkpoint.restart-frontier-opened",
                        **snapshot,
                        "required_for_run_terminal": True,
                        "allowed_resume_command": spec.pending_action,
                        "invalid_transition_handling": "REJECT_AND_FAIL_CLOSED",
                    },
                ),
                actor="checkpoint-frontier-command-handler",
            )
            snapshot["source_event_id"] = opened_refs[-1]["event_id"]
            snapshot["source_event_hash"] = opened_refs[-1]["event_hash"]
            process_id = "restart-process-" + stable_hash(
                "TRUE_MULTI_AGENT_RESTART_PROCESS",
                {"run": evidence.run_id, "frontier": spec.frontier_kind},
            )[:30]
            manager = ProcessManager(
                process_id,
                stable_hash(
                    "TRUE_MULTI_AGENT_RESTART_PROCESS_DEFINITION",
                    {"frontier": spec.frontier_kind, "action": spec.pending_action},
                ),
                max_steps=8,
            )
            manager, pending_step, process_facts = manager.plan_step(
                source_event_hash=opened_refs[-1]["event_hash"],
                action=spec.pending_action,
                payload=snapshot,
            )
            frontier_stream.append(
                "restart-process-step-planned",
                process_facts,
                actor="durable-process-manager",
            )

            checkpoint_id = "checkpoint-" + stable_hash(
                "TRUE_MULTI_AGENT_LIVE_CHECKPOINT",
                {"run": evidence.run_id, "frontier": spec.frontier_kind, "ordinal": ordinal},
            )[:36]
            checkpoint_stream = CanonicalStream(
                journal, evidence.run_id, f"checkpoint/{checkpoint_id}", self.policy_hash
            )
            checkpoint_stream.append(
                "checkpoint-prepare",
                (
                    {
                        "schema": "CHECKPOINT_PREPARATION_STARTED_V1",
                        "event_type": "checkpoint.preparation-started",
                        "checkpoint_id": checkpoint_id,
                        "frontier_kind": spec.frontier_kind,
                        "business_state_mutated": False,
                    },
                    {
                        "schema": "CHECKPOINT_PROCESS_MANAGERS_FLUSHED_V1",
                        "event_type": "checkpoint.process-managers-flushed",
                        "checkpoint_id": checkpoint_id,
                        "process_ids": [process_id],
                        "pending_command_ids": [pending_step.command_id],
                    },
                    {
                        "schema": "CHECKPOINT_PROTOCOL_STATES_FLUSHED_V1",
                        "event_type": "checkpoint.protocol-states-flushed",
                        "checkpoint_id": checkpoint_id,
                        "active_protocol_ids": [protocol_id],
                        "frontier_state_hash": snapshot["state_hash"],
                    },
                    {
                        "schema": "CHECKPOINT_EFFECT_STATE_FLUSHED_V1",
                        "event_type": "checkpoint.effect-state-flushed",
                        "checkpoint_id": checkpoint_id,
                        "effect_id": snapshot.get("effect_id"),
                        "effect_attempt_id": snapshot.get("effect_attempt_id"),
                        "outcome_state": snapshot.get("outcome_state"),
                    },
                    {
                        "schema": "CHECKPOINT_BLACKBOARD_STATE_REFERENCED_V1",
                        "event_type": "checkpoint.blackboard-state-referenced",
                        "checkpoint_id": checkpoint_id,
                        "document_id": snapshot.get("blackboard_document_id"),
                        "version": snapshot.get("blackboard_version"),
                        "document_hash": snapshot.get("blackboard_hash"),
                    },
                ),
                actor="checkpoint-command-handler",
            )
            validated_position = journal.head_position
            prefix_events = tuple(journal.iter_events(0))
            run_prefix_events = [
                event
                for event in prefix_events
                if event.position <= validated_position and event.payload.get("run_id") == evidence.run_id
            ]
            cas_refs = sorted(
                {
                    reference
                    for event in prefix_events
                    if event.position <= validated_position
                    for reference in event.object_refs
                }
            )
            command_ids = sorted(
                {
                    str(event.payload["causation_command_id"])
                    for event in run_prefix_events
                    if isinstance(event.payload.get("causation_command_id"), str)
                }
                | {pending_step.command_id}
            )
            manifest = finalize_checkpoint_manifest(
                {
                    "schema": "SITINA_LIVE_CHECKPOINT_MANIFEST_V1",
                    "checkpoint_id": checkpoint_id,
                    "run_id": evidence.run_id,
                    "journal_id": journal.journal_id,
                    "epoch": journal.epoch,
                    "genesis_hash": context.genesis.genesis_hash,
                    "validated_through_position": validated_position,
                    "validated_through_hash": journal._position_hash[validated_position],
                    "stream_heads": stream_heads(prefix_events, validated_position),
                    "active_protocol_instances": [
                        dict(item)
                        for item in evidence.protocol_graph
                        if item["terminal_disposition"] is None
                    ],
                    "process_manager_states": [
                        {
                            "process_id": process_id,
                            "definition_hash": manager.definition_hash,
                            "generation": manager.generation,
                            "state": manager.state.value,
                            "step_count": manager.step_count,
                            "max_steps": manager.max_steps,
                            "visited_transition_hashes": list(manager.visited_transition_hashes),
                            "pending_command_id": pending_step.command_id,
                            "pending_request_hash": pending_step.request_hash,
                            "pending_transition_hash": pending_step.transition_hash,
                        }
                    ],
                    "pending_commands": [
                        {
                            "command_id": pending_step.command_id,
                            "request_hash": pending_step.request_hash,
                            "action": pending_step.action,
                            "step_number": pending_step.step_number,
                        }
                    ],
                    "command_ids": command_ids,
                    "task_claims": (
                        [
                            {
                                key: snapshot[key]
                                for key in (
                                    "task_id",
                                    "task_attempt_id",
                                    "holder_agent_id",
                                    "claim_generation",
                                    "lease_id",
                                )
                                if key in snapshot
                            }
                        ]
                        if "task_id" in snapshot
                        else []
                    )
                    + (
                        [dict(snapshot["integrated_continuation"]["handoff_task"])]
                        if isinstance(snapshot.get("integrated_continuation"), dict)
                        else []
                    ),
                    "lease_ids": (
                        ([snapshot["lease_id"]] if snapshot.get("lease_id") else [])
                        + (
                            [snapshot["integrated_continuation"]["handoff_task"]["lease_id"]]
                            if isinstance(snapshot.get("integrated_continuation"), dict)
                            else []
                        )
                    ),
                    "fencing_tokens": (
                        ([snapshot["fencing_token"]] if snapshot.get("fencing_token") else [])
                        + (
                            [snapshot["integrated_continuation"]["handoff_task"]["fencing_token"]]
                            if isinstance(snapshot.get("integrated_continuation"), dict)
                            else []
                        )
                    ),
                    "blackboard_versions": [
                        {
                            "document_id": snapshot.get("blackboard_document_id"),
                            "version": snapshot.get("blackboard_version"),
                            "document_hash": snapshot.get("blackboard_hash"),
                        }
                    ]
                    if snapshot.get("blackboard_document_id")
                    else [],
                    "proposal_review_handoff_generations": {
                        "proposal_id": snapshot.get("proposal_id"),
                        "review_id": snapshot.get("review_id"),
                        "handoff_id": snapshot.get("handoff_id"),
                        "handoff_generation": snapshot.get("handoff_generation"),
                        "negotiation_round": snapshot.get("negotiation_round"),
                        "rework_id": snapshot.get("rework_id"),
                        "rework_parent_hash": snapshot.get("rework_parent_hash"),
                    },
                    "effect_attempt_states": [
                        {
                            "effect_id": snapshot.get("effect_id"),
                            "effect_attempt_id": snapshot.get("effect_attempt_id"),
                            "attempt_disposition": snapshot.get("attempt_disposition"),
                            "physical_send_count": snapshot.get("physical_send_count"),
                        }
                    ]
                    if snapshot.get("effect_id")
                    else [],
                    "outcome_exposure_states": [
                        {
                            "effect_id": snapshot.get("effect_id"),
                            "outcome_state": snapshot.get("outcome_state"),
                            "settlement_state": snapshot.get("settlement_state"),
                            "unresolved_exposure_count": snapshot.get(
                                "unresolved_transmission_exposure_count"
                            ),
                        }
                    ]
                    if snapshot.get("effect_id")
                    else [],
                    "obligation_states": dict(evidence.obligations),
                    "cas_refs": cas_refs,
                    "frontier_snapshot": snapshot,
                    "frontier_stream_id": frontier_stream_id,
                    "provider_call_ids": [item.call_id for item in evidence.calls],
                    "provider_effect_ids": [item.effect_id for item in evidence.calls],
                    "provider_send_count": executor.transport.physical_send_count,
                    "config_hash": sha256_bytes(
                        (self.home / "config/true_multi_agent_agents.json").read_bytes()
                    ),
                    "policy_hash": self.policy_hash,
                    "code_fingerprint": executor.activation.manifest_hash,
                    "old_process_pid": old_process_pid,
                }
            )
            receipt = executor._publish(manifest, purpose="true-multi-agent-live-checkpoint")
            _, publication_refs = checkpoint_stream.append(
                "checkpoint-manifest-published",
                (
                    {
                        "schema": "CHECKPOINT_MANIFEST_PUBLISHED_V1",
                        "event_type": "checkpoint.manifest-published",
                        "checkpoint_id": checkpoint_id,
                        "frontier_kind": spec.frontier_kind,
                        "validated_through_position": validated_position,
                        "manifest_ref": receipt.object_ref.reference_id,
                        "manifest_hash": manifest["manifest_hash"],
                        "manifest_object_ref": dict(receipt.object_ref.__dict__),
                        "pending_command_id": pending_step.command_id,
                        "provider_send_count_before": executor.transport.physical_send_count,
                        "old_process_pid": old_process_pid,
                        "_object_refs": [receipt.object_ref.reference_id],
                    },
                ),
                actor="checkpoint-command-handler",
                proofs=(receipt,),
            )
            _, flushed_refs = checkpoint_stream.append(
                "checkpoint-flushed",
                (
                    {
                        "schema": "CHECKPOINT_FLUSHED_V1",
                        "event_type": "checkpoint.flushed",
                        "checkpoint_id": checkpoint_id,
                        "manifest_ref": receipt.object_ref.reference_id,
                        "manifest_hash": manifest["manifest_hash"],
                        "validated_through_position": validated_position,
                        "all_references_committed": True,
                        "business_state_mutated": False,
                    },
                ),
                actor="checkpoint-command-handler",
            )
            prepared.append(
                {
                "checkpoint_id": checkpoint_id,
                "frontier_kind": spec.frontier_kind,
                "checkpoint_position": publication_refs[-1]["position"],
                "validated_through_position": validated_position,
                "manifest_ref": receipt.object_ref.reference_id,
                "manifest_hash": manifest["manifest_hash"],
                "source_frontier_event_id": snapshot["source_event_id"],
                "source_frontier_event_hash": snapshot["source_event_hash"],
                "pending_command_id": pending_step.command_id,
                "provider_call_count_before": len(evidence.calls),
                "provider_send_count_before": executor.transport.physical_send_count,
                "old_process_pid": old_process_pid,
                "flushed_position": flushed_refs[-1]["position"],
                }
            )

        if len(prepared) != len(FRONTIER_SPECS):
            raise DynamicCollaborationError("checkpoint restart preparation matrix is incomplete")
        for item in prepared:
            checkpoint_stream = CanonicalStream(
                journal,
                evidence.run_id,
                f"checkpoint/{item['checkpoint_id']}",
                self.policy_hash,
            )
            checkpoint_stream.append(
                "runtime-stopped",
                (
                    {
                        "schema": "CHECKPOINT_RUNTIME_STOP_REQUESTED_V1",
                        "event_type": "checkpoint.runtime-stop-requested",
                        "checkpoint_id": item["checkpoint_id"],
                        "old_process_pid": old_process_pid,
                        "safe_point": True,
                    },
                    {
                        "schema": "CHECKPOINT_RUNTIME_STOPPED_V1",
                        "event_type": "checkpoint.runtime-stopped",
                        "checkpoint_id": item["checkpoint_id"],
                        "old_process_pid": old_process_pid,
                        "checkpoint_position": item["flushed_position"],
                        "writer_closed_next": True,
                        "supervisor_survives": True,
                    },
                ),
                actor="runtime-lifecycle-command-handler",
            )
        handoff_stream = CanonicalStream(
            journal,
            evidence.run_id,
            "checkpoint-supervisor/" + evidence.run_id,
            self.policy_hash,
        )
        _, handoff_refs = handoff_stream.append(
            "checkpoint-supervisor-handoff",
            (
                {
                    "schema": "CHECKPOINT_SUPERVISOR_HANDOFF_REQUIRED_V1",
                    "event_type": "checkpoint.supervisor-handoff-required",
                    "checkpoint_ids": [item["checkpoint_id"] for item in prepared],
                    "frontier_kinds": [item["frontier_kind"] for item in prepared],
                    "old_process_pid": old_process_pid,
                    "provider_call_count": executor.provider_call_total(),
                    "provider_send_count": executor.transport.physical_send_count,
                    "provider_token_total": executor.usage_total,
                    "provider_cost_micro_usd": executor.cost_total_micro_usd,
                    "integrated_closure_required": integrated_continuation is not None,
                    "integrated_handoff_id": integrated_continuation.get("handoff_id")
                    if integrated_continuation is not None
                    else None,
                    "journal_head_before_worker_exit": journal.head_position,
                    "fresh_process_required": True,
                    "runtime_subprocess_forbidden_by_legacy_fence": True,
                },
            ),
            actor="runtime-lifecycle-command-handler",
        )
        return {
            "status": "checkpoint_restart_required",
            "run_id": evidence.run_id,
            "old_process_pid": old_process_pid,
            "checkpoint_ids": [item["checkpoint_id"] for item in prepared],
            "frontier_kinds": [item["frontier_kind"] for item in prepared],
            "provider_call_count": executor.provider_call_total(),
            "provider_physical_send_count": executor.physical_send_total(),
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "integrated_closure_required": integrated_continuation is not None,
            "integrated_handoff_id": integrated_continuation.get("handoff_id")
            if integrated_continuation is not None
            else None,
            "journal_head_before_worker_exit": handoff_refs[-1]["position"],
            "terminal_state": "RESTART_REQUIRED",
        }

    def _independent_verifier_id(
        self, proposer_id: str, executor_id: str
    ) -> str:
        """Select a currently registered, trusted, independent verifier."""
        for agent in self.registry.identities:
            caps = set(getattr(agent, "capabilities", ()))
            safety = set(getattr(agent, "safety_classes", ()))
            if (
                agent.agent_id not in {proposer_id, executor_id}
                and "verification" in caps
                and {"read-only", "provider-text-only"}.issubset(safety)
            ):
                return agent.agent_id
        raise DynamicCollaborationError(
            "execution has no qualified independent verifier"
        )

    def _post_execution_reviewer_id(
        self, proposer_id: str, executor_id: str, verifier_id: str
    ) -> str:
        """Select a distinct registered reviewer for the actual execution."""

        for agent in self.registry.identities:
            capabilities = set(getattr(agent, "capabilities", ()))
            safety = set(getattr(agent, "safety_classes", ()))
            if (
                agent.agent_id not in {proposer_id, executor_id, verifier_id}
                and {"review", "evaluation"}.intersection(capabilities)
                and {"read-only", "provider-text-only"}.issubset(safety)
            ):
                return agent.agent_id
        raise DynamicCollaborationError(
            "execution has no qualified independent post-execution reviewer"
        )

    # Runtime-state trees are excluded only by this reviewed, explicit list;
    # the identity roots are content-addressed and bounded.  The worker's
    # Seatbelt never includes the production root, so this is supplementary
    # evidence rather than the write boundary.
    _CODE_MODE_SENTINEL_IDENTITY_ROOTS = DEFAULT_IDENTITY_ROOTS
    _CODE_MODE_SENTINEL_EXCLUDED_RUNTIME_ROOTS = DEFAULT_RUNTIME_EXCLUDED_ROOTS

    @classmethod
    def _observe_code_mode_production_sentinel(
        cls,
        root: Path | None = None,
        *,
        identity_roots: Sequence[str] | None = None,
        runtime_excluded_roots: Sequence[str] | None = None,
    ) -> str:
        root = Path(root or "/Users/moss/SitinaHub").expanduser().resolve(strict=False)
        if not root.exists():
            return "absent"
        try:
            manifest = build_production_identity_manifest(
                root,
                identity_roots=(
                    identity_roots
                    if identity_roots is not None
                    else cls._CODE_MODE_SENTINEL_IDENTITY_ROOTS
                ),
                runtime_excluded_roots=(
                    runtime_excluded_roots
                    if runtime_excluded_roots is not None
                    else cls._CODE_MODE_SENTINEL_EXCLUDED_RUNTIME_ROOTS
                ),
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise DynamicCollaborationError("production sentinel observation failed") from error
        return str(manifest["manifest_hash"])

    def _seal_code_mode_receipt(
        self,
        *,
        context: Any,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        authorization: Mapping[str, Any],
        canary_authorization: Mapping[str, Any] | None,
        side_effect_counts: Mapping[str, Any],
        controls: Mapping[str, Any],
        finalize_stream: bool = True,
    ) -> dict[str, Any]:
        """Persist typed facts, then a no-replace receipt and one closing root."""

        from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext

        if not isinstance(context, CodeModeRuntimeContext):
            raise DynamicCollaborationError("Code Mode receipt requires its independent runtime context")
        if canary_authorization is not None:
            if not context.validate_canary_authorization(canary_authorization):
                raise DynamicCollaborationError("Code Mode receipt authorization is not issuer-bound")
            runtime_binding = context.canary_authority_binding()
            if any(canary_authorization.get(key) != value for key, value in runtime_binding.items()):
                raise DynamicCollaborationError("Code Mode receipt runtime binding changed")
            if any(authorization.get(key) != canary_authorization.get(key) for key in (
                "run_id", "session_id", "candidate_id", "workspace",
            )):
                raise DynamicCollaborationError("Code Mode receipt canary/code authorization binding changed")
        else:
            # Ordinary offline Code Mode still produces a durable, review-pending
            # handoff.  It is not a canary authority: the local scripted/client
            # override never supplies an issuer or physical transport proof.
            authorizer = getattr(self, "_code_mode_authorizer", None)
            if authorizer is None or not callable(getattr(authorizer, "validate_issued_authorization", None)):
                raise DynamicCollaborationError("Code Mode receipt authorization issuer is unavailable")
            if not authorizer.validate_issued_authorization(
                authorization,
                mode=str(authorization.get("mode") or "MULTI"),
                message=str(controls.get("conversation_user_message") or evidence.goal),
                session_id=str(authorization.get("session_id") or ""),
                workspace=Path(str(authorization.get("workspace") or "")),
            ):
                raise DynamicCollaborationError("Code Mode receipt authorization is not current")
            runtime_binding = {
                "runtime_state_identity": context.identity.state_identity,
                "runtime_journal_id": context.identity.journal_id,
                "issuer_id": "code-mode-offline-runtime-v1",
                "trust_scope": "offline-non-authoritative",
            }
        if evidence.expected_terminal != "SUCCEEDED":
            raise DynamicCollaborationError("Code Mode receipt requires a successful execution")
        if canary_authorization is not None:
            if str(authorization.get("run_id") or "") != evidence.run_id:
                raise DynamicCollaborationError("Code Mode receipt authorization run binding mismatch")
        elif authorization.get("run_id") not in (None, "", evidence.run_id):
            raise DynamicCollaborationError("Code Mode receipt authorization run binding mismatch")
        session_id = str(authorization.get("session_id") or "").strip()
        control_session = str(controls.get("conversation_session_id") or "").strip()
        if not session_id or session_id != control_session:
            raise DynamicCollaborationError("Code Mode receipt authorization session binding mismatch")
        session_instance_id = str(authorization.get("session_instance_id") or "").strip()
        control_instance = str(controls.get("session_instance_id") or "").strip()
        if not session_instance_id or session_instance_id != control_instance:
            raise DynamicCollaborationError("Code Mode receipt authorization instance binding mismatch")
        run_attempt = controls.get("run_attempt")
        if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1:
            raise DynamicCollaborationError("Code Mode receipt run attempt is invalid")
        if not isinstance(controls.get("execution_workspace"), str):
            raise DynamicCollaborationError("Code Mode receipt has no selected execution workspace")
        selected_workspace = Path(str(controls["execution_workspace"])).expanduser().resolve(strict=True)
        if selected_workspace.is_symlink() or str(selected_workspace) != str(authorization.get("workspace") or ""):
            raise DynamicCollaborationError("Code Mode receipt authorization workspace binding mismatch")
        # The baseline is the immutable authorization input for this run.  It
        # must be validated before any field is read from it; otherwise a
        # malformed handoff can turn a successful seal into an incidental
        # UnboundLocalError instead of a deterministic refusal.
        baseline_identity = controls.get("baseline_authorization_identity")
        baseline_candidate = controls.get("code_mode_candidate")
        if not isinstance(baseline_identity, Mapping) or not isinstance(baseline_candidate, Mapping):
            raise DynamicCollaborationError("Code Mode baseline authorization identity is missing")
        code_authorization = controls.get("code_mode_authorization")
        if not isinstance(code_authorization, Mapping) or code_authorization.get("intent_authorized") is not True:
            raise DynamicCollaborationError("Code Mode receipt requires the issued mutation intent authorization")
        if (
            str(code_authorization.get("session_instance_id") or "") != session_instance_id
            or str(code_authorization.get("session_id") or "") != session_id
            or str(code_authorization.get("workspace") or "") != str(selected_workspace)
            or code_authorization.get("run_attempt") != run_attempt
            or str(code_authorization.get("generation") or "") != str(baseline_identity.get("generation") or "")
        ):
            raise DynamicCollaborationError("Code Mode receipt code authorization binding mismatch")
        current_binding_assertion = getattr(context, "assert_current_code_mode_binding", None)
        if callable(current_binding_assertion):
            current_binding_assertion(
                session_instance_id=session_instance_id,
                session_id=session_id,
                run_id=str(evidence.run_id),
                run_attempt=run_attempt,
                generation=str(baseline_identity.get("generation") or ""),
                workspace=selected_workspace,
            )
        if baseline_identity.get("workspace") != str(selected_workspace):
            raise DynamicCollaborationError("Code Mode baseline workspace identity mismatch")
        for field in (
            "candidate_id", "tree_hash", "source_manifest_hash", "worktree_digest", "generation",
        ):
            if baseline_identity.get(field) != code_authorization.get(field):
                raise DynamicCollaborationError("Code Mode baseline authorization identity mismatch: " + field)
        if (
            baseline_candidate.get("candidate_id") != baseline_identity.get("candidate_id")
            or baseline_candidate.get("tree_hash") != baseline_identity.get("tree_hash")
            or baseline_candidate.get("worktree_digest") != baseline_identity.get("worktree_digest")
        ):
            raise DynamicCollaborationError("Code Mode baseline candidate does not match its authorization identity")
        execution = dict(evidence.execution_result or {})
        if execution.get("accepted") is not True or not isinstance(execution.get("diff_paths"), list) or not execution["diff_paths"]:
            raise DynamicCollaborationError("Code Mode receipt requires an accepted Forge diff")
        diff_hash = str(execution.get("patch_manifest_hash") or "")
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", diff_hash):
            raise DynamicCollaborationError("Code Mode receipt requires a verified patch manifest hash")
        verification = execution.get("verification") if isinstance(execution.get("verification"), Mapping) else {}
        tester_hash = execution.get("test_evidence_hash") or verification.get("test_evidence_hash")
        if not isinstance(tester_hash, str) or not tester_hash:
            raise DynamicCollaborationError("Code Mode receipt requires real Tester evidence")
        events = tuple(event for event in journal.iter_events(0) if event.stream_id == run_stream.stream_id)
        payloads = [event.payload for event in events if isinstance(event.payload, Mapping)]
        run_created = next(
            (payload for payload in payloads if payload.get("event_type") == "run.created"), None
        )
        if not isinstance(run_created, Mapping):
            raise DynamicCollaborationError("Code Mode receipt requires the original run authorization fact")
        persisted_controls = run_created.get("acceptance_controls")
        persisted_authorization = (
            persisted_controls.get("canary_authorization")
            if canary_authorization is not None and isinstance(persisted_controls, Mapping)
            else persisted_controls.get("code_mode_authorization")
            if isinstance(persisted_controls, Mapping)
            else None
        )
        latest_attempt_reader = getattr(context, "latest_execution_attempt", None)
        if not callable(latest_attempt_reader):
            raise DynamicCollaborationError("Code Mode receipt requires the latest-attempt verifier")
        try:
            latest_attempt = latest_attempt_reader(
                journal=journal,
                run_id=str(evidence.run_id),
                session_id=session_id,
                generation=str(baseline_identity.get("generation") or ""),
                workspace=selected_workspace,
            )
        except Exception as error:
            raise DynamicCollaborationError("Code Mode attempt chain could not be reopened") from error
        if latest_attempt.get("run_attempt") != run_attempt:
            raise DynamicCollaborationError("Code Mode receipt attempt is not the latest authenticated attempt")
        latest_execution_authorization_ref = latest_attempt.get("authorization_ref")
        if not isinstance(latest_execution_authorization_ref, str) or not latest_execution_authorization_ref:
            raise DynamicCollaborationError("Code Mode latest execution authorization is missing")
        if run_attempt > 1:
            persisted_authorization = latest_attempt.get("code_mode_authorization")
            replan_ref = latest_attempt.get("replan_plan_ref")
            if not isinstance(replan_ref, str) or not replan_ref:
                raise DynamicCollaborationError("Code Mode latest attempt has no replan receipt")
            try:
                replan_object = cas.resolve_reference(replan_ref)
                if replan_object.plaintext_commitment != str(latest_attempt.get("replan_plan_receipt_hash") or ""):
                    raise DynamicCollaborationError("Code Mode replan receipt commitment is not exact")
                replan_raw = cas.open_verified(replan_object)
            except Exception as error:
                if isinstance(error, DynamicCollaborationError):
                    raise
                raise DynamicCollaborationError("Code Mode replan receipt could not be reopened") from error
            expected_replan_body = {
                "schema": "SITINA_EXECUTION_REPLAN_PLAN_V1",
                "session_instance_id": latest_attempt.get("session_instance_id"),
                "session_id": latest_attempt.get("session_id"),
                "run_id": latest_attempt.get("run_id"),
                "run_attempt": latest_attempt.get("run_attempt"),
                "previous_authorization_ref": latest_attempt.get("previous_authorization_ref"),
                "original_intent_hash": (
                    (authorization.get("intent") or {}).get("intent_hash")
                    if isinstance(authorization.get("intent"), Mapping)
                    else None
                ),
                "original_plan_hash": (
                    latest_attempt.get("original_plan_hash")
                    or (latest_attempt.get("execution_authorization") or {}).get("original_plan_hash")
                ),
                "original_execution_plan": (
                    latest_attempt.get("original_execution_plan")
                    or (latest_attempt.get("execution_authorization") or {}).get("original_execution_plan")
                ),
                "execution_mode": "forge",
                "mutation_required": True,
                "recovery_mode": (
                    latest_attempt.get("recovery_mode")
                    or (latest_attempt.get("execution_authorization") or {}).get("recovery_mode")
                ),
                "prior_plan_hash": latest_attempt.get("prior_plan_hash"),
                "prior_failure_type": latest_attempt.get("prior_failure_type"),
                "prior_failure_hash": latest_attempt.get("prior_failure_hash"),
                "reason_code": (
                    latest_attempt.get("reason_code")
                    or (latest_attempt.get("execution_authorization") or {}).get("reason_code")
                    or "EXECUTION_FAILURE"
                ),
                "failure_stage": (
                    latest_attempt.get("failure_stage")
                    or (latest_attempt.get("execution_authorization") or {}).get("failure_stage")
                    or "Forge"
                ),
                "mutation_count": (
                    latest_attempt.get("mutation_count")
                    if latest_attempt.get("mutation_count") is not None
                    else (latest_attempt.get("execution_authorization") or {}).get("mutation_count") or 0
                ),
                "typed_prior_failure": {
                    "failure_type": latest_attempt.get("prior_failure_type"),
                    "failure_hash": latest_attempt.get("prior_failure_hash"),
                    "reason_code": (
                        latest_attempt.get("reason_code")
                        or (latest_attempt.get("execution_authorization") or {}).get("reason_code")
                        or "EXECUTION_FAILURE"
                    ),
                    "failure_stage": (
                        latest_attempt.get("failure_stage")
                        or (latest_attempt.get("execution_authorization") or {}).get("failure_stage")
                        or "Forge"
                    ),
                    "mutation_count": (
                        latest_attempt.get("mutation_count")
                        if latest_attempt.get("mutation_count") is not None
                        else (latest_attempt.get("execution_authorization") or {}).get("mutation_count") or 0
                    ),
                },
                "plan_hash": latest_attempt.get("replan_plan_hash"),
                **dict(latest_attempt.get("replan_plan") or {}),
            }
            # The CAS commitment proves which object was opened; the bytes
            # themselves must still be the one canonical projection committed
            # by the latest attempt.  Do not use json.loads + mapping equality
            # here: duplicate keys, non-canonical whitespace, and JSON
            # numeric coercions must be observable.
            _require_exact_replan_bytes(replan_raw, expected_replan_body)
        if not isinstance(persisted_authorization, Mapping):
            raise DynamicCollaborationError("Code Mode receipt authorization was not persisted for this run")
        for key in ("session_instance_id", "session_id", "candidate_id", "workspace", "run_attempt", "generation"):
            if persisted_authorization.get(key) != authorization.get(key):
                raise DynamicCollaborationError("Code Mode receipt authorization differs from run.created")
        if canary_authorization is not None and persisted_authorization.get("run_id") != authorization.get("run_id"):
            raise DynamicCollaborationError("Code Mode receipt authorization differs from run.created")
        stage_payloads = {
            stage: next(
                (payload for payload in reversed(payloads)
                 if payload.get("stage") == stage and payload.get("event_type") == "execution.stage"),
                None,
            )
            for stage in ("Controller", "Forge", "Tester", "Reviewer")
        }
        if any(value is None for value in stage_payloads.values()):
            raise DynamicCollaborationError("Code Mode receipt requires Controller, Planner, Forge, Tester and Reviewer")
        latest_authorization_ref = latest_execution_authorization_ref
        if not latest_authorization_ref:
            raise DynamicCollaborationError("Code Mode receipt latest authorization is missing")
        # Planner is different from the other stages: a stale/conflicting
        # Planner fact in the current attempt must not be hidden by selecting
        # the last matching ref.  Collect the complete current-attempt set
        # first, then require exactly one fact before checking its contents.
        stage_payloads["Planner"] = _require_current_attempt_planner(
            payloads,
            run_id=evidence.run_id,
            run_attempt=run_attempt,
        )
        # Every stage is an observation of one authenticated attempt.  Do not
        # accept a stage merely because it is the last event of that name:
        # rework can leave a valid-looking attempt-one event in the same run.
        for stage_name, stage_payload in stage_payloads.items():
            if not isinstance(stage_payload, Mapping):
                raise DynamicCollaborationError("Code Mode stage evidence is not a mapping: " + stage_name)
            if (
                type(stage_payload.get("run_attempt")) is not int
                or stage_payload.get("run_attempt") != run_attempt
                or stage_payload.get("authorization_ref") != latest_authorization_ref
            ):
                raise DynamicCollaborationError(
                    "Code Mode stage evidence is bound to a stale attempt: " + stage_name
                )
        controller = stage_payloads["Controller"] or {}
        planner = stage_payloads["Planner"] or {}
        forge = stage_payloads["Forge"] or {}
        tester_payload = stage_payloads["Tester"] or {}
        reviewer_payload = stage_payloads["Reviewer"] or {}
        if run_attempt > 1:
            latest_plan_fields = {
                "plan_hash": latest_attempt.get("plan_hash"),
                "replan_plan_hash": latest_attempt.get("replan_plan_hash"),
                "replan_plan_ref": latest_attempt.get("replan_plan_ref"),
                "replan_plan": latest_attempt.get("replan_plan"),
            }
            for fact_name, fact in {
                "Controller": controller,
                "Planner": planner,
                "Forge": forge,
                "Tester": tester_payload,
                "Reviewer": reviewer_payload,
            }.items():
                if any(fact.get(field) != expected for field, expected in latest_plan_fields.items()):
                    raise DynamicCollaborationError("Code Mode " + fact_name + " fact uses a stale replan")
        if not controller.get("authorization_ref") or controller.get("workspace") != str(selected_workspace):
            raise DynamicCollaborationError("Code Mode Controller evidence is incomplete")
        if not isinstance(planner.get("plan_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", planner["plan_hash"].removeprefix("sha256:")):
            raise DynamicCollaborationError("Code Mode Planner evidence is incomplete")
        review_decision = str(reviewer_payload.get("decision") or "").casefold()
        if review_decision not in {"accept", "accepted"} or reviewer_payload.get("post_execution") is not True:
            raise DynamicCollaborationError("Code Mode receipt requires the post-execution Reviewer acceptance")
        if tester_payload.get("accepted") is not True:
            raise DynamicCollaborationError("Code Mode Tester did not accept the execution")
        stage_results = {
            "Controller": bool(controller.get("authorization_ref")) and controller.get("workspace") == str(selected_workspace),
            "Planner": isinstance(planner.get("plan_hash"), str),
            "Forge": False,
            "Tester": tester_payload.get("accepted") is True,
            "Reviewer": review_decision in {"accept", "accepted"} and reviewer_payload.get("post_execution") is True,
        }
        forge_event = next(
            (payload for payload in reversed(payloads) if payload.get("event_type") == "forge.execution.result"),
            {},
        )
        if (
            type(forge_event.get("run_attempt")) is not int
            or forge_event.get("run_attempt") != run_attempt
            or forge_event.get("authorization_ref") != latest_authorization_ref
        ):
            raise DynamicCollaborationError("Code Mode Forge result is bound to a stale attempt")
        if forge_event.get("accepted") is not True:
            raise DynamicCollaborationError("Code Mode Forge evidence is not accepted")
        if run_attempt > 1:
            if any(forge_event.get(field) != expected for field, expected in latest_plan_fields.items()):
                raise DynamicCollaborationError("Code Mode Forge result uses a stale replan")
            attempt_ledger = forge_event.get("attempt_ledger")
            if (
                not isinstance(attempt_ledger, list)
                or not attempt_ledger
                or attempt_ledger[-1].get("attempt") != run_attempt
                or attempt_ledger[-1].get("plan_hash") != latest_plan_fields["plan_hash"]
            ):
                raise DynamicCollaborationError("Code Mode attempt ledger uses a stale replan")
        stage_results["Forge"] = True
        if not all(stage_results.values()):
            raise DynamicCollaborationError("Code Mode stage evidence is not uniformly successful")
        stages = {
            stage: {"status": "passed" if passed else "failed"}
            for stage, passed in stage_results.items()
        }
        tool_count = forge_event.get("embedded_tool_call_count")
        if not isinstance(tool_count, int) or tool_count <= 0:
            raise DynamicCollaborationError("Code Mode receipt requires an observed file-tool call")
        if side_effect_counts.get("observation_status") != "journal-derived" or side_effect_counts.get("observation_run_id") != evidence.run_id:
            raise DynamicCollaborationError("Code Mode side-effect observer is unavailable or not run-bound")
        if not isinstance(side_effect_counts.get("observation_receipt"), str) or not side_effect_counts["observation_receipt"]:
            raise DynamicCollaborationError("Code Mode side-effect observer has no receipt")
        # An accepted managed execution is intentionally still live while
        # this first receipt is sealed: the Tester machine receipt binds the
        # real worktree observation that the TTY/Gate will reopen later.  The
        # cleanup-finally fact is therefore a terminal/finalization
        # invariant, not a REVIEW_PENDING checkpoint invariant.
        managed_review_pending = bool(
            not finalize_stream
            and controls.get("_code_mode_managed_worktree_for_review") is True
        )
        cleanup_events = [
            payload for payload in payloads
            if payload.get("event_type") == "execution.worktree.cleanup.finally"
        ]
        if managed_review_pending:
            if cleanup_events:
                # A managed root that was already cleaned cannot produce a
                # valid pending Tester observation.  Do not silently accept
                # an out-of-order cleanup fact.
                raise DynamicCollaborationError(
                    "Code Mode managed worktree was cleaned before REVIEW_PENDING"
                )
            cleanup_status = "DEFERRED_REVIEW_PENDING"
            worktree_cleanup = {
                "status": cleanup_status,
                "removed": False,
                "physical_removed": False,
                "audit_recorded": False,
            }
        else:
            if len(cleanup_events) != 1:
                raise DynamicCollaborationError("Code Mode cleanup evidence is missing or duplicated")
            worktree_cleanup = cleanup_events[0]
            cleanup_status = str(worktree_cleanup.get("status") or "")
            if cleanup_status not in {"ok", "not_present"} or worktree_cleanup.get("removed") is not True or worktree_cleanup.get("audit_recorded") is not True:
                raise DynamicCollaborationError("Code Mode worktree cleanup was not verified")
            if cleanup_status == "ok" and worktree_cleanup.get("physical_removed") is not True:
                raise DynamicCollaborationError("Code Mode worktree physical cleanup was not verified")
        related_events = tuple(
            event for event in journal.iter_events(0)
            if event.stream_id == run_stream.stream_id
            or str(event.stream_id).startswith(f"run/forge-exec-{evidence.run_id}-")
        )
        process_cleanup_events = [
            event for event in related_events
            if isinstance(event.payload, Mapping)
            and event.payload.get("event_type") == "autonomous.managed-process-cleanup"
        ]
        if not process_cleanup_events:
            raise DynamicCollaborationError("Code Mode managed-process cleanup evidence is missing")
        for process_cleanup_event in process_cleanup_events:
            process_record_ref = process_cleanup_event.payload.get("record_ref")
            if not isinstance(process_record_ref, str):
                raise DynamicCollaborationError("Code Mode managed-process cleanup has no durable record")
            try:
                process_record = json.loads(cas.open_verified(cas.resolve_reference(process_record_ref)).decode("utf-8"))
            except Exception as error:
                raise DynamicCollaborationError("Code Mode managed-process cleanup record cannot be reopened") from error
            process_payload = process_record.get("payload") if isinstance(process_record, Mapping) else None
            if not isinstance(process_payload, Mapping) or process_record.get("event") != "managed_process_cleanup":
                raise DynamicCollaborationError("Code Mode managed-process cleanup record is invalid")
            if process_payload.get("failures") not in ([], None):
                raise DynamicCollaborationError("Code Mode managed-process cleanup reported failures")
        cleanup_ok = (
            not managed_review_pending
            and cleanup_status in {"ok", "not_present"}
            and worktree_cleanup.get("removed") is True
            and worktree_cleanup.get("audit_recorded") is True
            and (cleanup_status != "ok" or worktree_cleanup.get("physical_removed") is True)
        )
        if not managed_review_pending and not cleanup_ok:
            raise DynamicCollaborationError("Code Mode cleanup was not successful")
        cleanup_observation = {
            "worktree": {
                "status": cleanup_status,
                "removed": worktree_cleanup.get("removed"),
                "physical_removed": worktree_cleanup.get("physical_removed"),
                "audit_recorded": worktree_cleanup.get("audit_recorded"),
            },
            "managed_process": {
                "cleanup_event_ids": [event.event_id for event in process_cleanup_events],
                "failures": [],
            },
        }
        profile = executor.actual_provider_profile()
        provider_profile = str(getattr(profile, "name", "") or "")
        provider_model = str(getattr(profile, "model", "") or "")
        usage = executor.usage_totals()
        token_usage = {
            "input": int(usage["input_tokens"]),
            "output": int(usage["output_tokens"]),
            "total": int(usage["total_tokens"]),
        }
        if not provider_profile or not provider_model or token_usage["input"] <= 0 or token_usage["output"] <= 0:
            raise DynamicCollaborationError("Code Mode receipt requires settled provider usage")
        before = str(getattr(self, "_code_mode_production_sentinel_before", "") or "")
        # Scripted/offline providers are deliberately non-authoritative. Do
        # not scan the multi-gigabyte production home for an offline receipt;
        # record that the independent production observation was not made and
        # let the canary gate reject the non-authoritative transport.
        sentinel_observed = before != "offline-not-observed"
        after = before if not sentinel_observed else self._observe_code_mode_production_sentinel()
        if not before or (sentinel_observed and before != after):
            raise DynamicCollaborationError("Code Mode production sentinel is unavailable or changed")
        side_effect_observer_hash = stable_hash("CODE_MODE_SIDE_EFFECT_OBSERVER", dict(side_effect_counts))
        completion = {
            # This is the observer's own Journal-derived receipt, not a
            # sealer-generated boolean.  The Gate recomputes it from the same
            # run stream before accepting the CAS receipt.
            "side_effect_observation_receipt": side_effect_counts["observation_receipt"],
            "side_effect_observed_event_ids": list(side_effect_counts["observed_event_ids"]),
            "side_effect_observer_hash": side_effect_observer_hash,
            "cleanup": cleanup_ok,
            "cleanup_observation": cleanup_observation,
            "production_sentinel_before": before,
            "production_sentinel_after": after,
            "production_sentinel_observed": sentinel_observed,
            "production_sentinel_unchanged": sentinel_observed and before == after,
            "production_sentinel_allowlist": sorted(self._CODE_MODE_SENTINEL_EXCLUDED_RUNTIME_ROOTS),
            "production_sentinel_identity_roots": list(self._CODE_MODE_SENTINEL_IDENTITY_ROOTS),
            "production_sentinel_excluded_runtime_roots": list(self._CODE_MODE_SENTINEL_EXCLUDED_RUNTIME_ROOTS),
        }
        provider_facts = {
            "provider_profile": provider_profile,
            "provider_model": provider_model,
            "physical_send_count": executor.physical_send_total(),
            "fallback_count": int(usage["fallback_count"]),
            "token_usage": token_usage,
            "transport_authoritative": bool(getattr(executor.transport, "authoritative_physical", False)),
            "transport_receipts": [dict(item) for item in executor.provider_transport_receipts()],
        }
        if provider_facts["transport_authoritative"]:
            ledger_getter = getattr(context, "_authoritative_transport_ledger", None)
            if not callable(ledger_getter):
                raise DynamicCollaborationError("Code Mode provider ledger is unavailable")
            ledger, ledger_capability = ledger_getter()
            ledger_receipts = [dict(item) for item in ledger.snapshot(ledger_capability)]
            if ledger_receipts != provider_facts["transport_receipts"]:
                raise DynamicCollaborationError("Code Mode provider receipts are not ledger-complete")
            provider_facts["transport_ledger_hash"] = hashlib.sha256(
                canonical_json_bytes(ledger_receipts)
            ).hexdigest()
        else:
            provider_facts["transport_ledger_hash"] = None
        execution_facts = {
            "tool_call_count": tool_count,
            "changed_paths": list(execution["diff_paths"]),
            "diff_hash": diff_hash,
        }
        tester_ref = execution.get("test_evidence_ref") or verification.get("test_evidence_ref") or tester_payload.get("test_evidence_ref")
        if not isinstance(tester_ref, str) or not tester_ref.startswith("cas:"):
            raise DynamicCollaborationError("Code Mode Tester evidence has no CAS reference")
        try:
            tester_evidence = json.loads(cas.open_verified(cas.resolve_reference(tester_ref)).decode("utf-8"))
        except Exception as error:
            raise DynamicCollaborationError("Code Mode Tester evidence cannot be reopened") from error
        if not isinstance(tester_evidence, Mapping) or hashlib.sha256(canonical_json_bytes(tester_evidence)).hexdigest() != tester_hash:
            raise DynamicCollaborationError("Code Mode Tester evidence hash does not match its CAS object")
        if managed_review_pending:
            # Bind the deferred lifecycle state to the same durable Tester
            # cwd that will be used by the finalizer.  A displayed path or an
            # old scalar is insufficient: the run-scoped managed root must be
            # present now and its full observation must be reproducible.
            raw_tester_cwd = tester_evidence.get("cwd")
            raw_execution_root = execution.get("workspace") or controls.get("_code_mode_execution_root")
            if not isinstance(raw_tester_cwd, str) or not raw_tester_cwd.strip():
                raise DynamicCollaborationError("Code Mode pending Tester evidence has no workspace locator")
            if not isinstance(raw_execution_root, str) or not raw_execution_root.strip():
                raise DynamicCollaborationError("Code Mode pending execution has no managed root locator")
            try:
                tester_cwd_path = Path(raw_tester_cwd).expanduser()
                execution_root_path = Path(raw_execution_root).expanduser()
                if tester_cwd_path.is_symlink() or execution_root_path.is_symlink():
                    raise ValueError("managed root locator is a symlink")
                tester_root = tester_cwd_path.resolve(strict=True)
                execution_root = execution_root_path.resolve(strict=True)
                expected_root = (
                    self.home / "artifacts" / "worktrees" / str(evidence.run_id)
                ).expanduser().resolve(strict=False)
                if (
                    not tester_root.is_dir()
                    or tester_root != execution_root
                    or tester_root != expected_root
                ):
                    raise ValueError("Tester cwd is not the authenticated run-scoped managed root")
                from sitina.orchestrator.code_mode_runtime import _workspace_observation_hash
                pending_observation_hash = _workspace_observation_hash(tester_root)
            except Exception as error:
                raise DynamicCollaborationError(
                    "Code Mode pending managed workspace observation is unavailable"
                ) from error
            cleanup_observation["worktree"].update({
                "root": str(tester_root),
                "root_present": True,
                "workspace_observation_after_hash": pending_observation_hash,
            })
        if tester_evidence.get("accepted") is not True or type(tester_evidence.get("runner_return_code")) is not int or tester_evidence.get("runner_return_code") != 0:
            raise DynamicCollaborationError("Code Mode Tester evidence is not a passing verification")
        tester_passed = (
            tester_evidence.get("accepted") is True
            and type(tester_evidence.get("runner_return_code")) is int
            and tester_evidence.get("runner_return_code") == 0
        )
        tester = {
            "status": "passed" if tester_passed else "failed",
            "return_code": tester_evidence.get("runner_return_code"),
            "evidence_hash": tester_hash,
        }
        if not tester_passed:
            raise DynamicCollaborationError("Code Mode Tester evidence is not a passing verification")
        # This is the execution-loop review performed by the registered
        # reviewer agent.  It is not the final Code Mode review: the latter is
        # the controller-bound TTY/Gate decision and is intentionally absent
        # until ``finalize_code_mode_review``.  Keeping the two facts separate
        # prevents a successful Forge review from being mistaken for human
        # approval of the pending run.
        execution_reviewer = {
            "post_execution": reviewer_payload.get("post_execution") is True,
            "decision": "ACCEPT" if review_decision in {"accept", "accepted"} else "REJECT",
            "attempt": reviewer_payload.get("attempt"),
            "patch_manifest_hash": reviewer_payload.get("patch_manifest_hash"),
            "tester_evidence_hash": reviewer_payload.get("tester_evidence_hash"),
        }

        def append_fact(stage: str, payload: Mapping[str, Any]) -> None:
            run_stream.append(stage, (dict(payload),), actor="code-mode-receipt-sealer")

        append_fact("code-mode-authorization-fact", {
            "schema": "CODE_MODE_AUTHORIZATION_FACT_V1",
            "authorization_id": authorization.get("authorization_id"),
            "session_id": authorization.get("session_id"),
            "candidate_id": authorization.get("candidate_id"),
            "run_id": evidence.run_id,
            "workspace": authorization.get("workspace"),
            "intent_authorized": code_authorization.get("intent_authorized") is True,
            **runtime_binding,
        })
        for stage, value in stages.items():
            append_fact("code-mode-stage-fact", {"schema": "CODE_MODE_STAGE_FACT_V1", "stage": stage, "stage_result": value})
        append_fact("code-mode-provider-fact", {"schema": "CODE_MODE_PROVIDER_FACT_V1", "provider_facts": provider_facts})
        append_fact("code-mode-execution-fact", {"schema": "CODE_MODE_EXECUTION_FACT_V1", "execution_facts": execution_facts})
        append_fact("code-mode-tester-fact", {"schema": "CODE_MODE_TESTER_FACT_V1", "tester": tester})
        append_fact(
            "code-mode-execution-review-fact",
            {
                "schema": "CODE_MODE_EXECUTION_REVIEW_FACT_V1",
                "execution_reviewer": execution_reviewer,
                "run_id": evidence.run_id,
                "candidate_id": authorization.get("candidate_id"),
                "generation": runtime_binding.get("generation"),
                "patch_manifest_hash": diff_hash,
                "tester_evidence_hash": tester_hash,
            },
        )
        append_fact("code-mode-completion-fact", {"schema": "CODE_MODE_COMPLETION_FACT_V1", "completion_facts": completion})

        generation = str(
            runtime_binding.get("generation")
            or getattr(getattr(context, "identity", None), "epoch_root", "")
            or ""
        )
        if not generation:
            raise DynamicCollaborationError("Code Mode Review V2 handoff lacks current generation/source identity")

        # The baseline candidate authorizes the starting workspace only.  The
        # final candidate is frozen after Forge has applied its verified patch
        # and the execution evidence is complete; Gate reviews this output
        # identity, never the pre-tool baseline.
        from sitina.orchestrator.code_mode_gate import build_candidate_manifest
        from sitina.journal.model import parse_canonical_json
        patch_manifest_ref = execution.get("patch_manifest_ref")
        patch_manifest_hash = str(execution.get("patch_manifest_hash") or diff_hash)
        if not isinstance(patch_manifest_ref, str) or not re.fullmatch(
            r"cas:[0-9a-f]{64}", patch_manifest_ref
        ):
            raise DynamicCollaborationError("Code Mode output candidate lacks a durable patch manifest")
        try:
            patch_object = cas.resolve_reference(patch_manifest_ref)
            patch_publication = cas.verify_existing(patch_object)
            if not patch_publication.fresh_verified or not patch_publication.no_replace_published:
                raise ValueError("patch manifest CAS proof is not fresh and no-replace")
            reopened_patch = parse_canonical_json(cas.open_verified(patch_object))
        except Exception as error:
            raise DynamicCollaborationError("Code Mode patch manifest could not be reopened") from error
        if not isinstance(reopened_patch, Mapping) or reopened_patch.get("schema") != "SITINA_EXECUTION_PATCH_MANIFEST_V2":
            raise DynamicCollaborationError("Code Mode output patch manifest schema is invalid")
        reopened_patch_hash = sha256_bytes(canonical_json_bytes(reopened_patch))
        if reopened_patch_hash != patch_manifest_hash.removeprefix("sha256:"):
            raise DynamicCollaborationError("Code Mode output patch manifest identity changed")
        if reopened_patch.get("run_id") != evidence.run_id:
            raise DynamicCollaborationError("Code Mode output patch manifest run binding changed")
        patch_entries = reopened_patch.get("entries")
        if not isinstance(patch_entries, list) or not patch_entries:
            raise DynamicCollaborationError("Code Mode output candidate has no reviewed patch entries")
        output_changed_paths: list[str] = []
        for entry in patch_entries:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
                raise DynamicCollaborationError("Code Mode patch entry has no changed path identity")
            output_changed_paths.append(str(entry["path"]))
            if str(entry.get("operation")) == "rename":
                if not isinstance(entry.get("destination"), str) or not entry.get("destination"):
                    raise DynamicCollaborationError("Code Mode rename entry has no destination identity")
                output_changed_paths.append(str(entry["destination"]))
        try:
            output_candidate = build_candidate_manifest(
                selected_workspace,
                # The baseline identity authorizes only the starting state.
                # Re-inventory the post-apply workspace so root-level and
                # newly-created user files cannot be omitted, while retaining
                # explicit tombstone paths from the reviewed patch manifest.
                identity_paths=None,
                changed_paths=output_changed_paths,
            )
        except Exception as error:
            raise DynamicCollaborationError("Code Mode final workspace candidate could not be frozen") from error
        candidate_manifest = {
            **output_candidate,
            "generation": generation,
            "authorization_ref": latest_execution_authorization_ref,
            # Candidate-manifest facts are producer facts, not display
            # projections.  Bind the final output to the exact CLI/run
            # namespace before it is published so the host can require one
            # current candidate producer in its authenticated snapshot.
            "session_instance_id": controls.get("session_instance_id"),
            "run_attempt": controls.get("run_attempt"),
            "session_id": session_id,
            "turn_index": controls.get("conversation_turn_index"),
        }
        candidate_locator = context.seal_candidate_manifest(
            candidate=dict(candidate_manifest),
            run_id=evidence.run_id,
            journal=journal,
            cas=cas,
            run_stream=run_stream,
        )

        # The Review V2 handoff is produced by the actual execution path.  It
        # is deliberately sealed only after the real Forge/Tester/cleanup
        # facts above exist, and before the terminal receipt root closes the
        # stream.  No caller-supplied result mapping can manufacture this
        # package because every locator below is reopened from the current
        # run's CAS/Journal by the runtime context.
        candidate_id = str(candidate_manifest.get("candidate_id") or "")
        tree_hash = str(candidate_manifest.get("tree_hash") or "")
        source_manifest_hash = str(
            candidate_manifest.get("source_manifest_hash")
            or getattr(getattr(context, "identity", None), "source_manifest_hash", "")
        )
        if not candidate_id or not re.fullmatch(r"[0-9a-f]{64}", tree_hash.removeprefix("sha256:")):
            raise DynamicCollaborationError("Code Mode Review V2 handoff lacks the current candidate identity")
        if not generation or not source_manifest_hash:
            raise DynamicCollaborationError("Code Mode Review V2 handoff lacks current generation/source identity")
        verifier_identity = str(
            tester_evidence.get("execution_identity_hash")
            or execution.get("execution_identity_hash")
            or ""
        )
        if not re.fullmatch(r"[0-9a-f]{64}", verifier_identity):
            raise DynamicCollaborationError("Code Mode Review V2 handoff lacks the Tester execution identity")
        tester_targets = [
            str(item[0]) for item in tester_evidence.get("target_hashes", [])
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str)
        ]
        machine_before = str(tester_evidence.get("diff_hash_before") or "")
        machine_after = str(tester_evidence.get("diff_hash_after") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", machine_before) or not re.fullmatch(r"[0-9a-f]{64}", machine_after):
            raise DynamicCollaborationError("Code Mode Tester evidence lacks current worktree hashes")
        worktree_delta_hash = hashlib.sha256(canonical_json_bytes({
            "before": machine_before, "after": machine_after,
        })).hexdigest()
        try:
            tester_root = Path(str(tester_evidence.get("cwd") or "")).expanduser().resolve(strict=True)
            from sitina.orchestrator.code_mode_runtime import _workspace_observation_hash
            workspace_observation_after_hash = _workspace_observation_hash(tester_root)
        except Exception as error:
            raise DynamicCollaborationError(
                "Code Mode Tester workspace observation is unavailable"
            ) from error
        machine_command = _tester_machine_command(tester_evidence, tester_targets)
        machine_body = {
            "schema": "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
            "status": "MACHINE_CHECK_READY",
            "execution_observed": True,
            "candidate_id": candidate_id,
            "tree_hash": tree_hash,
            "source_manifest_hash": source_manifest_hash,
            "baseline_authorization_identity": dict(baseline_identity),
            # The candidate digest describes the frozen source inventory;
            # the before/after hashes below describe the selected execution
            # workspace.  Keep those identities distinct so a user-file
            # mutation cannot masquerade as candidate drift (or vice versa).
            "candidate_worktree_digest": str(candidate_manifest.get("worktree_digest") or ""),
            "candidate_manifest_ref": candidate_locator["reference_id"],
            "candidate_manifest_hash": candidate_locator["content_hash"],
            "worktree_before_hash": machine_before,
            "worktree_after_hash": machine_after,
            "workspace_observation_after_hash": workspace_observation_after_hash,
            # ``diff_hash`` is the immutable Forge patch identity.  The
            # Tester worktree transition has its own identity so the two
            # observations cannot silently diverge.
            "diff_hash": diff_hash,
            "worktree_delta_hash": worktree_delta_hash,
            "run_id": evidence.run_id,
            "authorization_ref": latest_execution_authorization_ref,
            "session_instance_id": controls.get("session_instance_id"),
            "run_attempt": controls.get("run_attempt"),
            "session_id": session_id,
            "turn_index": controls.get("conversation_turn_index"),
            "generation": generation,
            "verifier_identity": verifier_identity,
            "command": machine_command,
            "command_hash": hashlib.sha256(canonical_json_bytes(machine_command)).hexdigest(),
            "test_inventory": tester_targets,
            "inventory_hash": hashlib.sha256(canonical_json_bytes(tester_targets)).hexdigest(),
            "test_ids": tester_targets,
            "test_evidence_hash": tester_hash,
            "interpreter": str(tester_evidence.get("python_executable_hash") or ""),
            "dependencies": {"sandbox_policy_hash": tester_evidence.get("sandbox_policy_hash")},
            "cwd": tester_evidence.get("cwd"),
            "return_code": tester_evidence.get("runner_return_code"),
            "failures": tester_evidence.get("failed_test_count"),
            "errors": tester_evidence.get("error_test_count"),
            "skipped": tester_evidence.get("skipped_test_count"),
            "unexpected_successes": tester_evidence.get("unexpected_success_count"),
            "output_summary": {
                "stdout_hash": tester_evidence.get("stdout_hash"),
                "stderr_hash": tester_evidence.get("stderr_hash"),
            },
            "expires_at": int(time.time()) + 120,
        }
        # Publish the machine receipt on the already-open controller CAS and
        # stream.  Calling the generic offline publisher here would attempt a
        # second Journal writer while terminalization owns the first one.
        machine_body["runtime_state_identity"] = context.identity.state_identity
        machine_body["runtime_journal_id"] = context.identity.journal_id
        machine_body["issuer_identity"] = "code-mode-offline-runtime-v1"
        machine_body["authority_class"] = "OFFLINE_NON_AUTHORITATIVE"
        machine_body["content_hash"] = hashlib.sha256(canonical_json_bytes(machine_body)).hexdigest()
        machine_publication = cas.publish_plaintext(
            canonical_json_bytes(machine_body), tenant_id="code-mode-evidence",
            purpose_class="code-mode-machine-check", media_type="application/json",
        )
        if not machine_publication.receipt.fresh_verified or not machine_publication.receipt.no_replace_published:
            raise DynamicCollaborationError("Code Mode machine receipt CAS publication was not immutable")
        machine_fact_receipt, machine_fact_refs = run_stream.append_code_mode_fact(
            "code-mode-machine-check",
            ({
                "schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
                "evidence_schema": "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
                "purpose_class": "code-mode-machine-check",
                "reference_id": machine_publication.receipt.object_ref.reference_id,
                "content_hash": machine_body["content_hash"],
                "candidate_id": candidate_id, "tree_hash": tree_hash,
                "run_id": evidence.run_id, "session_id": session_id,
                "session_instance_id": controls.get("session_instance_id"),
                "run_attempt": controls.get("run_attempt"),
                "turn_index": controls.get("conversation_turn_index"),
                "generation": generation, "verifier_identity": verifier_identity,
                "issuer_identity": machine_body["issuer_identity"],
                "authority_class": machine_body["authority_class"],
                "worktree_digest": machine_after, "diff_hash": diff_hash,
                "worktree_delta_hash": worktree_delta_hash,
                "closing_root": False,
                "_object_refs": [machine_publication.receipt.object_ref.reference_id],
            },), actor="code-mode-receipt-sealer", proofs=(machine_publication.receipt,)
        )
        machine_locator = {
            "schema": "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
            "reference_id": machine_publication.receipt.object_ref.reference_id,
            "object_hash": machine_publication.receipt.object_ref.object_id,
            "content_hash": machine_body["content_hash"],
            "receipt_hash": machine_body["content_hash"],
            "run_id": evidence.run_id,
            "journal_event_hash": machine_fact_refs[0]["event_hash"],
            "fresh_verified": True, "no_replace_published": True,
        }

        forge_event_hash = sha256_bytes(canonical_json_bytes(forge_event))
        closing_receipt, closing_refs = run_stream.append_code_mode_fact(
            "code-mode-evidence-closing-root",
            ({
                "schema": "CODE_MODE_EVIDENCE_CLOSING_ROOT_V1",
                "event_type": "code-mode.evidence.closing-root",
                "purpose_class": "code-mode-evidence-closing-root",
                "run_id": evidence.run_id,
                "session_id": session_id,
                "candidate_id": candidate_id,
                "tree_hash": tree_hash,
                "generation": generation,
                "verifier_identity": machine_body["verifier_identity"],
                "forge_execution_event_hash": forge_event_hash,
                "tester_evidence_hash": tester_hash,
                "cleanup_observed": True,
                "cleanup_status": cleanup_status,
                "cleanup_observation": cleanup_observation,
            },),
            actor="code-mode-receipt-sealer",
        )
        closing_root_event_hash = str(closing_refs[-1]["event_hash"])
        package_body = {
            "schema": "CODE_MODE_EVIDENCE_PACKAGE_V1",
            "candidate_id": candidate_id,
            "tree_hash": tree_hash,
            "source_manifest_hash": source_manifest_hash,
            "baseline_authorization_identity": dict(baseline_identity),
            "candidate_manifest_ref": candidate_locator["reference_id"],
            "candidate_manifest_hash": candidate_locator["content_hash"],
            "candidate_worktree_digest": str(candidate_manifest.get("worktree_digest") or ""),
            "worktree_before_hash": machine_before,
            "worktree_after_hash": machine_after,
            "diff_hash": diff_hash,
            "worktree_delta_hash": worktree_delta_hash,
            "run_id": evidence.run_id,
            "authorization_ref": latest_execution_authorization_ref,
            "session_instance_id": controls.get("session_instance_id"),
            "run_attempt": controls.get("run_attempt"),
            "session_id": session_id,
            "turn_index": controls.get("conversation_turn_index"),
            "generation": generation,
            "verifier_identity": machine_body["verifier_identity"],
            "machine_check_ref": machine_locator["reference_id"],
            "machine_check_hash": machine_locator["content_hash"],
            "provider_profile": provider_profile,
            "provider_model": provider_model,
            "execution_receipt_refs": {
                "patch_manifest": str(execution.get("patch_manifest_ref") or ""),
                "tester_evidence": tester_ref,
                "forge_execution": str(execution.get("test_evidence_ref") or tester_ref),
            },
            "tool_ledger": {
                "observed": True,
                "count": tool_count,
                "forge_event_hash": forge_event_hash,
                "mutation_event_count": len(forge_event.get("mutation_events") or []),
            },
            "tester": {
                "receipt_ref": machine_locator["reference_id"],
                "receipt_hash": machine_locator["content_hash"],
                "status": "MACHINE_CHECK_READY",
                "accepted": True,
                "evidence_hash": tester_hash,
            },
            "cleanup": {
                "observed": True,
                "status": cleanup_status,
                **cleanup_observation,
            },
            "closing_root": {"sealed": True, "event_hash": closing_root_event_hash},
            "closing_root_event_hash": closing_root_event_hash,
            "execution_attempt_id": execution.get("execution_attempt_id"),
            "expires_at": int(time.time()) + 120,
        }
        package_body["content_hash"] = hashlib.sha256(canonical_json_bytes(package_body)).hexdigest()
        package_locator = context.seal_execution_evidence_package(
            package=package_body,
            run_id=evidence.run_id,
            closing_root_event_hash=closing_root_event_hash,
            journal=journal,
            cas=cas,
            run_stream=run_stream,
        )
        review_request = context.create_execution_review_request(
            candidate={"candidate_id": candidate_id, "tree_hash": tree_hash},
            machine_check=machine_locator,
            evidence_package=package_locator,
            journal=journal,
            cas=cas,
            run_stream=run_stream,
        )

        predecessor_events = tuple(event for event in journal.iter_events(0) if event.stream_id == run_stream.stream_id)
        body = {
            "schema": "CODE_MODE_RUN_RECEIPT_V1",
            "run_id": evidence.run_id,
            "session_id": authorization.get("session_id"),
            "candidate_id": candidate_id,
            "output_candidate_id": candidate_id,
            "output_tree_hash": tree_hash,
            "output_source_manifest_hash": source_manifest_hash,
            "baseline_authorization_identity": dict(baseline_identity),
            "authorization_id": authorization.get("authorization_id"),
            "workspace": authorization.get("workspace"),
            "issuer_id": runtime_binding.get("issuer_id"),
            "resolved_mode": "MULTI",
            "intent_authorized": code_authorization.get("intent_authorized") is True,
            "stages": stages,
            **execution_facts,
            "tester": tester,
            "execution_reviewer": execution_reviewer,
            **provider_facts,
            **completion,
            "journal_event_hashes": [str(event.event_hash) for event in predecessor_events],
            "fresh_verified": True,
            "no_replace_published": True,
            **runtime_binding,
        }
        body["content_hash"] = "sha256:" + sha256_bytes(canonical_json_bytes(body))
        receipt = executor._publish(body, purpose="code-mode-run-receipt")
        root_refs: list[Mapping[str, Any]] = []
        root_transaction_hash = None
        if finalize_stream:
            root_receipt, root_refs = run_stream.append(
                "code-mode-run-receipt-root",
                ({"schema": "CODE_MODE_RECEIPT_ROOT_V1", "run_id": evidence.run_id,
                  "record_ref": receipt.object_ref.reference_id, "receipt_content_hash": body["content_hash"],
                  "_object_refs": [receipt.object_ref.reference_id]},),
                actor="code-mode-receipt-sealer", proofs=(receipt,),
            )
            root_transaction_hash = root_receipt.transaction_hash
            run_stream.seal()
        return {
            "reference_id": receipt.object_ref.reference_id,
            "content_hash": body["content_hash"],
            "root_event_id": root_refs[-1]["event_id"] if root_refs else None,
            "root_event_hash": root_refs[-1]["event_hash"] if root_refs else None,
            "journal_event_count": len(predecessor_events),
            "root_transaction_hash": root_transaction_hash,
            "machine_check_receipt": dict(machine_locator),
            "test_receipt": dict(machine_locator),
            "test_inventory": list(tester_targets),
            "candidate": dict(candidate_manifest),
            "baseline_authorization_identity": dict(baseline_identity),
            "candidate_locator": dict(candidate_locator),
            "evidence_package": dict(package_locator),
            "review_request": dict(review_request),
            "headless_review_pending": True,
            "review_status": "REVIEW_PENDING",
        }

    def _execute_winner(
        self,
        context: Any,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        winner: AgentCallResult,
        winner_agent: Any,
        controls: Mapping[str, Any] | None = None,
    ) -> "ExecutionResult":
        """M2 safe execution bridge (SL layer): drive a Forge loop-instance to
        build the winner, then enforce the migrated handoff invariants via
        run_safe_execution — pre-write + deliverable boundary redaction (H4),
        independent read-only verification of the ACTUAL diff (H11/H12), bounded
        rework with per-attempt isolation (H6). Borrows the orchestrator journal
        (no second writer lock). Returns a formal ExecutionResult."""
        from sitina.extensions.runtime import (
            AutonomousRuntime,
            BoundedToolTurnClient,
            JournalAutonomousAudit,
        )
        from sitina.orchestrator.execution_bridge import (
            ExecutionBinding,
            ExecutionIdentityBinding,
            VerificationVerdict,
            run_safe_execution,
        )
        from sitina.orchestrator.execution_target import (
            ExecutionTargetError,
            WorkspaceBaseline,
            apply_verified_files,
            file_hash,
            overlay_workspace,
        )
        from sitina.orchestrator.managed_processes import ManagedProcessManager
        from sitina.orchestrator.git_ops import GitWorktreeManager
        from sitina.orchestrator.code_mode_controller import CodeModeControllerSession
        from sitina.runners.tool_executor import ToolExecutor
        from sitina.security.redaction import redact_boundary_value

        # The outer execute() owns this mutable control envelope.  Rework
        # must update that same envelope so the post-execution Tester,
        # Reviewer/Gate and sealer cannot observe attempt one after the
        # controller has advanced to attempt two.
        controls = controls if isinstance(controls, dict) else dict(controls or {})
        # Keep every live Forge/transport binding on the run owned by this
        # execution result.  The public CLI reaches this branch after the
        # root calls, so leaving this local unresolved turns a valid root into
        # a caught NameError before Forge can start.
        run_id = evidence.run_id
        code_mode_authorization = controls.get("code_mode_authorization")
        if code_mode_authorization is not None and not isinstance(code_mode_authorization, Mapping):
            raise DynamicCollaborationError("invalid Code Mode authorization binding")
        run_attempt = controls.get("run_attempt")
        if isinstance(code_mode_authorization, Mapping):
            if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1:
                raise DynamicCollaborationError("Code Mode execution attempt is not issued")
        elif run_attempt is None:
            run_attempt = 1
        proposal = winner.value if isinstance(winner.value, Mapping) else {}
        approach = str(proposal.get("approach") or proposal.get("summary") or "")
        acceptance = proposal.get("acceptance_checks") or []
        policy_hash_64 = self.policy_hash.removeprefix("sha256:")
        # FIX2 (identity model): the 8 registry agents are ALL read-only,
        # provider-text-only — Forge included (it is the FAST synthesis agent,
        # asserted read-only in fast_runtime). None may be recorded as having
        # performed a write. The bridge executor is therefore a DISTINCT,
        # write-authorized EXECUTION ROLE (a Forge tool-loop instance), not a
        # registry text agent. The winning text agent is only the PROPOSER.
        proposer_id = getattr(winner_agent, "agent_id", "unknown")
        executor_id = "forge-execution-role"  # write-authorized; not a text agent
        verifier_id = self._independent_verifier_id(proposer_id, executor_id)
        reviewer_id = self._post_execution_reviewer_id(proposer_id, executor_id, verifier_id)
        reviewer_agent = next(
            item for item in self.registry.identities if item.agent_id == reviewer_id
        )
        identity_binding = ExecutionIdentityBinding.from_registry(
            self.registry,
            policy_hash=policy_hash_64,
            authority_resolution=context.authority.resolution,
            proposer_id=proposer_id,
            executor_id=executor_id,
            verifier_id=verifier_id,
            now=int(time.time()),
        )
        raw_workspace = controls.get("execution_workspace") or controls.get("workspace")
        if not isinstance(raw_workspace, str) or not raw_workspace.strip():
            raise DynamicCollaborationError("execution requires an explicit selected workspace")
        selected_workspace = Path(raw_workspace).expanduser().resolve(strict=True)
        if not selected_workspace.is_dir() or selected_workspace.is_symlink():
            raise DynamicCollaborationError("selected execution workspace must be a real directory")
        # The public CLI carries the authenticated conversation binding in the
        # outer controls envelope.  Keep the live Forge path on that same
        # binding; never infer it from a caller-supplied payload or leave the
        # names unresolved until the live-capability branch below.
        conversation_session_id = str(
            controls.get("conversation_session_id")
            or (
                code_mode_authorization.get("session_id")
                if isinstance(code_mode_authorization, Mapping)
                else ""
            )
            or ""
        ).strip()
        conversation_turn_index = controls.get("conversation_turn_index")
        if type(conversation_turn_index) is not int and isinstance(code_mode_authorization, Mapping):
            bound_turn_index = code_mode_authorization.get("turn_index")
            if type(bound_turn_index) is int:
                conversation_turn_index = bound_turn_index
        intent_text = str(controls.get("conversation_user_message") or evidence.goal).strip()
        if isinstance(code_mode_authorization, Mapping):
            if code_mode_authorization.get("allowed") is not True:
                raise DynamicCollaborationError("Code Mode authorization is not admitted")
            authorized_workspace = str(code_mode_authorization.get("workspace") or "")
            if authorized_workspace != str(selected_workspace):
                raise DynamicCollaborationError("Code Mode workspace authorization binding mismatch")
            if str(code_mode_authorization.get("session_id") or "").strip() != str(controls.get("conversation_session_id") or "").strip():
                raise DynamicCollaborationError("Code Mode session authorization binding mismatch")
            authorizer = getattr(self, "_code_mode_authorizer", None)
            if authorizer is None or not callable(getattr(authorizer, "validate_issued_authorization", None)):
                raise DynamicCollaborationError("Code Mode authorization issuer is not bound to this runtime")
            if not authorizer.validate_issued_authorization(
                code_mode_authorization,
                mode=str(code_mode_authorization.get("mode") or ""),
                message=intent_text,
                session_id=str(controls.get("conversation_session_id") or ""),
                workspace=selected_workspace,
            ):
                raise DynamicCollaborationError("Code Mode authorization is not an issued current-session capability")
        target_baseline = WorkspaceBaseline.capture(selected_workspace)
        use_worktree = _execution_isolation_required(evidence.goal, controls)
        worktree_manager = GitWorktreeManager(self.home)
        managed_worktree: Path | None = None
        worktree_cleanup_report: Mapping[str, Any] | None = None
        prepared: Mapping[str, Any] = {}
        overlay_report: Mapping[str, Any] = {
            "schema": "SITINA_EXECUTION_WORKSPACE_DIRECT_V1",
            "copied_paths": [],
            "excluded_sensitive_paths": [],
            "quarantined_worktree_paths": [],
            "symlink_paths": [],
        }
        sandbox_parent = None
        sandbox_scratch_root: Path | None = None
        if isinstance(code_mode_authorization, Mapping):
            sandbox_scratch_root = (
                self.home / "state" / "code-mode-sandbox" / evidence.run_id
            ).resolve(strict=False)
        if use_worktree:
            prepared = worktree_manager.prepare(str(selected_workspace), evidence.run_id)
            if prepared.get("status") != "ok":
                raise DynamicCollaborationError(
                    "managed worktree preparation failed: " + str(prepared.get("reason") or prepared.get("stderr") or "unknown")
                )
            managed_worktree = Path(str(prepared["worktree"])).expanduser().resolve(strict=True)
            run_stream.append(
                "execution-worktree-prepared",
                ({
                    "schema": "SITINA_EXECUTION_WORKTREE_LIFECYCLE_V1",
                    "event_type": "execution.worktree.prepared",
                    "run_id": evidence.run_id,
                    "repo": str(prepared.get("repo") or selected_workspace),
                    "worktree": str(managed_worktree),
                    "status": prepared.get("status"),
                    "registration_created": bool(prepared.get("registration_created")),
                    "registration_before_sha256": prepared.get("registration_before_sha256"),
                    "registration_after_sha256": prepared.get("registration_after_sha256"),
                },),
                actor="controller-execution-authorizer",
            )
            # Preserve the user's existing tracked and untracked state in the
            # isolated worktree.  No reset/stash/checkout touches the target.
            overlay_report = overlay_workspace(selected_workspace, managed_worktree)
            # An accepted managed execution owns this run-scoped root until
            # the Review/TTY handoff has sealed its machine receipt.  Keep the
            # lifecycle fact on the mutable run controls so the checkpoint
            # and restart recovery can make the same cleanup decision without
            # inferring it from a display path.
            controls["_code_mode_managed_worktree_for_review"] = True
            controls["_code_mode_worktree_isolation_kind"] = str(
                prepared.get("isolation_kind") or "git_worktree"
            )
        else:
            controls["_code_mode_managed_worktree_for_review"] = False
        execution_root = managed_worktree or selected_workspace

        def record_worktree_cleanup(report: Mapping[str, Any]) -> None:
            if managed_worktree is None:
                return
            run_stream.append(
                "execution-worktree-cleanup",
                ({
                    "schema": "SITINA_EXECUTION_WORKTREE_LIFECYCLE_V1",
                    "event_type": "execution.worktree.cleanup",
                    "run_id": evidence.run_id,
                    "repo": str(selected_workspace),
                    "worktree": str(managed_worktree),
                    "status": report.get("status"),
                    "registered_before": report.get("registered_before"),
                    "registered_after": report.get("registered_after"),
                    "removed": bool(report.get("removed")),
                    "physical_removed": bool(report.get("physical_removed", report.get("removed"))),
                    "audit_recorded": bool(report.get("audit_recorded")),
                    "porcelain_before_sha256": report.get("porcelain_before_sha256"),
                    "porcelain_after_sha256": report.get("porcelain_after_sha256"),
                },),
                actor="controller-execution-authorizer",
            )
        # For Code Mode the intent hash must be the exact hash issued by the
        # session policy.  The legacy execution record uses the same digest
        # shape for non-Code-Mode callers; never manufacture a second shape
        # that would make the parent binding unverifiable.
        intent_hash = (
            str((code_mode_authorization.get("intent") or {}).get("intent_hash"))
            if isinstance(code_mode_authorization, Mapping)
            else sha256_bytes(intent_text.encode("utf-8"))
        )
        # Freeze the user-approved execution plan before the first Forge
        # attempt.  Rework may add a bounded recovery delta, but its durable
        # facts always point back to this exact goal/acceptance/root.
        original_execution_plan = {
            "goal": evidence.goal,
            "approach": approach,
            "acceptance_checks": list(acceptance),
            "intent_hash": intent_hash,
            "winner_hash": winner.output_hash.removeprefix("sha256:"),
            "mutation_required": True,
            "execution_root": str(execution_root),
        }
        original_execution_plan_hash = sha256_bytes(
            canonical_json_bytes(original_execution_plan)
        )
        before_hashes = target_baseline.before_hashes()
        before_hashes_record = {
            "schema": "SITINA_EXECUTION_BEFORE_HASHES_V1",
            "run_id": evidence.run_id,
            "workspace": str(selected_workspace),
            "hashes": before_hashes,
        }
        before_hashes_receipt = executor._publish(
            before_hashes_record, purpose="true-multi-agent-execution-before-hashes"
        )
        execution_expires_at = int(time.time()) + 900
        if isinstance(code_mode_authorization, Mapping):
            try:
                execution_expires_at = min(
                    execution_expires_at,
                    int(code_mode_authorization.get("expires_at") or 0),
                )
            except (TypeError, ValueError) as error:
                raise DynamicCollaborationError("Code Mode session authorization expiry is invalid") from error
        authorization_core = {
            "schema": "SITINA_EXECUTION_AUTHORIZATION_V1",
            "session_instance_id": str(controls.get("session_instance_id") or ""),
            "session_id": str(controls.get("conversation_session_id") or "standalone"),
            "run_id": evidence.run_id,
            "run_attempt": int(run_attempt),
            "generation": (
                str(code_mode_authorization.get("generation") or getattr(context.identity, "epoch_root", ""))
                if isinstance(code_mode_authorization, Mapping)
                else str(getattr(context.identity, "epoch_root", ""))
            ),
            "turn_index": int(controls.get("conversation_turn_index") or 0),
            "provider_profile": str(executor.transport.profile.name),
            "provider_model": str(executor.transport.profile.model),
            "workspace": str(selected_workspace),
            "execution_root": str(execution_root),
            "intent_hash": intent_hash,
            "plan_hash": winner.output_hash.removeprefix("sha256:"),
            "risk_level": "high" if use_worktree else "workspace",
            "scope": [
                item for item in (
                    str(selected_workspace),
                    str(execution_root),
                    str(sandbox_scratch_root) if sandbox_scratch_root is not None else None,
                )
                if item
            ],
            "before_hashes_ref": before_hashes_receipt.object_ref.reference_id,
            "before_hashes_hash": sha256_bytes(canonical_json_bytes(before_hashes_record)),
            "issued_at": int(time.time()),
            "expires_at": execution_expires_at,
            "conversation_dependency_binding": {
                "autonomous_runtime_bound": self.autonomous_runtime is not None,
                "approval_callback_bound": self.approval_callback is not None,
            },
        }
        if isinstance(code_mode_authorization, Mapping):
            authorization_core["code_mode"] = {
                "authorization_schema": code_mode_authorization.get("schema"),
                "session_instance_id": code_mode_authorization.get("session_instance_id"),
                "session_id": code_mode_authorization.get("session_id"),
                "workspace": code_mode_authorization.get("workspace"),
                "access_mode": code_mode_authorization.get("access_mode"),
                "intent_hash": (code_mode_authorization.get("intent") or {}).get("intent_hash"),
                "intent_authorized": code_mode_authorization.get("intent_authorized") is True,
            }
        authorization_ref = "execution-authorization:" + stable_hash(
            "SITINA_EXECUTION_AUTHORIZATION", authorization_core
        )
        authorization = {**authorization_core, "authorization_ref": authorization_ref}
        authorization_receipt = executor._publish(
            authorization, purpose="true-multi-agent-execution-authorization"
        )
        if isinstance(code_mode_authorization, Mapping):
            parent_registrar = getattr(context, "register_execution_parent", None)
            if not callable(parent_registrar):
                raise DynamicCollaborationError(
                    "Code Mode execution requires an independent runtime parent registrar"
                )
            sandbox_parent = parent_registrar(
                code_mode_authorization=code_mode_authorization,
                execution_authorization=authorization,
                session_id=str(controls.get("conversation_session_id") or ""),
                run_id=evidence.run_id,
                intent_hash=intent_hash,
                workspace=selected_workspace,
                scope=tuple(authorization["scope"]),
                expires_at=min(
                    int(authorization["expires_at"]),
                    int(code_mode_authorization.get("expires_at") or 0),
                ),
                trusted_authorizer=authorizer,
                authorization_message=intent_text,
                risk_level=str(authorization["risk_level"]),
            )
        parent_receipt = None
        if isinstance(code_mode_authorization, Mapping):
            # Persist the parent commitment before any Forge child is
            # published.  The raw session token remains controller-memory
            # only; Journal/host recovery receive only this authenticated
            # token hash and the exact non-secret parent projection.
            token = code_mode_authorization.get("authorization_token")
            if not isinstance(token, str) or not token or sandbox_parent is None:
                raise DynamicCollaborationError("Code Mode parent commitment cannot be published")
            try:
                parent_projection = execution_parent_projection(
                    authorization_token_hash=sha256_bytes(token.encode("utf-8")),
                    authorization_ref=authorization_ref,
                    session_instance_id=str(authorization.get("session_instance_id") or ""),
                    conversation_session_id=str(authorization.get("conversation_session_id") or authorization.get("session_id") or ""),
                    turn_index=int(authorization.get("turn_index")),
                    generation=str(authorization.get("generation") or ""),
                    provider_profile=str(authorization.get("provider_profile") or ""),
                    provider_model=str(authorization.get("provider_model") or ""),
                    session_id=str(authorization.get("session_id") or ""),
                    run_id=evidence.run_id,
                    intent_hash=intent_hash,
                    workspace=str(selected_workspace),
                    scope=tuple(sorted(str(item) for item in authorization["scope"])),
                    risk_level=str(authorization.get("risk_level") or ""),
                    attempt=0,
                    expires_at=min(
                        int(authorization["expires_at"]),
                        int(code_mode_authorization.get("expires_at") or 0),
                    ),
                )
            except Exception as error:
                raise DynamicCollaborationError("Code Mode parent commitment is invalid") from error
            if sandbox_parent.parent_hash != hashlib.sha256(canonical_json_bytes(parent_projection)).hexdigest():
                raise DynamicCollaborationError("Code Mode parent commitment disagrees with the registered parent")
            parent_body = dict(parent_projection)
            parent_body["parent_authorization_hash"] = sandbox_parent.parent_hash
            parent_receipt = executor._publish(
                parent_body, purpose="true-multi-agent-execution-parent"
            )
            run_stream.append_execution_parent_root(
                {
                    **parent_body,
                    "parent_authorization_ref": authorization_ref,
                    "authorization_receipt_ref": parent_receipt.object_ref.reference_id,
                    "authorization_receipt_hash": parent_receipt.object_ref.plaintext_commitment,
                    "_object_refs": [parent_receipt.object_ref.reference_id],
                },
                actor="controller-execution-authorizer",
                proofs=(parent_receipt,),
            )
        run_stream.append_execution_authorization_root(
            {
                **authorization,
                "event_type": "execution.authorization.bound",
                "authorization_object_ref": authorization_receipt.object_ref.reference_id,
                "_object_refs": [
                    authorization_receipt.object_ref.reference_id,
                    before_hashes_receipt.object_ref.reference_id,
                ],
            },
            actor="controller-execution-authorizer",
            proofs=(authorization_receipt, before_hashes_receipt),
        )
        run_stream.append(
            "execution-stage-controller",
            ({
                "schema": "SITINA_EXECUTION_STAGE_V1",
                "event_type": "execution.stage",
                "stage": "Controller",
                "role": "controller-execution-authorizer",
                "run_id": evidence.run_id,
                "attempt": run_attempt,
                "run_attempt": run_attempt,
                "authorization_ref": authorization_ref,
                "workspace": str(selected_workspace),
                "scope_hash": sha256_bytes(canonical_json_bytes(authorization_core["scope"])),
                "_object_refs": [
                    authorization_receipt.object_ref.reference_id,
                    before_hashes_receipt.object_ref.reference_id,
                ],
            },),
            actor="controller-execution-authorizer",
            proofs=(authorization_receipt, before_hashes_receipt),
        )
        run_stream.append(
            "execution-stage-planner",
            ({
                "schema": "SITINA_EXECUTION_STAGE_V1",
                "event_type": "execution.stage",
                "stage": "Planner",
                "role": getattr(winner_agent, "role", "planner"),
                "agent_id": proposer_id,
                "attempt": run_attempt,
                "run_attempt": run_attempt,
                "plan_hash": winner.output_hash,
                "authorization_ref": authorization_ref,
            },),
            actor=proposer_id,
        )
        # ConversationRuntime may reopen a fresh CodeModeRuntimeContext for a
        # later turn.  The controller session is still the live session
        # boundary, so keep it on the owning production runtime rather than
        # accidentally creating a second locked controller for the same CLI
        # session namespace.
        existing_controller = getattr(self, "_active_code_mode_controller", None)
        if existing_controller is None:
            existing_controller = getattr(context, "_active_controller_session", None)
        if isinstance(existing_controller, CodeModeControllerSession) and not getattr(existing_controller, "_closed", True):
            if existing_controller.session_instance_id != str(controls.get("session_instance_id") or ""):
                raise DynamicCollaborationError("active controller session instance changed")
            existing_controller.context = context
            existing_controller.start_new_run(run_id=evidence.run_id, authorization=authorization)
            controller_session = existing_controller
        else:
            controller_session = CodeModeControllerSession(
                context=context,
                run_id=evidence.run_id,
                session_id=str(controls.get("conversation_session_id") or "standalone"),
                authorization=authorization,
                workspace=selected_workspace,
                offline=not bool(getattr(executor.transport, "authoritative_physical", False)),
                session_instance_id=str(
                    controls.get("session_instance_id")
                    or authorization.get("session_instance_id")
                    or getattr(context, "session_instance_id", "")
                ),
            )
        self._active_code_mode_controller = controller_session
        if bool(controls.get("live_opt_in")):
            if not conversation_session_id or conversation_turn_index is None or conversation_turn_index < 0:
                raise DynamicCollaborationError("live canary requires a current conversation session and turn")
            # Only the trusted controller may mint this handle.  The
            # execution path consumes the controller-owned object; it never
            # constructs one from caller-controlled fields.
            controls["live_capability"] = controller_session.mint_live_network_capability(
                purpose="code-mode-live-canary",
                session_id=conversation_session_id,
                run_id=run_id,
            )
        # The acceptance gate may only discover the controller through the
        # exact context object used by this execution.  It is intentionally
        # not copied into controls or a caller-provided mapping.
        setattr(context, "_active_controller_session", controller_session)
        mutation_executor = ToolExecutor(
            self.home,
            enforce_write_boundary=True,
            authorization_binding=authorization,
        )
        binding = ExecutionBinding(
            winner_output_hash=winner.output_hash.removeprefix("sha256:"),
            approved_scope=tuple(dict.fromkeys((str(execution_root), str(selected_workspace)))),
            policy_hash=policy_hash_64,
            run_id=evidence.run_id,
            identity=identity_binding,
        )

        def attempt_ws(attempt: int) -> Path:
            del attempt
            return execution_root

        def scoped_approval(ws: Path):
            # Req 5: execution is bound to approved_scope. Explicit code intent
            # authorizes workspace reads/writes and task-local verification
            # commands for this run; external side effects remain gated.
            ws_root = str(ws.expanduser().resolve(strict=False))
            external_action = bool(controls.get("explicit_external_action"))

            def inside(value: str) -> bool:
                try:
                    resolved = str(Path(value).expanduser().resolve(strict=False))
                except Exception:
                    return False
                return resolved == ws_root or resolved.startswith(ws_root + "/")

            def _decide(request: Any) -> bool:
                permission = getattr(request, "permission", None)
                arguments = getattr(request, "arguments", {}) or {}
                tool_name = str(getattr(request, "tool_name", "") or "")
                if permission == "write":
                    path = str(arguments.get("path") or "")
                    if not inside(path):
                        return False
                    if tool_name in {"sitina_delete_file", "sitina_rename_file"}:
                        batch_size = int(arguments.get("batch_size", 1) or 1)
                        critical = Path(path).name.casefold() in {".git", ".env", "credentials", "secrets"}
                        if tool_name == "sitina_rename_file":
                            critical = critical or Path(str(arguments.get("destination") or "")).name.casefold() in {".git", ".env", "credentials", "secrets"}
                        if (batch_size > 1 or critical) and not bool(controls.get("explicit_destructive_confirmation")):
                            return False
                    return True
                if permission == "shell":
                    raw_command = arguments.get("command")
                    if isinstance(raw_command, list):
                        command = " ".join(str(item) for item in raw_command).casefold()
                    else:
                        command = str(raw_command or "").casefold()
                    cwd = str(arguments.get("cwd") or ws_root)
                    blocked = (
                        "git reset --hard", "git clean", "git push", "git commit", "git tag",
                        "deploy", "publish", "release", "drop database", "drop table",
                        "alembic upgrade", "prisma migrate deploy", "kubectl apply",
                        "terraform apply", "curl -x post", "curl --request post",
                    )
                    if not inside(cwd) or any(item in command for item in blocked):
                        return False
                    if tool_name == "sitina_process_start" and bool(arguments.get("keep")) and not bool(controls.get("explicit_keep")):
                        return False
                    # A dependency install is workspace-local only when its
                    # install destination is explicitly inside the workspace;
                    # brew/apt/system installs always need the stage-level
                    # external-action confirmation.
                    install = any(token in command for token in ("pip install", "python -m pip install", "npm install", "pnpm install", "yarn add", "brew install", "apt install"))
                    local_install = any(token in command for token in ("--target", "--prefix", "--install-dir")) and inside(cwd)
                    if external_action and self.approval_callback is not None:
                        try:
                            if not bool(self.approval_callback(request)):
                                return False
                        except Exception:
                            return False
                    return external_action or not install or local_install
                if permission == "network":
                    method = str(arguments.get("method") or "GET").upper()
                    if external_action and self.approval_callback is not None:
                        try:
                            if not bool(self.approval_callback(request)):
                                return False
                        except Exception:
                            return False
                    return external_action or method in {"GET", "HEAD"}
                if permission == "external_service":
                    if not external_action:
                        return False
                    if self.approval_callback is None:
                        return False
                    try:
                        return bool(self.approval_callback(request))
                    except Exception:
                        return False
                return False

            return _decide

        embedded_usage = {
            "provider_calls": 0,
            "physical_sends": 0,
            "tool_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "total_tokens": 0,
            "cost_micro_usd": 0,
            "retry_count": 0,
            "fallback_count": 0,
            "unsettled_usage_count": 0,
        }
        attempt_results: dict[int, Mapping[str, Any]] = {}
        attempt_baselines: dict[int, WorkspaceBaseline] = {}
        # Captured before each Forge child starts.  This inventory is
        # controller-owned test evidence, not mutation/patch input; it keeps
        # an existing untracked test available to the Tester without adding
        # it to the attempt diff.
        attempt_test_inventories: dict[int, tuple[Mapping[str, str], ...]] = {}
        attempt_workers: dict[int, Any] = {}
        replan_context: dict[int, Mapping[str, Any]] = {}

        def child_journal_facts(
            audit: Any,
            child_run_id: str,
            execution_root: Path,
        ) -> dict[str, Any]:
            """Rebuild completed tool/mutation facts from the child Journal.

            ``AutonomousRuntime`` may raise while asking for its next model
            turn, after earlier tools have completed.  The exception summary
            is not authoritative in that window; the durable child audit
            events are.  Contradictory write facts are rejected rather than
            silently downgraded to zero.
            """
            stream = getattr(audit, "stream", None)
            child_journal = getattr(stream, "journal", None)
            if child_journal is None:
                raise DynamicCollaborationError("Forge child audit has no bound Journal")
            authorized_root = execution_root.expanduser().resolve(strict=False)

            def resolve_workspace_relative(value: Any, *, field: str) -> tuple[str, str]:
                if not isinstance(value, str) or not value.strip():
                    raise DynamicCollaborationError(
                        f"Forge child Journal mutation {field} identity is missing"
                    )
                try:
                    relative_value = decode_workspace_relative_path(value)
                except (TypeError, ValueError) as error:
                    raise DynamicCollaborationError(
                        f"Forge child Journal mutation {field} identity is not redaction-stable"
                    ) from error
                relative = Path(relative_value)
                resolved = (authorized_root / relative).resolve(strict=False)
                try:
                    resolved.relative_to(authorized_root)
                except ValueError as error:
                    raise DynamicCollaborationError(
                        f"Forge child Journal mutation {field} escapes execution root"
                    ) from error
                return relative.as_posix(), str(resolved)

            completed: list[Mapping[str, Any]] = []
            mutations: list[dict[str, Any]] = []
            for event in child_journal.iter_events(0):
                if str(getattr(event, "stream_id", "")) != f"run/{child_run_id}":
                    continue
                payload = getattr(event, "payload", None)
                if not isinstance(payload, Mapping) or payload.get("event_type") != "autonomous.tool-completed":
                    continue
                completed.append(payload)
                fact = payload.get("mutation_fact")
                if not isinstance(fact, Mapping):
                    continue
                item = dict(fact)
                relative_path = item.get("path_identity")
                if not isinstance(relative_path, str) or not relative_path:
                    relative_path = item.get("workspace_relative_path")
                if not isinstance(relative_path, str) or not relative_path:
                    # ``path`` is the compact identity field in the Journal
                    # record.  It is encoded by AutonomousRuntime and must
                    # not be treated as a legacy absolute display path.
                    relative_path = item.get("path")
                if item.get("denied") is False:
                    normalized_relative, resolved_path = resolve_workspace_relative(
                        relative_path,
                        field="path",
                    )
                    item["path_identity"] = relative_path
                    item["workspace_relative_path"] = relative_path
                    item["path_relative_display"] = normalized_relative
                    item["path"] = resolved_path
                elif isinstance(relative_path, str) and relative_path:
                    # Denied effects are retained as facts, but a supplied
                    # path still cannot be allowed to escape the bound root.
                    normalized_relative, resolved_path = resolve_workspace_relative(
                        relative_path,
                        field="path",
                    )
                    item["path_identity"] = relative_path
                    item["workspace_relative_path"] = relative_path
                    item["path_relative_display"] = normalized_relative
                    item["path"] = resolved_path
                destination = item.get("destination_identity")
                if not isinstance(destination, str) or not destination:
                    destination = item.get("workspace_relative_destination")
                if not isinstance(destination, str) or not destination:
                    destination = item.get("destination")
                if isinstance(destination, str) and destination:
                    normalized_destination, resolved_destination = resolve_workspace_relative(
                        destination,
                        field="destination",
                    )
                    item["destination_identity"] = destination
                    item["workspace_relative_destination"] = destination
                    item["destination_relative_display"] = normalized_destination
                    item["destination"] = resolved_destination
                item["sequence"] = len(mutations) + 1
                item["tool_call_id"] = payload.get("call_id")
                item["tool_name"] = payload.get("name")
                mutations.append(item)
            return {
                "tool_call_count": len(completed),
                "mutation_events": mutations,
                "file_mutation_event_count": sum(
                    item.get("denied") is False for item in mutations
                ),
                "unique_mutated_path_count": len({
                    str(item["path"]) for item in mutations
                    if item.get("denied") is False and isinstance(item.get("path"), str)
                }),
                "denied_effect_attempt_count": sum(
                    item.get("denied") is True for item in mutations
                ),
            }

        def provider_accounting_snapshot() -> dict[str, int]:
            totals = executor.usage_totals()
            return {
                "provider_calls": int(getattr(executor, "embedded_call_count", 0)),
                "physical_sends": int(getattr(executor, "embedded_physical_send_count", 0)),
                "input_tokens": int(totals["input_tokens"]),
                "output_tokens": int(totals["output_tokens"]),
                "cache_read_tokens": int(totals["cache_read_tokens"]),
                "cache_write_tokens": int(totals["cache_write_tokens"]),
                "total_tokens": int(totals["total_tokens"]),
                "cost_micro_usd": int(totals["cost_micro_usd"]),
                "retry_count": int(totals.get("retry_count", 0)),
                "fallback_count": int(totals.get("fallback_count", 0)),
                "unsettled_usage_count": int(totals["unsettled_usage_count"]),
            }

        def provider_accounting_delta(before: Mapping[str, int]) -> dict[str, int]:
            after = provider_accounting_snapshot()
            return _provider_accounting_delta(before, after)

        def forge_runner(attempt: int, _workspace: str) -> Mapping[str, Any]:
            nonlocal authorization_ref, sandbox_parent
            ws = attempt_ws(attempt)
            replan_record = replan_context.get(attempt)
            effective_approach = approach
            effective_acceptance = list(acceptance)
            if attempt > 1:
                if not isinstance(replan_record, Mapping):
                    raise DynamicCollaborationError("Code Mode rework has no authenticated plan record")
                normalized_replan = replan_record.get("replan_plan")
                if not isinstance(normalized_replan, Mapping):
                    raise DynamicCollaborationError("Code Mode rework plan content is missing")
                effective_approach = str(normalized_replan.get("approach") or "")
                effective_acceptance = list(normalized_replan.get("acceptance_checks") or ())
                if not effective_approach.strip() or not effective_acceptance:
                    raise DynamicCollaborationError("Code Mode rework plan content is empty")
            # ``attempt`` is owned by the bounded execution bridge.  Rework is
            # a new authorization view, never a replay of attempt one.  Keep
            # the immutable session/run/candidate fields and advance only the
            # lifecycle attempt; the runtime context invalidates the prior
            # request binding before accepting this one.
            if isinstance(controls.get("code_mode_authorization"), Mapping):
                current_auth = dict(controls["code_mode_authorization"])
                current_attempt = current_auth.get("run_attempt")
                if isinstance(current_attempt, bool) or not isinstance(current_attempt, int) or current_attempt < 1:
                    raise DynamicCollaborationError("Code Mode attempt authority is missing")
                if attempt < current_attempt or attempt > current_attempt + 1:
                    raise DynamicCollaborationError("Code Mode attempt transition is not exact")
                if attempt != current_attempt:
                    previous_authorization_ref = str(authorization.get("authorization_ref") or "")
                    if not previous_authorization_ref:
                        raise DynamicCollaborationError("Code Mode predecessor authorization is missing")
                    if not isinstance(replan_record, Mapping):
                        raise DynamicCollaborationError("Code Mode rework has no authenticated plan record")
                    for field in (
                        "plan_hash", "replan_plan_hash", "replan_plan_ref",
                        "replan_plan_receipt_hash", "prior_plan_hash",
                        "prior_failure_type", "prior_failure_hash", "replan_plan",
                    ):
                        if field not in replan_record:
                            raise DynamicCollaborationError("Code Mode rework commitment is incomplete: " + field)
                    next_execution_authorization = {
                        **authorization,
                        "run_attempt": attempt,
                        "previous_authorization_ref": previous_authorization_ref,
                        "plan_hash": replan_record["plan_hash"],
                        "replan_plan_hash": replan_record["replan_plan_hash"],
                        "replan_plan_ref": replan_record["replan_plan_ref"],
                        "replan_plan_receipt_hash": replan_record["replan_plan_receipt_hash"],
                        "prior_plan_hash": replan_record["prior_plan_hash"],
                        "prior_failure_type": replan_record["prior_failure_type"],
                        "prior_failure_hash": replan_record["prior_failure_hash"],
                        "replan_plan": dict(replan_record["replan_plan"]),
                        "original_plan_hash": replan_record.get("original_plan_hash"),
                        "original_execution_plan": dict(replan_record.get("original_execution_plan") or {}),
                        "recovery_mode": replan_record.get("recovery_mode"),
                        "reason_code": replan_record.get("reason_code"),
                        "failure_stage": replan_record.get("failure_stage"),
                        "mutation_count": replan_record.get("mutation_count", 0),
                    }
                    next_execution_authorization["authorization_ref"] = execution_authorization_attempt_ref(
                        next_execution_authorization
                    )
                    next_authorization_receipt = executor._publish(
                        next_execution_authorization,
                        purpose="true-multi-agent-execution-authorization-attempt",
                    )
                    live_next_auth = {
                        **current_auth,
                        "run_attempt": attempt,
                        "authorization_ref": next_execution_authorization["authorization_ref"],
                        "authorization_receipt_ref": next_authorization_receipt.object_ref.reference_id,
                        "plan_hash": replan_record["plan_hash"],
                        "replan_plan_hash": replan_record["replan_plan_hash"],
                        "replan_plan_ref": replan_record["replan_plan_ref"],
                        "replan_plan_receipt_hash": replan_record["replan_plan_receipt_hash"],
                        "prior_plan_hash": replan_record["prior_plan_hash"],
                        "prior_failure_type": replan_record["prior_failure_type"],
                        "prior_failure_hash": replan_record["prior_failure_hash"],
                        "replan_plan": dict(replan_record["replan_plan"]),
                        "original_plan_hash": replan_record.get("original_plan_hash"),
                        "original_execution_plan": dict(replan_record.get("original_execution_plan") or {}),
                        "recovery_mode": replan_record.get("recovery_mode"),
                        "reason_code": replan_record.get("reason_code"),
                        "failure_stage": replan_record.get("failure_stage"),
                        "mutation_count": replan_record.get("mutation_count", 0),
                    }
                    try:
                        durable_next_auth = durable_code_mode_authorization_projection(live_next_auth)
                    except Exception as error:
                        raise DynamicCollaborationError(
                            "Code Mode rework authorization cannot be durably projected"
                        ) from error
                    from sitina.orchestrator.code_mode_runtime import _workspace_observation_hash
                    current_events = tuple(
                        item for item in journal.iter_events(0) if item.stream_id == run_stream.stream_id
                    )
                    frontier_hash = sha256_bytes(canonical_json_bytes({
                        "stream_id": run_stream.stream_id,
                        "stream_version": run_stream.version,
                        "event_hashes": [item.event_hash for item in current_events],
                    }))
                    advance_fact = {
                        "schema": "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
                        "event_type": "execution.authorization.attempt_advanced",
                        "run_id": evidence.run_id,
                        "session_instance_id": live_next_auth.get("session_instance_id"),
                        "session_id": live_next_auth.get("session_id"),
                        "stream_id": run_stream.stream_id,
                        "generation": live_next_auth.get("generation"),
                        "workspace": live_next_auth.get("workspace"),
                        "previous_run_attempt": current_attempt,
                        "run_attempt": attempt,
                        "previous_authorization_ref": previous_authorization_ref,
                        "authorization_ref": next_execution_authorization["authorization_ref"],
                        "authorization_receipt_ref": next_authorization_receipt.object_ref.reference_id,
                        "authorization_receipt_hash": next_authorization_receipt.object_ref.plaintext_commitment,
                        "workspace_observation_hash": _workspace_observation_hash(ws),
                        "frontier_hash": frontier_hash,
                        "plan_hash": replan_record["plan_hash"],
                        "replan_plan_ref": replan_record["replan_plan_ref"],
                        "replan_plan_receipt_hash": replan_record["replan_plan_receipt_hash"],
                        "replan_plan_hash": replan_record["replan_plan_hash"],
                        "replan_plan": dict(replan_record["replan_plan"]),
                        "prior_plan_hash": replan_record["prior_plan_hash"],
                        "prior_failure_type": replan_record["prior_failure_type"],
                        "prior_failure_hash": replan_record["prior_failure_hash"],
                        # Only the controller-owned live view carries the
                        # opaque token.  This event is durable evidence and
                        # therefore receives the shared hash-only projection.
                        "code_mode_authorization": durable_next_auth,
                        "execution_authorization": dict(next_execution_authorization),
                        "_object_refs": [
                            next_authorization_receipt.object_ref.reference_id,
                            replan_record["replan_plan_ref"],
                        ],
                    }
                    advance_command_id = "attempt-advance-" + stable_hash(
                        "SITINA_EXECUTION_ATTEMPT_ADVANCE_COMMAND",
                        {
                            "run_id": evidence.run_id,
                            "run_attempt": attempt,
                            "previous_authorization_ref": previous_authorization_ref,
                            "authorization_ref": next_execution_authorization["authorization_ref"],
                        },
                    )[:48]
                    latest_reader = getattr(context, "latest_execution_attempt", None)
                    if not callable(latest_reader):
                        raise DynamicCollaborationError("Code Mode attempt transition has no latest-attempt verifier")
                    try:
                        latest_existing = latest_reader(
                            journal=journal, run_id=str(evidence.run_id),
                            session_id=str(current_auth.get("session_id") or ""),
                            generation=str(current_auth.get("generation") or ""),
                            workspace=selected_workspace, require_current=False,
                        )
                    except PermissionError as error:
                        # The expected pre-advance state is the authenticated
                        # attempt-one (or immediately prior) chain.  Any
                        # other verifier failure is structural and must not be
                        # converted into a second mapping attempt.
                        if "attempt chain is missing" not in str(error):
                            raise DynamicCollaborationError(
                                "Code Mode attempt chain could not be reopened"
                            ) from error
                        latest_existing = None
                    if not (
                        isinstance(latest_existing, Mapping)
                        and latest_existing.get("run_attempt") == attempt
                        and latest_existing.get("previous_authorization_ref") == previous_authorization_ref
                        and latest_existing.get("authorization_ref") == next_execution_authorization["authorization_ref"]
                    ):
                        run_stream.append_attempt_advance(
                            advance_fact,
                            actor="controller-execution-authorizer",
                            proofs=(next_authorization_receipt, replan_record["replan_receipt"]),
                            command_id=advance_command_id,
                        )
                    else:
                        # A prior Journal commit followed by a process failure
                        # is an exact recovery case.  Reopen its canonical
                        # authorization instead of creating a second mapping.
                        next_execution_authorization = dict(
                            latest_existing.get("execution_authorization") or next_execution_authorization
                        )
                        durable_existing_auth = latest_existing.get("code_mode_authorization")
                        if not isinstance(durable_existing_auth, Mapping):
                            raise DynamicCollaborationError(
                                "Code Mode replay has no durable authorization projection"
                            )
                        if "authorization_token" in durable_existing_auth:
                            raise DynamicCollaborationError(
                                "Code Mode replay exposed a durable authorization token"
                            )
                        try:
                            durable_existing_auth = durable_code_mode_authorization_projection(
                                durable_existing_auth
                            )
                        except Exception as error:
                            raise DynamicCollaborationError(
                                "Code Mode replay authorization commitment is invalid"
                            ) from error
                        live_token = live_next_auth.get("authorization_token")
                        if type(live_token) is not str or not live_token:
                            raise DynamicCollaborationError(
                                "Code Mode replay cannot restore a live authorization token"
                            )
                        if hashlib.sha256(live_token.encode("utf-8")).hexdigest() != durable_existing_auth.get(
                            "authorization_token_hash"
                        ):
                            raise DynamicCollaborationError(
                                "Code Mode replay live token does not match durable commitment"
                            )
                        live_next_auth = {
                            **live_next_auth,
                            **dict(durable_existing_auth),
                            "authorization_token": live_token,
                        }
                    # Only expose the new attempt after the dedicated Journal
                    # mapping has committed (or exact-replayed).  A failed
                    # append therefore leaves controller/runtime/controls and
                    # all worker creation on the old attempt.
                    controller_session.advance_attempt(next_execution_authorization)
                    authorization.update(next_execution_authorization)
                    authorization_ref = str(next_execution_authorization["authorization_ref"])
                    controls["code_mode_authorization"] = live_next_auth
                    controls["run_attempt"] = attempt
                    binder = getattr(context, "bind_code_mode_request", None)
                    if not callable(binder):
                        raise DynamicCollaborationError("Code Mode attempt transition has no runtime binder")
                    binder(
                        session_instance_id=str(controls.get("session_instance_id") or ""),
                        session_id=str(controls.get("conversation_session_id") or current_auth.get("session_id") or ""),
                        run_id=evidence.run_id,
                        candidate_id=str(current_auth.get("candidate_id") or ""),
                        # Keep the logical selected workspace immutable; the
                        # managed worktree is only the execution root.
                        workspace=selected_workspace,
                        run_attempt=attempt,
                        generation=str(current_auth.get("generation") or ""),
                        stream_id=str(controls.get("conversation_stream_id") or "") or None,
                    )
                    # A child parent is an attempt-scoped authorization root.
                    # Re-register it from the committed latest mapping before
                    # any child or worker is created; the attempt-one parent
                    # must never remain the parent of attempt-two work.
                    parent_registrar = getattr(context, "register_execution_parent", None)
                    if not callable(parent_registrar):
                        raise DynamicCollaborationError("Code Mode attempt transition has no parent registrar")
                    sandbox_parent = parent_registrar(
                        code_mode_authorization=live_next_auth,
                        execution_authorization=next_execution_authorization,
                        session_id=str(controls.get("conversation_session_id") or current_auth.get("session_id") or ""),
                        run_id=evidence.run_id,
                        intent_hash=intent_hash,
                        workspace=selected_workspace,
                        scope=tuple(next_execution_authorization["scope"]),
                        expires_at=min(
                            int(next_execution_authorization["expires_at"]),
                            int(live_next_auth.get("expires_at") or 0),
                        ),
                        trusted_authorizer=authorizer,
                        authorization_message=intent_text,
                        risk_level=str(next_execution_authorization["risk_level"]),
                    )
                    parent_token = live_next_auth.get("authorization_token")
                    if not isinstance(parent_token, str) or not parent_token:
                        raise DynamicCollaborationError("Code Mode rework parent token is unavailable")
                    try:
                        parent_projection = execution_parent_projection(
                            authorization_token_hash=sha256_bytes(parent_token.encode("utf-8")),
                            authorization_ref=str(next_execution_authorization["authorization_ref"]),
                            session_instance_id=str(next_execution_authorization.get("session_instance_id") or ""),
                            conversation_session_id=str(next_execution_authorization.get("conversation_session_id") or next_execution_authorization.get("session_id") or ""),
                            turn_index=int(next_execution_authorization.get("turn_index") or 0),
                            generation=str(next_execution_authorization.get("generation") or ""),
                            provider_profile=str(next_execution_authorization.get("provider_profile") or ""),
                            provider_model=str(next_execution_authorization.get("provider_model") or ""),
                            session_id=str(next_execution_authorization.get("session_id") or ""),
                            run_id=evidence.run_id,
                            intent_hash=intent_hash,
                            workspace=str(selected_workspace),
                            scope=tuple(sorted(str(item) for item in next_execution_authorization["scope"])),
                            risk_level=str(next_execution_authorization.get("risk_level") or ""),
                            attempt=0,
                            expires_at=min(
                                int(next_execution_authorization["expires_at"]),
                                int(live_next_auth.get("expires_at") or 0),
                            ),
                        )
                    except Exception as error:
                        raise DynamicCollaborationError("Code Mode rework parent commitment is invalid") from error
                    if sandbox_parent.parent_hash != hashlib.sha256(canonical_json_bytes(parent_projection)).hexdigest():
                        raise DynamicCollaborationError("Code Mode rework parent commitment disagrees with the registered parent")
                    parent_body = dict(parent_projection)
                    parent_body["parent_authorization_hash"] = sandbox_parent.parent_hash
                    parent_receipt = executor._publish(
                        parent_body, purpose="true-multi-agent-execution-parent"
                    )
                    run_stream.append_execution_parent_root(
                        {
                            **parent_body,
                            "parent_authorization_ref": next_execution_authorization["authorization_ref"],
                            "authorization_receipt_ref": parent_receipt.object_ref.reference_id,
                            "authorization_receipt_hash": parent_receipt.object_ref.plaintext_commitment,
                            "_object_refs": [parent_receipt.object_ref.reference_id],
                        },
                        actor="controller-execution-authorizer",
                        proofs=(parent_receipt,),
                    )
                    run_stream.append(
                        "execution-stage-controller-attempt",
                        ({
                            "schema": "SITINA_EXECUTION_STAGE_V1",
                            "event_type": "execution.stage",
                            "stage": "Controller",
                            "role": "controller-execution-authorizer",
                            "attempt": attempt,
                            "run_attempt": attempt,
                            "run_id": evidence.run_id,
                            "authorization_ref": authorization_ref,
                            "workspace": str(selected_workspace),
                            "plan_hash": replan_record["plan_hash"],
                            "replan_plan_hash": replan_record["replan_plan_hash"],
                            "replan_plan_ref": replan_record["replan_plan_ref"],
                            "replan_plan": dict(replan_record["replan_plan"]),
                        },),
                        actor="controller-execution-authorizer",
                    )
                    # ``run_safe_execution`` obtains the new plan before this
                    # callback, but its durable Planner fact must not be
                    # written until the attempt mapping has committed.  This
                    # is the only Planner fact for the new attempt and is
                    # therefore bound to the exact latest authorization.
                    replan_record = replan_context.get(attempt)
                    if not isinstance(replan_record, Mapping):
                        raise DynamicCollaborationError("Code Mode rework has no authenticated plan record")
                    run_stream.append(
                        "execution-rework-started",
                        ({
                            "schema": "SITINA_EXECUTION_REWORK_V1",
                            "event_type": "execution.rework.started",
                            "automatic": True,
                            "attempt": attempt,
                            "run_attempt": attempt,
                            "prior_failure_type": replan_record["prior_failure_type"],
                            "prior_failure_hash": replan_record["prior_failure_hash"],
                            "replan_plan_hash": replan_record["plan_hash"],
                            "plan_hash": replan_record["plan_hash"],
                            "replan_plan_ref": replan_record["replan_plan_ref"],
                            "replan_plan": dict(replan_record["replan_plan"]),
                            "authorization_ref": authorization_ref,
                        },),
                        actor="controller-execution-authorizer",
                    )
                    run_stream.append(
                        "execution-stage-planner-replan",
                        ({
                            "schema": "SITINA_EXECUTION_STAGE_V1",
                            "event_type": "execution.stage",
                            "stage": "Planner",
                            "role": getattr(winner_agent, "role", "planner"),
                            "agent_id": getattr(winner_agent, "agent_id", "unknown"),
                            "replan": True,
                            "attempt": attempt,
                            "run_attempt": attempt,
                            "plan_hash": replan_record["plan_hash"],
                            "prior_failure_type": replan_record["prior_failure_type"],
                            "prior_failure_hash": replan_record["prior_failure_hash"],
                            "replan_plan_hash": replan_record["replan_plan_hash"],
                            "replan_plan_ref": replan_record["replan_plan_ref"],
                            "replan_plan": dict(replan_record["replan_plan"]),
                            "prior_plan_hash": replan_record["prior_plan_hash"],
                            "prior_failure_type": replan_record["prior_failure_type"],
                            "prior_failure_hash": replan_record["prior_failure_hash"],
                            "authorization_ref": authorization_ref,
                        },),
                        actor=getattr(winner_agent, "agent_id", "planner"),
                    )
            accounting_before = provider_accounting_snapshot()
            attempt_baselines[attempt] = WorkspaceBaseline.capture(ws)
            attempt_test_inventories[attempt] = tuple(
                {
                    "relative_path": relative,
                    "sha256": record.before_hash,
                }
                for relative, record in sorted(
                    attempt_baselines[attempt].records.items(), key=lambda item: item[0]
                )
                if Path(relative).name.startswith("test_") and Path(relative).suffix == ".py"
            )
            exec_run_id = f"forge-exec-{evidence.run_id}-{attempt}"
            audit = JournalAutonomousAudit(
                journal, cas, context.provider, run_id=exec_run_id, policy_hash=self.policy_hash
            )
            process_manager = ManagedProcessManager(
                self.home,
                workspace=ws,
                run_id=exec_run_id,
                audit=audit.append,
                allow_keep=bool(controls.get("keep_managed_processes"))
                and bool(controls.get("explicit_keep")),
            )
            run_stream.append(
                "execution-stage-forge",
                ({
                    "schema": "SITINA_EXECUTION_STAGE_V1",
                    "event_type": "execution.stage",
                    "stage": "Forge",
                    "role": "forge-execution-role",
                    "attempt": attempt,
                    "run_attempt": attempt,
                    "run_id": evidence.run_id,
                    "workspace": str(ws),
                    "authorization_ref": authorization_ref,
                    **({
                        "plan_hash": replan_record["plan_hash"],
                        "replan_plan_hash": replan_record["replan_plan_hash"],
                        "replan_plan_ref": replan_record["replan_plan_ref"],
                        "replan_plan": dict(replan_record["replan_plan"]),
                    } if isinstance(replan_record, Mapping) else {}),
                },),
                actor="forge-execution-role",
            )
            task = (
                f"Goal: {evidence.goal}\n\n"
                f"An approved approach was selected by multi-agent review. Implement it now "
                f"using the file tools; write all files under {ws}.\n\n"
                f"Approved approach:\n{effective_approach}\n\n"
                f"Acceptance checks: {json.dumps(list(effective_acceptance), ensure_ascii=False)}"
            )
            prior_replan = replan_context.get(attempt)
            if isinstance(prior_replan, Mapping):
                task += (
                    "\n\nThis is an automatic rework after a failed attempt. "
                    "Use this exact authenticated re-plan and immutable failure summary. "
                    "The original product goal and acceptance checks remain binding; apply only the bounded "
                    "recovery delta recorded below.\n"
                    + json.dumps({
                        "plan_hash": prior_replan.get("plan_hash"),
                        "replan_plan": prior_replan.get("replan_plan"),
                        "original_plan_hash": prior_replan.get("original_plan_hash"),
                        "original_execution_plan": prior_replan.get("original_execution_plan"),
                        "recovery_mode": prior_replan.get("recovery_mode"),
                        "prior_plan_hash": prior_replan.get("prior_plan_hash"),
                        "prior_failure_type": prior_replan.get("prior_failure_type"),
                        "prior_failure_hash": prior_replan.get("prior_failure_hash"),
                    }, ensure_ascii=False, sort_keys=True)
                )
            embedded_client: BoundedToolTurnClient | None = None
            forge_bound = False
            try:
                # ToolCatalog binds each embedded invocation to its own
                # autonomous run id.  Derive a narrowly scoped child view of
                # the parent task authorization so the capability check is
                # both run-correct and still anchored to the immutable parent
                # session/intent/workspace authorization.
                child_issuer = getattr(context, "issue_execution_child_authorization", None)
                if not callable(child_issuer):
                    raise DynamicCollaborationError(
                        "Code Mode execution requires a trusted child authorization registrar"
                    )
                attempt_authorization = child_issuer(
                    sandbox_parent,
                    attempt=attempt,
                    purpose="forge-attempt",
                    workspace=ws,
                    scope=(str(ws),),
                    expires_at=min(int(authorization["expires_at"]), int(time.time()) + 120),
                )
                child_receipt = executor._publish(
                    {
                        **attempt_authorization,
                        "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
                        # ``payload_hash`` is the issuer-derived commitment
                        # over the exact unsigned child scope.  The CAS
                        # wrapper carries the same commitment; hashing the
                        # wrapper here would create a different identity and
                        # allow the Journal event/CAS pair to drift.
                        "authorization_hash": attempt_authorization["payload_hash"],
                    },
                    purpose="true-multi-agent-child-execution-authorization",
                )
                run_stream.append_forge_child_authorization(
                    {
                        "schema": "CODE_MODE_FORGE_CHILD_AUTHORIZATION_V1",
                        "event_type": "execution.authorization.forge-child-bound",
                        "purpose": "true-multi-agent-forge-child",
                        "domain": "attempt_execution",
                        "session_instance_id": str(authorization.get("session_instance_id") or ""),
                        "conversation_session_id": str(authorization.get("session_id") or ""),
                        "turn_index": int(controls.get("conversation_turn_index") or 0),
                        "run_id": evidence.run_id,
                        "child_run_id": exec_run_id,
                        "run_attempt": attempt,
                        "generation": str(authorization.get("generation") or ""),
                        "authorization_ref": attempt_authorization["authorization_ref"],
                        "parent_authorization_ref": authorization_ref,
                        "parent_authorization_hash": attempt_authorization["parent_authorization_hash"],
                        "workspace": str(ws),
                        "execution_root": str(attempt_authorization["execution_root"]),
                        "scope": list(attempt_authorization["scope"]),
                        "risk_level": str(attempt_authorization["risk_level"]),
                        "provider_profile": str(executor.transport.profile.name),
                        "provider_model": str(executor.transport.profile.model),
                        "expires_at": int(attempt_authorization["expires_at"]),
                        "payload_hash": attempt_authorization["payload_hash"],
                        "authorization_receipt_ref": child_receipt.object_ref.reference_id,
                        "authorization_receipt_hash": child_receipt.object_ref.plaintext_commitment,
                        "_object_refs": [child_receipt.object_ref.reference_id],
                    },
                    actor="controller-execution-authorizer",
                    proofs=(child_receipt,),
                )
                if getattr(executor.transport, "authoritative_physical", False):
                    forge_binder = getattr(
                        getattr(executor.transport, "transport_ledger", None),
                        "bind_forge_execution_authorization",
                        None,
                    )
                    if not callable(forge_binder):
                        raise DynamicCollaborationError(
                            "authoritative Forge execution requires its dedicated transport authorization"
                        )
                    forge_authorization = forge_binder(
                        child_authorization_locator=child_receipt.object_ref.reference_id,
                    )
                    executor.bind_forge_transport_authorization_for_attempt(
                        child_run_id=exec_run_id,
                        attempt=attempt,
                        authorization_id=str(forge_authorization.get("authorization_id") or ""),
                    )
                    executor.transport.execution_authorization_ref = str(
                        forge_authorization.get("authorization_ref") or ""
                    )
                # The attempt is replan-eligible only after both the durable
                # child fact and (for authoritative transport) its host
                # attempt-control binding have committed.
                forge_bound = True
                embedded_client = BoundedToolTurnClient(
                    executor.transport.client,
                    executor.transport.profile,
                    run_id=exec_run_id,
                    authoritative_physical=bool(getattr(executor.transport, "authoritative_physical", False)),
                    transport_ledger=getattr(executor.transport, "transport_ledger", None),
                    transport_ledger_capability=getattr(executor.transport, "transport_ledger_capability", None),
                    receipt_sink=executor.record_embedded_transport_receipt,
                    retry_limit=executor.transport.max_retries,
                    fallback_profiles=executor.transport.fallback_profiles,
                    fallback_allowed=executor.transport.fallback_allowed,
                    max_fallbacks=executor.transport.max_fallbacks,
                    backoff_seconds=float(self.policy.get("retry_backoff_seconds", 0.25) or 0.25),
                )
                worker_executor = controller_session.worker_executor(
                    attempt=attempt,
                    authorization_binding=attempt_authorization,
                    workspace=ws,
                    before_hashes=attempt_baselines[attempt].before_hashes(),
                    store=mutation_executor.store,
                )
                attempt_workers[attempt] = worker_executor
                runtime = AutonomousRuntime(
                    self.home,
                    client=embedded_client,
                    profile=executor.transport.profile,
                    approval_callback=scoped_approval(ws),       # in-sandbox writes only
                    workspace=ws,
                    max_tokens=int(self.policy["max_output_tokens_per_request"]),
                    max_turns=int(self.policy.get("max_execution_turns", 16)),
                    enforce_write_boundary=True,                 # SL1 pre-write hard gate
                    before_hashes=attempt_baselines[attempt].before_hashes(),
                    strict_workspace=True,
                    managed_process_manager=process_manager,
                    authorization_binding=attempt_authorization,
                    authorization_authority=context,
                    provider_preflight=executor.admit_embedded_provider_call,
                    provider_settlement=executor.settle_embedded_provider_call,
                    provider_failure_settlement=executor.settle_failed_embedded_provider_call,
                    write_executor=worker_executor,
                )
                self._exec_last_attempt = attempt
                r = runtime.run_embedded(task, run_id=exec_run_id, journal_audit=audit)
            except Exception as error:
                # Keep Forge failures inside the bounded execution bridge so
                # Tester/rework evidence is still produced.  Only typed error
                # identity is persisted; exception text never enters
                # Journal/CAS/model-visible evidence.
                error_hash = sha256_bytes(str(error).encode("utf-8"))
                accounting = provider_accounting_delta(accounting_before)
                failure_receipts = _failed_transport_receipts(executor)
                cause = getattr(error, "__cause__", None)
                reason_code = (
                    getattr(error, "sitina_failure_reason_code", None)
                    or getattr(cause, "sitina_failure_reason_code", None)
                    or getattr(error, "reason_code", None)
                    or getattr(cause, "reason_code", None)
                )
                if not isinstance(reason_code, str) or not re.fullmatch(
                    r"[A-Z][A-Z0-9_]{2,96}", reason_code
                ):
                    error_name = type(cause).__name__ if cause is not None else type(error).__name__
                    if "ProviderHTTP" in error_name or "HTTP" in error_name and "Provider" in error_name:
                        reason_code = "PROVIDER_HTTP_FAILURE"
                    elif "Provider" in error_name or "Transport" in error_name:
                        reason_code = "PROVIDER_TRANSPORT_FAILURE"
                    else:
                        reason_code = "FORGE_EXECUTION_FAILURE"
                # The executor delta is authoritative even when the exception
                # was raised after a successful Provider settlement (for
                # example an unknown tool call). Transport attributes are only
                # a fallback for failures before the executor saw the call.
                # Authoritative embedded failures are reconciled from the
                # host ledger by ``settle_failed_embedded_provider_call``.
                # Exception attributes are retained only for the legacy
                # non-authoritative fixture path; using them after an
                # existing successful call would otherwise hide a later
                # failed physical attempt.
                if (
                    not getattr(executor.transport, "authoritative_physical", False)
                    and not accounting["provider_calls"]
                    and getattr(error, "sitina_physical_send_count", 0)
                ):
                    accounting.update(
                        {
                            "provider_calls": 1,
                            "physical_sends": int(getattr(error, "sitina_physical_send_count", 0) or 0),
                            "retry_count": int(getattr(error, "sitina_retry_count", 0) or 0),
                            "fallback_count": int(getattr(error, "sitina_fallback_count", 0) or 0),
                            "unsettled_usage_count": 1,
                        }
                    )
                r = {
                    "run_id": exec_run_id,
                    "status": "error",
                    "terminal_state": "FAILED",
                    "error_type": type(error).__name__,
                    "error_hash": error_hash,
                    "error_message_hash": error_hash,
                    "provider_call_count": accounting["provider_calls"],
                    "provider_physical_send_count": accounting["physical_sends"],
                    "provider_retry_count": accounting["retry_count"],
                    "provider_fallback_count": accounting["fallback_count"],
                    "provider_usage_status": "unknown" if accounting["unsettled_usage_count"] else "not_sent",
                    "provider_usage_unsettled_count": accounting["unsettled_usage_count"],
                    "provider_failure_reason_codes": _failed_transport_reason_codes(failure_receipts),
                    "reason_code": reason_code,
                    "failure_stage": "Forge",
                    "mutation_count": 0,
                    "provider_input_tokens": accounting["input_tokens"],
                    "provider_output_tokens": accounting["output_tokens"],
                    "provider_cache_read_tokens": accounting["cache_read_tokens"],
                    "provider_cache_write_tokens": accounting["cache_write_tokens"],
                    "provider_token_total": accounting["total_tokens"],
                    "provider_cost_micro_usd": accounting["cost_micro_usd"],
                    "tool_call_count": 0,
                    "mutation_events": [],
                    "external_mutation_count": 0,
                    "forge_bound": forge_bound,
                }
                try:
                    audit.append(
                        "forge_runtime_failed",
                        {
                            "error_type": type(error).__name__,
                            "error_hash": error_hash,
                            "provider_call_count": accounting["provider_calls"],
                            "provider_physical_send_count": accounting["physical_sends"],
                            "provider_retry_count": accounting["retry_count"],
                            "provider_fallback_count": accounting["fallback_count"],
                            "provider_usage_unsettled_count": accounting["unsettled_usage_count"],
                            "secret_values_included": False,
                        },
                    )
                except Exception:
                    pass
            # The child Journal is the source of truth for completed tool
            # activity, including the prefix of a run that failed on a later
            # Provider turn.  A nonzero runtime summary must agree with it;
            # an exception summary of zero must never erase it.
            child_facts = child_journal_facts(audit, exec_run_id, ws)
            declared_tool_count = int(r.get("tool_call_count", 0) or 0)
            if declared_tool_count not in {0, int(child_facts["tool_call_count"])}:
                raise DynamicCollaborationError("Forge child tool count contradicts its Journal")
            if declared_tool_count:
                def mutation_identity(item: Mapping[str, Any]) -> tuple[Any, ...]:
                    relative_identity = item.get("path_identity")
                    if not isinstance(relative_identity, str) or not relative_identity:
                        relative_identity = item.get("workspace_relative_path")
                    relative = None
                    if isinstance(relative_identity, str) and relative_identity:
                        try:
                            relative = decode_workspace_relative_path(relative_identity)
                        except (TypeError, ValueError) as error:
                            raise DynamicCollaborationError(
                                "Forge child mutation path identity is malformed"
                            ) from error
                    if not isinstance(relative, str) or not relative:
                        raw_path = item.get("path")
                        if isinstance(raw_path, str) and raw_path:
                            raw = Path(raw_path).expanduser()
                            if raw.is_absolute():
                                try:
                                    relative = raw.resolve(strict=False).relative_to(
                                        ws.expanduser().resolve(strict=False)
                                    ).as_posix()
                                except (OSError, RuntimeError, ValueError):
                                    relative = None
                            else:
                                relative = raw.as_posix()
                    destination_identity = item.get("destination_identity")
                    if not isinstance(destination_identity, str) or not destination_identity:
                        destination_identity = item.get("workspace_relative_destination")
                    destination = None
                    if isinstance(destination_identity, str) and destination_identity:
                        try:
                            destination = decode_workspace_relative_path(destination_identity)
                        except (TypeError, ValueError) as error:
                            raise DynamicCollaborationError(
                                "Forge child mutation destination identity is malformed"
                            ) from error
                    if not isinstance(destination, str) or not destination:
                        raw_destination = item.get("destination")
                        if isinstance(raw_destination, str) and raw_destination:
                            raw = Path(raw_destination).expanduser()
                            if raw.is_absolute():
                                try:
                                    destination = raw.resolve(strict=False).relative_to(
                                        ws.expanduser().resolve(strict=False)
                                    ).as_posix()
                                except (OSError, RuntimeError, ValueError):
                                    destination = None
                            else:
                                destination = raw.as_posix()
                    return (
                        item.get("operation"),
                        item.get("tool_call_id"),
                        relative,
                        destination,
                        item.get("before_hash"),
                        item.get("after_hash"),
                        item.get("denied") is True,
                    )

                declared_mutations = sorted(
                    mutation_identity(item)
                    for item in (r.get("mutation_events") or ())
                    if isinstance(item, Mapping)
                )
                journal_mutations = sorted(
                    mutation_identity(item)
                    for item in child_facts["mutation_events"]
                    if isinstance(item, Mapping)
                )
                if declared_mutations != journal_mutations:
                    raise DynamicCollaborationError("Forge child mutation facts contradict its Journal")
            r = {
                **r,
                **child_facts,
                "forge_bound": bool(r.get("forge_bound", forge_bound) or forge_bound),
                "mutation_count": int(
                    r.get("mutation_count") or child_facts.get("file_mutation_event_count") or 0
                ),
                "attempt_binding": {
                    "authorization_ref": str(getattr(executor.transport, "execution_authorization_ref", "") or authorization_ref),
                    "child_run_id": exec_run_id,
                    "attempt": attempt,
                    "receipt_cursor": len(getattr(executor, "_embedded_transport_receipts", ())),
                },
            }
            accounting = provider_accounting_delta(accounting_before)
            provider_identity = getattr(embedded_client, "last_profile", None) or executor.actual_provider_profile()
            r = _merge_embedded_attempt_accounting(
                r,
                accounting_before,
                provider_accounting_snapshot(),
                provider_profile=getattr(provider_identity, "name", r.get("provider_profile")),
                provider_model=getattr(provider_identity, "model", r.get("provider_model")),
            )
            # FIX3: aggregate embedded-loop usage so execution can't silently
            # bypass budget accounting; surface a typed Forge failure if the
            # provider result is malformed instead of leaking an exception
            # past the bounded attempt ledger.
            try:
                usage_delta = _embedded_usage_delta(r)
            except Exception as error:
                error_hash = sha256_bytes(str(error).encode("utf-8"))
                r = {
                    "run_id": exec_run_id,
                    "status": "error",
                    "terminal_state": "FAILED",
                    "error_type": type(error).__name__,
                    "error_hash": error_hash,
                    "error_message_hash": error_hash,
                    "provider_call_count": 0,
                    "provider_physical_send_count": 0,
                    "tool_call_count": 0,
                    "mutation_events": [],
                    "external_mutation_count": 0,
                    "secret_values_included": False,
                }
                attempt_results[attempt] = r
                try:
                    audit.append(
                        "forge_usage_aggregation_failed",
                        {
                            "error_type": "UsageAggregationError",
                            "error_hash": error_hash,
                            "secret_values_included": False,
                        },
                    )
                except Exception:
                    pass
                return r
            attempt_results[attempt] = r
            for target, value in usage_delta.items():
                embedded_usage[target] += value
            return r

        def collect_diff() -> list[str]:
            runtime = attempt_results.get(getattr(self, "_exec_last_attempt", 1), {})
            events = runtime.get("mutation_events")
            if not isinstance(events, list):
                return []
            return sorted(
                {
                    str(item["path"])
                    for item in events
                    if item.get("denied") is False
                    and isinstance(item.get("path"), str)
                }
            )

        def boundary_check(diff_paths: Sequence[str]) -> list[str]:
            # Deliverable-level H4 gate: fail-closed on sensitive content in the
            # actual produced files BEFORE they are accepted/persisted onward.
            flagged: list[str] = []
            for p in diff_paths:
                try:
                    text = Path(p).read_text(encoding="utf-8", errors="strict")
                except (UnicodeDecodeError, OSError):
                    continue
                if redact_boundary_value(text, boundary="write").redacted_paths:
                    flagged.append(p)
            return flagged

        # The patch is an input to the one and only post-execution Reviewer for
        # an attempt.  Keeping it here (inside the bounded bridge) is
        # intentional: a Reviewer rejection must be returned to
        # ``run_safe_execution`` so that the bridge owns rollback, Planner
        # replan, and the next attempt.  The final accepted artifact is reused
        # by the apply path below; it is never rebuilt from an unreviewed
        # snapshot after the bridge has already accepted the attempt.
        from sitina.orchestrator.execution_patch import (
            build_patch_manifest,
            verify_patch_replay,
        )
        patch_receipts: list[Any] = []
        attempt_patch_artifacts: dict[int, dict[str, Any]] = {}

        def _attempt_execution_id(attempt: int, diff_paths: Sequence[str]) -> str:
            raw = canonical_json_bytes(
                {
                    "run_id": evidence.run_id,
                    "attempt": attempt,
                    # Match ExecutionResult.execution_attempt_id exactly:
                    # the bridge identity is rooted at the authorized
                    # execution root, while the manifest separately records
                    # the concrete attempt workspace.
                    "workspace": str(execution_root),
                    "diff_paths": list(diff_paths),
                    "execution_identity_hash": identity_binding.binding_hash,
                }
            )
            return "execution-attempt:" + sha256_bytes(raw)

        def _prepare_review_artifact(
            attempt: int,
            diff_paths: Sequence[str],
            forge_result: Mapping[str, Any],
            verdict: VerificationVerdict,
        ) -> dict[str, Any]:
            mutation_events = attempt_results.get(attempt, {}).get("mutation_events")
            if not isinstance(mutation_events, list):
                raise DynamicCollaborationError("accepted execution has no mutation event ledger")
            successful_events = [
                item for item in mutation_events
                if item.get("denied") is False and isinstance(item.get("path"), str)
            ]
            latest_by_path: dict[str, Mapping[str, Any]] = {}
            for item in sorted(successful_events, key=lambda value: int(value.get("sequence", 0))):
                latest_by_path[str(Path(str(item["path"])).expanduser().resolve(strict=False))] = item
            content_refs: dict[str, str] = {}
            for value in diff_paths:
                canonical_path = str(Path(value).expanduser().resolve(strict=False))
                event = latest_by_path.get(canonical_path)
                if not isinstance(event, Mapping):
                    raise DynamicCollaborationError("changed path has no mutation evidence")
                if str(event.get("operation")) == "delete":
                    continue
                content_path = Path(canonical_path)
                if str(event.get("operation")) == "rename":
                    destination = event.get("destination")
                    if not isinstance(destination, str) or not destination:
                        raise DynamicCollaborationError("accepted rename has no destination evidence")
                    content_path = Path(destination).expanduser().resolve(strict=True)
                if not content_path.is_file() or content_path.is_symlink():
                    raise DynamicCollaborationError("accepted mutation content source is unavailable")
                receipt = executor._publish_body(
                    content_path.read_bytes(), purpose="true-multi-agent-execution-patch-content"
                )
                patch_receipts.append(receipt)
                content_refs[canonical_path] = receipt.object_ref.reference_id
            manifest, manifest_hash = build_patch_manifest(
                run_id=evidence.run_id,
                execution_attempt_id=_attempt_execution_id(attempt, diff_paths),
                workspace=attempt_ws(attempt),
                diff_paths=diff_paths,
                mutation_events=mutation_events,
                content_refs=content_refs,
                target_repo=str(selected_workspace),
            )
            verify_patch_replay(
                manifest,
                load_content=lambda reference: cas.open_verified(cas.resolve_reference(reference)),
            )
            manifest_receipt = executor._publish(
                manifest, purpose="true-multi-agent-execution-patch-manifest"
            )
            patch_receipts.append(manifest_receipt)
            artifact = {
                "manifest": manifest,
                "manifest_hash": manifest_hash,
                "manifest_ref": manifest_receipt.object_ref.reference_id,
                "content_refs": content_refs,
                "mutation_events": mutation_events,
                "tester_evidence_hash": verdict.test_evidence_hash,
                "tester_verdict_hash": verdict.verdict_hash,
                "execution_attempt_id": _attempt_execution_id(attempt, diff_paths),
            }
            test_evidence_ref = verdict.test_evidence_ref
            test_evidence_hash = verdict.test_evidence_hash
            if not isinstance(test_evidence_ref, str) or not test_evidence_ref.startswith("cas:"):
                raise DynamicCollaborationError("accepted execution has no immutable Tester evidence")
            if not isinstance(test_evidence_hash, str) or not re.fullmatch(
                r"[0-9a-f]{64}", test_evidence_hash
            ):
                raise DynamicCollaborationError("accepted execution Tester evidence hash is invalid")
            try:
                test_evidence_raw = cas.open_verified(cas.resolve_reference(test_evidence_ref))
                test_evidence = parse_canonical_json(test_evidence_raw)
            except Exception as error:
                raise DynamicCollaborationError(
                    "accepted execution Tester evidence cannot be reopened"
                ) from error
            if (
                sha256_bytes(test_evidence_raw) != test_evidence_hash
                or not isinstance(test_evidence, Mapping)
                or test_evidence.get("accepted") is not True
            ):
                raise DynamicCollaborationError(
                    "accepted execution Tester evidence is not exact and passing"
                )
            artifact["review_evidence"] = {
                "schema": "SITINA_POST_EXECUTION_REVIEW_EVIDENCE_V1",
                "forge": {
                    "status": forge_result.get("status"),
                    "terminal_state": forge_result.get("terminal_state"),
                    "provider_call_count": forge_result.get("provider_call_count"),
                    "tool_call_count": forge_result.get("tool_call_count"),
                    "file_mutation_event_count": forge_result.get("file_mutation_event_count"),
                    "unique_mutated_path_count": forge_result.get("unique_mutated_path_count"),
                    "denied_effect_attempt_count": forge_result.get("denied_effect_attempt_count"),
                    "external_mutation_count": forge_result.get("external_mutation_count"),
                },
                "tester": {
                    "accepted": test_evidence.get("accepted"),
                    "collected_test_count": test_evidence.get("collected_test_count"),
                    "executed_test_count": test_evidence.get("executed_test_count"),
                    "passed_test_count": test_evidence.get("passed_test_count"),
                    "failed_test_count": test_evidence.get("failed_test_count"),
                    "skipped_test_count": test_evidence.get("skipped_test_count"),
                    "error_test_count": test_evidence.get("error_test_count"),
                    "runner_return_code": test_evidence.get("runner_return_code"),
                    "timed_out": test_evidence.get("timed_out"),
                    "diff_hash_before": test_evidence.get("diff_hash_before"),
                    "diff_hash_after": test_evidence.get("diff_hash_after"),
                    "target_hashes": test_evidence.get("target_hashes"),
                    "evidence_ref": test_evidence_ref,
                    "evidence_hash": test_evidence_hash,
                },
                "patch_manifest": manifest,
                "patch_manifest_ref": manifest_receipt.object_ref.reference_id,
                "patch_manifest_hash": manifest_hash,
                "execution_identity_hash": identity_binding.binding_hash,
            }
            attempt_patch_artifacts[attempt] = artifact
            return artifact

        def verifier(diff_paths: Sequence[str], forge_result: Mapping[str, Any]) -> VerificationVerdict:
            # Delegating to extracted helper for testability (eliminates mirror drift)
            from sitina.orchestrator.execution_verification import verify_execution_diff
            from sitina.orchestrator.execution_sandbox import CASTestEvidencePublisher
            verdict = verify_execution_diff(
                diff_paths,
                verifier_id,
                forge_result,
                run_id=evidence.run_id,
                home=self.home,
                authority_resolution=context.authority.resolution,
                proposer_id=proposer_id,
                executor_id=executor_id,
                identity_binding=identity_binding,
                agent_registry=self.registry,
                execution_policy_hash=policy_hash_64,
                # Rework may have committed a new attempt mapping.  Read the
                # controller's current binding, not the attempt-one closure
                # captured before the bridge started.
                code_mode_authorization=controls.get("code_mode_authorization"),
                code_mode_parent_authority=context,
                code_mode_parent=sandbox_parent,
                code_mode_scratch_root=sandbox_scratch_root,
                execution_root=attempt_ws(int(forge_result.get("attempt") or getattr(self, "_exec_last_attempt", 1))),
                baseline_test_inventory=attempt_test_inventories.get(
                    int(forge_result.get("attempt") or getattr(self, "_exec_last_attempt", 1)), ()
                ),
                evidence_publisher=CASTestEvidencePublisher(cas, context.provider),
                worker_executor=attempt_workers.get(int(forge_result.get("attempt") or getattr(self, "_exec_last_attempt", 1))),
            )
            if not verdict.accepted:
                return verdict

            attempt = int(forge_result.get("attempt") or getattr(self, "_exec_last_attempt", 1))
            artifact = _prepare_review_artifact(attempt, diff_paths, forge_result, verdict)

            # This is the sole post-execution Reviewer for this attempt.  It
            # runs only after the independent Tester and after an immutable
            # manifest has been published.  A rejection is returned through
            # the bridge, which performs rollback and Planner replan without
            # resetting the bounded attempt budget.
            try:
                review = self._call(
                    executor,
                    evidence,
                    reviewer_agent,
                    task_id=f"execution-review-{attempt}",
                    kind="review",
                    contract=(
                        "Review only the completed Forge execution after Tester verification and immutable patch sealing. "
                        "Return exactly one JSON object with shape "
                        '{"agent_id":"<exact>","kind":"review","decision":"accept|reject",'
                        '"reason":"non-empty string","evidence_checks":["1-8 non-empty strings"]}. '
                        "Replace <exact> only with the assigned Agent id. decision must be lowercase accept or reject; "
                        "evidence_checks must be a JSON array containing 1 to 8 non-empty strings."
                    ),
                    prompt=(
                        "Independently review this execution evidence for this exact attempt after "
                        "independent Tester verification. Accept only when the actual diff, Tester "
                        "evidence, immutable patch manifest, and execution identity are mutually bound. "
                        "Reject when the evidence is not safe and complete. The verified_evidence object below is "
                        "reopened from immutable CAS objects after deterministic validation; inspect its concrete "
                        "test counts, mutation accounting, changed entries, content hashes, and identity bindings "
                        "instead of treating their top-level hashes as missing evidence. Return exactly this JSON "
                        "shape and no prose: "
                        '{"agent_id":"<exact>","kind":"review","decision":"accept|reject",'
                        '"reason":"non-empty string","evidence_checks":["1-8 non-empty strings"]}. '
                        "Use 1-8 non-empty string evidence_checks and lowercase decision only.\n"
                        + json.dumps(
                            {
                                "run_id": evidence.run_id,
                                "execution_attempt_id": artifact["execution_attempt_id"],
                                "attempt": attempt,
                                "diff_paths": list(diff_paths),
                                "tester_evidence_hash": verdict.test_evidence_hash,
                                "tester_verdict_hash": verdict.verdict_hash,
                                "patch_manifest_hash": artifact["manifest_hash"],
                                "execution_identity_hash": identity_binding.binding_hash,
                                "verified_evidence": artifact["review_evidence"],
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                    ),
                    context={
                        "attempt": attempt,
                        "execution_attempt_id": artifact["execution_attempt_id"],
                        "diff_hash": sha256_bytes(canonical_json_bytes(list(diff_paths))),
                        "tester_evidence_hash": verdict.test_evidence_hash,
                        "tester_verdict_hash": verdict.verdict_hash,
                        "patch_manifest_hash": artifact["manifest_hash"],
                        "execution_identity_hash": identity_binding.binding_hash,
                    },
                    validate=lambda value: (
                        _require_review_decision(value),
                        _require_string(value, "reason"),
                        _require_strings(value, "evidence_checks", minimum=1, maximum=8),
                    ),
                )
            except Exception as error:
                review = None
                review_error_hash = sha256_bytes(type(error).__name__.encode("utf-8"))
            else:
                review_error_hash = ""
            if review is None or str(review.value.get("decision") or "").casefold() != "accept":
                reason_hash = review_error_hash or sha256_bytes(
                    str(review.value.get("reason") or "review rejected").encode("utf-8")
                )
                run_stream.append(
                    "execution-stage-reviewer",
                    ({
                        "schema": "SITINA_EXECUTION_STAGE_V1",
                        "event_type": "execution.stage",
                        "stage": "Reviewer",
                        "role": "independent-post-execution-reviewer",
                        "agent_id": reviewer_id,
                        "post_execution": True,
                        "call_id": review.call_id if review is not None else None,
                        "output_hash": review.output_hash if review is not None else None,
                        "decision": "rejected",
                        "reason_hash": reason_hash,
                        "attempt": attempt,
                        "execution_attempt_id": artifact["execution_attempt_id"],
                        "diff_hash": sha256_bytes(canonical_json_bytes(list(diff_paths))),
                        "run_attempt": attempt,
                        "authorization_ref": authorization_ref,
                        **({
                            "plan_hash": replan_context[attempt]["plan_hash"],
                            "replan_plan_hash": replan_context[attempt]["replan_plan_hash"],
                            "replan_plan_ref": replan_context[attempt]["replan_plan_ref"],
                            "replan_plan": dict(replan_context[attempt]["replan_plan"]),
                        } if isinstance(replan_context.get(attempt), Mapping) else {}),
                        "tester_verdict_hash": verdict.verdict_hash,
                        "tester_evidence_hash": verdict.test_evidence_hash,
                        "patch_manifest_hash": artifact["manifest_hash"],
                        "execution_identity_hash": identity_binding.binding_hash,
                        "reviewer_decision_bound_to_execution": True,
                    },),
                    actor=reviewer_id,
                )
                run_stream.append(
                    "execution-review-rejected",
                    ({
                        "schema": "SITINA_EXECUTION_REVIEW_REJECTION_V1",
                        "event_type": "execution.rework.reviewer-rejected",
                        "attempt": attempt,
                        "run_attempt": attempt,
                        "reviewer_id": reviewer_id,
                        "authorization_ref": authorization_ref,
                        "review_output_hash": review.output_hash if review is not None else None,
                        "reason_hash": reason_hash,
                        "tester_evidence_hash": verdict.test_evidence_hash,
                        "tester_verdict_hash": verdict.verdict_hash,
                        "patch_manifest_hash": artifact["manifest_hash"],
                        "execution_attempt_id": artifact["execution_attempt_id"],
                        "execution_identity_hash": identity_binding.binding_hash,
                    },),
                    actor=reviewer_id,
                )
                return VerificationVerdict(
                    False, verdict.verifier_id, verdict.checked_diff, verdict.checked_tests,
                    verdict.identity,
                    verdict.reasons + ("post_execution_reviewer_rejected", reason_hash),
                    verdict.test_evidence_ref, verdict.test_evidence_hash,
                )
            run_stream.append(
                "execution-stage-reviewer",
                ({
                    "schema": "SITINA_EXECUTION_STAGE_V1",
                    "event_type": "execution.stage",
                    "stage": "Reviewer",
                    "role": "independent-post-execution-reviewer",
                    "agent_id": reviewer_id,
                    "post_execution": True,
                    "call_id": review.call_id,
                    "output_hash": review.output_hash,
                    "decision": "accepted",
                    "reason_hash": sha256_bytes(str(review.value.get("reason")).encode()),
                    "attempt": attempt,
                    "execution_attempt_id": artifact["execution_attempt_id"],
                    "diff_hash": sha256_bytes(canonical_json_bytes(list(diff_paths))),
                    "run_attempt": attempt,
                    "authorization_ref": authorization_ref,
                    **({
                        "plan_hash": replan_context[attempt]["plan_hash"],
                        "replan_plan_hash": replan_context[attempt]["replan_plan_hash"],
                        "replan_plan_ref": replan_context[attempt]["replan_plan_ref"],
                        "replan_plan": dict(replan_context[attempt]["replan_plan"]),
                    } if isinstance(replan_context.get(attempt), Mapping) else {}),
                    "tester_verdict_hash": verdict.verdict_hash,
                    "tester_evidence_hash": verdict.test_evidence_hash,
                    "patch_manifest_hash": artifact["manifest_hash"],
                    "execution_identity_hash": identity_binding.binding_hash,
                    "reviewer_decision_bound_to_execution": True,
                },),
                actor=reviewer_id,
            )
            return verdict

        def rollback(attempt: int) -> None:
            runtime = attempt_results.get(attempt, {})
            events = runtime.get("mutation_events")
            if not isinstance(events, list):
                return
            paths = [str(item["path"]) for item in events if item.get("denied") is False and item.get("path")]
            after_hashes = {
                str(item["path"]): item.get("after_hash")
                for item in events
                if item.get("denied") is False and item.get("path")
            }
            baseline = attempt_baselines.get(attempt)
            if baseline is None:
                raise ExecutionTargetError("cannot rollback an execution without a workspace baseline")
            rollback_run_id = f"rollback-{evidence.run_id}-{attempt}"
            # Rollback is a separate, restricted execution child.  It has an
            # exact purpose/root/run/attempt binding and cannot reuse the
            # Forge child or the parent authorization reference.
            rollback_issuer = getattr(context, "issue_execution_child_authorization", None)
            if not callable(rollback_issuer) or sandbox_parent is None:
                raise ExecutionTargetError("rollback requires a trusted Code Mode child issuer")
            rollback_authorization = rollback_issuer(
                sandbox_parent,
                attempt=attempt,
                purpose="rejected-attempt-rollback",
                workspace=execution_root,
                scope=(str(execution_root),),
                expires_at=min(int(authorization["expires_at"]), int(time.time()) + 120),
            )
            if rollback_authorization.get("run_id") != rollback_run_id:
                raise ExecutionTargetError("rollback child run binding mismatch")
            rollback_executor = ToolExecutor(
                self.home,
                store=mutation_executor.store,
                enforce_write_boundary=True,
                authorization_binding=rollback_authorization,
                authorization_authority=context,
            )
            rollback_capability = rollback_executor._mint_direct_capability(
                run_id=str(rollback_authorization["run_id"]),
                authorization_ref=str(rollback_authorization["authorization_ref"]),
                target_repo=str(execution_root),
                allowed_roots=[str(execution_root)],
                purpose="rejected-attempt-rollback",
            )
            baseline.restore_rejected_attempt(
                paths,
                expected_after_hashes=after_hashes,
                executor=rollback_executor,
                run_id=rollback_run_id,
                capability=rollback_capability,
            )

        def replan(attempt: int, failure: Mapping[str, Any]) -> Mapping[str, Any]:
            """Build a bounded replan from the prior typed attempt ledger.

            A Provider transport/HTTP failure before any mutation is not a
            product failure the model may reinterpret.  The controller
            deterministically resumes the frozen original plan, avoiding a
            second Planner call and preventing a "retry/backoff" goal rewrite.
            Other failures may receive a model-supplied delta, but the
            original acceptance checks remain complete in the resulting plan.
            """
            def validate_replan(value: Mapping[str, Any]) -> None:
                _require_string(value, "approach")
                _require_text_or_strings(value, "acceptance_checks", maximum=8)

            failure_type = str(failure.get("failure_type") or "")
            reason_code = str(failure.get("reason_code") or "")
            try:
                mutation_count = int(failure.get("mutation_count") or 0)
            except (TypeError, ValueError) as error:
                raise DynamicCollaborationError("typed replan mutation count is invalid") from error
            provider_failure = (
                mutation_count == 0
                and (
                    reason_code in {"PROVIDER_HTTP_FAILURE", "PROVIDER_TRANSPORT_FAILURE"}
                    or re.fullmatch(r"PROVIDER_HTTP_STATUS_[0-9]{3}", reason_code) is not None
                    or "providerhttp" in failure_type.casefold()
                    or ("provider" in failure_type.casefold() and "transport" in failure_type.casefold())
                )
            )
            recovery_mode = "resume-original" if provider_failure else "model-delta"
            if provider_failure:
                normalized_plan = {
                    "approach": str(original_execution_plan["approach"]),
                    "acceptance_checks": list(original_execution_plan["acceptance_checks"]),
                }
            else:
                replanned = self._call(
                    executor,
                    evidence,
                    winner_agent,
                    task_id=f"execution-replan-{attempt}",
                    kind="replan",
                    contract=(
                        "Produce a bounded recovery delta for the failed execution attempt. "
                        "Return approach and acceptance_checks; preserve the original product goal "
                        "and all original acceptance checks."
                    ),
                    prompt=(
                        "Recover the original requested implementation. Preserve this immutable original "
                        "execution plan and its acceptance checks; any response is only a bounded recovery "
                        "delta and must not replace the product goal with a Provider retry/backoff task.\n"
                        "ORIGINAL_EXECUTION_PLAN=\n"
                        + json.dumps(original_execution_plan, ensure_ascii=False, sort_keys=True)
                        + "\nTYPED_PRIOR_FAILURE=\n"
                        + json.dumps(dict(failure), ensure_ascii=False, sort_keys=True)
                    ),
                    context={
                        "prior_failure": dict(failure),
                        "prior_plan_hash": str(failure.get("plan_hash") or winner.output_hash),
                        "attempt": attempt,
                        "original_execution_plan": dict(original_execution_plan),
                        "original_execution_plan_hash": original_execution_plan_hash,
                        "original_intent_hash": intent_hash,
                        "execution_mode": "forge",
                        "mutation_required": True,
                    },
                    validate=validate_replan,
                )
                delta_approach = _require_string(replanned.value, "approach")
                delta_acceptance = _require_text_or_strings(
                    replanned.value, "acceptance_checks", maximum=8
                )
                combined_acceptance = list(original_execution_plan["acceptance_checks"])
                for check in delta_acceptance:
                    if check not in combined_acceptance:
                        combined_acceptance.append(check)
                if len(combined_acceptance) > 8:
                    raise DynamicCollaborationError("replan acceptance checks exceed bounded original plan")
                normalized_plan = {
                    "approach": str(original_execution_plan["approach"]) + "\nRecovery delta:\n" + delta_approach,
                    "acceptance_checks": combined_acceptance,
                }
            normalized_plan_hash = sha256_bytes(canonical_json_bytes(normalized_plan))
            prior_plan_hash = str(
                failure.get("plan_hash") or winner.output_hash
            ).removeprefix("sha256:")
            prior_failure_type = str(failure.get("failure_type") or "unknown")
            prior_failure_hash = str(failure.get("failure_hash") or "")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", normalized_plan_hash)
                or not re.fullmatch(r"[0-9a-f]{64}", prior_plan_hash)
                or not re.fullmatch(r"[0-9a-f]{64}", prior_failure_hash)
            ):
                raise DynamicCollaborationError("Code Mode replan predecessor commitment is invalid")
            replan_body = {
                "schema": "SITINA_EXECUTION_REPLAN_PLAN_V1",
                "session_instance_id": str(controls.get("session_instance_id") or ""),
                "session_id": str(controls.get("conversation_session_id") or ""),
                "run_id": evidence.run_id,
                "run_attempt": attempt,
                "previous_authorization_ref": str(authorization_ref),
                "original_intent_hash": intent_hash,
                "original_plan_hash": original_execution_plan_hash,
                "original_execution_plan": dict(original_execution_plan),
                "execution_mode": "forge",
                "mutation_required": True,
                "recovery_mode": recovery_mode,
                "prior_plan_hash": prior_plan_hash,
                "prior_failure_type": prior_failure_type,
                "prior_failure_hash": prior_failure_hash,
                "reason_code": reason_code or "EXECUTION_FAILURE",
                "failure_stage": str(failure.get("failure_stage") or "Forge"),
                "mutation_count": mutation_count,
                "typed_prior_failure": {
                    "failure_type": prior_failure_type,
                    "failure_hash": prior_failure_hash,
                    "reason_code": reason_code or "EXECUTION_FAILURE",
                    "failure_stage": str(failure.get("failure_stage") or "Forge"),
                    "mutation_count": mutation_count,
                },
                "plan_hash": normalized_plan_hash,
                **normalized_plan,
            }
            replan_receipt = executor._publish(
                replan_body, purpose="true-multi-agent-execution-replan"
            )
            record = {
                "attempt": attempt,
                "plan_hash": normalized_plan_hash,
                "replan_plan_hash": normalized_plan_hash,
                "replan_plan_ref": replan_receipt.object_ref.reference_id,
                "replan_plan_receipt_hash": replan_receipt.object_ref.plaintext_commitment,
                "replan_receipt": replan_receipt,
                "replan_plan": normalized_plan,
                "prior_plan_hash": prior_plan_hash,
                "prior_failure_type": prior_failure_type,
                "prior_failure_hash": prior_failure_hash,
                "original_plan_hash": original_execution_plan_hash,
                "original_execution_plan": dict(original_execution_plan),
                "original_intent_hash": intent_hash,
                "execution_mode": "forge",
                "mutation_required": True,
                "recovery_mode": recovery_mode,
                "reason_code": reason_code or "EXECUTION_FAILURE",
                "failure_stage": str(failure.get("failure_stage") or "Forge"),
                "mutation_count": mutation_count,
                "typed_prior_failure": {
                    "failure_type": prior_failure_type,
                    "failure_hash": prior_failure_hash,
                    "reason_code": reason_code or "EXECUTION_FAILURE",
                    "failure_stage": str(failure.get("failure_stage") or "Forge"),
                    "mutation_count": mutation_count,
                },
            }
            replan_context[attempt] = record
            return record

        result = run_safe_execution(
            binding=binding, executor_id=executor_id, workspace=str(execution_root),
            forge_runner=forge_runner, collect_diff=collect_diff,
            boundary_check=boundary_check, verifier=verifier, rollback=rollback,
            max_attempts=int(self.policy.get("max_execution_attempts", 2)),
            replan=replan,
            original_plan_hash=original_execution_plan_hash,
        )
        if not result.accepted and managed_worktree is not None:
            cleanup_report = worktree_manager.cleanup(
                str(selected_workspace), str(managed_worktree), evidence.run_id
            )
            worktree_cleanup_report = cleanup_report
            record_worktree_cleanup(cleanup_report)
            if cleanup_report.get("status") != "ok":
                result = dataclasses.replace(
                    result,
                    notes=result.notes + (
                        "managed_worktree_cleanup_failed",
                        "managed_worktree_cleanup_status=" + str(cleanup_report.get("status")),
                    ),
                )
        verification_mapping = result.verification.mapping() if result.verification is not None else None
        run_stream.append(
            "execution-stage-tester",
            ({
                "schema": "SITINA_EXECUTION_STAGE_V1",
                "event_type": "execution.stage",
                "stage": "Tester",
                "role": "independent-tester",
                "agent_id": verifier_id,
                "attempts": result.attempts,
                "run_attempt": result.attempts,
                "authorization_ref": authorization_ref,
                **({
                    "plan_hash": replan_context[result.attempts]["plan_hash"],
                    "replan_plan_hash": replan_context[result.attempts]["replan_plan_hash"],
                    "replan_plan_ref": replan_context[result.attempts]["replan_plan_ref"],
                    "replan_plan": dict(replan_context[result.attempts]["replan_plan"]),
                } if isinstance(replan_context.get(result.attempts), Mapping) else {}),
                "run_id": evidence.run_id,
                "accepted": bool(result.accepted),
                "verification": verification_mapping,
                "test_evidence_ref": result.verification.test_evidence_ref if result.verification else None,
                "test_evidence_hash": result.verification.test_evidence_hash if result.verification else None,
            },),
            actor="independent-tester",
        )
        if result.attempts > 1:
            run_stream.append(
                "execution-rework-cycle",
                ({
                    "schema": "SITINA_EXECUTION_REWORK_V1",
                    "event_type": "execution.rework",
                    "attempts": result.attempts,
                    "automatic": True,
                    "same_failure_requires_replan": any(
                        bool(item.get("same_failure")) and bool(item.get("replan"))
                        for item in result.attempt_ledger
                    ),
                    "replan_plan_hashes": [
                        str(item.get("plan_hash"))
                        for item in result.attempt_ledger
                        if item.get("replan") and item.get("plan_hash")
                    ],
                    "attempt_ledger": [dict(item) for item in result.attempt_ledger],
                    "notes": list(result.notes),
                },),
                actor="controller-execution-authorizer",
            )
        if result.accepted:
            accepted_runtime = attempt_results.get(result.attempts, {})
            if int(accepted_runtime.get("external_mutation_count", 0) or 0) != 0:
                result = dataclasses.replace(
                    result,
                    status="rejected",
                    accepted=False,
                    notes=result.notes + ("external_mutation_not_deliverable",),
                )
        if result.accepted:
            try:
                artifact = attempt_patch_artifacts.get(result.attempts)
                if not isinstance(artifact, Mapping):
                    raise DynamicCollaborationError(
                        "accepted execution has no reviewed immutable patch artifact"
                    )
                manifest = artifact["manifest"]
                manifest_hash = str(artifact["manifest_hash"])
                manifest_ref = str(artifact["manifest_ref"])
                mutation_events = artifact["mutation_events"]
                content_refs = artifact["content_refs"]
                result = dataclasses.replace(
                    result,
                    patch_manifest_ref=manifest_ref,
                    patch_manifest_hash=manifest_hash,
                )

                if result.accepted and managed_worktree is not None:
                    apply_issuer = getattr(context, "issue_execution_child_authorization", None)
                    if not callable(apply_issuer) or sandbox_parent is None:
                        raise DynamicCollaborationError("accepted patch apply requires a trusted child issuer")
                    apply_authorization = apply_issuer(
                        sandbox_parent,
                        attempt=result.attempts,
                        purpose="accepted-patch-apply",
                        workspace=selected_workspace,
                        scope=(str(selected_workspace),),
                        expires_at=min(int(authorization["expires_at"]), int(time.time()) + 120),
                    )
                    apply_executor = ToolExecutor(
                        self.home,
                        store=mutation_executor.store,
                        enforce_write_boundary=True,
                        authorization_binding=apply_authorization,
                        authorization_authority=context,
                    )
                    apply_capability = apply_executor._mint_direct_capability(
                        run_id=str(apply_authorization["run_id"]),
                        authorization_ref=str(apply_authorization["authorization_ref"]),
                        target_repo=str(selected_workspace),
                        allowed_roots=[str(selected_workspace)],
                        purpose="accepted-patch-apply",
                    )
                    applied_paths = apply_verified_files(
                        target_root=selected_workspace,
                        source_root=managed_worktree,
                        diff_paths=result.diff_paths,
                        mutation_events=mutation_events,
                        content_loader=lambda reference: cas.open_verified(cas.resolve_reference(reference)),
                        content_refs=content_refs,
                        manifest=manifest,
                        target_repo=str(selected_workspace),
                        executor=apply_executor,
                        run_id=str(apply_authorization["run_id"]),
                        capability=apply_capability,
                    )
                elif result.accepted:
                    applied_paths = tuple(result.diff_paths)
                if result.accepted:
                    result = dataclasses.replace(
                        result,
                        notes=result.notes + (
                            "target_workspace_applied" if managed_worktree is not None else "target_workspace_direct",
                        ),
                    )
                # Keep an accepted managed worktree alive through the first
                # Code Mode checkpoint and the subsequent TTY/internal Gate.
                # The checkpoint seals machine evidence from the real Tester
                # cwd; finalization performs the exact run-scoped cleanup
                # immediately before terminal/root sealing.  Rejected and
                # exception paths above still clean up synchronously.
            except Exception as error:
                rollback_error: str | None = None
                if result.accepted:
                    try:
                        rollback(result.attempts)
                    except Exception as rollback_failure:
                        rollback_error = type(rollback_failure).__name__
                result = dataclasses.replace(
                    result,
                    status="rejected",
                    accepted=False,
                    notes=result.notes
                    + (f"patch_manifest_rejected:{type(error).__name__}",)
                    + ((f"rollback_failed:{rollback_error}",) if rollback_error else ()),
                )
                if managed_worktree is not None:
                    cleanup_report = worktree_manager.cleanup(
                        str(selected_workspace), str(managed_worktree), evidence.run_id
                    )
                    worktree_cleanup_report = cleanup_report
                    record_worktree_cleanup(cleanup_report)
                    if cleanup_report.get("status") != "ok":
                        result = dataclasses.replace(
                            result,
                            notes=result.notes + (
                                "managed_worktree_cleanup_failed",
                                "managed_worktree_cleanup_status=" + str(cleanup_report.get("status")),
                            ),
                        )
        # FIX4: record real mutation accounting instead of a hardcoded 0.
        # Sandbox writes are sandbox_mutation_count (isolated temp, not the repo);
        # patch refs come from the produced diff. proposer vs executor vs verifier
        # are recorded distinctly so the audit is internally consistent.
        final_runtime = attempt_results.get(result.attempts, {})
        sandbox_mutations = int(final_runtime.get("file_mutation_event_count", 0) or 0)
        unique_mutated_paths = int(final_runtime.get("unique_mutated_path_count", 0) or 0)
        denied_effect_attempts = int(final_runtime.get("denied_effect_attempt_count", 0) or 0)
        external_mutations = int(final_runtime.get("external_mutation_count", 0) or 0)
        # A rejected attempt may have published a content object that the
        # successful replan produced again.  CAS is content-addressed, so the
        # receipts can legitimately share a reference, but Journal proofs
        # must contain each object exactly once.
        unique_patch_receipts: dict[str, Any] = {}
        for patch_receipt in patch_receipts:
            unique_patch_receipts.setdefault(patch_receipt.object_ref.reference_id, patch_receipt)
        patch_proofs = tuple(unique_patch_receipts.values())
        run_stream.append(
            "forge-execution-result",
            ({"event_type": "forge.execution.result", **result.as_event(),
              "proposer_id": proposer_id,
              "executor_id": executor_id,
              "executor_is_text_agent": False,
              "verifier_id": verifier_id,
              "post_execution_reviewer_id": reviewer_id,
              "run_attempt": result.attempts,
              "authorization_ref": authorization_ref,
              **({
                  "plan_hash": replan_context[result.attempts]["plan_hash"],
                  "replan_plan_hash": replan_context[result.attempts]["replan_plan_hash"],
                  "replan_plan_ref": replan_context[result.attempts]["replan_plan_ref"],
                  "replan_plan": dict(replan_context[result.attempts]["replan_plan"]),
              } if isinstance(replan_context.get(result.attempts), Mapping) else {}),
              "sandbox_mutation_count": sandbox_mutations,
              "sandbox_unique_mutated_path_count": unique_mutated_paths,
              "denied_effect_attempt_count": denied_effect_attempts,
              "sandbox_patch_paths": list(result.diff_paths),
              "selected_workspace": str(selected_workspace),
              "execution_root": str(execution_root),
              "workspace_mode": "managed_worktree" if managed_worktree is not None else "direct",
              "worktree_lifecycle": dict(prepared) if managed_worktree is not None else None,
              "worktree_cleanup": dict(worktree_cleanup_report or {}) if managed_worktree is not None else None,
              "overlay_report": dict(overlay_report),
              "mutation_events": list(final_runtime.get("mutation_events", [])),
              "external_mutation_count": external_mutations,
              "embedded_provider_call_count": embedded_usage["provider_calls"],
              "embedded_physical_send_count": embedded_usage["physical_sends"],
              "embedded_tool_call_count": embedded_usage["tool_calls"],
              "embedded_input_tokens": embedded_usage["input_tokens"],
              "embedded_output_tokens": embedded_usage["output_tokens"],
              "embedded_cache_read_tokens": embedded_usage["cache_read_tokens"],
              "embedded_cache_write_tokens": embedded_usage["cache_write_tokens"],
              "embedded_total_tokens": embedded_usage["total_tokens"],
              "embedded_cost_micro_usd": embedded_usage["cost_micro_usd"],
              "embedded_retry_count": embedded_usage["retry_count"],
              "embedded_fallback_count": embedded_usage["fallback_count"],
              "embedded_unsettled_usage_count": embedded_usage["unsettled_usage_count"],
              "unified_model_budget": executor.usage_totals(),
              "_object_refs": list(unique_patch_receipts)},),
            actor="forge-execution-bridge",
            proofs=patch_proofs,
        )
        return result

    def _seal_code_mode_execution_core(
        self,
        *,
        context: Any,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        code_receipt: Mapping[str, Any],
        side_effect_counts: Mapping[str, Any],
        controls: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist the complete, replayable Code Mode execution evidence.

        This is the source for post-restart terminalization.  It contains the
        original run evidence and only immutable locator projections for the
        candidate/machine/package/request objects.  It is not a caller result
        summary and is never rebuilt from the recovery facade.
        """
        user_response = str(evidence.user_response or "").strip()
        user_message = str(controls.get("conversation_user_message") or "").strip()
        calls = [_safe_code_mode_call(item) for item in evidence.calls]
        if not calls or not isinstance(evidence.execution_result, Mapping):
            raise DynamicCollaborationError("Code Mode execution evidence core is incomplete")
        response_locator: dict[str, str] | None = None
        response_proof: Any | None = None
        if user_response:
            from sitina.cas.crypto import encrypt_object
            response_publication = cas.publish_verified(
                encrypt_object(
                    user_response.encode("utf-8"),
                    context.provider,
                    tenant_id="sitina-conversation",
                    purpose="code-mode-assistant-response",
                )
            )
            response_proof = response_publication
            if not response_publication.fresh_verified or not response_publication.no_replace_published:
                raise DynamicCollaborationError("Code Mode response CAS publication was not immutable")
            response_locator = _code_mode_locator(
                {"reference_id": response_publication.object_ref.reference_id,
                 "object_hash": response_publication.object_ref.object_id},
                "assistant-response",
            )
        candidate_locator = _code_mode_locator(code_receipt.get("candidate_locator"), "candidate")
        machine_locator = _code_mode_locator(code_receipt.get("machine_check_receipt"), "machine-check")
        package_locator = _code_mode_locator(code_receipt.get("evidence_package"), "evidence-package")
        request_locator = _code_mode_locator(code_receipt.get("review_request"), "review-request")
        machine_object = cas.resolve_reference(machine_locator["reference_id"])
        machine_body = json.loads(cas.open_verified(machine_object).decode("utf-8"))
        if not isinstance(machine_body, Mapping):
            raise DynamicCollaborationError("Code Mode machine evidence is not a mapping")
        generation = machine_body.get("generation")
        verifier_identity = machine_body.get("verifier_identity")
        if not isinstance(generation, str) or not generation or not isinstance(verifier_identity, str) or not verifier_identity:
            raise DynamicCollaborationError("Code Mode machine evidence lacks generation/verifier identity")
        authorization_ref = str(
            (code_receipt.get("candidate") or {}).get("authorization_ref")
            or machine_body.get("authorization_ref")
            or ""
        )
        if not authorization_ref:
            raise DynamicCollaborationError("Code Mode execution evidence core lacks current authorization identity")
        core = {
            "schema": "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
            "run_id": evidence.run_id,
            "session_instance_id": controls.get("session_instance_id"),
            "candidate_id": str((code_receipt.get("candidate") or {}).get("candidate_id") or ""),
            "tree_hash": str((code_receipt.get("candidate") or {}).get("tree_hash") or ""),
            "source_manifest_hash": str((code_receipt.get("candidate") or {}).get("source_manifest_hash") or ""),
            "session_id": controls.get("conversation_session_id"),
            "run_attempt": controls.get("run_attempt"),
            "turn_index": controls.get("conversation_turn_index"),
            "conversation_turn_index": controls.get("conversation_turn_index"),
            "conversation_message_hash": sha256_bytes(user_message.encode("utf-8")),
            "response_hash": sha256_bytes(user_response.encode("utf-8")) if user_response else None,
            "response_locator": response_locator,
            "goal_hash": evidence.goal_hash,
            "policy_hash": evidence.policy_hash,
            "run_evidence": {
                "decisions": [
                    {
                        "fact_hash": stable_hash("CODE_MODE_DECISION", dict(item)),
                        "decision_type": str(item.get("decision_type") or item.get("event_type") or "unknown"),
                    }
                    for item in evidence.decisions
                    if isinstance(item, Mapping)
                ],
                "calls": calls,
                "protocol_graph": [
                    {
                        **_safe_code_mode_protocol(item),
                        "fact_hash": stable_hash("CODE_MODE_PROTOCOL", dict(item)),
                    }
                    for item in evidence.protocol_graph
                    if isinstance(item, Mapping)
                ],
                "obligations": dict(evidence.obligations),
                "called_agents": sorted(evidence.called_agents),
                "selected_agents": sorted(evidence.selected_agents),
                "filtered_agents": {key: sorted(set(value)) for key, value in sorted(evidence.filtered_agents.items())},
                "expected_terminal": evidence.expected_terminal,
                "actual_terminal": evidence.actual_terminal,
                "user_response_agent_id": evidence.user_response_agent_id,
                "user_response_output_hash": evidence.user_response_output_hash,
                "checkpoint_restarts": [
                    {"fact_hash": stable_hash("CODE_MODE_CHECKPOINT_RESTART", dict(item))}
                    for item in evidence.checkpoint_restarts
                    if isinstance(item, Mapping)
                ],
                "execution_result": _safe_code_mode_execution_result(evidence.execution_result),
                "readonly_workspace_evidence": (
                    dict(evidence.readonly_workspace_evidence)
                    if isinstance(evidence.readonly_workspace_evidence, Mapping)
                    else None
                ),
            },
            "provider_usage": {
                "call_count": executor.provider_call_total(),
                "physical_send_count": executor.physical_send_total(),
                **dict(executor.usage_totals()),
            },
            "side_effect_counts": dict(side_effect_counts),
            "candidate_locator": candidate_locator,
            "machine_check_locator": machine_locator,
            "evidence_package_locator": package_locator,
            "review_request_locator": request_locator,
            "generation": generation,
            "verifier_identity": verifier_identity,
            "authorization_ref": authorization_ref,
            "runtime_state_identity": getattr(getattr(context, "identity", None), "state_identity", None),
            "runtime_journal_id": getattr(getattr(context, "identity", None), "journal_id", None),
            "run_stream_frontier": self._run_stream_frontier(journal, run_stream),
            "source_event_hashes": [str(event.event_hash) for event in journal.iter_events(0) if event.stream_id == run_stream.stream_id],
        }
        core["content_hash"] = sha256_bytes(canonical_json_bytes(core))
        publication = cas.publish_plaintext(
            canonical_json_bytes(core), tenant_id="code-mode-evidence",
            purpose_class="code-mode-execution-evidence-core", media_type="application/json",
        )
        receipt = publication.receipt
        if not receipt.fresh_verified or not receipt.no_replace_published:
            raise DynamicCollaborationError("Code Mode execution evidence core CAS publication was not immutable")
        response_refs = [response_locator["reference_id"]] if response_locator else []
        _, refs = run_stream.append_code_mode_fact(
            "code-mode-execution-evidence-core",
            ({
                "schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
                "evidence_schema": "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
                "purpose_class": "code-mode-execution-evidence-core",
                "reference_id": receipt.object_ref.reference_id,
                "content_hash": core["content_hash"],
                "run_id": evidence.run_id,
                "session_id": controls.get("conversation_session_id"),
                "session_instance_id": controls.get("session_instance_id"),
                "run_attempt": controls.get("run_attempt"),
                "turn_index": controls.get("conversation_turn_index"),
                "generation": core.get("generation"),
                "verifier_identity": core.get("verifier_identity"),
                "authorization_ref": authorization_ref,
                "candidate_id": (code_receipt.get("candidate") or {}).get("candidate_id"),
                "tree_hash": (code_receipt.get("candidate") or {}).get("tree_hash"),
                "closing_root": False,
                "_object_refs": [receipt.object_ref.reference_id, *response_refs],
            },), actor="code-mode-execution-core",
            proofs=tuple(item for item in (receipt, response_proof) if item is not None),
        )
        if len(refs) != 1:
            raise DynamicCollaborationError("Code Mode execution evidence core fact was not unique")
        return {
            "schema": "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
            "reference_id": receipt.object_ref.reference_id,
            "object_hash": receipt.object_ref.object_id,
            "plaintext_commitment": receipt.object_ref.plaintext_commitment,
            "content_hash": core["content_hash"],
            "receipt_hash": core["content_hash"],
            "run_id": evidence.run_id,
            "journal_event_hash": refs[0]["event_hash"],
            "fresh_verified": True,
            "no_replace_published": True,
        }

    @staticmethod
    def _execution_facts_from_core(
        core: Mapping[str, Any], *, user_response: str | None = None
    ) -> CodeModeExecutionFacts:
        """Build only the typed terminal facts present in the immutable core."""
        raw = core.get("run_evidence")
        if not isinstance(raw, Mapping):
            raise DynamicCollaborationError("Code Mode execution evidence core has no run evidence")
        calls = raw.get("calls")
        if not isinstance(calls, list) or not calls:
            raise DynamicCollaborationError("Code Mode execution evidence core is sparse")

        class _RecoveredCall:
            def __init__(self, value: Mapping[str, Any]) -> None:
                self.__dict__.update(dict(value))
                self.value = dict(value.get("value") or {})
                self.retry_count = int(value.get("retry_count") or 0)
                self.fallback_count = int(value.get("fallback_count") or 0)

            def evidence(self) -> dict[str, Any]:
                return dict(self.__dict__)

        execution_result = raw.get("execution_result")
        if not isinstance(execution_result, Mapping):
            raise DynamicCollaborationError("Code Mode execution evidence core has no execution result")
        return CodeModeExecutionFacts(
            run_id=str(core.get("run_id") or ""),
            goal_hash=str(core.get("goal_hash") or ""),
            policy_hash=str(core.get("policy_hash") or ""),
            decisions=[dict(item) for item in raw.get("decisions", []) if isinstance(item, Mapping)],
            calls=[_RecoveredCall(item) for item in calls if isinstance(item, Mapping)],
            protocol_graph=[dict(item) for item in raw.get("protocol_graph", []) if isinstance(item, Mapping)],
            obligations={str(key): bool(value) for key, value in (raw.get("obligations") or {}).items()},
            called_agents=set(str(item) for item in raw.get("called_agents", [])),
            selected_agents=set(str(item) for item in raw.get("selected_agents", [])),
            filtered_agents={str(key): [str(item) for item in value] for key, value in (raw.get("filtered_agents") or {}).items() if isinstance(value, list)},
            expected_terminal=str(raw.get("expected_terminal") or "SUCCEEDED"),
            actual_terminal=raw.get("actual_terminal"),
            notes=[str(item) for item in raw.get("notes", [])],
            checkpoint_restarts=[dict(item) for item in raw.get("checkpoint_restarts", []) if isinstance(item, Mapping)],
            user_response=user_response,
            user_response_agent_id=(str(raw.get("user_response_agent_id")) if raw.get("user_response_agent_id") else None),
            user_response_output_hash=(str(raw.get("user_response_output_hash")) if raw.get("user_response_output_hash") else None),
            execution_result=dict(execution_result),
            readonly_workspace_evidence=(
                dict(raw.get("readonly_workspace_evidence"))
                if isinstance(raw.get("readonly_workspace_evidence"), Mapping)
                else None
            ),
        )

    def _checkpoint_code_mode_review(
        self,
        *,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        run: RunAggregate,
        runtime_context: Any,
        controls: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist a review checkpoint without completing the run or turn.

        Code Mode execution success is provisional until the durable Review V2
        request is accepted.  This method deliberately does not call
        ``begin_closing``, ``terminal`` or ``run_stream.seal``.  The controller
        retains the pending execution in memory for the immediate CLI handoff,
        while the package/request locators provide the durable recovery anchor.
        """
        side_effect_counter = getattr(runtime_context, "side_effect_counts", None)
        if not callable(side_effect_counter):
            raise DynamicCollaborationError("Code Mode review checkpoint has no side-effect observer")
        try:
            side_effect_counts = dict(side_effect_counter(run_id=evidence.run_id, journal=journal))
        except TypeError:
            side_effect_counts = dict(side_effect_counter(run_id=evidence.run_id))
        code_receipt = self._seal_code_mode_receipt(
            context=runtime_context,
            journal=journal,
            cas=cas,
            run_stream=run_stream,
            executor=executor,
            evidence=evidence,
            authorization=controls["code_mode_authorization"],
            canary_authorization=controls.get("canary_authorization")
            if isinstance(controls.get("canary_authorization"), Mapping) else None,
            side_effect_counts=side_effect_counts,
            controls=controls,
            finalize_stream=False,
        )
        # Preserve the complete execution object before reducing the live
        # handoff to locators.  Recovery must never manufacture a sparse
        # RunEvidence and then publish authoritative terminal evidence from
        # it.  The core is deliberately immutable and references the already
        # sealed execution objects rather than copying their mutable bodies.
        execution_core = self._seal_code_mode_execution_core(
            context=runtime_context,
            journal=journal,
            cas=cas,
            run_stream=run_stream,
            executor=executor,
            evidence=evidence,
            code_receipt=code_receipt,
            side_effect_counts=side_effect_counts,
            controls=controls,
        )
        checkpoint = {
            "schema": "CODE_MODE_REVIEW_PENDING_CHECKPOINT_V1",
            "event_type": "run.review-pending",
            "run_id": evidence.run_id,
            "session_id": controls.get("conversation_session_id"),
            "package_ref": code_receipt["evidence_package"]["reference_id"],
            "request_ref": code_receipt["review_request"]["reference_id"],
            "machine_check_ref": code_receipt["machine_check_receipt"]["reference_id"],
            "execution_receipt_ref": code_receipt["reference_id"],
            "review_status": "REVIEW_PENDING",
            "terminal_state": "REVIEW_PENDING",
            "conversation_completion_blocked": True,
            # The checkpoint is the durable recovery anchor.  Keep only
            # locators and binding hashes here; the live executor/evidence
            # objects below are an optimization for the current process.
            "candidate_locator": code_receipt.get("candidate_locator"),
            "machine_check_locator": code_receipt.get("machine_check_receipt"),
            "package_locator": code_receipt.get("evidence_package"),
            "request_locator": code_receipt.get("review_request"),
            "execution_core_locator": execution_core,
            "execution_core_ref": execution_core.get("reference_id"),
            "execution_core_hash": execution_core.get("content_hash"),
            "generation": code_receipt.get("evidence_package", {}).get("generation"),
            "verifier_identity": code_receipt.get("evidence_package", {}).get("verifier_identity"),
            "runtime_state_identity": getattr(getattr(runtime_context, "identity", None), "state_identity", None),
            "runtime_journal_id": getattr(getattr(runtime_context, "identity", None), "journal_id", None),
            "conversation_turn_index": controls.get("conversation_turn_index"),
            "conversation_message_hash": sha256_bytes(
                str(controls.get("conversation_user_message") or "").encode("utf-8")
            ),
            "response_locator": execution_core.get("response_locator"),
            "user_response_hash": sha256_bytes(str(evidence.user_response or "").encode("utf-8")),
            # This is a lifecycle binding, not an authorization source.  It
            # lets a restarted finalizer distinguish a managed execution
            # whose run-scoped root must still be present from a direct
            # execution that has nothing to clean.
            "managed_worktree_for_review": bool(
                controls.get("_code_mode_managed_worktree_for_review")
            ),
            "worktree_isolation_kind": controls.get("_code_mode_worktree_isolation_kind"),
            "execution_root": (evidence.execution_result or {}).get("workspace")
            if isinstance(evidence.execution_result, Mapping) else None,
        }
        _checkpoint_receipt, checkpoint_refs = run_stream.append(
            "code-mode-review-pending",
            (checkpoint,),
            actor="code-mode-review-controller",
        )
        self._pending_code_mode_runs[evidence.run_id] = {
            "run": run,
            "evidence": evidence,
            "executor": executor,
            "runtime_context": runtime_context,
            "controls": dict(controls),
            "code_receipt": dict(code_receipt),
            "execution_core_locator": dict(execution_core),
            # Keep the immutable payload projection separate from the Journal
            # append locator.  The locator identifies the authoritative event;
            # it is never used as a substitute for the checkpoint body.
            "checkpoint_payload": dict(checkpoint),
            "checkpoint_locator": {
                "run_id": evidence.run_id,
                "event_id": checkpoint_refs[-1]["event_id"],
                "event_hash": checkpoint_refs[-1]["event_hash"],
            },
            "managed_worktree_for_review": bool(
                checkpoint.get("managed_worktree_for_review")
            ),
        }
        result = {
            "run_id": evidence.run_id,
            "terminal_state": "REVIEW_PENDING",
            "code_mode_status": "CODE_MODE_REVIEW_PENDING",
            "review_status": "REVIEW_PENDING",
            "review_reason_type": "HEADLESS_REVIEW_PENDING",
            "conversation_completion_blocked": True,
            "conversation_message": controls.get("conversation_user_message"),
            "conversation_session_id": controls.get("conversation_session_id"),
            "conversation_turn_index": controls.get("conversation_turn_index"),
            "provider_call_count": executor.provider_call_total(),
            "provider_physical_send_count": executor.physical_send_total(),
            "provider_token_total": executor.usage_total,
            "provider_input_tokens": executor.usage_totals()["input_tokens"],
            "provider_output_tokens": executor.usage_totals()["output_tokens"],
            "provider_retry_count": executor.usage_totals()["retry_count"],
            "provider_fallback_count": executor.usage_totals()["fallback_count"],
            "external_mutation_count": int((evidence.execution_result or {}).get("external_mutation_count", 0) or 0),
            "review_checkpoint_event_id": checkpoint_refs[-1]["event_id"],
            "review_checkpoint_event_hash": checkpoint_refs[-1]["event_hash"],
        }
        for key in (
            "machine_check_receipt", "test_receipt", "test_inventory", "candidate",
            "candidate_locator", "baseline_authorization_identity", "evidence_package", "review_request",
            "headless_review_pending", "review_status",
        ):
            if key in code_receipt:
                result[key] = code_receipt[key]
        result["code_mode_run_receipt"] = dict(code_receipt)
        # These are read-only projections of the durable checkpoint.  They
        # are sufficient for the current CLI process to pass the managed
        # Tester root to the Gate, but are never an authority source: the
        # finalizer reopens the checkpoint and Journal independently.
        result["managed_worktree_for_review"] = bool(
            checkpoint.get("managed_worktree_for_review") is True
        )
        result["execution_root"] = checkpoint.get("execution_root")
        return result

    def _reopen_code_mode_checkpoint(
        self, context: Any, *, run_id: str, pending: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Reopen the current pending checkpoint body from its exact Journal event."""
        locator = pending.get("checkpoint_locator")
        if not isinstance(locator, Mapping):
            raise DynamicCollaborationError("Code Mode checkpoint locator is missing")
        if (
            locator.get("run_id") != run_id
            or not isinstance(locator.get("event_id"), str)
            or not isinstance(locator.get("event_hash"), str)
        ):
            raise DynamicCollaborationError("Code Mode checkpoint locator is invalid")
        journal = context.open_runtime_state_reader()
        try:
            matches = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and getattr(event, "event_id", None) == locator.get("event_id")
                and getattr(event, "event_hash", None) == locator.get("event_hash")
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_REVIEW_PENDING_CHECKPOINT_V1"
                and event.payload.get("run_id") == run_id
            ]
        finally:
            journal.close()
        if len(matches) != 1:
            raise DynamicCollaborationError("Code Mode checkpoint event could not be reopened")
        payload = dict(matches[0].payload)
        cached = pending.get("checkpoint_payload")
        if isinstance(cached, Mapping) and any(
            payload.get(field) != value for field, value in cached.items()
        ):
            raise DynamicCollaborationError("Code Mode checkpoint payload changed in memory")
        return payload

    def _reopen_code_mode_conversation_binding(
        self,
        context: Any,
        *,
        checkpoint: Mapping[str, Any],
        pending: Mapping[str, Any],
        conversation_message: str | None,
        conversation_session_id: str | None,
        conversation_turn_index: int | None,
    ) -> tuple[str, int, str]:
        """Reopen the immutable user message for both live and recovery paths.

        A caller may repeat the conversation arguments for a live retry, but
        those arguments are never the authority.  The checkpoint supplies the
        session/turn/hash and the current session Journal plus encrypted CAS
        supplies the message bytes.  Recovery therefore works without the
        caller retaining the original prompt, while a foreign message cannot
        be paired with a valid reviewed run.
        """
        expected_session = checkpoint.get("session_id")
        expected_turn = checkpoint.get("conversation_turn_index")
        expected_hash = checkpoint.get("conversation_message_hash")
        if (
            not isinstance(expected_session, str) or not expected_session
            or type(expected_turn) is not int
            or not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            raise DynamicCollaborationError("Code Mode checkpoint has no complete conversation binding")
        supplied = any(value is not None for value in (conversation_message, conversation_session_id, conversation_turn_index))
        if supplied and (
            conversation_session_id != expected_session
            or conversation_turn_index != expected_turn
            or not isinstance(conversation_message, str)
            or not conversation_message.strip()
            or sha256_bytes(conversation_message.encode("utf-8")) != expected_hash
        ):
            raise DynamicCollaborationError("Code Mode conversation message binding changed")

        journal = context.open_runtime_state_reader()
        try:
            messages = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"session/{expected_session}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "session.message-appended"
                and event.payload.get("role") == "user"
                and event.payload.get("session_id") == expected_session
                and type(event.payload.get("turn_index")) is int
                and event.payload.get("turn_index") == expected_turn
            ]
        finally:
            journal.close()
        if len(messages) != 1:
            raise DynamicCollaborationError("Code Mode persisted conversation message is missing or duplicated")
        message_event = messages[0]
        if message_event.payload.get("body_hash") != expected_hash:
            raise DynamicCollaborationError("Code Mode persisted conversation message hash changed")
        body_ref = message_event.payload.get("body_ref")
        if not isinstance(body_ref, str) or not body_ref.startswith("cas:"):
            raise DynamicCollaborationError("Code Mode persisted conversation message locator is invalid")
        try:
            reader = context.open_cas_reader()
            body = reader.open_verified(reader.resolve_reference(body_ref)).decode("utf-8")
        except Exception as error:
            raise DynamicCollaborationError("Code Mode persisted conversation message could not be reopened") from error
        if not body.strip() or sha256_bytes(body.encode("utf-8")) != expected_hash:
            raise DynamicCollaborationError("Code Mode persisted conversation message content changed")
        live_message = pending.get("controls", {}).get("conversation_user_message")
        if isinstance(live_message, str) and live_message.strip() and live_message != body:
            raise DynamicCollaborationError("Code Mode live conversation message disagrees with persisted content")
        return expected_session, expected_turn, body

    @staticmethod
    def _reopen_code_mode_cas_locator(context: Any, locator: Mapping[str, Any], *, schema: str) -> dict[str, Any]:
        """Reopen one controller-issued Code Mode object, never a caller body."""
        if not isinstance(locator, Mapping):
            raise DynamicCollaborationError("Code Mode durable locator is missing")
        reference_id = locator.get("reference_id")
        expected_hash = str(locator.get("content_hash") or "")
        if not isinstance(reference_id, str) or not reference_id.startswith("cas:"):
            raise DynamicCollaborationError("Code Mode durable locator reference is invalid")
        expected_hash = expected_hash.removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise DynamicCollaborationError("Code Mode durable locator hash is invalid")
        cas = context.open_cas_reader()
        try:
            object_ref = cas.resolve_reference(reference_id)
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise DynamicCollaborationError("Code Mode durable locator is not fresh and no-replace")
            body = parse_canonical_json(cas.open_verified(object_ref))
        except DynamicCollaborationError:
            raise
        except Exception as error:
            raise DynamicCollaborationError("Code Mode durable object could not be reopened") from error
        if not isinstance(body, Mapping) or body.get("schema") != schema:
            raise DynamicCollaborationError("Code Mode durable object schema is invalid")
        body_without_hash = {key: value for key, value in body.items() if key != "content_hash"}
        actual_hash = hashlib.sha256(canonical_json_bytes(body_without_hash)).hexdigest()
        body_hash = str(body.get("content_hash") or "").removeprefix("sha256:")
        # Patch V2 manifests predate the generic receipt wrapper and carry
        # their immutable identity as the CAS publication hash rather than a
        # duplicated content_hash field.
        patch_identity_ok = schema == "SITINA_EXECUTION_PATCH_MANIFEST_V2" and actual_hash == expected_hash
        draft_identity_ok = schema == "CODE_MODE_STAGE_DRAFT_V1" and not body_hash and actual_hash == expected_hash
        if actual_hash != expected_hash or (body_hash != expected_hash and not patch_identity_ok and not draft_identity_ok):
            raise DynamicCollaborationError("Code Mode durable object content identity changed")
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["object_hash"] = object_ref.object_id
        reopened["payload_hash"] = expected_hash
        reopened["content_hash"] = body.get("content_hash")
        return reopened

    def _recover_pending_code_mode_run(self, run_id: str) -> dict[str, Any]:
        """Rebuild pending state from the current run stream after a restart."""
        factory = getattr(self, "runtime_context_factory", None)
        if not callable(factory):
            raise DynamicCollaborationError("Code Mode pending run has no independent runtime context factory")
        context = factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            stream_id = f"run/{run_id}"
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == stream_id)
            checkpoint_events = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_REVIEW_PENDING_CHECKPOINT_V1"
                and event.payload.get("run_id") == run_id
            ]
            if len(checkpoint_events) != 1:
                raise DynamicCollaborationError("Code Mode pending checkpoint is missing or duplicated")
            checkpoint_event = checkpoint_events[0]
            checkpoint = dict(checkpoint_event.payload)
            abandonment_events = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_REVIEW_ABANDONED_V1"
                and event.payload.get("event_type") == "code-mode.review-abandoned"
                and event.payload.get("run_id") == run_id
            ]
            if len(abandonment_events) > 1:
                raise DynamicCollaborationError("Code Mode review abandonment is duplicated")
            if abandonment_events:
                raise DynamicCollaborationError("Code Mode review was durably abandoned")
            checkpoint_locator = {
                "run_id": run_id,
                "event_id": checkpoint_event.event_id,
                "event_hash": checkpoint_event.event_hash,
            }
            terminal_events = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and _code_mode_terminal_state(event.payload) is not None
            ]
            if any(
                _code_mode_terminal_state(event.payload) not in {None, "SUCCEEDED"}
                for event in terminal_events
            ):
                raise DynamicCollaborationError("Code Mode pending run has a failed or contradictory terminal")
            if len(terminal_events) > 1:
                raise DynamicCollaborationError("Code Mode pending run has multiple terminal events")
            accepted_fact_for_recovery = next(
                (
                    event.payload for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("event_type") == "run.review-accepted"
                    and event.payload.get("run_id") == run_id
                ),
                None,
            )
            accepted_at_for_recovery = (
                accepted_fact_for_recovery.get("accepted_at")
                if isinstance(accepted_fact_for_recovery, Mapping) else None
            )
            # Context reopen helpers acquire the same fixed-inode Journal
            # writer lock.  Release the recovery reader/writer before calling
            # them; the immutable event tuple above is the only input needed
            # from this scan.
            journal.close()
            package_locator = checkpoint.get("package_locator")
            package = self._reopen_code_mode_cas_locator(
                context, package_locator, schema="CODE_MODE_EVIDENCE_PACKAGE_V1"
            )
            candidate_locator = checkpoint.get("candidate_locator")
            if not isinstance(candidate_locator, Mapping):
                raise DynamicCollaborationError("Code Mode checkpoint lacks the typed candidate locator")
            candidate = context.reopen_candidate_manifest(candidate_locator, run_id=run_id)
            request_locator = checkpoint.get("request_locator")
            request = context._reopen_offline_review_request(
                candidate=candidate,
                request=request_locator,
                accepted_at=accepted_at_for_recovery
                if isinstance(accepted_at_for_recovery, int) else None,
            )
            core_locator = checkpoint.get("execution_core_locator")
            core = self._reopen_code_mode_cas_locator(
                context, core_locator, schema="CODE_MODE_EXECUTION_EVIDENCE_CORE_V1"
            )
            machine_locator = core.get("machine_check_locator")
            if not isinstance(machine_locator, Mapping):
                raise DynamicCollaborationError("Code Mode execution core lacks the typed machine locator")
            expected_machine_locator = {
                **dict(machine_locator),
                "reference_id": request.get("machine_check_ref"),
                "object_hash": str(request.get("machine_check_ref") or "").removeprefix("cas:"),
            }
            if (
                core.get("run_id") != run_id
                or core.get("session_id") != checkpoint.get("session_id")
                or core.get("generation") != request.get("generation")
                or core.get("verifier_identity") != request.get("verifier_identity")
                or not _code_mode_locators_equal(core.get("candidate_locator") or {}, candidate_locator, "candidate")
                or not _code_mode_locators_equal(
                    core.get("machine_check_locator") or {},
                    expected_machine_locator,
                    "machine-check",
                )
                or not _code_mode_locators_equal(core.get("evidence_package_locator") or {}, package_locator, "evidence-package")
                or not _code_mode_locators_equal(core.get("review_request_locator") or {}, request, "review-request")
            ):
                raise DynamicCollaborationError("Code Mode execution evidence core binding changed")
            if not isinstance(core.get("run_evidence"), Mapping) or not core["run_evidence"].get("calls"):
                raise DynamicCollaborationError("Code Mode execution evidence core is sparse")
            completion_plan = None
            plan_fact_events = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_COMPLETION_PLAN_FACT_V1"
                and event.payload.get("run_id") == run_id
            ]
            if len(plan_fact_events) > 1:
                raise DynamicCollaborationError("Code Mode completion plan is duplicated")
            if plan_fact_events:
                plan_fact_event = plan_fact_events[0]
                plan_fact = plan_fact_event.payload
                plan_locator = {
                    "reference_id": plan_fact.get("reference_id"),
                    "content_hash": plan_fact.get("content_hash"),
                    "receipt_hash": plan_fact.get("content_hash"),
                    "run_id": run_id,
                }
                plan_body = self._reopen_code_mode_cas_locator(
                    context, plan_locator, schema="CODE_MODE_COMPLETION_PLAN_V1"
                )
                if (
                    plan_body.get("run_id") != run_id
                    or plan_body.get("stream_id") != f"run/{run_id}"
                    or plan_body.get("generation") != request.get("generation")
                    or not isinstance(plan_body.get("operations"), list)
                    or len(plan_body["operations"]) != 3
                ):
                    raise DynamicCollaborationError("Code Mode completion plan binding changed")
                completion_plan = {
                    "schema": "CODE_MODE_COMPLETION_PLAN_LOCATOR_V1",
                    **plan_locator,
                    "generation": plan_body.get("generation"),
                    "journal_event_hash": plan_fact_event.event_hash,
                    "logical_operations": list(plan_body["operations"]),
                }
            accepted_facts = [
                event.payload for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("event_type") == "run.review-accepted"
                and event.payload.get("run_id") == run_id
            ]
            if len(accepted_facts) > 1 or (terminal_events and len(accepted_facts) != 1):
                raise DynamicCollaborationError(
                    "Code Mode successful terminal has no unique accepted reviewer fact"
                )
            accepted_review_locator = None
            accepted_review_body = None
            if accepted_facts:
                accepted = accepted_facts[0]
                review_receipt_facts = [
                    event for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                    and event.payload.get("evidence_schema") == "CODE_MODE_REVIEW_RECEIPT_V2"
                    and event.payload.get("reference_id") == accepted.get("review_receipt_ref")
                    and event.payload.get("content_hash") == accepted.get("review_receipt_hash")
                ]
                if len(review_receipt_facts) != 1:
                    raise DynamicCollaborationError(
                        "Code Mode accepted reviewer receipt has no unique current-run Journal fact"
                    )
                accepted_review_locator = {
                    "reference_id": accepted.get("review_receipt_ref"),
                    "content_hash": accepted.get("review_receipt_hash"),
                    "receipt_hash": accepted.get("review_receipt_hash"),
                    "run_id": run_id,
                    "journal_event_hash": review_receipt_facts[0].event_hash,
                }
                # Journal producer facts intentionally carry only the typed
                # locator and payload hash.  Recovery must enrich that
                # projection from the formal CAS resolver, rather than
                # weakening the CAS object-identity check or guessing the
                # object id from the reference string.
                try:
                    recovery_cas = context.open_cas_reader()
                    recovery_object = recovery_cas.resolve_reference(
                        str(accepted_review_locator["reference_id"])
                    )
                    accepted_review_locator["object_hash"] = recovery_object.object_id
                    accepted_review_locator["plaintext_commitment"] = recovery_object.plaintext_commitment
                except Exception as error:
                    raise DynamicCollaborationError(
                        "Code Mode accepted reviewer receipt CAS identity could not be reopened"
                    ) from error
                if (
                    accepted.get("request_ref") != request.get("reference_id")
                    or accepted.get("package_ref") != package_locator.get("reference_id")
                    or accepted.get("request_hash") != request.get("content_hash")
                ):
                    raise DynamicCollaborationError("Code Mode accepted reviewer fact is not bound to the pending request")
            if terminal_events:
                terminal_payload = terminal_events[0].payload
                terminal_evidence = self._reopen_code_mode_cas_locator(
                    context,
                    {
                        "reference_id": terminal_payload.get("evidence_package_ref"),
                        "content_hash": terminal_payload.get("evidence_package_hash"),
                    },
                    schema="CODE_MODE_TERMINAL_EVIDENCE_V1",
                )
                binding = terminal_evidence.get("code_mode_terminal_binding")
                if not isinstance(binding, Mapping):
                    raise DynamicCollaborationError("Code Mode terminal evidence has no complete binding")
                expected_binding = {
                    "run_id": run_id,
                    "session_id": checkpoint.get("session_id"),
                    "candidate_id": candidate.get("candidate_id"),
                    "tree_hash": candidate.get("tree_hash"),
                    "source_manifest_hash": candidate.get("source_manifest_hash"),
                    "worktree_digest": candidate.get("worktree_digest"),
                    "machine_check_ref": request.get("machine_check_ref"),
                    "machine_check_hash": request.get("machine_check_hash"),
                    "evidence_package_ref": package_locator.get("reference_id"),
                    "evidence_package_hash": package_locator.get("content_hash"),
                    "review_request_ref": request.get("reference_id"),
                    "review_request_hash": request.get("content_hash"),
                    "tty_review_receipt_ref": accepted_review_locator.get("reference_id") if isinstance(accepted_review_locator, Mapping) else None,
                    "tty_review_receipt_hash": accepted_review_locator.get("content_hash") if isinstance(accepted_review_locator, Mapping) else None,
                    "generation": request.get("generation"),
                    "verifier_identity": request.get("verifier_identity"),
                    "execution_core_ref": core_locator.get("reference_id") if isinstance(core_locator, Mapping) else None,
                    "execution_core_hash": core_locator.get("content_hash") if isinstance(core_locator, Mapping) else None,
                    "gate_status": "CODE_MODE_READY",
                    "gate_identity": "code-mode-acceptance-v1",
                    "user_response_hash": checkpoint.get("user_response_hash"),
                }
                for field, expected in expected_binding.items():
                    if binding.get(field) != expected:
                        raise DynamicCollaborationError("Code Mode terminal evidence binding changed: " + field)
                terminal_projection = terminal_evidence.get("code_mode_terminal_projection")
                if (
                    not isinstance(terminal_projection, Mapping)
                    or terminal_projection.get("schema") != "CODE_MODE_TERMINAL_PROJECTION_V1"
                    or terminal_projection.get("run_id") != run_id
                    or terminal_projection.get("execution_core_ref") != core_locator.get("reference_id")
                    or terminal_projection.get("execution_core_hash") != core_locator.get("content_hash")
                    or terminal_projection.get("candidate_id") != candidate.get("candidate_id")
                    or terminal_projection.get("tree_hash") != candidate.get("tree_hash")
                    or terminal_projection.get("generation") != request.get("generation")
                    or terminal_projection.get("verifier_identity") != request.get("verifier_identity")
                ):
                    raise DynamicCollaborationError(
                        "Code Mode terminal projection is missing or not bound to the current core"
                    )
                final_roots = [
                    event for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
                ]
                if len(final_roots) > 1:
                    raise DynamicCollaborationError("Code Mode final root is duplicated")
                if final_roots:
                    root_payload = final_roots[0].payload
                    final_locator = {
                        "reference_id": root_payload.get("final_receipt_ref"),
                        "content_hash": root_payload.get("final_receipt_hash"),
                        "receipt_hash": root_payload.get("final_receipt_hash"),
                        "run_id": run_id,
                    }
                    try:
                        context.verify_code_mode_reviewed_state(
                            final_locator, run_id=run_id, stage="ROOTED"
                        )
                    except Exception as error:
                        raise DynamicCollaborationError(
                            "Code Mode existing final root failed the unified state verifier"
                        ) from error
            machine_locator = dict(core.get("machine_check_locator") or {})
            machine_locator.update({
                "reference_id": request.get("machine_check_ref"),
                "content_hash": request.get("machine_check_hash"),
                "receipt_hash": request.get("machine_check_hash"),
                "run_id": run_id,
            })
            machine = self._reopen_code_mode_cas_locator(
                context, machine_locator, schema="CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
            )
            if any(
                package.get(field) != machine.get(field)
                for field in ("run_id", "session_id", "generation", "verifier_identity", "candidate_id", "tree_hash")
            ):
                raise DynamicCollaborationError("Code Mode pending package/machine identity diverged")
            if accepted_review_locator is not None:
                from sitina.orchestrator.code_mode_gate import _reopen_offline_receipt
                try:
                    accepted_review_body = _reopen_offline_receipt(
                        context,
                        accepted_review_locator,
                        schema="CODE_MODE_REVIEW_RECEIPT_V2",
                        candidate=candidate,
                        accepted_at=accepted_at_for_recovery
                        if isinstance(accepted_at_for_recovery, int) else None,
                    )
                except Exception as error:
                    raise DynamicCollaborationError(
                        "Code Mode accepted reviewer receipt could not be reopened"
                    ) from error
                for field, expected in (
                    ("run_id", run_id),
                    ("session_id", checkpoint.get("session_id")),
                    ("candidate_id", candidate.get("candidate_id")),
                    ("tree_hash", candidate.get("tree_hash")),
                    ("generation", request.get("generation")),
                    ("verifier_identity", request.get("verifier_identity")),
                    ("evidence_package_hash", request.get("evidence_package_hash")),
                    ("review_request_ref", request.get("reference_id")),
                    ("review_request_hash", request.get("content_hash")),
                    ("decision", "ACCEPT"),
                ):
                    if accepted_review_body.get(field) != expected:
                        raise DynamicCollaborationError(
                            "Code Mode accepted reviewer binding changed: " + field
                        )
            run_created = next(
                (event.payload for event in events
                 if isinstance(event.payload, Mapping) and event.payload.get("event_type") == "run.created"),
                None,
            )
            if not isinstance(run_created, Mapping):
                raise DynamicCollaborationError("Code Mode pending run has no run.created binding")
            persisted_controls = run_created.get("acceptance_controls")
            if not isinstance(persisted_controls, Mapping):
                raise DynamicCollaborationError("Code Mode pending authorization is not durable")
            code_auth = persisted_controls.get("code_mode_authorization")
            if not isinstance(code_auth, Mapping):
                raise DynamicCollaborationError("Code Mode pending authorization is missing")
            if code_auth.get("session_id") != checkpoint.get("session_id") or code_auth.get("workspace") != package.get("baseline_authorization_identity", {}).get("workspace"):
                raise DynamicCollaborationError("Code Mode pending authorization binding changed")
            # A recovered executor is intentionally only a counter/publisher
            # facade.  No provider is called during review recovery; all
            # authoritative facts come from the reopened package/Journal.
            from types import SimpleNamespace
            class _RecoveredExecutor:
                rejected_calls: list[dict[str, Any]] = []
                recovery_attempts: list[dict[str, Any]] = []
                def __init__(self, outer: "TrueMultiAgentProductionRuntime") -> None:
                    self.outer = outer
                    usage = core.get("provider_usage")
                    if not isinstance(usage, Mapping):
                        raise DynamicCollaborationError(
                            "Code Mode execution core has no authenticated provider usage"
                        )
                    # The terminal draft is rebuilt from the immutable core.
                    # The review package is an upstream fact and may carry a
                    # different summary (for example after a retry).  Using it
                    # here made recovery manufacture provider counts that did
                    # not match the reopened terminal evidence package.
                    self._usage = dict(usage)
                    self.usage_total = int(self._usage.get("total_tokens") or 0)
                    self.cost_total_micro_usd = int(self._usage.get("cost_micro_usd") or 0)
                def provider_call_total(self) -> int:
                    return int(self._usage.get("call_count") or 0)
                def physical_send_total(self) -> int:
                    return int(self._usage.get("physical_send_count") or 0)
                def usage_totals(self) -> dict[str, int]:
                    return {
                        "input_tokens": int(self._usage.get("input_tokens") or 0),
                        "output_tokens": int(self._usage.get("output_tokens") or 0),
                        "cache_read_tokens": int(self._usage.get("cache_read_tokens") or 0),
                        "cache_write_tokens": int(self._usage.get("cache_write_tokens") or 0),
                        "total_tokens": int(self._usage.get("total_tokens") or 0),
                        "cost_micro_usd": int(self._usage.get("cost_micro_usd") or 0),
                        "retry_count": int(self._usage.get("retry_count") or 0),
                        "fallback_count": int(self._usage.get("fallback_count") or 0),
                        "unsettled_usage_count": int(self._usage.get("unsettled_usage_count") or 0),
                    }
                def actual_provider_profile(self) -> Any:
                    return SimpleNamespace(
                        name=str(package.get("provider_profile") or "offline"),
                        model=str(package.get("provider_model") or "offline"),
                    )
                def _publish(self, value: Mapping[str, Any], *, purpose: str) -> Any:
                    return context.open_cas().publish_plaintext(
                        canonical_json_bytes(dict(value)), tenant_id="code-mode-evidence",
                        purpose_class=purpose, media_type="application/json",
                    ).receipt
            patch_ref = (package.get("execution_receipt_refs") or {}).get("patch_manifest")
            patch = self._reopen_code_mode_cas_locator(
                context, {"reference_id": patch_ref, "content_hash": package.get("diff_hash")},
                schema="SITINA_EXECUTION_PATCH_MANIFEST_V2",
            ) if isinstance(patch_ref, str) and patch_ref.startswith("cas:") else {}
            changed_paths = [
                str(entry.get("path")) for entry in (patch.get("entries") or ())
                if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
            ]
            response_locator = core.get("response_locator")
            if not isinstance(response_locator, Mapping):
                raise DynamicCollaborationError("Code Mode execution core has no encrypted response locator")
            try:
                response_cas = context.open_cas_reader()
                response_object = response_cas.resolve_reference(
                    str(response_locator.get("reference_id"))
                )
                response = response_cas.open_verified(response_object).decode("utf-8")
            except Exception as error:
                raise DynamicCollaborationError("Code Mode response CAS could not be reopened") from error
            if sha256_bytes(response.encode("utf-8")) != core.get("response_hash"):
                raise DynamicCollaborationError("Code Mode response content identity changed")
            evidence = self._execution_facts_from_core(core, user_response=response)
            if core.get("response_hash") != (
                sha256_bytes(str(evidence.user_response or "").encode("utf-8"))
                if evidence.user_response else None
            ):
                raise DynamicCollaborationError("Code Mode execution core response binding changed")
            run, _opened = RunAggregate.open(run_id)
            controls = {
                "code_mode_authorization": dict(code_auth),
                "conversation_session_id": checkpoint.get("session_id"),
                "conversation_turn_index": checkpoint.get("conversation_turn_index"),
                "execution_workspace": code_auth.get("workspace"),
                "code_mode_candidate": dict(candidate),
                "baseline_authorization_identity": dict(package.get("baseline_authorization_identity") or {}),
                "conversation_user_message_hash": checkpoint.get("conversation_message_hash"),
                "code_mode_execution_core": dict(core),
                "_code_mode_managed_worktree_for_review": bool(
                    checkpoint.get("managed_worktree_for_review")
                ),
                "_code_mode_worktree_isolation_kind": checkpoint.get("worktree_isolation_kind"),
            }
            if completion_plan is not None:
                controls["code_mode_completion_plan"] = dict(completion_plan)
            code_receipt = {
                "reference_id": checkpoint.get("execution_receipt_ref"),
                "candidate": candidate,
                "candidate_locator": candidate_locator,
                "machine_check_receipt": machine_locator,
                "evidence_package": {"reference_id": package_locator.get("reference_id"), "content_hash": package_locator.get("content_hash"), **package},
                "review_request": request,
                "review_status": "REVIEW_PENDING",
                "execution_core_locator": dict(core_locator),
                "completion_plan": dict(completion_plan) if completion_plan is not None else None,
            }
            return {
                "run": run, "evidence": evidence, "executor": _RecoveredExecutor(self),
                "runtime_context": context, "controls": controls, "code_receipt": code_receipt,
                "checkpoint_payload": checkpoint,
                "checkpoint_locator": checkpoint_locator,
                "recovered": True,
                "accepted_review_locator": accepted_review_locator,
                "execution_core_locator": dict(core_locator),
                "managed_worktree_for_review": bool(
                    checkpoint.get("managed_worktree_for_review")
                ),
            }
        finally:
            journal.close()

    def _code_mode_run_has_internal_gate_fact(self, context: Any, run_id: str) -> bool:
        """Return whether this run reached the durable internal Gate fact.

        A managed root that disappeared before this fact is not recoverable:
        there is no authenticated Gate to replay.  Conversely, a crash after
        this fact (including after cleanup) remains the existing bounded
        finalization-retry path.
        """
        reader = None
        try:
            reader = context.open_runtime_state_reader()
            return any(
                str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "code-mode.internal-gate-accepted"
                and event.payload.get("run_id") == run_id
                for event in reader.iter_events(0)
            )
        except Exception:
            # If the durable frontier cannot prove a Gate fact, do not leave a
            # deleted managed root looking retryable.
            return False
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass

    def _abandon_code_mode_review(
        self,
        *,
        run_id: str,
        pending: Mapping[str, Any],
        context: Any,
        reason_code: str,
    ) -> None:
        """Close an unrecoverable managed review after its root is gone.

        This is deliberately distinct from terminalization: no successful
        terminal or final-root fact is minted after a pre-Gate observation
        failure.  A durable abandonment fact fences restart recovery, while
        the process-local pending entry and controller session (including its
        namespace lock) are released exactly once.
        """
        run_id = str(run_id)
        journal = None
        try:
            journal = context.open_runtime_writer()
            events = tuple(
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
            )
            existing = [
                event for event in events
                if isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_REVIEW_ABANDONED_V1"
                and event.payload.get("event_type") == "code-mode.review-abandoned"
                and event.payload.get("run_id") == run_id
            ]
            if len(existing) > 1:
                raise DynamicCollaborationError("Code Mode review abandonment is duplicated")
            if not existing:
                cleanup_events = [
                    event for event in events
                    if isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("event_type") == "execution.worktree.cleanup.finally"
                ]
                cleanup = cleanup_events[0].payload if len(cleanup_events) == 1 else {}
                cleanup_event = cleanup_events[0] if len(cleanup_events) == 1 else None
                stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.policy_hash)
                stream.append(
                    "code-mode-review-abandoned",
                    ({
                        "schema": "CODE_MODE_REVIEW_ABANDONED_V1",
                        "event_type": "code-mode.review-abandoned",
                        "run_id": run_id,
                        "terminal_state": "FAILED",
                        "recoverable": False,
                        "reason_code": str(reason_code),
                        "cleanup_event_id": (
                            cleanup_event.event_id if cleanup_event is not None else None
                        ),
                        "cleanup_event_hash": (
                            cleanup_event.event_hash if cleanup_event is not None else None
                        ),
                        "cleanup_status": cleanup.get("status"),
                        "cleanup_removed": cleanup.get("removed"),
                    },),
                    actor="code-mode-review-controller",
                )
        except Exception:
            # Abandonment is a fail-closed fence.  Even if a best-effort
            # Journal marker cannot be appended, never retain a process-local
            # pending run or its controller lock after its root is gone.
            pass
        finally:
            if journal is not None:
                try:
                    journal.close()
                except Exception:
                    pass
            self._pending_code_mode_runs.pop(run_id, None)
            controllers: list[Any] = []
            active = getattr(self, "_active_code_mode_controller", None)
            if active is not None and getattr(active, "run_id", None) == run_id:
                controllers.append(active)
            context_controller = getattr(context, "_active_controller_session", None)
            if (
                context_controller is not None
                and getattr(context_controller, "run_id", None) == run_id
                and all(context_controller is not item for item in controllers)
            ):
                controllers.append(context_controller)
            for controller in controllers:
                try:
                    controller.close()
                except Exception:
                    pass
                if getattr(self, "_active_code_mode_controller", None) is controller:
                    self._active_code_mode_controller = None
                if getattr(context, "_active_controller_session", None) is controller:
                    try:
                        setattr(context, "_active_controller_session", None)
                    except Exception:
                        pass

    def _publish_code_mode_completion_plan(
        self,
        *,
        context: Any,
        cas: Any,
        run_stream: CanonicalStream,
        run_id: str,
        candidate: Mapping[str, Any],
        package: Mapping[str, Any],
        request: Mapping[str, Any],
        core: Mapping[str, Any],
        review_receipt: Mapping[str, Any],
        gate: Mapping[str, Any],
        accepted_at: int,
        terminal_stage_draft: Mapping[str, Any] | None = None,
        root_stage_draft: Mapping[str, Any] | None = None,
        conversation_stage_draft: Mapping[str, Any] | None = None,
        conversation_stream_id: str | None = None,
        conversation_stream_start_version: int | None = None,
    ) -> dict[str, Any]:
        """Publish the signed, non-self-referential completion plan."""
        start = int(run_stream.version)
        generation = str(package.get("generation") or request.get("generation") or "")
        if not generation or not isinstance(core.get("content_hash"), str):
            raise DynamicCollaborationError("Code Mode completion plan bindings are incomplete")
        broker_identity = dict(getattr(getattr(context, "_broker_client", None), "identity", {}))
        issuer_key_id = broker_identity.get("authority_key_id")
        if not isinstance(issuer_key_id, str) or not issuer_key_id:
            raise DynamicCollaborationError("Code Mode completion plan requires the host issuer")
        def durable_locator(value: Mapping[str, Any], role: str) -> dict[str, str]:
            locator = _code_mode_locator(value, role)
            return {"reference_id": locator["reference_id"], "object_hash": locator["object_hash"]}

        stage_drafts = {
            "terminal": terminal_stage_draft,
            "root": root_stage_draft,
            "conversation": conversation_stage_draft,
        }
        stage_draft_locators: dict[str, str] = {}
        stage_draft_payloads: dict[str, Mapping[str, Any]] = {}
        purpose_by_stage = {
            "terminal": "code-mode-stage-draft-terminal",
            "root": "code-mode-stage-draft-root",
            "conversation": "code-mode-stage-draft-conversation",
        }
        for stage, draft in stage_drafts.items():
            if not isinstance(draft, Mapping):
                raise DynamicCollaborationError(
                    f"Code Mode completion plan requires the pre-acceptance {stage} stage draft"
                )
            projection = draft.get("event_projection")
            proofs = draft.get("proofs")
            if not isinstance(projection, list) or not projection or not isinstance(proofs, tuple):
                raise DynamicCollaborationError(f"Code Mode {stage} stage draft is incomplete")
            draft_body = {
                "schema": "CODE_MODE_STAGE_DRAFT_V1",
                "stage": stage,
                "run_id": run_id,
                "generation": generation,
                "session_instance_id": request.get("session_instance_id"),
                "session_id": request.get("session_id"),
                "turn_index": request.get("turn_index"),
                "run_attempt": request.get("run_attempt"),
                "event_projection": list(projection),
                "event_projection_hash": sha256_bytes(
                    b"SITINA-CODE-MODE-ACTUAL-STAGE-V1\0" + canonical_json_bytes(list(projection))
                ),
                "proof_manifest": list(stable_stage_proof_manifest(proofs)),
                "proof_manifest_hash": stable_stage_proof_manifest_hash(proofs),
            }
            draft_publication = cas.publish_plaintext(
                canonical_json_bytes(draft_body), tenant_id="code-mode-evidence",
                purpose_class=purpose_by_stage[stage], media_type="application/json",
            )
            stage_draft_locators[stage] = draft_publication.receipt.object_ref.reference_id
            stage_draft_payloads[stage] = draft_body

        provider_profile = package.get("provider_profile")
        provider_model = package.get("provider_model")
        if (
            type(provider_profile) is not str or not provider_profile
            or type(provider_model) is not str or not provider_model
        ):
            raise DynamicCollaborationError(
                "Code Mode completion plan lacks the authenticated provider profile"
            )

        # Gate is a controller-owned fact.  Publish it before asking the
        # authority host so the host receives a real durable locator rather
        # than a caller-synthesized ``cas:<hash>`` placeholder.
        gate_body = code_mode_gate_projection(
            run_id=run_id, generation=generation,
            candidate_id=str(candidate.get("candidate_id") or ""),
            tree_hash=str(candidate.get("tree_hash") or ""),
            session_id=str(request.get("session_id") or ""),
            session_instance_id=str(request.get("session_instance_id") or ""),
            run_attempt=request.get("run_attempt"),
            turn_index=request.get("turn_index"),
            package_hash=str(package.get("content_hash") or ""),
            core_hash=str(core.get("content_hash") or ""),
            provider_profile=provider_profile,
            provider_model=provider_model,
            authorization_ref=str(package.get("authorization_ref") or ""),
        )
        gate_publication = cas.publish_plaintext(
            canonical_json_bytes(gate_body), tenant_id="code-mode-evidence",
            purpose_class="code-mode-gate-fact", media_type="application/json",
        )
        gate_locator = {"reference_id": gate_publication.receipt.object_ref.reference_id,
                        "object_hash": gate_publication.receipt.object_ref.object_id}

        # The host receives addresses only.  It derives all scalar identity
        # and operation commitments from the bound state root; version and
        # parent are carried as a typed frontier locator rather than caller
        # supplied operation fields.
        locator_request = {
            "schema": "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2",
            "run_locator": run_stream.stream_id,
            "conversation_locator": conversation_stream_id or "",
            "request_locator": durable_locator(request, "review-request")["reference_id"],
            "candidate_locator": durable_locator(
                {
                    "reference_id": package.get("candidate_manifest_ref"),
                    "object_hash": str(package.get("candidate_manifest_ref") or "").removeprefix("cas:"),
                },
                "candidate",
            )["reference_id"],
            "package_locator": durable_locator(package, "evidence-package")["reference_id"],
            "core_locator": durable_locator(core, "execution-core")["reference_id"],
            "review_locator": durable_locator(review_receipt, "review-receipt")["reference_id"],
            "gate_locator": gate_locator["reference_id"],
            "terminal_stage_draft_locator": stage_draft_locators["terminal"],
            "root_stage_draft_locator": stage_draft_locators["root"],
            "conversation_stage_draft_locator": stage_draft_locators["conversation"],
        }
        plan_inputs = locator_request
        requester = getattr(context, "request_completion_plan", None)
        if not callable(requester):
            raise DynamicCollaborationError("Code Mode completion-plan authority host is unavailable")
        try:
            body = dict(requester(plan_inputs))
        except Exception as error:
            raise DynamicCollaborationError(
                "Code Mode authority host refused the completion plan: " + str(error)
            ) from error
        if not isinstance(body.get("issuer_key_id"), str) or not isinstance(body.get("authority_signature_hex"), str):
            raise DynamicCollaborationError("Code Mode authority host returned an unsigned completion plan")
        operations = body.get("operations")
        if not isinstance(operations, list) or len(operations) != 3:
            raise DynamicCollaborationError("Code Mode authority host returned an incomplete completion plan")
        body["content_hash"] = sha256_bytes(canonical_json_bytes(body))
        publication = cas.publish_plaintext(
            canonical_json_bytes(body), tenant_id="code-mode-evidence",
            purpose_class="code-mode-completion-plan", media_type="application/json",
        )
        receipt = publication.receipt
        if not receipt.fresh_verified or not receipt.no_replace_published:
            raise DynamicCollaborationError("Code Mode completion plan publication was not immutable")
        _receipt, refs = run_stream.append_completion_plan_fact(
            {
                "schema": "CODE_MODE_COMPLETION_PLAN_FACT_V1",
                "event_type": "code-mode.completion-plan",
                "run_id": run_id,
                "reference_id": receipt.object_ref.reference_id,
                "content_hash": body["content_hash"],
                "logical_operation_hashes": [item["logical_operation_hash"] for item in operations],
                "generation": generation,
                "_object_refs": [receipt.object_ref.reference_id],
            },
            actor="code-mode-authority-host", proofs=(receipt,),
        )
        if len(refs) != 1:
            raise DynamicCollaborationError("Code Mode completion plan fact was not unique")
        return {
            "schema": "CODE_MODE_COMPLETION_PLAN_LOCATOR_V1",
            "reference_id": receipt.object_ref.reference_id,
            "content_hash": body["content_hash"],
            "receipt_hash": body["content_hash"],
            "run_id": run_id,
            "generation": generation,
            "journal_event_hash": refs[0]["event_hash"],
            "gate_locator": gate_locator["reference_id"],
            "logical_operations": operations,
        }

    def finalize_code_mode_review(
        self,
        *,
        run_id: str,
        review_receipt: Mapping[str, Any],
        gate_result: Mapping[str, Any],
        conversation_message: str | None = None,
        conversation_session_id: str | None = None,
        conversation_turn_index: int | None = None,
    ) -> dict[str, Any]:
        """Finalize a pending review under one run-scoped cleanup guard."""
        pending = self._pending_code_mode_runs.get(str(run_id))
        if not isinstance(pending, Mapping):
            pending = self._recover_pending_code_mode_run(str(run_id))
            self._pending_code_mode_runs[str(run_id)] = pending
        pending_controls = pending.get("controls")
        pending_evidence = pending.get("evidence")
        managed = bool(
            pending.get("managed_worktree_for_review")
            or (
                isinstance(pending_controls, Mapping)
                and pending_controls.get("_code_mode_managed_worktree_for_review") is True
            )
            or (
                isinstance(pending_evidence, (RunEvidence, CodeModeExecutionFacts))
                and isinstance(pending_evidence.execution_result, Mapping)
                and pending_evidence.execution_result.get("workspace_mode") == "managed_worktree"
            )
            or (
                isinstance(pending.get("checkpoint_payload"), Mapping)
                and pending["checkpoint_payload"].get("managed_worktree_for_review") is True
            )
        )
        finalization_error: BaseException | None = None
        try:
            return self._finalize_code_mode_review_impl(
                run_id=run_id,
                review_receipt=review_receipt,
                gate_result=gate_result,
                conversation_message=conversation_message,
                conversation_session_id=conversation_session_id,
                conversation_turn_index=conversation_turn_index,
            )
        except BaseException as error:
            finalization_error = error
            raise
        finally:
            # The implementation performs cleanup immediately after the
            # machine/internal Gate and marks it complete.  This outer guard
            # covers every earlier validation failure (checkpoint reopen,
            # reviewer receipt, conversation binding, or Gate) as well.
            context = pending.get("runtime_context")
            expected_worktree = (
                self.home / "artifacts" / "worktrees" / str(run_id)
            ).expanduser().resolve(strict=False)
            if managed and context is not None:
                # The implementation's success path removes the root before
                # returning.  If it still exists, this is an early failure
                # and the same authoritative helper must clean it.  Keep the
                # abandonment decision below in a nested finally so a
                # cleanup exception cannot strand the controller lock.
                try:
                    if expected_worktree.is_dir() and not expected_worktree.is_symlink():
                        self._cleanup_pending_code_mode_worktree(
                            run_id=str(run_id), pending=pending, context=context,
                            managed_worktree_for_review=True,
                        )
                finally:
                    if (
                        finalization_error is not None
                        and not expected_worktree.exists()
                        and not expected_worktree.is_symlink()
                        and not self._code_mode_run_has_internal_gate_fact(
                            context, str(run_id)
                        )
                    ):
                        self._abandon_code_mode_review(
                            run_id=str(run_id), pending=pending, context=context,
                            reason_code="MANAGED_REVIEW_ROOT_CLEANED_BEFORE_GATE",
                        )

    def _finalize_code_mode_review_impl(
        self,
        *,
        run_id: str,
        review_receipt: Mapping[str, Any],
        gate_result: Mapping[str, Any],
        conversation_message: str | None = None,
        conversation_session_id: str | None = None,
        conversation_turn_index: int | None = None,
    ) -> dict[str, Any]:
        """Reopen a pending run and commit its sole successful terminal state."""
        pending = self._pending_code_mode_runs.get(str(run_id))
        if not isinstance(pending, Mapping):
            pending = self._recover_pending_code_mode_run(str(run_id))
            self._pending_code_mode_runs[str(run_id)] = pending
        context = pending.get("runtime_context")
        if context is None:
            raise DynamicCollaborationError("Code Mode pending run has no runtime context")
        # ``journal`` is opened only after the TTY/internal Gate has been
        # revalidated.  Early finalization failures still use the helper's
        # short-lived writer so a managed root cannot be stranded.
        journal: Any | None = None
        cleanup_completed = False
        cleanup_report: Mapping[str, Any] | None = None
        pending_controls = pending.get("controls")
        pending_evidence = pending.get("evidence")
        managed_worktree_for_review = bool(
            pending.get("managed_worktree_for_review")
            or (
                isinstance(pending_controls, Mapping)
                and pending_controls.get("_code_mode_managed_worktree_for_review") is True
            )
            or (
                isinstance(pending_evidence, (RunEvidence, CodeModeExecutionFacts))
                and isinstance(pending_evidence.execution_result, Mapping)
                and pending_evidence.execution_result.get("workspace_mode") == "managed_worktree"
            )
            or (
                isinstance(pending.get("checkpoint_payload"), Mapping)
                and pending["checkpoint_payload"].get("managed_worktree_for_review") is True
            )
        )

        expected_worktree = (
            self.home / "artifacts" / "worktrees" / str(run_id)
        ).expanduser().resolve(strict=False)

        def lifecycle_events() -> tuple[Any, ...]:
            """Read this run's immutable lifecycle facts without a writer."""
            reader = context.open_runtime_state_reader()
            try:
                return tuple(
                    event for event in reader.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                )
            finally:
                reader.close()

        cleanup_fact_payload: Mapping[str, Any] | None = None
        cleanup_fact_binding: Mapping[str, Any] | None = None
        cleanup_fact_completed = False
        gate_fact_payload: Mapping[str, Any] | None = None
        managed_gate_workspace: Path | None = None
        if managed_worktree_for_review:
            prior_events = lifecycle_events()
            cleanup_facts = [
                event for event in prior_events
                if isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "execution.worktree.cleanup.finally"
            ]
            if len(cleanup_facts) > 1:
                raise DynamicCollaborationError("Code Mode managed cleanup fact is duplicated")
            if cleanup_facts:
                cleanup_fact_event = cleanup_facts[0]
                cleanup_fact_payload = cleanup_fact_event.payload
                cleanup_fact_binding = {
                    **dict(cleanup_fact_payload),
                    "event_id": cleanup_fact_event.event_id,
                    "event_hash": cleanup_fact_event.event_hash,
                }
                if cleanup_fact_payload.get("run_id") != str(run_id):
                    raise DynamicCollaborationError("Code Mode managed cleanup fact has the wrong run")
                fact_worktree = Path(str(cleanup_fact_payload.get("worktree") or "")).expanduser().resolve(strict=False)
                fact_status = str(cleanup_fact_payload.get("status") or "")
                if fact_worktree != expected_worktree:
                    raise DynamicCollaborationError("Code Mode managed cleanup fact is bound to another root")
                if fact_status == "failed":
                    raise DynamicCollaborationError("Code Mode managed cleanup fact reports failure")
                if (
                    fact_status not in {"ok", "not_present"}
                    or cleanup_fact_payload.get("removed") is not True
                    or cleanup_fact_payload.get("audit_recorded") is not True
                    or (fact_status == "ok" and cleanup_fact_payload.get("physical_removed") is not True)
                ):
                    raise DynamicCollaborationError("Code Mode managed cleanup fact is incomplete")
                if not expected_worktree.exists() and not expected_worktree.is_symlink():
                    cleanup_fact_completed = True
                else:
                    # A successful immutable removal fact and a live root are
                    # contradictory.  Do not mint a second cleanup fact or
                    # silently reinterpret the durable observation.
                    raise DynamicCollaborationError("Code Mode cleanup fact contradicts a live managed root")
            gate_facts = [
                event.payload for event in prior_events
                if isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "code-mode.internal-gate-accepted"
            ]
            if len(gate_facts) > 1:
                raise DynamicCollaborationError("Code Mode internal Gate fact is duplicated")
            if gate_facts:
                gate_fact_payload = gate_facts[0]
        if cleanup_fact_completed:
            cleanup_completed = True
            cleanup_report = dict(cleanup_fact_payload or {})

        def cleanup_pending_worktree() -> Mapping[str, Any] | None:
            """Remove the exact managed root once, after evidence validation."""
            nonlocal cleanup_completed, cleanup_report, cleanup_fact_binding
            if cleanup_completed or not managed_worktree_for_review:
                return cleanup_report
            report = self._cleanup_pending_code_mode_worktree(
                run_id=str(run_id), pending=pending, context=context,
                managed_worktree_for_review=managed_worktree_for_review,
                journal=journal,
            )
            cleanup_report = report
            cleanup_completed = True
            if journal is not None:
                current_events = [
                    event for event in journal.iter_events(0)
                    if event.stream_id == f"run/{run_id}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("event_type") == "execution.worktree.cleanup.finally"
                ]
                if len(current_events) != 1:
                    raise DynamicCollaborationError("Code Mode managed cleanup fact was not unique")
                cleanup_event = current_events[0]
                cleanup_fact_binding = {
                    **dict(cleanup_event.payload),
                    "event_id": cleanup_event.event_id,
                    "event_hash": cleanup_event.event_hash,
                }
            return report

        if (
            not isinstance(review_receipt, Mapping)
            or not isinstance(gate_result, Mapping)
            or gate_result.get("status") != "CODE_MODE_READY"
        ):
            # Even a malformed/declined finalization request is a terminal
            # failure for the pending execution; clean its managed root
            # before returning the rejection to the CLI.
            cleanup_pending_worktree()
            raise DynamicCollaborationError("Code Mode review was not accepted")
        checkpoint = self._reopen_code_mode_checkpoint(
            context, run_id=str(run_id), pending=pending
        )
        managed_worktree_for_review = bool(
            managed_worktree_for_review or checkpoint.get("managed_worktree_for_review") is True
        )
        response_hash = checkpoint.get("user_response_hash")
        empty_response_hash = sha256_bytes(b"")
        if not isinstance(response_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", response_hash) or response_hash == empty_response_hash:
            raise DynamicCollaborationError("Code Mode review checkpoint has no non-empty response")
        conversation_binding = self._reopen_code_mode_conversation_binding(
            context,
            checkpoint=checkpoint,
            pending=pending,
            conversation_message=conversation_message,
            conversation_session_id=conversation_session_id,
            conversation_turn_index=conversation_turn_index,
        )
        # The conversation layer carries only an immutable locator.  Reopen
        # the signed V2 body from the controller's CAS/Journal before any
        # terminal or conversation-success event is appended.
        from sitina.orchestrator.code_mode_gate import _reopen_offline_receipt
        candidate_locator = pending["code_receipt"].get("candidate_locator")
        if not isinstance(candidate_locator, Mapping):
            raise DynamicCollaborationError("Code Mode pending candidate locator is missing")
        try:
            reopened_candidate = context.reopen_candidate_manifest(
                dict(candidate_locator), run_id=str(run_id)
            )
        except Exception as error:
            raise DynamicCollaborationError("Code Mode pending candidate could not be reopened") from error
        pending_candidate_projection = pending["code_receipt"].get("candidate")
        if (
            isinstance(pending_candidate_projection, Mapping)
            and any(
                reopened_candidate.get(field) != pending_candidate_projection.get(field)
                for field in ("candidate_id", "tree_hash", "worktree_digest", "source_manifest_hash")
            )
        ):
            raise DynamicCollaborationError("Code Mode pending candidate projection drifted")
        pending["code_receipt"]["candidate"] = dict(reopened_candidate)
        accepted_at_hint: int | None = None
        accepted_reader = context.open_runtime_state_reader()
        try:
            accepted_events = [
                event for event in accepted_reader.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "run.review-accepted"
            ]
            if len(accepted_events) > 1:
                raise DynamicCollaborationError("Code Mode accepted reviewer fact is duplicated")
            if accepted_events:
                accepted_at_hint = accepted_events[0].payload.get("accepted_at")
        finally:
            accepted_reader.close()
        try:
            review_body = _reopen_offline_receipt(
                context,
                review_receipt,
                schema="CODE_MODE_REVIEW_RECEIPT_V2",
                candidate=pending["code_receipt"]["candidate"],
                accepted_at=accepted_at_hint if isinstance(accepted_at_hint, int) else None,
            )
        except Exception as error:
            raise DynamicCollaborationError(
                "Code Mode review receipt could not be reopened"
            ) from error
        if review_body.get("decision") != "ACCEPT":
            raise DynamicCollaborationError("Code Mode review was not accepted")
        accepted_review_locator = pending.get("accepted_review_locator")
        if isinstance(accepted_review_locator, Mapping) and (
            review_receipt.get("reference_id") != accepted_review_locator.get("reference_id")
            or review_receipt.get("content_hash") != accepted_review_locator.get("content_hash")
        ):
            raise DynamicCollaborationError("Code Mode review receipt is not the accepted reviewer fact")
        pending_candidate = pending["code_receipt"]["candidate"]
        pending_package = pending["code_receipt"]["evidence_package"]
        pending_request = pending["code_receipt"]["review_request"]
        # Locators intentionally contain only refs and hashes.  Reopen the
        # controller-created request before comparing the final TTY receipt;
        # never compare against a caller/result projection that omits the
        # generation and execution identities.
        try:
            reopened_request = context._reopen_offline_review_request(
                candidate=pending_candidate,
                request=pending_request,
            )
        except Exception as error:
            raise DynamicCollaborationError(
                "Code Mode pending Review V2 request could not be reopened"
            ) from error
        core_locator = pending.get("execution_core_locator") or checkpoint.get("execution_core_locator")
        execution_core = self._reopen_code_mode_cas_locator(
            context, core_locator, schema="CODE_MODE_EXECUTION_EVIDENCE_CORE_V1"
        )
        if (
            execution_core.get("run_id") != str(run_id)
            or execution_core.get("session_id") != pending["controls"].get("conversation_session_id")
            or execution_core.get("generation") != reopened_request.get("generation")
            or execution_core.get("verifier_identity") != reopened_request.get("verifier_identity")
        ):
            raise DynamicCollaborationError("Code Mode execution evidence core is not bound to the current request")
        core_candidate_locator = execution_core.get("candidate_locator")
        if not isinstance(core_candidate_locator, Mapping) or core_candidate_locator.get("reference_id") != candidate_locator.get("reference_id"):
            raise DynamicCollaborationError("Code Mode execution evidence core candidate binding changed")
        pending["execution_core_locator"] = dict(core_locator)
        pending["controls"]["code_mode_execution_core"] = dict(execution_core)
        # Never trust the conversation-layer Gate result.  Reopen the
        # controller-issued machine receipt and run the acceptance algorithm
        # again before appending any final-review or terminal fact.
        from sitina.orchestrator.code_mode_gate import CodeModeAcceptanceV1
        machine_locator = dict(execution_core.get("machine_check_locator") or {})
        machine_locator.update({
            "reference_id": reopened_request.get("machine_check_ref"),
            "content_hash": reopened_request.get("machine_check_hash"),
            "receipt_hash": reopened_request.get("machine_check_hash"),
            "run_id": str(run_id),
        })
        machine_body = self._reopen_code_mode_cas_locator(
            context, machine_locator, schema="CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
        )
        machine_journal = context.open_runtime_state_reader()
        try:
            machine_fact = next(
                (
                    event for event in machine_journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                    and event.payload.get("evidence_schema") == "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
                    and event.payload.get("reference_id") == machine_locator["reference_id"]
                    and event.payload.get("content_hash") == machine_locator["content_hash"]
                ),
                None,
            )
        finally:
            machine_journal.close()
        if machine_fact is None:
            raise DynamicCollaborationError("Code Mode machine receipt is not in the current run Journal")
        if managed_worktree_for_review and not cleanup_fact_completed:
            # Reopen the run-bound Tester locator from the machine receipt and
            # observe the live managed root immediately before Gate.  This is
            # deliberately independent of the caller's Gate projection.
            raw_tester_cwd = machine_body.get("cwd")
            if not isinstance(raw_tester_cwd, str) or not raw_tester_cwd.strip():
                raise DynamicCollaborationError("Code Mode Tester receipt has no durable workspace locator")
            checkpoint_root = checkpoint.get("execution_root")
            if not isinstance(checkpoint_root, str) or not checkpoint_root.strip():
                raise DynamicCollaborationError("Code Mode pending checkpoint has no execution-root locator")
            try:
                tester_cwd_path = Path(raw_tester_cwd).expanduser()
                checkpoint_root_path = Path(checkpoint_root).expanduser()
                if tester_cwd_path.is_symlink() or checkpoint_root_path.is_symlink():
                    raise ValueError("Code Mode Tester workspace locator is a symlink")
                tester_root = tester_cwd_path.resolve(strict=True)
                checkpoint_execution_root = checkpoint_root_path.resolve(strict=True)
                if (
                    not tester_root.is_dir()
                    or tester_root != checkpoint_execution_root
                    or tester_root != expected_worktree
                ):
                    raise ValueError("Code Mode Tester workspace locator is not the pending managed root")
                from sitina.orchestrator.code_mode_runtime import _workspace_observation_hash
                current_observation_hash = _workspace_observation_hash(tester_root)
                managed_gate_workspace = tester_root
            except Exception as error:
                raise DynamicCollaborationError(
                    "Code Mode Tester workspace observation is unavailable or out of date"
                ) from error
            sealed_observation_hash = str(machine_body.get("workspace_observation_after_hash") or "")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", sealed_observation_hash)
                or current_observation_hash != sealed_observation_hash
            ):
                raise DynamicCollaborationError("Code Mode Tester workspace observation drifted before Gate")

        if managed_worktree_for_review and cleanup_fact_completed:
            # A process crash can occur after the successful cleanup Journal
            # fact and before the terminal/root transaction.  The prior Gate
            # result is reopened from its own run-bound immutable fact so a
            # missing worktree is not mistaken for new evidence drift.
            if not isinstance(gate_fact_payload, Mapping):
                raise DynamicCollaborationError("Code Mode cleaned review has no durable internal Gate fact")
            persisted_gate = gate_fact_payload.get("gate_result")
            persisted_gate_hash = str(gate_fact_payload.get("gate_result_hash") or "")
            if (
                not isinstance(persisted_gate, Mapping)
                or not re.fullmatch(r"[0-9a-f]{64}", persisted_gate_hash)
                or hashlib.sha256(canonical_json_bytes(persisted_gate)).hexdigest() != persisted_gate_hash
                or gate_fact_payload.get("run_id") != str(run_id)
                or gate_fact_payload.get("machine_check_ref") != machine_locator.get("reference_id")
                or gate_fact_payload.get("machine_check_hash") != machine_locator.get("content_hash")
                or gate_fact_payload.get("candidate_id") != pending_candidate.get("candidate_id")
                or gate_fact_payload.get("tree_hash") != pending_candidate.get("tree_hash")
            ):
                raise DynamicCollaborationError("Code Mode persisted internal Gate fact is not bound")
            internal_gate = dict(persisted_gate)
        else:
            # Candidate-manifest verification must remain rooted in the
            # authenticated source workspace.  A managed execution's Tester
            # observation is separately bound to its run-scoped worktree via
            # ``execution_workspace``; passing that root as ``self.workspace``
            # would make the source candidate appear to drift (git metadata,
            # absolute workspace identity, and unborn snapshot HEAD differ).
            source_gate_workspace = Path(
                str(pending["controls"].get("execution_workspace") or self.source_root)
            ).expanduser().resolve(strict=True)
            execution_gate_workspace = (
                managed_gate_workspace
                if managed_worktree_for_review and managed_gate_workspace is not None
                else None
            )
            internal_gate = CodeModeAcceptanceV1(source_gate_workspace).evaluate_offline(
                candidate=dict(pending_candidate),
                runtime_context=context,
                test_receipt={
                    **machine_locator,
                    "content_hash": machine_body.get("content_hash"),
                    "journal_event_hash": machine_fact.event_hash,
                },
                reviewer_receipt=dict(review_receipt),
                test_inventory=machine_body.get("test_inventory"),
                execution_workspace=execution_gate_workspace,
            )
        if internal_gate.get("status") != "CODE_MODE_READY":
            raise DynamicCollaborationError("Code Mode controller Gate rejected the reopened evidence")
        # The conversation layer may carry a Gate projection for display, but
        # it cannot choose which fields the controller trusts.  Every field it
        # supplies must be a field of the freshly reopened internal result and
        # must compare exactly; unknown additions are rejected as well.
        for field, external_value in gate_result.items():
            if field not in internal_gate:
                raise DynamicCollaborationError("external Code Mode Gate result disagrees with controller Gate")
            if field in {"test_receipt", "reviewer_receipt"}:
                if not isinstance(external_value, Mapping) or not isinstance(internal_gate.get(field), Mapping):
                    raise DynamicCollaborationError("external Code Mode Gate receipt projection is invalid")
                for binding_field in (
                    "reference_id", "content_hash", "receipt_hash", "journal_event_hash",
                    "run_id", "candidate_id", "tree_hash", "generation",
                    "review_request_ref", "review_request_hash",
                ):
                    if binding_field in external_value and external_value.get(binding_field) != internal_gate[field].get(binding_field):
                        raise DynamicCollaborationError("external Code Mode Gate receipt binding disagrees")
            elif external_value != internal_gate.get(field):
                raise DynamicCollaborationError("external Code Mode Gate result disagrees with controller Gate")
        gate_result = dict(internal_gate)
        pending_request = reopened_request
        pending_package = {
            **dict(pending_package),
            "generation": reopened_request.get("generation"),
            "verifier_identity": reopened_request.get("verifier_identity"),
            "content_hash": reopened_request.get("evidence_package_hash"),
            "source_manifest_hash": reopened_request.get("source_manifest_hash"),
            "worktree_before_hash": reopened_request.get("worktree_before_hash"),
            "worktree_after_hash": reopened_request.get("worktree_after_hash"),
            "diff_hash": reopened_request.get("diff_hash"),
            "machine_check_ref": reopened_request.get("machine_check_ref"),
            "machine_check_hash": reopened_request.get("machine_check_hash"),
            "candidate_id": reopened_request.get("candidate_id"),
            "tree_hash": reopened_request.get("tree_hash"),
        }
        # Recovery projections may intentionally omit the candidate manifest
        # fields.  Reattach the already-verified locator from the pending
        # receipt; never derive it from the candidate's display mapping.
        pending_candidate_locator = pending["code_receipt"].get("candidate_locator")
        if isinstance(pending_candidate_locator, Mapping):
            pending_package["candidate_manifest_ref"] = pending_candidate_locator.get("reference_id")
            pending_package["candidate_manifest_hash"] = pending_candidate_locator.get("content_hash")
            if not isinstance(pending_candidate_locator.get("object_hash"), str):
                raise DynamicCollaborationError("Code Mode pending candidate locator lacks CAS object identity")
        for field, expected in (
            ("candidate_id", pending_candidate.get("candidate_id")),
            ("tree_hash", pending_candidate.get("tree_hash")),
            ("run_id", str(run_id)),
            ("session_id", pending["controls"].get("conversation_session_id")),
            ("generation", pending_package.get("generation")),
            ("verifier_identity", pending_package.get("verifier_identity")),
            ("evidence_package_hash", pending_package.get("content_hash")),
            ("review_request_hash", pending_request.get("content_hash")),
        ):
            if review_body.get(field) != expected:
                raise DynamicCollaborationError(
                    "Code Mode final review receipt binding mismatch: " + field
                )
        try:
            # Writer/CAS/stream setup, the durable Gate fact, cleanup and all
            # terminal/root operations share this one lifecycle guard.  Any
            # setup or append failure therefore closes the writer and lets the
            # outer guard perform only the remaining idempotent cleanup.
            journal = context.open_runtime_writer()
            cas = context.open_cas()
            run_stream = CanonicalStream(journal, str(run_id), f"run/{run_id}", self.policy_hash)
            if managed_worktree_for_review and gate_fact_payload is None:
                gate_fact_payload = {
                    "schema": "CODE_MODE_INTERNAL_GATE_ACCEPTED_V1",
                    "event_type": "code-mode.internal-gate-accepted",
                    "run_id": str(run_id),
                    "candidate_id": pending_candidate.get("candidate_id"),
                    "tree_hash": pending_candidate.get("tree_hash"),
                    "machine_check_ref": machine_locator.get("reference_id"),
                    "machine_check_hash": machine_locator.get("content_hash"),
                    "gate_result": dict(gate_result),
                    "gate_result_hash": hashlib.sha256(
                        canonical_json_bytes(gate_result)
                    ).hexdigest(),
                }
                _gate_receipt, gate_refs = run_stream.append(
                    "code-mode-internal-gate-accepted",
                    (gate_fact_payload,),
                    actor="code-mode-review-controller",
                )
                if len(gate_refs) != 1:
                    raise DynamicCollaborationError("Code Mode internal Gate fact was not unique")
            # The machine receipt and internal Gate have both been reopened
            # from durable facts above.  Only now remove a managed execution
            # root; every terminal/root operation below therefore observes a
            # completed cleanup, while the initial checkpoint saw the live
            # Tester cwd.
            cleanup_pending_worktree()
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == run_stream.stream_id)
            terminal_states = [
                _code_mode_terminal_state(event.payload)
                for event in events
                if isinstance(event.payload, Mapping)
                and _code_mode_terminal_state(event.payload) is not None
            ]
            if any(state != "SUCCEEDED" for state in terminal_states):
                raise DynamicCollaborationError("Code Mode reviewed terminal is failed or contradictory")
            existing_success = "SUCCEEDED" in terminal_states
            existing_roots = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
            ]
            final_reviewer_facts = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_FINAL_REVIEWER_FACT_V1"
            ]
            accepted_facts = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("event_type") == "run.review-accepted"
            ]
            if len(final_reviewer_facts) not in (0, 1) or len(accepted_facts) not in (0, 1):
                raise DynamicCollaborationError("Code Mode reviewer acceptance facts are duplicated")
            if bool(final_reviewer_facts) != bool(accepted_facts):
                raise DynamicCollaborationError("Code Mode reviewer acceptance transaction is partial")
            accepted_at: int | None = None
            if final_reviewer_facts:
                final_fact = final_reviewer_facts[0].payload
                accepted_fact = accepted_facts[0].payload
                acceptance_command_id = final_fact.get("causation_command_id")
                accepted_command_id = accepted_fact.get("causation_command_id")
                if (
                    not isinstance(acceptance_command_id, str)
                    or not acceptance_command_id
                    or accepted_command_id != acceptance_command_id
                    or final_reviewer_facts[0].position + 1 != accepted_facts[0].position
                    or getattr(journal, "_position_hash", {}).get(final_reviewer_facts[0].position)
                    != getattr(journal, "_position_hash", {}).get(accepted_facts[0].position)
                ):
                    raise DynamicCollaborationError("Code Mode reviewer acceptance facts are not one authenticated transaction")
                pair_values = {
                    "run_id": str(run_id),
                    "request_ref": pending_request.get("reference_id"),
                    "request_hash": pending_request.get("content_hash"),
                    "package_ref": pending_package.get("reference_id"),
                    "review_receipt_ref": review_receipt.get("reference_id"),
                    "review_receipt_hash": review_receipt.get("content_hash"),
                    "decision": "ACCEPT",
                    "gate_status": "CODE_MODE_READY",
                }
                for field, expected in pair_values.items():
                    if final_fact.get(field) != expected:
                        raise DynamicCollaborationError("Code Mode reviewer fact binding changed: " + field)
                for field in ("run_id", "request_ref", "package_ref", "review_receipt_ref", "review_receipt_hash", "gate_status"):
                    if accepted_fact.get(field) != pair_values[field]:
                        raise DynamicCollaborationError("Code Mode accepted fact binding changed: " + field)
                accepted_at = accepted_fact.get("accepted_at")
                if accepted_at != final_fact.get("accepted_at") or type(accepted_at) is not int or accepted_at <= 0:
                    raise DynamicCollaborationError("Code Mode accepted pair timestamp is invalid")
            if accepted_at is None:
                confirmed_at = review_body.get("confirmed_at")
                review_expires_at = review_body.get("expires_at")
                if type(confirmed_at) is not int or confirmed_at <= 0 or type(review_expires_at) is not int:
                    raise DynamicCollaborationError("Code Mode reviewer receipt has no authenticated acceptance time")
                if confirmed_at > review_expires_at or confirmed_at > int(time.time()) + 5:
                    raise DynamicCollaborationError("Code Mode reviewer acceptance is expired or from the future")
                accepted_at = confirmed_at
            plan_facts = [
                event for event in events
                if isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_COMPLETION_PLAN_FACT_V1"
            ]
            if len(plan_facts) > 1:
                raise DynamicCollaborationError("Code Mode completion plan is duplicated")
            if plan_facts:
                completion_plan = {
                    "schema": "CODE_MODE_COMPLETION_PLAN_LOCATOR_V1",
                    "reference_id": plan_facts[0].payload.get("reference_id"),
                    "content_hash": plan_facts[0].payload.get("content_hash"),
                    "receipt_hash": plan_facts[0].payload.get("content_hash"),
                    "run_id": str(run_id),
                    "generation": plan_facts[0].payload.get("generation"),
                    "journal_event_hash": plan_facts[0].event_hash,
                }
                recovered_plan = pending.get("completion_plan")
                if (
                    isinstance(recovered_plan, Mapping)
                    and recovered_plan.get("reference_id") == completion_plan["reference_id"]
                    and recovered_plan.get("content_hash") == completion_plan["content_hash"]
                    and isinstance(recovered_plan.get("logical_operations"), list)
                    and len(recovered_plan["logical_operations"]) == 3
                ):
                    completion_plan = dict(recovered_plan)
                else:
                    plan_body = self._reopen_code_mode_cas_locator(
                        context, completion_plan, schema="CODE_MODE_COMPLETION_PLAN_V1"
                    )
                    if (
                        plan_body.get("run_id") != str(run_id)
                        or plan_body.get("generation") != pending_package.get("generation")
                        or not isinstance(plan_body.get("operations"), list)
                        or len(plan_body["operations"]) != 3
                    ):
                        raise DynamicCollaborationError("Code Mode completion plan binding changed")
                    completion_plan["logical_operations"] = list(plan_body["operations"])
            else:
                draft_controls = dict(pending["controls"])
                draft_controls.update({
                    "code_mode_review_accepted": True,
                    "code_mode_tty_receipt": dict(review_receipt),
                    "code_mode_internal_gate": dict(gate_result),
                    "code_mode_evidence_package": dict(pending_package),
                    "code_mode_cleanup_fact": dict(cleanup_fact_binding or {})
                    if managed_worktree_for_review else None,
                    "code_mode_review_request": dict(pending_request),
                    "code_mode_candidate": dict(pending_candidate),
                    "code_mode_execution_core": dict(execution_core),
                })
                terminal_stage_draft = self._terminalize_code_mode(
                    journal, cas, run_stream, pending["executor"], pending["evidence"], pending["run"],
                    runtime_context=context, controls=draft_controls,
                    prepare_stage_draft=True,
                )
                # All semantic stage objects must exist before the signed
                # plan/acceptance.  The reviewed receipt deliberately uses a
                # logical terminal binding; physical event ids are assigned
                # only by Journal after acceptance and are checked through
                # the terminal stage mapping.
                terminal_projection_hash = sha256_bytes(
                    b"SITINA-CODE-MODE-ACTUAL-STAGE-V1\0"
                    + canonical_json_bytes(list(terminal_stage_draft["event_projection"]))
                )
                response_text = str(pending["evidence"].user_response or "").strip()
                if not response_text:
                    raise DynamicCollaborationError("Code Mode review has no user response to persist")
                response_message_hash = (
                    sha256_bytes(str(conversation_binding[2]).encode("utf-8"))
                    if conversation_binding is not None else None
                )
                draft_expiries = [
                    int(value) for value in (
                        pending_package.get("expires_at"), review_body.get("expires_at")
                    ) if type(value) is int and value > 0
                ]
                if not draft_expiries:
                    raise DynamicCollaborationError("Code Mode stage drafts have no expiry")
                final_receipt_draft_body = {
                    "schema": "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
                    "status": "SUCCEEDED",
                    "run_id": str(run_id),
                    "session_id": pending["controls"].get("conversation_session_id"),
                    "turn_index": pending["controls"].get("conversation_turn_index"),
                    "candidate_id": pending_candidate.get("candidate_id"),
                    "tree_hash": pending_candidate.get("tree_hash"),
                    "source_manifest_hash": pending_candidate.get("source_manifest_hash"),
                    "worktree_digest": pending_candidate.get("worktree_digest"),
                    "candidate_locator": pending["code_receipt"].get("candidate_locator"),
                    "machine_check_ref": machine_locator.get("reference_id"),
                    "machine_check_hash": machine_locator.get("content_hash"),
                    "evidence_package_ref": pending_package.get("reference_id"),
                    "evidence_package_hash": pending_package.get("content_hash"),
                    "review_request_ref": pending_request.get("reference_id"),
                    "review_request_hash": pending_request.get("content_hash"),
                    "tty_review_receipt_ref": review_receipt.get("reference_id"),
                    "tty_review_receipt_hash": review_receipt.get("content_hash"),
                    "gate_status": gate_result.get("status"),
                    "gate_identity": gate_result.get("gate_identity") or "code-mode-acceptance-v1",
                    "terminal_event_id": "logical:terminal",
                    "terminal_event_hash": terminal_projection_hash,
                    "generation": pending_package.get("generation"),
                    "verifier_identity": pending_package.get("verifier_identity"),
                    "reviewer_issuer_identity": review_body.get("issuer_identity"),
                    "reviewer_authority_class": review_body.get("authority_class"),
                    "execution_core_ref": (core_locator or {}).get("reference_id") if isinstance(core_locator, Mapping) else None,
                    "execution_core_hash": (core_locator or {}).get("content_hash") if isinstance(core_locator, Mapping) else None,
                    "cleanup_fact": dict(cleanup_fact_binding or {})
                    if managed_worktree_for_review else None,
                    "completion_plan_ref": None,
                    "completion_plan_hash": None,
                    "user_response_hash": response_hash,
                    "conversation_message_hash": response_message_hash,
                    "issued_at": int(accepted_at),
                    "expires_at": min(draft_expiries),
                }
                final_receipt_draft_body["content_hash"] = "sha256:" + sha256_bytes(
                    canonical_json_bytes(final_receipt_draft_body)
                )
                final_draft_publication = cas.publish_plaintext(
                    canonical_json_bytes(final_receipt_draft_body),
                    tenant_id="code-mode-evidence",
                    purpose_class="code-mode-reviewed-terminal-receipt",
                    media_type="application/json",
                )
                final_draft_receipt = final_draft_publication.receipt
                def make_semantic_stage_draft(
                    stage: str, fact: Mapping[str, Any], stream_id: str
                ) -> dict[str, Any]:
                    event = EventEnvelope(
                        f"{stage}-draft-event", str(fact.get("event_type") or ""),
                        "code-mode", stream_id, 0, 0, "1970-01-01T00:00:00Z",
                        {key: value for key, value in fact.items() if key != "_object_refs"},
                        tuple(sorted(set(str(item) for item in fact.get("_object_refs", ())))),
                    )
                    return {
                        "stage": stage,
                        "events": (dict(fact),),
                        "event_projection": stage_actual_event_projection((event,)),
                        "proofs": (final_draft_receipt,),
                    }
                root_stage_draft = make_semantic_stage_draft(
                    "root",
                    {
                        "schema": "CODE_MODE_FINAL_ROOT_V2",
                        "event_type": "code-mode.final-root",
                        "run_id": str(run_id),
                        "candidate_id": pending_candidate.get("candidate_id"),
                        "generation": pending_package.get("generation"),
                        "review_request_ref": pending_request.get("reference_id"),
                        "tty_review_receipt_ref": review_receipt.get("reference_id"),
                        "gate_status": gate_result.get("status"),
                        "authenticated_seal": True,
                        "finalization_transaction": True,
                    "final_receipt_ref": final_draft_receipt.object_ref.reference_id,
                    "final_receipt_hash": final_receipt_draft_body["content_hash"],
                    "terminal_event_id": "logical:terminal",
                    "terminal_event_hash": "logical:terminal",
                    "completion_plan_ref": "logical:completion-plan",
                    "completion_plan_hash": "logical:completion-plan",
                    "seal_command_id": "logical:final-root",
                        "_object_refs": [final_draft_receipt.object_ref.reference_id],
                    },
                    run_stream.stream_id,
                )
                conversation_stage_draft = make_semantic_stage_draft(
                    "conversation",
                    {
                        "schema": "CODE_MODE_CONVERSATION_COMPLETION_V1",
                        "event_type": "code-mode.conversation-completion",
                        "run_id": str(run_id),
                        "session_id": conversation_binding[0] if conversation_binding else None,
                        "turn_index": conversation_binding[1] if conversation_binding else None,
                        "assistant_message_id": (
                            f"{conversation_binding[0]}-assistant-{conversation_binding[1]}"
                            if conversation_binding else None
                        ),
                        "response_hash": response_hash,
                        "final_receipt_ref": final_draft_receipt.object_ref.reference_id,
                        "final_receipt_hash": final_receipt_draft_body["content_hash"],
                        "completion_plan_ref": "logical:completion-plan",
                        "completion_plan_hash": "logical:completion-plan",
                        "_object_refs": [final_draft_receipt.object_ref.reference_id],
                    },
                    f"session/{conversation_binding[0]}" if conversation_binding else run_stream.stream_id,
                )
                completion_plan = self._publish_code_mode_completion_plan(
                    context=context, cas=cas, run_stream=run_stream, run_id=str(run_id),
                    candidate=pending_candidate, package=pending_package, request=pending_request,
                    core=execution_core, review_receipt=review_receipt, gate=gate_result,
                    accepted_at=int(accepted_at),
                    terminal_stage_draft=terminal_stage_draft,
                    root_stage_draft=root_stage_draft,
                    conversation_stage_draft=conversation_stage_draft,
                    conversation_stream_id=(
                        "session/" + str(pending["controls"].get("conversation_session_id"))
                        if pending["controls"].get("conversation_session_id") else None
                    ),
                    conversation_stream_start_version=(
                        max(
                            (
                                event.stream_version for event in journal.iter_events(0)
                                if event.stream_id == "session/" + str(pending["controls"].get("conversation_session_id"))
                            ),
                            default=0,
                        )
                        if pending["controls"].get("conversation_session_id") else 0
                    ),
                )
            pending["completion_plan"] = dict(completion_plan)
            plan_ref = completion_plan.get("reference_id")
            plan_hash = completion_plan.get("content_hash")
            if existing_success and len(existing_roots) > 1:
                raise DynamicCollaborationError("Code Mode reviewed terminal root is duplicated")
            if existing_success:
                terminal_events = [
                    event for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("event_type") == "code-mode.terminal-success"
                    and event.payload.get("terminal_state") == "SUCCEEDED"
                ]
                if len(terminal_events) != 1:
                    raise DynamicCollaborationError("Code Mode reviewed terminal is not unique")
                terminal_payload = terminal_events[0].payload
                terminal_evidence = self._reopen_code_mode_cas_locator(
                    context,
                    {
                        "reference_id": terminal_payload.get("evidence_package_ref"),
                        "content_hash": terminal_payload.get("evidence_package_hash"),
                    },
                    schema="CODE_MODE_TERMINAL_EVIDENCE_V1",
                )
                binding = terminal_evidence.get("code_mode_terminal_binding")
                expected_binding = {
                    "run_id": str(run_id),
                    "session_id": pending["controls"].get("conversation_session_id"),
                    "candidate_id": pending_candidate.get("candidate_id"),
                    "tree_hash": pending_candidate.get("tree_hash"),
                    "evidence_package_ref": pending_package.get("reference_id"),
                    "evidence_package_hash": pending_package.get("content_hash"),
                    "review_request_ref": pending_request.get("reference_id"),
                    "review_request_hash": pending_request.get("content_hash"),
                    "tty_review_receipt_ref": review_receipt.get("reference_id"),
                    "tty_review_receipt_hash": review_receipt.get("content_hash"),
                    "generation": pending_package.get("generation"),
                    "verifier_identity": pending_package.get("verifier_identity"),
                    "execution_core_ref": core_locator.get("reference_id") if isinstance(core_locator, Mapping) else None,
                    "execution_core_hash": core_locator.get("content_hash") if isinstance(core_locator, Mapping) else None,
                    "gate_status": "CODE_MODE_READY",
                    "completion_plan_ref": "logical:completion-plan",
                    "completion_plan_hash": "logical:completion-plan",
                }
                if not isinstance(binding, Mapping) or any(
                    binding.get(field) != expected for field, expected in expected_binding.items()
                ):
                    raise DynamicCollaborationError("Code Mode terminal evidence binding changed")
            if existing_success and existing_roots:
                root = existing_roots[0]
                final_ref = root.payload.get("final_receipt_ref")
                final_hash = root.payload.get("final_receipt_hash")
                if not isinstance(final_ref, str) or not isinstance(final_hash, str):
                    raise DynamicCollaborationError("Code Mode final root is incomplete")
                final_locator = {
                    "schema": "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
                    "reference_id": final_ref,
                    "content_hash": final_hash,
                    "receipt_hash": final_hash,
                    "run_id": str(run_id),
                    "journal_event_hash": root.event_hash,
                    "root_event_id": root.event_id,
                    "root_event_hash": root.event_hash,
                    "fresh_verified": True,
                    "no_replace_published": True,
                }
                try:
                    # The strict context verifier opens the authoritative
                    # Journal itself.  Release this writer first; otherwise a
                    # lifecycle retry would deadlock on the fixed-inode lock.
                    journal.close()
                    final_body = context.verify_code_mode_reviewed_state(
                        final_locator, run_id=str(run_id), stage="CONVERSATION_COMMITTED"
                    )
                except Exception as error:
                    raise DynamicCollaborationError(
                        "Code Mode final reviewed terminal receipt could not be reopened"
                    ) from error
                finally:
                    journal = context.open_runtime_writer()
                    cas = context.open_cas()
                    run_stream = CanonicalStream(journal, str(run_id), f"run/{run_id}", self.policy_hash)
                if any(
                    final_body.get(field) != expected
                    for field, expected in (
                        ("run_id", str(run_id)),
                        ("candidate_id", pending_candidate.get("candidate_id")),
                        ("tree_hash", pending_candidate.get("tree_hash")),
                        ("review_request_ref", pending_request.get("reference_id")),
                        ("review_request_hash", pending_request.get("content_hash")),
                        ("machine_check_ref", pending_package.get("machine_check_ref")),
                        ("machine_check_hash", pending_package.get("machine_check_hash")),
                        ("evidence_package_ref", pending_package.get("reference_id")),
                        ("evidence_package_hash", pending_package.get("content_hash")),
                        ("tty_review_receipt_ref", review_receipt.get("reference_id")),
                        ("tty_review_receipt_hash", review_receipt.get("content_hash")),
                        ("source_manifest_hash", pending_candidate.get("source_manifest_hash")),
                        ("worktree_digest", pending_candidate.get("worktree_digest")),
                        ("generation", pending_package.get("generation")),
                        ("verifier_identity", pending_package.get("verifier_identity")),
                        ("gate_status", "CODE_MODE_READY"),
                        ("user_response_hash", response_hash),
                        ("status", "SUCCEEDED"),
                    )
                ):
                    raise DynamicCollaborationError("Code Mode final receipt binding changed")
                response = str(pending["evidence"].user_response or "").strip()
                if not response:
                    raise DynamicCollaborationError("Code Mode recovered review has no user response")
                from sitina.conversation.lifecycle import ConversationLifecycle
                ConversationLifecycle(journal, cas, context.provider).complete_turn(
                    session_id=conversation_binding[0],
                    turn_index=conversation_binding[1],
                    message=conversation_binding[2],
                    response=response,
                    occurred_at=now_rfc3339(),
                )
                return {
                    "run_id": str(run_id), "terminal_state": "SUCCEEDED",
                    "code_mode_status": "CODE_MODE_READY", "review_status": "ACCEPT",
                    "code_mode_run_receipt": final_locator,
                    "final_reviewed_terminal_receipt": final_locator,
                    "review_request": dict(pending_request),
                    "evidence_package": dict(pending_package),
                    "candidate": dict(pending_candidate),
                    # Keep the complete typed handoff available to the live
                    # canary admission boundary.  These are opaque durable
                    # locators; the candidate display projection is never
                    # used as an authorization source.
                    "candidate_locator": dict(pending.get("code_receipt", {}).get("candidate_locator") or {}),
                    "machine_check_receipt": dict(pending.get("code_receipt", {}).get("machine_check_receipt") or {}),
                    "execution_core_locator": dict(core_locator or {}),
                    "tty_review_receipt": dict(review_receipt),
                    "code_mode_gate": dict(gate_result),
                    "gate_locator": completion_plan.get("gate_locator"),
                }
            request_ref = pending["code_receipt"]["review_request"]["reference_id"]
            if review_receipt.get("review_request_ref") != request_ref:
                raise DynamicCollaborationError("Code Mode review receipt is not bound to the pending request")
            if gate_result.get("candidate_id") not in (None, pending["code_receipt"]["candidate"]["candidate_id"]):
                raise DynamicCollaborationError("Code Mode gate candidate does not match the pending run")
            confirmed_at = review_body.get("confirmed_at")
            review_expires_at = review_body.get("expires_at")
            if not final_reviewer_facts:
                if type(confirmed_at) is not int or confirmed_at <= 0 or type(review_expires_at) is not int:
                    raise DynamicCollaborationError("Code Mode reviewer receipt has no authenticated acceptance time")
                if confirmed_at > review_expires_at or confirmed_at > int(time.time()) + 5:
                    raise DynamicCollaborationError("Code Mode reviewer acceptance is expired or from the future")
                accepted_at = confirmed_at
            acceptance_command_id = "code-mode-review-accept-" + stable_hash(
                "CODE_MODE_REVIEW_ACCEPTANCE",
                {
                    "run_id": str(run_id),
                    "request_ref": request_ref,
                    "request_hash": pending_request.get("content_hash"),
                    "review_receipt_ref": review_receipt.get("reference_id"),
                    "review_receipt_hash": review_receipt.get("content_hash"),
                    "gate_identity": gate_result.get("gate_identity") or "code-mode-acceptance-v1",
                },
            )[:44]
            final_review_fact = {
                "schema": "CODE_MODE_FINAL_REVIEWER_FACT_V1",
                "event_type": "code-mode.final-reviewer-fact",
                "run_id": str(run_id),
                "session_id": pending["controls"].get("conversation_session_id"),
                "turn_index": pending["controls"].get("conversation_turn_index"),
                "candidate_id": pending_candidate.get("candidate_id"),
                "tree_hash": pending_candidate.get("tree_hash"),
                "generation": pending_package.get("generation"),
                "verifier_identity": pending_package.get("verifier_identity"),
                "package_ref": pending_package.get("reference_id"),
                "package_hash": pending_package.get("content_hash"),
                "request_ref": request_ref,
                "request_hash": pending_request.get("content_hash"),
                "review_receipt_ref": review_receipt.get("reference_id"),
                "review_receipt_hash": review_receipt.get("content_hash"),
                "authority_class": review_body.get("authority_class"),
                "issuer_identity": review_body.get("issuer_identity"),
                "reviewer_session_id": review_body.get("reviewer_session_id"),
                "decision": "ACCEPT",
                "gate_status": gate_result.get("status"),
                "gate_identity": gate_result.get("gate_identity") or "code-mode-acceptance-v1",
                "accepted_at": accepted_at,
                "acceptance_command_id": acceptance_command_id,
            }
            if not final_reviewer_facts and not existing_success:
                candidate_ref = str(
                    (pending["code_receipt"].get("candidate_locator") or {}).get("reference_id")
                    or pending_candidate.get("reference_id") or ""
                )
                gate_ref = str(completion_plan.get("gate_locator") or "")
                acceptance_refs = (
                    request_ref, candidate_ref, str(pending_package.get("reference_id") or ""),
                    str(core_locator.get("reference_id") if isinstance(core_locator, Mapping) else ""),
                    str(review_receipt.get("reference_id") or ""), gate_ref, str(plan_ref or ""),
                )
                try:
                    acceptance_proofs = tuple(
                        cas.verify_existing(cas.resolve_reference(reference))
                        for reference in acceptance_refs if reference
                    )
                except Exception as error:
                    raise DynamicCollaborationError("Code Mode acceptance CAS proofs could not be reopened") from error
                if len(acceptance_proofs) != len(acceptance_refs) or len({item.object_ref.reference_id for item in acceptance_proofs}) != len(acceptance_refs):
                    raise DynamicCollaborationError("Code Mode acceptance CAS proof set is not exact")
                # Object ownership is part of the pair commitment.  The
                # reviewer fact owns the execution/review facts; the
                # accepted fact owns the request and signed plan.  The
                # Journal still receives the union as proof inputs, but the
                # event payloads may not be swapped between the two events.
                final_review_fact["_object_refs"] = sorted({
                    candidate_ref, str(pending_package.get("reference_id") or ""),
                    str(core_locator.get("reference_id") if isinstance(core_locator, Mapping) else ""),
                    str(review_receipt.get("reference_id") or ""), gate_ref,
                })
                acceptance_envelope = _request_acceptance_transaction(
                    context,
                    locators={
                        "schema": "CODE_MODE_ACCEPTANCE_LOCATOR_REQUEST_V2",
                        # The authority host receives only durable IDs.  It
                        # reopens versions/generation and CAS object identity
                        # from its launcher-bound state root.
                        "run_locator": run_stream.stream_id,
                        "request_locator": request_ref,
                        "candidate_locator": str((pending["code_receipt"].get("candidate_locator") or {}).get("reference_id") or pending_candidate.get("reference_id") or ""),
                        "package_locator": str(pending_package.get("reference_id") or ""),
                        "core_locator": str(core_locator.get("reference_id") if isinstance(core_locator, Mapping) else ""),
                        "review_locator": str(review_receipt.get("reference_id") or ""),
                        "gate_locator": str(completion_plan.get("gate_locator") or ""),
                        "completion_plan_locator": str(plan_ref or ""),
                    },
                )
                run_stream.append_code_mode_acceptance(
                    "code-mode-review-acceptance",
                    (
                        final_review_fact,
                        {
                        "schema": "CODE_MODE_REVIEW_ACCEPTED_V1",
                        "event_type": "run.review-accepted",
                        "run_id": str(run_id),
                        "session_id": pending["controls"].get("conversation_session_id"),
                        "turn_index": pending["controls"].get("conversation_turn_index"),
                        "request_ref": request_ref,
                        "request_hash": pending_request.get("content_hash"),
                        "package_ref": pending["code_receipt"]["evidence_package"]["reference_id"],
                        "review_receipt_ref": review_receipt.get("reference_id"),
                        "review_receipt_hash": review_receipt.get("content_hash"),
                        "gate_status": gate_result.get("status"),
                        "gate_identity": gate_result.get("gate_identity") or "code-mode-acceptance-v1",
                        "accepted_at": accepted_at,
                        "acceptance_command_id": acceptance_command_id,
                        "completion_plan_ref": plan_ref,
                        "completion_plan_hash": plan_hash,
                        "_object_refs": sorted({request_ref, str(plan_ref or "")}),
                        },
                    ),
                    actor="code-mode-review-controller",
                    envelope=acceptance_envelope,
                    proofs=acceptance_proofs,
                    command_id=acceptance_command_id,
                )
            controls = dict(pending["controls"])
            controls["code_mode_review_accepted"] = True
            controls["code_mode_tty_receipt"] = dict(review_receipt)
            controls["code_mode_internal_gate"] = dict(gate_result)
            controls["code_mode_evidence_package"] = dict(pending_package)
            controls["code_mode_cleanup_fact"] = (
                dict(cleanup_fact_binding or {}) if managed_worktree_for_review else None
            )
            controls["code_mode_review_request"] = dict(pending_request)
            controls["code_mode_candidate"] = dict(pending_candidate)
            controls["code_mode_completion_plan"] = dict(completion_plan)
            if not existing_success and isinstance(locals().get("terminal_stage_draft"), Mapping):
                controls["code_mode_terminal_stage_draft"] = terminal_stage_draft
            if not existing_success and isinstance(locals().get("root_stage_draft"), Mapping):
                controls["code_mode_root_stage_draft"] = root_stage_draft
            if not existing_success and isinstance(locals().get("conversation_stage_draft"), Mapping):
                controls["code_mode_conversation_stage_draft"] = conversation_stage_draft
            if not existing_success and "final_draft_receipt" in locals() and "final_receipt_draft_body" in locals():
                controls["code_mode_final_receipt_stage_draft"] = {
                    "receipt": final_draft_receipt,
                    "body": dict(final_receipt_draft_body),
                }
            if existing_success:
                terminal_event = next(
                    event for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("event_type") == "code-mode.terminal-success"
                    and event.payload.get("terminal_state") == "SUCCEEDED"
                )
                result = {
                    "run_id": str(run_id), "terminal_state": "SUCCEEDED",
                    "terminal_event_id": terminal_event.event_id,
                    "terminal_position": terminal_event.position,
                }
            else:
                controls["code_mode_acceptance_operation_hash"] = str(
                    (final_reviewer_facts[0].payload.get("authority_operation") or {}).get("payload_hash")
                    if final_reviewer_facts else plan_hash
                )
                result = self._terminalize_code_mode(
                    journal, cas, run_stream, pending["executor"], pending["evidence"], pending["run"],
                    runtime_context=context, controls=controls,
                )
            terminal_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == run_stream.stream_id
                and isinstance(event.payload, Mapping)
                and event.payload.get("event_type") == "code-mode.terminal-success"
                and event.payload.get("terminal_state") == "SUCCEEDED"
            ]
            if len(terminal_events) != 1:
                raise DynamicCollaborationError("Code Mode reviewed terminal is not unique")
            terminal_event = terminal_events[0]
            verified_tty_locator = dict(review_receipt)
            for field in (
                "authority_class", "issuer_identity", "decision", "verdict_decision",
                "reviewer_id", "reviewer_session_id", "generation",
            ):
                if field in review_body:
                    verified_tty_locator[field] = review_body[field]
            prepared_final = controls.get("code_mode_final_receipt_stage_draft")
            if not isinstance(prepared_final, Mapping):
                # After a process restart the in-memory draft is gone, but
                # the signed plan's root-stage draft is a durable recovery
                # anchor.  Reopen that draft and its exact final-receipt CAS
                # object instead of minting a second receipt from a caller
                # projection.
                root_operation = next(
                    (
                        item for item in (completion_plan.get("logical_operations") or ())
                        if isinstance(item, Mapping)
                        and item.get("operation") == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"
                    ),
                    None,
                )
                if isinstance(root_operation, Mapping):
                    root_draft_ref = root_operation.get("stage_draft_ref")
                    root_draft_hash = root_operation.get("stage_draft_hash")
                    if isinstance(root_draft_ref, str) and isinstance(root_draft_hash, str):
                        root_draft_payload = self._reopen_code_mode_cas_locator(
                            context,
                            {"reference_id": root_draft_ref, "content_hash": root_draft_hash},
                            schema="CODE_MODE_STAGE_DRAFT_V1",
                        )
                        root_projection = root_draft_payload.get("event_projection")
                        root_projection_payload = (
                            root_projection[0].get("payload")
                            if isinstance(root_projection, list) and root_projection
                            and isinstance(root_projection[0], Mapping)
                            else None
                        )
                        final_ref = (
                            root_projection_payload.get("final_receipt_ref")
                            if isinstance(root_projection_payload, Mapping) else None
                        )
                        final_hash = (
                            root_projection_payload.get("final_receipt_hash")
                            if isinstance(root_projection_payload, Mapping) else None
                        )
                        if not isinstance(final_ref, str) or not isinstance(final_hash, str):
                            raise DynamicCollaborationError("Code Mode root draft lacks final receipt binding")
                        try:
                            final_object = cas.resolve_reference(final_ref)
                            final_proof = cas.verify_existing(final_object)
                            final_payload = parse_canonical_json(cas.open_verified(final_object))
                        except Exception as error:
                            raise DynamicCollaborationError(
                                "Code Mode pre-acceptance final receipt could not be reopened"
                            ) from error
                        if (
                            not isinstance(final_payload, Mapping)
                            or final_payload.get("content_hash") != final_hash
                            or final_proof.object_ref.reference_id != final_ref
                            or not final_proof.fresh_verified
                            or not final_proof.no_replace_published
                        ):
                            raise DynamicCollaborationError("Code Mode pre-acceptance final receipt identity changed")
                        prepared_final = {"body": dict(final_payload), "receipt": final_proof}
            if isinstance(prepared_final, Mapping) and isinstance(prepared_final.get("body"), Mapping):
                final_body = dict(prepared_final["body"])
                final_receipt = prepared_final.get("receipt")
                if final_receipt is None:
                    raise DynamicCollaborationError("Code Mode final receipt draft has no CAS receipt")
            else:
                final_body = {
                "schema": "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
                "status": "SUCCEEDED",
                "run_id": str(run_id),
                "session_id": pending["controls"].get("conversation_session_id"),
                "turn_index": pending["controls"].get("conversation_turn_index"),
                "candidate_id": pending_candidate.get("candidate_id"),
                "tree_hash": pending_candidate.get("tree_hash"),
                "source_manifest_hash": pending_candidate.get("source_manifest_hash"),
                "worktree_digest": pending_candidate.get("worktree_digest"),
                "candidate_locator": pending["code_receipt"].get("candidate_locator"),
                "machine_check_ref": machine_locator.get("reference_id"),
                "machine_check_hash": machine_locator.get("content_hash"),
                "evidence_package_ref": pending_package.get("reference_id"),
                "evidence_package_hash": pending_package.get("content_hash"),
                "review_request_ref": pending_request.get("reference_id"),
                "review_request_hash": pending_request.get("content_hash"),
                "tty_review_receipt_ref": review_receipt.get("reference_id"),
                "tty_review_receipt_hash": review_receipt.get("content_hash"),
                "gate_status": gate_result.get("status"),
                "gate_identity": gate_result.get("gate_identity") or "code-mode-acceptance-v1",
                "terminal_event_id": terminal_event.event_id,
                "terminal_event_hash": terminal_event.event_hash,
                "generation": pending_package.get("generation"),
                "verifier_identity": pending_package.get("verifier_identity"),
                "reviewer_issuer_identity": review_body.get("issuer_identity"),
                "reviewer_authority_class": review_body.get("authority_class"),
                "execution_core_ref": (core_locator or {}).get("reference_id") if isinstance(core_locator, Mapping) else None,
                "execution_core_hash": (core_locator or {}).get("content_hash") if isinstance(core_locator, Mapping) else None,
                "cleanup_fact": dict(cleanup_fact_binding or {})
                if managed_worktree_for_review else None,
                "completion_plan_ref": plan_ref,
                "completion_plan_hash": plan_hash,
                "user_response_hash": response_hash,
                "conversation_message_hash": (
                    sha256_bytes(str(conversation_binding[2]).encode("utf-8"))
                    if conversation_binding is not None else None
                ),
                "issued_at": int(accepted_at or confirmed_at or 0),
                "expires_at": min(
                    value for value in (
                        int(pending_package.get("expires_at") or 0),
                        int(review_body.get("expires_at") or 0),
                    ) if value > 0
                ),
                }
                final_body["content_hash"] = "sha256:" + sha256_bytes(canonical_json_bytes(final_body))
                final_publication = cas.publish_plaintext(
                    canonical_json_bytes(final_body), tenant_id="code-mode-evidence",
                    purpose_class="code-mode-reviewed-terminal-receipt", media_type="application/json",
                )
                final_receipt = final_publication.receipt
            if not final_receipt.fresh_verified or not final_receipt.no_replace_published:
                raise DynamicCollaborationError("Code Mode final receipt CAS proof was not immutable")
            final_root_command_id = "code-mode-final-root-" + stable_hash(
                "CODE_MODE_FINAL_ROOT_COMMAND",
                {
                    "run_id": str(run_id),
                    "final_receipt_ref": final_receipt.object_ref.reference_id,
                    "final_receipt_hash": final_body["content_hash"],
                    "terminal_event_hash": final_body["terminal_event_hash"],
                },
            )[:44]
            root_plan_operation = next(
                (
                    item for item in (completion_plan.get("logical_operations") or ())
                    if isinstance(item, Mapping)
                    and item.get("operation") == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"
                ),
                {},
            )
            terminal_parent_hash = plan_hash
            terminal_event_for_parent = next(
                (
                    event for event in journal.iter_events(0)
                    if event.stream_id == run_stream.stream_id
                    and isinstance(event.payload, Mapping)
                    and event.payload.get("event_type") == "code-mode.terminal-success"
                    and isinstance(event.payload.get("authority_operation"), Mapping)
                ),
                None,
            )
            if terminal_event_for_parent is not None:
                terminal_parent_hash = str(
                    terminal_event_for_parent.payload["authority_operation"].get("payload_hash") or plan_hash
                )
            # The final-root operation is authorized by the already signed
            # completion plan.  Once acceptance is durable, no online host
            # signer is consulted and no caller can introduce a new envelope.
            try:
                plan_proof = cas.verify_existing(cas.resolve_reference(str(plan_ref)))
            except Exception as error:
                raise DynamicCollaborationError(
                    "Code Mode finalization requires a reopened completion-plan proof"
                ) from error
            if not plan_proof.fresh_verified or not plan_proof.no_replace_published:
                raise DynamicCollaborationError("Code Mode completion-plan proof is not immutable")
            completion_plan_body: Mapping[str, Any] = completion_plan
            completion_plan_reference = str(plan_ref) if isinstance(plan_ref, str) else None
            if completion_plan.get("reference_id"):
                try:
                    completion_plan_body = json.loads(
                        cas.open_verified(cas.resolve_reference(str(completion_plan["reference_id"]))).decode("utf-8")
                    )
                except Exception as error:
                    raise DynamicCollaborationError("Code Mode finalization plan could not be reopened") from error
            final_root_receipt, final_root_refs = run_stream.append_planned_authority_operation(
                "code-mode-final-root",
                ({
                    "schema": "CODE_MODE_FINAL_ROOT_V2",
                    "event_type": "code-mode.final-root",
                    "run_id": str(run_id),
                    "candidate_id": final_body["candidate_id"],
                    "generation": final_body["generation"],
                "review_request_ref": final_body["review_request_ref"],
                "completion_plan_ref": plan_ref,
                "completion_plan_hash": plan_hash,
                "tty_review_receipt_ref": final_body["tty_review_receipt_ref"],
                    "gate_status": final_body["gate_status"],
                    "terminal_event_id": terminal_event.event_id,
                    "terminal_event_hash": terminal_event.event_hash,
                    "seal_command_id": final_root_command_id,
                    "logical_operation_id": root_plan_operation.get("logical_operation_id"),
                    "logical_operation_hash": root_plan_operation.get("logical_operation_hash"),
                    "authenticated_seal": True,
                    "finalization_transaction": True,
                    "final_receipt_ref": final_receipt.object_ref.reference_id,
                    "final_receipt_hash": final_body["content_hash"],
                    "_object_refs": [final_receipt.object_ref.reference_id],
                },),
                actor="code-mode-review-controller", proofs=(final_receipt, plan_proof),
                command_id=final_root_command_id,
                completion_plan=completion_plan_body,
                logical_operation_id=str(root_plan_operation.get("logical_operation_id") or final_root_command_id),
                completion_plan_reference=completion_plan_reference,
            )
            if len(final_root_refs) != 1:
                raise DynamicCollaborationError("Code Mode final root was not unique")
            operation_mappings: dict[str, Any] = {}
            final_root_event = next(
                (
                    event for event in journal.iter_events(0)
                    if event.stream_id == run_stream.stream_id
                    and event.event_id == final_root_refs[0].get("event_id")
                ),
                None,
            )
            for event in (
                accepted_facts[0] if accepted_facts else None,
                terminal_event_for_parent,
                final_root_event,
            ):
                if event is None:
                    continue
                operation = event.payload.get("authority_operation") if isinstance(event.payload, Mapping) else None
                operation_id = operation.get("operation_id") if isinstance(operation, Mapping) else None
                if not isinstance(operation_id, str) or not callable(getattr(journal, "authority_operation_mapping", None)):
                    raise DynamicCollaborationError("Code Mode authority operation mapping is missing")
                operation_mappings[operation_id] = journal.authority_operation_mapping(
                    operation_id, stream_id=run_stream.stream_id
                )
            # Conversation completion is the third planned operation.  It is
            # intentionally written to the session stream (not the already
            # sealed run stream) and is an authority mapping in its own right;
            # the lifecycle projection below remains the final user-visible
            # step and can therefore be retried without creating a second
            # authority operation.
            conversation_operation = next(
                (
                    item for item in (completion_plan_body.get("operations") or ())
                    if isinstance(item, Mapping)
                    and item.get("operation") == "LOGICAL_CONVERSATION_COMPLETION_V1"
                ),
                None,
            )
            if conversation_binding is not None and isinstance(conversation_operation, Mapping):
                conversation_stream_id = f"session/{conversation_binding[0]}"
                if conversation_operation.get("stream_id") != conversation_stream_id:
                    raise DynamicCollaborationError("completion plan conversation stream binding changed")
                conversation_stream = CanonicalStream(
                    journal, str(run_id), conversation_stream_id, self.policy_hash
                )
                conversation_command_id = "code-mode-conversation-" + stable_hash(
                    "CODE_MODE_CONVERSATION_COMPLETION",
                    {
                        "run_id": str(run_id),
                        "session_id": conversation_binding[0],
                        "turn_index": conversation_binding[1],
                        "response_hash": response_hash,
                        "logical_operation_hash": conversation_operation.get("logical_operation_hash"),
                    },
                )[:44]
                conversation_receipt, conversation_refs = conversation_stream.append_planned_authority_operation(
                    "code-mode-conversation",
                    ({
                        "schema": "CODE_MODE_CONVERSATION_COMPLETION_V1",
                        "event_type": "code-mode.conversation-completion",
                        "run_id": str(run_id),
                        "session_id": conversation_binding[0],
                        "turn_index": conversation_binding[1],
                        "assistant_message_id": f"{conversation_binding[0]}-assistant-{conversation_binding[1]}",
                        "response_hash": response_hash,
                        "final_receipt_ref": final_receipt.object_ref.reference_id,
                        "final_receipt_hash": final_body["content_hash"],
                        "completion_plan_ref": plan_ref,
                        "completion_plan_hash": plan_hash,
                        "_object_refs": [final_receipt.object_ref.reference_id],
                    },),
                    actor="code-mode-review-controller",
                    proofs=(final_receipt, plan_proof),
                    command_id=conversation_command_id,
                completion_plan=completion_plan_body,
                logical_operation_id=str(conversation_operation["logical_operation_id"]),
                completion_plan_reference=completion_plan_reference,
                )
                if len(conversation_refs) != 1:
                    raise DynamicCollaborationError("Code Mode conversation operation was not unique")
                conversation_event = next(
                    (
                        event for event in journal.iter_events(0)
                        if event.stream_id == conversation_stream_id
                        and event.event_id == conversation_refs[0].get("event_id")
                    ),
                    None,
                )
                if conversation_event is None:
                    raise DynamicCollaborationError("Code Mode conversation operation mapping is missing")
                conversation_operation_id = str(conversation_operation["logical_operation_id"])
                operation_mappings[conversation_operation_id] = journal.authority_operation_mapping(
                    conversation_operation_id, stream_id=conversation_stream_id
                )
            run_stream.seal()
            final_locator = {
                "schema": final_body["schema"],
                "reference_id": final_receipt.object_ref.reference_id,
                "content_hash": final_body["content_hash"],
                "receipt_hash": final_body["content_hash"],
                "run_id": str(run_id),
                "journal_event_hash": final_root_refs[0]["event_hash"],
                "root_event_id": final_root_refs[0]["event_id"],
                "root_event_hash": final_root_refs[0]["event_hash"],
                "fresh_verified": True,
                "no_replace_published": True,
                "authority_operation_mappings": operation_mappings,
            }
            result.update({
                "code_mode_status": "CODE_MODE_READY",
                "review_status": "ACCEPT",
                "conversation_message": pending["controls"].get("conversation_user_message"),
                "conversation_session_id": pending["controls"].get("conversation_session_id"),
                "conversation_turn_index": pending["controls"].get("conversation_turn_index"),
                "tty_review_receipt": verified_tty_locator,
                "code_mode_run_receipt": final_locator,
                "temporary_code_mode_run_receipt": dict(pending["code_receipt"]),
                "final_reviewed_terminal_receipt": final_locator,
                "review_request": dict(pending["code_receipt"]["review_request"]),
                "evidence_package": dict(pending["code_receipt"]["evidence_package"]),
                "candidate": dict(pending["code_receipt"]["candidate"]),
                "candidate_locator": dict(pending["code_receipt"].get("candidate_locator") or {}),
                "machine_check_receipt": dict(pending["code_receipt"].get("machine_check_receipt") or {}),
                "execution_core_locator": dict(core_locator or {}),
                "gate_locator": completion_plan.get("gate_locator"),
            })
            # Completion is the last operation.  A CAS/root failure therefore
            # cannot leave a successful conversation turn behind an
            # unreviewed or unsealed result.
            if conversation_binding is not None:
                from sitina.conversation.lifecycle import ConversationLifecycle
                lifecycle = ConversationLifecycle(journal, cas, context.provider)
                response = str(pending["evidence"].user_response or "").strip()
                if not response:
                    raise DynamicCollaborationError("Code Mode review has no user response to persist")
                lifecycle.complete_turn(
                    session_id=conversation_binding[0],
                    turn_index=conversation_binding[1],
                    message=conversation_binding[2],
                    response=response,
                    occurred_at=now_rfc3339(),
                )
                # The same stage-aware verifier closes the final transition;
                # a root alone is intentionally insufficient for a committed
                # conversation response.
                journal.close()
                context.verify_code_mode_reviewed_state(
                    final_locator, run_id=str(run_id), stage="CONVERSATION_COMMITTED"
                )
            self._pending_code_mode_runs.pop(str(run_id), None)
            return result
        finally:
            # Cleanup must run while an already-open Journal writer is still
            # usable.  If an exception occurs while opening the writer/CAS or
            # constructing the stream, the guard therefore cleans first and
            # closes the writer in the nested finally.  Success-path cleanup
            # above is idempotently marked complete and is not repeated here.
            try:
                if managed_worktree_for_review and not cleanup_completed:
                    cleanup_pending_worktree()
            finally:
                if journal is not None:
                    journal.close()

    def _legacy_terminal_frontier(self, journal: Any) -> int:
        """Read the legacy global frontier only for legacy terminalization."""
        return int(journal.head_position)

    def _legacy_terminal_frontier_mapping(self, journal: Any) -> Mapping[str, Any]:
        """Legacy evidence compatibility; Code Mode never calls this."""
        return self._frontier(journal).__dict__

    def _terminalize_code_mode(
        self,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: Any,
        run: RunAggregate,
        runtime_context: Any | None = None,
        controls: Mapping[str, Any] | None = None,
        authority_parent_hash: str | None = None,
        prepare_stage_draft: bool = False,
    ) -> dict[str, Any]:
        """Terminalize an accepted Code Mode execution.

        The Code Mode entrypoint is deliberately distinct from the legacy
        terminalizer.  It requires the immutable execution core and the
        run-stream frontier; the shared implementation below is retained only
        for the final Journal projection mechanics.
        """
        # The first Code Mode terminalization call is the durable handoff
        # boundary.  It must be allowed to create the immutable execution
        # core and REVIEW_PENDING checkpoint before the post-review path is
        # admitted.  Once a reviewer is accepted, the same entry point below
        # requires both artifacts before it can create a terminal.
        return self._terminalize_code_mode_projection(
            journal, cas, run_stream, executor, evidence, run,
            runtime_context=runtime_context, controls=controls,
            authority_parent_hash=authority_parent_hash,
            prepare_stage_draft=prepare_stage_draft,
        )

    def _terminalize_code_mode_projection(
        self,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: Any,
        run: RunAggregate,
        runtime_context: Any | None = None,
        controls: Mapping[str, Any] | None = None,
        authority_parent_hash: str | None = None,
        prepare_stage_draft: bool = False,
    ) -> dict[str, Any]:
        controls = dict(controls or {})
        code_core = controls.get("code_mode_execution_core")
        code_mode_authorized = isinstance(controls.get("code_mode_authorization"), Mapping)
        frozen_frontier_position: int | None = None
        if isinstance(code_core, Mapping):
            raw_frontier = code_core.get("run_stream_frontier")
            if (
                not isinstance(raw_frontier, Mapping)
                or raw_frontier.get("stream_id") != run_stream.stream_id
                or type(raw_frontier.get("stream_version")) is not int
                or not isinstance(raw_frontier.get("commitment"), str)
            ):
                raise DynamicCollaborationError("Code Mode terminalizer requires a frozen run frontier")
            frozen_frontier_position = int(raw_frontier["stream_version"])
            if frozen_frontier_position < 0:
                raise DynamicCollaborationError("Code Mode terminalizer received an invalid frozen frontier")
        if (
            evidence.expected_terminal == "SUCCEEDED"
            and isinstance(controls.get("code_mode_authorization"), Mapping)
            and not bool(controls.get("code_mode_review_accepted"))
        ):
            return self._checkpoint_code_mode_review(
                journal=journal,
                cas=cas,
                run_stream=run_stream,
                executor=executor,
                evidence=evidence,
                run=run,
                runtime_context=runtime_context,
                controls=controls,
            )
        if code_mode_authorized and not isinstance(code_core, Mapping) and evidence.expected_terminal != "FAILED":
            raise DynamicCollaborationError("Code Mode requires an immutable execution core")
        if code_mode_authorized and evidence.expected_terminal != "FAILED" and not isinstance(controls.get("code_mode_internal_gate"), Mapping):
            raise DynamicCollaborationError("Code Mode requires the verified internal Gate")
        if (
            code_mode_authorized
            and evidence.expected_terminal == "SUCCEEDED"
            and not isinstance(code_core, Mapping)
        ):
            raise DynamicCollaborationError(
                "Code Mode terminalization requires the immutable execution core"
            )
        unsatisfied = sorted(key for key, complete in evidence.obligations.items() if not complete)
        if unsatisfied:
            raise DynamicCollaborationError("terminal blocked by open protocol obligations: " + ",".join(unsatisfied))
        if run.state is RunState.ACTIVE:
            run, closing = run.begin_closing(expected_stream_version=run.stream_version)
        elif run.state is RunState.CLOSING:
            closing = {
                "schema": "RUN_CLOSING_RESUMED_V1",
                "run_id": run.run_id,
                "state": run.state.value,
                "stream_version": run.stream_version,
                "admission_generation": run.admission_generation,
                "closing_reentered": False,
            }
        else:
            raise DynamicCollaborationError("terminalization requires an ACTIVE or durably restored CLOSING Run")
        empty_counts = {kind: 0 for kind in BlockerKind}
        negative_counts = dict(empty_counts)
        negative_counts[BlockerKind.PROTOCOL] = 1
        negative_projection = TerminalEligibilityProjection(
            evidence.run_id,
            negative_counts,
            frozen_frontier_position if frozen_frontier_position is not None else (0 if code_mode_authorized else self._legacy_terminal_frontier(journal)),
        )
        negative_block_ref = stable_hash("TRUE_MULTI_AGENT_TERMINAL_NEGATIVE_BLOCKER", {"run": evidence.run_id})
        negative_facts = AuthoritativeTerminalFacts(
            {kind: ((negative_block_ref,) if kind is BlockerKind.PROTOCOL else ()) for kind in BlockerKind},
            None,
            (),
            stable_hash("TRUE_MULTI_AGENT_OBLIGATIONS_COMPLETE", {"run": evidence.run_id}),
            self.policy_hash,
        )
        try:
            full_validate(negative_projection, run, negative_facts)
        except Exception as error:
            negative_probe = {
                "schema": "TERMINAL_NEGATIVE_PROBE_REJECTED_V1",
                "event_type": "protocol.terminal.negative.probe.rejected",
                "blocker_kind": BlockerKind.PROTOCOL.value,
                "blocker_ref": negative_block_ref,
                "terminal_committed": False,
                "reason_hash": sha256_bytes(str(error).encode()),
            }
        else:
            raise DynamicCollaborationError("terminal negative probe did not reject an authoritative blocker")
        obligations_ref = stable_hash(
            "TRUE_MULTI_AGENT_REQUIRED_OBLIGATIONS_COMPLETE",
            {"run": evidence.run_id, "obligations": sorted(evidence.obligations)},
        )
        failure_refs = (
            (stable_hash("TRUE_MULTI_AGENT_RUN_FAILURE", {"run": evidence.run_id, "notes": evidence.notes}),)
            if evidence.expected_terminal == "FAILED"
            else ()
        )
        terminal_facts = AuthoritativeTerminalFacts(
            {kind: () for kind in BlockerKind},
            None,
            failure_refs,
            None if failure_refs else obligations_ref,
            self.policy_hash,
        )
        projection = TerminalEligibilityProjection(
            evidence.run_id,
            empty_counts,
            frozen_frontier_position if frozen_frontier_position is not None else (0 if code_mode_authorized else self._legacy_terminal_frontier(journal)),
        )
        decision = full_validate(projection, run, terminal_facts)
        run, terminal = apply_terminal_decision(run, decision)
        if run.state.value != evidence.expected_terminal:
            raise DynamicCollaborationError("terminal decision contradicted expected failure/success facts")
        negotiation_protocol_count = sum(
            item.get("protocol_kind") == "debate" for item in evidence.protocol_graph
        )
        handoff_protocol_count = sum(
            item.get("protocol_kind") == "handoff" for item in evidence.protocol_graph
        )
        side_effect_counter = getattr(runtime_context, "side_effect_counts", None)
        if callable(side_effect_counter):
            try:
                side_effect_counts = dict(side_effect_counter(run_id=evidence.run_id, journal=journal))
            except TypeError:
                # Legacy contexts do not accept the borrowed writer.  They
                # remain valid for ordinary runs but cannot satisfy a Code
                # Mode receipt unless they provide a journal-derived result.
                side_effect_counts = dict(side_effect_counter(run_id=evidence.run_id))
        else:
            side_effect_counts = {
                "legacy_read_count": None,
                "legacy_write_count": None,
                "acceptance_runtime_read_count": None,
                "sqlite_connect_count": None,
                "sqlite_write_count": None,
            }
        code_mode_terminal_binding = None
        terminal_cleanup_fact = controls.get("code_mode_cleanup_fact")
        if terminal_cleanup_fact is not None:
            if (
                not isinstance(terminal_cleanup_fact, Mapping)
                or terminal_cleanup_fact.get("event_type") != "execution.worktree.cleanup.finally"
                or terminal_cleanup_fact.get("run_id") != evidence.run_id
                or terminal_cleanup_fact.get("status") not in {"ok", "not_present"}
                or terminal_cleanup_fact.get("removed") is not True
                or terminal_cleanup_fact.get("audit_recorded") is not True
                or (
                    terminal_cleanup_fact.get("status") == "ok"
                    and terminal_cleanup_fact.get("physical_removed") is not True
                )
                or not isinstance(terminal_cleanup_fact.get("event_hash"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", terminal_cleanup_fact["event_hash"])
            ):
                raise DynamicCollaborationError("Code Mode terminal cleanup fact is invalid")
        if isinstance(controls.get("code_mode_internal_gate"), Mapping):
            candidate = controls.get("code_mode_candidate")
            package = controls.get("code_mode_evidence_package")
            request = controls.get("code_mode_review_request")
            tty_receipt = controls.get("code_mode_tty_receipt")
            if not all(isinstance(item, Mapping) for item in (candidate, package, request, tty_receipt)):
                raise DynamicCollaborationError("Code Mode terminal evidence binding is incomplete")
            internal_gate = controls["code_mode_internal_gate"]
            if internal_gate.get("status") != "CODE_MODE_READY":
                raise DynamicCollaborationError("Code Mode terminal evidence requires the internal READY Gate")
            code_mode_terminal_binding = {
                "run_id": evidence.run_id,
                "session_id": controls.get("conversation_session_id"),
                "candidate_id": candidate.get("candidate_id"),
                "tree_hash": candidate.get("tree_hash"),
                "source_manifest_hash": candidate.get("source_manifest_hash"),
                "worktree_digest": candidate.get("worktree_digest"),
                "machine_check_ref": package.get("machine_check_ref"),
                "machine_check_hash": package.get("machine_check_hash"),
                "evidence_package_ref": package.get("reference_id"),
                "evidence_package_hash": package.get("content_hash"),
                "review_request_ref": request.get("reference_id"),
                "review_request_hash": request.get("content_hash"),
                "tty_review_receipt_ref": tty_receipt.get("reference_id"),
                "tty_review_receipt_hash": tty_receipt.get("content_hash"),
                "gate_status": internal_gate.get("status"),
                "gate_identity": internal_gate.get("gate_identity") or "code-mode-acceptance-v1",
                # The terminal semantic object is prepared before the plan
                # exists.  Plan identity is bound by the stage transaction;
                # including it here would make the pre-acceptance draft
                # self-referential and produce a different CAS object.
                "completion_plan_ref": "logical:completion-plan",
                "completion_plan_hash": "logical:completion-plan",
                "generation": package.get("generation"),
                "verifier_identity": package.get("verifier_identity"),
                "execution_core_ref": (controls.get("code_mode_execution_core") or {}).get("reference_id"),
                "execution_core_hash": (controls.get("code_mode_execution_core") or {}).get("content_hash"),
                "user_response_hash": sha256_bytes(str(evidence.user_response or "").encode("utf-8")),
            }
            if terminal_cleanup_fact is not None:
                code_mode_terminal_binding["cleanup_fact"] = dict(terminal_cleanup_fact)
        failed_transport_receipts = _failed_transport_receipts(executor)
        failed_provider_call_ids = _failed_transport_call_ids(
            executor, failed_transport_receipts
        )
        provider_call_ids: list[str] = []
        for call in evidence.calls:
            call_id = getattr(call, "call_id", None)
            if not isinstance(call_id, str) or not call_id:
                raise DynamicCollaborationError("Provider evidence call has no call identity")
            if call_id not in provider_call_ids:
                provider_call_ids.append(call_id)
        for call_id in failed_provider_call_ids:
            if call_id not in provider_call_ids:
                provider_call_ids.append(call_id)
        failed_receipt_fields = (
            {
                "failed_provider_transport_receipts": [dict(item) for item in failed_transport_receipts],
                "failed_provider_call_ids": list(failed_provider_call_ids),
                "failed_provider_reason_codes": _failed_transport_reason_codes(failed_transport_receipts),
            }
            if failed_transport_receipts
            else {}
        )
        if isinstance(code_core, Mapping):
            core_run = code_core.get("run_evidence")
            usage = code_core.get("provider_usage")
            if not isinstance(core_run, Mapping) or not isinstance(usage, Mapping):
                raise DynamicCollaborationError("Code Mode terminalizer requires a complete execution core")
            safe_calls = core_run.get("calls")
            safe_protocol = core_run.get("protocol_graph")
            if not isinstance(safe_calls, list) or not safe_calls or not isinstance(safe_protocol, list):
                raise DynamicCollaborationError("Code Mode terminalizer received a sparse execution core")
            evidence_package = {
                "schema": "CODE_MODE_TERMINAL_EVIDENCE_V1",
                "code_mode_terminal_projection": {
                    "schema": "CODE_MODE_TERMINAL_PROJECTION_V1",
                    "run_id": evidence.run_id,
                    "execution_core_ref": code_core.get("reference_id"),
                    "execution_core_hash": code_core.get("content_hash"),
                    "candidate_id": (controls.get("code_mode_candidate") or {}).get("candidate_id"),
                    "tree_hash": (controls.get("code_mode_candidate") or {}).get("tree_hash"),
                    "generation": (controls.get("code_mode_evidence_package") or {}).get("generation"),
                    "verifier_identity": (controls.get("code_mode_evidence_package") or {}).get("verifier_identity"),
                    "review_request_ref": (controls.get("code_mode_review_request") or {}).get("reference_id"),
                    "review_request_hash": (controls.get("code_mode_review_request") or {}).get("content_hash"),
                    "review_receipt_ref": (controls.get("code_mode_tty_receipt") or {}).get("reference_id"),
                    "review_receipt_hash": (controls.get("code_mode_tty_receipt") or {}).get("content_hash"),
                    "gate_identity": (controls.get("code_mode_internal_gate") or {}).get("gate_identity"),
                    "frozen_frontier_position": (
                        (code_core.get("run_stream_frontier") or {}).get("stream_version")
                    ),
                    "admission_generation": int(run.admission_generation),
                    "terminal_state": core_run.get("expected_terminal"),
                },
                "run_id": evidence.run_id,
                "admission_generation": int(run.admission_generation),
                "goal_hash": code_core.get("goal_hash"),
                "policy_hash": code_core.get("policy_hash"),
                "run_stream_frontier": dict(code_core.get("run_stream_frontier") or {}),
                "decisions": list(core_run.get("decisions") or []),
                "calls": list(safe_calls),
                **failed_receipt_fields,
                "rejected_call_hashes": [
                    stable_hash("CODE_MODE_REJECTED_CALL", dict(item))
                    for item in executor.rejected_calls
                    if isinstance(item, Mapping)
                ],
                "provider_recovery_attempt_hashes": [
                    stable_hash("CODE_MODE_PROVIDER_RECOVERY", dict(item))
                    for item in executor.recovery_attempts
                    if isinstance(item, Mapping)
                ],
                "checkpoint_restarts": [
                    {"fact_hash": stable_hash("CODE_MODE_CHECKPOINT_RESTART", dict(item))}
                    for item in core_run.get("checkpoint_restarts", [])
                    if isinstance(item, Mapping)
                ],
                "called_agents": list(core_run.get("called_agents") or []),
                "selected_agents": list(core_run.get("selected_agents") or []),
                "filtered_agents": dict(core_run.get("filtered_agents") or {}),
                "protocol_graph": list(safe_protocol),
                "obligations": dict(core_run.get("obligations") or {}),
                "expected_terminal": core_run.get("expected_terminal"),
                "terminal_decision": decision.__dict__,
                "execution_result": dict(core_run.get("execution_result") or {}),
                "cleanup_fact": dict(terminal_cleanup_fact) if terminal_cleanup_fact is not None else None,
                "provider_physical_send_count": int(usage.get("physical_send_count") or 0),
                "provider_call_count": int(usage.get("call_count") or 0),
                "provider_retry_count": int(usage.get("retry_count") or 0),
                "provider_fallback_count": int(usage.get("fallback_count") or 0),
                "provider_token_total": int(usage.get("total_tokens") or 0),
                "provider_cost_micro_usd": int(usage.get("cost_micro_usd") or 0),
                "provider_input_tokens": int(usage.get("input_tokens") or 0),
                "provider_output_tokens": int(usage.get("output_tokens") or 0),
                "provider_cache_read_tokens": int(usage.get("cache_read_tokens") or 0),
                "provider_cache_write_tokens": int(usage.get("cache_write_tokens") or 0),
                "provider_unsettled_usage_count": int(usage.get("unsettled_usage_count") or 0),
                "legacy_read_count": side_effect_counts.get("legacy_read_count"),
                "acceptance_runtime_read_count": side_effect_counts.get("acceptance_runtime_read_count"),
                "proposal_competition_count": sum(
                    1 for item in safe_calls if item.get("kind") == "proposal"
                ),
                "reviewer_call_count": sum(
                    1 for item in safe_calls if item.get("kind") in {"review", "fresh_review"}
                ),
                "negotiation_protocol_count": sum(
                    item.get("protocol_kind") == "debate" for item in safe_protocol
                    if isinstance(item, Mapping)
                ),
                "handoff_protocol_count": sum(
                    item.get("protocol_kind") == "handoff" for item in safe_protocol
                    if isinstance(item, Mapping)
                ),
                "external_mutation_count": int((core_run.get("execution_result") or {}).get("external_mutation_count", 0) or 0),
                "user_response_hash": code_core.get("response_hash"),
            }
        else:
            evidence_package = {
                "schema": "SITINA_TRUE_MULTI_AGENT_RUN_EVIDENCE_V1",
                "run_id": evidence.run_id,
                "goal": evidence.goal,
                "goal_hash": evidence.goal_hash,
                "policy_hash": evidence.policy_hash,
                "analysis": evidence.analysis.mapping() if evidence.analysis else None,
                "source_frontier": (
                    self._run_stream_frontier(journal, run_stream)
                    if code_mode_authorized
                    else self._legacy_terminal_frontier_mapping(journal)
                ),
                "decisions": list(evidence.decisions),
                "calls": [item.evidence() for item in evidence.calls],
                **failed_receipt_fields,
                "rejected_calls": list(executor.rejected_calls),
                "provider_recovery_attempts": list(executor.recovery_attempts),
                "checkpoint_restarts": list(evidence.checkpoint_restarts),
                "called_agents": sorted(evidence.called_agents),
                "selected_agents": sorted(evidence.selected_agents),
                "filtered_agents": {key: sorted(set(value)) for key, value in sorted(evidence.filtered_agents.items())},
                "protocol_graph": list(evidence.protocol_graph),
                "obligations": dict(evidence.obligations),
                "expected_terminal": evidence.expected_terminal,
                "terminal_decision": decision.__dict__,
                "execution_result": dict(evidence.execution_result or {}),
                "cleanup_fact": dict(terminal_cleanup_fact) if terminal_cleanup_fact is not None else None,
                "readonly_workspace_evidence": (
                    dict(evidence.readonly_workspace_evidence)
                    if isinstance(evidence.readonly_workspace_evidence, Mapping)
                    else None
                ),
                "provider_physical_send_count": executor.physical_send_total(),
                "provider_call_count": executor.provider_call_total(),
                "provider_retry_count": _provider_retry_projection(evidence.calls, executor),
                "provider_fallback_count": _provider_fallback_projection(evidence.calls, executor),
                "provider_token_total": executor.usage_total,
                "provider_cost_micro_usd": executor.cost_total_micro_usd,
                "provider_input_tokens": executor.usage_totals()["input_tokens"],
                "provider_output_tokens": executor.usage_totals()["output_tokens"],
                "provider_cache_read_tokens": executor.usage_totals()["cache_read_tokens"],
                "provider_cache_write_tokens": executor.usage_totals()["cache_write_tokens"],
                "provider_unsettled_usage_count": executor.usage_totals()["unsettled_usage_count"],
                "proposal_competition_count": sum(1 for item in evidence.calls if item.value.get("kind") == "proposal"),
                "reviewer_call_count": sum(1 for item in evidence.calls if item.value.get("kind") in {"review", "fresh_review"}),
                "negotiation_protocol_count": negotiation_protocol_count,
                "handoff_protocol_count": handoff_protocol_count,
                "external_mutation_count": int((evidence.execution_result or {}).get("external_mutation_count", 0) or 0),
                "legacy_read_count": side_effect_counts.get("legacy_read_count"),
                "acceptance_runtime_read_count": side_effect_counts.get("acceptance_runtime_read_count"),
                "notes": list(evidence.notes),
                "user_response": evidence.user_response,
                "user_response_agent_id": evidence.user_response_agent_id,
                "user_response_output_hash": evidence.user_response_output_hash,
            }
        if code_mode_terminal_binding is not None:
            evidence_package["code_mode_terminal_binding"] = code_mode_terminal_binding
        evidence_hash = sha256_bytes(canonical_json_bytes(evidence_package))
        # Store the same content identity inside the generic terminal evidence
        # body.  Recovery must reopen the exact CAS bytes, not rely on a
        # terminal event's self-reported hash alone.
        evidence_package["content_hash"] = evidence_hash
        prepared_terminal = controls.get("code_mode_terminal_stage_draft")
        prepared_receipt = prepared_terminal.get("receipt") if isinstance(prepared_terminal, Mapping) else None
        if prepared_receipt is not None and prepared_terminal.get("evidence_content_hash") == evidence_hash:
            # Reuse the immutable pre-acceptance semantic object.  Publishing
            # it again would assign a different CAS reference and make the
            # signed stage commitment disagree with the actual append.
            receipt = prepared_receipt
        else:
            receipt = executor._publish(evidence_package, purpose="true-multi-agent-run-evidence")
        terminal_event_type = (
            "code-mode.terminal-success"
            if run.state.value == "SUCCEEDED"
            else "code-mode.terminal-failed"
        )
        terminal_schema = (
            "CODE_MODE_TERMINAL_SUCCESS_V1"
            if run.state.value == "SUCCEEDED"
            else "CODE_MODE_TERMINAL_FAILED_V1"
        )
        if run.state.value not in {"SUCCEEDED", "FAILED"}:
            raise DynamicCollaborationError("Code Mode terminal state cannot be projected")
        terminal_fact = {
            **terminal,
            "schema": terminal_schema,
            "event_type": terminal_event_type,
            "status": "terminal",
            "required_obligations_open": 0,
            "terminal_state": run.state.value,
            "terminal_command_id": decision.command_id,
            "terminal_request_hash": decision.request_hash,
            "authoritative_fact_hash": decision.authoritative_fact_hash,
            "evidence_package_ref": receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "called_agents": sorted(evidence.called_agents),
            "selected_agents": sorted(evidence.selected_agents),
            "provider_call_count": executor.provider_call_total(),
            "provider_physical_send_count": executor.physical_send_total(),
            "provider_retry_count": _provider_retry_projection(evidence.calls, executor),
            "provider_fallback_count": _provider_fallback_projection(evidence.calls, executor),
            "provider_unsettled_usage_count": executor.usage_totals()["unsettled_usage_count"],
            "negotiation_protocol_count": negotiation_protocol_count,
            "handoff_protocol_count": handoff_protocol_count,
            "external_mutation_count": int((evidence.execution_result or {}).get("external_mutation_count", 0) or 0),
            "legacy_read_count": side_effect_counts.get("legacy_read_count"),
            "acceptance_runtime_read_count": side_effect_counts.get("acceptance_runtime_read_count"),
            "user_response_hash": sha256_bytes(evidence.user_response.encode())
            if evidence.user_response
            else None,
            "_object_refs": [receipt.object_ref.reference_id],
        }
        if code_mode_terminal_binding is not None:
            terminal_fact["code_mode_terminal_binding"] = dict(code_mode_terminal_binding)
        terminal_stage_facts = (
            {**closing, "event_type": "run.closing"},
            negative_probe,
            {
                "schema": "TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                "event_type": "protocol.terminal.full.validation.accepted",
                "projection_source_position": projection.source_position,
                "projection_candidate": projection.candidate,
                "authoritative_blocker_counts": {kind.value: 0 for kind in BlockerKind},
                "required_obligations_complete_ref": None if failure_refs else obligations_ref,
                "failure_refs": list(failure_refs),
                "decision": decision.__dict__,
            },
            {
                "schema": "RUN_EVIDENCE_PACKAGE_SEALED_V1",
                "event_type": "protocol.run.evidence.package.sealed",
                "evidence_package_ref": receipt.object_ref.reference_id,
                "evidence_package_hash": evidence_hash,
                "provider_call_ids": list(provider_call_ids),
                "provider_recovery_call_ids": [item["call_id"] for item in executor.recovery_attempts],
                "_object_refs": [receipt.object_ref.reference_id],
            },
            terminal_fact,
        )
        if not code_mode_authorized:
            # Ordinary read-only MULTI still uses the same evidence/CAS
            # projection, but must enter the ordinary Journal gate.  Do not
            # reuse Code Mode authority-reserved schema/event names.
            ordinary_package = dict(terminal_stage_facts[3])
            ordinary_package["schema"] = "TRUE_MULTI_AGENT_RUN_EVIDENCE_SEALED_V1"
            ordinary_package["event_type"] = "run.evidence.package.sealed"
            ordinary_terminal = dict(terminal_stage_facts[4])
            ordinary_terminal["schema"] = "TRUE_MULTI_AGENT_TERMINAL_V1"
            ordinary_terminal["event_type"] = "run.terminal"
            terminal_stage_facts = (
                terminal_stage_facts[0], terminal_stage_facts[1], terminal_stage_facts[2],
                ordinary_package, ordinary_terminal,
            )
        if prepare_stage_draft:
            # This path publishes only the immutable semantic evidence object;
            # it never appends a terminal or changes the RunAggregate.  The
            # returned projection is used by the host to sign the exact
            # terminal stage commitment before acceptance.
            draft_events = tuple(
                EventEnvelope(
                    f"draft-event-{index}",
                    str(fact.get("event_type") or ""),
                    "code-mode",
                    run_stream.stream_id,
                    0,
                    0,
                    "1970-01-01T00:00:00Z",
                    {
                        **({"run_id": run.run_id} if "run_id" not in fact else {}),
                        **{
                            key: value for key, value in fact.items()
                            if key != "_object_refs"
                        },
                    },
                    tuple(sorted(set(str(item) for item in fact.get("_object_refs", ())))),
                )
                for index, fact in enumerate(terminal_stage_facts)
            )
            return {
                "stage": "terminal",
                "events": tuple(dict(fact) for fact in terminal_stage_facts),
                "event_projection": stage_actual_event_projection(draft_events),
                "proofs": (receipt,),
                "receipt": receipt,
                "evidence_package": dict(evidence_package),
                "evidence_reference_id": receipt.object_ref.reference_id,
                "evidence_content_hash": evidence_hash,
            }
        terminal_authority_envelope = None
        planned_code_mode_terminal = False
        if (
            isinstance(runtime_context, object)
            and isinstance(code_mode_terminal_binding, Mapping)
            and bool(controls.get("code_mode_review_accepted"))
        ):
            terminal_plan_operation = next(
                (
                    item for item in (controls.get("code_mode_completion_plan") or {}).get("logical_operations", ())
                    if isinstance(item, Mapping)
                    and item.get("operation") == "LOGICAL_TERMINAL_OPERATION_V1"
                ),
                {},
            )
            planned_code_mode_terminal = True
        append_terminal = (
            run_stream.append_code_mode_fact
            if code_mode_authorized and terminal_authority_envelope is None
            else (run_stream.append_authority_operation if terminal_authority_envelope else run_stream.append)
        )
        append_kwargs = (
            {"envelope": terminal_authority_envelope}
            if terminal_authority_envelope is not None else {}
        )
        if planned_code_mode_terminal and isinstance(terminal_plan_operation, Mapping):
            completion_plan_body: Mapping[str, Any] = controls["code_mode_completion_plan"]
            completion_plan_reference = (
                str(completion_plan_body.get("reference_id"))
                if isinstance(completion_plan_body.get("reference_id"), str)
                else None
            )
            if completion_plan_body.get("reference_id"):
                try:
                    completion_plan_body = json.loads(
                        cas.open_verified(cas.resolve_reference(str(completion_plan_body["reference_id"]))).decode("utf-8")
                    )
                except Exception as error:
                    raise DynamicCollaborationError("Code Mode terminal plan could not be reopened") from error
            receipt_event, refs = run_stream.append_planned_authority_operation(
                "code-mode-terminal",
                terminal_stage_facts,
                actor="terminal-command-handler", proofs=(receipt,),
                command_id=decision.command_id,
                completion_plan=completion_plan_body,
                logical_operation_id=str(terminal_plan_operation["logical_operation_id"]),
                completion_plan_reference=completion_plan_reference,
            )
        else:
            receipt_event, refs = append_terminal(
                "code-mode-terminal" if code_mode_authorized else "run-terminal",
                terminal_stage_facts,
                actor="terminal-command-handler",
                proofs=(receipt,),
                command_id=decision.command_id,
                **append_kwargs,
            )
        evidence.actual_terminal = run.state.value
        evidence.terminal_event = refs[-1]
        result = {
            "run_id": evidence.run_id,
            "terminal_state": run.state.value,
            "provider_call_count": executor.provider_call_total(),
            "provider_physical_send_count": executor.physical_send_total(),
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "provider_input_tokens": executor.usage_totals()["input_tokens"],
            "provider_output_tokens": executor.usage_totals()["output_tokens"],
            "provider_cache_read_tokens": executor.usage_totals()["cache_read_tokens"],
            "provider_cache_write_tokens": executor.usage_totals()["cache_write_tokens"],
            "provider_unsettled_usage_count": executor.usage_totals()["unsettled_usage_count"],
            "proposal_competition_count": sum(
                1 for item in evidence.calls if item.value.get("kind") == "proposal"
            ),
            "reviewer_call_count": sum(
                1 for item in evidence.calls if item.value.get("kind") in {"review", "fresh_review"}
            ),
            "negotiation_protocol_count": negotiation_protocol_count,
            "handoff_protocol_count": handoff_protocol_count,
            "provider_retry_count": _provider_retry_projection(evidence.calls, executor),
            "provider_fallback_count": _provider_fallback_projection(evidence.calls, executor),
            "external_mutation_count": int(
                (evidence.execution_result or {}).get("external_mutation_count", 0) or 0
            ),
            "legacy_read_count": side_effect_counts.get("legacy_read_count"),
            "legacy_write_count": side_effect_counts.get("legacy_write_count"),
            "sqlite_connect_count": side_effect_counts.get("sqlite_connect_count"),
            "sqlite_write_count": side_effect_counts.get("sqlite_write_count"),
            "called_agents": sorted(evidence.called_agents),
            "selected_agents": sorted(evidence.selected_agents),
            "decision_count": len(evidence.decisions),
            "protocol_count": len(evidence.protocol_graph),
            "evidence_package_ref": receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "terminal_event_id": refs[-1]["event_id"],
            "terminal_position": refs[-1]["position"],
            "terminal_transaction_hash": receipt_event.transaction_hash,
            "notes": list(evidence.notes),
            "checkpoint_restart_count": len(evidence.checkpoint_restarts),
            "checkpoint_ids": [item["checkpoint_id"] for item in evidence.checkpoint_restarts],
        }
        if run.state is RunState.SUCCEEDED and evidence.user_response:
            result.update(
                {
                    "response": evidence.user_response,
                    "response_agent_id": evidence.user_response_agent_id,
                    "response_output_hash": evidence.user_response_output_hash,
                }
            )
        return result

    def _terminalize_legacy(
        self,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: Any,
        run: RunAggregate,
        runtime_context: Any | None = None,
        controls: Mapping[str, Any] | None = None,
        authority_parent_hash: str | None = None,
    ) -> dict[str, Any]:
        """Legacy-only terminal entry retained for non-Code-Mode runs.

        Code Mode calls ``_terminalize_code_mode`` and therefore never enters
        this compatibility symbol.  Keeping this adapter preserves the
        legacy command contract without making it an authorization path for
        the new execution protocol.
        """
        return self._terminalize_code_mode_projection(
            journal, cas, run_stream, executor, evidence, run,
            runtime_context=runtime_context, controls=controls,
            authority_parent_hash=authority_parent_hash,
        )

    def _cleanup_pending_code_mode_worktree(
        self,
        *,
        run_id: str,
        pending: Mapping[str, Any],
        context: Any,
        managed_worktree_for_review: bool,
        journal: Any | None = None,
    ) -> Mapping[str, Any] | None:
        """Clean one pending managed root and require an auditable removal."""
        if not managed_worktree_for_review:
            return None
        pending_controls = pending.get("controls")
        pending_evidence = pending.get("evidence")
        if not isinstance(pending_controls, Mapping) or not isinstance(
            pending_evidence, (RunEvidence, CodeModeExecutionFacts)
        ):
            raise DynamicCollaborationError("Code Mode managed cleanup lacks pending execution facts")
        raw_workspace = pending_controls.get("execution_workspace") or pending_controls.get("workspace")
        if not isinstance(raw_workspace, str) or not raw_workspace.strip():
            raise DynamicCollaborationError("Code Mode managed cleanup lacks the bound workspace")
        expected_worktree = (self.home / "artifacts" / "worktrees" / str(run_id)).expanduser().resolve(strict=False)
        if not expected_worktree.is_dir() or expected_worktree.is_symlink():
            raise DynamicCollaborationError(
                "Code Mode managed execution root is unavailable before final cleanup"
            )
        owns_journal = journal is None
        if owns_journal:
            journal = context.open_runtime_writer()
        try:
            stream = CanonicalStream(journal, str(run_id), f"run/{run_id}", self.policy_hash)
            report = self._cleanup_before_terminalize(
                run_id=str(run_id),
                controls=pending_controls,
                run_stream=stream,
                evidence=pending_evidence,
            )
        finally:
            if owns_journal and journal is not None:
                journal.close()
        if not isinstance(report, Mapping) or report.get("status") != "ok":
            raise DynamicCollaborationError("Code Mode managed worktree cleanup failed")
        return report

    def _cleanup_before_terminalize(
        self,
        *,
        run_id: str,
        controls: Mapping[str, Any],
        run_stream: CanonicalStream,
        evidence: RunEvidence,
    ) -> Mapping[str, Any] | None:
        """Reconcile the exact worktree before sealing the run evidence."""
        raw_workspace = controls.get("execution_workspace") or controls.get("workspace")
        if not isinstance(raw_workspace, str) or not raw_workspace.strip():
            return None
        from sitina.orchestrator.git_ops import GitWorktreeManager

        try:
            report = GitWorktreeManager(self.home).cleanup_for_run(raw_workspace, run_id)
        except Exception as error:
            error_hash = sha256_bytes(str(error).encode("utf-8"))
            report = {
                "run_id": run_id,
                "repo": str(Path(raw_workspace).expanduser().resolve(strict=False)),
                "worktree": str((self.home / "artifacts" / "worktrees" / run_id).resolve(strict=False)),
                "status": "failed",
                "removed": False,
                "physical_removed": False,
                "audit_recorded": False,
                "cleanup_error_type": type(error).__name__,
                "cleanup_error_hash": error_hash,
            }
        safe_report: dict[str, Any] = {
            key: report.get(key)
            for key in (
                "run_id", "repo", "worktree", "registered_before", "registered_after",
                "removed", "audit_recorded", "status",
                "porcelain_before_sha256", "porcelain_after_sha256",
                "cleanup_error_type", "cleanup_error_hash",
            )
        }
        # Git's worktree remover reports physical absence as ``removed``;
        # preserve that authoritative fact explicitly in the durable cleanup
        # receipt rather than leaving a missing/unknown field for the terminal
        # verifier to reject.
        safe_report["physical_removed"] = report.get(
            "physical_removed", report.get("removed")
        )
        try:
            run_stream.append(
                "execution-worktree-cleanup-finally",
                ({
                    "schema": "SITINA_EXECUTION_WORKTREE_LIFECYCLE_V1",
                    "event_type": "execution.worktree.cleanup.finally",
                    **safe_report,
                },),
                actor="controller-execution-authorizer",
            )
        except Exception as error:
            safe_report["cleanup_event_record_failed"] = True
            safe_report["cleanup_event_error_type"] = type(error).__name__
            report["status"] = "failed"
            report["audit_recorded"] = False
            safe_report["status"] = "failed"
            safe_report["audit_recorded"] = False
        if report.get("status") == "failed":
            evidence.expected_terminal = "FAILED"
            evidence.notes.extend(("cleanup_failed", "cleanup_status=" + str(report.get("status"))))
            evidence.execution_result = {
                **dict(evidence.execution_result or {}),
                "cleanup_failed": True,
                "cleanup_report": safe_report,
            }
        return report

    def execute(self, goal: str, *, label: str = "live", overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if not isinstance(goal, str) or not goal.strip():
            raise DynamicCollaborationError("true multi-agent execution requires a non-empty goal")
        controls = dict(overrides or {})
        # Code Mode authorization is a typed production input, not an
        # optional decoration of the run.  Validate its schema and derive the
        # non-secret projection before a context, Journal/CAS writer, or
        # run-created fact can be opened.  This prevents a malformed mapping
        # (including one carrying a bearer token) from reaching the durable
        # path through a schema-dependent redaction branch.
        raw_code_mode_authorization = controls.get("code_mode_authorization")
        if raw_code_mode_authorization is not None and not isinstance(
            raw_code_mode_authorization, Mapping
        ):
            raise DynamicCollaborationError("Code Mode authorization must be a mapping")
        durable_code_mode_authorization: Mapping[str, Any] | None = None
        if isinstance(raw_code_mode_authorization, Mapping):
            if raw_code_mode_authorization.get("schema") != "CODE_MODE_RUNTIME_AUTHORIZATION_V1":
                raise DynamicCollaborationError(
                    "Code Mode authorization schema is missing or invalid"
                )
            try:
                durable_code_mode_authorization = (
                    durable_code_mode_authorization_projection(raw_code_mode_authorization)
                )
            except Exception as error:
                raise DynamicCollaborationError(
                    "Code Mode authorization cannot be durably projected"
                ) from error
        if isinstance(controls.get("canary_authorization"), Mapping) or isinstance(
            controls.get("code_mode_authorization"), Mapping
        ):
            # An injected provider client is the explicit scripted/offline
            # mode. A normal live runtime leaves this unset until the
            # authoritative ProviderExecutor creates its transport, so it
            # must take the real sentinel-observation path.
            offline_provider = self.provider_client is not None
            if not offline_provider:
                self._code_mode_production_sentinel_before = self._observe_code_mode_production_sentinel()
            else:
                self._code_mode_production_sentinel_before = "offline-not-observed"
        journal = None
        run_id: str | None = None
        conversation_lifecycle: ConversationLifecycle | None = None
        conversation_message: str | None = None
        conversation_session_id: str | None = None
        conversation_turn_index: int | None = None
        pre_provider_authorization: Mapping[str, Any] | None = None
        try:
            # A live network action is meaningful only for the current
            # conversation turn.  Reject it before opening a Journal/CAS
            # writer so an absent/stale session cannot enter the production
            # activation path (and so a test double cannot hide this guard).
            if bool(controls.get("live_opt_in")):
                raw_live_session = controls.get("conversation_session_id")
                raw_live_turn = controls.get("conversation_turn_index")
                if (
                    not isinstance(raw_live_session, str)
                    or not raw_live_session.strip()
                    or type(raw_live_turn) is not int
                    or raw_live_turn < 0
                ):
                    raise DynamicCollaborationError(
                        "live canary requires a current conversation session and turn"
                    )
            runtime_context_factory = getattr(self, "runtime_context_factory", None)
            # A Code Mode authorization is never a reason to fall back to the
            # Legacy/B+ context.  The independent runtime must already be
            # constructed by the conversation/CLI boundary; otherwise fail
            # closed before importing or loading ProductionRuntimeContext.
            if (
                isinstance(controls.get("code_mode_authorization"), Mapping)
                or bool(controls.get("code_mode"))
            ) and not callable(runtime_context_factory):
                raise DynamicCollaborationError(
                    "Code Mode execution requires an independent runtime context factory"
                )
            supplied_code_context = getattr(self, "_active_code_mode_context", None)
            if supplied_code_context is not None:
                context_type = type(supplied_code_context)
                if (
                    context_type.__name__ != "CodeModeRuntimeContext"
                    or context_type.__module__ != "sitina.orchestrator.code_mode_runtime"
                ):
                    raise DynamicCollaborationError("Code Mode runtime context has an invalid type")
                context = supplied_code_context
            elif runtime_context_factory is not None:
                context = runtime_context_factory(self.home)
            else:
                # Ordinary turns use the current session context.  Legacy
                # Production/B+ is audit-only and is never a runtime fallback.
                from sitina.conversation.session_runtime import SessionRuntimeContext
                context = SessionRuntimeContext.open(
                    self.home,
                    provider=getattr(self, "session_runtime_provider", None),
                    source_root=getattr(self, "source_root", None),
                    session_instance_id=str(getattr(self, "session_instance_id", "") or "") or None,
                )
            code_mode_authorization = controls.get("code_mode_authorization")
            if isinstance(code_mode_authorization, Mapping):
                session_instance_id = str(controls.get("session_instance_id") or "").strip()
                context_instance_id = str(getattr(context, "session_instance_id", "")).strip()
                authorized_instance_id = str(code_mode_authorization.get("session_instance_id") or "").strip()
                if not session_instance_id or session_instance_id != context_instance_id or session_instance_id != authorized_instance_id:
                    raise DynamicCollaborationError(
                        "Code Mode execution session instance binding is incomplete or stale"
                    )
                # The issued authorization is the owner of the execution
                # identity.  Carry its already-validated values into the
                # mutable execution envelope before any evidence producer is
                # constructed; downstream receipts must not observe a
                # missing value and silently invent one.
                controls["session_instance_id"] = session_instance_id
            runtime_writer = getattr(type(context), "open_runtime_writer", None)
            journal = context.open_runtime_writer() if callable(runtime_writer) else context.open_writer()
            cas = context.open_cas()
            planned_run_id = (
                controls.get("canary_authorization", {}).get("run_id")
                if isinstance(controls.get("canary_authorization"), Mapping)
                else None
            )
            run_id = str(planned_run_id).strip() if planned_run_id else "tma-run-" + stable_hash(
                "TRUE_MULTI_AGENT_RUN_ID",
                {"goal": goal, "label": label, "nonce": uuid.uuid4().hex, "created_at_ns": time.time_ns()},
            )[:36]
            run_attempt = controls.get("run_attempt")
            if isinstance(code_mode_authorization, Mapping):
                if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1:
                    raise DynamicCollaborationError("Code Mode execution requires an issued run attempt")
            else:
                run_attempt = 1
            if isinstance(code_mode_authorization, Mapping):
                controls["run_attempt"] = run_attempt
            interactive_chat = bool(controls.get("interactive_chat"))
            raw_session_id = controls.get("conversation_session_id")
            conversation_session_id = str(raw_session_id or "").strip() or None
            if interactive_chat:
                conversation_message = str(controls.get("conversation_user_message") or "").strip()
                try:
                    conversation_turn_index = int(controls.get("conversation_turn_index"))
                except (TypeError, ValueError) as error:
                    raise DynamicCollaborationError("interactive chat requires a valid conversation turn index") from error
                route_mapping = controls.get("conversation_route_decision")
                if not conversation_message or not conversation_session_id or not isinstance(route_mapping, Mapping):
                    raise DynamicCollaborationError(
                        "interactive chat requires its original message, session identity, and route decision"
                    )
            elif controls.get("conversation_turn_index") is not None:
                try:
                    conversation_turn_index = int(controls.get("conversation_turn_index"))
                except (TypeError, ValueError) as error:
                    raise DynamicCollaborationError("conversation turn index must be an integer") from error
            request_binder = getattr(context, "bind_code_mode_request", None)
            code_mode_authorization = controls.get("code_mode_authorization")
            canary_binding = controls.get("canary_authorization")
            authorization_generation = str(
                code_mode_authorization.get("generation")
                if isinstance(code_mode_authorization, Mapping)
                else getattr(getattr(context, "identity", None), "epoch_root", "")
            )
            authorization_workspace = str(
                code_mode_authorization.get("workspace")
                if isinstance(code_mode_authorization, Mapping)
                else ""
            )
            if callable(request_binder) and isinstance(code_mode_authorization, Mapping):
                bound_session = conversation_session_id or str(code_mode_authorization.get("session_id") or "").strip()
                bound_candidate = (
                    str(canary_binding.get("candidate_id") or "").strip()
                    if isinstance(canary_binding, Mapping) else ""
                ) or str(code_mode_authorization.get("candidate_id") or "").strip()
                if not bound_candidate:
                    bound_candidate = stable_hash(
                        "CODE_MODE_REQUEST_CANDIDATE",
                        {
                            "workspace": str(code_mode_authorization.get("workspace") or ""),
                            "intent_hash": str((code_mode_authorization.get("intent") or {}).get("intent_hash") or ""),
                            "source_manifest_hash": getattr(
                                getattr(context, "identity", None), "source_manifest_hash", ""
                            ),
                        },
                    )
                request_binder(
                    session_instance_id=str(controls.get("session_instance_id") or ""),
                    session_id=bound_session,
                    run_id=run_id,
                    candidate_id=bound_candidate,
                    workspace=Path(
                        str(controls.get("execution_workspace") or authorization_workspace or "")
                    ),
                    run_attempt=int(run_attempt),
                    generation=authorization_generation,
                )
            # Every live MULTI root call, including read-only discovery, must
            # enter the broker-owned pre-provider permit domain before
            # activation.  Code Mode mutation authorization is not required
            # for this admission; it is a separate execution gate later in
            # the run.  Offline/scripted providers deliberately skip this
            # network capability domain.
            if getattr(self, "provider_client", None) is None and bool(controls.get("live_opt_in")) and pre_provider_authorization is None and not isinstance(canary_binding, Mapping):
                pre_session_id = conversation_session_id
                pre_turn_index = conversation_turn_index
                if isinstance(code_mode_authorization, Mapping):
                    pre_session_id = pre_session_id or str(code_mode_authorization.get("session_id") or "").strip()
                    if pre_turn_index is None and type(code_mode_authorization.get("turn_index")) is int:
                        pre_turn_index = code_mode_authorization.get("turn_index")
                if not pre_session_id or type(pre_turn_index) is not int or pre_turn_index < 0:
                    raise DynamicCollaborationError(
                        "live MULTI Provider execution requires a launcher-owned pre-provider issuer and turn"
                    )
                # A malformed test double/policy is not allowed to mint a
                # synthetic permit.  Leave admission empty so the real
                # activation boundary fails closed; valid production
                # policies always carry ``provider_profile`` (or an explicit
                # provider profile object) and take the broker-issued path.
                configured_profile = self.policy.get("provider_profile")
                supplied_profile = getattr(self, "provider_profile", None)
                if configured_profile or supplied_profile is not None:
                    pre_provider_authorization = issue_root_pre_provider_authorization(
                        context,
                        policy=self.policy,
                        session_id=pre_session_id,
                        turn_index=pre_turn_index,
                        run_id=run_id,
                        run_attempt=int(run_attempt),
                        provider_profile=supplied_profile,
                    )
            elif isinstance(code_mode_authorization, Mapping) and getattr(self, "provider_client", None) is None:
                if not bool(controls.get("live_opt_in")):
                    raise DynamicCollaborationError(
                        "live Code Mode Provider execution requires explicit live opt-in"
                    )
            if interactive_chat:
                conversation_lifecycle = ConversationLifecycle(journal, cas, context.provider)
                # Commit the original user body and deterministic route before
                # activation or any Provider physical send.
                conversation_lifecycle.start_turn(
                    session_id=conversation_session_id,
                    turn_index=conversation_turn_index,
                    message=conversation_message,
                    route_decision=route_decision_from_mapping(route_mapping),
                    occurred_at=now_rfc3339(),
                    session_instance_id=controls.get("session_instance_id"),
                    run_attempt=run_attempt,
                    generation=authorization_generation,
                    workspace=str(
                        controls.get("execution_workspace")
                        or controls.get("workspace")
                        or authorization_workspace
                        or self.home
                    ),
                )
            activation = activate_runtime(
                self.home, context, cas, self.registry, self.policy,
                live_capability=controls.get("live_capability"),
                pre_provider_authorization=pre_provider_authorization,
                run_id=run_id,
                session_id=conversation_session_id,
                provider_profile=getattr(self, "provider_profile", None),
                offline=getattr(self, "provider_client", None) is not None,
                # A few legacy callers construct the coordinator with
                # ``__new__`` for pre-activation lifecycle tests.  Those
                # calls do not enter Code Mode; preserve their explicit home
                # as the source root without creating a Production/B+
                # fallback for Code Mode (the Code Mode branch rejects a
                # missing runtime context before reaching activation).
                source_root=getattr(self, "source_root", self.home),
            )
            if isinstance(code_mode_authorization, Mapping):
                # Code Mode uses the typed in-memory execution facts object;
                # generic RunEvidence remains confined to the legacy path.
                evidence = CodeModeExecutionFacts(
                    run_id=run_id,
                    goal_hash=sha256_bytes(goal.encode()),
                    policy_hash=self.policy_hash,
                    goal=goal,
                )
            else:
                evidence = RunEvidence(run_id, goal, sha256_bytes(goal.encode()), self.policy_hash)
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None and conversation_turn_index is not None
                conversation_lifecycle.link_run(
                    session_id=conversation_session_id,
                    turn_index=conversation_turn_index,
                    run_id=run_id,
                    occurred_at=now_rfc3339(),
                    session_instance_id=controls.get("session_instance_id"),
                    run_attempt=run_attempt,
                    generation=authorization_generation,
                    workspace=str(
                        controls.get("execution_workspace")
                        or controls.get("workspace")
                        or authorization_workspace
                        or self.home
                    ),
                )
            run, opened = RunAggregate.open(run_id)
            run_stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.policy_hash)
            persisted_controls = dict(controls)
            if isinstance(pre_provider_authorization, Mapping):
                # The root permit is an in-process capability; only its
                # issuer-bound, non-secret scope is durable.  Read-only live
                # MULTI has no Code Mode mutation authorization, so this
                # projection is also the host's Journal anchor for the
                # ordinary root-planning path.
                persisted_controls["root_pre_provider_binding"] = {
                    field: pre_provider_authorization.get(field)
                    for field in (
                        "session_instance_id", "conversation_session_id", "turn_index",
                        "run_id", "run_attempt", "generation", "provider_profile",
                        "provider_model",
                    )
                }
            persisted_auth = persisted_controls.get("code_mode_authorization")
            if isinstance(persisted_auth, Mapping):
                # The in-process token authorizes this run but is not evidence
                # and must not be copied into Journal/CAS/artifacts.  Use the
                # same shared projection as attempt-advance mappings so the
                # two durable forms cannot drift.
                if durable_code_mode_authorization is None:
                    raise DynamicCollaborationError(
                        "Code Mode authorization durable projection is missing"
                    )
                persisted_controls["code_mode_authorization"] = dict(
                    durable_code_mode_authorization
                )
            run_stream.append(
                "run-created",
                (
                    {
                        "schema": "TRUE_MULTI_AGENT_RUN_CREATED_V1",
                        "event_type": "run.created",
                        "run_id": run_id,
                        "goal_hash": evidence.goal_hash,
                        "run_label": label,
                        "formal_acceptance_run": label.startswith("formal-"),
                        "acceptance_controls": persisted_controls,
                        "agent_count": len(self.registry.identities),
                        "execution_mode": "production-journal-cas-deepseek-live",
                        "provider_mode": str(
                            (activation.mapping.get("provider") or {}).get("effective_activation_level")
                            or "UNKNOWN"
                        ),
                        "runtime_activation_ref": activation.receipt.object_ref.reference_id,
                        "runtime_activation_hash": activation.manifest_hash,
                        "registry_hash": self.registry.registry_hash,
                        "registry_generation": self.registry.generation,
                        "fixed_workflow_pipeline_used": bool(
                            self.policy.get("execution_bridge_enabled")
                            and _execution_goal_authorized(evidence.goal, controls)
                        ),
                        "external_mutation_allowed": bool(
                            (activation.mapping.get("external_mutation_allowed"))
                        ),
                        "legacy_read_allowed": False,
                        "acceptance_read_allowed": False,
                        "_object_refs": [activation.receipt.object_ref.reference_id],
                    },
                    opened,
                ),
                actor="true-multi-agent-runtime",
                proofs=(activation.receipt,),
            )
            self._record_conversation_route(run_stream, controls)
            executor = ProviderExecutor(
                self.home,
                context,
                run_id,
                self.policy_hash,
                self.policy,
                activation,
                journal,
                cas,
                # The activation's signed provider specialization is the
                # authoritative no-fallback switch.  The optional control is
                # intentionally not consulted for this security decision.
                allow_provider_fallback=True,
                client_override=getattr(self, "provider_client", None),
                profile_override=getattr(self, "provider_profile", None),
                canary_authorization=(
                    dict(canary_binding)
                    if isinstance(canary_binding, Mapping) else None
                ),
                pre_provider_authorization=pre_provider_authorization,
            )
        except BaseException as error:
            if conversation_lifecycle is not None and conversation_session_id is not None and conversation_turn_index is not None:
                try:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=type(error).__name__,
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    pass
            if journal is not None:
                try:
                    journal.close()
                except Exception:
                    pass
            raise
        terminal_result: dict[str, Any] | None = None
        cleanup_done = False
        # Accepted managed executions retain their run-scoped worktree while
        # REVIEW_PENDING so the machine receipt can observe the real Tester
        # cwd.  The finalizer owns cleanup after the TTY/internal Gate; all
        # other terminal paths continue to clean before sealing.
        defer_managed_worktree_cleanup = False

        def cleanup_before_terminalize() -> Mapping[str, Any] | None:
            """Finish exact-run cleanup and journal it before sealing evidence."""
            nonlocal cleanup_done
            if cleanup_done:
                return None
            cleanup_done = True
            return self._cleanup_before_terminalize(
                run_id=run_id,
                controls=controls,
                run_stream=run_stream,
                evidence=evidence,
            )

        def terminalize_after_cleanup() -> dict[str, Any]:
            defer = bool(
                defer_managed_worktree_cleanup
                and evidence.expected_terminal == "SUCCEEDED"
                and not bool(controls.get("code_mode_review_accepted"))
            )
            report: Mapping[str, Any] | None = None
            if not defer:
                report = cleanup_before_terminalize()
            try:
                if isinstance(controls.get("code_mode_authorization"), Mapping):
                    result = self._terminalize_code_mode(
                        journal, cas, run_stream, executor, evidence, run,
                        runtime_context=context, controls=controls,
                    )
                else:
                    result = self._terminalize_legacy(
                        journal, cas, run_stream, executor, evidence, run,
                        runtime_context=context, controls=controls,
                    )
            except Exception:
                # A checkpoint failure must not strand the managed root.  A
                # successful checkpoint is the only state allowed to defer
                # cleanup, and it is durably represented in the pending map.
                if defer:
                    cleanup_before_terminalize()
                raise
            if defer and result.get("terminal_state") != "REVIEW_PENDING":
                report = cleanup_before_terminalize()
            if isinstance(report, Mapping) and report.get("status") == "failed":
                result["cleanup_failed"] = True
                result["execution_failed_closed"] = True
                result["cleanup_report"] = {
                    key: report.get(key)
                    for key in (
                        "run_id", "repo", "worktree", "registered_before", "registered_after",
                        "removed", "physical_removed", "audit_recorded", "status",
                        "porcelain_before_sha256", "porcelain_after_sha256",
                        "cleanup_error_type", "cleanup_error_hash",
                    )
                }
            return result

        try:
            analysis, _, _ = self._discover(journal, run_stream, executor, evidence, controls)
            analysis = self._analysis_with_constraints(analysis, controls, run_stream, evidence.goal)
            if bool(controls.get("interactive_chat")):
                if isinstance(controls.get("code_mode_authorization"), Mapping) and bool(
                    controls.get("intent_authorized")
                ):
                    analysis = self._code_mode_analysis(analysis)
                else:
                    analysis = self._interactive_chat_analysis(analysis)
                    if not _execution_goal_authorized(evidence.goal, controls):
                        # Read-only MULTI is a reviewed analysis response. It
                        # must not implicitly enter Debate/Handoff (both are
                        # execution-adjacent protocols and can create writes).
                        analysis = dataclasses.replace(
                            analysis,
                            protocols=("proposal", "review"),
                            task_graph=(
                                "interpret the current message and bounded conversation context",
                                "produce and independently review candidate answers",
                            ),
                            proposal_count=1,
                            rationale="read-only MULTI returns the reviewed analysis directly",
                        )
                run_stream.append(
                    "interactive-chat-analysis-constrained",
                    (
                        {
                            "schema": "INTERACTIVE_CHAT_ANALYSIS_CONSTRAINED_V1",
                            "event_type": "run.interactive-chat-analysis-constrained",
                            "goal_hash": evidence.goal_hash,
                            "protocols": list(analysis.protocols),
                            "proposal_count": analysis.proposal_count,
                            "external_mutation_allowed": False,
                        },
                    ),
                    actor="true-multi-agent-runtime",
                )
            evidence.analysis = analysis
            if bool(controls.get("interactive_chat")) and not _execution_goal_authorized(evidence.goal, controls):
                # Ordinary live MULTI (including a Code Mode policy mapping
                # whose intent is read-only) gets a bounded, CAS-backed
                # workspace observation before any Proposal/Review call.
                # The observation is deliberately independent of Forge and
                # carries no mutation authorization.
                raw_workspace = controls.get("execution_workspace") or controls.get("workspace")
                if not isinstance(raw_workspace, str) or not raw_workspace.strip():
                    raise DynamicCollaborationError(
                        "read-only MULTI requires a bound workspace for evidence"
                    )
                self._collect_readonly_workspace_evidence(
                    cas=cas,
                    run_stream=run_stream,
                    evidence=evidence,
                    workspace=Path(raw_workspace),
                    user_request=str(controls.get("conversation_user_message") or evidence.goal or ""),
                )
            self._materialize_topology(journal, run_stream, evidence, analysis)
            winner, winner_agent, proposals, proposal_decision = self._proposal_and_review(
                journal, run_stream, executor, evidence, analysis, controls
            )
            if bool(controls.get("interactive_chat")):
                response = render_selected_user_response(winner.value)
                if not response:
                    raise DynamicCollaborationError("selected chat proposal has no user-facing response")
                evidence.user_response = response
                evidence.user_response_agent_id = winner_agent.agent_id
                evidence.user_response_output_hash = winner.output_hash
            integrated_closure = _integrated_closure_required(evidence.goal)
            integrated_continuation: Mapping[str, Any] | None = None
            if "arbitration" in analysis.protocols:
                self._arbitrate(
                    journal, run_stream, executor, evidence, analysis, proposals, winner, winner_agent, proposal_decision, controls
                )
            if integrated_closure:
                required = {"blackboard", "handoff", "lease", "checkpoint", "debate", "rework"}
                missing = required.difference(analysis.protocols)
                if missing or not (
                    analysis.requires_conflict
                    and analysis.requires_handoff_reject
                    and analysis.requires_reassignment
                    and analysis.requires_rework
                ):
                    raise DynamicCollaborationError(
                        "integrated business constraints were not fully admitted: " + ",".join(sorted(missing))
                    )
                if _provider_recovery_required(evidence.goal):
                    self._provider_recovery(journal, run_stream, executor, evidence, controls)
                lease_context = self._integrated_lease_begin(
                    journal, evidence, winner_agent, proposal_decision, winner
                )
                blackboard_state = self._blackboard(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    analysis,
                    winner,
                    winner_agent,
                    proposal_decision,
                    controls,
                    primary_writer=winner_agent,
                    leased_task=lease_context["task"],
                )
                failover = self._integrated_lease_failover(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    lease_context,
                    blackboard_state,
                    controls,
                )
                integrated_continuation = self._handoff(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    analysis,
                    failover["source"],
                    failover["new_agent"],
                    failover["new_decision"],
                    controls,
                    defer_after_execution_prepared=True,
                    integrated_context=failover,
                )
                if integrated_continuation is None:
                    raise DynamicCollaborationError("integrated Handoff did not produce a restart continuation")
            else:
                if "blackboard" in analysis.protocols:
                    self._blackboard(
                        journal, run_stream, executor, evidence, analysis, winner, winner_agent, proposal_decision, controls
                    )
                # Req 1: for execution goals, deterministically bypass the
                # text-handoff protocol when the bypass flag is on — the
                # execution bridge + SL safety layer carry the invariants. The
                # non-execution handoff path is unchanged (Req 9).
                bypass_handoff = (
                    bool(self.policy.get("execution_handoff_bypass_enabled"))
                    and bool(self.policy.get("execution_bridge_enabled"))
                    and _execution_goal_authorized(evidence.goal, controls)
                )
                read_only_chat = bool(controls.get("interactive_chat")) and not _execution_goal_authorized(evidence.goal, controls)
                if "handoff" in analysis.protocols and not bypass_handoff and not read_only_chat:
                    self._handoff(
                        journal, run_stream, executor, evidence, analysis, winner, winner_agent, proposal_decision, controls
                    )
                if _provider_recovery_required(evidence.goal):
                    self._provider_recovery(journal, run_stream, executor, evidence, controls)
                if "lease" in analysis.protocols or analysis.requires_reassignment:
                    self._lease_and_reassign(journal, run_stream, executor, evidence, controls)
            if bool(controls.get("force_after_start_worker_loss")):
                fault = executor.inject_worker_loss(
                    winner_agent,
                    task_id="post-invocation-start-worker-loss",
                    after_invocation_started=True,
                )
                if fault["outcome_state"] != "OUTCOME_UNKNOWN" or fault["physical_send_count"] != 0:
                    raise DynamicCollaborationError("controlled post-InvocationStarted loss did not become OUTCOME_UNKNOWN")
                evidence.expected_terminal = "FAILED"
                evidence.notes.extend(("post_invocation_started_outcome_unknown", "policy_disposition_failed_no_retry"))
                transfer = MonitoringTransfer.create(
                    "monitoring-transfer-" + stable_hash("TRUE_MULTI_AGENT_MONITORING_TRANSFER", {"run": run_id})[:24],
                    run_id,
                    "incident-" + run_id,
                    (str(fault["effect_id"]),),
                    self.policy_hash,
                )
                transfer, monitoring_accepted = transfer.accept_successor(authority="incident-monitor-owner")
                CanonicalStream(
                    journal,
                    run_id,
                    "incident-" + run_id,
                    self.policy_hash,
                ).append(
                    "monitoring-obligation-accepted",
                    (monitoring_accepted,),
                    actor="incident-monitor-owner",
                )
                transfer, monitoring_acknowledged = transfer.acknowledge_source()
                run_stream.append(
                    "provider-unknown-contained",
                    (
                        {
                            "schema": "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
                            "event_type": "effect.unknown.policy-disposition",
                            "effect_id": fault["effect_id"],
                            "effect_attempt_id": fault["effect_attempt_id"],
                            "prior_outcome_state": fault["outcome_state"],
                            "disposition": "FAIL_RUN_AND_PERMANENTLY_BLOCK_RETRY",
                            "automatic_retry_performed": False,
                            "new_effect_created": False,
                            "physical_send_count_observed_by_controlled_transport": 0,
                            "success_claimed": False,
                            "monitoring_responsibility": transfer.successor_stream_id,
                            "successor_authority": transfer.successor_authority,
                            "terminal_effect_exposure_blocker_transferred": True,
                        },
                        monitoring_acknowledged,
                    ),
                    actor="effect-reconciliation-policy",
                )
            # Deterministic execution-goal decision (Req 1): NOT dependent on
            # whether Atlas emitted a "handoff" protocol.
            execution_goal = bool(self.policy.get("execution_bridge_enabled")) and _execution_goal_authorized(evidence.goal, controls)
            if "checkpoint" in analysis.protocols or bool(controls.get("force_checkpoint_restart")):
                # Req 8: an execution goal must never be resolved via a restart
                # that skips the execution bridge — that would mark it done
                # without execution + verification. Fail closed instead.
                if execution_goal:
                    raise DynamicCollaborationError(
                        "execution goal cannot resolve via checkpoint restart before the execution bridge"
                    )
                restart_plan = self._checkpoint_restart(
                    context,
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    run,
                    integrated_continuation=integrated_continuation,
                )
                journal.close()
                return restart_plan
            # Execution bridge (M2 + SL safety layer): build the winner, then
            # enforce migrated invariants (boundary redaction, independent
            # verify, bounded rework). Gated by execution_bridge_enabled.
            if execution_goal:
                review_calls = [
                    item for item in evidence.calls
                    if item.value.get("kind") in {"review", "fresh_review"}
                ]
                if review_calls:
                    review_call = review_calls[-1]
                    controls["proposal_review_evidence"] = {
                        "reviewer_id": str(review_call.value.get("agent_id") or "independent-reviewer"),
                        "review_call_id": review_call.call_id,
                        "review_output_hash": review_call.output_hash,
                        "verdict": str(review_call.value.get("verdict") or "unknown"),
                    }
                exec_result = self._execute_winner(
                    context, journal, cas, run_stream, executor, evidence, winner, winner_agent, controls,
                )
                evidence.execution_result = exec_result.as_event()
                if controls.get("_code_mode_managed_worktree_for_review") is True:
                    # Preserve this small lifecycle fact in the immutable
                    # execution core used by restart recovery.
                    evidence.execution_result["workspace_mode"] = "managed_worktree"
                    defer_managed_worktree_cleanup = bool(exec_result.accepted)
                # Req 4/7/8: only an ACCEPTED execution may terminalize SUCCEEDED.
                if not exec_result.accepted:
                    raise DynamicCollaborationError(
                        f"execution not accepted ({exec_result.status}); "
                        f"attempts={exec_result.attempts}; fail-closed"
                    )
            terminal_result = terminalize_after_cleanup()
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None
                assert conversation_turn_index is not None
                assert conversation_message is not None
                response = str(terminal_result.get("response") or "").strip()
                if terminal_result.get("terminal_state") == "REVIEW_PENDING":
                    # The conversation turn remains open until the controller
                    # reopens this run and commits Review V2 acceptance.
                    pass
                elif terminal_result.get("terminal_state") == "SUCCEEDED" and response:
                    conversation_lifecycle.complete_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        message=conversation_message,
                        response=response,
                        occurred_at=now_rfc3339(),
                    )
                else:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=str(terminal_result.get("error_type") or "MultiAgentRunFailed"),
                        occurred_at=now_rfc3339(),
                    )
            return terminal_result
        except Exception as error:
            # Session finalization occurs after the immutable run terminal. If
            # it fails, surface the reconciliation requirement; never attempt
            # a second run terminal transition.
            if terminal_result is not None:
                if conversation_lifecycle is not None:
                    assert conversation_session_id is not None and conversation_turn_index is not None
                    try:
                        conversation_lifecycle.fail_turn(
                            session_id=conversation_session_id,
                            turn_index=conversation_turn_index,
                            error_type=type(error).__name__,
                            occurred_at=now_rfc3339(),
                        )
                    except Exception:
                        pass
                raise
            evidence.expected_terminal = "FAILED"
            evidence.notes.extend(
                (
                    "execution_failed_closed",
                    "error_type=" + type(error).__name__,
                    "error_hash=" + sha256_bytes(str(error).encode()),
                )
            )
            provider_http_status_code = None
            for error_candidate in (error, getattr(error, "__cause__", None), getattr(error, "__context__", None)):
                candidate_status = getattr(error_candidate, "status_code", None)
                if type(candidate_status) is int and 100 <= candidate_status <= 599:
                    provider_http_status_code = candidate_status
                    break
            failed_transport_receipts = _failed_transport_receipts(executor)
            failed_provider_call_ids = _failed_transport_call_ids(
                executor, failed_transport_receipts
            )
            aborted: list[Mapping[str, Any]] = []
            for obligation_id, complete in list(evidence.obligations.items()):
                if complete:
                    continue
                instance = next(
                    (
                        item
                        for item in evidence.protocol_graph
                        if item["parent_obligation"] == obligation_id and item["terminal_disposition"] is None
                    ),
                    None,
                )
                if instance is not None:
                    aborted.append(
                        self._protocol_close(
                            evidence,
                            str(instance["protocol_instance"]),
                            obligation_id,
                            "FAILED_CLOSED",
                        )
                    )
                else:
                    evidence.obligations[obligation_id] = True
            run_stream.append(
                "run-execution-failed-closed",
                (
                    {
                        "schema": "RUN_EXECUTION_FAILED_CLOSED_V1",
                        "event_type": "run.execution.failed-closed",
                        "error_type": type(error).__name__,
                        "error_hash": sha256_bytes(str(error).encode()),
                        "provider_http_status_code": provider_http_status_code,
                        "provider_call_count": executor.provider_call_total(),
                        "provider_physical_send_count": executor.physical_send_total(),
                        "provider_retry_count": _provider_retry_projection(evidence.calls, executor),
                        "provider_fallback_count": _provider_fallback_projection(evidence.calls, executor),
                        "provider_unsettled_usage_count": executor.usage_totals()["unsettled_usage_count"],
                        "failed_provider_transport_receipts": [dict(item) for item in failed_transport_receipts],
                        "failed_provider_call_ids": list(failed_provider_call_ids),
                        "failed_provider_reason_codes": _failed_transport_reason_codes(failed_transport_receipts),
                        "rejected_provider_output_count": len(executor.rejected_calls),
                        "automatic_retry_performed": bool(
                            len((evidence.execution_result or {}).get("attempt_ledger", ())) > 1
                            or _provider_retry_projection(evidence.calls, executor) > 0
                            or executor.usage_totals()["retry_count"] > 0
                            or _provider_fallback_projection(evidence.calls, executor) > 0
                            or executor.usage_totals()["fallback_count"] > 0
                        ),
                        "fallback_performed": bool(
                            _provider_fallback_projection(evidence.calls, executor) > 0
                            or executor.usage_totals()["fallback_count"] > 0
                        ),
                        "success_claimed": False,
                    },
                    *aborted,
                ),
                actor="failure-containment-command-handler",
            )
            result = terminalize_after_cleanup()
            result["execution_failed_closed"] = True
            result["error_type"] = type(error).__name__
            result["error_hash"] = sha256_bytes(str(error).encode())
            result["provider_http_status_code"] = provider_http_status_code
            result["failed_provider_reason_codes"] = _failed_transport_reason_codes(failed_transport_receipts)
            result["failure_phase"] = (
                "provider_output_contract"
                if isinstance(error, AgentOutputContractRejected)
                or isinstance(error.__cause__, AgentOutputContractRejected)
                else "orchestration"
            )
            result["last_successful_call_id"] = evidence.calls[-1].call_id if evidence.calls else None
            result["last_successful_task_id"] = evidence.calls[-1].task_id if evidence.calls else None
            result["rejected_provider_output_count"] = len(executor.rejected_calls)
            result["rejected_provider_output_reason_types"] = sorted({
                str(item.get("reason_type"))
                for item in executor.rejected_calls
                if item.get("reason_type")
            })
            result["rejected_provider_output_reason_hashes"] = sorted({
                str(item.get("reason_hash"))
                for item in executor.rejected_calls
                if item.get("reason_hash")
            })
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None and conversation_turn_index is not None
                try:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=type(error).__name__,
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    result["session_failure_record_failed_closed"] = True
            return result
        finally:
            pending_review = bool(
                defer_managed_worktree_cleanup
                and terminal_result is not None
                and terminal_result.get("terminal_state") == "REVIEW_PENDING"
                and run_id in getattr(self, "_pending_code_mode_runs", {})
            )
            if run_id is not None and "cleanup_before_terminalize" in locals() and not cleanup_done and not pending_review:
                try:
                    cleanup_before_terminalize()
                except Exception:
                    if terminal_result is not None:
                        terminal_result["cleanup_failed"] = True
                        terminal_result["execution_failed_closed"] = True
            try:
                journal.close()
            except Exception:
                pass
            # A pending review deliberately keeps the controller alive for
            # the explicit TTY handoff.  Every completed/failed run releases
            # the namespace lock here, rather than relying on ``__del__``;
            # this also fences the managed-process registry deterministically.
            if run_id is not None and run_id not in getattr(self, "_pending_code_mode_runs", {}):
                controller = getattr(self, "_active_code_mode_controller", None)
                if controller is not None and callable(getattr(controller, "close", None)):
                    try:
                        controller.close()
                    except Exception:
                        pass
                    if getattr(self, "_active_code_mode_controller", None) is controller:
                        self._active_code_mode_controller = None
