from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Protocol, Sequence


CANONICAL_PROFILE_ID = "SITINA_CANONICAL_JSON_V1"
IDENTIFIER_PROFILE_ID = "SITINA_IDENTIFIER_HASH_V1"
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]*$")
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


class CanonicalizationError(ValueError):
    pass


class JournalModelError(ValueError):
    pass


class _Pairs(list[tuple[str, Any]]):
    pass


# Code Mode producer metadata is a shared, side-effect-free contract.  It is
# deliberately descriptive: this table does not authenticate a producer or
# return a verification decision.  Journal, CAS and the authority host use
# the same role names so a generic evidence event cannot silently stand in
# for a role-specific producer fact.
CODE_MODE_PRODUCER_SPECS: dict[str, dict[str, Any]] = {
    "candidate": {
        "fact_schema": "CODE_MODE_CANDIDATE_MANIFEST_FACT_V1",
        "event_type": "code-mode.candidate-manifest",
        "purpose_class": "code-mode-candidate-manifest",
        "required_fields": (
            "schema", "event_type", "purpose_class", "reference_id", "content_hash", "run_id", "session_instance_id",
            "session_id", "turn_index", "run_attempt", "generation",
            "candidate_id", "tree_hash", "source_manifest_hash",
            "authorization_ref",
        ),
    },
    "machine": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
        "purpose_class": "code-mode-machine-check",
    },
    "package": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_EVIDENCE_PACKAGE_V1",
        "purpose_class": "code-mode-execution-package",
    },
    "core": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
        "purpose_class": "code-mode-execution-evidence-core",
    },
    "request": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_REVIEW_REQUEST_V2",
        "purpose_class": "code-mode-review-request",
    },
    "review": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_REVIEW_RECEIPT_V2",
        "purpose_class": "code-mode-evidence",
    },
    "tty_consumption": {
        "fact_schema": "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1",
        "purpose_class": "code-mode-tty-nonce-consumption",
    },
    "closing_root": {
        "fact_schema": "CODE_MODE_EVIDENCE_CLOSING_ROOT_V1",
        "event_type": "code-mode.evidence.closing-root",
        "purpose_class": "code-mode-evidence-closing-root",
    },
    "terminal": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_TERMINAL_EVIDENCE_V1",
        "event_type": "code-mode.terminal-evidence",
        "purpose_class": "code-mode-terminal-evidence",
    },
    "reviewed_terminal": {
        "fact_schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
        "evidence_schema": "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
        "event_type": "code-mode.reviewed-terminal-receipt",
        "purpose_class": "code-mode-reviewed-terminal-receipt",
    },
    "conversation": {
        "fact_schema": "CODE_MODE_CONVERSATION_COMPLETION_V1",
        "event_type": "code-mode.conversation-completion",
        "purpose_class": "code-mode-conversation-completion",
    },
    # Root planning producer facts are separate from model output.  The host
    # consumes these authenticated Journal facts when validating the next
    # deterministic transition; an event that merely resembles one of these
    # schemas cannot be written through ordinary append.
    "root_dispatch": {
        "fact_schema": "CODE_MODE_ROOT_DISPATCH_FACT_V1",
        "event_type": "code-mode.root-call-dispatched",
        "purpose_class": "code-mode-root-call-dispatch",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "agent_id",
            "task_id", "role", "phase", "call_index", "dispatch_commitment",
            "predecessor_identity", "pre_provider_call_identity", "provider_profile",
            "provider_model", "provider_call_id", "state", "scheduling_task_id", "scheduling_decision_id",
            "scheduling_decision_commitment", "dispatch_command_id", "dispatch_command_commitment",
            "selected_agent_id", "slot",
        ),
    },
    "root_settled": {
        "fact_schema": "CODE_MODE_ROOT_SETTLED_FACT_V1",
        "event_type": "code-mode.root-call-settled",
        "purpose_class": "code-mode-root-call-settled",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "agent_id",
            "task_id", "role", "phase", "call_index", "dispatch_commitment",
            "predecessor_identity", "pre_provider_call_identity", "provider_profile",
            "provider_model", "provider_call_id", "state", "response_id", "response_receipt_hash",
            "scheduling_task_id", "scheduling_decision_id", "scheduling_decision_commitment", "dispatch_command_id",
            "dispatch_command_commitment", "selected_agent_id", "slot",
        ),
    },
    "root_selection": {
        "fact_schema": "CODE_MODE_ROOT_SELECTION_FACT_V1",
        "event_type": "code-mode.root-selection-committed",
        "purpose_class": "code-mode-root-selection",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "selected_agent_id",
            "selected_agent_role", "selected_agent_capabilities", "selected_task_id",
            "selected_output_hash", "selected_output_ref", "selected_provider_call_id",
            "selected_dispatch_commitment",
        ),
    },
    "root_scheduling": {
        "fact_schema": "AGENT_SCHEDULING_DECISION_V1",
        "event_type": "scheduling.decision",
        "purpose_class": "code-mode-agent-scheduling-decision",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "decision_id", "decision_commitment",
            "task_id", "phase", "selected_agents", "requested_slots", "decision",
            "required_capabilities",
        ),
    },
    "root_dispatch_acceptance": {
        "fact_schema": "DISPATCH_COMMAND_ACCEPTED_V1",
        "event_type": "dispatch.command.accepted",
        "purpose_class": "code-mode-dispatch-command-accepted",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "decision_id", "decision_commitment",
            "dispatch_command_id", "dispatch_commitment", "task_id", "phase", "selected_agents",
            "requested_slots", "required_capabilities", "state",
        ),
    },
    "root_result_accepted": {
        "fact_schema": "CODE_MODE_ROOT_RESULT_ACCEPTED_V1",
        "event_type": "code-mode.root-result-accepted",
        "purpose_class": "code-mode-root-result-accepted",
        "required_fields": (
            "schema", "event_type", "purpose", "purpose_class", "run_id", "session_instance_id",
            "conversation_session_id", "turn_index", "generation", "run_attempt", "agent_id", "task_id", "role",
            "phase", "call_index", "provider_call_id", "scheduling_task_id", "scheduling_decision_id",
            "scheduling_decision_commitment", "dispatch_command_id", "dispatch_command_commitment",
            "dispatch_commitment", "state", "response_id", "response_receipt_hash", "output_ref",
            "output_hash", "task_attempt_id",
        ),
    },
}

# These schemas are authority-reserved even when the event payload is
# malformed.  Keeping the schema and event-type sets here gives ordinary
# Journal writers one mechanical deny-list; it is deliberately descriptive
# and performs no authentication.
CODE_MODE_AUTHORITY_RESERVED_SCHEMAS = frozenset({
    "AUTHORITY_ACCEPTANCE_TRANSACTION_V1",
    "AUTHORITY_FINALIZATION_TRANSACTION_V1",
    "AUTHORITY_OPERATION_TRANSACTION_V1",
    "CODE_MODE_COMPLETION_PLAN_V1",
    "CODE_MODE_COMPLETION_PLAN_FACT_V1",
    "CODE_MODE_CANDIDATE_MANIFEST_FACT_V1",
    "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
    "CODE_MODE_FINAL_REVIEWER_FACT_V1",
    "CODE_MODE_REVIEW_ACCEPTED_V1",
    "CODE_MODE_TERMINAL_EVIDENCE_V1",
    "CODE_MODE_TERMINAL_SUCCESS_V1",
    "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
    "CODE_MODE_EVIDENCE_CLOSING_ROOT_V1",
    "RUN_EVIDENCE_PACKAGE_SEALED_V1",
    "CODE_MODE_FINAL_ROOT_V2",
    "CODE_MODE_TERMINAL_PROJECTION_V1",
    "CODE_MODE_CONVERSATION_COMPLETION_V1",
    "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
    "SITINA_EXECUTION_AUTHORIZATION_V1",
    "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1",
    "CODE_MODE_REVIEW_CANCELLED_V1",
    "CODE_MODE_FORGE_CHILD_AUTHORIZATION_V1",
    "SITINA_EXECUTION_CHILD_AUTHORIZATION_BOUND_V1",
    "CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_V1",
    "CODE_MODE_EXECUTION_PARENT_V1",
    "CODE_MODE_ROOT_DISPATCH_FACT_V1",
    "CODE_MODE_ROOT_SETTLED_FACT_V1",
    "CODE_MODE_ROOT_SELECTION_FACT_V1",
    "AGENT_SCHEDULING_DECISION_V1",
    "DISPATCH_COMMAND_ACCEPTED_V1",
    "CODE_MODE_ROOT_RESULT_ACCEPTED_V1",
})
CODE_MODE_AUTHORITY_RESERVED_EVENT_TYPES = frozenset({
    "code-mode.completion-plan",
    "code-mode.candidate-manifest",
    "code-mode.evidence-receipt",
    "code-mode.final-reviewer-fact",
    "code-mode.review-accepted",
    "code-mode.terminal-evidence",
    "code-mode.reviewed-terminal-receipt",
    "code-mode.evidence.closing-root",
    "code-mode.evidence.package-sealed",
    "protocol.run.evidence.package.sealed",
    "code-mode.final-root",
    "code-mode.terminal-projection",
    "code-mode.terminal-success",
    "code-mode.conversation-completion",
    "execution.authorization.attempt_advanced",
    "execution.authorization.bound",
    "code-mode.tty-review-nonce-consumed",
    "code-mode.review-cancelled",
    "execution.authorization.forge-child-bound",
    "execution.authorization.child-bound",
    "execution.authorization.attempt-control-bound",
    "execution.authorization.parent-bound",
    "code-mode.root-call-dispatched",
    "code-mode.root-call-settled",
    "code-mode.root-selection-committed",
    "scheduling.decision",
    "dispatch.command.accepted",
    "code-mode.root-result-accepted",
    "run.review-accepted",
})

# Provider calls made while the reviewed Forge plan is still being formed are
# a different capability domain from the post-review canary.  Keep the phase
# vocabulary in the shared model so a caller cannot widen it by sending an
# arbitrary string to a broker or host.
CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA = "CODE_MODE_PRE_PROVIDER_AUTHORIZATION_V1"
# FAST is a distinct one-call root workflow.  It uses the same signed
# session/run/turn/provider permit as MULTI planning, but it must not be
# represented as discovery (which would make the host expect a proposal).
CODE_MODE_FAST_PRE_PROVIDER_PHASE = "fast/synthesis"
CODE_MODE_PRE_PROVIDER_PHASES = (
    "discovery/controller",
    "proposal/planner/candidate",
    "review/selection",
    CODE_MODE_FAST_PRE_PROVIDER_PHASE,
)

# Transport permissions are intentionally disjoint.  These names are part of
# the signed/replayed projection rather than a caller-selected boolean, so a
# post-review permit cannot be presented as a Forge or planning permit.
CODE_MODE_AUTHORIZATION_DOMAINS = frozenset({
    "pre_provider_root",
    "attempt_execution",
    "attempt_control",
    "post_review_canary",
})
# Capability purposes describe authorization domains, not providers.
CODE_MODE_LIVE_CAPABILITY_PURPOSE = "code-mode-live-canary"
CODE_MODE_PROVIDER_TOKEN_TEST_PURPOSE = "code-mode-provider-token-test"
CODE_MODE_LIVE_CAPABILITY_PURPOSES = frozenset({
    CODE_MODE_LIVE_CAPABILITY_PURPOSE,
    CODE_MODE_PROVIDER_TOKEN_TEST_PURPOSE,
})
CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA = "CODE_MODE_FORGE_CHILD_AUTHORIZATION_V1"
CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE = "execution.authorization.forge-child-bound"
CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE = "true-multi-agent-forge-child"
CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_SCHEMA = "CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_V1"
CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_EVENT_TYPE = "execution.authorization.attempt-control-bound"
CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_PURPOSE = "true-multi-agent-attempt-control"
CODE_MODE_EXECUTION_PARENT_SCHEMA = "CODE_MODE_EXECUTION_PARENT_V1"
CODE_MODE_EXECUTION_PARENT_EVENT_TYPE = "execution.authorization.parent-bound"
CODE_MODE_EXECUTION_PARENT_PURPOSE = "true-multi-agent-execution-parent"
CODE_MODE_EXECUTION_PARENT_PROJECTION_FIELDS = frozenset({
    "schema", "event_type", "purpose", "authorization_token_hash",
    "authorization_ref", "session_instance_id", "conversation_session_id",
    "turn_index", "generation", "provider_profile", "provider_model",
    "session_id", "run_id", "intent_hash", "workspace", "scope",
    "risk_level", "attempt", "expires_at",
})

CODE_MODE_ROOT_FSM_STAGES = (
    "EXPECT_DISCOVERY",
    "EXPECT_PROPOSAL",
    "EXPECT_REVIEW",
    "WAIT_SELECTION",
    "ROOT_COMPLETE",
)


def pre_provider_call_identity(
    *,
    session_instance_id: str,
    conversation_session_id: str,
    turn_index: int,
    run_id: str,
    run_attempt: int,
    phase: str,
    role: str,
    call_index: int,
    provider_profile: str,
    provider_model: str,
) -> str:
    """Derive a deterministic identity for one pre-Forge provider call.

    This is a pure projection only.  The host still authenticates the
    controller-issued capability and checks the current session/attempt
    before accepting the identity.
    """
    if phase not in CODE_MODE_PRE_PROVIDER_PHASES:
        raise JournalModelError("pre-provider phase is not in the fixed allowlist")
    if any(not isinstance(value, str) or not value.strip() for value in (
        session_instance_id, conversation_session_id, run_id, role,
        provider_profile, provider_model,
    )):
        raise JournalModelError("pre-provider call identity has incomplete text binding")
    if type(turn_index) is not int or turn_index < 0:
        raise JournalModelError("pre-provider turn index is invalid")
    if type(run_attempt) is not int or run_attempt < 1:
        raise JournalModelError("pre-provider run attempt is invalid")
    if type(call_index) is not int or call_index < 1:
        raise JournalModelError("pre-provider call index is invalid")
    return domain_hash(
        "CODE_MODE_PRE_PROVIDER_CALL",
        canonical_json_bytes({
            "session_instance_id": session_instance_id,
            "conversation_session_id": conversation_session_id,
            "turn_index": turn_index,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "phase": phase,
            "role": role,
            "call_index": call_index,
            "provider_profile": provider_profile,
            "provider_model": provider_model,
        }),
    )


def pre_provider_scope_projection(
    *,
    session_instance_id: str,
    conversation_session_id: str,
    turn_index: int,
    run_id: str,
    run_attempt: int,
    generation: str,
    provider_profile: str,
    provider_model: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
) -> dict[str, Any]:
    """Return the exact signed scope of the pre-provider controller handle."""
    if not isinstance(nonce, str) or not nonce:
        raise JournalModelError("pre-provider nonce is required")
    # Validate phase-independent bindings via the same strict checks used by
    # call identity derivation.  This also rejects bools masquerading as ints.
    pre_provider_call_identity(
        session_instance_id=session_instance_id,
        conversation_session_id=conversation_session_id,
        turn_index=turn_index,
        run_id=run_id,
        run_attempt=run_attempt,
        phase=CODE_MODE_PRE_PROVIDER_PHASES[0],
        role="controller",
        call_index=1,
        provider_profile=provider_profile,
        provider_model=provider_model,
    )
    if not isinstance(generation, str) or not generation.strip():
        raise JournalModelError("pre-provider generation is required")
    if type(issued_at) is not int or type(expires_at) is not int or expires_at <= issued_at:
        raise JournalModelError("pre-provider lifetime is invalid")
    return {
        "schema": CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA,
        "purpose": "pre-provider-root-planning",
        "scope": "current-session-run",
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "generation": generation,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "allowed_phases": list(CODE_MODE_PRE_PROVIDER_PHASES),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }


def provider_call_identity_v2(
    *,
    session_instance_id: str,
    conversation_session_id: str,
    turn_index: int,
    run_id: str,
    run_attempt: int,
    agent_id: str,
    task_id: str,
    dispatch_commitment: str,
    predecessor_identity: str,
    phase: str,
    role: str,
    call_index: int,
    provider_profile: str,
    provider_model: str,
) -> str:
    """Pure V2 identity for a root-planning Provider call.

    The old identity helper remains available for frozen compatibility tests;
    production calls use this projection, which prevents a caller from
    changing agent/task/dispatch provenance while retaining the same index.
    """
    if phase not in CODE_MODE_PRE_PROVIDER_PHASES:
        raise JournalModelError("provider phase is not in the fixed root FSM")
    fields = {
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "agent_id": agent_id,
        "task_id": task_id,
        "dispatch_commitment": dispatch_commitment,
        "predecessor_identity": predecessor_identity,
        "phase": phase,
        "role": role,
        "call_index": call_index,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
    }
    if any(not isinstance(fields[key], str) or not fields[key].strip() for key in (
        "session_instance_id", "conversation_session_id", "run_id", "agent_id",
        "task_id", "dispatch_commitment", "predecessor_identity", "role",
        "provider_profile", "provider_model",
    )):
        raise JournalModelError("provider call identity text binding is incomplete")
    if type(turn_index) is not int or turn_index < 0:
        raise JournalModelError("provider call turn index is invalid")
    if type(run_attempt) is not int or run_attempt < 1:
        raise JournalModelError("provider call attempt is invalid")
    if type(call_index) is not int or call_index < 1:
        raise JournalModelError("provider call index is invalid")
    return domain_hash("CODE_MODE_PRE_PROVIDER_CALL_V2", canonical_json_bytes(fields))


def forge_child_authorization_reference(
    *, parent_authorization_hash: str, parent_run_id: str, child_run_id: str,
    run_attempt: int, session_instance_id: str, conversation_session_id: str,
    turn_index: int, generation: str, provider_profile: str,
    provider_model: str, execution_root: str, scope: Sequence[str],
) -> str:
    """Derive the issuer identity for one Forge child authorization.

    This is the same stable pre-CAS identity used by the trusted runtime
    registrar.  It intentionally excludes receipt/object and Journal
    coordinates; those are checked separately as ownership proofs.
    """
    values = {
        "parent_authorization_hash": parent_authorization_hash,
        "parent_run_id": parent_run_id,
        "run_id": child_run_id,
        "attempt": run_attempt,
        "purpose": "forge-attempt",
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "generation": generation,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "execution_root": execution_root,
        "scope": list(scope),
    }
    return "execution-authorization-child:" + domain_hash(
        "SITINA_EXECUTION_CHILD_AUTHORIZATION", canonical_json_bytes(values)
    )


def execution_parent_projection(
    *, authorization_token_hash: str, authorization_ref: str,
    session_instance_id: str, conversation_session_id: str, turn_index: int,
    generation: str, provider_profile: str, provider_model: str,
    session_id: str, run_id: str, intent_hash: str, workspace: str,
    scope: Sequence[str], risk_level: str, attempt: int, expires_at: int,
) -> dict[str, Any]:
    """Build the non-secret authenticated parent binding projection."""
    text_values = {
        "authorization_token_hash": authorization_token_hash,
        "authorization_ref": authorization_ref,
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "generation": generation,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "session_id": session_id,
        "run_id": run_id,
        "intent_hash": intent_hash,
        "workspace": workspace,
        "risk_level": risk_level,
    }
    if any(type(value) is not str or not value.strip() for value in text_values.values()):
        raise JournalModelError("execution parent binding has incomplete text fields")
    if not re.fullmatch(r"[0-9a-f]{64}", authorization_token_hash):
        raise JournalModelError("execution parent token commitment is invalid")
    if type(turn_index) is not int or turn_index < 0:
        raise JournalModelError("execution parent turn index is invalid")
    if type(attempt) is not int or attempt < 0:
        raise JournalModelError("execution parent attempt is invalid")
    if type(expires_at) is not int or expires_at <= 0:
        raise JournalModelError("execution parent expiry is invalid")
    if not isinstance(scope, Sequence) or isinstance(scope, (str, bytes)) or not scope:
        raise JournalModelError("execution parent scope is invalid")
    scope_values = list(scope)
    if any(type(item) is not str or not item.strip() for item in scope_values) or scope_values != sorted(scope_values):
        raise JournalModelError("execution parent scope is not canonical")
    return {
        "schema": CODE_MODE_EXECUTION_PARENT_SCHEMA,
        "event_type": CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
        "purpose": CODE_MODE_EXECUTION_PARENT_PURPOSE,
        "authorization_token_hash": authorization_token_hash,
        "authorization_ref": authorization_ref,
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "generation": generation,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "session_id": session_id,
        "run_id": run_id,
        "intent_hash": intent_hash,
        "workspace": workspace,
        "scope": scope_values,
        "risk_level": risk_level,
        "attempt": attempt,
        "expires_at": expires_at,
    }


def execution_parent_hash(projection: Mapping[str, Any]) -> str:
    """Derive the stable parent commitment from the shared projection."""
    if not isinstance(projection, Mapping) or projection.get("schema") != CODE_MODE_EXECUTION_PARENT_SCHEMA:
        raise JournalModelError("execution parent projection is invalid")
    return hashlib.sha256(canonical_json_bytes(dict(projection))).hexdigest()


def forge_child_authorization_projection(
    *, session_instance_id: str, conversation_session_id: str, turn_index: int,
    run_id: str, child_run_id: str, run_attempt: int, generation: str,
    parent_authorization_ref: str, parent_authorization_hash: str,
    authorization_ref: str, workspace: str, scope: Sequence[str],
    execution_root: str, risk_level: str, provider_profile: str,
    provider_model: str, expires_at: int, payload_hash: str,
) -> dict[str, Any]:
    """Return the exact logical child binding used by Journal and host."""
    if any(not isinstance(value, str) or not value.strip() for value in (
        session_instance_id, conversation_session_id, run_id, child_run_id,
        generation, parent_authorization_ref, parent_authorization_hash,
        authorization_ref, workspace, execution_root, risk_level,
        provider_profile, provider_model, payload_hash,
    )):
        raise JournalModelError("Forge child binding is incomplete")
    if type(turn_index) is not int or turn_index < 0 or type(run_attempt) is not int or run_attempt < 1:
        raise JournalModelError("Forge child numeric binding is invalid")
    if type(expires_at) is not int or expires_at <= 0:
        raise JournalModelError("Forge child expiry is invalid")
    if not isinstance(scope, Sequence) or isinstance(scope, (str, bytes)):
        raise JournalModelError("Forge child scope is invalid")
    scope_values = [str(item) for item in scope]
    if scope_values != [execution_root]:
        raise JournalModelError("Forge child scope is not exact")
    if not re.fullmatch(r"[0-9a-f]{64}", payload_hash):
        raise JournalModelError("Forge child payload hash is invalid")
    expected_authorization_ref = forge_child_authorization_reference(
        parent_authorization_hash=parent_authorization_hash,
        parent_run_id=run_id,
        child_run_id=child_run_id,
        run_attempt=run_attempt,
        session_instance_id=session_instance_id,
        conversation_session_id=conversation_session_id,
        turn_index=turn_index,
        generation=generation,
        provider_profile=provider_profile,
        provider_model=provider_model,
        execution_root=execution_root,
        scope=scope_values,
    )
    if authorization_ref != expected_authorization_ref:
        raise JournalModelError("Forge child reference is not issuer-derived")
    return {
        "schema": CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA,
        "event_type": CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE,
        "purpose": CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE,
        "domain": "attempt_execution",
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "run_id": run_id,
        "child_run_id": child_run_id,
        "run_attempt": run_attempt,
        "generation": generation,
        "parent_authorization_ref": parent_authorization_ref,
        "parent_authorization_hash": parent_authorization_hash,
        "authorization_ref": authorization_ref,
        "workspace": workspace,
        "scope": scope_values,
        "execution_root": execution_root,
        "risk_level": risk_level,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "expires_at": expires_at,
        "payload_hash": payload_hash,
    }


def attempt_control_authorization_projection(
    *, session_instance_id: str, conversation_session_id: str,
    turn_index: int, run_id: str, run_attempt: int, generation: str,
    authorization_ref: str, parent_execution_authorization_ref: str,
    provider_profile: str, provider_model: str, expires_at: int,
) -> dict[str, Any]:
    """Project the post-Forge Reviewer/replan transport domain."""
    if any(not isinstance(value, str) or not value.strip() for value in (
        session_instance_id, conversation_session_id, run_id, generation,
        authorization_ref, parent_execution_authorization_ref,
        provider_profile, provider_model,
    )):
        raise JournalModelError("attempt-control authorization is incomplete")
    if type(turn_index) is not int or turn_index < 0:
        raise JournalModelError("attempt-control turn index is invalid")
    if type(run_attempt) is not int or run_attempt < 1:
        raise JournalModelError("attempt-control run attempt is invalid")
    if type(expires_at) is not int or expires_at <= 0:
        raise JournalModelError("attempt-control expiry is invalid")
    return {
        "schema": CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_SCHEMA,
        "event_type": CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_EVENT_TYPE,
        "purpose": CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_PURPOSE,
        "domain": "attempt_control",
        "session_instance_id": session_instance_id,
        "conversation_session_id": conversation_session_id,
        "turn_index": turn_index,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "generation": generation,
        "authorization_ref": authorization_ref,
        "parent_execution_authorization_ref": parent_execution_authorization_ref,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
        "expires_at": expires_at,
    }


def is_code_mode_authority_reserved(event: Any) -> bool:
    """Return whether an event claims an authority-reserved identity.

    This is intentionally a pure structural predicate.  Dedicated Journal
    entry points perform the actual authentication and fact validation.
    """
    payload = getattr(event, "payload", event)
    if not isinstance(payload, Mapping):
        return False
    return (
        payload.get("schema") in CODE_MODE_AUTHORITY_RESERVED_SCHEMAS
        or payload.get("event_type") in CODE_MODE_AUTHORITY_RESERVED_EVENT_TYPES
    )


_STAGE_PHYSICAL_PAYLOAD_FIELDS = frozenset({
    # These are assigned by Journal/runtime transport after the semantic
    # draft exists.  They are deliberately excluded from the stage logical
    # commitment; event bodies, schema, refs and every other stable field are
    # retained verbatim.
    "authority_operation", "finalization_transaction", "logical_operation_id",
    "logical_operation_hash", "runtime_namespace", "actor_id",
    "causation_command_id", "policy_hash", "fact_hash",
})


def _stage_logicalize_predecessor_fields(payload: dict[str, object]) -> None:
    """Normalize future physical predecessors to explicit logical bindings.

    A pre-acceptance stage draft cannot contain a CAS reference, physical
    event id, transaction hash, or seal command generated by a later append.
    Those values are nevertheless semantic predecessor fields and must not be
    silently dropped from the commitment.  The stage protocol therefore uses
    typed logical placeholders.  Journal physical mappings retain the real
    values outside this semantic projection.
    """
    if "completion_plan_ref" in payload:
        payload["completion_plan_ref"] = "logical:completion-plan"
    if "completion_plan_hash" in payload:
        payload["completion_plan_hash"] = "logical:completion-plan"
    if "terminal_event_id" in payload:
        payload["terminal_event_id"] = "logical:terminal"
    if "terminal_event_hash" in payload:
        payload["terminal_event_hash"] = "logical:terminal"
    if "seal_command_id" in payload:
        payload["seal_command_id"] = "logical:final-root"


def stage_actual_event_projection(events: Sequence[EventEnvelope]) -> list[dict[str, Any]]:
    """Return the canonical *semantic* stage projection.

    Journal coordinates and authority envelopes are physical commit metadata,
    not pre-acceptance facts.  The projection keeps the complete ordered
    stable event bodies and per-event object ownership so a stage draft cannot
    be reduced to event names or a shared binding hash.
    """
    if not isinstance(events, Sequence) or not events:
        raise JournalModelError("stage must contain ordered events")
    projection = []
    for event in events:
        if not isinstance(event, EventEnvelope):
            raise JournalModelError("stage event is not an EventEnvelope")
        payload = {
            str(key): value for key, value in event.payload.items()
            if str(key) not in _STAGE_PHYSICAL_PAYLOAD_FIELDS
        }
        _stage_logicalize_predecessor_fields(payload)
        projection.append({
            "event_type": event.event_type,
            "schema": payload.get("schema"),
            "payload": payload,
            "object_refs": list(event.object_refs),
        })
    return projection


def stage_actual_projection_bytes(events: Sequence[EventEnvelope]) -> bytes:
    """Canonical ordered actual stage projection, including full bodies."""
    return b"SITINA-CODE-MODE-ACTUAL-STAGE-V1\0" + canonical_json_bytes(
        stage_actual_event_projection(events)
    )


def stage_actual_projection_hash(events: Sequence[EventEnvelope]) -> str:
    return hashlib.sha256(stage_actual_projection_bytes(events)).hexdigest()


def stable_stage_proof_manifest(
    proofs: Sequence[Any],
) -> tuple[dict[str, Any], ...]:
    """Project proof identity without freshness or physical Journal fields."""
    values = []
    for proof in proofs:
        object_ref = getattr(proof, "object_ref", None)
        if object_ref is None:
            raise JournalModelError("stage proof has no object reference")
        value = {
            "reference_id": object_ref.reference_id,
            "object_id": object_ref.object_id,
            "tenant_id": object_ref.tenant_id,
            "plaintext_commitment": object_ref.plaintext_commitment,
            "commitment_key_id": object_ref.commitment_key_id,
            "profile": object_ref.profile,
            "proof_type": "published" if proof.__class__.__name__ == "PublishedObjectReceipt" else "existing_root",
            "purpose_class": getattr(proof, "purpose_class", None),
            "core_header_hash": getattr(proof, "core_header_hash", None),
            "envelope_id": getattr(proof, "envelope_id", None),
            "rooted_transaction_hash": getattr(proof, "rooted_transaction_hash", None),
        }
        values.append(value)
    return tuple(sorted(values, key=lambda item: str(item["reference_id"])))


def stable_stage_proof_manifest_hash(proofs: Sequence[Any]) -> str:
    return proof_manifest_hash(stable_stage_proof_manifest(proofs))


def code_mode_producer_spec(role: str) -> dict[str, Any]:
    """Return a copy of a role contract; no I/O or trust decision occurs."""
    value = CODE_MODE_PRODUCER_SPECS.get(role)
    if value is None:
        raise JournalModelError("unknown Code Mode producer role")
    return dict(value)


_SURROGATE_CODE_POINT = re.compile(r"[\ud800-\udfff]")


def _normalize_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if _SURROGATE_CODE_POINT.search(normalized) is not None:
        raise CanonicalizationError("surrogate code point is forbidden")
    return normalized


def _normalize(value: Any, *, set_like_fields: frozenset[str], field: str | None = None) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not INT64_MIN <= value <= INT64_MAX:
            raise CanonicalizationError("integer is outside signed 64-bit bounds")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating point values are forbidden")
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            canonical_key = _normalize_string(key)
            if canonical_key in normalized:
                raise CanonicalizationError("duplicate key after NFC normalization")
            normalized[canonical_key] = _normalize(item, set_like_fields=set_like_fields, field=canonical_key)
        return normalized
    if isinstance(value, (list, tuple)):
        items = [_normalize(item, set_like_fields=set_like_fields) for item in value]
        if field in set_like_fields:
            encoded = [(canonical_json_bytes(item, set_like_fields=set_like_fields), item) for item in items]
            encoded.sort(key=lambda pair: pair[0])
            if any(encoded[index - 1][0] == encoded[index][0] for index in range(1, len(encoded))):
                raise CanonicalizationError(f"duplicate value in set-like field: {field}")
            return [item for _, item in encoded]
        return items
    raise CanonicalizationError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Any, *, set_like_fields: Iterable[str] = ()) -> bytes:
    normalized = _normalize(value, set_like_fields=frozenset(set_like_fields))
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError) as error:
        raise CanonicalizationError(str(error)) from error


def event_replay_projection(event: Any) -> dict[str, Any]:
    """Canonical caller-controlled event identity used for Journal replay.

    Stream coordinates and Journal authentication are assigned by the
    Journal, so they are intentionally excluded.  This function is shared by
    live append and Fast Start checkpointing; keeping one projection prevents
    schema drift and Python's ``1 == True`` coercion from changing identity.
    """
    if not isinstance(event, EventEnvelope):
        raise TypeError("event replay projection requires an EventEnvelope")
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "tenant_id": event.tenant_id,
        "stream_id": event.stream_id,
        "occurred_at": event.occurred_at,
        "payload": dict(event.payload),
        "object_refs": list(event.object_refs),
    }


def event_replay_projection_bytes(events: Sequence[EventEnvelope] | Sequence[Mapping[str, Any]]) -> bytes:
    """Return canonical bytes for an ordered event projection sequence."""
    values: list[dict[str, Any]] = []
    for event in events:
        if isinstance(event, EventEnvelope):
            values.append(event_replay_projection(event))
        elif isinstance(event, Mapping):
            # Checkpoint entries are already the shared projection.  Rebuild
            # the exact field set so an added/removed field cannot hide in a
            # dict comparison.
            required = ("event_id", "event_type", "tenant_id", "stream_id", "occurred_at", "payload", "object_refs")
            if set(event) != set(required):
                raise JournalModelError("event replay projection schema is invalid")
            values.append({key: event[key] for key in required})
        else:
            raise TypeError("event replay projection requires event mappings")
    return b"SITINA-JOURNAL-EVENT-REPLAY-V1\0" + canonical_json_bytes(values)


def event_replay_projection_hash(events: Sequence[EventEnvelope] | Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(event_replay_projection_bytes(events)).hexdigest()


def proof_manifest_bytes(manifest: Sequence[Mapping[str, Any]]) -> bytes:
    """Canonical proof identity shared by append, frames, and checkpoints.

    Proof freshness is deliberately absent.  The identity contains only the
    authenticated object/envelope/purpose binding, so an exact replay cannot
    be changed by a new lease or receipt timestamp.  The domain prefix keeps
    proof identity separate from event identity and makes JSON type changes
    (for example ``1`` versus ``True``) observable.
    """
    return b"SITINA-JOURNAL-PROOF-REPLAY-V1\0" + canonical_json_bytes(
        [dict(item) for item in manifest]
    )


def proof_manifest_hash(manifest: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(proof_manifest_bytes(manifest)).hexdigest()


def acceptance_event_projection_hash(events: Sequence[Mapping[str, Any]]) -> str:
    """Hash the complete stable payload of an acceptance pair.

    Journal-assigned coordinates, actor plumbing, command causation and the
    Journal authentication envelope are deliberately excluded.  Every field
    authored by the acceptance operation remains, so adding, removing or
    changing a candidate/package/Gate binding changes the commitment.  Both
    the authority host and LocalJournal call this function.
    """
    dynamic = frozenset({
        "causation_command_id", "acceptance_command_id", "authority_operation",
        "runtime_namespace", "actor_id", "policy_hash", "fact_hash",
    })
    stable: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, Mapping):
            raise JournalModelError("acceptance event projection requires mappings")
        # These are logical conversation bindings, not Journal coordinates.
        # They must be present in every acceptance event and retain their JSON
        # types: Python equality would otherwise make 1 and True equivalent.
        if not isinstance(event.get("session_id"), str) or not event.get("session_id"):
            raise JournalModelError("acceptance event session binding is required")
        if type(event.get("turn_index")) is not int or event.get("turn_index") < 0:
            raise JournalModelError("acceptance event turn binding is required")
        value = {str(key): item for key, item in event.items() if key not in dynamic}
        stable.append(value)
    return hashlib.sha256(
        b"SITINA-CODE-MODE-ACCEPTANCE-EVENTS-V2\0" + canonical_json_bytes(stable)
    ).hexdigest()


def planned_operation_projection(operation: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable, typed identity of a Code Mode logical operation.

    Physical Journal coordinates are deliberately absent.  The projection is
    shared by the authority host and Journal so a plan cannot be verified with
    Python's permissive mapping equality or a different JSON encoder.
    """
    if not isinstance(operation, Mapping):
        raise JournalModelError("logical operation must be an object")
    required = {
        "operation", "stream_id", "run_id", "generation",
        "expected_start_version", "expected_end_version",
        "parent_logical_hash", "event_count", "event_schema_order",
        "event_projection_hash", "proof_manifest_hash", "proof_purpose_order",
        "cas_object_hashes", "frontier_commitment", "logical_binding",
        "logical_event_projection",
    }
    optional = {
        # A stage authority may commit the complete actual projection before
        # the planned append.  These fields are commitments, never caller
        # supplied verification results; LocalJournal independently derives
        # and compares them from the submitted events/proofs.
        "stage_actual_event_projection",
        "stage_actual_event_projection_hash",
        "stage_actual_proof_manifest",
        "stage_actual_proof_manifest_hash",
        "stage_draft_ref",
        "stage_draft_hash",
        # Each stage has a separately signed, pre-acceptance transaction
        # commitment.  Its signature is validated against the pinned host
        # key by LocalJournal; the transaction is deliberately excluded from
        # the logical-operation hash to avoid a self-reference.
        "stage_transaction",
        "stage_transaction_hash",
    }
    if set(operation) - (required | optional | {"logical_operation_id", "logical_operation_hash", "bindings", "conversation_binding"}):
        raise JournalModelError("logical operation contains unknown fields")
    result = {
        key: operation.get(key)
        for key in sorted(required | (set(operation) & optional) - {"stage_transaction", "stage_transaction_hash"})
    }
    return result


def planned_operation_hash(operation: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes({
            "domain": "SITINA-CODE-MODE-LOGICAL-OPERATION-V1",
            "logical": planned_operation_projection(operation),
        })
    ).hexdigest()


def _pairs_to_value(value: Any) -> Any:
    if isinstance(value, _Pairs):
        result: dict[str, Any] = {}
        for key, item in value:
            normalized = _normalize_string(key)
            if normalized in result:
                raise CanonicalizationError(f"duplicate object member: {normalized}")
            result[normalized] = _pairs_to_value(item)
        return result
    if isinstance(value, list):
        return [_pairs_to_value(item) for item in value]
    return value


def parse_canonical_json(raw: bytes, *, allowed_fields: Iterable[str] | None = None) -> Any:
    if not isinstance(raw, bytes):
        raise TypeError("canonical input must be bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalizationError("invalid UTF-8") from error

    def reject_float(_value: str) -> None:
        raise CanonicalizationError("floating point values are forbidden")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_Pairs,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except json.JSONDecodeError as error:
        raise CanonicalizationError(str(error)) from error
    value = _pairs_to_value(parsed)
    normalized = _normalize(value, set_like_fields=frozenset())
    if canonical_json_bytes(normalized) != raw:
        raise CanonicalizationError("persisted JSON bytes are not canonical")
    if allowed_fields is not None:
        if not isinstance(normalized, dict):
            raise CanonicalizationError("schema-bound value must be an object")
        unknown = normalized.keys() - set(allowed_fields)
        if unknown:
            raise CanonicalizationError(f"unknown fields: {sorted(unknown)}")
    return normalized


def domain_hash(domain: str, payload: bytes) -> str:
    if not re.fullmatch(r"[A-Z0-9_]+", domain):
        raise ValueError("hash domain must be uppercase ASCII")
    return hashlib.sha256(b"SITINA-BPLUS-V1\0" + domain.encode("ascii") + b"\0" + payload).hexdigest()


def canonical_payload_hash(
    payload: Mapping[str, Any], *, self_field: str = "content_hash", domain: str = "SITINA-CANONICAL-PAYLOAD-V1"
) -> str:
    """Hash a typed payload without its self-referential identity field.

    This is deliberately a pure projection helper.  It performs no CAS or
    Journal verification and never returns a "verified" result.  Callers must
    still authenticate the object and bind the returned hash to its typed
    locator.  Keeping this projection here prevents candidate/package/host
    code from silently choosing different self-hash or JSON semantics.
    """
    if not isinstance(payload, Mapping):
        raise JournalModelError("canonical payload hash requires an object")
    if not isinstance(self_field, str) or not self_field:
        raise JournalModelError("canonical payload self field is invalid")
    body = {str(key): value for key, value in payload.items() if key != self_field}
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_json_bytes(body)).hexdigest()


def candidate_payload_hash(payload: Mapping[str, Any]) -> str:
    """Return the candidate manifest payload identity, excluding content_hash."""
    return payload_self_hash(payload)


def payload_self_hash(payload: Mapping[str, Any], *, self_field: str = "content_hash") -> str:
    """Return the plain SHA-256 identity of a canonical self-hashed payload.

    This is intentionally not a proof or verification result.  It is the
    single byte-level projection used by CAS publishers and reopeners for
    payloads whose self identity is stored in ``self_field``.  Authentication
    and typed-role checks remain the caller's responsibility.
    """
    if not isinstance(payload, Mapping) or not isinstance(self_field, str) or not self_field:
        raise JournalModelError("payload self hash requires an object and field")
    body = {str(key): value for key, value in payload.items() if key != self_field}
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def code_mode_gate_projection(
    *, run_id: str, generation: str, candidate_id: str, tree_hash: str,
    session_id: str, session_instance_id: str, run_attempt: int,
    turn_index: int, package_hash: str, core_hash: str,
    provider_profile: str, provider_model: str,
    authorization_ref: str | None = None,
) -> dict[str, Any]:
    """Build the deterministic Code Mode Gate fact projection.

    The function performs no I/O and does not assert that the result is
    trusted.  Host/runtime/Journals must independently reopen their inputs
    and compare this exact canonical projection.
    """
    values = {
        "schema": "CODE_MODE_GATE_FACT_V1",
        "status": "CODE_MODE_READY",
        "gate_identity": "code-mode-acceptance-v1",
        "issuer_identity": "code-mode-gate-v1",
        "authority_class": "CODE_MODE_GATE_AUTHORITY",
        "run_id": run_id,
        "generation": generation,
        "candidate_id": candidate_id,
        "tree_hash": tree_hash,
        "session_id": session_id,
        "session_instance_id": session_instance_id,
        "run_attempt": run_attempt,
        "turn_index": turn_index,
        "package_hash": package_hash,
        "core_hash": core_hash,
        "provider_profile": provider_profile,
        "provider_model": provider_model,
    }
    if authorization_ref is not None:
        if not isinstance(authorization_ref, str) or not authorization_ref:
            raise JournalModelError("Code Mode Gate authorization binding is invalid")
        values["authorization_ref"] = authorization_ref
    values["content_hash"] = payload_self_hash(values)
    return values


def typed_locator_projection(
    *, role: str, reference_id: str, object_id: str, plaintext_commitment: str, payload_hash: str | None = None
) -> dict[str, Any]:
    """Build the address-only CAS identity shared by Code Mode producers.

    Object identity, plaintext commitment, and payload self-hash are separate
    fields by design.  This function only canonicalizes caller-independent
    values; it does not inspect storage or assert that a locator is valid.
    """
    if not isinstance(role, str) or not role:
        raise JournalModelError("typed locator role is required")
    if not isinstance(reference_id, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", reference_id):
        raise JournalModelError("typed locator reference is invalid")
    if not isinstance(object_id, str) or not re.fullmatch(r"[0-9a-f]{64}", object_id):
        raise JournalModelError("typed locator object identity is invalid")
    if reference_id != "cas:" + object_id:
        raise JournalModelError("typed locator reference/object identity mismatch")
    if not isinstance(plaintext_commitment, str) or not re.fullmatch(r"[0-9a-f]{64}", plaintext_commitment):
        raise JournalModelError("typed locator plaintext commitment is invalid")
    result: dict[str, Any] = {
        "schema": "CODE_MODE_TYPED_LOCATOR_V2",
        "role": role,
        "reference_id": reference_id,
        "cas_object_id": object_id,
        "plaintext_commitment": plaintext_commitment,
    }
    if payload_hash is not None:
        if not isinstance(payload_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", payload_hash):
            raise JournalModelError("typed locator payload hash is invalid")
        result["payload_hash"] = payload_hash
    return result


def execution_authorization_attempt_ref(value: Mapping[str, Any]) -> str:
    """Derive the stable identity of one rework authorization projection."""
    fields = (
        "session_instance_id", "session_id", "run_id", "run_attempt",
        "workspace", "execution_root", "intent_hash", "plan_hash",
        "risk_level", "scope", "before_hashes_ref", "before_hashes_hash",
        "previous_authorization_ref", "prior_plan_hash", "prior_failure_type",
        "prior_failure_hash", "replan_plan_ref", "replan_plan_hash",
        "replan_plan",
    )
    projection = {key: value[key] for key in fields if key in value}
    return "execution-authorization:" + domain_hash(
        "SITINA_EXECUTION_AUTHORIZATION_ATTEMPT", canonical_json_bytes(projection)
    )


def durable_code_mode_authorization_projection(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the non-secret Code Mode authorization projection.

    The live authorization held by the controller may contain the opaque
    session token.  Durable facts never do: the only persisted token
    commitment is its SHA-256 digest.  This is the one projection used for
    both the run-created snapshot and every attempt-advance mapping.
    """
    if not isinstance(value, Mapping):
        raise JournalModelError("Code Mode authorization projection is not a mapping")
    if "authorization_token" in value:
        token = value.get("authorization_token")
        if type(token) is not str or not token:
            raise JournalModelError("Code Mode authorization token is invalid")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        supplied_hash = value.get("authorization_token_hash")
        if supplied_hash is not None and supplied_hash != token_hash:
            raise JournalModelError("Code Mode authorization token commitment changed")
    else:
        token_hash = value.get("authorization_token_hash")
        if type(token_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", token_hash):
            raise JournalModelError("Code Mode authorization token commitment is missing")
    result = {
        key: item for key, item in value.items()
        if key != "authorization_token"
    }
    result["authorization_token_hash"] = token_hash
    if "authorization_token" in result:
        raise JournalModelError("Code Mode authorization token is not durable")
    return result


def validate_identifier(value: str, *, field: str = "identifier", max_bytes: int = 255) -> str:
    if not isinstance(value, str) or value != value.strip() or unicodedata.normalize("NFC", value) != value:
        raise JournalModelError(f"{field} must be a trimmed NFC string")
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= max_bytes or not _ID.fullmatch(value) or ".." in value or "\0" in value:
        raise JournalModelError(f"invalid {field}")
    return value


def validate_timestamp(value: str) -> str:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise JournalModelError("timestamp must be RFC3339 UTC")
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise JournalModelError("invalid calendar timestamp") from error
    return value


@dataclass(frozen=True)
class FrontierRef:
    journal_id: str
    epoch: int
    shard: str
    position: int
    commitment: str

    def __post_init__(self) -> None:
        validate_identifier(self.journal_id, field="journal_id")
        validate_identifier(self.shard, field="shard")
        if self.epoch < 1 or self.position < 0:
            raise JournalModelError("invalid frontier coordinate")
        if not re.fullmatch(r"[0-9a-f]{64}", self.commitment):
            raise JournalModelError("invalid frontier commitment")


class JournalAuthenticator(Protocol):
    def authenticate(self, journal_id: str, epoch: int, event_hash: str) -> tuple[str, str]: ...

    def verify(self, journal_id: str, epoch: int, key_id: str, event_hash: str, tag: str) -> bool: ...


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    tenant_id: str
    stream_id: str
    stream_version: int
    position: int
    occurred_at: str
    payload: Mapping[str, Any]
    object_refs: tuple[str, ...] = ()
    schema_major: int = 1
    event_hash: str | None = None
    journal_auth_key_id: str | None = None
    journal_auth_tag: str | None = None

    _CORE_FIELDS = frozenset(
        {"schema_major", "event_id", "event_type", "tenant_id", "stream_id", "stream_version", "position", "occurred_at", "payload", "object_refs"}
    )
    _STORED_FIELDS = _CORE_FIELDS | {"event_hash", "journal_auth_key_id", "journal_auth_tag"}

    def __post_init__(self) -> None:
        if self.schema_major != 1:
            raise JournalModelError("unknown event major version")
        for value, field in (
            (self.event_id, "event_id"), (self.event_type, "event_type"), (self.tenant_id, "tenant_id"), (self.stream_id, "stream_id")
        ):
            validate_identifier(value, field=field)
        if self.stream_version < 0 or self.position < 0:
            raise JournalModelError("event coordinates cannot be negative")
        validate_timestamp(self.occurred_at)
        if not isinstance(self.payload, Mapping):
            raise JournalModelError("event payload must be an object")
        canonical_json_bytes(dict(self.payload))
        normalized_refs = tuple(sorted(self.object_refs))
        if normalized_refs != self.object_refs or len(set(self.object_refs)) != len(self.object_refs):
            raise JournalModelError("object references must be unique and sorted")
        for reference in self.object_refs:
            validate_identifier(reference, field="object_ref")
        present = (self.event_hash, self.journal_auth_key_id, self.journal_auth_tag)
        if any(item is not None for item in present) and not all(item is not None for item in present):
            raise JournalModelError("event hash and auth fields must be all present or all absent")
        if self.event_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", self.event_hash):
            raise JournalModelError("invalid event hash")
        if self.journal_auth_tag is not None and not re.fullmatch(r"[0-9a-f]{64}", self.journal_auth_tag):
            raise JournalModelError("invalid Journal auth tag")

    def core_mapping(self) -> dict[str, Any]:
        return {
            "schema_major": self.schema_major,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "stream_id": self.stream_id,
            "stream_version": self.stream_version,
            "position": self.position,
            "occurred_at": self.occurred_at,
            "payload": dict(self.payload),
            "object_refs": list(self.object_refs),
        }

    def canonical_bytes_for_hash(self) -> bytes:
        return canonical_json_bytes(self.core_mapping(), set_like_fields={"object_refs"})

    @property
    def computed_event_hash(self) -> str:
        return domain_hash("EVENT_CORE", self.canonical_bytes_for_hash())

    def assign(self, *, stream_version: int, position: int) -> "EventEnvelope":
        if self.event_hash is not None:
            raise JournalModelError("cannot reassign a sealed event")
        return replace(self, stream_version=stream_version, position=position)

    def seal(self, *, journal_id: str, epoch: int, authenticator: JournalAuthenticator) -> "EventEnvelope":
        if self.event_hash is not None:
            raise JournalModelError("event is already sealed")
        event_hash = self.computed_event_hash
        key_id, tag = authenticator.authenticate(journal_id, epoch, event_hash)
        validate_identifier(key_id, field="journal_auth_key_id")
        return replace(self, event_hash=event_hash, journal_auth_key_id=key_id, journal_auth_tag=tag)

    def verify(self, *, journal_id: str, epoch: int, authenticator: JournalAuthenticator) -> bool:
        return bool(
            self.event_hash == self.computed_event_hash
            and self.journal_auth_key_id
            and self.journal_auth_tag
            and authenticator.verify(journal_id, epoch, self.journal_auth_key_id, self.event_hash, self.journal_auth_tag)
        )

    def stored_mapping(self) -> dict[str, Any]:
        if self.event_hash is None:
            raise JournalModelError("unsealed event cannot be stored")
        return {
            **self.core_mapping(),
            "event_hash": self.event_hash,
            "journal_auth_key_id": self.journal_auth_key_id,
            "journal_auth_tag": self.journal_auth_tag,
        }

    def canonical_stored_bytes(self) -> bytes:
        return canonical_json_bytes(self.stored_mapping(), set_like_fields={"object_refs"})

    @classmethod
    def from_stored_bytes(cls, raw: bytes) -> "EventEnvelope":
        value = parse_canonical_json(raw, allowed_fields=cls._STORED_FIELDS)
        if not isinstance(value, dict):
            raise JournalModelError("event must be an object")
        missing = cls._STORED_FIELDS - value.keys()
        if missing:
            raise JournalModelError(f"missing event fields: {sorted(missing)}")
        value["object_refs"] = tuple(value["object_refs"])
        return cls(**value)


def object_reference_manifest_hash(references: Sequence[str]) -> str:
    ordered = sorted(references)
    if len(set(ordered)) != len(ordered):
        raise JournalModelError("duplicate object reference")
    return domain_hash("OBJECT_REFERENCE_MANIFEST", canonical_json_bytes(ordered))


@dataclass(frozen=True)
class JournalTransaction:
    transaction_id: str
    command_id: str
    command_request_hash: str
    stream_id: str
    events: tuple[EventEnvelope, ...]
    object_references: tuple[str, ...] = ()
    # Transaction metadata, not an event-provided assertion. Only the
    # Journal's authenticated finalization entry point may set it.
    authenticated_seal_stream_id: str | None = None
    # Canonical proof identity is part of the durable transaction frame.  It
    # prevents command replay from validating a merely well-formed but
    # different proof (for example a different purpose or root-proof type).
    proof_manifest: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.transaction_id, field="transaction_id")
        validate_identifier(self.command_id, field="command_id")
        validate_identifier(self.stream_id, field="stream_id")
        if self.authenticated_seal_stream_id is not None:
            if self.authenticated_seal_stream_id != self.stream_id:
                raise JournalModelError("authenticated seal must name the transaction stream")
            validate_identifier(self.authenticated_seal_stream_id, field="authenticated_seal_stream_id")
        if not re.fullmatch(r"[0-9a-f]{64}", self.command_request_hash):
            raise JournalModelError("invalid command request hash")
        if not self.events:
            raise JournalModelError("transaction requires at least one event")
        if any(event.stream_id != self.stream_id for event in self.events):
            raise JournalModelError("one transaction may modify only one stream")
        positions = [event.position for event in self.events]
        versions = [event.stream_version for event in self.events]
        if positions != list(range(positions[0], positions[0] + len(positions))):
            raise JournalModelError("local positions must be contiguous")
        if versions != list(range(versions[0], versions[0] + len(versions))):
            raise JournalModelError("stream versions must be contiguous")
        derived = tuple(sorted({ref for event in self.events for ref in event.object_refs}))
        if tuple(self.object_references) != derived:
            raise JournalModelError("transaction object references must exactly equal event references")
        proof_refs = tuple(item.get("reference_id") for item in self.proof_manifest)
        if proof_refs != tuple(sorted(proof_refs)) or len(set(proof_refs)) != len(proof_refs):
            raise JournalModelError("transaction proof manifest references are not canonical")
        if tuple(proof_refs) != derived:
            raise JournalModelError("transaction proof manifest must exactly equal event references")
        proof_manifest_bytes(self.proof_manifest)

    @property
    def object_reference_manifest_hash(self) -> str:
        return object_reference_manifest_hash(self.object_references)

    @property
    def first_position(self) -> int:
        return self.events[0].position

    @property
    def last_position(self) -> int:
        return self.events[-1].position

    @property
    def first_stream_version(self) -> int:
        return self.events[0].stream_version

    @property
    def last_stream_version(self) -> int:
        return self.events[-1].stream_version


@dataclass(frozen=True)
class AppendReceipt:
    journal_id: str
    epoch: int
    transaction_id: str
    command_id: str
    command_request_hash: str
    stream_id: str
    first_position: int
    last_position: int
    first_stream_version: int
    last_stream_version: int
    transaction_hash: str
    object_reference_manifest_hash: str
    durability_profile: str = "MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1"

    @property
    def frontier(self) -> FrontierRef:
        return FrontierRef(self.journal_id, self.epoch, "local", self.last_position, self.transaction_hash)
