"""Provider-neutral structured output contracts.

The same immutable specification supplies the provider tool schema and the
local validator.  Contract identity is per task type; ``kind`` alone is not a
stable schema discriminator (for example, proposal is used for discovery and
candidate generation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class OutputContractError(ValueError):
    pass


@dataclass(frozen=True)
class OutputContractSpec:
    output_contract_id: str
    task_type: str
    schema_id: str
    required: tuple[str, ...]
    properties: Mapping[str, Mapping[str, Any]]
    additional_properties: bool = False

    def wire_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {key: dict(value) for key, value in self.properties.items()},
            "required": list(self.required),
            "additionalProperties": self.additional_properties,
        }


_ENVELOPE = {
    "agent_id": {"type": "string", "minLength": 1, "maxLength": 120},
    "kind": {"type": "string", "minLength": 1, "maxLength": 80},
}
_FAST_ANSWER = OutputContractSpec(
    "sitina.conversation-answer.v1", "conversation_answer", "SITINA_CONVERSATION_ANSWER_V1",
    ("agent_id", "kind", "answer", "confidence", "needs_multi", "escalation_reasons"),
    {
        **_ENVELOPE,
        "answer": {"type": "string", "minLength": 1, "maxLength": 12000},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "needs_multi": {"type": "boolean"},
        "escalation_reasons": {
            "type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 160},
            "maxItems": 8,
        },
    },
)
_DISCOVERY = OutputContractSpec(
    "sitina.goal-discovery.v1", "goal_discovery", "SITINA_GOAL_DISCOVERY_V1",
    ("agent_id", "kind", "complexity", "risk_level", "protocols", "task_graph",
     "proposal_count", "domain_capability", "requires_rework", "requires_conflict",
     "requires_handoff_reject", "requires_reassignment", "requires_provider_unknown", "rationale"),
    {
        **_ENVELOPE,
        "complexity": {"type": "string", "enum": ["simple", "standard", "high"]},
        "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
        "protocols": {"type": "array", "items": {"type": "string"}, "maxItems": 9},
        "task_graph": {"type": "array", "items": {"type": "string"}, "maxItems": 16},
        "proposal_count": {"type": "integer", "minimum": 1, "maximum": 16},
        "domain_capability": {"type": ["string", "null"], "maxLength": 160},
        **{key: {"type": "boolean"} for key in (
            "requires_rework", "requires_conflict", "requires_handoff_reject",
            "requires_reassignment", "requires_provider_unknown",
        )},
        "rationale": {"type": "string", "minLength": 1, "maxLength": 4000},
    },
)
_CANDIDATE = OutputContractSpec(
    "sitina.candidate-generation.v1", "candidate_generation", "SITINA_CANDIDATE_GENERATION_V1",
    ("agent_id", "kind", "summary", "approach", "risks", "assumptions", "acceptance_checks"),
    {
        **_ENVELOPE,
        "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
        "approach": {"type": "string", "minLength": 1, "maxLength": 8000},
        "risks": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "maxItems": 8}]},
        "assumptions": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "maxItems": 8}]},
        "acceptance_checks": {"type": "array", "items": {"type": "string"}, "maxItems": 12},
    },
)
_REVIEW = OutputContractSpec(
    "sitina.proposal-review.v1", "proposal_review", "SITINA_PROPOSAL_REVIEW_V1",
    ("agent_id", "kind", "verdict", "score", "reason", "defects"),
    {
        **_ENVELOPE,
        "verdict": {"type": "string", "enum": ["approved", "changes_requested", "rejected", "accept", "reject"]},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "reason": {"type": "string", "minLength": 1, "maxLength": 4000},
        "defects": {"type": "array", "items": {"type": "string"}, "maxItems": 16},
    },
)
_REVISION = OutputContractSpec(
    "sitina.proposal-revision.v1", "proposal_revision", "SITINA_PROPOSAL_REVISION_V1",
    ("agent_id", "kind", "parent_output_hash", "defect_responses"),
    {
        **_ENVELOPE,
        "parent_output_hash": {"type": "string", "minLength": 64, "maxLength": 64},
        "defect_responses": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"anyOf": [
            {"type": "string", "minLength": 1, "maxLength": 4000},
            {"type": "object", "properties": {
                "defect": {"type": "string", "minLength": 1, "maxLength": 4000},
                "response": {"type": "string", "minLength": 1, "maxLength": 4000},
            }, "required": ["defect", "response"], "additionalProperties": False},
            {"type": "object", "properties": {
                "objection": {"type": "string", "minLength": 1, "maxLength": 4000},
                "response": {"type": "string", "minLength": 1, "maxLength": 4000},
            }, "required": ["objection", "response"], "additionalProperties": False},
        ]}},
        "acceptance_checks": {"type": "array", "items": {"type": "string"}, "maxItems": 12},
        "summary": {"type": "string", "maxLength": 4000},
        "approach": {"type": "string", "maxLength": 8000},
    },
)
_EXECUTION_REVIEW = OutputContractSpec(
    "sitina.execution-review.v1", "execution_review", "SITINA_EXECUTION_REVIEW_V1",
    ("agent_id", "kind", "decision", "reason", "evidence_checks"),
    {
        **_ENVELOPE,
        "decision": {"type": "string", "enum": ["accept", "reject"]},
        "reason": {"type": "string", "minLength": 1, "maxLength": 4000},
        "evidence_checks": {"type": "array", "items": {"type": "string"}, "maxItems": 16},
    },
)
_EXECUTION_REPLAN = OutputContractSpec(
    "sitina.execution-replan.v1", "execution_replan", "SITINA_EXECUTION_REPLAN_V1",
    ("agent_id", "kind", "approach", "acceptance_checks"),
    {
        **_ENVELOPE,
        "approach": {"type": "string", "minLength": 1, "maxLength": 8000},
        "acceptance_checks": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 1000}, "minItems": 1, "maxItems": 8},
    },
)
_READONLY_ANSWER = OutputContractSpec(
    "sitina.readonly-answer.v1", "readonly_answer", "SITINA_READONLY_ANSWER_V1",
    ("agent_id", "kind", "claim_id", "evidence_hash", "answer_fragment"),
    {
        **_ENVELOPE,
        "claim_id": {"type": "string", "minLength": 1, "maxLength": 160},
        "evidence_hash": {"type": "string", "minLength": 64, "maxLength": 64},
        "answer_fragment": {"type": "string", "minLength": 1, "maxLength": 12000},
    },
)
_READONLY_REVIEW = OutputContractSpec(
    "sitina.readonly-review.v1", "readonly_review", "SITINA_READONLY_REVIEW_V1",
    ("agent_id", "kind", "verdict", "score", "reason", "defects", "verified_claim_ids"),
    {
        **_ENVELOPE,
        "verdict": {"type": "string", "enum": ["approved", "changes_requested", "reject"]},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "reason": {"type": "string", "minLength": 1, "maxLength": 4000},
        "defects": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "verified_claim_ids": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 160}, "minItems": 1, "maxItems": 128},
    },
)
_GENERIC = OutputContractSpec(
    "sitina.agent-envelope.v1", "agent_envelope", "SITINA_AGENT_ENVELOPE_V1",
    ("agent_id", "kind"), _ENVELOPE, additional_properties=True,
)

_TASK_SPECS: tuple[tuple[str, OutputContractSpec], ...] = (
    ("conversation-answer", _FAST_ANSWER),
    ("goal-discovery", _DISCOVERY),
    ("execution-review", _EXECUTION_REVIEW),
    ("execution-replan", _EXECUTION_REPLAN),
    ("readonly-answer", _READONLY_ANSWER),
    ("readonly-review", _READONLY_REVIEW),
    ("proposal-revision", _REVISION),
    ("review", _REVIEW),
    ("proposal", _CANDIDATE),
)

# A narrow seam for two pre-existing storage tests that exercise the low-level
# executor with a legacy negotiation task.  All production call sites now pass
# an explicit identity; unknown task IDs cannot silently receive a generic wire
# schema.
_LEGACY_COMPAT_PREFIXES = (
    "debate-final-review-", "handoff-contract-assessment-", "handoff-execution-generation-",
    "handoff-receive-generation-", "handoff-verification-generation-", "negotiation-round-2-",
)
_LEGACY_COMPAT_TASKS = frozenset({
    "arbitration", "blackboard-branch-a", "blackboard-branch-b", "blackboard-concurrent-collaborator",
    "blackboard-concurrent-writers", "blackboard-conflict-merge", "blackboard-continuation",
    "blackboard-continuation-current", "blackboard-downstream-consumer", "blackboard-merge-review",
    "handoff-receive", "independent-review", "integrated-reassigned-owner-transfer-source",
    "integrated-selected-owner-loss", "integrated-task-failover", "lease-owner-a-progress", "lease-work",
    "lease-work-reassignment", "post-invocation-start-worker-loss", "provider-explicit-remote-failure",
    "provider-recovery-owner", "provider-recovery-pre-send-failure", "provider-recovery-reassignment",
    "provider-timeout-after-invocation-started", "restart-provider-unknown-reconciliation",
})


def resolve_output_contract(task_id: str, kind: str, *, task_type: str | None = None,
                            output_contract_id: str | None = None,
                            schema_id: str | None = None,
                            allow_legacy_compat: bool = False) -> OutputContractSpec:
    if output_contract_id or task_type or schema_id:
        for _, spec in _TASK_SPECS:
            if (output_contract_id, task_type, schema_id) == (
                spec.output_contract_id, spec.task_type, spec.schema_id
            ):
                return spec
        if output_contract_id and task_type and schema_id and str(output_contract_id).startswith("sitina.legacy."):
            return OutputContractSpec(str(output_contract_id), str(task_type), str(schema_id),
                                      _GENERIC.required, _GENERIC.properties, True)
        raise OutputContractError("output contract identity is incomplete or unknown")
    lowered = str(task_id or "").casefold()
    if lowered == "conversation-answer":
        return _FAST_ANSWER
    if lowered == "goal-discovery":
        return _DISCOVERY
    if lowered.startswith("execution-review-"):
        return _EXECUTION_REVIEW
    if lowered.startswith("execution-replan-"):
        return _EXECUTION_REPLAN
    if lowered.startswith("readonly-answer-"):
        return _READONLY_ANSWER
    if lowered.startswith("readonly-review-"):
        return _READONLY_REVIEW
    if lowered.startswith("proposal-revision-"):
        return _REVISION
    if lowered.startswith("review-") or lowered.startswith("review-revision-"):
        return _REVIEW
    if lowered == "proposal-competition" or (lowered.startswith("proposal-") and lowered[9:].isdigit()):
        return _CANDIDATE
    if not allow_legacy_compat or (
        lowered not in _LEGACY_COMPAT_TASKS and not lowered.startswith(_LEGACY_COMPAT_PREFIXES)
    ):
        raise OutputContractError("critical Provider call requires an explicit output contract identity")
    return OutputContractSpec(
        f"sitina.legacy.{str(task_id).replace('_', '-')}.v1", str(task_id),
        f"SITINA_{str(task_id).upper().replace('-', '_')}_V1", _GENERIC.required,
        _GENERIC.properties, True,
    )


def is_critical_contract_task(task_id: str) -> bool:
    lowered = str(task_id or "").casefold()
    return (
        lowered == "conversation-answer"
        or lowered == "goal-discovery"
        or lowered == "proposal-competition"
        or lowered.startswith("proposal-") and lowered[9:].isdigit()
        or lowered.startswith("proposal-revision-")
        or lowered.startswith("review-")
        or lowered.startswith("execution-review-")
        or lowered.startswith("execution-replan-")
        or lowered.startswith("readonly-answer-")
        or lowered.startswith("readonly-review-")
    )


def validate_output_contract(value: Mapping[str, Any], spec: OutputContractSpec) -> None:
    if not isinstance(value, Mapping):
        raise OutputContractError("structured output is not an object")
    missing = [key for key in spec.required if key not in value]
    if missing:
        raise OutputContractError("output contract missing required fields: " + ",".join(missing))
    if not spec.additional_properties:
        unknown = set(value).difference(spec.properties)
        if unknown:
            raise OutputContractError("output contract has unknown fields: " + ",".join(sorted(unknown)))
    for key, schema in spec.properties.items():
        if key in value:
            _validate_schema(value[key], schema, key)


def _validate_schema(value: Any, schema: Mapping[str, Any], path: str) -> None:
    if "anyOf" in schema:
        errors = []
        for alternative in schema["anyOf"]:
            try:
                _validate_schema(value, alternative, path)
                return
            except OutputContractError as error:
                errors.append(error)
        raise OutputContractError(f"output contract field {path} has the wrong shape") from errors[-1]
    allowed_types = schema.get("type")
    if isinstance(allowed_types, list):
        type_ok = any(_json_type(value, name) for name in allowed_types)
    else:
        type_ok = _json_type(value, allowed_types) if allowed_types else True
    if not type_ok:
        raise OutputContractError(f"output contract field {path} has the wrong type")
    if isinstance(value, Mapping):
        required = schema.get("required", ())
        missing = [key for key in required if key not in value]
        if missing:
            raise OutputContractError(f"output contract field {path} is missing required fields")
        if schema.get("additionalProperties") is False:
            unknown = set(value).difference(schema.get("properties", {}))
            if unknown:
                raise OutputContractError(f"output contract field {path} has unknown fields")
        for key, child in (schema.get("properties") or {}).items():
            if key in value:
                _validate_schema(value[key], child, f"{path}.{key}")
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise OutputContractError(f"output contract field {path} is too short")
        if len(value) > int(schema.get("maxLength", 10**9)):
            raise OutputContractError(f"output contract field {path} is too long")
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            raise OutputContractError(f"output contract field {path} has too few items")
        if len(value) > int(schema.get("maxItems", 10**9)):
            raise OutputContractError(f"output contract field {path} has too many items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{index}]")
    if "enum" in schema and value not in schema["enum"]:
        raise OutputContractError(f"output contract field {path} has an invalid value")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]:
            raise OutputContractError(f"output contract field {path} is out of bounds")


def _json_type(value: Any, name: str | None) -> bool:
    return {
        "string": isinstance(value, str), "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool), "array": isinstance(value, list),
        "object": isinstance(value, Mapping), "null": value is None,
    }.get(str(name), True)


__all__ = ["OutputContractError", "OutputContractSpec", "resolve_output_contract", "validate_output_contract", "is_critical_contract_task"]
