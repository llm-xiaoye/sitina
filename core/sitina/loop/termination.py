from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.security.redaction import redact_text


TERMINATION_CONTRACT_VERSION = "sitina-termination-v1"

COUNT_NEUTRAL = "COUNT_NEUTRAL"
COUNT_NO_PROGRESS = "NO_PROGRESS"
COUNT_PROGRESSED = "PROGRESSED"
COUNT_EFFECTS = frozenset({COUNT_NEUTRAL, COUNT_NO_PROGRESS, COUNT_PROGRESSED})
REVIEW_SCHEMA_V2 = "SITINA_LOOP_REVIEW_V2"
REVIEW_RESPONSE_FIELDS = (
    "schema",
    "termination_contract_version",
    "acceptance_item_id",
    "review_subject_lineage",
    "observed_artifact_ref",
    "verdict",
    "reason",
    "findings",
)
REVIEW_FINDING_FIELDS = (
    "stable_issue_id",
    "issue_slot_id",
    "rule_id",
    "locus_id",
    "object_id",
    "finding_code",
    "disposition",
    "evidence_refs",
    "summary",
)
REVIEW_FINDING_DISPOSITIONS = ("OPEN", "RESOLVED", "NOT_APPLICABLE")
REVIEW_ISSUE_INVENTORY_INSTRUCTION = (
    "Every item in response_contract.persisted_issue_inventory must appear exactly once in findings, even for PASS. "
    "Preserve its stable_issue_id, issue_slot_id, rule_id, locus_id, object_id and finding_code. "
    "Use OPEN while unresolved; RESOLVED only when read evidence proves a changed bound object or a new "
    "host-linked relevant fact; NOT_APPLICABLE only after a persisted criteria-lineage change. "
    "Cite verified evidence_refs and explain the change in summary. Never omit an issue to produce PASS. "
    "New issues use stable_issue_id=null and OPEN."
)
REVIEW_REPAIR_KINDS = frozenset({"FORMAT_INVALID", "EVIDENCE_MISSING", "IDENTITY_ALIGNMENT"})
REVIEW_FINDING_CODES = frozenset({
    "ARTIFACT_REQUIREMENT_MISMATCH",
    "PROGRAM_RESULT_MISMATCH",
    "EVIDENCE_INSUFFICIENT",
})
CHILD_CONTRACT_SCHEMA = "SITINA_LOOP_CHILD_CONTRACT_V1"


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, float):
        return repr(value)
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            _canonical(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class ReviewProtocolError(ValueError):
    def __init__(self, kind: str, message: str, *, unread_source_refs: tuple[str, ...] = ()):
        if kind not in REVIEW_REPAIR_KINDS:
            raise ValueError("review protocol error kind is invalid")
        super().__init__(message)
        self.kind = kind
        self.unread_source_refs = unread_source_refs


def review_subject_lineage(task_id: str, acceptance_item_id: str) -> str:
    if not task_id.strip() or not acceptance_item_id.strip():
        raise ValueError("review subject lineage requires task and acceptance identities")
    return "review-subject:" + _digest({
        "task_id": task_id,
        "acceptance_item_id": acceptance_item_id,
    })


def review_rule_manifest(
    acceptance_item_id: str,
    *,
    program_method_id: str | None,
    object_ids: Sequence[str] = ("workspace-root",),
    issue_slots_per_rule: int = 16,
    registered_issue_slots: Mapping[str, Sequence[str]] | None = None,
) -> tuple[dict[str, Any], ...]:
    if not acceptance_item_id.strip() or issue_slots_per_rule < 2:
        raise ValueError("review manifest requires an acceptance item and at least two issue slots")
    stable_objects = tuple(dict.fromkeys(str(item) for item in object_ids if str(item).strip()))
    if not stable_objects:
        stable_objects = ("workspace-root",)
    registered_issue_slots = registered_issue_slots or {}

    def rule(rule_id: str, locus_id: str, finding_code: str) -> dict[str, Any]:
        prior_slots = tuple(dict.fromkeys(str(item) for item in registered_issue_slots.get(rule_id, ())))
        slot_prefix = f"{rule_id}:issue-slot-"
        used_numbers = [
            int(item.removeprefix(slot_prefix))
            for item in prior_slots
            if item.startswith(slot_prefix) and item.removeprefix(slot_prefix).isdigit()
        ]
        first_new = max(used_numbers, default=0) + 1
        return {
            "rule_id": rule_id,
            "locus_id": locus_id,
            "allowed_object_ids": list(stable_objects),
            "allowed_finding_codes": [finding_code],
            # Slots are host-issued opaque identities.  They allow independent
            # defects under one predicate/object without deriving identity from
            # reviewer prose.  Once a slot is registered, later reviews must use
            # its persisted stable_issue_id.
            "issue_slot_ids": [
                *prior_slots,
                *(f"{rule_id}:issue-slot-{index:04d}" for index in range(first_new, first_new + issue_slots_per_rule)),
            ],
        }

    rules = [
        rule(
            f"acceptance:{acceptance_item_id}:artifact",
            "workspace-artifact",
            "ARTIFACT_REQUIREMENT_MISMATCH",
        ),
        rule(
            f"acceptance:{acceptance_item_id}:evidence",
            "required-evidence-bundle",
            "EVIDENCE_INSUFFICIENT",
        ),
    ]
    if program_method_id:
        rules.append(rule(
            f"acceptance:{acceptance_item_id}:program:{program_method_id}",
            "program-check-result",
            "PROGRAM_RESULT_MISMATCH",
        ))
    return tuple(rules)


def stable_review_issue_id(
    *,
    criteria_lineage_id: str,
    acceptance_item_id: str,
    review_subject_lineage_id: str,
    rule_id: str,
    locus_id: str,
    object_id: str,
    issue_slot_id: str,
    finding_code: str,
) -> str:
    values = (
        criteria_lineage_id,
        acceptance_item_id,
        review_subject_lineage_id,
        rule_id,
        locus_id,
        object_id,
        issue_slot_id,
        finding_code,
    )
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("stable review issue identity fields are required")
    if finding_code not in REVIEW_FINDING_CODES:
        raise ValueError("review finding code is not host-recognized")
    return "review-issue:" + _digest({
        "termination_contract_version": TERMINATION_CONTRACT_VERSION,
        "criteria_lineage_id": criteria_lineage_id,
        "acceptance_item_id": acceptance_item_id,
        "review_subject_lineage": review_subject_lineage_id,
        "rule_id": rule_id,
        "locus_id": locus_id,
        "object_id": object_id,
        "issue_slot_id": issue_slot_id,
        "finding_code": finding_code,
    })


def validate_review_document_contract(
    document: Mapping[str, Any],
    *,
    acceptance_item_id: str,
    review_subject_lineage_id: str,
    observed_artifact_ref: str,
    criteria_lineage_id: str,
    rules: Sequence[Mapping[str, Any]],
    unresolved_issues: Mapping[str, Mapping[str, Any]],
    completion_requirements: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    required_fields = set(REVIEW_RESPONSE_FIELDS)
    if set(document) != required_fields:
        raise ReviewProtocolError("FORMAT_INVALID", "review response fields are not exact")
    if (
        document.get("schema") != REVIEW_SCHEMA_V2
        or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
    ):
        raise ReviewProtocolError("FORMAT_INVALID", "new review response requires the current V2 contract")
    mismatches = {}
    for field, expected in (
        ("acceptance_item_id", acceptance_item_id),
        ("review_subject_lineage", review_subject_lineage_id),
        ("observed_artifact_ref", observed_artifact_ref),
    ):
        returned = document.get(field)
        if returned != expected:
            # Only the existing digest identities have a safe historical form.
            # A different acceptance item is not established by this contract.
            identity_pattern = {
                "observed_artifact_ref": r"cas:[0-9a-f]{64}",
                "review_subject_lineage": r"review-subject:[0-9a-f]{64}",
            }.get(field)
            visible = (
                returned if identity_pattern is not None and isinstance(returned, str)
                and re.fullmatch(identity_pattern, returned) is not None
                and redact_text(returned) == returned
                else "<non-identity value>"
            )
            mismatches[field] = {"expected": expected, "returned": visible}
    if mismatches:
        raise ReviewProtocolError(
            "IDENTITY_ALIGNMENT",
            "review response binding is invalid: "
            + json.dumps(mismatches, ensure_ascii=True, separators=(",", ":")),
        )
    verdict = document.get("verdict")
    reason = document.get("reason")
    findings = document.get("findings")
    if (
        verdict not in {"PASS", "BLOCK", "NEEDS_EVIDENCE"}
        or not isinstance(reason, str)
        or not reason.strip()
        or not isinstance(findings, list)
    ):
        raise ReviewProtocolError("FORMAT_INVALID", "review verdict, reason, or findings are invalid")

    rule_index = {
        str(rule["rule_id"]): {
            "locus_id": str(rule["locus_id"]),
            "allowed_object_ids": tuple(str(item) for item in rule["allowed_object_ids"]),
            "allowed_finding_codes": tuple(str(item) for item in rule["allowed_finding_codes"]),
            "issue_slot_ids": tuple(str(item) for item in rule["issue_slot_ids"]),
        }
        for rule in rules
    }
    canonical_findings: list[dict[str, Any]] = []
    seen_issue_ids: set[str] = set()
    completion_observed: set[str] = set()
    completion_requirements = completion_requirements or {}
    for raw in findings:
        finding_fields = set(REVIEW_FINDING_FIELDS)
        if not isinstance(raw, Mapping):
            raise ReviewProtocolError("FORMAT_INVALID", "review finding must be an object with the exact declared fields")
        if set(raw) != finding_fields:
            missing = sorted(finding_fields - set(raw))
            unexpected = sorted(str(key) for key in set(raw) - finding_fields)
            raise ReviewProtocolError(
                "FORMAT_INVALID",
                "review finding fields are not exact: missing="
                + json.dumps(missing) + "; unexpected=" + json.dumps(unexpected),
            )
        rule_id = str(raw.get("rule_id") or "")
        locus_id = str(raw.get("locus_id") or "")
        object_id = str(raw.get("object_id") or "")
        issue_slot_id = str(raw.get("issue_slot_id") or "")
        finding_code = str(raw.get("finding_code") or "")
        rule = rule_index.get(rule_id)
        if (
            rule is None
            or locus_id != rule["locus_id"]
            or object_id not in rule["allowed_object_ids"]
            or issue_slot_id not in rule["issue_slot_ids"]
            or finding_code not in rule["allowed_finding_codes"]
        ):
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "review finding is not one of the host-issued reviewable predicates",
            )
        disposition = str(raw.get("disposition") or "")
        evidence_refs = raw.get("evidence_refs")
        summary = raw.get("summary")
        if (
            disposition not in REVIEW_FINDING_DISPOSITIONS
            or not isinstance(evidence_refs, list)
            or not evidence_refs
            or any(not isinstance(item, str) or not item for item in evidence_refs)
            or len(set(evidence_refs)) != len(evidence_refs)
            or not isinstance(summary, str)
            or not summary.strip()
        ):
            raise ReviewProtocolError("FORMAT_INVALID", "review finding values are invalid")
        completion_requirement = completion_requirements.get(rule_id)
        proposed_issue_id = raw.get("stable_issue_id")
        if proposed_issue_id is not None and not isinstance(proposed_issue_id, str):
            raise ReviewProtocolError("FORMAT_INVALID", "review issue identity must be a string or null")
        if completion_requirement is not None:
            # A host-issued current condition is not an existing review issue.
            # Only this explicit completion call can use a positive observation
            # in an unregistered slot; independent review semantics stay intact.
            if (
                proposed_issue_id not in {None, ""}
                or issue_slot_id != completion_requirement["issue_slot_id"]
                or object_id != completion_requirement["object_id"]
                or locus_id != completion_requirement["locus_id"]
                or disposition not in {"OPEN", "RESOLVED"}
                or rule_id in completion_observed
            ):
                raise ReviewProtocolError("IDENTITY_ALIGNMENT", "invalid current condition observation")
            completion_observed.add(rule_id)
            canonical_findings.append({
                **dict(raw), "stable_issue_id": None,
                "criteria_lineage_id": criteria_lineage_id,
                "completion_condition_id": completion_requirement["condition_id"],
            })
            continue
        registered = (
            unresolved_issues.get(str(proposed_issue_id))
            if isinstance(proposed_issue_id, str) and proposed_issue_id
            else None
        )
        identity_criteria_lineage = str(
            registered.get("criteria_lineage_id") if registered is not None else criteria_lineage_id
        )
        expected_issue_id = stable_review_issue_id(
            criteria_lineage_id=identity_criteria_lineage,
            acceptance_item_id=acceptance_item_id,
            review_subject_lineage_id=review_subject_lineage_id,
            rule_id=rule_id,
            locus_id=locus_id,
            object_id=object_id,
            issue_slot_id=issue_slot_id,
            finding_code=finding_code,
        )
        if proposed_issue_id and registered is None:
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "review supplied an issue identity absent from the persisted inventory",
            )
        if registered is not None and proposed_issue_id != expected_issue_id:
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "review must retain the persisted identity for an existing issue slot",
            )
        if registered is None and proposed_issue_id not in {None, ""}:
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "a new issue must use an unregistered host slot without inventing an identity",
            )
        if registered is None and disposition != "OPEN":
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "an unregistered issue slot can only introduce an OPEN issue",
            )
        if registered is not None and disposition == "NOT_APPLICABLE" and (
            registered.get("criteria_lineage_id") in {None, criteria_lineage_id}
        ):
            raise ReviewProtocolError(
                "IDENTITY_ALIGNMENT",
                "NOT_APPLICABLE requires a persisted criteria-lineage change",
            )
        if expected_issue_id in seen_issue_ids:
            raise ReviewProtocolError("FORMAT_INVALID", "review response duplicates a stable issue")
        seen_issue_ids.add(expected_issue_id)
        canonical_findings.append({
            "stable_issue_id": expected_issue_id,
            "issue_slot_id": issue_slot_id,
            "rule_id": rule_id,
            "locus_id": locus_id,
            "object_id": object_id,
            "finding_code": finding_code,
            "disposition": disposition,
            "evidence_refs": list(evidence_refs),
            "criteria_lineage_id": identity_criteria_lineage,
            "summary": summary,
        })

    missing_inventory = sorted(
        issue_id
        for issue_id, issue in unresolved_issues.items()
        if issue.get("status") == "OPEN" and issue_id not in seen_issue_ids
    )
    if missing_inventory:
        raise ReviewProtocolError(
            "IDENTITY_ALIGNMENT",
            "review omitted unresolved issue inventory: " + ", ".join(missing_inventory),
        )
    open_findings = [item for item in canonical_findings if item["disposition"] == "OPEN"]
    if verdict == "PASS" and open_findings:
        raise ReviewProtocolError("FORMAT_INVALID", "PASS review cannot contain an open finding")
    if verdict in {"BLOCK", "NEEDS_EVIDENCE"} and not open_findings:
        raise ReviewProtocolError("FORMAT_INVALID", "non-PASS review requires an open finding")
    return {
        **dict(document),
        "findings": canonical_findings,
        "criteria_lineage_id": criteria_lineage_id,
    }


def validate_review_document(
    document: Mapping[str, Any],
    *,
    acceptance_item_id: str,
    review_subject_lineage_id: str,
    observed_artifact_ref: str,
    criteria_lineage_id: str,
    rules: Sequence[Mapping[str, Any]],
    queried_source_refs: Sequence[str],
    unresolved_issues: Mapping[str, Mapping[str, Any]],
    source_facts: Mapping[str, Mapping[str, Any]] | None = None,
    object_fingerprints: Mapping[str, str] | None = None,
    completion_requirements: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    canonical = validate_review_document_contract(
        document, acceptance_item_id=acceptance_item_id,
        review_subject_lineage_id=review_subject_lineage_id,
        observed_artifact_ref=observed_artifact_ref,
        criteria_lineage_id=criteria_lineage_id, rules=rules,
        unresolved_issues=unresolved_issues,
        completion_requirements=completion_requirements,
    )
    queried = set(queried_source_refs)
    source_facts = source_facts or {}
    object_fingerprints = object_fingerprints or {}
    completion_requirements = completion_requirements or {}
    for raw, finding in zip(document["findings"], canonical["findings"]):
        rule_id = finding["rule_id"]
        object_id = finding["object_id"]
        disposition = finding["disposition"]
        evidence_refs = finding["evidence_refs"]
        completion_requirement = completion_requirements.get(rule_id)
        if finding["finding_code"] == "CAPABILITY_UNAVAILABLE":
            eligible_blocks = set((completion_requirement or {}).get("capability_block_source_refs", ()))
            if (completion_requirement is None or disposition != "OPEN"
                    or not set(evidence_refs) & eligible_blocks
                    or not set(evidence_refs) <= set(completion_requirement["allowed_evidence_refs"])):
                raise ReviewProtocolError(
                    "EVIDENCE_MISSING",
                    "CAPABILITY_UNAVAILABLE requires an OPEN current condition and a cited current "
                    "executor-confirmed initialization block; remote error text is not proof",
                )
        # Reject ineligible citations before asking the model to read them.
        if completion_requirement is not None and disposition == "RESOLVED":
            if completion_requirement["host_observation_satisfied"] is False:
                raise ReviewProtocolError("EVIDENCE_MISSING", "current condition has incomplete business observations")
            allowed = set(completion_requirement["allowed_evidence_refs"])
            required = set(completion_requirement["evidence_refs"])
            if not set(evidence_refs) <= allowed or not required <= set(evidence_refs):
                raise ReviewProtocolError(
                    "EVIDENCE_MISSING",
                    f"condition citations do not cover its actual business evidence; rule_id={rule_id}; "
                    f"object_id={object_id}; missing_required_refs={sorted(required - set(evidence_refs))!r}; "
                    f"outside_allowed_refs={sorted(set(evidence_refs) - allowed)!r}; "
                    "cite only the supplied allowed references; reading an outside reference does not make it eligible",
                )
            evidence_kind = completion_requirement.get("evidence_kind", "SEMANTIC")
            if evidence_kind != "SEMANTIC":
                if evidence_kind not in {"EXECUTION_SUCCESS", "EXECUTION_OBSERVATION"}:
                    raise ReviewProtocolError("EVIDENCE_MISSING", "unknown execution evidence requirement")
                eligible = set(completion_requirement.get("eligible_execution_refs", ()))
                verified = []
                for reference in set(evidence_refs) & eligible:
                    execution = source_facts.get(reference, {}).get("native_execution")
                    if not isinstance(execution, Mapping) or execution.get("trusted_observation") is not True:
                        continue
                    if evidence_kind == "EXECUTION_SUCCESS" and not (
                        execution.get("state") == "COMPLETED"
                        and execution.get("trusted_completion") is True
                        and type(execution.get("exit_code")) is int and execution["exit_code"] == 0
                        and execution.get("versions_current") is True
                    ):
                        continue
                    verified.append(reference)
                if not verified:
                    raise ReviewProtocolError(
                        "EVIDENCE_MISSING",
                        f"condition requires a cited, trusted native execution outcome; rule_id={rule_id}; "
                        f"object_id={object_id}; evidence_kind={evidence_kind}; "
                        f"eligible_execution_refs={sorted(eligible)!r}; "
                        f"cited_execution_refs={sorted(set(evidence_refs) & eligible)!r}; "
                        "use this condition's current eligible_execution_refs in response_contract to locate "
                        "the authenticated outcome. Cite it only if its actual result supports this condition, "
                        "alongside the relevant business evidence. Eligibility alone does not prove coverage. "
                        "If no eligible outcome supports the condition, return NEEDS_EVIDENCE instead of PASS; "
                        "do not repeat completed business operations. Logs and completion claims alone are insufficient",
                    )
        if any(item not in source_facts for item in evidence_refs):
            raise ReviewProtocolError(
                "EVIDENCE_MISSING",
                f"review finding evidence lacks a host-verified semantic fingerprint; rule_id={rule_id}; "
                f"object_id={object_id}; unverified_source_refs={[ref for ref in evidence_refs if ref not in source_facts]!r}; "
                "cite only current eligible references; reading an outside reference does not make it eligible",
            )
        unread_source_refs = tuple(item for item in evidence_refs if item not in queried and not (
            completion_requirement is not None and source_facts.get(item, {}).get(
                "completion_visible") is True
        ))
        if unread_source_refs:
            raise ReviewProtocolError(
                "EVIDENCE_MISSING",
                f"review finding cites a source that the reviewer did not actually read; rule_id={rule_id}; "
                f"object_id={object_id}; unread_source_refs={list(unread_source_refs)!r}",
                unread_source_refs=unread_source_refs,
            )
        if completion_requirement is not None:
            finding["evidence_fingerprints"] = [source_facts[ref]["semantic_fingerprint"] for ref in evidence_refs]
            continue
        proposed_issue_id = raw["stable_issue_id"]
        registered = unresolved_issues.get(proposed_issue_id) if proposed_issue_id else None
        if registered is not None and disposition == "RESOLVED":
            current_object_fingerprint = object_fingerprints.get(object_id)
            object_changed = bool(
                current_object_fingerprint
                and current_object_fingerprint != registered.get("object_fingerprint")
            )
            prior_fingerprints = set(
                str(item) for item in registered.get("evidence_fingerprints", ())
            )
            new_relevant_fact = any(
                str(source_facts[reference].get("semantic_fingerprint") or "")
                not in prior_fingerprints
                and source_facts[reference].get("resolution_eligible") is True
                and object_id in set(source_facts[reference].get("relevant_object_ids") or ())
                for reference in evidence_refs
            )
            if not object_changed and not new_relevant_fact:
                raise ReviewProtocolError(
                    "IDENTITY_ALIGNMENT",
                    "RESOLVED requires a changed bound object or a new host-linked semantic fact",
                )
        finding["evidence_fingerprints"] = list(dict.fromkeys(
            str(source_facts[reference]["semantic_fingerprint"])
            for reference in evidence_refs
        ))
        finding["object_fingerprint"] = object_fingerprints.get(object_id)
    completion_observed = {finding["rule_id"] for finding in canonical["findings"]
                           if finding["rule_id"] in completion_requirements}
    if canonical["verdict"] == "PASS" and completion_observed != set(completion_requirements):
        missing = [
            {key: requirement.get(key) for key in
             ("rule_id", "condition", "issue_slot_id", "locus_id", "object_id")}
            for rule_id, requirement in completion_requirements.items()
            if rule_id not in completion_observed
        ]
        raise ReviewProtocolError(
            "EVIDENCE_MISSING",
            "PASS must cover every current acceptance condition; missing_condition_findings="
            + json.dumps(missing, ensure_ascii=False, separators=(",", ":"))
            + ". Assess each missing condition from the existing evidence and return the complete document. "
            "Similar wording does not merge distinct declared conditions. Keep valid findings; "
            "do not repeat completed actions. If evidence does not establish a condition, report it OPEN "
            "with the appropriate non-PASS verdict; never invent a RESOLVED finding.",
        )
    return canonical


def child_delegation_id(
    *,
    parent_task_id: str,
    parent_scope_lineage_id: str,
    stable_problem_id: str,
    scope: Mapping[str, Any],
    generation: int,
) -> str:
    """Return the host identity for one contract-only delegation generation."""

    if any(not isinstance(item, str) or not item.strip() for item in (
        parent_task_id, parent_scope_lineage_id, stable_problem_id
    )) or type(generation) is not int or generation < 1:
        raise ValueError("delegation identity inputs are invalid")
    return "delegation:" + _digest({
        "termination_contract_version": TERMINATION_CONTRACT_VERSION,
        "parent_task_id": parent_task_id,
        "parent_scope_lineage_id": parent_scope_lineage_id,
        "stable_problem_id": stable_problem_id,
        "scope": scope,
        "generation": generation,
    })


def _unique_strings(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{label} must be unique non-empty strings")
    return list(value)


def validate_child_contract(
    value: Mapping[str, Any],
    *,
    prior_contracts: Sequence[Mapping[str, Any]] = (),
    sibling_contracts: Sequence[Mapping[str, Any]] = (),
    parent_ancestor_delegation_ids: Sequence[str] = (),
    parent_depth: int = 0,
    trusted_max_depth: int = 2,
) -> dict[str, Any]:
    """Validate a read-only child contract without spawning or scheduling it."""

    required = {
        "schema", "termination_contract_version", "contract_only", "runtime_wiring",
        "delegation_id", "parent_binding", "lineage", "objective",
        "question_or_hypothesis", "scope", "ownership", "acceptance",
        "result_contract", "dependency_ids", "cancellation", "reconciliation", "lifecycle",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ValueError("child contract fields are not exact")
    if (
        value.get("schema") != CHILD_CONTRACT_SCHEMA
        or value.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
        or value.get("contract_only") is not True
        or value.get("runtime_wiring") is not False
    ):
        raise ValueError("child contract must explicitly remain CONTRACT_ONLY without runtime wiring")
    for field in ("delegation_id", "objective", "question_or_hypothesis"):
        if not isinstance(value.get(field), str) or not str(value[field]).strip():
            raise ValueError(f"child contract {field} is required")

    binding = value.get("parent_binding")
    binding_fields = {
        "task_id", "attempt_id", "run_instance_id", "execution_epoch", "goal_version",
        "acceptance_version", "criteria_lineage_version", "handled_input_seq", "artifact_ref",
        "parent_scope_lineage_id", "control_intent",
    }
    if not isinstance(binding, Mapping) or set(binding) != binding_fields:
        raise ValueError("child contract parent binding is invalid")
    if any(not isinstance(binding[field], str) or not binding[field] for field in (
        "task_id", "attempt_id", "run_instance_id", "artifact_ref", "parent_scope_lineage_id"
    )) or any(type(binding[field]) is not int or binding[field] < 0 for field in (
        "execution_epoch", "goal_version", "acceptance_version", "criteria_lineage_version",
        "handled_input_seq",
    )) or binding.get("control_intent") != "RUN":
        raise ValueError("child parent binding values or control intent are invalid")

    lineage = value.get("lineage")
    lineage_fields = {
        "stable_problem_id", "generation", "prior_delegation_id", "depth", "max_depth",
        "inherited_evidence_refs", "inherited_attempt_ids", "inherited_review_issue_ids",
    }
    if not isinstance(lineage, Mapping) or set(lineage) != lineage_fields:
        raise ValueError("child lineage is invalid")
    stable_problem_id = lineage.get("stable_problem_id")
    generation = lineage.get("generation")
    if not isinstance(stable_problem_id, str) or not stable_problem_id.strip():
        raise ValueError("child stable problem identity is required")
    if type(generation) is not int or generation < 1:
        raise ValueError("child generation is invalid")
    if (
        type(parent_depth) is not int
        or type(trusted_max_depth) is not int
        or parent_depth < 0
        or trusted_max_depth < 1
        or lineage.get("depth") != parent_depth + 1
        or lineage.get("max_depth") != trusted_max_depth
        or type(lineage.get("depth")) is not int
        or type(lineage.get("max_depth")) is not int
        or not 1 <= lineage["depth"] <= lineage["max_depth"]
    ):
        raise ValueError("child depth exceeds the explicit contract depth limit")
    for field in ("inherited_evidence_refs", "inherited_attempt_ids", "inherited_review_issue_ids"):
        _unique_strings(lineage.get(field), f"child {field}", allow_empty=True)

    scope = value.get("scope")
    if not isinstance(scope, Mapping) or set(scope) != {
        "max_control_segments", "allowed_action_kinds", "allowed_source_refs", "exit_conditions"
    }:
        raise ValueError("child contract scope is invalid")
    if type(scope["max_control_segments"]) is not int or scope["max_control_segments"] < 1:
        raise ValueError("child contract scope limit must be positive")
    allowed_actions = _unique_strings(scope.get("allowed_action_kinds"), "child allowed actions")
    if not set(allowed_actions).issubset({"READ", "ANALYZE", "REPORT"}):
        raise ValueError("contract-only child cannot receive write or side-effect authority")
    _unique_strings(scope.get("allowed_source_refs"), "child allowed sources")
    _unique_strings(scope.get("exit_conditions"), "child exit conditions")

    expected_id = child_delegation_id(
        parent_task_id=str(binding["task_id"]),
        parent_scope_lineage_id=str(binding["parent_scope_lineage_id"]),
        stable_problem_id=stable_problem_id,
        scope=scope,
        generation=generation,
    )
    if value.get("delegation_id") != expected_id:
        raise ValueError("child delegation identity is not the host-derived identity")

    ownership = value.get("ownership")
    if (
        not isinstance(ownership, Mapping)
        or set(ownership) != {"owner_id", "exclusive_problem_owner", "owned_resource_ids"}
        or not isinstance(ownership.get("owner_id"), str)
        or not ownership["owner_id"].strip()
        or ownership.get("exclusive_problem_owner") is not True
    ):
        raise ValueError("child contract requires one explicit problem owner")
    _unique_strings(ownership.get("owned_resource_ids"), "child owned resources", allow_empty=True)

    acceptance = value.get("acceptance")
    if not isinstance(acceptance, Mapping) or set(acceptance) != {
        "required_outcome_ids", "required_evidence_kinds", "completion_condition"
    } or not isinstance(acceptance.get("completion_condition"), str) or not acceptance["completion_condition"].strip():
        raise ValueError("child acceptance is invalid")
    _unique_strings(acceptance.get("required_outcome_ids"), "child outcomes")
    _unique_strings(acceptance.get("required_evidence_kinds"), "child evidence kinds")

    result_contract = value.get("result_contract")
    if not isinstance(result_contract, Mapping) or set(result_contract) != {
        "schema", "required_fields", "return_to_parent_task_id"
    } or not isinstance(result_contract.get("schema"), str) or not result_contract["schema"].strip():
        raise ValueError("child result contract is invalid")
    _unique_strings(result_contract.get("required_fields"), "child result fields")
    if result_contract.get("return_to_parent_task_id") != binding["task_id"]:
        raise ValueError("child result must return to its direct parent")

    dependencies = _unique_strings(value.get("dependency_ids"), "child dependencies", allow_empty=True)
    ancestor_ids = set(str(item) for item in parent_ancestor_delegation_ids)
    if value["delegation_id"] in dependencies or ancestor_ids.intersection(dependencies):
        raise ValueError("child dependency graph cannot point to self or an ancestor")

    cancellation = value.get("cancellation")
    if not isinstance(cancellation, Mapping) or cancellation != {
        "policy": "RETURN_AT_CHECKPOINT",
        "stop_new_dispatch_on_parent_change": True,
        "late_result_policy": "EVIDENCE_ONLY",
    }:
        raise ValueError("child cancellation contract is invalid")
    reconciliation = value.get("reconciliation")
    if not isinstance(reconciliation, Mapping) or reconciliation != {
        "parent_validates": True,
        "child_may_approve_parent": False,
        "binding_mismatch_policy": "LATE_EVIDENCE_ONLY",
    }:
        raise ValueError("child reconciliation contract is invalid")
    lifecycle = value.get("lifecycle")
    if not isinstance(lifecycle, Mapping) or lifecycle != {
        "required_before_parent_terminal": "SETTLED_CANCELLED_VERIFIED_OR_HANDED_OFF",
        "handoff_requires_receipt": True,
        "unknown_effect_blocks_parent_terminal": True,
    }:
        raise ValueError("child lifecycle contract is invalid")

    relevant_prior = [
        item for item in prior_contracts
        if isinstance(item, Mapping)
        and (item.get("lineage") or {}).get("stable_problem_id") == stable_problem_id
    ]
    prior_id = lineage.get("prior_delegation_id")
    if generation == 1:
        if prior_id is not None or relevant_prior:
            raise ValueError("first delegation generation cannot name a prior delegation")
    else:
        if not relevant_prior:
            raise ValueError("repeat delegation must inherit a prior contract for the same problem")
        prior = max(relevant_prior, key=lambda item: int((item.get("lineage") or {}).get("generation", 0)))
        prior_lineage = prior.get("lineage") or {}
        if generation != int(prior_lineage.get("generation", 0)) + 1 or prior_id != prior.get("delegation_id"):
            raise ValueError("repeat delegation generation or prior identity is discontinuous")
        for field in ("inherited_evidence_refs", "inherited_attempt_ids", "inherited_review_issue_ids"):
            if not set(prior_lineage.get(field, ())).issubset(set(lineage.get(field, ()))):
                raise ValueError("repeat delegation cannot discard inherited history")

    graph = {str(value["delegation_id"]): set(dependencies)}
    for sibling in sibling_contracts:
        if not isinstance(sibling, Mapping):
            raise ValueError("sibling child contract is invalid")
        sibling_lineage = sibling.get("lineage") or {}
        if (
            sibling.get("delegation_id") == value["delegation_id"]
            or (
                sibling_lineage.get("stable_problem_id") == stable_problem_id
                and sibling_lineage.get("generation") == generation
            )
        ):
            raise ValueError("one problem generation cannot have multiple child owners")
        sibling_dependencies = set(sibling.get("dependency_ids") or ())
        graph[str(sibling.get("delegation_id") or "")] = set(str(item) for item in sibling_dependencies)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError("child dependency graph contains a cycle")
        if node in visited or node not in graph:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for delegation_id in tuple(graph):
        visit(delegation_id)
    return _canonical(value)


def validate_child_result(
    contract: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    current_parent_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify a contract-only child result against the current parent binding."""

    required = {"schema", "delegation_id", "parent_binding", "result_refs", "settlement_status", "approves_parent"}
    if not isinstance(result, Mapping) or set(result) != required:
        raise ValueError("child result fields are not exact")
    result_contract = contract.get("result_contract") or {}
    if result.get("schema") != result_contract.get("schema") or result.get("delegation_id") != contract.get("delegation_id"):
        raise ValueError("child result identity is invalid")
    _unique_strings(result.get("result_refs"), "child result refs")
    if result.get("settlement_status") not in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
        raise ValueError("child result is not settled")
    if result.get("approves_parent") is not False:
        raise ValueError("a child result cannot approve its parent task")
    bound = result.get("parent_binding")
    if not isinstance(bound, Mapping) or dict(bound) != dict(contract.get("parent_binding") or {}):
        raise ValueError("child result is not bound to its contract parent version")
    comparable_fields = (
        "task_id", "attempt_id", "parent_scope_lineage_id", "run_instance_id",
        "execution_epoch", "goal_version", "acceptance_version",
        "criteria_lineage_version", "handled_input_seq", "artifact_ref", "control_intent",
    )
    current = all(bound.get(field) == current_parent_binding.get(field) for field in comparable_fields)
    return {**_canonical(result), "applicability": "CURRENT_PARENT_INPUT" if current else "LATE_EVIDENCE_ONLY"}


def validate_parent_child_settlement(child_states: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Validate the pure pre-terminal join/handoff obligation for required children."""

    settled: list[str] = []
    for state in child_states:
        if not isinstance(state, Mapping) or set(state) != {
            "delegation_id", "required", "status", "unknown_effect", "handoff_receipt_ref"
        }:
            raise ValueError("child settlement state is invalid")
        if type(state.get("required")) is not bool or type(state.get("unknown_effect")) is not bool:
            raise ValueError("child settlement required and unknown-effect flags must be booleans")
        if state.get("unknown_effect") is True:
            raise ValueError("unknown child effect blocks parent terminal settlement")
        status = state.get("status")
        if state.get("required") is True and status not in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
            raise ValueError("required child is not settled before parent terminal")
        if status == "HANDED_OFF" and not str(state.get("handoff_receipt_ref") or "").strip():
            raise ValueError("child handoff requires a receipt")
        if status in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
            settled.append(str(state.get("delegation_id") or ""))
    return tuple(settled)


@dataclass(frozen=True)
class AttemptPlan:
    attempt_id: str
    lineage_id: str
    acceptance_item_id: str
    blocker_id: str
    blocker_source: str
    question_or_hypothesis: str
    max_control_segments: int
    max_provider_responses: int
    max_tool_call_groups: int
    allowed_action_kinds: tuple[str, ...]
    exit_conditions: tuple[str, ...]
    relevant_source_refs: tuple[str, ...] = ()
    relevant_object_ids: tuple[str, ...] = ()
    prior_attempt_id: str | None = None
    capability_producer_contracts: tuple[Mapping[str, Any], ...] = ()
    capability_source_contracts: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        required = (
            self.attempt_id,
            self.lineage_id,
            self.acceptance_item_id,
            self.blocker_id,
            self.blocker_source,
            self.question_or_hypothesis,
        )
        if any(not isinstance(value, str) or not value.strip() for value in required):
            raise ValueError("attempt plan identity and investigation question are required")
        limits = (
            self.max_control_segments,
            self.max_provider_responses,
            self.max_tool_call_groups,
        )
        if any(type(value) is not int or value < 1 for value in limits):
            raise ValueError("attempt plan local scope must be positive")
        if (
            not self.allowed_action_kinds
            or not self.exit_conditions
            or any(
                not isinstance(value, str) or not value.strip()
                for value in (*self.allowed_action_kinds, *self.exit_conditions)
            )
        ):
            raise ValueError("attempt plan requires allowed actions and exit conditions")
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (*self.relevant_source_refs, *self.relevant_object_ids)
        ):
            raise ValueError("attempt plan relevance identities must be non-empty strings")
        if self.prior_attempt_id is not None and (
            not isinstance(self.prior_attempt_id, str) or not self.prior_attempt_id.strip()
        ):
            raise ValueError("prior attempt identity must be a non-empty string")
        if any(not isinstance(value, Mapping) for value in self.capability_source_contracts):
            raise ValueError("capability source contracts must be mappings")
        if any(not isinstance(value, Mapping) for value in self.capability_producer_contracts):
            raise ValueError("capability producer contracts must be mappings")

    def as_dict(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_ATTEMPT_PLAN_V1",
            "termination_contract_version": TERMINATION_CONTRACT_VERSION,
            "attempt_id": self.attempt_id,
            "lineage_id": self.lineage_id,
            "prior_attempt_id": self.prior_attempt_id,
            "acceptance_item_id": self.acceptance_item_id,
            "blocker_id": self.blocker_id,
            "blocker_source": self.blocker_source,
            "question_or_hypothesis": self.question_or_hypothesis,
            "scope": {
                "max_control_segments": self.max_control_segments,
                "max_provider_responses": self.max_provider_responses,
                "max_tool_call_groups": self.max_tool_call_groups,
                "allowed_action_kinds": list(self.allowed_action_kinds),
            },
            "exit_conditions": list(self.exit_conditions),
            "relevant_source_refs": list(self.relevant_source_refs),
            "relevant_object_ids": list(self.relevant_object_ids),
            "capability_producer_contracts": [dict(item) for item in self.capability_producer_contracts],
            "capability_source_contracts": [dict(item) for item in self.capability_source_contracts],
            **dict(binding),
        }


def history_read_diagnostic(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Keep authenticated paging facts separate from business-progress credit."""
    result = item.get("result")
    arguments = item.get("arguments")
    if (item.get("name") != "sitina_history_query" or item.get("status") != "ok"
            or not isinstance(result, Mapping) or result.get("status") != "OK"
            or not isinstance(arguments, Mapping)):
        return None
    operation = arguments.get("operation")
    if operation == "list" and isinstance(result.get("entries"), list):
        return {
            "operation": "list", "cursor": arguments.get("cursor"),
            "next_cursor": result.get("next_cursor"), "kind": arguments.get("kind"),
            "has_more": result.get("has_more") is True,
            "task_session_binding": result.get("task_session_binding"),
        }
    if operation != "read":
        return None
    source_ref, content_hash = result.get("source_ref"), result.get("content_hash")
    offset, returned = result.get("offset"), result.get("returned_bytes")
    if (not isinstance(source_ref, str) or not source_ref
            or not isinstance(content_hash, str) or len(content_hash) != 64
            or any(character not in "0123456789abcdef" for character in content_hash)
            or type(offset) is not int or offset < 0
            or type(returned) is not int or returned <= 0):
        return None
    diagnostic = {
        "operation": "read", "source_ref": source_ref, "content_hash": content_hash,
        "offset": offset, "returned_bytes": returned, "next_offset": result.get("next_offset"),
        "has_more": result.get("has_more") is True,
        "source_tool": str(item.get("history_source_tool") or ""),
        "request_fingerprint": _digest(arguments),
    }
    read_range, requested = result.get("read_range"), result.get("requested_range")
    if (result.get("read_mode") in {"seek", "continue"}
            and isinstance(read_range, Mapping) and isinstance(requested, Mapping)
            and read_range.get("coordinate") == requested.get("coordinate") == "utf-8-bytes"
            and read_range.get("start") == offset and read_range.get("end") == offset + returned
            and type(requested.get("start")) is int and type(requested.get("end")) is int
            and 0 <= requested["start"] <= offset < offset + returned <= requested["end"]):
        diagnostic.update(read_mode=result["read_mode"], read_range=dict(read_range),
                          requested_range=dict(requested), range_complete=result.get("range_complete"))
    return diagnostic


def history_read_coverage(
    observations: Sequence[Mapping[str, Any]],
    previous: Sequence[Mapping[str, Any]] = (),
    *,
    prior_settlements: Sequence[Mapping[str, Any]] = (),
    prior_read_sources: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Track actual source-byte coverage separately from request identity and business completion."""
    covered: dict[str, list[tuple[int, int]]] = {}
    for source in prior_read_sources:
        if (source.get("applicability") != "CURRENT_BINDING"
                or not isinstance(source.get("source_ref"), str)
                or not isinstance(source.get("read_content_hash"), str)):
            continue
        key = _digest({"source_ref": source["source_ref"], "content_hash": source["read_content_hash"]})
        for interval in source.get("read_ranges", ()):
            if (isinstance(interval, (list, tuple)) and len(interval) == 2
                    and type(interval[0]) is int and type(interval[1]) is int and 0 <= interval[0] < interval[1]):
                covered.setdefault(key, []).append((interval[0], interval[1]))
    for settlement in prior_settlements:
        for record in (settlement.get("progress_basis") or {}).get("history_read_intervals", ()):
            if not isinstance(record, Mapping):
                continue
            key, interval = record.get("history_source_key"), record.get("interval")
            if (isinstance(key, str) and isinstance(interval, (list, tuple)) and len(interval) == 2
                    and type(interval[0]) is int and type(interval[1]) is int and 0 <= interval[0] < interval[1]):
                covered.setdefault(key, []).append((interval[0], interval[1]))

    def add(page: Mapping[str, Any]) -> tuple[str, int, list[tuple[int, int]]] | None:
        start, size = page.get("offset"), page.get("returned_bytes")
        if (page.get("operation") != "read" or type(start) is not int or type(size) is not int
                or start < 0 or size <= 0 or not isinstance(page.get("source_ref"), str)
                or not isinstance(page.get("content_hash"), str)):
            return None
        key = _digest({"source_ref": page["source_ref"], "content_hash": page["content_hash"]})
        old = _merge_intervals(covered.get(key, ()))
        cursor, end = start, start + size
        new: list[tuple[int, int]] = []
        for left, right in old:
            if right <= cursor:
                continue
            if left > cursor:
                new.append((cursor, min(left, end)))
            cursor = max(cursor, right)
            if cursor >= end:
                break
        if cursor < end:
            new.append((cursor, end))
        covered[key] = _merge_intervals((*old, (start, end)))
        return key, sum(right - left for left, right in new), new

    for item in previous:
        page = item.get("history_read")
        if isinstance(page, Mapping):
            add(page)
    output, new_records = [], []
    for item in observations:
        observation = dict(item)
        page = item.get("history_read")
        added = add(page) if isinstance(page, Mapping) else None
        if added is not None:
            key, delta, intervals = added
            observation["history_read"] = dict(page, new_read_bytes=delta)
            new_records.extend({"history_source_key": key, "interval": [left, right]}
                               for left, right in intervals)
            if page.get("read_mode") in {"seek", "continue"} and delta == 0:
                observation["progress_eligible"] = False
                observation["ineligible_reason"] = "history_range_already_covered"
        output.append(observation)
    return {
        "observations": tuple(output),
        "history_read_intervals": [
            {"history_source_key": key, "interval": [left, right]}
            for key, intervals in sorted(covered.items()) for left, right in _merge_intervals(intervals)
        ],
        "new_history_read_intervals": new_records,
    }


def history_read_loop_reason(
    observations: Sequence[Mapping[str, Any]],
    previous: Sequence[Mapping[str, Any]],
    *,
    repeated_only: bool = False,
) -> str | None:
    """Detect an all-history detour without mistaking forward paging for a loop."""
    def pages(items: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        if not items or any(item.get("name") != "sitina_history_query"
                            or not isinstance(item.get("history_read"), Mapping) for item in items):
            return []
        return [item["history_read"] for item in items]

    current_pages = pages(observations)
    if not current_pages or (not repeated_only
                             and any(item.get("progress_eligible") is True for item in observations)):
        return None
    if any(page.get("source_tool") == "sitina_history_query" for page in current_pages):
        return "HISTORY_QUERY_RECEIPT_RECURSION"
    if all(page.get("read_mode") in {"seek", "continue"}
           and type(page.get("new_read_bytes")) is int for page in current_pages):
        # A seek, gap, or first recall is legal. A loop requires the same
        # requests to stay stationary across both observations, rather than
        # a fixed reread allowance or a guessed offset frontier.
        if any(page["new_read_bytes"] > 0 for page in current_pages):
            return None
        prior_pages = pages(previous)
        if (prior_pages and all(page.get("read_mode") in {"seek", "continue"}
                                and page.get("new_read_bytes") == 0 for page in prior_pages)
                and [page.get("request_fingerprint") for page in current_pages]
                    == [page.get("request_fingerprint") for page in prior_pages]):
            return "HISTORY_SOURCE_PAGE_REPEATED"
        return None
    if repeated_only:
        return "HISTORY_SOURCE_PAGE_REPEATED"
    prior_pages = pages(previous)
    if not prior_pages or any(item.get("progress_eligible") is True for item in previous):
        return None

    def follows(current: Mapping[str, Any], prior: Mapping[str, Any]) -> bool:
        if prior.get("has_more") is not True or current.get("operation") != prior.get("operation"):
            return False
        if current["operation"] == "list":
            return (isinstance(current.get("cursor"), str) and bool(current["cursor"])
                    and current["cursor"] == prior.get("next_cursor")
                    and current.get("kind") == prior.get("kind")
                    and current.get("task_session_binding") == prior.get("task_session_binding"))
        return (current.get("source_ref") == prior.get("source_ref")
                and current.get("content_hash") == prior.get("content_hash")
                and type(prior.get("next_offset")) is int
                and current.get("offset") == prior["next_offset"]
                and type(prior.get("offset")) is int
                and prior["next_offset"] > prior["offset"])

    read_frontiers: dict[tuple[Any, Any, Any], Mapping[str, Any]] = {}
    for page in current_pages:
        if page.get("operation") != "read":
            if not any(follows(page, prior) for prior in prior_pages):
                return "HISTORY_READ_WITHOUT_BUSINESS_PROGRESS"
            continue
        identity = (page.get("operation"), page.get("source_ref"), page.get("content_hash"))
        candidates = (read_frontiers[identity],) if identity in read_frontiers else prior_pages
        if not any(follows(page, prior) for prior in candidates):
            return "HISTORY_READ_WITHOUT_BUSINESS_PROGRESS"
        read_frontiers[identity] = page
    return None


def original_input_read_verified(
    result: Mapping[str, Any],
    original_input_versions: Mapping[str, str],
    *,
    object_id: str | None = None,
) -> bool:
    """Check a committed read against the task-created input, never a write scope."""
    from sitina.extensions.tools import file_read_content_bound

    path = result.get("path")
    if not isinstance(path, str) or result.get("exists") is not True:
        return False
    resolved = str(Path(path).expanduser().resolve(strict=False))
    if object_id is not None and resolved != str(Path(object_id).expanduser().resolve(strict=False)):
        return False
    expected = original_input_versions.get(resolved)
    return bool(
        expected and result.get("version") == expected and file_read_content_bound(result)
    )


def action_observations(
    tool_results: Sequence[Mapping[str, Any]],
    *,
    relevant_source_refs: Sequence[str] = (),
    relevant_object_ids: Sequence[str] = (),
    self_modified_object_ids: Sequence[str] = (),
    object_base: str | None = None,
    original_input_versions: Mapping[str, str] | None = None,
    capability_source_bindings: Sequence[Mapping[str, Any]] = (),
) -> tuple[dict[str, Any], ...]:
    """Extract verified stable evidence facts for explicitly supported tools.

    Unknown tools and failed results remain diagnosable observations but are
    never eligible to reset a business no-progress count.
    """

    observations: list[dict[str, Any]] = []
    relevant = {str(item) for item in relevant_source_refs}
    relevant_objects = {
        str(Path(item).expanduser().resolve(strict=False)) for item in relevant_object_ids
    }
    self_modified_objects = {
        str(Path(item).expanduser().resolve(strict=False)) for item in self_modified_object_ids
    }
    capability_bindings = tuple(
        dict(item) for item in capability_source_bindings if isinstance(item, Mapping)
    )
    capability_by_source = {
        str(item.get("source_ref")): item
        for item in capability_bindings
        if str(item.get("source_ref") or "")
    }
    for item in tool_results:
        name = str(item.get("name") or "")
        status = str(item.get("status") or "")
        arguments = item.get("arguments") if isinstance(item.get("arguments"), Mapping) else {}
        raw_result = item.get("result")
        result = raw_result if isinstance(raw_result, Mapping) else {}
        eligible = False
        evidence_fact: Mapping[str, Any] | None = None
        observation_fingerprint: str | None = None
        ineligible_reason = "unsupported_tool_evidence"
        if status != "ok":
            ineligible_reason = "tool_call_not_successful"
        elif name == "sitina_history_query":
            source_ref = str(result.get("source_ref") or arguments.get("source_ref") or "")
            read_status = str(result.get("status") or "")
            content_hash = str(result.get("content_hash") or "")
            offset = result.get("offset")
            returned_bytes = result.get("returned_bytes")
            business_offset = result.get("capability_business_offset")
            business_returned_bytes = result.get("capability_business_returned_bytes")
            business_total_bytes = result.get("capability_business_total_bytes")
            capability_binding = capability_by_source.get(source_ref)
            if capability_binding is not None:
                source_key = str(result.get("capability_source_key") or "")
                value_hash = str(result.get("capability_value_hash") or "")
                total_bytes = result.get("total_bytes")
                next_offset = result.get("next_offset")
                end = (
                    int(offset) + int(returned_bytes)
                    if type(offset) is int and type(returned_bytes) is int
                    else None
                )
                business_end = (
                    int(business_offset) + int(business_returned_bytes)
                    if type(business_offset) is int and type(business_returned_bytes) is int
                    else None
                )
                try:
                    binding_value_bytes = int(
                        capability_binding.get("capability_value_bytes", -1)
                    )
                except (TypeError, ValueError, OverflowError):
                    binding_value_bytes = -1
                # The producer binding must carry its own finite budget.  A
                # missing budget is an unverified source, never permission to
                # fall back to a global history-size ceiling.
                max_total = capability_binding.get("max_total_bytes")
                capability_valid = (
                    read_status == "OK"
                    and source_key == str(capability_binding.get("capability_source_key") or "")
                    and source_key != ""
                    and value_hash == str(capability_binding.get("capability_value_hash") or "")
                    and value_hash != ""
                    and (
                        result.get("capability_operation_id") is None
                        or str(result.get("capability_operation_id") or "")
                        == str(capability_binding.get("operation_id") or "")
                    )
                    and (
                        result.get("capability_method_id") is None
                        or str(result.get("capability_method_id") or "")
                        == str(capability_binding.get("method_id") or "")
                    )
                    and len(content_hash) == 64
                    and all(character in "0123456789abcdef" for character in content_hash)
                    and type(offset) is int
                    and not isinstance(offset, bool)
                    and offset >= 0
                    and type(returned_bytes) is int
                    and not isinstance(returned_bytes, bool)
                    and returned_bytes >= 0
                    and type(total_bytes) is int
                    and not isinstance(total_bytes, bool)
                    and total_bytes >= int(end or 0)
                    and type(max_total) is int
                    and not isinstance(max_total, bool)
                    and max_total >= total_bytes
                    and (next_offset is None or next_offset == end)
                    and (next_offset is None or int(next_offset) > int(offset))
                    and type(business_offset) is int
                    and not isinstance(business_offset, bool)
                    and business_offset >= 0
                    and type(business_returned_bytes) is int
                    and not isinstance(business_returned_bytes, bool)
                    and business_returned_bytes > 0
                    and type(business_total_bytes) is int
                    and not isinstance(business_total_bytes, bool)
                    and business_total_bytes == binding_value_bytes
                    and business_total_bytes >= int(business_end or 0)
                )
                if capability_valid:
                    evidence_fact = {
                        "tool": name,
                        "source_ref": source_ref,
                        "capability_source_key": source_key,
                        "capability_value_hash": value_hash,
                        "projected_content_hash": content_hash,
                        # Business progress is measured only over the
                        # serialized value bytes.  Raw envelope offsets stay
                        # diagnostic and cannot make a new operation/page
                        # appear to cover new business content.
                        "offset": int(business_offset),
                        "returned_bytes": int(business_returned_bytes),
                        "next_offset": int(business_end),
                        "total_bytes": int(business_total_bytes),
                        "raw_offset": int(offset),
                        "raw_returned_bytes": int(returned_bytes),
                        "raw_next_offset": next_offset,
                        "raw_total_bytes": int(total_bytes),
                        "capability_interval": [int(business_offset), int(business_end)],
                    }
                    eligible = True
                    ineligible_reason = ""
                    # This fingerprint intentionally excludes operation ID,
                    # nonce, raw result hash, and envelope ordering.  Those
                    # are transport identities, not business progress.
                    observation_fingerprint = _digest({
                        "capability_source_key": source_key,
                        "capability_value_hash": value_hash,
                        "offset": int(business_offset),
                        "end": int(business_end),
                        "total_bytes": int(business_total_bytes),
                    })
                else:
                    ineligible_reason = "capability_page_is_not_verified_success"
                    observation_fingerprint = None
            else:
                observation_fingerprint = None
            if (
                capability_binding is None
                and
                read_status == "OK"
                and source_ref in relevant
                and len(content_hash) == 64
                and all(character in "0123456789abcdef" for character in content_hash)
                and type(offset) is int
                and offset >= 0
                and type(returned_bytes) is int
                and returned_bytes > 0
            ):
                evidence_fact = {
                    "tool": name,
                    "source_ref": source_ref,
                    "source_content_hash": str(result.get("source_content_hash") or content_hash),
                    "projected_content_hash": content_hash,
                    "offset": offset,
                    "returned_bytes": returned_bytes,
                    "total_bytes": int(result.get("total_bytes") or 0),
                }
                eligible = True
                ineligible_reason = ""
            elif capability_binding is None and source_ref not in relevant:
                ineligible_reason = "source_not_bound_to_current_plan"
            elif capability_binding is None:
                ineligible_reason = "history_page_is_not_verified_success"
        elif name in {"sitina_read_file", "sitina_list_directory", "sitina_grep", "sitina_glob"}:
            raw_path = arguments.get("path")
            if name == "sitina_glob":
                raw_path = arguments.get("pattern")
            normalized_path = ""
            if isinstance(raw_path, str) and raw_path:
                prefix = raw_path
                if name == "sitina_glob":
                    wildcard = min(
                        (prefix.find(char) for char in "*?[" if char in prefix),
                        default=len(prefix),
                    )
                    prefix = prefix[:wildcard] or "."
                candidate = Path(prefix).expanduser()
                if not candidate.is_absolute() and object_base is not None:
                    candidate = Path(object_base) / candidate
                normalized_path = str(candidate.resolve(strict=False))
            object_is_bound = bool(
                normalized_path
                and any(
                    normalized_path == candidate
                    or normalized_path.startswith(candidate.rstrip("/") + "/")
                    for candidate in relevant_objects
                )
            )
            object_is_self_generated = bool(
                normalized_path
                and any(
                    normalized_path == candidate
                    or normalized_path.startswith(candidate.rstrip("/") + "/")
                    or candidate.startswith(normalized_path.rstrip("/") + "/")
                    for candidate in self_modified_objects
                )
            )
            bound_matches: set[tuple[str, int, str]] = set()
            if name == "sitina_grep" and not object_is_bound:
                matches = result.get("matches")
                if isinstance(matches, list):
                    for match in matches:
                        if not isinstance(match, Mapping):
                            continue
                        file = match.get("file")
                        line = match.get("line")
                        text = match.get("text")
                        if (not isinstance(file, str) or not file
                                or type(line) is not int or line < 1
                                or not isinstance(text, str)):
                            continue
                        matched_path = Path(file).expanduser()
                        if not matched_path.is_absolute() and object_base is not None:
                            matched_path = Path(object_base) / matched_path
                        matched_object = str(matched_path.resolve(strict=False))
                        if not any(
                            matched_object == candidate
                            or matched_object.startswith(candidate.rstrip("/") + "/")
                            for candidate in relevant_objects
                        ):
                            continue
                        if any(
                            matched_object == candidate
                            or matched_object.startswith(candidate.rstrip("/") + "/")
                            or candidate.startswith(matched_object.rstrip("/") + "/")
                            for candidate in self_modified_objects
                        ):
                            continue
                        bound_matches.add((matched_object, line, text))
            original_input_verified = (
                name == "sitina_read_file"
                and original_input_read_verified(
                    result, original_input_versions or {}, object_id=normalized_path
                )
            )
            if object_is_bound and (not object_is_self_generated or original_input_verified):
                content = raw_result
                evidence_fact = {
                    "tool": name,
                    "object_id": normalized_path,
                    "content_hash": _digest(content),
                    "result_shape": type(content).__name__,
                }
                eligible = True
                ineligible_reason = ""
            elif bound_matches:
                # A directory search can return a declared file. Only its
                # bound matches are progress; unrelated results are excluded.
                evidence_fact = {
                    "tool": name,
                    "object_ids": sorted({match[0] for match in bound_matches}),
                    "content_hash": _digest(sorted(bound_matches)),
                    "result_shape": type(raw_result).__name__,
                }
                eligible = True
                ineligible_reason = ""
            elif object_is_self_generated:
                ineligible_reason = "self_generated_object_requires_independent_verification"
            else:
                ineligible_reason = "object_not_bound_to_current_plan"
        elif name == "sitina_delegate_readonly":
            # A renamed delegation can carry a stable fingerprint of a
            # previously settled immutable child result.  Treat that exact
            # carried fact as eligible evidence for the parent no-progress
            # protocol; the newly admitted child remains a separate durable
            # responsibility and still cannot approve the parent.
            repeated_fingerprint = result.get("prior_evidence_fingerprint")
            if (
                status == "ok"
                and isinstance(repeated_fingerprint, str)
                and repeated_fingerprint.strip()
            ):
                evidence_fact = {
                    "tool": name,
                    "child_evidence_fingerprint": repeated_fingerprint,
                }
                eligible = True
                ineligible_reason = ""
        observation = {
            "name": name,
            "status": status,
            "progress_eligible": eligible,
            "ineligible_reason": ineligible_reason,
            "evidence_fact": dict(evidence_fact or {}),
        }
        if evidence_fact is not None:
            observation["fingerprint"] = observation_fingerprint or _digest(evidence_fact)
        history_read = history_read_diagnostic(item)
        if history_read is not None:
            observation["history_read"] = dict(history_read)
        observations.append(observation)
    return tuple(observations)


def historical_action_progress(
    prior_settlements: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    read_coverage = history_read_coverage(observations, prior_settlements=prior_settlements)
    observations = read_coverage["observations"]
    seen = {
        str(value)
        for settlement in prior_settlements
        for value in (settlement.get("progress_basis") or {}).get("action_fingerprints", ())
    }
    prior_intervals: dict[str, list[tuple[int, int]]] = {}
    for settlement in prior_settlements:
        for item in (settlement.get("progress_basis") or {}).get("capability_intervals", ()):
            if not isinstance(item, Mapping):
                continue
            key = str(item.get("capability_source_key") or "")
            interval = item.get("interval")
            if not key or not isinstance(interval, (list, tuple)) or len(interval) != 2:
                continue
            if type(interval[0]) is int and type(interval[1]) is int and interval[0] < interval[1]:
                prior_intervals.setdefault(key, []).append((interval[0], interval[1]))
    current = tuple(
        dict.fromkeys(
            str(item.get("fingerprint"))
            for item in observations
            if item.get("progress_eligible") is True
            and isinstance(item.get("fingerprint"), str)
            and item.get("fingerprint")
        )
    )
    new = tuple(value for value in current if value not in seen)
    capability_fingerprints = {
        str(item.get("fingerprint"))
        for item in observations
        if item.get("progress_eligible") is True
        and isinstance(item.get("evidence_fact"), Mapping)
        and item.get("evidence_fact", {}).get("capability_source_key")
        and isinstance(item.get("fingerprint"), str)
    }
    all_intervals = {key: list(value) for key, value in prior_intervals.items()}
    new_interval_records: list[dict[str, Any]] = []
    for item in observations:
        if item.get("progress_eligible") is not True:
            continue
        fact = item.get("evidence_fact")
        if not isinstance(fact, Mapping):
            continue
        key = str(fact.get("capability_source_key") or "")
        interval = fact.get("capability_interval")
        if not key or not isinstance(interval, (list, tuple)) or len(interval) != 2:
            continue
        start, end = interval
        if type(start) is not int or type(end) is not int or start >= end:
            continue
        covered = sorted(all_intervals.get(key, ()))
        uncovered: list[tuple[int, int]] = []
        cursor = start
        for left, right in covered:
            if right <= cursor:
                continue
            if left > cursor:
                uncovered.append((cursor, min(left, end)))
            cursor = max(cursor, right)
            if cursor >= end:
                break
        if cursor < end:
            uncovered.append((cursor, end))
        if uncovered:
            new_interval_records.extend(
                {
                    "capability_source_key": key,
                    "interval": [left, right],
                }
                for left, right in uncovered
                if left < right
            )
        all_intervals.setdefault(key, []).append((start, end))
        all_intervals[key] = _merge_intervals(all_intervals[key])
    return {
        "schema": "SITINA_LOOP_ACTION_PROGRESS_V1",
        "action_fingerprints": list(current),
        "new_action_fingerprints": list(new),
        "repeated_action_fingerprints": [value for value in current if value in seen],
        "capability_intervals": [
            {
                "capability_source_key": key,
                "interval": [left, right],
            }
            for key, intervals in sorted(all_intervals.items())
            for left, right in _merge_intervals(intervals)
        ],
        "new_capability_intervals": new_interval_records,
        "history_read_intervals": read_coverage["history_read_intervals"],
        "new_history_read_intervals": read_coverage["new_history_read_intervals"],
        "relevant_progress": bool(
            any(value not in capability_fingerprints for value in new)
            or new_interval_records
        ),
    }


def _merge_intervals(intervals: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for left, right in sorted((int(a), int(b)) for a, b in intervals if int(a) < int(b)):
        if not merged or left > merged[-1][1]:
            merged.append((left, right))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
    return merged


def aggregate_attempt_step_results(
    steps: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate metrics over exactly one business attempt's control steps."""

    numeric_fields = (
        "provider_call_count",
        "provider_physical_send_count",
        "provider_retry_count",
        "provider_fallback_count",
        "provider_input_tokens",
        "provider_output_tokens",
        "provider_cache_read_tokens",
        "provider_cache_write_tokens",
        "provider_token_total",
        "provider_cost_micro_usd",
        "file_mutation_event_count",
        "denied_effect_attempt_count",
        "external_mutation_count",
    )
    result = {field: 0 for field in numeric_fields}
    tool_results: list[dict[str, Any]] = []
    provider_metadata: list[dict[str, Any]] = []
    mutation_events: list[dict[str, Any]] = []
    profiles: list[str] = []
    models: list[str] = []
    skills: list[str] = []
    agents: list[str] = []
    for step in steps:
        for field in numeric_fields:
            result[field] += int(step.get(field, 0) or 0)
        tool_results.extend(
            dict(item) for item in step.get("tool_results", ()) if isinstance(item, Mapping)
        )
        provider_metadata.extend(
            dict(item)
            for item in step.get("provider_metadata", ())
            if isinstance(item, Mapping)
        )
        mutation_events.extend(
            dict(item) for item in step.get("mutation_events", ()) if isinstance(item, Mapping)
        )
        for target, field in (
            (profiles, "provider_profiles"),
            (models, "provider_models"),
            (skills, "selected_skills"),
            (agents, "selected_plugin_agents"),
        ):
            values = step.get(field, ())
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                target.extend(str(item) for item in values if isinstance(item, str))
    unique_paths = {
        str(event[key])
        for event in mutation_events
        for key in ("path", "destination")
        if isinstance(event.get(key), str) and event.get(key)
    }
    return {
        **result,
        "metrics_scope": "business_attempt",
        "metrics_step_count": len(steps),
        "tool_results": tool_results,
        "tool_call_count": len(tool_results),
        "provider_metadata": provider_metadata,
        "mutation_events": mutation_events,
        "unique_mutated_path_count": len(unique_paths),
        "provider_profiles": list(dict.fromkeys(profiles)),
        "provider_models": list(dict.fromkeys(models)),
        "provider_profile": profiles[-1] if profiles else None,
        "provider_model": models[-1] if models else None,
        "selected_skills": list(dict.fromkeys(skills)),
        "selected_plugin_agents": list(dict.fromkeys(agents)),
    }
def structured_progress_decision(
    history: Sequence[Mapping[str, Any]],
    current: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Compare a current check observation with every compatible historical fact.

    The historical frontier is a set of identified facts, not a scalar maximum.
    Current validity remains separate and is never inferred from that frontier.
    """

    empty = {
        "schema": "SITINA_LOOP_PROGRESS_DECISION_V1",
        "compatible": False,
        "relevant_progress": False,
        "new_facts": [],
        "regressed_facts": [],
        "recovered_prior_state": False,
        "oscillation_detected": False,
        "current_state_fingerprint": None,
    }
    if not current or current.get("schema") != "SITINA_LOOP_CHECK_PROGRESS_V1":
        return empty
    current_satisfied = {str(item) for item in current.get("satisfied", ())}
    current_remaining = {str(item) for item in current.get("remaining", ())}
    universe = current_satisfied | current_remaining
    if not universe or current_satisfied & current_remaining:
        return empty

    optional_fields = ("evidence_refs", "conditions", "excluded_causes")
    current_facts = {"satisfied:" + item for item in current_satisfied}
    for field in optional_fields:
        current_facts.update(f"{field}:" + str(item) for item in current.get(field, ()))

    compatible_history: list[Mapping[str, Any]] = []
    historical_facts: set[str] = set()
    state_fingerprints: list[str] = []
    for item in history:
        if item.get("schema") != "SITINA_LOOP_CHECK_PROGRESS_V1":
            continue
        satisfied = {str(value) for value in item.get("satisfied", ())}
        remaining = {str(value) for value in item.get("remaining", ())}
        if satisfied | remaining != universe or satisfied & remaining:
            continue
        compatible_history.append(item)
        historical_facts.update("satisfied:" + value for value in satisfied)
        for field in optional_fields:
            historical_facts.update(f"{field}:" + str(value) for value in item.get(field, ()))
        state_fingerprints.append(
            _digest({
                "satisfied": sorted(satisfied),
                "remaining": sorted(remaining),
                **{field: sorted(str(value) for value in item.get(field, ())) for field in optional_fields},
            })
        )

    current_state = _digest({
        "satisfied": sorted(current_satisfied),
        "remaining": sorted(current_remaining),
        **{field: sorted(str(value) for value in current.get(field, ())) for field in optional_fields},
    })
    if history and not compatible_history:
        return {
            **empty,
            "incompatible_history": True,
            "current_state_fingerprint": current_state,
        }
    new_facts = sorted(current_facts - historical_facts) if compatible_history else []
    prior_current_facts: set[str] = set()
    if compatible_history:
        prior = compatible_history[-1]
        prior_current_facts.update("satisfied:" + str(value) for value in prior.get("satisfied", ()))
        for field in optional_fields:
            prior_current_facts.update(f"{field}:" + str(value) for value in prior.get(field, ()))
    regressed = sorted(prior_current_facts - current_facts)
    recovered = bool(compatible_history and current_state in state_fingerprints)
    oscillation = bool(
        len(state_fingerprints) >= 3
        and current_state == state_fingerprints[-2]
        and state_fingerprints[-1] == state_fingerprints[-3]
    )
    return {
        "schema": "SITINA_LOOP_PROGRESS_DECISION_V1",
        "compatible": True,
        "relevant_progress": bool(compatible_history and new_facts),
        "new_facts": new_facts,
        "regressed_facts": regressed,
        "recovered_prior_state": recovered,
        "oscillation_detected": oscillation,
        "current_state_fingerprint": current_state,
        "baseline_created": not compatible_history,
        "incompatible_history": False,
    }
