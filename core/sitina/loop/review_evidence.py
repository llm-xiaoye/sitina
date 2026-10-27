"""Review evidence views and bounded coverage, backed by native immutable records.

These helpers do not run tools, grant permissions, infer business correctness,
or treat model assertions as file facts. Raw receipts remain independently readable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


REVIEW_VIEW = "review-content-v2"


def compact_review_materials(context: Mapping[str, Any]) -> dict[str, Any]:
    """Factor exact repeated wire lists without changing host evidence or credit.

    Only the final model view uses this representation. The original execution
    context remains authoritative for navigation, read progress and validation.
    """
    original = dict(context)
    if context.get("phase") not in {"independent_read_only_review", "goal_completion"}:
        return original
    if "shared_review_sets" in context or "review_material_projection" in context:
        return original
    projected = json.loads(json.dumps(original, ensure_ascii=False))
    fields = frozenset({"paths", "allowed_object_ids", "allowed_source_refs",
                        "allowed_evidence_refs", "eligible_execution_refs",
                        "required_source_refs", "missing_source_refs", "unread_source_refs"})
    groups: dict[str, list[tuple[dict[str, Any], str]]] = {}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in tuple(value.items()):
                if (key in fields and isinstance(child, list) and child
                        and all(isinstance(item, str) for item in child)
                        and key + "_set" not in value):
                    identity = json.dumps(child, ensure_ascii=False, separators=(",", ":"))
                    if len(identity.encode("utf-8")) >= 96:
                        groups.setdefault(identity, []).append((value, key))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for section in ("response_contract", "review_source_roles", "history_read_progress"):
        visit(projected.get(section))
    shared: dict[str, list[str]] = {}
    for identity, locations in groups.items():
        if len(locations) < 2:
            continue
        name = "set-" + str(len(shared) + 1)
        shared[name] = json.loads(identity)
        for parent, key in locations:
            del parent[key]
            parent[key + "_set"] = name
    contract = projected.get("response_contract")
    aliases = contract.get("condition_aliases") if isinstance(contract, dict) else None
    aliased = (isinstance(aliases, dict) and bool(aliases)
               and list(aliases.values()) == projected.get("acceptance_conditions"))
    if aliased:
        projected["acceptance_conditions"] = list(aliases)
    if not shared and not aliased:
        return original
    projected["shared_review_sets"] = shared
    projected["review_material_projection"] = {
        "schema": "SITINA_REVIEW_MATERIAL_PROJECTION_V1",
        "conditions_use_existing_aliases": aliased,
        "instruction": (
            "Fields ending in _set reference the exact ordered list in shared_review_sets; "
            "read them as the corresponding field without _set. acceptance_conditions keys "
            "resolve to their verbatim text in response_contract.condition_aliases. No requirement "
            "or scope is removed. Set names are navigation only, never evidence, citations or read "
            "credit. Use canonical source refs for history tools and the existing citation aliases "
            "only where the response contract permits them."
        ),
    }
    size = lambda value: len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return projected if size(projected) < size(original) else original

# Evidence consumers recognize the same closed set of read-only review plans.
# This grants no source, task, binding, range or delivery credit on its own.
REVIEW_EVIDENCE_PLAN_BLOCKERS = frozenset({
    "review-disagreement:outcome-1",
    "review-protocol-repair:outcome-1",
    "review-independent-recheck:outcome-1",
})

REVIEW_ACCEPTANCE_POLICY = (
    "Cover every explicit user requirement. Implicit blocking conditions are limited to what makes the "
    "requested delivery valid (correct inputs and target, usable output, required authorization and no "
    "duplicate effects). Unrequested polish, refactoring and performance improvements are advisory, not "
    "new acceptance gates. Risk changes the depth of evidence, not which explicit requirements count. "
    "Judge actual outcomes; require a particular tool or action order only when the user requires it or "
    "it is necessary for validity. A hard requirement cannot be offset by a score on another requirement. "
    "Report all currently supported actionable gaps together, each tied to a requirement, observed "
    "evidence and the missing verification or correction. Separate missing evidence from a proven "
    "defect; ask the user only for information or authority the task actually lacks. "
    "Preserve command outcomes exactly; nonzero exit semantics come from the command contract, never "
    "from a success claim. Global claims require complete relevant coverage; sampling proves only its scope."
)


def review_read_handles(progress: Mapping[str, Any], artifact_ref: str) -> dict[str, Any]:
    """Name only authenticated ranges for this exact recipient and artifact.

    This is a request-local projection, not a read ledger or an evidence grant.
    A new reader root, source version or projection gets a different name.
    The name identifies evidence, not mutable reading progress. The validator
    independently resolves its scope from current authenticated ranges; the
    name itself grants no bytes and cannot restore lost read coverage.
    """
    recipient = progress.get("recipient_attempt_id")
    root = progress.get("recipient_root_attempt_id")
    if not isinstance(recipient, str) or not recipient or not isinstance(root, str) or not root:
        return {}
    handles = {}
    for row in progress["read_sources"]:
        ranges = [list(pair) for pair in row["read_ranges"]]
        if not ranges:
            continue
        total = row["total_bytes"]
        if (type(total) is not int or total <= 0
                or any(len(pair) != 2 or any(type(value) is not int for value in pair)
                       or not 0 <= pair[0] < pair[1] <= total for pair in ranges)):
            raise ValueError("native review progress contains invalid read ranges")
        scope = {"source_ref": row["source_ref"],
                 "scope": "whole_source" if _covers_whole_source(ranges, total) else "bounded",
                 "ranges": ranges}
        # Native protocol-repair attempts retain the same authenticated reader
        # root. An operation attempt is not a new reader; independent rechecks
        # have a different root and cannot borrow these handles or read credit.
        binding = {"artifact_ref": artifact_ref,
                   "recipient_root_attempt_id": root, "source_ref": row["source_ref"], "total_bytes": total,
                   "content_hash": row["content_hash"],
                   "source_content_hash": row["source_content_hash"],
                   "content_projection": row["content_projection"]}
        key = "read:" + hashlib.sha256(_json(binding).encode("utf-8")).hexdigest()[:32]
        if key in handles:
            raise ValueError("native review read handles are ambiguous")
        handles[key] = scope
    return handles


def review_scope_wire_contract(*, require_behavioral_coverage: bool = False) -> dict[str, Any]:
    """Use host-issued mechanical bindings; reviewer judgments remain required."""
    contract = review_scope_contract(require_behavioral_coverage=require_behavioral_coverage)
    condition = contract["properties"]["conditions"]["items"]
    condition["properties"]["sources"]["items"] = {
        "type": "object", "additionalProperties": False,
        "properties": {"read_handle": {"type": "string", "description":
            "Exact key from response_contract.read_handles. It binds only the displayed actual read ranges."}},
        "required": ["read_handle"]}
    for node in (condition, contract["properties"]["omitted_sources"]["items"]):
        node["required"].remove("requirement_quote")
        node["properties"]["requirement_quote"]["description"] = (
            "Optional. If omitted, the host binds the exact original text for requirement_source_ref. "
            "If supplied, it must be a verbatim quote; incorrect supplied text is rejected.")
    if require_behavioral_coverage:
        check = condition["properties"]["behavioral_checks"]["items"]
        check["properties"]["source_refs"]["description"] = (
            "Use distinct keys from response_contract.read_handles for evidence actually read. "
            "The host binds each key to its actual source and read ranges. Partial reads remain bounded. "
            "Legacy source references or citation aliases are accepted only when actually read.")
        check["properties"]["covered_scope"] = {
            "type": "string", "minLength": 1,
            "description": "Describe the behavior this check establishes. A legacy list is also accepted. "
                           "Required: the host never invents this judgment."}
    contract["description"] = (
        "Mandatory for PASS. Select actual read_handles instead of transcribing byte ranges. "
        "The host fills omitted original requirement quotes, but never a judgment, behavioral check, "
        "unverified scope or missing read. Partial evidence does not establish a global claim. "
        "For missing content follow history_read_progress.next_reads before submitting a verdict. "
        "Legacy explicit source_ref/scope/ranges remain supported with all original validation.")
    return contract


def _bind_review_mechanical_fields(assessment: Any, *, progress: Mapping[str, Any],
                                 artifact_ref: str, requirement_text: Mapping[str, str],
                                 citation_aliases: Mapping[str, str]) -> Any:
    """Expand only exact native handles and omitted quotes, never repair assertions."""
    from .termination import ReviewProtocolError

    if not isinstance(assessment, Mapping):
        return assessment  # The canonical format checker owns malformed structure.
    handles = review_read_handles(progress, artifact_ref)
    result = dict(assessment)
    for field in ("conditions", "omitted_sources"):
        rows = assessment.get(field)
        if not isinstance(rows, list):
            continue
        bound_rows = []
        for row in rows:
            if not isinstance(row, Mapping):
                bound_rows.append(row)
                continue
            bound = dict(row)
            reference = row.get("requirement_source_ref")
            if isinstance(reference, str):
                reference = citation_aliases.get(reference, reference)
                if "requirement_quote" not in row and reference in requirement_text:
                    bound["requirement_quote"] = requirement_text[reference]
            if field == "conditions" and isinstance(row.get("sources"), list):
                sources = []
                for source in row["sources"]:
                    if isinstance(source, Mapping) and "read_handle" in source:
                        key = source["read_handle"]
                        if set(source) != {"read_handle"}:
                            raise ReviewProtocolError("FORMAT_INVALID", "read_handle cannot override source or ranges")
                        # Both names are host-issued identities. An exact current
                        # citation alias can resolve only to an already-read
                        # source, never to all merely available evidence.
                        if isinstance(key, str) and key in citation_aliases:
                            matching = [handle for handle, scope in handles.items()
                                        if scope["source_ref"] == citation_aliases[key]]
                            if len(matching) == 1:
                                key = matching[0]
                        if not isinstance(key, str) or key not in handles:
                            raise ReviewProtocolError("EVIDENCE_MISSING", "unknown or stale read_handle; use current "
                                "response_contract.read_handles or read the missing native evidence")
                        sources.append({**handles[key], "ranges": [list(pair) for pair in handles[key]["ranges"]]})
                    else:
                        sources.append(source)
                bound["sources"] = sources
            if field == "conditions" and isinstance(row.get("behavioral_checks"), list):
                checks = []
                for check in row["behavioral_checks"]:
                    if not isinstance(check, Mapping):
                        checks.append(check)
                        continue
                    normalized = dict(check)
                    # A scalar statement and its singleton list have identical
                    # meaning. Missing semantic fields remain missing and fail.
                    if isinstance(check.get("covered_scope"), str):
                        normalized["covered_scope"] = [check["covered_scope"]]
                    refs = check.get("source_refs")
                    if isinstance(refs, list):
                        expanded = []
                        for ref in refs:
                            # Match the condition-level read_handle alias rule:
                            # selecting a current citation names only its actual
                            # authenticated ranges, including bounded reads.
                            handle_ref = ref
                            if isinstance(ref, str) and ref in citation_aliases:
                                matching = [handle for handle, scope in handles.items()
                                            if scope["source_ref"] == citation_aliases[ref]]
                                if len(matching) == 1:
                                    handle_ref = matching[0]
                            if isinstance(handle_ref, str) and handle_ref.startswith("read:"):
                                if handle_ref not in handles:
                                    raise ReviewProtocolError("EVIDENCE_MISSING",
                                        "unknown or stale behavioral read_handle; use current response_contract.read_handles")
                                evidence = handles[handle_ref]
                                expanded.append(evidence["source_ref"])
                                selected = bound.get("sources")
                                if isinstance(selected, list) and not any(
                                    isinstance(item, Mapping) and isinstance(item.get("source_ref"), str) and citation_aliases.get(
                                        item.get("source_ref"), item.get("source_ref")) == evidence["source_ref"]
                                    for item in selected
                                ):
                                    selected.append({**evidence, "ranges": [list(pair) for pair in evidence["ranges"]]})
                            else:
                                expanded.append(ref)
                        normalized["source_refs"] = expanded
                    checks.append(normalized)
                bound["behavioral_checks"] = checks
            bound_rows.append(bound)
        result[field] = bound_rows
    return result


def review_scope_contract(*, require_behavioral_coverage: bool = False) -> dict[str, Any]:
    """One nested contract supplies both the model instructions and format checks."""
    text = {"type": "string"}
    interval = {"type": "array", "minItems": 2, "maxItems": 2,
                "items": {"type": "integer"}}
    source = {"type": "object", "additionalProperties": False,
              "properties": {"source_ref": text,
                             "scope": {"type": "string", "enum": ["whole_source", "bounded"]},
                             "ranges": {"type": "array", "minItems": 1, "items": interval}}}
    condition = {"type": "object", "additionalProperties": False,
                 "properties": {
                     "condition": text, "requirement_source_ref": text, "requirement_quote": text,
                     "sources": {"type": "array", "items": source},
                     "justification": {"type": "string", "description":
                         "Reviewer judgment: why these actual ranges cover the requirement and its dependencies; never host-filled."},
                     "unverified": {"type": "array", "items": text}}}
    if require_behavioral_coverage:
        check = {"type": "object", "additionalProperties": False, "properties": {
            "claim": {"type": "string", "description": "Specific required behavior, including requirements delegated to an authorized specification; not just an umbrella acceptance summary."},
            "covered_scope": {"type": "array", "minItems": 1, "items": text},
            "challenge": {"type": "string", "description": "A concrete alternative path, boundary, or counterexample that could falsify the claim. Do not invent a new requirement."},
            "expected": text,
            "observed": {"type": "string", "description": "What the cited evidence actually establishes, not an inferred success from a test count."},
            "method": {"type": "string", "enum": ["source_analysis", "execution_record"]},
            "source_refs": {"type": "array", "minItems": 1, "items": text, "description":
                "Distinct current evidence references. A fully read source may be cited directly; "
                "a partially read source must also declare its verified ranges in this condition's sources. "
                "Requirements alone do not prove behavior."},
            "remaining_scope": {"type": "array", "items": text, "description":
                "Unresolved REQUIRED behavior only; any entry blocks PASS. Explain non-blocking method "
                "limitations or out-of-task scope in condition.justification instead, with why the requirement "
                "is established. Never hide a required evidence gap as a limitation."},
        }}
        check["required"] = list(check["properties"])
        condition["properties"]["behavioral_checks"] = {
            "type": "array", "items": check,
            "description": "PASS needs at least one concrete check per condition. For missing evidence, keep the gap in unverified; never fabricate a check."
        }
    omission = {"type": "object", "additionalProperties": False,
                "properties": {"source_ref": text, "reason": text,
                               "requirement_source_ref": text, "requirement_quote": text}}
    contract = {"type": "object", "additionalProperties": False,
                "description": ("Mandatory for PASS; optional as a whole for non-PASS. "
                                if require_behavioral_coverage else "Optional as a whole. ")
                               + "When supplied, every declared nested field is required. "
                               "PASS requires empty unverified arrays. A non-PASS may preserve independently "
                               "verified conditions while identifying remaining gaps. A behavioral source may reuse "
                               "one unambiguous explicit source scope declared in any condition of this same response; "
                               "partial reads remain bounded and never become full-source evidence.",
                "properties": {"conditions": {"type": "array", "minItems": 1, "items": condition},
                               "omitted_sources": {"type": "array", "items": omission, "description":
                                   "Explain unused current required or optional sources when appropriate. "
                                   "Never omit an original requirement, an already-used source, or an unknown source. "
                                   "Each omission needs a nonempty reason anchored to the real user requirement; "
                                   "an omission gives no read or behavior credit."}}}
    for node in (source, condition, omission, contract):
        node["required"] = list(node["properties"])
    return contract


def bind_review_response_aliases(context: dict[str, Any]) -> None:
    """Provide short exact identities; never supply a verdict or read credit.

    References added by native file reads retain the same names. A changed
    artifact or acceptance list changes the namespace and rejects stale names.
    """
    contract = context["response_contract"]
    conditions = context["acceptance_conditions"]
    scope = {"artifact_ref": contract["observed_artifact_ref"],
             "review_subject_lineage": contract["review_subject_lineage"],
             "conditions": conditions}
    namespace = hashlib.sha256(_json(scope).encode("utf-8")).hexdigest()[:24]
    references = sorted({row["source_ref"] for row in context["review_source_roles"]})
    citations = {f"cite:{namespace}:{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:12]}": ref
                 for ref in references}
    if len(citations) != len(references):
        raise ValueError("review citation aliases are ambiguous")
    contract["citation_aliases"] = citations
    contract["condition_aliases"] = {
        f"condition:{namespace}:{index + 1}": text for index, text in enumerate(conditions)
    }
    contract["read_handles"] = review_read_handles(
        context.get("history_read_progress", {}), contract["observed_artifact_ref"])
    contract["scope_identity_instruction"] = (
        "In evidence_assessment.conditions[].condition use the exact key from condition_aliases. "
        "Use citation_aliases for requirement_source_ref and finding evidence_refs. "
        "For behavioral source_refs select read_handles of evidence actually read. "
        "For conditions[].sources select exact read_handles as {read_handle: key}; the host binds only "
        "those actual ranges. Omit requirement_quote to bind original text from the chosen requirement "
        "source; an explicitly supplied incorrect quote remains an error. Supply your own semantic "
        "coverage judgment and behavioral checks. A bounded handle cannot prove an unread part. "
        "An available source is not necessarily read: follow history_read_progress.next_reads for gaps. "
        "Handles remain stable as the same reviewer reads more of unchanged evidence. "
        "Their coverage always comes from current authenticated read ranges. Reader-root, artifact "
        "or content changes invalidate handles. Exact current citation aliases for already-read "
        "sources are also accepted; aliases for unread evidence never grant coverage. "
        "Never guess, abbreviate or repair a source hash."
    )


def _expand_scope_aliases(assessment: Mapping[str, Any], *,
                          condition_aliases: Mapping[str, str],
                          citation_aliases: Mapping[str, str]) -> dict[str, Any]:
    from .termination import ReviewProtocolError

    def resolve(value: str, aliases: Mapping[str, str], prefix: str) -> str:
        if not value.startswith(prefix):
            return value  # Exact legacy identities remain valid; no fuzzy matching.
        if value not in aliases:
            raise ReviewProtocolError("EVIDENCE_MISSING", "unknown or stale review identity alias: " + value)
        return aliases[value]

    rows = []
    for row in assessment["conditions"]:
        rows.append({**dict(row),
            "condition": resolve(row["condition"], condition_aliases, "condition:"),
            "requirement_source_ref": resolve(row["requirement_source_ref"], citation_aliases, "cite:"),
            "sources": [{**dict(source), "source_ref": resolve(source["source_ref"], citation_aliases, "cite:")}
                        for source in row["sources"]]})
    omitted = [{**dict(row),
                "source_ref": resolve(row["source_ref"], citation_aliases, "cite:"),
                "requirement_source_ref": resolve(row["requirement_source_ref"], citation_aliases, "cite:")}
               for row in assessment["omitted_sources"]]
    return {**dict(assessment), "conditions": rows, "omitted_sources": omitted}


def _scope_format_errors(value: Any, contract: Mapping[str, Any], path: str = "") -> list[dict[str, Any]]:
    expected = contract["type"]
    valid = {"object": isinstance(value, Mapping), "array": isinstance(value, list),
             "string": isinstance(value, str), "integer": type(value) is int}[expected]
    if not valid:
        return [{"path": path or "/", "expected_type": expected, "observed_type": type(value).__name__}]
    errors = []
    if expected == "object":
        fields = contract["required"]
        missing = [field for field in fields if field not in value]
        unexpected = sorted(str(field) for field in value if field not in contract["properties"])
        if missing or unexpected:
            errors.append({"path": path or "/", "expected_fields": sorted(fields),
                           "missing_fields": missing, "unexpected_fields": unexpected,
                           "missing_field_paths": [path + "/" + field for field in missing]})
        for field, child in contract["properties"].items():
            if field in value:
                errors.extend(_scope_format_errors(value[field], child, path + "/" + field))
    elif expected == "array":
        if len(value) < contract.get("minItems", 0) or len(value) > contract.get("maxItems", len(value)):
            errors.append({"path": path or "/", "observed_count": len(value),
                           "min_items": contract.get("minItems", 0), "max_items": contract.get("maxItems")})
        for index, item in enumerate(value):
            errors.extend(_scope_format_errors(item, contract["items"], path + "/" + str(index)))
    elif "enum" in contract and value not in contract["enum"]:
        errors.append({"path": path or "/", "expected_values": list(contract["enum"]), "observed": value})
    return errors


def bind_review_identity(document: Mapping[str, Any], *, acceptance_item_id: str,
                         review_subject_lineage_id: str, artifact_ref: str) -> dict[str, Any]:
    """Fill only absent host-owned metadata; conflicting model values still fail."""
    from .termination import REVIEW_SCHEMA_V2, TERMINATION_CONTRACT_VERSION
    bound = dict(document)
    for key, value in {
        "schema": REVIEW_SCHEMA_V2, "termination_contract_version": TERMINATION_CONTRACT_VERSION,
        "acceptance_item_id": acceptance_item_id, "review_subject_lineage": review_subject_lineage_id,
        "observed_artifact_ref": artifact_ref,
    }.items():
        bound.setdefault(key, value)
    return bound


def review_recipient_attempt_chain(plans: Mapping[str, Mapping[str, Any]], attempt_id: str, *,
                                   task_id: str, session_id: str) -> tuple[str, ...]:
    """Recover a native reader, including its protocol repairs but never another reader."""
    anchor = plans.get(attempt_id)
    if not isinstance(anchor, Mapping):
        return ()
    fields = ("artifact_ref", "goal_version", "criteria_lineage_version")
    chain: list[str] = []
    pending_protocol: list[str] = []
    seen: set[str] = set()
    reader_kind: str | None = None
    cursor = attempt_id
    while cursor:
        if cursor in seen:
            return ()
        seen.add(cursor)
        plan = plans.get(cursor)
        if (not isinstance(plan, Mapping) or plan.get("attempt_id") != cursor
                or plan.get("schema") != "SITINA_LOOP_ATTEMPT_PLAN_V1"
                or plan.get("task_id") != task_id or plan.get("session_id") != session_id):
            return ()
        blocker = plan.get("blocker_id")
        if blocker not in REVIEW_EVIDENCE_PLAN_BLOCKERS:
            return tuple(chain)
        if (plan.get("lineage_id") != f"lineage:{plan.get('goal_version')}:{blocker}"
                or not isinstance(plan.get("artifact_ref"), str)):
            return ()
        if any(plan.get(key) != anchor.get(key) for key in fields):
            return tuple(chain)
        if blocker == "review-protocol-repair:outcome-1":
            pending_protocol.append(cursor)
        else:
            kind = "independent" if blocker == "review-independent-recheck:outcome-1" else "primary"
            if reader_kind is not None and kind != reader_kind:
                return tuple(chain)
            reader_kind = kind
            chain.extend(pending_protocol)
            pending_protocol.clear()
            chain.append(cursor)
        prior = plan.get("prior_attempt_id")
        if prior is not None and (not isinstance(prior, str) or not prior):
            return ()
        cursor = prior
    # Protocol-only tails have no native reader to authorize inherited credit.
    return tuple(chain)


def review_recipient_attempt_ids(plans: Mapping[str, Mapping[str, Any]], attempt_id: str, *,
                                 task_id: str, session_id: str) -> frozenset[str]:
    return frozenset(review_recipient_attempt_chain(
        plans, attempt_id, task_id=task_id, session_id=session_id,
    ))


def latest_primary_review_attempt(plans: Mapping[str, Mapping[str, Any]], *, task_id: str,
                                  session_id: str, artifact_ref: str, goal_version: int,
                                  acceptance_version: int, criteria_lineage_version: int) -> str | None:
    """Continue the actual primary reader, not merely the latest same-blocker plan."""
    expected = {"artifact_ref": artifact_ref, "goal_version": goal_version,
                "acceptance_version": acceptance_version,
                "criteria_lineage_version": criteria_lineage_version}
    for attempt_id, plan in reversed(tuple(plans.items())):
        if any(plan.get(key) != value for key, value in expected.items()):
            continue
        chain = review_recipient_attempt_chain(
            plans, attempt_id, task_id=task_id, session_id=session_id,
        )
        if chain and plans[chain[-1]].get("blocker_id") == "review-disagreement:outcome-1":
            return attempt_id
    return None


def classify_review_failure(*, request: Mapping[str, Any] | None,
                            unread_source_refs: Sequence[str],
                            citable_source_refs: Sequence[str]) -> str:
    """Attribute only what the authenticated request and current gate establish."""
    if request is None:
        return "UNDETERMINED"
    advertised = set(request["citable_source_refs"])
    current = set(citable_source_refs)
    if advertised - current or set(unread_source_refs) & advertised:
        return "INTERNAL_EVIDENCE_CONFLICT"
    return "MODEL_RESPONSE"


def current_review_summary(summary: Mapping[str, Any], *, roles: Sequence[Mapping[str, Any]],
                           progress: Mapping[str, Any]) -> dict[str, Any]:
    """Historical locators never become current citation candidates by presentation."""
    allowed = {row["source_ref"] for row in roles}
    observed = set(progress.get("citable_source_refs", ()))
    result: dict[str, Any] = {
        "kind": "current_review_evidence",
        "authority": "Only review_source_roles grants citation eligibility. Read coverage is in "
                     "history_read_progress; eligibility and historical success are not business approval.",
    }
    omitted = 0
    # Capacity forecasting consumes these host counters. They describe the
    # current journal binding and never grant a citation or a business verdict.
    for field in ("binding", "history_query_receipt_count"):
        if field in summary:
            result[field] = summary[field]
    for field in ("file_read_sources", "history_read_sources", "recent_action_results"):
        selected = []
        for row in summary.get(field, ()):
            ref = row.get("source_ref")
            if ref not in allowed:
                omitted += 1
                continue
            selected.append({**dict(row), "current_review_citation":
                "READ_RANGES_ONLY" if ref in observed else "NOT_YET_AUTHENTICATED_READ",
                "coverage_authority": "execution_context.history_read_progress"})
        result[field] = selected
    # Main-agent plans, free-form notes and action counters are not independent
    # review evidence. Their original records remain available through authorized sources.
    result["omitted_historical_locator_count"] = omitted
    return result


def independent_review_used(plans: Mapping[str, Mapping[str, Any]], artifact_ref: str) -> bool:
    """A committed plan consumes the single recheck even if interrupted before send."""
    return any(plan.get("artifact_ref") == artifact_ref
               and plan.get("blocker_id") == "review-independent-recheck:outcome-1"
               for plan in plans.values())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def review_content_bytes(document: Mapping[str, Any]) -> tuple[bytes, str] | None:
    """Expose a stable NFC display of verified file contents once.

    The directory binds every member, including opaque members and relationships.
    Original bytes remain bound by their own hashes and raw source.
    Offsets and display hashes address the NFC view, never the original bytes.
    Only the native read-file producer is unwrapped; arbitrary JSON strings are not.
    """
    from sitina.extensions.tools import file_read_content_bound

    if not isinstance(document, Mapping):
        return None
    result = document.get("result")
    if (document.get("effect_status") != "SUCCEEDED" or not isinstance(result, Mapping)
            or result.get("tool") != "sitina_read_file" or result.get("status") != "ok"):
        return None
    value = result.get("value")
    if (not isinstance(value, Mapping) or value.get("exists") is not True
            or not isinstance(value.get("path"), str) or not file_read_content_bound(value)):
        return None
    members = []
    content_view = value.get("content_view")
    if isinstance(content_view, Mapping) and content_view.get("format") == "utf8-nfc":
        raw = base64.b64decode(content_view["source_bytes_base64"], validate=True)
        text = raw.decode("utf-8", errors="strict")
        members.append({"name": "content", "text": text, "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(), "directory": False})
    elif isinstance(content_view, Mapping) and content_view.get("format") == "zip-members-json":
        archive = json.loads(value["content"])
        for entry in archive["entries"]:
            if not isinstance(entry, Mapping):
                raise ValueError("review file member is not an object")
            name, text = entry.get("name"), entry.get("content")
            size, digest = entry.get("size_bytes"), entry.get("sha256")
            if (not isinstance(name, str) or type(size) is not int or size < 0
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise ValueError("review file member identity is invalid")
            if text is not None:
                if not isinstance(text, str) or entry.get("content_encoding") != "utf-8":
                    raise ValueError("review file member encoding is invalid")
                source_bytes = entry.get("source_bytes_base64")
                if source_bytes is None:
                    raw = text.encode("utf-8")
                else:
                    if not isinstance(source_bytes, str):
                        raise ValueError("review member source bytes are invalid")
                    raw = base64.b64decode(source_bytes, validate=True)
                    original = raw.decode("utf-8", errors="strict")
                    if (base64.b64encode(raw).decode("ascii") != source_bytes
                            or unicodedata.normalize("NFC", original) != text):
                        raise ValueError("review member display does not match original bytes")
                    text = original
                if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError("review file member does not match its content identity")
            elif entry.get("content_encoding") is not None or entry.get("source_bytes_base64") is not None:
                raise ValueError("opaque review member has a text encoding or text source bytes")
            members.append({"name": name, "text": text, "size_bytes": size, "sha256": digest,
                            "directory": entry.get("directory") is True})
        if len({member["name"] for member in members}) != len(members):
            raise ValueError("review file members have ambiguous names")
    else:
        raw = value["content"].encode("utf-8")
        members.append({"name": "content", "text": value["content"], "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(), "directory": False})
    body = bytearray()
    rows = []
    for member in members:
        row = {key: member[key] for key in ("name", "size_bytes", "sha256", "directory")}
        row["opaque"] = member["text"] is None
        if member["text"] is not None:
            body.extend(("\nMEMBER " + _json(member["name"]) + "\n").encode("utf-8"))
            displayed = unicodedata.normalize("NFC", member["text"]).encode("utf-8")
            row["display_normalization"] = "NFC"
            row["display_size_bytes"] = len(displayed)
            row["display_sha256"] = hashlib.sha256(displayed).hexdigest()
            row["start_byte"] = len(body)
            body.extend(displayed)
            row["end_byte"] = len(body)
            body.extend(b"\n")
        rows.append(row)
    metadata = {"schema": "SITINA_REVIEW_FILE_VIEW_V2", "path": value["path"],
                "source_version": value["version"], "view": REVIEW_VIEW,
                "text_normalization": "NFC", "original_bytes_view": "raw",
                "limitations": "Displayed text is NFC-normalized. Member size_bytes/sha256 bind original "
                              "bytes; display_* and offsets bind displayed text. For byte- or Unicode-"
                              "representation-sensitive checks, read the raw source and its base64 bytes. "
                              "Reading this view does not verify opaque bytes, formulas, business "
                              "correctness or preservation.",
                "members": rows}
    # Header length grows monotonically as decimal byte offsets gain digits.
    header_size = 0
    while True:
        directory = [{**row, **({"start_byte": row["start_byte"] + header_size,
                                "end_byte": row["end_byte"] + header_size}
                               if "start_byte" in row else {})} for row in rows]
        header = (_json({**metadata, "members": directory}) + "\n").encode("utf-8")
        if len(header) == header_size:
            return header + bytes(body), REVIEW_VIEW
        if len(header) < header_size:
            raise ValueError("review view directory offsets did not converge")
        header_size = len(header)


def source_read_bytes(document: Mapping[str, Any], projection: str | None,
                      view: str = "raw") -> tuple[bytes, str | None]:
    if view not in {"raw", "review"}:
        raise ValueError("source view must be raw or review")
    if view == "review":
        content = review_content_bytes(document)
        if content is not None:
            return content
    from sitina.journal.model import canonical_json_bytes

    return canonical_json_bytes(document), projection


def review_file_delivery_ranges(document: Mapping[str, Any], envelope: Any) -> tuple[bytes, str, list[list[int]]] | None:
    """Credit only verbatim file-member text in a complete native tool result.

    The caller authenticates the sent request, recipient and source scope.
    Metadata headers, opaque members and original-byte views gain no credit.
    """
    if (not isinstance(envelope, Mapping)
            or envelope.get("schema") != "SITINA_UNTRUSTED_TOOL_DATA_V1"
            or envelope.get("tool") != "sitina_read_file" or envelope.get("status") != "ok"):
        return None
    delivered = envelope.get("result")
    original = document.get("result")
    if (not isinstance(delivered, Mapping) or delivered.get("kind") != "operation_result"
            or delivered.get("status") != "OK" or delivered.get("complete_value_visible") is not True
            or not isinstance(original, Mapping) or delivered.get("value") != original.get("value")):
        return None
    try:
        projected = review_content_bytes(document)
        if projected is None:
            return None
        raw, projection = projected
        directory = json.loads(raw.split(b"\n", 1)[0])
        value = delivered["value"]
        view = value.get("content_view")
        if isinstance(view, Mapping) and view.get("format") == "zip-members-json":
            visible = {item["name"]: item.get("content") for item in json.loads(value["content"])["entries"]}
        else:
            visible = {"content": value["content"]}
        ranges = []
        for member in directory["members"]:
            if member["opaque"] or "start_byte" not in member:
                continue
            start, end = member["start_byte"], member["end_byte"]
            text = visible.get(member["name"])
            if (type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(raw)
                    or not isinstance(text, str) or text.encode("utf-8") != raw[start:end]):
                return None
            if start < end:
                ranges.append([start, end])
        return (raw, projection, ranges) if ranges else None
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None

def _contains(ranges: Sequence[Sequence[int]], start: int, end: int) -> bool:
    return any(left <= start <= end <= right for left, right in ranges)


def _covers_whole_source(ranges: Sequence[Sequence[int]], total: int) -> bool:
    """Accept equivalent pagination, never fill gaps or count overlaps twice."""
    if total <= 0:
        return False
    covered = 0
    for start, end in sorted(ranges):
        if not 0 <= start < end <= total or start > covered:
            return False
        covered = max(covered, end)
    return covered == total


def requirement_text(document: Any) -> str:
    """Keep original strings quotable; derived acceptance lists are not authority."""
    if isinstance(document, str):
        return document
    if isinstance(document, Mapping):
        return "\n".join(requirement_text(value) for key, value in document.items()
                         if key != "acceptance_conditions")
    if isinstance(document, list):
        return "\n".join(requirement_text(value) for value in document)
    return ""


def validate_scoped_review(
    assessment: Mapping[str, Any], *, conditions: Sequence[str],
    requirement_text: Mapping[str, str], progress: Mapping[str, Any],
    required_sources: Sequence[str], available_sources: Sequence[str],
    object_bindings: Mapping[str, str], artifact_ref: str,
    input_bindings: Mapping[str, str] | None = None,
    require_complete: bool = True,
    condition_aliases: Mapping[str, str] | None = None,
    citation_aliases: Mapping[str, str] | None = None,
    require_behavioral_coverage: bool = False,
    allow_read_handles: bool = False,
) -> dict[str, Any]:
    """Validate traceability/coverage of a reviewer-owned scope explanation.

    Semantic sufficiency remains the independent reviewer responsibility. The
    host verifies citations and actual coverage, not an assertion of correct work.
    Legacy reviews without this optional contract still require full source reads.
    """
    from .termination import ReviewProtocolError

    def reject(message: str, *, kind: str = "EVIDENCE_MISSING",
               scope_path: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        if scope_path is not None:
            diagnostic = {"scope_path": scope_path, **dict(details or {})}
            message += "; scope_diagnostic=" + json.dumps(diagnostic, ensure_ascii=False, sort_keys=True)
        raise ReviewProtocolError(kind, "review scope: " + message)

    if allow_read_handles:
        assessment = _bind_review_mechanical_fields(
            assessment, progress=progress, artifact_ref=artifact_ref,
            requirement_text=requirement_text, citation_aliases=citation_aliases or {})
    format_errors = _scope_format_errors(assessment, review_scope_contract(
        require_behavioral_coverage=require_behavioral_coverage))
    if format_errors:
        first = format_errors[0]
        grouped = {}
        for error in format_errors:
            shape = {key: value for key, value in error.items() if key != "path"}
            key = json.dumps(shape, sort_keys=True)
            group = grouped.setdefault(key, {**shape, "count": 0, "example_paths": []})
            group["count"] += 1
            if len(group["example_paths"]) < 2:
                group["example_paths"].append(error["path"])
        reject("expected conditions and omitted_sources with the complete nested contract",
               kind="FORMAT_INVALID", scope_path=first["path"],
               details={**{key: value for key, value in first.items() if key != "path"},
                        "format_errors": [first], "format_error_count": len(format_errors),
                        "format_errors_omitted": max(0, len(format_errors) - 1),
                        "format_error_groups": list(grouped.values())[:4],
                        "format_error_groups_omitted": max(0, len(grouped) - 4)})
    assessment = _expand_scope_aliases(assessment, condition_aliases=condition_aliases or {},
                                       citation_aliases=citation_aliases or {})
    rows, omitted = assessment["conditions"], assessment["omitted_sources"]
    by_ref = {row["source_ref"]: row for row in progress["read_sources"]}
    available = set(available_sources)
    seen_conditions, used_sources, omission_refs = set(), set(), set()
    normalized = []
    reference_errors = []
    for condition_index, row in enumerate(rows):
        seen = set()
        for source_index, source in enumerate(row["sources"]):
            ref = source["source_ref"]
            reasons = []
            if ref not in available:
                reasons.append("SOURCE_UNAVAILABLE")
            if ref in seen:
                reasons.append("SOURCE_DUPLICATED")
            if ref not in by_ref:
                reasons.append("SOURCE_NOT_READ")
            seen.add(ref)
            if reasons:
                reference_errors.append({"condition_index": condition_index, "source_index": source_index,
                                         "source_ref": ref, "reasons": reasons})
    if reference_errors:
        diagnostic = reference_errors[0] if len(reference_errors) == 1 else {
            "issues": reference_errors[:8], "issue_count": len(reference_errors),
            "issues_omitted": max(0, len(reference_errors) - 8),
        }
        reject("source reference validation failed: " + json.dumps(diagnostic, ensure_ascii=False, sort_keys=True))

    def requirement(row: Mapping[str, Any], scope_path: str) -> dict[str, str]:
        reference, quote = row.get("requirement_source_ref"), row.get("requirement_quote")
        if reference not in requirement_text or not quote.strip() or quote not in requirement_text[reference]:
            reject("each scope must cite a verbatim current user requirement", scope_path=scope_path)
        return {"source_ref": reference, "quote": quote}

    for condition_index, row in enumerate(rows):
        condition = row["condition"]
        if not isinstance(condition, str) or not condition.strip() or condition in seen_conditions:
            reject("condition is empty or duplicated", kind="FORMAT_INVALID", scope_path=f"/conditions/{condition_index}/condition",
                   details={"expected": "nonempty unique condition string"})
        seen_conditions.add(condition)
        anchor = requirement(row, f"/conditions/{condition_index}")
        if not row["justification"].strip():
            reject("scope reduction requires a coverage explanation",
                   scope_path=f"/conditions/{condition_index}/justification")
        if require_complete and row["unverified"]:
            reject("an unverified part of a requirement cannot obtain complete coverage",
                   scope_path=f"/conditions/{condition_index}/unverified",
                   details={"unverified_count": len(row["unverified"]),
                            "required_for_complete_coverage": []})
        evidence = []
        seen_refs = set()
        for source_index, source in enumerate(row["sources"]):
            ref, scope, ranges = source["source_ref"], source["scope"], source["ranges"]
            observed = by_ref[ref]
            for interval_index, interval in enumerate(ranges):
                scope_path = f"/conditions/{condition_index}/sources/{source_index}/ranges/{interval_index}"
                if (not 0 <= interval[0] < interval[1] <= observed["total_bytes"]
                        or not _contains(observed["read_ranges"], *interval)):
                    reject("declared evidence range was not actually delivered and read",
                           scope_path=scope_path, details={
                               "source_ref": ref, "declared_range": interval,
                               "total_bytes": observed["total_bytes"],
                               "read_ranges": observed["read_ranges"][:8],
                               "read_range_count": len(observed["read_ranges"]),
                               "read_ranges_omitted": max(0, len(observed["read_ranges"]) - 8),
                           })
            if scope == "whole_source" and (not observed["complete_source_read"]
                                          or not _covers_whole_source(ranges, observed["total_bytes"])):
                reject("whole-source coverage requires a complete actual read and declared ranges without gaps",
                       scope_path=f"/conditions/{condition_index}/sources/{source_index}/ranges",
                       details={"source_ref": ref, "total_bytes": observed["total_bytes"],
                                "complete_source_read": observed["complete_source_read"],
                                "declared_ranges": ranges[:8], "declared_range_count": len(ranges),
                                "read_ranges": observed["read_ranges"][:8]})
            seen_refs.add(ref)
            used_sources.add(ref)
            evidence.append({**dict(source), **{key: observed[key] for key in
                ("source_content_hash", "content_hash", "content_projection", "total_bytes", "receipt_source_ref")}})
        normalized_row = {"condition": condition, "requirement": anchor, "sources": evidence,
                          "justification": row["justification"], "unverified": list(row["unverified"])}
        if require_behavioral_coverage:
            checks = []
            if not row["behavioral_checks"] and (require_complete or not row["unverified"]):
                reject("reading sources or passing producer tests alone does not establish behavior coverage; "
                       "supply concrete behavioral_checks or report the actual evidence gap",
                       scope_path=f"/conditions/{condition_index}/behavioral_checks")
            for check_index, check in enumerate(row["behavioral_checks"]):
                check_path = f"/conditions/{condition_index}/behavioral_checks/{check_index}"
                for key in ("claim", "challenge", "expected", "observed"):
                    if not check[key].strip():
                        reject("a behavioral check needs an explicit claim, challenge, expectation and observation",
                               scope_path=check_path + "/" + key)
                for key in ("covered_scope", "remaining_scope"):
                    if any(not value.strip() for value in check[key]) or len(set(check[key])) != len(check[key]):
                        reject("behavior scope entries must be nonempty and unique", scope_path=check_path + "/" + key)
                if check["remaining_scope"] and (require_complete or not row["unverified"]):
                    reject("remaining behavior scope must stay unverified and cannot pass",
                           scope_path=check_path + "/remaining_scope")
                references = []
                for ref in check["source_refs"]:
                    if ref.startswith("cite:"):
                        if ref not in (citation_aliases or {}):
                            reject("unknown or stale behavioral evidence alias", scope_path=check_path + "/source_refs")
                        ref = (citation_aliases or {})[ref]
                    if ref in references:
                        reject("behavioral evidence contains a duplicate reference",
                               scope_path=check_path + "/source_refs")
                    if ref not in seen_refs:
                        if ref not in available or ref not in by_ref:
                            reject("behavioral evidence must be current, available and actually read",
                                   scope_path=check_path + "/source_refs",
                                   details={"source_ref": ref,
                                            "reason": "SOURCE_UNAVAILABLE" if ref not in available else "SOURCE_NOT_READ",
                                            "next_action": "select an actual read_handle or read this source before citing it"})
                        observed = by_ref[ref]
                        total = observed["total_bytes"]
                        # Source identity and explicit byte scope are shared within
                        # this one response. Conditions still own their semantic
                        # claims. Never infer a broader scope from another claim.
                        declarations = {
                            json.dumps(source, sort_keys=True): source
                            for other_row in rows for source in other_row["sources"]
                            if source["source_ref"] == ref
                        }
                        if len(declarations) > 1:
                            reject("shared behavioral source has conflicting declared scopes; declare the intended scope locally",
                                   scope_path=check_path + "/source_refs",
                                   details={"source_ref": ref, "declared_scope_count": len(declarations)})
                        if declarations:
                            shared = dict(next(iter(declarations.values())))
                            for interval in shared["ranges"]:
                                if (not 0 <= interval[0] < interval[1] <= total
                                        or not _contains(observed["read_ranges"], *interval)):
                                    reject("shared evidence range was not actually delivered and read",
                                           scope_path=check_path + "/source_refs",
                                           details={"source_ref": ref, "declared_range": interval,
                                                    "read_ranges": observed["read_ranges"][:8]})
                            if shared["scope"] == "whole_source" and (
                                    not observed["complete_source_read"]
                                    or not _covers_whole_source(shared["ranges"], total)):
                                reject("shared whole-source coverage requires a complete actual read without gaps",
                                       scope_path=check_path + "/source_refs", details={"source_ref": ref})
                        else:
                            if (not observed["complete_source_read"] or total <= 0
                                    or not _contains(observed["read_ranges"], 0, total)):
                                reject("a partially read behavioral source needs explicit verified ranges in the assessment's sources",
                                       scope_path=check_path + "/source_refs",
                                       details={"source_ref": ref, "total_bytes": total,
                                                "read_ranges": observed["read_ranges"][:8],
                                                "read_range_count": len(observed["read_ranges"]),
                                                "required_action": "Declare only the actually used, already-read ranges; read more if the claim requires more evidence."})
                            shared = {"source_ref": ref, "scope": "whole_source", "ranges": [[0, total]]}
                        evidence.append({**shared,
                            **{key: observed[key] for key in
                               ("source_content_hash", "content_hash", "content_projection", "total_bytes", "receipt_source_ref")}})
                        seen_refs.add(ref)
                        used_sources.add(ref)
                    references.append(ref)
                if set(references) <= set(requirement_text):
                    reject("requirements alone do not demonstrate a behavioral check",
                           scope_path=check_path + "/source_refs")
                checks.append({**check, "source_refs": references})
            normalized_row["behavioral_checks"] = checks
        # Check the resolved evidence, after behavioral citations have passed
        # the same availability/read/range checks as explicit source entries.
        # Otherwise the documented direct-citation form is rejected before its
        # existing validation branch can bind any evidence. No claim is filled.
        if not evidence and not (row["unverified"] and not require_complete):
            reject("each condition requires actual evidence")
        if not row["unverified"] and seen_refs <= set(requirement_text):
            reject("reading requirements alone is not evidence about the deliverable")
        normalized.append(normalized_row)
    if require_complete and not set(conditions) <= seen_conditions:
        by_condition = {text: alias for alias, text in (condition_aliases or {}).items()}
        missing = [by_condition.get(text, text) for text in conditions if text not in seen_conditions]
        reject("scope omitted a current acceptance condition", scope_path="/conditions",
               details={"missing_condition_identities": missing[:8], "missing_count": len(missing)})
    for omission_index, row in enumerate(omitted):
        ref = row["source_ref"]
        # Optional receipts may be explicitly excluded with a reason. Requiring
        # an omission to be required contradicts the same catalog's optional role.
        reasons = []
        if ref not in available:
            reasons.append("SOURCE_UNAVAILABLE")
        if ref in used_sources:
            reasons.append("SOURCE_ALSO_USED")
        if ref in omission_refs:
            reasons.append("SOURCE_ALREADY_OMITTED")
        if ref in requirement_text:
            reasons.append("ORIGINAL_REQUIREMENT_CANNOT_BE_OMITTED")
        if not row["reason"].strip():
            reasons.append("OMISSION_REASON_EMPTY")
        if reasons:
            reject("source omission is duplicate, contradictory or lacks a reason",
                   scope_path=f"/omitted_sources/{omission_index}",
                   details={"source_ref": ref, "reasons": reasons})
        requirement(row, f"/omitted_sources/{omission_index}")
        omission_refs.add(ref)
    missing_sources = sorted(set(required_sources) - used_sources - omission_refs - set(progress["completed_source_refs"]))
    if require_complete and missing_sources:
        reject("every remaining required source needs evidence or an explicit omission explanation",
               scope_path="/omitted_sources",
               details={"missing_source_refs": missing_sources[:8],
                        "missing_count": len(missing_sources),
                        "required_action": "Read and use the relevant evidence, or explain why it is not necessary for the cited requirement. Do not omit original requirements."})
    delivered = {row["source_ref"] for row in progress.get("delivered_requirement_sources", ())
                 if row["source_ref"] in requirement_text and row["text_hash"] == hashlib.sha256(
                     requirement_text[row["source_ref"]].encode("utf-8")).hexdigest()}
    if not set(requirement_text) <= set(progress["completed_source_refs"]) | delivered:
        reject("the original request and effective corrections must still be read in full")
    return {"schema": "SITINA_REVIEW_SCOPE_EVIDENCE_V1", "artifact_ref": artifact_ref,
            "complete_review": require_complete,
            "conditions": normalized, "omitted_sources": omitted,
            "object_bindings": dict(object_bindings),
            "input_sources": dict(input_bindings) if input_bindings is not None else {
                ref: hashlib.sha256(text.encode("utf-8")).hexdigest()
                for ref, text in requirement_text.items()},
            "limitations": "Host verified source identity and coverage; semantic sufficiency is the reviewer verdict."}


def reusable_review_checks(record: Mapping[str, Any], *, input_sources: Mapping[str, str],
                           object_bindings: Mapping[str, str]) -> list[dict[str, Any]]:
    """Conservative reuse: no inferred dependency graph and no rebinding old results.

    Without a closed dependency set, any changed object invalidates the checks.
    Unchanged checks retain the original artifact/receipt identities explicitly.
    """
    review = record.get("review")
    if not isinstance(review, Mapping) or review.get("verdict") not in {"PASS", "BLOCK", "NEEDS_EVIDENCE"}:
        return []
    evidence = review.get("verified_scope")
    if (not isinstance(evidence, Mapping) or evidence.get("schema") != "SITINA_REVIEW_SCOPE_EVIDENCE_V1"
            or evidence.get("input_sources") != dict(input_sources)
            or evidence.get("object_bindings") != dict(object_bindings)):
        return []
    if review["verdict"] != "PASS" and evidence.get("complete_review") is not False:
        return []
    conditions = evidence.get("conditions")
    if not isinstance(conditions, list):
        return []
    return [{"condition": item["condition"], "original_artifact_ref": evidence["artifact_ref"],
             "original_check": item, "applicability": "unchanged_inputs_and_complete_object_binding",
             "rerun": False} for item in conditions if isinstance(item, Mapping)
            and item.get("unverified") == [] and item.get("sources")]
