from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePath
from typing import Any, Mapping, Sequence


def apply_completion_text_measurements(
    requirements: Mapping[str, dict[str, Any]], receipts: Sequence[Mapping[str, Any]],
    *, artifact_ref: str, goal_version: int, acceptance_version: int, input_seq: int, candidate_response: str,
) -> None:
    """A semantic PASS cannot replace complete current deterministic text evidence."""
    expected_binding = {"goal_version": goal_version, "acceptance_version": acceptance_version, "handled_input_seq": input_seq}
    candidate_hash = hashlib.sha256(candidate_response.encode("utf-8")).hexdigest()
    for requirement in requirements.values():
        contract = requirement.get("text_length_requirement")
        if not isinstance(contract, Mapping):
            continue
        errors = list(requirement.get("base_scope_errors", requirement["scope_errors"]))
        base_refs = list(requirement.get("base_evidence_refs", requirement["evidence_refs"]))
        observations: list[dict[str, Any]] = []
        if contract.get("status") != "BOUND":
            errors.append("Text measurement remains unverified: " + str(contract.get("reason", "unknown complete scope")))
        else:
            for target in contract["required_targets"]:
                expected_hash = candidate_hash if target["target"] == "candidate_response" else target["text_content_hash"]
                applicable = [item for item in receipts
                    if item.get("condition_id") == requirement["condition_id"]
                    and item.get("artifact_ref") == artifact_ref and item.get("binding") == expected_binding
                    and item.get("target_key") == target["target_key"] and item.get("target") == target["target"]
                    and item.get("scope_contract_hash") == contract["scope_contract_hash"]
                    and ((item.get("status") == "MEASURED" and item.get("text_content_hash") == expected_hash)
                         or (item.get("status") == "INVALID_MEASUREMENT" and item.get("required_text_content_hash") == expected_hash))
                    and (target["target"] == "candidate_response" or item.get("source_ref") in target["source_refs"])
                    and isinstance(item.get("measurement_source_ref"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", str(item.get("measurement_content_hash", "")))
                    and item.get("status") in {"MEASURED", "INVALID_MEASUREMENT"}]
                measured = [item for item in applicable if item.get("status") == "MEASURED"]
                if not measured:
                    failed = [item for item in applicable if item.get("status") == "INVALID_MEASUREMENT"]
                    if failed:
                        failure = failed[-1]
                        errors.append("Current complete text measurement failed for " + target["target_key"] + ": " + str(failure["reason"]))
                        observations.append({"target_key": target["target_key"], "status": "INVALID_MEASUREMENT",
                                             "reason": failure["reason"], "measurement_source_ref": failure["measurement_source_ref"],
                                             **({"format_feedback": dict(failure["format_feedback"])}
                                                if isinstance(failure.get("format_feedback"), Mapping) else {})})
                        base_refs.append(failure["measurement_source_ref"])
                    else:
                        errors.append("No committed current complete measurement for " + target["target_key"] +
                                      "; only goal_completion may call sitina_history_query measure_text. "
                                      "During main, correct and read back the deliverable, then submit the current candidate "
                                      "for a new completion measurement; do not call measure_text from main.")
                        observations.append({"target_key": target["target_key"], "status": "MISSING_CURRENT_MEASUREMENT"})
                    continue
                item = measured[-1]
                counts = item.get("counts")
                valid = (item.get("unit") == contract["unit"]
                         and item.get("minimum") == contract["minimum"] and item.get("maximum") == contract["maximum"]
                         and item.get("expected_items") == contract["expected_items"]
                         and item.get("item_count") == contract["expected_items"]
                         and isinstance(counts, list) and len(counts) == contract["expected_items"]
                         and all(type(count) is int and count > 0 for count in counts)
                         and item.get("scope") in {"numbered_items", "whole_text"}
                         and (not contract["source_labels"] or item.get("source_labels") == contract["source_labels"]))
                if not valid:
                    errors.append("The committed measurement does not cover the exact complete item contract for " + target["target_key"])
                    observations.append({"target_key": target["target_key"], "status": "INVALID_COMPLETE_SCOPE"})
                    continue
                outliers = [ordinal + 1 for ordinal, count in enumerate(counts)
                            if not contract["minimum"] <= count <= contract["maximum"]]
                observations.append({"target_key": target["target_key"], "status": "MEASURED",
                    "counts": counts, "out_of_range_items": outliers, "unit": contract["unit"],
                    "minimum": contract["minimum"], "maximum": contract["maximum"],
                    "measurement_source_ref": item["measurement_source_ref"], "text_content_hash": expected_hash,
                    "excluded_metadata": list(item.get("excluded_metadata", ()))})
                base_refs.append(item["measurement_source_ref"])
                if outliers:
                    errors.append("Text length outside the current range for " + target["target_key"] + ": "
                                  + json.dumps({"counts": counts, "out_of_range_items": outliers,
                                                "minimum": contract["minimum"], "maximum": contract["maximum"],
                                                "unit": contract["unit"]}, ensure_ascii=False))
        requirement["scope_errors"] = errors
        requirement["evidence_refs"] = list(dict.fromkeys(base_refs))
        requirement["text_measurement_observations"] = observations
        if "allowed_evidence_refs" in requirement:
            requirement["allowed_evidence_refs"] = list(dict.fromkeys([
                *requirement["allowed_evidence_refs"], *base_refs,
            ]))
        requirement["host_observation_satisfied"] = not requirement["missing_paths"] and not errors

    # The completion wire declares one shared semantic citation domain.
    # Use that same current domain for every semantic verdict check; each
    # condition keeps its own required refs and independent business finding.
    semantic_requirements = [
        item for item in requirements.values()
        if item.get("kind") == "SEMANTIC_CONDITION" and "allowed_evidence_refs" in item
    ]
    semantic_allowed = list(dict.fromkeys(
        reference for item in semantic_requirements for reference in item["allowed_evidence_refs"]
    ))
    for item in semantic_requirements:
        item["allowed_evidence_refs"] = semantic_allowed

def completion_measurement_next_action(
    *, unread_source_refs: Sequence[str], pending_measurements: Sequence[Mapping[str, Any]],
    remaining_work: Sequence[Mapping[str, Any]],
) -> str:
    """Use one priority order for internal and finalized model-view coverage."""
    if unread_source_refs:
        return "READ_REQUIRED_EVIDENCE"
    if pending_measurements:
        return "MEASURE_REQUIRED_DELIVERABLES"
    if any(item["status"] != "INVALID_MEASUREMENT" for item in remaining_work):
        return "CORRECT_REQUIRED_DELIVERABLES"
    if remaining_work:
        return "RESOLVE_MEASUREMENT_ERROR"
    return "ASSESS_CONDITIONS"


def completion_text_measurement_progress(
    requirements: Sequence[Mapping[str, Any]], receipts: Sequence[Mapping[str, Any]],
    *, artifact_ref: str, goal_version: int, acceptance_version: int, input_seq: int,
    candidate_response: str, history_query_max_bytes: int, unread_source_refs: Sequence[str],
) -> dict[str, Any] | None:
    """Project current quantitative work without changing conditions or durable state."""
    projected = {str(ordinal): dict(requirement) for ordinal, requirement in enumerate(requirements)
                 if isinstance(requirement.get("text_length_requirement"), Mapping)}
    if not projected:
        return None
    apply_completion_text_measurements(
        projected, receipts, artifact_ref=artifact_ref, goal_version=goal_version,
        acceptance_version=acceptance_version, input_seq=input_seq, candidate_response=candidate_response,
    )
    pending: list[dict[str, Any]] = []
    measured: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    for requirement in projected.values():
        condition_id = requirement["condition_id"]
        contract = requirement["text_length_requirement"]
        if contract["status"] != "BOUND":
            remaining.append({"condition_id": condition_id, "status": "UNVERIFIED_COMPLETE_SCOPE",
                              "reason": contract.get("reason", "unknown complete scope")})
            continue
        observations = {item["target_key"]: item for item in requirement["text_measurement_observations"]}
        for target in contract["required_targets"]:
            observation = observations[target["target_key"]]
            current = {"condition_id": condition_id, **observation}
            if observation["status"] == "MEASURED":
                measured.append(current)
                if observation["out_of_range_items"]:
                    remaining.append({"condition_id": condition_id, "target_key": target["target_key"],
                                      "status": "OUT_OF_RANGE", "measurement_source_ref": observation["measurement_source_ref"]})
                continue
            if observation["status"] == "INVALID_MEASUREMENT":
                remaining.append(current)
                continue
            if target["target"] == "source" and not target["source_refs"]:
                remaining.append({"condition_id": condition_id, "target_key": target["target_key"],
                                  "status": "MISSING_AUTHENTICATED_DELIVERABLE", "path": target["path"],
                                  "reason": "The current deliverable needs an authenticated complete read in the normal business correction flow."})
                continue
            arguments = {"operation": "measure_text", "condition_id": condition_id, "target": target["target"],
                         "scope": "numbered_items" if contract["expected_items"] > 1 else "whole_text",
                         "max_bytes": history_query_max_bytes}
            if target["target"] == "source":
                arguments["source_ref"] = target["source_refs"][0]
            pending.append({**current, "tool": "sitina_history_query", "arguments": arguments})
    next_action = completion_measurement_next_action(
        unread_source_refs=unread_source_refs, pending_measurements=pending, remaining_work=remaining)
    return {"binding": {"artifact_ref": artifact_ref, "goal_version": goal_version,
                        "acceptance_version": acceptance_version, "handled_input_seq": input_seq},
            "next_action": next_action, "pending_measurements": pending,
            "measurements": measured, "remaining_work": remaining}


_RANGE = re.compile(
    r"(?<![\d.])(\d+)\s*(?:[-–—~～至到]|\bto\b)\s*(\d+)\s*-?\s*"
    r"(characters?|chars?|words?|字符|字|词)(?![A-Za-z])", re.I,
)
_NUMBER = r"(?:\d+|[零〇一二两三四五六七八九十百千万]+|one|two|three|four|five|six|seven|eight|nine|ten)"
_PARAGRAPHS = re.compile(r"(" + _NUMBER + r")\s*(?:段|paragraphs?|summaries|summary)(?![A-Za-z])", re.I)
_ENGLISH_SOURCE_NOUN = r"(?:files?|documents?|sources?)"
_CHINESE_SOURCE_NOUN = r"(?:资料|文件|文档|来源)"
_SOURCES = re.compile(r"(" + _NUMBER + r")\s*(?:份|个\s*" + _CHINESE_SOURCE_NOUN
                      + r"|" + _ENGLISH_SOURCE_NOUN + r")(?![A-Za-z])", re.I)
_SOURCE_NOUN = re.compile(_CHINESE_SOURCE_NOUN + r"|(?<![A-Za-z])" + _ENGLISH_SOURCE_NOUN + r"(?![A-Za-z])", re.I)
_ITEM = re.compile(r"^\s*(\d+)[.)、]\s*(.*)$")
_FILE = re.compile(r"[^/\s]+\.[A-Za-z][A-Za-z0-9]{0,11}$")
_RESPONSE = re.compile(r"final\s+(?:answer|response|reply)|respond|answer|reply|response|答复|回答|回复", re.I)
_WRITE = re.compile(r"write|written|save|saved|create|created|写入|保存|生成", re.I)

_SUMMARY_MODIFIERS = r"(?:(?:有效|完整|简要|简短|独立|清晰|精炼)\s*(?:的\s*)?)*"
_SUMMARY_ITEMS = re.compile(
    r"(" + _NUMBER + r")\s*(?:份|篇|则|个|项)\s*(?:的\s*)?" + _SUMMARY_MODIFIERS
    + r"(?:" + _RANGE.pattern + r"\s*(?:的\s*)?)?" + _SUMMARY_MODIFIERS
    + r"(?:总结|摘要|概述|综述)", re.I,
)
_READ = re.compile(r"\b(?:read|inspect|examine|process)\b|阅读|读取|读完|读回|研读", re.I)
_REFERENCE_START = r"(?<![\w./\\-])"
_REFERENCE_END = r"(?=$|[\s,;、，；。\"\x27“”‘’<>])"
_ABSOLUTE_FILE = re.compile(
    _REFERENCE_START
    + r"(/[^\s,;、，；。\"\x27“”‘’<>]+\.[A-Za-z][A-Za-z0-9]{0,11})"
    + _REFERENCE_END
)


def _explicit_file_references(text: str) -> list[str]:
    """Keep complete quoted identities ahead of unquoted path tokens."""
    quoted: list[tuple[int, int, str]] = []
    for opening, closing in (("\x60", "\x60"), ('"', '"'), ("\x27", "\x27"), ("“", "”"), ("‘", "’")):
        pattern = re.escape(opening) + r"([^\n]*?)" + re.escape(closing)
        for match in re.finditer(pattern, text):
            path = match[1]
            if path.startswith("/") and re.search(r"\.[A-Za-z][A-Za-z0-9]{0,11}$", path):
                quoted.append((match.start(), match.end(), path))
    mentions = [*quoted, *((match.start(), match.end(), match[0])
        for match in _ABSOLUTE_FILE.finditer(text)
        if not any(start <= match.start() < end for start, end, _ in quoted))]
    return list(dict.fromkeys(path for _, _, path in sorted(mentions)))


def _mentioned_file_references(text: str, identities: Sequence[str]) -> list[str]:
    if not identities:
        return []
    pattern = (_REFERENCE_START + "(?:"
               + "|".join(re.escape(path) for path in sorted(set(identities), key=lambda value: (-len(value), value)))
               + ")" + _REFERENCE_END)
    return list(dict.fromkeys(match[0] for match in re.finditer(pattern, text)))


def _declared_input_labels(
    file_objects: Sequence[str], target_paths: Sequence[str], goal_input: Mapping[str, Any],
    *, source_identities: dict[str, str] | None = None, source_display_order: list[str] | None = None,
) -> tuple[list[str], str | None]:
    sources = list(dict.fromkeys(value for value in file_objects if value not in target_paths))
    targets = {PurePath(value).name for value in target_paths}
    # The caller binds this view to the current native request/goal lineage.
    # A derived intent may abbreviate a complete list without erasing it.
    request = goal_input.get("goal", "")
    if not isinstance(request, str):
        return [], "The current source declaration is not text."
    try:
        structured = json.loads(request)
    except (ValueError, TypeError):
        structured = None
    if isinstance(structured, Mapping) and isinstance(structured.get("objective"), str):
        clauses = structured.get("constraints", ())
        if not isinstance(clauses, list) or any(not isinstance(value, str) for value in clauses):
            return [], "The current structured source declaration is invalid."
        request = "\n".join([structured["objective"], *clauses])
    negative = re.compile(r"\b(?:not|never|without|example|quoted|if)\b|不要|不得|不必|无需|并非|例如|示例|举例|引用|假设|如果", re.I)
    readback = re.compile(r"\bread\s*back\b|\breread\b|读回", re.I)
    reference_role = re.compile(
        r"\bas\s+(?:a\s+)?reference\b|(?:作为|用作)(?:待核对成果|参考资料|参考成果|参考)"
        r"|从(?:其|已形成的)成果(?:继续|接续)", re.I,
    )
    reference_paths: set[str] = set()
    declared_paths = _explicit_file_references(request)
    reference_labels: dict[str, set[str]] = {}
    # A role label can point to a file only when the native request itself
    # binds that exact label to a complete path. A model description alone
    # cannot label another source as a reference or authorize an alias.
    for candidate in declared_paths:
        header = re.compile(
            r"(?:^|\n)[^\S\r\n]*(?P<label>[^\r\n:：]+?)(?:的)?(?:真实)?(?:绝对)?(?:文件)?"
            r"路径\s*[:：]\s*[\x60\"\x27“‘]?" + re.escape(candidate) + _REFERENCE_END,
        )
        for declaration in header.finditer(request):
            label = declaration["label"].strip()
            if (not label or label.startswith((">", "\x60", "\"", "\x27", "“", "‘"))
                    or negative.search(label)):
                continue
            reference_labels.setdefault(label, set()).add(candidate)
    intent = goal_input.get("intent", {})
    for description in intent.get("objects", ()) if isinstance(intent, Mapping) else ():
        if not isinstance(description, str):
            continue
        paths = _mentioned_file_references(description, declared_paths)
        if len(paths) != 1:
            continue
        path = paths[0]
        prefix, _, suffix = description.partition(path)
        label = prefix.strip().rstrip(":：\x60\"\x27“‘").strip()
        if not label or suffix.strip(" \t\x60\"\x27”’"):
            continue
        header = (r"(?:^|\n)\s*" + re.escape(label)
                  + r"(?:的)?(?:真实)?(?:绝对)?(?:文件)?路径\s*[:：]\s*[\x60\"\x27“‘]?")
        inline = _REFERENCE_START + re.escape(label) + r"\s+[:：]?\s*[\x60\"\x27“‘]?"
        for candidate in declared_paths:
            if re.search("(?:" + header + "|" + inline + ")" + re.escape(candidate) + _REFERENCE_END, request):
                reference_labels.setdefault(label, set()).add(candidate)
    # A reference report remains a read obligation, but is not another item
    # to summarize. Only a complete path with an explicit role can exclude it.
    for declaration in [request, *goal_input.get("constraints", ()), *goal_input.get("acceptance_conditions", ())]:
        if not isinstance(declaration, str):
            continue
        for clause in re.split(r"[。；;\n]", declaration):
            if (clause.lstrip().startswith(">") or negative.search(clause)
                    or not _READ.search(clause) or not reference_role.search(clause)):
                continue
            paths = _explicit_file_references(clause)
            if len(paths) == 1:
                reference_paths.add(paths[0])
            elif not paths:
                for label, bound_paths in reference_labels.items():
                    mention = re.search(_REFERENCE_START + re.escape(label)
                                        + r"(?=\s*(?:可|作为|用作|as\b))", clause, re.I)
                    if mention is None and declaration == request:
                        # A native path header may be referenced by a direct
                        # read instruction before its continuation role.
                        mention = re.search(
                            r"(?<![不未])(?:读取|阅读|研读)\s*(?:这份|该份|该)?\s*"
                            + re.escape(label) + _REFERENCE_END, clause, re.I,
                        )
                        if mention and re.search(r"summar(?:y|ies|ize)|总结|摘要|概述|综述", clause, re.I):
                            return [], "A reference input also has an unresolved summary-source role."
                    if mention and reference_role.search(clause[mention.end():]):
                        if len(bound_paths) != 1:
                            return [], "A reference label has multiple declared complete paths."
                        reference_paths.update(bound_paths)
    def ordered_read_declaration(text: str) -> bool:
        # A preceding sentence cannot lend its order to a new path declaration.
        text = re.split(r"[。！？!?\n]|(?<=[A-Za-z])\.\s+", text.rstrip("。！？!? \t"))[-1]
        return bool(re.search(
            r"(?<![不未])依次[^。；;\n]*?(?:阅读|读取|研读)"
            r"|(?<![不未])按(?:以下|下列|指定)顺序[^。；;\n]*?(?:阅读|读取|研读)"
            r"|\b(?:read|inspect|examine)\b[^.;\n]*?\bin (?:the (?:following|given|listed) )?order\b",
            text, re.I,
        ))

    # Only the original request can establish positional display aliases.
    # Keep each positive ordered declaration intact, including duplicates.
    ordered_lists: list[list[str]] = []
    ordered_list: list[str] | None = None
    current_sources: list[str] = []
    excluded_sources: list[str] = []
    current_texts: list[str] = []
    list_role: str | None = None
    for line in request.splitlines():
        text = line.strip()
        if not text:
            continue
        quoted = text.startswith(">")
        if quoted:
            text = text.lstrip(">").strip()
        row = re.sub(r"^(?:[-*+]|\d+[.)、])\s+", "", text)
        for opening, closing in (("\x60", "\x60"), ('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’")):
            if row.startswith(opening) and row.endswith(closing) and len(row) > 1:
                row = row[1:-1]
                break
        if list_role is not None and row.startswith("/") and _FILE.fullmatch(PurePath(row).name):
            if re.search(r"\s+(?:through|to|至|到)\s+", row, re.I):
                return [], "A source filename range cannot replace explicitly declared complete paths."
            if ordered_list is not None:
                ordered_list.append(row if not quoted else "")
            destination = current_sources if list_role == "read" and not quoted else excluded_sources
            if row not in destination:
                destination.append(row)
            continue
        list_role = None
        ordered_list = None
        if not (_READ.search(text) or _WRITE.search(text) or negative.search(text) or quoted):
            continue
        excluded = not _READ.search(text) or quoted or bool(negative.search(text)) or bool(_WRITE.search(text)) or bool(readback.search(text))
        if re.search(r"[:：]\s*$", text):
            list_role = "excluded" if excluded else "read"
            if not excluded and ordered_read_declaration(text):
                ordered_list = []
                ordered_lists.append(ordered_list)
        if excluded:
            excluded_sources.extend(match[0] for match in _ABSOLUTE_FILE.finditer(text))
        else:
            current_texts.append(text)
    if reference_paths.intersection(current_sources):
        return [], "A declared summary source is also assigned a reference-only role."
    sources = list(dict.fromkeys(value for value in [*current_sources, *sources] if value not in reference_paths))
    read_lists: list[tuple[str, list[re.Match[str]]]] = []
    declarations = [(text, True) for text in current_texts] + [
        (text, False) for text in [*goal_input.get("constraints", ()), *goal_input.get("acceptance_conditions", ())]
    ]
    for text, original in declarations:
        if (not isinstance(text, str) or not _READ.search(text) or _WRITE.search(text)
                or negative.search(text) or readback.search(text)):
            continue
        # Match registered complete identities before prose delimiters. A real
        # filename may itself contain a delimiter or another filename prefix.
        known_paths = sorted(
            {value for value in [*file_objects, *sources] if value.startswith("/")},
            key=lambda value: (-len(value), value),
        )
        pattern = _ABSOLUTE_FILE.pattern
        if known_paths:
            pattern = (_REFERENCE_START + "(?:" + "|".join(re.escape(value) for value in known_paths)
                       + ")" + _REFERENCE_END + "|" + pattern)
        paths = list(re.finditer(pattern, text))
        read_lists.append((text, paths))
        if original and paths and ordered_read_declaration(text):
            # Inline paths must all be in the same ordered read clause.
            clauses = re.split(r"[。；;\n]", text)
            same_clause = [clause for clause in clauses if ordered_read_declaration(clause)
                           and all(match[0] in clause for match in paths)]
            ordered_lists.append([match[0] for match in paths] if len(same_clause) == 1 else [])
        for left, right in zip(paths, paths[1:]):
            if re.search(r"\b(?:through|to)\b|至|到|[–—~～]", text[left.end():right.start()], re.I):
                return [], "A source filename range cannot replace explicitly declared complete paths."
        for match in paths:
            path = match[0]
            if path in reference_paths:
                if path in current_sources or re.search(r"summar(?:y|ies|ize)|总结|摘要|概述|综述", text, re.I):
                    return [], "A reference input also has an unresolved summary-source role."
                continue
            if path in target_paths:
                return [], "An input path and an output label have an unresolved identity overlap."
            if PurePath(path).name in targets:
                return [], "An input path and an output label have an unresolved identity overlap."
            if original and path not in current_sources:
                current_sources.append(path)
            if path not in sources:
                sources.append(path)
    if current_sources or excluded_sources:
        current_labels = {PurePath(path).name for path in current_sources}
        for path in sources:
            if path in excluded_sources:
                return [], "An input conflicts with an excluded current source declaration."
            if path not in current_sources and not (path == PurePath(path).name and path in current_labels):
                return [], "A derived input is not present in the current explicit source declaration."
        sources = list(dict.fromkeys(current_sources))
    by_label: dict[str, list[str]] = {}
    for path in sources:
        if path in target_paths or PurePath(path).name in targets:
            return [], "An input path and an output label have an unresolved identity overlap."
        by_label.setdefault(PurePath(path).name, []).append(path)
    for label, paths in by_label.items():
        # A bare object label may refer to its one fully declared path. Distinct
        # paths must never collapse merely because their basenames are equal.
        explicit = [path for path in paths if path != label]
        if len(explicit) > 1:
            return [], "Distinct declared input paths share one source basename."
    # A list may abbreviate later entries, but only with unique current input
    # labels. It cannot create new paths by inheriting a preceding directory.
    labels = sorted(by_label, key=lambda value: (-len(value), value))
    alternatives = [*(re.escape(label) for label in labels),
                    r"[^/\s,;、，；。\"\x27“”‘’<>]+\.[A-Za-z][A-Za-z0-9]{0,11}"]
    shorthand = re.compile(r"\s*[,;、，；]\s*(" + "|".join(alternatives) + ")" + _REFERENCE_END)
    for text, paths in read_lists:
        for path in paths:
            offset = path.end()
            while match := shorthand.match(text, offset):
                label = match[1]
                if label not in by_label:
                    return [], f"Source list shorthand {label!r} does not identify a declared input."
                offset = match.end()
    if source_identities is not None:
        source_identities.update({label: next((path for path in paths if path != label), label)
                                  for label, paths in by_label.items()})
    if source_display_order is not None and ordered_lists:
        current_paths = [next((path for path in paths if path != label), label)
                         for label, paths in by_label.items()]
        first_order = ordered_lists[0]
        if (all(path.startswith("/") for path in current_paths)
                and len(first_order) == len(current_paths)
                and len(set(first_order)) == len(first_order)
                and set(first_order) == set(current_paths)
                and all(order == first_order for order in ordered_lists)):
            source_display_order.extend(PurePath(path).name for path in first_order)
    return list(by_label), None


def _number(value: str) -> int:
    if value.isdigit():
        return int(value)
    english = dict(zip(("one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"), range(1, 11)))
    if value.lower() in english:
        return english[value.lower()]
    digits = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4,
              "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
    units = {"十": 10, "百": 100, "千": 1000, "万": 10000}
    total = part = current = 0
    for character in value:
        if character in digits:
            current = digits[character]
        elif character in units:
            unit = units[character]
            if unit == 10000:
                total += (part + current) * unit
                part = current = 0
            else:
                part += (current or 1) * unit
                current = 0
        else:
            raise ValueError("unsupported quantity representation")
    return total + part + current


def _quantity_matches(
    pattern: re.Pattern[str], text: str, *, excluded_spans: Sequence[tuple[int, int]] = (),
) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for match in pattern.finditer(text):
        if any(start <= match.start() and match.end() <= end for start, end in excluded_spans):
            continue
        # Item references do not declare the size of the complete collection.
        prefix = text[:match.start()]
        if re.search(r"(?:[第上下前后这那哪某每任]|(?<![A-Za-z])(?:next|previous|following|preceding|last))\s*$", prefix, re.I):
            continue
        # A paired one-source-then-next-source step does not redeclare the total.
        if (pattern is _SOURCES and _number(match[1]) == 1
                and re.search(r"(?:读完|阅读完|读取完|完整阅读|完整读取|处理完|完成)\s*$", prefix)
                and re.match(
                    r"(?:" + _CHINESE_SOURCE_NOUN + r")?\s*(?:之后|以后|后)?\s*"
                    r"(?:再|才|然后|随后)\s*(?:继续\s*)?"
                    r"(?:(?:阅读|读取|读|处理)\s*)?下一(?:份|个\s*"
                    + _CHINESE_SOURCE_NOUN + r")(?![A-Za-z])", text[match.end():])):
            continue
        matches.append(match)
    return matches


def _quantities(
    pattern: re.Pattern[str], text: str, *, excluded_spans: Sequence[tuple[int, int]] = (),
) -> set[int]:
    return {_number(match[1]) for match in _quantity_matches(pattern, text, excluded_spans=excluded_spans)}


def _item_quantities(text: str) -> set[int]:
    return _quantities(_PARAGRAPHS, text) | _quantities(_SUMMARY_ITEMS, text)


def _source_item_markers(condition: str, source_quantities: set[int]) -> tuple[list[int], str | None]:
    """Locate output quantities distributed over the current declared sources."""
    markers: list[int] = []
    # Use the same source vocabulary and bridge for both distribution forms.
    # ASCII word boundaries preserve original offsets in mixed-language text.
    source_bridge = re.compile(
        r"(?:(?:\s|[,，:：])|(?:(?:are|were|have|been|be|all|already|fully|completely|read|reviewed|"
        r"and|then|provide|give|write|produce|yield)(?![A-Za-z]))|"
        r"(?:均|都|应当|应该|必须|需要|应|须|需|要|被|已经|已|依次|按顺序|逐一|完整|全部|先|各自|各|分别|"
        r"阅读|读完|读过|读|看完|核对|完成|完毕|一遍|一次|之后|以后|后|并|且|再|随后|然后))*", re.I,
    )
    for marker in re.finditer(r"(?<![A-Za-z])each(?:\s+(file|document|source)(?![A-Za-z]))?(?![A-Za-z])", condition, re.I):
        if marker[1] is not None:
            markers.append(marker.end())
            continue
        sentence = condition[:marker.start()]
        sources = list(_SOURCE_NOUN.finditer(sentence))
        if not sources:
            continue
        if len(sources) != 1:
            return [], "English each crosses multiple unresolved source groups."
        source = sources[0]
        item_references = [item for pattern in (_PARAGRAPHS, _SUMMARY_ITEMS)
                           for item in _quantity_matches(pattern, sentence)]
        if any(item.start() >= source.end() for item in item_references):
            continue  # "two summaries, each ..." distributes over the summaries.
        if not source_bridge.fullmatch(sentence[source.end():]):
            return [], "English each has an unresolved source or changed subject."
        markers.append(marker.end())
    distribution = re.compile(r"每(?:份|篇|个|项)(?:资料|文件|文档|来源)?|逐份|各(?:自)?|分别")
    action_modifiers = r"(?:(?:都|均|应当|应该|必须|需要|应|须|需|要|被|已经|已|依次|逐一|完整|全部|先)\s*)*"
    output_action = re.compile(r"^" + action_modifiers + r"(?:产出|提炼|生成|输出|撰写|写|提供|给出|有|形成|编写|总结)")
    # Obtaining text is an output relation only for an explicit summary,
    # never for a quoted input passage or a different source/subject.
    obtained_summary = re.compile(
        r"^" + action_modifiers + r"得到\s*" + _NUMBER
        + r"\s*(?:段|份|篇|则|个|项)\s*(?:的\s*)?" + _SUMMARY_MODIFIERS
        + r"(?:" + _RANGE.pattern + r"\s*(?:的\s*)?)?" + _SUMMARY_MODIFIERS
        + r"(?:总结|摘要|概述|综述)", re.I,
    )
    reading_action = re.compile(r"^" + action_modifiers + r"(?:阅读|读|查看|核对|检查|审阅|浏览)")
    correspondence_action = re.compile(r"^" + action_modifiers + r"对应\s*")

    def has_output_action(text: str) -> bool:
        if output_action.match(text) or obtained_summary.match(text):
            return True
        correspondence = correspondence_action.match(text)
        # Correspondence binds only a directly adjacent output quantity.
        return correspondence is not None and any(
            item.start() == correspondence.end()
            for pattern in (_PARAGRAPHS, _SUMMARY_ITEMS)
            for item in _quantity_matches(pattern, text)
        )

    for clause in re.finditer(r"[^,，;；。\n]+", condition):
        for marker in distribution.finditer(clause[0]):
            tail = clause[0][marker.end():].lstrip()
            tail = re.sub(r"^(?:各(?:自)?|分别)\s*", "", tail)
            if reading_action.match(tail):
                continuations = [join for join in re.finditer(r"然后|随后|并|且|再", tail)
                                 if has_output_action(tail[join.end():].lstrip())]
                if not continuations:
                    if _item_quantities(tail):
                        return [], "A reading distribution does not bind the later output quantity."
                    continue
                continuation = continuations[0]
                if not source_bridge.fullmatch(tail[:continuation.start()]):
                    return [], "A joined output has an unresolved reading subject or source group."
                tail = tail[continuation.end():].lstrip()
            quantities = [item for pattern in (_PARAGRAPHS, _SUMMARY_ITEMS)
                          for item in _quantity_matches(pattern, tail)]
            if not quantities and not _RANGE.search(tail):
                correspondence = correspondence_action.match(tail)
                if correspondence:
                    remainder = tail[correspondence.end():]
                    if _SOURCE_NOUN.search(remainder) is None:
                        return [], "An output distribution has no unambiguous source/action binding."
                    reference_count = re.match(r"(" + _NUMBER + r")\s*(?:份|个)", remainder)
                    if reference_count and source_quantities != {_number(reference_count[1])}:
                        return [], "The source correspondence conflicts with the explicit source quantity."
                    continue  # A source reference does not declare an output quantity.
                if re.search(r"(?:未用|不以).*替代\s*$", clause[0][:marker.start()]):
                    continue  # The object of a negated replacement is not an output action.
            if not has_output_action(tail) and not any(item.start() == 0 for item in quantities):
                # Correspondence to sources is not another output distribution.
                # Reject unresolved output quantities, not a source-only clause.
                if quantities or correspondence_action.match(tail):
                    return [], "An output distribution has no unambiguous source/action binding."
                continue
            if (not marker[0].startswith("每")
                    or (correspondence_action.match(tail) and _SOURCE_NOUN.search(marker[0]) is None)):
                prefix = condition[:clause.start() + marker.start()]
                sentence = prefix
                antecedents = list(_SOURCE_NOUN.finditer(sentence))
                if len(antecedents) != 1 or not source_bridge.fullmatch(sentence[antecedents[0].end():]):
                    return [], "An output distribution crosses an unresolved subject or source group."
            markers.append(clause.end() - len(tail))
    return markers, None


def missing_source_distribution_contract(goal_input: Mapping[str, Any]) -> bool:
    """A current goal's source distribution must survive its executable handoff.

    Inspect only the product's current interpretation, not the original request's
    historical quotations. This detects a lost quantifier; it neither invents an
    item count nor binds historical actions or source identities.
    """
    def distributed_ranges(text: str) -> set[tuple[int, int, str, tuple[str, ...], tuple[int, ...]]]:
        result: set[tuple[int, int, str, tuple[str, ...], tuple[int, ...]]] = set()
        for sentence in re.split(r"[;；。\n]", text):
            if sentence.lstrip().startswith(">") or re.search(
                r"\b(?:not|never|without|example|quoted|if|previous|historical|superseded|withdrawn)\b|"
                r"不要|不得|不必|不再|无需|并非|例如|示例|假设|如果|旧方案|旧要求|旧版本|历史要求|已撤回|作废",
                sentence, re.I,
            ):
                continue
            sentence = re.sub(r'“[^”]*”|‘[^’]*’|"[^"]*"|\x27[^\x27]*\x27', "", sentence)
            ranges = list(_RANGE.finditer(sentence))
            markers, error = _source_item_markers(sentence, _quantities(_SOURCES, sentence))
            if len(ranges) == 1 and markers and error is None:
                match = ranges[0]
                unit = "words" if match[3].lower() in {"word", "words", "词"} else "characters"
                result.add((int(match[1]), int(match[2]), unit,
                            tuple(sorted(item[0] for item in _ABSOLUTE_FILE.finditer(sentence))),
                            tuple(sorted(_quantities(_SOURCES, sentence)))))
        return result

    declared = set().union(*(distributed_ranges(value) for value in
                            [*goal_input["constraints"], *goal_input["acceptance_conditions"]]))
    for obligation in distributed_ranges(goal_input["goal"]):
        if obligation in declared:
            continue
        # A matching range alone cannot align different file/source scopes.
        # Leave that ambiguity to the existing complete-scope check rather
        # than inventing equivalence or a goal-repair obligation.
        if any(candidate[:3] == obligation[:3] for candidate in declared):
            continue
        return True
    return False


def _output_file_scope(
    objects: Sequence[str], goal_input: Mapping[str, Any], workspace: PurePath | None,
) -> tuple[list[str], list[str], list[dict[str, str]], str | None]:
    """Resolve explicit workspace references before assigning input/output roles."""
    from os.path import normpath

    workspace_label = r"(?:本次|本|当前)?会话工作目录"
    scoped_file = re.compile(
        workspace_label + r"(?:下|中)?(?:的)?\s*"
        r"(?P<path>[A-Za-z0-9_./-]+\.[A-Za-z][A-Za-z0-9]{0,11})"
        r"(?=$|[\s,;、，；。（）()\"\x27“”‘’<>])"
    )
    negative = re.compile(
        r"\b(?:not|never|without|example|quoted|if|or)\b|"
        r"不要|不得|不必|无需|并非|例如|示例|举例|引用|假设|如果|或者|或|不写|未写", re.I,
    )
    quoted = re.compile(r"“[^”]*”|‘[^’]*’|\"[^\"]*\"|\x27[^\x27]*\x27|\x60[^\x60]*\x60")

    def parts(text: str, *, writing: bool = False) -> list[str]:
        values = []
        for part in re.split(r"[,，;；。\n]", text):
            if part.lstrip().startswith(">") or negative.search(part):
                continue
            # A quoted instruction cannot confer a write role. Quoted literal
            # filenames remain literal references, not workspace descriptions.
            part = quoted.sub(lambda match: "" if _WRITE.search(match[0]) else match[0], part)
            if not writing or _WRITE.search(part):
                values.append(part)
        return values

    def identity(path: str) -> str:
        return normpath(str(PurePath(workspace) / path) if workspace is not None else path)

    def relative_scoped(match: re.Match[str]) -> str | None:
        path = PurePath(match["path"])
        if path.is_absolute() or ".." in path.parts:
            return None
        return str(path)

    def mentions(path: str, declarations: Sequence[str]) -> bool:
        forms = {path, normpath(path), identity(path)}
        if workspace is not None:
            try:
                forms.add(str(PurePath(identity(path)).relative_to(workspace)))
            except ValueError:
                pass
        literal_patterns = [
            re.compile(_REFERENCE_START + re.escape(value) + _REFERENCE_END)
            for value in forms
        ]
        # Bind an attached Chinese content phrase through its explicit write
        # relation; do not treat arbitrary filename prefixes/suffixes as prose.
        written_content_patterns = [
            re.compile(r"(?:^|[\s、])(?:写入|保存|生成)\s*" + re.escape(value)
                       + r"(?=的(?:总结|摘要|内容)(?:和|与|以及|及|$|[\s,;、，；。]))")
            for value in forms
        ]
        for declaration in declarations:
            if any(pattern.search(declaration) for pattern in [*literal_patterns, *written_content_patterns]):
                return True
            spans = list(quoted.finditer(declaration))
            for match in scoped_file.finditer(declaration):
                if any(span.start() <= match.start() and span.end() >= match.end() for span in spans):
                    continue
                value = relative_scoped(match)
                if value is not None and identity(value) == identity(path):
                    return True
        return False

    output_parts = parts(str(goal_input["intent"].get("output") or ""))
    write_parts = [part for condition in goal_input.get("acceptance_conditions", ())
                   if isinstance(condition, str) for part in parts(condition, writing=True)]
    request = goal_input.get("goal", "")
    if not isinstance(request, str):
        return [], [], [], "The current output declaration is not text."
    try:
        structured = json.loads(request)
    except (ValueError, TypeError):
        structured = None
    if isinstance(structured, Mapping) and isinstance(structured.get("objective"), str):
        constraints = structured.get("constraints", ())
        if not isinstance(constraints, list) or any(not isinstance(value, str) for value in constraints):
            return [], [], [], "The current structured output declaration is invalid."
        request = "\n".join([structured["objective"], *constraints])
    requested_write_parts = parts(request, writing=True)
    # Descriptions may contain a complete native-request identity. They are
    # not themselves paths; only exact, uniquely declared references resolve.
    declared_paths = _explicit_file_references(request)
    scoped_outputs: list[str] = []
    for part in requested_write_parts:
        spans = list(quoted.finditer(part))
        for match in scoped_file.finditer(part):
            if any(span.start() <= match.start() < span.end() for span in spans):
                continue
            value = relative_scoped(match)
            if value is not None and mentions(value, output_parts):
                scoped_outputs.append(value)
    # Exact native identities take precedence over surrounding prose, including
    # parentheses or spaces that are part of a declared filename.
    reference_end = r"(?=$|[\s,;、，；。（）()\"\x27“”‘’<>])"
    complete_paths = [*declared_paths, *(identity(value) for value in scoped_outputs if workspace is not None)]
    resolved, targets, bindings = [], [], []
    workspace_context_seen = False
    for original in objects:
        # A complete directory label supplies location, never a file identity.
        if re.fullmatch(workspace_label, original.strip()):
            workspace_context_seen = True
            continue
        workspace_context = bool(re.match(workspace_label, original)
                                 or re.match(r"(?:本次|本|当前)会话", original))
        known_paths = sorted(set([*complete_paths, *(scoped_outputs if workspace_context else [])]),
                             key=lambda value: (-len(value), value))
        references = []
        if original in complete_paths:
            references = [(original, (0, len(original)))]
        elif known_paths:
            pattern = _REFERENCE_START + "(?:" + "|".join(re.escape(value) for value in known_paths) + ")" + reference_end
            references = [(match[0], match.span()) for match in re.finditer(pattern, original)]
        scoped = None
        if not references:
            scoped = scoped_file.match(original)
            if scoped is not None:
                path = relative_scoped(scoped)
                if path is None:
                    return [], [], [], "The workspace output reference is not an unambiguous relative path."
                references = [(path, scoped.span("path"))]
            elif re.match(workspace_label, original):
                return [], [], [], "The described workspace output has an incomplete or ambiguous file reference."
            elif _FILE.fullmatch(PurePath(original).name):
                references = [(original, (0, len(original)))]
            else:
                continue
        if len({identity(path) for path, _ in references}) != 1:
            return [], [], [], "An object description has multiple current file references."
        path = references[0][0]
        if scoped is None:
            scoped_match = scoped_file.match(original)
            relative = relative_scoped(scoped_match) if scoped_match is not None else None
            if relative is not None and identity(relative) == identity(path):
                scoped = scoped_match
                path = relative
        described_workspace = workspace_context and any(identity(path) == identity(value) for value in scoped_outputs)
        if described_workspace and scoped is None:
            path = identity(path)
        residual = original
        for _, (start, end) in reversed(references):
            residual = residual[:start] + " " + residual[end:]
        # A second reference cannot disappear just because it was not in the
        # declared-path lookup. Compare identities, never basename aliases.
        extra_file = re.search(r"[^\s,，;；。（）()]+\.[A-Za-z][A-Za-z0-9]{0,11}(?=$|[\s,，;；。（）()])", residual)
        if extra_file or "/" in residual or "\\" in residual:
            return [], [], [], "An object description has an additional unresolved file or path."
        is_output = mentions(path, output_parts) or mentions(path, write_parts)
        described = bool(residual.strip(" \t\r\n\x60\"\x27“”‘’（）()"))
        if scoped or described_workspace or (is_output and described):
            if not mentions(path, output_parts) or not mentions(path, requested_write_parts):
                return [], [], [], "The described workspace output is not bound to the current explicit write request."
        if is_output:
            # Role and authority come from the current request, not isolated
            # words in a description of report contents. Check only relations
            # attached to this file reference, equally for every entry path.
            for _, (start, end) in references:
                prefix = original[:start].rstrip(" \t\x60\"\x27“‘")
                suffix = original[end:].lstrip(" \t\x60\"\x27”’")
                role_before = re.search(
                    r"\b(?:input|source|reference|readonly)(?:\s+(?:file|report))?\s*$|"
                    r"(?:只读|参考|输入|来源)(?:文件|报告|成果|产物|资料)?\s*$", prefix, re.I)
                role_after = re.match(
                    r"^[\s,，;；（(]*(?:(?:仅供|只供|仅作|只作|作为|用作)\s*(?:只读|参考|输入|来源)|"
                    r"只读(?:文件|报告)?[\s）)]*$)", suffix)
                negative_before = re.search(
                    r"(?:不要|不得|不必|无需|不再|不是|并非|而非|\bnot|\bnever)\s*"
                    r"(?:(?:写入|保存|生成|输出|write|save|create)\s*)?(?:的)?\s*$", prefix, re.I)
                negative_after = re.match(
                    r"^[\s,，;；（(]*(?:不要|不得|不必|无需|不再|不|\bnot|\bnever)\s*"
                    r"(?:写入|保存|生成|输出|write|save|create)", suffix, re.I)
                changed_target = re.match(
                    r"^[\s,，;；（(]*(?:另存为|改为|改名|替换为|移到|"
                    r"(?:其他|不同|另一个|另一)(?:目录|路径|文件|版本))", suffix)
                file_quantity = re.search("(" + _NUMBER + r")\s*(?:个|份)\s*(?:文件|报告|产物|成果)\s*$",
                                          prefix, re.I)
                if (role_before or role_after or negative_before or negative_after or changed_target
                        or (file_quantity is not None and _number(file_quantity[1]) != 1)):
                    return [], [], [], "The description assigns a conflicting role or target to the requested output."
        if path not in resolved:
            resolved.append(path)
        if is_output:
            if path not in targets:
                targets.append(path)
            bindings.append({"object": original, "path": path,
                             "scope": "session_workspace" if scoped or described_workspace else "explicit_path"})
    if workspace_context_seen and (not targets or any(
            not mentions(path, output_parts) or not mentions(path, requested_write_parts)
            for path in targets)):
        return [], [], [], "The workspace context is not bound to an explicit current output file."
    return resolved, targets, bindings, None


def text_length_requirement(
    condition: str, goal_input: Mapping[str, Any] | None = None, *, workspace: PurePath | None = None,
) -> dict[str, Any] | None:
    """Bind explicit units, complete quantities and declared outputs from the current goal."""
    matches = list(_RANGE.finditer(condition))
    if not matches:
        return None
    unresolved = {"status": "UNVERIFIED", "condition": condition}
    if len(matches) != 1:
        return {**unresolved, "reason": "Multiple text-unit ranges require separate current conditions."}
    if re.search(r"\b(?:not|never|without)\b|不要|不得|不必|无需|并非", condition, re.I):
        return {**unresolved, "reason": "A negated text range is not a positive measurable obligation."}
    match = matches[0]
    quoted_spans = list(re.finditer(r'“[^”]*”|‘[^’]*’|"[^"]*"|\x27[^\x27]*\x27', condition))
    if any(span.start() <= match.start() and span.end() >= match.end() for span in quoted_spans):
        return {**unresolved, "reason": "A quoted text range is not an independently bound positive obligation."}
    minimum, maximum = int(match[1]), int(match[2])
    raw_unit = match[3].lower()
    unit = "words" if raw_unit in {"word", "words", "词"} else "characters"
    if minimum > maximum:
        return {**unresolved, "reason": "The text-unit range is reversed."}
    if unit == "words" and (raw_unit == "词" or not re.search(r"whitespace[- ]separated|按空白分隔", condition, re.I)):
        return {**unresolved, "reason": "Word counting requires an explicit whitespace-separated contract; Chinese segmentation is not inferred."}
    if goal_input is None:
        return {**unresolved, "reason": "Current goal scope is required before a text range can be measured."}
    conditions = [str(value) for value in goal_input.get("acceptance_conditions", ())]
    intent = goal_input.get("intent")
    if not isinstance(intent, Mapping):
        return {**unresolved, "reason": "The current goal has no declared output scope."}
    output = str(intent.get("output") or "")
    objects = [value for value in intent.get("objects", ()) if isinstance(value, str)]
    file_objects, target_paths, output_bindings, output_error = _output_file_scope(objects, goal_input, workspace)
    if output_error is not None:
        return {**unresolved, "reason": output_error}
    item_quantities = _item_quantities(condition)
    summary_spans = [match.span() for match in _SUMMARY_ITEMS.finditer(condition)]
    source_quantities = _quantities(_SOURCES, condition, excluded_spans=summary_spans)
    per_item_markers, distribution_error = _source_item_markers(condition, source_quantities)
    if distribution_error is not None:
        return {**unresolved, "reason": distribution_error}
    per_source = bool(per_item_markers)
    input_labels, source_error = _declared_input_labels(file_objects, target_paths, goal_input) if per_source else ([], None)
    if source_error is not None:
        return {**unresolved, "reason": source_error}
    if per_source:
        source_count = len(input_labels)
        if not source_count:
            return {**unresolved, "reason": "The complete declared source set is missing."}
        if source_quantities and source_quantities != {source_count}:
            return {**unresolved, "reason": "The explicit source quantity conflicts with the complete declared source set."}
        total_marker = re.compile(r"(?:共计|总共|总计|合计|共|\btotal(?:\s+of)?|\bin\s+total)\s*$", re.I)
        output_total_prefix = re.compile(
            r"^\s*(?:(?:先|需|须|应|要|必须|需要|应当|应该)\s*)*"
            r"(?:产出|输出|提供|给出|生成|撰写|写|编写|形成|"
            r"(?:produce|provide|write|give|generate|create)(?![A-Za-z]))\s*"
            r"(?:(?:(?:经|已)(?:核对|检查|验证|校验)(?:的)?|有效|完整|简要|简短|独立|清晰|精炼|"
            r"(?:the|verified|complete|concise|independent)(?![A-Za-z]))\s*)*$", re.I,
        )
        per_item_quantities: set[int] = set()
        total_quantities: set[int] = set()
        unbound_quantities: set[int] = set()
        output_total_count = 0
        # Bind each quantity to its own clause and role before comparing N * K = T.
        for clause in re.finditer(r"[^,，;；。\n]+", condition):
            for pattern in (_PARAGRAPHS, _SUMMARY_ITEMS):
                for quantity_match in _quantity_matches(pattern, clause[0]):
                    prefix = clause[0][:quantity_match.start()]
                    quantity = _number(quantity_match[1])
                    if total_marker.search(prefix):
                        total_quantities.add(quantity)
                    elif any(clause.start() <= marker <= clause.start() + quantity_match.start()
                             for marker in per_item_markers):
                        per_item_quantities.add(quantity)
                    elif output_total_prefix.fullmatch(prefix):
                        # An explicit output action establishes the total role;
                        # numeric agreement alone never establishes that role.
                        total_quantities.add(quantity)
                        output_total_count += 1
                    else:
                        unbound_quantities.add(quantity)
        if unbound_quantities:
            return {**unresolved, "reason": "An item quantity is not bound to a per-source or total role."}
        if output_total_count > 1:
            return {**unresolved, "reason": "Multiple output clauses do not bind one total deliverable."}
        if len(per_item_quantities) != 1:
            return {**unresolved, "reason": "The per-source item quantity must be unambiguous."}
        if len(total_quantities) > 1:
            return {**unresolved, "reason": "The total item quantity must be unambiguous."}
        expected_items = source_count * next(iter(per_item_quantities))
        if total_quantities and total_quantities != {expected_items}:
            return {**unresolved, "reason": "The total item quantity conflicts with source count times items per source."}
    elif len(item_quantities) == 1:
        expected_items = next(iter(item_quantities))
        source_count = None
    elif not item_quantities:
        declared = set().union(*(_item_quantities(value) for value in [*conditions, output]))
        if len(declared) != 1:
            return {**unresolved, "reason": "The complete item quantity is not unambiguously declared."}
        expected_items = next(iter(declared))
        source_count = None
    else:
        return {**unresolved, "reason": "The complete item quantity is ambiguous."}
    if expected_items < 1:
        return {**unresolved, "reason": "The item quantity must be positive."}
    # A current condition may state only the total while a current constraint
    # assigns one summary to each source. Bind both, without inferring sources
    # from that total or importing historical/quoted request instructions.
    if (not per_source and condition in conditions
            and re.search(r"summar(?:y|ies)|总结|摘要|概述|综述", condition, re.I)):
        distributions: list[dict[str, Any]] = []
        for constraint in goal_input.get("constraints", ()):
            if not isinstance(constraint, str) or not re.search(r"summar(?:y|ies)|总结|摘要|概述|综述", constraint, re.I):
                continue
            ranges = list(_RANGE.finditer(constraint))
            if len(ranges) != 1 or (ranges[0][1], ranges[0][2], ranges[0][3].lower()) != (match[1], match[2], raw_unit):
                continue
            if re.search(r"\b(?:not|never|without|example|quoted|if)\b|不要|不得|不必|无需|并非|例如|示例|引用|假设|如果", constraint, re.I):
                continue
            quantities = _quantities(_SOURCES, constraint,
                                    excluded_spans=[item.span() for item in _SUMMARY_ITEMS.finditer(constraint)])
            markers, error = _source_item_markers(constraint, quantities)
            if error is not None:
                return {**unresolved, "reason": error}
            if not markers:
                continue
            if len(target_paths) > 1 or _ABSOLUTE_FILE.search(constraint):
                return {**unresolved, "reason": "The per-source constraint has an independently scoped deliverable or source set."}
            distributed = text_length_requirement(constraint, goal_input, workspace=workspace)
            if distributed is None or distributed["status"] != "BOUND":
                return {**unresolved, "reason": "The current per-source constraint cannot bind its complete source collection."}
            if distributed["expected_items"] != expected_items:
                return {**unresolved, "reason": "The current total conflicts with the current per-source item quantity."}
            distributions.append(distributed)
        if distributions:
            input_labels = distributions[0]["source_labels"]
            if any(item["source_labels"] != input_labels or item["target_paths"] != target_paths for item in distributions):
                return {**unresolved, "reason": "The current per-source constraints have conflicting source or output scopes."}
            source_count = len(input_labels)
    response_required = any(
        _RESPONSE.search(value) and expected_items in _item_quantities(value)
        for value in [*conditions, output]
    )
    if not target_paths:
        response_required = True
    # Locator identity does not grant a per-source allocation. Total-only
    # conditions can recognize an optional basename without requiring one,
    # inferring a distribution, or treating the locator dictionary as coverage.
    source_identities: dict[str, str] = {}
    source_display_order: list[str] = []
    locator_labels, locator_error = _declared_input_labels(
        file_objects, target_paths, goal_input, source_identities=source_identities,
        source_display_order=source_display_order,
    )
    if locator_error is not None:
        return {**unresolved, "reason": locator_error}
    return {
        "status": "BOUND", "condition_text": condition, "minimum": minimum, "maximum": maximum, "unit": unit,
        "expected_items": expected_items, "source_labels": input_labels if source_count is not None else [],
        "source_locator_paths": {label: source_identities[label] for label in locator_labels},
        "source_display_order": source_display_order if source_count is not None else [],
        "target_paths": target_paths, "candidate_response_required": response_required,
        "output_bindings": output_bindings,
        "basis": ("Unicode code points, including punctuation and internal whitespace"
                  if unit == "characters" else "explicitly whitespace-separated words"),
        "prefix_policy": "unique source locators and item markers are structural; unverified title text remains counted",
        "scope_policy": "complete source-bound summary blocks; separate auxiliary blocks are traced for semantic review, never proof of scope, reading or completion",
    }


def _label_body(
    text: str, labels: list[str], requested_separator: str | None,
    source_display_order: Sequence[str] = (),
) -> tuple[str, str | None]:
    first, separator, rest = text.partition("\n")
    colon = re.search(r"[:：]", first)
    prefix = first[:colon.start()].strip() if colon else first.strip()
    if prefix.startswith("**") and prefix.endswith("**"):
        prefix = prefix[2:-2]
    ordinal = re.match(
        r"^(?:第(" + _NUMBER + r")(?:份|篇)(?:资料|文件|文档|来源)"
        r"|(?:资料|文件|文档|来源)\s*(" + _NUMBER + r"))(?!\d)",
        prefix, re.I,
    )
    if ordinal and source_display_order:
        position = _number(ordinal[1] or ordinal[2])
        if (position is None or not 1 <= position <= len(source_display_order)
                or set(source_display_order) != set(labels)
                or len(source_display_order) != len(set(source_display_order))):
            raise ValueError("a source ordinal is outside the uniquely declared current source order")
        label = source_display_order[position - 1]
        trailing = prefix[ordinal.end():].strip()
        # A basename immediately attached to the ordinal is another locator;
        # source names mentioned later in the counted prose are not locators.
        explicit = re.match(r"^[（(]([^）)]+)[）)]", trailing)
        if explicit and _FILE.fullmatch(explicit[1].strip()):
            if explicit[1].strip() != label:
                raise ValueError("a source ordinal conflicts with its attached source basename")
            trailing = trailing[explicit.end():].lstrip()
        else:
            attached = [name for name in labels
                        if trailing.startswith(name)
                        and (len(trailing) == len(name) or not re.match(r"[\w.-]", trailing[len(name)]))]
            if attached:
                if attached != [label]:
                    raise ValueError("a source ordinal conflicts with its attached source basename")
                trailing = trailing[len(label):].lstrip()
        if re.match(r"^[、,，/]\s*(?:第" + _NUMBER + r"(?:份|篇)(?:资料|文件|文档|来源)"
                    r"|(?:资料|文件|文档|来源)\s*" + _NUMBER + r")", trailing, re.I):
            raise ValueError("one item has multiple source ordinals")
        if colon and requested_separator is not None and first[colon.start()] != requested_separator:
            raise ValueError("label_separator differs from the confirmed source prefix")
        if not colon and requested_separator is not None:
            raise ValueError("a source ordinal without a colon has no label_separator")
        # A colon inside an unlabelled prose continuation is body punctuation;
        # only a colon immediately after the locator is structural.
        if colon and trailing and requested_separator is not None:
            raise ValueError("label_separator does not immediately follow the source ordinal")
        body = trailing + ((first[colon.start():] if trailing else first[colon.end():]) if colon else "")
        if separator:
            body += separator + rest
        return body.strip(), label
    if labels:
        matches = [(label, match) for label in labels
                   for match in re.finditer(r"(?<![\w.-])" + re.escape(label) + r"(?![\w.-])", prefix)]
        if len(matches) != 1:
            raise ValueError("each per-source item must identify exactly one declared source basename")
        label, match = matches[0]
        leading, trailing = prefix[:match.start()].strip(), prefix[match.end():].strip()
        leading = re.sub(r"^(?:第" + _NUMBER + r"(?:份|篇|项)|(?:file|source)\s+\d+)\s*",
                         "", leading, flags=re.I)
        # Only the ordinal, basename and their enclosing locator punctuation
        # are structural. Unverified source titles remain counted content.
        if leading in {"(", "（"} and trailing.startswith(")" if leading == "(" else "）"):
            trailing = trailing[1:].lstrip(",， ").strip()
            leading = ""
        if leading:
            raise ValueError("text before a source locator has ambiguous summary ownership")
        if colon and requested_separator is not None and first[colon.start()] != requested_separator:
            raise ValueError("label_separator differs from the confirmed source prefix")
        if not colon and requested_separator is not None:
            raise ValueError("a heading source locator has no label_separator; omit that optional argument")
        if colon and trailing and requested_separator is not None:
            raise ValueError("label_separator does not immediately follow the source basename")
        body = trailing + ((first[colon.start():] if trailing else first[colon.end():]) if colon else "")
        if separator:
            body += separator + rest
        return body.strip(), label
    if colon:
        if requested_separator is not None or re.fullmatch(r"[^，。；;!?！？]+", prefix):
            raise ValueError("an unconfirmed colon prefix cannot be excluded or assumed to be body")
    if requested_separator is not None:
        raise ValueError("label exclusion requires a confirmed source basename")
    return text.strip(), None


def _source_item_rows(
    lines: list[str], requirement: Mapping[str, Any], metadata_context: str,
    target_titles: list[str], section_heading: str | None,
) -> tuple[list[tuple[int, int, str]], list[dict[str, Any]], list[tuple[str, int | None, int | None]]]:
    """Recognize source-bound list/heading items without losing any body block."""
    labels = list(requirement["source_labels"] or requirement.get("source_locator_paths", {}))
    rows: list[tuple[int, int, str]] = []
    excluded: list[dict[str, Any]] = []
    issues: list[tuple[str, int | None, int | None]] = []

    def heading(line: str) -> tuple[int, str] | None:
        match = re.fullmatch(r"\s*(#{1,6})\s+(.+?)\s*", line)
        if match:
            return len(match[1]), match[2]
        match = re.fullmatch(r"\s*\*\*(.+?)\*\*\s*", line)
        if match:
            return 0, match[1]
        # Plain colon headings are structural too; the same complete section
        # and goal/metadata checks below still decide whether to exclude them.
        plain = line.strip()
        if (plain.endswith(":") or plain.endswith("：")) and not (
            _ITEM.match(plain) or re.match(r"[-*+]\s+", plain)
        ):
            return 0, plain[:-1].strip()
        return None

    def marker(line: str) -> tuple[int | None, str, int | None] | None:
        title = heading(line)
        value = title[1] if title else line
        numbered = _ITEM.match(value)
        if numbered:
            return int(numbered[1]), numbered[2], title[0] if title else None
        try:
            body, label = _label_body(value, labels, None, requirement.get("source_display_order", ()))
        except ValueError:
            return None
        if label and title is None and body:
            # Without a heading or list marker, only an adjacent delimiter
            # makes a locator structural. A source mention in ordinary prose
            # remains part of the existing body, including later colons.
            delimiter = re.search(r"[:：]", value)
            if delimiter is None:
                return None
            try:
                _label_body(value, labels, delimiter[0], requirement.get("source_display_order", ()))
            except ValueError:
                return None
        return (None, value, title[0] if title else None) if label else None

    def grounded_heading(title: str) -> bool:
        title = re.sub(r"^(?:第" + _NUMBER + r"(?:章|节|部分)|[零〇一二两三四五六七八九十百]+)"
                       r"[、.．]\s*", "", title).strip()
        parts = re.split(r"[:：]", title, maxsplit=1)
        if len(parts) == 2 and parts[0].strip() in target_titles:
            title = parts[1].strip()
        qualified = re.fullmatch(r"(.+?)[（(]([^（）()]+)[）)]", title)
        if qualified:
            base, qualifier = qualified[1].strip(), qualified[2].strip()
            order = list(requirement.get("source_display_order", ()))
            mapping = re.fullmatch(
                r"第\s*1\s*[-–—~～至到]\s*(\d+)\s*段依次对应\s*(\S+)\s+至\s+(\S+)", qualifier,
            )
            count_range = re.fullmatch(
                r"(?:每份|每段)?\s*(\d+)\s*[-–—~～至到]\s*(\d+)\s*字", qualifier,
            )
            grounded_qualifier = (
                qualifier in metadata_context
                or (count_range and (int(count_range[1]), int(count_range[2]))
                    == (requirement["minimum"], requirement["maximum"]))
                or (mapping and order and int(mapping[1]) == requirement["expected_items"] == len(order)
                    and (mapping[2], mapping[3]) == (order[0], order[-1]))
            )
            if not grounded_qualifier:
                return False
            title = base
        if title in metadata_context or title in target_titles or title in labels:
            return True
        collection = re.fullmatch(
            r"(" + _NUMBER + r")\s*(?:份|段|篇)?\s*(?:资料|文件|文档|来源)?\s*"
            r"(?:总结|摘要|概述|综述)", title,
        )
        return bool(collection and _number(collection[1]) == requirement["expected_items"])

    def metadata_field(line: str) -> str | None:
        bullet = re.fullmatch(r"\s*[-*+]\s+(.+?)\s*", line)
        field = re.match(r"([^:：]+)[:：]", bullet[1]) if bullet else None
        label = field[1].strip().strip("*") if field else ""
        subject_pattern = r"第(" + _NUMBER + r")份(?:资料|文件|文档)"
        locator = re.search(r"[（(]([^（）()]+)[）)]", label)
        if locator:
            # Parentheses may identify the same source; they cannot hide an
            # arbitrary suffix, a second source or a different field name.
            subject = re.fullmatch(subject_pattern, label[:locator.start()])
            order = list(requirement.get("source_display_order", ()))
            position = _number(subject[1]) if subject else None
            if not (position and position <= len(order) and locator[1] == order[position - 1]):
                return None
            label = label[:locator.start()] + label[locator.end():]
        if not label or label in requirement["condition_text"] or label in labels:
            return None
        if label in metadata_context:
            return label
        qualified = re.fullmatch("(" + subject_pattern + r")(?:里的|中的|的)?(.+)", label)
        if not qualified:
            return None
        subject, name = qualified[1], qualified[3]
        declaration = re.compile(re.escape(subject) + r"(?:里的|中的|的)([^。；;:\n]+)")
        for match in declaration.finditer(metadata_context):
            # A shared qualifier applies only inside this explicit coordinated
            # list. Do not borrow a field from a different sentence or source.
            fields = [item.strip() for item in re.split(r"、|，|以及|和|及|与", match[1])]
            if name in fields and name not in requirement["condition_text"]:
                return label
        return None

    candidates = {index: item for index, line in enumerate(lines) if (item := marker(line)) is not None}

    def fields_for_source(source_label: str) -> set[str]:
        order = list(requirement.get("source_display_order", ()))
        fields: set[str] = set()
        declarations = re.finditer(
            r"(?P<subject>第(?P<ordinal>" + _NUMBER + r")份(?:资料|文件|文档))"
            r"(?:里的|中的|的)(?P<names>[^。；;:\n]+)", metadata_context,
        )
        for declaration in declarations:
            position = _number(declaration["ordinal"])
            if not (position and position <= len(order) and order[position - 1] == source_label):
                continue
            names = [name.strip() for name in re.split(r"、|，|以及|和|及|与", declaration["names"])]
            fields.update(names)
            fields.update(declaration["subject"] + qualifier + name
                          for qualifier in ("里的", "中的", "的") for name in names)
        return fields

    metadata_headings: set[int] = set()
    for index, line in enumerate(lines):
        title = heading(line)
        if title is None or (index in candidates and candidates[index][0] is not None):
            continue
        if re.search(r"summar(?:y|ies)|总结|摘要|概述|综述", title[1], re.I):
            continue
        fields = []
        for following in range(index + 1, len(lines)):
            following_title = heading(lines[following])
            if following_title is not None:
                if title[0] == 0 or following_title[0] == 0 or following_title[0] <= title[0]:
                    break
                # A nested subsection belongs to this complete block; it
                # prevents an earlier field prefix from certifying the block.
                fields.append(None)
                continue
            if following in candidates:
                break
            if lines[following].strip():
                fields.append(metadata_field(lines[following]))
        # Classify the complete field section before assigning a source item.
        # A source-bearing heading must also bind every field to that source
        # in the current goal. Unknown prose and explicit summary headings
        # cannot acquire an exclusion through a few matching field labels.
        if fields and all(fields):
            if index in candidates:
                _, source_label = _label_body(
                    title[1], labels, None, requirement.get("source_display_order", ()),
                )
                if not source_label or not set(fields) <= fields_for_source(source_label):
                    continue
            metadata_headings.add(index)
    markers = {index: item for index, item in candidates.items() if index not in metadata_headings}
    numbers = [item[0] for item in markers.values()]
    if (len(markers) != requirement["expected_items"]
            or (any(number is not None for number in numbers)
                and numbers != list(range(1, requirement["expected_items"] + 1)))):
        issues.append(("source items must cover the complete declared collection exactly once", None, None))
    last_marker = max(markers, default=-1)
    active: list[str] | None = None
    start = 0
    level: int | None = None

    def close(stop: int) -> None:
        nonlocal active
        if active is not None:
            rows.append((start + 1, stop, "\n".join(active).strip()))
            active = None

    for index, line in enumerate(lines):
        if index in markers:
            close(index)
            _, first, level = markers[index]
            active, start = [first], index
            continue
        title = heading(line)
        field = metadata_field(line)
        # A new section ends the final summary, but still needs its own scope
        # justification below. Auxiliary candidates remain in the source and
        # are traced for semantic review, never certified by their heading.
        if active is not None and index > last_marker and (
            (title and (level is None or title[0] <= level))
            or (field and active and not active[-1].strip())
        ):
            close(index)
        if active is not None:
            active.append(line)
            continue
        if not line.strip():
            continue
        if title:
            if not grounded_heading(title[1]) and index not in metadata_headings:
                if re.search(r"summar(?:y|ies)|总结|摘要|概述|综述", title[1], re.I):
                    issues.append(("an additional summary heading has no unambiguous source ownership",
                                   index + 1, index + 1))
                    continue
                if not metadata_context.strip():
                    issues.append(("an excluded heading has no current semantic review context", index + 1, index + 1))
                    continue
                kind, label = "auxiliary-heading-for-semantic-review", title[1]
            else:
                kind, label = "goal-or-target-heading", title[1]
        elif field:
            kind, label = "separate-required-metadata-field", field
        else:
            # The user constrains each summary, not every word in a report.
            # Separate auxiliary blocks remain in the authenticated source and
            # are only candidates for exclusion: semantic review must reject
            # false claims or summary content displaced here and remeasure the
            # corrected current artifact. A label alone never certifies them.
            if not metadata_context.strip():
                issues.append(("unassigned prose has no current semantic review context", index + 1, index + 1))
                continue
            kind, label = "auxiliary-prose-for-semantic-review", "current-source auxiliary block"
        excluded.append({"line": index + 1, "end_line": index + 1, "kind": kind, "label": label,
                         "content_hash": hashlib.sha256(line.encode("utf-8")).hexdigest()})
    close(len(lines))
    if section_heading is not None:
        positions = [index for index, line in enumerate(lines) if line.strip() == section_heading]
        section = heading(section_heading)
        if len(positions) != 1 or section is None:
            issues.append(("section_heading must identify one exact Markdown section", None, None))
        else:
            begin = positions[0]
            end = next((index for index in range(begin + 1, len(lines))
                        if (following := heading(lines[index])) and following[0] <= section[0]), len(lines))
            if any(start <= begin + 1 or stop > end for start, stop, _ in rows):
                issues.append(("the selected section does not cover the complete required item set",
                               begin + 1, begin + 1))
    return rows, excluded, issues


class TextMeasurementScopeError(ValueError):
    def __init__(self, reason: str, feedback: Mapping[str, Any]) -> None:
        super().__init__(reason)
        self.feedback = dict(feedback)


def measure_text(
    text: str, *, requirement: Mapping[str, Any], scope: str,
    metadata_context: str, target_titles: list[str],
    section_heading: str | None = None, label_separator: str | None = None,
) -> dict[str, Any]:
    """Bind counted item spans and trace auxiliary spans for semantic review."""
    if not isinstance(text, str) or requirement.get("status") != "BOUND":
        raise ValueError("measurement requires verified text and one bound current scope")
    if label_separator not in {None, ":", "："}:
        raise ValueError("label_separator must be an explicit colon or null")
    labels = list(requirement["source_labels"])
    lines = text.splitlines()
    excluded: list[dict[str, Any]] = []
    item_rows: list[tuple[int, int, str]] = []
    rules: list[str] = []
    issues: list[dict[str, Any]] = []

    def reject(reason: str, start: int | None = None, stop: int | None = None) -> None:
        if reason not in rules:
            rules.append(reason)
        fragment = lines[start - 1] if start is not None and 0 < start <= len(lines) else None
        issues.append({"rule": rules.index(reason), "line": start, "end_line": stop or start,
                       "fragment": fragment[:64] if fragment is not None else None,
                       "fragment_truncated": fragment is not None and len(fragment) > 64})

    if scope == "whole_text":
        if requirement["expected_items"] != 1 or section_heading is not None or label_separator is not None:
            raise ValueError("whole_text measures exactly one complete text, without exclusions")
        item_rows = [(1, len(lines) or 1, text.strip())]
        labels = []
    elif scope == "numbered_items" and (labels or requirement.get("source_locator_paths")):
        item_rows, excluded, source_issues = _source_item_rows(
            lines, requirement, metadata_context, target_titles, section_heading,
        )
        for reason, start, stop in source_issues:
            reject(reason, start, stop)
    elif scope == "numbered_items":
        markers = [(index, _ITEM.match(line)) for index, line in enumerate(lines) if _ITEM.match(line)]
        numbers = [int(match[1]) for _, match in markers]
        if numbers != list(range(1, requirement["expected_items"] + 1)):
            reject("numbered_items must cover every declared item exactly once, starting at one")
        first_marker = markers[0][0] if markers else -1
        last_marker = markers[-1][0] if markers else -1
        active: list[str] | None = None
        start = 0
        for index, line in enumerate(lines):
            match = _ITEM.match(line)
            if match:
                if active is not None:
                    item_rows.append((start + 1, index, "\n".join(active).strip()))
                active, start = [match[2]], index
                continue
            if not line.strip():
                if active is not None:
                    item_rows.append((start + 1, index, "\n".join(active).strip()))
                    active = None
                continue
            heading = re.fullmatch(r"\s*(#{1,6})\s+(.+?)\s*", line)
            bullet = re.fullmatch(r"\s*[-*+]\s+(.+?)\s*", line)
            if heading or bullet:
                if active is not None or first_marker < index < last_marker:
                    reject("heading/bullet interrupts a required body item; no text was silently omitted", index + 1)
                if heading:
                    title = heading[2].strip()
                    title_base = re.split(r"[（(]", title, maxsplit=1)[0].strip()
                    if (title not in metadata_context and title not in target_titles
                            and title_base not in metadata_context
                            and not any(label in title for label in labels)):
                        reject("an excluded heading is not grounded in the current goal or target identity", index + 1)
                        continue
                    label, kind = title, "goal-or-target-heading"
                else:
                    field = re.match(r"([^:：]+)[:：]", bullet[1])
                    label = re.split(r"[（(]", field[1].strip().strip("*"), maxsplit=1)[0] if field else ""
                    if (not label or label not in metadata_context
                            or label in requirement["condition_text"] or label in labels):
                        reject("an excluded bullet is not a separately required metadata field", index + 1)
                        continue
                    kind = "separate-required-metadata-field"
                excluded.append({"line": index + 1, "kind": kind, "label": label,
                                 "content_hash": hashlib.sha256(line.encode("utf-8")).hexdigest()})
            elif active is not None:
                active.append(line)
            else:
                reject("unassigned prose outside numbered items cannot be omitted", index + 1)
        if active is not None:
            item_rows.append((start + 1, len(lines), "\n".join(active).strip()))
        if section_heading is not None:
            positions = [index for index, line in enumerate(lines) if line.strip() == section_heading]
            if len(positions) != 1 or not re.match(r"^#{1,6}\s+", section_heading):
                reject("section_heading must identify one exact Markdown section")
            else:
                section_start = positions[0]
                level = len(section_heading) - len(section_heading.lstrip("#"))
                section_end = next((index for index in range(section_start + 1, len(lines))
                                    if (heading := re.match(r"^(#{1,6})\s+", lines[index]))
                                    and len(heading[1]) <= level), len(lines))
                if any(start <= section_start + 1 or stop > section_end for start, stop, _ in item_rows):
                    reject("the selected section does not cover the complete required item set", section_start + 1)
    else:
        raise ValueError("scope must be numbered_items or whole_text")
    if len(item_rows) != requirement["expected_items"]:
        reject("every declared item must have exactly one complete body block")
    bodies: list[str] = []
    identities: list[str | None] = []
    for start, stop, raw in item_rows:
        try:
            if scope == "numbered_items":
                locator_labels = labels
                if not labels:
                    prefix = re.split(r"[:：\n]", raw, maxsplit=1)[0]
                    locator_labels = [label for label in requirement.get("source_locator_paths", {})
                                      if re.search(r"(?<![\w.-])" + re.escape(label) + r"(?![\w.-])", prefix)]
                body, label = _label_body(raw, locator_labels, label_separator,
                                          requirement.get("source_display_order", ()))
            else:
                body, label = raw, None
        except ValueError as error:
            reject(str(error), start, stop)
            identities.append(None)
            continue
        if not body:
            reject("measurement contains an empty body item", start, stop)
        bodies.append(body)
        identities.append(label)
    if labels and (len(identities) != len(labels) or set(identities) != set(labels)):
        reject("the measured items do not cover the complete declared source collection")
    if issues:
        raise TextMeasurementScopeError(rules[0], {
            "status": "UNBOUND_CURRENT_TEXT_SCOPE", "counts_status": "NOT_MEASURED",
            "expected_items": requirement["expected_items"], "source_labels": labels,
            "observed_source_labels": identities,
            "unit": requirement["unit"], "minimum": requirement["minimum"], "maximum": requirement["maximum"],
            "format_rules": rules, "issues": issues,
            "repair_guidance": [
                "These are measurement-format limits, not new user requirements; no body count is established.",
                ("Cover each declared source exactly once using numbered items or source-bound Markdown headings. "
                 if labels else "Cover the declared total with numbered items; confirmed source locators are optional. "
                 "This total-only measurement does not verify a per-source allocation. ") +
                "Parenthesized basenames are accepted when unambiguous; source titles and all body blocks remain counted. "
                "For heading locators omit the optional label_separator; do not select only a convenient section.",
                "Ordinal source labels are accepted only when the original request uniquely declares the complete source order. "
                "Preserve every separately requested fact. Outside the items, use separate bullets with "
                "goal-bound field labels and a colon; shared source qualifiers must stay unambiguous. "
                "Independent auxiliary blocks remain semantic review inputs, not reading or completion evidence. "
                "If they contain summary content, restore it to the corresponding counted item and remeasure the "
                "corrected current artifact; do not omit content or relabel an old measurement.",
                "Preserve source titles as body text after the basename colon. A stated count such as (97字) "
                "is not evidence and is counted if retained. Unassigned completion narration is not a summary or proof: "
                "keep required facts in their own clearly labelled fields and do not discard source-specific content. "
                "During main, reformat and read back every affected deliverable, then submit the corrected candidate. "
                "Do not call measure_text from main; only goal_completion can measure the new current artifact. "
                "During goal_completion, measure every required current target again. "
                "Do not shorten the entire report to one item range.",
            ],
        })
    counts = [len(body) if requirement["unit"] == "characters" else len(body.split()) for body in bodies]
    minimum, maximum = requirement["minimum"], requirement["maximum"]
    return {
        "unit": requirement["unit"], "minimum": minimum, "maximum": maximum,
        "basis": requirement["basis"], "scope": scope, "section_heading": section_heading,
        "label_separator": label_separator, "prefix_policy": requirement["prefix_policy"],
        "scope_policy": requirement["scope_policy"], "expected_items": requirement["expected_items"],
        "item_count": len(bodies), "counts": counts, "source_labels": identities,
        "item_line_ranges": [[start, stop] for start, stop, _ in item_rows],
        "item_content_hashes": [hashlib.sha256(body.encode("utf-8")).hexdigest() for body in bodies],
        "excluded_metadata": excluded,
        "out_of_range_items": [index + 1 for index, count in enumerate(counts) if not minimum <= count <= maximum],
        "within_range_all": all(minimum <= count <= maximum for count in counts),
    }
