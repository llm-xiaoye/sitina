"""Exact-request optimizations. No new evidence, permissions, or completion credit."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


def omit_resident_history_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """Omit a recall view only while its full original is resident in this request.

    Callers bind resident ranges to source_ref + content_hash + projection from
    actual selected tool result bodies. Durable read coverage alone is not enough.
    The authoritative history row and its read/confirmation state are unchanged.
    """
    result = dict(row)
    if "source_view" not in row or row.get("applicability") != "CURRENT_BINDING":
        return result
    page = row.get("last_history_page")
    ranges = row.get("resident_read_ranges")
    if not isinstance(page, Mapping) or not isinstance(ranges, list):
        return result
    total = page.get("total_bytes")
    if type(total) is not int or total <= 0:
        return result
    # The assembler already merges actual intervals; require complete, exact
    # coverage rather than trusting a complete_source_read boolean or next offset.
    if ranges != [[0, total]]:
        return result
    del result["source_view"]
    result["source_view_location"] = "Full original pages are resident in this request's selected protocol history."
    return result


def review_task_navigation(task_context: Mapping[str, Any],
                           roles: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Keep review navigation within its already authorized evidence catalog.

    Only directory locators are filtered. Requirements, open obligations,
    unresolved calls and blocker state remain byte-equivalent. This does not
    change the durable history index or confer citation/read authority.
    """
    result = dict(task_context)
    directory = task_context.get("history_directory")
    if not isinstance(directory, list):
        return result
    allowed = {row["source_ref"] for row in roles}
    selected = [row for row in directory if row["source_ref"] in allowed]
    if len(selected) == len(directory):
        return result
    result["history_directory"] = selected
    result["review_navigation"] = {
        "omitted_unrelated_locator_count": len(directory) - len(selected),
        "catalog": "execution_context.review_source_roles",
        "instruction": "Use the current review evidence catalog and authenticated next_reads. "
                       "Only navigation locators outside this review's authority were omitted; "
                       "requirements and pending work are unchanged. A locator is not evidence or approval.",
    }
    return result


def request_material_profile(*, role: str, phase: str, system_prompt: str,
                             tools: Sequence[Mapping[str, Any]],
                             context_document: Mapping[str, Any],
                             protocol_messages: Sequence[Mapping[str, Any]],
                             wire_body: bytes) -> dict[str, Any]:
    """Account final admitted request bytes, outside the model context itself.

    Component JSON byte sizes are diagnostic and not additive wire token counts:
    transport escaping and envelopes differ. Never infer delivery or billing.
    """
    def encoded(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    def size(value: Any) -> int:
        return len(encoded(value))
    def identity(value: Any) -> dict[str, Any]:
        raw = encoded(value)
        return {"json_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    # Exact field paths let offline analysis distinguish goals, Skill pins,
    # artifacts and review inputs without guessing categories or copying bodies.
    # Bound expansion to two object levels; never expand individual receipts.
    sections = {}
    for key, value in context_document.items():
        path = "/" + str(key).replace("~", "~0").replace("/", "~1")
        sections[path] = identity(value)
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                child_path = path + "/" + str(child_key).replace("~", "~0").replace("/", "~1")
                sections[child_path] = identity(child_value)
    summary = context_document.get("working_summary", {})
    views = summary.get("history_read_sources", []) if isinstance(summary, Mapping) else []
    return {
        "schema": "SITINA_REQUEST_MATERIAL_PROFILE_V1",
        "role": role, "phase": phase,
        "wire_body_sha256": hashlib.sha256(wire_body).hexdigest(),
        "wire_body_bytes": len(wire_body),
        "system_and_skill_text_bytes": len(system_prompt.encode("utf-8")),
        "system_and_skill_text_sha256": hashlib.sha256(system_prompt.encode("utf-8")).hexdigest(),
        "tool_schema_json_bytes": size(tools),
        "protocol_history_json_bytes": size(protocol_messages),
        "context_section_json_bytes": {key: size(value) for key, value in context_document.items()},
        "context_material_identities": sections,
        "protocol_message_identities": [identity(message) for message in protocol_messages],
        "resident_duplicate_views_omitted": sum(
            isinstance(row, Mapping) and "source_view_location" in row for row in views),
        "scope": "Final prepared request only, not a send receipt, token count or charge. Component sizes are not additive wire bytes.",
    }
