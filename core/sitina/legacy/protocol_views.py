from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Iterable, Mapping


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    raise TypeError("legacy protocol view accepts mappings or dataclasses")


class LegacyProtocolViews:
    """Read-only representations; these views have no persistence adapter."""

    @staticmethod
    def proposal_view(
        proposals: Iterable[Any], evaluations: Iterable[Any], selections: Iterable[Any] = ()
    ) -> dict[str, Any]:
        return {
            "submitted": [_mapping(item) for item in proposals],
            "evaluations": [_mapping(item) for item in evaluations],
            "selections": [_mapping(item) for item in selections],
        }

    @staticmethod
    def handoff_view(handoffs: Iterable[Any]) -> dict[str, Any]:
        items = [_mapping(item) for item in handoffs]
        return {"count": len(items), "items": items}

    @staticmethod
    def blackboard_view(documents: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "count": len(documents),
            "documents": {key: _mapping(value) if not isinstance(value, Mapping) else dict(value) for key, value in sorted(documents.items())},
        }

    @staticmethod
    def compare_baseline(
        baseline: Mapping[str, Any],
        *,
        proposal: Mapping[str, Any],
        handoff: Mapping[str, Any],
        blackboard: Mapping[str, Any],
    ) -> dict[str, Any]:
        semantic = baseline.get("semantic")
        if not isinstance(semantic, Mapping):
            raise ValueError("Legacy baseline lacks semantic section")
        expected = {
            "proposal": dict(semantic["proposal"]),
            "handoff": dict(semantic["handoff"]),
            "blackboard": dict(semantic["blackboard"]),
        }
        observed = {
            "proposal": dict(proposal),
            "handoff": dict(handoff),
            "blackboard": dict(blackboard),
        }
        differences: list[dict[str, Any]] = []
        for area in ("proposal", "handoff", "blackboard"):
            keys = sorted(set(expected[area]) | set(observed[area]))
            for key in keys:
                before = expected[area].get(key)
                after = observed[area].get(key)
                if before == after:
                    continue
                representation_only = key in {"items", "documents"}
                differences.append(
                    {
                        "area": area,
                        "field": key,
                        "before": before,
                        "after": after,
                        "classification": "EXPECTED_REPRESENTATION_CHANGE" if representation_only else "REGRESSION",
                    }
                )
        return {
            "schema": "BPLUS_PROTOCOL_LEGACY_COMPARISON_V1",
            "differences": differences,
            "blocking_count": sum(item["classification"] == "REGRESSION" for item in differences),
            "authority": False,
        }
