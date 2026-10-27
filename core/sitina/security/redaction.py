"""Content-preserving boundary adapters.

Sitina does not classify, redact, or reject text because it resembles personal
data or credentials. Environment inheritance is a separate capability boundary.
Legacy function signatures remain available for installed callers and records.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


def is_secret_name(name: str) -> bool:
    """Classify environment names for process inheritance, not content filtering."""
    upper = name.upper()
    return any(fragment in upper for fragment in
               ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "API_KEY", "AUTH", "CREDENTIAL", "SSH"))


def isolated_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    source = dict(base or os.environ)
    return {key: value for key, value in source.items() if not is_secret_name(key)}


def redact_text(text: str) -> str:
    """Compatibility adapter: return the original text unchanged."""
    return text


def sensitive_field_paths(value: Any, *, path: str = "$") -> tuple[str, ...]:
    """Content and field names no longer create a persistence restriction."""
    return ()


@dataclass(frozen=True)
class BoundaryRedactionResult:
    boundary: str
    value: Any
    redacted_paths: tuple[str, ...]


def redact_boundary_value(
    value: Any,
    *,
    boundary: str,
    allowlist: Sequence[str] = (),
    verified_source_paths: Sequence[str] = (),
) -> BoundaryRedactionResult:
    """Preserve content; retain boundary validation and detached containers.

    The old allowlist/provenance parameters are accepted for compatibility,
    but are unnecessary now that there is no content-based redaction policy.
    """
    if boundary not in {"write", "read", "log", "handoff"}:
        raise ValueError("unknown context redaction boundary")

    def copy_value(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {key: copy_value(child) for key, child in item.items()}
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            values = [copy_value(child) for child in item]
            return tuple(values) if isinstance(item, tuple) else values
        return item

    return BoundaryRedactionResult(boundary, copy_value(value), ())
