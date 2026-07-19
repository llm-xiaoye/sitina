from __future__ import annotations

import os
import re
import base64
import binascii
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


_SENSITIVE_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "auth_token",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "set_cookie",
    }
)


def is_secret_name(name: str) -> bool:
    upper = name.upper()
    return any(
        fragment in upper
        for fragment in (
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PRIVATE_KEY",
            "API_KEY",
            "AUTH",
            "CREDENTIAL",
            "SSH",
        )
    )


def isolated_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    source = dict(base or os.environ)
    return {key: value for key, value in source.items() if not is_secret_name(key)}


def redact_text(text: str) -> str:
    patterns = (
        (
            r"(?i)(api[_ -]?key|apikey|auth[_ -]?token|token|secret|password)\s*[:=]\s*[\"']?[^\"'\s]+",
            r"\1=<redacted>",
        ),
        (r"(?i)sk-[A-Za-z0-9_-]{8,}", "<redacted-key>"),
        (r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1<redacted>"),
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            "<redacted-private-key>",
        ),
    )
    redacted = text
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.DOTALL)
    return redacted


def sensitive_field_paths(value: Any, *, path: str = "$") -> tuple[str, ...]:
    """Return sensitive mapping-key paths without copying or logging values."""

    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}"
            if key_text.casefold() in _SENSITIVE_FIELD_NAMES:
                found.append(child)
            found.extend(sensitive_field_paths(item, path=child))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            found.extend(sensitive_field_paths(item, path=f"{path}[{index}]"))
    return tuple(found)


@dataclass(frozen=True)
class BoundaryRedactionResult:
    boundary: str
    value: Any
    redacted_paths: tuple[str, ...]


def _normalized_field_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(character for character in normalized if unicodedata.category(character) != "Cf").casefold()


def _redact_boundary_text(text: str, allowlist: Sequence[str]) -> tuple[str, bool]:
    placeholders: dict[str, str] = {}
    protected = text
    for index, item in enumerate(sorted(set(allowlist), key=lambda value: (-len(value), value))):
        if item:
            marker = f"__SITINA_REDACTION_ALLOWLIST_{index}__"
            protected = protected.replace(item, marker)
            placeholders[marker] = item
    normalized = unicodedata.normalize("NFKC", protected)
    normalized = "".join(character for character in normalized if unicodedata.category(character) != "Cf")
    redacted = redact_text(normalized)
    redacted = re.sub(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "<redacted-email>",
        redacted,
    )
    def phone(match: re.Match[str]) -> str:
        candidate = match.group(0)
        digit_count = sum(character.isdigit() for character in candidate)
        return "<redacted-phone>" if 8 <= digit_count <= 15 else candidate

    redacted = re.sub(r"(?<!\w)(?:\+?\d[\d .()-]{6,80}\d)(?!\w)", phone, redacted)

    def encoded(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return token
        decoded_redacted = redact_text(unicodedata.normalize("NFKC", decoded))
        return "<redacted-encoded>" if decoded_redacted != decoded else token

    redacted = re.sub(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])", encoded, redacted)
    for marker, original in placeholders.items():
        redacted = redacted.replace(marker, original)
    return redacted, redacted != text


def redact_boundary_value(
    value: Any,
    *,
    boundary: str,
    allowlist: Sequence[str] = (),
) -> BoundaryRedactionResult:
    """Redact structured values at write/read/log/Handoff boundaries.

    The result reports paths only; callers can audit the decision without
    persisting the sensitive values that triggered it.
    """

    if boundary not in {"write", "read", "log", "handoff"}:
        raise ValueError("unknown context redaction boundary")
    redacted_paths: list[str] = []

    def visit(item: Any, path: str) -> Any:
        if isinstance(item, Mapping):
            result = {}
            for key, child in item.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}"
                normalized_key = _normalized_field_name(key_text)
                if normalized_key in _SENSITIVE_FIELD_NAMES:
                    result[key_text] = "<redacted-sensitive-field>"
                    redacted_paths.append(child_path)
                else:
                    result[key_text] = visit(child, child_path)
            return result
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            joined = "".join(str(value) for value in item if isinstance(value, str))
            _joined_redacted, joined_changed = _redact_boundary_text(joined, allowlist)
            if joined and joined_changed:
                redacted_paths.append(path)
                values = ["<redacted-fragment>" if isinstance(value, str) else visit(value, f"{path}[{index}]") for index, value in enumerate(item)]
            else:
                values = [visit(value, f"{path}[{index}]") for index, value in enumerate(item)]
            return tuple(values) if isinstance(item, tuple) else values
        if isinstance(item, str):
            redacted, changed = _redact_boundary_text(item, allowlist)
            if changed:
                redacted_paths.append(path)
            return redacted
        return item

    redacted = visit(value, "$")
    return BoundaryRedactionResult(boundary, redacted, tuple(sorted(set(redacted_paths))))
