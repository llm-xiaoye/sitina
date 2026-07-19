from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
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
