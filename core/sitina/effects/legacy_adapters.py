from __future__ import annotations

import os
from enum import Enum
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash


class LegacyAdapterKind(str, Enum):
    PROVIDER = "PROVIDER"
    MCP = "MCP"
    TOOL = "TOOL"


class ShadowEffectBridge:
    """Request-identity shadow that never claims Effect authority."""

    def __init__(self, *, enabled: bool):
        self.enabled = enabled

    @classmethod
    def from_environment(cls) -> "ShadowEffectBridge":
        return cls(enabled=os.environ.get("SITINA_BPLUS_EFFECT_SHADOW", "0") == "1")

    def identity(self, kind: LegacyAdapterKind, request: Mapping[str, Any]) -> dict[str, Any]:
        request_hash = domain_hash("LEGACY_ADAPTER_SHADOW_REQUEST", canonical_json_bytes({"adapter_kind": kind.value, "request": dict(request)}))
        return {
            "schema": "LEGACY_ADAPTER_EFFECT_SHADOW_V1",
            "adapter_kind": kind.value,
            "request_hash": request_hash,
            "authority": False,
            "live_capability": False,
        }

    def execute(self, kind: LegacyAdapterKind, request: Mapping[str, Any], direct: Callable[[], Any]) -> Any:
        if not self.enabled:
            return direct()
        return {"status": "shadowed", **self.identity(kind, request), "physical_send_count": 0}
