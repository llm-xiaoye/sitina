from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sitina.compatibility.capabilities import FormatCapabilityRegistry
from sitina.compatibility.leases import RuntimeCompatibilityLease
from sitina.compatibility.upcasters import UpcasterRegistry


def runtime_compatibility_report(home: str | Path, *, now: str) -> dict[str, Any]:
    """Read configs and existing leases without creating the Runtime lease directory."""
    root = Path(home).resolve(strict=True)
    registry = FormatCapabilityRegistry.load(root / "config" / "format_capabilities.json")
    feature_path = root / "config" / "feature_flags.json"
    features = json.loads(feature_path.read_text(encoding="utf-8"))
    lease_root = root / "runtime" / "compatibility-leases"
    leases: list[RuntimeCompatibilityLease] = []
    if lease_root.is_dir() and not lease_root.is_symlink():
        for path in sorted(lease_root.glob("*.lease.json")):
            if path.is_symlink() or not path.is_file():
                continue
            leases.append(RuntimeCompatibilityLease.from_mapping(json.loads(path.read_text(encoding="utf-8"))))
    active = [lease for lease in leases if lease.is_active(now)]
    formats = [registry.get(name).mapping() for name in registry.names]
    return {
        "schema": "SITINA_RUNTIME_COMPATIBILITY_REPORT_V1",
        "read_only": True,
        "capability_registry_hash": registry.registry_hash,
        "formats": formats,
        "configured_feature_flags": dict(features.get("features", {})),
        "configured_flags_are_authority": False,
        "activation_authority": features.get("activation_authority"),
        "active_runtime_leases": [lease.mapping() for lease in active],
        "active_runtime_lease_count": len(active),
        "upcasters": list(UpcasterRegistry.default().manifest),
        "rollback_floors": {
            item["format_name"]: item["rollback_floor_version"]
            for item in formats
        },
        "writer_opened": False,
        "journal_events_appended": 0,
    }


__all__ = ["runtime_compatibility_report"]
