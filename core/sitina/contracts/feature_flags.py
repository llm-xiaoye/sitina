from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class SharedContractFeatureError(ValueError):
    pass


FEATURE_FLAG = "shared_contracts_v1_write"


def shared_contract_writes_enabled(config: Mapping[str, Any] | None) -> bool:
    """Old or absent configuration remains read-compatible and write-disabled."""

    if config is None:
        return False
    features = config.get("features", {})
    if not isinstance(features, Mapping):
        raise SharedContractFeatureError("feature flags features must be an object")
    value = features.get(FEATURE_FLAG, False)
    if not isinstance(value, bool):
        raise SharedContractFeatureError(f"{FEATURE_FLAG} must be boolean")
    return value


def assert_shared_contract_write_enabled(config: Mapping[str, Any] | None) -> None:
    if not shared_contract_writes_enabled(config):
        raise SharedContractFeatureError("shared contract V1 writes are disabled")
