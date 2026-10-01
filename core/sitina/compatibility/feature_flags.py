from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes

from .errors import FeatureGateError
from .leases import CompatibilityLeaseRegistry


@dataclass(frozen=True)
class FeatureActivation:
    feature: str
    state: str
    required_reader_capabilities: tuple[str, ...]
    prepared_position: int
    activated_position: int | None
    rollback_floor_version: int
    first_write_position: int | None
    rollback_safe_after_first_write: bool

    @property
    def commitment(self) -> str:
        value = {
            "schema": "SITINA_FEATURE_ACTIVATION_STATE_V1",
            "feature": self.feature,
            "state": self.state,
            "required_reader_capabilities": list(self.required_reader_capabilities),
            "prepared_position": self.prepared_position,
            "activated_position": self.activated_position,
            "rollback_floor_version": self.rollback_floor_version,
            "first_write_position": self.first_write_position,
            "rollback_safe_after_first_write": self.rollback_safe_after_first_write,
        }
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class FeatureActivationRegistry:
    """Derived control state. Callers must source transitions from committed Journal events."""

    def __init__(self) -> None:
        self._features: dict[str, FeatureActivation] = {}

    _FIRST_WRITE_SCHEMAS = {
        "SITINA_RUN_CHECKPOINT_PUBLISHED_V2": "checkpoint_v2_write",
        "SITINA_RUN_EVIDENCE_PUBLISHED_V2": "evidence_v2_write",
        "SITINA_AGENT_CONTEXT_MANIFEST_PUBLISHED_V2": "agent_context_v2_write",
        "SITINA_MEMORY_CANDIDATE_CREATED_V1": "memory_v1_write",
        "SITINA_MEMORY_DECISION_V1": "memory_v1_write",
        "SITINA_EPISODE_V1": "memory_v1_write",
        "SITINA_EPISODE_CREATED_V2": "memory_v1_write",
        "SITINA_EXPERIENCE_MANIFEST_V1": "memory_v1_write",
        "SITINA_EXPERIENCE_DECISION_V1": "memory_v1_write",
        "SESSION_DELETION_PREPARED_V1": "trash_bundle_v1_write",
    }

    @classmethod
    def from_journal_events(cls, events: Iterable[Any]) -> "FeatureActivationRegistry":
        """Replay durable feature state without consulting mutable config.

        Compatibility leases are admission evidence for the original prepare
        command.  Recovery verifies the committed transition order and never
        re-runs admission against today's process set.
        """

        registry = cls()
        ordered = sorted(events, key=lambda item: int(getattr(item, "position", 0)))
        for event in ordered:
            payload = getattr(event, "payload", event)
            if not isinstance(payload, Mapping):
                continue
            event_type = str(getattr(event, "event_type", payload.get("event_type", "")))
            schema = str(payload.get("schema", ""))
            position = int(getattr(event, "position", payload.get("journal_position", 0)))
            if position < 1:
                continue
            if event_type == "runtime.feature-prepared" and schema == "RUNTIME_FEATURE_PREPARED_V1":
                feature = str(payload.get("feature", ""))
                required = payload.get("required_reader_capabilities", ())
                if not feature or not isinstance(required, (list, tuple)) or any(not isinstance(item, str) for item in required):
                    raise FeatureGateError("committed feature preparation is malformed")
                if feature in registry._features:
                    raise FeatureGateError("committed feature preparation is duplicated")
                registry._features[feature] = FeatureActivation(
                    feature, "PREPARED", tuple(sorted(set(required))), position, None, 1, None, True
                )
                continue
            if event_type == "runtime.feature-activated" and schema == "RUNTIME_FEATURE_ACTIVATED_V1":
                feature = str(payload.get("feature", ""))
                current = registry._features.get(feature)
                floor = payload.get("rollback_floor_version")
                rollback_safe = payload.get("rollback_safe_after_first_write", False)
                if current is None or current.state != "PREPARED" or not isinstance(floor, int) or floor < 1:
                    raise FeatureGateError("committed feature activation is malformed or out of order")
                if not isinstance(rollback_safe, bool):
                    raise FeatureGateError("committed feature activation has invalid rollback safety")
                registry._features[feature] = FeatureActivation(
                    feature, "ACTIVATED", current.required_reader_capabilities, current.prepared_position,
                    position, floor, None, rollback_safe,
                )
                continue
            feature = cls._FIRST_WRITE_SCHEMAS.get(schema)
            if feature is not None:
                current = registry._features.get(feature)
                if current is None or current.state != "ACTIVATED":
                    raise FeatureGateError(f"{schema} appears before its Journal feature activation")
                registry.record_first_write(feature, journal_position=position)
        return registry

    @staticmethod
    def _assert_control_event(
        event: Mapping[str, Any] | None,
        *,
        feature: str,
        event_type: str,
        schema: str,
    ) -> None:
        if not isinstance(event, Mapping):
            raise FeatureGateError("feature transition requires a committed Journal control event")
        if event.get("event_type") != event_type or event.get("schema") != schema or event.get("feature") != feature:
            raise FeatureGateError("feature Journal control event does not bind the requested transition")

    def prepare(
        self,
        feature: str,
        *,
        required_reader_capabilities: Iterable[str],
        leases: CompatibilityLeaseRegistry,
        now: str,
        journal_position: int,
        journal_control_event: Mapping[str, Any] | None,
    ) -> FeatureActivation:
        required = tuple(sorted(set(required_reader_capabilities)))
        leases.assert_all_readers(required, now=now)
        self._assert_control_event(
            journal_control_event,
            feature=feature,
            event_type="runtime.feature-prepared",
            schema="RUNTIME_FEATURE_PREPARED_V1",
        )
        if feature in self._features:
            raise FeatureGateError("feature was already prepared or activated")
        value = FeatureActivation(feature, "PREPARED", required, journal_position, None, 1, None, True)
        self._features[feature] = value
        return value

    def activate(
        self,
        feature: str,
        *,
        rollback_floor_version: int,
        journal_position: int,
        journal_control_event: Mapping[str, Any] | None,
    ) -> FeatureActivation:
        current = self._features.get(feature)
        if current is None or current.state != "PREPARED":
            raise FeatureGateError("feature must be prepared before activation")
        self._assert_control_event(
            journal_control_event,
            feature=feature,
            event_type="runtime.feature-activated",
            schema="RUNTIME_FEATURE_ACTIVATED_V1",
        )
        if rollback_floor_version < 1:
            raise FeatureGateError("rollback floor must be positive")
        value = FeatureActivation(
            feature,
            "ACTIVATED",
            current.required_reader_capabilities,
            current.prepared_position,
            journal_position,
            rollback_floor_version,
            None,
            bool(journal_control_event.get("rollback_safe_after_first_write", False)),
        )
        self._features[feature] = value
        return value

    def record_first_write(self, feature: str, *, journal_position: int) -> FeatureActivation:
        current = self._features.get(feature)
        if current is None or current.state != "ACTIVATED":
            raise FeatureGateError("new format write requires an activated feature")
        if current.first_write_position is not None:
            return current
        value = FeatureActivation(
            current.feature,
            current.state,
            current.required_reader_capabilities,
            current.prepared_position,
            current.activated_position,
            current.rollback_floor_version,
            journal_position,
            current.rollback_safe_after_first_write,
        )
        self._features[feature] = value
        return value

    def assert_write_enabled(self, feature: str) -> FeatureActivation:
        current = self._features.get(feature)
        if current is None or current.state != "ACTIVATED":
            raise FeatureGateError(f"{feature} write requires an activated Journal feature state")
        return current

    def state(self, feature: str) -> FeatureActivation | None:
        return self._features.get(feature)

    def assert_writer_compatible(self, *, binary_version: int, capabilities: Iterable[str]) -> None:
        supplied = set(capabilities)
        for feature in self._features.values():
            if feature.state != "ACTIVATED":
                continue
            if binary_version < feature.rollback_floor_version:
                raise FeatureGateError("binary is below the active format rollback floor")
            if not set(feature.required_reader_capabilities).issubset(supplied):
                raise FeatureGateError("binary cannot read every activated format")

    @property
    def active_capabilities_hash(self) -> str:
        value = [
            {"feature": item.feature, "commitment": item.commitment}
            for item in sorted(self._features.values(), key=lambda item: item.feature)
            if item.state == "ACTIVATED"
        ]
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = ["FeatureActivation", "FeatureActivationRegistry", "FeatureGateError"]
