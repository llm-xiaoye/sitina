from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from sitina.commands.model import CommandEnvelope
from sitina.journal.model import EventEnvelope, canonical_json_bytes

from .capabilities import CapabilityError, FormatCapability, FormatCapabilityRegistry
from .errors import FeatureGateError
from .feature_flags import FeatureActivation, FeatureActivationRegistry
from .leases import CompatibilityLeaseRegistry


@dataclass(frozen=True)
class FeatureRolloutReceipt:
    feature: str
    state: str
    prepared_position: int
    activated_position: int | None
    required_reader_capabilities: tuple[str, ...]
    rollback_floor_version: int
    rollback_safe_after_first_write: bool

    def mapping(self) -> dict[str, object]:
        return {
            "feature": self.feature,
            "state": self.state,
            "prepared_position": self.prepared_position,
            "activated_position": self.activated_position,
            "required_reader_capabilities": list(self.required_reader_capabilities),
            "rollback_floor_version": self.rollback_floor_version,
            "rollback_safe_after_first_write": self.rollback_safe_after_first_write,
        }


class JournalFeatureRollout:
    """Lease-fenced, Journal-authoritative feature prepare/activate protocol."""

    TENANT = "sitina-runtime"

    def __init__(
        self,
        journal: Any,
        leases: CompatibilityLeaseRegistry,
        formats: FormatCapabilityRegistry,
        *,
        process_id: str,
        fencing_token: int,
        binary_version: str,
        actor: str,
        goal_thread_id: str,
    ):
        self.journal = journal
        self.leases = leases
        self.formats = formats
        self.process_id = process_id
        self.fencing_token = fencing_token
        self.binary_version = binary_version
        self.actor = actor
        self.goal_thread_id = goal_thread_id

    def _format(self, feature: str) -> FormatCapability:
        matching = [self.formats.get(name) for name in self.formats.names if self.formats.get(name).feature_flag == feature]
        if len(matching) != 1:
            raise CapabilityError("feature flag does not identify exactly one registered format")
        return matching[0]

    def _state(self) -> FeatureActivationRegistry:
        return FeatureActivationRegistry.from_journal_events(self.journal.iter_events(0))

    def _admit(
        self,
        required_reader_capabilities: tuple[str, ...],
        *,
        now: str,
    ) -> tuple[str, ...]:
        writer = self.leases.assert_writer(
            self.process_id,
            fencing_token=self.fencing_token,
            now=now,
        )
        required = set(required_reader_capabilities)
        if not required.issubset(writer.reader_capabilities) or not required.issubset(writer.writer_capabilities):
            raise FeatureGateError("rollout writer lease lacks the required read/write capability")
        self.leases.assert_all_readers(required, now=now)
        active = self.leases.active(now=now)
        return tuple(sorted(item.commitment for item in active))

    @staticmethod
    def _receipt(value: FeatureActivation) -> FeatureRolloutReceipt:
        return FeatureRolloutReceipt(
            value.feature,
            value.state,
            value.prepared_position,
            value.activated_position,
            value.required_reader_capabilities,
            value.rollback_floor_version,
            value.rollback_safe_after_first_write,
        )

    def _append(self, *, feature: str, stage: str, payload: dict[str, object], occurred_at: str) -> None:
        stream_id = f"runtime/features/{feature}"
        digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "goal_thread_id": self.goal_thread_id,
                    "feature": feature,
                    "stage": stage,
                    "payload": payload,
                }
            )
        ).hexdigest()
        command = CommandEnvelope(
            f"feature-{stage}-command-" + digest[:39],
            self.TENANT,
            stream_id,
            f"runtime.feature-{stage}",
            self.actor,
            occurred_at,
            {
                "feature": feature,
                "goal_thread_id": self.goal_thread_id,
                "rollout_hash": digest,
            },
        )
        event = EventEnvelope(
            f"feature-{stage}-event-" + digest[:41],
            f"runtime.feature-{stage}d" if stage == "prepare" else "runtime.feature-activated",
            self.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            payload,
        )
        self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
        )

    def prepare(
        self,
        feature: str,
        *,
        required_reader_capabilities: Iterable[str],
        occurred_at: str,
    ) -> FeatureRolloutReceipt:
        required = tuple(sorted(set(required_reader_capabilities)))
        capability = self._format(feature)
        current = self._state().state(feature)
        if current is not None:
            if current.required_reader_capabilities != required:
                raise FeatureGateError("existing feature preparation has different Reader Capabilities")
            return self._receipt(current)
        lease_commitments = self._admit(required, now=occurred_at)
        payload: dict[str, object] = {
            "schema": "RUNTIME_FEATURE_PREPARED_V1",
            "event_type": "runtime.feature-prepared",
            "feature": feature,
            "format_name": capability.format_name,
            "writer_version": capability.writer_version,
            "minimum_reader_version": capability.minimum_reader_version,
            "required_reader_capabilities": list(required),
            "compatibility_lease_commitments": list(lease_commitments),
            "format_registry_hash": self.formats.registry_hash,
            "binary_version": self.binary_version,
            "goal_thread_id": self.goal_thread_id,
            "rollback_safe_before_first_write": capability.rollback_safe_before_first_write,
        }
        self._append(feature=feature, stage="prepare", payload=payload, occurred_at=occurred_at)
        state = self._state().state(feature)
        if state is None or state.state != "PREPARED":
            raise FeatureGateError("committed feature preparation did not replay")
        return self._receipt(state)

    def activate(self, feature: str, *, occurred_at: str) -> FeatureRolloutReceipt:
        capability = self._format(feature)
        current = self._state().state(feature)
        if current is None:
            raise FeatureGateError("feature must be prepared before activation")
        if current.state == "ACTIVATED":
            if current.rollback_floor_version != capability.rollback_floor_version:
                raise FeatureGateError("active feature rollback floor differs from the format registry")
            return self._receipt(current)
        lease_commitments = self._admit(current.required_reader_capabilities, now=occurred_at)
        payload: dict[str, object] = {
            "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
            "event_type": "runtime.feature-activated",
            "feature": feature,
            "format_name": capability.format_name,
            "rollback_floor_version": capability.rollback_floor_version,
            "rollback_safe_after_first_write": capability.rollback_safe_after_first_write,
            "required_reader_capabilities": list(current.required_reader_capabilities),
            "compatibility_lease_commitments": list(lease_commitments),
            "format_registry_hash": self.formats.registry_hash,
            "binary_version": self.binary_version,
            "goal_thread_id": self.goal_thread_id,
        }
        self._append(feature=feature, stage="activate", payload=payload, occurred_at=occurred_at)
        state = self._state().state(feature)
        if state is None or state.state != "ACTIVATED":
            raise FeatureGateError("committed feature activation did not replay")
        if state.rollback_safe_after_first_write != capability.rollback_safe_after_first_write:
            raise FeatureGateError("committed feature rollback safety differs from the format registry")
        return self._receipt(state)


__all__ = ["FeatureRolloutReceipt", "JournalFeatureRollout"]
