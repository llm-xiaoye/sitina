from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import validate_identifier


class MonitoringTransferError(RuntimeError):
    pass


class TransferState(str, Enum):
    OFFERED = "OFFERED"
    ACCEPTED = "ACCEPTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"


@dataclass(frozen=True)
class MonitoringTransfer:
    transfer_id: str
    source_run_id: str
    successor_stream_id: str
    effect_ids: tuple[str, ...]
    monitoring_policy_hash: str
    state: TransferState = TransferState.OFFERED
    successor_authority: str | None = None

    @classmethod
    def create(cls, transfer_id: str, source_run_id: str, successor_stream_id: str, effect_ids: tuple[str, ...], monitoring_policy_hash: str) -> "MonitoringTransfer":
        for value, field in ((transfer_id, "transfer_id"), (source_run_id, "source_run_id"), (successor_stream_id, "successor_stream_id")):
            validate_identifier(value, field=field)
        if not effect_ids or len(monitoring_policy_hash) != 64:
            raise MonitoringTransferError("monitoring transfer requires effects and exact policy")
        return cls(transfer_id, source_run_id, successor_stream_id, tuple(sorted(set(effect_ids))), monitoring_policy_hash)

    def accept_successor(self, *, authority: str) -> tuple["MonitoringTransfer", dict[str, object]]:
        if self.state is not TransferState.OFFERED:
            raise MonitoringTransferError("monitoring transfer is not awaiting acceptance")
        validate_identifier(authority, field="successor_authority")
        updated = replace(self, state=TransferState.ACCEPTED, successor_authority=authority)
        return updated, {
            "schema": "MONITORING_OBLIGATION_ACCEPTED_V1",
            "transfer_id": self.transfer_id,
            "successor_stream_id": self.successor_stream_id,
            "effect_ids": list(self.effect_ids),
            "authority": authority,
        }

    def acknowledge_source(self) -> tuple["MonitoringTransfer", dict[str, object]]:
        if self.state is not TransferState.ACCEPTED:
            raise MonitoringTransferError("successor must durably accept before source acknowledgement")
        updated = replace(self, state=TransferState.ACKNOWLEDGED)
        return updated, {
            "schema": "MONITORING_TRANSFER_ACKNOWLEDGED_V1",
            "transfer_id": self.transfer_id,
            "source_run_id": self.source_run_id,
            "terminal_blocker_released": True,
        }

    def authorize_late_action(self, effect_id: str, *, authority: str) -> dict[str, object]:
        if self.state is not TransferState.ACKNOWLEDGED or authority != self.successor_authority or effect_id not in self.effect_ids:
            raise MonitoringTransferError("late action lacks successor authority")
        return {
            "schema": "MONITORING_SUCCESSOR_ACTION_AUTHORIZED_V1",
            "effect_id": effect_id,
            "authority": authority,
            "authority_stream": self.successor_stream_id,
        }
