from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from typing import Any, Literal, Sequence

from sitina.contracts.models import BlackboardDocumentRecord
from sitina.journal.model import validate_identifier, validate_timestamp


class ContextRetentionError(RuntimeError):
    pass


@dataclass(frozen=True)
class BlackboardRetention:
    document: BlackboardDocumentRecord
    run_id: str
    registered_at: str
    retain_until: str
    run_terminal_at: str | None = None
    legal_hold: bool = False
    audit_hold: bool = False
    reference_ids: tuple[str, ...] = ()
    status: Literal["ACTIVE", "COLLECTED"] = "ACTIVE"

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, field="blackboard_retention_run")
        validate_timestamp(self.registered_at)
        validate_timestamp(self.retain_until)
        if self.run_terminal_at is not None:
            validate_timestamp(self.run_terminal_at)
        registered = dt.datetime.fromisoformat(self.registered_at.replace("Z", "+00:00"))
        retained = dt.datetime.fromisoformat(self.retain_until.replace("Z", "+00:00"))
        if retained < registered:
            raise ContextRetentionError("Blackboard retention boundary precedes registration")
        if tuple(sorted(set(self.reference_ids))) != self.reference_ids:
            raise ContextRetentionError("Blackboard retention references must be unique and sorted")
        for item in self.reference_ids:
            validate_identifier(item, field="blackboard_retention_reference")

    @classmethod
    def register(
        cls,
        document: BlackboardDocumentRecord,
        *,
        run_id: str,
        registered_at: str,
        retain_until: str,
    ) -> tuple["BlackboardRetention", dict[str, Any]]:
        aggregate = cls(document, run_id, registered_at, retain_until)
        return aggregate, {
            "schema": "BLACKBOARD_RETENTION_REGISTERED_V1",
            "run_id": run_id,
            "registered_at": registered_at,
            "retain_until": retain_until,
            "document": document.model_dump(mode="json", by_alias=True),
        }

    def mark_run_terminal(self, *, terminal_at: str) -> tuple["BlackboardRetention", dict[str, Any]]:
        validate_timestamp(terminal_at)
        if self.run_terminal_at is not None or self.status != "ACTIVE":
            raise ContextRetentionError("Blackboard retention run is already terminal or collected")
        if dt.datetime.fromisoformat(terminal_at.replace("Z", "+00:00")) < dt.datetime.fromisoformat(
            self.registered_at.replace("Z", "+00:00")
        ):
            raise ContextRetentionError("Blackboard terminal timestamp precedes registration")
        updated = replace(self, run_terminal_at=terminal_at)
        return updated, {
            "schema": "BLACKBOARD_RETENTION_RUN_TERMINAL_V1",
            "run_id": self.run_id,
            "document_id": self.document.document_id,
            "terminal_at": terminal_at,
        }

    def set_holds(
        self,
        *,
        legal_hold: bool,
        audit_hold: bool,
        actor: str,
    ) -> tuple["BlackboardRetention", dict[str, Any]]:
        validate_identifier(actor, field="blackboard_retention_actor")
        if self.status != "ACTIVE":
            raise ContextRetentionError("collected Blackboard document cannot receive a hold")
        updated = replace(self, legal_hold=legal_hold, audit_hold=audit_hold)
        return updated, {
            "schema": "BLACKBOARD_RETENTION_HOLD_CHANGED_V1",
            "run_id": self.run_id,
            "document_id": self.document.document_id,
            "actor": actor,
            "legal_hold": legal_hold,
            "audit_hold": audit_hold,
        }

    def set_references(
        self,
        reference_ids: Sequence[str],
        *,
        actor: str,
    ) -> tuple["BlackboardRetention", dict[str, Any]]:
        validate_identifier(actor, field="blackboard_retention_actor")
        values = tuple(sorted(set(reference_ids)))
        for item in values:
            validate_identifier(item, field="blackboard_retention_reference")
        if self.status != "ACTIVE":
            raise ContextRetentionError("collected Blackboard document cannot change references")
        updated = replace(self, reference_ids=values)
        return updated, {
            "schema": "BLACKBOARD_RETENTION_REFERENCES_CHANGED_V1",
            "run_id": self.run_id,
            "document_id": self.document.document_id,
            "actor": actor,
            "reference_ids": list(values),
        }

    def collect(self, *, at: str, actor: str) -> tuple["BlackboardRetention", dict[str, Any]]:
        validate_timestamp(at)
        validate_identifier(actor, field="blackboard_retention_actor")
        now = dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
        retain_until = dt.datetime.fromisoformat(self.retain_until.replace("Z", "+00:00"))
        if self.status != "ACTIVE":
            raise ContextRetentionError("Blackboard document retention is already terminal")
        if (
            self.run_terminal_at is None
            or now < retain_until
            or now < dt.datetime.fromisoformat(self.run_terminal_at.replace("Z", "+00:00"))
        ):
            raise ContextRetentionError("Blackboard document is not beyond terminal retention")
        if self.legal_hold or self.audit_hold or self.reference_ids:
            raise ContextRetentionError("Blackboard document is protected by hold or reference")
        updated = replace(self, status="COLLECTED")
        return updated, {
            "schema": "BLACKBOARD_DOCUMENT_GC_ELIGIBLE_V1",
            "run_id": self.run_id,
            "document_id": self.document.document_id,
            "document_version": self.document.document_version,
            "document_hash": self.document.document_hash,
            "content_ref": self.document.content_ref,
            "actor": actor,
            "collected_at": at,
            "holds_verified_clear": True,
            "references_verified_clear": True,
        }

    @classmethod
    def rebuild(cls, facts: Sequence[dict[str, Any]]) -> "BlackboardRetention":
        current: BlackboardRetention | None = None
        for fact in facts:
            schema = str(fact.get("schema", ""))
            if schema == "BLACKBOARD_RETENTION_REGISTERED_V1":
                if current is not None:
                    raise ContextRetentionError("duplicate Blackboard retention registration")
                current = cls(
                    BlackboardDocumentRecord.model_validate(fact["document"]),
                    str(fact["run_id"]),
                    str(fact["registered_at"]),
                    str(fact["retain_until"]),
                )
                continue
            if current is None or fact.get("document_id") != current.document.document_id:
                continue
            if schema == "BLACKBOARD_RETENTION_RUN_TERMINAL_V1":
                current = replace(current, run_terminal_at=str(fact["terminal_at"]))
            elif schema == "BLACKBOARD_RETENTION_HOLD_CHANGED_V1":
                current = replace(
                    current,
                    legal_hold=bool(fact["legal_hold"]),
                    audit_hold=bool(fact["audit_hold"]),
                )
            elif schema == "BLACKBOARD_RETENTION_REFERENCES_CHANGED_V1":
                current = replace(
                    current,
                    reference_ids=tuple(str(item) for item in fact["reference_ids"]),
                )
            elif schema == "BLACKBOARD_DOCUMENT_GC_ELIGIBLE_V1":
                current = replace(current, status="COLLECTED")
        if current is None:
            raise ContextRetentionError("cannot rebuild Blackboard retention without registration")
        return current


__all__ = ["BlackboardRetention", "ContextRetentionError"]
