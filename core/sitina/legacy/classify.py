"""Versioned Legacy fact classification with provenance-preserving conflicts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from sitina.legacy.model import LegacySourceKind, LegacySourceRecord, canonical_bytes


class IncompleteReason(str, Enum):
    MISSING_CAUSATION = "MISSING_CAUSATION"
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"
    MISSING_PAYLOAD = "MISSING_PAYLOAD"
    MISSING_ACTOR = "MISSING_ACTOR"
    MISSING_STREAM_HISTORY = "MISSING_STREAM_HISTORY"
    UNVERIFIABLE_HASH = "UNVERIFIABLE_HASH"
    ORPHAN_RECORD = "ORPHAN_RECORD"
    CONFLICTING_RECORD = "CONFLICTING_RECORD"


class LegacyFactDisposition(str, Enum):
    MIGRATED_CANONICAL_FACT = "MIGRATED_CANONICAL_FACT"
    IMPORTED_LEGACY_FACT = "IMPORTED_LEGACY_FACT"
    PRESERVED_ARTIFACT = "PRESERVED_ARTIFACT"
    NATIVE_CANONICAL_EVENT = "NATIVE_CANONICAL_EVENT"


@dataclass(frozen=True)
class LegacyFactClassification:
    fact_kind: str
    authority_weight: str
    migration_event_type: str
    completeness_reason: IncompleteReason | None
    dedup_key: str
    disposition: LegacyFactDisposition
    source_ref: str
    content_hash: str


@dataclass(frozen=True)
class PreservedConflict:
    migration_id: str
    source_ref: str
    content_hash: str
    incomplete_reason: IncompleteReason


class LegacyFactClassifier:
    def __init__(self, definition: dict[str, Any]):
        if definition.get("schema") != "LEGACY_FACT_CLASSIFICATION_V1":
            raise ValueError("unsupported Legacy classification schema")
        rules = definition.get("rules")
        if not isinstance(rules, dict):
            raise ValueError("classification rules must be an object")
        self.definition = definition
        self.rules = rules
        self.profile_hash = "sha256:" + hashlib.sha256(canonical_bytes(definition)).hexdigest()

    @classmethod
    def from_file(cls, path: Path) -> "LegacyFactClassifier":
        candidate = Path(path)
        if not candidate.is_file() or candidate.is_symlink():
            raise FileNotFoundError(candidate)
        return cls(json.loads(candidate.read_text(encoding="utf-8")))

    def _rule_name(self, record: LegacySourceRecord) -> str:
        if record.kind is LegacySourceKind.SQLITE_TABLE and "#run_ledger" in record.source_ref:
            return "run_ledger"
        if record.kind is LegacySourceKind.EVENT_JSONL:
            return "event_jsonl"
        if record.kind is LegacySourceKind.AUDIT_JSONL:
            return "audit_jsonl"
        if record.kind in {LegacySourceKind.MUTABLE_SNAPSHOT, LegacySourceKind.BLACKBOARD}:
            return "mutable_snapshot"
        if record.kind in {
            LegacySourceKind.CHECKPOINT,
            LegacySourceKind.RUN_MANIFEST,
            LegacySourceKind.REPLAY_SNAPSHOT,
            LegacySourceKind.EVIDENCE_EXPORT,
        }:
            return "legacy_evidence_artifact"
        return "artifact" if record.kind is LegacySourceKind.ARTIFACT else "event_jsonl"

    def classify(
        self,
        record: LegacySourceRecord,
        *,
        incomplete_reason: IncompleteReason | None = None,
    ) -> LegacyFactClassification:
        rule = self.rules[self._rule_name(record)]
        disposition = (
            LegacyFactDisposition.MIGRATED_CANONICAL_FACT
            if rule["migration_event_type"] == "MigratedFactRecorded"
            else LegacyFactDisposition.PRESERVED_ARTIFACT
            if rule["migration_event_type"] == "ImportedLegacyArtifact"
            else LegacyFactDisposition.IMPORTED_LEGACY_FACT
        )
        dedup_core = {
            "profile_hash": self.profile_hash,
            "source_ref": record.source_ref,
            "content_hash": record.content_hash,
            "kind": record.kind.value,
        }
        return LegacyFactClassification(
            fact_kind=str(rule["fact_kind"]),
            authority_weight=str(rule["authority_weight"]),
            migration_event_type=str(rule["migration_event_type"]),
            completeness_reason=incomplete_reason,
            dedup_key="sha256:" + hashlib.sha256(canonical_bytes(dedup_core)).hexdigest(),
            disposition=disposition,
            source_ref=record.source_ref,
            content_hash=record.content_hash,
        )


def preserve_conflicting_records(
    records: Iterable[LegacySourceRecord],
    *,
    installation_id: str,
) -> list[PreservedConflict]:
    if not installation_id:
        raise ValueError("installation_id is required")
    items = sorted(records, key=lambda item: (item.source_ref, item.content_hash, item.kind.value))
    refs: dict[str, set[str]] = {}
    for item in items:
        refs.setdefault(item.source_ref, set()).add(item.content_hash)
    output: list[PreservedConflict] = []
    for item in items:
        if len(refs[item.source_ref]) < 2:
            continue
        identity = {
            "installation_id": installation_id,
            "source_ref": item.source_ref,
            "content_hash": item.content_hash,
            "kind": item.kind.value,
        }
        output.append(
            PreservedConflict(
                migration_id="legacy-conflict-" + hashlib.sha256(canonical_bytes(identity)).hexdigest(),
                source_ref=item.source_ref,
                content_hash=item.content_hash,
                incomplete_reason=IncompleteReason.CONFLICTING_RECORD,
            )
        )
    return output
