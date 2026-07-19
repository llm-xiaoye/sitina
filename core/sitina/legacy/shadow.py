"""Physically isolated, non-authoritative Shadow import envelopes."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sitina.legacy.model import LegacySourceKind, LegacySourceRecord, canonical_bytes


class ShadowExecutionDenied(RuntimeError):
    pass


class ShadowExecutionGuard:
    _DENIED = {"provider", "mcp", "tool", "approval", "timer", "terminal", "evidence_seal", "effect"}

    def __init__(self, *, authority: bool):
        self.authority = authority

    def assert_operation_allowed(self, operation: str) -> None:
        if not self.authority and operation in self._DENIED:
            raise ShadowExecutionDenied(f"non-authoritative Shadow context cannot execute {operation}")


@dataclass(frozen=True)
class ShadowFactEnvelope:
    schema: str
    migration_fact_id: str
    namespace: str
    authority: bool
    event_type: str
    installation_id: str
    snapshot_id: str
    snapshot_hash: str
    source_kind: str
    source_ref: str
    source_content_hash: str
    conversion_rule_hash: str
    historical_observed_at: str
    committed_at: str
    payload: dict[str, Any]
    payload_hash: str


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


class ShadowImporter:
    def __init__(
        self,
        *,
        source_home: Path,
        shadow_root: Path,
        installation_id: str,
        snapshot_id: str,
        snapshot_hash: str,
        conversion_rule_hash: str,
    ):
        self.source_home = Path(source_home).expanduser().resolve(strict=True)
        self.shadow_root = Path(shadow_root).expanduser().resolve(strict=False)
        if self.shadow_root == self.source_home or _inside(self.shadow_root, self.source_home) or _inside(self.source_home, self.shadow_root):
            raise ValueError("Shadow and Legacy source roots must be physically disjoint")
        if not installation_id or not snapshot_id:
            raise ValueError("installation_id and snapshot_id are required")
        for name, value in (("snapshot_hash", snapshot_hash), ("conversion_rule_hash", conversion_rule_hash)):
            if not value.startswith("sha256:") or len(value) != 71:
                raise ValueError(f"{name} must be sha256:<64-hex>")
        self.installation_id = installation_id
        self.snapshot_id = snapshot_id
        self.snapshot_hash = snapshot_hash
        self.conversion_rule_hash = conversion_rule_hash
        self.namespace = f"shadow/{snapshot_id}"
        self.output_path = self.shadow_root / "shadow" / snapshot_id / "facts.jsonl"

    def _identity(self, record: LegacySourceRecord) -> str:
        value = {
            "installation_id": self.installation_id,
            "snapshot_hash": self.snapshot_hash,
            "source_ref": record.source_ref,
            "source_content_hash": record.content_hash,
            "conversion_rule_hash": self.conversion_rule_hash,
        }
        return "shadow-fact-" + hashlib.sha256(canonical_bytes(value)).hexdigest()

    def _existing_ids(self) -> set[str]:
        if not self.output_path.exists():
            return set()
        result: set[str] = set()
        for line_number, line in enumerate(self.output_path.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"corrupt Shadow import at line {line_number}") from error
            result.add(str(value["migration_fact_id"]))
        return result

    def import_record(self, record: LegacySourceRecord, *, payload: dict[str, Any]) -> ShadowFactEnvelope:
        migration_id = self._identity(record)
        event_type = "MigratedFactRecorded" if record.kind is LegacySourceKind.SQLITE_TABLE and "#run_ledger" in record.source_ref else "ImportedLegacyFact"
        payload_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
        envelope = ShadowFactEnvelope(
            schema="SHADOW_FACT_ENVELOPE_V1",
            migration_fact_id=migration_id,
            namespace=self.namespace,
            authority=False,
            event_type=event_type,
            installation_id=self.installation_id,
            snapshot_id=self.snapshot_id,
            snapshot_hash=self.snapshot_hash,
            source_kind=record.kind.value,
            source_ref=record.source_ref,
            source_content_hash=record.content_hash,
            conversion_rule_hash=self.conversion_rule_hash,
            historical_observed_at=record.observed_at,
            committed_at=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            payload=dict(payload),
            payload_hash=payload_hash,
        )
        existing = self._existing_ids()
        if migration_id in existing:
            return envelope
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.output_path, flags, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(asdict(envelope), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return envelope
