"""Immutable Legacy source and writer-authority types for B+ migration tooling."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _valid_utc(value: str) -> bool:
    if not value.endswith("Z"):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0)


class LegacySourceKind(str, Enum):
    SQLITE_TABLE = "sqlite_table"
    EVENT_JSONL = "event_jsonl"
    AUDIT_JSONL = "audit_jsonl"
    MUTABLE_SNAPSHOT = "mutable_snapshot"
    CHECKPOINT = "checkpoint"
    RUN_MANIFEST = "run_manifest"
    REPLAY_SNAPSHOT = "replay_snapshot"
    BLACKBOARD = "blackboard"
    EVIDENCE_EXPORT = "evidence_export"
    ARTIFACT = "artifact"


class LegacyAuthorityStage(str, Enum):
    LEGACY_ACTIVE_PROVEN = "legacy_active_proven"
    SNAPSHOT_FENCED_NO_WRITER = "snapshot_fenced_no_writer"
    SHADOW_JOURNAL = "shadow_journal"
    JOURNAL_FIRST_SHADOW_READ = "journal_first_shadow_read"
    DUAL_READ_VALIDATION = "dual_read_validation"
    CUTOVER_TOOLING_READY = "cutover_tooling_ready"
    CUTOVER_PREPARED_NO_WRITER = "cutover_prepared_no_writer"
    CUTOVER_OUTCOME_UNKNOWN_NO_WRITER = "cutover_outcome_unknown_no_writer"
    JOURNAL_AUTHORITY_PROVEN = "journal_authority_proven"
    LEGACY_RETAINED_READ_ONLY = "legacy_retained_read_only"
    CUTOVER_VERIFIED = "cutover_verified"


class AuthorityResolution(str, Enum):
    LEGACY_WRITER_AUTHORIZED = "legacy_writer_authorized"
    CUTOVER_PREPARED_NO_WRITER = "cutover_prepared_no_writer"
    CUTOVER_OUTCOME_UNKNOWN_NO_WRITER = "cutover_outcome_unknown_no_writer"
    JOURNAL_WRITER_AUTHORIZED = "journal_writer_authorized"
    RECOVERY_REQUIRED_NO_WRITER = "recovery_required_no_writer"

    @property
    def writer(self) -> str | None:
        if self is AuthorityResolution.LEGACY_WRITER_AUTHORIZED:
            return "legacy"
        if self is AuthorityResolution.JOURNAL_WRITER_AUTHORIZED:
            return "journal"
        return None


class AuthorityResolver:
    """Derive writer authority only from verified cutover facts, never phase names."""

    def resolve(
        self,
        *,
        legacy_fence_verified: bool,
        production_genesis_verified: bool,
        cutover_outcome: str | None,
        recovery_required: bool = False,
    ) -> AuthorityResolution:
        if recovery_required:
            return AuthorityResolution.RECOVERY_REQUIRED_NO_WRITER
        if not legacy_fence_verified and not production_genesis_verified and cutover_outcome is None:
            return AuthorityResolution.LEGACY_WRITER_AUTHORIZED
        if legacy_fence_verified and production_genesis_verified:
            if cutover_outcome is None:
                return AuthorityResolution.CUTOVER_PREPARED_NO_WRITER
            normalized = cutover_outcome.upper()
            if normalized == "COMMITTED":
                return AuthorityResolution.JOURNAL_WRITER_AUTHORIZED
            if normalized in {"UNKNOWN", "ACK_LOST", "INDETERMINATE"}:
                return AuthorityResolution.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER
        return AuthorityResolution.RECOVERY_REQUIRED_NO_WRITER


@dataclass(frozen=True)
class LegacySourceRecord:
    kind: LegacySourceKind
    source_ref: str
    content_hash: str
    observed_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source_ref or self.source_ref.strip() != self.source_ref:
            raise ValueError("source_ref must be non-empty and canonical")
        if not _SHA256.fullmatch(self.content_hash):
            raise ValueError("content_hash must be lowercase sha256:<64-hex>")
        if not _valid_utc(self.observed_at):
            raise ValueError("observed_at must be canonical UTC ending in Z")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source_ref": self.source_ref,
            "content_hash": self.content_hash,
            "observed_at": self.observed_at,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class FileObservation:
    source_ref: str
    size: int
    mtime_ns: int
    inode: int
    device: int
    mode: str
    content_hash: str
    observation_status: str


@dataclass(frozen=True)
class SQLiteTableSummary:
    row_count: int
    max_integer_key: int | None


@dataclass(frozen=True)
class CapacityCheck:
    required_bytes: int
    free_bytes: int
    required_inodes: int
    free_inodes: int
    safety_multiplier: float
    passed: bool


@dataclass(frozen=True)
class LegacyObservationManifest:
    schema: str
    coherence: str
    source_home: str
    sqlite_snapshot_hash: str
    entries: tuple[FileObservation, ...]
    table_summaries: Mapping[str, SQLiteTableSummary]
    capacity_check: CapacityCheck
    semantic_manifest_hash: str
    observed_at: str

    def to_mapping(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value["entries"] = [dataclasses.asdict(item) for item in self.entries]
        value["table_summaries"] = {
            key: dataclasses.asdict(item) for key, item in sorted(self.table_summaries.items())
        }
        return value


@dataclass(frozen=True)
class LegacySnapshotManifest(LegacyObservationManifest):
    cutoff: str = ""
    fence_snapshot_id: str = ""
    fence_record_hash: str = ""

