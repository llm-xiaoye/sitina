from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AuthorityState(str, Enum):
    LEGACY_WRITER_AUTHORIZED = "LEGACY_WRITER_AUTHORIZED"
    CUTOVER_PREPARED_NO_WRITER = "CUTOVER_PREPARED_NO_WRITER"
    CUTOVER_OUTCOME_UNKNOWN_NO_WRITER = "CUTOVER_OUTCOME_UNKNOWN_NO_WRITER"
    JOURNAL_WRITER_AUTHORIZED = "JOURNAL_WRITER_AUTHORIZED"
    RECOVERY_REQUIRED_NO_WRITER = "RECOVERY_REQUIRED_NO_WRITER"


@dataclass(frozen=True)
class LegacyAuthorityFact:
    verified: bool
    fact_hash: str
    frontier_hash: str


@dataclass(frozen=True)
class AuthorityControlFacts:
    control_stream_readable: bool
    signatures_valid: bool
    continuity_verified: bool
    conflicting_evidence: bool
    same_identity_different_hash: bool
    legacy: LegacyAuthorityFact | None
    cutover_absence_proven: bool
    prepared: bool
    command_id: str | None
    request_hash: str | None
    genesis_hash: str | None
    snapshot_hash: str | None
    outcome_status: str
    outcome_verified: bool
    outcome_command_id: str | None
    outcome_request_hash: str | None
    outcome_genesis_hash: str | None
    outcome_snapshot_hash: str | None
    input_frontier_hash: str

    def input_mapping(self) -> dict[str, object]:
        return {
            "control_stream_readable": self.control_stream_readable,
            "signatures_valid": self.signatures_valid,
            "continuity_verified": self.continuity_verified,
            "conflicting_evidence": self.conflicting_evidence,
            "same_identity_different_hash": self.same_identity_different_hash,
            "legacy": self.legacy.__dict__ if self.legacy else None,
            "cutover_absence_proven": self.cutover_absence_proven,
            "prepared": self.prepared,
            "command_id": self.command_id,
            "request_hash": self.request_hash,
            "genesis_hash": self.genesis_hash,
            "snapshot_hash": self.snapshot_hash,
            "outcome_status": self.outcome_status,
            "outcome_verified": self.outcome_verified,
            "outcome_command_id": self.outcome_command_id,
            "outcome_request_hash": self.outcome_request_hash,
            "outcome_genesis_hash": self.outcome_genesis_hash,
            "outcome_snapshot_hash": self.outcome_snapshot_hash,
            "input_frontier_hash": self.input_frontier_hash,
        }


@dataclass(frozen=True)
class AuthorityResolution:
    state: AuthorityState
    resolution_id: str
    input_frontier_hash: str
    input_hash: str
    resolver_binary_hash: str
    resolver_profile: str
    issued_at: int
    expires_at: int
    reason: str

    @property
    def authorizes_legacy(self) -> bool:
        return self.state is AuthorityState.LEGACY_WRITER_AUTHORIZED

    @property
    def authorizes_journal(self) -> bool:
        return self.state is AuthorityState.JOURNAL_WRITER_AUTHORIZED

    @property
    def writer_count(self) -> int:
        return int(self.authorizes_legacy) + int(self.authorizes_journal)

    def assert_fresh(self, *, now: int) -> None:
        if now >= self.expires_at:
            from .resolver import AuthorityResolverError
            raise AuthorityResolverError("authority resolution is stale")
