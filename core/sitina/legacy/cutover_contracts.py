from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ContractError(ValueError):
    pass


READINESS_PREDICATE_IDS = (
    "PHASE_MINUS1_THROUGH_PHASE5_ACCEPTED",
    "CAPACITY_PROFILE_REVIEWED",
    "KEY_AND_TRUST_PROFILES_VERIFIED",
    "CANONICAL_BACKUP_VERIFIED",
    "FINAL_COLD_RESTORE_DRILL_VERIFIED",
    "LEGACY_WRITER_FENCE_COVERAGE_COMPLETE",
    "AUTHORITY_RESOLVER_EXHAUSTIVE",
    "GENESIS_NAMESPACE_BARRIER_VERIFIED",
    "EFFECT_EXPOSURE_DRAINED",
    "MONITORING_TRANSFER_VERIFIED",
    "MIGRATION_CLOSURE_VERIFIED",
    "FIXED_FRONTIER_DUAL_READ_VERIFIED",
    "JOURNAL_CAS_REBUILD_VERIFIED",
    "READER_ROLLBACK_MATRIX_VERIFIED",
    "RETENTION_DESTRUCTIVE_CAPABILITY_ABSENT",
    "EXTERNAL_CAPABILITY_CEILING_MOCK_ONLY",
    "PRODUCTION_SENTINELS_UNCHANGED",
)


@dataclass(frozen=True)
class CutoverCommandIdentity:
    command_id: str
    request_hash: str

    @classmethod
    def freeze(cls, command_id: str, request: Mapping[str, object]) -> "CutoverCommandIdentity":
        validate_identifier(command_id, field="cutover command_id")
        return cls(command_id, domain_hash("CUTOVER_COMMAND_REQUEST", canonical_json_bytes(dict(request))))

    def assert_same(self, command_id: str, request_hash: str) -> None:
        if self.command_id != command_id or self.request_hash != request_hash:
            raise ContractError("same cutover identity is bound to a different request")


@dataclass(frozen=True)
class CutoverContracts:
    profile_id: str
    canonical_profile: str
    schemas: Mapping[str, str]
    predicate_ids: tuple[str, ...]
    authority_states: tuple[str, ...]
    policy_input_signed: bool
    policy_attestation_hash: str
    contract_hash: str

    @classmethod
    def from_file(cls, path: Path) -> "CutoverContracts":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("profile_id") != "SITINA_CUTOVER_CONTRACTS_BPLUS_V1":
            raise ContractError("unknown cutover contract profile")
        predicates = tuple(raw.get("predicate_ids", ()))
        if predicates != READINESS_PREDICATE_IDS or len(set(predicates)) != len(predicates):
            raise ContractError("readiness predicate registry drifted")
        attestation = raw.get("policy_attestation")
        if not isinstance(attestation, dict) or attestation.get("signed") is not True:
            raise ContractError("cutover contract policy input is unsigned")
        declared = str(attestation.get("attested_payload_sha256", ""))
        body = dict(raw); body.pop("policy_attestation", None)
        actual = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        if declared != actual:
            raise ContractError("cutover contract policy attestation does not match canonical payload")
        if attestation.get("signature_profile") != "OWNER_ATTESTED_SHA256_V1" or not attestation.get("signer_key_id"):
            raise ContractError("cutover contract attestation profile is invalid")
        schemas = raw.get("schemas")
        states = tuple(raw.get("authority_states", ()))
        if not isinstance(schemas, dict) or not schemas or len(states) != 5:
            raise ContractError("cutover contract schemas or authority state registry is incomplete")
        return cls(
            raw["profile_id"], raw["canonical_profile"], dict(schemas), predicates, states, True,
            actual, hashlib.sha256(canonical_json_bytes(raw)).hexdigest(),
        )

    def validate_predicates(self, values: Mapping[str, bool]) -> None:
        if set(values) != set(self.predicate_ids):
            raise ContractError("readiness predicates are missing or unknown")
        if any(not isinstance(value, bool) for value in values.values()):
            raise ContractError("readiness predicate values must be booleans")

