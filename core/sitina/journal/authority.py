"""Signed, run-scoped authority operation envelopes.

The ordinary Journal append path deliberately has no finalization switch.  A
Code Mode controller submits one of these envelopes through the dedicated
authority-operation path; the Journal verifies the signature and the exact
logical operation before it can create a seal-bearing transaction.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .model import canonical_json_bytes, validate_identifier


@dataclass(frozen=True)
class AuthorityOperationEnvelope:
    schema: str
    operation: str
    operation_id: str
    run_id: str
    stream_id: str
    generation: str
    expected_stream_version: int
    parent_operation_hash: str
    payload_hash: str
    issuer_key_id: str
    signature_hex: str
    # Acceptance carries the host-authenticated logical plan and the stable
    # proof/event commitments.  They are optional only for legacy non-Code
    # Mode authority transactions; Code Mode acceptance requires them at the
    # Journal boundary.
    completion_plan_hash: str | None = None
    event_projection_hash: str | None = None
    proof_manifest_hash: str | None = None

    def unsigned(self) -> dict[str, Any]:
        value = {
            "schema": self.schema,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "generation": self.generation,
            "expected_stream_version": self.expected_stream_version,
            "parent_operation_hash": self.parent_operation_hash,
            "payload_hash": self.payload_hash,
            "issuer_key_id": self.issuer_key_id,
        }
        for key in ("completion_plan_hash", "event_projection_hash", "proof_manifest_hash"):
            item = getattr(self, key)
            if item is not None:
                value[key] = item
        return value

    def canonical_unsigned(self) -> bytes:
        return canonical_json_bytes(self.unsigned())

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthorityOperationEnvelope":
        fields = {
            "schema", "operation", "operation_id", "run_id", "stream_id",
            "generation", "expected_stream_version", "parent_operation_hash",
            "payload_hash", "issuer_key_id", "signature_hex",
        }
        optional = {"completion_plan_hash", "event_projection_hash", "proof_manifest_hash"}
        if set(value) not in (fields, fields | optional):
            raise ValueError("authority operation envelope fields are not exact")
        if value.get("schema") not in {
            "AUTHORITY_ACCEPTANCE_TRANSACTION_V1",
            "AUTHORITY_FINALIZATION_TRANSACTION_V1",
            "AUTHORITY_OPERATION_TRANSACTION_V1",
        }:
            raise ValueError("unsupported authority operation schema")
        for field in ("operation", "operation_id", "run_id", "stream_id", "generation", "issuer_key_id"):
            validate_identifier(str(value[field]), field=field)
        if type(value["expected_stream_version"]) is not int or value["expected_stream_version"] < 0:
            raise ValueError("authority operation stream version is invalid")
        for field in ("parent_operation_hash", "payload_hash"):
            if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
                raise ValueError("authority operation hash is invalid")
        for field in optional:
            if field in value and (
                not isinstance(value[field], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value[field])
            ):
                raise ValueError("authority operation commitment is invalid")
        if not isinstance(value["signature_hex"], str) or not re.fullmatch(r"[0-9a-f]{64,}", value["signature_hex"]):
            raise ValueError("authority operation signature is invalid")
        return cls(**dict(value))

    def operation_hash(self) -> str:
        unsigned = self.unsigned()
        unsigned["payload_hash"] = ""
        return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
