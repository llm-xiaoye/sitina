from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .operational import OperationalAuthority, OperationalFactRef, OperationalFactType


@dataclass(frozen=True)
class SecurityIntakeResult:
    disposition: str
    metadata: dict
    authority_ref: OperationalFactRef


class SecurityIntake:
    def __init__(self, authority: OperationalAuthority, *, max_bytes: int = 1024 * 1024):
        self.authority = authority
        self.max_bytes = max_bytes

    def ingest(self, raw: bytes, *, content_type: str, occurred_at: str) -> SecurityIntakeResult:
        digest = hashlib.sha256(raw).hexdigest()
        oversized = len(raw) > self.max_bytes
        disposition = "QUARANTINE_ATTESTATION" if oversized or not content_type else "BOUNDED_REDACTED_METADATA"
        metadata = {
            "schema": "SECURITY_INTAKE_METADATA_V1", "content_sha256": digest, "content_length": len(raw),
            "content_type": content_type[:128] if content_type else "unknown", "raw_payload_stored": False,
            "oversized": oversized, "disposition": disposition,
        }
        reference = self.authority.record(OperationalFactType.SECURITY_INTAKE, metadata, occurred_at=occurred_at, blocking=oversized)
        return SecurityIntakeResult(disposition, metadata, reference)

