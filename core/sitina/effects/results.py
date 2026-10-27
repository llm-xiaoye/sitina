from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import PublishedObjectReceipt
from sitina.security.key_provider import InMemoryKeyProvider


class PipelineDisposition(str, Enum):
    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"
    DESTROYED_SECRET_POSITIVE = "DESTROYED_SECRET_POSITIVE"


@dataclass(frozen=True)
class ResultPolicy:
    max_bytes: int
    required_schema_keys: frozenset[str]
    max_decompressed_bytes: int | None = None


@dataclass(frozen=True)
class ResultPipelineOutcome:
    disposition: PipelineDisposition
    quarantine_id: str
    trust: str
    can_be_system_instruction: bool
    object_receipt: PublishedObjectReceipt | None = None
    destruction_attestation: dict[str, Any] | None = None
    rejection_reason: str | None = None
    injection_detected: bool = False


_INJECTION = re.compile(r"(?i)(ignore (?:all |any )?(?:prior|previous) instructions|become system|system prompt)")


class ResultPipeline:
    def __init__(self, cas: LocalCAS, provider: InMemoryKeyProvider, policy: ResultPolicy):
        if policy.max_bytes < 1:
            raise ValueError("result size policy must be positive")
        self.cas = cas
        self.provider = provider
        self.policy = policy

    def _reject(self, quarantine_id: str, reason: str) -> ResultPipelineOutcome:
        attestation = self.cas.destroy_quarantine(quarantine_id, reason=reason)
        return ResultPipelineOutcome(PipelineDisposition.REJECTED, quarantine_id, "UNTRUSTED_DATA", False, destruction_attestation=attestation, rejection_reason=reason)

    def process(self, raw: bytes, *, tenant_id: str, trust_source: str) -> ResultPipelineOutcome:
        quarantine_id = self.cas.publish_quarantine(raw, classification="external-result")
        if len(raw) > self.policy.max_bytes:
            return self._reject(quarantine_id, "SIZE_LIMIT")
        candidate = self.cas.open_quarantine(quarantine_id, classification="external-result")
        if candidate.startswith(b"\x1f\x8b"):
            try:
                candidate = gzip.decompress(candidate)
            except (gzip.BadGzipFile, OSError):
                return self._reject(quarantine_id, "DECOMPRESSION_INVALID")
            limit = self.policy.max_decompressed_bytes or self.policy.max_bytes
            if len(candidate) > limit:
                return self._reject(quarantine_id, "DECOMPRESSION_LIMIT")
        try:
            value = json.loads(candidate.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._reject(quarantine_id, "SCHEMA_INVALID_JSON")
        if not isinstance(value, dict) or not self.policy.required_schema_keys.issubset(value):
            return self._reject(quarantine_id, "SCHEMA_REQUIRED_KEYS_MISSING")
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        injection = bool(_INJECTION.search(serialized))
        content = serialized.encode("utf-8")
        encrypted = encrypt_object(content, self.provider, tenant_id=tenant_id, purpose="validated-external-result")
        receipt = self.cas.publish_verified(encrypted)
        self.cas.destroy_quarantine(quarantine_id, reason="VALIDATED_AND_PUBLISHED")
        trust = "TRUSTED_ADAPTER_DATA" if trust_source == "trusted_adapter" and not injection else "UNTRUSTED_DATA"
        return ResultPipelineOutcome(PipelineDisposition.PUBLISHED, quarantine_id, trust, False, receipt, injection_detected=injection)
