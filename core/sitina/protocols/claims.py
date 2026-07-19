from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from sitina.journal.model import validate_identifier


class ClaimError(RuntimeError):
    pass


@dataclass(frozen=True)
class KnowledgeClaim:
    claim_id: str
    target_id: str
    body_ref: str
    evidence_refs: tuple[str, ...]
    version: int = 1


@dataclass(frozen=True)
class ClaimRegistry:
    claims: Mapping[str, KnowledgeClaim] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.claims is None:
            object.__setattr__(self, "claims", {})

    def create(
        self,
        claim_id: str,
        target_id: str,
        body_ref: str,
        evidence_refs: tuple[str, ...],
    ) -> tuple["ClaimRegistry", KnowledgeClaim, dict[str, Any]]:
        validate_identifier(claim_id, field="claim_id")
        validate_identifier(target_id, field="claim_target_id")
        if claim_id in self.claims:
            raise ClaimError("Claim ID already exists")
        if len(body_ref) != 64 or any(len(item) != 64 for item in evidence_refs):
            raise ClaimError("Claim body/evidence requires canonical references")
        claim = KnowledgeClaim(claim_id, target_id, body_ref, tuple(sorted(evidence_refs)))
        claims = dict(self.claims)
        claims[claim_id] = claim
        return ClaimRegistry(claims), claim, {
            "schema": "KNOWLEDGE_CLAIM_CREATED_V1",
            **claim.__dict__,
            "evidence_refs": list(claim.evidence_refs),
        }

    def revise(
        self, claim_id: str, body_ref: str, evidence_refs: tuple[str, ...]
    ) -> tuple["ClaimRegistry", KnowledgeClaim, dict[str, Any]]:
        try:
            claim = self.claims[claim_id]
        except KeyError as error:
            raise ClaimError("unknown Claim") from error
        if len(body_ref) != 64 or any(len(item) != 64 for item in evidence_refs):
            raise ClaimError("Claim body/evidence requires canonical references")
        revised = replace(
            claim,
            body_ref=body_ref,
            evidence_refs=tuple(sorted(evidence_refs)),
            version=claim.version + 1,
        )
        claims = dict(self.claims)
        claims[claim_id] = revised
        return ClaimRegistry(claims), revised, {
            "schema": "KNOWLEDGE_CLAIM_REVISED_V1",
            "claim_id": claim_id,
            "version": revised.version,
            "body_ref": body_ref,
            "evidence_refs": list(revised.evidence_refs),
        }

    def require(self, claim_id: str, *, target_id: str | None = None) -> KnowledgeClaim:
        try:
            claim = self.claims[claim_id]
        except KeyError as error:
            raise ClaimError("unknown Claim") from error
        if target_id is not None and claim.target_id != target_id:
            raise ClaimError("Claim belongs to another target")
        return claim
