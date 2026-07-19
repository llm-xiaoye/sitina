from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ReviewError(RuntimeError):
    pass


class ReviewVerdict(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    NEEDS_CHANGES = "NEEDS_CHANGES"


@dataclass(frozen=True)
class ReviewResponse:
    reviewer_id: str
    capabilities: tuple[str, ...]
    verdict: ReviewVerdict
    response_ref: str
    independent: bool
    security_reviewer: bool

    @property
    def commitment(self) -> str:
        return domain_hash(
            "REVIEW_RESPONSE",
            canonical_json_bytes(
                {
                    **self.__dict__,
                    "capabilities": list(self.capabilities),
                    "verdict": self.verdict.value,
                }
            ),
        )


@dataclass(frozen=True)
class ReviewRequest:
    review_id: str
    artifact_hash: str
    artifact_author_id: str
    rubric_hash: str
    quorum: int
    high_risk: bool
    security_review_required: bool
    version: int = 1
    responses: tuple[ReviewResponse, ...] = ()
    disposition: str | None = None

    @classmethod
    def open(
        cls,
        review_id: str,
        artifact_hash: str,
        artifact_author_id: str,
        rubric_hash: str,
        *,
        quorum: int,
        high_risk: bool,
        security_review_required: bool,
    ) -> tuple["ReviewRequest", dict[str, Any]]:
        validate_identifier(review_id, field="review_id")
        validate_identifier(artifact_author_id, field="artifact_author_id")
        if len(artifact_hash) != 64 or len(rubric_hash) != 64 or quorum < 1:
            raise ReviewError("invalid Review request")
        if high_risk and not security_review_required:
            raise ReviewError("high-risk Review must require a security reviewer")
        review = cls(
            review_id,
            artifact_hash,
            artifact_author_id,
            rubric_hash,
            quorum,
            high_risk,
            security_review_required,
        )
        return review, {
            "schema": "REVIEW_REQUESTED_V1",
            "review_id": review_id,
            "artifact_hash": artifact_hash,
            "artifact_author_id": artifact_author_id,
            "rubric_hash": rubric_hash,
            "quorum": quorum,
            "high_risk": high_risk,
            "security_review_required": security_review_required,
        }

    @property
    def terminal(self) -> bool:
        return self.disposition is not None

    @property
    def artifact_accepted(self) -> bool:
        return False

    def respond(
        self,
        reviewer_id: str,
        capabilities: tuple[str, ...],
        conflicting_lease: bool,
        verdict: ReviewVerdict,
        response_ref: str,
    ) -> tuple["ReviewRequest", dict[str, Any]]:
        if self.terminal:
            raise ReviewError("terminal Review cannot accept responses")
        validate_identifier(reviewer_id, field="reviewer_id")
        if reviewer_id == self.artifact_author_id:
            raise ReviewError("artifact author is not an independent reviewer")
        if "review" not in capabilities:
            raise ReviewError("reviewer lacks Review capability")
        if conflicting_lease:
            raise ReviewError("reviewer holds a conflicting artifact lease")
        if len(response_ref) != 64:
            raise ReviewError("Review response requires a canonical reference")
        if any(item.reviewer_id == reviewer_id for item in self.responses):
            raise ReviewError("reviewer already responded")
        security = "security-review" in capabilities
        response = ReviewResponse(
            reviewer_id,
            tuple(sorted(capabilities)),
            verdict,
            response_ref,
            True,
            security,
        )
        updated = replace(
            self,
            version=self.version + 1,
            responses=self.responses + (response,),
        )
        return updated, {
            "schema": "REVIEW_RESPONSE_RECORDED_V1",
            "review_id": self.review_id,
            "reviewer_id": reviewer_id,
            "verdict": verdict.value,
            "response_ref": response_ref,
            "security_reviewer": security,
            "response_commitment": response.commitment,
        }

    def dispose(self) -> tuple["ReviewRequest", dict[str, Any]]:
        if self.terminal:
            raise ReviewError("Review already has a disposition")
        accepts = [item for item in self.responses if item.verdict is ReviewVerdict.ACCEPT]
        if len(self.responses) < self.quorum:
            raise ReviewError("Review quorum is not satisfied")
        if self.security_review_required and not any(item.security_reviewer for item in self.responses):
            raise ReviewError("security-reviewer response is required")
        if any(item.verdict is ReviewVerdict.REJECT for item in self.responses):
            disposition = "REJECT"
        elif any(item.verdict is ReviewVerdict.NEEDS_CHANGES for item in self.responses):
            disposition = "NEEDS_CHANGES"
        else:
            disposition = "ACCEPT"
        if disposition == "ACCEPT" and len(accepts) < self.quorum:
            raise ReviewError("accepted Review requires an accepting quorum")
        frozen_responses = tuple(sorted(item.commitment for item in self.responses))
        updated = replace(self, version=self.version + 1, disposition=disposition)
        return updated, {
            "schema": "REVIEW_DISPOSITION_RECORDED_V1",
            "review_id": self.review_id,
            "artifact_hash": self.artifact_hash,
            "disposition": disposition,
            "response_commitments": list(frozen_responses),
            "artifact_accepted": False,
        }


@dataclass(frozen=True)
class ArtifactAcceptanceProcess:
    acceptance_id: str
    artifact_hash: str
    review_id: str
    review_response_commitments: tuple[str, ...]
    criteria_hash: str
    policy_hash: str
    accepted: bool = False

    @classmethod
    def freeze(
        cls, review: ReviewRequest, *, criteria_hash: str, policy_hash: str
    ) -> "ArtifactAcceptanceProcess":
        if review.disposition != "ACCEPT":
            raise ReviewError("Artifact Acceptance requires an accepted terminal Review disposition")
        if len(criteria_hash) != 64 or len(policy_hash) != 64:
            raise ReviewError("invalid Artifact Acceptance criteria/policy")
        commitments = tuple(sorted(item.commitment for item in review.responses))
        identity = domain_hash(
            "ARTIFACT_ACCEPTANCE_ID",
            canonical_json_bytes(
                {
                    "review_id": review.review_id,
                    "artifact_hash": review.artifact_hash,
                    "response_commitments": list(commitments),
                    "criteria_hash": criteria_hash,
                    "policy_hash": policy_hash,
                }
            ),
        )
        return cls(
            f"artifact-acceptance-{identity}",
            review.artifact_hash,
            review.review_id,
            commitments,
            criteria_hash,
            policy_hash,
        )

    def accept(
        self, artifact_hash: str, *, approval_artifact_hash: str
    ) -> tuple["ArtifactAcceptanceProcess", dict[str, Any]]:
        if self.accepted:
            return self, {
                "schema": "ARTIFACT_ACCEPTANCE_DUPLICATE_V1",
                "acceptance_id": self.acceptance_id,
                "artifact_hash": self.artifact_hash,
            }
        if artifact_hash != self.artifact_hash:
            raise ReviewError("Artifact Hash changed after Review freeze")
        if approval_artifact_hash != self.artifact_hash:
            raise ReviewError("Approval is historical but inapplicable to this Artifact Hash")
        updated = replace(self, accepted=True)
        return updated, {
            "schema": "ARTIFACT_ACCEPTED_V1",
            "acceptance_id": self.acceptance_id,
            "artifact_hash": artifact_hash,
            "review_id": self.review_id,
            "criteria_hash": self.criteria_hash,
            "policy_hash": self.policy_hash,
            "review_response_commitments": list(self.review_response_commitments),
        }
