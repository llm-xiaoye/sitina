from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp

from .claims import ClaimError, ClaimRegistry


class DebateError(RuntimeError):
    pass


class DebateOutcome(str, Enum):
    CONSENSUS = "CONSENSUS"
    NO_CONSENSUS = "NO_CONSENSUS"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class DebateResponse:
    response_id: str
    claim_id: str
    target_claim_id: str
    actor_id: str
    round_number: int
    token_count: int
    body_ref: str


@dataclass(frozen=True)
class Debate:
    debate_id: str
    target_id: str
    max_rounds: int
    max_tokens: int
    deadline: str
    version: int = 1
    responses: tuple[DebateResponse, ...] = ()
    outcome: DebateOutcome | None = None
    synthesis_candidate_hash: str | None = None
    synthesis_hash: str | None = None
    successor_obligation_id: str | None = None

    @classmethod
    def open(
        cls,
        debate_id: str,
        target_id: str,
        *,
        max_rounds: int,
        max_tokens: int,
        deadline: str,
    ) -> tuple["Debate", dict[str, Any]]:
        validate_identifier(debate_id, field="debate_id")
        validate_identifier(target_id, field="debate_target_id")
        validate_timestamp(deadline)
        if max_rounds < 1 or max_tokens < 1:
            raise DebateError("Debate bounds must be positive")
        debate = cls(debate_id, target_id, max_rounds, max_tokens, deadline)
        return debate, {
            "schema": "DEBATE_OPENED_V1",
            "debate_id": debate_id,
            "target_id": target_id,
            "max_rounds": max_rounds,
            "max_tokens": max_tokens,
            "deadline": deadline,
        }

    @property
    def terminal(self) -> bool:
        return self.outcome is not None

    def respond(
        self,
        claims: ClaimRegistry,
        response_id: str,
        claim_id: str,
        target_claim_id: str,
        actor_id: str,
        round_number: int,
        token_count: int,
        body_ref: str,
        *,
        now: str = "2026-07-13T00:00:00Z",
    ) -> tuple["Debate", DebateResponse, dict[str, Any]]:
        if self.terminal:
            raise DebateError("terminal Debate cannot accept Responses")
        for value, field in ((response_id, "response_id"), (actor_id, "actor_id")):
            validate_identifier(value, field=field)
        try:
            claims.require(claim_id, target_id=self.target_id)
            claims.require(target_claim_id, target_id=self.target_id)
        except ClaimError as error:
            raise DebateError(str(error)) from error
        validate_timestamp(now)
        if dt.datetime.fromisoformat(now.replace("Z", "+00:00")) >= dt.datetime.fromisoformat(
            self.deadline.replace("Z", "+00:00")
        ):
            raise DebateError("Debate deadline passed")
        if not 1 <= round_number <= self.max_rounds:
            raise DebateError("Debate round bound exceeded")
        if token_count < 1 or sum(item.token_count for item in self.responses) + token_count > self.max_tokens:
            raise DebateError("Debate token bound exceeded")
        if len(body_ref) != 64 or any(item.response_id == response_id for item in self.responses):
            raise DebateError("invalid or duplicate Response")
        response = DebateResponse(
            response_id,
            claim_id,
            target_claim_id,
            actor_id,
            round_number,
            token_count,
            body_ref,
        )
        updated = replace(
            self,
            version=self.version + 1,
            responses=self.responses + (response,),
        )
        return updated, response, {
            "schema": "DEBATE_RESPONSE_RECORDED_V1",
            "debate_id": self.debate_id,
            **response.__dict__,
        }

    def submit_synthesis(
        self,
        claims: ClaimRegistry,
        *,
        evidence_map: Mapping[str, tuple[str, ...]],
        synthesizer_id: str,
    ) -> tuple["Debate", dict[str, Any]]:
        if self.terminal or self.synthesis_candidate_hash is not None:
            raise DebateError("Debate synthesis candidate is already submitted or terminal")
        validate_identifier(synthesizer_id, field="debate_synthesizer_id")
        expected = set(claims.claims)
        if not self.responses or set(evidence_map) != expected:
            raise DebateError("Debate synthesis candidate must cover every Claim after Responses")
        for claim_id, references in evidence_map.items():
            claims.require(claim_id, target_id=self.target_id)
            if not references or any(len(reference) != 64 for reference in references):
                raise DebateError("Debate synthesis candidate contains invalid evidence references")
        candidate = {
            "debate_id": self.debate_id,
            "target_id": self.target_id,
            "response_ids": sorted(item.response_id for item in self.responses),
            "evidence_map": {key: sorted(value) for key, value in sorted(evidence_map.items())},
            "synthesizer_id": synthesizer_id,
        }
        candidate_hash = domain_hash("DEBATE_SYNTHESIS_CANDIDATE", canonical_json_bytes(candidate))
        updated = replace(
            self,
            version=self.version + 1,
            synthesis_candidate_hash=candidate_hash,
        )
        return updated, {
            "schema": "DEBATE_SYNTHESIS_SUBMITTED_V1",
            **candidate,
            "synthesis_candidate_hash": candidate_hash,
        }

    def finalize(
        self,
        claims: ClaimRegistry,
        *,
        included: tuple[str, ...],
        excluded: tuple[str, ...],
        unresolved: tuple[str, ...],
        evidence_map: Mapping[str, tuple[str, ...]],
        outcome: DebateOutcome,
    ) -> tuple["Debate", dict[str, Any]]:
        if self.terminal:
            raise DebateError("Debate synthesis already finalized")
        if self.synthesis_candidate_hash is None:
            raise DebateError("Debate finalization requires a submitted synthesis candidate")
        groups = (included, excluded, unresolved)
        flattened = [item for group in groups for item in group]
        expected = set(claims.claims)
        if set(flattened) != expected or len(flattened) != len(set(flattened)):
            raise DebateError("synthesis must exactly partition every Claim")
        if set(evidence_map) != expected:
            raise DebateError("Evidence Map must cover every Claim")
        for claim_id, references in evidence_map.items():
            claims.require(claim_id, target_id=self.target_id)
            if not references or any(len(reference) != 64 for reference in references):
                raise DebateError("Evidence Map contains invalid references")
        if outcome is DebateOutcome.CONSENSUS and unresolved:
            raise DebateError("CONSENSUS cannot retain unresolved Claims")
        if outcome is DebateOutcome.NO_CONSENSUS and not unresolved:
            raise DebateError("NO_CONSENSUS requires unresolved Claims")
        synthesis = {
            "debate_id": self.debate_id,
            "synthesis_candidate_hash": self.synthesis_candidate_hash,
            "included": sorted(included),
            "excluded": sorted(excluded),
            "unresolved": sorted(unresolved),
            "evidence_map": {key: sorted(value) for key, value in sorted(evidence_map.items())},
            "outcome": outcome.value,
        }
        synthesis_hash = domain_hash("DEBATE_SYNTHESIS", canonical_json_bytes(synthesis))
        successor = None
        next_action = "NONE"
        if outcome is DebateOutcome.NO_CONSENSUS:
            successor = "obligation-debate-" + domain_hash(
                "DEBATE_SUCCESSOR_OBLIGATION",
                canonical_json_bytes({"debate_id": self.debate_id, "synthesis_hash": synthesis_hash}),
            )
            next_action = "CREATE_SUCCESSOR_OBLIGATION"
        updated = replace(
            self,
            version=self.version + 1,
            outcome=outcome,
            synthesis_hash=synthesis_hash,
            successor_obligation_id=successor,
        )
        return updated, {
            "schema": "DEBATE_SYNTHESIS_FINALIZED_V1",
            **synthesis,
            "synthesis_hash": synthesis_hash,
            "successor_obligation_id": successor,
            "next_action": next_action,
        }
