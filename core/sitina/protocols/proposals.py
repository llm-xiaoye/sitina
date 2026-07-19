from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class ProposalError(RuntimeError):
    pass


class ProposalRoundState(str, Enum):
    OPEN = "OPEN"
    SELECTED = "SELECTED"
    NO_SELECTION = "NO_SELECTION"
    CANCELLED = "CANCELLED"


class ProposalState(str, Enum):
    ACTIVE = "ACTIVE"
    NEEDS_REVISION = "NEEDS_REVISION"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    participant_id: str
    body_ref: str
    revision: int = 1
    state: ProposalState = ProposalState.ACTIVE


@dataclass(frozen=True)
class ProposalEvaluation:
    proposal_id: str
    revision: int
    evaluator_id: str
    score: int
    disposition: str


@dataclass(frozen=True)
class ProposalRound:
    round_id: str
    generation: int
    participants: tuple[str, ...]
    evaluators: tuple[str, ...]
    rubric_hash: str
    policy_hash: str
    deadline: str
    minimum_score: int
    max_revisions: int
    config_hash: str
    state: ProposalRoundState = ProposalRoundState.OPEN
    version: int = 1
    proposals: tuple[Proposal, ...] = ()
    evaluations: tuple[ProposalEvaluation, ...] = ()
    selected_proposal_id: str | None = None

    @classmethod
    def open(
        cls,
        round_id: str,
        *,
        generation: int,
        participants: tuple[str, ...],
        evaluators: tuple[str, ...],
        rubric_hash: str,
        policy_hash: str,
        deadline: str,
        minimum_score: int,
        max_revisions: int,
    ) -> tuple["ProposalRound", dict[str, Any]]:
        validate_identifier(round_id, field="round_id")
        for value in participants:
            validate_identifier(value, field="participant_id")
        for value in evaluators:
            validate_identifier(value, field="evaluator_id")
        validate_timestamp(deadline)
        if generation < 1 or not participants or not evaluators:
            raise ProposalError("ProposalRound requires positive generation and participants/evaluators")
        if len(set(participants)) != len(participants) or len(set(evaluators)) != len(evaluators):
            raise ProposalError("ProposalRound participant/evaluator sets contain duplicates")
        if len(rubric_hash) != 64 or len(policy_hash) != 64:
            raise ProposalError("invalid frozen policy hash")
        if not 0 <= minimum_score <= 100 or max_revisions < 1:
            raise ProposalError("invalid ProposalRound scoring/revision bounds")
        frozen = {
            "round_id": round_id,
            "generation": generation,
            "participants": sorted(participants),
            "evaluators": sorted(evaluators),
            "rubric_hash": rubric_hash,
            "policy_hash": policy_hash,
            "deadline": deadline,
            "minimum_score": minimum_score,
            "max_revisions": max_revisions,
        }
        config_hash = domain_hash("PROPOSAL_ROUND_CONFIG", canonical_json_bytes(frozen))
        aggregate = cls(
            round_id,
            generation,
            tuple(sorted(participants)),
            tuple(sorted(evaluators)),
            rubric_hash,
            policy_hash,
            deadline,
            minimum_score,
            max_revisions,
            config_hash,
        )
        return aggregate, {"schema": "PROPOSAL_ROUND_OPENED_V1", **frozen, "config_hash": config_hash}

    def _open(self) -> None:
        if self.state is not ProposalRoundState.OPEN:
            raise ProposalError(f"ProposalRound is {self.state.value}")

    def _proposal(self, proposal_id: str) -> Proposal:
        try:
            return next(item for item in self.proposals if item.proposal_id == proposal_id)
        except StopIteration as error:
            raise ProposalError("unknown Proposal") from error

    def submit(
        self, proposal_id: str, participant_id: str, body_ref: str
    ) -> tuple["ProposalRound", Proposal, dict[str, Any]]:
        self._open()
        validate_identifier(proposal_id, field="proposal_id")
        if participant_id not in self.participants:
            raise ProposalError("participant is outside frozen ProposalRound set")
        if len(body_ref) != 64:
            raise ProposalError("Proposal body must be an Object/Artifact reference hash")
        if any(item.proposal_id == proposal_id for item in self.proposals):
            raise ProposalError("Proposal ID already exists")
        proposal = Proposal(proposal_id, participant_id, body_ref)
        updated = replace(
            self,
            version=self.version + 1,
            proposals=self.proposals + (proposal,),
        )
        return updated, proposal, {
            "schema": "PROPOSAL_SUBMITTED_V1",
            "round_id": self.round_id,
            "generation": self.generation,
            **proposal.__dict__,
            "state": proposal.state.value,
        }

    def evaluate(
        self,
        proposal_id: str,
        evaluator_id: str,
        *,
        score: int,
        disposition: str,
    ) -> tuple["ProposalRound", dict[str, Any]]:
        self._open()
        proposal = self._proposal(proposal_id)
        if evaluator_id not in self.evaluators or not 0 <= score <= 100:
            raise ProposalError("invalid evaluator or score")
        disposition = disposition.upper()
        if disposition not in {"ACCEPT", "NEEDS_REVISION", "REJECT"}:
            raise ProposalError("invalid Proposal evaluation disposition")
        state = {
            "ACCEPT": ProposalState.ACTIVE,
            "NEEDS_REVISION": ProposalState.NEEDS_REVISION,
            "REJECT": ProposalState.REJECTED,
        }[disposition]
        evaluated = replace(proposal, state=state)
        evaluation = ProposalEvaluation(proposal_id, proposal.revision, evaluator_id, score, disposition)
        proposals = tuple(evaluated if item.proposal_id == proposal_id else item for item in self.proposals)
        updated = replace(
            self,
            version=self.version + 1,
            proposals=proposals,
            evaluations=self.evaluations + (evaluation,),
        )
        return updated, {
            "schema": "PROPOSAL_EVALUATED_V1",
            "round_id": self.round_id,
            "generation": self.generation,
            **evaluation.__dict__,
        }

    def revise(
        self, proposal_id: str, body_ref: str
    ) -> tuple["ProposalRound", Proposal, dict[str, Any]]:
        self._open()
        proposal = self._proposal(proposal_id)
        if proposal.state is not ProposalState.NEEDS_REVISION:
            raise ProposalError("only NEEDS_REVISION Proposal may be revised")
        if proposal.revision >= self.max_revisions or len(body_ref) != 64:
            raise ProposalError("Proposal revision bound or body reference invalid")
        revised = replace(
            proposal,
            body_ref=body_ref,
            revision=proposal.revision + 1,
            state=ProposalState.ACTIVE,
        )
        updated = replace(
            self,
            version=self.version + 1,
            proposals=tuple(revised if item.proposal_id == proposal_id else item for item in self.proposals),
        )
        return updated, revised, {
            "schema": "PROPOSAL_REVISED_V1",
            "round_id": self.round_id,
            "generation": self.generation,
            "proposal_id": proposal_id,
            "revision": revised.revision,
            "body_ref": body_ref,
        }

    def select(
        self, proposal_id: str, *, expected_version: int
    ) -> tuple["ProposalRound", dict[str, Any]]:
        self._open()
        if expected_version != self.version:
            raise ProposalError("ProposalRound stream CAS conflict")
        proposal = self._proposal(proposal_id)
        if proposal.state is not ProposalState.ACTIVE:
            raise ProposalError("rejected or revision-required Proposal cannot be selected")
        evaluations = [
            item
            for item in self.evaluations
            if item.proposal_id == proposal_id
            and item.revision == proposal.revision
            and item.disposition == "ACCEPT"
        ]
        if not evaluations or max(item.score for item in evaluations) < self.minimum_score:
            raise ProposalError("Proposal lacks qualifying frozen-rubric evaluation")
        updated = replace(
            self,
            state=ProposalRoundState.SELECTED,
            version=self.version + 1,
            selected_proposal_id=proposal_id,
        )
        return updated, {
            "schema": "PROPOSAL_SELECTED_V1",
            "round_id": self.round_id,
            "generation": self.generation,
            "proposal_id": proposal_id,
            "config_hash": self.config_hash,
        }

    def no_selection(
        self, next_action: str, *, expected_version: int
    ) -> tuple["ProposalRound", dict[str, Any]]:
        self._open()
        if expected_version != self.version:
            raise ProposalError("ProposalRound stream CAS conflict")
        if next_action not in {"NEW_GENERATION", "ARBITRATION", "REWORK", "CANCEL"}:
            raise ProposalError("NoSelection next action is outside frozen whitelist")
        updated = replace(
            self,
            state=ProposalRoundState.NO_SELECTION,
            version=self.version + 1,
        )
        return updated, {
            "schema": "PROPOSAL_ROUND_NO_SELECTION_V1",
            "round_id": self.round_id,
            "generation": self.generation,
            "next_action": next_action,
        }

    def change_config(self, **_changes: Any) -> None:
        raise ProposalError("frozen ProposalRound config changes require a new generation")

    def new_generation(self, **config: Any) -> tuple["ProposalRound", dict[str, Any]]:
        next_round, opened = ProposalRound.open(
            self.round_id,
            generation=self.generation + 1,
            **config,
        )
        return next_round, {
            **opened,
            "schema": "PROPOSAL_ROUND_GENERATION_OPENED_V1",
            "prior_generation": self.generation,
        }
