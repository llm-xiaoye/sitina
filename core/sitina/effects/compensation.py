from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .model import EffectRequest


class CompensationError(RuntimeError):
    pass


class IrreversibleDisposition(str, Enum):
    MITIGATION = "MITIGATION"
    CONTAINMENT = "CONTAINMENT"
    DISCLOSURE = "DISCLOSURE"
    RISK_ACCEPTANCE = "RISK_ACCEPTANCE"
    INCIDENT_OBLIGATION = "INCIDENT_OBLIGATION"


@dataclass(frozen=True)
class CompensationLink:
    original_effect_id: str
    compensation_effect_id: str
    compensates_effect_id: str
    chain_depth: int
    approval_hash: str


class CompensationRegistry:
    def __init__(self, *, max_chain_depth: int):
        self.max_chain_depth = max_chain_depth
        self._by_original: dict[str, CompensationLink] = {}
        self._by_compensation: dict[str, CompensationLink] = {}

    def create(
        self,
        original: EffectRequest,
        compensation: EffectRequest,
        *,
        original_reversibility: str,
        approval_hash: str,
    ) -> tuple[CompensationLink, dict[str, object]]:
        if original_reversibility == "IRREVERSIBLE":
            raise CompensationError("an irreversible Effect cannot be represented as compensated")
        if original.effect_id in self._by_original:
            raise CompensationError("duplicate compensation is forbidden")
        if compensation.effect_id == original.effect_id or len(approval_hash) != 64:
            raise CompensationError("invalid compensation identity or approval")
        parent = self._by_compensation.get(original.effect_id)
        depth = (parent.chain_depth + 1) if parent else 1
        if depth > self.max_chain_depth:
            raise CompensationError("compensation chain depth exceeds policy")
        link = CompensationLink(original.effect_id, compensation.effect_id, original.effect_id, depth, approval_hash)
        self._by_original[original.effect_id] = link
        self._by_compensation[compensation.effect_id] = link
        return link, {
            "schema": "COMPENSATION_EFFECT_LINKED_V1",
            "original_effect_id": original.effect_id,
            "compensation_effect_id": compensation.effect_id,
            "chain_depth": depth,
            "approval_hash": approval_hash,
        }

    def complete(self, compensation_effect_id: str, *, succeeded: bool) -> dict[str, object]:
        try:
            link = self._by_compensation[compensation_effect_id]
        except KeyError as error:
            raise CompensationError("unknown compensation effect") from error
        return {
            "schema": "COMPENSATION_OUTCOME_LINKED_V1",
            "original_effect_id": link.original_effect_id,
            "compensation_effect_id": compensation_effect_id,
            "compensation_succeeded": succeeded,
            "original_outcome_rewritten": False,
        }

    def disposition_irreversible(self, original: EffectRequest, disposition: IrreversibleDisposition, *, authority: str) -> dict[str, object]:
        if not authority:
            raise CompensationError("irreversible disposition requires authority")
        return {
            "schema": "IRREVERSIBLE_EFFECT_DISPOSITION_V1",
            "effect_id": original.effect_id,
            "disposition": disposition.value,
            "authority": authority,
            "claims_compensated": False,
        }
