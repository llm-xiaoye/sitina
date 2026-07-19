from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class ArbitrationError(RuntimeError):
    pass


class ArbitrationState(str, Enum):
    OPEN = "OPEN"
    ADMITTED = "ADMITTED"
    ENFORCEMENT_PENDING = "ENFORCEMENT_PENDING"
    ENFORCED = "ENFORCED"
    FAILED = "FAILED"
    APPEALED = "APPEALED"


@dataclass(frozen=True)
class Arbitration:
    arbitration_id: str
    obligation_id: str
    authority_policy_hash: str
    max_appeals: int
    appeal_deadline: str
    appeal_authorities: tuple[str, ...]
    state: ArbitrationState = ArbitrationState.OPEN
    version: int = 1
    generation: int = 1
    admitted_claims: tuple[str, ...] = ()
    arbiter_id: str | None = None
    decision: str | None = None
    binding_scope: tuple[str, ...] = ()
    decision_evidence_refs: tuple[str, ...] = ()
    enforcement_ref: str | None = None
    appeal_generation: int = 0
    appeal_evidence_refs: tuple[str, ...] = ()

    @classmethod
    def open(
        cls,
        arbitration_id: str,
        obligation_id: str,
        authority_policy_hash: str,
        *,
        max_appeals: int,
        appeal_deadline: str,
        appeal_authorities: tuple[str, ...],
    ) -> tuple["Arbitration", dict[str, Any]]:
        validate_identifier(arbitration_id, field="arbitration_id")
        validate_identifier(obligation_id, field="obligation_id")
        validate_timestamp(appeal_deadline)
        for authority in appeal_authorities:
            validate_identifier(authority, field="appeal_authority")
        if len(authority_policy_hash) != 64 or max_appeals < 0 or not appeal_authorities:
            raise ArbitrationError("invalid Arbitration policy")
        aggregate = cls(
            arbitration_id,
            obligation_id,
            authority_policy_hash,
            max_appeals,
            appeal_deadline,
            tuple(sorted(appeal_authorities)),
        )
        return aggregate, {
            "schema": "ARBITRATION_OPENED_V1",
            "arbitration_id": arbitration_id,
            "obligation_id": obligation_id,
            "authority_policy_hash": authority_policy_hash,
            "max_appeals": max_appeals,
            "appeal_deadline": appeal_deadline,
            "appeal_authorities": list(aggregate.appeal_authorities),
        }

    @property
    def obligation_satisfied(self) -> bool:
        return self.state is ArbitrationState.ENFORCED and self.enforcement_ref is not None

    def blocks_dispatch(self, target_id: str) -> bool:
        return self.state is ArbitrationState.ENFORCEMENT_PENDING and target_id in self.binding_scope

    def admit(
        self, claim_ids: tuple[str, ...], arbiter_id: str
    ) -> tuple["Arbitration", dict[str, Any]]:
        if self.state not in {ArbitrationState.OPEN, ArbitrationState.APPEALED}:
            raise ArbitrationError("Arbitration cannot admit claims in current state")
        validate_identifier(arbiter_id, field="arbiter_id")
        if not claim_ids or len(set(claim_ids)) != len(claim_ids):
            raise ArbitrationError("Arbitration requires unique admitted Claims")
        for claim_id in claim_ids:
            validate_identifier(claim_id, field="claim_id")
        updated = replace(
            self,
            state=ArbitrationState.ADMITTED,
            version=self.version + 1,
            admitted_claims=tuple(sorted(claim_ids)),
            arbiter_id=arbiter_id,
            decision=None,
            binding_scope=(),
            decision_evidence_refs=(),
            enforcement_ref=None,
        )
        return updated, {
            "schema": "ARBITRATION_CLAIMS_ADMITTED_V1",
            "arbitration_id": self.arbitration_id,
            "generation": self.generation,
            "claim_ids": list(updated.admitted_claims),
            "arbiter_id": arbiter_id,
        }

    def decide(
        self,
        decision: str,
        *,
        binding_scope: tuple[str, ...],
        evidence_refs: tuple[str, ...],
    ) -> tuple["Arbitration", dict[str, Any]]:
        if self.state is not ArbitrationState.ADMITTED:
            raise ArbitrationError("Arbitration Decision requires admitted state")
        if not binding_scope or not evidence_refs or any(len(item) != 64 for item in evidence_refs):
            raise ArbitrationError("binding scope and evidence are required")
        for target in binding_scope:
            validate_identifier(target, field="binding_target_id")
        decision_hash = domain_hash(
            "ARBITRATION_DECISION",
            canonical_json_bytes(
                {
                    "arbitration_id": self.arbitration_id,
                    "generation": self.generation,
                    "decision": decision,
                    "binding_scope": sorted(binding_scope),
                    "evidence_refs": sorted(evidence_refs),
                }
            ),
        )
        updated = replace(
            self,
            state=ArbitrationState.ENFORCEMENT_PENDING,
            version=self.version + 1,
            decision=decision,
            binding_scope=tuple(sorted(binding_scope)),
            decision_evidence_refs=tuple(sorted(evidence_refs)),
        )
        return updated, {
            "schema": "ARBITRATION_DECIDED_V1",
            "arbitration_id": self.arbitration_id,
            "generation": self.generation,
            "decision_hash": decision_hash,
            "binding_scope": list(updated.binding_scope),
            "obligation_satisfied": False,
            "dispatcher_block": True,
        }

    def enforce(self, enforcement_ref: str) -> tuple["Arbitration", dict[str, Any]]:
        if self.state is not ArbitrationState.ENFORCEMENT_PENDING or len(enforcement_ref) != 64:
            raise ArbitrationError("Arbitration enforcement requires pending Decision and canonical proof")
        updated = replace(
            self,
            state=ArbitrationState.ENFORCED,
            version=self.version + 1,
            enforcement_ref=enforcement_ref,
        )
        return updated, {
            "schema": "ARBITRATION_ENFORCED_V1",
            "arbitration_id": self.arbitration_id,
            "generation": self.generation,
            "enforcement_ref": enforcement_ref,
            "binding_scope": list(self.binding_scope),
            "obligation_satisfied": True,
            "dispatcher_block": False,
        }

    def fail(self, reason: str) -> tuple["Arbitration", dict[str, Any]]:
        if self.state is ArbitrationState.ENFORCED:
            raise ArbitrationError("enforced Arbitration cannot fail")
        updated = replace(self, state=ArbitrationState.FAILED, version=self.version + 1)
        return updated, {
            "schema": "ARBITRATION_FAILED_V1",
            "arbitration_id": self.arbitration_id,
            "generation": self.generation,
            "reason": reason,
            "obligation_satisfied": False,
        }

    def appeal(
        self, authority_id: str, evidence_refs: tuple[str, ...], *, now: str
    ) -> tuple["Arbitration", dict[str, Any]]:
        if self.state not in {ArbitrationState.ENFORCED, ArbitrationState.FAILED, ArbitrationState.APPEALED}:
            raise ArbitrationError("Arbitration is not appealable in current state")
        if authority_id not in self.appeal_authorities:
            raise ArbitrationError("actor lacks Appeal authority")
        validate_timestamp(now)
        if dt.datetime.fromisoformat(now.replace("Z", "+00:00")) >= dt.datetime.fromisoformat(
            self.appeal_deadline.replace("Z", "+00:00")
        ):
            raise ArbitrationError("Appeal deadline passed")
        if self.appeal_generation >= self.max_appeals:
            raise ArbitrationError("maximum Appeal generation reached")
        if not evidence_refs or any(len(item) != 64 for item in evidence_refs):
            raise ArbitrationError("Appeal requires canonical new evidence")
        previously_seen = set(self.appeal_evidence_refs) | set(self.decision_evidence_refs)
        if not set(evidence_refs).isdisjoint(previously_seen):
            raise ArbitrationError("same Evidence cannot loop Appeals")
        generation = self.appeal_generation + 1
        updated = replace(
            self,
            state=ArbitrationState.APPEALED,
            version=self.version + 1,
            generation=self.generation + 1,
            appeal_generation=generation,
            appeal_evidence_refs=self.appeal_evidence_refs + tuple(sorted(evidence_refs)),
        )
        return updated, {
            "schema": "ARBITRATION_APPEALED_V1",
            "arbitration_id": self.arbitration_id,
            "appeal_generation": generation,
            "new_protocol_generation": updated.generation,
            "authority_id": authority_id,
            "evidence_refs": sorted(evidence_refs),
        }
