from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash


@dataclass(frozen=True)
class SideEffectAuditReport:
    passed: bool
    logical_effect_count: int
    attempt_count: int
    invocation_count: int
    admitted_observation_count: int
    confirmed_success_count: int
    confirmed_failure_count: int
    policy_settled_unknown_count: int
    unresolved_unknown_count: int
    unexplained_in_flight: int
    unresolved_exposure: int
    destruction_gap_count: int
    permit_gap_count: int
    authorization_gap_count: int
    orphan_observation_count: int
    reconciliation_count: int
    compensation_count: int
    budget_event_count: int
    gaps: tuple[str, ...]


class SideEffectAudit:
    @staticmethod
    def build(events: Iterable[Mapping[str, object]]) -> SideEffectAuditReport:
        rows = [dict(event) for event in events]
        effects = {str(row["effect_id"]) for row in rows if row.get("schema") == "EFFECT_REQUESTED_V1" and row.get("effect_id")}
        attempts = [row for row in rows if row.get("schema") == "EFFECT_ATTEMPT_CLAIMED_V1"]
        invocations = [row for row in rows if row.get("schema") == "EFFECT_INVOCATION_STARTED_V1"]
        observations = [row for row in rows if row.get("schema") == "OBSERVATION_ADMITTED_V1"]
        outcomes = {str(row["effect_id"]): row for row in rows if row.get("schema") == "EFFECT_OUTCOME_ADVANCED_V1" and row.get("effect_id")}
        destructions = {str(row.get("quarantine_id")) for row in rows if row.get("schema") in {"CAS_QUARANTINE_DESTRUCTION_ATTESTATION_V1", "QUARANTINE_DESTROYED_V1"}}
        secret_positive = {str(row.get("quarantine_id")) for row in rows if row.get("schema") == "QUARANTINE_SECRET_POSITIVE_V1"}
        gaps: list[str] = []
        permit_gap = sum(not row.get("permit_id") for row in rows if row.get("schema") == "EFFECT_REQUESTED_V1")
        if permit_gap:
            gaps.append(f"PERMIT_GAP:{permit_gap}")
        authorization_gap = 0
        for attempt in attempts:
            if not attempt.get("task_fence") or not attempt.get("dispatch_fence"):
                gaps.append(f"ATTEMPT_FENCE_GAP:{attempt.get('effect_attempt_id')}")
                authorization_gap += 1
        for invocation in invocations:
            if not invocation.get("approval_id") or not invocation.get("budget_bundle_id"):
                gaps.append(f"INVOCATION_AUTHORIZATION_GAP:{invocation.get('effect_attempt_id')}")
                authorization_gap += 1
        attempt_ids = {str(row.get("effect_attempt_id")) for row in attempts}
        orphan_observation = sum(
            str(row.get("effect_id")) not in effects or str(row.get("effect_attempt_id")) not in attempt_ids
            for row in observations
        )
        if orphan_observation:
            gaps.append(f"ORPHAN_OBSERVATION:{orphan_observation}")
        unexplained = sum(effect_id not in outcomes for effect_id in effects)
        if unexplained:
            gaps.append(f"UNEXPLAINED_IN_FLIGHT:{unexplained}")
        unresolved_unknown = sum(row.get("outcome") == "OUTCOME_UNKNOWN" and row.get("settlement") != "SETTLED" for row in outcomes.values())
        unresolved_exposure = unresolved_unknown
        if unresolved_exposure:
            gaps.append(f"UNRESOLVED_EXPOSURE:{unresolved_exposure}")
        destruction_gap = len(secret_positive - destructions)
        if destruction_gap:
            gaps.append(f"DESTRUCTION_GAP:{destruction_gap}")
        for effect_id, outcome in outcomes.items():
            if outcome.get("basis") == "AUTHORITATIVE_REMOTE_OBSERVATION" and not any(str(row.get("effect_id")) == effect_id for row in observations):
                gaps.append(f"REMOTE_OUTCOME_WITHOUT_OBSERVATION:{effect_id}")
        reconciliations = [row for row in rows if str(row.get("schema", "")).startswith("RECONCILIATION_")]
        compensation = [row for row in rows if row.get("schema") in {"COMPENSATION_EFFECT_LINKED_V1", "COMPENSATION_OUTCOME_LINKED_V1"}]
        for row in reconciliations:
            if not row.get("effect_id"):
                gaps.append("RECONCILIATION_IDENTITY_GAP")
        for row in compensation:
            if not row.get("original_effect_id") or not row.get("compensation_effect_id"):
                gaps.append("COMPENSATION_LINK_GAP")
        budget_events = [row for row in rows if str(row.get("schema", "")).startswith("BUDGET_")]
        confirmed_success = sum(row.get("outcome") == "SUCCEEDED" and row.get("basis") == "AUTHORITATIVE_REMOTE_OBSERVATION" for row in outcomes.values())
        confirmed_failure = sum(row.get("outcome") == "FAILED_CONFIRMED" and row.get("basis") == "AUTHORITATIVE_REMOTE_OBSERVATION" for row in outcomes.values())
        policy_unknown = sum(row.get("outcome") == "OUTCOME_UNKNOWN" and row.get("settlement") == "SETTLED" and row.get("basis") == "POLICY_DISPOSITION" for row in outcomes.values())
        return SideEffectAuditReport(
            not gaps,
            len(effects),
            len(attempts),
            len(invocations),
            len(observations),
            confirmed_success,
            confirmed_failure,
            policy_unknown,
            unresolved_unknown,
            unexplained,
            unresolved_exposure,
            destruction_gap,
            permit_gap,
            authorization_gap,
            orphan_observation,
            len(reconciliations),
            len(compensation),
            len(budget_events),
            tuple(gaps),
        )


def rebuild_effect_projection(events: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Rebuild a disposable Effect/Observation view from canonical facts only."""
    effects: dict[str, dict[str, object]] = {}
    observations: dict[str, dict[str, object]] = {}
    attempts: dict[str, dict[str, object]] = {}
    for source in events:
        row = dict(source)
        fact = row.get("fact")
        if isinstance(fact, Mapping):
            row = dict(fact)
        schema = row.get("schema")
        effect_id = row.get("effect_id")
        if schema == "EFFECT_REQUESTED_V1" and effect_id:
            effects[str(effect_id)] = {"request_hash": row.get("request_hash"), "outcome": "NOT_SENT", "settlement": "OPEN"}
        elif schema == "EFFECT_ATTEMPT_CLAIMED_V1" and row.get("effect_attempt_id"):
            attempts[str(row["effect_attempt_id"])] = {"effect_id": effect_id, "disposition": "ACTIVE"}
        elif schema == "EFFECT_ATTEMPT_DISPOSITION_V1" and row.get("effect_attempt_id"):
            attempts.setdefault(str(row["effect_attempt_id"]), {"effect_id": effect_id})["disposition"] = row.get("disposition")
        elif schema == "OBSERVATION_ADMITTED_V1" and row.get("observation_id"):
            observations[str(row["observation_id"])] = {"effect_id": effect_id, "effect_attempt_id": row.get("effect_attempt_id"), "outcome": row.get("outcome")}
        elif schema == "EFFECT_OUTCOME_ADVANCED_V1" and effect_id:
            effects.setdefault(str(effect_id), {})
            effects[str(effect_id)].update({"outcome": row.get("outcome"), "settlement": row.get("settlement"), "basis": row.get("basis")})
    body = {"effects": effects, "attempts": attempts, "observations": observations}
    return {**body, "semantic_checksum": domain_hash("EFFECT_PROJECTION", canonical_json_bytes(body))}
