from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.leases import LeaseManager
from sitina.orchestrator.policy import AgentOwnershipRegistry, ExecutionPlan, TASK_TYPES, WorkflowPolicyEngine
from sitina.orchestrator.team import AgentCapabilityRegistry
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import file_sha256, iso_now, new_id, read_json, sha256_text, stable_json, write_json


EnvelopeStatus = Literal["ok", "blocked", "failed", "needs_approval", "skipped"]


class AgentOutputEnvelope(StrictModel):
    schema_version: str
    run_id: str
    agent_id: str
    task_id: str
    task_type: str
    status: EnvelopeStatus
    decision: dict[str, Any]
    artifacts: list[str] = Field(default_factory=list)
    handoff: dict[str, Any] = Field(default_factory=dict)
    audit: dict[str, Any] = Field(default_factory=dict)
    next_recommended_agents: list[str] = Field(default_factory=list)
    blocked_reason: str | None = None
    failure_reason: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def fail_closed_status_reason(self) -> "AgentOutputEnvelope":
        if str(self.schema_version).split(".", 1)[0] != "1":
            raise ValueError("envelope schema_version major must be 1")
        for field_name in ("run_id", "agent_id", "task_id", "task_type"):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.task_type not in TASK_TYPES:
            raise ValueError(f"unknown task_type: {self.task_type}")
        if self.status == "blocked" and not self.blocked_reason:
            raise ValueError("blocked envelope requires blocked_reason")
        if self.status == "failed" and not self.failure_reason:
            raise ValueError("failed envelope requires failure_reason")
        return self


class HandoffContract(StrictModel):
    schema_version: str = "1.0"
    handoff_id: str
    run_id: str
    task_id: str
    task_type: str
    from_agent: str
    to_agent: str
    reason: str
    required_inputs: list[str]
    provided_artifacts: list[str]
    gate_requirements: list[str]
    input_refs: list[str] = Field(default_factory=list)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    required_gates: list[str] = Field(default_factory=list)
    ownership_constraints: list[str] = Field(default_factory=list)
    scope_lease_ids: list[str] = Field(default_factory=list)
    side_effect_descriptor_ids: list[str] = Field(default_factory=list)
    status: Literal["ok", "pending", "accepted", "rejected", "blocked"] = "ok"
    acceptance_status: Literal["pending", "accepted", "rejected", "blocked"] = "pending"
    accepted_by: str | None = None
    rejected_by: str | None = None
    reviewed_at: str | None = None
    rejected_reason: str | None = None
    blocked_reason: str | None = None
    created_at: str

    @model_validator(mode="after")
    def validate_contract(self) -> "HandoffContract":
        if str(self.schema_version).split(".", 1)[0] != "1":
            raise ValueError("handoff schema_version major must be 1")
        for field_name in ("handoff_id", "run_id", "task_id", "task_type", "from_agent", "to_agent", "reason"):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.task_type not in TASK_TYPES:
            raise ValueError(f"unknown task_type: {self.task_type}")
        if self.status == "blocked" and not self.blocked_reason:
            raise ValueError("blocked handoff requires blocked_reason")
        if self.status == "rejected" and not self.rejected_reason:
            raise ValueError("rejected handoff requires rejected_reason")
        return self


class EnvelopeFactory:
    @staticmethod
    def wrap_agent_output(
        *,
        run_id: str,
        agent_id: str,
        task_id: str,
        task_type: str,
        payload: dict[str, Any],
        artifacts: list[str] | None = None,
        handoff: dict[str, Any] | None = None,
        status: EnvelopeStatus | None = None,
        blocked_reason: str | None = None,
        failure_reason: str | None = None,
    ) -> AgentOutputEnvelope:
        decision = {"agent_decision": payload.get("decision"), "payload_hash": sha256_text(stable_json(payload))}
        envelope_status: EnvelopeStatus = status or ("blocked" if payload.get("agent_status") == "cannot_complete" else "ok")
        derived_blocked_reason = blocked_reason
        if envelope_status == "blocked" and not derived_blocked_reason:
            extensions = payload.get("extensions") if isinstance(payload.get("extensions"), dict) else {}
            derived_blocked_reason = str(
                payload.get("blocked_reason")
                or extensions.get("blocked_reason")
                or extensions.get("reason")
                or f"{agent_id} reported agent_status=cannot_complete"
            )
        next_agents = payload.get("next_agents") or ([payload["next_agent"]] if payload.get("next_agent") else [])
        evidence = payload.get("evidence", [])
        return AgentOutputEnvelope(
            schema_version="1.0",
            run_id=run_id,
            agent_id=agent_id,
            task_id=task_id,
            task_type=task_type,
            status=envelope_status,
            decision=decision,
            artifacts=artifacts or [],
            handoff=handoff or {},
            audit={"payload_hash": sha256_text(stable_json(payload))},
            next_recommended_agents=list(next_agents),
            blocked_reason=derived_blocked_reason,
            failure_reason=failure_reason,
            evidence=evidence if isinstance(evidence, list) else [],
        )

    @staticmethod
    def skipped_envelope(*, run_id: str, agent_id: str, task_id: str, task_type: str, reason: str) -> AgentOutputEnvelope:
        return AgentOutputEnvelope(
            schema_version="1.0",
            run_id=run_id,
            agent_id=agent_id,
            task_id=task_id,
            task_type=task_type,
            status="skipped",
            decision={"skip_reason": reason},
            artifacts=[],
            handoff={},
            audit={},
            next_recommended_agents=[],
            blocked_reason=None,
            failure_reason=None,
            evidence=[],
        )


class HandoffManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "state" / "handoffs.json"
        self.ownership = AgentOwnershipRegistry(home)
        self.policy = WorkflowPolicyEngine(home, self.store)
        self.capabilities = AgentCapabilityRegistry(home)

    def create_handoff(
        self,
        *,
        run_id: str,
        task_id: str,
        task_type: str,
        from_agent: str,
        to_agent: str,
        reason: str,
        required_inputs: list[str] | None = None,
        provided_artifacts: list[str] | None = None,
        gate_requirements: list[str] | None = None,
        input_refs: list[str] | None = None,
        artifact_hashes: dict[str, str] | None = None,
        ownership_constraints: list[str] | None = None,
        scope_lease_ids: list[str] | None = None,
        side_effect_descriptor_ids: list[str] | None = None,
        mutation_intent: bool = False,
        execution_plan: ExecutionPlan | None = None,
        completed_agents: set[str] | None = None,
    ) -> HandoffContract:
        final_inputs = input_refs if input_refs is not None else (required_inputs or [])
        final_gates = gate_requirements or []
        final_artifacts = provided_artifacts or []
        final_hashes = artifact_hashes or self._artifact_hashes(final_artifacts)
        final_constraints = ownership_constraints or self._ownership_constraints(to_agent)
        final_leases = scope_lease_ids or []
        final_descriptors = side_effect_descriptor_ids or []
        blocked_reason = self._blocked_reason(
            task_type=task_type,
            from_agent=from_agent,
            to_agent=to_agent,
            required_inputs=final_inputs,
            provided_artifacts=final_artifacts,
            artifact_hashes=final_hashes,
            gate_requirements=final_gates,
            scope_lease_ids=final_leases,
            mutation_intent=mutation_intent,
            execution_plan=execution_plan,
            completed_agents=completed_agents or set(),
        )
        contract = HandoffContract(
            handoff_id="handoff_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            from_agent=from_agent,
            to_agent=to_agent,
            reason=reason,
            required_inputs=final_inputs,
            provided_artifacts=final_artifacts,
            gate_requirements=final_gates,
            input_refs=final_inputs,
            artifact_hashes=final_hashes,
            required_gates=final_gates,
            ownership_constraints=final_constraints,
            scope_lease_ids=final_leases,
            side_effect_descriptor_ids=final_descriptors,
            status="blocked" if blocked_reason else "ok",
            acceptance_status="blocked" if blocked_reason else "pending",
            blocked_reason=blocked_reason,
            created_at=iso_now(),
        )
        self.record_handoff(contract)
        return contract

    def record_handoff(self, contract: HandoffContract) -> None:
        payload = contract.model_dump()
        self._upsert(contract)
        self.store.record_event("agent_handoff", payload, run_id=contract.run_id, trace_id=f"{contract.run_id}:handoff:{contract.handoff_id}")
        self.store.record_audit(
            "agent_handoff",
            payload,
            run_id=contract.run_id,
            trace_id=f"{contract.run_id}:handoff:{contract.handoff_id}",
            agent=contract.from_agent,
            exit_status=contract.status,
            output_hash=sha256_text(stable_json(payload)),
        )
        RunLedger(self.home, self.store).record(
            "agent_handoff",
            run_id=contract.run_id,
            task_id=contract.task_id,
            task_type=contract.task_type,
            agent_id=contract.to_agent,
            status="ok" if contract.status == "ok" else "blocked",
            reason=contract.blocked_reason or contract.reason,
            payload=payload,
        )

    def accept_handoff(self, handoff_id: str, *, reviewer: str, reason: str = "handoff accepted") -> HandoffContract:
        contract = self._require(handoff_id)
        if contract.status == "blocked":
            return contract
        updated = contract.model_copy(
            update={
                "status": "accepted",
                "acceptance_status": "accepted",
                "accepted_by": reviewer,
                "reviewed_at": iso_now(),
                "blocked_reason": None,
            }
        )
        self._upsert(updated)
        self._record_review("handoff_accepted", updated, reviewer=reviewer, status="ok", reason=reason)
        return updated

    def reject_handoff(self, handoff_id: str, *, reviewer: str, reason: str) -> HandoffContract:
        contract = self._require(handoff_id)
        updated = contract.model_copy(
            update={
                "status": "rejected",
                "acceptance_status": "rejected",
                "rejected_by": reviewer,
                "reviewed_at": iso_now(),
                "rejected_reason": reason,
                "blocked_reason": reason,
            }
        )
        self._upsert(updated)
        self._record_review("handoff_rejected", updated, reviewer=reviewer, status="blocked", reason=reason)
        try:
            from sitina.orchestrator.arbitration import ArbitrationManager

            ArbitrationManager(self.home, self.store).arbitrate(
                run_id=updated.run_id,
                task_id=updated.task_id,
                task_type=updated.task_type,
                conflict_type="scope_conflict",
                participants=[updated.from_agent, updated.to_agent, reviewer],
                resources=[updated.handoff_id, *updated.input_refs, *updated.provided_artifacts],
                claims=[reason],
                runner=None,
                reason="handoff rejected; independent arbitration required",
            )
        except Exception:
            # Rejection itself must remain persisted even if follow-up arbitration fails.
            pass
        return updated

    def handoffs(self, *, run_id: str | None = None) -> list[HandoffContract]:
        items = [HandoffContract.model_validate(item) for item in (read_json(self.path, default={}) or {}).get("handoffs", []) if isinstance(item, dict)]
        if run_id:
            items = [item for item in items if item.run_id == run_id]
        return items

    def get_handoff(self, handoff_id: str) -> HandoffContract | None:
        for contract in self.handoffs():
            if contract.handoff_id == handoff_id:
                return contract
        return None

    def record_skip(self, *, run_id: str, task_id: str, task_type: str, agent_id: str, reason: str) -> AgentOutputEnvelope:
        envelope = EnvelopeFactory.skipped_envelope(run_id=run_id, agent_id=agent_id, task_id=task_id, task_type=task_type, reason=reason)
        payload = envelope.model_dump()
        self.store.record_event("agent_skipped", payload, run_id=run_id, trace_id=f"{run_id}:{agent_id}")
        self.store.record_audit("agent_skipped", payload, run_id=run_id, trace_id=f"{run_id}:{agent_id}", agent=agent_id, exit_status="skipped")
        RunLedger(self.home, self.store).record(
            "agent_skipped",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent_id,
            status="skipped",
            reason=reason,
            payload=payload,
        )
        return envelope

    def record_envelope(self, envelope: AgentOutputEnvelope) -> None:
        payload = envelope.model_dump()
        self.store.record_event("agent_envelope", payload, run_id=envelope.run_id, trace_id=f"{envelope.run_id}:{envelope.agent_id}")
        self.store.record_audit(
            "agent_envelope",
            payload,
            run_id=envelope.run_id,
            trace_id=f"{envelope.run_id}:{envelope.agent_id}",
            agent=envelope.agent_id,
            exit_status=envelope.status,
            output_hash=sha256_text(stable_json(payload)),
        )

    def _record_review(self, event_type: str, contract: HandoffContract, *, reviewer: str, status: Literal["ok", "blocked"], reason: str) -> None:
        payload = contract.model_dump() | {"reviewer": reviewer}
        self.store.record_event(event_type, payload, run_id=contract.run_id, trace_id=f"{contract.run_id}:handoff:{contract.handoff_id}:{event_type}")
        self.store.record_audit(event_type, payload, run_id=contract.run_id, trace_id=f"{contract.run_id}:handoff:{contract.handoff_id}:{event_type}", agent=reviewer, exit_status=status, output_hash=sha256_text(stable_json(payload)))
        RunLedger(self.home, self.store).record(
            event_type,
            run_id=contract.run_id,
            task_id=contract.task_id,
            task_type=contract.task_type,
            agent_id=reviewer,
            status=status,
            reason=reason,
            payload=payload,
        )

    def _upsert(self, contract: HandoffContract) -> None:
        state = read_json(self.path, default={}) or {}
        handoffs = [item for item in state.get("handoffs", []) if item.get("handoff_id") != contract.handoff_id]
        handoffs.append(contract.model_dump())
        state["handoffs"] = handoffs
        write_json(self.path, state)

    def _require(self, handoff_id: str) -> HandoffContract:
        contract = self.get_handoff(handoff_id)
        if not contract:
            raise ValueError(f"handoff not found: {handoff_id}")
        return contract

    def _blocked_reason(
        self,
        *,
        task_type: str,
        from_agent: str,
        to_agent: str,
        required_inputs: list[str],
        provided_artifacts: list[str],
        artifact_hashes: dict[str, str],
        gate_requirements: list[str],
        scope_lease_ids: list[str],
        mutation_intent: bool,
        execution_plan: ExecutionPlan | None,
        completed_agents: set[str],
    ) -> str | None:
        if task_type not in TASK_TYPES:
            return f"handoff task_type unknown: {task_type}"
        if to_agent not in self.ownership.ids:
            return f"handoff target agent/module unknown: {to_agent}"
        hash_error = self._artifact_hash_error(provided_artifacts, artifact_hashes)
        if hash_error:
            return hash_error
        policy = self.policy.task_policies.get(task_type, {})
        if to_agent in policy.get("forbidden_agents", []):
            return f"handoff target forbidden for task_type {task_type}: {to_agent}"
        if not self.ownership.can_handoff(from_agent, to_agent):
            return f"ownership forbids handoff {from_agent}->{to_agent}"
        if execution_plan and to_agent == "summary":
            mandatory_agents = [item for item in execution_plan.mandatory_gates if item in self.ownership.ids and item not in {"summary", "memory"}]
            missing = sorted(set(mandatory_agents) - completed_agents)
            if missing:
                return f"handoff to summary would bypass mandatory gate(s): {', '.join(missing)}"
        if from_agent != "initial" and not required_inputs:
            return "handoff missing input_refs"
        capability = self.capabilities.entries.get(to_agent)
        if capability and task_type not in capability.supported_task_types:
            return f"handoff target lacks task_type capability: {to_agent}:{task_type}"
        required_capability_error = self._required_gate_capability_error(to_agent, gate_requirements)
        if required_capability_error:
            return required_capability_error
        if self._needs_lease(to_agent, gate_requirements, mutation_intent) and not scope_lease_ids:
            return "mutation handoff requires scope lease"
        for lease_id in scope_lease_ids:
            ok, reason = LeaseManager(self.home, self.store).validate_lease(lease_id, holder_agent=to_agent)
            if not ok:
                return f"handoff lease invalid: {reason}"
        return None

    def _artifact_hashes(self, artifacts: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for ref in artifacts:
            if ref.startswith("sha256:"):
                out[ref] = ref
                continue
            path = Path(ref)
            digest = file_sha256(path) if path.is_file() else None
            if digest:
                out[ref] = digest
        return out

    def _artifact_hash_error(self, artifacts: list[str], hashes: dict[str, str]) -> str | None:
        for ref in artifacts:
            if ref.startswith("sha256:"):
                expected = hashes.get(ref)
                if expected and expected != ref:
                    return f"handoff artifact hash mismatch for {ref}"
                continue
            path = Path(ref)
            actual = file_sha256(path) if path.is_file() else None
            expected = hashes.get(ref)
            if expected and actual and expected != actual:
                return f"handoff artifact hash mismatch for {ref}"
        return None

    def _ownership_constraints(self, to_agent: str) -> list[str]:
        entry = self.ownership.entry(to_agent)
        if not entry:
            return []
        return [f"owns:{item}" for item in entry.owns] + [f"not_owns:{item}" for item in entry.not_owns]

    def _required_gate_capability_error(self, to_agent: str, gates: list[str]) -> str | None:
        capability = self.capabilities.entries.get(to_agent)
        if not capability:
            return None
        caps = set(capability.capabilities)
        gate_map = {
            "tester": "unit_testing",
            "reviewer": "code_review",
            "multi_reviewer_merge": "code_review",
            "approval": "policy_decision",
            "patch_apply": "git_patch_apply",
            "patch_hash_verify": "patch_hash_verify",
            "filesystem_readonly": "filesystem_readonly",
        }
        for gate in gates:
            required = gate_map.get(gate)
            if required and required not in caps and gate != "approval":
                return f"handoff target lacks capability for gate {gate}: {to_agent}"
        return None

    def _needs_lease(self, to_agent: str, gates: list[str], mutation_intent: bool) -> bool:
        if mutation_intent:
            return True
        if any(gate in {"patch_apply", "worktree", "approved_scope"} for gate in gates) and to_agent in {"coder", "git_worktree_manager", "maintenance_ops"}:
            return True
        capability = self.capabilities.entries.get(to_agent)
        return bool(capability and capability.can_execute_side_effect and any(gate in {"patch_apply", "approval", "worktree"} for gate in gates))
