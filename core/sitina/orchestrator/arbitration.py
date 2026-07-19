from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from sitina.constants import SITINA_HOME
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.leases import ArbitrationNode, LeaseManager
from sitina.orchestrator.ledger import RunLedger
from sitina.runners.agent_runner import AgentRunner
from sitina.storage import SitinaStore
from sitina.utils import new_id, sha256_text, stable_json


class ArbitrationManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.leases = LeaseManager(home, self.store)
        self.ledger = RunLedger(home, self.store)
        self.blackboard = Blackboard(home, self.store)

    def arbitrate(
        self,
        *,
        run_id: str,
        task_id: str,
        task_type: str,
        conflict_type: Literal["lease_conflict", "proposal_conflict", "reviewer_conflict", "scope_conflict"],
        participants: list[str],
        resources: list[str],
        claims: list[str],
        context: dict[str, Any] | None = None,
        runner: AgentRunner | None = None,
        provider_mode: str = "mock",
        profile_overrides: dict[str, str] | None = None,
        reason: str | None = None,
        existing_node: ArbitrationNode | None = None,
    ) -> dict[str, Any]:
        node = existing_node or self.leases.create_arbitration(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            conflict_type=conflict_type,
            participants=participants,
            resources=resources,
            claims=claims,
            reason=reason or f"{conflict_type} requires independent arbitration",
        )
        decision = "block"
        resolution_reason = "arbiter unavailable; fail-closed"
        winning_agent = None
        if runner is not None:
            try:
                blackboard_context = self.blackboard.summary(run_id, max_items=10)
                policy_context = {
                    "task_type": task_type,
                    "fail_closed": True,
                    "blackboard_context": blackboard_context,
                    "conflict_context": context or {},
                }
                input_payload = {
                    "conflict_id": node.arbitration_id,
                    "conflict_type": conflict_type,
                    "participants": participants or ["unknown"],
                    "claims": claims or ["no claims supplied"],
                    "resources": resources or ["unknown"],
                    "policy_context": policy_context,
                }
                if blackboard_context:
                    input_payload["blackboard_context"] = blackboard_context
                input_hash = sha256_text(stable_json(input_payload))
                logical_call_id = "logical_call_" + new_id()
                self.ledger.record("agent_started", run_id=run_id, task_id=task_id, task_type=task_type, agent_id="arbiter", reason="arbiter started", payload={"input_hash": input_hash, "provider_mode": provider_mode, "input_payload": input_payload, "call_id": logical_call_id})
                result = runner.run_agent(
                    "arbiter",
                    input_payload,
                    provider_mode=provider_mode,
                    profile_override=(profile_overrides or {}).get("arbiter"),
                    run_id=run_id,
                    task_id=task_id,
                    task_type=task_type,
                    logical_call_id=logical_call_id,
                    audit_context={
                        "call_origin": "arbitration",
                        "role": "arbiter",
                        "arbitration_id": node.arbitration_id,
                        "call_id": logical_call_id,
                    },
                )
                output_hash = sha256_text(stable_json(result.payload))
                self.store.record_audit(
                    "agent_call",
                    {
                        "agent": "arbiter",
                        "provider_mode": result.provider_mode,
                        "profile_name": result.profile_name,
                        "model": result.model,
                        "provider_identity": result.provider_identity,
                        "provider_calls": result.provider_calls,
                        "fallback_used": result.fallback_used,
                        "arbitration_id": node.arbitration_id,
                        "call_id": logical_call_id,
                    },
                    run_id=run_id,
                    trace_id=f"{run_id}:arbitration:{node.arbitration_id}:arbiter",
                    agent="arbiter",
                    input_hash=input_hash,
                    output_hash=output_hash,
                    exit_status="ok",
                )
                self.ledger.record(
                    "agent_completed",
                    run_id=run_id,
                    task_id=task_id,
                    task_type=task_type,
                    agent_id="arbiter",
                    reason="arbiter completed",
                    payload={
                        "input_hash": input_hash,
                        "output_hash": output_hash,
                        "provider_mode": result.provider_mode,
                        "profile_name": result.profile_name,
                        "model": result.model,
                        "provider_identity": result.provider_identity,
                        "provider_calls": result.provider_calls,
                        "fallback_used": result.fallback_used,
                        "call_id": logical_call_id,
                    },
                )
                payload = result.payload
                if payload.get("decision") in {"grant_agent_a", "grant_agent_b", "merge", "block", "ask_user"}:
                    decision = str(payload["decision"])
                resolution_reason = str(payload.get("resolution_reason") or payload.get("decision") or resolution_reason)
                winning_agent = payload.get("winning_agent")
            except Exception as exc:  # noqa: BLE001
                if provider_mode == "live":
                    raise
                resolution_reason = f"arbiter failed fail-closed: {exc}"
        decided = self.leases.decide_arbitration(node.arbitration_id, decision=decision, reason=resolution_reason) or node
        payload = decided.model_dump() | {"winning_agent": winning_agent, "policy_hash": sha256_text(stable_json({"task_type": task_type, "conflict_type": conflict_type}))}
        self.blackboard.record_document(
            run_id=run_id,
            task_id=task_id,
            author_agent="arbiter",
            doc_type="arbitration_note",
            content_summary=f"{decision}: {resolution_reason}",
            related_docs=claims,
        )
        return payload

    def list(self, *, run_id: str | None = None) -> list[ArbitrationNode]:
        return self.leases.arbitrations(run_id=run_id)

    def show(self, arbitration_id: str) -> ArbitrationNode | None:
        for node in self.leases.arbitrations():
            if node.arbitration_id == arbitration_id:
                return node
        return None
