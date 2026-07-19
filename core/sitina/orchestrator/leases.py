from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, read_json, sha256_text, stable_json, write_json


LeaseResourceType = Literal["file", "directory", "artifact", "patch", "memory_candidate", "approval_scope", "blackboard_doc", "external_tool"]
LeaseMode = Literal["read", "write", "review", "apply", "approve"]
LeaseStatus = Literal["requested", "granted", "denied", "released", "conflict", "expired"]


class ResourceLease(StrictModel):
    schema_version: str = "1.0"
    lease_id: str
    run_id: str
    task_id: str
    resource_type: LeaseResourceType
    resource_id: str
    holder_agent: str
    mode: LeaseMode
    scope_hash: str
    status: LeaseStatus
    expires_at: str
    created_at: str


class ArbitrationNode(StrictModel):
    schema_version: str = "1.0"
    arbitration_id: str
    run_id: str
    task_id: str
    task_type: str = "code_change"
    conflict_type: Literal["lease_conflict", "proposal_conflict", "reviewer_conflict", "scope_conflict"]
    participants: list[str]
    resources: list[str]
    claims: list[str] = Field(default_factory=list)
    decision: Literal["grant_agent_a", "grant_agent_b", "merge", "block", "ask_user"] | None = None
    reason: str
    created_at: str


class LeaseManager:
    EXCLUSIVE_MODES = {"write", "apply", "approve"}

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "state" / "leases.json"
        self.ledger = RunLedger(home, self.store)
        self.blackboard = Blackboard(home, self.store)

    def request_lease(
        self,
        *,
        run_id: str,
        task_id: str,
        resource_type: LeaseResourceType,
        resource_id: str,
        holder_agent: str,
        mode: LeaseMode,
        scope_hash: str | None = None,
        ttl_seconds: int = 3600,
    ) -> ResourceLease:
        lease = ResourceLease(
            lease_id="lease_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            resource_type=resource_type,
            resource_id=resource_id,
            holder_agent=holder_agent,
            mode=mode,
            scope_hash=scope_hash or sha256_text(stable_json({"resource_type": resource_type, "resource_id": resource_id, "holder_agent": holder_agent, "mode": mode})),
            status="requested",
            expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z"),
            created_at=iso_now(),
        )
        self._record("lease_requested", lease, "lease requested", "pending")
        conflict = self._active_conflict(lease)
        if conflict:
            lease = lease.model_copy(update={"status": "conflict"})
            self._upsert_lease(lease)
            self._record("lease_conflict_detected", lease, f"lease conflicts with {conflict.lease_id}", "blocked", related=[conflict.lease_id])
            self.create_arbitration(
                run_id=run_id,
                task_id=task_id,
                conflict_type="lease_conflict",
                participants=sorted({holder_agent, conflict.holder_agent}),
                resources=[resource_id],
                claims=[lease.lease_id, conflict.lease_id],
                reason=f"exclusive lease conflict on {resource_type}:{resource_id}",
            )
            return lease
        lease = lease.model_copy(update={"status": "granted"})
        self._upsert_lease(lease)
        self._record("lease_granted", lease, "lease granted", "ok")
        return lease

    def release(self, lease_id: str, *, run_id: str | None = None, reason: str = "lease released") -> ResourceLease | None:
        lease = self.get_lease(lease_id)
        if not lease:
            return None
        updated = lease.model_copy(update={"status": "released"})
        self._upsert_lease(updated)
        self._record("lease_released", updated, reason, "ok")
        return updated

    def create_arbitration(
        self,
        *,
        run_id: str,
        task_id: str,
        task_type: str = "code_change",
        conflict_type: Literal["lease_conflict", "proposal_conflict", "reviewer_conflict", "scope_conflict"],
        participants: list[str],
        resources: list[str],
        claims: list[str] | None = None,
        reason: str,
    ) -> ArbitrationNode:
        node = ArbitrationNode(
            arbitration_id="arb_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            conflict_type=conflict_type,
            participants=participants,
            resources=resources,
            claims=claims or [],
            decision=None,
            reason=reason,
            created_at=iso_now(),
        )
        state = self._state()
        state.setdefault("arbitrations", []).append(node.model_dump())
        write_json(self.path, state)
        self.ledger.record("arbitration_node_created", run_id=run_id, task_id=task_id, task_type=task_type, agent_id="arbiter", status="blocked", reason=reason, payload=node.model_dump())
        self.store.record_audit("arbitration_node_created", node.model_dump(), run_id=run_id, trace_id=f"{run_id}:arbitration:{node.arbitration_id}", exit_status="blocked")
        self.blackboard.record_document(run_id=run_id, task_id=task_id, author_agent="controller", doc_type="arbitration_note", content_summary=reason, related_docs=claims or [])
        return node

    def decide_arbitration(self, arbitration_id: str, *, decision: Literal["grant_agent_a", "grant_agent_b", "merge", "block", "ask_user"], reason: str) -> ArbitrationNode | None:
        state = self._state()
        nodes = []
        updated: ArbitrationNode | None = None
        for raw in state.get("arbitrations", []):
            node = ArbitrationNode.model_validate(raw)
            if node.arbitration_id == arbitration_id:
                node = node.model_copy(update={"decision": decision, "reason": reason})
                updated = node
            nodes.append(node.model_dump())
        state["arbitrations"] = nodes
        write_json(self.path, state)
        if updated:
            self.ledger.record("arbitration_decision", run_id=updated.run_id, task_id=updated.task_id, task_type=updated.task_type, agent_id="arbiter", status="blocked" if decision in {"block", "ask_user"} else "ok", reason=reason, payload=updated.model_dump())
            self.store.record_audit("arbitration_decision", updated.model_dump(), run_id=updated.run_id, trace_id=f"{updated.run_id}:arbitration:{updated.arbitration_id}", agent="arbiter", exit_status=decision)
        return updated

    def validate_lease(self, lease_id: str, *, holder_agent: str, mode: LeaseMode | None = None) -> tuple[bool, str]:
        lease = self.get_lease(lease_id)
        if not lease:
            return False, "lease not found"
        if lease.holder_agent != holder_agent:
            return False, "lease holder mismatch"
        if mode and lease.mode != mode:
            return False, "lease mode mismatch"
        if lease.status != "granted":
            return False, f"lease is not granted: {lease.status}"
        if self._expired(lease):
            expired = lease.model_copy(update={"status": "expired"})
            self._upsert_lease(expired)
            return False, "lease expired"
        return True, "lease valid"

    def record_holder_blocked(self, lease_id: str, *, holder_agent: str, run_id: str, task_id: str, reason: str) -> None:
        lease = self.get_lease(lease_id)
        payload = {
            "lease_id": lease_id,
            "holder_agent": holder_agent,
            "task_id": task_id,
            "reason": reason,
            "lease": lease.model_dump() if lease else None,
        }
        self.ledger.record(
            "lease_holder_blocked",
            run_id=run_id,
            task_id=task_id,
            task_type=lease.task_type if hasattr(lease, "task_type") else "code_change",
            agent_id=holder_agent,
            status="blocked",
            reason=reason,
            payload=payload,
        )
        self.store.record_audit("lease_holder_blocked", payload, run_id=run_id, trace_id=f"{run_id}:lease:{lease_id}:blocked", agent=holder_agent, exit_status="blocked")
        self.blackboard.record_document(run_id=run_id, task_id=task_id, author_agent=holder_agent, doc_type="lease_note", content_summary=f"lease_holder_blocked: {reason}")

    def get_lease(self, lease_id: str) -> ResourceLease | None:
        for item in self.leases():
            if item.lease_id == lease_id:
                return item
        return None

    def leases(self, *, run_id: str | None = None) -> list[ResourceLease]:
        leases = [ResourceLease.model_validate(item) for item in self._state().get("leases", []) if isinstance(item, dict)]
        if run_id:
            leases = [item for item in leases if item.run_id == run_id]
        return leases

    def arbitrations(self, *, run_id: str | None = None) -> list[ArbitrationNode]:
        nodes = [ArbitrationNode.model_validate(item) for item in self._state().get("arbitrations", []) if isinstance(item, dict)]
        if run_id:
            nodes = [item for item in nodes if item.run_id == run_id]
        return nodes

    def _active_conflict(self, lease: ResourceLease) -> ResourceLease | None:
        for existing in self.leases():
            if existing.resource_type != lease.resource_type or existing.resource_id != lease.resource_id:
                continue
            if existing.status != "granted" or self._expired(existing):
                continue
            if lease.mode in {"read", "review"} and existing.mode in {"read", "review"}:
                continue
            if lease.mode in self.EXCLUSIVE_MODES or existing.mode in self.EXCLUSIVE_MODES:
                return existing
        return None

    def _expired(self, lease: ResourceLease) -> bool:
        try:
            expires = dt.datetime.fromisoformat(lease.expires_at.replace("Z", "+00:00"))
            return expires <= dt.datetime.now(dt.timezone.utc)
        except ValueError:
            return True

    def _upsert_lease(self, lease: ResourceLease) -> None:
        state = self._state()
        leases = [item for item in state.get("leases", []) if item.get("lease_id") != lease.lease_id]
        leases.append(lease.model_dump())
        state["leases"] = leases
        write_json(self.path, state)

    def _record(self, event_type: str, lease: ResourceLease, reason: str, status: str, *, related: list[str] | None = None) -> None:
        self.ledger.record(
            event_type,
            run_id=lease.run_id,
            task_id=lease.task_id,
            task_type="code_change",
            agent_id=lease.holder_agent,
            status="blocked" if status == "blocked" else ("pending" if status == "pending" else "ok"),
            reason=reason,
            related_event_ids=related or [],
            payload=lease.model_dump(),
        )
        self.store.record_audit(event_type, lease.model_dump(), run_id=lease.run_id, trace_id=f"{lease.run_id}:lease:{lease.lease_id}", agent=lease.holder_agent, exit_status=status)
        if event_type in {"lease_granted", "lease_conflict_detected", "lease_denied"}:
            self.blackboard.record_document(run_id=lease.run_id, task_id=lease.task_id, author_agent=lease.holder_agent, doc_type="lease_note", content_summary=f"{event_type}: {lease.resource_type}:{lease.resource_id} {lease.mode} {lease.status}")

    def _state(self) -> dict[str, Any]:
        return read_json(self.path, default={}) or {}
