from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, read_json, redact_text, sha256_text, stable_json, write_json


EffectType = Literal["file_write", "git_apply", "maintenance", "memory_accept", "memory_reject", "approval_mutation", "external_command"]
DescriptorStatus = Literal["proposed", "reviewed", "approved", "verified", "executed", "blocked"]


class SideEffectRequest(StrictModel):
    schema_version: str = "1.0"
    descriptor_id: str
    run_id: str
    task_id: str
    requested_by_agent: str
    effect_type: str
    target_refs: list[str] = Field(default_factory=list)
    scope_hash: str
    required_gates: list[str] = Field(default_factory=list)
    approval_id: str | None = None
    reviewer_decision_id: str | None = None
    verifier_id: str | None = None
    lease_id: str | None = None
    status: DescriptorStatus
    reason: str | None = None
    created_at: str


class SideEffectManager:
    KNOWN_EFFECTS = {"file_write", "git_apply", "maintenance", "memory_accept", "memory_reject", "approval_mutation", "external_command"}
    REVIEW_REQUIRED = {"file_write", "git_apply", "external_command"}
    APPROVAL_REQUIRED = {"file_write", "git_apply", "maintenance", "memory_accept", "approval_mutation", "external_command"}
    VERIFY_REQUIRED = {"file_write", "git_apply", "external_command"}

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "state" / "side_effects.json"
        self.ledger = RunLedger(home, self.store)

    def propose(
        self,
        *,
        run_id: str,
        task_id: str,
        requested_by_agent: str,
        effect_type: str,
        target_refs: list[str],
        scope_hash: str,
        required_gates: list[str] | None = None,
        lease_id: str | None = None,
    ) -> SideEffectRequest:
        clean_targets = [redact_text(str(item))[:500] for item in target_refs]
        status: DescriptorStatus = "proposed"
        reason = None
        if effect_type not in self.KNOWN_EFFECTS:
            status = "blocked"
            reason = f"unknown side effect type: {effect_type}"
        descriptor = SideEffectRequest(
            descriptor_id="se_desc_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            requested_by_agent=requested_by_agent,
            effect_type=effect_type,
            target_refs=clean_targets,
            scope_hash=scope_hash,
            required_gates=required_gates or self._required_gates(effect_type),
            lease_id=lease_id,
            status=status,
            reason=reason,
            created_at=iso_now(),
        )
        self._upsert(descriptor)
        self._record("side_effect_blocked" if status == "blocked" else "side_effect_descriptor_created", descriptor, reason or "side effect descriptor proposed")
        return descriptor

    def mark_reviewed(self, descriptor_id: str, *, reviewer_decision_id: str, decision: str = "accept", reason: str = "reviewed") -> SideEffectRequest:
        descriptor = self._require(descriptor_id)
        if decision != "accept":
            descriptor = descriptor.model_copy(update={"status": "blocked", "reviewer_decision_id": reviewer_decision_id, "reason": reason})
            self._upsert(descriptor)
            self._record("side_effect_blocked", descriptor, reason)
            return descriptor
        descriptor = descriptor.model_copy(update={"status": "reviewed", "reviewer_decision_id": reviewer_decision_id, "reason": reason})
        self._upsert(descriptor)
        self._record("side_effect_reviewed", descriptor, reason)
        return descriptor

    def approve(self, descriptor_id: str, *, approval_id: str, reason: str = "approved") -> SideEffectRequest:
        descriptor = self._require(descriptor_id)
        descriptor = descriptor.model_copy(update={"status": "approved", "approval_id": approval_id, "reason": reason})
        self._upsert(descriptor)
        self._record("side_effect_approved", descriptor, reason)
        return descriptor

    def verify(
        self,
        descriptor_id: str,
        *,
        verifier_id: str,
        expected_scope_hash: str | None = None,
        actual_scope_hash: str | None = None,
        expected_patch_hash: str | None = None,
        actual_patch_hash: str | None = None,
        reason: str = "verified",
    ) -> SideEffectRequest:
        descriptor = self._require(descriptor_id)
        blocked_reason = None
        if expected_scope_hash and actual_scope_hash and expected_scope_hash != actual_scope_hash:
            blocked_reason = "scope_hash mismatch"
        if expected_patch_hash and actual_patch_hash and expected_patch_hash != actual_patch_hash:
            blocked_reason = "patch_hash mismatch"
        if blocked_reason:
            descriptor = descriptor.model_copy(update={"status": "blocked", "verifier_id": verifier_id, "reason": blocked_reason})
            self._upsert(descriptor)
            self._record("side_effect_blocked", descriptor, blocked_reason)
            return descriptor
        descriptor = descriptor.model_copy(update={"status": "verified", "verifier_id": verifier_id, "reason": reason})
        self._upsert(descriptor)
        self._record("side_effect_verified", descriptor, reason)
        return descriptor

    def execute(self, descriptor_id: str, *, reason: str = "executed") -> SideEffectRequest:
        descriptor = self._require(descriptor_id)
        blocked_reason = self._execution_blocker(descriptor)
        if blocked_reason:
            descriptor = descriptor.model_copy(update={"status": "blocked", "reason": blocked_reason})
            self._upsert(descriptor)
            self._record("side_effect_blocked", descriptor, blocked_reason)
            return descriptor
        descriptor = descriptor.model_copy(update={"status": "executed", "reason": reason})
        self._upsert(descriptor)
        self._record("side_effect_executed", descriptor, reason)
        return descriptor

    def descriptors(self, *, run_id: str | None = None) -> list[SideEffectRequest]:
        items = [SideEffectRequest.model_validate(item) for item in (read_json(self.path, default={}) or {}).get("descriptors", []) if isinstance(item, dict)]
        if run_id:
            items = [item for item in items if item.run_id == run_id]
        return items

    def _execution_blocker(self, descriptor: SideEffectRequest) -> str | None:
        if descriptor.effect_type not in self.KNOWN_EFFECTS:
            return f"unknown side effect type: {descriptor.effect_type}"
        if descriptor.effect_type in self.REVIEW_REQUIRED and not descriptor.reviewer_decision_id:
            return f"{descriptor.effect_type} requires reviewer decision before execution"
        if descriptor.effect_type in self.APPROVAL_REQUIRED and not descriptor.approval_id:
            return f"{descriptor.effect_type} requires approval before execution"
        if descriptor.effect_type in self.VERIFY_REQUIRED and not descriptor.verifier_id:
            return f"{descriptor.effect_type} requires verifier before execution"
        if descriptor.effect_type == "memory_accept" and descriptor.requested_by_agent in {"planner", "coder", "tester", "reviewer", "security", "critic"}:
            return "memory_accept cannot be proposal-triggered"
        if not descriptor.lease_id and descriptor.effect_type in {"file_write", "git_apply", "maintenance", "approval_mutation"}:
            return f"{descriptor.effect_type} requires granted lease binding"
        return None

    def _required_gates(self, effect_type: str) -> list[str]:
        if effect_type == "git_apply":
            return ["reviewer", "approval", "patch_hash_verify", "lease"]
        if effect_type == "file_write":
            return ["reviewer", "approval", "scope_verify", "lease"]
        if effect_type == "memory_accept":
            return ["memory_review", "approval"]
        if effect_type == "approval_mutation":
            return ["approval", "lease"]
        if effect_type == "maintenance":
            return ["approval", "audit", "lease"]
        if effect_type == "external_command":
            return ["reviewer", "approval", "verifier"]
        return []

    def _upsert(self, descriptor: SideEffectRequest) -> None:
        state = read_json(self.path, default={}) or {}
        descriptors = [item for item in state.get("descriptors", []) if item.get("descriptor_id") != descriptor.descriptor_id]
        descriptors.append(descriptor.model_dump())
        state["descriptors"] = descriptors
        write_json(self.path, state)

    def _require(self, descriptor_id: str) -> SideEffectRequest:
        for descriptor in self.descriptors():
            if descriptor.descriptor_id == descriptor_id:
                return descriptor
        raise ValueError(f"side effect descriptor not found: {descriptor_id}")

    def _record(self, event_type: str, descriptor: SideEffectRequest, reason: str) -> None:
        status = "blocked" if descriptor.status == "blocked" else ("pending" if descriptor.status == "proposed" else "ok")
        payload = descriptor.model_dump()
        self.ledger.record(
            event_type,
            run_id=descriptor.run_id,
            task_id=descriptor.task_id,
            task_type="code_change",
            agent_id=descriptor.requested_by_agent,
            status=status,
            reason=reason,
            payload=payload,
        )
        self.store.record_audit(
            event_type,
            payload,
            run_id=descriptor.run_id,
            trace_id=f"{descriptor.run_id}:side_effect:{descriptor.descriptor_id}",
            agent=descriptor.requested_by_agent,
            exit_status=descriptor.status,
            output_hash=sha256_text(stable_json(payload)),
        )
