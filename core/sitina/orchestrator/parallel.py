from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, load_json_yaml, new_id, sha256_text, stable_json


ParallelMode = Literal["all_required", "any_success", "advisory"]


class ParallelGroup(StrictModel):
    schema_version: str = "1.0"
    parallel_group_id: str
    run_id: str
    task_type: str
    agents: list[str]
    mode: ParallelMode
    timeout_seconds: int
    merge_policy: str
    created_at: str

    @model_validator(mode="after")
    def validate_group(self) -> "ParallelGroup":
        if str(self.schema_version).split(".", 1)[0] != "1":
            raise ValueError("parallel group schema_version major must be 1")
        if self.timeout_seconds <= 0:
            raise ValueError("parallel timeout_seconds must be positive")
        if not self.agents:
            raise ValueError("parallel group requires at least one agent")
        return self


class ParallelMergeResult(StrictModel):
    schema_version: str = "1.0"
    parallel_group_id: str
    run_id: str
    task_type: str
    status: Literal["ok", "blocked", "warning"]
    merge_order: list[str]
    blocking_agents: list[str] = Field(default_factory=list)
    warning_agents: list[str] = Field(default_factory=list)
    reason: str
    results: list[dict[str, Any]]
    created_at: str


class ParallelCoordinator:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "config" / "parallel_policy.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}

    @property
    def policy(self) -> dict[str, Any]:
        return self.config.get("parallel_policy", {})

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["parallel_policy config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("parallel_policy schema_version major must be 1")
        policy = self.policy
        for key in ("allowed_agent_kinds", "forbidden_agents", "forbidden_operations", "default_timeout_seconds", "merge_order", "groups"):
            if key not in policy:
                errors.append(f"parallel_policy missing {key}")
        if int(policy.get("default_timeout_seconds", 0)) <= 0:
            errors.append("parallel_policy default_timeout_seconds must be positive")
        for forbidden in ("coder", "git_worktree_manager", "maintenance_ops", "memory"):
            if forbidden not in policy.get("forbidden_agents", []):
                errors.append(f"parallel_policy must forbid {forbidden}")
        return errors, warnings

    def create_group(
        self,
        *,
        run_id: str,
        task_type: str,
        agents: list[str],
        mode: ParallelMode = "all_required",
        merge_policy: str = "review_merge_policy",
        timeout_seconds: int | None = None,
    ) -> ParallelGroup:
        group = ParallelGroup(
            parallel_group_id="parallel_" + new_id(),
            run_id=run_id,
            task_type=task_type,
            agents=agents,
            mode=mode,
            timeout_seconds=timeout_seconds or int(self.policy.get("default_timeout_seconds", 120)),
            merge_policy=merge_policy,
            created_at=iso_now(),
        )
        blocked = self._blocked_reason(group)
        status = "blocked" if blocked else "ok"
        RunLedger(self.home, self.store).record(
            "parallel_group_started",
            run_id=run_id,
            task_type=task_type,
            status=status,
            reason=blocked or "parallel group started",
            payload=group.model_dump(),
        )
        if blocked:
            self.store.record_audit("parallel_group_blocked", {**group.model_dump(), "reason": blocked}, run_id=run_id, exit_status="blocked")
            raise ValueError(blocked)
        return group

    def merge_results(self, group: ParallelGroup, results: list[dict[str, Any]]) -> ParallelMergeResult:
        sorted_results = sorted(results, key=lambda item: str(item.get("agent_id") or item.get("reviewer_id") or ""))
        merge_order = [str(item.get("agent_id") or item.get("reviewer_id") or "") for item in sorted_results]
        blocking: list[str] = []
        warnings: list[str] = []
        for item in sorted_results:
            agent_id = str(item.get("agent_id") or item.get("reviewer_id") or "")
            status = str(item.get("status") or item.get("decision") or "")
            required = bool(item.get("required", group.mode == "all_required"))
            timed_out = bool(item.get("timeout"))
            severity = str(item.get("severity", "none"))
            if timed_out and required:
                blocking.append(agent_id)
            elif timed_out:
                warnings.append(agent_id)
            elif severity == "critical":
                blocking.append(agent_id)
            elif required and status in {"fail", "failed", "blocked", "reject", "needs_changes"}:
                blocking.append(agent_id)
            elif status in {"fail", "failed", "blocked"}:
                warnings.append(agent_id)
        if blocking:
            status_value: Literal["ok", "blocked", "warning"] = "blocked"
            reason = f"parallel group blocked by: {', '.join(sorted(set(blocking)))}"
        elif warnings:
            status_value = "warning"
            reason = f"parallel group completed with warnings: {', '.join(sorted(set(warnings)))}"
        else:
            status_value = "ok"
            reason = "parallel group completed"
        merged = ParallelMergeResult(
            parallel_group_id=group.parallel_group_id,
            run_id=group.run_id,
            task_type=group.task_type,
            status=status_value,
            merge_order=merge_order,
            blocking_agents=sorted(set(blocking)),
            warning_agents=sorted(set(warnings)),
            reason=reason,
            results=sorted_results,
            created_at=iso_now(),
        )
        RunLedger(self.home, self.store).record(
            "parallel_group_completed",
            run_id=group.run_id,
            task_type=group.task_type,
            status="blocked" if merged.status == "blocked" else ("warning" if merged.status == "warning" else "ok"),
            reason=merged.reason,
            payload=merged.model_dump(),
        )
        self.store.record_audit(
            "parallel_group_completed",
            merged.model_dump(),
            run_id=group.run_id,
            exit_status=merged.status,
            output_hash=sha256_text(stable_json(merged.model_dump())),
        )
        return merged

    def _blocked_reason(self, group: ParallelGroup) -> str | None:
        forbidden = set(self.policy.get("forbidden_agents", []))
        matched_forbidden = sorted(set(group.agents) & forbidden)
        if matched_forbidden:
            return f"parallel group contains forbidden agent(s): {', '.join(matched_forbidden)}"
        allowed = set(self.policy.get("allowed_agent_kinds", []))
        for agent in group.agents:
            if agent not in allowed and agent not in {"tester", "reviewer"}:
                return f"parallel group agent is not read-only reviewer/tester: {agent}"
        for operation in self.policy.get("forbidden_operations", []):
            if operation in group.merge_policy:
                return f"parallel group merge_policy references forbidden operation: {operation}"
        return None
