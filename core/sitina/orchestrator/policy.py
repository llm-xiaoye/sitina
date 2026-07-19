from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import AGENTS, SITINA_HOME
from sitina.schemas.models import RiskLevel, StrictModel
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, iso_now, load_json_yaml, sha256_text, stable_json, write_json


TASK_TYPES = {
    "chat",
    "local_file_query",
    "code_change",
    "high_risk_code_change",
    "maintenance",
    "memory_review",
    "mcp_tool_task",
}
MODULE_IDS = {"filesystem", "git", "sqlite", "obsidian", "git_worktree_manager", "maintenance_ops", "provider_fallback"}
SPECIAL_GATES = {"approval", "audit", "patch_apply", "worktree"}
MUTATION_AGENTS = {"coder", "git_worktree_manager", "maintenance_ops"}


class OwnershipEntry(StrictModel):
    owns: list[str]
    not_owns: list[str]
    allowed_inputs: list[str]
    required_outputs: list[str]
    can_call_tools: list[str]
    can_write_files: bool
    write_requires_approval: bool = False
    gate_level: Literal["none", "warning", "blocking", "final"]
    mandatory_for_task_types: list[str] = Field(default_factory=list)
    optional_for_task_types: list[str] = Field(default_factory=list)
    forbidden_for_task_types: list[str] = Field(default_factory=list)
    handoff_in: list[str] = Field(default_factory=list)
    handoff_out: list[str] = Field(default_factory=list)


class ControllerDecision(StrictModel):
    task_type: str
    need_planner: bool
    need_coder: bool
    need_filesystem: bool
    need_tester: bool
    need_reviewer: bool
    risk_level: RiskLevel
    requested_tools: list[str]
    target_paths: list[str]
    next_agents: list[str]
    blocked_reason: str | None

    @model_validator(mode="after")
    def validate_no_empty_strings(self) -> "ControllerDecision":
        if not self.task_type.strip():
            raise ValueError("task_type must not be empty")
        for field_name in ("requested_tools", "target_paths", "next_agents"):
            for value in getattr(self, field_name):
                if not str(value).strip():
                    raise ValueError(f"{field_name} contains an empty value")
        return self


class ExecutionPlan(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    task_id: str = "main"
    task_type: str
    status: Literal["ok", "blocked"]
    reason: str
    agents_to_run: list[str]
    mandatory_gates: list[str]
    optional_agents: list[str]
    forbidden_agents: list[str]
    skipped_agents: list[dict[str, str]]
    requested_tools: list[str]
    target_paths: list[str]
    allowed_tools: list[str]
    memory_check: Literal["always", "on_summary", "never"]
    requires_approval: bool
    requires_worktree: bool
    requires_patch_hash: bool
    policy_hash: str
    controller_decision_hash: str
    created_at: str

    @property
    def runnable_agents(self) -> set[str]:
        return set(self.agents_to_run)


class AgentOwnershipRegistry:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.path = home / "config" / "agent_ownership.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}

    @property
    def entries(self) -> dict[str, OwnershipEntry]:
        raw: dict[str, Any] = {}
        raw.update(self.config.get("agents", {}))
        raw.update(self.config.get("modules", {}))
        entries: dict[str, OwnershipEntry] = {}
        for key, value in raw.items():
            entries[key] = OwnershipEntry.model_validate(value)
        return entries

    @property
    def ids(self) -> set[str]:
        return set(self.entries)

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["agent ownership config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("agent_ownership schema_version major must be 1")
        try:
            entries = self.entries
        except Exception as exc:  # noqa: BLE001
            return [f"agent_ownership invalid: {exc}"], warnings

        for agent in AGENTS:
            if agent not in entries:
                errors.append(f"ownership missing agent: {agent}")
        for module_id in MODULE_IDS:
            if module_id not in entries:
                errors.append(f"ownership missing module: {module_id}")

        for entry_id, entry in entries.items():
            overlap = sorted(set(entry.owns) & set(entry.not_owns))
            if overlap:
                errors.append(f"ownership conflict for {entry_id}: owns and not_owns overlap {overlap}")
            if entry.can_write_files and (not entry.write_requires_approval or entry.gate_level not in {"blocking", "final"}):
                errors.append(f"write-capable entry must require approval and blocking/final gate: {entry_id}")
            for task_type in entry.mandatory_for_task_types + entry.optional_for_task_types + entry.forbidden_for_task_types:
                if task_type not in TASK_TYPES:
                    errors.append(f"ownership {entry_id} references unknown task_type: {task_type}")
            both = sorted((set(entry.mandatory_for_task_types) | set(entry.optional_for_task_types)) & set(entry.forbidden_for_task_types))
            if both:
                errors.append(f"ownership {entry_id} both allows and forbids task_types: {both}")
            if entry_id == "memory" and entry.can_write_files:
                errors.append("memory ownership must not write files; only pending candidates are allowed")
            if entry_id == "controller" and "patch_apply" not in entry.not_owns:
                warnings.append("controller ownership should explicitly exclude patch_apply")
        return errors, warnings

    def entry(self, entry_id: str) -> OwnershipEntry | None:
        return self.entries.get(entry_id)

    def can_handoff(self, from_agent: str, to_agent: str) -> bool:
        entries = self.entries
        if to_agent not in entries:
            return False
        if from_agent == to_agent:
            return True
        if from_agent == "initial":
            return "initial" in entries[to_agent].handoff_in or to_agent == "controller"
        source = entries.get(from_agent)
        if not source:
            return False
        target = entries[to_agent]
        return to_agent in source.handoff_out and from_agent in target.handoff_in


class WorkflowPolicyEngine:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "config" / "workflow_policy.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}
        self.ownership = AgentOwnershipRegistry(home)

    @property
    def task_policies(self) -> dict[str, dict[str, Any]]:
        return self.config.get("task_types", {})

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        ownership_errors, ownership_warnings = self.ownership.validate()
        errors.extend(ownership_errors)
        warnings.extend(ownership_warnings)
        if not self.config:
            return ["workflow policy config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("workflow_policy schema_version major must be 1")
        policies = self.task_policies
        for task_type in sorted(TASK_TYPES):
            if task_type not in policies:
                errors.append(f"workflow policy missing task_type: {task_type}")
        known = self.ownership.ids | SPECIAL_GATES
        for task_type, policy in policies.items():
            if task_type not in TASK_TYPES:
                errors.append(f"workflow policy unknown task_type: {task_type}")
            for key in ("optional_agents", "mandatory_gates", "forbidden_agents", "required_audit_events", "approval_required_when", "worktree_required_when"):
                if key not in policy or not isinstance(policy.get(key), list):
                    errors.append(f"workflow policy {task_type} missing list: {key}")
            if policy.get("memory_check") not in {"always", "on_summary", "never"}:
                errors.append(f"workflow policy {task_type} invalid memory_check")
            for ref in policy.get("optional_agents", []) + policy.get("mandatory_gates", []) + policy.get("forbidden_agents", []):
                if ref not in known:
                    errors.append(f"workflow policy {task_type} references unknown agent/gate: {ref}")
            for ref in policy.get("optional_agents", []) + policy.get("mandatory_gates", []):
                entry = self.ownership.entry(ref)
                if entry and task_type in entry.forbidden_for_task_types:
                    errors.append(f"workflow policy {task_type} allows ownership-forbidden entry: {ref}")
            if task_type == "chat":
                for forbidden in ("coder", "tester", "reviewer"):
                    if forbidden not in policy.get("forbidden_agents", []):
                        errors.append(f"chat policy must forbid {forbidden}")
            if task_type == "local_file_query":
                for tool in policy.get("allowed_tools", []):
                    if not str(tool).startswith("filesystem:") or tool.endswith("write_file"):
                        errors.append("local_file_query may only allow readonly filesystem tools")
            if task_type == "high_risk_code_change":
                for gate in ("git_worktree_manager", "approval", "reviewer", "patch_apply"):
                    if gate not in policy.get("mandatory_gates", []):
                        errors.append(f"high_risk_code_change must require {gate}")
                if not policy.get("requires_patch_hash"):
                    errors.append("high_risk_code_change must require patch_hash")
        return errors, warnings

    def build_execution_plan(self, run_id: str, controller_payload: dict[str, Any], *, task_id: str = "main") -> ExecutionPlan:
        policy_hash = sha256_text(stable_json(self.config))
        try:
            decision_payload = {name: controller_payload.get(name) for name in ControllerDecision.model_fields}
            decision = ControllerDecision.model_validate(decision_payload)
        except Exception as exc:  # noqa: BLE001
            return self._blocked_plan(
                run_id,
                task_id,
                task_type=str(controller_payload.get("task_type", "invalid")),
                reason=f"controller decision schema invalid: {exc}",
                controller_payload=controller_payload,
                policy_hash=policy_hash,
            )

        task_type = decision.task_type
        if task_type not in TASK_TYPES:
            return self._blocked_plan(
                run_id,
                task_id,
                task_type=task_type,
                reason=f"unknown task_type: {task_type}",
                controller_payload=controller_payload,
                policy_hash=policy_hash,
            )
        if decision.risk_level in {"high", "critical"} and task_type == "code_change":
            task_type = "high_risk_code_change"
        policy = self.task_policies.get(task_type)
        if not policy:
            return self._blocked_plan(
                run_id,
                task_id,
                task_type=task_type,
                reason=f"workflow policy missing task_type: {task_type}",
                controller_payload=controller_payload,
                policy_hash=policy_hash,
            )
        forbidden = list(policy.get("forbidden_agents", []))
        requested = self._requested_entries(decision)
        requested_forbidden = sorted(requested & set(forbidden))
        if requested_forbidden:
            return self._plan_from_policy(
                run_id,
                task_id,
                task_type,
                decision,
                policy,
                status="blocked",
                reason=f"controller requested forbidden agent(s): {', '.join(requested_forbidden)}",
                policy_hash=policy_hash,
            )
        unknown_requested = sorted(item for item in requested if item not in self.ownership.ids)
        if unknown_requested:
            return self._plan_from_policy(
                run_id,
                task_id,
                task_type,
                decision,
                policy,
                status="blocked",
                reason=f"controller requested unknown agent/module(s): {', '.join(unknown_requested)}",
                policy_hash=policy_hash,
            )
        allowed_tools = list(policy.get("allowed_tools", []))
        tool_error = self._tool_policy_error(task_type, decision.requested_tools, allowed_tools)
        if tool_error:
            return self._plan_from_policy(run_id, task_id, task_type, decision, policy, status="blocked", reason=tool_error, policy_hash=policy_hash)
        if decision.blocked_reason:
            return self._plan_from_policy(
                run_id,
                task_id,
                task_type,
                decision,
                policy,
                status="blocked",
                reason=decision.blocked_reason,
                policy_hash=policy_hash,
            )
        return self._plan_from_policy(
            run_id,
            task_id,
            task_type,
            decision,
            policy,
            status="ok",
            reason="controller decision accepted by workflow policy",
            policy_hash=policy_hash,
        )

    def record_execution_plan(self, plan: ExecutionPlan) -> Path:
        from sitina.orchestrator.ledger import RunLedger

        out = self.home / "artifacts" / "execution_plans" / f"{plan.run_id}-{plan.task_id}.json"
        ensure_dir(out.parent)
        write_json(out, plan.model_dump())
        payload = plan.model_dump()
        payload["artifact_path"] = str(out)
        self.store.record_event("policy_execution_plan", payload, run_id=plan.run_id, trace_id=f"{plan.run_id}:policy")
        self.store.record_audit(
            "policy_execution_plan",
            payload,
            run_id=plan.run_id,
            trace_id=f"{plan.run_id}:policy",
            exit_status=plan.status,
            output_hash=sha256_text(stable_json(payload)),
        )
        RunLedger(self.home, self.store).record(
            "policy_execution_plan",
            run_id=plan.run_id,
            task_id=plan.task_id,
            task_type=plan.task_type if plan.task_type in TASK_TYPES else "chat",
            status="ok" if plan.status == "ok" else "blocked",
            reason=plan.reason,
            artifacts=[str(out)],
            payload=payload,
        )
        return out

    def _requested_entries(self, decision: ControllerDecision) -> set[str]:
        requested = set(decision.next_agents)
        if decision.need_planner:
            requested.add("planner")
        if decision.need_coder:
            requested.add("coder")
        if decision.need_tester:
            requested.add("tester")
        if decision.need_reviewer:
            requested.add("reviewer")
        if decision.need_filesystem:
            requested.add("filesystem")
        return {item for item in requested if item}

    def _plan_from_policy(
        self,
        run_id: str,
        task_id: str,
        task_type: str,
        decision: ControllerDecision,
        policy: dict[str, Any],
        *,
        status: Literal["ok", "blocked"],
        reason: str,
        policy_hash: str,
    ) -> ExecutionPlan:
        requested = self._requested_entries(decision)
        mandatory = list(policy.get("mandatory_gates", []))
        optional = list(policy.get("optional_agents", []))
        agent_like_mandatory = [item for item in mandatory if item in self.ownership.ids]
        agents_to_run = ["controller"]
        for item in [*agent_like_mandatory, *sorted(requested), "summary"]:
            if item in self.ownership.ids and item not in policy.get("forbidden_agents", []) and item not in agents_to_run:
                agents_to_run.append(item)
        if policy.get("memory_check") in {"always", "on_summary"} and "memory" in self.ownership.ids and "memory" not in agents_to_run:
            agents_to_run.append("memory")
        core_entries = ["planner", "coder", "tester", "reviewer", "summary", "memory", "filesystem", "git_worktree_manager", "maintenance_ops"]
        skipped = [
            {"agent_id": item, "reason": f"not required for task_type {task_type}"}
            for item in core_entries
            if item not in agents_to_run and item not in policy.get("forbidden_agents", [])
        ]
        skipped.extend({"agent_id": item, "reason": f"forbidden for task_type {task_type}"} for item in policy.get("forbidden_agents", []))
        approval_rules = set(policy.get("approval_required_when", []))
        requires_approval = "always" in approval_rules or ("coder_requested" in approval_rules and decision.need_coder) or decision.risk_level in {"high", "critical"}
        worktree_rules = set(policy.get("worktree_required_when", []))
        requires_worktree = "always" in worktree_rules or ("risk_level_high_or_critical" in worktree_rules and decision.risk_level in {"high", "critical"})
        return ExecutionPlan(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            status=status,
            reason=reason,
            agents_to_run=agents_to_run,
            mandatory_gates=mandatory,
            optional_agents=optional,
            forbidden_agents=list(policy.get("forbidden_agents", [])),
            skipped_agents=skipped,
            requested_tools=list(decision.requested_tools),
            target_paths=list(decision.target_paths),
            allowed_tools=list(policy.get("allowed_tools", [])),
            memory_check=policy.get("memory_check", "never"),
            requires_approval=requires_approval,
            requires_worktree=requires_worktree,
            requires_patch_hash=bool(policy.get("requires_patch_hash")),
            policy_hash=policy_hash,
            controller_decision_hash=sha256_text(stable_json(decision.model_dump())),
            created_at=iso_now(),
        )

    def _blocked_plan(
        self,
        run_id: str,
        task_id: str,
        *,
        task_type: str,
        reason: str,
        controller_payload: dict[str, Any],
        policy_hash: str,
    ) -> ExecutionPlan:
        policy = self.task_policies.get("chat", {})
        decision_hash = sha256_text(stable_json(controller_payload))
        return ExecutionPlan(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            status="blocked",
            reason=reason,
            agents_to_run=["controller"],
            mandatory_gates=list(policy.get("mandatory_gates", [])),
            optional_agents=list(policy.get("optional_agents", [])),
            forbidden_agents=list(policy.get("forbidden_agents", [])),
            skipped_agents=[{"agent_id": item, "reason": "policy blocked before execution"} for item in ["planner", "coder", "tester", "reviewer", "summary", "memory"]],
            requested_tools=list(controller_payload.get("requested_tools", [])) if isinstance(controller_payload.get("requested_tools", []), list) else [],
            target_paths=list(controller_payload.get("target_paths", [])) if isinstance(controller_payload.get("target_paths", []), list) else [],
            allowed_tools=list(policy.get("allowed_tools", [])),
            memory_check="never",
            requires_approval=False,
            requires_worktree=False,
            requires_patch_hash=False,
            policy_hash=policy_hash,
            controller_decision_hash=decision_hash,
            created_at=iso_now(),
        )

    def _tool_policy_error(self, task_type: str, requested_tools: list[str], allowed_tools: list[str]) -> str | None:
        allowed = set(allowed_tools)
        for tool in requested_tools:
            if tool not in allowed and tool.split(":", 1)[-1] not in allowed:
                return f"requested tool is not allowed for {task_type}: {tool}"
            lower = tool.lower()
            if task_type in {"local_file_query", "mcp_tool_task"} and any(name in lower for name in ("write", "delete", "move", "overwrite")):
                return f"mutating tool is forbidden for readonly task_type {task_type}: {tool}"
        return None
