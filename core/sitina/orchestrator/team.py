from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import RISK_ORDER, SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.policy import AgentOwnershipRegistry, TASK_TYPES, WorkflowPolicyEngine
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, load_json_yaml, sha256_text, stable_json


CapabilityRisk = Literal["low", "medium", "high", "critical"]


class AgentCapability(StrictModel):
    agent_id: str
    capabilities: list[str] = Field(default_factory=list)
    supported_task_types: list[str] = Field(default_factory=list)
    risk_ceiling: CapabilityRisk = "low"
    can_propose: bool = False
    can_evaluate: bool = False
    can_execute_side_effect: bool = False
    requires_approval_for: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)


class TeamSelection(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    task_id: str
    task_type: str
    risk_level: CapabilityRisk
    candidate_agents: list[str]
    required_agents: list[str]
    optional_agents: list[str]
    forbidden_agents: list[str]
    reviewer_set: list[str]
    tester_set: list[str]
    proposer_set: list[str]
    evaluator_set: list[str]
    excluded: dict[str, str] = Field(default_factory=dict)
    selected_agents: list[str]
    created_at: str


class AgentCapabilityRegistry:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.path = home / "config" / "agent_capabilities.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}

    @property
    def entries(self) -> dict[str, AgentCapability]:
        raw = self.config.get("agents", {}) if self.config else {}
        return {agent_id: AgentCapability.model_validate({"agent_id": agent_id, **value}) for agent_id, value in raw.items()}

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["agent_capabilities config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("agent_capabilities schema_version major must be 1")
        try:
            entries = self.entries
        except Exception as exc:  # noqa: BLE001
            return [f"agent_capabilities invalid: {exc}"], warnings
        for agent_id, entry in entries.items():
            if not entry.capabilities:
                errors.append(f"agent_capabilities {agent_id} has no capabilities")
            for task_type in entry.supported_task_types:
                if task_type not in TASK_TYPES:
                    errors.append(f"agent_capabilities {agent_id} references unknown task_type: {task_type}")
            if "memory_accept" not in entry.forbidden_actions and agent_id not in {"controller", "summary"}:
                warnings.append(f"agent_capabilities {agent_id} should explicitly forbid memory_accept unless reviewed")
        return errors, warnings


class DynamicTeamBuilder:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.registry = AgentCapabilityRegistry(home)
        self.ownership = AgentOwnershipRegistry(home)
        self.policy = WorkflowPolicyEngine(home, self.store)
        self.ledger = RunLedger(home, self.store)

    def validate(self) -> tuple[list[str], list[str]]:
        return self.registry.validate()

    def agents_status(self) -> dict[str, Any]:
        ownership = {agent_id: entry.model_dump() for agent_id, entry in self.ownership.entries.items()}
        capabilities = {agent_id: entry.model_dump() for agent_id, entry in self.registry.entries.items()}
        ids = sorted(set(ownership) | set(capabilities))
        return {
            "status": "ok",
            "agents": [
                {
                    "agent_id": agent_id,
                    "ownership": ownership.get(agent_id),
                    "capability": capabilities.get(agent_id),
                }
                for agent_id in ids
            ],
        }

    def select_team(
        self,
        *,
        run_id: str,
        task_id: str,
        task_type: str,
        risk_level: str,
        requested_tools: list[str] | None = None,
        target_paths: list[str] | None = None,
        required_gates: list[str] | None = None,
        requested_agents: list[str] | None = None,
    ) -> TeamSelection:
        selection = self.preview_team(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            risk_level=risk_level,
            requested_tools=requested_tools,
            target_paths=target_paths,
            required_gates=required_gates,
            requested_agents=requested_agents,
            created_at=iso_now(),
        )
        registry = self.registry.entries
        requested_tools = requested_tools or []
        required_gates = required_gates or list(self.policy.task_policies.get(task_type, {}).get("mandatory_gates", []))
        registry_payload = {"registry_hash": sha256_text(stable_json({k: v.model_dump() for k, v in registry.items()})), "agent_count": len(registry)}
        self.ledger.record("agent_capability_registered", run_id=run_id, task_id=task_id, task_type=task_type, status="ok", reason="agent capability registry loaded", payload=registry_payload)
        self.ledger.record(
            "agent_team_candidate_selected",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id="controller",
            status="ok",
            reason="dynamic team selected from capability registry",
            payload=selection.model_dump() | {"requested_tools": requested_tools, "target_paths": target_paths or [], "required_gates": required_gates},
        )
        self.store.record_audit(
            "agent_team_candidate_selected",
            selection.model_dump(),
            run_id=run_id,
            trace_id=f"{run_id}:team:{task_id}",
            agent="controller",
            exit_status="ok",
            output_hash=sha256_text(stable_json(selection.model_dump())),
        )
        return selection

    def preview_team(
        self,
        *,
        run_id: str,
        task_id: str,
        task_type: str,
        risk_level: str,
        requested_tools: list[str] | None = None,
        target_paths: list[str] | None = None,
        required_gates: list[str] | None = None,
        requested_agents: list[str] | None = None,
        created_at: str = "estimate",
    ) -> TeamSelection:
        """Resolve the real team policy without recording events or audits."""
        risk: CapabilityRisk = risk_level if risk_level in RISK_ORDER else "low"  # type: ignore[assignment]
        policy = self.policy.task_policies.get(task_type, {})
        registry = self.registry.entries
        requested = set(requested_agents or [])
        requested_tools = requested_tools or []
        required_gates = required_gates or list(policy.get("mandatory_gates", []))
        hard_required = self._required_agents(task_type)
        optional = [item for item in policy.get("optional_agents", []) if item in registry or item in self.ownership.ids]
        selected: list[str] = []
        excluded: dict[str, str] = {}
        forbidden = set(policy.get("forbidden_agents", []))

        candidate_ids = sorted(set(registry) | requested | set(hard_required) | set(optional))
        for agent_id in candidate_ids:
            capability = registry.get(agent_id)
            if agent_id in forbidden:
                excluded[agent_id] = f"forbidden by workflow policy for {task_type}"
                continue
            if agent_id in requested and agent_id not in registry and agent_id not in self.ownership.ids:
                excluded[agent_id] = "requested agent is not registered"
                continue
            if capability:
                if task_type not in capability.supported_task_types:
                    excluded[agent_id] = f"unsupported task_type {task_type}"
                    continue
                if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(capability.risk_ceiling, 0):
                    excluded[agent_id] = f"risk {risk} exceeds ceiling {capability.risk_ceiling}"
                    continue
                if any(action in capability.forbidden_actions for action in ("memory_accept", "approval_mutation")) and "memory_accept" in requested_tools:
                    excluded[agent_id] = "memory_accept cannot be auto-selected"
                    continue
            if agent_id in hard_required or agent_id in optional or agent_id in requested:
                selected.append(agent_id)

        for agent_id in hard_required:
            if agent_id not in selected and agent_id not in forbidden:
                selected.append(agent_id)

        reviewer_set = ["code", "test"]
        if task_type == "high_risk_code_change":
            reviewer_set = ["security", "code", "architecture", "test", "docs"]
        tester_set = ["tester"] if task_type in {"code_change", "high_risk_code_change"} else []
        proposer_set = sorted(agent for agent in selected if registry.get(agent) and registry[agent].can_propose)
        evaluator_set = sorted(agent for agent in selected if registry.get(agent) and registry[agent].can_evaluate)
        if task_type == "high_risk_code_change" and "security" not in evaluator_set:
            evaluator_set.append("security")

        selection = TeamSelection(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            risk_level=risk,
            candidate_agents=candidate_ids,
            required_agents=hard_required,
            optional_agents=optional,
            forbidden_agents=sorted(forbidden),
            reviewer_set=reviewer_set,
            tester_set=tester_set,
            proposer_set=sorted(set(proposer_set)),
            evaluator_set=sorted(set(evaluator_set)),
            excluded=excluded,
            selected_agents=sorted(set(selected)),
            created_at=created_at,
        )
        return selection

    def _required_agents(self, task_type: str) -> list[str]:
        if task_type == "chat":
            return ["controller", "summary", "memory"]
        if task_type == "local_file_query":
            return ["controller", "filesystem", "summary", "memory"]
        if task_type == "code_change":
            return ["controller", "planner", "coder", "tester", "reviewer", "summary", "memory"]
        if task_type == "high_risk_code_change":
            return ["controller", "planner", "architect", "coder", "tester", "reviewer", "security", "git_worktree_manager", "summary", "memory"]
        if task_type == "maintenance":
            return ["controller", "reviewer", "security", "maintenance_ops", "summary", "memory"]
        return ["controller", "summary"]
