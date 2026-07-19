from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sitina.constants import AGENTS, REQUIRED_DIRS, SITINA_HOME
from sitina.contracts.feature_flags import SharedContractFeatureError, shared_contract_writes_enabled
from sitina.orchestrator.autonomy import AutonomyManager
from sitina.orchestrator.parallel import ParallelCoordinator
from sitina.orchestrator.observability_management import ObservabilityPolicy, ObservabilityPolicyError
from sitina.orchestrator.performance_management import PerformancePolicy, PerformancePolicyError
from sitina.orchestrator.policy import WorkflowPolicyEngine
from sitina.orchestrator.proposals import ProposalManager
from sitina.orchestrator.retry import RetryPolicy
from sitina.orchestrator.reviewers import MultiReviewer
from sitina.orchestrator.schema_registry import SchemaRegistry
from sitina.orchestrator.team import DynamicTeamBuilder
from sitina.orchestrator.workflow import WorkflowPolicy
from sitina.protocols.blackboard_state import BlackboardLimits, BlackboardStateError
from sitina.memory.management import MemoryCapacityPolicy, MemoryManagementError
from sitina.runners.profiles import ProfileLoader
from sitina.runners.prompt_contracts import PromptContractRegistry
from sitina.legacy.retirement import LegacyRuntimePolicy
from sitina.schemas.models import AGENT_OUTPUT_MODELS
from sitina.utils import chmod_octal, load_json_yaml, write_json


class ConfigValidator:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def validate(self) -> dict[str, Any]:
        self.errors = []
        self.warnings = []
        self._required_dirs()
        self._config_files()
        self._schemas()
        self._prompts()
        self._workflow()
        self._collaboration_policy()
        self._risk_rules()
        self._mcp()
        self._profiles()
        return {"ok": not self.errors, "errors": self.errors, "warnings": self.warnings}

    def _required_dirs(self) -> None:
        policy = LegacyRuntimePolicy.load(self.home)
        retired_prefixes = ("data/", "memory/", "logs/", "artifacts/", "outputs/", "backups")
        for rel in REQUIRED_DIRS:
            if policy.protected_environment and policy.fully_disabled and rel.startswith(retired_prefixes):
                continue
            if not (self.home / rel).exists():
                self.errors.append(f"required directory missing: {rel}")
        if policy.protected_environment and policy.fully_disabled:
            for rel in ("journal", "cas", "projections", "output"):
                if not (self.home / rel).is_dir():
                    self.errors.append(f"required B+ directory missing: {rel}")

    def _load(self, rel: str) -> dict[str, Any]:
        path = self.home / rel
        if not path.exists():
            self.errors.append(f"config missing: {rel}")
            return {}
        try:
            data = load_json_yaml(path)
            if not isinstance(data, dict):
                self.errors.append(f"config must be an object: {rel}")
                return {}
            return data
        except Exception as exc:  # noqa: BLE001
            self.errors.append(str(exc))
            return {}

    def _config_files(self) -> None:
        sitina = self._load("config/sitina.yaml")
        agents = self._load("config/agents.yaml")
        self._load("config/workflows.yaml")
        self._load("config/agent_ownership.yaml")
        self._load("config/workflow_policy.yaml")
        self._load("config/retry_policy.yaml")
        self._load("config/reviewers.yaml")
        self._load("config/parallel_policy.yaml")
        self._load("config/proposal_policy.yaml")
        self._load("config/agent_capabilities.yaml")
        self._load("config/agent_prompt_contracts.json")
        try:
            ObservabilityPolicy.load(self.home)
        except ObservabilityPolicyError as exc:
            self.errors.append(f"config/observability_policy.json invalid: {exc}")
        try:
            PerformancePolicy.load(self.home)
        except PerformancePolicyError as exc:
            self.errors.append(f"config/performance_policy.json invalid: {exc}")
        self._load("config/permissions.yaml")
        feature_flags = self._load("config/feature_flags.json")
        blackboard_limits_path = self.home / "config/blackboard_limits.json"
        if blackboard_limits_path.exists():
            try:
                BlackboardLimits.load(blackboard_limits_path)
            except BlackboardStateError as exc:
                self.errors.append(f"config/blackboard_limits.json invalid: {exc}")
        else:
            self.warnings.append("config/blackboard_limits.json missing; safe built-in limits apply")
        memory_capacity_path = self.home / "config/memory_capacity.json"
        if memory_capacity_path.exists():
            try:
                MemoryCapacityPolicy.load(memory_capacity_path)
            except MemoryManagementError as exc:
                self.errors.append(f"config/memory_capacity.json invalid: {exc}")
        else:
            self.warnings.append("config/memory_capacity.json missing; safe built-in limits apply")
        if sitina and sitina.get("schema_version", "1.0").split(".", 1)[0] != "1":
            self.errors.append("config/sitina.yaml schema_version major mismatch")
        if sitina:
            policy = LegacyRuntimePolicy.load(self.home)
            self.errors.extend(policy.validate_protected())
            if policy.protected_environment and sitina.get("state_source_of_truth") != "canonical_journal":
                self.errors.append("protected B+ environment requires state_source_of_truth=canonical_journal")
            authority = sitina.get("storage_authority")
            if policy.protected_environment and (
                not isinstance(authority, dict)
                or authority.get("canonical_source") != "journal"
                or authority.get("content_source") != "cas"
                or authority.get("projection_role") != "disposable_rebuildable_view"
            ):
                self.errors.append("protected B+ storage authority declaration is incomplete")
        registered = set(agents.get("agents", {}).keys()) if agents else set()
        for agent in AGENTS:
            if agent not in registered:
                self.errors.append(f"agent not registered in agents.yaml: {agent}")
        try:
            shared_contract_writes_enabled(feature_flags)
        except SharedContractFeatureError as exc:
            self.errors.append(f"config/feature_flags.json invalid: {exc}")

    def _schemas(self) -> None:
        for name in ("common", *AGENTS):
            path = self.home / "schemas" / f"{name}.schema.json"
            if not path.exists():
                self.errors.append(f"JSON Schema missing: schemas/{name}.schema.json")
                continue
            try:
                schema = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                self.errors.append(f"invalid JSON Schema {name}: {exc}")
                continue
            if schema.get("additionalProperties") is not False:
                # Pydantic can place this within allOf/$defs for inherited models;
                # require the root common schema to show it directly and warn on others.
                if name == "common":
                    self.errors.append("common schema must forbid additionalProperties")
                else:
                    self.warnings.append(f"schema root additionalProperties not explicit for {name}; Pydantic nested defs still forbid extras")
        contract_path = self.home / "schemas/contracts/shared-contracts-v1.schema.json"
        if not contract_path.exists():
            self.errors.append("JSON Schema missing: schemas/contracts/shared-contracts-v1.schema.json")
        else:
            try:
                contract_schema = json.loads(contract_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                self.errors.append(f"invalid shared contract JSON Schema: {exc}")
            else:
                if contract_schema.get("x-sitina-unknown-field-strategy") != "reject":
                    self.errors.append("shared contract schema must reject unknown fields")
                if contract_schema.get("x-sitina-new-write-default") != "disabled":
                    self.errors.append("shared contract schema writes must default disabled")

    def _prompts(self) -> None:
        for agent in AGENTS:
            path = self.home / "prompts" / "agents" / f"{agent}.md"
            if not path.exists():
                self.errors.append(f"prompt missing: prompts/agents/{agent}.md")
            elif "single JSON" not in path.read_text(encoding="utf-8"):
                self.errors.append(f"prompt must require single JSON output: {agent}")
        self.errors.extend(PromptContractRegistry(self.home).validate())

    def _workflow(self) -> None:
        self.errors.extend(WorkflowPolicy(self.home).validate())

    def _collaboration_policy(self) -> None:
        for validator in (
            WorkflowPolicyEngine(self.home),
            RetryPolicy(self.home),
            MultiReviewer(self.home),
            ParallelCoordinator(self.home),
            ProposalManager(self.home),
            DynamicTeamBuilder(self.home),
            AutonomyManager(self.home),
            SchemaRegistry(self.home),
        ):
            errors, warnings = validator.validate()
            self.errors.extend(errors)
            self.warnings.extend(warnings)

    def _risk_rules(self) -> None:
        data = self._load("config/permissions.yaml")
        for idx, rule in enumerate(data.get("risk_rules", [])):
            for key in ("id", "risk_level", "action"):
                if key not in rule:
                    self.errors.append(f"risk rule {idx} missing {key}")
            if rule.get("risk_level") not in {"low", "medium", "high", "critical"}:
                self.errors.append(f"risk rule {rule.get('id', idx)} has invalid risk_level")
            if rule.get("action") not in {"allow", "approval", "block"}:
                self.errors.append(f"risk rule {rule.get('id', idx)} has invalid action")

    def _mcp(self) -> None:
        allowlist = self._load("config/mcp/allowlist.yaml")
        if allowlist.get("default_policy") != "deny":
            self.errors.append("MCP default policy must be deny")
        servers = self._load("config/mcp/servers.yaml")
        if servers:
            from sitina.runners.mcp_adapter import McpAdapter

            result = McpAdapter(self.home).validate_registry()
            self.errors.extend(result.get("errors", []))
            self.warnings.extend(result.get("warnings", []))

    def _profiles(self) -> None:
        loader = ProfileLoader(self.home)
        profiles = [p for p in (self.home / "profiles").glob("*.env") if not p.name.endswith(".template")]
        for path in profiles:
            mode = chmod_octal(path)
            if mode != "600":
                self.errors.append(f"profile permissions must be 600: {path} ({mode})")
            ok, message = loader.check_profile(path.stem)
            if not ok:
                self.errors.append(message)


def export_json_schemas(home: Path = SITINA_HOME) -> list[Path]:
    out: list[Path] = []
    for name, model in AGENT_OUTPUT_MODELS.items():
        path = home / "schemas" / f"{name}.schema.json"
        write_json(path, model.model_json_schema())
        out.append(path)
    return out
