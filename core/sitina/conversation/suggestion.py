from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sitina.conversation.context import ContextPolicy, ConversationContextSnapshot, TokenEstimator
from sitina.conversation.models import ChatMode
from sitina.conversation.router import ConversationRouter, ConversationRouterError
from sitina.conversation.routing_policy import RISK_ORDER, LatencyClass, RoutingHistoryState, RoutingSignals, normalize_intent_text
from sitina.orchestrator.policy import ControllerDecision, TASK_TYPES, WorkflowPolicyEngine
from sitina.orchestrator.team import DynamicTeamBuilder
from sitina.utils import load_json_yaml, sha256_text, stable_json


class SuggestionError(RuntimeError):
    """The read-only decision preview cannot be produced from current policy."""


class SuggestionEngine:
    """Provider-free preview over the production router and workflow/team policy."""

    SCHEMA = "SITINA_TASK_SUGGESTION_V1"
    VERSION = "suggestion-engine-1.0"
    ESTIMATOR_VERSION = "deterministic-estimate-1.0"

    def __init__(self, home: Path):
        self.home = Path(home)
        try:
            self.context_policy = ContextPolicy.load(self.home)
            router_config = self._json("config/conversation_router.json")
            self.routing_policy = self._json("config/routing_policy.json")
            self.router = ConversationRouter(
                router_config,
                context_policy=self.context_policy,
                routing_policy=self.routing_policy,
                clock=lambda: 1000.0,
            )
            self.workflow = WorkflowPolicyEngine(self.home)
            workflow_errors, _warnings = self.workflow.validate()
            if workflow_errors:
                raise SuggestionError("workflow/team policy invalid: " + "; ".join(workflow_errors))
            self.team = DynamicTeamBuilder(self.home)
            team_errors, _warnings = self.team.validate()
            if team_errors:
                raise SuggestionError("team capability policy invalid: " + "; ".join(team_errors))
            proposal_document = load_json_yaml(self.home / "config/proposal_policy.yaml")
            self.proposal_policy = dict(proposal_document.get("proposal_policy", {}))
            enabled = self.proposal_policy.get("enabled_task_types")
            if not isinstance(enabled, list) or not set(enabled).issubset(TASK_TYPES):
                raise SuggestionError("proposal policy enabled_task_types is invalid")
            self.orchestration_policy = self._json("config/orchestration_policy.json")
            if self.orchestration_policy.get("schema") != "SITINA_ORCHESTRATION_POLICY_V1":
                raise SuggestionError("orchestration policy schema is invalid")
            topologies = self.orchestration_policy.get("topologies")
            if not isinstance(topologies, list) or not topologies or any(not isinstance(item, str) or not item for item in topologies):
                raise SuggestionError("orchestration policy topologies are invalid")
        except SuggestionError:
            raise
        except (ConversationRouterError, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise SuggestionError(str(error)) from error

    def _json(self, relative: str) -> dict[str, Any]:
        path = self.home / relative
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SuggestionError(f"{relative} is required and must be valid JSON") from error
        if not isinstance(value, dict):
            raise SuggestionError(f"{relative} must contain an object")
        return value

    @staticmethod
    def _snapshot(context: str) -> ConversationContextSnapshot:
        transcript = context.strip()
        digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
        return ConversationContextSnapshot(
            transcript=transcript,
            turn_count=1 if transcript else 0,
            char_count=len(transcript),
            context_hash=digest,
            token_count=TokenEstimator.count(transcript),
        )

    @staticmethod
    def _classify_task_type(description: str, signals: RoutingSignals, override: str | None) -> tuple[str, bool]:
        if override is not None:
            if override not in TASK_TYPES:
                raise SuggestionError(f"unknown task_type override: {override}")
            task_type = override
            overridden = True
        else:
            text = normalize_intent_text(description)
            maintenance = (
                "backup", "restore", "rollback run", "maintenance", "rotate key", "prune", "garbage collect",
                "备份", "恢复备份", "运行回滚", "维护", "密钥轮换", "归档清理",
            )
            memory = ("memory review", "review memory", "记忆审核", "记忆复核")
            architecture = ("architecture", "架构", "系统设计", "design review")
            code_change = (
                "code", "代码", "bug", "修复", "实现", "refactor", "重构", "repository", "repo", "pull request", "api change",
            )
            readonly_file = ("读取", "查看文件", "列出目录", "搜索文件", "read file", "list directory", "inspect file")
            if any(marker in text for marker in maintenance):
                task_type = "maintenance"
            elif any(marker in text for marker in memory):
                task_type = "memory_review"
            elif any(marker in text for marker in architecture + code_change) or "code" in signals.artifact_classes:
                task_type = "code_change"
            elif "filesystem" in signals.tool_classes and not signals.side_effect_classes and any(marker in text for marker in readonly_file):
                task_type = "local_file_query"
            elif set(signals.tool_classes) & {"network", "database"}:
                task_type = "mcp_tool_task"
            else:
                task_type = "chat"
            overridden = False
        if task_type == "code_change" and signals.risk in {"high", "critical"}:
            task_type = "high_risk_code_change"
        return task_type, overridden

    def _topology(self, *, route: ChatMode, task_type: str, description: str, override: str | None) -> tuple[str, bool]:
        allowed = tuple(str(item) for item in self.orchestration_policy["topologies"])
        if override is not None:
            if override not in allowed:
                raise SuggestionError(f"topology override is not configured: {override}")
            return override, True
        text = normalize_intent_text(description)
        if task_type in {"high_risk_code_change", "maintenance"} and "hierarchy" in allowed:
            return "hierarchy", False
        if any(marker in text for marker in ("architecture", "架构", "trade-off", "权衡")) and "network" in allowed:
            return "network", False
        if route is ChatMode.MULTI and "supervisor" in allowed:
            return "supervisor", False
        if "pipeline" in allowed:
            return "pipeline", False
        return allowed[0], False

    def suggest(
        self,
        description: str,
        *,
        mode: ChatMode | str = ChatMode.AUTO,
        budget_tokens: int | None = None,
        sla_class: LatencyClass | str = LatencyClass.STANDARD,
        sla_remaining_ms: int | None = None,
        context: str = "",
        prior_mode: ChatMode | str | None = None,
        prior_complexity: int = 0,
        unfinished_goal: bool = False,
        task_type_override: str | None = None,
        risk_override: str | None = None,
        topology_override: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(description, str) or not description.strip():
            raise SuggestionError("task description must be non-empty")
        requested_mode = mode if isinstance(mode, ChatMode) else ChatMode(str(mode).upper())
        latency = sla_class if isinstance(sla_class, LatencyClass) else LatencyClass(str(sla_class).lower())
        default_budget = int(self.routing_policy["default_run_budget_tokens"])
        remaining_tokens = default_budget if budget_tokens is None else int(budget_tokens)
        if remaining_tokens < 0:
            raise SuggestionError("budget_tokens cannot be negative")
        if not 0 <= int(prior_complexity) <= 100:
            raise SuggestionError("prior_complexity must be between 0 and 100")
        inherited_mode = None if prior_mode is None else (prior_mode if isinstance(prior_mode, ChatMode) else ChatMode(str(prior_mode).upper()))
        history = RoutingHistoryState(inherited_mode, int(prior_complexity), inherited_mode is not None, bool(unfinished_goal))
        deadline_ms = int(self.routing_policy["latency_deadlines_ms"][latency.value])
        if sla_remaining_ms is not None and not 0 <= int(sla_remaining_ms) <= deadline_ms:
            raise SuggestionError(f"sla_remaining_ms must be between 0 and {deadline_ms} for {latency.value}")
        started_at = None if sla_remaining_ms is None else 1000.0 - (deadline_ms - int(sla_remaining_ms)) / 1000.0
        snapshot = self._snapshot(context)
        try:
            decision = self.router.decide(
                requested_mode,
                description,
                snapshot,
                history=history,
                remaining_tokens=remaining_tokens,
                latency_class=latency,
                latency_started_at=started_at,
                risk_override=risk_override,
            )
        except (ConversationRouterError, ValueError) as error:
            raise SuggestionError(str(error)) from error
        signals = RoutingSignals.infer(
            description,
            context_tokens=snapshot.token_count,
            prior_complexity_score=int(prior_complexity),
            inherit_history=history.can_inherit,
        )
        if risk_override is not None:
            if risk_override not in {"low", "medium", "high", "critical"}:
                raise SuggestionError("risk override is invalid")
            if RISK_ORDER[risk_override] > RISK_ORDER[signals.risk]:
                signals = RoutingSignals(**{**signals.__dict__, "risk": risk_override})
        task_type, task_overridden = self._classify_task_type(description, signals, task_type_override)
        policy = self.workflow.task_policies.get(task_type)
        if not policy:
            raise SuggestionError(f"workflow policy missing task_type: {task_type}")
        code_task = task_type in {"code_change", "high_risk_code_change"}
        controller = ControllerDecision(
            task_type=task_type,
            need_planner=code_task or task_type == "maintenance",
            need_coder=code_task,
            need_filesystem=task_type == "local_file_query",
            need_tester=code_task,
            need_reviewer=code_task or task_type == "maintenance",
            risk_level=signals.risk,
            requested_tools=[],
            target_paths=[],
            next_agents=[],
            blocked_reason=None,
        )
        plan = self.workflow.build_execution_plan("suggest-preview", controller.model_dump())
        if plan.status != "ok":
            raise SuggestionError(plan.reason)
        preview = self.team.preview_team(
            run_id="suggest-preview",
            task_id="main",
            task_type=plan.task_type,
            risk_level=signals.risk,
            required_gates=plan.mandatory_gates,
            requested_agents=plan.agents_to_run,
        )
        topology, topology_overridden = self._topology(
            route=decision.resolved_mode,
            task_type=plan.task_type,
            description=description,
            override=topology_override,
        )
        proposal_enabled = plan.task_type in set(self.proposal_policy["enabled_task_types"])
        proposal_round = decision.resolved_mode is ChatMode.MULTI and proposal_enabled
        budget = dict(decision.observability or {}).get("budget", {})
        route_upper = int(budget["multi_upper_tokens"] if decision.resolved_mode is ChatMode.MULTI else budget["fast_upper_tokens"])
        complexity = int(dict(decision.observability or {}).get("scores", {}).get("complexity_total", 0))
        token_lower = min(route_upper, max(64, route_upper // 4 + complexity * 4))
        team_size = len(preview.selected_agents)
        seconds_lower = max(1, (complexity + 9) // 10 + (team_size // 3 if decision.resolved_mode is ChatMode.MULTI else 0))
        seconds_upper = seconds_lower * (4 if decision.resolved_mode is ChatMode.MULTI else 2)
        sla = dict(decision.observability or {}).get("sla", {})
        budget_blocked = str(budget.get("status")) in {"blocked-review-budget", "budget-exhausted"}
        sla_blocked = str(sla.get("action")) in {"fail-closed", "review-required"} or (
            sla_remaining_ms is not None and int(sla.get("remaining_ms", deadline_ms)) < seconds_lower * 1000
        )
        constraint_status = "constraint_blocked" if budget_blocked or sla_blocked else "ok"
        domain_profile = str(dict(decision.observability or {}).get("domain_profile", "general@unknown"))
        assumptions = [
            "Token and time ranges are deterministic estimates, not Provider usage or precise work-time promises.",
            "No Provider, network, tool, or side-effect execution is performed by suggest.",
            "The execution router may refine the plan when bounded runtime context or verified artifacts add evidence.",
        ]
        if domain_profile.startswith("general@"):
            assumptions.append("No configured specialist domain matched; the general routing profile was used.")
        risks = [f"detected-risk:{signals.risk}"]
        risks.extend(f"routing-conflict:{item}" for item in dict(decision.observability or {}).get("conflicts", []))
        if budget_blocked:
            risks.append("budget-does-not-admit-the-required-route")
        if sla_blocked:
            risks.append("sla-does-not-admit-the-estimated-critical-path")
        overrides = {
            "mode": requested_mode.value,
            "task_type": task_type_override,
            "risk": risk_override,
            "budget_tokens": budget_tokens,
            "sla_class": latency.value,
            "sla_remaining_ms": sla_remaining_ms,
            "topology": topology_override,
            "context_supplied": bool(context.strip()),
            "prior_mode": inherited_mode.value if inherited_mode else None,
            "prior_complexity": int(prior_complexity),
            "unfinished_goal": bool(unfinished_goal),
        }
        key_reasons = list(dict.fromkeys([
            *decision.reasons,
            f"task-type:{plan.task_type}{':override' if task_overridden else ':inferred'}",
            f"team-policy:{len(preview.selected_agents)}-agents",
            f"topology:{topology}{':override' if topology_overridden else ':policy'}",
        ]))
        result: dict[str, Any] = {
            "schema": self.SCHEMA,
            "version": self.VERSION,
            "status": constraint_status,
            "input_hash": decision.input_hash,
            "task_type": plan.task_type,
            "route": {
                "requested": decision.requested_mode.value,
                "recommended": decision.resolved_mode.value,
                "decision_path": decision.decision_path,
                "source": decision.source.value,
            },
            "proposal_round": proposal_round,
            "worktree": plan.requires_worktree,
            "team": preview.selected_agents,
            "topology": topology,
            "estimated_tokens": {
                "kind": "estimate",
                "lower": token_lower,
                "upper": route_upper,
                "budget_available": remaining_tokens,
                "budget_status": budget.get("status"),
                "not_provider_usage": True,
                "estimator_version": self.ESTIMATOR_VERSION,
            },
            "estimated_time": {
                "kind": "estimate",
                "lower_seconds": seconds_lower,
                "upper_seconds": seconds_upper,
                "sla_class": latency.value,
                "sla_remaining_ms": sla.get("remaining_ms"),
                "not_precise_work_time": True,
                "estimator_version": self.ESTIMATOR_VERSION,
            },
            "key_reasons": key_reasons,
            "confidence": round(float(decision.confidence), 6),
            "assumptions": assumptions,
            "risks": risks,
            "override_parameters": overrides,
            "policy_versions": {
                "conversation_router": decision.policy_version,
                "routing": self.router.routing_policy_version,
                "workflow_sha256": sha256_text(stable_json(self.workflow.config)),
                "team_capabilities_sha256": sha256_text(stable_json(self.team.registry.config)),
                "proposal": str(load_json_yaml(self.home / "config/proposal_policy.yaml").get("schema_version")),
                "orchestration": str(self.orchestration_policy.get("version")),
            },
            "side_effects": {"provider_calls": 0, "network_calls": 0, "state_writes": 0},
        }
        result["friendly_text"] = (
            f"建议 {result['task_type']}，采用 {result['route']['recommended']} / {topology}；"
            f"团队 {team_size} 人，{'需要' if proposal_round else '不需要'} proposal round，"
            f"{'需要' if result['worktree'] else '不需要'} worktree。"
            f"预计 {token_lower}–{route_upper} tokens、{seconds_lower}–{seconds_upper} 秒；这些均为估算，不是真实 Provider usage。"
        )
        return result
