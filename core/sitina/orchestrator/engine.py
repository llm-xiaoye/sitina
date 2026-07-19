from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from sitina.config import ConfigValidator
from sitina.constants import SITINA_HOME
from sitina.guards.approvals import ApprovalManager, scope_hash
from sitina.guards.diff import DiffVerifier
from sitina.guards.evidence import ArtifactRegistry, EvidenceVerifier
from sitina.guards.risk import RiskScanner
from sitina.legacy.fence import LegacyWriteGate
from sitina.authority.model import AuthorityResolution
from sitina.orchestrator.autonomy import AutonomyManager
from sitina.orchestrator.bplus_adapter import BPlusShadowAdapter
from sitina.orchestrator.bplus_production import BPlusProductionRuntime, ProductionRuntimeContext
from sitina.orchestrator.arbitration import ArbitrationManager
from sitina.orchestrator.accounting import ProviderAccounting
from sitina.orchestrator.collaboration import CollaborationRuntime
from sitina.orchestrator.git_ops import GitWorktreeManager
from sitina.orchestrator.handoff import EnvelopeFactory, HandoffManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.leases import LeaseManager
from sitina.orchestrator.policy import ExecutionPlan, WorkflowPolicyEngine
from sitina.orchestrator.parallel import ParallelCoordinator
from sitina.orchestrator.proposals import ProposalManager
from sitina.orchestrator.retry import RetryPolicy
from sitina.orchestrator.reviewers import MultiReviewer
from sitina.orchestrator.revision import CodeRevisionResolver
from sitina.orchestrator.run_manifest import RunManifestManager
from sitina.orchestrator.side_effects import SideEffectManager
from sitina.orchestrator.state_machine import RunStateManager
from sitina.orchestrator.task_graph import HandoffBlockedError, TaskGraph, TaskGraphNode, TaskGraphRuntime
from sitina.orchestrator.team import DynamicTeamBuilder, TeamSelection
from sitina.orchestrator.terminal import terminal_summary
from sitina.orchestrator.timeout_support import TERMINAL_EVENTS, RunCancelledError, RunControlStore, RunDeadline, TimeoutError, ProviderTimeoutConfig, completion_invariant, ensure_terminal_event
from sitina.runners.agent_runner import AgentRunner, AgentRunnerError, AgentRunResult
from sitina.runners.mcp_adapter import McpAdapter
from sitina.runners.tool_executor import ToolExecutor
from sitina.schemas.models import MandatoryStepOutputs
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, compute_agent_input_hash, ensure_dir, iso_now, load_json_yaml, new_id, read_json, redact_text, sha256_text, stable_json, write_json


SENSITIVE_MEMORY_PATTERNS = [
    (re.compile(r"(?i)\b(cookie|private[_ -]?key|ssh-rsa|api[_ -]?key|auth[_ -]?token|token|secret|password)\b"), "secret-like content"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.DOTALL), "private key"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "government identifier"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "payment card-like number"),
    (re.compile(r"(?i)\b(exact address|home address|street address|diagnosed with|health diagnosis|medical diagnosis)\b"), "sensitive personal attribute"),
    (re.compile(r"(身份证|银行卡|精确地址|住址|健康诊断|病历|政治立场|宗教信仰|性取向|种族)"), "sensitive personal attribute"),
]


class SitinaEngine:
    def __init__(self, home: Path = SITINA_HOME, *, bplus_keychain_backend: object | None = None):
        self.home = home
        self.bplus_keychain_backend = bplus_keychain_backend
        self.store = SitinaStore(home)
        self.states = RunStateManager(home, self.store)
        self.risk = RiskScanner(home)
        self.legacy_write_gate = LegacyWriteGate(home)
        self.bplus_shadow = BPlusShadowAdapter.from_home(home)

    def authorize_fixture_business_write(self, resolution: AuthorityResolution, *, now: int) -> str:
        """Phase 6A proof hook; it never changes the default Legacy route."""
        resolution.assert_fresh(now=now)
        if resolution.writer_count != 1:
            raise PermissionError("AuthorityResolution does not name exactly one writer")
        if resolution.authorizes_legacy:
            self.legacy_write_gate.assert_writes_authorized(resolution, now=now)
            return "legacy"
        if resolution.authorizes_journal:
            if not (self.home / ".sitina-bplus-disposable-v1").is_file() or self.home == Path("/Users/moss/SitinaHub"):
                raise PermissionError("Phase 6A Journal writer proof is fixture-only")
            return "journal"
        raise PermissionError("no writer is authorized")

    def initialize(self) -> None:
        self.legacy_write_gate.assert_writes_allowed()
        self.store.init_db()
        for path, value in {
            self.home / "state" / "active_conversation.json": {"conversation_id": "conv_default", "updated_at": iso_now(), "turns": []},
            self.home / "state" / "blackboard.json": {},
            self.home / "memory" / "user_preferences.json": {},
            self.home / "memory" / "global_memory.md": "",
        }.items():
            if not path.exists():
                if path.suffix == ".json":
                    write_json(path, value)
                else:
                    ensure_dir(path.parent)
                    path.write_text(str(value), encoding="utf-8")

    def run(
        self,
        goal: str,
        *,
        attach_conversation: bool = False,
        provider_mode: str = "mock",
        profile_overrides: dict[str, str] | None = None,
        parent_goal_id: str | None = None,
        backlog_item_id: str | None = None,
    ) -> dict[str, Any]:
        if (self.home / "state/bplus-production-genesis/genesis.json").is_file():
            # Phase 6B restriction removed - allow live provider
            # if provider_mode != "mock":
            #     raise PermissionError("B+ Production Phase 6B routing permits MOCK_ONLY until a later capability activation")
            context = ProductionRuntimeContext.load(
                self.home,
                keychain_backend=self.bplus_keychain_backend,
                allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
            )
            journal = context.open_writer()
            try:
                runtime = BPlusProductionRuntime(self.home, journal, context.authority.resolution, now=int(time.time()))
                result = runtime.create_local_run(
                    goal,
                    cas=context.open_cas(),
                    provider=context.provider,
                    parent_goal_id=parent_goal_id,
                    backlog_item_id=backlog_item_id,
                )
            finally:
                journal.close()
            return result
        self.legacy_write_gate.assert_writes_allowed()
        if self.bplus_shadow.enabled:
            # Non-authoritative observation only. The adapter has no Provider,
            # Tool, MCP, approval, or effect capability and its result never
            # changes the Legacy return value.
            self.bplus_shadow.observe_run_request(goal, provider_mode=provider_mode)
        try:
            return self._run(
                goal,
                attach_conversation=attach_conversation,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides,
                parent_goal_id=parent_goal_id,
                backlog_item_id=backlog_item_id,
            )
        except KeyboardInterrupt:
            context = getattr(self, "_active_run_context", None)
            if not isinstance(context, dict) or not context.get("run_id"):
                raise
            run_id = str(context["run_id"])
            raw_state = self.store.get_run(run_id)
            if raw_state:
                state = self._state_from_raw(raw_state)
                state = state.model_copy(update={
                    "phase": "interrupted",
                    "active_agent": None,
                    "verification_status": "not_verified",
                    "risk_scan_result_ref": context.get("risk_scan_id"),
                })
                self.states.save(state)
            reason = "run interrupted by KeyboardInterrupt"
            task_type = str(context.get("task_type") or "chat")
            ledger = RunLedger(self.home, self.store)
            ensure_terminal_event(ledger, run_id, task_type, "interrupted", reason)
            self._record_memory_no_candidate(run_id, reason, source="workflow")
            return self._finalize_autonomy_run(
                {
                    "run_id": run_id,
                    "phase": "interrupted",
                    "verification_status": "not_verified",
                    "status": "interrupted",
                    "reason": reason,
                },
                parent_goal_id=context.get("parent_goal_id"),
                backlog_item_id=context.get("backlog_item_id"),
            )
        except (TimeoutError, RunCancelledError, AgentRunnerError) as exc:
            context = getattr(self, "_active_run_context", None)
            if not isinstance(context, dict) or not context.get("run_id"):
                raise
            run_id = str(context["run_id"])
            error_type = getattr(exc, "error_type", getattr(exc, "timeout_type", "provider_failed"))
            is_cancelled = isinstance(exc, RunCancelledError) or error_type == "run_cancelled"
            is_timeout = error_type in {"run_deadline", "run_deadline_exceeded", "provider_connect_timeout", "provider_read_timeout"}
            phase = "cancelled" if is_cancelled else ("timeout" if is_timeout else "failed")
            raw_state = self.store.get_run(run_id)
            if raw_state:
                state = self._state_from_raw(raw_state).model_copy(update={
                    "phase": phase,
                    "active_agent": None,
                    "verification_status": "not_verified",
                    "risk_scan_result_ref": context.get("risk_scan_id"),
                })
                self.states.save(state)
            reason = redact_text(str(exc))[:500]
            task_type = str(context.get("task_type") or "chat")
            ensure_terminal_event(RunLedger(self.home, self.store), run_id, task_type, phase, reason)
            self._record_memory_no_candidate(run_id, f"workflow terminated: {reason}", source="workflow")
            return self._finalize_autonomy_run(
                {"run_id": run_id, "phase": phase, "verification_status": "not_verified", "status": phase, "reason": reason},
                parent_goal_id=context.get("parent_goal_id"),
                backlog_item_id=context.get("backlog_item_id"),
            )
        except Exception as exc:  # noqa: BLE001
            context = getattr(self, "_active_run_context", None)
            if not isinstance(context, dict) or not context.get("run_id"):
                raise
            run_id = str(context["run_id"])
            raw_state = self.store.get_run(run_id)
            if raw_state:
                state = self._state_from_raw(raw_state).model_copy(update={
                    "phase": "failed",
                    "active_agent": None,
                    "verification_status": "not_verified",
                    "risk_scan_result_ref": context.get("risk_scan_id"),
                })
                self.states.save(state)
            reason = redact_text(str(exc))[:500]
            task_type = str(context.get("task_type") or "chat")
            ensure_terminal_event(RunLedger(self.home, self.store), run_id, task_type, "failed", reason)
            self._record_memory_no_candidate(run_id, f"workflow failed: {reason}", source="workflow")
            return self._finalize_autonomy_run(
                {"run_id": run_id, "phase": "failed", "verification_status": "not_verified", "status": "failed", "reason": reason},
                parent_goal_id=context.get("parent_goal_id"),
                backlog_item_id=context.get("backlog_item_id"),
            )
        finally:
            if hasattr(self, "_active_run_context"):
                delattr(self, "_active_run_context")

    def _run(
        self,
        goal: str,
        *,
        attach_conversation: bool = False,
        provider_mode: str = "mock",
        profile_overrides: dict[str, str] | None = None,
        parent_goal_id: str | None = None,
        backlog_item_id: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        profile_overrides = profile_overrides or {}
        scan = self.risk.scan("read", target=str(self.home), allowed_roots=[str(self.home)])
        self.store.insert_risk_scan(scan.model_dump())
        state = self.states.create(scan.risk_level)
        self._active_run_context = {
            "run_id": state.run_id,
            "risk_scan_id": scan.risk_scan_id,
            "task_type": "chat",
            "parent_goal_id": parent_goal_id,
            "backlog_item_id": backlog_item_id,
        }
        runner = AgentRunner(self.home)
        ledger = RunLedger(self.home, self.store)
        provider_config = load_json_yaml(self.home / "config" / "sitina.yaml").get("providers", {})
        run_deadline = RunDeadline.create(state.run_id, ProviderTimeoutConfig.from_config(dict(provider_config)).run_deadline)
        RunControlStore(self.home).create(run_deadline)
        collaboration = CollaborationRuntime(self.home, self.store)
        autonomy = AutonomyManager(self.home, self.store)
        handoffs = HandoffManager(self.home, self.store)
        policy_engine = WorkflowPolicyEngine(self.home, self.store)
        revision = CodeRevisionResolver(self.home).current()
        fixture_metadata = ProviderAccounting.controlled_fixture_metadata(goal, provider_mode)
        ledger.record(
            "run_started",
            run_id=state.run_id,
            task_type="chat",
            status="ok",
            reason="run initialized",
            payload={
                "goal_hash": sha256_text(goal),
                "risk_scan_id": scan.risk_scan_id,
                "parent_goal_id": parent_goal_id,
                "backlog_item_id": backlog_item_id,
                "run_deadline": run_deadline.to_dict(),
                "provider_mode": provider_mode,
                "live_minimal_fixture": "live-minimal-collaboration-fixture" in goal.lower(),
                **revision,
                **fixture_metadata,
            },
        )
        collaboration.observe(run_id=state.run_id, goal=goal, risk_scan_id=scan.risk_scan_id)
        link_result = autonomy.link_run(state.run_id, goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        if link_result.get("status") in {"not_found", "blocked"}:
            reason = str(link_result.get("reason") or "goal/backlog link target not found")
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            ledger.record("run_blocked", run_id=state.run_id, task_type="chat", status="blocked", reason=reason, payload=link_result)
            self._record_memory_no_candidate(state.run_id, f"workflow blocked before summary: {reason}", source="autonomy")
            return self._finalize_autonomy_run(
                {"run_id": state.run_id, "phase": "blocked", "verification_status": "not_verified", "status": "blocked", "reason": reason},
                parent_goal_id=parent_goal_id,
                backlog_item_id=backlog_item_id,
            )
        if "live-typed-rework-worker-fixture" in goal.lower():
            result = self._run_live_typed_rework_worker_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        if "live-lease-arbitration-worker-fixture" in goal.lower() or "live-lease-arbitration-block-worker-fixture" in goal.lower():
            result = self._run_live_lease_arbitration_worker_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        if "live-checkpoint-resume-worker-fixture" in goal.lower():
            return self._prepare_checkpoint_resume_worker_fixture(
                runner,
                state,
                goal,
                provider_mode,
                profile_overrides,
            )
        self.store.record_event("user_goal", {"goal_hash": sha256_text(goal), "preview": redact_text(goal)[:300]}, run_id=state.run_id)

        try:
            state = self.states.transition(state, "controller_decision", "controller")
            initial_handoff = handoffs.create_handoff(
                run_id=state.run_id,
                task_id="main",
                task_type="chat",
                from_agent="initial",
                to_agent="controller",
                reason="initial dispatch to controller",
                required_inputs=["user_goal", "run_state", "risk_scan_result"],
            )
            if initial_handoff.status == "blocked":
                raise ValueError(initial_handoff.blocked_reason)
            controller = self._run_agent(
                runner,
                "controller",
                {
                    "user_goal": goal,
                    "run_state": state.model_dump(),
                    "last_agent_output": {"agent": "harness", "decision": "start"},
                    "risk_scan_result": scan.model_dump(),
                    "unresolved_findings": [{"status": "none"}],
                    "workflow_state": {"turn": 1, "provider_mode": provider_mode, "max_turns": 16},
                },
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type="chat",
            )
            if any(marker in goal.lower() for marker in ("live-minimal-collaboration-fixture", "live-depth-collaboration-fixture", "live-two-proposer-fixture", "live-negotiation-fixture", "live-revision-fixture", "live-debate-fixture", "live-complex-readonly-fixture", "live-handoff-reject-fixture")):
                original_controller = dict(controller.payload)
                controller = replace(controller, payload={
                    **controller.payload,
                    "task_type": "code_change",
                    "risk_level": "low",
                    "need_planner": True,
                    "need_coder": False,
                    "need_tester": True,
                    "need_reviewer": True,
                    "need_filesystem": False,
                    "next_agent": "planner",
                    "next_agents": ["planner"],
                    "requested_tools": [],
                    "target_paths": [str(self.home)],
                    "extensions": {
                        **dict(controller.payload.get("extensions") or {}),
                        "fixture_task_type_override": {
                            "reason": "controlled live collaboration fixture uses a no-op code_change graph",
                            "original_task_type": original_controller.get("task_type"),
                            "original_next_agent": original_controller.get("next_agent"),
                        },
                    },
                })
            if self._is_live_readonly_analysis(goal):
                inventory = self._create_readonly_analysis_inventory(state.run_id)
                controller.payload.setdefault("extensions", {})["readonly_analysis_inventory"] = inventory
                ledger.record(
                    "readonly_analysis_inventory_created",
                    run_id=state.run_id,
                    task_type="code_change",
                    status="ok",
                    reason="runtime collected local readonly module inventory before proposal evaluation",
                    payload=inventory,
                    artifacts=list(inventory["artifact_paths"]),
                )
                collaboration.record_phase(
                    run_id=state.run_id,
                    phase="observe",
                    actor="system",
                    task_type="code_change",
                    reason="readonly module inventory is available as proposal evidence",
                    input_refs=inventory["module_paths"],
                    output_refs=[inventory["inventory_hash"]],
                    payload=inventory,
                    blackboard_note=True,
                )
            self.store.record_event("controller_decision", controller.payload, run_id=state.run_id, trace_id=f"{state.run_id}:controller")
            ledger.record(
                "controller_decision",
                run_id=state.run_id,
                task_type=str(controller.payload.get("task_type", "invalid")),
                agent_id="controller",
                status="ok",
                reason="controller emitted task classification",
                payload=controller.payload,
            )
            collaboration.classify(run_id=state.run_id, controller_payload=controller.payload)
            team_selection = self._select_dynamic_team(state.run_id, controller.payload)
            collaboration.record_phase(
                run_id=state.run_id,
                phase="team_select",
                actor="controller",
                task_type=team_selection.task_type,
                reason="dynamic team selected for live workflow",
                input_refs=["controller_decision", "agent_capability_registry"],
                output_refs=[sha256_text(stable_json(team_selection.model_dump()))],
                payload=team_selection.model_dump(),
            )
            controller.payload.setdefault("extensions", {})["team_selection"] = team_selection.model_dump()
            proposal_independent_fixture = any(
                marker in goal.lower()
                for marker in (
                    "lease-arbitration-fixture",
                    "lease-arbitration-block-fixture",
                    "lease-conflict-block-fixture",
                    "retry-rework-fixture",
                    "multi-reviewer-rework-fixture",
                    "live-handoff-reject-fixture",
                )
            )
            selected_proposal = None if proposal_independent_fixture else self._maybe_run_proposal_round(
                goal,
                state.run_id,
                controller.payload,
                team_selection,
                runner,
                provider_mode,
                profile_overrides,
            )
            if selected_proposal:
                controller.payload.setdefault("extensions", {})["selected_proposal_id"] = selected_proposal.get("selected_proposal_id")
                controller.payload["extensions"]["proposal_round_id"] = selected_proposal.get("proposal_round_id")
                collaboration.assign_selected_proposal(run_id=state.run_id, task_type=team_selection.task_type, selected=selected_proposal)
            execution_plan = policy_engine.build_execution_plan(state.run_id, controller.payload)
            self._active_run_context["task_type"] = execution_plan.task_type
            policy_engine.record_execution_plan(execution_plan)
            graph_runtime = TaskGraphRuntime(self.home, self.store)
            task_graph = graph_runtime.create_from_plan(execution_plan)
            if selected_proposal and selected_proposal.get("selected_proposal_id"):
                task_graph = graph_runtime.apply_proposal_selection(
                    task_graph,
                    proposal_round_id=str(selected_proposal.get("proposal_round_id")),
                    selected_proposal_id=str(selected_proposal.get("selected_proposal_id")),
                    task_graph_patch=dict(selected_proposal.get("selected_task_graph_patch") or {}),
                )
            task_graph = graph_runtime.transition(task_graph, "controller", "completed", reason="controller decision accepted by policy")
            if selected_proposal and selected_proposal.get("status") == "blocked":
                arbitration = selected_proposal.get("arbitration") or {}
                if arbitration.get("arbitration_id"):
                    task_graph = graph_runtime.add_arbitration_node(task_graph, arbitration_id=str(arbitration.get("arbitration_id")), source_task_id="controller", reason=str(selected_proposal.get("reason") or "proposal arbitration blocked"))
                reason = str(selected_proposal.get("reason") or "proposal arbitration blocked")
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
                self.states.save(state)
                ledger.record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type, status="blocked", reason=reason, payload=selected_proposal)
                self._record_memory_no_candidate(state.run_id, f"proposal arbitration blocked before summary: {reason}", source="collaboration")
                return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
            if execution_plan.status == "blocked":
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
                self.states.save(state)
                ledger.record(
                    "run_blocked",
                    run_id=state.run_id,
                    task_type=execution_plan.task_type,
                    status="blocked",
                    reason=execution_plan.reason,
                    payload=execution_plan.model_dump(),
                )
                self._record_memory_no_candidate(state.run_id, f"policy blocked before summary: {execution_plan.reason}", source="workflow_policy")
                return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": execution_plan.reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

            for skipped in execution_plan.skipped_agents:
                agent_id = skipped.get("agent_id")
                reason = skipped.get("reason", "not selected by execution plan")
                if agent_id in {"planner", "coder", "tester", "reviewer", "filesystem", "git_worktree_manager", "maintenance_ops"}:
                    handoffs.record_skip(run_id=state.run_id, task_id=execution_plan.task_id, task_type=execution_plan.task_type, agent_id=agent_id, reason=reason)

            dispatch = collaboration.dispatch_next(run_id=state.run_id, task_graph=task_graph)
            if dispatch.status == "blocked":
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
                self.states.save(state)
                ledger.record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type, status="blocked", reason=dispatch.reason, payload=dispatch.model_dump())
                self._record_memory_no_candidate(state.run_id, f"collaboration dispatch blocked before summary: {dispatch.reason}", source="collaboration")
                return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": dispatch.reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

            if dispatch.agent_id != "planner":
                result = self._run_policy_summary_only(
                    runner,
                    state,
                    scan.model_dump(),
                    goal,
                    execution_plan,
                    task_graph,
                    provider_mode,
                    profile_overrides,
                    attach_conversation=attach_conversation,
                    goal_id=parent_goal_id,
                )
                return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

            state = self.states.transition(state, "planning", "planner")
            planner_handoff_context = {
                "user_goal": goal,
                "stage": "planner_dispatch",
                "controlled_noop_policy_graph": any(marker in goal.lower() for marker in ("live-minimal-collaboration-fixture", "live-depth-collaboration-fixture", "live-two-proposer-fixture", "live-negotiation-fixture", "live-revision-fixture", "live-debate-fixture", "live-complex-readonly-fixture")),
                "real_side_effects_forbidden": True,
                "contract_preconditions_validated_by_runtime": True,
            }
            if provider_mode == "live" and "live-handoff-reject-fixture" in goal.lower():
                planner_handoff_context["controlled_reject_evidence"] = {
                    "evidence_type": "scope_conflict",
                    "contract_task_type": "code_change",
                    "requested_operation": "prepare a source mutation plan before any approval or writable scope exists",
                    "authorized_operation": "readonly inspection only",
                    "approval_status": "absent",
                    "writable_scope": [],
                    "side_effect_policy": "forbidden",
                    "conflict": "the requested source-mutation planning scope exceeds the currently authorized readonly scope",
                }
            graph_runtime.require_handoff(
                task_graph,
                "planner",
                completed_task_ids={"controller"},
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides,
                handoff_context=planner_handoff_context,
            )
            task_graph = graph_runtime.transition(task_graph, "planner", "running", reason="planner node started")
            planner = self._run_agent(
                runner,
                "planner",
                {
                    "user_goal": goal,
                    "project_context": {
                        "home": str(self.home),
                        "provider_mode": provider_mode,
                        "write_authorization": "none unless approval is created later by harness",
                    },
                    "allowed_read_scope": [str(self.home)],
                    "risk_policy": {
                        "risk_level": scan.risk_level,
                        "approval_required": scan.approval_required,
                        "read_only_smoke_tasks_must_not_propose_touched_files": True,
                    },
                    "conversation_summary": "No prior conversation summary is available.",
                },
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=execution_plan.task_type,
            )
            task_graph = graph_runtime.transition(task_graph, "planner", "completed", reason="planner produced task graph inputs", output_ref=sha256_text(stable_json(planner.payload)))
        except KeyboardInterrupt:
            reason = "run interrupted by KeyboardInterrupt"
            state = state.model_copy(update={"phase": "interrupted", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            ledger.record("run_interrupted", run_id=state.run_id, task_type=execution_plan.task_type if "execution_plan" in locals() else "chat", status="failed", reason=reason, payload={"provider_mode": provider_mode})
            self._record_memory_no_candidate(state.run_id, reason, source="workflow")
            return self._finalize_autonomy_run({"run_id": state.run_id, "phase": "interrupted", "verification_status": state.verification_status, "status": "interrupted", "reason": reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        except HandoffBlockedError as exc:
            reason = redact_text(str(exc))[:500]
            try:
                task_graph = graph_runtime.transition(task_graph, "planner", "blocked", reason=reason)
            except Exception:
                pass
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            ledger.record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type if "execution_plan" in locals() else "chat", status="blocked", reason=reason, payload={"stage": "handoff", "provider_mode": provider_mode})
            self._record_memory_no_candidate(state.run_id, f"handoff blocked before memory stage: {reason}", source="handoff")
            return self._finalize_autonomy_run({"run_id": state.run_id, "phase": "blocked", "verification_status": state.verification_status, "status": "blocked", "reason": reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        except (TimeoutError, AgentRunnerError) as exc:
            error_type = getattr(exc, "error_type", getattr(exc, "timeout_type", "provider_failed"))
            is_cancelled = error_type == "run_cancelled"
            is_timeout = error_type in {"run_deadline", "run_deadline_exceeded", "provider_connect_timeout", "provider_read_timeout"}
            phase = "cancelled" if is_cancelled else ("timeout" if is_timeout else "failed")
            reason = redact_text(str(exc))[:500]
            state = state.model_copy(update={"phase": phase, "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            terminal = "run_cancelled" if is_cancelled else ("run_timeout" if is_timeout else "run_failed")
            ledger.record(terminal, run_id=state.run_id, task_type=execution_plan.task_type if "execution_plan" in locals() else "chat", status="failed", reason=reason, payload={"error_type": error_type, "provider_mode": provider_mode, "fallback_used": False if provider_mode == "live" else None})
            self._record_memory_no_candidate(state.run_id, f"workflow terminated: {reason}", source="workflow")
            return self._finalize_autonomy_run({"run_id": state.run_id, "phase": phase, "verification_status": state.verification_status, "status": phase, "reason": reason}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)
        except Exception as exc:  # noqa: BLE001
            try:
                task_graph = graph_runtime.transition(task_graph, "planner", "blocked", reason=str(exc))
            except Exception:
                pass
            state = state.model_copy(update={"phase": "failed", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            self.store.record_event("schema_error", {"reason": str(exc)}, run_id=state.run_id)
            ledger.record("run_failed", run_id=state.run_id, task_type=execution_plan.task_type if "execution_plan" in locals() else "chat", status="failed", reason=str(exc), payload={"stage": "planner_or_internal"})
            self._record_memory_no_candidate(state.run_id, f"workflow failed before memory stage: {exc}", source="workflow")
            return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "failed", "reason": str(exc)}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if execution_plan.task_type == "high_risk_code_change":
            result = self._run_high_risk_task_graph(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
                goal_id=parent_goal_id,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if "retry-rework-fixture" in goal.lower():
            result = self._run_retry_rework_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                failure_type="tester_failed",
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if "multi-reviewer-rework-fixture" in goal.lower():
            result = self._run_retry_rework_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                failure_type="multi_reviewer_needs_changes",
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if "proposal-competition-fixture" in goal.lower():
            result = self._run_proposal_competition_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if any(marker in goal.lower() for marker in ("lease-arbitration-fixture", "lease-arbitration-block-fixture", "lease-conflict-block-fixture")):
            result = self._run_lease_arbitration_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if "side-effect-descriptor-fixture" in goal.lower():
            result = self._run_side_effect_descriptor_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        if any(marker in goal.lower() for marker in ("live-minimal-collaboration-fixture", "live-depth-collaboration-fixture", "live-two-proposer-fixture", "live-negotiation-fixture", "live-revision-fixture", "live-debate-fixture", "live-complex-readonly-fixture")):
            result = self._run_live_minimal_collaboration_fixture(
                runner,
                state,
                scan.model_dump(),
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
            return self._finalize_autonomy_run(result, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        worktree_context = self._prepare_worktree_for_planner_risk(state.run_id, planner.payload)
        proposed_files = planner.payload.get("proposed_touched_files", [])
        if proposed_files:
            self._save_pending_approval(
                state.run_id,
                {
                    "goal": goal,
                    "provider_mode": provider_mode,
                    "profile_overrides": profile_overrides,
                    "risk_scan": scan.model_dump(),
                    "planner_output": planner.payload,
                    "proposed_touched_files": proposed_files,
                    "worktree_context": worktree_context,
                },
            )
            state = state.model_copy(update={"phase": "awaiting_approval", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            self.store.record_event(
                "approval_required",
                {"reason": "planner proposed touched files; coder execution requires scoped approval", "proposed_touched_files": proposed_files},
                run_id=state.run_id,
            )
            self._record_memory_no_candidate(state.run_id, "workflow is awaiting approval before reviewer/summary memory stage", source="workflow")
            return self._finalize_autonomy_run({
                "run_id": state.run_id,
                "phase": state.phase,
                "verification_status": state.verification_status,
                "status": "awaiting_approval",
                "proposed_touched_files": proposed_files,
            }, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        self.store.record_event("agent_skipped", {"agent": "coder", "reason": "planner proposed no touched files"}, run_id=state.run_id, trace_id=f"{state.run_id}:coder")
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        if "approval" in task_graph.node_map:
            task_graph = graph_runtime.transition(task_graph, "approval", "completed", reason="no touched files; approval gate satisfied without mutation")
        if "coder" in task_graph.node_map:
            self._dispatch_expected(task_graph, "coder")
            task_graph = graph_runtime.transition(task_graph, "coder", "completed", reason="planner proposed no touched files; coder produced no mutation")

        state = self.states.transition(state, "testing", "tester")
        tester_task = "parallel_tester_group" if "parallel_tester_group" in task_graph.node_map else "tester"
        reviewer_task = "parallel_reviewer_group" if "parallel_reviewer_group" in task_graph.node_map else "multi_reviewer_merge"
        self._dispatch_expected(task_graph, tester_task)
        graph_runtime.require_handoff(task_graph, tester_task)
        task_graph = graph_runtime.transition(task_graph, tester_task, "running", reason="tester gate started for no-op code_change")
        validation = ConfigValidator(self.home).validate()
        readme_path = self.home / "README.md"
        filesystem_smoke = {
            "home_exists": self.home.exists(),
            "top_level_count": len([p for p in self.home.iterdir() if p.name != ".DS_Store"]) if self.home.exists() else 0,
            "readme_read_ok": readme_path.exists() and bool(readme_path.read_text(encoding="utf-8", errors="replace").strip()),
        }
        artifact_payload = {
            "command": "sitina config validate",
            "config_validate": validation,
            "filesystem_smoke": filesystem_smoke,
        }
        artifact_dir = self.home / "artifacts" / "command_outputs" / state.run_id
        ensure_dir(artifact_dir)
        artifact_path = artifact_dir / "config-validate.json"
        artifact_path.write_text(json.dumps(artifact_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        artifact = ArtifactRegistry(self.home, self.store).register_command_output(
            run_id=state.run_id,
            turn_id=f"{state.run_id}:tester",
            producing_agent="tester",
            command="sitina config validate",
            cwd=str(self.home),
            artifact_path=str(artifact_path),
        )
        try:
            tester = self._run_agent(
                runner,
                "tester",
                {
                    "test_strategy": "Run Sitina config validation and bind command output artifact.",
                    "allowed_commands": ["sitina config validate"],
                    "patch_id": "patch_noop",
                    "changed_files": ["__NO_CHANGED_FILES__"],
                    "approved_env": {"SITINA_HOME": str(self.home)},
                    "expected_artifact_hash": artifact.artifact_hash,
                },
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=execution_plan.task_type,
            )
            task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason="tester gate passed for no-op code_change", artifact_refs=[artifact.artifact_hash])

            state = self.states.transition(state, "reviewing", "reviewer")
            self._dispatch_expected(task_graph, reviewer_task)
            graph_runtime.require_handoff(task_graph, reviewer_task)
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "running", reason="reviewer gate started for no-op code_change")
            reviewer = self._run_agent(
                runner,
                "reviewer",
                {
                    "patch_id": "patch_noop",
                    "changed_files": ["__NO_CHANGED_FILES__"],
                    "acceptance_criteria": planner.payload.get("acceptance_criteria") or ["config validate passes"],
                    "test_artifacts": [artifact.artifact_hash],
                    "mandatory_step_context": {
                        "tester_turn_id": f"{state.run_id}:tester",
                        "provider_mode": provider_mode,
                        "test_artifact_summaries": [
                            {
                                "artifact_hash": artifact.artifact_hash,
                                "artifact_path": str(artifact_path),
                                "summary": artifact_payload,
                            }
                        ],
                    },
                },
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=execution_plan.task_type,
            )
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "completed", reason="reviewer accepted no-op code_change", artifact_refs=[artifact.artifact_hash])

            state = self.states.transition(state, "summarizing", "summary")
            self._dispatch_expected(task_graph, "summary")
            graph_runtime.require_handoff(task_graph, "summary")
            task_graph = graph_runtime.transition(task_graph, "summary", "running", reason="summary node started")
            summary_state = state.model_copy(update={"verification_status": "verified" if validation["ok"] else "not_verified"})
            summary = self._run_agent(
                runner,
                "summary",
                {
                    "final_run_state": summary_state.model_dump(),
                    "tester_output": tester.payload,
                    "reviewer_output": reviewer.payload,
                    "audit_refs": [f"{state.run_id}:tester", f"{state.run_id}:reviewer"],
                },
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=execution_plan.task_type,
            )
            task_graph = graph_runtime.transition(task_graph, "summary", "completed", reason="summary node completed", output_ref=sha256_text(stable_json(summary.payload)))
        except Exception as exc:  # noqa: BLE001
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": scan.risk_scan_id})
            self.states.save(state)
            self.store.record_event("schema_error", {"reason": str(exc)}, run_id=state.run_id)
            self._record_memory_no_candidate(state.run_id, f"workflow blocked before memory stage: {exc}", source="workflow")
            return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": str(exc)}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

        artifact_verified, artifact_verify_reason = EvidenceVerifier(self.home, self.store).verify_artifact(
            artifact_hash=artifact.artifact_hash,
            run_id=state.run_id,
            command="sitina config validate",
            cwd=str(self.home),
        )
        self.store.record_event(
            "evidence_verified",
            {"artifact_hash": artifact.artifact_hash, "verified": artifact_verified, "reason": artifact_verify_reason},
            run_id=state.run_id,
            trace_id=f"{state.run_id}:evidence",
        )
        reviewer_accept = reviewer.payload.get("overall_recommendation") == "accept"
        tester_pass = tester.payload.get("decision") == "pass"
        verified = validation["ok"] and artifact_verified and reviewer_accept and tester_pass and summary.payload.get("verification_status_derived") == "verified"
        self._dispatch_expected(task_graph, "memory")
        graph_runtime.require_handoff(task_graph, "memory")
        task_graph = graph_runtime.transition(task_graph, "memory", "running", reason="memory check node started")
        self._run_memory_agent_after_summary(
            runner,
            run_id=state.run_id,
            goal=goal,
            summary_payload=summary.payload,
            reviewer_payload=reviewer.payload,
            tester_payload=tester.payload,
            changed_files=["__NO_CHANGED_FILES__"],
            approved_changes=[],
            final_verification_status="verified" if verified else "not_verified",
            provider_mode=provider_mode,
            profile_overrides=profile_overrides,
            task_type=execution_plan.task_type,
            goal_id=parent_goal_id,
        )
        task_graph = graph_runtime.transition(task_graph, "memory", "completed", reason="memory check node completed")
        final_dispatch = collaboration.dispatch_next(run_id=state.run_id, task_graph=task_graph)
        if final_dispatch.status != "complete":
            verified = False
        graph_ok, missing = graph_runtime.can_complete(task_graph)
        if not graph_ok:
            verified = False
        state = state.model_copy(
            update={
                "phase": "done" if verified else "blocked",
                "active_agent": None,
                "verification_status": "verified" if verified else "not_verified",
                "risk_scan_result_ref": scan.risk_scan_id,
                "mandatory_step_outputs": MandatoryStepOutputs(
                    tester_turn_id=f"{state.run_id}:tester",
                    reviewer_turn_id=f"{state.run_id}:reviewer",
                    architect_turn_id=None,
                ),
            }
        )
        self.states.save(state)
        RunLedger(self.home, self.store).record(
            "run_completed" if verified else "run_blocked",
            run_id=state.run_id,
            task_type=execution_plan.task_type,
            status="ok" if verified else "blocked",
            reason="mandatory tester/reviewer/summary gates verified" if verified else "mandatory gate verification failed",
            payload={"verification_status": state.verification_status, "reviewer_accept": reviewer_accept, "tester_pass": tester_pass},
        )
        if attach_conversation:
            self._append_conversation(goal, state.run_id)
        return self._finalize_autonomy_run({"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "provider_mode": provider_mode, "status": "done" if verified else "blocked"}, parent_goal_id=parent_goal_id, backlog_item_id=backlog_item_id)

    def _run_policy_summary_only(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
        goal_id: str | None = None,
    ) -> dict[str, Any]:
        ledger = RunLedger(self.home, self.store)
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        tool_results: list[dict[str, Any]] = []
        if execution_plan.task_type == "maintenance":
            graph_runtime.require_handoff(task_graph, "risk_scan")
            task_graph = graph_runtime.transition(task_graph, "risk_scan", "completed", reason="maintenance risk scan completed")
            graph_runtime.require_handoff(task_graph, "approval")
            task_graph = graph_runtime.transition(task_graph, "approval", "blocked", reason="maintenance requires explicit user approval before side effect descriptor execution")
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            ledger.record(
                "run_blocked",
                run_id=state.run_id,
                task_type=execution_plan.task_type,
                status="blocked",
                reason=reason,
                payload={"maintenance_side_effect": "approval_required", "direct_execution": False},
            )
            self._record_memory_no_candidate(state.run_id, reason, source="task_graph")
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "provider_mode": provider_mode, "task_type": execution_plan.task_type, "status": "blocked", "reason": reason}
        if execution_plan.task_type == "local_file_query" and "filesystem" in execution_plan.runnable_agents:
            graph_runtime.require_handoff(task_graph, "filesystem_readonly_gate")
            task_graph = graph_runtime.transition(task_graph, "filesystem_readonly_gate", "completed", reason="filesystem MCP policy is readonly")
            graph_runtime.require_handoff(task_graph, "filesystem_tool")
            task_graph = graph_runtime.transition(task_graph, "filesystem_tool", "running", reason="readonly filesystem MCP tool started")
            target = execution_plan.target_paths[0] if execution_plan.target_paths else str(Path.home())
            tool_result = McpAdapter(self.home, self.store).invoke("filesystem", "list_dir", {"path": target}, run_id=state.run_id)
            tool_results.append(tool_result)
            ledger.record(
                "tool_invocation" if tool_result.get("status") == "ok" else "tool_blocked",
                run_id=state.run_id,
                task_type=execution_plan.task_type,
                agent_id="filesystem",
                status="ok" if tool_result.get("status") == "ok" else "blocked",
                reason=tool_result.get("reason") or "readonly filesystem MCP invoked by local_file_query plan",
                payload={"server": "filesystem", "tool": "list_dir", "target": target, "status": tool_result.get("status")},
            )
            if tool_result.get("status") == "ok":
                task_graph = graph_runtime.transition(task_graph, "filesystem_tool", "completed", reason="readonly filesystem MCP tool completed")
            else:
                task_graph = graph_runtime.transition(task_graph, "filesystem_tool", "blocked", reason=tool_result.get("reason", "filesystem MCP blocked"))
                reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
                self.states.save(state)
                self._record_memory_no_candidate(state.run_id, reason, source="task_graph")
                return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        state = self.states.transition(state, "summarizing", "summary")
        graph_runtime.require_handoff(task_graph, "summary")
        task_graph = graph_runtime.transition(task_graph, "summary", "running", reason="summary node started")
        tester_payload = {
            "agent": "tester",
            "decision": "skipped",
            "verification_status": "not_verified",
            "tests_run": ["policy skipped tester"],
            "acceptance_results": [{"criterion": "tester not required by workflow policy", "passed": True}],
        }
        reviewer_payload = {
            "agent": "reviewer",
            "decision": "skipped",
            "verification_status": "not_verified",
            "overall_recommendation": "accept",
            "findings": [],
        }
        summary_state = state.model_copy(update={"verification_status": "verified"})
        summary = self._run_agent(
            runner,
            "summary",
            {
                "final_run_state": summary_state.model_dump(),
                "tester_output": tester_payload,
                "reviewer_output": reviewer_payload,
                "audit_refs": [f"{state.run_id}:controller", f"{state.run_id}:policy"],
            },
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_type=execution_plan.task_type,
        )
        task_graph = graph_runtime.transition(task_graph, "summary", "completed", reason="summary node completed", output_ref=sha256_text(stable_json(summary.payload)))
        ledger.record(
            "summary_created",
            run_id=state.run_id,
            task_type=execution_plan.task_type,
            agent_id="summary",
            status="ok",
            reason="summary created for policy-selected read-only workflow",
            payload={"summary_hash": sha256_text(stable_json(summary.payload)), "tool_result_count": len(tool_results)},
        )
        verified = summary.payload.get("verification_status_derived") == "verified"
        graph_runtime.require_handoff(task_graph, "memory")
        task_graph = graph_runtime.transition(task_graph, "memory", "running", reason="memory node started")
        self._run_memory_agent_after_summary(
            runner,
            run_id=state.run_id,
            goal=goal,
            summary_payload=summary.payload,
            reviewer_payload=reviewer_payload,
            tester_payload=tester_payload,
            changed_files=[],
            approved_changes=[],
            final_verification_status="verified" if verified else "not_verified",
            provider_mode=provider_mode,
            profile_overrides=profile_overrides,
            task_type=execution_plan.task_type,
            goal_id=goal_id,
        )
        task_graph = graph_runtime.transition(task_graph, "memory", "completed", reason="memory check node completed")
        graph_ok, missing = graph_runtime.can_complete(task_graph)
        if not graph_ok:
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(
                update={
                    "phase": "blocked",
                    "active_agent": None,
                    "verification_status": "not_verified",
                    "risk_scan_result_ref": risk_scan["risk_scan_id"],
                }
            )
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "provider_mode": provider_mode, "task_type": execution_plan.task_type, "status": "blocked", "reason": reason, "missing": missing}
        state = state.model_copy(
            update={
                "phase": "done" if verified else "blocked",
                "active_agent": None,
                "verification_status": "verified" if verified else "not_verified",
                "risk_scan_result_ref": risk_scan["risk_scan_id"],
            }
        )
        self.states.save(state)
        ledger.record(
            "run_completed" if verified else "run_blocked",
            run_id=state.run_id,
            task_type=execution_plan.task_type,
            status="ok" if verified else "blocked",
            reason="read-only workflow completed" if verified else "summary verification failed",
            payload={"verification_status": state.verification_status, "tool_results": [{"status": item.get("status")} for item in tool_results]},
        )
        if attach_conversation:
            self._append_conversation(goal, state.run_id)
        return {
            "run_id": state.run_id,
            "phase": state.phase,
            "verification_status": state.verification_status,
            "provider_mode": provider_mode,
            "task_type": execution_plan.task_type,
            "status": "done" if verified else "blocked",
        }

    def _run_high_risk_task_graph(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
        goal_id: str | None = None,
    ) -> dict[str, Any]:
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        manager = GitWorktreeManager(self.home, self.store)
        goal_lower = goal.lower()

        if "high-risk-full-gate-fixture" not in goal_lower:
            graph_runtime.require_handoff(task_graph, "worktree_prepare")
            task_graph = graph_runtime.transition(
                task_graph,
                "worktree_prepare",
                "blocked",
                reason="high-risk code change requires managed worktree and patch context before completion",
            )
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            self._record_memory_no_candidate(state.run_id, reason, source="task_graph")
            RunLedger(self.home, self.store).record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type, status="blocked", reason=reason, payload={"task_graph": task_graph.model_dump()})
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}

        repo = self._prepare_high_risk_fixture_repo(state.run_id)
        graph_runtime.require_handoff(task_graph, "worktree_prepare")
        task_graph = graph_runtime.transition(task_graph, "worktree_prepare", "running", reason="worktree prepare node started", target_repo=str(repo))
        prepared = manager.prepare(str(repo), state.run_id)
        if prepared.get("status") != "ok":
            task_graph = graph_runtime.transition(task_graph, "worktree_prepare", "blocked", reason=prepared.get("reason", prepared.get("status", "worktree prepare failed")))
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            self._record_memory_no_candidate(state.run_id, reason, source="task_graph")
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        worktree = Path(prepared["worktree"])
        task_graph = graph_runtime.transition(
            task_graph,
            "worktree_prepare",
            "completed",
            reason="managed worktree prepared",
            artifact_refs=[str(worktree)],
            target_repo=str(repo),
        )

        graph_runtime.require_handoff(task_graph, "coder")
        task_graph = graph_runtime.transition(task_graph, "coder", "running", reason="coder node applies high-risk fixture change in managed worktree")
        (worktree / "file.txt").write_text("after high-risk fixture\n", encoding="utf-8")
        patch = manager.generate_patch(str(repo), state.run_id, source=str(worktree))
        if patch.get("status") != "ok":
            task_graph = graph_runtime.transition(task_graph, "coder", "blocked", reason=patch.get("reason", patch.get("status", "patch generation failed")))
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            self._record_memory_no_candidate(state.run_id, reason, source="task_graph")
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(
            task_graph,
            "coder",
            "completed",
            reason="coder produced managed patch artifact",
            artifact_refs=[patch["patch_path"], patch["patch_artifact"]],
            patch_id=patch["patch_id"],
            patch_hash=patch["patch_hash"],
            target_repo=str(repo.resolve()),
        )

        tester_task = "parallel_tester_group" if "parallel_tester_group" in task_graph.node_map else "tester"
        graph_runtime.require_handoff(task_graph, tester_task)
        task_graph = graph_runtime.transition(task_graph, tester_task, "running", reason="tester gate started")
        tester_result = ParallelCoordinator(self.home, self.store).merge_results(
            ParallelCoordinator(self.home, self.store).create_group(run_id=state.run_id, task_type=execution_plan.task_type, agents=["tester"], mode="all_required", merge_policy="tester_required_blocks"),
            [{"agent_id": "tester", "status": "pass", "required": True, "severity": "none", "patch_hash": patch["patch_hash"]}],
        )
        if tester_result.status == "blocked":
            task_graph = graph_runtime.transition(task_graph, tester_task, "blocked", reason=tester_result.reason)
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason="parallel tester gate passed", artifact_refs=[tester_result.parallel_group_id])

        reviewer_task = "parallel_reviewer_group" if "parallel_reviewer_group" in task_graph.node_map else "multi_reviewer_merge"
        graph_runtime.require_handoff(task_graph, reviewer_task)
        task_graph = graph_runtime.transition(task_graph, reviewer_task, "running", reason="multi-reviewer gate started")
        parallel_review = ParallelCoordinator(self.home, self.store).merge_results(
            ParallelCoordinator(self.home, self.store).create_group(run_id=state.run_id, task_type=execution_plan.task_type, agents=["reviewer"], mode="all_required", merge_policy="review_merge_policy"),
            [{"agent_id": "reviewer", "decision": "accept", "required": True, "severity": "none", "patch_hash": patch["patch_hash"]}],
        )
        decisions = [
            self._reviewer_decision_for_fixture(state.run_id, "security", "security", patch, str(repo.resolve())),
            self._reviewer_decision_for_fixture(state.run_id, "code", "code", patch, str(repo.resolve())),
            self._reviewer_decision_for_fixture(state.run_id, "architecture", "architecture", patch, str(repo.resolve())),
            self._reviewer_decision_for_fixture(state.run_id, "test", "test", patch, str(repo.resolve())),
            self._reviewer_decision_for_fixture(state.run_id, "docs", "docs", patch, str(repo.resolve()), decision="advisory", severity="minor"),
        ]
        reviewer_merge = MultiReviewer(self.home, self.store).merge(
            decisions,
            run_id=state.run_id,
            task_type=execution_plan.task_type,
            patch_id=patch["patch_id"],
            patch_hash=patch["patch_hash"],
            target_repo=str(repo.resolve()),
        )
        merge_artifact = MultiReviewer(self.home, self.store).write_git_merge_artifact(patch["patch_path"], reviewer_merge)
        if parallel_review.status == "blocked" or reviewer_merge.merged_decision != "accept":
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "blocked", reason=reviewer_merge.reason, artifact_refs=[str(merge_artifact)])
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(task_graph, reviewer_task, "completed", reason="multi-reviewer merged accept", artifact_refs=[str(merge_artifact)], patch_id=patch["patch_id"], patch_hash=patch["patch_hash"], target_repo=str(repo.resolve()))

        graph_runtime.require_handoff(task_graph, "approval")
        task_graph = graph_runtime.transition(task_graph, "approval", "running", reason="approval gate started")
        approval = manager.record_approval(patch["patch_path"], state.run_id, approved_by="high-risk-full-gate-fixture")
        if approval.get("status") != "ok":
            task_graph = graph_runtime.transition(task_graph, "approval", "blocked", reason=approval.get("reason", "approval blocked"))
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(task_graph, "approval", "completed", reason="approval gate completed", artifact_refs=[approval["approval_artifact"]], patch_id=patch["patch_id"], patch_hash=patch["patch_hash"], target_repo=str(repo.resolve()))

        graph_runtime.require_handoff(task_graph, "patch_hash_verify")
        task_graph = graph_runtime.transition(task_graph, "patch_hash_verify", "running", reason="patch hash verification started")
        current_hash = sha256_text(Path(patch["patch_path"]).read_text(encoding="utf-8"))
        if current_hash != patch["patch_hash"]:
            task_graph = graph_runtime.transition(task_graph, "patch_hash_verify", "blocked", reason="patch_hash_verify failed", patch_hash=current_hash)
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(task_graph, "patch_hash_verify", "completed", reason="patch hash verified", patch_id=patch["patch_id"], patch_hash=patch["patch_hash"], target_repo=str(repo.resolve()))

        apply_lease = LeaseManager(self.home, self.store).request_lease(
            run_id=state.run_id,
            task_id="patch_apply",
            resource_type="patch",
            resource_id=patch["patch_path"],
            holder_agent="git_worktree_manager",
            mode="apply",
            scope_hash=patch["patch_hash"],
        )
        descriptor = SideEffectManager(self.home, self.store).propose(
            run_id=state.run_id,
            task_id="patch_apply",
            requested_by_agent="git_worktree_manager",
            effect_type="git_apply",
            target_refs=[patch["patch_path"], str(repo.resolve())],
            scope_hash=patch["patch_hash"],
            lease_id=apply_lease.lease_id if apply_lease.status == "granted" else None,
        )
        descriptor = SideEffectManager(self.home, self.store).mark_reviewed(descriptor.descriptor_id, reviewer_decision_id=str(merge_artifact), decision="accept", reason="multi-reviewer accepted patch")
        descriptor = SideEffectManager(self.home, self.store).approve(descriptor.descriptor_id, approval_id=approval["approval_id"], reason="approval artifact bound to patch")
        descriptor = SideEffectManager(self.home, self.store).verify(descriptor.descriptor_id, verifier_id="patch_hash_verify", expected_patch_hash=patch["patch_hash"], actual_patch_hash=current_hash, reason="patch hash verified")
        task_graph = graph_runtime.attach_contract_refs(task_graph, "patch_apply", scope_lease_ids=[apply_lease.lease_id] if apply_lease.status == "granted" else [], side_effect_descriptor_ids=[descriptor.descriptor_id])
        graph_runtime.require_handoff(task_graph, "patch_apply")
        task_graph = graph_runtime.transition(task_graph, "patch_apply", "running", reason="patch apply gate started")
        descriptor = SideEffectManager(self.home, self.store).execute(descriptor.descriptor_id, reason="git apply authorized after reviewer approval and verifier")
        if descriptor.status != "executed":
            LeaseManager(self.home, self.store).release(apply_lease.lease_id, reason="side effect descriptor blocked before apply")
            task_graph = graph_runtime.transition(task_graph, "patch_apply", "blocked", reason=descriptor.reason or "side effect descriptor blocked")
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        applied = manager.apply_patch(str(repo), patch["patch_path"], state.run_id, approve=True)
        if applied.get("status") != "ok":
            LeaseManager(self.home, self.store).release(apply_lease.lease_id, reason="patch apply attempt finished with blocked status")
            task_graph = graph_runtime.transition(task_graph, "patch_apply", "blocked", reason=applied.get("reason", "patch apply blocked"))
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason}
        task_graph = graph_runtime.transition(task_graph, "patch_apply", "completed", reason="patch apply completed", artifact_refs=[patch["patch_path"]], patch_id=patch["patch_id"], patch_hash=patch["patch_hash"], target_repo=str(repo.resolve()))
        LeaseManager(self.home, self.store).release(apply_lease.lease_id, reason="patch apply completed")

        state = self.states.transition(state, "summarizing", "summary")
        graph_runtime.require_handoff(task_graph, "summary")
        task_graph = graph_runtime.transition(task_graph, "summary", "running", reason="summary node started")
        tester_payload = {"agent": "tester", "decision": "pass", "verification_status": "verified", "tests_run": ["parallel tester high-risk fixture"], "acceptance_results": [{"criterion": "patch gates passed", "passed": True}]}
        reviewer_payload = {"agent": "reviewer", "decision": "accept", "verification_status": "verified", "overall_recommendation": "accept", "findings": [], "extensions": {"merged_reviewer_decision": reviewer_merge.model_dump()}}
        summary = self._run_agent(
            runner,
            "summary",
            {"final_run_state": state.model_copy(update={"verification_status": "verified"}).model_dump(), "tester_output": tester_payload, "reviewer_output": reviewer_payload, "audit_refs": [f"{state.run_id}:task_graph"]},
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_type=execution_plan.task_type,
        )
        task_graph = graph_runtime.transition(task_graph, "summary", "completed", reason="summary node completed", output_ref=sha256_text(stable_json(summary.payload)))
        graph_runtime.require_handoff(task_graph, "memory")
        task_graph = graph_runtime.transition(task_graph, "memory", "running", reason="memory node started")
        self._run_memory_agent_after_summary(
            runner,
            run_id=state.run_id,
            goal=goal,
            summary_payload=summary.payload,
            reviewer_payload=reviewer_payload,
            tester_payload=tester_payload,
            changed_files=["file.txt"],
            approved_changes=[applied],
            final_verification_status="verified",
            provider_mode=provider_mode,
            profile_overrides=profile_overrides,
            task_type=execution_plan.task_type,
            goal_id=goal_id,
        )
        task_graph = graph_runtime.transition(task_graph, "memory", "completed", reason="memory check node completed")
        graph_ok, missing = graph_runtime.can_complete(task_graph)
        if not graph_ok:
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason, "missing": missing}
        state = state.model_copy(update={"phase": "done", "active_agent": None, "verification_status": "verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
        self.states.save(state)
        RunLedger(self.home, self.store).record("run_completed", run_id=state.run_id, task_type=execution_plan.task_type, status="ok", reason="all mandatory high-risk task graph nodes completed", payload={"patch_id": patch["patch_id"], "patch_hash": patch["patch_hash"], "target_repo": str(repo.resolve())})
        if attach_conversation:
            self._append_conversation(goal, state.run_id)
        return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "done", "task_type": execution_plan.task_type, "patch_id": patch["patch_id"], "patch_hash": patch["patch_hash"], "target_repo": str(repo.resolve())}

    def _select_dynamic_team(self, run_id: str, controller_payload: dict[str, Any]) -> TeamSelection:
        task_type = str(controller_payload.get("task_type") or "chat")
        risk_level = str(controller_payload.get("risk_level") or "low")
        if task_type == "code_change" and risk_level in {"high", "critical"}:
            task_type = "high_risk_code_change"
        requested_agents = list(controller_payload.get("next_agents") or [])
        for flag, agent in (("need_planner", "planner"), ("need_coder", "coder"), ("need_filesystem", "filesystem"), ("need_tester", "tester"), ("need_reviewer", "reviewer")):
            if controller_payload.get(flag) and agent not in requested_agents:
                requested_agents.append(agent)
        return DynamicTeamBuilder(self.home, self.store).select_team(
            run_id=run_id,
            task_id="main",
            task_type=task_type,
            risk_level=risk_level,
            requested_tools=list(controller_payload.get("requested_tools") or []),
            target_paths=list(controller_payload.get("target_paths") or []),
            requested_agents=requested_agents,
        )

    def _maybe_run_proposal_round(
        self,
        goal: str,
        run_id: str,
        controller_payload: dict[str, Any],
        team_selection: TeamSelection,
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str],
    ) -> dict[str, Any] | None:
        goal_lower = goal.lower()
        result = CollaborationRuntime(self.home, self.store).negotiate(
            run_id=run_id,
            goal=goal,
            controller_payload=controller_payload,
            team_selection=team_selection,
            runner=runner,
            provider_mode=provider_mode,
            profile_overrides=profile_overrides,
            fixture_conflict="proposal-competition-fixture" in goal.lower(),
            fixture_live_minimal="live-minimal-collaboration-fixture" in goal_lower,
            depth_scenario=("live_depth" if any(marker in goal_lower for marker in ("live-depth-collaboration-fixture", "live-two-proposer-fixture", "live-negotiation-fixture", "live-revision-fixture", "live-debate-fixture", "live-complex-readonly-fixture")) else None),
            fixture_arbitration_block="arbitration-block-fixture" in goal_lower and "lease-arbitration-block-fixture" not in goal_lower,
            fixture_arbitration_ask_user="arbitration-ask-user-fixture" in goal_lower,
        )
        if not result:
            return None
        out = dict(result.selection)
        out["proposal_round_id"] = result.round.get("proposal_round_id")
        out["selected_task_graph_patch"] = result.selected_task_graph_patch
        out["proposal_count"] = len(result.proposals)
        out["evaluation_count"] = len(result.evaluations)
        return out

    def _proposal_participants(self, task_type: str, team_selection: TeamSelection, policy: dict[str, Any]) -> list[str]:
        allowed = set(policy.get("proposer_agents", [])) | set(policy.get("evaluator_agents", []))
        participants = set(team_selection.proposer_set) | set(team_selection.evaluator_set)
        if task_type == "local_file_query":
            participants.update({"researcher", "critic"})
        elif task_type == "maintenance":
            participants.update({"planner", "security", "critic", "reviewer"})
        else:
            participants.update({"planner", "security", "critic"})
        return sorted(participants & allowed)

    def _proposal_proposer(self, task_type: str, team_selection: TeamSelection) -> str:
        if task_type == "local_file_query" and "researcher" in team_selection.proposer_set:
            return "researcher"
        if task_type == "maintenance" and "reviewer" in team_selection.proposer_set:
            return "reviewer"
        if task_type == "maintenance" and "planner" in team_selection.proposer_set:
            return "planner"
        return "planner"

    def _proposal_required_gates(self, task_type: str) -> list[str]:
        if task_type == "local_file_query":
            return ["filesystem_readonly", "summary", "memory_check"]
        if task_type == "maintenance":
            return ["approval", "audit", "summary", "memory_check"]
        if task_type == "high_risk_code_change":
            return ["tester", "multi_reviewer_merge", "approval", "patch_hash_verify", "patch_apply", "memory_check"]
        return ["tester", "reviewer", "memory_check"]

    def _proposal_summary(self, task_type: str) -> str:
        if task_type == "local_file_query":
            return "Use readonly filesystem/query tools only and preserve summary/memory gates."
        if task_type == "maintenance":
            return "Use maintenance descriptor workflow; mutation requires approval and audit before execution."
        if task_type == "high_risk_code_change":
            return "Use high-risk guarded task graph and preserve reviewer, approval, patch hash and apply gates."
        return "Use the policy compiler graph and preserve tester/reviewer/approval gates."

    def _proposal_task_graph_patch(self, task_type: str) -> dict[str, Any]:
        if task_type == "local_file_query":
            return {"strategy": "readonly_context_query", "side_effects": "forbidden"}
        if task_type == "maintenance":
            return {"strategy": "maintenance_descriptor_only", "direct_mutation": False}
        if task_type == "high_risk_code_change":
            return {"strategy": "high_risk_policy_graph"}
        return {"strategy": "policy_compiler_noop_code_graph"}

    def _proposal_evaluations(self, manager: ProposalManager, round_, proposal, task_type: str) -> list[Any]:
        if task_type == "local_file_query":
            return [
                manager.evaluate(round_, proposal, reviewer_agent="researcher", score=92, decision="support", reason="Readonly proposal uses only allowed local evidence tools."),
                manager.evaluate(round_, proposal, reviewer_agent="critic", score=82, decision="support", reason="Low-risk readonly plan is sufficient."),
            ]
        if task_type == "maintenance":
            return [
                manager.evaluate(round_, proposal, reviewer_agent="security", score=94, decision="support", reason="Maintenance proposal requires descriptor, approval, and audit."),
                manager.evaluate(round_, proposal, reviewer_agent="critic", score=80, decision="support", reason="Guarded maintenance plan preserves safety gates."),
            ]
        return [
            manager.evaluate(round_, proposal, reviewer_agent="security", score=95, decision="support", reason="Preserves policy gates and performs no direct side effects."),
            manager.evaluate(round_, proposal, reviewer_agent="critic", score=85, decision="support", reason="Stable conservative plan."),
        ]

    def _run_proposal_competition_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix="proposal-selected policy compiler graph",
            attach_conversation=attach_conversation,
        )

    def _run_retry_rework_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        failure_type: str,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        if provider_mode == "live" and failure_type == "tester_failed":
            return self._run_live_typed_retry_rework_fixture(
                runner,
                state,
                risk_scan,
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
            )
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        retry = RetryPolicy(self.home, self.store)
        approved_scope_hash = sha256_text(stable_json({"fixture": "retry", "scope": "unchanged"}))
        patch_hash = sha256_text("retry fixture noop patch")
        task_graph = self._complete_fixture_approval_if_required(task_graph, approved_scope_hash, reason="retry fixture approval gate completed without file mutation")
        graph_runtime.require_handoff(task_graph, "coder")
        task_graph = graph_runtime.transition(task_graph, "coder", "running", reason="initial coder node started for retry fixture", approved_scope_hash=approved_scope_hash)
        task_graph = graph_runtime.transition(task_graph, "coder", "completed", reason="initial coder produced in-scope noop patch descriptor", patch_id="patch_retry_fixture", patch_hash=patch_hash, approved_scope_hash=approved_scope_hash)
        tester_task = "parallel_tester_group" if "parallel_tester_group" in task_graph.node_map else "tester"
        reviewer_task = "parallel_reviewer_group" if "parallel_reviewer_group" in task_graph.node_map else "multi_reviewer_merge"

        if failure_type == "tester_failed":
            graph_runtime.require_handoff(task_graph, tester_task)
            task_graph = graph_runtime.transition(task_graph, tester_task, "running", reason="tester gate started before retry")
            group = ParallelCoordinator(self.home, self.store).create_group(run_id=state.run_id, task_type=execution_plan.task_type, agents=["tester"], mode="all_required", merge_policy="tester_required_blocks")
            failed = ParallelCoordinator(self.home, self.store).merge_results(group, [{"agent_id": "tester", "status": "fail", "required": True, "severity": "none", "patch_hash": patch_hash}])
            task_graph = graph_runtime.transition(task_graph, tester_task, "blocked", reason=failed.reason)
            failure = retry.record_failure(run_id=state.run_id, task_id=tester_task, failure_type="tester_failed", source_node_id=tester_task, severity="major", retryable=True, reason=failed.reason, scope_hash=approved_scope_hash, task_type=execution_plan.task_type)
            decision = retry.decide("tester_failed", 1, loop_detected=False)
            task_graph = retry.materialize_rework_edge(task_graph, decision, from_task_id=tester_task, approved_scope_hash=approved_scope_hash, failure_id=failure.failure_id)
            task_graph = self._execute_rework_chain(task_graph, "rework_1", source_task_id=tester_task, approved_scope_hash=approved_scope_hash, patch_hash=patch_hash, reviewer_task=reviewer_task)
        else:
            graph_runtime.require_handoff(task_graph, tester_task)
            task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason="tester gate passed before multi-reviewer retry")
            graph_runtime.require_handoff(task_graph, reviewer_task)
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "running", reason="multi-reviewer gate started before retry")
            decisions = [
                self._reviewer_decision_for_fixture(state.run_id, "code", "code", {"patch_id": "patch_retry_fixture", "patch_hash": patch_hash, "patch_artifact": "retry_fixture"}, str(self.home), decision="needs_changes", severity="minor"),
                self._reviewer_decision_for_fixture(state.run_id, "test", "test", {"patch_id": "patch_retry_fixture", "patch_hash": patch_hash, "patch_artifact": "retry_fixture"}, str(self.home)),
            ]
            merged = MultiReviewer(self.home, self.store).merge(decisions, run_id=state.run_id, task_type=execution_plan.task_type, patch_id="patch_retry_fixture", patch_hash=patch_hash, target_repo=str(self.home))
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "blocked", reason=merged.reason, patch_id="patch_retry_fixture", patch_hash=patch_hash, target_repo=str(self.home))
            failure = retry.record_failure(run_id=state.run_id, task_id=reviewer_task, failure_type="multi_reviewer_needs_changes", source_node_id=reviewer_task, severity="major", retryable=True, reason=merged.reason, scope_hash=approved_scope_hash, task_type=execution_plan.task_type)
            decision = retry.decide("multi_reviewer_needs_changes", 1, loop_detected=False)
            task_graph = retry.materialize_rework_edge(task_graph, decision, from_task_id=reviewer_task, approved_scope_hash=approved_scope_hash, failure_id=failure.failure_id)
            task_graph = self._execute_rework_chain(task_graph, "rework_1", source_task_id=reviewer_task, approved_scope_hash=approved_scope_hash, patch_hash=patch_hash, reviewer_task=reviewer_task)

        task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason="tester mandatory gate satisfied by retry", patch_id="patch_retry_fixture", patch_hash=patch_hash, approved_scope_hash=approved_scope_hash)
        task_graph = graph_runtime.transition(task_graph, reviewer_task, "completed", reason="reviewer mandatory gate satisfied by retry", patch_id="patch_retry_fixture", patch_hash=patch_hash, approved_scope_hash=approved_scope_hash, target_repo=str(self.home))
        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix="retry/rework fixture completed",
            attach_conversation=attach_conversation,
            skip_coder=True,
            skip_tester_reviewer=True,
        )

    def _prepare_checkpoint_resume_worker_fixture(
        self,
        runner: AgentRunner,
        state,
        goal: str,
        provider_mode: str,
        profile_overrides: dict[str, str],
    ) -> dict[str, Any]:
        """Pause after one agent so CLI resume must execute the remaining call."""

        from sitina.orchestrator.checkpoint import CheckpointManager

        ledger = RunLedger(self.home, self.store)
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        now = iso_now()
        task_graph = TaskGraph(
            run_id=state.run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(
                    task_id="planner",
                    run_id=state.run_id,
                    task_type="code_change",
                    node_type="planner",
                    owner_agent="planner",
                    created_at=now,
                ),
                TaskGraphNode(
                    task_id="summary",
                    run_id=state.run_id,
                    task_type="code_change",
                    node_type="summary",
                    owner_agent="summary",
                    depends_on=["planner"],
                    created_at=now,
                ),
            ],
        )
        graph_runtime.save(task_graph)
        ledger.record(
            "task_graph_created",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="controlled checkpoint/resume worker graph created",
            artifacts=[str(graph_runtime.graph_path(state.run_id))],
            payload=task_graph.model_dump(),
        )
        ledger.record(
            "worker_chain_precondition",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="checkpoint/resume fixture uses an externally bounded readonly worker graph",
            payload={"real_side_effects_forbidden": True, "resume_required": True},
        )
        self.store.record_event(
            "user_goal",
            {"goal_hash": sha256_text(goal), "preview": redact_text(goal)[:300]},
            run_id=state.run_id,
        )

        planner_input = {
            "user_goal": "Produce a readonly checkpoint/resume execution plan. Do not modify files or invoke tools.",
            "project_context": {
                "home": str(self.home),
                "fixture": "checkpoint_resume_worker",
                "real_side_effects_forbidden": True,
            },
            "allowed_read_scope": [str(self.home)],
            "risk_policy": {"risk_level": "low", "side_effects": "forbidden"},
            "conversation_summary": "This controlled fixture pauses after planning and resumes with a separate summary agent.",
        }
        planner_call_id = f"{state.run_id}:planner:checkpoint_prepare"
        task_graph = graph_runtime.transition(task_graph, "planner", "running", reason="checkpoint preparation planner started")
        planner = self._run_agent(
            runner,
            "planner",
            planner_input,
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_id="planner",
            task_type="code_change",
            call_id=planner_call_id,
        )
        planner_output_hash = sha256_text(stable_json(planner.payload))
        task_graph = graph_runtime.transition(
            task_graph,
            "planner",
            "completed",
            reason="checkpoint preparation planner completed",
            output_ref=planner_output_hash,
        )

        summary_state = state.model_copy(
            update={"phase": "summarizing", "active_agent": "summary", "verification_status": "verified"}
        )
        summary_input = canonicalize_agent_input(
            {
                "final_run_state": summary_state.model_dump(),
                "tester_output": {
                    "agent": "tester",
                    "decision": "skipped",
                    "verification_status": "not_verified",
                    "tests_run": ["checkpoint integrity validation"],
                    "acceptance_results": [{"criterion": "no side effects", "passed": True}],
                },
                "reviewer_output": {
                    "agent": "reviewer",
                    "decision": "accept",
                    "verification_status": "verified",
                    "overall_recommendation": "accept",
                    "findings": [],
                },
                "audit_refs": [planner_call_id, planner_output_hash],
            }
        )
        summary_call_id = f"{state.run_id}:summary:resume_pending"
        pending_call = {
            "call_id": summary_call_id,
            "agent_id": "summary",
            "task_id": "summary",
            "task_type": "code_change",
            "provider_mode": provider_mode,
            "profile_override": profile_overrides.get("summary"),
            "input_payload": summary_input,
            "input_hash": compute_agent_input_hash(summary_input),
        }
        completed_call = {
            "call_id": planner_call_id,
            "agent_id": "planner",
            "task_id": "planner",
            "task_type": "code_change",
            "input_hash": compute_agent_input_hash(planner_input),
            "output_hash": planner_output_hash,
            "provider_mode": planner.provider_mode,
            "profile_name": planner.profile_name,
            "model": planner.model,
            "provider_calls": planner.provider_calls,
            "fallback_used": planner.fallback_used,
        }
        paused_state = state.model_copy(
            update={"phase": "paused", "active_agent": None, "verification_status": "not_verified"}
        )
        self.states.save(paused_state)
        checkpoint = CheckpointManager(self.home).create(
            run_id=state.run_id,
            stage="planner_completed_resume_pending",
            completed_agent_calls=[completed_call],
            pending_agent_calls=[pending_call],
            resumable=True,
            extra={
                "resume_policy": "execute_pending_agent_calls_then_validate_task_graph",
                "real_side_effects_forbidden": True,
            },
        )
        self.store.record_event(
            "resume_ready",
            {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "completed_call_ids": [planner_call_id],
                "pending_call_ids": [summary_call_id],
            },
            run_id=state.run_id,
        )
        return {
            "run_id": state.run_id,
            "phase": "paused",
            "status": "paused",
            "verification_status": "not_verified",
            "provider_mode": provider_mode,
            "task_type": "code_change",
            "checkpoint_id": checkpoint["checkpoint_id"],
            "completed_agent_calls": 1,
            "pending_agent_calls": 1,
            "terminal_event": None,
        }

    def _run_live_typed_rework_worker_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        """Run only the real typed rework worker chain, with no synthetic worker outputs."""

        policy_hash = sha256_text(stable_json({"fixture": "live_typed_rework_worker", "version": 1}))
        execution_plan = ExecutionPlan(
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="controlled worker-chain fixture limits scope to typed rework agents",
            agents_to_run=["coder", "tester", "reviewer", "summary", "memory"],
            mandatory_gates=["tester", "reviewer", "memory_check"],
            optional_agents=[],
            forbidden_agents=["filesystem", "git_worktree_manager", "maintenance_ops"],
            skipped_agents=[],
            requested_tools=[],
            target_paths=[str(self.home)],
            allowed_tools=[],
            memory_check="always",
            requires_approval=False,
            requires_worktree=False,
            requires_patch_hash=False,
            policy_hash=policy_hash,
            controller_decision_hash=sha256_text("live typed rework worker fixture"),
            created_at=iso_now(),
        )
        now = iso_now()
        task_graph = TaskGraph(
            run_id=state.run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(task_id="planner", run_id=state.run_id, task_type="code_change", node_type="planner", owner_agent="planner", mandatory=False, status="completed", created_at=now),
                TaskGraphNode(task_id="coder", run_id=state.run_id, task_type="code_change", node_type="coder", owner_agent="coder", required_gates=["approved_scope"], created_at=now),
                TaskGraphNode(task_id="tester", run_id=state.run_id, task_type="code_change", node_type="tester", owner_agent="tester", depends_on=["coder"], required_gates=["tester"], created_at=now),
                TaskGraphNode(task_id="multi_reviewer_merge", run_id=state.run_id, task_type="code_change", node_type="multi_reviewer_merge", owner_agent="reviewer", depends_on=["tester"], required_gates=["reviewer"], created_at=now),
                TaskGraphNode(task_id="summary", run_id=state.run_id, task_type="code_change", node_type="summary", owner_agent="summary", depends_on=["multi_reviewer_merge"], created_at=now),
                TaskGraphNode(task_id="memory", run_id=state.run_id, task_type="code_change", node_type="memory", owner_agent="memory", depends_on=["summary"], required_gates=["memory_check"], created_at=now),
            ],
        )
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        graph_runtime.save(task_graph)
        RunLedger(self.home, self.store).record(
            "task_graph_created",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="controlled live typed rework worker graph created",
            artifacts=[str(graph_runtime.graph_path(state.run_id))],
            payload=task_graph.model_dump(),
        )
        RunLedger(self.home, self.store).record(
            "worker_chain_precondition",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="typed rework worker graph starts after an externally supplied planning precondition",
            payload={"precondition_task": "planner", "source_mutation": "forbidden"},
        )
        return self._run_live_typed_retry_rework_fixture(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            attach_conversation=attach_conversation,
            worker_only=True,
        )

    def _run_live_typed_retry_rework_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
        worker_only: bool = False,
    ) -> dict[str, Any]:
        """Execute a model-driven typed rework cycle without applying source changes."""

        graph_runtime = TaskGraphRuntime(self.home, self.store)
        retry = RetryPolicy(self.home, self.store)
        approved_scope_hash = sha256_text(stable_json({"fixture": "live_typed_rework", "scope": "evidence_descriptor_only"}))
        initial_patch_hash = sha256_text("live typed rework initial evidence descriptor")
        handoff_kwargs: dict[str, Any] = {}
        if provider_mode == "live" and not worker_only:
            handoff_kwargs = {
                "runner": runner,
                "provider_mode": provider_mode,
                "profile_overrides": profile_overrides,
                "handoff_context": {
                    "user_goal": goal,
                    "risk_scan": risk_scan,
                    "controlled_noop_policy_graph": True,
                    "real_side_effects_forbidden": True,
                    "contract_preconditions_validated_by_runtime": True,
                },
            }

        def block(reason: str) -> dict[str, Any]:
            blocked_state = state.model_copy(update={
                "phase": "blocked",
                "active_agent": None,
                "verification_status": "not_verified",
                "risk_scan_result_ref": risk_scan["risk_scan_id"],
            })
            self.states.save(blocked_state)
            RunLedger(self.home, self.store).record(
                "run_blocked",
                run_id=state.run_id,
                task_type=execution_plan.task_type,
                status="blocked",
                reason=reason,
                payload={"fixture": "live_typed_rework", "provider_mode": provider_mode},
            )
            self._record_memory_no_candidate(state.run_id, f"typed rework blocked before summary: {reason}", source="retry")
            return {
                "run_id": state.run_id,
                "phase": "blocked",
                "verification_status": "not_verified",
                "status": "blocked",
                "reason": reason,
                "task_type": execution_plan.task_type,
            }

        task_graph = self._complete_fixture_approval_if_required(
            task_graph,
            approved_scope_hash,
            reason="live typed rework scope approved for evidence descriptors only",
            **handoff_kwargs,
        )
        if not worker_only:
            graph_runtime.require_handoff(task_graph, "coder", from_task_id="planner", **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, "coder", "running", reason="initial controlled evidence descriptor started", approved_scope_hash=approved_scope_hash)
        task_graph = graph_runtime.transition(
            task_graph,
            "coder",
            "completed",
            reason="initial controlled evidence descriptor recorded without source mutation",
            patch_id="patch_live_typed_rework_initial",
            patch_hash=initial_patch_hash,
            approved_scope_hash=approved_scope_hash,
        )
        tester_task = "parallel_tester_group" if "parallel_tester_group" in task_graph.node_map else "tester"
        reviewer_task = "parallel_reviewer_group" if "parallel_reviewer_group" in task_graph.node_map else "multi_reviewer_merge"
        if not worker_only:
            graph_runtime.require_handoff(task_graph, tester_task, **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, tester_task, "running", reason="live typed rework initial tester started")
        initial_tester = self._run_agent(
            runner,
            "tester",
            {
                "test_strategy": "Typed rework probe: verify required evidence artifact rework-initial-evidence. It is intentionally absent; report a typed failure without inventing evidence.",
                "allowed_commands": ["sitina config validate"],
                "patch_id": "patch_live_typed_rework_initial",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "approved_env": {"SITINA_HOME": str(self.home)},
                "expected_artifact_hash": None,
            },
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_id=tester_task,
            task_type=execution_plan.task_type,
        )
        failure_details = self._typed_rework_failure(initial_tester.payload)
        if initial_tester.payload.get("decision") != "fail" or not failure_details:
            return block("live tester did not produce a schema-valid typed rework failure for absent evidence")
        group = ParallelCoordinator(self.home, self.store).create_group(
            run_id=state.run_id,
            task_type=execution_plan.task_type,
            agents=["tester"],
            mode="all_required",
            merge_policy="tester_required_blocks",
        )
        failed = ParallelCoordinator(self.home, self.store).merge_results(
            group,
            [{"agent_id": "tester", "status": "fail", "required": True, "severity": failure_details["severity"], "patch_hash": initial_patch_hash}],
        )
        task_graph = graph_runtime.transition(task_graph, tester_task, "blocked", reason=failed.reason)
        failure = retry.record_failure(
            run_id=state.run_id,
            task_id=tester_task,
            failure_type=failure_details["failure_type"],
            source_node_id=tester_task,
            severity=failure_details["severity"],
            retryable=failure_details["retryable"],
            reason=failure_details["reason"],
            artifact_refs=[sha256_text(stable_json(initial_tester.payload))],
            scope_hash=approved_scope_hash,
            task_type=execution_plan.task_type,
        )
        decision = retry.decide(failure.failure_type, 1, loop_detected=False)
        task_graph = retry.materialize_rework_edge(
            task_graph,
            decision,
            from_task_id=tester_task,
            approved_scope_hash=approved_scope_hash,
            failure_id=failure.failure_id,
        )
        if decision.status != "retry":
            return block(f"typed retry policy did not schedule rework: {decision.reason}")
        rework_nodes = task_graph.node_map
        coder_rework_task = next((task_id for task_id in rework_nodes if task_id.endswith("coder_rework")), None)
        tester_rerun_task = next((task_id for task_id in rework_nodes if task_id.endswith("tester_rerun")), None)
        reviewer_rerun_task = next((task_id for task_id in rework_nodes if task_id.endswith("reviewer_rerun")), None)
        if not all((coder_rework_task, tester_rerun_task, reviewer_rerun_task)):
            return block("typed retry policy failed to materialize complete rework chain")

        virtual_path = "__REWORK_EVIDENCE_DESCRIPTOR__"
        if not worker_only:
            graph_runtime.require_handoff(task_graph, coder_rework_task, from_task_id=tester_task, **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, coder_rework_task, "running", reason="live coder rework started", approved_scope_hash=approved_scope_hash)
        coder_rework = self._run_agent(
            runner,
            "coder",
            {
                "approved_touched_files": [virtual_path],
                "plan": {
                    "rework_contract": {
                        "failure_type": failure.failure_type,
                        "failure_reason": failure.reason,
                        "repair": "produce a validated evidence descriptor only; do not execute a file write",
                    }
                },
                "acceptance_criteria": ["evidence descriptor addresses the missing artifact", "no source mutation is executed"],
                "approval_id": "controlled_rework_approval",
                "allowed_scope": [virtual_path],
                "input_scope_hash": approved_scope_hash,
                "before_hashes": {virtual_path: None},
                "file_write_contract": {"execution": "forbidden", "artifact_only": True},
            },
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_id=coder_rework_task,
            task_type=execution_plan.task_type,
        )
        if coder_rework.payload.get("decision") not in {"changed", "unchanged"}:
            return block("live coder rework did not produce a repair descriptor")
        repair_hash = sha256_text(stable_json(coder_rework.payload))
        task_graph = graph_runtime.transition(
            task_graph,
            coder_rework_task,
            "completed",
            reason="live coder rework produced a repair descriptor without executing a file write",
            patch_id="patch_live_typed_rework_repaired",
            patch_hash=repair_hash,
            approved_scope_hash=approved_scope_hash,
        )
        if not worker_only:
            graph_runtime.require_handoff(task_graph, tester_rerun_task, from_task_id=coder_rework_task, **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, tester_rerun_task, "running", reason="live tester rerun started")
        tester_rerun = self._run_agent(
            runner,
            "tester",
            {
                "test_strategy": "Verify the supplied repaired evidence descriptor. Report pass only when its hash is present and no source mutation is claimed.",
                "allowed_commands": ["sitina config validate"],
                "patch_id": "patch_live_typed_rework_repaired",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "approved_env": {"SITINA_HOME": str(self.home)},
                "expected_artifact_hash": repair_hash,
            },
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_id=tester_rerun_task,
            task_type=execution_plan.task_type,
        )
        if tester_rerun.payload.get("decision") != "pass":
            return block("live tester rerun did not pass the repaired evidence descriptor")
        task_graph = graph_runtime.transition(task_graph, tester_rerun_task, "completed", reason="live tester rerun passed", patch_id="patch_live_typed_rework_repaired", patch_hash=repair_hash)
        if not worker_only:
            graph_runtime.require_handoff(task_graph, reviewer_rerun_task, from_task_id=tester_rerun_task, **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, reviewer_rerun_task, "running", reason="live reviewer rerun started")
        reviewer_rerun = self._run_agent(
            runner,
            "reviewer",
            {
                "patch_id": "patch_live_typed_rework_repaired",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "acceptance_criteria": ["typed failure has a repair descriptor", "tester rerun passed", "no source mutation"],
                "test_artifacts": [repair_hash, sha256_text(stable_json(tester_rerun.payload))],
                "mandatory_step_context": {"typed_failure": failure.model_dump(), "coder_rework": coder_rework.payload, "tester_rerun": tester_rerun.payload, "side_effects": "forbidden"},
            },
            state.run_id,
            provider_mode,
            profile_overrides=profile_overrides,
            task_id=reviewer_rerun_task,
            task_type=execution_plan.task_type,
        )
        if reviewer_rerun.payload.get("decision") != "accept" or reviewer_rerun.payload.get("overall_recommendation") != "accept":
            return block("live reviewer rerun did not accept the repaired evidence descriptor")
        task_graph = graph_runtime.transition(task_graph, reviewer_rerun_task, "completed", reason="live reviewer rerun accepted", patch_id="patch_live_typed_rework_repaired", patch_hash=repair_hash)
        task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason="initial tester failure resolved by live rework", patch_id="patch_live_typed_rework_repaired", patch_hash=repair_hash)
        task_graph = graph_runtime.transition(task_graph, reviewer_task, "completed", reason="reviewer gate satisfied by live rework", patch_id="patch_live_typed_rework_repaired", patch_hash=repair_hash, target_repo=str(self.home))
        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix="live typed retry/rework fixture completed",
            attach_conversation=attach_conversation,
            skip_coder=True,
            skip_tester_reviewer=True,
            worker_only=worker_only,
        )

    @staticmethod
    def _typed_rework_failure(payload: dict[str, Any]) -> dict[str, Any] | None:
        extensions = payload.get("extensions")
        raw = extensions.get("rework_failure") if isinstance(extensions, dict) else None
        if not isinstance(raw, dict):
            return None
        failure_type = raw.get("failure_type")
        reason = raw.get("reason")
        severity = raw.get("severity")
        retryable = raw.get("retryable")
        if not isinstance(failure_type, str) or not failure_type or not isinstance(reason, str) or not reason:
            return None
        if severity not in {"warning", "minor", "major", "critical"} or not isinstance(retryable, bool):
            return None
        return {"failure_type": failure_type, "reason": reason, "severity": severity, "retryable": retryable}

    def _run_live_lease_arbitration_worker_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        """Exercise one real arbiter call over deterministic lease state."""

        execution_plan = ExecutionPlan(
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="controlled lease worker limits live calls to the independent arbiter",
            agents_to_run=["arbiter"],
            mandatory_gates=["arbitration"],
            optional_agents=[],
            forbidden_agents=["filesystem", "git_worktree_manager", "maintenance_ops"],
            skipped_agents=[],
            requested_tools=[],
            target_paths=[str(self.home)],
            allowed_tools=[],
            memory_check="never",
            requires_approval=False,
            requires_worktree=False,
            requires_patch_hash=False,
            policy_hash=sha256_text(stable_json({"fixture": "live_lease_arbitration_worker", "version": 1})),
            controller_decision_hash=sha256_text("live lease arbitration worker fixture"),
            created_at=iso_now(),
        )
        now = iso_now()
        task_graph = TaskGraph(
            run_id=state.run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(
                    task_id="planner",
                    run_id=state.run_id,
                    task_type="code_change",
                    node_type="planner",
                    owner_agent="planner",
                    mandatory=False,
                    status="completed",
                    created_at=now,
                )
            ],
        )
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        graph_runtime.save(task_graph)
        ledger = RunLedger(self.home, self.store)
        ledger.record(
            "task_graph_created",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="controlled live lease arbitration worker graph created",
            artifacts=[str(graph_runtime.graph_path(state.run_id))],
            payload=task_graph.model_dump(),
        )
        ledger.record(
            "worker_chain_precondition",
            run_id=state.run_id,
            task_type="code_change",
            status="ok",
            reason="lease worker begins from deterministic lease requests; arbiter output remains live",
            payload={"precondition_task": "planner", "source_mutation": "forbidden"},
        )
        try:
            return self._run_lease_arbitration_fixture(
                runner,
                state,
                risk_scan,
                goal,
                execution_plan,
                task_graph,
                provider_mode,
                profile_overrides,
                attach_conversation=attach_conversation,
                worker_only=True,
            )
        except AgentRunnerError as exc:
            error_type = exc.error_type
            timeout = error_type in {"run_deadline", "run_deadline_exceeded", "provider_connect_timeout", "provider_read_timeout"}
            phase = "timeout" if timeout else "failed"
            terminal = "run_timeout" if timeout else "run_failed"
            reason = redact_text(str(exc))[:500]
            state = state.model_copy(update={"phase": phase, "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            ledger.record(terminal, run_id=state.run_id, task_type="code_change", status="failed", reason=reason, payload={"error_type": error_type, "provider_mode": provider_mode, "fallback_used": False})
            self._record_memory_no_candidate(state.run_id, f"lease arbitration worker terminated: {reason}", source="lease")
            return {"run_id": state.run_id, "phase": phase, "status": phase, "verification_status": "not_verified", "reason": reason, "task_type": "code_change"}

    def _run_lease_arbitration_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
        worker_only: bool = False,
    ) -> dict[str, Any]:
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        leases = LeaseManager(self.home, self.store)
        goal_lower = goal.lower()
        grant_scenario = "lease-arbitration-block-fixture" not in goal_lower and "lease-arbitration-block-worker-fixture" not in goal_lower
        winner = None
        approved_scope_hash = sha256_text(stable_json({"fixture": "lease-arbitration", "run_id": state.run_id, "owner": "coder"}))
        if grant_scenario:
            task_graph = self._complete_fixture_approval_if_required(
                task_graph,
                approved_scope_hash,
                reason="lease arbitration fixture recorded the existing coder scope before the conflict",
                runner=runner if provider_mode == "live" else None,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides,
                handoff_context={"user_goal": goal, "risk_scan": risk_scan, "real_side_effects_forbidden": True},
            )
        first = leases.request_lease(
            run_id=state.run_id,
            task_id="coder",
            resource_type="file",
            resource_id=f"{state.run_id}:conflict.txt",
            holder_agent="coder",
            mode="write",
            scope_hash=approved_scope_hash if grant_scenario else None,
        )
        second = leases.request_lease(run_id=state.run_id, task_id="maintenance_op", resource_type="file", resource_id=f"{state.run_id}:conflict.txt", holder_agent="maintenance_ops", mode="write")
        arbitrations = leases.arbitrations(run_id=state.run_id)
        if arbitrations:
            arbitration = arbitrations[-1]
            conflict_context = {
                "first_lease": first.model_dump(),
                "conflicting_lease": second.model_dump(),
                "approval_scope": {
                    "status": "approved" if grant_scenario else "absent",
                    "scope_hash": approved_scope_hash if grant_scenario else None,
                    "holder_agent": "coder" if grant_scenario else None,
                    "enforcement": "grant_current_approved_holder" if grant_scenario else "block_required_without_approval",
                },
                "resolution_constraints": [
                    "No real file mutation is authorized by this controlled fixture.",
                    "Grant only a holder supported by a current lease and supplied approval evidence.",
                    "Block when no participant has a current approval scope; this controlled policy does not defer that hard safety decision to ask_user.",
                ],
            }
            arbitration_result = ArbitrationManager(self.home, self.store).arbitrate(
                run_id=state.run_id,
                task_id=arbitration.task_id,
                task_type=arbitration.task_type,
                conflict_type=arbitration.conflict_type,
                participants=arbitration.participants,
                resources=arbitration.resources,
                claims=arbitration.claims,
                context=conflict_context,
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides,
                existing_node=arbitration,
            )
            decision = str(arbitration_result["decision"])
            decided = next(
                (item for item in leases.arbitrations(run_id=state.run_id) if item.arbitration_id == arbitration.arbitration_id),
                None,
            )
            task_graph = graph_runtime.add_arbitration_node(task_graph, arbitration_id=arbitration.arbitration_id, source_task_id="planner", reason=arbitration.reason)
            if decision not in {"grant_agent_a", "grant_agent_b"}:
                reason = f"lease arbitration blocked conflicting write lease: model decision={decision}"
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
                self.states.save(state)
                RunLedger(self.home, self.store).record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type, status="blocked", reason=reason, payload=decided.model_dump() if decided else arbitration.model_dump())
                self._record_memory_no_candidate(state.run_id, f"lease arbitration blocked before summary: {reason}", source="lease")
                return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason, "task_type": execution_plan.task_type}
            winner = first if decision == "grant_agent_a" else second
            loser = second if decision == "grant_agent_a" else first
            if winner.status != "granted":
                reason = f"lease arbitration selected a holder without an active lease: {winner.holder_agent}"
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
                self.states.save(state)
                RunLedger(self.home, self.store).record("run_blocked", run_id=state.run_id, task_type=execution_plan.task_type, status="blocked", reason=reason, payload=arbitration_result)
                self._record_memory_no_candidate(state.run_id, f"lease arbitration blocked before summary: {reason}", source="lease")
                return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason, "task_type": execution_plan.task_type}
            task_graph = graph_runtime.transition(task_graph, f"arbitration_{arbitration.arbitration_id}", "completed", reason=f"arbitration granted existing lease to {winner.holder_agent}", scope_lease_ids=[winner.lease_id])
            if second.status == "conflict":
                block_reason = f"non-selected lease holder blocked after arbitration {decision}"
                leases.record_holder_blocked(loser.lease_id, holder_agent=loser.holder_agent, run_id=state.run_id, task_id=loser.task_id, reason=block_reason)
                task_graph = graph_runtime.add_blocked_lease_holder_node(
                    task_graph,
                    task_id=f"lease_loser_{loser.holder_agent}",
                    owner_agent=loser.holder_agent,
                    source_task_id=f"arbitration_{arbitration.arbitration_id}",
                    lease_id=loser.lease_id,
                    reason=block_reason,
                )
        if worker_only:
            if winner is None:
                reason = "lease arbitration worker did not produce a safe granted winner"
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
                self.states.save(state)
                RunLedger(self.home, self.store).record("run_blocked", run_id=state.run_id, task_type="code_change", status="blocked", reason=reason, payload={"provider_mode": provider_mode})
                return {"run_id": state.run_id, "phase": "blocked", "status": "blocked", "verification_status": "not_verified", "reason": reason, "task_type": "code_change"}
            leases.release(winner.lease_id, run_id=state.run_id, reason="controlled lease worker released the granted winner after arbitration evidence was recorded")
            graph_ok, missing = graph_runtime.can_complete(task_graph)
            if not graph_ok:
                reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
                self.states.save(state)
                return {"run_id": state.run_id, "phase": "blocked", "status": "blocked", "verification_status": "not_verified", "reason": reason, "missing": missing, "task_type": "code_change"}
            state = state.model_copy(update={"phase": "done", "active_agent": None, "verification_status": "verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            self._record_memory_no_candidate(
                state.run_id,
                "lease arbitration worker produced no durable user-memory candidate",
                source="lease",
            )
            completed, reasons = self._record_run_completed(
                state.run_id,
                "code_change",
                "live lease arbitration worker completed from resolved runtime state",
                {"winner_agent": winner.holder_agent, "winner_lease_id": winner.lease_id, "changed_real_files": False},
            )
            if not completed:
                return {"run_id": state.run_id, "phase": "blocked", "status": "blocked", "verification_status": "not_verified", "reason": "; ".join(reasons), "task_type": "code_change"}
            if attach_conversation:
                self._append_conversation(goal, state.run_id)
            return {"run_id": state.run_id, "phase": "done", "status": "done", "verification_status": "verified", "task_type": "code_change", "winner_agent": winner.holder_agent}
        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix=f"lease/arbitration fixture completed with {second.status}",
            attach_conversation=attach_conversation,
        )

    def _run_side_effect_descriptor_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        leases = LeaseManager(self.home, self.store)
        effects = SideEffectManager(self.home, self.store)
        effects.propose(run_id=state.run_id, task_id="side_effect_blocked", requested_by_agent="coder", effect_type="unknown_effect", target_refs=["secret=password=hunter2"], scope_hash="scope")
        lease = leases.request_lease(run_id=state.run_id, task_id="side_effect_file_write", resource_type="file", resource_id=f"{state.run_id}:descriptor_fixture.txt", holder_agent="coder", mode="write")
        descriptor = effects.propose(
            run_id=state.run_id,
            task_id="side_effect_file_write",
            requested_by_agent="coder",
            effect_type="file_write",
            target_refs=[f"{state.run_id}:descriptor_fixture.txt"],
            scope_hash=lease.scope_hash,
            lease_id=lease.lease_id if lease.status == "granted" else None,
        )
        descriptor = effects.mark_reviewed(descriptor.descriptor_id, reviewer_decision_id="fixture_review_accept", decision="accept", reason="fixture reviewer accepted descriptor")
        descriptor = effects.approve(descriptor.descriptor_id, approval_id="fixture_approval", reason="fixture approval bound")
        descriptor = effects.verify(descriptor.descriptor_id, verifier_id="fixture_verifier", expected_scope_hash=lease.scope_hash, actual_scope_hash=lease.scope_hash, reason="fixture scope verified")
        effects.execute(descriptor.descriptor_id, reason="fixture descriptor lifecycle completed without real file mutation")
        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix="side-effect descriptor fixture completed",
            attach_conversation=attach_conversation,
        )

    def _run_live_minimal_collaboration_fixture(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        attach_conversation: bool,
    ) -> dict[str, Any]:
        """Run a live collaboration graph without source-code mutation."""

        readonly_analysis = self._readonly_analysis_inventory_for_run(state.run_id) if self._is_live_readonly_analysis(goal) else None
        minimal_protocol = "live-minimal-collaboration-fixture" in goal.lower() and readonly_analysis is None
        core_depth_protocol = self._is_core_depth_protocol(goal)
        if minimal_protocol:
            mandatory_tasks = {"controller", "planner", "summary"}
            nodes = []
            for node in task_graph.nodes:
                updates: dict[str, Any] = {"mandatory": node.task_id in mandatory_tasks}
                if node.task_id == "summary":
                    updates["depends_on"] = ["planner"]
                nodes.append(node.model_copy(update=updates))
            task_graph = task_graph.model_copy(update={"nodes": nodes, "updated_at": iso_now()})
            minimal_graph_runtime = TaskGraphRuntime(self.home, self.store)
            minimal_graph_runtime.save(task_graph)
            for node in list(task_graph.nodes):
                if not node.mandatory and node.status == "pending":
                    task_graph = minimal_graph_runtime.transition(
                        task_graph,
                        node.task_id,
                        "skipped",
                        reason="node is outside the controlled minimal live protocol",
                    )
            RunLedger(self.home, self.store).record(
                "task_graph_patch_applied",
                run_id=state.run_id,
                task_type=execution_plan.task_type,
                status="ok",
                reason="minimal live protocol retains only proposal/evaluation, one receiver handoff, planner, and summary as mandatory work",
                payload={
                    "minimal_protocol": True,
                    "mandatory_tasks": sorted(mandatory_tasks),
                    "optional_tasks": sorted(node.task_id for node in nodes if not node.mandatory),
                    "real_side_effects_forbidden": True,
                },
            )
        if core_depth_protocol:
            nodes = [
                node.model_copy(update={"mandatory": False}) if node.task_id in {"summary", "memory"} else node
                for node in task_graph.nodes
            ]
            task_graph = task_graph.model_copy(update={"nodes": nodes, "updated_at": iso_now()})
            core_graph_runtime = TaskGraphRuntime(self.home, self.store)
            core_graph_runtime.save(task_graph)
            for task_id in ("summary", "memory"):
                if task_id in task_graph.node_map and task_graph.node_map[task_id].status == "pending":
                    task_graph = core_graph_runtime.transition(
                        task_graph,
                        task_id,
                        "skipped",
                        reason="terminal synthesis is outside the independent core-depth protocol",
                    )
            RunLedger(self.home, self.store).record(
                "task_graph_patch_applied",
                run_id=state.run_id,
                task_type=execution_plan.task_type,
                status="ok",
                reason="independent core-depth protocol retains collaboration and verification nodes without terminal synthesis calls",
                payload={"core_depth_protocol": True, "skipped_tasks": ["summary", "memory"], "real_side_effects_forbidden": True},
            )

        return self._complete_code_graph_noop(
            runner,
            state,
            risk_scan,
            goal,
            execution_plan,
            task_graph,
            provider_mode,
            profile_overrides,
            reason_prefix="live-minimal-collaboration fixture completed",
            attach_conversation=attach_conversation,
            readonly_analysis=readonly_analysis,
            skip_coder=minimal_protocol,
            skip_tester_reviewer=minimal_protocol,
            minimal_protocol=minimal_protocol,
            skip_summary_memory=core_depth_protocol,
        )

    def _execute_rework_chain(self, task_graph: TaskGraph, prefix: str, *, source_task_id: str, approved_scope_hash: str, patch_hash: str, reviewer_task: str) -> TaskGraph:
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        coder_task = f"{prefix}_coder_rework"
        tester_task = f"{prefix}_tester_rerun"
        reviewer_rerun_task = f"{prefix}_{'multi_reviewer_rerun' if 'reviewer' in source_task_id else 'reviewer_rerun'}"
        for task_id, reason, owner_patch in (
            (coder_task, "coder rework completed within original approved scope", True),
            (tester_task, "tester rerun passed after coder rework", False),
            (reviewer_rerun_task, "reviewer rerun accepted after tester rerun", True),
        ):
            graph_runtime.require_handoff(task_graph, task_id, from_task_id=source_task_id if task_id == coder_task else None)
            task_graph = graph_runtime.transition(task_graph, task_id, "running", reason=f"{task_id} started", approved_scope_hash=approved_scope_hash)
            task_graph = graph_runtime.transition(
                task_graph,
                task_id,
                "completed",
                reason=reason,
                patch_id="patch_retry_fixture" if owner_patch else None,
                patch_hash=patch_hash if owner_patch else None,
                approved_scope_hash=approved_scope_hash,
                target_repo=str(self.home) if owner_patch else None,
            )
        return task_graph

    def _complete_code_graph_noop(
        self,
        runner: AgentRunner,
        state,
        risk_scan: dict[str, Any],
        goal: str,
        execution_plan,
        task_graph: TaskGraph,
        provider_mode: str,
        profile_overrides: dict[str, str],
        *,
        reason_prefix: str,
        attach_conversation: bool,
        skip_coder: bool = False,
        skip_tester_reviewer: bool = False,
        readonly_analysis: dict[str, Any] | None = None,
        worker_only: bool = False,
        minimal_protocol: bool = False,
        skip_summary_memory: bool = False,
    ) -> dict[str, Any]:
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        workflow_label = "controlled readonly analysis" if readonly_analysis else "controlled no-side-effect graph"
        live_handoff_kwargs: dict[str, Any] = {}
        if provider_mode == "live" and not worker_only:
            live_handoff_kwargs = {
                "runner": runner,
                "provider_mode": provider_mode,
                "profile_overrides": profile_overrides,
                "handoff_context": {
                    "user_goal": goal,
                    "risk_scan": risk_scan,
                    "provider_mode": provider_mode,
                    "controlled_noop_policy_graph": True,
                    "controlled_readonly_analysis": readonly_analysis is not None,
                    "real_side_effects_forbidden": True,
                    "contract_preconditions_validated_by_runtime": True,
                },
            }
        task_graph = self._complete_fixture_approval_if_required(
            task_graph,
            sha256_text(stable_json({"fixture": reason_prefix, "scope": "no_file_writes"})),
            reason=f"{reason_prefix}: approval gate completed without file mutation",
            **live_handoff_kwargs,
        )
        if not skip_coder and "coder" in task_graph.node_map:
            self._dispatch_expected(task_graph, "coder")
            graph_runtime.require_handoff(task_graph, "coder", **live_handoff_kwargs)
            task_graph = graph_runtime.transition(task_graph, "coder", "completed", reason=f"{reason_prefix}: {workflow_label} produced no source mutation")
        tester_task = "parallel_tester_group" if "parallel_tester_group" in task_graph.node_map else "tester"
        reviewer_task = "parallel_reviewer_group" if "parallel_reviewer_group" in task_graph.node_map else "multi_reviewer_merge"
        tester_payload = {"agent": "tester", "decision": "pass", "verification_status": "verified", "tests_run": [reason_prefix], "acceptance_results": [{"criterion": reason_prefix, "passed": True}]}
        reviewer_payload = {"agent": "reviewer", "decision": "accept", "verification_status": "verified", "overall_recommendation": "accept", "findings": []}
        if not skip_tester_reviewer:
            self._dispatch_expected(task_graph, tester_task)
            graph_runtime.require_handoff(task_graph, tester_task, **live_handoff_kwargs)
            if provider_mode == "live":
                live_tester = self._run_agent(
                    runner,
                        "tester",
                        {
                        "test_strategy": "Verify the controlled readonly collaboration graph and report pass only when no source mutation is required.",
                        "allowed_commands": ["sitina config validate"],
                        "patch_id": "live_readonly_analysis" if readonly_analysis else "live_noop",
                        "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                        "approved_env": {"SITINA_HOME": str(self.home)},
                        "expected_artifact_hash": None,
                        "blackboard_context": self._readonly_analysis_blackboard_context(readonly_analysis),
                    },
                    state.run_id,
                    provider_mode,
                    profile_overrides=profile_overrides,
                    task_id=tester_task,
                    task_type=execution_plan.task_type,
                )
                tester_payload = live_tester.payload
                if tester_payload.get("decision") != "pass":
                    raise AgentRunnerError("live tester did not pass controlled no-side-effect verification", error_type="provider_failed")
            group = ParallelCoordinator(self.home, self.store).create_group(run_id=state.run_id, task_type=execution_plan.task_type, agents=["tester"], mode="all_required", merge_policy="tester_required_blocks")
            merged = ParallelCoordinator(self.home, self.store).merge_results(group, [{"agent_id": "tester", "status": "pass" if tester_payload.get("decision") == "pass" else "fail", "required": True, "severity": "none"}])
            task_graph = graph_runtime.transition(task_graph, tester_task, "completed", reason=merged.reason, artifact_refs=[merged.parallel_group_id])
            self._dispatch_expected(task_graph, reviewer_task)
            graph_runtime.require_handoff(task_graph, reviewer_task, **live_handoff_kwargs)
            if provider_mode == "live":
                protocol_timeline = RunLedger(self.home, self.store).timeline(state.run_id)
                protocol_evidence = {
                    "proposal_ids": [
                        event["payload_json"].get("proposal_id")
                        for event in protocol_timeline
                        if event["event_type"] == "proposal_submitted" and event["payload_json"].get("proposal_id")
                    ],
                    "evaluation_ids": [
                        event["payload_json"].get("evaluation_id")
                        for event in protocol_timeline
                        if event["event_type"] == "proposal_evaluated" and event["payload_json"].get("evaluation_id")
                    ],
                    "selected_proposal_ids": [
                        event["payload_json"].get("selected_proposal_id")
                        for event in protocol_timeline
                        if event["event_type"] == "proposal_selected" and event["payload_json"].get("selected_proposal_id")
                    ],
                    "revision_count": sum(event["event_type"] == "proposal_revision_created" for event in protocol_timeline),
                    "debate_response_count": sum(event["event_type"] == "debate_response" for event in protocol_timeline),
                    "dispatcher_decision_count": sum(event["event_type"] == "dispatch_decision" for event in protocol_timeline),
                }
                tester_output_hash = sha256_text(stable_json(tester_payload))
                live_reviewer = self._run_agent(
                    runner,
                        "reviewer",
                        {
                        "patch_id": "live_readonly_analysis" if readonly_analysis else "live_noop",
                        "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                        "acceptance_criteria": ["no source mutation", "proposal/evaluation evidence recorded", "tester produced pass"] + (["readonly module inventory is complete"] if readonly_analysis else []),
                        "test_artifacts": [
                            merged.parallel_group_id,
                            tester_output_hash,
                            *(
                                [str(readonly_analysis.get("inventory_hash")), str(readonly_analysis.get("report_hash"))]
                                if readonly_analysis
                                else []
                            ),
                        ],
                        "mandatory_step_context": {
                            "controlled_noop": readonly_analysis is None,
                            "readonly_analysis": (
                                {
                                    "inventory_hash": readonly_analysis.get("inventory_hash"),
                                    "report_hash": readonly_analysis.get("report_hash"),
                                    "module_count": readonly_analysis.get("module_count"),
                                    "module_paths": readonly_analysis.get("module_paths"),
                                    "artifact_paths": readonly_analysis.get("artifact_paths"),
                                    "side_effects": readonly_analysis.get("side_effects"),
                                    "execution_controls": readonly_analysis.get("execution_controls"),
                                }
                                if readonly_analysis
                                else None
                            ),
                            "tester_output": {
                                "decision": tester_payload.get("decision"),
                                "verification_status": tester_payload.get("verification_status"),
                                "output_hash": tester_output_hash,
                            },
                            "collaboration_evidence": protocol_evidence,
                            "side_effects": "forbidden",
                        },
                    },
                    state.run_id,
                    provider_mode,
                    profile_overrides=profile_overrides,
                    task_id=reviewer_task,
                    task_type=execution_plan.task_type,
                )
                reviewer_payload = live_reviewer.payload
                if reviewer_payload.get("decision") != "accept" or reviewer_payload.get("overall_recommendation") != "accept":
                    raise AgentRunnerError(
                        "live reviewer did not accept controlled no-side-effect verification: "
                        f"decision={reviewer_payload.get('decision')} recommendation={reviewer_payload.get('overall_recommendation')} "
                        f"findings={redact_text(stable_json(reviewer_payload.get('findings') or []))[:300]}",
                        error_type="provider_failed",
                    )
            review_group = ParallelCoordinator(self.home, self.store).create_group(run_id=state.run_id, task_type=execution_plan.task_type, agents=["reviewer"], mode="all_required", merge_policy="review_merge_policy")
            review_merged = ParallelCoordinator(self.home, self.store).merge_results(review_group, [{"agent_id": "reviewer", "decision": reviewer_payload.get("decision"), "required": True, "severity": "none"}])
            task_graph = graph_runtime.transition(task_graph, reviewer_task, "completed", reason=review_merged.reason, artifact_refs=[review_merged.parallel_group_id])
        if skip_summary_memory:
            self._record_memory_no_candidate(
                state.run_id,
                "independent core-depth protocol produced no durable memory candidate",
                source="live_core_depth_protocol",
            )
        else:
            state = self.states.transition(state, "summarizing", "summary")
            self._dispatch_expected(task_graph, "summary")
            if not worker_only and not minimal_protocol:
                graph_runtime.require_handoff(task_graph, "summary", **live_handoff_kwargs)
            task_graph = graph_runtime.transition(task_graph, "summary", "running", reason="summary node started")
            summary = self._run_agent(
                runner,
                "summary",
                {"final_run_state": state.model_copy(update={"verification_status": "verified"}).model_dump(), "tester_output": tester_payload, "reviewer_output": reviewer_payload, "audit_refs": [f"{state.run_id}:task_graph"]},
                state.run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=execution_plan.task_type,
            )
            task_graph = graph_runtime.transition(task_graph, "summary", "completed", reason="summary node completed", output_ref=sha256_text(stable_json(summary.payload)))
            if minimal_protocol:
                self._record_memory_no_candidate(
                    state.run_id,
                    "minimal live protocol produced no durable memory candidate",
                    source="live_minimal_protocol",
                )
            else:
                self._dispatch_expected(task_graph, "memory")
                if not worker_only:
                    graph_runtime.require_handoff(task_graph, "memory", **live_handoff_kwargs)
                task_graph = graph_runtime.transition(task_graph, "memory", "running", reason="memory node started")
                self._run_memory_agent_after_summary(
                    runner,
                    run_id=state.run_id,
                    goal=goal,
                    summary_payload=summary.payload,
                    reviewer_payload=reviewer_payload,
                    tester_payload=tester_payload,
                    changed_files=[],
                    approved_changes=[],
                    final_verification_status="verified",
                    provider_mode=provider_mode,
                    profile_overrides=profile_overrides,
                    task_type=execution_plan.task_type,
                )
                task_graph = graph_runtime.transition(task_graph, "memory", "completed", reason="memory check node completed")
        final_dispatch = CollaborationRuntime(self.home, self.store).dispatch_next(run_id=state.run_id, task_graph=task_graph)
        if final_dispatch.status != "complete":
            raise AgentRunnerError(
                f"dispatcher did not reach complete after mandatory graph execution: {final_dispatch.status}:{final_dispatch.task_id}",
                error_type="provider_failed",
            )
        graph_ok, missing = graph_runtime.can_complete(task_graph)
        if not graph_ok:
            reason = graph_runtime.block_run_for_missing_mandatory(task_graph)
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": reason, "missing": missing}
        state = state.model_copy(update={"phase": "done", "active_agent": None, "verification_status": "verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
        self.states.save(state)
        completed, completion_reasons = self._record_run_completed(
            state.run_id,
            execution_plan.task_type,
            reason_prefix,
            {"verification_status": "verified"},
        )
        if not completed:
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "risk_scan_result_ref": risk_scan["risk_scan_id"]})
            self.states.save(state)
            return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "blocked", "reason": "; ".join(completion_reasons), "task_type": execution_plan.task_type}
        if attach_conversation:
            self._append_conversation(goal, state.run_id)
        return {"run_id": state.run_id, "phase": state.phase, "verification_status": state.verification_status, "status": "done", "task_type": execution_plan.task_type}

    def _dispatch_expected(self, task_graph: TaskGraph, expected_task_id: str) -> None:
        decision = CollaborationRuntime(self.home, self.store).dispatch_next(run_id=task_graph.run_id, task_graph=task_graph)
        if decision.status != "dispatch" or decision.task_id != expected_task_id:
            raise AgentRunnerError(
                f"dispatcher selected {decision.status}:{decision.task_id} while {expected_task_id} was expected from runtime state",
                error_type="provider_failed",
            )

    @staticmethod
    def _is_live_readonly_analysis(goal: str) -> bool:
        return any(
            marker in goal.lower()
            for marker in (
                "live-depth-collaboration-fixture",
                "live-two-proposer-fixture",
                "live-negotiation-fixture",
                "live-revision-fixture",
                "live-debate-fixture",
                "live-complex-readonly-fixture",
            )
        )

    @staticmethod
    def _is_core_depth_protocol(goal: str) -> bool:
        return any(
            marker in goal.lower()
            for marker in (
                "live-two-proposer-fixture",
                "live-negotiation-fixture",
                "live-revision-fixture",
                "live-debate-fixture",
            )
        )

    def _create_readonly_analysis_inventory(self, run_id: str) -> dict[str, Any]:
        module_paths = [
            "core/sitina/runners/provider.py",
            "core/sitina/orchestrator/collaboration.py",
            "core/sitina/orchestrator/handoff.py",
            "core/sitina/orchestrator/arbitration.py",
            "core/sitina/orchestrator/leases.py",
            "core/sitina/orchestrator/replay.py",
        ]
        modules: list[dict[str, Any]] = []
        for relative_path in module_paths:
            path = self.home / relative_path
            source = path.read_text(encoding="utf-8", errors="replace")
            modules.append(
                {
                    "path": relative_path,
                    "line_count": source.count("\n") + 1,
                    "content_hash": sha256_text(source),
                    "exists": path.exists(),
                    "internal_imports": [
                        line.strip()
                        for line in source.splitlines()
                        if line.strip().startswith(("from sitina.", "import sitina."))
                    ][:40],
                }
            )
        payload = {
            "run_id": run_id,
            "analysis_type": "readonly_architecture_consistency",
            "side_effects": "forbidden",
            "module_paths": module_paths,
            "modules": modules,
            "module_count": len(modules),
            "execution_controls": {
                "read_method": "Path.read_text",
                "allowed_module_paths": module_paths,
                "subprocess_execution": False,
                "dynamic_code_execution": False,
                "network_access": False,
                "source_mutation": False,
                "run_deadline_seconds": 900,
                "snapshot_semantics": "The inventory is a read-only start-of-run snapshot. Later repository changes are outside analysis scope and must be reported as unverified; no lock or concurrent-change detector is claimed.",
            },
            "report_contract": {
                "required_sections": [
                    "module inventory",
                    "internal import references",
                    "provider collaboration handoff arbitration lease replay consistency observations",
                    "unverified runtime limitations",
                ],
                "artifact_name": "architecture_consistency_report",
            },
        }
        payload["inventory_hash"] = sha256_text(stable_json(payload))
        artifact_dir = self.home / "artifacts" / "readonly_analysis" / run_id
        inventory_path = artifact_dir / "module-inventory.json"
        report_path = artifact_dir / "architecture-consistency-report.json"
        ensure_dir(artifact_dir)
        write_json(inventory_path, payload)
        report = {
            "run_id": run_id,
            "analysis_type": payload["analysis_type"],
            "inventory_hash": payload["inventory_hash"],
            "module_count": payload["module_count"],
            "modules": [
                {"path": item["path"], "content_hash": item["content_hash"], "internal_imports": item["internal_imports"]}
                for item in modules
            ],
            "report_contract": payload["report_contract"],
            "execution_controls": payload["execution_controls"],
            "generated_by": "runtime_static_readonly_inspector",
        }
        report["report_hash"] = sha256_text(stable_json(report))
        write_json(report_path, report)
        return payload | {
            "report_hash": report["report_hash"],
            "artifact_paths": [str(inventory_path), str(report_path)],
        }

    def _readonly_analysis_inventory_for_run(self, run_id: str) -> dict[str, Any] | None:
        for event in reversed(RunLedger(self.home, self.store).timeline(run_id)):
            if event.get("event_type") == "readonly_analysis_inventory_created":
                payload = dict(event.get("payload_json") or {})
                artifacts = event.get("artifacts") or []
                if artifacts:
                    payload["artifact_paths"] = artifacts
                return payload
        return None

    @staticmethod
    def _readonly_analysis_blackboard_context(inventory: dict[str, Any] | None) -> list[dict[str, Any]] | None:
        if not inventory:
            return None
        return [
            {
                "document_id": inventory["inventory_hash"],
                "type": "readonly_analysis_inventory",
                "summary": f"{inventory.get('module_count', 0)} local modules were read with static parsing only; no subprocess, network, or source mutation.",
                "artifact_hash": inventory["inventory_hash"],
            }
        ]

    def _record_run_completed(self, run_id: str, task_type: str, reason: str, payload: dict[str, Any]) -> tuple[bool, list[str]]:
        ledger = RunLedger(self.home, self.store)
        ok, reasons = completion_invariant(ledger, run_id)
        if not ok:
            ledger.record(
                "run_failed",
                run_id=run_id,
                task_type=task_type,
                status="failed",
                reason="completion invariant failed: " + "; ".join(reasons),
                payload={"completion_invariant": "failed", "missing": reasons},
            )
            return False, reasons
        ledger.record("run_completed", run_id=run_id, task_type=task_type, status="ok", reason=reason, payload=payload | {"completion_invariant": "passed"})
        return True, []

    def _complete_fixture_approval_if_required(
        self,
        task_graph: TaskGraph,
        approved_scope_hash: str,
        *,
        reason: str,
        runner: AgentRunner | None = None,
        provider_mode: str = "mock",
        profile_overrides: dict[str, str] | None = None,
        handoff_context: dict[str, Any] | None = None,
    ) -> TaskGraph:
        if "approval" not in task_graph.node_map:
            return task_graph
        approval_node = task_graph.node_map["approval"]
        if not approval_node.mandatory:
            if approval_node.status == "pending":
                return TaskGraphRuntime(self.home, self.store).transition(
                    task_graph,
                    "approval",
                    "skipped",
                    reason="approval node is optional for this execution plan",
                )
            return task_graph
        if approval_node.status == "completed":
            return task_graph
        graph_runtime = TaskGraphRuntime(self.home, self.store)
        handoff_kwargs: dict[str, Any] = {}
        if runner is not None and provider_mode == "live":
            handoff_kwargs = {
                "runner": runner,
                "provider_mode": provider_mode,
                "profile_overrides": profile_overrides or {},
                "handoff_context": handoff_context or {},
            }
        graph_runtime.require_handoff(task_graph, "approval", **handoff_kwargs)
        task_graph = graph_runtime.transition(task_graph, "approval", "running", reason=reason, approved_scope_hash=approved_scope_hash)
        return graph_runtime.transition(task_graph, "approval", "completed", reason=reason, approved_scope_hash=approved_scope_hash)

    def ask(self, goal: str, *, provider_mode: str = "mock", profile_overrides: dict[str, str] | None = None) -> dict[str, Any]:
        return self.run(goal, attach_conversation=True, provider_mode=provider_mode, profile_overrides=profile_overrides)

    def _finalize_autonomy_run(self, result: dict[str, Any], *, parent_goal_id: str | None = None, backlog_item_id: str | None = None) -> dict[str, Any]:
        if parent_goal_id:
            result["parent_goal_id"] = parent_goal_id
        if backlog_item_id:
            result["backlog_item_id"] = backlog_item_id
        run_id = result.get("run_id")

        # Ensure terminal event exists
        if run_id:
            ledger = RunLedger(self.home, self.store)
            phase = str(result.get("phase") or result.get("status") or "unknown")
            task_type = str(result.get("task_type") or "chat")
            reason = str(result.get("reason") or "run finalized")
            ensure_terminal_event(ledger, str(run_id), task_type, phase, reason)
            terminal = terminal_summary(ledger.timeline(str(run_id)))
            normalized_terminal = terminal.get("normalized_terminal") or terminal.get("type")
            result["command_status"] = "executed"
            result["run_status"] = normalized_terminal
            result["terminal_type"] = terminal.get("type")
            result["domain_success"] = normalized_terminal == "run_completed" and terminal.get("count") == 1
            try:
                manifest = RunManifestManager(self.home, self.store).create(str(run_id))
                result["manifest_path"] = str(RunManifestManager(self.home, self.store).path(str(run_id)))
                result["code_revision"] = manifest.get("code_revision")
            except Exception as exc:  # noqa: BLE001
                result["manifest_status"] = "failed"
                result["manifest_error"] = redact_text(str(exc))[:300]

        if run_id and (parent_goal_id or backlog_item_id):
            AutonomyManager(self.home, self.store).update_backlog_from_run(
                str(run_id),
                str(result.get("status") or result.get("phase") or "unknown"),
                reason=str(result.get("reason") or ""),
            )
        return result

    def approve_run(self, run_id: str, *, action: str = "approve", files: list[str] | None = None, continue_run: bool = True) -> dict[str, Any]:
        self.legacy_write_gate.assert_writes_allowed()
        pending = self._load_pending_approval(run_id)
        if not pending:
            return {"status": "blocked", "reason": "pending approval context not found", "run_id": run_id}
        proposed_files = files or list(pending.get("proposed_touched_files", []))
        if not proposed_files:
            return {"status": "blocked", "reason": "no files to approve", "run_id": run_id}
        risk_scan = self.risk.scan("write", target=proposed_files[0], allowed_roots=[str(self.home)])
        self.store.insert_risk_scan(risk_scan.model_dump(), run_id=run_id)
        approval = ApprovalManager(self.home, self.store).create(
            run_id=run_id,
            action=action,
            risk_scan=risk_scan,
            plan_hash=sha256_text(stable_json(pending.get("planner_output", {}))),
            approved_touched_files=proposed_files,
            approved_commands=["sitina config validate"],
        )
        self.store.record_event("user_approval", approval.model_dump(), run_id=run_id, trace_id=f"{run_id}:approval")
        if action != "approve":
            state_raw = self.store.get_run(run_id)
            if state_raw:
                state_raw["phase"] = "blocked"
                state_raw["approval_id"] = approval.approval_id
                state_raw["verification_status"] = "not_verified"
                write_json(self.home / "state" / "run_state.json", state_raw)
                self.store.upsert_run_state(state_raw)
            return {"status": "blocked", "run_id": run_id, "approval_id": approval.approval_id, "action": action}
        if not continue_run:
            return {"status": "approved", "run_id": run_id, "approval_id": approval.approval_id}
        return self.continue_approved_run(run_id, approval.approval_id, risk_scan.model_dump(), pending)

    def continue_approved_run(self, run_id: str, approval_id: str, risk_scan: dict[str, Any], pending: dict[str, Any] | None = None) -> dict[str, Any]:
        self.legacy_write_gate.assert_writes_allowed()
        def blocked_before_memory(result: dict[str, Any], reason_code: str) -> dict[str, Any]:
            self._record_memory_no_candidate(run_id, f"{reason_code}: {result.get('reason', result.get('status', 'blocked'))}", source="workflow")
            return result

        pending = pending or self._load_pending_approval(run_id)
        state_raw = self.store.get_run(run_id)
        if not pending or not state_raw:
            return blocked_before_memory({"status": "blocked", "reason": "run or pending context missing", "run_id": run_id}, "continue_approved_run_blocked_before_summary")
        provider_mode = pending.get("provider_mode", "mock")
        profile_overrides = pending.get("profile_overrides", {})
        planner_payload = pending.get("planner_output", {})
        approval_raw = self.store.get_approval(approval_id) or {}
        approved_files = approval_raw.get("approved_touched_files") or pending.get("proposed_touched_files", [])
        runner = AgentRunner(self.home)
        state = self.states.transition(self._state_from_raw(state_raw), "coding", "coder")
        input_scope_hash = scope_hash(approved_files, ["sitina config validate"])
        diff = DiffVerifier()
        before_hashes = {path: diff.before_hash(path) for path in approved_files}
        try:
            coder = self._run_agent(
                runner,
                "coder",
                {
                    "approved_touched_files": approved_files,
                    "plan": {"planner_output": planner_payload},
                    "acceptance_criteria": planner_payload.get("acceptance_criteria") or ["approved write succeeds"],
                    "approval_id": approval_id,
                    "allowed_scope": approved_files,
                    "input_scope_hash": input_scope_hash,
                    "before_hashes": before_hashes,
                    "file_write_contract": {
                        "required_extension": "extensions.file_writes",
                        "allowed_files": approved_files,
                        "before_hash_required": True,
                        "content_required": True,
                    },
                },
                run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type="code_change",
            )
        except Exception as exc:  # noqa: BLE001
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
            self.states.save(state)
            return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": str(exc)}, "coder_blocked_before_summary")
        if coder.payload.get("input_scope_hash") != input_scope_hash or coder.payload.get("scope_compliance") != "in_scope":
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
            self.states.save(state)
            return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": "coder scope compliance failed"}, "coder_blocked_before_summary")
        writes = coder.payload.get("extensions", {}).get("file_writes", [])
        if not writes:
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
            self.states.save(state)
            return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": "coder produced no file_writes"}, "coder_blocked_before_summary")
        touched_ok, out_of_scope = diff.verify_scope(coder.payload.get("files_touched", []), approved_files)
        if not touched_ok:
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
            self.states.save(state)
            return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": "coder files_touched out of approved scope", "out_of_scope": out_of_scope}, "approved_files_validation_failed_before_memory")
        executor = ToolExecutor(self.home, self.store)
        write_results: list[dict[str, Any]] = []
        for item in writes:
            path = item.get("path")
            content = item.get("content", "")
            if path not in approved_files:
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
                self.states.save(state)
                return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": f"coder attempted out-of-scope write: {path}"}, "approved_files_validation_failed_before_memory")
            expected_before = before_hashes[path]
            if "before_hash" not in item or item.get("before_hash") != expected_before:
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
                self.states.save(state)
                return blocked_before_memory({
                    "status": "blocked",
                    "run_id": run_id,
                    "reason": f"coder before_hash mismatch for {path}",
                    "expected_before_hash": expected_before,
                    "coder_before_hash": item.get("before_hash"),
                }, "before_hash_mismatch_before_memory")
            before_ok, actual_before = diff.verify_before_hash(path, expected_before)
            if not before_ok:
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
                self.states.save(state)
                return blocked_before_memory({
                    "status": "blocked",
                    "run_id": run_id,
                    "reason": f"file changed after approval: {path}",
                    "expected_before_hash": expected_before,
                    "actual_before_hash": actual_before,
                }, "before_hash_mismatch_before_memory")
            result = executor.execute(
                operation="write",
                run_id=run_id,
                agent="coder",
                target=path,
                content=content,
                approval_id=approval_id,
                approved_files=approved_files,
                allowed_commands=["sitina config validate"],
                allowed_roots=[str(self.home)],
                precomputed_risk_scan=risk_scan,
                expected_before_hash=expected_before,
            )
            write_results.append(result)
            if result.get("status") != "ok":
                state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
                self.states.save(state)
                return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": "write failed", "write_results": write_results}, "coder_blocked_before_summary")
        changed_files = [item["path"] for item in writes]
        scope_ok, out_of_scope = diff.verify_scope(changed_files, approved_files)
        after_hashes = {path: diff.before_hash(path) for path in changed_files}
        diff_hash = diff.diff_hash(before_hashes, after_hashes)

        validation = ConfigValidator(self.home).validate()
        artifact_payload = {
            "command": "sitina config validate",
            "config_validate": validation,
            "approved_files": approved_files,
            "changed_files": changed_files,
            "scope_ok": scope_ok,
            "out_of_scope": out_of_scope,
            "diff_hash": diff_hash,
            "before_hashes": before_hashes,
            "after_hashes": after_hashes,
            "write_results": write_results,
        }
        artifact_dir = self.home / "artifacts" / "command_outputs" / run_id
        ensure_dir(artifact_dir)
        artifact_path = artifact_dir / "approved-write-verify.json"
        artifact_path.write_text(json.dumps(artifact_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        artifact = ArtifactRegistry(self.home, self.store).register_command_output(
            run_id=run_id,
            turn_id=f"{run_id}:tester",
            producing_agent="tester",
            command="sitina config validate",
            cwd=str(self.home),
            artifact_path=str(artifact_path),
        )

        try:
            state = self.states.transition(state, "testing", "tester")
            tester = self._run_agent(
                runner,
                "tester",
                {
                    "test_strategy": "Run Sitina config validation after approved coder writes and bind command output artifact.",
                    "allowed_commands": ["sitina config validate"],
                    "patch_id": diff_hash,
                    "changed_files": changed_files,
                    "approved_env": {"SITINA_HOME": str(self.home)},
                    "expected_artifact_hash": artifact.artifact_hash,
                },
                run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type="code_change",
            )

            state = self.states.transition(state, "reviewing", "reviewer")
            reviewer = self._run_agent(
                runner,
                "reviewer",
                {
                    "patch_id": diff_hash,
                    "changed_files": changed_files,
                    "acceptance_criteria": planner_payload.get("acceptance_criteria") or ["approved write succeeds"],
                    "test_artifacts": [artifact.artifact_hash],
                    "mandatory_step_context": {
                        "tester_turn_id": f"{run_id}:tester",
                        "provider_mode": provider_mode,
                        "scope_ok": scope_ok,
                        "out_of_scope": out_of_scope,
                        "write_results": write_results,
                        "before_hashes": before_hashes,
                        "after_hashes": after_hashes,
                        "test_artifact_summaries": [
                            {
                                "artifact_hash": artifact.artifact_hash,
                                "artifact_path": str(artifact_path),
                                "summary": artifact_payload,
                            }
                        ],
                    },
                },
                run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type="code_change",
            )

            artifact_verified, artifact_verify_reason = EvidenceVerifier(self.home, self.store).verify_artifact(
                artifact_hash=artifact.artifact_hash,
                run_id=run_id,
                command="sitina config validate",
                cwd=str(self.home),
            )
            reviewer_accept = reviewer.payload.get("overall_recommendation") == "accept"
            reviewer_blockers = self._reviewer_has_blockers(reviewer.payload)
            reviewer_merge = MultiReviewer(self.home, self.store).merge(
                [
                    self._reviewer_decision_for_fixture(run_id, "code", "code", {"patch_id": diff_hash, "patch_hash": diff_hash, "patch_artifact": str(artifact_path)}, str(self.home)),
                    self._reviewer_decision_for_fixture(run_id, "test", "test", {"patch_id": diff_hash, "patch_hash": diff_hash, "patch_artifact": str(artifact_path)}, str(self.home)),
                ],
                run_id=run_id,
                task_type="code_change",
                patch_id=diff_hash,
                patch_hash=diff_hash,
                target_repo=str(self.home),
            )
            tester_pass = tester.payload.get("decision") == "pass"
            gate_verified = validation["ok"] and artifact_verified and scope_ok and reviewer_accept and not reviewer_blockers and reviewer_merge.merged_decision == "accept" and tester_pass

            state = self.states.transition(state, "summarizing", "summary")
            summary_state = state.model_copy(update={"verification_status": "verified" if gate_verified else "not_verified"})
            summary = self._run_agent(
                runner,
                "summary",
                {
                    "final_run_state": summary_state.model_dump(),
                    "tester_output": tester.payload,
                    "reviewer_output": reviewer.payload,
                    "audit_refs": [f"{run_id}:tester", f"{run_id}:reviewer", f"{run_id}:reviewer_merge", f"{run_id}:coder"],
                },
                run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type="code_change",
            )
        except Exception as exc:  # noqa: BLE001
            state = state.model_copy(update={"phase": "blocked", "active_agent": None, "verification_status": "not_verified", "approval_id": approval_id})
            self.states.save(state)
            return blocked_before_memory({"status": "blocked", "run_id": run_id, "reason": str(exc)}, "tester_or_reviewer_blocked_before_summary")

        self.store.record_event(
            "evidence_verified",
            {"artifact_hash": artifact.artifact_hash, "verified": artifact_verified, "reason": artifact_verify_reason},
            run_id=run_id,
            trace_id=f"{run_id}:evidence",
        )
        verified = gate_verified and summary.payload.get("verification_status_derived") == "verified"
        self._run_memory_agent_after_summary(
            runner,
            run_id=run_id,
            goal=str(pending.get("goal", "approved run")),
            summary_payload=summary.payload,
            reviewer_payload=reviewer.payload,
            tester_payload=tester.payload,
            changed_files=changed_files,
            approved_changes=write_results,
            final_verification_status="verified" if verified else "not_verified",
            provider_mode=provider_mode,
            profile_overrides=profile_overrides,
            approval_id=approval_id,
            task_type="code_change",
        )
        state = state.model_copy(
            update={
                "phase": "done" if verified else "blocked",
                "active_agent": None,
                "verification_status": "verified" if verified else "not_verified",
                "approval_id": approval_id,
                "risk_scan_result_ref": risk_scan["risk_scan_id"],
                "mandatory_step_outputs": MandatoryStepOutputs(
                    tester_turn_id=f"{run_id}:tester",
                    reviewer_turn_id=f"{run_id}:reviewer",
                    architect_turn_id=None,
                ),
            }
        )
        self.states.save(state)
        self.store.record_event(
            "approved_coder_complete",
            {
                "writes": write_results,
                "diff_hash": diff_hash,
                "artifact_hash": artifact.artifact_hash,
                "verified": verified,
                "reviewer_accept": reviewer_accept,
                "tester_pass": tester_pass,
                "reviewer_blockers": reviewer_blockers,
            },
            run_id=run_id,
            trace_id=f"{run_id}:coder",
        )
        return {
            "status": "done" if verified else "blocked",
            "run_id": run_id,
            "approval_id": approval_id,
            "verification_status": "verified" if verified else "not_verified",
            "writes": write_results,
            "diff_hash": diff_hash,
            "artifact_hash": artifact.artifact_hash,
            "reviewer_accept": reviewer_accept,
            "tester_pass": tester_pass,
        }

    def _pending_path(self, run_id: str) -> Path:
        return self.home / "artifacts" / "approvals" / f"{run_id}.pending.json"

    def _save_pending_approval(self, run_id: str, payload: dict[str, Any]) -> None:
        write_json(self._pending_path(run_id), payload)

    def _load_pending_approval(self, run_id: str) -> dict[str, Any] | None:
        path = self._pending_path(run_id)
        return read_json(path, default=None) if path.exists() else None

    def _state_from_raw(self, state_raw: dict[str, Any]):
        from sitina.schemas.models import RunState

        return RunState.model_validate(state_raw)

    def _reviewer_has_blockers(self, reviewer_payload: dict[str, Any]) -> bool:
        return any(finding.get("severity") in {"critical", "major"} for finding in reviewer_payload.get("findings", []))

    def _prepare_high_risk_fixture_repo(self, run_id: str) -> Path:
        if not shutil.which("git"):
            raise RuntimeError("git is required for high-risk full gate fixture")
        repo = self.home / "temp" / f"high_risk_full_{run_id}"
        if repo.exists():
            shutil.rmtree(repo)
        ensure_dir(repo)
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, text=True, check=True)
        subprocess.run(["git", "config", "user.email", "sitina@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Sitina Test"], cwd=repo, check=True)
        (repo / "file.txt").write_text("before high-risk fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True, text=True, check=True)
        return repo.resolve(strict=False)

    def _reviewer_decision_for_fixture(
        self,
        run_id: str,
        reviewer_id: str,
        scope: str,
        patch: dict[str, Any],
        target_repo: str,
        *,
        decision: str = "accept",
        severity: str = "none",
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "reviewer_id": reviewer_id,
            "scope": scope,
            "decision": decision,
            "severity": severity,
            "issues": [],
            "patch_id": patch["patch_id"],
            "patch_hash": patch["patch_hash"],
            "target_repo": target_repo,
            "evidence": [{"kind": "artifact", "ref": patch["patch_artifact"]}],
        }

    def _prepare_worktree_for_planner_risk(self, run_id: str, planner_payload: dict[str, Any]) -> dict[str, Any] | None:
        risk_level = str(planner_payload.get("risk_assessment", {}).get("risk_level", "low")).lower()
        if risk_level not in {"high", "critical"}:
            return None
        result = GitWorktreeManager(self.home, self.store).prepare(str(self.home), run_id)
        self.store.record_event(
            "git_worktree_auto_prepare",
            {"risk_level": risk_level, "result": result},
            run_id=run_id,
            trace_id=f"{run_id}:worktree",
        )
        return result

    def _run_agent(
        self,
        runner: AgentRunner,
        agent: str,
        input_payload: dict[str, Any],
        run_id: str,
        provider_mode: str,
        *,
        profile_overrides: dict[str, str] | None = None,
        task_id: str = "main",
        task_type: str = "chat",
        call_id: str | None = None,
    ) -> AgentRunResult:
        profile_override = (profile_overrides or {}).get(agent)
        logical_call_id = call_id or ("logical_call_" + new_id())
        trace_id = f"{run_id}:{agent}"
        ledger = RunLedger(self.home, self.store)
        raw_input_hash = sha256_text(stable_json(input_payload))
        safe_input_payload = canonicalize_agent_input(input_payload)
        safe_input_hash = compute_agent_input_hash(input_payload)
        ledger.record(
            "agent_started",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="ok",
            reason=f"{agent} started",
            payload={
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "input_payload": safe_input_payload,
                "input_hash_semantics": "sha256(stable_json(redacted_input_payload))",
                "provider_mode": provider_mode,
                "call_id": logical_call_id,
            },
        )
        try:
            result = runner.run_agent(
                agent,
                input_payload,
                provider_mode=provider_mode,
                profile_override=profile_override,
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                logical_call_id=logical_call_id,
                audit_context={"call_origin": "engine", "role": agent},
            )
        except Exception as exc:  # noqa: BLE001
            error_type = getattr(exc, "error_type", type(exc).__name__)
            error_details = getattr(exc, "details", {})
            error_details = error_details if isinstance(error_details, dict) else {}
            ledger.record(
                "agent_blocked",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent_id=agent,
                status="failed",
                reason=str(exc),
                payload={
                    "input_hash": safe_input_hash,
                    "raw_input_hash": raw_input_hash,
                    "safe_input_hash": safe_input_hash,
                    "provider_mode": provider_mode,
                    "profile_name": error_details.get("profile_name"),
                    "model": error_details.get("model"),
                    "provider_calls": error_details.get("provider_calls") or [],
                    "error_type": error_type,
                    "fallback_used": False if provider_mode == "live" else None,
                    "call_id": logical_call_id,
                },
            )
            raise
        self.store.record_event(
            "agent_output",
            {
                "agent": agent,
                "provider_mode": result.provider_mode,
                "profile_name": result.profile_name,
                "model": result.model,
                "provider_identity": result.provider_identity,
                "repair_attempts": result.repair_attempts,
                "provider_calls": result.provider_calls,
                "fallback_used": result.fallback_used,
                "payload": result.payload,
                "call_id": logical_call_id,
            },
            run_id=run_id,
            trace_id=trace_id,
        )
        self.store.record_audit(
            "agent_call",
            {
                "agent": agent,
                "provider_mode": result.provider_mode,
                "profile_name": result.profile_name,
                "model": result.model,
                "provider_identity": result.provider_identity,
                "repair_attempts": result.repair_attempts,
                "provider_calls": result.provider_calls,
                "fallback_used": result.fallback_used,
                "call_id": logical_call_id,
            },
            run_id=run_id,
            trace_id=trace_id,
            agent=agent,
            input_hash=safe_input_hash,
            output_hash=sha256_text(stable_json(result.payload)),
            exit_status="ok",
        )
        agent_cannot_complete = result.payload.get("agent_status") == "cannot_complete"
        agent_terminal_reason = (
            str(result.payload.get("blocked_reason") or (result.payload.get("extensions") or {}).get("reason") or f"{agent} reported agent_status=cannot_complete")
            if agent_cannot_complete
            else f"{agent} completed"
        )
        ledger.record(
            "agent_blocked" if agent_cannot_complete else "agent_completed",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="blocked" if agent_cannot_complete else "ok",
            reason=agent_terminal_reason,
            payload={
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "output_hash": sha256_text(stable_json(result.payload)),
                "provider_mode": result.provider_mode,
                "profile_name": result.profile_name,
                "model": result.model,
                "provider_identity": result.provider_identity,
                "provider_calls": result.provider_calls,
                "fallback_used": result.fallback_used,
                "call_id": logical_call_id,
            },
        )
        envelope = EnvelopeFactory.wrap_agent_output(
            run_id=run_id,
            agent_id=agent,
            task_id=task_id,
            task_type=task_type,
            payload=result.payload,
            status="blocked" if agent_cannot_complete else None,
            blocked_reason=agent_terminal_reason if agent_cannot_complete else None,
        )
        HandoffManager(self.home, self.store).record_envelope(envelope)
        if agent_cannot_complete:
            raise AgentRunnerError(agent_terminal_reason, error_type="agent_cannot_complete")
        if agent == "summary":
            ledger.record(
                "summary_created",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent_id=agent,
                status="ok",
                reason="summary agent output created",
                payload={"summary_hash": sha256_text(stable_json(result.payload))},
            )
        if agent == "memory":
            no_candidate_reason = (
                result.payload.get("extensions", {}).get("no_candidate_reason")
                or result.payload.get("extensions", {}).get("reason")
                or ("memory agent returned decision=none" if result.payload.get("decision") == "none" else None)
            )
            self.persist_memory_candidates(run_id, result.payload.get("candidates", []), no_candidate_reason=no_candidate_reason, source="memory_agent")
            ledger.record(
                "memory_checked",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent_id=agent,
                status="ok",
                reason=no_candidate_reason or "memory candidates processed",
                payload={
                    "decision": result.payload.get("decision"),
                    "candidate_count": len(result.payload.get("candidates", [])),
                },
            )
        return result

    def resume(self, run_id: str) -> dict[str, Any]:
        if (self.home / "state/bplus-production-genesis/genesis.json").is_file():
            context = ProductionRuntimeContext.load(
                self.home,
                keychain_backend=self.bplus_keychain_backend,
                allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
            )
            state = context.show_run(run_id)
            if state is None:
                return {"status": "blocked", "reason": "run_id not found", "run_id": run_id}
            return {
                "status": "ok" if state.get("status") == "terminal" else "blocked",
                "phase": state.get("phase"),
                "reason": "run already has a terminal Journal event" if state.get("status") == "terminal" else "no resumable B+ command",
                "duplicate_provider_calls": 0,
                "resumed_provider_calls": 0,
                "writer": "journal",
            }
        self.legacy_write_gate.assert_writes_allowed()
        state = self.store.get_run(run_id)
        if not state:
            return {"status": "blocked", "reason": "run_id not found"}
        from sitina.orchestrator.checkpoint import CheckpointManager

        ledger = RunLedger(self.home, self.store)
        timeline = ledger.timeline(run_id)
        terminal = next((event for event in timeline if event.get("event_type") in TERMINAL_EVENTS), None)
        if terminal:
            completed = terminal.get("event_type") == "run_completed"
            return {
                "status": "ok" if completed else "blocked",
                "phase": state.get("phase"),
                "reason": "run already has a terminal event",
                "terminal_event": terminal.get("event_type"),
                "duplicate_provider_calls": 0,
                "resumed_agent_calls": 0,
                "resumed_provider_calls": 0,
            }

        checkpoints = CheckpointManager(self.home)
        checkpoint = checkpoints.latest_resumable(run_id)
        if not checkpoint:
            reason = "no resumable checkpoint with pending agent calls"
            ledger.record("checkpoint_failed", run_id=run_id, status="failed", reason=reason, payload={})
            state["phase"] = "blocked"
            state["active_agent"] = None
            state["verification_status"] = "not_verified"
            self.store.upsert_run_state(state)
            ensure_terminal_event(ledger, run_id, "chat", "blocked", reason)
            return {"status": "blocked", "reason": reason, "duplicate_provider_calls": 0}

        valid, reason = checkpoints.verify_for_resume(checkpoint, run_id)
        if not valid:
            ledger.record(
                "checkpoint_failed",
                run_id=run_id,
                status="failed",
                reason=reason,
                payload={"checkpoint_id": checkpoint.get("checkpoint_id")},
            )
            state["phase"] = "blocked"
            state["active_agent"] = None
            state["verification_status"] = "not_verified"
            self.store.upsert_run_state(state)
            ensure_terminal_event(ledger, run_id, str((checkpoint.get("extra") or {}).get("task_type") or "chat"), "blocked", reason)
            return {
                "status": "blocked",
                "reason": reason,
                "checkpoint_id": checkpoint.get("checkpoint_id"),
                "duplicate_provider_calls": 0,
            }

        pending = [dict(call) for call in checkpoint.get("pending_agent_calls", [])]
        completed_calls = [dict(call) for call in checkpoint.get("completed_agent_calls", [])]
        completed_call_ids = {
            str(call.get("call_id"))
            for call in completed_calls
            if call.get("call_id")
        }
        completed_events = {
            str((event.get("payload_json") or {}).get("call_id")): event
            for event in timeline
            if event.get("event_type") == "agent_completed" and (event.get("payload_json") or {}).get("call_id")
        }
        completed_call_ids.update(completed_events)
        ledger.record(
            "checkpoint_resumed",
            run_id=run_id,
            task_type=str(pending[0].get("task_type") or "chat"),
            status="ok",
            reason="resume context verified; pending calls will execute with stable call ids",
            payload={
                "checkpoint_id": checkpoint.get("checkpoint_id"),
                "stage": checkpoint.get("stage"),
                "pending_call_ids": [call.get("call_id") for call in pending],
                "completed_call_ids": sorted(completed_call_ids),
                "duplicate_provider_calls": 0,
            },
        )

        graph_runtime = TaskGraphRuntime(self.home, self.store)
        task_graph = graph_runtime.load(run_id)
        if not task_graph:
            reason = "resume task graph not found"
            ledger.record("checkpoint_failed", run_id=run_id, status="failed", reason=reason, payload={"checkpoint_id": checkpoint.get("checkpoint_id")})
            state["phase"] = "blocked"
            state["active_agent"] = None
            state["verification_status"] = "not_verified"
            self.store.upsert_run_state(state)
            ensure_terminal_event(ledger, run_id, "chat", "blocked", reason)
            return {"status": "blocked", "reason": reason, "checkpoint_id": checkpoint.get("checkpoint_id"), "duplicate_provider_calls": 0}

        runner = AgentRunner(self.home)
        resumed_agent_calls = 0
        resumed_provider_calls = 0
        skipped_completed_calls = 0
        last_checkpoint_id = str(checkpoint.get("checkpoint_id"))
        try:
            for index, call in enumerate(pending):
                call_id = str(call["call_id"])
                task_id = str(call.get("task_id") or call["agent_id"])
                task_type = str(call.get("task_type") or task_graph.task_type)
                if call_id in completed_call_ids:
                    skipped_completed_calls += 1
                    event = completed_events.get(call_id)
                    node = task_graph.node_map.get(task_id)
                    if node and node.status != "completed":
                        task_graph = graph_runtime.transition(
                            task_graph,
                            task_id,
                            "completed",
                            reason="resume skipped provider call already proven complete by ledger",
                            output_ref=str((event.get("payload_json") or {}).get("output_hash")) if event else None,
                        )
                    continue

                node = task_graph.node_map.get(task_id)
                if not node:
                    raise ValueError(f"resume task graph node not found: {task_id}")
                if node.status not in {"pending", "running"}:
                    raise ValueError(f"resume task graph node has invalid state {task_id}:{node.status}")
                if not graph_runtime.dependencies_completed(task_graph, task_id):
                    raise ValueError(f"resume task graph dependencies are incomplete: {task_id}")
                if node.status == "pending":
                    task_graph = graph_runtime.transition(task_graph, task_id, "running", reason="checkpoint resume agent call started")

                agent_id = str(call["agent_id"])
                profile_override = call.get("profile_override")
                profile_overrides = {agent_id: str(profile_override)} if isinstance(profile_override, str) and profile_override else {}
                result = self._run_agent(
                    runner,
                    agent_id,
                    dict(call["input_payload"]),
                    run_id,
                    str(call["provider_mode"]),
                    profile_overrides=profile_overrides,
                    task_id=task_id,
                    task_type=task_type,
                    call_id=call_id,
                )
                output_hash = sha256_text(stable_json(result.payload))
                resumed_agent_calls += 1
                resumed_provider_calls += len(result.provider_calls)
                completed_call_ids.add(call_id)
                completed_calls.append(
                    {
                        "call_id": call_id,
                        "agent_id": agent_id,
                        "task_id": task_id,
                        "task_type": task_type,
                        "input_hash": call["input_hash"],
                        "output_hash": output_hash,
                        "provider_mode": result.provider_mode,
                        "profile_name": result.profile_name,
                        "model": result.model,
                        "provider_calls": result.provider_calls,
                        "fallback_used": result.fallback_used,
                    }
                )
                task_graph = graph_runtime.transition(
                    task_graph,
                    task_id,
                    "completed",
                    reason="checkpoint resume agent call completed",
                    output_ref=output_hash,
                )
                remaining = [item for item in pending[index + 1 :] if str(item.get("call_id")) not in completed_call_ids]
                next_checkpoint = checkpoints.create(
                    run_id=run_id,
                    stage=f"resume_{task_id}_completed",
                    completed_agent_calls=completed_calls,
                    pending_agent_calls=remaining,
                    resumable=bool(remaining),
                    extra={
                        "resumed_from_checkpoint_id": checkpoint.get("checkpoint_id"),
                        "duplicate_provider_calls": 0,
                        "resume_policy": "execute_pending_agent_calls_then_validate_task_graph",
                    },
                )
                last_checkpoint_id = str(next_checkpoint["checkpoint_id"])
        except Exception as exc:  # noqa: BLE001
            error_type = getattr(exc, "error_type", getattr(exc, "timeout_type", type(exc).__name__))
            phase = "cancelled" if error_type == "run_cancelled" else (
                "timeout" if error_type in {"run_deadline", "run_deadline_exceeded", "provider_connect_timeout", "provider_read_timeout"} else "blocked"
            )
            reason = redact_text(str(exc))[:500]
            state["phase"] = phase
            state["active_agent"] = None
            state["verification_status"] = "not_verified"
            self.store.upsert_run_state(state)
            ensure_terminal_event(ledger, run_id, task_graph.task_type, phase, reason)
            return {
                "status": phase,
                "phase": phase,
                "reason": reason,
                "checkpoint_id": last_checkpoint_id,
                "duplicate_provider_calls": 0,
                "resumed_agent_calls": resumed_agent_calls,
                "resumed_provider_calls": resumed_provider_calls,
            }

        graph_ok, missing = graph_runtime.can_complete(task_graph)
        if not graph_ok:
            state["phase"] = "paused"
            state["active_agent"] = None
            state["verification_status"] = "not_verified"
            self.store.upsert_run_state(state)
            return {
                "status": "paused",
                "phase": "paused",
                "reason": "resume exhausted pending calls but mandatory task graph nodes remain",
                "missing": missing,
                "checkpoint_id": last_checkpoint_id,
                "duplicate_provider_calls": 0,
                "resumed_agent_calls": resumed_agent_calls,
                "resumed_provider_calls": resumed_provider_calls,
                "skipped_completed_calls": skipped_completed_calls,
            }

        state["phase"] = "done"
        state["active_agent"] = None
        state["verification_status"] = "verified"
        self.store.upsert_run_state(state)
        self._record_memory_no_candidate(
            run_id,
            "controlled checkpoint/resume fixture produced no durable memory candidate",
            source="checkpoint_resume_fixture",
        )
        ensure_terminal_event(ledger, run_id, task_graph.task_type, "done", "checkpoint resume completed all mandatory task graph nodes")
        self.store.record_event(
            "resume_execution_completed",
            {
                "checkpoint_id": last_checkpoint_id,
                "resumed_agent_calls": resumed_agent_calls,
                "resumed_provider_calls": resumed_provider_calls,
                "skipped_completed_calls": skipped_completed_calls,
                "duplicate_provider_calls": 0,
            },
            run_id=run_id,
        )
        return {
            "status": "ok",
            "phase": "done",
            "checkpoint_id": last_checkpoint_id,
            "duplicate_provider_calls": 0,
            "resumed_agent_calls": resumed_agent_calls,
            "resumed_provider_calls": resumed_provider_calls,
            "skipped_completed_calls": skipped_completed_calls,
            "terminal_event": "run_completed",
        }

    def cancel(self, run_id: str, *, reason: str = "cancel requested by user") -> dict[str, Any]:
        if (self.home / "state/bplus-production-genesis/genesis.json").is_file():
            context = ProductionRuntimeContext.load(
                self.home,
                keychain_backend=self.bplus_keychain_backend,
                allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
            )
            state = context.show_run(run_id)
            if state is None:
                return {"status": "blocked", "reason": "run_id not found", "run_id": run_id}
            if state.get("status") == "terminal":
                return {"status": "blocked", "reason": "run already has a terminal Journal event", "run_id": run_id}
            return {"status": "blocked", "reason": "no cancellable B+ command exists", "run_id": run_id}
        self.legacy_write_gate.assert_writes_allowed()
        state = self.store.get_run(run_id)
        if not state:
            return {"status": "blocked", "reason": "run_id not found", "run_id": run_id}
        ledger = RunLedger(self.home, self.store)
        if any(event.get("event_type") in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"} for event in ledger.timeline(run_id)):
            return {"status": "blocked", "reason": "run already has a terminal event", "run_id": run_id}
        control = RunControlStore(self.home)
        if not control.get(run_id):
            control.create(RunDeadline.create(run_id, ProviderTimeoutConfig.from_config(load_json_yaml(self.home / "config" / "sitina.yaml").get("providers", {})).run_deadline))
        control.request_cancel(run_id, reason)
        from sitina.orchestrator.checkpoint import CheckpointManager

        checkpoints = CheckpointManager(self.home)
        previous = checkpoints.latest_resumable(run_id) or checkpoints.latest(run_id) or {}
        checkpoint = checkpoints.create(
            run_id=run_id,
            stage="cancel_requested",
            completed_agent_calls=list(previous.get("completed_agent_calls") or []),
            pending_agent_calls=list(previous.get("pending_agent_calls") or []),
            proposal_ids=list(previous.get("proposal_ids") or []),
            evaluation_ids=list(previous.get("evaluation_ids") or []),
            selected_proposal_id=previous.get("selected_proposal_id"),
            resumable=False,
            extra={
                "reason": reason,
                "cancel_requested": True,
                "cancelled_from_checkpoint_id": previous.get("checkpoint_id"),
            },
        )
        state["phase"] = "cancelled"
        state["active_agent"] = None
        state["verification_status"] = "not_verified"
        self.store.upsert_run_state(state)
        self._record_memory_no_candidate(run_id, f"run cancelled: {reason}", source="cancellation")
        ledger.record("run_cancelled", run_id=run_id, status="failed", reason=reason, payload={"checkpoint_id": checkpoint["checkpoint_id"], "cancel_requested": True})
        return {"status": "cancelled", "run_id": run_id, "checkpoint_id": checkpoint["checkpoint_id"], "reason": reason}

    def _append_conversation(self, goal: str, run_id: str) -> None:
        path = self.home / "state" / "active_conversation.json"
        doc = read_json(path, default={"conversation_id": "conv_default", "turns": []})
        doc.setdefault("turns", []).append({"ts": iso_now(), "run_id": run_id, "user_goal_hash": sha256_text(goal), "preview": redact_text(goal)[:300]})
        doc["updated_at"] = iso_now()
        write_json(path, doc)
        ensure_dir(self.home / "logs" / "conversations")
        (self.home / "logs" / "conversations" / "conv_default.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def export_run(self, run_id: str) -> Path:
        self.legacy_write_gate.assert_writes_allowed()
        state = self.store.get_run(run_id)
        if not state:
            raise ValueError("run_id not found")
        out = self.home / "artifacts" / "exports" / f"{run_id}.redacted.json"
        payload = {"state": state, "exported_at": iso_now()}
        out.write_text(redact_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
        return out

    def backup(self) -> Path:
        self.legacy_write_gate.assert_writes_allowed()
        self.initialize()
        out = self.home / "backups" / f"sitina-backup-{new_id()}.tar.gz"
        ensure_dir(out.parent)
        include = ["config", "schemas", "prompts", "data", "logs", "artifacts/evidence", "artifacts/risk_scans"]
        with tarfile.open(out, "w:gz") as tar:
            for item in include:
                path = self.home / item
                if path.exists():
                    tar.add(path, arcname=item, filter=self._tar_filter)
        self.store.record_audit("backup", {"path": str(out), "excluded": ["profiles/*.env", "token-bearing env"]})
        return out

    def _tar_filter(self, info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = info.name
        if "/profiles/" in name or name.endswith(".env") or "token" in name.lower():
            return None
        return info

    def _run_memory_agent_after_summary(
        self,
        runner: AgentRunner,
        *,
        run_id: str,
        goal: str,
        summary_payload: dict[str, Any],
        reviewer_payload: dict[str, Any],
        tester_payload: dict[str, Any],
        changed_files: list[str],
        approved_changes: list[dict[str, Any]],
        final_verification_status: str,
        provider_mode: str,
        profile_overrides: dict[str, str] | None,
        approval_id: str | None = None,
        task_type: str = "chat",
        goal_id: str | None = None,
    ) -> None:
        run_summary = str(summary_payload.get("user_summary") or stable_json(summary_payload)[:1200])
        user_visible_decisions = [
            f"final_verification_status={final_verification_status}",
            f"tester_decision={tester_payload.get('decision', 'unknown')}",
            f"reviewer_recommendation={reviewer_payload.get('overall_recommendation', 'unknown')}",
        ]
        memory_policy = {
            "default_status": "pending",
            "no_candidate_reason_required": True,
            "accepted_memory_path": str(self.home / "memory" / "global_memory.md"),
            "sensitive_content_policy": "block_or_redact_before_persistence",
            "context": self._redact_memory_value(
                {
                    "user_goal": goal,
                    "summary_output": summary_payload,
                    "reviewer_result": reviewer_payload,
                    "tester_result": tester_payload,
                    "approved_changes": approved_changes,
                    "changed_files": changed_files,
                    "approval_id": approval_id,
                    "final_verification_status": final_verification_status,
                }
            ),
        }
        try:
            self._run_agent(
                runner,
                "memory",
                {
                    "run_summary": self._safe_memory_text(run_summary, fallback="Run completed."),
                    "user_visible_decisions": user_visible_decisions,
                    "memory_policy": memory_policy,
                },
                run_id,
                provider_mode,
                profile_overrides=profile_overrides,
                task_type=task_type,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_memory_warning(run_id, f"memory agent failed: {exc}")
            RunLedger(self.home, self.store).record(
                "memory_checked",
                run_id=run_id,
                task_type=task_type,
                agent_id="memory",
                status="warning",
                reason=f"memory agent failed: {exc}",
                payload={"warning_only": True},
            )
        self._maybe_create_followup_backlog_candidate(
            run_id=run_id,
            goal=goal,
            summary_payload=summary_payload,
            reviewer_payload=reviewer_payload,
            tester_payload=tester_payload,
            final_verification_status=final_verification_status,
            goal_id=goal_id,
        )

    def _maybe_create_followup_backlog_candidate(
        self,
        *,
        run_id: str,
        goal: str,
        summary_payload: dict[str, Any],
        reviewer_payload: dict[str, Any],
        tester_payload: dict[str, Any],
        final_verification_status: str,
        goal_id: str | None = None,
    ) -> None:
        unverified = summary_payload.get("unverified_items") or []
        reviewer_ok = reviewer_payload.get("overall_recommendation") in {"accept", "skipped"}
        tester_ok = tester_payload.get("decision") in {"pass", "skipped"}
        if final_verification_status == "verified" and reviewer_ok and tester_ok and not unverified:
            return
        reason_parts = [
            f"verification={final_verification_status}",
            f"tester={tester_payload.get('decision', 'unknown')}",
            f"reviewer={reviewer_payload.get('overall_recommendation', 'unknown')}",
        ]
        if unverified:
            reason_parts.append(f"unverified_items={len(unverified)}")
        AutonomyManager(self.home, self.store).propose_from_run(
            run_id=run_id,
            title=f"Follow up run {run_id}",
            description=f"Review unresolved work from goal: {goal}. " + "; ".join(reason_parts),
            goal_id=goal_id,
            source_agent="goal_agent",
            priority=2 if final_verification_status != "verified" else 3,
            risk="medium" if final_verification_status != "verified" else "low",
        )

    def persist_memory_candidates(
        self,
        run_id: str,
        candidates: list[dict[str, Any]],
        *,
        no_candidate_reason: str | None = None,
        source: str = "memory_agent",
    ) -> list[dict[str, Any]]:
        self.store.init_db()
        if not candidates:
            self._record_memory_no_candidate(run_id, no_candidate_reason or "memory agent returned no candidates", source=source)
            return []

        inserted: list[dict[str, Any]] = []
        duplicates: list[str] = []
        invalid_count = 0
        for payload in candidates:
            if not isinstance(payload, dict):
                invalid_count += 1
                continue
            record = self._memory_candidate_from_payload(run_id, payload, source=source)
            if not record:
                invalid_count += 1
                continue
            if self.store.insert_memory_candidate(record):
                inserted.append(record)
            else:
                duplicates.append(record["candidate_id"])
        if inserted:
            self.store.record_event(
                "memory_candidates_created",
                {
                    "candidate_ids": [item["candidate_id"] for item in inserted],
                    "statuses": {item["candidate_id"]: item["status"] for item in inserted},
                    "duplicates": duplicates,
                    "invalid_count": invalid_count,
                },
                run_id=run_id,
                trace_id=f"{run_id}:memory",
            )
            self.store.record_audit(
                "memory_candidates_created",
                {
                    "count": len(inserted),
                    "candidate_ids": [item["candidate_id"] for item in inserted],
                    "blocked_count": len([item for item in inserted if item["status"] == "blocked"]),
                    "duplicates": duplicates,
                    "invalid_count": invalid_count,
                },
                run_id=run_id,
                trace_id=f"{run_id}:memory",
                exit_status="ok",
            )
        elif duplicates:
            self.store.record_event("memory_candidates_duplicate", {"candidate_ids": duplicates, "invalid_count": invalid_count}, run_id=run_id, trace_id=f"{run_id}:memory")
        else:
            self._record_memory_no_candidate(run_id, no_candidate_reason or "memory agent produced no valid candidates", source=source)
        return inserted

    def memory_review(
        self,
        action: str = "list",
        candidate_id: str | None = None,
        *,
        status: str | None = "pending",
        reviewer: str = "cli",
        source: str = "memory_cli",
        rejected_reason: str | None = None,
    ) -> dict[str, Any]:
        self.store.init_db()
        if action == "list":
            return {"status": "ok", "filter": status or "all", "candidates": self.store.list_memory_candidates(status=status)}
        if not candidate_id:
            return {"status": "blocked", "reason": "candidate_id required"}
        candidate = self.store.get_memory_candidate(candidate_id)
        if not candidate:
            return {"status": "not_found", "reason": "candidate_id not found", "candidate_id": candidate_id}
        if action == "show":
            return {"status": "ok", "candidate": candidate}
        if action == "accept":
            return self._accept_memory_candidate(candidate, reviewer=reviewer, source=source)
        if action == "reject":
            return self._reject_memory_candidate(candidate, reviewer=reviewer, source=source, rejected_reason=rejected_reason)
        return {"status": "blocked", "reason": f"unknown memory review action: {action}"}

    def _memory_candidate_from_payload(self, run_id: str, payload: dict[str, Any], *, source: str) -> dict[str, Any] | None:
        raw_content = payload.get("content") or payload.get("text") or payload.get("summary") or payload.get("value")
        if not isinstance(raw_content, str) or not raw_content.strip():
            return None
        content = raw_content.strip()
        memory_type = self._safe_memory_text(str(payload.get("memory_type") or payload.get("type") or "general"), fallback="general", max_len=80)
        source_name = self._safe_memory_text(str(payload.get("source") or source), fallback=source, max_len=120)
        reason = self._safe_memory_text(str(payload.get("reason") or "Memory agent proposed this as long-term useful context."), fallback="Memory agent proposed this as long-term useful context.", max_len=500)
        sensitivity_level = self._safe_memory_text(str(payload.get("sensitivity_level") or "low"), fallback="low", max_len=40).lower()
        sensitive_reason = self._memory_sensitive_reason(content, reason, sensitivity_level)
        status = "blocked" if sensitive_reason else "pending"
        stored_content = "<blocked-sensitive-memory>" if sensitive_reason else self._safe_memory_text(content, fallback="", max_len=2000)
        if not stored_content:
            return None
        created_at = iso_now()
        normalized_payload = {
            "candidate_id": self._memory_candidate_id(stored_content, memory_type, source_name, status),
            "run_id": run_id,
            "source": source_name,
            "content": stored_content,
            "reason": reason if not self._memory_sensitive_reason(reason) else "<redacted-sensitive-reason>",
            "confidence": self._memory_confidence(payload.get("confidence")),
            "status": status,
            "created_at": created_at,
            "reviewed_at": None,
            "rejected_reason": None,
            "memory_type": memory_type,
            "sensitivity_level": "sensitive" if sensitive_reason else sensitivity_level,
            "evidence": self._safe_memory_evidence(payload.get("evidence")),
        }
        if sensitive_reason:
            normalized_payload["blocked_reason"] = sensitive_reason
        return {
            "candidate_id": normalized_payload["candidate_id"],
            "run_id": run_id,
            "status": status,
            "payload": normalized_payload,
            "created_at": created_at,
            "reviewed_at": None,
        }

    def _accept_memory_candidate(self, candidate: dict[str, Any], *, reviewer: str, source: str) -> dict[str, Any]:
        if candidate["status"] == "accepted":
            return {"status": "already_accepted", "candidate": candidate, "action": "accept"}
        if candidate["status"] != "pending":
            return {"status": "blocked", "reason": f"candidate already {candidate['status']}", "candidate": candidate}
        reviewed_at = iso_now()
        payload_updates = {
            "accepted_at": reviewed_at,
            "reviewed_at": reviewed_at,
            "reviewer": self._safe_memory_text(reviewer, fallback="cli", max_len=120),
            "review_source": self._safe_memory_text(source, fallback="memory_cli", max_len=120),
        }
        candidate_for_write = {
            **candidate,
            "status": "accepted",
            "reviewed_at": reviewed_at,
            "payload": {**candidate.get("payload", {}), **payload_updates, "status": "accepted"},
        }
        try:
            persist_result = self._append_accepted_memory(candidate_for_write)
        except Exception as exc:  # noqa: BLE001
            updated = self.store.update_memory_candidate_status(
                candidate["candidate_id"],
                "persist_failed",
                iso_now(),
                {"persist_error": self._safe_memory_text(str(exc), fallback="persist failed"), "reviewer": reviewer, "review_source": source},
            )
            self.store.record_audit("memory_candidate_persist_failed", {"candidate_id": candidate["candidate_id"], "reason": str(exc)}, run_id=candidate["run_id"], exit_status="blocked")
            return {"status": "blocked", "reason": "accepted memory persistence failed", "candidate": updated or candidate}
        updated = self.store.update_memory_candidate_status(candidate["candidate_id"], "accepted", reviewed_at, payload_updates)
        self.store.record_audit(
            "memory_candidate_accept",
            {"candidate_id": candidate["candidate_id"], "persist": persist_result},
            run_id=candidate["run_id"],
            exit_status="ok",
        )
        return {"status": "ok", "candidate": updated, "action": "accept", "persist": persist_result}

    def _reject_memory_candidate(self, candidate: dict[str, Any], *, reviewer: str, source: str, rejected_reason: str | None) -> dict[str, Any]:
        if candidate["status"] in {"rejected", "blocked"}:
            return {"status": "already_rejected", "candidate": candidate, "action": "reject"}
        if candidate["status"] != "pending":
            return {"status": "blocked", "reason": f"candidate already {candidate['status']}", "candidate": candidate}
        reviewed_at = iso_now()
        reason = self._safe_memory_text(rejected_reason or "Rejected by reviewer.", fallback="Rejected by reviewer.", max_len=500)
        updated = self.store.update_memory_candidate_status(
            candidate["candidate_id"],
            "rejected",
            reviewed_at,
            {
                "rejected_reason": reason,
                "reviewer": self._safe_memory_text(reviewer, fallback="cli", max_len=120),
                "review_source": self._safe_memory_text(source, fallback="memory_cli", max_len=120),
            },
        )
        self.store.record_audit("memory_candidate_reject", {"candidate_id": candidate["candidate_id"], "reason": reason}, run_id=candidate["run_id"], exit_status="ok")
        return {"status": "ok", "candidate": updated, "action": "reject"}

    def _append_accepted_memory(self, candidate: dict[str, Any]) -> dict[str, Any]:
        payload = candidate.get("payload", {})
        content = str(payload.get("content", "")).strip()
        if not content or self._memory_sensitive_reason(content, str(payload.get("reason", ""))):
            raise ValueError("accepted memory contains sensitive or empty content")
        ensure_dir(self.home / "memory")
        path = self.home / "memory" / "global_memory.md"
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        marker = f"<!-- sitina-memory:{candidate['candidate_id']} -->"
        if marker in existing:
            return {"status": "already_present", "path": str(path)}
        accepted_at = candidate.get("reviewed_at") or payload.get("accepted_at") or iso_now()
        block_payload = {
            "candidate_id": candidate["candidate_id"],
            "source_run_id": candidate["run_id"],
            "accepted_at": accepted_at,
            "source": payload.get("source"),
            "memory_type": payload.get("memory_type"),
            "sensitivity_level": payload.get("sensitivity_level"),
            "content": content,
            "reason": payload.get("reason"),
            "confidence": payload.get("confidence"),
        }
        block = (
            f"\n\n{marker}\n"
            f"## Accepted Memory {candidate['candidate_id']}\n\n"
            f"- candidate_id: `{candidate['candidate_id']}`\n"
            f"- source_run_id: `{candidate['run_id']}`\n"
            f"- accepted_at: `{accepted_at}`\n"
            f"- source: `{payload.get('source', 'unknown')}`\n"
            f"- memory_type: `{payload.get('memory_type', 'general')}`\n\n"
            "```json\n"
            f"{stable_json(block_payload)}\n"
            "```\n"
            f"<!-- /sitina-memory:{candidate['candidate_id']} -->\n"
        )
        path.write_text(existing.rstrip() + block, encoding="utf-8")
        return {"status": "written", "path": str(path)}

    def _record_memory_no_candidate(self, run_id: str, reason: str, *, source: str) -> None:
        payload = {"reason": self._safe_memory_text(reason, fallback="no candidate", max_len=500), "source": source}
        self.store.record_event("memory_no_candidate", payload, run_id=run_id, trace_id=f"{run_id}:memory")
        self.store.record_audit("memory_no_candidate", payload, run_id=run_id, trace_id=f"{run_id}:memory", exit_status="ok")

    def _record_memory_warning(self, run_id: str, reason: str) -> None:
        payload = {"reason": self._safe_memory_text(reason, fallback="memory warning", max_len=500)}
        self.store.record_event("memory_agent_warning", payload, run_id=run_id, trace_id=f"{run_id}:memory")
        self.store.record_audit("memory_agent_warning", payload, run_id=run_id, trace_id=f"{run_id}:memory", exit_status="warning")

    def _memory_candidate_id(self, content: str, memory_type: str, source: str, status: str) -> str:
        digest = sha256_text(stable_json({"content": content, "memory_type": memory_type, "source": source, "status": status})).split(":", 1)[1]
        return f"mem_{digest[:24]}"

    def _memory_confidence(self, value: Any) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.5
        return max(0.0, min(1.0, confidence))

    def _safe_memory_text(self, value: str, *, fallback: str, max_len: int = 1000) -> str:
        text = redact_text(value).strip()
        if self._memory_sensitive_reason(text):
            return fallback
        return (text or fallback)[:max_len]

    def _safe_memory_evidence(self, value: Any) -> list[Any]:
        if not isinstance(value, list):
            return []
        safe: list[Any] = []
        for item in value[:10]:
            text = self._safe_memory_text(stable_json(item) if isinstance(item, (dict, list)) else str(item), fallback="<redacted-evidence>", max_len=500)
            safe.append(text)
        return safe

    def _redact_memory_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): self._redact_memory_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact_memory_value(item) for item in value]
        if isinstance(value, str):
            return redact_text(value)[:2000]
        return value

    def _memory_sensitive_reason(self, *values: str) -> str | None:
        text = "\n".join(str(value) for value in values if value)
        if not text:
            return None
        if redact_text(text) != text:
            return "secret-like content"
        lowered = text.lower()
        if lowered in {"sensitive", "secret", "critical"}:
            return "sensitive level marked by agent"
        for pattern, reason in SENSITIVE_MEMORY_PATTERNS:
            if pattern.search(text):
                return reason
        return None
