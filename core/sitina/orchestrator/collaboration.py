from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.proposals import Proposal, ProposalEvaluation, ProposalManager, ProposalRound, ProposalSelection
from sitina.orchestrator.team import TeamSelection
from sitina.runners.agent_runner import AgentRunner, AgentRunnerError
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, compute_agent_input_hash, iso_now, new_id, redact_text, sha256_text, stable_json


CollaborationPhaseName = Literal[
    "observe",
    "classify",
    "team_select",
    "propose",
    "critique",
    "arbitrate",
    "assign",
    "execute",
    "handoff",
    "verify",
    "rework",
    "resolve_conflict",
    "summarize",
    "memory_backlog",
    "audit_replay",
]


class CollaborationPhase(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    task_id: str = "main"
    task_type: str = "chat"
    phase: CollaborationPhaseName
    actor: str
    status: Literal["ok", "blocked", "warning", "pending"] = "ok"
    reason: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    payload_hash: str
    created_at: str


DispatcherDecisionSource = Literal[
    "runtime_rule",
    "controller_output",
    "arbiter_output",
    "resume_state",
    "retry_policy",
    "handoff_result",
]


class DispatcherDecision(StrictModel):
    schema_version: str = "1.0"
    decision_id: str
    run_id: str
    round_id: str
    state_snapshot_hash: str
    task_graph_hash: str
    candidate_agents: list[str] = Field(default_factory=list)
    eligible_agents: list[str] = Field(default_factory=list)
    blocked_agents: list[dict[str, str]] = Field(default_factory=list)
    selected_agent: str | None = None
    selected_task: str | None = None
    reason_code: str
    reason_summary: str
    decision_source: DispatcherDecisionSource
    created_at: str
    dispatch_mode: Literal["task_graph_constrained_dynamic_dispatch"] = "task_graph_constrained_dynamic_dispatch"
    fully_open_dynamic_dispatch: bool = False

    # Compatibility fields retained for the existing engine contract.
    task_id: str | None = None
    agent_id: str | None = None
    status: Literal["dispatch", "blocked", "complete"]
    reason: str
    dependency_refs: list[str] = Field(default_factory=list)
    blocked_candidates: list[dict[str, str]] = Field(default_factory=list)
    next_task: str | None = None


DispatchDecision = DispatcherDecision


class NegotiationResult(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    round: dict[str, Any]
    proposals: list[dict[str, Any]]
    evaluations: list[dict[str, Any]]
    selection: dict[str, Any]
    selected_task_graph_patch: dict[str, Any] = Field(default_factory=dict)


class CollaborationRuntime:
    """Coordinates the live multi-agent collaboration protocol.

    Side effects remain outside this runtime. This object decides dispatch,
    proposal competition, evaluation, arbitration, and handoff protocol events,
    then records every decision to ledger/audit/blackboard.
    """

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.ledger = RunLedger(home, self.store)
        self.blackboard = Blackboard(home, self.store)

    def record_phase(
        self,
        *,
        run_id: str,
        phase: CollaborationPhaseName,
        actor: str,
        reason: str,
        task_id: str = "main",
        task_type: str = "chat",
        status: Literal["ok", "blocked", "warning", "pending"] = "ok",
        input_refs: list[str] | None = None,
        output_refs: list[str] | None = None,
        payload: dict[str, Any] | None = None,
        blackboard_note: bool = False,
    ) -> CollaborationPhase:
        safe_payload = self._safe_payload(payload or {})
        phase_record = CollaborationPhase(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            phase=phase,
            actor=actor,
            status=status,
            reason=reason[:1000],
            input_refs=input_refs or [],
            output_refs=output_refs or [],
            payload_hash=sha256_text(stable_json(safe_payload)),
            created_at=iso_now(),
        )
        payload_json = phase_record.model_dump() | {"payload": safe_payload}
        self.ledger.record(
            "collaboration_phase",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=actor,
            status="blocked" if status == "blocked" else ("warning" if status == "warning" else "ok"),
            reason=reason,
            payload=payload_json,
        )
        self.store.record_audit(
            "collaboration_phase",
            payload_json,
            run_id=run_id,
            trace_id=f"{run_id}:collaboration:{phase}",
            agent=actor,
            exit_status=status,
            output_hash=sha256_text(stable_json(payload_json)),
        )
        if blackboard_note:
            self.blackboard.record_document(
                run_id=run_id,
                task_id=task_id,
                author_agent=actor,
                doc_type="decision" if status == "ok" else "conflict",
                content_summary=f"{phase}: {reason}",
                artifact_refs=output_refs or [],
            )
        return phase_record

    def observe(self, *, run_id: str, goal: str, risk_scan_id: str) -> CollaborationPhase:
        return self.record_phase(
            run_id=run_id,
            phase="observe",
            actor="controller",
            reason="collaboration runtime observed goal, context, risk scan, ledger and blackboard",
            input_refs=["user_goal", risk_scan_id],
            payload={"goal_hash": sha256_text(goal), "goal_preview": redact_text(goal)[:300], "risk_scan_id": risk_scan_id},
        )

    def classify(self, *, run_id: str, controller_payload: dict[str, Any]) -> CollaborationPhase:
        task_type = str(controller_payload.get("task_type") or "chat")
        return self.record_phase(
            run_id=run_id,
            phase="classify",
            actor="controller",
            task_type=task_type,
            reason=f"controller classified task as {task_type}",
            input_refs=["controller_output"],
            output_refs=[sha256_text(stable_json(controller_payload))],
            payload=controller_payload,
        )

    def assign_selected_proposal(self, *, run_id: str, task_type: str, selected: dict[str, Any]) -> CollaborationPhase:
        return self.record_phase(
            run_id=run_id,
            phase="assign",
            actor="controller",
            task_type=task_type,
            reason="selected proposal assigned to policy compiler/task graph patch",
            input_refs=[str(selected.get("proposal_round_id"))],
            output_refs=[str(selected.get("selected_proposal_id"))],
            payload=selected,
            blackboard_note=True,
        )

    def dispatch_next(self, *, run_id: str, task_graph: Any) -> DispatchDecision:
        nodes = {node.task_id: node for node in task_graph.nodes}
        completed = {task_id for task_id, node in nodes.items() if node.status == "completed"}
        blocked = [node for node in task_graph.nodes if node.status in {"blocked", "failed"} and node.mandatory]
        state_snapshot = {
            "run_id": run_id,
            "task_type": task_graph.task_type,
            "nodes": {node.task_id: {"status": node.status, "depends_on": node.depends_on, "owner_agent": node.owner_agent} for node in task_graph.nodes},
        }
        state_snapshot_hash = sha256_text(stable_json(state_snapshot))
        task_graph_hash = sha256_text(stable_json(task_graph.model_dump()))
        blocked_candidates = [
            {"task_id": node.task_id, "agent_id": node.owner_agent, "reason": node.blocked_reason or "mandatory node blocked"}
            for node in task_graph.nodes
            if node.status in {"blocked", "failed"}
        ]
        blocked_candidates.extend(
            {
                "task_id": node.task_id,
                "agent_id": node.owner_agent,
                "reason": "dependency not completed",
            }
            for node in task_graph.nodes
            if node.status == "pending" and not all(dep in completed for dep in node.depends_on)
        )
        candidate_agents = sorted(
            {
                node.owner_agent
                for node in task_graph.nodes
                if node.status not in {"completed", "skipped"}
            }
        )
        round_id = str(task_graph.proposal_round_id or "task_graph_runtime")
        if blocked:
            first = blocked[0]
            reason = first.blocked_reason or f"mandatory node blocked: {first.task_id}"
            source: DispatcherDecisionSource = "handoff_result" if "handoff" in reason.lower() else "runtime_rule"
            decision = DispatcherDecision(
                decision_id="dispatch_" + iso_now().replace(":", "").replace("-", "").replace(".", ""),
                run_id=run_id,
                round_id=round_id,
                state_snapshot_hash=state_snapshot_hash,
                task_graph_hash=task_graph_hash,
                candidate_agents=candidate_agents,
                eligible_agents=[],
                blocked_agents=blocked_candidates,
                selected_agent=None,
                selected_task=None,
                reason_code="mandatory_task_blocked",
                reason_summary=reason,
                decision_source=source,
                task_id=first.task_id,
                agent_id=first.owner_agent,
                status="blocked",
                reason=reason,
                blocked_candidates=blocked_candidates,
                next_task=None,
                created_at=iso_now(),
            )
            self._record_dispatch(decision, task_graph)
            self.record_phase(run_id=run_id, phase="execute", actor="controller", task_type=task_graph.task_type, status="blocked", reason=decision.reason, payload=decision.model_dump())
            return decision
        ready = [node for node in task_graph.nodes if node.status == "pending" and all(dep in completed for dep in node.depends_on)]
        if ready:
            # This is a state-derived priority, not a hard-coded role sequence.
            # Rework nodes supersede ordinary nodes; otherwise lexical task IDs
            # make the decision deterministic and replayable for the same state.
            ready.sort(key=lambda node: (0 if node.task_id.startswith("rework_") else 1, node.task_id, node.owner_agent))
            node = ready[0]
            rework = node.task_id.startswith("rework_")
            arbitration = node.node_type == "arbitration" or node.owner_agent == "arbiter"
            reason_code = "rework_ready" if rework else ("conflict_requires_arbitration" if arbitration else "dependency_ready")
            source = "retry_policy" if rework else "runtime_rule"
            reason = f"dispatch selected from {len(ready)} dependency-ready runtime candidates"
            decision = DispatcherDecision(
                decision_id="dispatch_" + iso_now().replace(":", "").replace("-", "").replace(".", ""),
                run_id=run_id,
                round_id=round_id,
                state_snapshot_hash=state_snapshot_hash,
                task_graph_hash=task_graph_hash,
                candidate_agents=candidate_agents,
                eligible_agents=sorted({item.owner_agent for item in ready}),
                blocked_agents=blocked_candidates,
                selected_agent=node.owner_agent,
                selected_task=node.task_id,
                reason_code=reason_code,
                reason_summary=reason,
                decision_source=source,
                task_id=node.task_id,
                agent_id=node.owner_agent,
                status="dispatch",
                reason=reason,
                dependency_refs=list(node.depends_on),
                blocked_candidates=blocked_candidates,
                next_task=node.task_id,
                created_at=iso_now(),
            )
            self._record_dispatch(decision, task_graph)
            self.record_phase(run_id=run_id, phase="execute", actor="controller", task_type=task_graph.task_type, reason=decision.reason, input_refs=list(node.depends_on), output_refs=[node.task_id], payload=decision.model_dump())
            return decision
        decision = DispatcherDecision(
            decision_id="dispatch_" + iso_now().replace(":", "").replace("-", "").replace(".", ""),
            run_id=run_id,
            round_id=round_id,
            state_snapshot_hash=state_snapshot_hash,
            task_graph_hash=task_graph_hash,
            candidate_agents=candidate_agents,
            eligible_agents=[],
            blocked_agents=blocked_candidates,
            selected_agent=None,
            selected_task=None,
            reason_code="task_graph_complete",
            reason_summary="no pending dispatchable task graph node",
            decision_source="runtime_rule",
            status="complete",
            reason="no pending dispatchable task graph node",
            blocked_candidates=blocked_candidates,
            next_task=None,
            created_at=iso_now(),
        )
        self._record_dispatch(decision, task_graph)
        self.record_phase(run_id=run_id, phase="execute", actor="controller", task_type=task_graph.task_type, reason=decision.reason, payload=decision.model_dump())
        return decision

    def _record_dispatch(self, decision: DispatchDecision, task_graph: Any) -> None:
        payload = decision.model_dump()
        self.ledger.record(
            "dispatcher_decision_created",
            run_id=decision.run_id,
            task_id=decision.task_id or "main",
            task_type=task_graph.task_type,
            agent_id="controller",
            status="blocked" if decision.status == "blocked" else "ok",
            reason=decision.reason,
            payload=payload,
        )
        explicit_event = "dispatcher_agent_selected" if decision.status == "dispatch" else "dispatcher_no_eligible_agent"
        self.ledger.record(
            explicit_event,
            run_id=decision.run_id,
            task_id=decision.task_id or "main",
            task_type=task_graph.task_type,
            agent_id=decision.selected_agent or "controller",
            status="blocked" if decision.status == "blocked" else "ok",
            reason=decision.reason,
            payload=payload,
        )
        self.ledger.record(
            "dispatch_decision",
            run_id=decision.run_id,
            task_id=decision.task_id or "main",
            task_type=task_graph.task_type,
            agent_id="controller",
            status="blocked" if decision.status == "blocked" else "ok",
            reason=decision.reason,
            payload=payload,
        )

    def _checkpoint(
        self,
        *,
        run_id: str,
        stage: str,
        proposal_ids: list[str] | None = None,
        evaluation_ids: list[str] | None = None,
        selected_proposal_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        from sitina.orchestrator.checkpoint import CheckpointManager

        try:
            CheckpointManager(self.home).create(
                run_id=run_id,
                stage=stage,
                proposal_ids=proposal_ids,
                evaluation_ids=evaluation_ids,
                selected_proposal_id=selected_proposal_id,
                extra=extra,
            )
        except Exception as exc:  # noqa: BLE001
            self.ledger.record(
                "checkpoint_failed",
                run_id=run_id,
                status="failed",
                reason=f"checkpoint failed after {stage}: {exc}",
                payload={"stage": stage},
            )
            raise

    def negotiate(
        self,
        *,
        run_id: str,
        goal: str,
        controller_payload: dict[str, Any],
        team_selection: TeamSelection,
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str] | None = None,
        fixture_conflict: bool = False,
        fixture_live_minimal: bool = False,
        depth_scenario: str | None = None,
        fixture_arbitration_block: bool = False,
        fixture_arbitration_ask_user: bool = False,
    ) -> NegotiationResult | None:
        manager = ProposalManager(self.home, self.store)
        task_type = team_selection.task_type
        enabled = set(manager.policy.get("enabled_task_types", []))
        live_enabled = set(manager.policy.get("live_enabled_task_types", []))
        should_run = fixture_conflict or task_type in live_enabled
        if task_type == "chat" and not fixture_conflict:
            from sitina.orchestrator.proposal_review_management import CompetitionAdmission

            complexity = int(controller_payload.get("complexity_score", controller_payload.get("complexity", 0)) or 0)
            risk = str(controller_payload.get("risk_level") or "low")
            if risk not in {"low", "medium", "high", "critical"}:
                risk = "low"
            total_budget = int(controller_payload.get("remaining_tokens", controller_payload.get("token_budget", 1_000_000)) or 0)
            hot_path_safe = bool(controller_payload.get("hot_path_safe", complexity < 25 and risk == "low"))
            admission = CompetitionAdmission().decide(
                task_type="chat",
                complexity=complexity,
                risk=risk,
                total_budget=total_budget,
                minimum_cost=500,
                hot_path_safe=hot_path_safe,
            )
            should_run = admission.action == "compete"
        if not should_run or task_type not in enabled:
            return None

        participants = self._proposal_participants(task_type, team_selection, manager.policy)
        if depth_scenario:
            participants = [agent for agent in ("planner", "architect", "critic", "reviewer") if agent in (set(manager.policy.get("proposer_agents", [])) | set(manager.policy.get("evaluator_agents", [])))]
        if fixture_live_minimal:
            minimal = [agent for agent in ("planner", "critic") if agent in (set(manager.policy.get("proposer_agents", [])) | set(manager.policy.get("evaluator_agents", [])))]
            if len(minimal) >= 2:
                participants = minimal
        round_ = manager.open_round(run_id=run_id, task_id="main", task_type=task_type, participants=participants)
        self.record_phase(
            run_id=run_id,
            phase="propose",
            actor="controller",
            task_type=task_type,
            reason=f"proposal round opened for live {task_type} collaboration",
            output_refs=[round_.proposal_round_id],
            payload=round_.model_dump(),
            blackboard_note=True,
        )
        proposals = self._collect_agent_proposals(
            manager,
            round_,
            goal=goal,
            controller_payload=controller_payload,
            team_selection=team_selection,
            runner=runner,
            provider_mode=provider_mode,
            profile_overrides=profile_overrides or {},
            participants=participants,
            fixture_live_minimal=fixture_live_minimal,
            proposer_agents_override=["planner", "architect"] if depth_scenario else None,
        )
        if fixture_conflict and provider_mode == "mock":
            proposals.append(
                manager.submit(
                    round_,
                    proposer_agent="planner",
                    proposal_type="implementation_strategy",
                    summary="Unsafe proposal requesting direct patch apply.",
                    risk_level="high",
                    task_graph_patch={"direct_side_effect": "patch_apply"},
                    required_gates=["bypass_reviewer"],
                    forbidden_actions=["patch_apply"],
                    known_risks=["would bypass reviewer gate"],
                    bid={
                        "estimated_steps": 1,
                        "estimated_risk": "high",
                        "required_tools": ["patch_apply"],
                        "required_side_effects": ["patch_apply"],
                        "assumptions": ["reviewer gate can be bypassed"],
                        "confidence": 0.1,
                        "safety_notes": ["unsafe direct apply"],
                    },
                )
            )
        self._checkpoint(
            run_id=run_id,
            stage="proposers_completed",
            proposal_ids=[proposal.proposal_id for proposal in proposals],
            extra={"proposal_round_id": round_.proposal_round_id},
        )
        evaluations = self._evaluate_proposals(
            manager,
            round_,
            proposals,
            goal=goal,
            controller_payload=controller_payload,
            runner=runner,
            provider_mode=provider_mode,
            profile_overrides=profile_overrides or {},
            participants=participants,
            fixture_live_minimal=fixture_live_minimal,
            evaluator_agents_override=["critic", "reviewer"] if depth_scenario else None,
        )
        self._checkpoint(
            run_id=run_id,
            stage="evaluators_completed",
            proposal_ids=[proposal.proposal_id for proposal in proposals],
            evaluation_ids=[evaluation.evaluation_id for evaluation in evaluations],
            extra={"proposal_round_id": round_.proposal_round_id},
        )
        if depth_scenario and proposals:
            debate_evaluations = self._run_live_debate(
                manager,
                round_,
                proposals,
                goal=goal,
                controller_payload=controller_payload,
                team_selection=team_selection,
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides or {},
            )
            evaluations.extend(debate_evaluations)
            revisions = self._run_live_revisions(
                manager,
                round_,
                proposals,
                evaluations,
                goal=goal,
                controller_payload=controller_payload,
                team_selection=team_selection,
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides or {},
            )
            for revision in revisions:
                proposals.append(revision)
            if revisions:
                evaluations.extend(
                    self._evaluate_proposals(
                        manager,
                        round_,
                        revisions,
                        goal=goal,
                        controller_payload=controller_payload,
                        runner=runner,
                        provider_mode=provider_mode,
                        profile_overrides=profile_overrides or {},
                        participants=participants,
                        evaluator_agents_override=["critic", "reviewer"],
                    )
                )
        self.record_phase(
            run_id=run_id,
            phase="critique",
            actor="critic",
            task_type=task_type,
            reason="proposal evaluations recorded by evaluator agents",
            input_refs=[proposal.proposal_id for proposal in proposals],
            output_refs=[item.evaluation_id for item in evaluations],
            payload={"proposal_ids": [proposal.proposal_id for proposal in proposals], "evaluation_ids": [item.evaluation_id for item in evaluations]},
        )
        selection = manager.select(round_, proposals, evaluations)
        if depth_scenario and selection.selected_proposal_id:
            selected_evaluations = [item for item in evaluations if item.proposal_id == selection.selected_proposal_id]
            if any(item.decision in {"needs_revision", "block"} for item in selected_evaluations):
                rejected = dict(selection.rejected) | {selection.selected_proposal_id: "selected proposal has unresolved evaluator revision/block finding"}
                selection = ProposalSelection(
                    proposal_round_id=round_.proposal_round_id,
                    run_id=round_.run_id,
                    selected_proposal_id=None,
                    status="blocked",
                    reason="selected proposal retains unresolved evaluator findings",
                    rejected=rejected,
                    created_at=iso_now(),
                )
                manager.ledger.record(
                    "proposal_blocked",
                    run_id=round_.run_id,
                    task_id=round_.task_id,
                    task_type=round_.task_type,
                    agent_id="controller",
                    status="blocked",
                    reason=selection.reason,
                    payload=selection.model_dump(),
                )
        self._checkpoint(
            run_id=run_id,
            stage="selection_completed",
            proposal_ids=[proposal.proposal_id for proposal in proposals],
            evaluation_ids=[evaluation.evaluation_id for evaluation in evaluations],
            selected_proposal_id=selection.selected_proposal_id,
            extra={"proposal_round_id": round_.proposal_round_id},
        )
        selected_patch = self._selected_patch(selection, proposals)
        arbitration_result: dict[str, Any] | None = None
        decisions_by_proposal: dict[str, set[str]] = {}
        for evaluation in evaluations:
            decisions_by_proposal.setdefault(evaluation.proposal_id, set()).add(evaluation.decision)
        evaluator_conflict = any(
            ("support" in decisions and ("oppose" in decisions or "block" in decisions))
            for decisions in decisions_by_proposal.values()
        )
        if len(proposals) > 1 and (evaluator_conflict or fixture_arbitration_block or fixture_arbitration_ask_user):
            claims = [selection.reason]
            if fixture_arbitration_block:
                claims.append("force_arbitration_block")
            if fixture_arbitration_ask_user:
                claims.append("force_arbitration_ask_user")
            arbitration_result = self.arbitrate(
                run_id=run_id,
                task_id="main",
                task_type=task_type,
                conflict_type="proposal_conflict",
                participants=sorted({proposal.proposer_agent for proposal in proposals}),
                resources=[proposal.proposal_id for proposal in proposals],
                claims=claims,
                context={
                    "proposal_author_map": {proposal.proposal_id: proposal.proposer_agent for proposal in proposals},
                    "proposal_summaries": [
                        {
                            "proposal_id": proposal.proposal_id,
                            "proposer_agent": proposal.proposer_agent,
                            "strategy": proposal.task_graph_patch.get("strategy"),
                            "required_gates": proposal.required_gates,
                        }
                        for proposal in proposals
                    ],
                    "selection": selection.model_dump(),
                    "evaluations": [
                        {
                            "proposal_id": evaluation.proposal_id,
                            "reviewer_agent": evaluation.reviewer_agent,
                            "decision": evaluation.decision,
                            "score": evaluation.score,
                            "reason": evaluation.reason,
                        }
                        for evaluation in evaluations
                    ],
                },
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides or {},
            )
            if arbitration_result.get("decision") in {"block", "ask_user"}:
                rejected = {proposal.proposal_id: f"arbitration {arbitration_result.get('decision')} blocked proposal round" for proposal in proposals}
                selection = ProposalSelection(
                    proposal_round_id=round_.proposal_round_id,
                    run_id=round_.run_id,
                    selected_proposal_id=None,
                    status="blocked",
                    reason=str(arbitration_result.get("reason") or "arbitration blocked proposal round"),
                    rejected=rejected,
                    created_at=iso_now(),
                )
                manager.ledger.record("proposal_blocked", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id="arbiter", status="blocked", reason=selection.reason, payload=selection.model_dump() | {"arbitration": arbitration_result})
                manager.store.record_audit("proposal_blocked", selection.model_dump() | {"arbitration": arbitration_result}, run_id=round_.run_id, trace_id=f"{round_.run_id}:proposal:{round_.proposal_round_id}:arbitration_block", agent="arbiter", exit_status="blocked")
                self.blackboard.record_document(run_id=round_.run_id, task_id=round_.task_id, author_agent="arbiter", doc_type="conflict", content_summary=selection.reason, related_docs=list(rejected))
                selected_patch = {}
        self.record_phase(
            run_id=run_id,
            phase="arbitrate",
            actor="arbiter" if len(proposals) > 1 else "controller",
            task_type=task_type,
            status="blocked" if selection.status == "blocked" else "ok",
            reason=selection.reason,
            input_refs=[round_.proposal_round_id],
            output_refs=[selection.selected_proposal_id] if selection.selected_proposal_id else [],
            payload=selection.model_dump(),
            blackboard_note=True,
        )
        return NegotiationResult(
            run_id=run_id,
            round=round_.model_dump(),
            proposals=[proposal.model_dump() for proposal in proposals],
            evaluations=[evaluation.model_dump() for evaluation in evaluations],
            selection=selection.model_dump() | ({"arbitration": arbitration_result} if arbitration_result else {}),
            selected_task_graph_patch=selected_patch,
        )


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
    ) -> dict[str, Any]:
        from sitina.orchestrator.arbitration import ArbitrationManager

        result = ArbitrationManager(self.home, self.store).arbitrate(
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            conflict_type=conflict_type,
            participants=participants,
            resources=resources,
            claims=claims,
            context=context,
            runner=runner,
            provider_mode=provider_mode,
            profile_overrides=profile_overrides or {},
        )
        self.record_phase(
            run_id=run_id,
            phase="resolve_conflict",
            actor="arbiter",
            task_id=task_id,
            task_type=task_type,
            status="blocked" if result.get("decision") in {"block", "ask_user"} else "ok",
            reason=str(result.get("reason") or result.get("resolution_reason") or "arbitration completed"),
            input_refs=resources,
            output_refs=[str(result.get("arbitration_id"))],
            payload=result,
            blackboard_note=True,
        )
        return result

    def handoff(self, *, contract: Any, accepted: bool, reason: str, reviewer: str | None = None) -> dict[str, Any]:
        from sitina.orchestrator.handoff import HandoffManager

        manager = HandoffManager(self.home, self.store)
        updated = manager.accept_handoff(contract.handoff_id, reviewer=reviewer or contract.to_agent, reason=reason) if accepted else manager.reject_handoff(contract.handoff_id, reviewer=reviewer or contract.to_agent, reason=reason)
        self.record_phase(
            run_id=contract.run_id,
            phase="handoff",
            actor=reviewer or contract.to_agent,
            task_id=contract.task_id,
            task_type=contract.task_type,
            status="ok" if accepted else "blocked",
            reason=reason,
            input_refs=[contract.handoff_id],
            output_refs=[updated.handoff_id],
            payload=updated.model_dump(),
        )
        return updated.model_dump()

    def _safe_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        return canonicalize_agent_input(payload)

    def _proposal_participants(self, task_type: str, team_selection: TeamSelection, policy: dict[str, Any]) -> list[str]:
        allowed = set(policy.get("proposer_agents", [])) | set(policy.get("evaluator_agents", []))
        participants = set(team_selection.proposer_set) | set(team_selection.evaluator_set)
        if task_type == "local_file_query":
            participants.update({"researcher", "critic", "arbiter"})
        elif task_type == "maintenance":
            participants.update({"reviewer", "security", "critic", "arbiter"})
        elif task_type == "high_risk_code_change":
            participants.update({"planner", "architect", "tester", "reviewer", "security", "critic", "arbiter"})
        else:
            participants.update({"planner", "tester", "reviewer", "security", "critic", "arbiter"})
        return sorted(participants & allowed)

    def _collect_agent_proposals(
        self,
        manager: ProposalManager,
        round_: ProposalRound,
        *,
        goal: str,
        controller_payload: dict[str, Any],
        team_selection: TeamSelection,
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str],
        participants: list[str],
        fixture_live_minimal: bool = False,
        proposer_agents_override: list[str] | None = None,
    ) -> list[Proposal]:
        proposer_agents = proposer_agents_override or [agent for agent in participants if agent in set(manager.policy.get("proposer_agents", []))]
        if not proposer_agents:
            proposer_agents = ["planner"] if "planner" in team_selection.selected_agents else []
        proposals: list[Proposal] = []
        for agent in proposer_agents:
            try:
                output = self._run_agent(
                    runner,
                    agent,
                    self._proposal_agent_input(agent, goal, controller_payload, team_selection),
                    run_id=round_.run_id,
                    task_id="proposal",
                    task_type=round_.task_type,
                    provider_mode=provider_mode,
                    profile_override=profile_overrides.get(agent),
                )
            except Exception as exc:  # noqa: BLE001
                self.record_phase(run_id=round_.run_id, phase="propose", actor=agent, task_type=round_.task_type, status="warning", reason=f"{agent} proposal failed: {exc}", payload={"agent": agent, "error": str(exc)})
                if provider_mode == "live" and proposer_agents_override is not None:
                    raise AgentRunnerError(
                        f"required live depth proposer {agent} failed: {exc}",
                        error_type=getattr(exc, "error_type", "provider_failed"),
                    ) from exc
                continue
            proposals.append(
                self._submit_from_agent_output(
                    manager,
                    round_,
                    agent,
                    output.payload,
                    team_selection,
                    controller_payload,
                    execution_contract=self._minimal_live_contract(goal) if fixture_live_minimal else None,
                )
            )
        if not proposals and provider_mode == "live":
            self.record_phase(
                run_id=round_.run_id,
                phase="propose",
                actor="controller",
                task_type=round_.task_type,
                status="blocked",
                reason="no live proposer produced a schema-valid provider-backed proposal",
                payload={"provider_mode": "live", "fallback_used": False},
                blackboard_note=True,
            )
            return []
        if not proposals:
            proposals.append(
                manager.submit(
                    round_,
                    proposer_agent="planner",
                    proposal_type="task_graph",
                    summary="No proposer produced a valid bid; fail-closed policy graph selected for review.",
                    risk_level="high" if round_.task_type == "high_risk_code_change" else "medium",
                    task_graph_patch={"strategy": "fail_closed_no_valid_agent_bid"},
                    required_gates=self._required_gates(round_.task_type),
                    known_risks=["no proposer agent produced a schema-valid proposal"],
                    bid={"estimated_steps": 0, "estimated_risk": "high", "confidence": 0.0, "safety_notes": ["fail closed"], "assumptions": ["no valid agent proposal available"]},
                )
            )
        return proposals

    def _evaluate_proposals(
        self,
        manager: ProposalManager,
        round_: ProposalRound,
        proposals: list[Proposal],
        *,
        goal: str,
        controller_payload: dict[str, Any],
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str],
        participants: list[str],
        fixture_live_minimal: bool = False,
        evaluator_agents_override: list[str] | None = None,
    ) -> list[ProposalEvaluation]:
        evaluator_agents = evaluator_agents_override or [agent for agent in participants if agent in set(manager.policy.get("evaluator_agents", []))]
        if fixture_live_minimal:
            evaluator_agents = [agent for agent in ("critic", "reviewer", "security", "tester") if agent in evaluator_agents][:1]
        elif evaluator_agents_override is None and round_.task_type in {"code_change", "high_risk_code_change", "maintenance"}:
            evaluator_agents = sorted(set(evaluator_agents) | {"critic", "security"})
        evaluations: list[ProposalEvaluation] = []
        for proposal in proposals:
            for agent in evaluator_agents:
                if agent == proposal.proposer_agent:
                    continue
                try:
                    output = self._run_agent(
                        runner,
                        agent,
                        self._evaluation_agent_input(agent, goal, controller_payload, proposal),
                        run_id=round_.run_id,
                        task_id="proposal_evaluation",
                        task_type=round_.task_type,
                        provider_mode=provider_mode,
                        profile_override=profile_overrides.get(agent),
                    )
                    evaluation = self._evaluation_from_agent_output(manager, round_, proposal, agent, output.payload)
                    evaluations.append(evaluation)
                    if proposal.revision_id:
                        self.ledger.record(
                            "proposal_revision_evaluated",
                            run_id=round_.run_id,
                            task_id=round_.task_id,
                            task_type=round_.task_type,
                            agent_id=agent,
                            status="blocked" if evaluation.decision == "block" else "ok",
                            reason="provider-backed evaluator reviewed a linked proposal revision",
                            payload={
                                "revision_id": proposal.revision_id,
                                "revision_round": proposal.revision_round,
                                "proposal_id": proposal.proposal_id,
                                "parent_proposal_id": proposal.parent_proposal_id,
                                "evaluation_id": evaluation.evaluation_id,
                                "reviewer_agent": evaluation.reviewer_agent,
                                "decision": evaluation.decision,
                                "score": evaluation.score,
                            },
                        )
                except Exception as exc:  # noqa: BLE001
                    if provider_mode == "live":
                        self.record_phase(
                            run_id=round_.run_id,
                            phase="critique",
                            actor=agent,
                            task_type=round_.task_type,
                            status="blocked",
                            reason=f"live evaluator failed closed: {exc}",
                            payload={"agent": agent, "proposal_id": proposal.proposal_id, "provider_mode": "live", "fallback_used": False},
                        )
                        raise
                    if round_.task_type == "high_risk_code_change" and agent == "security":
                        evaluations.append(manager.evaluate(round_, proposal, reviewer_agent="security", score=0, decision="block", reason=f"security evaluation failed fail-closed: {exc}", safety_issues=["security_evaluation_failed"]))
                    else:
                        self.record_phase(run_id=round_.run_id, phase="critique", actor=agent, task_type=round_.task_type, status="warning", reason=f"{agent} evaluation failed: {exc}", payload={"agent": agent, "proposal_id": proposal.proposal_id, "error": str(exc)})
            if proposal.status == "blocked" and not any(e.proposal_id == proposal.proposal_id and e.decision == "block" for e in evaluations):
                evaluations.append(manager.evaluate(round_, proposal, reviewer_agent="security", score=0, decision="block", reason=proposal.blocked_reason or "proposal blocked by policy", safety_issues=proposal.forbidden_actions or ["policy_invalid"]))
        return evaluations

    def _submit_from_agent_output(
        self,
        manager: ProposalManager,
        round_: ProposalRound,
        agent: str,
        payload: dict[str, Any],
        team_selection: TeamSelection,
        controller_payload: dict[str, Any],
        *,
        parent: Proposal | None = None,
        revision_round: int = 0,
        execution_contract: dict[str, Any] | None = None,
    ) -> Proposal:
        ext = payload.get("extensions", {}) if isinstance(payload.get("extensions"), dict) else {}
        bid_data = ext.get("proposal_bid") if isinstance(ext.get("proposal_bid"), dict) else {}
        risk = self._risk_level(
            bid_data.get("estimated_risk"),
            default="low" if round_.task_type == "local_file_query" else ("high" if round_.task_type == "high_risk_code_change" else "medium"),
        )
        required_gates = self._string_list(bid_data.get("required_gates"), default=self._required_gates(round_.task_type))
        task_graph_patch = bid_data.get("task_graph_patch") if isinstance(bid_data.get("task_graph_patch"), dict) else self._task_graph_patch(round_.task_type, agent)
        summary = str(bid_data.get("summary") or self._summary_from_payload(agent, payload, round_.task_type))
        bid = {
            "estimated_steps": self._bounded_int(bid_data.get("estimated_steps"), default=self._estimated_steps(round_.task_type, agent), minimum=0, maximum=50),
            "estimated_risk": risk,
            "required_agents": self._string_list(bid_data.get("required_agents"), default=team_selection.required_agents),
            "required_tools": self._string_list(bid_data.get("required_tools"), default=controller_payload.get("requested_tools") or []),
            "required_gates": required_gates,
            "read_paths": self._string_list(bid_data.get("read_paths"), default=(execution_contract or {}).get("read_paths") or []),
            "write_paths": self._string_list(bid_data.get("write_paths")),
            "writable_scope": self._string_list(bid_data.get("writable_scope"), default=(execution_contract or {}).get("writable_scope") or []),
            "touched_files": self._string_list(
                bid_data.get("touched_files"),
                default=[] if execution_contract and execution_contract.get("source_mutation_allowed") is False else controller_payload.get("target_paths") or [],
            ),
            "required_side_effects": self._string_list(bid_data.get("required_side_effects")),
            "assumptions": self._string_list(bid_data.get("assumptions"), default=["Agent proposal derived from schema-valid agent output."]),
            "confidence": self._bounded_float(bid_data.get("confidence"), default=0.7, minimum=0.0, maximum=1.0),
            "rollback_plan": self._string_list(bid_data.get("rollback_plan"), default=["No mutation before approval; rollback handled by existing gates."]),
            "verification_plan": self._string_list(bid_data.get("verification_plan"), default=self._verification_plan(round_.task_type)),
            "expected_artifacts": self._string_list(bid_data.get("expected_artifacts"), default=["task_graph", "run_ledger"]),
            "safety_notes": self._string_list(bid_data.get("safety_notes"), default=["proposal enters policy compiler instead of executing directly"]),
        }
        common = {
            "proposer_agent": agent,
            "summary": summary,
            "risk_level": risk,
            "task_graph_patch": task_graph_patch,
            "required_gates": required_gates,
            "claimed_benefits": self._string_list(bid_data.get("claimed_benefits"), default=[f"{agent} produced a schema-valid proposal"]),
            "known_risks": self._string_list(bid_data.get("known_risks")),
            "forbidden_actions": self._string_list(bid_data.get("forbidden_actions")),
            "bid": bid,
        }
        if parent is not None:
            return manager.revise(round_, parent, revision_round=revision_round, execution_contract=execution_contract, **common)
        return manager.submit(
            round_,
            proposal_type=self._proposal_type(bid_data.get("proposal_type")),
            execution_contract=execution_contract,
            **common,
        )

    def _run_live_debate(
        self,
        manager: ProposalManager,
        round_: ProposalRound,
        proposals: list[Proposal],
        *,
        goal: str,
        controller_payload: dict[str, Any],
        team_selection: TeamSelection,
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str],
    ) -> list[ProposalEvaluation]:
        """Run a bounded, provider-backed debate before final selection."""

        debate_id = "debate_" + iso_now().replace(":", "").replace("-", "").replace(".", "")
        proposal_payloads = [self._proposal_evidence_summary(proposal) for proposal in proposals]
        self.ledger.record(
            "debate_round_opened",
            run_id=round_.run_id,
            task_id=round_.task_id,
            task_type=round_.task_type,
            agent_id="controller",
            status="ok",
            reason="provider-backed cross-agent debate opened",
            payload={"debate_id": debate_id, "round": 1, "proposal_ids": [proposal.proposal_id for proposal in proposals], "max_rounds": 1},
        )
        critic_input = {
            "debate_question": "Compare both proposals, identify the strongest hidden risk, and state concrete changes needed before selection.",
            "current_plan": {
                "goal": self._short_text(goal, 1200),
                "controller": self._controller_evidence_summary(controller_payload),
                "proposals": proposal_payloads,
                "debate_id": debate_id,
            },
            "risk_context": {"task_type": round_.task_type, "side_effects": "forbidden", "debate_round": 1},
            "allowed_read_scope": [str(self.home)],
            "blackboard_context": self._blackboard_context(round_.run_id),
        }
        critic = self._run_agent(runner, "critic", critic_input, run_id=round_.run_id, task_id="debate_critic", task_type=round_.task_type, provider_mode=provider_mode, profile_override=profile_overrides.get("critic"))
        responses: list[dict[str, Any]] = [{"agent_id": "critic", "output_hash": sha256_text(stable_json(critic.payload))}]
        for proposal in proposals:
            agent = proposal.proposer_agent
            response_input = self._proposal_agent_input(agent, goal, controller_payload, team_selection)
            debate_context = self._compact_debate_context(debate_id, proposal, critic.payload)
            if agent == "planner":
                response_input["project_context"]["debate_context"] = debate_context
                response_input["conversation_summary"] = "Give a compact defense or correction to the critic in extensions.proposal_bid."
            else:
                response_input["current_plan"]["debate_context"] = debate_context
                response_input["constraints"].append("Give a compact response to critic evidence; do not perform side effects.")
            response_input["blackboard_context"] = self._blackboard_context(round_.run_id, max_items=4)
            response = self._run_agent(runner, agent, response_input, run_id=round_.run_id, task_id=f"debate_response_{agent}", task_type=round_.task_type, provider_mode=provider_mode, profile_override=profile_overrides.get(agent))
            descriptor = {"agent_id": agent, "proposal_id": proposal.proposal_id, "output_hash": sha256_text(stable_json(response.payload))}
            responses.append(descriptor)
            self.ledger.record("debate_response", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id=agent, status="ok", reason="proposer response generated from critic output", payload={"debate_id": debate_id, **descriptor, "source_agent": "critic"})
        evaluations: list[ProposalEvaluation] = []
        for proposal in proposals:
            review_input = self._evaluation_agent_input("reviewer", goal, controller_payload | {"extensions": {"debate": {"debate_id": debate_id, "responses": responses}}}, proposal)
            review_input["mandatory_step_context"]["debate_evaluation_instruction"] = (
                "For this controlled readonly protocol, accept when the proposal preserves no-side-effect boundaries, "
                "uses only allowed read scope, and the debate reveals no concrete policy violation. Request changes only for a specific unresolved defect."
            )
            reviewed = self._run_agent(runner, "reviewer", review_input, run_id=round_.run_id, task_id="debate_reviewer_compare", task_type=round_.task_type, provider_mode=provider_mode, profile_override=profile_overrides.get("reviewer"))
            evaluations.append(self._evaluation_from_agent_output(manager, round_, proposal, "reviewer", reviewed.payload))
        self.ledger.record("debate_round_closed", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id="reviewer", status="ok", reason="reviewer comparison evaluations will affect proposal selection", payload={"debate_id": debate_id, "response_count": len(responses), "evaluation_ids": [item.evaluation_id for item in evaluations]})
        self.record_phase(run_id=round_.run_id, phase="critique", actor="reviewer", task_type=round_.task_type, reason="cross-agent debate completed with reviewer evaluations", input_refs=[debate_id], output_refs=[item.evaluation_id for item in evaluations], payload={"debate_id": debate_id, "responses": responses}, blackboard_note=True)
        return evaluations

    def _run_live_revisions(
        self,
        manager: ProposalManager,
        round_: ProposalRound,
        proposals: list[Proposal],
        evaluations: list[ProposalEvaluation],
        *,
        goal: str,
        controller_payload: dict[str, Any],
        team_selection: TeamSelection,
        runner: AgentRunner,
        provider_mode: str,
        profile_overrides: dict[str, str],
    ) -> list[Proposal]:
        by_id = {proposal.proposal_id: proposal for proposal in proposals}
        revision_requests = [evaluation for evaluation in evaluations if evaluation.decision == "needs_revision" and evaluation.proposal_id in by_id]
        if not revision_requests:
            self.record_phase(run_id=round_.run_id, phase="rework", actor="controller", task_type=round_.task_type, status="warning", reason="live evaluators did not request a proposal revision", payload={"proposal_ids": [proposal.proposal_id for proposal in proposals]}, blackboard_note=True)
            return []
        request = revision_requests[0]
        parent = by_id[request.proposal_id]
        input_payload = self._proposal_agent_input(parent.proposer_agent, goal, controller_payload, team_selection)
        revision_context = {
            "parent_proposal": self._proposal_evidence_summary(parent),
            "evaluation": self._evaluation_evidence_summary(request),
            "instruction": (
                "Revise the proposal specifically against the evaluator-required changes. When the required change cites the controlled "
                "depth_revision_contract, set extensions.proposal_bid.task_graph_patch.revision_evidence=critic_gap_addressed."
            ),
        }
        if parent.proposer_agent == "planner":
            input_payload["project_context"]["revision_context"] = revision_context
            input_payload["conversation_summary"] = "Produce a revised proposal_bid linked to the supplied critique."
        else:
            input_payload["current_plan"]["revision_context"] = revision_context
            input_payload["constraints"].append("Address the evaluator-required changes in extensions.proposal_bid.")
        output = self._run_agent(runner, parent.proposer_agent, input_payload, run_id=round_.run_id, task_id="proposal_revision", task_type=round_.task_type, provider_mode=provider_mode, profile_override=profile_overrides.get(parent.proposer_agent))
        revised = self._submit_from_agent_output(
            manager,
            round_,
            parent.proposer_agent,
            output.payload,
            team_selection,
            controller_payload,
            parent=parent,
            revision_round=parent.revision_round + 1,
            execution_contract=self._minimal_live_contract(goal),
        )
        self.record_phase(run_id=round_.run_id, phase="rework", actor=parent.proposer_agent, task_type=round_.task_type, status="blocked" if revised.status == "blocked" else "ok", reason="provider-backed proposal revision created from evaluator critique", input_refs=[parent.proposal_id, request.evaluation_id], output_refs=[revised.proposal_id], payload=revised.model_dump(), blackboard_note=True)
        return [revised]

    def _evaluation_from_agent_output(self, manager: ProposalManager, round_: ProposalRound, proposal: Proposal, agent: str, payload: dict[str, Any]) -> ProposalEvaluation:
        ext = payload.get("extensions", {}) if isinstance(payload.get("extensions"), dict) else {}
        raw = ext.get("proposal_evaluation") if isinstance(ext.get("proposal_evaluation"), dict) else {}
        raw_decision = str(raw.get("decision") or "").strip().lower()
        decision_aliases = {
            "accept": "support",
            "accepted": "support",
            "approve": "support",
            "approved": "support",
            "approve_with_changes": "needs_revision",
            "accept_with_changes": "needs_revision",
            "request_changes": "needs_revision",
            "needs_changes": "needs_revision",
            "revise": "needs_revision",
            "reject": "oppose",
            "rejected": "oppose",
        }
        decision = decision_aliases.get(raw_decision, raw_decision)
        if decision not in {"support", "oppose", "needs_revision", "block"}:
            if agent == "security" and (payload.get("decision") == "block" or payload.get("severity") in {"major", "critical"}):
                decision = "block"
            elif payload.get("decision") in {"request_changes", "needs_changes"}:
                decision = "needs_revision"
            elif payload.get("decision") in {"counterargument", "cannot_complete"} and payload.get("objections"):
                decision = "oppose"
            else:
                decision = "support"
        contract_write_rejection = bool(
            proposal.status == "blocked"
            and proposal.blocked_reason
            and "no-side-effect contract rejects write intent" in proposal.blocked_reason
        )
        if contract_write_rejection:
            decision = "block"
        claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
        supported_negative_claims = [
            claim
            for claim in claims
            if isinstance(claim, dict)
            and claim.get("label") in {"confirmed", "inferred"}
            and isinstance(claim.get("evidence_ref"), list)
            and bool(claim.get("evidence_ref"))
        ]
        if agent == "critic" and decision in {"oppose", "block"} and not supported_negative_claims and not contract_write_rejection:
            original_decision = decision
            decision = "support"
            reason = str(raw.get("reason") or payload.get("resolution_reason") or payload.get("overall_recommendation") or payload.get("decision") or "proposal evaluated")
            reason = f"{reason} (critic concerns retained as advisory: no confirmed/inferred evidence-backed blocking claim)"
            self.ledger.record(
                "proposal_evaluation_evidence_insufficient",
                run_id=round_.run_id,
                task_id=round_.task_id,
                task_type=round_.task_type,
                agent_id=agent,
                status="warning",
                reason="negative critic evaluation was advisory because its claims lacked confirmed/inferred evidence",
                payload={
                    "proposal_id": proposal.proposal_id,
                    "original_decision": original_decision,
                    "normalized_decision": decision,
                    "claim_labels": [claim.get("label") for claim in claims if isinstance(claim, dict)],
                },
            )
        else:
            reason = (
                str(proposal.blocked_reason)
                if contract_write_rejection
                else str(raw.get("reason") or payload.get("resolution_reason") or payload.get("overall_recommendation") or payload.get("decision") or "proposal evaluated")
            )
        score = self._bounded_int(raw.get("score"), default=90 if decision == "support" else (55 if decision == "needs_revision" else 0 if decision == "block" else 40), minimum=0, maximum=100)
        return manager.evaluate(
            round_,
            proposal,
            reviewer_agent=agent,
            score=score,
            decision=decision,
            reason=reason,
            safety_issues=self._string_list(raw.get("safety_issues"), default=payload.get("security_findings") or []),
            quality_issues=self._string_list(raw.get("quality_issues"), default=payload.get("objections") or []),
            required_changes=self._string_list(raw.get("required_changes")),
        )

    def _bounded_int(self, value: Any, *, default: int, minimum: int, maximum: int) -> int:
        try:
            if isinstance(value, str) and value.strip().lower() in {"low", "minor"}:
                parsed = minimum
            elif isinstance(value, str) and value.strip().lower() in {"medium", "moderate"}:
                parsed = (minimum + maximum) // 2
            elif isinstance(value, str) and value.strip().lower() in {"high", "major"}:
                parsed = maximum
            elif isinstance(value, str) and value.strip().lower() == "critical":
                parsed = maximum
            else:
                parsed = int(float(value))
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(maximum, parsed))

    @staticmethod
    def _proposal_type(value: Any) -> str:
        raw = str(value or "task_graph").strip().lower()
        allowed = {"task_graph", "implementation_strategy", "test_strategy", "risk_strategy", "review_strategy"}
        aliases = {
            "readonly_architecture_analysis": "task_graph",
            "readonly_analysis": "task_graph",
            "architecture_analysis": "task_graph",
            "architecture_plan": "task_graph",
            "architecture_strategy": "task_graph",
            "architecture_change": "task_graph",
            "code_change": "task_graph",
            "plan": "task_graph",
            "implementation_plan": "implementation_strategy",
            "verification_strategy": "test_strategy",
            "security_strategy": "risk_strategy",
        }
        normalized = aliases.get(raw, raw)
        if normalized not in allowed:
            raise ValueError(f"unsupported proposal_type: {raw}")
        return normalized

    def _bounded_float(self, value: Any, *, default: float, minimum: float, maximum: float) -> float:
        try:
            if isinstance(value, str) and value.strip().lower() in {"low", "minor"}:
                parsed = minimum
            elif isinstance(value, str) and value.strip().lower() in {"medium", "moderate"}:
                parsed = (minimum + maximum) / 2
            elif isinstance(value, str) and value.strip().lower() in {"high", "major", "critical"}:
                parsed = maximum
            else:
                parsed = float(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(maximum, parsed))

    def _risk_level(self, value: Any, *, default: str) -> str:
        risk = str(value or default).strip().lower()
        return risk if risk in {"low", "medium", "high", "critical"} else default

    def _string_list(self, value: Any, *, default: Any | None = None) -> list[str]:
        source = default if value in (None, "") else value
        if source in (None, ""):
            return []
        if isinstance(source, str):
            return [source]
        if isinstance(source, (list, tuple, set)):
            return [str(item) for item in source if item not in (None, "")]
        return [str(source)]

    def _compact_debate_context(self, debate_id: str, proposal: Proposal, critic_payload: dict[str, Any]) -> dict[str, Any]:
        """Keep a debate response causally grounded without recursively copying full turns."""

        evaluation = critic_payload.get("extensions", {}).get("proposal_evaluation", {})
        if not isinstance(evaluation, dict):
            evaluation = {}
        return {
            "debate_id": debate_id,
            "own_proposal": {
                "proposal_id": proposal.proposal_id,
                "summary": self._short_text(proposal.summary, 600),
                "risk_level": proposal.risk_level,
                "required_gates": proposal.required_gates[:6],
                "required_agents": proposal.bid.required_agents[:8],
                "proposal_hash": sha256_text(stable_json(proposal.model_dump())),
            },
            "critic": {
                "agent_id": "critic",
                "decision": critic_payload.get("decision"),
                "objections": [self._short_text(item, 360) for item in critic_payload.get("objections", [])[:3]],
                "required_changes": [self._short_text(item, 360) for item in evaluation.get("required_changes", [])[:3]],
                "reason": self._short_text(evaluation.get("reason") or critic_payload.get("overall_recommendation") or "", 600),
                "output_hash": sha256_text(stable_json(critic_payload)),
            },
        }

    @staticmethod
    def _short_text(value: Any, limit: int) -> str:
        text = str(value or "").replace("\n", " ").replace("\r", " ").strip()
        return text[:limit]

    def _proposal_agent_input(self, agent: str, goal: str, controller_payload: dict[str, Any], team_selection: TeamSelection) -> dict[str, Any]:
        readonly_contract = self._readonly_analysis_contract(goal, controller_payload)
        minimal_live_contract = self._minimal_live_contract(goal)
        team_context = self._team_evidence_summary(team_selection)
        if agent == "planner":
            project_context = {"home": str(self.home), "collaboration_mode": "proposal_authoring", "team_selection": team_context}
            if readonly_contract:
                project_context["readonly_analysis_contract"] = readonly_contract
            if minimal_live_contract:
                project_context["minimal_live_contract"] = minimal_live_contract
            proposal_instruction = "Author a proposal_bid in extensions.proposal_bid."
            if minimal_live_contract:
                proposal_instruction += (
                    " This is a runtime-enforced no-side-effect fixture: set required_tools=[], required_side_effects=[], "
                    "write_paths=[], writable_scope=[], and touched_files=[]; put the supplied project root only in read_paths; "
                    "limit required_agents to the contract participants; keep source mutation forbidden; "
                    "and include controlled_noop_policy_graph=true plus real_side_effects_forbidden=true in task_graph_patch."
                )
            return {
                "user_goal": goal,
                "project_context": project_context,
                "allowed_read_scope": [str(self.home)],
                "risk_policy": {"risk_level": team_selection.risk_level, "approval_required": False, "task_type": team_selection.task_type},
                "conversation_summary": proposal_instruction + (" Use the supplied readonly analysis contract and inventory as evidence." if readonly_contract else ""),
                "blackboard_context": self._blackboard_context(team_selection.run_id, max_items=4),
            }
        if agent == "architect":
            current_plan = {"controller": self._controller_evidence_summary(controller_payload), "team_selection": team_context, "blackboard_context": self._blackboard_context(team_selection.run_id, max_items=4)}
            if readonly_contract:
                current_plan["readonly_analysis_contract"] = readonly_contract
            return {"architecture_question": self._short_text(goal, 1200), "current_plan": current_plan, "constraints": ["preserve approval/test/reviewer gates"] + (["use the readonly analysis inventory and do not propose a no-op placeholder"] if readonly_contract else []), "rollback_requirements": ["describe rollback before any mutation"], "blackboard_context": self._blackboard_context(team_selection.run_id, max_items=4)}
        if agent == "tester":
            return {"test_strategy": "Author a verification proposal for this task.", "allowed_commands": ["sitina config validate"], "patch_id": "proposal_only", "changed_files": ["__PROPOSAL_ONLY__"], "approved_env": {"SITINA_HOME": str(self.home)}, "expected_artifact_hash": None, "blackboard_context": self._blackboard_context(team_selection.run_id)}
        if agent == "reviewer":
            return {"patch_id": "proposal_only", "changed_files": ["__PROPOSAL_ONLY__"], "acceptance_criteria": ["proposal preserves gates"], "test_artifacts": ["proposal_only"], "mandatory_step_context": {"proposal_authoring": True, "task_type": team_selection.task_type, "blackboard_context": self._blackboard_context(team_selection.run_id)}, "blackboard_context": self._blackboard_context(team_selection.run_id)}
        if agent == "researcher":
            return {"research_question": goal, "source_policy": {"mode": "local_readonly"}, "allowed_sources": [str(self.home)], "approval_id_if_web": None, "blackboard_context": self._blackboard_context(team_selection.run_id)}
        raise ValueError(f"agent cannot author proposal: {agent}")

    @staticmethod
    def _team_evidence_summary(team_selection: TeamSelection) -> dict[str, Any]:
        return {
            "run_id": team_selection.run_id,
            "task_id": team_selection.task_id,
            "task_type": team_selection.task_type,
            "risk_level": team_selection.risk_level,
            "required_agents": team_selection.required_agents,
            "proposer_set": team_selection.proposer_set,
            "evaluator_set": team_selection.evaluator_set,
            "selected_agents": team_selection.selected_agents,
            "forbidden_agents": team_selection.forbidden_agents,
        }

    def _evaluation_agent_input(self, agent: str, goal: str, controller_payload: dict[str, Any], proposal: Proposal) -> dict[str, Any]:
        depth_revision_scenario = any(
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
        current_plan = {
            "goal": self._short_text(goal, 1200),
            "controller": self._controller_evidence_summary(controller_payload),
            "proposal": self._proposal_evidence_summary(proposal),
            "blackboard_context": self._blackboard_context(proposal.run_id, max_items=6),
        }
        readonly_contract = self._readonly_analysis_contract(goal, controller_payload)
        if readonly_contract:
            current_plan["readonly_analysis_contract"] = readonly_contract
        minimal_live_contract = self._minimal_live_contract(goal)
        if minimal_live_contract:
            current_plan["minimal_live_contract"] = minimal_live_contract
        if depth_revision_scenario:
            current_plan["depth_revision_contract"] = {
                "required_task_graph_patch_field": "revision_evidence",
                "expected_value": "critic_gap_addressed",
                "purpose": "force one evidence-grounded revision edge in the controlled depth scenario",
            }
        if agent == "security":
            return {"security_question": "Evaluate this proposal for gate bypass, side effects, and sensitive-data risk.", "current_plan": current_plan, "risk_context": {"proposal_risk": proposal.risk_level, "required_gates": proposal.required_gates}, "allowed_read_scope": [str(self.home)], "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "critic":
            question = "Find hidden assumptions or unsafe shortcuts in this proposal."
            if minimal_live_contract:
                question = (
                    "Evaluate the proposal against minimal_live_contract. The code_change label only enters proposal policy and "
                    "does not authorize mutation. Return support only when required_tools, required_side_effects, write_paths, "
                    "writable_scope, and touched_files are empty, read_paths contains only the allowed read scope, source mutation "
                    "remains forbidden, and the no-side-effect task graph flags are present; otherwise "
                    "return needs_revision or block with the exact contract gap. Do not require mutation gates for a contract-compliant no-op."
                )
            if depth_revision_scenario:
                question = (
                    "Check the supplied depth_revision_contract against proposal.task_graph_patch. When its required field/value is absent, "
                    "return extensions.proposal_evaluation.decision=needs_revision with that exact repair in required_changes; do not invent other blockers."
                )
            return {"debate_question": question, "current_plan": current_plan, "risk_context": {"proposal_risk": proposal.risk_level}, "allowed_read_scope": [str(self.home)], "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "reviewer":
            return {"patch_id": "proposal_only", "changed_files": ["__PROPOSAL_ONLY__"], "acceptance_criteria": ["proposal preserves mandatory gates"], "test_artifacts": ["proposal_only"], "mandatory_step_context": {"proposal": proposal.model_dump(), "blackboard_context": self._blackboard_context(proposal.run_id)}, "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "architect":
            return {"architecture_question": "Evaluate proposal architecture and rollback plan.", "current_plan": current_plan, "constraints": ["preserve task graph integrity"], "rollback_requirements": proposal.bid.rollback_plan or ["no mutation before approval"], "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "tester":
            return {"test_strategy": "Evaluate proposal verification plan.", "allowed_commands": ["sitina config validate"], "patch_id": "proposal_only", "changed_files": ["__PROPOSAL_ONLY__"], "approved_env": {"SITINA_HOME": str(self.home)}, "expected_artifact_hash": None, "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "researcher":
            return {"research_question": "Evaluate whether proposal needs additional local evidence.", "source_policy": {"mode": "local_readonly"}, "allowed_sources": [str(self.home)], "approval_id_if_web": None, "blackboard_context": self._blackboard_context(proposal.run_id)}
        if agent == "arbiter":
            return {"conflict_id": proposal.proposal_id, "conflict_type": "proposal_conflict", "participants": [proposal.proposer_agent, "policy"], "claims": [proposal.summary], "resources": [proposal.proposal_id], "policy_context": {"proposal": proposal.model_dump(), "blackboard_context": self._blackboard_context(proposal.run_id)}, "blackboard_context": self._blackboard_context(proposal.run_id)}
        raise ValueError(f"agent cannot evaluate proposal: {agent}")

    def _minimal_live_contract(self, goal: str) -> dict[str, Any] | None:
        if "live-minimal-collaboration-fixture" not in goal.lower():
            return None
        return {
            "fixture": "live-minimal-collaboration-fixture",
            "runtime_graph": "controlled_noop_policy_graph",
            "task_type_label": "code_change",
            "task_type_label_purpose": "enter proposal policy without authorizing source mutation",
            "participants": ["controller", "planner", "critic", "summary"],
            "agent_availability_enforcement": "each live call loads its configured profile and fails closed without fallback",
            "real_side_effects_forbidden": True,
            "source_mutation_allowed": False,
            "tool_execution_allowed": False,
            "read_paths": [str(self.home)],
            "write_paths": [],
            "writable_scope": [],
            "required_tools": [],
            "required_side_effects": [],
            "touched_files": [],
            "required_task_graph_flags": {
                "controlled_noop_policy_graph": True,
                "real_side_effects_forbidden": True,
            },
        }

    def _controller_evidence_summary(self, controller_payload: dict[str, Any]) -> dict[str, Any]:
        extensions = controller_payload.get("extensions") if isinstance(controller_payload.get("extensions"), dict) else {}
        return {
            "task_type": controller_payload.get("task_type"),
            "risk_level": controller_payload.get("risk_level"),
            "need_tester": controller_payload.get("need_tester"),
            "need_reviewer": controller_payload.get("need_reviewer"),
            "target_paths": controller_payload.get("target_paths", []),
            "readonly_analysis_inventory": extensions.get("readonly_analysis_inventory"),
        }

    def _proposal_evidence_summary(self, proposal: Proposal) -> dict[str, Any]:
        return {
            "proposal_id": proposal.proposal_id,
            "proposer_agent": proposal.proposer_agent,
            "summary": self._short_text(proposal.summary, 900),
            "risk_level": proposal.risk_level,
            "task_graph_patch": proposal.task_graph_patch,
            "required_gates": proposal.required_gates,
            "expected_artifacts": proposal.bid.expected_artifacts,
            "verification_plan": proposal.bid.verification_plan,
            "safety_notes": proposal.bid.safety_notes,
            "assumptions": proposal.bid.assumptions,
            "parent_proposal_id": proposal.parent_proposal_id,
            "revision_id": proposal.revision_id,
            "revision_round": proposal.revision_round,
            "status": proposal.status,
        }

    @staticmethod
    def _evaluation_evidence_summary(evaluation: ProposalEvaluation) -> dict[str, Any]:
        return {
            "evaluation_id": evaluation.evaluation_id,
            "proposal_id": evaluation.proposal_id,
            "reviewer_agent": evaluation.reviewer_agent,
            "decision": evaluation.decision,
            "score": evaluation.score,
            "reason": evaluation.reason,
            "safety_issues": evaluation.safety_issues,
            "quality_issues": evaluation.quality_issues,
            "required_changes": evaluation.required_changes,
        }

    def _required_gates(self, task_type: str) -> list[str]:
        if task_type == "local_file_query":
            return ["filesystem_readonly", "summary", "memory_check"]
        if task_type == "maintenance":
            return ["approval", "audit", "summary", "memory_check"]
        if task_type == "high_risk_code_change":
            return ["tester", "multi_reviewer_merge", "approval", "patch_hash_verify", "patch_apply", "memory_check"]
        return ["tester", "reviewer", "memory_check"]

    @staticmethod
    def _readonly_analysis_contract(goal: str, controller_payload: dict[str, Any]) -> dict[str, Any] | None:
        if not any(
            marker in goal.lower()
            for marker in (
                "live-depth-collaboration-fixture",
                "live-two-proposer-fixture",
                "live-negotiation-fixture",
                "live-revision-fixture",
                "live-debate-fixture",
                "live-complex-readonly-fixture",
            )
        ):
            return None
        inventory = dict((controller_payload.get("extensions") or {}).get("readonly_analysis_inventory") or {})
        return {
            "operation": "readonly architecture consistency analysis",
            "required_task_graph_strategy": "readonly_architecture_analysis",
            "required_artifacts": ["readonly_module_inventory", "architecture_consistency_report"],
            "required_gates": ["tester", "reviewer", "memory_check", "sensitive_path_review"],
            "required_verification": ["inventory hash matches report", "exact listed read scope", "no subprocess or dynamic execution", "no network or source mutation", "bounded by run deadline", "later repository changes marked unverified"],
            "side_effects": "forbidden",
            "source_mutation": "forbidden",
            "inventory": {
                "inventory_hash": inventory.get("inventory_hash"),
                "report_hash": inventory.get("report_hash"),
                "module_count": inventory.get("module_count"),
                "module_paths": inventory.get("module_paths", []),
                "execution_controls": inventory.get("execution_controls", {}),
                "report_contract": inventory.get("report_contract", {}),
            },
        }

    def _task_graph_patch(self, task_type: str, agent: str) -> dict[str, Any]:
        if task_type == "local_file_query":
            return {"strategy": "readonly_context_query", "side_effects": "forbidden", "proposed_by": agent}
        if task_type == "maintenance":
            return {"strategy": "maintenance_descriptor_only", "direct_mutation": False, "proposed_by": agent}
        if task_type == "high_risk_code_change":
            return {"strategy": "high_risk_policy_graph", "proposed_by": agent}
        return {"strategy": "policy_compiler_noop_code_graph", "proposed_by": agent}

    def _summary_from_payload(self, agent: str, payload: dict[str, Any], task_type: str) -> str:
        if agent == "architect":
            return "Architecture proposal: " + "; ".join(payload.get("architecture_decisions") or ["preserve guarded architecture"])
        if agent == "tester":
            return "Tester proposal: verify task graph and rerun mandatory gates."
        if agent == "reviewer":
            return "Reviewer proposal: preserve review gate and block unsafe findings."
        if agent == "researcher":
            return "Researcher proposal: use readonly evidence gathering and cite local sources."
        return f"{agent} proposal for {task_type}."

    def _estimated_steps(self, task_type: str, agent: str) -> int:
        if task_type == "local_file_query":
            return 2
        if task_type == "maintenance":
            return 4
        if task_type == "high_risk_code_change":
            return 6 if agent == "architect" else 5
        return 3

    def _verification_plan(self, task_type: str) -> list[str]:
        if task_type == "local_file_query":
            return ["verify readonly filesystem query", "summarize cited evidence"]
        if task_type == "maintenance":
            return ["require approval", "record audit", "verify no direct mutation before approval"]
        if task_type == "high_risk_code_change":
            return ["tester gate", "multi-reviewer merge", "approval artifact", "patch hash verify"]
        return ["tester gate", "reviewer gate", "replay diff"]

    def _blackboard_context(self, run_id: str, *, max_items: int = 10) -> list[dict[str, Any]]:
        return self.blackboard.summary(run_id, max_items=max_items)

    def _selected_patch(self, selection: ProposalSelection, proposals: list[Proposal]) -> dict[str, Any]:
        for proposal in proposals:
            if proposal.proposal_id == selection.selected_proposal_id:
                return proposal.task_graph_patch
        return {}

    def _run_agent(
        self,
        runner: AgentRunner,
        agent: str,
        input_payload: dict[str, Any],
        *,
        run_id: str,
        task_id: str,
        task_type: str,
        provider_mode: str,
        profile_override: str | None,
    ) -> Any:
        safe_input_payload = self._safe_payload(input_payload)
        raw_input_hash = sha256_text(stable_json(input_payload))
        safe_input_hash = compute_agent_input_hash(input_payload)
        logical_call_id = "logical_call_" + new_id()
        audit_context = self._agent_call_audit_context(agent, task_id, input_payload)
        self.ledger.record(
            "agent_started",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="ok",
            reason=f"{agent} collaboration call started",
            payload={
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "provider_mode": provider_mode,
                "collaboration": True,
                "call_id": logical_call_id,
                "input_payload": safe_input_payload,
                "input_hash_semantics": "sha256(stable_json(redacted_input_payload))",
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
                audit_context=audit_context,
            )
        except Exception as exc:  # noqa: BLE001
            self.ledger.record(
                "agent_blocked",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent_id=agent,
                status="failed",
                reason=str(exc),
                payload={"input_hash": safe_input_hash, "raw_input_hash": raw_input_hash, "safe_input_hash": safe_input_hash, "provider_mode": provider_mode, "collaboration": True, "call_id": logical_call_id},
            )
            raise
        if result.payload.get("agent_status") == "cannot_complete":
            reason = str(result.payload.get("blocked_reason") or (result.payload.get("extensions") or {}).get("reason") or f"{agent} reported agent_status=cannot_complete")
            self.ledger.record(
                "agent_blocked",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent_id=agent,
                status="blocked",
                reason=reason,
                payload={"input_hash": safe_input_hash, "provider_mode": provider_mode, "collaboration": True, "agent_status": "cannot_complete"},
            )
            raise AgentRunnerError(reason, error_type="agent_cannot_complete")
        output_hash = sha256_text(stable_json(result.payload))
        trace_id = f"{run_id}:collaboration:{task_id}:{agent}"
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
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "output_hash": output_hash,
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
                "collaboration": True,
                "call_id": logical_call_id,
            },
            run_id=run_id,
            trace_id=trace_id,
            agent=agent,
            input_hash=safe_input_hash,
            output_hash=output_hash,
            exit_status="ok",
        )
        self.ledger.record(
            "agent_completed",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="ok",
            reason=f"{agent} collaboration call completed",
            payload={
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "output_hash": output_hash,
                "provider_mode": result.provider_mode,
                "profile_name": result.profile_name,
                "model": result.model,
                "provider_identity": result.provider_identity,
                "provider_calls": result.provider_calls,
                "fallback_used": result.fallback_used,
                "collaboration": True,
                "call_id": logical_call_id,
            },
        )
        return result

    @staticmethod
    def _agent_call_audit_context(agent: str, task_id: str, input_payload: dict[str, Any]) -> dict[str, Any]:
        context: dict[str, Any] = {"call_origin": "collaboration", "role": agent}
        current_plan = input_payload.get("current_plan") if isinstance(input_payload.get("current_plan"), dict) else {}
        proposal = current_plan.get("proposal") if isinstance(current_plan.get("proposal"), dict) else {}
        if proposal.get("proposal_id"):
            context["proposal_id"] = proposal["proposal_id"]
        project_context = input_payload.get("project_context") if isinstance(input_payload.get("project_context"), dict) else {}
        revision = project_context.get("revision_context") if isinstance(project_context.get("revision_context"), dict) else {}
        parent = revision.get("parent_proposal") if isinstance(revision.get("parent_proposal"), dict) else {}
        evaluation = revision.get("evaluation") if isinstance(revision.get("evaluation"), dict) else {}
        if parent.get("proposal_id"):
            context["proposal_id"] = parent["proposal_id"]
        if evaluation.get("evaluation_id"):
            context["evaluation_id"] = evaluation["evaluation_id"]
        if task_id.startswith("rework_"):
            context["rework_id"] = task_id
        if "retry" in task_id:
            context["retry_id"] = task_id
        return context
