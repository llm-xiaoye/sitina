from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from sitina.constants import SITINA_HOME
from sitina.orchestrator.autonomy import BacklogItem, LongTermGoal, Milestone, ProjectPlan
from sitina.orchestrator.blackboard import BlackboardDocument
from sitina.orchestrator.collaboration import CollaborationPhase
from sitina.orchestrator.handoff import AgentOutputEnvelope, HandoffContract
from sitina.orchestrator.ledger import LedgerEvent
from sitina.orchestrator.leases import ArbitrationNode, ResourceLease
from sitina.orchestrator.parallel import ParallelGroup, ParallelMergeResult
from sitina.orchestrator.policy import ControllerDecision, ExecutionPlan
from sitina.orchestrator.proposals import Proposal, ProposalBid, ProposalEvaluation, ProposalRound, ProposalSelection
from sitina.orchestrator.replay import ReplayResult, ReplaySimulationResult, SideEffectDescriptor
from sitina.orchestrator.retry import RetryDecision
from sitina.orchestrator.reviewers import ReviewerDecision, ReviewerMergeResult
from sitina.orchestrator.side_effects import SideEffectRequest
from sitina.orchestrator.task_graph import ReworkEdge, TaskGraph, TaskGraphNode
from sitina.orchestrator.team import AgentCapability, TeamSelection
from sitina.schemas.models import (
    ApprovalRecord,
    ArtifactRecord,
    ArbiterOutput,
    CoderOutput,
    MemoryOutput,
    PlannerOutput,
    ReviewerOutput,
    RiskScanResult,
    SecurityOutput,
    TesterOutput,
)


class SchemaRegistry:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home

    def models(self) -> dict[str, type[BaseModel]]:
        return {
            "controller_decision": ControllerDecision,
            "execution_plan": ExecutionPlan,
            "agent_output_envelope": AgentOutputEnvelope,
            "handoff_contract": HandoffContract,
            "planner_task_graph": PlannerOutput,
            "coder_change": CoderOutput,
            "tester_result": TesterOutput,
            "security_result": SecurityOutput,
            "arbiter_decision": ArbiterOutput,
            "reviewer_decision": ReviewerDecision,
            "legacy_reviewer_output": ReviewerOutput,
            "memory_candidate": MemoryOutput,
            "mcp_result": ArtifactRecord,
            "git_patch_artifact": ArtifactRecord,
            "approval_artifact": ApprovalRecord,
            "risk_scan_result": RiskScanResult,
            "run_ledger_event": LedgerEvent,
            "retry_decision": RetryDecision,
            "reviewer_merge": ReviewerMergeResult,
            "parallel_group": ParallelGroup,
            "parallel_merge": ParallelMergeResult,
            "task_graph": TaskGraph,
            "task_graph_node": TaskGraphNode,
            "rework_edge": ReworkEdge,
            "replay_result": ReplayResult,
            "replay_simulation_result": ReplaySimulationResult,
            "side_effect_descriptor": SideEffectDescriptor,
            "side_effect_request": SideEffectRequest,
            "proposal_round": ProposalRound,
            "proposal": Proposal,
            "proposal_bid": ProposalBid,
            "proposal_evaluation": ProposalEvaluation,
            "proposal_selection": ProposalSelection,
            "blackboard_document": BlackboardDocument,
            "agent_capability": AgentCapability,
            "team_selection": TeamSelection,
            "resource_lease": ResourceLease,
            "arbitration_node": ArbitrationNode,
            "collaboration_phase": CollaborationPhase,
            "long_term_goal": LongTermGoal,
            "backlog_item": BacklogItem,
            "project_plan": ProjectPlan,
            "milestone": Milestone,
        }

    def json_schemas(self) -> dict[str, dict[str, Any]]:
        return {name: model.model_json_schema() for name, model in self.models().items()}

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        for name, model in self.models().items():
            try:
                schema = model.model_json_schema()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"schema registry model {name} cannot export JSON schema: {exc}")
                continue
            if schema.get("additionalProperties") is not False:
                warnings.append(f"schema registry {name} root additionalProperties is not explicit; inherited StrictModel still forbids extras")
        return errors, warnings
