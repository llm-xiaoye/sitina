from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sitina.constants import AGENTS, PHASES


AgentName = Literal[
    "controller",
    "planner",
    "architect",
    "coder",
    "tester",
    "reviewer",
    "security",
    "critic",
    "arbiter",
    "researcher",
    "memory",
    "summary",
]
RiskLevel = Literal["low", "medium", "high", "critical"]
RiskAction = Literal["allow", "approval", "block"]
VerificationStatus = Literal["not_verified", "partially_verified", "verified", "unable_to_verify"]
TaskType = Literal[
    "chat",
    "local_file_query",
    "code_change",
    "high_risk_code_change",
    "maintenance",
    "memory_review",
    "mcp_tool_task",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(StrictModel):
    ref: str
    kind: Literal["artifact", "file", "url", "obsidian", "audit", "event"] = "artifact"
    trust_level: Literal["trusted", "local_note", "official", "general_web", "untrusted"] = "untrusted"


class Claim(StrictModel):
    text: str
    label: Literal["confirmed", "inferred", "suggested", "unverified", "unable_to_verify"]
    evidence_ref: list[str] = Field(default_factory=list)


class CommonAgentOutput(StrictModel):
    schema_version: str = "1.0"
    agent: AgentName
    agent_status: Literal["ok", "need_more_input", "cannot_complete"]
    decision: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    verification_status: VerificationStatus = "not_verified"
    warnings: list[str] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)


class ControllerOutput(CommonAgentOutput):
    agent: Literal["controller"] = "controller"
    decision: Literal["next_agent", "skip", "insert", "rework", "block", "approval", "summarize"]
    next_agent: AgentName
    mandatory_steps_ack: bool = True
    task_type: TaskType
    need_planner: bool
    need_coder: bool
    need_filesystem: bool
    need_tester: bool
    need_reviewer: bool
    risk_level: RiskLevel
    requested_tools: list[str]
    target_paths: list[str]
    next_agents: list[AgentName]
    blocked_reason: str | None


class PlannerOutput(CommonAgentOutput):
    agent: Literal["planner"] = "planner"
    decision: Literal["plan", "blocked", "need_input"] = "plan"
    plan_steps: list[str]
    acceptance_criteria: list[str]
    proposed_touched_files: list[str]
    risk_assessment: dict[str, Any]


class ArchitectOutput(CommonAgentOutput):
    agent: Literal["architect"] = "architect"
    decision: Literal["architecture_plan", "blocked", "need_input"] = "architecture_plan"
    architecture_decisions: list[str]
    rollback_plan: list[str]
    boundary_notes: list[str]


class CoderOutput(CommonAgentOutput):
    agent: Literal["coder"] = "coder"
    decision: Literal["changed", "unchanged", "blocked"] = "changed"
    input_scope_hash: str
    files_touched: list[str]
    patch_id: str
    scope_compliance: Literal["in_scope", "out_of_scope", "unknown"]


class TesterOutput(CommonAgentOutput):
    agent: Literal["tester"] = "tester"
    decision: Literal["pass", "fail", "blocked", "skipped"] = "pass"
    tests_run: list[str]
    acceptance_results: list[dict[str, Any]]
    artifact_hash: str | None = None
    resolved_findings: list[str] = Field(default_factory=list)


class ReviewerFinding(StrictModel):
    severity: Literal["critical", "major", "minor"]
    file: str
    line: int | None = None
    message: str
    suggested_fix: str | None = None
    finding_id: str | None = None


class ReviewerOutput(CommonAgentOutput):
    agent: Literal["reviewer"] = "reviewer"
    decision: Literal["accept", "request_changes", "blocked"] = "accept"
    findings: list[ReviewerFinding] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)
    overall_recommendation: Literal["accept", "request_changes", "block"]

    @model_validator(mode="after")
    def no_accept_with_blockers(self) -> "ReviewerOutput":
        if self.overall_recommendation == "accept":
            for finding in self.findings:
                if finding.severity in {"critical", "major"}:
                    raise ValueError("reviewer cannot accept with critical or major findings")
        return self


class SecurityOutput(CommonAgentOutput):
    agent: Literal["security"] = "security"
    decision: Literal["support", "needs_changes", "block", "cannot_complete"] = "support"
    security_findings: list[str] = Field(default_factory=list)
    severity: Literal["none", "minor", "major", "critical"] = "none"

    @model_validator(mode="after")
    def no_support_with_blockers(self) -> "SecurityOutput":
        if self.decision == "support" and self.severity in {"major", "critical"}:
            raise ValueError("security cannot support with major or critical severity")
        return self


class CriticOutput(CommonAgentOutput):
    agent: Literal["critic"] = "critic"
    decision: Literal["counterargument", "no_objection", "cannot_complete"] = "counterargument"
    objections: list[str] = Field(default_factory=list)


class ArbiterOutput(CommonAgentOutput):
    agent: Literal["arbiter"] = "arbiter"
    decision: Literal["grant_agent_a", "grant_agent_b", "merge", "block", "ask_user"] = "block"
    conflict_id: str
    conflict_type: str
    winning_agent: str | None = None
    resolution_reason: str
    rework_required: bool = False


class ResearcherOutput(CommonAgentOutput):
    agent: Literal["researcher"] = "researcher"
    decision: Literal["evidence", "cannot_complete"] = "evidence"
    sources_checked: list[str]
    untrusted_blocks: list[str] = Field(default_factory=list)


class MemoryCandidateProposal(StrictModel):
    content: str = Field(min_length=1, max_length=8_000)
    reason: str = Field(min_length=1, max_length=1_000)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]*$")
    memory_type: Literal["general", "preference", "workflow_rule", "fact", "lesson", "constraint"] = "general"
    sensitivity_level: Literal["low", "moderate", "high", "restricted"] = "low"
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=64)


class MemoryOutput(CommonAgentOutput):
    agent: Literal["memory"] = "memory"
    decision: Literal["candidate", "none", "cannot_complete"] = "candidate"
    candidates: list[MemoryCandidateProposal] = Field(default_factory=list, max_length=32)


class SummaryOutput(CommonAgentOutput):
    agent: Literal["summary"] = "summary"
    decision: Literal["summary", "blocked"] = "summary"
    user_summary: str
    verification_status_derived: VerificationStatus
    unverified_items: list[str] = Field(default_factory=list)


class MandatorySteps(StrictModel):
    tester_required: bool = False
    reviewer_required: bool = False
    architect_required: bool = False


class MandatoryStepOutputs(StrictModel):
    tester_turn_id: str | None = None
    reviewer_turn_id: str | None = None
    architect_turn_id: str | None = None


class RunState(StrictModel):
    run_id: str
    phase: Literal[
        "created",
        "planning",
        "awaiting_approval",
        "coding",
        "testing",
        "reviewing",
        "controller_decision",
        "summarizing",
        "done",
        "blocked",
        "timeout",
        "cancelled",
        "interrupted",
        "failed",
        "paused",
    ] = "created"
    active_agent: AgentName | None = None
    risk_level: RiskLevel = "critical"
    approval_required: bool = True
    approval_id: str | None = None
    rework_count: int = 0
    max_rework_rounds: int = 2
    mandatory_steps: MandatorySteps = Field(default_factory=MandatorySteps)
    mandatory_step_outputs: MandatoryStepOutputs = Field(default_factory=MandatoryStepOutputs)
    open_findings: list[ReviewerFinding] = Field(default_factory=list)
    verification_status: VerificationStatus = "not_verified"
    locks_held: list[str] = Field(default_factory=list)
    risk_scan_result_ref: str | None = None
    updated_by: Literal["harness"] = "harness"


class RiskMatch(StrictModel):
    rule_id: str
    risk_level: RiskLevel
    action: RiskAction
    reason: str


class RiskScanResult(StrictModel):
    risk_scan_id: str
    operation: str
    target: str | None = None
    command: str | None = None
    risk_level: RiskLevel
    action: RiskAction
    approval_required: bool
    matches: list[RiskMatch] = Field(default_factory=list)
    risk_scan_hash: str
    created_at: str


class ApprovalRecord(StrictModel):
    approval_id: str
    run_id: str
    action: Literal["approve", "reject", "request_changes", "timeout"]
    scope_hash: str
    risk_scan_id: str
    risk_scan_hash: str
    plan_hash: str
    approved_touched_files: list[str]
    approved_commands: list[str] = Field(default_factory=list)
    expires_at: str
    created_at: str


class ArtifactRecord(StrictModel):
    artifact_hash: str
    run_id: str
    turn_id: str
    producing_agent: AgentName
    producing_command_fingerprint: str
    artifact_path: str
    created_at: str


class AgentInputBase(StrictModel):
    blackboard_context: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def reject_empty_required_values(self) -> "AgentInputBase":
        for name in type(self).model_fields:
            value = getattr(self, name)
            if value == "" or value == [] or value == {}:
                raise ValueError(f"{name} must not be empty")
        return self


class ControllerInput(AgentInputBase):
    user_goal: str
    run_state: RunState
    last_agent_output: dict[str, Any]
    risk_scan_result: RiskScanResult
    unresolved_findings: list[dict[str, Any]]
    workflow_state: dict[str, Any]


class PlannerInput(AgentInputBase):
    user_goal: str
    project_context: dict[str, Any]
    allowed_read_scope: list[str]
    risk_policy: dict[str, Any]
    conversation_summary: str


class ArchitectInput(AgentInputBase):
    architecture_question: str
    current_plan: dict[str, Any]
    constraints: list[str]
    rollback_requirements: list[str]


class CoderInput(AgentInputBase):
    approved_touched_files: list[str]
    plan: dict[str, Any]
    acceptance_criteria: list[str]
    approval_id: str
    allowed_scope: list[str]
    input_scope_hash: str
    before_hashes: dict[str, str | None]
    file_write_contract: dict[str, Any]


class TesterInput(AgentInputBase):
    test_strategy: str
    allowed_commands: list[str]
    patch_id: str
    changed_files: list[str]
    approved_env: dict[str, str]
    expected_artifact_hash: str | None = None


class ReviewerInput(AgentInputBase):
    patch_id: str
    changed_files: list[str]
    acceptance_criteria: list[str]
    test_artifacts: list[str]
    mandatory_step_context: dict[str, Any]


class SecurityInput(AgentInputBase):
    security_question: str
    current_plan: dict[str, Any]
    risk_context: dict[str, Any]
    allowed_read_scope: list[str]


class CriticInput(AgentInputBase):
    debate_question: str
    current_plan: dict[str, Any]
    risk_context: dict[str, Any]
    allowed_read_scope: list[str]


class ArbiterInput(AgentInputBase):
    conflict_id: str
    conflict_type: str
    participants: list[str]
    claims: list[str]
    resources: list[str]
    policy_context: dict[str, Any]


class ResearcherInput(AgentInputBase):
    research_question: str
    source_policy: dict[str, Any]
    allowed_sources: list[str]
    approval_id_if_web: str | None = None


class MemoryInput(AgentInputBase):
    run_summary: str
    user_visible_decisions: list[str]
    memory_policy: dict[str, Any]


class SummaryInput(AgentInputBase):
    final_run_state: RunState
    tester_output: dict[str, Any]
    reviewer_output: dict[str, Any]
    audit_refs: list[str]


AGENT_OUTPUT_MODELS = {
    "common": CommonAgentOutput,
    "controller": ControllerOutput,
    "planner": PlannerOutput,
    "architect": ArchitectOutput,
    "coder": CoderOutput,
    "tester": TesterOutput,
    "reviewer": ReviewerOutput,
    "security": SecurityOutput,
    "critic": CriticOutput,
    "arbiter": ArbiterOutput,
    "researcher": ResearcherOutput,
    "memory": MemoryOutput,
    "summary": SummaryOutput,
}

AGENT_INPUT_MODELS = {
    "controller": ControllerInput,
    "planner": PlannerInput,
    "architect": ArchitectInput,
    "coder": CoderInput,
    "tester": TesterInput,
    "reviewer": ReviewerInput,
    "security": SecurityInput,
    "critic": CriticInput,
    "arbiter": ArbiterInput,
    "researcher": ResearcherInput,
    "memory": MemoryInput,
    "summary": SummaryInput,
}


def validate_agent_input(agent: str, payload: dict[str, Any]) -> AgentInputBase:
    if agent not in AGENT_INPUT_MODELS:
        raise ValueError(f"unknown agent: {agent}")
    return AGENT_INPUT_MODELS[agent].model_validate(payload)


def validate_agent_output(agent: str, payload: dict[str, Any]) -> CommonAgentOutput:
    if agent not in AGENT_OUTPUT_MODELS:
        raise ValueError(f"unknown output schema: {agent}")
    model = AGENT_OUTPUT_MODELS[agent]
    result = model.model_validate(payload)
    major = str(result.schema_version).split(".", 1)[0]
    if major != "1":
        raise ValueError("schema_version major must be 1")
    return result
