from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from sitina.journal.model import validate_identifier, validate_timestamp
from sitina.security.redaction import sensitive_field_paths


def _identifier(value: str) -> str:
    return validate_identifier(value, field="contract_identifier")


def _timestamp(value: str) -> str:
    return validate_timestamp(value)


Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$", min_length=1, max_length=255),
    AfterValidator(_identifier),
]
Timestamp = Annotated[str, AfterValidator(_timestamp)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
CASReference = Annotated[str, StringConstraints(pattern=r"^cas:[0-9a-f]{64}$", min_length=68, max_length=68)]
TrustLevel = Literal["untrusted", "derived", "verified", "authoritative"]


class ContractModel(BaseModel):
    """Strict immutable interchange data; never a persistence or policy owner."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_sensitive_fields(cls, value: Any) -> Any:
        paths = sensitive_field_paths(value)
        if paths:
            raise ValueError(f"sensitive fields are forbidden at the contract boundary: {list(paths)}")
        return value


class SourceDescriptor(ContractModel):
    component: Identifier
    actor_id: Identifier | None = None
    source_ref: Identifier | CASReference | None = None


class VersionedRecord(ContractModel):
    schema_version: Literal["1.0"]
    correlation_id: Identifier
    causation_id: Identifier | None
    created_at: Timestamp
    source: SourceDescriptor
    trust: TrustLevel
    extensions: dict[str, Any] = Field(default_factory=dict)


TaskStatus = Literal[
    "PENDING",
    "READY",
    "RUNNING",
    "BLOCKED",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    "SKIPPED",
]


class TaskContract(VersionedRecord):
    schema_id: Literal["SITINA_TASK_V1"] = Field(alias="schema")
    task_id: Identifier
    graph_id: Identifier
    specification_hash: Digest
    status: TaskStatus
    required: bool
    owner_id: Identifier | None = None
    attempt: int = Field(default=0, ge=0)
    updated_at: Timestamp | None = None


class DependencyContract(VersionedRecord):
    schema_id: Literal["SITINA_TASK_DEPENDENCY_V1"] = Field(alias="schema")
    dependency_id: Identifier
    graph_id: Identifier
    task_id: Identifier
    depends_on_task_id: Identifier
    kind: Literal["hard", "soft", "gate"] = "hard"

    @model_validator(mode="after")
    def _no_self_dependency(self) -> "DependencyContract":
        if self.task_id == self.depends_on_task_id:
            raise ValueError("a task cannot depend on itself")
        return self


class TaskGraphContract(VersionedRecord):
    schema_id: Literal["SITINA_TASK_GRAPH_V1"] = Field(alias="schema")
    graph_id: Identifier
    run_id: Identifier
    graph_version: int = Field(ge=0)
    tasks: tuple[TaskContract, ...] = ()
    dependencies: tuple[DependencyContract, ...] = ()
    updated_at: Timestamp | None = None

    @model_validator(mode="after")
    def _consistent_graph(self) -> "TaskGraphContract":
        task_ids = [task.task_id for task in self.tasks]
        dependency_ids = [edge.dependency_id for edge in self.dependencies]
        edge_pairs = [(edge.task_id, edge.depends_on_task_id) for edge in self.dependencies]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("TaskGraph contains duplicate task IDs")
        if len(dependency_ids) != len(set(dependency_ids)) or len(edge_pairs) != len(set(edge_pairs)):
            raise ValueError("TaskGraph contains duplicate dependencies")
        known = set(task_ids)
        if any(task.graph_id != self.graph_id for task in self.tasks):
            raise ValueError("Task belongs to a different TaskGraph")
        if any(
            edge.graph_id != self.graph_id
            or edge.task_id not in known
            or edge.depends_on_task_id not in known
            for edge in self.dependencies
        ):
            raise ValueError("TaskGraph dependency endpoint is invalid")
        adjacency: dict[str, list[str]] = {task_id: [] for task_id in known}
        for task_id, dependency_id in edge_pairs:
            adjacency[task_id].append(dependency_id)

        def visit(task_id: str, active: set[str], complete: set[str]) -> None:
            if task_id in active:
                raise ValueError("TaskGraph dependency cycle is forbidden")
            if task_id in complete:
                return
            active.add(task_id)
            for dependency_id in adjacency[task_id]:
                visit(dependency_id, active, complete)
            active.remove(task_id)
            complete.add(task_id)

        complete: set[str] = set()
        for task_id in sorted(known):
            visit(task_id, set(), complete)
        return self


class FailureContract(VersionedRecord):
    schema_id: Literal["SITINA_FAILURE_V1"] = Field(alias="schema")
    failure_id: Identifier
    run_id: Identifier
    task_id: Identifier | None = None
    span_id: Identifier | None = None
    failure_type: Identifier
    severity: Literal["warning", "minor", "major", "critical"]
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] = "OPEN"
    retryable: bool
    message: str = Field(min_length=1, max_length=2_000)
    details_ref: CASReference | None = None
    redacted: Literal[True]


class SpanEventContract(VersionedRecord):
    schema_id: Literal["SITINA_SPAN_EVENT_V1"] = Field(alias="schema")
    event_id: Identifier
    trace_id: Identifier
    span_id: Identifier
    name: Identifier
    attributes_ref: CASReference | None = None
    redacted: Literal[True]


class SpanContract(VersionedRecord):
    schema_id: Literal["SITINA_SPAN_V1"] = Field(alias="schema")
    trace_id: Identifier
    span_id: Identifier
    parent_span_id: Identifier | None = None
    name: Identifier
    kind: Literal["internal", "agent", "tool", "provider", "client", "server"]
    status: Literal["PENDING", "RUNNING", "OK", "ERROR", "CANCELLED"]
    started_at: Timestamp
    ended_at: Timestamp | None = None
    failure_id: Identifier | None = None
    events: tuple[SpanEventContract, ...] = ()

    @model_validator(mode="after")
    def _valid_span(self) -> "SpanContract":
        if self.parent_span_id == self.span_id:
            raise ValueError("Span cannot be its own parent")
        if self.status in {"OK", "ERROR", "CANCELLED"} and self.ended_at is None:
            raise ValueError("terminal Span requires ended_at")
        if self.status in {"PENDING", "RUNNING"} and self.ended_at is not None:
            raise ValueError("non-terminal Span cannot have ended_at")
        if self.status == "ERROR" and self.failure_id is None:
            raise ValueError("error Span requires failure_id")
        if self.ended_at is not None and _as_datetime(self.ended_at) < _as_datetime(self.started_at):
            raise ValueError("Span ended_at precedes started_at")
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("Span contains duplicate event IDs")
        if any(event.trace_id != self.trace_id or event.span_id != self.span_id for event in self.events):
            raise ValueError("Span event identity binding is invalid")
        return self


class TraceContract(VersionedRecord):
    schema_id: Literal["SITINA_TRACE_V1"] = Field(alias="schema")
    trace_id: Identifier
    root_span_id: Identifier
    spans: tuple[SpanContract, ...]

    @model_validator(mode="after")
    def _valid_trace(self) -> "TraceContract":
        span_ids = [span.span_id for span in self.spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("Trace contains duplicate Span IDs")
        known = set(span_ids)
        if self.root_span_id not in known:
            raise ValueError("Trace root Span is missing")
        roots = [span for span in self.spans if span.parent_span_id is None]
        if len(roots) != 1 or roots[0].span_id != self.root_span_id:
            raise ValueError("Trace requires exactly one declared root Span")
        if any(span.trace_id != self.trace_id for span in self.spans):
            raise ValueError("Span belongs to a different Trace")
        if any(span.parent_span_id is not None and span.parent_span_id not in known for span in self.spans):
            raise ValueError("Span parent is missing from Trace")
        parents = {span.span_id: span.parent_span_id for span in self.spans}
        for span_id in span_ids:
            active: set[str] = set()
            current: str | None = span_id
            while current is not None:
                if current in active:
                    raise ValueError("Trace Span parent cycle is forbidden")
                active.add(current)
                current = parents[current]
        return self


class TokenBudgetContract(VersionedRecord):
    schema_id: Literal["SITINA_TOKEN_BUDGET_V1"] = Field(alias="schema")
    budget_id: Identifier
    scope_type: Literal["run", "task", "agent", "call"]
    scope_id: Identifier
    maximum_tokens: int = Field(gt=0)
    reserved_tokens: int = Field(default=0, ge=0)
    consumed_tokens: int = Field(default=0, ge=0)
    hard_limit: bool = True
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def _valid_budget(self) -> "TokenBudgetContract":
        if self.reserved_tokens > self.maximum_tokens:
            raise ValueError("reserved token budget exceeds maximum")
        if self.hard_limit and self.consumed_tokens > self.maximum_tokens:
            raise ValueError("hard token budget is over limit")
        return self


class UsageContract(VersionedRecord):
    schema_id: Literal["SITINA_TOKEN_USAGE_V1"] = Field(alias="schema")
    usage_id: Identifier
    budget_id: Identifier | None = None
    run_id: Identifier
    task_id: Identifier | None = None
    call_id: Identifier | None = None
    attempt: int = Field(default=1, ge=1)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    provider_receipt_ref: CASReference | None = None

    @model_validator(mode="after")
    def _valid_total(self) -> "UsageContract":
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("total_tokens must equal prompt_tokens plus completion_tokens")
        return self


class HandoffRecord(VersionedRecord):
    schema_id: Literal["SITINA_HANDOFF_V1"] = Field(alias="schema")
    handoff_id: Identifier
    run_id: Identifier
    task_id: Identifier
    generation: int = Field(ge=1)
    sender_id: Identifier
    receiver_id: Identifier
    status: Literal["OFFERED", "ACCEPTED", "REJECTED", "CANCELLED", "EXPIRED"]
    objective_ref: Digest
    frozen_contract_ref: CASReference
    budget_id: Identifier | None = None
    deadline: Timestamp

    @model_validator(mode="after")
    def _different_parties(self) -> "HandoffRecord":
        if self.sender_id == self.receiver_id:
            raise ValueError("Handoff sender and receiver must differ")
        return self


class BlackboardDocumentRecord(VersionedRecord):
    schema_id: Literal["SITINA_BLACKBOARD_DOCUMENT_V1"] = Field(alias="schema")
    document_id: Identifier
    namespace: Identifier
    document_version: int = Field(ge=1)
    document_hash: Digest
    content_ref: CASReference
    classification: Literal["public", "internal", "confidential", "restricted"]
    writer_policy_hash: Digest
    merge_policy_hash: Digest
    last_writer_id: Identifier | None = None


class MemoryRecord(VersionedRecord):
    schema_id: Literal["SITINA_MEMORY_RECORD_V1"] = Field(alias="schema")
    memory_id: Identifier
    scope: Literal["agent_private", "run_shared", "project_shared", "user"]
    owner_id: Identifier
    namespace: Identifier
    content_ref: CASReference
    content_hash: Digest
    source_event_ids: tuple[Identifier, ...] = ()
    source_run_ids: tuple[Identifier, ...] = ()
    evidence_refs: tuple[CASReference, ...] = ()
    confidence_millis: int = Field(ge=0, le=1_000)
    sensitivity: Literal["low", "moderate", "high", "restricted"]
    status: Literal["candidate", "accepted", "rejected", "superseded", "revoked", "expired"]
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def _unique_provenance(self) -> "MemoryRecord":
        for name, values in (
            ("source_event_ids", self.source_event_ids),
            ("source_run_ids", self.source_run_ids),
            ("evidence_refs", self.evidence_refs),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"Memory {name} contains duplicates")
        return self


class EvaluationResult(VersionedRecord):
    schema_id: Literal["SITINA_EVALUATION_RESULT_V1"] = Field(alias="schema")
    evaluation_id: Identifier
    run_id: Identifier
    subject_id: Identifier
    subject_ref: CASReference | Digest
    evaluator_id: Identifier
    rubric_ref: CASReference | Digest
    score: int = Field(ge=0)
    maximum_score: int = Field(gt=0)
    decision: Literal["PASS", "FAIL", "NEEDS_REVISION", "BLOCK"]
    status: Literal["DRAFT", "FINAL", "INVALIDATED"]
    finding_refs: tuple[CASReference, ...] = ()
    redacted: Literal[True]

    @model_validator(mode="after")
    def _bounded_score(self) -> "EvaluationResult":
        if self.score > self.maximum_score:
            raise ValueError("evaluation score exceeds maximum_score")
        if len(self.finding_refs) != len(set(self.finding_refs)):
            raise ValueError("EvaluationResult contains duplicate finding refs")
        return self


def _as_datetime(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


CONTRACT_MODELS: dict[str, type[VersionedRecord]] = {
    "SITINA_BLACKBOARD_DOCUMENT_V1": BlackboardDocumentRecord,
    "SITINA_EVALUATION_RESULT_V1": EvaluationResult,
    "SITINA_FAILURE_V1": FailureContract,
    "SITINA_HANDOFF_V1": HandoffRecord,
    "SITINA_MEMORY_RECORD_V1": MemoryRecord,
    "SITINA_SPAN_V1": SpanContract,
    "SITINA_SPAN_EVENT_V1": SpanEventContract,
    "SITINA_TASK_DEPENDENCY_V1": DependencyContract,
    "SITINA_TASK_GRAPH_V1": TaskGraphContract,
    "SITINA_TASK_V1": TaskContract,
    "SITINA_TOKEN_BUDGET_V1": TokenBudgetContract,
    "SITINA_TOKEN_USAGE_V1": UsageContract,
    "SITINA_TRACE_V1": TraceContract,
}
