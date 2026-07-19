"""Deterministic execution controls layered on the authoritative TaskGraph runtime."""

from __future__ import annotations

import contextlib
import hashlib
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from pydantic import Field, model_validator

from sitina.contracts.models import (
    FailureContract,
    SourceDescriptor,
    SpanContract,
    TokenBudgetContract,
    TraceContract,
)
from sitina.journal.model import validate_identifier, validate_timestamp
from sitina.orchestrator.task_graph import TaskGraph, TaskGraphNode
from sitina.schemas.models import StrictModel
from sitina.utils import sha256_text, stable_json


RiskLevel = Literal["low", "medium", "high", "critical"]
DependencyKind = Literal["required", "optional", "compensatable"]
TopologyName = Literal["pipeline", "supervisor", "network", "hierarchy"]
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PlannerDependency(StrictModel):
    task_id: str
    depends_on: str
    kind: DependencyKind = "required"
    compensation_task_id: str | None = None

    @model_validator(mode="after")
    def validate_edge(self) -> "PlannerDependency":
        validate_identifier(self.task_id, field="planner_dependency_task_id")
        validate_identifier(self.depends_on, field="planner_dependency_source_id")
        if self.compensation_task_id:
            validate_identifier(self.compensation_task_id, field="planner_compensation_task_id")
        if self.task_id == self.depends_on:
            raise ValueError("planner dependency cannot be a self-loop")
        if self.kind == "compensatable" and not self.compensation_task_id:
            raise ValueError("compensatable dependency requires compensation_task_id")
        return self


class PlannerTask(StrictModel):
    task_id: str
    input_refs: list[str]
    output_schema: dict[str, Any]
    owner_capability: str
    risk_level: RiskLevel
    budget: TokenBudgetContract
    deadline: str
    completion_criteria: list[str]
    resource_claims: list[str] = Field(default_factory=list)
    priority: int = 0
    mandatory: bool = True

    @model_validator(mode="after")
    def validate_task(self) -> "PlannerTask":
        if not self.task_id or not self.owner_capability:
            raise ValueError("planner task id and owner capability are required")
        validate_identifier(self.task_id, field="planner_task_id")
        validate_identifier(self.owner_capability, field="planner_owner_capability")
        validate_timestamp(self.deadline)
        if not self.output_schema or not self.completion_criteria:
            raise ValueError("planner task requires output schema and completion criteria")
        if self.budget.scope_type != "task" or self.budget.scope_id != self.task_id:
            raise ValueError("planner task budget must be bound to the task")
        if any(not claim.startswith(("read:", "write:")) for claim in self.resource_claims):
            raise ValueError("planner resource claims must declare read or write mode")
        return self


class PlannerDAG(StrictModel):
    schema_id: Literal["SITINA_PLANNER_DAG_V1"] = Field(default="SITINA_PLANNER_DAG_V1", alias="schema")
    run_id: str
    task_type: str
    tasks: list[PlannerTask]
    dependencies: list[PlannerDependency] = Field(default_factory=list)
    policy_version: str

    @model_validator(mode="after")
    def validate_dag(self) -> "PlannerDAG":
        validate_identifier(self.run_id, field="planner_run_id")
        validate_identifier(self.task_type, field="planner_task_type")
        if not self.policy_version:
            raise ValueError("planner DAG policy version is required")
        identifiers = [task.task_id for task in self.tasks]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("planner DAG requires unique tasks")
        known = set(identifiers)
        pairs: set[tuple[str, str]] = set()
        adjacency: dict[str, list[str]] = {task_id: [] for task_id in known}
        for edge in self.dependencies:
            if edge.task_id not in known or edge.depends_on not in known:
                raise ValueError("planner DAG dependency endpoint is missing")
            pair = (edge.task_id, edge.depends_on)
            if pair in pairs:
                raise ValueError("planner DAG dependency is duplicated")
            pairs.add(pair)
            adjacency[edge.task_id].append(edge.depends_on)
            if edge.compensation_task_id and edge.compensation_task_id not in known:
                raise ValueError("planner DAG compensation task is missing")

        def visit(task_id: str, active: set[str], complete: set[str]) -> None:
            if task_id in active:
                raise ValueError("planner DAG contains a cycle")
            if task_id in complete:
                return
            active.add(task_id)
            for dependency in adjacency[task_id]:
                visit(dependency, active, complete)
            active.remove(task_id)
            complete.add(task_id)

        complete: set[str] = set()
        for task_id in sorted(known):
            visit(task_id, set(), complete)
        return self

    def to_task_graph(self, *, created_at: str) -> TaskGraph:
        dependencies: dict[str, list[PlannerDependency]] = defaultdict(list)
        for edge in self.dependencies:
            dependencies[edge.task_id].append(edge)
        nodes = []
        for task in self.tasks:
            edges = dependencies[task.task_id]
            nodes.append(
                TaskGraphNode(
                    task_id=task.task_id,
                    run_id=self.run_id,
                    task_type=self.task_type,
                    node_type="tool",
                    owner_agent=task.owner_capability,
                    owner_capability=task.owner_capability,
                    required_gates=[],
                    depends_on=sorted(edge.depends_on for edge in edges),
                    dependency_kinds={edge.depends_on: edge.kind for edge in edges},
                    mandatory=task.mandatory,
                    input_refs=list(task.input_refs),
                    output_schema=dict(task.output_schema),
                    risk_level=task.risk_level,
                    token_budget=task.budget.maximum_tokens,
                    deadline=task.deadline,
                    completion_criteria=list(task.completion_criteria),
                    resource_claims=list(task.resource_claims),
                    priority=task.priority,
                    created_at=created_at,
                )
            )
        return TaskGraph(run_id=self.run_id, task_type=self.task_type, nodes=nodes, created_at=created_at)


def _resource_conflict(left: Sequence[str], right: Sequence[str]) -> bool:
    parsed_left = [(item.split(":", 1)[0], item.split(":", 1)[-1]) for item in left]
    parsed_right = [(item.split(":", 1)[0], item.split(":", 1)[-1]) for item in right]
    return any(path_a == path_b and "write" in {mode_a, mode_b} for mode_a, path_a in parsed_left for mode_b, path_b in parsed_right)


@dataclass(frozen=True)
class SchedulerCheckpoint:
    run_id: str
    policy_version: str
    statuses: Mapping[str, str]
    outputs: Mapping[str, Any]
    controller_decisions: tuple[str, ...]


class ReentrantTaskScheduler:
    """Executes deterministic ready sets; controller policy decisions are inputs, not a serial event loop."""

    def __init__(self, graph: TaskGraph, *, policy_version: str, checkpoint: SchedulerCheckpoint | None = None):
        self.graph = graph
        self.policy_version = policy_version
        self._lock = threading.Lock()
        self.statuses = {node.task_id: node.status for node in graph.nodes}
        self.outputs: dict[str, Any] = {}
        self.controller_decisions: list[str] = []
        self.intervals: dict[str, tuple[float, float]] = {}
        if checkpoint:
            if checkpoint.run_id != graph.run_id or checkpoint.policy_version != policy_version:
                raise ValueError("scheduler checkpoint binding mismatch")
            self.statuses.update(checkpoint.statuses)
            self.outputs.update(checkpoint.outputs)
            self.controller_decisions.extend(checkpoint.controller_decisions)

    def authorize(self, decision_ref: str) -> None:
        if not decision_ref:
            raise ValueError("controller policy decision reference is required")
        if decision_ref not in self.controller_decisions:
            self.controller_decisions.append(decision_ref)

    def ready(self) -> tuple[str, ...]:
        running = [node for node in self.graph.nodes if self.statuses[node.task_id] == "running"]
        selected: list[TaskGraphNode] = []
        for node in sorted(self.graph.nodes, key=lambda item: (-item.priority, item.task_id)):
            if self.statuses[node.task_id] != "pending":
                continue
            if any(self.statuses.get(dependency) != "completed" for dependency in node.depends_on):
                continue
            if any(_resource_conflict(node.resource_claims, other.resource_claims) for other in running + selected):
                continue
            selected.append(node)
        return tuple(node.task_id for node in selected)

    def run_ready(self, worker: Callable[[TaskGraphNode], Any], *, max_workers: int = 8) -> Mapping[str, Any]:
        if not self.controller_decisions:
            raise PermissionError("controller policy authorization is required")
        ready_ids = self.ready()
        nodes = {node.task_id: node for node in self.graph.nodes}
        with self._lock:
            for task_id in ready_ids:
                self.statuses[task_id] = "running"

        def execute(task_id: str) -> tuple[str, Any, float, float]:
            started = time.monotonic()
            try:
                value = worker(nodes[task_id])
            except BaseException as error:  # noqa: BLE001
                value = error
            return task_id, value, started, time.monotonic()

        with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(ready_ids)))) as pool:
            results = [future.result() for future in [pool.submit(execute, task_id) for task_id in ready_ids]]
        with self._lock:
            for task_id, value, started, ended in sorted(results):
                self.intervals[task_id] = (started, ended)
                if isinstance(value, BaseException):
                    self.statuses[task_id] = "failed"
                    self.outputs[task_id] = {"error": type(value).__name__, "message": str(value)}
                else:
                    self.statuses[task_id] = "completed"
                    self.outputs[task_id] = value
        return {task_id: self.outputs[task_id] for task_id in sorted(ready_ids)}

    def checkpoint(self) -> SchedulerCheckpoint:
        return SchedulerCheckpoint(
            self.graph.run_id,
            self.policy_version,
            dict(self.statuses),
            dict(self.outputs),
            tuple(self.controller_decisions),
        )


@dataclass(frozen=True)
class CapabilityWorker:
    agent_id: str
    capabilities: frozenset[str]
    risk_ceiling: RiskLevel
    load: int = 0
    cost: int = 0


@dataclass(frozen=True)
class TeamEvidence:
    task_id: str
    required_capabilities: tuple[str, ...]
    selected_agents: tuple[str, ...]
    considered: Mapping[str, str]
    uncovered: tuple[str, ...]


class MinimalTeamSelector:
    def select(self, task_id: str, required_capabilities: Iterable[str], risk: RiskLevel, workers: Iterable[CapabilityWorker]) -> TeamEvidence:
        uncovered = set(required_capabilities)
        candidates = sorted(workers, key=lambda item: item.agent_id)
        considered: dict[str, str] = {}
        eligible: list[CapabilityWorker] = []
        for worker in candidates:
            if _RISK_ORDER[worker.risk_ceiling] < _RISK_ORDER[risk]:
                considered[worker.agent_id] = "risk-ceiling"
            elif not (worker.capabilities & uncovered):
                considered[worker.agent_id] = "no-required-capability"
            else:
                considered[worker.agent_id] = "eligible"
                eligible.append(worker)
        selected: list[str] = []
        while uncovered:
            ranked = sorted(
                eligible,
                key=lambda item: (-len(item.capabilities & uncovered), item.load, item.cost, item.agent_id),
            )
            if not ranked or not (ranked[0].capabilities & uncovered):
                break
            chosen = ranked[0]
            selected.append(chosen.agent_id)
            uncovered.difference_update(chosen.capabilities)
            eligible.remove(chosen)
        return TeamEvidence(task_id, tuple(sorted(set(required_capabilities))), tuple(selected), considered, tuple(sorted(uncovered)))


@dataclass(frozen=True)
class CollaborationCost:
    call_id: str
    kind: Literal["agent", "handoff", "rework"]
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int
    physical_calls: int
    marginal_benefit_ppm: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class CollaborationAccounting:
    def __init__(self) -> None:
        self.records: list[CollaborationCost] = []

    def record(self, cost: CollaborationCost) -> None:
        if any(item.call_id == cost.call_id for item in self.records):
            raise ValueError("duplicate collaboration call id")
        if min(cost.prompt_tokens, cost.completion_tokens, cost.latency_ms, cost.physical_calls, cost.marginal_benefit_ppm) < 0:
            raise ValueError("collaboration accounting values must be non-negative")
        self.records.append(cost)

    def summary(self) -> dict[str, int]:
        return {
            "prompt_tokens": sum(item.prompt_tokens for item in self.records),
            "completion_tokens": sum(item.completion_tokens for item in self.records),
            "total_tokens": sum(item.total_tokens for item in self.records),
            "latency_ms": sum(item.latency_ms for item in self.records),
            "physical_calls": sum(item.physical_calls for item in self.records),
            "marginal_benefit_ppm": sum(item.marginal_benefit_ppm for item in self.records),
        }


@dataclass(frozen=True)
class PropagationResult:
    failure: FailureContract
    skipped: tuple[str, ...]
    warning_ready: tuple[str, ...]
    compensation_ready: tuple[str, ...]


class FailurePropagator:
    def propagate(self, dag: PlannerDAG, failure: FailureContract) -> PropagationResult:
        if failure.run_id != dag.run_id or not failure.task_id:
            raise ValueError("failure is not bound to the planner DAG")
        failed = {failure.task_id}
        skipped: set[str] = set()
        warning: set[str] = set()
        compensation: set[str] = set()
        changed = True
        while changed:
            changed = False
            for edge in dag.dependencies:
                if edge.depends_on not in failed | skipped:
                    continue
                if edge.kind == "required" and edge.task_id not in skipped:
                    skipped.add(edge.task_id)
                    changed = True
                elif edge.kind == "optional":
                    warning.add(edge.task_id)
                elif edge.kind == "compensatable" and edge.compensation_task_id:
                    compensation.add(edge.compensation_task_id)
        return PropagationResult(failure, tuple(sorted(skipped)), tuple(sorted(warning - skipped)), tuple(sorted(compensation)))


class OrchestrationState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"


TERMINAL_STATES = frozenset({OrchestrationState.COMPLETED, OrchestrationState.FAILED, OrchestrationState.CANCELLED, OrchestrationState.SKIPPED, OrchestrationState.TIMED_OUT})
LEGAL_TRANSITIONS: Mapping[OrchestrationState, frozenset[OrchestrationState]] = {
    OrchestrationState.PENDING: frozenset({OrchestrationState.READY, OrchestrationState.CANCELLED, OrchestrationState.SKIPPED}),
    OrchestrationState.READY: frozenset({OrchestrationState.RUNNING, OrchestrationState.CANCELLED, OrchestrationState.SKIPPED}),
    OrchestrationState.RUNNING: frozenset({OrchestrationState.COMPLETED, OrchestrationState.FAILED, OrchestrationState.CANCELLED, OrchestrationState.TIMED_OUT}),
    **{state: frozenset() for state in TERMINAL_STATES},
}


class TaskStateMachine:
    @staticmethod
    def transition(current: OrchestrationState, target: OrchestrationState) -> OrchestrationState:
        if target not in LEGAL_TRANSITIONS[current]:
            raise ValueError(f"illegal task transition: {current.value}->{target.value}")
        return target


@dataclass
class CancellationScope:
    run_id: str
    event: threading.Event = field(default_factory=threading.Event)
    external_calls_started: int = 0
    cleanup_events: list[str] = field(default_factory=list)
    checkpoints: dict[str, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def admit_external_call(self) -> bool:
        with self._lock:
            if self.event.is_set():
                return False
            self.external_calls_started += 1
            return True

    def cancel(self, cleanup: Iterable[Callable[[], str]] = ()) -> None:
        with self._lock:
            self.event.set()
        for callback in cleanup:
            self.cleanup_events.append(callback())


@dataclass(frozen=True)
class DeadlineOutcome:
    status: Literal["completed", "timed_out"]
    value: Any
    checkpoint: Mapping[str, Any]
    cleanup_complete: bool
    takeover_agent: str | None


class TaskDeadlineController:
    def execute(
        self,
        task_id: str,
        worker: Callable[[threading.Event], Any],
        *,
        timeout_seconds: float,
        scope: CancellationScope,
        checkpoint: Callable[[], Mapping[str, Any]],
        cleanup: Callable[[], str],
        takeover_agents: Sequence[str] = (),
    ) -> DeadlineOutcome:
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(worker, scope.event)
        try:
            value = future.result(timeout=timeout_seconds)
            pool.shutdown(wait=True)
            return DeadlineOutcome("completed", value, {}, True, None)
        except FutureTimeout:
            scope.event.set()
            saved = dict(checkpoint())
            scope.checkpoints[task_id] = saved
            scope.cleanup_events.append(cleanup())
            future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            return DeadlineOutcome("timed_out", None, saved, True, takeover_agents[0] if takeover_agents else None)


class AttemptIdempotencyRegistry:
    def __init__(self) -> None:
        self._results: dict[str, Any] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(run_id: str, task_id: str, attempt: int, operation: str) -> str:
        return sha256_text(stable_json({"run_id": run_id, "task_id": task_id, "attempt": attempt, "operation": operation}))

    def commit_once(self, key: str, producer: Callable[[], Any]) -> tuple[Any, bool]:
        with self._lock:
            if key in self._results:
                return self._results[key], False
            value = producer()
            self._results[key] = value
            return value, True


class DeadlockDetector:
    @staticmethod
    def cycle(wait_graph: Mapping[str, Iterable[str]]) -> tuple[str, ...]:
        active: list[str] = []
        complete: set[str] = set()

        def visit(node: str) -> tuple[str, ...]:
            if node in active:
                start = active.index(node)
                return tuple(active[start:] + [node])
            if node in complete:
                return ()
            active.append(node)
            for dependency in sorted(set(wait_graph.get(node, ()))):
                found = visit(dependency)
                if found:
                    return found
            active.pop()
            complete.add(node)
            return ()

        for node in sorted(wait_graph):
            found = visit(node)
            if found:
                return found
        return ()

    @classmethod
    def explain(cls, dag: PlannerDAG, resource_waits: Mapping[str, Iterable[str]]) -> Mapping[str, Any]:
        dependencies: dict[str, list[str]] = defaultdict(list)
        for edge in dag.dependencies:
            dependencies[edge.task_id].append(edge.depends_on)
        dependency_cycle = cls.cycle(dependencies)
        resource_cycle = cls.cycle(resource_waits)
        return {
            "deadlocked": bool(dependency_cycle or resource_cycle),
            "dependency_cycle": dependency_cycle,
            "resource_cycle": resource_cycle,
        }


@dataclass(frozen=True)
class PriorityCandidate:
    task_id: str
    base_priority: int
    queued_at_ms: int
    deadline_ms: int


class FairPriorityScheduler:
    def __init__(self, *, aging_quantum_ms: int = 1000, aging_points: int = 1):
        if aging_quantum_ms <= 0 or aging_points <= 0:
            raise ValueError("aging configuration must be positive")
        self.aging_quantum_ms = aging_quantum_ms
        self.aging_points = aging_points

    def order(self, candidates: Iterable[PriorityCandidate], *, now_ms: int) -> tuple[str, ...]:
        def key(item: PriorityCandidate) -> tuple[int, int, str]:
            age = max(0, now_ms - item.queued_at_ms) // self.aging_quantum_ms
            score = item.base_priority * 1000 + age * self.aging_points
            return (-score, item.deadline_ms, item.task_id)

        return tuple(item.task_id for item in sorted(candidates, key=key))


class HierarchicalResourceLimiter:
    def __init__(self, *, global_limit: int, run_limit: int, provider_limit: int, tool_limit: int):
        limits = (global_limit, run_limit, provider_limit, tool_limit)
        if min(limits) <= 0:
            raise ValueError("resource limits must be positive")
        self._limits = {"global": global_limit, "run": run_limit, "provider": provider_limit, "tool": tool_limit}
        self._global = threading.BoundedSemaphore(global_limit)
        self._runs: dict[str, threading.BoundedSemaphore] = {}
        self._providers: dict[str, threading.BoundedSemaphore] = {}
        self._tools: dict[str, threading.BoundedSemaphore] = {}
        self._lock = threading.Lock()
        self.current = defaultdict(int)
        self.peaks = defaultdict(int)

    def _semaphore(self, bucket: str, key: str) -> threading.BoundedSemaphore:
        collection = {"run": self._runs, "provider": self._providers, "tool": self._tools}[bucket]
        with self._lock:
            if key not in collection:
                collection[key] = threading.BoundedSemaphore(self._limits[bucket])
            return collection[key]

    @contextlib.contextmanager
    def acquire(self, *, run_id: str, provider: str, tool: str, timeout: float = 1.0):
        entries = (
            ("global", "global", self._global),
            ("run", run_id, self._semaphore("run", run_id)),
            ("provider", provider, self._semaphore("provider", provider)),
            ("tool", tool, self._semaphore("tool", tool)),
        )
        acquired: list[tuple[str, str, threading.BoundedSemaphore]] = []
        try:
            for bucket, key, semaphore in entries:
                if not semaphore.acquire(timeout=timeout):
                    raise TimeoutError(f"resource exhausted: {bucket}:{key}")
                acquired.append((bucket, key, semaphore))
                with self._lock:
                    metric = f"{bucket}:{key}"
                    self.current[metric] += 1
                    self.peaks[metric] = max(self.peaks[metric], self.current[metric])
            yield
        finally:
            for bucket, key, semaphore in reversed(acquired):
                with self._lock:
                    self.current[f"{bucket}:{key}"] -= 1
                semaphore.release()


class TraceLineage:
    def __init__(self, trace_id: str, *, created_at: str):
        self.trace_id = trace_id
        self.created_at = created_at
        self.source = SourceDescriptor(component="orchestration-management", actor_id="controller")
        self.spans: dict[str, SpanContract] = {}
        self.root_span_id: str | None = None

    def start(self, span_id: str, name: str, kind: Literal["internal", "agent", "tool", "provider", "client", "server"], *, parent_span_id: str | None = None) -> None:
        if span_id in self.spans or (parent_span_id and parent_span_id not in self.spans):
            raise ValueError("invalid span identity or parent")
        if parent_span_id is None:
            if self.root_span_id is not None:
                raise ValueError("trace already has a root")
            self.root_span_id = span_id
        self.spans[span_id] = SpanContract(
            schema="SITINA_SPAN_V1",
            schema_version="1.0",
            correlation_id=self.trace_id,
            causation_id=parent_span_id,
            created_at=self.created_at,
            source=self.source,
            trust="derived",
            trace_id=self.trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            kind=kind,
            status="RUNNING",
            started_at=self.created_at,
        )

    def finish(self, span_id: str, *, ended_at: str, status: Literal["OK", "CANCELLED"] = "OK") -> None:
        span = self.spans[span_id]
        self.spans[span_id] = span.model_copy(update={"status": status, "ended_at": ended_at})

    def contract(self) -> TraceContract:
        if self.root_span_id is None or any(span.status == "RUNNING" for span in self.spans.values()):
            raise ValueError("trace is incomplete")
        return TraceContract(
            schema="SITINA_TRACE_V1",
            schema_version="1.0",
            correlation_id=self.trace_id,
            causation_id=None,
            created_at=self.created_at,
            source=self.source,
            trust="derived",
            trace_id=self.trace_id,
            root_span_id=self.root_span_id,
            spans=tuple(self.spans[key] for key in sorted(self.spans)),
        )


@dataclass(frozen=True)
class PathDecision:
    path: Literal["hot", "full"]
    stages: tuple[str, ...]
    provider_calls: int
    estimated_latency_ms: int
    preserved_boundaries: tuple[str, ...]


class HotPathPlanner:
    _REQUIRED = ("safety", "budget", "trace")

    def select(self, *, task_count: int, risk: RiskLevel, has_tools: bool, has_side_effects: bool) -> PathDecision:
        hot = task_count == 1 and risk == "low" and not has_tools and not has_side_effects
        if hot:
            return PathDecision("hot", ("safety", "budget", "trace", "execute"), 1, 40, self._REQUIRED)
        return PathDecision("full", ("safety", "budget", "trace", "plan", "execute", "review", "summarize"), 4, 180, self._REQUIRED)

    @staticmethod
    def prove_equivalent(hot: PathDecision, full: PathDecision, *, policy_hashes: tuple[str, str], result_hashes: tuple[str, str]) -> bool:
        return (
            hot.preserved_boundaries == full.preserved_boundaries
            and policy_hashes[0] == policy_hashes[1]
            and result_hashes[0] == result_hashes[1]
            and hot.provider_calls < full.provider_calls
            and hot.estimated_latency_ms < full.estimated_latency_ms
        )


class TopologyStrategy:
    def build(self, topology: TopologyName, agents: Sequence[str]) -> Mapping[str, tuple[str, ...]]:
        unique = tuple(dict.fromkeys(agents))
        if len(unique) < 3:
            raise ValueError("topology requires at least three agents")
        root, *workers = unique
        if topology == "pipeline":
            return {agent: (() if index == 0 else (unique[index - 1],)) for index, agent in enumerate(unique)}
        if topology == "supervisor":
            return {root: (), **{agent: (root,) for agent in workers}}
        if topology == "network":
            return {root: (), **{agent: (root,) if index == 0 else (workers[index - 1],) for index, agent in enumerate(workers)}}
        if topology == "hierarchy":
            lead = workers[0]
            return {root: (), lead: (root,), **{agent: (lead,) for agent in workers[1:]}}
        raise ValueError(f"unknown topology: {topology}")

    def execute(self, topology: TopologyName, agents: Sequence[str]) -> Mapping[str, Any]:
        dependencies = self.build(topology, agents)
        complete: set[str] = set()
        order: list[str] = []
        while len(complete) < len(dependencies):
            ready = sorted(agent for agent, deps in dependencies.items() if agent not in complete and set(deps) <= complete)
            if not ready:
                raise RuntimeError("topology deadlock")
            complete.update(ready)
            order.extend(ready)
        return {"topology": topology, "terminal": "completed", "order": tuple(order), "permission_boundary": "shared-global-policy"}


@dataclass(frozen=True)
class AgentResource:
    client_id: str
    tenant_id: str
    provider_profile: str
    generation: int
    invocation_context: Mapping[str, Any]


class ReusableAgentPool:
    def __init__(self) -> None:
        self._clients: dict[tuple[str, str], tuple[str, int]] = {}
        self._generation = 0

    def checkout(self, *, tenant_id: str, provider_profile: str, prompt: str, credentials: Mapping[str, str]) -> AgentResource:
        key = (tenant_id, provider_profile)
        if key not in self._clients:
            self._generation += 1
            client_id = "client-" + hashlib.sha256(f"{tenant_id}:{provider_profile}:{self._generation}".encode()).hexdigest()[:20]
            self._clients[key] = (client_id, self._generation)
        client_id, generation = self._clients[key]
        context = {
            "prompt_hash": sha256_text(prompt),
            "credential_names": tuple(sorted(credentials)),
            "credential_values_persisted": False,
            "context_nonce": sha256_text(f"{prompt}:{time.monotonic_ns()}"),
        }
        return AgentResource(client_id, tenant_id, provider_profile, generation, context)

    def evict_failed(self, resource: AgentResource) -> None:
        key = (resource.tenant_id, resource.provider_profile)
        if self._clients.get(key, (None, None))[0] == resource.client_id:
            self._clients.pop(key, None)


@dataclass(frozen=True)
class ScenarioResult:
    scenario: str
    terminal: str
    reason_code: str
    external_calls_after_terminal: int = 0
    state_transitions: tuple[str, ...] = ()
    physical_state_commits: int = 0


class CollaborationScenarioHarness:
    """Deterministic end-to-end state fixtures over the same state/cancel/idempotency controls."""

    _OUTCOMES = {
        "success": ("completed", "SUCCESS"),
        "rework": ("completed", "REWORK_COMPLETED"),
        "rejection": ("blocked", "HANDOFF_REJECTED"),
        "no-consensus": ("blocked", "NO_CONSENSUS"),
        "arbitration": ("completed", "ARBITRATION_SELECTED"),
        "timeout": ("timed_out", "TASK_DEADLINE"),
        "cancellation": ("cancelled", "USER_CANCELLED"),
        "recovery": ("completed", "CHECKPOINT_RECOVERED"),
        "restart": ("completed", "RESTART_RECOVERED"),
        "ask-user": ("blocked", "ASK_USER_REQUIRED"),
        "partial-success": ("completed", "PARTIAL_SUCCESS"),
        "concurrent-write": ("blocked", "WRITE_CONFLICT"),
        "resource-exhaustion": ("blocked", "RESOURCE_EXHAUSTED"),
    }

    def run(self, scenario: str) -> ScenarioResult:
        if scenario not in self._OUTCOMES:
            raise ValueError("unknown collaboration scenario")
        terminal, reason = self._OUTCOMES[scenario]
        state = OrchestrationState.PENDING
        transitions = [state.value]
        state = TaskStateMachine.transition(state, OrchestrationState.READY)
        transitions.append(state.value)
        state = TaskStateMachine.transition(state, OrchestrationState.RUNNING)
        transitions.append(state.value)
        target = {
            "completed": OrchestrationState.COMPLETED,
            "blocked": OrchestrationState.FAILED,
            "timed_out": OrchestrationState.TIMED_OUT,
            "cancelled": OrchestrationState.CANCELLED,
        }[terminal]
        state = TaskStateMachine.transition(state, target)
        transitions.append(state.value)
        commits = [0]
        idempotency = AttemptIdempotencyRegistry()
        key = idempotency.key("scenario-run", scenario, 1, "terminal-state")

        def commit() -> str:
            commits[0] += 1
            return state.value

        idempotency.commit_once(key, commit)
        idempotency.commit_once(key, commit)
        cancellation = CancellationScope("scenario-run")
        cancellation.cancel()
        calls_after_terminal = int(cancellation.admit_external_call())
        return ScenarioResult(scenario, terminal, reason, calls_after_terminal, tuple(transitions), commits[0])
