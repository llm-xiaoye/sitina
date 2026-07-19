from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError, model_validator

from sitina.constants import SITINA_HOME
from sitina.orchestrator.handoff import HandoffManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.leases import LeaseManager
from sitina.orchestrator.policy import ExecutionPlan
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, compute_agent_input_hash, ensure_dir, iso_now, load_json_yaml, new_id, read_json, sha256_text, stable_json, write_json


class HandoffBlockedError(ValueError):
    """Receiver or contract policy rejected a handoff."""


TaskGraphStatus = Literal["pending", "running", "completed", "blocked", "skipped", "failed"]
NodeType = Literal[
    "controller",
    "planner",
    "coder",
    "tester",
    "reviewer",
    "multi_reviewer_merge",
    "approval",
    "worktree_prepare",
    "patch_hash_verify",
    "patch_apply",
    "summary",
    "memory",
    "tool",
    "parallel_group",
    "retry",
    "planner_rework",
    "coder_rework",
    "tester_rerun",
    "reviewer_rerun",
    "multi_reviewer_rerun",
    "reapproval_required",
    "retry_exhausted",
    "arbitration",
    "side_effect",
    "escalation",
    "maintenance_op",
    "risk_scan",
    "audit",
    "sensitive_path_gate",
    "filesystem_readonly_gate",
]


GATE_NODE_TYPES = {
    "tester",
    "reviewer",
    "multi_reviewer_merge",
    "approval",
    "worktree_prepare",
    "patch_hash_verify",
    "patch_apply",
    "memory",
    "sensitive_path_gate",
    "filesystem_readonly_gate",
}


class TaskGraphNode(StrictModel):
    task_id: str
    run_id: str
    task_type: str
    node_type: NodeType
    owner_agent: str
    required_gates: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    mandatory: bool = True
    status: TaskGraphStatus = "pending"
    input_refs: list[str] = Field(default_factory=list)
    artifact_refs: list[str] = Field(default_factory=list)
    approved_scope_hash: str | None = None
    patch_id: str | None = None
    patch_hash: str | None = None
    target_repo: str | None = None
    blocked_reason: str | None = None
    output_ref: str | None = None
    scope_lease_ids: list[str] = Field(default_factory=list)
    side_effect_descriptor_ids: list[str] = Field(default_factory=list)
    proposal_round_id: str | None = None
    selected_proposal_id: str | None = None
    failure_id: str | None = None
    rework_id: str | None = None
    source_node_id: str | None = None
    rework_reason: str | None = None
    rework_failure_type: str | None = None
    source_evaluation_id: str | None = None
    rework_input_hash: str | None = None
    attempt: int | None = None
    max_attempts: int | None = None
    created_at: str
    updated_at: str | None = None

    @model_validator(mode="after")
    def validate_node(self) -> "TaskGraphNode":
        if not self.task_id or not self.run_id or not self.task_type:
            raise ValueError("task_id, run_id and task_type are required")
        if self.status in {"blocked", "failed"} and not self.blocked_reason:
            raise ValueError("blocked/failed task graph node requires blocked_reason")
        return self


class ReworkEdge(StrictModel):
    edge_id: str
    run_id: str
    task_type: str
    from_task_id: str
    to_task_id: str
    reason: str
    retry_attempt: int
    approved_scope_hash: str | None = None
    created_at: str


class ReworkLifecycleEvent(StrictModel):
    schema_version: str = "1.0"
    rework_id: str
    source_evaluation_id: str | None = None
    failure_type: str
    target_agent: str | None = None
    parent_task_id: str
    retry_index: int
    max_retries: int
    input_hash: str
    output_hash: str | None = None
    terminal_status: Literal["requested", "dispatched", "running", "completed", "failed", "retry_exhausted"]
    created_at: str


class HandoffDecision(StrictModel):
    decision: Literal["accept", "reject"]
    reason: str
    required_gates: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    notes: list[str] = Field(default_factory=list)
    safety_issues: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_confidence(self) -> "HandoffDecision":
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        return self


class TaskGraph(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    task_type: str
    nodes: list[TaskGraphNode]
    rework_edges: list[ReworkEdge] = Field(default_factory=list)
    selected_proposal_id: str | None = None
    proposal_round_id: str | None = None
    created_at: str
    updated_at: str | None = None

    @property
    def node_map(self) -> dict[str, TaskGraphNode]:
        return {node.task_id: node for node in self.nodes}

    def mandatory_nodes(self) -> list[TaskGraphNode]:
        return [node for node in self.nodes if node.mandatory]


class PolicyCompiler:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.parallel_policy = load_json_yaml(home / "config" / "parallel_policy.yaml") if (home / "config" / "parallel_policy.yaml").exists() else {}

    def compile(self, plan: ExecutionPlan) -> TaskGraph:
        task_type = plan.task_type
        if task_type == "chat":
            nodes = self._chat(plan)
        elif task_type == "local_file_query":
            nodes = self._local_file_query(plan)
        elif task_type == "code_change":
            nodes = self._code_change(plan)
        elif task_type == "high_risk_code_change":
            nodes = self._high_risk_code_change(plan)
        elif task_type == "maintenance":
            nodes = self._maintenance(plan)
        else:
            nodes = self._chat(plan)
            for node in nodes:
                node.status = "blocked"
                node.blocked_reason = f"unsupported task_type for task graph compiler: {task_type}"
        return TaskGraph(run_id=plan.run_id, task_type=task_type, nodes=nodes, created_at=iso_now())

    def _node(
        self,
        plan: ExecutionPlan,
        task_id: str,
        node_type: NodeType,
        owner_agent: str,
        *,
        depends_on: list[str] | None = None,
        mandatory: bool = True,
        required_gates: list[str] | None = None,
        input_refs: list[str] | None = None,
    ) -> TaskGraphNode:
        return TaskGraphNode(
            task_id=task_id,
            run_id=plan.run_id,
            task_type=plan.task_type,
            node_type=node_type,
            owner_agent=owner_agent,
            depends_on=depends_on or [],
            mandatory=mandatory,
            required_gates=required_gates or [],
            input_refs=input_refs or [],
            created_at=iso_now(),
        )

    def _chat(self, plan: ExecutionPlan) -> list[TaskGraphNode]:
        return [
            self._node(plan, "controller", "controller", "controller"),
            self._node(plan, "summary", "summary", "summary", depends_on=["controller"]),
            self._node(plan, "memory", "memory", "memory", depends_on=["summary"], required_gates=["memory_check"]),
        ]

    def _local_file_query(self, plan: ExecutionPlan) -> list[TaskGraphNode]:
        return [
            self._node(plan, "controller", "controller", "controller"),
            self._node(plan, "filesystem_readonly_gate", "filesystem_readonly_gate", "filesystem", depends_on=["controller"], required_gates=["filesystem_readonly"]),
            self._node(plan, "filesystem_tool", "tool", "filesystem", depends_on=["filesystem_readonly_gate"], input_refs=list(plan.target_paths)),
            self._node(plan, "summary", "summary", "summary", depends_on=["filesystem_tool"]),
            self._node(plan, "memory", "memory", "memory", depends_on=["summary"], required_gates=["memory_check"]),
        ]

    def _code_change(self, plan: ExecutionPlan) -> list[TaskGraphNode]:
        reviewer_node = "parallel_reviewer_group" if self._parallel_enabled(plan) else "multi_reviewer_merge"
        tester_node = "parallel_tester_group" if self._parallel_enabled(plan) else "tester"
        return [
            self._node(plan, "controller", "controller", "controller"),
            self._node(plan, "planner", "planner", "planner", depends_on=["controller"]),
            self._node(plan, "approval", "approval", "controller", depends_on=["planner"], required_gates=["approval"], mandatory=plan.requires_approval),
            self._node(plan, "coder", "coder", "coder", depends_on=["approval" if plan.requires_approval else "planner"], required_gates=["approved_scope"]),
            self._node(plan, tester_node, "parallel_group" if tester_node.startswith("parallel") else "tester", "tester", depends_on=["coder"], required_gates=["tester"]),
            self._node(plan, reviewer_node, "parallel_group" if reviewer_node.startswith("parallel") else "multi_reviewer_merge", "reviewer", depends_on=[tester_node], required_gates=["reviewer"]),
            self._node(plan, "summary", "summary", "summary", depends_on=[reviewer_node]),
            self._node(plan, "memory", "memory", "memory", depends_on=["summary"], required_gates=["memory_check"]),
        ]

    def _high_risk_code_change(self, plan: ExecutionPlan) -> list[TaskGraphNode]:
        tester_node = "parallel_tester_group" if self._parallel_enabled(plan) else "tester"
        reviewer_node = "parallel_reviewer_group" if self._parallel_enabled(plan) else "multi_reviewer_merge"
        return [
            self._node(plan, "controller", "controller", "controller"),
            self._node(plan, "planner", "planner", "planner", depends_on=["controller"]),
            self._node(plan, "worktree_prepare", "worktree_prepare", "git_worktree_manager", depends_on=["planner"], required_gates=["worktree"]),
            self._node(plan, "coder", "coder", "coder", depends_on=["worktree_prepare"], required_gates=["worktree"]),
            self._node(plan, tester_node, "parallel_group" if tester_node.startswith("parallel") else "tester", "tester", depends_on=["coder"], required_gates=["tester"]),
            self._node(plan, reviewer_node, "parallel_group" if reviewer_node.startswith("parallel") else "multi_reviewer_merge", "reviewer", depends_on=[tester_node], required_gates=["multi_reviewer_merge"]),
            self._node(plan, "approval", "approval", "controller", depends_on=[reviewer_node], required_gates=["approval"]),
            self._node(plan, "patch_hash_verify", "patch_hash_verify", "git_worktree_manager", depends_on=["approval"], required_gates=["patch_hash_verify"]),
            self._node(plan, "patch_apply", "patch_apply", "git_worktree_manager", depends_on=["patch_hash_verify"], required_gates=["patch_apply"]),
            self._node(plan, "summary", "summary", "summary", depends_on=["patch_apply"]),
            self._node(plan, "memory", "memory", "memory", depends_on=["summary"], required_gates=["memory_check"]),
        ]

    def _maintenance(self, plan: ExecutionPlan) -> list[TaskGraphNode]:
        return [
            self._node(plan, "controller", "controller", "controller"),
            self._node(plan, "risk_scan", "risk_scan", "controller", depends_on=["controller"]),
            self._node(plan, "approval", "approval", "controller", depends_on=["risk_scan"], required_gates=["approval"]),
            self._node(plan, "maintenance_op", "maintenance_op", "maintenance_ops", depends_on=["approval"]),
            self._node(plan, "audit", "audit", "controller", depends_on=["maintenance_op"]),
            self._node(plan, "summary", "summary", "summary", depends_on=["audit"]),
            self._node(plan, "memory", "memory", "memory", depends_on=["summary"], required_gates=["memory_check"]),
        ]

    def _parallel_enabled(self, plan: ExecutionPlan) -> bool:
        return plan.task_type in {"code_change", "high_risk_code_change"} and "parallel_allowed_agents" in (load_json_yaml(self.home / "config" / "workflow_policy.yaml").get("task_types", {}).get(plan.task_type, {}))


class TaskGraphRuntime:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.ledger = RunLedger(home, self.store)
        self.handoffs = HandoffManager(home, self.store)

    def graph_path(self, run_id: str) -> Path:
        return self.home / "artifacts" / "task_graphs" / f"{run_id}.json"

    def save(self, graph: TaskGraph) -> None:
        graph = graph.model_copy(update={"updated_at": iso_now()})
        ensure_dir(self.graph_path(graph.run_id).parent)
        write_json(self.graph_path(graph.run_id), graph.model_dump())

    def load(self, run_id: str) -> TaskGraph | None:
        path = self.graph_path(run_id)
        if not path.exists():
            return None
        return TaskGraph.model_validate(read_json(path))

    def create_from_plan(self, plan: ExecutionPlan) -> TaskGraph:
        graph = PolicyCompiler(self.home).compile(plan)
        self.save(graph)
        self.ledger.record(
            "task_graph_created",
            run_id=graph.run_id,
            task_type=graph.task_type,
            reason="execution plan compiled to task graph",
            artifacts=[str(self.graph_path(graph.run_id))],
            payload=graph.model_dump(),
        )
        self.store.record_audit("task_graph_created", graph.model_dump(), run_id=graph.run_id, exit_status="ok")
        for node in graph.nodes:
            if node.node_type in GATE_NODE_TYPES:
                self.ledger.record(
                    "gate_required",
                    run_id=graph.run_id,
                    task_id=node.task_id,
                    task_type=graph.task_type,
                    agent_id=node.owner_agent,
                    status="pending",
                    reason=f"gate node required: {node.task_id}",
                    payload=node.model_dump(),
                )
        return graph

    def transition(
        self,
        graph: TaskGraph,
        task_id: str,
        status: TaskGraphStatus,
        *,
        reason: str,
        artifact_refs: list[str] | None = None,
        patch_id: str | None = None,
        patch_hash: str | None = None,
        target_repo: str | None = None,
        approved_scope_hash: str | None = None,
        output_ref: str | None = None,
        scope_lease_ids: list[str] | None = None,
        side_effect_descriptor_ids: list[str] | None = None,
        failure_id: str | None = None,
    ) -> TaskGraph:
        latest = self.load(graph.run_id)
        if latest and latest.updated_at != graph.updated_at:
            graph = latest
        nodes: list[TaskGraphNode] = []
        node_found = False
        for node in graph.nodes:
            if node.task_id == task_id:
                node_found = True
                existing_artifacts = list(node.artifact_refs)
                for ref in artifact_refs or []:
                    if ref not in existing_artifacts:
                        existing_artifacts.append(ref)
                node = node.model_copy(
                    update={
                        "status": status,
                        "blocked_reason": reason if status in {"blocked", "failed"} else None,
                        "artifact_refs": existing_artifacts,
                        "patch_id": patch_id if patch_id is not None else node.patch_id,
                        "patch_hash": patch_hash if patch_hash is not None else node.patch_hash,
                        "target_repo": target_repo if target_repo is not None else node.target_repo,
                        "approved_scope_hash": approved_scope_hash if approved_scope_hash is not None else node.approved_scope_hash,
                        "output_ref": output_ref if output_ref is not None else node.output_ref,
                        "scope_lease_ids": scope_lease_ids if scope_lease_ids is not None else node.scope_lease_ids,
                        "side_effect_descriptor_ids": side_effect_descriptor_ids if side_effect_descriptor_ids is not None else node.side_effect_descriptor_ids,
                        "failure_id": failure_id if failure_id is not None else node.failure_id,
                        "updated_at": iso_now(),
                    }
                )
                self._record_node_status(graph, node, reason)
            nodes.append(node)
        if not node_found:
            raise ValueError(f"task graph node not found: {task_id}")
        updated = graph.model_copy(update={"nodes": nodes, "updated_at": iso_now()})
        self.save(updated)
        return updated

    def require_handoff(
        self,
        graph: TaskGraph,
        task_id: str,
        *,
        from_task_id: str | None = None,
        completed_task_ids: set[str] | None = None,
        receiver_decision: Literal["accept", "reject"] = "accept",
        reject_reason: str | None = None,
        runner: Any | None = None,
        provider_mode: str = "mock",
        profile_overrides: dict[str, str] | None = None,
        handoff_context: dict[str, Any] | None = None,
    ) -> Any:
        node = graph.node_map[task_id]
        from_agent = "initial"
        if from_task_id:
            from_node = graph.node_map[from_task_id]
            from_agent = from_node.owner_agent
        elif node.depends_on:
            completed = completed_task_ids or {item.task_id for item in graph.nodes if item.status == "completed"}
            completed_deps = [dep for dep in node.depends_on if dep in completed]
            if completed_deps:
                from_agent = graph.node_map[completed_deps[-1]].owner_agent
            elif node.task_id != "controller":
                raise ValueError(f"missing handoff source for node {task_id}")
        if self._needs_node_lease(node) and not node.scope_lease_ids:
            lease = LeaseManager(self.home, self.store).request_lease(
                run_id=graph.run_id,
                task_id=node.task_id,
                resource_type=self._lease_resource_type(node),
                resource_id=self._lease_resource_id(node),
                holder_agent=node.owner_agent,
                mode=self._lease_mode(node),
                scope_hash=node.approved_scope_hash or node.patch_hash or sha256_text(stable_json({"run_id": graph.run_id, "task_id": node.task_id})),
            )
            if lease.status == "granted":
                graph = self.attach_contract_refs(graph, task_id, scope_lease_ids=[lease.lease_id])
                node = graph.node_map[task_id]
        for lease_id in node.scope_lease_ids:
            ok, reason = LeaseManager(self.home, self.store).validate_lease(lease_id, holder_agent=node.owner_agent)
            if not ok:
                LeaseManager(self.home, self.store).record_holder_blocked(lease_id, holder_agent=node.owner_agent, run_id=graph.run_id, task_id=node.task_id, reason=reason)
        contract = self.handoffs.create_handoff(
            run_id=graph.run_id,
            task_id=node.task_id,
            task_type=graph.task_type,
            from_agent=from_agent,
            to_agent=node.owner_agent,
            reason=f"task graph dispatch to {node.task_id}",
            required_inputs=self._handoff_input_refs(graph, node, from_agent),
            provided_artifacts=self._dependency_artifacts(graph, node),
            gate_requirements=list(node.required_gates),
            scope_lease_ids=list(node.scope_lease_ids),
            side_effect_descriptor_ids=list(node.side_effect_descriptor_ids),
        )
        from sitina.orchestrator.collaboration import CollaborationRuntime

        collaboration = CollaborationRuntime(self.home, self.store)
        if contract.status != "ok":
            collaboration.handoff(contract=contract, accepted=False, reason=contract.blocked_reason or f"handoff blocked for {task_id}", reviewer=node.owner_agent)
            raise HandoffBlockedError(contract.blocked_reason or f"handoff blocked for {task_id}")
        if runner is not None:
            decision = self._request_receiver_decision(
                graph=graph,
                node=node,
                contract=contract,
                runner=runner,
                provider_mode=provider_mode,
                profile_overrides=profile_overrides or {},
                handoff_context=handoff_context or {},
            )
            if decision.decision == "reject":
                collaboration.handoff(contract=contract, accepted=False, reason=decision.reason, reviewer=node.owner_agent)
                raise HandoffBlockedError(decision.reason)
            accepted = collaboration.handoff(contract=contract, accepted=True, reason=decision.reason, reviewer=node.owner_agent)
            return accepted
        if receiver_decision == "reject":
            reason = reject_reason or f"{node.owner_agent} rejected task graph dispatch for {node.task_id}"
            collaboration.handoff(contract=contract, accepted=False, reason=reason, reviewer=node.owner_agent)
            raise HandoffBlockedError(reason)
        accepted = collaboration.handoff(contract=contract, accepted=True, reason=f"{node.owner_agent} accepted task graph dispatch for {node.task_id}", reviewer=node.owner_agent)
        return accepted

    def _request_receiver_decision(
        self,
        *,
        graph: TaskGraph,
        node: TaskGraphNode,
        contract: Any,
        runner: Any,
        provider_mode: str,
        profile_overrides: dict[str, str],
        handoff_context: dict[str, Any],
    ) -> HandoffDecision:
        input_payload = self._receiver_decision_input(graph=graph, node=node, contract=contract, handoff_context=handoff_context)
        raw_input_hash = sha256_text(stable_json(input_payload))
        safe_input_hash = compute_agent_input_hash(input_payload)
        safe_input_payload = canonicalize_agent_input(input_payload)
        logical_call_id = "logical_call_" + new_id()
        self.ledger.record(
            "agent_started",
            run_id=graph.run_id,
            task_id=node.task_id,
            task_type=graph.task_type,
            agent_id=node.owner_agent,
            status="ok",
            reason=f"{node.owner_agent} handoff receiver decision started",
            payload={
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "input_payload": safe_input_payload,
                "provider_mode": provider_mode,
                "handoff_id": contract.handoff_id,
                "handoff_receiver_decision": True,
                "call_id": logical_call_id,
                "input_hash_semantics": "sha256(stable_json(redacted_input_payload))",
            },
        )
        terminal_error: Exception | None = None
        try:
            result = runner.run_agent(
                node.owner_agent,
                input_payload,
                provider_mode=provider_mode,
                profile_override=profile_overrides.get(node.owner_agent),
                run_id=graph.run_id,
                task_id=node.task_id,
                task_type=graph.task_type,
                max_tokens=4096,
                logical_call_id=logical_call_id,
                audit_context={
                    "call_origin": "handoff_receiver",
                    "role": node.owner_agent,
                    "handoff_id": contract.handoff_id,
                },
            )
            output_hash = sha256_text(stable_json(result.payload))
            self.ledger.record(
                "agent_completed",
                run_id=graph.run_id,
                task_id=node.task_id,
                task_type=graph.task_type,
                agent_id=node.owner_agent,
                status="ok",
                reason=f"{node.owner_agent} handoff receiver decision completed",
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
                    "handoff_id": contract.handoff_id,
                    "handoff_receiver_decision": True,
                    "call_id": logical_call_id,
                },
            )
            decision_payload = result.payload.get("extensions", {}).get("handoff_decision")
            decision = HandoffDecision.model_validate(self._normalize_handoff_decision_payload(decision_payload, node.owner_agent))
            self.ledger.record(
                "handoff_receiver_decision",
                run_id=graph.run_id,
                task_id=node.task_id,
                task_type=graph.task_type,
                agent_id=node.owner_agent,
                status="blocked" if decision.decision == "reject" else "ok",
                reason=decision.reason,
                payload={
                    "handoff_id": contract.handoff_id,
                    "receiver_agent": node.owner_agent,
                    "decision": decision.model_dump(),
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
                    "call_id": logical_call_id,
                },
            )
            self.store.record_event(
                "handoff_receiver_decision",
                {
                    "handoff_id": contract.handoff_id,
                    "task_id": node.task_id,
                    "receiver_agent": node.owner_agent,
                    "decision": decision.model_dump(),
                    "input_hash": safe_input_hash,
                    "raw_input_hash": raw_input_hash,
                    "safe_input_hash": safe_input_hash,
                    "output_hash": output_hash,
                    "provider_mode": result.provider_mode,
                    "call_id": logical_call_id,
                },
                run_id=graph.run_id,
                trace_id=f"{graph.run_id}:handoff:{contract.handoff_id}:receiver_decision",
            )
            self.store.record_audit(
                "handoff_receiver_decision",
                {"handoff_id": contract.handoff_id, "receiver_agent": node.owner_agent, "decision": decision.model_dump()},
                run_id=graph.run_id,
                trace_id=f"{graph.run_id}:handoff:{contract.handoff_id}:receiver_decision",
                agent=node.owner_agent,
                input_hash=safe_input_hash,
                output_hash=output_hash,
                exit_status=decision.decision,
            )
            return decision
        except (ValidationError, ValueError, TypeError) as exc:
            reason = f"invalid receiver handoff decision from {node.owner_agent}: {exc}"
        except Exception as exc:  # noqa: BLE001
            reason = f"receiver handoff decision failed from {node.owner_agent}: {exc}"
            if getattr(exc, "error_type", None):
                terminal_error = exc
        self.ledger.record(
            "handoff_receiver_decision",
            run_id=graph.run_id,
            task_id=node.task_id,
            task_type=graph.task_type,
            agent_id=node.owner_agent,
            status="blocked",
            reason=reason,
            payload={
                "handoff_id": contract.handoff_id,
                "receiver_agent": node.owner_agent,
                "reason": reason,
                "input_hash": safe_input_hash,
                "raw_input_hash": raw_input_hash,
                "safe_input_hash": safe_input_hash,
                "call_id": logical_call_id,
            },
        )
        self.store.record_audit(
            "handoff_receiver_decision",
            {"handoff_id": contract.handoff_id, "receiver_agent": node.owner_agent, "reason": reason},
            run_id=graph.run_id,
            trace_id=f"{graph.run_id}:handoff:{contract.handoff_id}:receiver_decision",
            agent=node.owner_agent,
            input_hash=safe_input_hash,
            exit_status="blocked",
        )
        from sitina.orchestrator.collaboration import CollaborationRuntime

        CollaborationRuntime(self.home, self.store).handoff(contract=contract, accepted=False, reason=reason, reviewer=node.owner_agent)
        if terminal_error is not None:
            raise terminal_error
        raise HandoffBlockedError(reason)

    def _normalize_handoff_decision_payload(self, payload: Any, receiver_agent: str) -> dict[str, Any]:
        if isinstance(payload, str):
            decision = payload.strip().lower()
            if decision in {"accept", "reject"}:
                return {
                    "decision": decision,
                    "reason": f"{receiver_agent} returned shorthand {decision} handoff decision",
                    "confidence": 0.5,
                    "notes": ["normalized from shorthand live provider output"],
                }
            return {"decision": decision, "reason": ""}
        if isinstance(payload, dict):
            out = dict(payload)
            if "decision" not in out and isinstance(out.get("accepted"), bool):
                out["decision"] = "accept" if out.get("accepted") else "reject"
            out.pop("accepted", None)
            if out.get("decision") in {"accept", "reject"} and not out.get("reason"):
                out["reason"] = f"{receiver_agent} returned {out['decision']} handoff decision"
            try:
                out["confidence"] = max(0.0, min(1.0, float(out.get("confidence", 0.5))))
            except (TypeError, ValueError):
                out["confidence"] = 0.5
            return out
        return payload

    def _receiver_decision_input(self, *, graph: TaskGraph, node: TaskGraphNode, contract: Any, handoff_context: dict[str, Any]) -> dict[str, Any]:
        compact_handoff_context = {
            key: value
            for key, value in handoff_context.items()
            if key in {
                "stage",
                "provider_mode",
                "controlled_noop_policy_graph",
                "controlled_readonly_analysis",
                "real_side_effects_forbidden",
                "contract_preconditions_validated_by_runtime",
                "controlled_reject_evidence",
            }
        }
        if handoff_context.get("user_goal"):
            compact_handoff_context["user_goal_hash"] = sha256_text(str(handoff_context["user_goal"]))
        risk_scan = handoff_context.get("risk_scan")
        if isinstance(risk_scan, dict) and risk_scan.get("risk_scan_id"):
            compact_handoff_context["risk_scan_id"] = risk_scan["risk_scan_id"]
        context = {
            "home": str(self.home),
            "task_type": graph.task_type,
            "task_id": node.task_id,
            "handoff_decision_request": True,
            "handoff_contract": contract.model_dump() if hasattr(contract, "model_dump") else dict(contract),
            "task_graph_status": {item.task_id: item.status for item in graph.nodes},
            "handoff_context": compact_handoff_context,
        }
        if node.owner_agent == "planner":
            receiver_goal = str(handoff_context.get("user_goal") or "handoff decision")[:600]
            if "controlled_reject_evidence" in compact_handoff_context:
                receiver_goal = "Evaluate this handoff contract against the supplied structured scope evidence."
            return {
                "user_goal": receiver_goal,
                "project_context": context,
                "allowed_read_scope": [str(self.home)],
                "risk_policy": {"task_type": graph.task_type, "handoff_decision_required": True, "fail_closed": True},
                "conversation_summary": "Decide whether to accept or reject this handoff. Return extensions.handoff_decision.",
            }
        handoff_note = {
            "document_id": contract.handoff_id,
            "type": "handoff_contract",
            "summary": f"Receiver decision required for {node.task_id}; runtime contract preconditions are supplied.",
            "handoff_decision_request": True,
            "handoff_contract": context["handoff_contract"],
        }
        if node.owner_agent == "controller":
            run_state = self.store.get_run(graph.run_id) or {
                "run_id": graph.run_id,
                "phase": "controller_decision",
                "active_agent": "controller",
                "risk_level": "low",
                "approval_required": False,
                "approval_id": None,
                "rework_count": 0,
                "max_rework_rounds": 2,
                "mandatory_steps": {},
                "mandatory_step_outputs": {},
                "open_findings": [],
                "verification_status": "not_verified",
                "locks_held": [],
                "risk_scan_result_ref": None,
                "updated_by": "harness",
            }
            risk_scan = handoff_context.get("risk_scan")
            if not isinstance(risk_scan, dict):
                raise ValueError("controller handoff decision requires risk_scan context")
            return {
                "user_goal": str(handoff_context.get("user_goal") or "handoff decision"),
                "run_state": run_state,
                "last_agent_output": {"agent": contract.from_agent, "decision": "handoff"},
                "risk_scan_result": risk_scan,
                "unresolved_findings": [{"status": "none"}],
                "workflow_state": context | {"turn": 1, "provider_mode": str(handoff_context.get("provider_mode") or "live"), "max_turns": 1},
                "blackboard_context": [handoff_note],
            }
        if node.owner_agent == "coder":
            return {
                "approved_touched_files": ["__READONLY_HANDOFF_NO_MUTATION__"],
                "plan": context,
                "acceptance_criteria": ["accept only a contract that preserves no source mutation"],
                "approval_id": "readonly_handoff_decision",
                "allowed_scope": [str(self.home)],
                "input_scope_hash": sha256_text(stable_json({"run_id": graph.run_id, "handoff_id": contract.handoff_id})),
                "before_hashes": {"__READONLY_HANDOFF_NO_MUTATION__": None},
                "file_write_contract": context | {"handoff_decision_request": True, "source_mutation": "forbidden"},
                "blackboard_context": [handoff_note],
            }
        if node.owner_agent == "tester":
            return {
                "test_strategy": "Decide whether the supplied handoff contract permits controlled readonly verification.",
                "allowed_commands": ["sitina config validate"],
                "patch_id": "handoff_decision_only",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "approved_env": {"SITINA_HOME": str(self.home)},
                "expected_artifact_hash": None,
                "blackboard_context": [handoff_note],
            }
        if node.owner_agent == "reviewer":
            return {
                "patch_id": "handoff_decision_only",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "acceptance_criteria": ["contract ownership and gates are coherent"],
                "test_artifacts": [contract.handoff_id],
                "mandatory_step_context": context | {"handoff_decision_request": True},
                "blackboard_context": [handoff_note],
            }
        if node.owner_agent == "summary":
            run_state = self.store.get_run(graph.run_id) or {"run_id": graph.run_id, "phase": "summarizing", "active_agent": "summary", "risk_level": "low", "approval_required": False, "approval_id": None, "rework_count": 0, "max_rework_rounds": 2, "mandatory_steps": {}, "mandatory_step_outputs": {}, "open_findings": [], "verification_status": "not_verified", "locks_held": [], "risk_scan_result_ref": None, "updated_by": "harness"}
            return {
                "final_run_state": run_state,
                "tester_output": {"agent": "tester", "decision": "handoff_pending"},
                "reviewer_output": context | {"handoff_decision_request": True},
                "audit_refs": [contract.handoff_id],
                "blackboard_context": [handoff_note],
            }
        if node.owner_agent == "memory":
            return {
                "run_summary": "Receiver decision for controlled handoff contract.",
                "user_visible_decisions": [f"handoff_id={contract.handoff_id}"],
                "memory_policy": context | {"handoff_decision_request": True, "no_auto_accept": True},
                "blackboard_context": [handoff_note],
            }
        raise ValueError(f"receiver handoff decision input not implemented for {node.owner_agent}")
    def dependencies_completed(self, graph: TaskGraph, task_id: str) -> bool:
        nodes = graph.node_map
        return all(nodes[dep].status == "completed" for dep in nodes[task_id].depends_on)

    def missing_mandatory_nodes(self, graph: TaskGraph) -> list[TaskGraphNode]:
        return [node for node in graph.mandatory_nodes() if node.status != "completed"]

    def can_complete(self, graph: TaskGraph) -> tuple[bool, list[str]]:
        missing = self.missing_mandatory_nodes(graph)
        return not missing, [f"{node.task_id}:{node.status}" for node in missing]

    def add_rework_edge(
        self,
        graph: TaskGraph,
        *,
        from_task_id: str,
        to_task_id: str,
        reason: str,
        retry_attempt: int,
        approved_scope_hash: str | None = None,
    ) -> TaskGraph:
        edge = ReworkEdge(
            edge_id="rework_" + new_id(),
            run_id=graph.run_id,
            task_type=graph.task_type,
            from_task_id=from_task_id,
            to_task_id=to_task_id,
            reason=reason,
            retry_attempt=retry_attempt,
            approved_scope_hash=approved_scope_hash,
            created_at=iso_now(),
        )
        updated = graph.model_copy(update={"rework_edges": [*graph.rework_edges, edge], "updated_at": iso_now()})
        self.save(updated)
        self.ledger.record(
            "rework_edge_created",
            run_id=graph.run_id,
            task_id=from_task_id,
            task_type=graph.task_type,
            status="ok",
            reason=reason,
            payload=edge.model_dump(),
        )
        self.store.record_audit("rework_edge_created", edge.model_dump(), run_id=graph.run_id, exit_status="ok")
        return updated

    def attach_contract_refs(
        self,
        graph: TaskGraph,
        task_id: str,
        *,
        scope_lease_ids: list[str] | None = None,
        side_effect_descriptor_ids: list[str] | None = None,
    ) -> TaskGraph:
        nodes: list[TaskGraphNode] = []
        for node in graph.nodes:
            if node.task_id == task_id:
                node = node.model_copy(
                    update={
                        "scope_lease_ids": sorted(set([*node.scope_lease_ids, *(scope_lease_ids or [])])),
                        "side_effect_descriptor_ids": sorted(set([*node.side_effect_descriptor_ids, *(side_effect_descriptor_ids or [])])),
                        "updated_at": iso_now(),
                    }
                )
                self._record_node_status(graph, node, f"{task_id} contract refs updated")
            nodes.append(node)
        updated = graph.model_copy(update={"nodes": nodes, "updated_at": iso_now()})
        self.save(updated)
        return updated

    def apply_proposal_selection(
        self,
        graph: TaskGraph,
        *,
        proposal_round_id: str,
        selected_proposal_id: str,
        task_graph_patch: dict[str, Any],
    ) -> TaskGraph:
        nodes = [
            node.model_copy(update={"proposal_round_id": proposal_round_id, "selected_proposal_id": selected_proposal_id})
            if node.task_id == "controller"
            else node
            for node in graph.nodes
        ]
        updated = graph.model_copy(update={"nodes": nodes, "proposal_round_id": proposal_round_id, "selected_proposal_id": selected_proposal_id, "updated_at": iso_now()})
        self.save(updated)
        payload = {"proposal_round_id": proposal_round_id, "selected_proposal_id": selected_proposal_id, "task_graph_patch": task_graph_patch, "graph_path": str(self.graph_path(graph.run_id))}
        self.ledger.record(
            "task_graph_patch_applied",
            run_id=graph.run_id,
            task_id="controller",
            task_type=graph.task_type,
            agent_id="controller",
            status="ok",
            reason="selected proposal metadata applied to task graph",
            artifacts=[str(self.graph_path(graph.run_id))],
            payload=payload,
        )
        self.store.record_audit("task_graph_patch_applied", payload, run_id=graph.run_id, trace_id=f"{graph.run_id}:task_graph:proposal", agent="controller", exit_status="ok")
        return updated

    def add_arbitration_node(
        self,
        graph: TaskGraph,
        *,
        arbitration_id: str,
        source_task_id: str,
        reason: str,
    ) -> TaskGraph:
        task_id = f"arbitration_{arbitration_id}"
        if task_id in graph.node_map:
            return graph
        node = TaskGraphNode(
            task_id=task_id,
            run_id=graph.run_id,
            task_type=graph.task_type,
            node_type="arbitration",
            owner_agent="controller",
            depends_on=[source_task_id],
            required_gates=["arbitration"],
            status="blocked",
            blocked_reason=reason,
            created_at=iso_now(),
        )
        updated = graph.model_copy(update={"nodes": [*graph.nodes, node], "updated_at": iso_now()})
        self.save(updated)
        self.ledger.record("arbitration_node_created", run_id=graph.run_id, task_id=task_id, task_type=graph.task_type, agent_id="controller", status="blocked", reason=reason, payload=node.model_dump())
        self.store.record_audit("arbitration_node_created", node.model_dump(), run_id=graph.run_id, trace_id=f"{graph.run_id}:task_graph:{task_id}", agent="controller", exit_status="blocked")
        return updated

    def add_blocked_lease_holder_node(
        self,
        graph: TaskGraph,
        *,
        task_id: str,
        owner_agent: str,
        source_task_id: str,
        lease_id: str,
        reason: str,
    ) -> TaskGraph:
        if task_id in graph.node_map:
            return graph
        node = TaskGraphNode(
            task_id=task_id,
            run_id=graph.run_id,
            task_type=graph.task_type,
            node_type="maintenance_op",
            owner_agent=owner_agent,
            depends_on=[source_task_id],
            required_gates=["lease"],
            status="blocked",
            mandatory=False,
            blocked_reason=reason,
            scope_lease_ids=[lease_id],
            created_at=iso_now(),
        )
        updated = graph.model_copy(update={"nodes": [*graph.nodes, node], "updated_at": iso_now()})
        self.save(updated)
        self._record_node_status(updated, node, reason)
        return updated

    def add_rework_chain(
        self,
        graph: TaskGraph,
        *,
        source_node_id: str,
        reason: str,
        attempt: int,
        max_attempts: int,
        approved_scope_hash: str | None = None,
        high_risk: bool = False,
        multi_reviewer: bool = False,
        planner_rework: bool = False,
        failure_id: str | None = None,
        failure_type: str = "unknown",
        source_evaluation_id: str | None = None,
    ) -> TaskGraph:
        prefix = f"rework_{attempt}"
        chain_specs: list[tuple[str, NodeType, str, list[str], list[str]]] = []
        first_task = f"{prefix}_{'planner_rework' if planner_rework else 'coder_rework'}"
        chain_specs.append(
            (
                first_task,
                "planner_rework" if planner_rework else "coder_rework",
                "planner" if planner_rework else "coder",
                [source_node_id],
                ["approved_scope"],
            )
        )
        tester_task = f"{prefix}_tester_rerun"
        chain_specs.append((tester_task, "tester_rerun", "tester", [first_task], ["tester"]))
        reviewer_task = f"{prefix}_{'multi_reviewer_rerun' if multi_reviewer else 'reviewer_rerun'}"
        chain_specs.append((reviewer_task, "multi_reviewer_rerun" if multi_reviewer else "reviewer_rerun", "reviewer", [tester_task], ["multi_reviewer_merge" if multi_reviewer else "reviewer"]))
        if high_risk:
            approval_task = f"{prefix}_reapproval_required"
            verify_task = f"{prefix}_patch_hash_verify"
            chain_specs.append((approval_task, "reapproval_required", "controller", [reviewer_task], ["approval"]))
            chain_specs.append((verify_task, "patch_hash_verify", "git_worktree_manager", [approval_task], ["patch_hash_verify"]))
        rework_id = "rework_" + new_id()
        input_hash = sha256_text(
            stable_json(
                {
                    "run_id": graph.run_id,
                    "source_node_id": source_node_id,
                    "failure_id": failure_id,
                    "failure_type": failure_type,
                    "reason": reason,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "approved_scope_hash": approved_scope_hash,
                }
            )
        )
        self._record_rework_lifecycle(
            "rework_requested",
            graph,
            rework_id=rework_id,
            source_evaluation_id=source_evaluation_id or failure_id,
            failure_type=failure_type,
            target_agent=chain_specs[0][2],
            parent_task_id=source_node_id,
            retry_index=attempt,
            max_retries=max_attempts,
            input_hash=input_hash,
            terminal_status="requested",
            reason=reason,
        )
        existing = graph.node_map
        nodes = list(graph.nodes)
        for task_id, node_type, owner_agent, depends_on, required_gates in chain_specs:
            if task_id in existing:
                continue
            node = TaskGraphNode(
                task_id=task_id,
                run_id=graph.run_id,
                task_type=graph.task_type,
                node_type=node_type,
                owner_agent=owner_agent,
                depends_on=depends_on,
                required_gates=required_gates,
                approved_scope_hash=approved_scope_hash,
                rework_id=rework_id,
                source_node_id=source_node_id,
                rework_reason=reason,
                rework_failure_type=failure_type,
                source_evaluation_id=source_evaluation_id or failure_id,
                rework_input_hash=input_hash,
                attempt=attempt,
                max_attempts=max_attempts,
                failure_id=failure_id,
                created_at=iso_now(),
            )
            nodes.append(node)
            self.ledger.record(
                "rework_node_created",
                run_id=graph.run_id,
                task_id=task_id,
                task_type=graph.task_type,
                agent_id=owner_agent,
                status="pending",
                reason=reason,
                payload=node.model_dump(),
            )
            self.store.record_audit("rework_node_created", node.model_dump(), run_id=graph.run_id, trace_id=f"{graph.run_id}:rework:{task_id}", agent=owner_agent, exit_status="pending")
        updated = graph.model_copy(update={"nodes": nodes, "updated_at": iso_now()})
        self.save(updated)
        updated = self.add_rework_edge(
            updated,
            from_task_id=source_node_id,
            to_task_id=first_task,
            reason=reason,
            retry_attempt=attempt,
            approved_scope_hash=approved_scope_hash,
        )
        self._record_rework_lifecycle(
            "rework_dispatched",
            updated,
            rework_id=rework_id,
            source_evaluation_id=source_evaluation_id or failure_id,
            failure_type=failure_type,
            target_agent=chain_specs[0][2],
            parent_task_id=source_node_id,
            retry_index=attempt,
            max_retries=max_attempts,
            input_hash=input_hash,
            terminal_status="dispatched",
            reason=reason,
        )
        return updated

    def record_rework_exhausted(
        self,
        graph: TaskGraph,
        *,
        source_node_id: str,
        failure_type: str,
        attempt: int,
        max_attempts: int,
        reason: str,
        failure_id: str | None = None,
    ) -> str:
        rework_id = "rework_" + new_id()
        input_hash = sha256_text(stable_json({"run_id": graph.run_id, "source_node_id": source_node_id, "failure_id": failure_id, "failure_type": failure_type, "attempt": attempt, "max_attempts": max_attempts}))
        common = {
            "rework_id": rework_id,
            "source_evaluation_id": failure_id,
            "failure_type": failure_type,
            "target_agent": None,
            "parent_task_id": source_node_id,
            "retry_index": attempt,
            "max_retries": max_attempts,
            "input_hash": input_hash,
            "reason": reason,
        }
        self._record_rework_lifecycle("rework_requested", graph, terminal_status="requested", **common)
        self._record_rework_lifecycle("rework_retry_exhausted", graph, terminal_status="retry_exhausted", **common)
        return rework_id

    def block_run_for_missing_mandatory(self, graph: TaskGraph) -> str:
        missing = self.missing_mandatory_nodes(graph)
        reason = "mandatory task graph node(s) incomplete: " + ", ".join(f"{node.task_id}={node.status}" for node in missing)
        self.ledger.record("gate_blocked", run_id=graph.run_id, task_type=graph.task_type, status="blocked", reason=reason, payload={"missing": [node.model_dump() for node in missing]})
        self.store.record_audit("task_graph_completion_blocked", {"reason": reason, "missing": [node.task_id for node in missing]}, run_id=graph.run_id, exit_status="blocked")
        return reason

    def _record_node_status(self, graph: TaskGraph, node: TaskGraphNode, reason: str) -> None:
        self.ledger.record(
            "task_graph_node_status",
            run_id=graph.run_id,
            task_id=node.task_id,
            task_type=graph.task_type,
            agent_id=node.owner_agent,
            status="blocked" if node.status in {"blocked", "failed"} else ("skipped" if node.status == "skipped" else "ok"),
            reason=reason,
            artifacts=node.artifact_refs,
            payload=node.model_dump(),
        )
        if node.node_type in GATE_NODE_TYPES:
            event = "gate_passed" if node.status == "completed" else ("gate_blocked" if node.status in {"blocked", "failed"} else "gate_required")
            self.ledger.record(
                event,
                run_id=graph.run_id,
                task_id=node.task_id,
                task_type=graph.task_type,
                agent_id=node.owner_agent,
                status="blocked" if event == "gate_blocked" else ("pending" if event == "gate_required" else "ok"),
                reason=reason,
                artifacts=node.artifact_refs,
                payload=node.model_dump(),
            )
        self.store.record_audit(
            "task_graph_node_status",
            node.model_dump(),
            run_id=graph.run_id,
            trace_id=f"{graph.run_id}:task_graph:{node.task_id}",
            agent=node.owner_agent,
            exit_status=node.status,
            output_hash=sha256_text(stable_json(node.model_dump())),
        )
        if node.rework_id and node.rework_input_hash:
            siblings = [item for item in graph.nodes if item.rework_id == node.rework_id]
            first = not any(item.task_id in node.depends_on for item in siblings)
            terminal = not any(node.task_id in item.depends_on for item in siblings)
            common = {
                "rework_id": node.rework_id,
                "source_evaluation_id": node.source_evaluation_id or node.failure_id,
                "failure_type": node.rework_failure_type or "unknown",
                "target_agent": node.owner_agent,
                "parent_task_id": node.source_node_id or node.task_id,
                "retry_index": int(node.attempt or 0),
                "max_retries": int(node.max_attempts or 0),
                "input_hash": node.rework_input_hash,
            }
            if node.status == "running" and first:
                self._record_rework_lifecycle("rework_started", graph, terminal_status="running", reason=reason, **common)
            elif node.status == "completed" and terminal:
                output_hash = node.patch_hash or node.output_ref or sha256_text(stable_json(node.model_dump()))
                self._record_rework_lifecycle("rework_completed", graph, terminal_status="completed", output_hash=output_hash, reason=reason, **common)
            elif node.status in {"blocked", "failed"}:
                self._record_rework_lifecycle("rework_failed", graph, terminal_status="failed", reason=reason, **common)

    def _record_rework_lifecycle(
        self,
        event_type: str,
        graph: TaskGraph,
        *,
        rework_id: str,
        source_evaluation_id: str | None,
        failure_type: str,
        target_agent: str | None,
        parent_task_id: str,
        retry_index: int,
        max_retries: int,
        input_hash: str,
        terminal_status: Literal["requested", "dispatched", "running", "completed", "failed", "retry_exhausted"],
        reason: str,
        output_hash: str | None = None,
    ) -> None:
        lifecycle = ReworkLifecycleEvent(
            rework_id=rework_id,
            source_evaluation_id=source_evaluation_id,
            failure_type=failure_type,
            target_agent=target_agent,
            parent_task_id=parent_task_id,
            retry_index=retry_index,
            max_retries=max_retries,
            input_hash=input_hash,
            output_hash=output_hash,
            terminal_status=terminal_status,
            created_at=iso_now(),
        )
        status = "blocked" if terminal_status in {"failed", "retry_exhausted"} else "ok"
        self.ledger.record(
            event_type,
            run_id=graph.run_id,
            task_id=parent_task_id,
            task_type=graph.task_type,
            agent_id=target_agent,
            status=status,
            reason=reason,
            payload=lifecycle.model_dump(),
        )
        self.store.record_audit(
            event_type,
            lifecycle.model_dump(),
            run_id=graph.run_id,
            trace_id=f"{graph.run_id}:rework:{rework_id}:{event_type}",
            agent=target_agent,
            exit_status=terminal_status,
        )
    def _dependency_artifacts(self, graph: TaskGraph, node: TaskGraphNode) -> list[str]:
        refs: list[str] = []
        for dep in node.depends_on:
            dep_node = graph.node_map.get(dep)
            if dep_node:
                refs.extend(dep_node.artifact_refs)
        return refs

    def _needs_node_lease(self, node: TaskGraphNode) -> bool:
        if node.owner_agent not in {"coder", "git_worktree_manager", "maintenance_ops"}:
            return False
        return bool({"approved_scope", "worktree", "patch_apply", "approval"} & set(node.required_gates) or node.node_type in {"coder", "patch_apply", "maintenance_op"})

    def _lease_resource_type(self, node: TaskGraphNode) -> str:
        if node.node_type == "patch_apply":
            return "patch"
        if node.node_type == "worktree_prepare":
            return "directory"
        if node.node_type == "maintenance_op":
            return "external_tool"
        return "approval_scope"

    def _lease_resource_id(self, node: TaskGraphNode) -> str:
        if node.patch_id:
            return node.patch_id
        if node.target_repo:
            return node.target_repo
        if node.artifact_refs:
            return node.artifact_refs[0]
        return f"{node.run_id}:{node.task_id}"

    def _lease_mode(self, node: TaskGraphNode) -> str:
        if node.node_type == "patch_apply":
            return "apply"
        if node.node_type == "maintenance_op":
            return "approve"
        return "write"

    def _handoff_input_refs(self, graph: TaskGraph, node: TaskGraphNode, from_agent: str) -> list[str]:
        refs = list(node.input_refs)
        if refs or from_agent == "initial":
            return refs
        for dep in node.depends_on:
            dep_node = graph.node_map.get(dep)
            if not dep_node:
                continue
            refs.append(dep_node.output_ref or f"task:{dep_node.task_id}:{dep_node.status}")
        if not refs:
            refs.append(f"task:{node.task_id}:policy")
        return refs
