from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class TaskProtocolError(RuntimeError):
    pass


class MaterializationState(str, Enum):
    PENDING = "PENDING"
    MATERIALIZED = "MATERIALIZED"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class TaskNode:
    node_id: str
    specification_generation: int
    specification_hash: str
    specification: Mapping[str, Any]
    required_obligation: bool
    materialization_state: MaterializationState = MaterializationState.PENDING
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()

    @property
    def schedulable(self) -> bool:
        return self.materialization_state is MaterializationState.MATERIALIZED and not self.superseded_by


@dataclass(frozen=True)
class GatingConstraint:
    constraint_id: str
    node_id: str
    reason_code: str
    active: bool = True


@dataclass(frozen=True)
class TaskDefinitionMaterializationProcess:
    process_id: str
    node_id: str
    create_command_id: str
    request_hash: str
    state: MaterializationState = MaterializationState.PENDING


@dataclass(frozen=True)
class TaskGraphAggregate:
    graph_id: str
    version: int = 0
    nodes: tuple[TaskNode, ...] = ()
    dependencies: tuple[tuple[str, str], ...] = ()
    constraints: tuple[GatingConstraint, ...] = ()
    materializations: tuple[TaskDefinitionMaterializationProcess, ...] = ()

    @classmethod
    def create(cls, graph_id: str) -> "TaskGraphAggregate":
        validate_identifier(graph_id, field="graph_id")
        return cls(graph_id)

    def _cas(self, expected_graph_version: int) -> None:
        if expected_graph_version != self.version:
            raise TaskProtocolError("TaskGraph expected version conflict")

    def _node(self, node_id: str) -> TaskNode:
        try: return next(node for node in self.nodes if node.node_id == node_id)
        except StopIteration as error: raise TaskProtocolError(f"unknown TaskGraph node: {node_id}") from error

    def add_task(self, *, expected_graph_version: int, node_id: str, specification: Mapping[str, Any], required_obligation: bool) -> tuple["TaskGraphAggregate", dict]:
        self._cas(expected_graph_version); validate_identifier(node_id, field="node_id")
        if any(node.node_id == node_id for node in self.nodes): raise TaskProtocolError("Task Node already exists")
        spec_hash = domain_hash("TASK_SPECIFICATION", canonical_json_bytes(dict(specification)))
        node = TaskNode(node_id, 1, spec_hash, dict(specification), required_obligation)
        updated = replace(self, version=self.version + 1, nodes=self.nodes + (node,))
        return updated, {"schema": "TASK_NODE_ADDED_V1", "graph_id": self.graph_id, "node_id": node_id, "specification_generation": 1, "specification_hash": spec_hash, "materialization": "PENDING"}

    def supersede_task(self, *, expected_graph_version: int, old_node_id: str, new_node_id: str, specification: Mapping[str, Any]) -> tuple["TaskGraphAggregate", tuple[dict, ...]]:
        self._cas(expected_graph_version); old = self._node(old_node_id)
        if old.superseded_by: raise TaskProtocolError("Task Node was already superseded")
        if any(node.node_id == new_node_id for node in self.nodes): raise TaskProtocolError("replacement Node already exists")
        spec_hash = domain_hash("TASK_SPECIFICATION", canonical_json_bytes(dict(specification)))
        new = TaskNode(new_node_id, old.specification_generation + 1, spec_hash, dict(specification), old.required_obligation, supersedes=(old_node_id,))
        replaced = replace(old, superseded_by=(new_node_id,))
        nodes = tuple(replaced if node.node_id == old_node_id else node for node in self.nodes) + (new,)
        updated = replace(self, version=self.version + 1, nodes=nodes)
        return updated, (
            {"schema": "TASK_NODE_SUPERSEDED_V1", "old_node_id": old_node_id, "new_node_id": new_node_id, "lineage_generation": new.specification_generation},
            {"schema": "TASK_NODE_ADDED_V1", "node_id": new_node_id, "specification_hash": spec_hash, "materialization": "PENDING"},
        )

    def split_task(self, *, expected_graph_version: int, old_node_id: str, replacements: Mapping[str, Mapping[str, Any]]) -> tuple["TaskGraphAggregate", tuple[dict, ...]]:
        self._cas(expected_graph_version)
        graph = self; events = []
        for index, (node_id, spec) in enumerate(sorted(replacements.items())):
            if index == 0:
                graph, emitted = graph.supersede_task(expected_graph_version=graph.version, old_node_id=old_node_id, new_node_id=node_id, specification=spec)
                events.extend(emitted)
            else:
                graph, event = graph.add_task(expected_graph_version=graph.version, node_id=node_id, specification=spec, required_obligation=self._node(old_node_id).required_obligation)
                events.append(event)
        events.append({"schema": "TASK_NODE_SPLIT_V1", "old_node_id": old_node_id, "new_node_ids": sorted(replacements)})
        return graph, tuple(events)

    def merge_tasks(self, *, expected_graph_version: int, source_node_ids: tuple[str, ...], new_node_id: str, specification: Mapping[str, Any]) -> tuple["TaskGraphAggregate", tuple[dict, ...]]:
        self._cas(expected_graph_version)
        sources = tuple(self._node(node_id) for node_id in source_node_ids)
        spec_hash = domain_hash("TASK_SPECIFICATION", canonical_json_bytes(dict(specification)))
        new = TaskNode(new_node_id, max(node.specification_generation for node in sources) + 1, spec_hash, dict(specification), any(node.required_obligation for node in sources), supersedes=tuple(sorted(source_node_ids)))
        nodes = tuple(replace(node, superseded_by=(new_node_id,)) if node.node_id in source_node_ids else node for node in self.nodes) + (new,)
        return replace(self, version=self.version + 1, nodes=nodes), ({"schema": "TASK_NODES_MERGED_V1", "source_node_ids": sorted(source_node_ids), "new_node_id": new_node_id, "specification_hash": spec_hash},)

    def add_dependency(self, *, expected_graph_version: int, node_id: str, depends_on: str) -> tuple["TaskGraphAggregate", dict]:
        self._cas(expected_graph_version); self._node(node_id); self._node(depends_on)
        edge = (node_id, depends_on)
        if edge in self.dependencies: return self, {"schema": "TASK_DEPENDENCY_DUPLICATE_V1", "node_id": node_id, "depends_on": depends_on}
        candidate = self.dependencies + (edge,)
        def reaches(start: str, target: str, seen: set[str]) -> bool:
            if start == target: return True
            if start in seen: return False
            seen.add(start)
            return any(reaches(dependency, target, seen) for owner, dependency in candidate if owner == start)
        if reaches(depends_on, node_id, set()): raise TaskProtocolError("TaskGraph dependency would create a cycle")
        updated = replace(self, version=self.version + 1, dependencies=candidate)
        return updated, {"schema": "TASK_DEPENDENCY_ADDED_V1", "node_id": node_id, "depends_on": depends_on}

    def remove_dependency(self, *, expected_graph_version: int, node_id: str, depends_on: str) -> tuple["TaskGraphAggregate", dict]:
        self._cas(expected_graph_version)
        updated = replace(self, version=self.version + 1, dependencies=tuple(edge for edge in self.dependencies if edge != (node_id, depends_on)))
        return updated, {"schema": "TASK_DEPENDENCY_REMOVED_V1", "node_id": node_id, "depends_on": depends_on}

    def block_task_node(self, *, expected_graph_version: int, node_id: str, reason_code: str) -> tuple["TaskGraphAggregate", dict]:
        self._cas(expected_graph_version); self._node(node_id)
        constraint = GatingConstraint(f"constraint-{uuid.uuid4().hex}", node_id, reason_code)
        return replace(self, version=self.version + 1, constraints=self.constraints + (constraint,)), {"schema": "TASK_GATING_CONSTRAINT_ADDED_V1", **constraint.__dict__}

    def begin_materialization(self, *, expected_graph_version: int, node_id: str, create_command_id: str) -> tuple["TaskGraphAggregate", TaskDefinitionMaterializationProcess, dict]:
        self._cas(expected_graph_version); node = self._node(node_id)
        if node.materialization_state is not MaterializationState.PENDING: raise TaskProtocolError("Node materialization already has a disposition")
        request_hash = domain_hash("CREATE_TASK", canonical_json_bytes({"graph_id": self.graph_id, "node_id": node_id, "specification_hash": node.specification_hash}))
        process = TaskDefinitionMaterializationProcess(f"materialize-{node_id}", node_id, create_command_id, request_hash)
        updated = replace(self, version=self.version + 1, materializations=self.materializations + (process,))
        return updated, process, {"schema": "TASK_NODE_MATERIALIZATION_PENDING_V1", "node_id": node_id, "create_command_id": create_command_id, "request_hash": request_hash}

    def finish_materialization(self, *, expected_graph_version: int, node_id: str, created: bool, canonical_request_hash: str) -> tuple["TaskGraphAggregate", dict]:
        self._cas(expected_graph_version); process = next((item for item in self.materializations if item.node_id == node_id), None)
        if process is None or process.state is not MaterializationState.PENDING: raise TaskProtocolError("no pending materialization")
        if canonical_request_hash != process.request_hash: raise TaskProtocolError("Task materialization canonical hash conflict")
        state = MaterializationState.MATERIALIZED if created else MaterializationState.ABORTED
        nodes = tuple(replace(node, materialization_state=state) if node.node_id == node_id else node for node in self.nodes)
        processes = tuple(replace(item, state=state) if item.node_id == node_id else item for item in self.materializations)
        updated = replace(self, version=self.version + 1, nodes=nodes, materializations=processes)
        return updated, {"schema": "TASK_NODE_MATERIALIZED_V1" if created else "TASK_NODE_MATERIALIZATION_ABORTED_V1", "node_id": node_id, "request_hash": canonical_request_hash}

    @property
    def topology_hash(self) -> str:
        return domain_hash("TASK_GRAPH_TOPOLOGY", canonical_json_bytes({"nodes": [(n.node_id, n.specification_hash, n.materialization_state.value, n.supersedes, n.superseded_by) for n in sorted(self.nodes, key=lambda n: n.node_id)], "dependencies": sorted(self.dependencies), "constraints": [c.__dict__ for c in self.constraints if c.active]}))

    @property
    def closing_blockers(self) -> tuple[str, ...]:
        pending = [f"materialization:{item.node_id}" for item in self.materializations if item.state is MaterializationState.PENDING]
        aborted_required = [f"required-aborted:{node.node_id}" for node in self.nodes if node.required_obligation and node.materialization_state is MaterializationState.ABORTED]
        return tuple(sorted(pending + aborted_required))


class TaskState(str, Enum):
    OPEN = "OPEN"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class AttemptState(str, Enum):
    CLAIMED = "CLAIMED"
    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class TaskAttempt:
    task_attempt_id: str
    claim_generation: int
    fencing_token: str
    claim_command_id: str
    holder_agent_id: str
    lease_id: str
    state: AttemptState
    lease_expires_at: str
    submitted_artifact_hash: str | None = None
    acceptance_policy_hash: str | None = None
    accepted_by: str | None = None
    progress_evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaskAggregate:
    task_id: str
    specification_hash: str
    state: TaskState = TaskState.OPEN
    stream_version: int = 1
    claim_generation: int = 0
    attempts: tuple[TaskAttempt, ...] = ()

    @property
    def active_attempt(self) -> TaskAttempt | None:
        return next((attempt for attempt in reversed(self.attempts) if attempt.state in {AttemptState.CLAIMED, AttemptState.SUBMITTED}), None)

    def claim(
        self,
        *,
        claim_command_id: str,
        lease_expires_at: str,
        holder_agent_id: str = "unspecified-task-holder",
        expected_stream_version: int | None = None,
    ) -> tuple["TaskAggregate", TaskAttempt, dict]:
        validate_identifier(claim_command_id, field="claim_command_id")
        validate_identifier(holder_agent_id, field="task_holder_agent_id")
        validate_timestamp(lease_expires_at)
        duplicate = next((attempt for attempt in self.attempts if attempt.claim_command_id == claim_command_id), None)
        if duplicate:
            return self, duplicate, {
                "schema": "TASK_CLAIM_DUPLICATE_V1",
                "task_id": self.task_id,
                "task_attempt_id": duplicate.task_attempt_id,
                "attempt_id": duplicate.task_attempt_id,
                "holder_agent_id": duplicate.holder_agent_id,
                "claim_generation": duplicate.claim_generation,
                "lease_id": duplicate.lease_id,
                "expires_at": duplicate.lease_expires_at,
                "fencing_token": duplicate.fencing_token,
            }
        if expected_stream_version is not None and expected_stream_version != self.stream_version:
            raise TaskProtocolError("Task stream expected version conflict")
        if self.state is not TaskState.OPEN or self.active_attempt: raise TaskProtocolError("Task already has an active Attempt or is terminal")
        generation = self.claim_generation + 1
        attempt_id = f"attempt-{self.task_id}-{generation}"
        lease_id = "lease-" + domain_hash(
            "TASK_LEASE_ID",
            canonical_json_bytes(
                {
                    "task_id": self.task_id,
                    "attempt_id": attempt_id,
                    "claim_generation": generation,
                    "claim_command_id": claim_command_id,
                    "holder_agent_id": holder_agent_id,
                }
            ),
        )[:40]
        token = domain_hash(
            "TASK_FENCING_TOKEN",
            canonical_json_bytes(
                {
                    "task_id": self.task_id,
                    "attempt_id": attempt_id,
                    "claim_generation": generation,
                    "claim_command_id": claim_command_id,
                    "holder_agent_id": holder_agent_id,
                    "lease_id": lease_id,
                }
            ),
        )
        attempt = TaskAttempt(
            attempt_id,
            generation,
            token,
            claim_command_id,
            holder_agent_id,
            lease_id,
            AttemptState.CLAIMED,
            lease_expires_at,
        )
        updated = replace(self, stream_version=self.stream_version + 1, claim_generation=generation, attempts=self.attempts + (attempt,))
        return updated, attempt, {
            "schema": "TASK_CLAIMED_V1",
            "task_id": self.task_id,
            **attempt.__dict__,
            "attempt_id": attempt.task_attempt_id,
            "expires_at": attempt.lease_expires_at,
            "state": attempt.state.value,
            "expected_stream_version": self.stream_version if expected_stream_version is None else expected_stream_version,
            "committed_stream_version": updated.stream_version,
        }

    def claim_or_reject(
        self,
        *,
        claim_command_id: str,
        lease_expires_at: str,
        holder_agent_id: str,
        expected_stream_version: int,
    ) -> tuple["TaskAggregate", TaskAttempt | None, dict]:
        duplicate = next((attempt for attempt in self.attempts if attempt.claim_command_id == claim_command_id), None)
        if duplicate is not None:
            task, attempt, event = self.claim(
                claim_command_id=claim_command_id,
                lease_expires_at=lease_expires_at,
                holder_agent_id=holder_agent_id,
                expected_stream_version=expected_stream_version,
            )
            return task, attempt, event
        validate_identifier(claim_command_id, field="claim_command_id")
        validate_identifier(holder_agent_id, field="task_holder_agent_id")
        validate_timestamp(lease_expires_at)
        active = self.active_attempt
        if expected_stream_version == self.stream_version and self.state is TaskState.OPEN and active is None:
            task, attempt, event = self.claim(
                claim_command_id=claim_command_id,
                lease_expires_at=lease_expires_at,
                holder_agent_id=holder_agent_id,
                expected_stream_version=expected_stream_version,
            )
            return task, attempt, event
        reason = (
            "TASK_STREAM_VERSION_CONFLICT"
            if expected_stream_version != self.stream_version
            else "ACTIVE_ATTEMPT_EXISTS"
            if active is not None
            else "TASK_TERMINAL"
        )
        rejection_id = "task-claim-rejection-" + domain_hash(
            "TASK_CLAIM_REJECTION",
            canonical_json_bytes(
                {
                    "task_id": self.task_id,
                    "claim_command_id": claim_command_id,
                    "holder_agent_id": holder_agent_id,
                    "expected_stream_version": expected_stream_version,
                    "actual_stream_version": self.stream_version,
                    "active_attempt_id": active.task_attempt_id if active else None,
                }
            ),
        )[:40]
        return self, None, {
            "schema": "TASK_CLAIM_REJECTED_V1",
            "rejection_id": rejection_id,
            "task_id": self.task_id,
            "claim_command_id": claim_command_id,
            "rejected_holder_agent_id": holder_agent_id,
            "expected_stream_version": expected_stream_version,
            "actual_stream_version": self.stream_version,
            "active_attempt_id": active.task_attempt_id if active else None,
            "active_holder_agent_id": active.holder_agent_id if active else None,
            "active_claim_generation": active.claim_generation if active else None,
            "active_lease_id": active.lease_id if active else None,
            "reason_code": reason,
            "task_stream_mutated": False,
        }

    def _attempt(self, fencing_token: str) -> TaskAttempt:
        active = self.active_attempt
        if not active or active.fencing_token != fencing_token: raise TaskProtocolError("stale or inactive Task fencing token")
        return active

    def _replace_attempt(self, attempt: TaskAttempt) -> "TaskAggregate":
        return replace(self, stream_version=self.stream_version + 1, attempts=tuple(attempt if item.task_attempt_id == attempt.task_attempt_id else item for item in self.attempts))

    def renew(
        self,
        fencing_token: str,
        *,
        lease_expires_at: str,
        progress_evidence_refs: tuple[str, ...],
    ) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token)
        validate_timestamp(lease_expires_at)
        if lease_expires_at <= attempt.lease_expires_at:
            raise TaskProtocolError("Task Lease renewal must extend its expiry")
        if not progress_evidence_refs or any(
            not isinstance(reference, str)
            or not (
                len(reference) == 64
                or (reference.startswith("cas:") and len(reference.removeprefix("cas:")) == 64)
            )
            for reference in progress_evidence_refs
        ):
            raise TaskProtocolError("Task Lease renewal requires durable progress Evidence")
        renewed = replace(
            attempt,
            lease_expires_at=lease_expires_at,
            progress_evidence_refs=tuple(sorted(set(attempt.progress_evidence_refs + progress_evidence_refs))),
        )
        updated = self._replace_attempt(renewed)
        return updated, {
            "schema": "TASK_LEASE_RENEWED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "prior_expires_at": attempt.lease_expires_at,
            "expires_at": renewed.lease_expires_at,
            "fencing_token": attempt.fencing_token,
            "progress_evidence_refs": list(progress_evidence_refs),
            "committed_stream_version": updated.stream_version,
        }

    def expire(self, fencing_token: str, *, observed_at: str | None = None) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token); updated_attempt = replace(attempt, state=AttemptState.EXPIRED)
        if observed_at is not None:
            validate_timestamp(observed_at)
            if observed_at < attempt.lease_expires_at:
                raise TaskProtocolError("Task Lease cannot expire before its deadline")
        updated = self._replace_attempt(updated_attempt)
        return updated, {
            "schema": "TASK_LEASE_EXPIRED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "expires_at": attempt.lease_expires_at,
            "observed_at": observed_at,
            "fencing_token": fencing_token,
            "fencing_token_permanently_revoked": True,
            "committed_stream_version": updated.stream_version,
        }

    def release(self, fencing_token: str) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token); updated_attempt = replace(attempt, state=AttemptState.RELEASED)
        updated = self._replace_attempt(updated_attempt)
        return updated, {
            "schema": "TASK_LEASE_RELEASED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "fencing_token": fencing_token,
            "fencing_token_permanently_revoked": True,
            "committed_stream_version": updated.stream_version,
        }

    def fail_attempt(self, fencing_token: str, reason: str) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token); updated_attempt = replace(attempt, state=AttemptState.FAILED)
        updated = self._replace_attempt(updated_attempt)
        return updated, {
            "schema": "TASK_ATTEMPT_FAILED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "fencing_token": attempt.fencing_token,
            "reason": reason,
            "task_state": self.state.value,
            "committed_stream_version": updated.stream_version,
        }

    def submit(self, fencing_token: str, artifact_hash: str) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token)
        if len(artifact_hash) != 64: raise TaskProtocolError("invalid Artifact Hash")
        submitted = replace(attempt, state=AttemptState.SUBMITTED, submitted_artifact_hash=artifact_hash)
        updated = self._replace_attempt(submitted)
        return updated, {
            "schema": "TASK_RESULT_SUBMITTED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "artifact_hash": artifact_hash,
            "fencing_token": fencing_token,
            "committed_stream_version": updated.stream_version,
        }

    def submit_or_reject(self, fencing_token: str, artifact_hash: str) -> tuple["TaskAggregate", dict]:
        if len(artifact_hash) != 64:
            raise TaskProtocolError("invalid Artifact Hash")
        active = self.active_attempt
        if active is not None and active.fencing_token == fencing_token:
            return self.submit(fencing_token, artifact_hash)
        stale = next((attempt for attempt in self.attempts if attempt.fencing_token == fencing_token), None)
        current = active or (self.attempts[-1] if self.attempts else None)
        rejection_id = "task-stale-fence-rejection-" + domain_hash(
            "TASK_STALE_FENCE_REJECTION",
            canonical_json_bytes(
                {
                    "task_id": self.task_id,
                    "stale_attempt_id": stale.task_attempt_id if stale else None,
                    "stale_fencing_token": fencing_token,
                    "current_attempt_id": current.task_attempt_id if current else None,
                    "artifact_hash": artifact_hash,
                    "stream_version": self.stream_version,
                }
            ),
        )[:40]
        return self, {
            "schema": "TASK_STALE_FENCE_REJECTED_V1",
            "rejection_id": rejection_id,
            "task_id": self.task_id,
            "stale_attempt_id": stale.task_attempt_id if stale else None,
            "stale_holder_agent_id": stale.holder_agent_id if stale else None,
            "stale_claim_generation": stale.claim_generation if stale else None,
            "stale_lease_id": stale.lease_id if stale else None,
            "stale_fencing_token": fencing_token,
            "current_attempt_id": current.task_attempt_id if current else None,
            "current_holder_agent_id": current.holder_agent_id if current else None,
            "current_claim_generation": current.claim_generation if current else None,
            "current_lease_id": current.lease_id if current else None,
            "current_fencing_token": current.fencing_token if current else None,
            "artifact_hash": artifact_hash,
            "reason_code": "STALE_OR_INACTIVE_FENCING_TOKEN",
            "business_state_committed": False,
            "task_stream_mutated": False,
        }

    def reassignment_decided(
        self,
        *,
        prior_decision_id: str,
        new_decision_id: str,
        new_holder_agent_id: str,
        reason_code: str,
    ) -> dict:
        validate_identifier(prior_decision_id, field="prior_decision_id")
        validate_identifier(new_decision_id, field="new_decision_id")
        validate_identifier(new_holder_agent_id, field="new_holder_agent_id")
        if prior_decision_id == new_decision_id:
            raise TaskProtocolError("Task reassignment requires a fresh Scheduling Decision")
        prior = self.attempts[-1] if self.attempts else None
        if prior is None or prior.state not in {AttemptState.EXPIRED, AttemptState.RELEASED, AttemptState.FAILED}:
            raise TaskProtocolError("Task reassignment requires an inactive prior Attempt")
        if prior.holder_agent_id == new_holder_agent_id:
            raise TaskProtocolError("Task reassignment requires a different owner")
        return {
            "schema": "AGENT_REASSIGNMENT_DECIDED_V1",
            "task_id": self.task_id,
            "prior_decision_id": prior_decision_id,
            "new_decision_id": new_decision_id,
            "prior_agent_id": prior.holder_agent_id,
            "new_agent_id": new_holder_agent_id,
            "prior_attempt_id": prior.task_attempt_id,
            "prior_claim_generation": prior.claim_generation,
            "prior_lease_id": prior.lease_id,
            "reason_code": reason_code,
            "candidate_set_changed": True,
        }

    def accept(
        self,
        fencing_token: str,
        *,
        artifact_hash: str,
        policy_hash: str,
        accepted_by: str = "result-admission-verifier",
        acceptance_evidence_refs: tuple[str, ...] = (),
    ) -> tuple["TaskAggregate", dict]:
        attempt = self._attempt(fencing_token)
        validate_identifier(accepted_by, field="task_result_acceptor")
        if attempt.state is not AttemptState.SUBMITTED or attempt.submitted_artifact_hash != artifact_hash or len(policy_hash) != 64:
            raise TaskProtocolError("Acceptance must bind exact submitted Artifact Hash and Policy")
        accepted = replace(
            attempt,
            state=AttemptState.ACCEPTED,
            acceptance_policy_hash=policy_hash,
            accepted_by=accepted_by,
        )
        updated = self._replace_attempt(accepted)
        updated = replace(updated, state=TaskState.COMPLETED)
        return updated, {
            "schema": "TASK_RESULT_ACCEPTED_V1",
            "task_id": self.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "attempt_id": attempt.task_attempt_id,
            "holder_agent_id": attempt.holder_agent_id,
            "claim_generation": attempt.claim_generation,
            "lease_id": attempt.lease_id,
            "artifact_hash": artifact_hash,
            "fencing_token": fencing_token,
            "policy_hash": policy_hash,
            "accepted_by": accepted_by,
            "acceptance_evidence_refs": list(acceptance_evidence_refs),
            "agent_self_declared_complete": False,
            "task_state": updated.state.value,
            "committed_stream_version": updated.stream_version,
        }
