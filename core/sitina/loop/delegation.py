"""Native parent/child delegation and execution primitives.

This module deliberately does not open a Backend or a Journal for a child.
The parent coordinator remains the only durable authority. Ready independent
work gets its own worker; resource ownership and parent controls fence effects.
The legacy readonly capability remains available for source-only delegation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


DELEGATION_CONTRACT_VERSION = "sitina-delegation-v1"
CHILD_RUNTIME_SCHEMA = "SITINA_LOOP_CHILD_RUNTIME_CONTRACT_V1"
CHILD_RUNTIME_RESULT_SCHEMA = "SITINA_LOOP_CHILD_RUNTIME_RESULT_V1"
CHILD_SOURCE_SCHEMA = "SITINA_LOOP_CHILD_SOURCE_V1"


class ReadonlyChildError(RuntimeError):
    """Base error for a child capability or lifecycle violation."""


class ReadonlySourceDenied(ReadonlyChildError):
    pass


class ChildLifecycleError(ReadonlyChildError):
    pass


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def child_operation_navigation(task: Any, child: Mapping[str, Any], read_document: Callable) -> dict[str, Any]:
    """Bounded locators from the native ledger, never child-claimed evidence credit."""
    rows = []
    owner = child.get("delegation_id")
    if not isinstance(owner, str) or not owner:
        return {"source_navigation_only": True, "operation_count": 0, "operations": []}
    for operation in task.operations.values():
        if (operation.execution_owner != owner or not operation.result_ref
                or operation.bound_goal_version != task.goal_version):
            continue
        document = read_document(str(operation.result_ref))
        result = document.get("result") if isinstance(document, Mapping) else None
        if not isinstance(result, Mapping) or not isinstance(result.get("tool"), str):
            continue
        tool = result["tool"]
        # Skip the internal pin/discovery records; the public load has its own value.
        value = result.get("value")
        if tool == "sitina_task_skills":
            arguments = value.get("arguments") if isinstance(value, Mapping) else None
            if not isinstance(arguments, Mapping) or arguments.get("action") != "load":
                continue
        elif tool not in {"sitina_write_file", "sitina_edit_file", "sitina_delete_file",
                          "sitina_rename_file", "sitina_exec", "sitina_shell"}:
            continue
        row = {"operation_id": operation.operation_id, "tool": tool,
               "source_ref": str(operation.result_ref),
               "effect_status": operation.effect_status.value,
               "unknown_effect": operation.unknown_effect,
               "resources": list(operation.resources)}
        if (operation.effect_status.value == "SUCCEEDED" and not operation.unknown_effect
                and result.get("status") == "ok" and isinstance(value, Mapping)):
            skill = value.get("skill")
            if tool == "sitina_task_skills" and isinstance(skill, Mapping):
                row["skill_identity"] = {key: skill[key] for key in (
                    "qualified_name", "candidate_id", "snapshot_id", "version", "body_sha256"
                ) if key in skill}
            if isinstance(value.get("after_hash"), str):
                row["after_hash"] = value["after_hash"]
        rows.append(row)
    # The full operation IDs/report remain available through the original result_ref.
    return {"source_navigation_only": True, "operation_count": len(rows),
            "omitted_operation_count": max(0, len(rows) - 12), "operations": rows[-12:]}


def child_identity(parent_task_id: str, problem_id: str, generation: int, request_fingerprint: str) -> str:
    if not all(isinstance(value, str) and value.strip() for value in (parent_task_id, problem_id, request_fingerprint)):
        raise ValueError("child identity inputs are required")
    if type(generation) is not int or generation < 1:
        raise ValueError("child generation must be positive")
    return "delegation:" + canonical_digest({
        "contract": DELEGATION_CONTRACT_VERSION,
        "parent_task_id": parent_task_id,
        "problem_id": problem_id,
        "generation": generation,
        "request_fingerprint": request_fingerprint,
    })


@dataclass(frozen=True)
class ChildDelegationProjection:
    delegation_id: str
    child_task_id: str
    parent_task_id: str
    problem_id: str
    parent_attempt_id: str | None
    objective: str
    generation: int
    status: str
    required: bool
    unknown_effect: bool
    applicability: str
    parent_binding: Mapping[str, Any]
    source_manifest: tuple[Mapping[str, Any], ...]
    result_ref: str | None = None
    settlement_ref: str | None = None
    evidence_fingerprint: str | None = None
    prior_evidence_fingerprint: str | None = None
    physical_send_state: str = "NOT_STARTED"
    continuation_pending: bool = False
    prior_delegation_id: str | None = None
    inherited_evidence_refs: tuple[str, ...] = ()
    inherited_attempt_ids: tuple[str, ...] = ()
    inherited_review_issue_ids: tuple[str, ...] = ()
    execution_mode: str = "readonly"
    resources: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ("read",)
    completion_condition: str = ""
    checkpoint_ref: str | None = None
    change_reason: str = ""
    required_tools: tuple[str, ...] = ()
    read_resources: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CHILD_RUNTIME_SCHEMA,
            "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
            "delegation_id": self.delegation_id,
            "child_task_id": self.child_task_id,
            "parent_task_id": self.parent_task_id,
            "problem_id": self.problem_id,
            "parent_attempt_id": self.parent_attempt_id,
            "objective": self.objective,
            "generation": self.generation,
            "status": self.status,
            "required": self.required,
            "unknown_effect": self.unknown_effect,
            "applicability": self.applicability,
            "parent_binding": dict(self.parent_binding),
            "source_manifest": [dict(item) for item in self.source_manifest],
            "result_ref": self.result_ref,
            "settlement_ref": self.settlement_ref,
            "evidence_fingerprint": self.evidence_fingerprint,
            "prior_evidence_fingerprint": self.prior_evidence_fingerprint,
            "physical_send_state": self.physical_send_state,
            "continuation_pending": self.continuation_pending,
            "prior_delegation_id": self.prior_delegation_id,
            "inherited_evidence_refs": list(self.inherited_evidence_refs),
            "inherited_attempt_ids": list(self.inherited_attempt_ids),
            "inherited_review_issue_ids": list(self.inherited_review_issue_ids),
            "execution_mode": self.execution_mode,
            "resources": list(self.resources),
            "read_resources": list(self.read_resources),
            "dependencies": list(self.dependencies),
            "permissions": list(self.permissions),
            "completion_condition": self.completion_condition,
            "checkpoint_ref": self.checkpoint_ref,
            "change_reason": self.change_reason,
            "required_tools": list(self.required_tools),
        }


def projection_from_mapping(value: Mapping[str, Any]) -> ChildDelegationProjection:
    return ChildDelegationProjection(
        delegation_id=str(value["delegation_id"]),
        child_task_id=str(value["child_task_id"]),
        parent_task_id=str(value["parent_task_id"]),
        problem_id=str(value["problem_id"]),
        parent_attempt_id=(str(value["parent_attempt_id"]) if value.get("parent_attempt_id") else None),
        objective=str(value.get("objective") or ""),
        generation=int(value["generation"]),
        status=str(value["status"]),
        required=bool(value["required"]),
        unknown_effect=bool(value.get("unknown_effect", False)),
        applicability=str(value.get("applicability") or "CURRENT_PARENT_INPUT"),
        parent_binding=dict(value.get("parent_binding") or {}),
        source_manifest=tuple(dict(item) for item in value.get("source_manifest", ())),
        result_ref=(str(value["result_ref"]) if value.get("result_ref") else None),
        settlement_ref=(str(value["settlement_ref"]) if value.get("settlement_ref") else None),
        evidence_fingerprint=(str(value["evidence_fingerprint"]) if value.get("evidence_fingerprint") else None),
        prior_evidence_fingerprint=(
            str(value["prior_evidence_fingerprint"])
            if value.get("prior_evidence_fingerprint") else None
        ),
        physical_send_state=str(value.get("physical_send_state") or "NOT_STARTED"),
        continuation_pending=bool(value.get("continuation_pending", False)),
        prior_delegation_id=(str(value["prior_delegation_id"]) if value.get("prior_delegation_id") else None),
        inherited_evidence_refs=tuple(str(item) for item in value.get("inherited_evidence_refs", ())),
        inherited_attempt_ids=tuple(str(item) for item in value.get("inherited_attempt_ids", ())),
        inherited_review_issue_ids=tuple(str(item) for item in value.get("inherited_review_issue_ids", ())),
        execution_mode=str(value.get("execution_mode") or "readonly"),
        resources=tuple(str(item) for item in value.get("resources", ())),
        read_resources=tuple(str(item) for item in value.get("read_resources", ())),
        dependencies=tuple(str(item) for item in value.get("dependencies", ())),
        permissions=tuple(str(item) for item in value.get("permissions", ("read",))),
        completion_condition=str(value.get("completion_condition") or ""),
        checkpoint_ref=value.get("checkpoint_ref"),
        change_reason=str(value.get("change_reason") or ""),
        required_tools=tuple(str(item) for item in value.get("required_tools", ())),
    )


class ReadonlyChildCapability:
    """Actual dispatch guard for one immutable source manifest.

    No Backend, ToolCatalog, plugin manager or shell executor is exposed to a
    child.  Every read checks the exact manifest entry again, including hash.
    """

    ALLOWED_ACTIONS = frozenset({"READ", "ANALYZE", "REPORT"})

    def __init__(
        self,
        sources: Sequence[Mapping[str, Any]],
        *,
        parent_binding: Mapping[str, Any],
        binding_guard: Callable[[], Mapping[str, Any]] | None = None,
        objective: str = "",
    ):
        self._sources = {str(item["source_id"]): dict(item) for item in sources}
        self.parent_binding = dict(parent_binding)
        self.objective = objective
        self._binding_guard = binding_guard
        self._lock = threading.RLock()
        self._observations: list[dict[str, Any]] = []

    def list_sources(self) -> tuple[dict[str, Any], ...]:
        return tuple({key: value for key, value in item.items() if key not in {"content_b64", "content_json"}}
                     for item in self._sources.values())

    def _entry(self, source_id: str) -> dict[str, Any]:
        if not isinstance(source_id, str) or source_id not in self._sources:
            raise ReadonlySourceDenied("source is not declared by the child manifest")
        return self._sources[source_id]

    def _check_current_binding(self) -> None:
        if self._binding_guard is None:
            return
        current = self._binding_guard()
        if not isinstance(current, Mapping):
            raise ChildLifecycleError("parent binding guard returned an invalid value")
        # The admission event itself advances task_revision.  Revision is an
        # event-stream frontier, not a semantic parent input change; all
        # other binding fields remain immutable during this child execution.
        for key in ("task_id", "run_instance_id", "execution_epoch", "goal_version", "acceptance_version", "received_input_seq", "handled_input_seq", "artifact_ref", "control_intent"):
            if current.get(key) != self.parent_binding.get(key):
                raise ChildLifecycleError("parent control or input binding changed during child dispatch")

    def check_binding(self) -> None:
        """Recheck the parent barrier before a model/tool dispatch."""

        self._check_current_binding()

    def read_source(self, source_id: str, *, offset: int = 0, max_bytes: int | None = None) -> Any:
        self._check_current_binding()
        if type(offset) is not int or offset < 0:
            raise ReadonlySourceDenied("source offset is invalid")
        if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
            raise ReadonlySourceDenied("source byte bound is invalid")
        entry = self._entry(source_id)
        kind = str(entry.get("kind") or "")
        if kind not in {"history", "file"}:
            raise ReadonlySourceDenied("source kind is not supported by T5A")
        if kind == "file":
            raw = base64.b64decode(str(entry.get("content_b64") or ""), validate=True)
            if hashlib.sha256(raw).hexdigest() != entry.get("content_hash"):
                raise ReadonlySourceDenied("immutable file source hash changed")
            view = raw[offset:] if max_bytes is None else raw[offset:offset + max_bytes]
            value: Any
            try:
                value = view.decode("utf-8")
            except UnicodeDecodeError:
                value = {"encoding": "base64", "data": base64.b64encode(view).decode("ascii")}
        else:
            raw_json = entry.get("content_json")
            raw = json.dumps(raw_json, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(raw).hexdigest() != entry.get("content_hash"):
                raise ReadonlySourceDenied("history source hash changed")
            sliced = raw[offset:] if max_bytes is None else raw[offset:offset + max_bytes]
            try:
                value = json.loads(sliced.decode("utf-8")) if offset == 0 and max_bytes is None else sliced.decode("utf-8", errors="replace")
            except json.JSONDecodeError as error:
                raise ReadonlySourceDenied("history source is not a complete JSON page") from error
        observation = {
            "source_id": source_id,
            "kind": kind,
            "offset": offset,
            "returned_bytes": len(view if kind == "file" else sliced),
            "content_hash": str(entry.get("content_hash")),
        }
        with self._lock:
            self._observations.append(observation)
        return value

    def report(self, *, summary: str, evidence_source_ids: Sequence[str] = ()) -> dict[str, Any]:
        self._check_current_binding()
        if not isinstance(summary, str) or not summary.strip():
            raise ReadonlyChildError("child report summary is required")
        normalized_ids = list(dict.fromkeys(str(item) for item in evidence_source_ids))
        if not normalized_ids:
            # An empty citation cannot be represented as a successful
            # investigation.  Return an explicit durable rejection so the
            # slot may settle without laundering source-less model text.
            return {
                "schema": CHILD_RUNTIME_RESULT_SCHEMA,
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "summary": str(summary),
                "status": "REJECTED",
                "rejection_reason": "successful readonly results require an observed source",
                "evidence_source_ids": [],
                "approves_parent": False,
                "observations": [],
                "parent_binding": dict(self.parent_binding),
            }
        for source_id in normalized_ids:
            self._entry(str(source_id))
        with self._lock:
            observations = tuple(dict(item) for item in self._observations)
        return {
            "schema": CHILD_RUNTIME_RESULT_SCHEMA,
            "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
            "summary": summary,
            "evidence_source_ids": normalized_ids,
            "observations": list(observations),
            "status": "SUCCEEDED",
            "approves_parent": False,
            "parent_binding": dict(self.parent_binding),
        }

    @property
    def observations(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(item) for item in self._observations)

    def deny(self, operation: str) -> None:
        raise ReadonlySourceDenied(f"child operation is not allowed: {operation}")


class ReadonlyChildExecutor:
    """Create a worker for ready work; the parent owns durable admission.

    The historical class name and optional argument remain import compatible.
    ``max_workers`` is no longer a concurrency limit. Dependencies, resource
    ownership and actual host/Provider failures determine whether work waits.
    """

    def __init__(self, *, max_workers: int | None = None):
        if max_workers is not None and (type(max_workers) is not int or max_workers < 1):
            raise ValueError("legacy worker hint must be positive when supplied")
        self._lock = threading.RLock()
        self._futures: set[Future[Any]] = set()
        self._threads: set[threading.Thread] = set()
        self._closed = False

    def submit(self, work: Callable[[], Any]) -> Future[Any]:
        if not callable(work):
            raise TypeError("child executor requires a callable")
        with self._lock:
            if self._closed:
                raise ChildLifecycleError("child executor is closed")
            future: Future[Any] = Future()
            self._futures.add(future)

            def run() -> None:
                try:
                    if future.set_running_or_notify_cancel():
                        try:
                            future.set_result(work())
                        except BaseException as error:
                            future.set_exception(error)
                finally:
                    with self._lock:
                        self._futures.discard(future)
                        self._threads.discard(threading.current_thread())

            thread = threading.Thread(target=run, name="sitina-child", daemon=False)
            self._threads.add(thread)
            try:
                thread.start()
            except BaseException:
                self._threads.discard(thread)
                self._futures.discard(future)
                raise
            return future

    def active(self) -> int:
        with self._lock:
            return sum(not future.done() for future in self._futures)

    def close(self, *, wait: bool = True) -> None:
        with self._lock:
            self._closed = True
            threads = tuple(self._threads)
        if wait:
            for thread in threads:
                if thread is not threading.current_thread():
                    thread.join()
