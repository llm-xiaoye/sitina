from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, load_json_yaml, new_id, sha256_text, stable_json


RetryAction = Literal[
    "retry_same_agent",
    "return_to_coder",
    "return_to_planner",
    "fallback_provider",
    "ask_approval",
    "degrade",
    "blocked",
    "warning",
]
Escalation = Literal["ask_user", "blocked", "needs_approval", "needs_replan", "needs_manual_review", "warning_only"]
FailureType = Literal[
    "tester_failed",
    "reviewer_needs_changes",
    "security_reviewer_blocked",
    "multi_reviewer_needs_changes",
    "patch_hash_mismatch",
    "approval_expired",
    "lease_conflict",
    "handoff_invalid",
    "policy_invalid",
    "provider_failed",
    "mcp_blocked",
    "sensitive_path_blocked",
    "proposal_blocked",
    "arbitration_blocked",
    "memory_failed",
]


class RetryRule(StrictModel):
    action: RetryAction
    max_attempts: int
    escalation: Escalation
    rerun_gates: list[str] = Field(default_factory=list)


class RetryDecision(StrictModel):
    schema_version: str = "1.0"
    failure_type: str
    status: Literal["retry", "blocked", "warning", "fallback", "needs_approval"]
    action: RetryAction
    attempt: int
    max_attempts: int
    rerun_gates: list[str]
    escalation: Escalation
    reason: str


class TypedFailure(StrictModel):
    schema_version: str = "1.0"
    failure_id: str
    run_id: str
    task_id: str
    failure_type: str
    source_node_id: str
    severity: Literal["warning", "minor", "major", "critical"]
    retryable: bool
    reason: str
    artifact_refs: list[str] = Field(default_factory=list)
    scope_hash: str | None = None
    created_at: str


class RetryPolicy:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "config" / "retry_policy.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}

    @property
    def rules(self) -> dict[str, RetryRule]:
        raw = self.config.get("retry_policy", {}).get("rules", {})
        return {key: RetryRule.model_validate(value) for key, value in raw.items()}

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["retry_policy config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("retry_policy schema_version major must be 1")
        policy = self.config.get("retry_policy", {})
        if int(policy.get("default_max_attempts", -1)) < 0:
            errors.append("retry_policy default_max_attempts must be non-negative")
        if int(policy.get("max_total_agent_steps", 0)) <= 0:
            errors.append("retry_policy max_total_agent_steps must be positive")
        try:
            rules = self.rules
        except Exception as exc:  # noqa: BLE001
            return [f"retry_policy invalid: {exc}"], warnings
        for required in ("tester_failed", "reviewer_needs_changes", "security_reviewer_blocked", "multi_reviewer_needs_changes", "patch_hash_mismatch", "approval_expired", "lease_conflict", "handoff_invalid", "policy_invalid", "provider_failed", "mcp_blocked", "sensitive_path_blocked", "proposal_blocked", "arbitration_blocked", "memory_failed"):
            if required not in rules:
                errors.append(f"retry_policy missing rule: {required}")
        for name, rule in rules.items():
            if rule.max_attempts < 0:
                errors.append(f"retry rule {name} max_attempts must be non-negative")
            if name == "memory_failed" and rule.action != "warning":
                errors.append("memory_failed retry rule must be warning only")
            if rule.action in {"return_to_coder", "return_to_planner"} and "reviewer" not in rule.rerun_gates:
                errors.append(f"retry rule {name} must rerun reviewer gate")
        return errors, warnings

    def decide(self, failure_type: str, attempt: int, *, loop_detected: bool = False) -> RetryDecision:
        if loop_detected:
            rule = self.rules.get("loop_detected", RetryRule(action="blocked", max_attempts=0, escalation="blocked"))
            return RetryDecision(
                failure_type="loop_detected",
                status="blocked",
                action=rule.action,
                attempt=attempt,
                max_attempts=rule.max_attempts,
                rerun_gates=rule.rerun_gates,
                escalation=rule.escalation,
                reason="loop detection blocked retry",
            )
        rule = self.rules.get(failure_type)
        if not rule:
            rule = RetryRule(action="blocked", max_attempts=0, escalation="blocked")
        if failure_type == "memory_failed":
            status: Literal["retry", "blocked", "warning", "fallback", "needs_approval"] = "warning"
        elif rule.action == "fallback_provider" and attempt <= rule.max_attempts:
            status = "fallback"
        elif rule.action in {"ask_approval"} and attempt <= rule.max_attempts:
            status = "needs_approval"
        elif attempt > rule.max_attempts or rule.action == "blocked":
            status = "blocked"
        else:
            status = "retry"
        return RetryDecision(
            failure_type=failure_type,
            status=status,
            action=rule.action,
            attempt=attempt,
            max_attempts=rule.max_attempts,
            rerun_gates=rule.rerun_gates,
            escalation=rule.escalation,
            reason=self._reason(failure_type, status, rule, attempt),
        )

    def record_decision(self, run_id: str, decision: RetryDecision, *, task_id: str = "main", task_type: str = "code_change") -> RetryDecision:
        payload = decision.model_dump()
        event_type = "retry_scheduled" if decision.status in {"retry", "fallback", "needs_approval"} else "retry_exhausted"
        if decision.status == "warning":
            event_type = "retry_exhausted"
        RunLedger(self.home, self.store).record(
            event_type,
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            status="warning" if decision.status == "warning" else ("blocked" if decision.status == "blocked" else "ok"),
            reason=decision.reason,
            payload=payload,
        )
        self.store.record_audit(
            "retry_decision",
            payload,
            run_id=run_id,
            trace_id=f"{run_id}:retry:{decision.failure_type}",
            exit_status=decision.status,
            output_hash=sha256_text(stable_json(payload)),
        )
        return decision

    def record_failure(
        self,
        *,
        run_id: str,
        task_id: str,
        failure_type: str,
        source_node_id: str,
        severity: Literal["warning", "minor", "major", "critical"],
        retryable: bool,
        reason: str,
        artifact_refs: list[str] | None = None,
        scope_hash: str | None = None,
        task_type: str = "code_change",
    ) -> TypedFailure:
        failure = TypedFailure(
            failure_id="failure_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            failure_type=failure_type,
            source_node_id=source_node_id,
            severity=severity,
            retryable=retryable,
            reason=reason,
            artifact_refs=artifact_refs or [],
            scope_hash=scope_hash,
            created_at=iso_now(),
        )
        RunLedger(self.home, self.store).record(
            "typed_failure_recorded",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            status="warning" if severity in {"warning", "minor"} else "blocked",
            reason=reason,
            artifacts=artifact_refs or [],
            payload=failure.model_dump(),
        )
        self.store.record_audit("typed_failure_recorded", failure.model_dump(), run_id=run_id, trace_id=f"{run_id}:failure:{failure.failure_id}", exit_status=severity)
        return failure

    def materialize_rework_edge(
        self,
        graph,
        decision: RetryDecision,
        *,
        from_task_id: str,
        approved_scope_hash: str | None = None,
        failure_id: str | None = None,
    ):
        from sitina.orchestrator.task_graph import TaskGraphRuntime

        if decision.status == "blocked":
            self.record_decision(graph.run_id, decision, task_id=from_task_id, task_type=graph.task_type)
            from sitina.orchestrator.task_graph import TaskGraphRuntime

            TaskGraphRuntime(self.home, self.store).record_rework_exhausted(
                graph,
                source_node_id=from_task_id,
                failure_type=decision.failure_type,
                attempt=decision.attempt,
                max_attempts=decision.max_attempts,
                reason=decision.reason,
                failure_id=failure_id,
            )
            return graph
        if decision.failure_type in {"tester_failed", "missing_evidence", "insufficient_test_plan"}:
            to_task_id = "coder"
        elif decision.failure_type in {"reviewer_needs_changes", "multi_reviewer_needs_changes"}:
            to_task_id = "coder" if decision.action == "return_to_coder" else "planner"
        elif decision.status == "warning":
            self.record_decision(graph.run_id, decision, task_id=from_task_id, task_type=graph.task_type)
            return graph
        else:
            to_task_id = from_task_id
        self.record_decision(graph.run_id, decision, task_id=from_task_id, task_type=graph.task_type)
        runtime = TaskGraphRuntime(self.home, self.store)
        if to_task_id in {"coder", "planner"}:
            return runtime.add_rework_chain(
                graph,
                source_node_id=from_task_id,
                reason=decision.reason,
                attempt=decision.attempt,
                max_attempts=decision.max_attempts,
                approved_scope_hash=approved_scope_hash,
                high_risk=graph.task_type == "high_risk_code_change",
                multi_reviewer=decision.failure_type == "multi_reviewer_needs_changes" or "reviewer" in from_task_id,
                planner_rework=to_task_id == "planner",
                failure_id=failure_id,
                failure_type=decision.failure_type,
                source_evaluation_id=failure_id,
            )
        return runtime.add_rework_edge(graph, from_task_id=from_task_id, to_task_id=to_task_id, reason=decision.reason, retry_attempt=decision.attempt, approved_scope_hash=approved_scope_hash)

    def detect_loop(self, history: list[dict[str, Any]]) -> bool:
        seen: set[str] = set()
        for item in history:
            key = sha256_text(stable_json({"agent": item.get("agent"), "patch_hash": item.get("patch_hash"), "decision": item.get("decision")}))
            if key in seen:
                return True
            seen.add(key)
        return False

    def _reason(self, failure_type: str, status: str, rule: RetryRule, attempt: int) -> str:
        if status == "blocked":
            return f"{failure_type} blocked after attempt {attempt}; max_attempts={rule.max_attempts}"
        if status == "warning":
            return f"{failure_type} recorded as warning only"
        if status == "fallback":
            return f"{failure_type} will try fallback provider"
        if status == "needs_approval":
            return f"{failure_type} requires explicit approval"
        return f"{failure_type} scheduled action={rule.action}; attempt={attempt}/{rule.max_attempts}"
