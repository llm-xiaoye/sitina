"""Hard security boundaries for untrusted tool and MCP invocations."""

from __future__ import annotations

import concurrent.futures
import fnmatch
import hashlib
import json
import re
import threading
import time
import unicodedata
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from sitina.journal.model import canonical_json_bytes
from sitina.reliability import (
    FailureEnvelope,
    ReliabilityEventLog,
    RetryScheduler,
)
from sitina.security.redaction import redact_boundary_value


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": 4}


def normalize_tool_name(server: str, tool: str) -> str:
    def normalize(value: str) -> str:
        value = unicodedata.normalize("NFKC", value).strip().casefold().replace("-", "_")
        if not value or not re.fullmatch(r"[a-z0-9_.:]+", value):
            raise ValueError("tool identity contains unsupported characters")
        return value

    return f"{normalize(server)}.{normalize(tool)}"


def summarize_tool_arguments(server: str, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    boundary = redact_boundary_value(dict(arguments), boundary="log")
    encoded = canonical_json_bytes(boundary.value)
    return {
        "schema": "SITINA_TOOL_ARGUMENT_SUMMARY_V1",
        "normalized_tool_name": normalize_tool_name(server, tool),
        "argument_keys": sorted(str(key) for key in arguments),
        "argument_hash": hashlib.sha256(encoded).hexdigest(),
        "redacted_paths": list(boundary.redacted_paths),
        "argument_bytes_after_redaction": len(encoded),
    }


def summarize_tool_result(
    server: str,
    tool: str,
    *,
    status: str,
    value: Any,
    duration_ms: int,
    permission_decision: str,
) -> dict[str, Any]:
    boundary = redact_boundary_value(value, boundary="log")
    try:
        encoded = canonical_json_bytes(boundary.value)
    except (TypeError, ValueError):
        encoded = repr(boundary.value).encode("utf-8", errors="replace")
    error = None
    if status != "ok":
        error_type = str(boundary.value).partition(":")[0][:120] or "ToolError"
        error = {
            "error_type": error_type,
            "diagnostic_hash": hashlib.sha256(encoded).hexdigest(),
            "redacted_paths": list(boundary.redacted_paths),
        }
    return {
        "schema": "SITINA_TOOL_RESULT_SUMMARY_V1",
        "normalized_tool_name": normalize_tool_name(server, tool),
        "status": status,
        "permission_decision": permission_decision,
        "duration_ms": max(0, duration_ms),
        "result_ref": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "result_bytes_after_redaction": len(encoded),
        "result_redacted_paths": list(boundary.redacted_paths),
        "error": error,
    }


@dataclass(frozen=True)
class ToolPermissionRule:
    rule_id: str
    principals: tuple[str, ...]
    server_pattern: str
    tool_pattern: str
    actions: tuple[str, ...]
    effect: str
    resource_patterns: tuple[str, ...] = ("*",)
    resource_roots: tuple[Path, ...] = ()
    allowed_arguments: frozenset[str] = frozenset()
    max_risk: str = "critical"

    def __post_init__(self) -> None:
        if self.effect not in {"allow", "deny", "approval"}:
            raise ValueError("permission rule effect is invalid")
        if self.max_risk not in RISK_ORDER:
            raise ValueError("permission rule risk ceiling is invalid")
        if not self.rule_id or not self.principals or not self.actions:
            raise ValueError("permission rule identity, principals and actions are required")


@dataclass(frozen=True)
class ToolAccessRequest:
    principal: str
    server: str
    tool: str
    action: str
    resource: str
    arguments: Mapping[str, Any]
    risk: str
    approval_granted: bool = False
    argument_aliases: Mapping[str, str] | None = None


@dataclass(frozen=True)
class ToolAccessDecision:
    disposition: str
    rule_id: str | None
    normalized_tool_name: str
    canonical_argument_keys: tuple[str, ...]
    reason: str

    @property
    def allowed(self) -> bool:
        return self.disposition == "allow"

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_TOOL_ACCESS_DECISION_V1",
            "disposition": self.disposition,
            "rule_id": self.rule_id,
            "normalized_tool_name": self.normalized_tool_name,
            "canonical_argument_keys": list(self.canonical_argument_keys),
            "reason": self.reason,
        }


class ToolAccessPolicy:
    """Default-deny server/tool/action/resource/argument/risk policy."""

    def __init__(
        self,
        rules: Sequence[ToolPermissionRule],
        *,
        inheritance: Mapping[str, Sequence[str]] | None = None,
        events: ReliabilityEventLog | None = None,
    ):
        self.rules = tuple(rules)
        self.inheritance = {key: tuple(value) for key, value in (inheritance or {}).items()}
        self.events = events

    def _principals(self, principal: str) -> set[str]:
        effective: set[str] = set()
        visiting: set[str] = set()

        def visit(value: str) -> None:
            if value in visiting:
                raise ValueError("permission inheritance cycle")
            if value in effective:
                return
            visiting.add(value)
            effective.add(value)
            for parent in self.inheritance.get(value, ()):
                visit(parent)
            visiting.remove(value)

        visit(principal)
        return effective

    @staticmethod
    def _canonical_arguments(request: ToolAccessRequest) -> tuple[dict[str, Any], str | None]:
        aliases = {
            unicodedata.normalize("NFKC", str(key)).casefold(): unicodedata.normalize(
                "NFKC", str(value)
            ).casefold()
            for key, value in (request.argument_aliases or {}).items()
        }
        canonical: dict[str, Any] = {}
        for raw_key, value in request.arguments.items():
            key = unicodedata.normalize("NFKC", str(raw_key)).casefold()
            target = aliases.get(key, key)
            if target in canonical and canonical[target] != value:
                return {}, f"argument alias conflicts with canonical field: {target}"
            canonical[target] = value
        return canonical, None

    @staticmethod
    def _resource_matches(rule: ToolPermissionRule, resource: str) -> bool:
        decoded = unicodedata.normalize("NFKC", resource)
        for _attempt in range(3):
            next_value = urllib.parse.unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        portable_path = decoded.replace("\\", "/")
        raw_path = Path(portable_path).expanduser()
        path_like = decoded.startswith(("/", ".", "~")) or "/" in decoded or "\\" in decoded
        if path_like and ".." in raw_path.parts:
            return False
        if rule.resource_roots:
            if not path_like:
                return False
            resolved = raw_path.resolve(strict=False)
            if not any(
                resolved == root.resolve(strict=False)
                or root.resolve(strict=False) in resolved.parents
                for root in rule.resource_roots
            ):
                return False
        return any(fnmatch.fnmatchcase(decoded, pattern) for pattern in rule.resource_patterns)

    def decide(self, request: ToolAccessRequest) -> ToolAccessDecision:
        try:
            identity = normalize_tool_name(request.server, request.tool)
            principals = self._principals(request.principal)
        except ValueError as error:
            return self._record(ToolAccessDecision("deny", None, "invalid.invalid", (), str(error)))
        canonical, alias_error = self._canonical_arguments(request)
        keys = tuple(sorted(canonical))
        if alias_error:
            return self._record(ToolAccessDecision("deny", None, identity, keys, alias_error))
        if request.risk not in RISK_ORDER or request.risk == "unknown":
            return self._record(ToolAccessDecision("deny", None, identity, keys, "unknown risk fails closed"))
        matches: list[ToolPermissionRule] = []
        for rule in self.rules:
            if not principals.intersection(rule.principals):
                continue
            if not fnmatch.fnmatchcase(request.server.casefold(), rule.server_pattern.casefold()):
                continue
            if not fnmatch.fnmatchcase(request.tool.casefold(), rule.tool_pattern.casefold()):
                continue
            if request.action not in rule.actions and "*" not in rule.actions:
                continue
            if rule.effect != "deny" and RISK_ORDER[request.risk] > RISK_ORDER[rule.max_risk]:
                continue
            if rule.effect != "deny" and not set(canonical).issubset(rule.allowed_arguments):
                continue
            if not self._resource_matches(rule, request.resource):
                continue
            matches.append(rule)
        denied = next((rule for rule in matches if rule.effect == "deny"), None)
        if denied is not None:
            return self._record(ToolAccessDecision("deny", denied.rule_id, identity, keys, "explicit deny rule matched"))
        selected = next((rule for rule in matches if rule.effect == "approval"), None)
        if selected is None:
            selected = next((rule for rule in matches if rule.effect == "allow"), None)
        if selected is None:
            return self._record(ToolAccessDecision("deny", None, identity, keys, "no matching allow rule"))
        if selected.effect == "approval" and not request.approval_granted:
            return self._record(ToolAccessDecision("approval", selected.rule_id, identity, keys, "exact invocation requires approval"))
        return self._record(ToolAccessDecision("allow", selected.rule_id, identity, keys, "exact invocation allowed"))

    def _record(self, decision: ToolAccessDecision) -> ToolAccessDecision:
        if self.events is not None:
            self.events.record("tool.permission-decided", decision.mapping())
        return decision


@dataclass(frozen=True)
class ToolTimeouts:
    connection_seconds: float
    read_seconds: float
    total_seconds: float
    cleanup_grace_seconds: float = 0.5

    def __post_init__(self) -> None:
        if min(self.connection_seconds, self.read_seconds, self.total_seconds, self.cleanup_grace_seconds) <= 0:
            raise ValueError("tool timeouts must be positive")
        if self.total_seconds < max(self.connection_seconds, self.read_seconds):
            raise ValueError("total tool timeout must cover connection and read timeout")


class ToolCancellation:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class ToolExecutionContext:
    connection_timeout_seconds: float
    read_timeout_seconds: float
    cancellation: ToolCancellation
    idempotency_key: str | None


@dataclass(frozen=True)
class ToolAdapterResult:
    value: Any
    result_ref: str | None = None


class ToolAdapter(Protocol):
    def invoke(self, arguments: Mapping[str, Any], context: ToolExecutionContext) -> ToolAdapterResult: ...

    def cleanup(self) -> None: ...


class ToolFailure(RuntimeError):
    def __init__(
        self,
        failure_type: str,
        message: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ):
        super().__init__(message)
        self.failure_type = failure_type
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class ToolExecutionOutcome:
    status: str
    attempts: int
    permission: ToolAccessDecision
    result_ref: str | None
    error: FailureEnvelope | None
    manual_recovery_required: bool = False


class SecureToolExecutor:
    """Authorize, execute, retry and audit one tool invocation."""

    def __init__(
        self,
        access: ToolAccessPolicy,
        retry: RetryScheduler,
        timeouts: ToolTimeouts,
        *,
        events: ReliabilityEventLog,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.access = access
        self.retry = retry
        self.timeouts = timeouts
        self.events = events
        self.monotonic = monotonic

    def _invoke_once(
        self,
        adapter: ToolAdapter,
        arguments: Mapping[str, Any],
        idempotency_key: str | None,
    ) -> ToolAdapterResult:
        cancellation = ToolCancellation()
        context = ToolExecutionContext(
            self.timeouts.connection_seconds,
            self.timeouts.read_seconds,
            cancellation,
            idempotency_key,
        )
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="sitina-tool")
        future = pool.submit(adapter.invoke, dict(arguments), context)
        wait_for_worker = True
        try:
            return future.result(timeout=self.timeouts.total_seconds)
        except concurrent.futures.TimeoutError as error:
            cancellation.cancel()
            try:
                future.result(timeout=self.timeouts.cleanup_grace_seconds)
            except concurrent.futures.TimeoutError as stuck:
                wait_for_worker = False
                raise ToolFailure("tool_cleanup_timeout", "tool ignored cancellation during cleanup") from stuck
            except Exception:
                pass
            raise ToolFailure("tool_total_timeout", "tool exceeded its total deadline") from error
        finally:
            try:
                adapter.cleanup()
            finally:
                pool.shutdown(wait=wait_for_worker, cancel_futures=True)

    def execute(
        self,
        *,
        run_id: str,
        request: ToolAccessRequest,
        adapter: ToolAdapter,
        idempotent: bool,
        idempotency_key: str | None,
    ) -> ToolExecutionOutcome:
        permission = self.access.decide(request)
        summary = summarize_tool_arguments(request.server, request.tool, request.arguments)
        if not permission.allowed:
            self.events.record(
                "tool.audit",
                summary | {"run_id": run_id, "permission": permission.mapping(), "status": "blocked"},
            )
            return ToolExecutionOutcome("blocked", 0, permission, None, None)
        total_deadline = self.monotonic() + self.timeouts.total_seconds * (self.retry.settings.max_retries + 1)
        attempt = 0
        while True:
            attempt += 1
            started = self.monotonic()
            try:
                result = self._invoke_once(adapter, request.arguments, idempotency_key)
            except Exception as raw_error:  # noqa: BLE001
                error = raw_error if isinstance(raw_error, ToolFailure) else ToolFailure(type(raw_error).__name__, str(raw_error))
                envelope = FailureEnvelope.from_exception(
                    error,
                    failure_id=f"tool-failure-{hashlib.sha256(f'{run_id}:{identity(request)}:{attempt}'.encode()).hexdigest()[:20]}",
                    run_id=run_id,
                    failure_type=error.failure_type,
                    stage="tool-execution",
                    source_agent=request.principal,
                    status_code=error.status_code,
                )
                schedule = self.retry.plan(
                    failure_type=error.failure_type,
                    failed_attempt=attempt,
                    remaining_seconds=max(0.0, total_deadline - self.monotonic()),
                    retry_after_seconds=error.retry_after_seconds,
                    status_code=error.status_code,
                    jitter_seed=f"{run_id}:{identity(request)}",
                )
                duration_ms = max(0, int((self.monotonic() - started) * 1000))
                safe_to_retry = idempotent or bool(idempotency_key)
                status = "retrying" if schedule.should_retry and safe_to_retry else (
                    "manual-recovery" if schedule.should_retry and not safe_to_retry else "failed"
                )
                self.events.record(
                    "tool.audit",
                    summary
                    | {
                        "run_id": run_id,
                        "permission": permission.mapping(),
                        "attempt": attempt,
                        "duration_ms": duration_ms,
                        "status": status,
                        "result_ref": None,
                        "error": envelope.mapping(),
                    },
                )
                if schedule.should_retry and safe_to_retry:
                    self.retry.wait(schedule)
                    continue
                return ToolExecutionOutcome(status, attempt, permission, None, envelope, status == "manual-recovery")
            boundary = redact_boundary_value(result.value, boundary="log")
            result_ref = result.result_ref or "sha256:" + hashlib.sha256(canonical_json_bytes(boundary.value)).hexdigest()
            duration_ms = max(0, int((self.monotonic() - started) * 1000))
            self.events.record(
                "tool.audit",
                summary
                | {
                    "run_id": run_id,
                    "permission": permission.mapping(),
                    "attempt": attempt,
                    "duration_ms": duration_ms,
                    "status": "succeeded",
                    "result_ref": result_ref,
                    "result_redacted_paths": list(boundary.redacted_paths),
                    "error": None,
                },
            )
            return ToolExecutionOutcome("succeeded", attempt, permission, result_ref, None)


def identity(request: ToolAccessRequest) -> str:
    return normalize_tool_name(request.server, request.tool)


@dataclass(frozen=True)
class ToolRiskDecision:
    rules_version: str
    score: int
    risk: str
    action: str
    matched_rules: tuple[str, ...]
    decision_hash: str

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_TOOL_RISK_DECISION_V1",
            "rules_version": self.rules_version,
            "score": self.score,
            "risk": self.risk,
            "action": self.action,
            "matched_rules": list(self.matched_rules),
            "decision_hash": self.decision_hash,
        }


class ContextualToolRiskScanner:
    rules_version = "1.0"
    _BASE = {"read": 5, "list": 5, "write": 35, "network": 40, "shell": 60, "delete": 70}

    def __init__(self, events: ReliabilityEventLog | None = None):
        self.events = events

    def scan(
        self,
        *,
        action: str,
        capability_present: bool,
        impact_count: int,
        untrusted_context: bool,
        external_target: bool,
    ) -> ToolRiskDecision:
        matched: list[str] = []
        if action not in self._BASE:
            score = 100
            matched.append("unknown-action-fail-closed")
        else:
            score = self._BASE[action]
        if not capability_present:
            score += 35
            matched.append("missing-capability")
        if impact_count > 1:
            score += min(30, impact_count * 3)
            matched.append("impact-scope")
        if untrusted_context:
            score += 20
            matched.append("untrusted-context")
        if external_target:
            score += 15
            matched.append("external-target")
        score = min(100, score)
        risk = "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 25 else "low"
        action_decision = "deny" if risk == "critical" else "approval" if risk in {"medium", "high"} else "allow"
        body = {
            "rules_version": self.rules_version,
            "score": score,
            "risk": risk,
            "action": action_decision,
            "matched_rules": matched,
        }
        decision = ToolRiskDecision(
            self.rules_version,
            score,
            risk,
            action_decision,
            tuple(matched),
            hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
        )
        if self.events is not None:
            self.events.record("tool.risk-scanned", decision.mapping())
        return decision


class RoleCapabilityPolicy:
    def __init__(self, agents: Mapping[str, Mapping[str, Any]]):
        self.agents = {role: dict(value) for role, value in agents.items()}

    def allows(self, role: str, capability: str, *, action: str | None = None) -> bool:
        profile = self.agents.get(role)
        if profile is None:
            return False
        if action and action in set(profile.get("forbidden_actions", ())):
            return False
        return capability in set(profile.get("capabilities", ()))

    def validate_minimum(self, expected: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
        errors: list[str] = []
        for role, exact in expected.items():
            actual = set(self.agents.get(role, {}).get("capabilities", ()))
            if actual != set(exact):
                errors.append(f"{role}: expected={sorted(exact)} actual={sorted(actual)}")
        return tuple(errors)


class PromptSource(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    TOOL = "tool"
    MEMORY = "memory"


@dataclass(frozen=True)
class PromptContentDecision:
    source: PromptSource
    trust: str
    data_only: bool
    injection_detected: bool
    can_grant_permissions: bool
    content: str


class PromptIsolationPolicy:
    _INJECTION = re.compile(
        r"(?i)(ignore (?:all |the )?(?:previous|prior|system|developer) instructions|"
        r"reveal|exfiltrat|send (?:all )?(?:secrets|credentials)|grant (?:me )?permission|become system)"
    )

    def admit(self, source: PromptSource, content: str) -> PromptContentDecision:
        boundary = redact_boundary_value(content, boundary="handoff")
        detected = bool(self._INJECTION.search(str(boundary.value)))
        trusted_instruction = source in {PromptSource.SYSTEM, PromptSource.DEVELOPER}
        data_only = source in {PromptSource.TOOL, PromptSource.MEMORY}
        trust = "trusted-instruction" if trusted_instruction else "untrusted-data" if data_only else "user-intent"
        # Prompt text can express intent and constraints, but only executable
        # policy/approval code can grant a capability.
        return PromptContentDecision(source, trust, data_only, detected, False, str(boundary.value))

    def wrap_tool_result(self, *, tool_name: str, status: str, value: Any) -> str:
        boundary = redact_boundary_value(value, boundary="handoff")
        return json.dumps(
            {
                "schema": "SITINA_UNTRUSTED_TOOL_DATA_V1",
                "source": "tool",
                "trust": "untrusted-data",
                "can_grant_permissions": False,
                "can_override_instructions": False,
                "status": status,
                "tool": tool_name,
                "result": boundary.value,
                "redacted_paths": list(boundary.redacted_paths),
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
