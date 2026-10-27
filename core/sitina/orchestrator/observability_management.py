from __future__ import annotations

import json
import resource
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Literal, Mapping, Sequence

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.schemas.models import StrictModel
from sitina.security.redaction import redact_boundary_value
from sitina.utils import load_json_yaml, redact_text, sha256_text, stable_json


class ObservabilityPolicyError(ValueError):
    pass


class ObservabilityPolicy:
    REQUIRED_SECTIONS = {"sampling", "alerts", "profiling", "trajectory"}

    def __init__(self, value: Mapping[str, Any]):
        self.value = dict(value)
        self.validate()

    @classmethod
    def load(cls, home: Path = SITINA_HOME) -> "ObservabilityPolicy":
        path = Path(home) / "config" / "observability_policy.json"
        if not path.exists():
            raise ObservabilityPolicyError("observability policy missing")
        value = load_json_yaml(path)
        if not isinstance(value, dict):
            raise ObservabilityPolicyError("observability policy must be an object")
        return cls(value)

    def validate(self) -> None:
        if self.value.get("schema") != "SITINA_OBSERVABILITY_POLICY_V1" or self.value.get("version") != "1.0":
            raise ObservabilityPolicyError("observability policy schema/version mismatch")
        missing = self.REQUIRED_SECTIONS - set(self.value)
        if missing:
            raise ObservabilityPolicyError(f"observability policy sections missing: {sorted(missing)}")
        sampling = self.value["sampling"]
        trajectory = self.value["trajectory"]
        alerts = self.value["alerts"]
        if not 0 <= int(sampling.get("ordinary_success_rate_ppm", -1)) <= 1_000_000:
            raise ObservabilityPolicyError("sampling rate must be within 0..1000000 ppm")
        for name in ("same_tool_threshold", "permission_denial_threshold", "unchanged_state_threshold"):
            if int(trajectory.get(name, 0)) < 2:
                raise ObservabilityPolicyError(f"trajectory {name} must be at least 2")
        for name in ("fast_burn_rate_ppm", "slow_burn_rate_ppm", "token_anomaly_ratio_ppm", "cost_anomaly_ratio_ppm"):
            if int(alerts.get(name, 0)) <= 0:
                raise ObservabilityPolicyError(f"alert {name} must be positive")


TraceLayer = Literal["run", "task", "agent", "provider", "tool", "state", "effect"]


class TraceObservation(StrictModel):
    schema_id: Literal["SITINA_TRACE_OBSERVATION_V1"] = Field(default="SITINA_TRACE_OBSERVATION_V1", alias="schema")
    schema_version: Literal["1.0"] = "1.0"
    trace_id: str
    correlation_id: str
    span_id: str
    parent_span_id: str | None
    layer: TraceLayer
    name: str
    status: Literal["PENDING", "RUNNING", "OK", "ERROR", "CANCELLED"]
    run_id: str
    task_id: str | None = None
    agent_id: str | None = None
    started_at: str
    ended_at: str | None = None
    error_type: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)
    policy_version: str
    observed_schema_version: str
    links: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_terminal_metadata(self) -> "TraceObservation":
        terminal = self.status in {"OK", "ERROR", "CANCELLED"}
        if terminal != (self.ended_at is not None):
            raise ValueError("trace terminal status and ended_at must agree")
        if self.status == "ERROR" and not self.error_type:
            raise ValueError("error trace observation requires error_type")
        if self.layer != "run" and not self.task_id:
            raise ValueError("non-run trace observation requires task_id")
        if self.layer in {"agent", "provider", "tool"} and not self.agent_id:
            raise ValueError("agent/provider/tool observation requires agent_id")
        if self.layer == "provider" and terminal and not {"input_tokens", "output_tokens", "total_tokens"}.issubset(self.usage):
            raise ValueError("terminal provider observation requires token usage")
        return self


class TraceIntegrityReport(StrictModel):
    schema_id: Literal["SITINA_TRACE_INTEGRITY_REPORT_V1"] = Field(default="SITINA_TRACE_INTEGRITY_REPORT_V1", alias="schema")
    status: Literal["complete", "invalid"]
    trace_id: str | None
    root_span_id: str | None
    span_count: int
    errors: tuple[str, ...]


class TraceIntegrityValidator:
    ALLOWED_PARENTS: dict[TraceLayer, set[TraceLayer]] = {
        "run": set(),
        "task": {"run"},
        "agent": {"task"},
        "provider": {"agent"},
        "tool": {"agent"},
        "state": {"task", "agent", "provider", "tool"},
        "effect": {"task", "agent", "tool"},
    }

    def validate(self, observations: Sequence[TraceObservation]) -> TraceIntegrityReport:
        errors: list[str] = []
        ids = [item.span_id for item in observations]
        if len(ids) != len(set(ids)):
            errors.append("DUPLICATE_SPAN")
        by_id = {item.span_id: item for item in observations}
        trace_ids = {item.trace_id for item in observations}
        correlations = {item.correlation_id for item in observations}
        if len(trace_ids) != 1:
            errors.append("TRACE_ID_MISMATCH")
        if len(correlations) != 1:
            errors.append("CORRELATION_ID_MISMATCH")
        roots = [item for item in observations if item.parent_span_id is None]
        if len(roots) != 1 or (roots and roots[0].layer != "run"):
            errors.append("ROOT_INVALID")
        for item in observations:
            if not item.policy_version or not item.observed_schema_version:
                errors.append(f"VERSION_MISSING:{item.span_id}")
            if item.parent_span_id is not None:
                parent = by_id.get(item.parent_span_id)
                if parent is None:
                    errors.append(f"ORPHAN:{item.span_id}")
                elif parent.layer not in self.ALLOWED_PARENTS[item.layer]:
                    errors.append(f"LAYER_BREAK:{item.span_id}")
        for span_id in ids:
            active: set[str] = set()
            cursor: str | None = span_id
            while cursor is not None and cursor in by_id:
                if cursor in active:
                    errors.append(f"CYCLE:{span_id}")
                    break
                active.add(cursor)
                cursor = by_id[cursor].parent_span_id
        layers = {item.layer for item in observations}
        for required in ("run", "task", "agent", "state", "effect"):
            if required not in layers:
                errors.append(f"LAYER_MISSING:{required}")
        if not layers.intersection({"provider", "tool"}):
            errors.append("LAYER_MISSING:provider_or_tool")
        unique_errors = tuple(sorted(set(errors)))
        return TraceIntegrityReport(
            status="invalid" if unique_errors else "complete",
            trace_id=next(iter(trace_ids)) if len(trace_ids) == 1 else None,
            root_span_id=roots[0].span_id if len(roots) == 1 else None,
            span_count=len(observations),
            errors=unique_errors,
        )


class SamplingDecision(StrictModel):
    keep: bool
    reason: str
    deterministic_bucket_ppm: int


class TraceSamplingPolicy:
    def __init__(self, config: Mapping[str, Any]):
        self.rate = int(config["ordinary_success_rate_ppm"])
        self.always_risks = set(config["always_keep_risks"])
        self.always_classes = set(config["always_keep_classes"])

    def decide(self, *, trace_id: str, status: str, risk: str, event_classes: Iterable[str]) -> SamplingDecision:
        classes = set(event_classes)
        digest = int(sha256_text(trace_id).split(":", 1)[-1][:12], 16)
        bucket = digest % 1_000_000
        if status in {"ERROR", "FAILED", "BLOCKED"}:
            return SamplingDecision(keep=True, reason="terminal_error", deterministic_bucket_ppm=bucket)
        forced = sorted(classes & self.always_classes)
        if risk in self.always_risks:
            return SamplingDecision(keep=True, reason="high_risk", deterministic_bucket_ppm=bucket)
        if forced:
            return SamplingDecision(keep=True, reason=f"protected_class:{forced[0]}", deterministic_bucket_ppm=bucket)
        return SamplingDecision(keep=bucket < self.rate, reason="deterministic_probability", deterministic_bucket_ppm=bucket)


class TraceQuery(StrictModel):
    run_id: str
    agent: str | None = None
    tool: str | None = None
    status: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    correlation_id: str | None = None
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


class TraceQueryResult(StrictModel):
    schema_id: Literal["SITINA_TRACE_QUERY_RESULT_V1"] = Field(default="SITINA_TRACE_QUERY_RESULT_V1", alias="schema")
    authoritative_source: Literal["run_ledger"] = "run_ledger"
    read_only: Literal[True] = True
    items: list[dict[str, Any]]
    next_cursor: int | None
    total_matches: int


class TraceQueryEngine:
    @staticmethod
    def _safe(value: Mapping[str, Any]) -> dict[str, Any]:
        redacted = redact_boundary_value(dict(value), boundary="read").value
        return json.loads(redact_text(json.dumps(redacted, ensure_ascii=False, sort_keys=True)))

    def query(self, events: Sequence[Mapping[str, Any]], query: TraceQuery) -> TraceQueryResult:
        matches: list[dict[str, Any]] = []
        for source in events:
            item = dict(source)
            payload = item.get("payload_json") if isinstance(item.get("payload_json"), dict) else {}
            if (item.get("run_id") or payload.get("run_id")) != query.run_id:
                continue
            if query.agent and (item.get("agent_id") or payload.get("agent_id") or payload.get("agent")) != query.agent:
                continue
            if query.status and (item.get("status") or payload.get("status")) != query.status:
                continue
            if query.tool:
                tool_values = {str(payload.get("tool") or ""), str(payload.get("tool_name") or ""), str(item.get("event_type") or "")}
                if not any(query.tool in value for value in tool_values):
                    continue
            timestamp = str(item.get("timestamp") or item.get("_recorded_ts") or "")
            if query.started_at and timestamp < query.started_at:
                continue
            if query.ended_at and timestamp > query.ended_at:
                continue
            if query.correlation_id:
                correlations = {str(item.get("_trace_id") or ""), str(payload.get("correlation_id") or "")}
                if query.correlation_id not in correlations:
                    continue
            matches.append(self._safe(item))
        matches.sort(key=lambda item: (str(item.get("timestamp") or item.get("_recorded_ts") or ""), str(item.get("event_id") or "")))
        page = matches[query.cursor : query.cursor + query.limit]
        next_cursor = query.cursor + len(page) if query.cursor + len(page) < len(matches) else None
        return TraceQueryResult(items=page, next_cursor=next_cursor, total_matches=len(matches))


class ReplayConsistencyReport(StrictModel):
    status: Literal["match", "mismatch"]
    left_hash: str
    right_hash: str


class ReplayConsistencyVerifier:
    VOLATILE_FIELDS = {"timestamp", "_recorded_ts", "created_at", "updated_at", "duration_ms"}

    def upcast_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(event)
        version = str(value.get("schema_version", "0.9"))
        if version.startswith("0."):
            if "ts" in value and "timestamp" not in value:
                value["timestamp"] = value.pop("ts")
            if "payload" in value and "payload_json" not in value:
                value["payload_json"] = value.pop("payload")
            value["schema_version"] = "1.0"
        if not str(value.get("schema_version", "")).startswith("1."):
            raise ValueError("unsupported replay event schema version")
        return value

    def _normalize(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._normalize(item) for key, item in sorted(value.items()) if key not in self.VOLATILE_FIELDS}
        if isinstance(value, list):
            return [self._normalize(item) for item in value]
        return value

    def state_hash(self, value: Any) -> str:
        return sha256_text(stable_json(self._normalize(value)))

    def compare(self, left: Any, right: Any) -> ReplayConsistencyReport:
        left_hash = self.state_hash(left)
        right_hash = self.state_hash(right)
        return ReplayConsistencyReport(status="match" if left_hash == right_hash else "mismatch", left_hash=left_hash, right_hash=right_hash)


class BusinessMetricSnapshot(StrictModel):
    schema_id: Literal["SITINA_BUSINESS_METRICS_V1"] = Field(default="SITINA_BUSINESS_METRICS_V1", alias="schema")
    metrics: dict[str, int]
    dimension_keys: tuple[str, ...] = ("policy_version", "risk_band", "terminal_status")
    authoritative_source: Literal["run_ledger"] = "run_ledger"


class BusinessMetricCollector:
    def collect(self, events: Sequence[Mapping[str, Any]]) -> BusinessMetricSnapshot:
        types = Counter(str(item.get("event_type")) for item in events)
        task_terminals = [item for item in events if item.get("event_type") == "task_graph_node_status" and item.get("status") in {"ok", "failed", "blocked"}]
        task_success = sum(item.get("status") == "ok" for item in task_terminals)
        routes = types["dispatcher_agent_selected"] + types["dispatcher_no_eligible_agent"]
        metrics = {
            "task_success_rate_ppm": int(task_success * 1_000_000 / len(task_terminals)) if task_terminals else 0,
            "routing_quality_ppm": int(types["dispatcher_agent_selected"] * 1_000_000 / routes) if routes else 0,
            "rework_count": types["rework_requested"],
            "handoff_count": types["agent_handoff"],
            "handoff_acceptance_count": types["handoff_accepted"],
            "budget_exceeded_count": sum("budget" in str(item.get("event_type")) and item.get("status") in {"failed", "blocked"} for item in events),
            "partial_success_count": sum(item.get("payload_json", {}).get("partial_success") is True for item in events if isinstance(item.get("payload_json"), dict)),
            "recovery_success_count": types["checkpoint_resumed"] + sum(item.get("event_type") == "retry_scheduled" and item.get("status") == "ok" for item in events),
        }
        return BusinessMetricSnapshot(metrics=metrics)


class AlertSignalSnapshot(StrictModel):
    fast_burn_rate_ppm: int = Field(ge=0)
    slow_burn_rate_ppm: int = Field(ge=0)
    repeated_failures: int = Field(ge=0)
    queue_depth: int = Field(ge=0)
    token_ratio_ppm: int | None = Field(default=None, ge=0)
    cost_ratio_ppm: int | None = Field(default=None, ge=0)
    timeouts: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)
    cancel_failures: int = Field(default=0, ge=0)
    unknown_effects: int = Field(default=0, ge=0)
    resource_rejections: int = Field(default=0, ge=0)
    usage_unknown: int = Field(default=0, ge=0)


class AlertState(StrictModel):
    active: dict[str, int] = Field(default_factory=dict)
    last_emitted: dict[str, int] = Field(default_factory=dict)


class AlertNotification(StrictModel):
    code: str
    kind: Literal["firing", "recovered"]
    severity: Literal["warning", "critical", "recovery"]
    fingerprint: str
    observed_at_epoch: int


class AlertEvaluation(StrictModel):
    notifications: tuple[AlertNotification, ...]
    state: AlertState


class AlertEngine:
    def __init__(self, config: Mapping[str, Any]):
        self.config = dict(config)

    def evaluate(self, signals: AlertSignalSnapshot, *, state: AlertState, now_epoch: int) -> AlertEvaluation:
        breaches: dict[str, Literal["warning", "critical"]] = {}
        if signals.fast_burn_rate_ppm >= int(self.config["fast_burn_rate_ppm"]) and signals.slow_burn_rate_ppm >= int(self.config["slow_burn_rate_ppm"]):
            breaches["SLO_MULTI_WINDOW_BURN"] = "critical"
        if signals.repeated_failures >= int(self.config["repeated_failure_threshold"]):
            breaches["REPEATED_FAILURE"] = "warning"
        if signals.queue_depth >= int(self.config["queue_backlog_threshold"]):
            breaches["QUEUE_BACKLOG"] = "warning"
        if signals.token_ratio_ppm is not None and signals.token_ratio_ppm >= int(self.config["token_anomaly_ratio_ppm"]):
            breaches["TOKEN_ANOMALY"] = "critical"
        if signals.cost_ratio_ppm is not None and signals.cost_ratio_ppm >= int(self.config["cost_anomaly_ratio_ppm"]):
            breaches["COST_ANOMALY"] = "critical"
        for count, code in (
            (signals.timeouts, "TIMEOUT"), (signals.retries, "RETRY"),
            (signals.cancel_failures, "CANCEL_FAILURE"),
            (signals.unknown_effects, "UNKNOWN_EFFECT"),
            (signals.resource_rejections, "RESOURCE_LIMIT"),
            (signals.usage_unknown, "USAGE_UNKNOWN"),
        ):
            if count:
                breaches[code] = "warning"
        active = dict(state.active)
        emitted = dict(state.last_emitted)
        notifications: list[AlertNotification] = []
        cooldown = int(self.config["dedupe_cooldown_seconds"])
        for code, severity in sorted(breaches.items()):
            if code not in active and now_epoch - emitted.get(code, -cooldown) >= cooldown:
                notifications.append(AlertNotification(code=code, kind="firing", severity=severity, fingerprint=sha256_text(code), observed_at_epoch=now_epoch))
                emitted[code] = now_epoch
            active[code] = now_epoch
        for code in sorted(set(active) - set(breaches)):
            notifications.append(AlertNotification(code=code, kind="recovered", severity="recovery", fingerprint=sha256_text(code), observed_at_epoch=now_epoch))
            active.pop(code, None)
            emitted[code] = now_epoch
        return AlertEvaluation(notifications=tuple(notifications), state=AlertState(active=active, last_emitted=emitted))


class StructuredLogRecord(StrictModel):
    schema_id: Literal["SITINA_STRUCTURED_LOG_V1"] = Field(default="SITINA_STRUCTURED_LOG_V1", alias="schema")
    schema_version: Literal["1.0"] = "1.0"
    timestamp: str
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    event_code: str
    correlation_id: str
    run_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    message: str
    fields: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = False


class StructuredLogBuilder:
    def build(self, **values: Any) -> StructuredLogRecord:
        values.pop("redacted", None)
        raw_fields = values.pop("fields", {})
        raw_message = values.pop("message")
        redacted = redact_boundary_value(raw_fields, boundary="log").value
        safe_fields = json.loads(redact_text(json.dumps(redacted, ensure_ascii=False, sort_keys=True)))
        return StructuredLogRecord(message=redact_text(str(raw_message)), fields=safe_fields, **values)

    @staticmethod
    def human(record: StructuredLogRecord) -> str:
        return f"{record.timestamp} {record.level} {record.event_code} [{record.correlation_id}] {record.message}"


class TracePropagationContext(StrictModel):
    schema_id: Literal["SITINA_TRACE_PROPAGATION_V1"] = Field(default="SITINA_TRACE_PROPAGATION_V1", alias="schema")
    trace_id: str
    span_id: str
    correlation_id: str
    parent_span_id: str | None = None
    links: tuple[str, ...] = ()


class TracePropagator:
    @staticmethod
    def child(parent: TracePropagationContext, *, span_id: str) -> TracePropagationContext:
        return TracePropagationContext(trace_id=parent.trace_id, span_id=span_id, correlation_id=parent.correlation_id, parent_span_id=parent.span_id)

    @staticmethod
    def queue_link(source: TracePropagationContext, *, consumer_span_id: str) -> TracePropagationContext:
        return TracePropagationContext(trace_id=source.trace_id, span_id=consumer_span_id, correlation_id=source.correlation_id, links=(source.span_id,))

    @staticmethod
    def inject(context: TracePropagationContext) -> dict[str, str]:
        return {"trace_id": context.trace_id, "span_id": context.span_id, "correlation_id": context.correlation_id, "parent_span_id": context.parent_span_id or "", "links": ",".join(context.links)}

    @staticmethod
    def extract(headers: Mapping[str, str]) -> TracePropagationContext:
        return TracePropagationContext(
            trace_id=headers["trace_id"],
            span_id=headers["span_id"],
            correlation_id=headers["correlation_id"],
            parent_span_id=headers.get("parent_span_id") or None,
            links=tuple(filter(None, str(headers.get("links", "")).split(","))),
        )


class StageProfile(StrictModel):
    stage: str
    wall_time_ns: int = Field(ge=0)
    cpu_time_ns: int = Field(ge=0)
    memory_delta_bytes: int
    queue_wait_ns: int = Field(ge=0)


class LowOverheadProfiler:
    def __init__(
        self,
        *,
        enabled: bool = False,
        wall_clock_ns: Callable[[], int] = time.perf_counter_ns,
        cpu_clock_ns: Callable[[], int] = time.process_time_ns,
        memory_bytes: Callable[[], int] | None = None,
    ):
        self.enabled = enabled
        self.wall_clock_ns = wall_clock_ns
        self.cpu_clock_ns = cpu_clock_ns
        self.memory_bytes = memory_bytes or (lambda: int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024)
        self.reports: list[StageProfile] = []

    @contextmanager
    def measure(self, stage: str, *, queue_wait_ns: int = 0) -> Iterator[None]:
        if not self.enabled:
            yield
            return
        wall = self.wall_clock_ns()
        cpu = self.cpu_clock_ns()
        memory = self.memory_bytes()
        try:
            yield
        finally:
            self.reports.append(StageProfile(
                stage=stage,
                wall_time_ns=max(0, self.wall_clock_ns() - wall),
                cpu_time_ns=max(0, self.cpu_clock_ns() - cpu),
                memory_delta_bytes=self.memory_bytes() - memory,
                queue_wait_ns=queue_wait_ns,
            ))


class TrajectoryEvent(StrictModel):
    event_id: str
    kind: Literal["tool_call", "permission_denied", "state_transition", "token_usage"]
    tool_name: str | None = None
    state_hash: str | None = None
    tokens: int = Field(default=0, ge=0)
    budget: int = Field(default=0, ge=0)


class TrajectoryMonitorState(StrictModel):
    seen_fingerprints: tuple[str, ...] = ()


class TrajectoryAnomaly(StrictModel):
    code: Literal["SAME_TOOL_REPEAT", "PERMISSION_DENIAL_REPEAT", "UNCHANGED_STATE_LOOP", "TOKEN_BUDGET_ANOMALY"]
    count: int
    threshold: int
    action: Literal["warn", "circuit_break", "pause_and_request_review"]
    fingerprint: str


class TrajectoryMonitorResult(StrictModel):
    anomalies: tuple[TrajectoryAnomaly, ...]
    state: TrajectoryMonitorState


class RunTrajectoryMonitor:
    def __init__(self, config: Mapping[str, Any]):
        self.config = dict(config)

    def evaluate(self, run_id: str, events: Sequence[TrajectoryEvent], *, state: TrajectoryMonitorState | None = None) -> TrajectoryMonitorResult:
        state = state or TrajectoryMonitorState()
        seen = set(state.seen_fingerprints)
        candidates: list[tuple[str, int, int]] = []
        tool_counts = Counter(item.tool_name for item in events if item.kind == "tool_call" and item.tool_name)
        if tool_counts:
            _tool, count = sorted(tool_counts.items(), key=lambda item: (-item[1], str(item[0])))[0]
            threshold = int(self.config["same_tool_threshold"])
            if count >= threshold:
                candidates.append(("SAME_TOOL_REPEAT", count, threshold))
        permission_count = sum(item.kind == "permission_denied" for item in events)
        permission_threshold = int(self.config["permission_denial_threshold"])
        if permission_count >= permission_threshold:
            candidates.append(("PERMISSION_DENIAL_REPEAT", permission_count, permission_threshold))
        longest_unchanged = 0
        current_unchanged = 0
        previous_state: str | None = None
        for item in events:
            if item.kind != "state_transition" or not item.state_hash:
                continue
            current_unchanged = current_unchanged + 1 if item.state_hash == previous_state else 1
            previous_state = item.state_hash
            longest_unchanged = max(longest_unchanged, current_unchanged)
        state_threshold = int(self.config["unchanged_state_threshold"])
        if longest_unchanged >= state_threshold:
            candidates.append(("UNCHANGED_STATE_LOOP", longest_unchanged, state_threshold))
        token_events = [item for item in events if item.kind == "token_usage" and item.budget > 0]
        if token_events:
            tokens = sum(item.tokens for item in token_events)
            budget = max(item.budget for item in token_events)
            multiplier = int(self.config["token_budget_multiplier_ppm"])
            threshold = budget * multiplier // 1_000_000
            if tokens >= threshold:
                candidates.append(("TOKEN_BUDGET_ANOMALY", tokens, threshold))
        anomalies: list[TrajectoryAnomaly] = []
        actions = self.config["actions"]
        evidence_ids = tuple(sorted(item.event_id for item in events))
        for code, count, threshold in candidates:
            fingerprint = sha256_text(stable_json({"run_id": run_id, "code": code, "evidence_ids": evidence_ids}))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            anomalies.append(TrajectoryAnomaly(code=code, count=count, threshold=threshold, action=actions[code], fingerprint=fingerprint))
        return TrajectoryMonitorResult(anomalies=tuple(anomalies), state=TrajectoryMonitorState(seen_fingerprints=tuple(sorted(seen))))


__all__ = [
    "AlertEngine", "AlertSignalSnapshot", "AlertState", "BusinessMetricCollector", "LowOverheadProfiler",
    "ObservabilityPolicy", "ObservabilityPolicyError", "ReplayConsistencyVerifier", "RunTrajectoryMonitor",
    "StructuredLogBuilder", "TraceIntegrityValidator", "TraceObservation", "TracePropagationContext", "TracePropagator",
    "TraceQuery", "TraceQueryEngine", "TrajectoryEvent", "TrajectoryMonitorState", "TraceSamplingPolicy",
]
