"""Versioned reliability contracts shared by provider, tool and Effect paths.

The module is deliberately policy-only: callers provide clocks, sleepers and
event sinks.  This keeps retry/fallback/rollback decisions deterministic and
testable without adding another persistence authority beside the Journal.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from sitina.security.redaction import redact_boundary_value


FAILURE_TAXONOMY_VERSION = "1.0"


class FailureCategory(str, Enum):
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    AUTH = "auth"
    QUOTA = "quota"
    SCHEMA = "schema"
    SAFETY = "safety"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class FailureTaxonomy:
    """Classify boundary failure codes without depending on provider classes."""

    version = FAILURE_TAXONOMY_VERSION

    @classmethod
    def classify(cls, failure_type: str, *, status_code: int | None = None) -> FailureCategory:
        code = failure_type.casefold().replace("-", "_")
        if status_code in {401, 403} or any(item in code for item in ("auth", "credential", "permission_denied")):
            return FailureCategory.AUTH
        if status_code == 429 or any(item in code for item in ("quota", "rate_limit", "throttl")):
            return FailureCategory.QUOTA
        if any(item in code for item in ("cancel", "interrupt")):
            return FailureCategory.CANCELLED
        if any(item in code for item in ("schema", "parse", "malformed", "invalid_json", "validation")):
            return FailureCategory.SCHEMA
        if any(item in code for item in ("safety", "policy_block", "sensitive_path", "unsafe")):
            return FailureCategory.SAFETY
        if status_code is not None and 500 <= status_code <= 599:
            return FailureCategory.TRANSIENT
        if any(
            item in code
            for item in (
                "timeout",
                "network",
                "connection",
                "connect",
                "incompleteread",
                "incomplete_read",
                "temporar",
                "unavailable",
                "provider_5",
            )
        ):
            return FailureCategory.TRANSIENT
        if status_code is not None and 400 <= status_code <= 499:
            return FailureCategory.PERMANENT
        if any(item in code for item in ("permanent", "not_found", "unsupported", "rejected")):
            return FailureCategory.PERMANENT
        return FailureCategory.UNKNOWN

    @staticmethod
    def retryable(category: FailureCategory) -> bool:
        return category in {FailureCategory.TRANSIENT, FailureCategory.QUOTA}


class ReliabilityEventLog:
    """In-memory event projection for tests or adapters with an external sink.

    Production callers should pass a Journal append callback.  Dedupe queries
    are derived from recorded facts rather than a second mutable database.
    """

    def __init__(self, append: Callable[[Mapping[str, Any]], Any] | None = None):
        self._append = append
        self._events: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def record(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        boundary = redact_boundary_value(dict(payload), boundary="log")
        with self._lock:
            event = {
                "schema": "SITINA_RELIABILITY_EVENT_V1",
                "event_type": event_type,
                "sequence": len(self._events) + 1,
                "payload": boundary.value,
                "redacted_paths": list(boundary.redacted_paths),
            }
            if self._append is not None:
                self._append(event)
            self._events.append(event)
            return dict(event)

    def events(self, event_type: str | None = None) -> tuple[dict[str, Any], ...]:
        with self._lock:
            selected = self._events if event_type is None else [
                event for event in self._events if event["event_type"] == event_type
            ]
            return tuple(dict(event) for event in selected)


@dataclass(frozen=True)
class FailureCause:
    error_type: str
    stage: str
    message: str

    def __post_init__(self) -> None:
        safe = redact_boundary_value(self.message, boundary="handoff").value
        object.__setattr__(self, "message", str(safe)[:500])

    def mapping(self) -> dict[str, str]:
        return {"error_type": self.error_type, "stage": self.stage, "message": self.message}


@dataclass(frozen=True)
class FailureEnvelope:
    failure_id: str
    run_id: str
    failure_type: str
    category: FailureCategory
    stage: str
    retryable: bool
    source_agent: str
    destination_agent: str | None
    causes: tuple[FailureCause, ...]
    diagnostic: str

    def __post_init__(self) -> None:
        safe = redact_boundary_value(self.diagnostic, boundary="handoff").value
        object.__setattr__(self, "diagnostic", str(safe)[:500])

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_FAILURE_ENVELOPE_V1",
            "taxonomy_version": FAILURE_TAXONOMY_VERSION,
            "failure_id": self.failure_id,
            "run_id": self.run_id,
            "failure_type": self.failure_type,
            "category": self.category.value,
            "stage": self.stage,
            "retryable": self.retryable,
            "source_agent": self.source_agent,
            "destination_agent": self.destination_agent,
            "causes": [item.mapping() for item in self.causes],
            "diagnostic": self.diagnostic,
        }

    @classmethod
    def from_exception(
        cls,
        error: BaseException,
        *,
        failure_id: str,
        run_id: str,
        failure_type: str,
        stage: str,
        source_agent: str,
        destination_agent: str | None = None,
        status_code: int | None = None,
    ) -> "FailureEnvelope":
        causes: list[FailureCause] = []
        current: BaseException | None = error
        seen: set[int] = set()
        while current is not None and id(current) not in seen and len(causes) < 8:
            seen.add(id(current))
            safe = redact_boundary_value(str(current), boundary="handoff").value
            causes.append(FailureCause(type(current).__name__, stage, str(safe)[:500]))
            current = current.__cause__ or current.__context__
        category = FailureTaxonomy.classify(failure_type, status_code=status_code)
        diagnostic = causes[0].message if causes else "failure details unavailable"
        return cls(
            failure_id,
            run_id,
            failure_type,
            category,
            stage,
            FailureTaxonomy.retryable(category),
            source_agent,
            destination_agent,
            tuple(causes),
            diagnostic,
        )


@dataclass(frozen=True)
class RetrySettings:
    max_retries: int = 1
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.max_retries < 0 or self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("retry counts and delays must be non-negative")
        if self.base_delay_seconds > self.max_delay_seconds:
            raise ValueError("retry base delay exceeds maximum delay")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("retry jitter ratio must be between zero and one")


@dataclass(frozen=True)
class RetrySchedule:
    failure_type: str
    category: FailureCategory
    failed_attempt: int
    max_retries: int
    should_retry: bool
    delay_seconds: float
    retry_after_seconds: float | None
    blocked_by_deadline: bool
    reason: str

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_RETRY_SCHEDULE_V1",
            "taxonomy_version": FAILURE_TAXONOMY_VERSION,
            "failure_type": self.failure_type,
            "category": self.category.value,
            "failed_attempt": self.failed_attempt,
            "max_retries": self.max_retries,
            "should_retry": self.should_retry,
            "delay_seconds": self.delay_seconds,
            "retry_after_seconds": self.retry_after_seconds,
            "blocked_by_deadline": self.blocked_by_deadline,
            "reason": self.reason,
        }


class RetryScheduler:
    def __init__(
        self,
        settings: RetrySettings,
        *,
        sleep: Callable[[float], None] | None = None,
        events: ReliabilityEventLog | None = None,
    ):
        self.settings = settings
        self._sleep = sleep
        self.events = events

    @staticmethod
    def _jitter_unit(seed: str) -> float:
        numerator = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16], 16)
        return numerator / float(0xFFFFFFFFFFFFFFFF)

    def plan(
        self,
        *,
        failure_type: str,
        failed_attempt: int,
        remaining_seconds: float,
        retry_after_seconds: float | None = None,
        status_code: int | None = None,
        jitter_seed: str = "sitina-retry",
    ) -> RetrySchedule:
        if failed_attempt < 1:
            raise ValueError("failed_attempt is one-based")
        if retry_after_seconds is not None and retry_after_seconds < 0:
            raise ValueError("Retry-After cannot be negative")
        category = FailureTaxonomy.classify(failure_type, status_code=status_code)
        retryable = FailureTaxonomy.retryable(category)
        exhausted = failed_attempt > self.settings.max_retries
        exponential = min(
            self.settings.max_delay_seconds,
            self.settings.base_delay_seconds * (2 ** (failed_attempt - 1)),
        )
        unit = self._jitter_unit(f"{jitter_seed}:{failed_attempt}:{failure_type}")
        jittered = exponential * (1.0 + self.settings.jitter_ratio * ((2.0 * unit) - 1.0))
        delay = round(max(0.0, jittered, retry_after_seconds or 0.0), 6)
        deadline_block = retryable and not exhausted and delay >= max(0.0, remaining_seconds)
        should_retry = retryable and not exhausted and not deadline_block
        if not retryable:
            reason = f"failure category {category.value} is not retryable"
        elif exhausted:
            reason = f"retry budget exhausted after failed attempt {failed_attempt}"
        elif deadline_block:
            reason = "retry delay would reach or exceed the run deadline"
        else:
            reason = "retry admitted by the unified reliability policy"
        schedule = RetrySchedule(
            failure_type,
            category,
            failed_attempt,
            self.settings.max_retries,
            should_retry,
            delay,
            retry_after_seconds,
            deadline_block,
            reason,
        )
        if self.events is not None:
            self.events.record("retry.scheduled" if should_retry else "retry.denied", schedule.mapping())
        return schedule

    def wait(self, schedule: RetrySchedule) -> None:
        if not schedule.should_retry:
            raise ValueError("cannot wait for a denied retry")
        if self._sleep is None:
            raise RuntimeError("RetryScheduler requires an injected sleeper at execution time")
        self._sleep(schedule.delay_seconds)
        if self.events is not None:
            self.events.record("retry.wait-completed", schedule.mapping())


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DegradationDecision:
    disposition: str
    missing_capabilities: tuple[str, ...]
    selected_fallbacks: Mapping[str, str]
    reason: str

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_DEGRADATION_DECISION_V1",
            "disposition": self.disposition,
            "missing_capabilities": list(self.missing_capabilities),
            "selected_fallbacks": dict(self.selected_fallbacks),
            "reason": self.reason,
        }


class DegradationPolicy:
    def __init__(self, capability_matrix: Mapping[str, Sequence[str]], *, events: ReliabilityEventLog):
        self.capability_matrix = {key: tuple(value) for key, value in capability_matrix.items()}
        self.events = events

    def decide(
        self,
        *,
        risk: RiskLevel,
        required_capabilities: Sequence[str],
        available_capabilities: Sequence[str],
        permission_granted: bool,
        uncertain_side_effects: bool,
    ) -> DegradationDecision:
        available = set(available_capabilities)
        missing = tuple(sorted(set(required_capabilities) - available))
        fallbacks: dict[str, str] = {}
        for capability in missing:
            candidate = next((item for item in self.capability_matrix.get(capability, ()) if item in available), None)
            if candidate is not None:
                fallbacks[capability] = candidate
        fail_closed = (
            risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            or not permission_granted
            or uncertain_side_effects
            or any(capability not in fallbacks for capability in missing)
        )
        if not missing:
            decision = DegradationDecision("full-capability", (), {}, "all required capabilities are available")
        elif fail_closed:
            decision = DegradationDecision(
                "fail-closed",
                missing,
                fallbacks,
                "risk, permission, uncertain side effects, or capability coverage forbids degradation",
            )
        else:
            decision = DegradationDecision("degraded", missing, fallbacks, "approved capability substitutions cover the low-risk gap")
        self.events.record("degradation.decided", decision.mapping())
        return decision


class CircuitOpenError(RuntimeError):
    pass


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclass(frozen=True)
class CircuitScope:
    provider: str
    tool: str
    profile: str

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.tool}/{self.profile}"


@dataclass
class _CircuitRecord:
    state: CircuitState = CircuitState.CLOSED
    failures: int = 0
    reopen_at: float = 0.0
    probe_in_flight: bool = False


class CircuitBreakerRegistry:
    def __init__(
        self,
        *,
        failure_threshold: int,
        cooldown_seconds: float,
        clock: Callable[[], float],
        events: ReliabilityEventLog,
    ):
        if failure_threshold < 1 or cooldown_seconds < 0:
            raise ValueError("circuit breaker threshold and cooldown are invalid")
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.clock = clock
        self.events = events
        self._records: dict[CircuitScope, _CircuitRecord] = {}
        self._lock = threading.RLock()

    def before_call(self, scope: CircuitScope) -> CircuitState:
        with self._lock:
            record = self._records.setdefault(scope, _CircuitRecord())
            now = self.clock()
            if record.state is CircuitState.OPEN and now >= record.reopen_at:
                record.state = CircuitState.HALF_OPEN
                record.probe_in_flight = False
                self.events.record("circuit.half-opened", {"scope": scope.key})
            if record.state is CircuitState.OPEN:
                raise CircuitOpenError(f"circuit is open for {scope.key}")
            if record.state is CircuitState.HALF_OPEN:
                if record.probe_in_flight:
                    raise CircuitOpenError(f"half-open probe already in flight for {scope.key}")
                record.probe_in_flight = True
                self.events.record("circuit.probe-authorized", {"scope": scope.key})
            return record.state

    def record_failure(self, scope: CircuitScope, *, category: FailureCategory) -> CircuitState:
        with self._lock:
            record = self._records.setdefault(scope, _CircuitRecord())
            record.failures += 1
            if record.state is CircuitState.HALF_OPEN or record.failures >= self.failure_threshold:
                record.state = CircuitState.OPEN
                record.reopen_at = self.clock() + self.cooldown_seconds
                record.probe_in_flight = False
            self.events.record(
                "circuit.failure-recorded",
                {"scope": scope.key, "category": category.value, "state": record.state.value, "failures": record.failures},
            )
            return record.state

    def record_success(self, scope: CircuitScope) -> CircuitState:
        with self._lock:
            record = self._records.setdefault(scope, _CircuitRecord())
            record.state = CircuitState.CLOSED
            record.failures = 0
            record.reopen_at = 0.0
            record.probe_in_flight = False
            self.events.record("circuit.closed", {"scope": scope.key})
            return record.state

    def state(self, scope: CircuitScope) -> CircuitState:
        with self._lock:
            return self._records.get(scope, _CircuitRecord()).state


@dataclass(frozen=True)
class RollbackOutcome:
    effect_id: str
    rollback_id: str
    status: str
    deduplicated: bool
    error_type: str | None = None

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROLLBACK_OUTCOME_V1",
            "effect_id": self.effect_id,
            "rollback_id": self.rollback_id,
            "status": self.status,
            "deduplicated": self.deduplicated,
            "error_type": self.error_type,
        }


class RollbackCoordinator:
    def __init__(self, events: ReliabilityEventLog):
        self.events = events
        self._lock = threading.RLock()

    def _prior(self, rollback_id: str) -> RollbackOutcome | None:
        for event in reversed(self.events.events()):
            payload = event["payload"]
            if event["event_type"] in {"rollback.succeeded", "rollback.failed"} and payload.get("rollback_id") == rollback_id:
                return RollbackOutcome(
                    str(payload["effect_id"]),
                    rollback_id,
                    str(payload["status"]),
                    True,
                    payload.get("error_type"),
                )
        return None

    def execute(self, *, effect_id: str, rollback_id: str, action: Callable[[], Any]) -> RollbackOutcome:
        with self._lock:
            prior = self._prior(rollback_id)
            if prior is not None:
                self.events.record("rollback.deduplicated", prior.mapping())
                return prior
            self.events.record("rollback.started", {"effect_id": effect_id, "rollback_id": rollback_id})
            try:
                action()
            except Exception as error:  # noqa: BLE001
                outcome = RollbackOutcome(effect_id, rollback_id, "failed", False, type(error).__name__)
                self.events.record("rollback.failed", outcome.mapping())
                return outcome
            outcome = RollbackOutcome(effect_id, rollback_id, "succeeded", False)
            self.events.record("rollback.succeeded", outcome.mapping())
            return outcome


@dataclass(frozen=True)
class DisasterRecoveryEvidence:
    backup_id: str
    manifest_hash: str
    restored: bool
    replayed_event_count: int
    writer_activated: bool


class DisasterRecoveryVerifier:
    def __init__(self, *, production_home: Path, events: ReliabilityEventLog):
        self.production_home = production_home.resolve(strict=False)
        self.events = events

    @staticmethod
    def _marked_disposable(path: Path) -> bool:
        resolved = path.resolve(strict=False)
        return any((parent / ".sitina-bplus-disposable-v1").is_file() for parent in (resolved, *resolved.parents))

    def verify(
        self,
        *,
        backup_id: str,
        manifest_hash: str,
        restored_path: Path,
        expected_event_count: int,
        replayed_events: Sequence[Mapping[str, Any]],
        writer_activated: bool,
    ) -> DisasterRecoveryEvidence:
        restored = restored_path.resolve(strict=False)
        replayed_event_count = len(replayed_events)
        if restored == self.production_home or self.production_home in restored.parents or not self._marked_disposable(restored):
            raise ValueError("DR verification target must be an isolated disposable copy")
        if (
            writer_activated
            or replayed_event_count != expected_event_count
            or any(not isinstance(event, Mapping) or not event.get("event_id") for event in replayed_events)
        ):
            raise ValueError("DR restore/replay evidence is incomplete or activated a writer")
        evidence = DisasterRecoveryEvidence(backup_id, manifest_hash, True, replayed_event_count, False)
        self.events.record("dr.restore-replay-verified", evidence.__dict__)
        return evidence


@dataclass(frozen=True)
class ComponentHealth:
    component: str
    live: bool
    ready: bool
    diagnostic: str


@dataclass(frozen=True)
class HealthReport:
    liveness: str
    readiness: str
    components: tuple[ComponentHealth, ...]

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_HEALTH_REPORT_V1",
            "liveness": self.liveness,
            "readiness": self.readiness,
            "components": [item.__dict__ for item in self.components],
        }


class HealthService:
    REQUIRED_COMPONENTS = ("provider", "journal", "cas", "projection", "queue", "config")

    def __init__(self, probes: Mapping[str, Callable[[], Mapping[str, Any]]], *, events: ReliabilityEventLog):
        self.probes = dict(probes)
        self.events = events

    def check(self) -> HealthReport:
        results: list[ComponentHealth] = []
        for component in self.REQUIRED_COMPONENTS:
            probe = self.probes.get(component)
            if probe is None:
                results.append(ComponentHealth(component, False, False, "probe is not configured"))
                continue
            try:
                raw = dict(probe())
                boundary = redact_boundary_value(str(raw.get("diagnostic", "ok")), boundary="log")
                results.append(ComponentHealth(component, bool(raw.get("live")), bool(raw.get("ready")), str(boundary.value)[:300]))
            except Exception as error:  # noqa: BLE001
                safe = redact_boundary_value(str(error), boundary="log").value
                results.append(ComponentHealth(component, False, False, str(safe)[:300]))
        report = HealthReport(
            "alive" if all(item.live for item in results) else "dead",
            "ready" if all(item.ready for item in results) else "not-ready",
            tuple(results),
        )
        self.events.record("health.checked", report.mapping())
        return report


@dataclass(frozen=True)
class PartialSuccess:
    run_id: str
    status: str
    completed: tuple[str, ...]
    failed: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    next_steps: tuple[str, ...]

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_PARTIAL_SUCCESS_V1",
            "run_id": self.run_id,
            "status": self.status,
            "completed": list(self.completed),
            "failed": list(self.failed),
            "missing_capabilities": list(self.missing_capabilities),
            "next_steps": list(self.next_steps),
        }


def build_partial_success(
    *,
    run_id: str,
    completed: Sequence[str],
    failed: Sequence[str],
    missing_capabilities: Sequence[str],
    next_steps: Sequence[str],
) -> PartialSuccess:
    incomplete = bool(failed or missing_capabilities)
    if incomplete and not next_steps:
        raise ValueError("partial success requires an actionable next step")
    return PartialSuccess(
        run_id,
        "partial-success" if incomplete else "success",
        tuple(completed),
        tuple(failed),
        tuple(missing_capabilities),
        tuple(next_steps),
    )


@dataclass(frozen=True)
class FailureNotification:
    notification_id: str
    run_id: str
    user_reason: str
    retryable: bool
    safe_advice: str
    deduplicated: bool

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_FAILURE_NOTIFICATION_V1",
            "notification_id": self.notification_id,
            "run_id": self.run_id,
            "user_reason": self.user_reason,
            "retryable": self.retryable,
            "safe_advice": self.safe_advice,
            "deduplicated": self.deduplicated,
        }


class FailureNotifier:
    _REASONS = {
        FailureCategory.TRANSIENT: "A temporary service or network problem interrupted this run.",
        FailureCategory.QUOTA: "A service limit temporarily prevented this run from continuing.",
        FailureCategory.AUTH: "This run does not currently have valid access for the requested operation.",
        FailureCategory.SCHEMA: "A response did not match the required data format.",
        FailureCategory.SAFETY: "A safety or policy check blocked the requested operation.",
        FailureCategory.CANCELLED: "The run was cancelled before it completed.",
        FailureCategory.PERMANENT: "The requested operation cannot complete with the current inputs.",
        FailureCategory.UNKNOWN: "The run stopped because of an unclassified failure.",
    }

    def __init__(self, events: ReliabilityEventLog):
        self.events = events

    def notify(self, failure: FailureEnvelope) -> FailureNotification:
        fingerprint = hashlib.sha256(
            f"{failure.run_id}:{failure.failure_type}:{failure.stage}:{failure.category.value}".encode("utf-8")
        ).hexdigest()
        for event in self.events.events("failure.notification-sent"):
            if event["payload"].get("fingerprint") == fingerprint:
                original = event["payload"]
                return FailureNotification(
                    str(original["notification_id"]),
                    failure.run_id,
                    str(original["user_reason"]),
                    bool(original["retryable"]),
                    str(original["safe_advice"]),
                    True,
                )
        notification = FailureNotification(
            "notification-" + fingerprint[:20],
            failure.run_id,
            self._REASONS[failure.category],
            failure.retryable,
            "Retry later using the same run ID." if failure.retryable else "Review access, inputs, and policy before starting a new run.",
            False,
        )
        self.events.record("failure.notification-sent", notification.mapping() | {"fingerprint": fingerprint})
        return notification
