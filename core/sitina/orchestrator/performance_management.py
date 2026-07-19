from __future__ import annotations

import json
import os
import platform
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.schemas.models import StrictModel
from sitina.utils import load_json_yaml, sha256_bytes, sha256_text, stable_json


class PerformancePolicyError(ValueError):
    pass


class PerformancePolicy:
    REQUIRED_SECTIONS = {"token_budget", "concurrency", "provider_cache", "benchmark", "resource_pool"}

    def __init__(self, value: Mapping[str, Any]):
        self.value = dict(value)
        self.validate()

    @classmethod
    def load(cls, home: Path = SITINA_HOME) -> "PerformancePolicy":
        path = Path(home) / "config" / "performance_policy.json"
        if not path.exists():
            raise PerformancePolicyError("performance policy missing")
        value = load_json_yaml(path)
        if not isinstance(value, dict):
            raise PerformancePolicyError("performance policy must be an object")
        return cls(value)

    def validate(self) -> None:
        if self.value.get("schema") != "SITINA_PERFORMANCE_POLICY_V1" or self.value.get("version") != "1.0":
            raise PerformancePolicyError("performance policy schema/version mismatch")
        missing = self.REQUIRED_SECTIONS - set(self.value)
        if missing:
            raise PerformancePolicyError(f"performance policy sections missing: {sorted(missing)}")
        try:
            budget = self.value["token_budget"]
            concurrency = self.value["concurrency"]
            cache = self.value["provider_cache"]
            benchmark = self.value["benchmark"]
            pool = self.value["resource_pool"]
            if int(budget["default_run_limit"]) <= 0 or budget["missing_usage_state"] != "unsettled":
                raise PerformancePolicyError("token budget defaults are invalid")
            for name in ("global_limit", "run_limit", "provider_limit", "tool_limit", "backpressure_timeout_ms"):
                if int(concurrency[name]) <= 0:
                    raise PerformancePolicyError(f"concurrency {name} must be positive")
            required = {"tenant_id", "model", "prompt_hash", "tools_hash", "policy_hash", "permission_hash"}
            if set(cache["required_bindings"]) != required or int(cache["default_ttl_seconds"]) <= 0:
                raise PerformancePolicyError("provider cache bindings or TTL are invalid")
            if int(benchmark["warmup_iterations"]) < 0 or int(benchmark["measurement_iterations"]) < 1:
                raise PerformancePolicyError("benchmark iteration counts are invalid")
            if tuple(benchmark["quantiles"]) != (50, 95) or int(pool["default_ttl_seconds"]) <= 0:
                raise PerformancePolicyError("benchmark quantiles or resource-pool TTL are invalid")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, PerformancePolicyError):
                raise
            raise PerformancePolicyError(f"performance policy value invalid: {exc}") from exc


BudgetScope = Literal["run", "stage", "agent", "tool"]


class BudgetNode(StrictModel):
    scope_id: str
    scope: BudgetScope
    parent_scope_id: str | None = None
    maximum_tokens: int = Field(gt=0)


class TokenUsage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def total_is_complete(self) -> "TokenUsage":
        if self.total_tokens < self.input_tokens + self.output_tokens:
            raise ValueError("total token usage cannot be less than input plus output")
        return self


class BudgetReservation(StrictModel):
    reservation_id: str
    leaf_scope_id: str
    path: tuple[str, ...]
    reserved_tokens: int = Field(gt=0)
    state: Literal["reserved", "settled", "refunded", "unsettled"] = "reserved"
    usage: TokenUsage | None = None


class BudgetNodeSnapshot(StrictModel):
    scope_id: str
    scope: BudgetScope
    maximum_tokens: int
    used_tokens: int
    reserved_tokens: int
    remaining_tokens: int
    unsettled_reservations: int


class BudgetSnapshot(StrictModel):
    schema_id: Literal["SITINA_HIERARCHICAL_BUDGET_SNAPSHOT_V1"] = Field(
        default="SITINA_HIERARCHICAL_BUDGET_SNAPSHOT_V1", alias="schema"
    )
    nodes: tuple[BudgetNodeSnapshot, ...]
    hard_limit_enforced: Literal[True] = True


class BudgetExceededError(RuntimeError):
    pass


class HierarchicalTokenBudget:
    """Atomic reservation accounting shared by run, stage, agent, and tool scopes."""

    def __init__(self, nodes: Sequence[BudgetNode]):
        if not nodes or len({item.scope_id for item in nodes}) != len(nodes):
            raise ValueError("budget nodes must be non-empty and unique")
        self.nodes = {item.scope_id: item for item in nodes}
        roots = [item for item in nodes if item.parent_scope_id is None]
        if len(roots) != 1 or roots[0].scope != "run":
            raise ValueError("budget hierarchy requires exactly one run root")
        for node in nodes:
            if node.parent_scope_id is not None and node.parent_scope_id not in self.nodes:
                raise ValueError("budget hierarchy contains an orphan")
            expected_parent = {"run": None, "stage": "run", "agent": "stage", "tool": "stage"}[node.scope]
            actual_parent = None if node.parent_scope_id is None else self.nodes[node.parent_scope_id].scope
            if actual_parent != expected_parent:
                raise ValueError(f"invalid parent scope for {node.scope}:{node.scope_id}")
        for node in nodes:
            self._path(node.scope_id)
        self._used: dict[str, int] = defaultdict(int)
        self._reserved: dict[str, int] = defaultdict(int)
        self._reservations: dict[str, BudgetReservation] = {}
        self._lock = threading.RLock()

    def _path(self, leaf_scope_id: str) -> tuple[str, ...]:
        path: list[str] = []
        seen: set[str] = set()
        cursor: str | None = leaf_scope_id
        while cursor is not None:
            if cursor in seen or cursor not in self.nodes:
                raise ValueError("budget hierarchy contains a cycle or unknown scope")
            seen.add(cursor)
            path.append(cursor)
            cursor = self.nodes[cursor].parent_scope_id
        return tuple(reversed(path))

    def reserve(self, reservation_id: str, *, leaf_scope_id: str, tokens: int) -> BudgetReservation:
        if not reservation_id or tokens <= 0:
            raise ValueError("reservation identity and tokens are required")
        with self._lock:
            if reservation_id in self._reservations:
                raise ValueError("duplicate budget reservation")
            path = self._path(leaf_scope_id)
            for scope_id in path:
                node = self.nodes[scope_id]
                if self._used[scope_id] + self._reserved[scope_id] + tokens > node.maximum_tokens:
                    raise BudgetExceededError(f"token budget exceeded at {node.scope}:{scope_id}")
            reservation = BudgetReservation(
                reservation_id=reservation_id,
                leaf_scope_id=leaf_scope_id,
                path=path,
                reserved_tokens=tokens,
            )
            self._reservations[reservation_id] = reservation
            for scope_id in path:
                self._reserved[scope_id] += tokens
            return reservation

    def settle(self, reservation_id: str, usage: TokenUsage | None) -> BudgetReservation:
        with self._lock:
            current = self._reservations[reservation_id]
            if current.state not in {"reserved", "unsettled"}:
                raise ValueError("only a reserved or unsettled budget can be settled")
            if usage is None:
                if current.state == "unsettled":
                    return current
                unresolved = current.model_copy(update={"state": "unsettled"})
                self._reservations[reservation_id] = unresolved
                return unresolved
            actual = usage.total_tokens
            for scope_id in current.path:
                projected = self._used[scope_id] + self._reserved[scope_id] - current.reserved_tokens + actual
                if projected > self.nodes[scope_id].maximum_tokens:
                    unresolved = current.model_copy(update={"state": "unsettled"})
                    self._reservations[reservation_id] = unresolved
                    raise BudgetExceededError(f"settled usage exceeds hard limit at {scope_id}")
            for scope_id in current.path:
                self._reserved[scope_id] -= current.reserved_tokens
                self._used[scope_id] += actual
            settled = current.model_copy(update={"state": "settled", "usage": usage})
            self._reservations[reservation_id] = settled
            return settled

    def refund(self, reservation_id: str) -> BudgetReservation:
        with self._lock:
            current = self._reservations[reservation_id]
            if current.state not in {"reserved", "unsettled"}:
                raise ValueError("only reserved or unsettled budgets can be refunded")
            for scope_id in current.path:
                self._reserved[scope_id] -= current.reserved_tokens
            refunded = current.model_copy(update={"state": "refunded"})
            self._reservations[reservation_id] = refunded
            return refunded

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            nodes = []
            for scope_id in sorted(self.nodes):
                node = self.nodes[scope_id]
                unsettled = sum(
                    item.state == "unsettled" and scope_id in item.path for item in self._reservations.values()
                )
                nodes.append(
                    BudgetNodeSnapshot(
                        scope_id=scope_id,
                        scope=node.scope,
                        maximum_tokens=node.maximum_tokens,
                        used_tokens=self._used[scope_id],
                        reserved_tokens=self._reserved[scope_id],
                        remaining_tokens=node.maximum_tokens - self._used[scope_id] - self._reserved[scope_id],
                        unsettled_reservations=unsettled,
                    )
                )
            return BudgetSnapshot(nodes=tuple(nodes))


AttemptKind = Literal["initial", "retry", "fallback", "cache_hit"]


class AttemptCostRecord(StrictModel):
    run_id: str
    stage_id: str
    agent_id: str
    logical_call_id: str
    physical_attempt_id: str | None
    attempt: int = Field(ge=0)
    kind: AttemptKind
    usage: TokenUsage | None
    cost_micro_usd: int = Field(ge=0)
    latency_ms: int = Field(ge=0)

    @model_validator(mode="after")
    def cache_and_attempt_identity_agree(self) -> "AttemptCostRecord":
        if self.kind == "cache_hit" and self.physical_attempt_id is not None:
            raise ValueError("cache hits cannot claim a physical provider attempt")
        if self.kind != "cache_hit" and not self.physical_attempt_id:
            raise ValueError("provider attempts require a physical attempt identity")
        return self


class CostAttributionSummary(StrictModel):
    schema_id: Literal["SITINA_COST_ATTRIBUTION_V1"] = Field(default="SITINA_COST_ATTRIBUTION_V1", alias="schema")
    run_id: str
    logical_call_count: int
    physical_attempt_count: int
    retry_attempt_count: int
    fallback_attempt_count: int
    cache_hit_count: int
    unsettled_attempt_count: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    total_tokens: int
    cost_micro_usd: int
    latency_ms: int
    by_stage: dict[str, dict[str, int]]
    by_agent: dict[str, dict[str, int]]
    by_logical_call: dict[str, dict[str, int]]


class CostAttributionLedger:
    def __init__(self) -> None:
        self._records: list[AttemptCostRecord] = []
        self._physical_attempt_ids: set[str] = set()
        self._lock = threading.Lock()

    def record(self, item: AttemptCostRecord) -> None:
        with self._lock:
            if item.physical_attempt_id and item.physical_attempt_id in self._physical_attempt_ids:
                raise ValueError("duplicate physical provider attempt")
            if item.physical_attempt_id:
                self._physical_attempt_ids.add(item.physical_attempt_id)
            self._records.append(item)

    @staticmethod
    def _totals(records: Iterable[AttemptCostRecord]) -> dict[str, int]:
        items = tuple(records)
        usages = tuple(item.usage for item in items if item.usage is not None)
        return {
            "physical_attempts": sum(item.physical_attempt_id is not None for item in items),
            "input_tokens": sum(item.input_tokens for item in usages),
            "output_tokens": sum(item.output_tokens for item in usages),
            "cache_read_tokens": sum(item.cache_read_tokens for item in usages),
            "cache_write_tokens": sum(item.cache_write_tokens for item in usages),
            "total_tokens": sum(item.total_tokens for item in usages),
            "cost_micro_usd": sum(item.cost_micro_usd for item in items),
            "latency_ms": sum(item.latency_ms for item in items),
            "unsettled_attempts": sum(item.usage is None and item.physical_attempt_id is not None for item in items),
        }

    def summarize(self, run_id: str) -> CostAttributionSummary:
        with self._lock:
            records = tuple(item for item in self._records if item.run_id == run_id)
        totals = self._totals(records)

        def grouped(field: str) -> dict[str, dict[str, int]]:
            keys = sorted({str(getattr(item, field)) for item in records})
            return {key: self._totals(item for item in records if str(getattr(item, field)) == key) for key in keys}

        return CostAttributionSummary(
            run_id=run_id,
            logical_call_count=len({item.logical_call_id for item in records}),
            physical_attempt_count=totals["physical_attempts"],
            retry_attempt_count=sum(item.kind == "retry" for item in records),
            fallback_attempt_count=sum(item.kind == "fallback" for item in records),
            cache_hit_count=sum(item.kind == "cache_hit" for item in records),
            unsettled_attempt_count=totals["unsettled_attempts"],
            input_tokens=totals["input_tokens"],
            output_tokens=totals["output_tokens"],
            cache_read_tokens=totals["cache_read_tokens"],
            cache_write_tokens=totals["cache_write_tokens"],
            total_tokens=totals["total_tokens"],
            cost_micro_usd=totals["cost_micro_usd"],
            latency_ms=totals["latency_ms"],
            by_stage=grouped("stage_id"),
            by_agent=grouped("agent_id"),
            by_logical_call=grouped("logical_call_id"),
        )


class CacheBinding(StrictModel):
    tenant_id: str
    model: str
    prompt_hash: str
    tools_hash: str
    policy_hash: str
    permission_hash: str

    @classmethod
    def from_request(
        cls,
        *,
        tenant_id: str,
        model: str,
        prompt: str,
        tools: Any,
        policy: Any,
        permissions: Any,
    ) -> "CacheBinding":
        return cls(
            tenant_id=tenant_id,
            model=model,
            prompt_hash=sha256_text(prompt),
            tools_hash=sha256_text(stable_json(tools)),
            policy_hash=sha256_text(stable_json(policy)),
            permission_hash=sha256_text(stable_json(permissions)),
        )


class CacheLookup(StrictModel):
    hit: bool
    response: dict[str, Any] | None = None
    usage_source: Literal["cache_hit", "new_physical_call", "new_physical_call_required"]
    cache_hit_count: int
    new_physical_call_count: int


@dataclass(frozen=True)
class _EncryptedCacheEntry:
    binding: CacheBinding
    nonce: bytes
    ciphertext: bytes
    expires_at_epoch: int


class SecureProviderCache:
    def __init__(self, encryption_key: bytes, *, default_ttl_seconds: int = 300):
        if len(encryption_key) not in {16, 24, 32} or default_ttl_seconds <= 0:
            raise ValueError("cache encryption key or TTL is invalid")
        self._cipher = AESGCM(encryption_key)
        self.default_ttl_seconds = default_ttl_seconds
        self._entries: dict[str, _EncryptedCacheEntry] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(binding: CacheBinding) -> str:
        return sha256_text(stable_json(binding.model_dump()))

    def put(
        self,
        binding: CacheBinding,
        response: Mapping[str, Any],
        *,
        deterministic: bool,
        side_effect_free: bool,
        response_complete: bool,
        now_epoch: int,
        ttl_seconds: int | None = None,
    ) -> bool:
        if not deterministic or not side_effect_free or not response_complete:
            return False
        if not all(binding.model_dump().values()):
            raise ValueError("cache binding is incomplete")
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValueError("cache TTL must be positive")
        key = self._key(binding)
        nonce = os.urandom(12)
        plaintext = stable_json(dict(response)).encode("utf-8")
        ciphertext = self._cipher.encrypt(nonce, plaintext, key.encode("utf-8"))
        with self._lock:
            self._entries[key] = _EncryptedCacheEntry(binding, nonce, ciphertext, now_epoch + ttl)
        return True

    def get(self, binding: CacheBinding, *, now_epoch: int) -> CacheLookup:
        key = self._key(binding)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and now_epoch >= entry.expires_at_epoch:
                self._entries.pop(key, None)
                entry = None
        if entry is None:
            return CacheLookup(hit=False, usage_source="new_physical_call_required", cache_hit_count=0, new_physical_call_count=1)
        plaintext = self._cipher.decrypt(entry.nonce, entry.ciphertext, key.encode("utf-8"))
        return CacheLookup(
            hit=True,
            response=json.loads(plaintext),
            usage_source="cache_hit",
            cache_hit_count=1,
            new_physical_call_count=0,
        )

    def invalidate(self, *, tenant_id: str | None = None, policy_hash: str | None = None) -> int:
        with self._lock:
            selected = [
                key
                for key, entry in self._entries.items()
                if (tenant_id is None or entry.binding.tenant_id == tenant_id)
                and (policy_hash is None or entry.binding.policy_hash == policy_hash)
            ]
            for key in selected:
                self._entries.pop(key, None)
            return len(selected)

    def get_or_compute(
        self,
        binding: CacheBinding,
        producer: Callable[[], Mapping[str, Any]],
        *,
        deterministic: bool,
        side_effect_free: bool,
        now_epoch: int,
    ) -> CacheLookup:
        if not deterministic or not side_effect_free:
            raise ValueError("concurrent cache fill requires a deterministic side-effect-free request")
        with self._lock:
            existing = self.get(binding, now_epoch=now_epoch)
            if existing.hit:
                return existing
            response = dict(producer())
            self.put(
                binding,
                response,
                deterministic=True,
                side_effect_free=True,
                response_complete=True,
                now_epoch=now_epoch,
            )
            return CacheLookup(
                hit=False,
                response=response,
                usage_source="new_physical_call",
                cache_hit_count=0,
                new_physical_call_count=1,
            )

    def encrypted_fingerprints(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(sha256_bytes(item.ciphertext) for item in self._entries.values()))

    def encrypted_payloads(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(item.ciphertext for _key, item in sorted(self._entries.items()))


class BatchRequest(StrictModel):
    request_id: str
    idempotency_key: str
    provider: str
    model: str
    tenant_id: str
    policy_hash: str
    permission_hash: str
    compatibility_key: str
    payload: dict[str, Any]


class BatchResponse(StrictModel):
    request_id: str
    status: Literal["ok", "error"]
    usage: TokenUsage | None = None
    error_code: str | None = None


class BatchDispatchReport(StrictModel):
    batch_used: bool
    batch_calls: int
    individual_calls: int
    responses: tuple[BatchResponse, ...]


class ProviderBatchDispatcher:
    def __init__(self, capabilities: Mapping[str, bool]):
        self.capabilities = dict(capabilities)

    @staticmethod
    def _compatible(requests: Sequence[BatchRequest]) -> bool:
        fields = ("provider", "model", "tenant_id", "policy_hash", "permission_hash", "compatibility_key")
        return all(len({getattr(item, field) for item in requests}) == 1 for field in fields)

    def dispatch(
        self,
        requests: Sequence[BatchRequest],
        *,
        send_batch: Callable[[tuple[BatchRequest, ...]], Sequence[BatchResponse]],
        send_one: Callable[[BatchRequest], BatchResponse],
    ) -> BatchDispatchReport:
        items = tuple(requests)
        if not items:
            return BatchDispatchReport(batch_used=False, batch_calls=0, individual_calls=0, responses=())
        if len({item.request_id for item in items}) != len(items) or len({item.idempotency_key for item in items}) != len(items):
            raise ValueError("batch request and idempotency identities must be unique")
        supported = bool(self.capabilities.get(items[0].provider))
        if supported and self._compatible(items):
            responses = tuple(send_batch(items))
            if {item.request_id for item in responses} != {item.request_id for item in items}:
                raise ValueError("batch response identities do not match requests")
            by_id = {item.request_id: item for item in responses}
            ordered = tuple(by_id[item.request_id] for item in items)
            return BatchDispatchReport(batch_used=True, batch_calls=1, individual_calls=0, responses=ordered)
        responses = tuple(send_one(item) for item in items)
        if tuple(item.request_id for item in responses) != tuple(item.request_id for item in items):
            raise ValueError("individual response identities do not match requests")
        return BatchDispatchReport(batch_used=False, batch_calls=0, individual_calls=len(items), responses=responses)


class CriticalPathStage(StrictModel):
    stage_id: str
    duration_ns: int = Field(ge=0)
    queue_wait_ns: int = Field(default=0, ge=0)
    physical_calls: int = Field(default=0, ge=0)
    depends_on: tuple[str, ...] = ()
    parallelizable: bool = False
    reusable: bool = False


class CriticalPathPlan(StrictModel):
    critical_path: tuple[str, ...]
    total_duration_ns: int
    bottleneck_stage: str
    action: Literal["parallelize", "reuse", "measure_only"]
    estimated_physical_calls_saved: int


class CriticalPathAnalyzer:
    def analyze(self, stages: Sequence[CriticalPathStage]) -> CriticalPathPlan:
        by_id = {item.stage_id: item for item in stages}
        if not by_id or len(by_id) != len(stages):
            raise ValueError("critical-path stages must be non-empty and unique")
        visiting: set[str] = set()
        totals: dict[str, int] = {}
        predecessors: dict[str, str | None] = {}

        def visit(stage_id: str) -> int:
            if stage_id in totals:
                return totals[stage_id]
            if stage_id in visiting or stage_id not in by_id:
                raise ValueError("critical-path graph contains a cycle or orphan")
            visiting.add(stage_id)
            stage = by_id[stage_id]
            parent_totals = [(visit(parent), parent) for parent in stage.depends_on]
            parent_total, parent_id = max(parent_totals, default=(0, None), key=lambda item: (item[0], item[1] or ""))
            visiting.remove(stage_id)
            totals[stage_id] = parent_total + stage.duration_ns + stage.queue_wait_ns
            predecessors[stage_id] = parent_id
            return totals[stage_id]

        for stage_id in sorted(by_id):
            visit(stage_id)
        terminal = max(totals, key=lambda item: (totals[item], item))
        path: list[str] = []
        cursor: str | None = terminal
        while cursor is not None:
            path.append(cursor)
            cursor = predecessors[cursor]
        path.reverse()
        candidates = [by_id[item] for item in path]
        bottleneck = max(candidates, key=lambda item: (item.duration_ns + item.queue_wait_ns, item.stage_id))
        action: Literal["parallelize", "reuse", "measure_only"] = "measure_only"
        if bottleneck.reusable:
            action = "reuse"
        elif bottleneck.parallelizable:
            action = "parallelize"
        return CriticalPathPlan(
            critical_path=tuple(path),
            total_duration_ns=totals[terminal],
            bottleneck_stage=bottleneck.stage_id,
            action=action,
            estimated_physical_calls_saved=bottleneck.physical_calls if action in {"parallelize", "reuse"} else 0,
        )


class BenchmarkObservation(StrictModel):
    duration_ns: int = Field(ge=0)
    physical_calls: int = Field(ge=0)
    resource_units: int = Field(ge=0)
    output_hash: str
    error_code: str | None = None


class BenchmarkReport(StrictModel):
    schema_id: Literal["SITINA_REPEATABLE_BENCHMARK_V1"] = Field(default="SITINA_REPEATABLE_BENCHMARK_V1", alias="schema")
    label: str
    environment: dict[str, str]
    warmup_iterations: int
    measurement_iterations: int
    sample_count: int
    p50_duration_ns: int
    p95_duration_ns: int
    total_duration_ns: int
    throughput_per_second_milli: int
    error_count: int
    error_rate_ppm: int
    physical_call_count: int
    peak_resource_units: int
    output_hashes: tuple[str, ...]


class BenchmarkComparison(StrictModel):
    output_equivalent: bool
    latency_improved: bool
    throughput_improved: bool
    physical_calls_not_increased: bool
    resources_not_increased: bool
    accepted: bool


class RepeatableBenchmark:
    @staticmethod
    def environment() -> dict[str, str]:
        return {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.machine(),
        }

    @staticmethod
    def _quantile(values: Sequence[int], percentile: int) -> int:
        if not values:
            return 0
        ordered = sorted(values)
        index = max(0, (len(ordered) * percentile + 99) // 100 - 1)
        return ordered[min(index, len(ordered) - 1)]

    def measure(
        self,
        label: str,
        operation: Callable[[], tuple[Any, int] | tuple[Any, int, int]],
        *,
        warmup_iterations: int,
        measurement_iterations: int,
        clock_ns: Callable[[], int] = time.perf_counter_ns,
        environment: Mapping[str, str] | None = None,
    ) -> BenchmarkReport:
        if warmup_iterations < 0 or measurement_iterations < 1:
            raise ValueError("benchmark iterations are invalid")
        for _ in range(warmup_iterations):
            operation()
        observations: list[BenchmarkObservation] = []
        for _ in range(measurement_iterations):
            started = clock_ns()
            try:
                operation_result = operation()
                if len(operation_result) == 2:
                    output, physical_calls = operation_result
                    resource_units = physical_calls
                else:
                    output, physical_calls, resource_units = operation_result
                error_code = None
                output_hash = sha256_text(stable_json(output))
            except Exception as exc:  # noqa: BLE001 - benchmark records controlled operation failure
                physical_calls = int(getattr(exc, "physical_calls", 0))
                resource_units = int(getattr(exc, "resource_units", 0))
                error_code = type(exc).__name__
                output_hash = sha256_text(stable_json({"error_code": error_code}))
            observations.append(
                BenchmarkObservation(
                    duration_ns=max(0, clock_ns() - started),
                    physical_calls=physical_calls,
                    resource_units=resource_units,
                    output_hash=output_hash,
                    error_code=error_code,
                )
            )
        durations = [item.duration_ns for item in observations]
        total_duration = sum(durations)
        errors = sum(item.error_code is not None for item in observations)
        return BenchmarkReport(
            label=label,
            environment=dict(sorted((environment or self.environment()).items())),
            warmup_iterations=warmup_iterations,
            measurement_iterations=measurement_iterations,
            sample_count=len(observations),
            p50_duration_ns=self._quantile(durations, 50),
            p95_duration_ns=self._quantile(durations, 95),
            total_duration_ns=total_duration,
            throughput_per_second_milli=(len(observations) * 1_000_000_000_000 // total_duration) if total_duration else 0,
            error_count=errors,
            error_rate_ppm=errors * 1_000_000 // len(observations),
            physical_call_count=sum(item.physical_calls for item in observations),
            peak_resource_units=max((item.resource_units for item in observations), default=0),
            output_hashes=tuple(sorted(set(item.output_hash for item in observations))),
        )

    @staticmethod
    def compare(baseline: BenchmarkReport, candidate: BenchmarkReport) -> BenchmarkComparison:
        equivalent = baseline.output_hashes == candidate.output_hashes and baseline.error_count == candidate.error_count == 0
        latency = (
            candidate.p50_duration_ns < baseline.p50_duration_ns
            and candidate.p95_duration_ns < baseline.p95_duration_ns
        )
        calls = candidate.physical_call_count <= baseline.physical_call_count
        throughput = candidate.throughput_per_second_milli > baseline.throughput_per_second_milli
        resources = candidate.peak_resource_units <= baseline.peak_resource_units
        return BenchmarkComparison(
            output_equivalent=equivalent,
            latency_improved=latency,
            throughput_improved=throughput,
            physical_calls_not_increased=calls,
            resources_not_increased=resources,
            accepted=equivalent and latency and throughput and calls and resources,
        )


@dataclass(frozen=True)
class PooledResourceLease:
    lease_id: str
    resource_id: str
    tenant_id: str
    provider_profile: str
    credential_fingerprint: str
    generation: int
    expires_at_epoch: int
    resource: Any


@dataclass
class _PooledResource:
    resource_id: str
    generation: int
    expires_at_epoch: int
    resource: Any
    close: Callable[[Any], None]
    in_use: int = 0


class IsolatedResourcePool:
    """Thread-safe pool isolated by tenant, profile, and credential fingerprint."""

    def __init__(self, *, default_ttl_seconds: int = 300):
        if default_ttl_seconds <= 0:
            raise ValueError("resource pool TTL must be positive")
        self.default_ttl_seconds = default_ttl_seconds
        self._entries: dict[tuple[str, str, str], _PooledResource] = {}
        self._generation = 0
        self._lease_counter = 0
        self._lock = threading.RLock()

    @staticmethod
    def _credential_fingerprint(reference: str) -> str:
        if not reference:
            raise ValueError("credential reference is required")
        return sha256_text(reference)

    def checkout(
        self,
        *,
        tenant_id: str,
        provider_profile: str,
        credential_reference: str,
        now_epoch: int,
        factory: Callable[[], Any],
        close: Callable[[Any], None],
        ttl_seconds: int | None = None,
    ) -> PooledResourceLease:
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if not tenant_id or not provider_profile or ttl <= 0:
            raise ValueError("pool identity and TTL are required")
        fingerprint = self._credential_fingerprint(credential_reference)
        key = (tenant_id, provider_profile, fingerprint)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and now_epoch >= entry.expires_at_epoch:
                if entry.in_use:
                    raise TimeoutError("expired pooled resource is still in use")
                entry.close(entry.resource)
                self._entries.pop(key, None)
                entry = None
            if entry is None:
                self._generation += 1
                resource_id = "resource-" + sha256_text(f"{key}:{self._generation}").split(":", 1)[-1][:20]
                entry = _PooledResource(resource_id, self._generation, now_epoch + ttl, factory(), close)
                self._entries[key] = entry
            entry.in_use += 1
            self._lease_counter += 1
            lease_id = f"lease-{self._lease_counter}"
            return PooledResourceLease(
                lease_id,
                entry.resource_id,
                tenant_id,
                provider_profile,
                fingerprint,
                entry.generation,
                entry.expires_at_epoch,
                entry.resource,
            )

    def release(self, lease: PooledResourceLease, *, failed: bool = False, now_epoch: int | None = None) -> None:
        key = (lease.tenant_id, lease.provider_profile, lease.credential_fingerprint)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.generation != lease.generation or entry.in_use <= 0:
                raise ValueError("unknown or already released resource lease")
            entry.in_use -= 1
            expired = now_epoch is not None and now_epoch >= entry.expires_at_epoch
            if failed or expired:
                if entry.in_use:
                    raise RuntimeError("cannot evict a pooled resource while another lease is active")
                entry.close(entry.resource)
                self._entries.pop(key, None)

    def close(self) -> int:
        with self._lock:
            if any(item.in_use for item in self._entries.values()):
                raise RuntimeError("cannot close resource pool with active leases")
            entries = tuple(self._entries.values())
            self._entries.clear()
        for entry in entries:
            entry.close(entry.resource)
        return len(entries)

    def isolation_fingerprints(self) -> tuple[tuple[str, str, str], ...]:
        with self._lock:
            return tuple(sorted(self._entries))


class RuntimeCostSnapshot(StrictModel):
    schema_id: Literal["SITINA_RUNTIME_COST_SNAPSHOT_V1"] = Field(default="SITINA_RUNTIME_COST_SNAPSHOT_V1", alias="schema")
    run_id: str
    used_tokens: int
    reserved_tokens: int
    remaining_tokens: int
    forecast_total_tokens: int
    predicted_to_exceed: bool
    hard_stop: bool
    unsettled_usage_count: int
    data_freshness: str | None
    source: Literal["run_ledger"] = "run_ledger"
    read_only: Literal[True] = True


class RuntimeCostMonitor:
    @staticmethod
    def snapshot(
        run_id: str,
        events: Sequence[Mapping[str, Any]],
        *,
        hard_limit_tokens: int,
        forecast_additional_tokens: int = 0,
    ) -> RuntimeCostSnapshot:
        if hard_limit_tokens <= 0 or forecast_additional_tokens < 0:
            raise ValueError("cost monitor limits are invalid")
        used = 0
        unsettled = 0
        reservations: dict[str, int] = {}
        timestamps: list[str] = []
        for source in events:
            item = dict(source)
            payload = item.get("payload_json") if isinstance(item.get("payload_json"), dict) else {}
            if (item.get("run_id") or payload.get("run_id")) != run_id:
                continue
            event_type = str(item.get("event_type") or "")
            timestamp = str(item.get("timestamp") or item.get("_recorded_ts") or "")
            if timestamp:
                timestamps.append(timestamp)
            if event_type in {"provider_http_attempt_completed", "provider_http_attempt_failed"}:
                usage = payload.get("token_usage")
                if isinstance(usage, dict):
                    input_tokens = max(0, int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0))
                    output_tokens = max(0, int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0))
                    used += max(0, int(usage.get("total_tokens", input_tokens + output_tokens) or 0))
                else:
                    unsettled += 1
            reservation_id = str(payload.get("reservation_id") or "")
            if event_type == "token_budget_reserved" and reservation_id:
                reservations[reservation_id] = max(0, int(payload.get("reserved_tokens", 0) or 0))
            elif event_type in {"token_budget_settled", "token_budget_refunded"} and reservation_id:
                reservations.pop(reservation_id, None)
        reserved = sum(reservations.values())
        remaining = max(0, hard_limit_tokens - used - reserved)
        forecast = used + reserved + forecast_additional_tokens
        return RuntimeCostSnapshot(
            run_id=run_id,
            used_tokens=used,
            reserved_tokens=reserved,
            remaining_tokens=remaining,
            forecast_total_tokens=forecast,
            predicted_to_exceed=forecast > hard_limit_tokens,
            hard_stop=used + reserved >= hard_limit_tokens,
            unsettled_usage_count=unsettled,
            data_freshness=max(timestamps) if timestamps else None,
        )


__all__ = [
    "AttemptCostRecord",
    "BatchRequest",
    "BatchResponse",
    "BudgetExceededError",
    "BudgetNode",
    "CacheBinding",
    "CostAttributionLedger",
    "CriticalPathAnalyzer",
    "CriticalPathStage",
    "HierarchicalTokenBudget",
    "IsolatedResourcePool",
    "PerformancePolicy",
    "PerformancePolicyError",
    "ProviderBatchDispatcher",
    "RepeatableBenchmark",
    "RuntimeCostMonitor",
    "SecureProviderCache",
    "TokenUsage",
]
