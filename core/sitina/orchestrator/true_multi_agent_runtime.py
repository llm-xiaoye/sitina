from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef, PublishedObjectReceipt
from sitina.commands.gateway import CommandGateway, CommandPlan
from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.effects.approval import ApprovalBinding, issue_approval
from sitina.effects.breakers import CircuitBreaker
from sitina.effects.budgets import BudgetBundle, BudgetReservation
from sitina.effects.gateway import DispatchFence, EffectGateway, TaskFence
from sitina.effects.model import EffectRequest, OutcomeState
from sitina.effects.observations import EffectObservationApplier, ObservationIngress, make_signed_observation
from sitina.effects.results import PipelineDisposition, ResultPipeline, ResultPolicy
from sitina.guards.secrets import scan_json_for_secrets
from sitina.journal.model import EventEnvelope, FrontierRef, canonical_json_bytes, domain_hash
from sitina.legacy.fence import issue_frozen_network_egress_capability
from sitina.orchestrator.agent_context_v2 import AgentContextManifestRepository
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.protocols.tasks import TaskAggregate
from sitina.runners.provider import (
    AnthropicCompatibleClient,
    ProviderCompletion,
    ProviderError,
    ProviderHTTPError,
    token_usage_summary,
)
from sitina.security.key_provider import KeyPurpose
from sitina.scheduling.agents import AgentCandidate


TENANT = "default"
RUNTIME_NAMESPACE = "sitina-true-multi-agent-v1"
SIGNING_DOMAIN = b"SITINA-TRUE-MULTI-AGENT-ACTIVATION-V1\0"


class TrueMultiAgentRuntimeError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_hash(label: str, value: Any) -> str:
    return domain_hash(label, canonical_json_bytes(value))


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def event_type_for(fact: Mapping[str, Any]) -> str:
    explicit = fact.get("event_type")
    if isinstance(explicit, str):
        return explicit
    schema = str(fact.get("schema", "TRUE_MULTI_AGENT_FACT_V1"))
    return "protocol." + schema.lower().removesuffix("_v1").replace("_", ".")


def _physical_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    role: str
    capabilities: tuple[str, ...]
    provider_profile: str
    cost_weight: int
    safety_classes: tuple[str, ...]

    def candidate(
        self,
        *,
        load: int = 0,
        eligible: bool = True,
        safety_allowed: bool = True,
        budget_allowed: bool = True,
        lease_available: bool = True,
        independent: bool = True,
        policy_allowed: bool = True,
        source_versions: Mapping[str, int] | None = None,
    ) -> AgentCandidate:
        return AgentCandidate(
            self.agent_id,
            self.role,
            self.capabilities,
            eligible,
            safety_allowed,
            budget_allowed,
            lease_available,
            independent,
            policy_allowed,
            load,
            self.cost_weight,
            source_versions,
        )

    def mapping(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "capabilities": list(self.capabilities),
            "provider_profile": self.provider_profile,
            "cost_weight": self.cost_weight,
            "safety_classes": list(self.safety_classes),
        }


class AgentRegistry:
    def __init__(self, generation: int, identities: Sequence[AgentIdentity], registry_hash: str):
        if generation < 1 or not identities or len({item.agent_id for item in identities}) != len(identities):
            raise TrueMultiAgentRuntimeError("invalid Agent registry")
        self.generation = generation
        self.identities = tuple(identities)
        self.registry_hash = registry_hash

    @classmethod
    def load(cls, home: Path) -> "AgentRegistry":
        path = home / "config/true_multi_agent_agents.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema") != "SITINA_TRUE_MULTI_AGENT_REGISTRY_V1":
            raise TrueMultiAgentRuntimeError("unsupported Agent registry")
        identities = tuple(
            AgentIdentity(
                str(item["agent_id"]),
                str(item["role"]),
                tuple(str(value) for value in item["capabilities"]),
                str(item["provider_profile"]),
                int(item["cost_weight"]),
                tuple(str(value) for value in item["safety_classes"]),
            )
            for item in raw["agents"]
        )
        return cls(int(raw["generation"]), identities, sha256_bytes(canonical_json_bytes(raw)))

    def get(self, agent_id: str) -> AgentIdentity:
        try:
            return next(item for item in self.identities if item.agent_id == agent_id)
        except StopIteration as error:
            raise TrueMultiAgentRuntimeError(f"unknown Agent identity: {agent_id}") from error


@dataclass(frozen=True)
class RuntimeActivation:
    mapping: Mapping[str, Any]
    manifest_hash: str
    receipt: PublishedObjectReceipt


def activate_runtime(
    home: Path,
    context: ProductionRuntimeContext,
    cas: LocalCAS,
    registry: AgentRegistry,
    policy: Mapping[str, Any],
) -> RuntimeActivation:
    source_paths = (
        home / "core/sitina/orchestrator/true_multi_agent_runtime.py",
        home / "core/sitina/orchestrator/true_multi_agent.py",
        home / "core/sitina/orchestrator/execution_bridge.py",
        home / "core/sitina/orchestrator/execution_sandbox.py",
        home / "core/sitina/orchestrator/execution_verification.py",
        home / "core/sitina/legacy/fence.py",
        home / "core/sitina/conversation/__init__.py",
        home / "core/sitina/conversation/models.py",
        home / "core/sitina/conversation/context.py",
        home / "core/sitina/conversation/router.py",
        home / "core/sitina/conversation/runtime.py",
        home / "core/sitina/conversation/fast_runtime.py",
        home / "core/sitina/scheduling/agents.py",
        home / "core/sitina/protocols/handoff_contracts.py",
        home / "core/sitina/runners/provider.py",
        home / "config/conversation_router.json",
        home / "config/true_multi_agent_agents.json",
        home / "config/true_multi_agent_policy.json",
    )
    profile = AnthropicCompatibleClient(home).load_profile(str(policy["provider_profile"]))
    host = urlparse(profile.base_url).hostname
    if host not in {"api.deepseek.com", "api.deepseek.com.cn"}:
        raise TrueMultiAgentRuntimeError("true multi-agent runtime permits only the configured DeepSeek endpoint")
    if profile.model not in set(policy["provider_model_allowlist"]):
        raise TrueMultiAgentRuntimeError("Provider model is outside the true multi-agent allowlist")
    unsigned = {
        "schema": "SITINA_TRUE_MULTI_AGENT_ACTIVATION_V1",
        "production_home": str(home),
        "production_genesis_hash": context.genesis.genesis_hash,
        "journal_id": context.genesis.journal_id,
        "journal_epoch": int(context.genesis.epoch_root.rsplit("-", 1)[1]),
        "registry_generation": registry.generation,
        "registry_hash": registry.registry_hash,
        "policy_hash": sha256_bytes(canonical_json_bytes(dict(policy))),
        "source_sha256": {str(path): _physical_sha256(path) for path in source_paths},
        "provider": {
            "profile": profile.name,
            "model": profile.model,
            "base_url_host": host,
            "transport_retries": 0,
            "sdk_retries": 0,
            "fallbacks": 0,
        },
        "allowed_mutations": [str(home / "journal"), str(home / "cas"), str(home / "projections/disposable-rebuilds"), str(home / "output")],
        "legacy_read_allowed": False,
        "acceptance_read_allowed": False,
        "external_mutation_allowed": False,
        "created_at": now_rfc3339(),
    }
    key_id, signature = context.provider.sign(
        KeyPurpose.AUTHORITY_SIGNING,
        SIGNING_DOMAIN + canonical_json_bytes(unsigned),
    )
    signed = {**unsigned, "authority_key_id": key_id, "authority_signature_hex": signature.hex()}
    if not context.provider.verify(
        key_id,
        KeyPurpose.AUTHORITY_SIGNING,
        SIGNING_DOMAIN + canonical_json_bytes(unsigned),
        signature,
    ):
        raise TrueMultiAgentRuntimeError("runtime activation authority signature failed verification")
    manifest_hash = sha256_bytes(canonical_json_bytes(signed))
    receipt = cas.publish_verified(
        encrypt_object(canonical_json_bytes(signed), context.provider, tenant_id=TENANT, purpose="true-multi-agent-activation")
    )
    return RuntimeActivation(signed, manifest_hash, receipt)


class CanonicalStream:
    """Command-only writer for one authoritative Stream with CAS proof enforcement."""

    def __init__(
        self,
        journal: Any,
        run_id: str,
        stream_id: str,
        policy_hash: str,
        *,
        namespace: str = RUNTIME_NAMESPACE,
    ):
        self.journal = journal
        self.run_id = run_id
        self.stream_id = stream_id
        self.policy_hash = policy_hash
        self.namespace = namespace
        existing = [item for item in journal.iter_events(0) if item.stream_id == stream_id]
        # Fast Start intentionally materializes only checkpoint control facts
        # plus the active tail.  Stream heads are authenticated checkpoint
        # state, so command writers must use them instead of treating a sealed
        # historical stream as version zero.
        self.version = int(getattr(journal, "_stream_heads", {}).get(stream_id, existing[-1].stream_version if existing else 0))
        self.ordinal = self.version
        self.gateway = CommandGateway(journal)

    def append(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        source_frontier: FrontierRef | None = None,
        deadline: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        if not facts:
            raise TrueMultiAgentRuntimeError("canonical Command requires at least one fact")
        timestamp = now_rfc3339()
        expected_version = self.version
        identity = command_id or "tma-command-" + stable_hash(
            "TRUE_MULTI_AGENT_COMMAND_ID",
            {
                "run_id": self.run_id,
                "stream_id": self.stream_id,
                "stage": stage,
                "expected_version": expected_version,
                "fact_hashes": [stable_hash("TRUE_MULTI_AGENT_FACT", dict(item)) for item in facts],
            },
        )[:44]
        command = CommandEnvelope(
            identity,
            TENANT,
            self.stream_id,
            "true-multi-agent." + stage,
            actor,
            timestamp,
            {
                "run_id": self.run_id,
                "stage": stage,
                "expected_stream_version": expected_version,
                "source_frontier": source_frontier.__dict__ if source_frontier else None,
                "policy_hash": self.policy_hash,
                "deadline": deadline,
                "fact_hashes": [stable_hash("TRUE_MULTI_AGENT_FACT", dict(item)) for item in facts],
            },
        )
        built: list[EventEnvelope] = []
        references: list[dict[str, Any]] = []

        def plan(_command: CommandEnvelope) -> CommandPlan:
            current = [item for item in self.journal.iter_events(0) if item.stream_id == self.stream_id]
            current_version = current[-1].stream_version if current else 0
            if current_version != expected_version:
                return CommandPlan(rejection_reason="STREAM_VERSION_CHANGED")
            if deadline is not None and timestamp >= deadline:
                return CommandPlan(rejection_reason="DEADLINE_EXPIRED")
            for fact in facts:
                self.ordinal += 1
                raw = dict(fact)
                object_refs = tuple(sorted(set(str(item) for item in raw.pop("_object_refs", ()))))
                fact_hash = stable_hash("TRUE_MULTI_AGENT_FACT", raw)
                event_type = event_type_for(raw)
                payload = {
                    **raw,
                    "run_id": self.run_id,
                    "runtime_namespace": self.namespace,
                    "actor_id": actor,
                    "causation_command_id": identity,
                    "policy_hash": self.policy_hash,
                    "fact_hash": fact_hash,
                }
                event_id = "event-" + stable_hash(
                    "TRUE_MULTI_AGENT_EVENT_ID",
                    {
                        "run_id": self.run_id,
                        "stream_id": self.stream_id,
                        "ordinal": self.ordinal,
                        "event_type": event_type,
                        "fact_hash": fact_hash,
                    },
                )[:48]
                built.append(EventEnvelope(event_id, event_type, TENANT, self.stream_id, 0, 0, timestamp, payload, object_refs))
            return CommandPlan(events=tuple(built))

        result = self.gateway.submit(command, expected_version, plan, proofs)
        if result.status is not CommandStatus.COMMITTED or result.receipt is None:
            raise TrueMultiAgentRuntimeError(f"Command {identity} failed closed: {result.status.value} {result.reason or ''}")
        self.version = result.receipt.last_stream_version
        committed = [
            {
                "event_id": item.event_id,
                "event_type": item.event_type,
                "position": item.position,
                "stream_id": item.stream_id,
                "stream_version": item.stream_version,
                "event_hash": item.event_hash,
            }
            for item in self.journal.iter_events(result.receipt.first_position - 1)
            if result.receipt.first_position <= item.position <= result.receipt.last_position
        ]
        references.extend(committed)
        return result.receipt, tuple(references)


class CapturingDeepSeekClient(AnthropicCompatibleClient):
    def _request_json(self, *args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        payload, metadata = super()._request_json(*args, **kwargs)
        response_id = payload.get("id")
        if isinstance(response_id, str) and response_id:
            metadata["provider_response_id"] = response_id[:300]
        usage = payload.get("usage")
        if isinstance(usage, dict):
            metadata["provider_usage_details"] = {
                str(key): value
                for key, value in usage.items()
                if isinstance(value, int) and value >= 0
            }
        return payload, metadata


class OneShotDeepSeekTransport:
    def __init__(self, client: CapturingDeepSeekClient, profile: Any, *, timeout: int, max_sends: int):
        self.client = client
        self.profile = profile
        self.timeout = timeout
        self.max_sends = max_sends
        self.physical_send_count = 0
        self.prompts: dict[str, tuple[str, str]] = {}
        self.fault_modes: dict[str, str] = {}

    def configure_fault(self, effect_id: str, mode: str) -> None:
        if mode != "explicit_remote_failure":
            raise TrueMultiAgentRuntimeError("unsupported controlled Provider fault mode")
        self.fault_modes[effect_id] = mode

    def send_once(self, request: EffectRequest, effect_attempt_id: str) -> dict[str, Any]:
        if request.operation != "model_text_generation" or request.target != self.profile.name:
            raise TrueMultiAgentRuntimeError("Provider transport received an out-of-scope request")
        if self.physical_send_count >= self.max_sends:
            raise TrueMultiAgentRuntimeError("per-run Provider request ceiling reached")
        system_prompt, user_prompt = self.prompts[request.effect_id]
        if request.request.get("system_prompt_hash") != sha256_bytes(system_prompt.encode()):
            raise TrueMultiAgentRuntimeError("system prompt binding changed after admission")
        if request.request.get("user_prompt_hash") != sha256_bytes(user_prompt.encode()):
            raise TrueMultiAgentRuntimeError("user prompt binding changed after admission")
        self.physical_send_count += 1
        fault_mode = self.fault_modes.pop(request.effect_id, None)
        if fault_mode == "explicit_remote_failure":
            try:
                self.client._complete_openai(
                    self.profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=-1,
                    request_timeout_seconds=float(self.timeout),
                    expect_json=True,
                )
            except ProviderHTTPError:
                raise
            except ProviderError as error:
                raise TrueMultiAgentRuntimeError(
                    "controlled explicit remote failure did not return an authoritative HTTP response"
                ) from error
            raise TrueMultiAgentRuntimeError("controlled invalid Provider request unexpectedly succeeded")
        completion: ProviderCompletion = self.client._complete_openai(
            self.profile,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=int(request.request["max_output_tokens"]),
            request_timeout_seconds=float(self.timeout),
            expect_json=True,
            json_schema=None,
        )
        metadata = dict(completion.metadata)
        if metadata.get("protocol") != "openai_chat_completions":
            raise TrueMultiAgentRuntimeError("DeepSeek response used an unexpected protocol")
        if metadata.get("protocol_fallback_used") or metadata.get("structured_feature_fallback") or metadata.get("fallback_used"):
            raise TrueMultiAgentRuntimeError("Provider fallback is forbidden")
        return {
            "raw_text": completion.text,
            "metadata": metadata,
            "effect_attempt_id": effect_attempt_id,
            "physical_send_count": self.physical_send_count,
        }


def normalize_usage(metadata: Mapping[str, Any]) -> dict[str, int]:
    summary = dict(metadata.get("token_usage") or {})
    details = dict(metadata.get("provider_usage_details") or {})
    input_tokens = int(summary.get("input_tokens", details.get("prompt_tokens", 0)) or 0)
    output_tokens = int(summary.get("output_tokens", details.get("completion_tokens", 0)) or 0)
    total_tokens = int(summary.get("total_tokens", details.get("total_tokens", input_tokens + output_tokens)) or 0)
    cache_read_tokens = int(
        summary.get(
            "cache_read_tokens",
            details.get("cache_read_tokens", details.get("prompt_cache_hit_tokens", 0)),
        )
        or 0
    )
    cache_write_tokens = int(
        summary.get(
            "cache_write_tokens",
            details.get("cache_write_tokens", details.get("prompt_cache_miss_tokens", 0)),
        )
        or 0
    )
    if (
        min(input_tokens, output_tokens, cache_read_tokens, cache_write_tokens) < 0
        or total_tokens <= 0
        or total_tokens != input_tokens + output_tokens
        or cache_read_tokens > input_tokens
        or cache_write_tokens > input_tokens
    ):
        raise TrueMultiAgentRuntimeError("Provider response has invalid token accounting")
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read_tokens,
        "cache_write_tokens": cache_write_tokens,
        "total_tokens": total_tokens,
    }


@dataclass(frozen=True)
class AgentCallResult:
    call_id: str
    run_id: str
    agent_id: str
    role: str
    task_id: str
    task_attempt_id: str
    effect_id: str
    effect_attempt_id: str
    provider_request_id: str
    input_snapshot_ref: str
    input_snapshot_hash: str
    output_ref: str
    output_object_ref: ObjectRef = field(repr=False)
    output_hash: str
    value: Mapping[str, Any]
    usage: Mapping[str, int]
    cost_micro_usd: int
    started_at: str
    completed_at: str
    outcome: str
    settlement: str
    retry_count: int = 0
    fallback_count: int = 0

    def evidence(self) -> dict[str, Any]:
        return {
            **{key: value for key, value in self.__dict__.items() if key != "output_object_ref"},
            "value": dict(self.value),
            "usage": dict(self.usage),
        }


@dataclass
class ProviderExecutor:
    home: Path
    context: ProductionRuntimeContext
    run_id: str
    policy_hash: str
    policy: Mapping[str, Any]
    activation: RuntimeActivation
    journal: Any
    cas: LocalCAS
    call_count: int = 0
    embedded_call_count: int = 0
    embedded_physical_send_count: int = 0
    usage_input_total: int = 0
    usage_output_total: int = 0
    usage_cache_read_total: int = 0
    usage_cache_write_total: int = 0
    usage_total: int = 0
    cost_total_micro_usd: int = 0
    unsettled_usage_count: int = 0
    results: list[AgentCallResult] = field(default_factory=list)
    rejected_calls: list[dict[str, Any]] = field(default_factory=list)
    recovery_attempts: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.feature_activations = FeatureActivationRegistry.from_journal_events(self.context.events)
        capability = issue_frozen_network_egress_capability(
            self.context.authority.resolution,
            manifest_hash=self.activation.manifest_hash,
            operation="model_text_generation",
            allowed_hosts=(str(self.activation.mapping["provider"]["base_url_host"]),),
            expires_at=int(time.time()) + 1200,
        )
        client = CapturingDeepSeekClient(self.home, network_egress_capability=capability)
        profile = client.load_profile(str(self.policy["provider_profile"]))
        self.transport = OneShotDeepSeekTransport(
            client,
            profile,
            timeout=int(self.policy["request_timeout_seconds"]),
            max_sends=int(self.policy["max_provider_requests_per_run"]),
        )
        self.gateway = EffectGateway(self.transport)
        self.pipeline = ResultPipeline(
            self.cas,
            self.context.provider,
            ResultPolicy(64 * 1024, frozenset({"agent_id", "kind"}), 64 * 1024),
        )

    def _usage_cost(self, usage: Mapping[str, int]) -> int:
        pricing = dict(self.policy["pricing"])
        return (
            int(usage["input_tokens"])
            * int(pricing["input_micro_usd_per_million_tokens"])
            + int(usage["output_tokens"])
            * int(pricing["output_micro_usd_per_million_tokens"])
        ) // 1_000_000

    def _provider_call_total(self) -> int:
        return int(self.call_count) + int(getattr(self, "embedded_call_count", 0))

    def _assert_model_admission(self, max_output_tokens: int) -> None:
        if self._provider_call_total() >= int(self.policy["max_provider_requests_per_run"]):
            raise TrueMultiAgentRuntimeError("Provider call ceiling reached before admission")
        remaining_tokens = int(self.policy["max_total_tokens_per_run"]) - int(self.usage_total)
        if remaining_tokens < max(1, int(max_output_tokens)):
            raise TrueMultiAgentRuntimeError("per-run token budget insufficient before admission")
        output_rate = int(self.policy["pricing"]["output_micro_usd_per_million_tokens"])
        minimum_reserved_cost = (max(1, int(max_output_tokens)) * output_rate) // 1_000_000
        remaining_cost = int(self.policy["max_total_cost_micro_usd_per_run"]) - int(
            self.cost_total_micro_usd
        )
        if remaining_cost < minimum_reserved_cost:
            raise TrueMultiAgentRuntimeError("per-run cost budget insufficient before admission")

    def _record_usage(self, usage: Mapping[str, int], cost_micro: int) -> tuple[bool, bool]:
        self.usage_input_total = int(getattr(self, "usage_input_total", 0)) + int(
            usage["input_tokens"]
        )
        self.usage_output_total = int(getattr(self, "usage_output_total", 0)) + int(
            usage["output_tokens"]
        )
        self.usage_cache_read_total = int(getattr(self, "usage_cache_read_total", 0)) + int(
            usage["cache_read_tokens"]
        )
        self.usage_cache_write_total = int(getattr(self, "usage_cache_write_total", 0)) + int(
            usage["cache_write_tokens"]
        )
        self.usage_total += int(usage["total_tokens"])
        self.cost_total_micro_usd += int(cost_micro)
        return (
            self.usage_total > int(self.policy["max_total_tokens_per_run"]),
            self.cost_total_micro_usd > int(self.policy["max_total_cost_micro_usd_per_run"]),
        )

    def provider_call_total(self) -> int:
        return self._provider_call_total()

    def physical_send_total(self) -> int:
        return int(self.transport.physical_send_count) + int(
            getattr(self, "embedded_physical_send_count", 0)
        )

    def usage_totals(self) -> dict[str, int]:
        return {
            "input_tokens": int(getattr(self, "usage_input_total", 0)),
            "output_tokens": int(getattr(self, "usage_output_total", 0)),
            "cache_read_tokens": int(getattr(self, "usage_cache_read_total", 0)),
            "cache_write_tokens": int(getattr(self, "usage_cache_write_total", 0)),
            "total_tokens": int(self.usage_total),
            "cost_micro_usd": int(self.cost_total_micro_usd),
            "unsettled_usage_count": int(getattr(self, "unsettled_usage_count", 0)),
        }

    def admit_embedded_provider_call(self, max_output_tokens: int) -> None:
        self._assert_model_admission(max_output_tokens)

    def settle_embedded_provider_call(self, metadata: Mapping[str, Any]) -> None:
        try:
            usage = normalize_usage(metadata)
        except Exception:
            self.unsettled_usage_count = int(getattr(self, "unsettled_usage_count", 0)) + 1
            raise
        cost_micro = self._usage_cost(usage)
        self.embedded_call_count = int(getattr(self, "embedded_call_count", 0)) + 1
        physical = metadata.get("physical_send_count", 1)
        self.embedded_physical_send_count = int(
            getattr(self, "embedded_physical_send_count", 0)
        ) + (int(physical) if isinstance(physical, int) and not isinstance(physical, bool) else 1)
        token_over, cost_over = self._record_usage(usage, cost_micro)
        if token_over or cost_over:
            raise TrueMultiAgentRuntimeError(
                "embedded Provider response exceeded the unified per-run model budget"
            )

    def _publish(self, value: Mapping[str, Any], *, purpose: str) -> PublishedObjectReceipt:
        return self.cas.publish_verified(
            encrypt_object(canonical_json_bytes(dict(value)), self.context.provider, tenant_id=TENANT, purpose=purpose)
        )

    def _publish_body(self, value: bytes, *, purpose: str) -> PublishedObjectReceipt:
        return self.cas.publish_plaintext(
            value,
            tenant_id=TENANT,
            purpose_class=purpose,
            compression="auto",
            media_type="text/plain",
        ).receipt

    def _publish_input_binding_v2(
        self,
        *,
        call_id: str,
        agent_id: str,
        system_prompt: str,
        user_prompt: str,
        input_context: Mapping[str, Any],
    ) -> tuple[PublishedObjectReceipt, str, str]:
        """Publish deduplicated context components and a small reconstructable manifest.

        Provider transport bytes stay runtime-only.  The durable input identity is
        the V2 manifest plus its component CAS refs, gated solely by committed
        Journal feature activation state.
        """

        prompt_template = self._publish_body(
            system_prompt.encode("utf-8"), purpose="agent-context-prompt-template-v2"
        )
        conversation_state = self._publish_body(
            canonical_json_bytes(dict(input_context)), purpose="agent-context-conversation-state-v2"
        )
        delta = self._publish_body(user_prompt.encode("utf-8"), purpose="agent-context-delta-v2")
        published = AgentContextManifestRepository(
            self.journal,
            self.cas,
            self.context.provider,
            feature_activations=self.feature_activations,
        ).create(
            run_id=self.run_id,
            call_id=call_id,
            agent_id=agent_id,
            prompt_template_ref=prompt_template.object_ref,
            base_project_context_ref=None,
            conversation_state_ref=conversation_state.object_ref,
            rolling_summary_ref=None,
            retrieved_memory_refs=(),
            blackboard_base_ref=None,
            delta_refs=(delta.object_ref,),
            occurred_at=now_rfc3339(),
        )
        manifest_bytes = canonical_json_bytes(published.manifest.model_dump(mode="json", by_alias=True))
        manifest_receipt = self.cas.verify_existing(published.manifest_ref)
        return manifest_receipt, sha256_bytes(manifest_bytes), published.manifest.rendered_input_hash

    def call(
        self,
        agent: AgentIdentity,
        *,
        task_id: str,
        kind: str,
        system_prompt: str,
        user_prompt: str,
        input_context: Mapping[str, Any],
        validate: Callable[[Mapping[str, Any]], None],
        ack_lost: bool = False,
    ) -> AgentCallResult:
        self._assert_model_admission(int(self.policy["max_output_tokens_per_request"]))
        ordinal = self._provider_call_total() + 1
        call_id = "call-" + stable_hash(
            "TRUE_MULTI_AGENT_CALL_ID",
            {"run_id": self.run_id, "agent_id": agent.agent_id, "task_id": task_id, "ordinal": ordinal},
        )[:40]
        task_identity = task_id + "-" + stable_hash("TRUE_MULTI_AGENT_TASK_INSTANCE", {"run": self.run_id, "call": call_id})[:16]
        task = TaskAggregate(task_identity, stable_hash("TRUE_MULTI_AGENT_TASK_SPEC", {"task_id": task_id, "kind": kind, "context": dict(input_context)}))
        task, attempt, claim_fact = task.claim(
            claim_command_id="claim-" + stable_hash("TRUE_MULTI_AGENT_CLAIM", {"call": call_id})[:40],
            lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id=agent.agent_id,
            expected_stream_version=task.stream_version,
        )
        feature = self.feature_activations.state("agent_context_v2_write")
        if feature is not None and feature.state == "ACTIVATED":
            input_receipt, input_snapshot_hash, rendered_input_hash = self._publish_input_binding_v2(
                call_id=call_id,
                agent_id=agent.agent_id,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                input_context=input_context,
            )
            input_schema = "SITINA_AGENT_CONTEXT_MANIFEST_V2"
        else:
            input_snapshot = {
                "schema": "SITINA_AGENT_INPUT_SNAPSHOT_V1",
                "run_id": self.run_id,
                "call_id": call_id,
                "agent_id": agent.agent_id,
                "role": agent.role,
                "capabilities": list(agent.capabilities),
                "task_id": task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "shared_context": dict(input_context),
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
            input_snapshot_hash = sha256_bytes(canonical_json_bytes(input_snapshot))
            input_receipt = self._publish(input_snapshot, purpose="true-multi-agent-input")
            input_schema = "SITINA_AGENT_INPUT_SNAPSHOT_V1"
            rendered_input_hash = input_snapshot_hash
        effect_id = "effect-" + stable_hash("TRUE_MULTI_AGENT_EFFECT", {"call": call_id})[:40]
        effect_attempt_id = "effect-attempt-" + stable_hash("TRUE_MULTI_AGENT_EFFECT_ATTEMPT", {"call": call_id, "attempt": 1})[:32]
        request = EffectRequest(
            effect_id,
            "model_text_generation",
            {
                "agent_id": agent.agent_id,
                "role": agent.role,
                "task_id": task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "input_snapshot_hash": input_snapshot_hash,
                "input_snapshot_ref": input_receipt.object_ref.reference_id,
                "input_schema": input_schema,
                "rendered_input_hash": rendered_input_hash,
                "system_prompt_hash": sha256_bytes(system_prompt.encode()),
                "user_prompt_hash": sha256_bytes(user_prompt.encode()),
                "max_output_tokens": int(self.policy["max_output_tokens_per_request"]),
                "response_format": "json_object",
                "tool_calls_allowed": False,
            },
            str(self.policy["provider_profile"]),
            self.policy_hash,
            self.activation.manifest_hash,
            "low-non-mutating-text",
            "true-multi-agent-provider-principal",
            "model-text-generation",
            "idempotency-" + stable_hash("TRUE_MULTI_AGENT_IDEMPOTENCY", {"effect": effect_id})[:40],
        )
        self.transport.prompts[effect_id] = (system_prompt, user_prompt)
        binding = ApprovalBinding(
            effect_id,
            request.request_hash,
            str(self.policy["provider_profile"]),
            "one-text-generation-request",
            self.policy_hash,
            "low-non-mutating-text",
            "true-multi-agent-provider-principal",
            "model-text-generation",
            "model_text_generation",
            self.activation.manifest_hash,
        )
        current = int(time.time())
        approval = issue_approval(
            "approval-" + effect_id,
            binding,
            authority="goal-owner-provider-inference-authorization",
            expires_at=current + 600,
            allowed_attempts=1,
            allowed_transport_retries=0,
        )
        approval, approval_fact = approval.authorize(binding, effect_attempt_id=effect_attempt_id, now=current, transport_retries=0)
        task_fence = TaskFence(attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, current + 600)
        dispatch = DispatchFence(
            "dispatch-" + stable_hash("TRUE_MULTI_AGENT_DISPATCH", {"call": call_id})[:32],
            1,
            "dispatch-fence-" + stable_hash("TRUE_MULTI_AGENT_DISPATCH_FENCE", {"call": call_id})[:32],
            current + 600,
        )
        bundle = BudgetBundle.create(
            "budget-" + stable_hash("TRUE_MULTI_AGENT_BUDGET", {"call": call_id})[:32],
            effect_id,
            effect_attempt_id,
            dispatch.token,
            (
                BudgetReservation(
                    "billable_tokens",
                    int(self.policy["max_total_tokens_per_run"]) - int(self.usage_total),
                    current + 600,
                ),
                BudgetReservation(
                    "cost_micro_usd",
                    int(self.policy["max_total_cost_micro_usd_per_run"])
                    - int(self.cost_total_micro_usd),
                    current + 600,
                ),
                BudgetReservation("provider_attempts", 1, current + 600),
            ),
        )
        for budget_kind in ("billable_tokens", "cost_micro_usd", "provider_attempts"):
            bundle = bundle.activate(budget_kind)
        breaker = CircuitBreaker("breaker-" + stable_hash("TRUE_MULTI_AGENT_BREAKER", {"call": call_id})[:32], 1)
        precheck = breaker.precheck(effect_attempt_id, dispatch.token)
        breaker, breaker_fact = breaker.authorize_final(precheck, expected_version=breaker.version)
        self.gateway.open_effect(request)
        self.gateway.claim_attempt(effect_id, effect_attempt_id, task_fence)
        self.gateway.prepare(
            effect_id,
            effect_attempt_id,
            approval_hash=binding.binding_hash,
            credential_handle_id="deepseek-credential-handle",
            manifest_hash=self.activation.manifest_hash,
        )
        started_fact = self.gateway.start_invocation(
            effect_id,
            effect_attempt_id,
            dispatch,
            now=current,
            budget_bundle=bundle,
            breaker_authorization=breaker_fact,
        )
        effect_stream = CanonicalStream(self.journal, self.run_id, f"effect/{self.run_id}/{effect_id}", self.policy_hash)
        effect_stream.append(
            "effect-invocation-started",
            (
                {"schema": "TASK_CREATED_V1", "task_id": task.task_id, "specification_hash": task.specification_hash},
                claim_fact,
                {
                    "schema": "AGENT_ATTEMPT_BOUND_V1",
                    "call_id": call_id,
                    "agent_id": agent.agent_id,
                    "role": agent.role,
                    "capabilities": list(agent.capabilities),
                    "task_id": task_id,
                    "task_attempt_id": attempt.task_attempt_id,
                    "claim_generation": attempt.claim_generation,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                    "input_snapshot_hash": input_snapshot_hash,
                    "input_snapshot_ref": input_receipt.object_ref.reference_id,
                    "input_schema": input_schema,
                    "rendered_input_hash": rendered_input_hash,
                    "_object_refs": [input_receipt.object_ref.reference_id],
                },
                {
                    "schema": "EFFECT_REQUEST_OPENED_V1",
                    "call_id": call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": effect_attempt_id,
                    "request_hash": request.request_hash,
                    "idempotency_binding": request.idempotency_binding,
                    "transport_retry_limit": 0,
                    "sdk_retry_limit": 0,
                    "fallback_limit": 0,
                },
                approval_fact,
                breaker_fact,
                started_fact,
            ),
            actor=agent.agent_id,
            proofs=(input_receipt,),
        )
        started_at = now_rfc3339()
        prior_sends = self.transport.physical_send_count
        transport_value = self.gateway.transmit(effect_id, effect_attempt_id)
        raw_text = str(transport_value.pop("raw_text"))
        metadata = dict(transport_value.pop("metadata"))
        self.call_count += 1
        if self.transport.physical_send_count != prior_sends + 1:
            raise TrueMultiAgentRuntimeError("Provider physical-send accounting mismatch")
        unknown_fact: dict[str, Any] | None = None
        if ack_lost:
            recovered = self.gateway.recover_after_crash(effect_id, effect_attempt_id)
            unknown_fact = {
                "schema": "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1",
                "call_id": call_id,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "attempt_disposition": recovered.disposition.value if recovered.disposition else None,
                "outcome_state": self.gateway.effect(effect_id).state.outcome_state.value,
                "settlement_state": self.gateway.effect(effect_id).state.settlement_state.value,
                "automatic_retry_performed": False,
            }
            effect_stream.append("effect-outcome-unknown", (unknown_fact,), actor=agent.agent_id)
        raw = raw_text.encode("utf-8")
        usage = normalize_usage(metadata)
        cost_micro = self._usage_cost(usage)
        token_over, cost_over = self._record_usage(usage, cost_micro)
        bundle, token_fact = bundle.record_actual("billable_tokens", usage["total_tokens"])
        bundle, cost_fact = bundle.record_actual("cost_micro_usd", cost_micro)
        bundle, attempts_fact = bundle.record_actual("provider_attempts", 1)
        if token_over or cost_over:
            effect_stream.append(
                "effect-budget-overrun-after-response",
                (
                    {
                        "schema": "PROVIDER_USAGE_RECORDED_AFTER_BUDGET_OVERRUN_V1",
                        "call_id": call_id,
                        "run_id": self.run_id,
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        **usage,
                        "cost_micro_usd": cost_micro,
                        "token_budget_exceeded": token_over,
                        "cost_budget_exceeded": cost_over,
                        "physical_send_count": 1,
                    },
                    token_fact,
                    cost_fact,
                    attempts_fact,
                ),
                actor="provider-budget-controller",
            )
            raise TrueMultiAgentRuntimeError(
                "Provider response exceeded the unified per-run model budget after settlement"
            )
        provider_response_id = metadata.get("provider_response_id")
        provider_request_id = provider_response_id or metadata.get("provider_request_id")
        if not isinstance(provider_request_id, str) or not provider_request_id:
            raise TrueMultiAgentRuntimeError("Provider returned no request/response identity")
        observation_key = hashlib.sha256(
            b"SITINA-TRUE-MULTI-AGENT-OBSERVATION-V1\0" + bytes.fromhex(self.activation.manifest_hash)
        ).digest()
        source = "deepseek-provider-response"
        raw_observation = make_signed_observation(
            {
                "schema_major": 1,
                "observation_id": "observation-" + stable_hash("TRUE_MULTI_AGENT_OBSERVATION", {"call": call_id})[:40],
                "source_identity": source,
                "manifest_hash": self.activation.manifest_hash,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "request_hash": request.request_hash,
                "nonce": "nonce-" + stable_hash("TRUE_MULTI_AGENT_OBSERVATION_NONCE", {"request": provider_request_id})[:32],
                "received_at": int(time.time()),
                "remote_outcome": OutcomeState.SUCCEEDED.value,
                "external_request_id": provider_request_id,
                "remote_execution_id": provider_request_id,
            },
            observation_key,
        )
        ingress = ObservationIngress({source: observation_key}, now=lambda: int(time.time()), max_clock_skew_seconds=300)
        admission = ingress.admit(
            raw_observation,
            expected={
                "source_identity": source,
                "manifest_hash": self.activation.manifest_hash,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "request_hash": request.request_hash,
                "external_request_id": provider_request_id,
            },
            external_request_id_required=True,
        )
        if admission.observation is None:
            raise TrueMultiAgentRuntimeError("Provider observation failed admission")
        settled = EffectObservationApplier(self.gateway.effect(effect_id).state).apply(
            admission.observation, expected_effect_version=0
        )
        self.gateway.settle_from_observation(
            effect_id,
            effect_attempt_id,
            admission.observation.observation_id,
            settled.state,
        )
        pipeline_outcome = self.pipeline.process(raw, tenant_id=TENANT, trust_source="trusted_adapter")
        if pipeline_outcome.disposition is not PipelineDisposition.PUBLISHED or pipeline_outcome.object_receipt is None:
            task, failed_fact = task.fail_attempt(attempt.fencing_token, "PROVIDER_OUTPUT_PIPELINE_REJECTED")
            rejection = {
                "schema": "AGENT_OUTPUT_PIPELINE_REJECTED_V1",
                "call_id": call_id,
                "agent_id": agent.agent_id,
                "role": agent.role,
                "task_id": task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "provider_request_id": provider_request_id,
                "input_snapshot_hash": input_snapshot_hash,
                "input_snapshot_ref": input_receipt.object_ref.reference_id,
                "pipeline_disposition": pipeline_outcome.disposition.value,
                "pipeline_rejection_reason": pipeline_outcome.rejection_reason,
                "quarantine_destroyed": pipeline_outcome.destruction_attestation is not None,
                "provider_outcome": "SUCCEEDED",
                "result_admission": "REJECTED",
                "automatic_retry_performed": False,
            }
            self.rejected_calls.append(dict(rejection))
            effect_stream.append(
                "effect-output-pipeline-rejected",
                (
                    {
                        "schema": "PROVIDER_USAGE_RECORDED_V1",
                        "call_id": call_id,
                        "run_id": self.run_id,
                        "agent_id": agent.agent_id,
                        "role": agent.role,
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "task_attempt_id": attempt.task_attempt_id,
                        "provider": self.transport.profile.name,
                        "model": self.transport.profile.model,
                        "provider_request_id": provider_request_id,
                        "input_tokens": usage["input_tokens"],
                        "output_tokens": usage["output_tokens"],
                        "total_tokens": usage["total_tokens"],
                        "cost_micro_usd": cost_micro,
                        "started_at": started_at,
                        "completed_at": now_rfc3339(),
                        "outcome": "SUCCEEDED_OUTPUT_REJECTED",
                        "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                        "retry_count": 0,
                        "fallback_count": 0,
                        "physical_send_count": 1,
                    },
                    token_fact,
                    cost_fact,
                    attempts_fact,
                    rejection,
                    {
                        "schema": "EFFECT_OBSERVATION_ADMITTED_V1",
                        "observation_id": admission.observation.observation_id,
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "external_request_id": provider_request_id,
                        "raw_evidence_hash": admission.observation.raw_evidence_hash,
                    },
                    {
                        "schema": "EFFECT_RECONCILIATION_SETTLED_V1",
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "state": settled.state.mapping(),
                        "ack_lost_reconciled": ack_lost,
                        "automatic_retry_performed": False,
                    },
                    failed_fact,
                ),
                actor="result-admission-verifier",
            )
            raise TrueMultiAgentRuntimeError(
                f"Provider output pipeline failed closed: {pipeline_outcome.disposition.value}"
            )
        output_receipt = pipeline_outcome.object_receipt
        value = json.loads(self.cas.open_verified(output_receipt.object_ref).decode("utf-8"))
        try:
            if not isinstance(value, dict) or value.get("agent_id") != agent.agent_id or value.get("kind") != kind:
                raise TrueMultiAgentRuntimeError("Provider output violated Agent identity or output-kind contract")
            validate(value)
            if scan_json_for_secrets(value, scope="true-multi-agent-provider-output"):
                raise TrueMultiAgentRuntimeError("Provider output secret scan failed")
        except Exception as error:
            task, failed_fact = task.fail_attempt(attempt.fencing_token, "PROVIDER_OUTPUT_CONTRACT_REJECTED")
            rejection = {
                "schema": "AGENT_OUTPUT_CONTRACT_REJECTED_V1",
                "call_id": call_id,
                "agent_id": agent.agent_id,
                "role": agent.role,
                "task_id": task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "provider_request_id": provider_request_id,
                "input_snapshot_hash": input_snapshot_hash,
                "input_snapshot_ref": input_receipt.object_ref.reference_id,
                "rejected_output_ref": output_receipt.object_ref.reference_id,
                "rejected_output_object_id": output_receipt.object_ref.object_id,
                "reason_type": type(error).__name__,
                "reason_hash": sha256_bytes(str(error).encode()),
                "provider_outcome": "SUCCEEDED",
                "result_admission": "REJECTED",
                "automatic_retry_performed": False,
                "_object_refs": [output_receipt.object_ref.reference_id],
            }
            self.rejected_calls.append({key: value for key, value in rejection.items() if key != "_object_refs"})
            effect_stream.append(
                "effect-output-contract-rejected",
                (
                    {
                        "schema": "PROVIDER_USAGE_RECORDED_V1",
                        "call_id": call_id,
                        "run_id": self.run_id,
                        "agent_id": agent.agent_id,
                        "role": agent.role,
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "task_attempt_id": attempt.task_attempt_id,
                        "provider": self.transport.profile.name,
                        "model": self.transport.profile.model,
                        "provider_request_id": provider_request_id,
                        "input_tokens": usage["input_tokens"],
                        "output_tokens": usage["output_tokens"],
                        "total_tokens": usage["total_tokens"],
                        "cost_micro_usd": cost_micro,
                        "started_at": started_at,
                        "completed_at": now_rfc3339(),
                        "outcome": "SUCCEEDED_OUTPUT_REJECTED",
                        "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                        "retry_count": 0,
                        "fallback_count": 0,
                        "physical_send_count": 1,
                    },
                    token_fact,
                    cost_fact,
                    attempts_fact,
                    rejection,
                    {
                        "schema": "EFFECT_OBSERVATION_ADMITTED_V1",
                        "observation_id": admission.observation.observation_id,
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "external_request_id": provider_request_id,
                        "raw_evidence_hash": admission.observation.raw_evidence_hash,
                    },
                    {
                        "schema": "EFFECT_RECONCILIATION_SETTLED_V1",
                        "effect_id": effect_id,
                        "effect_attempt_id": effect_attempt_id,
                        "state": settled.state.mapping(),
                        "ack_lost_reconciled": ack_lost,
                        "automatic_retry_performed": False,
                    },
                    failed_fact,
                ),
                actor="result-admission-verifier",
                proofs=(output_receipt,),
            )
            raise TrueMultiAgentRuntimeError(
                f"Provider output contract rejected for {call_id}: {type(error).__name__}"
            ) from error
        task, submitted_fact = task.submit(attempt.fencing_token, output_receipt.object_ref.object_id)
        task, accepted_fact = task.accept(
            attempt.fencing_token,
            artifact_hash=output_receipt.object_ref.object_id,
            policy_hash=self.policy_hash,
        )
        completed_at = now_rfc3339()
        output_hash = sha256_bytes(canonical_json_bytes(value))
        facts: list[Mapping[str, Any]] = [
            {
                "schema": "PROVIDER_USAGE_RECORDED_V1",
                "call_id": call_id,
                "run_id": self.run_id,
                "agent_id": agent.agent_id,
                "role": agent.role,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "task_attempt_id": attempt.task_attempt_id,
                "provider": self.transport.profile.name,
                "model": self.transport.profile.model,
                "provider_request_id": provider_request_id,
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "total_tokens": usage["total_tokens"],
                "cost_micro_usd": cost_micro,
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": "SUCCEEDED",
                "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                "retry_count": 0,
                "fallback_count": 0,
                "physical_send_count": 1,
            },
            token_fact,
            cost_fact,
            attempts_fact,
            {
                "schema": "AGENT_OUTPUT_COMMITTED_V1",
                "call_id": call_id,
                "agent_id": agent.agent_id,
                "role": agent.role,
                "task_id": task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "input_snapshot_hash": input_snapshot_hash,
                "input_snapshot_ref": input_receipt.object_ref.reference_id,
                "output_hash": output_hash,
                "output_ref": output_receipt.object_ref.reference_id,
                "output_object_id": output_receipt.object_ref.object_id,
                "agent_may_impersonate_other_agent": False,
                "_object_refs": [output_receipt.object_ref.reference_id],
            },
            {
                "schema": "EFFECT_OBSERVATION_ADMITTED_V1",
                "observation_id": admission.observation.observation_id,
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "external_request_id": provider_request_id,
                "raw_evidence_hash": admission.observation.raw_evidence_hash,
            },
            {
                "schema": "EFFECT_RECONCILIATION_SETTLED_V1",
                "effect_id": effect_id,
                "effect_attempt_id": effect_attempt_id,
                "state": settled.state.mapping(),
                "ack_lost_reconciled": ack_lost,
                "automatic_retry_performed": False,
            },
            submitted_fact,
            accepted_fact,
        ]
        effect_stream.append(
            "effect-result-committed",
            facts,
            actor="result-admission-verifier",
            proofs=(output_receipt,),
        )
        result = AgentCallResult(
            call_id,
            self.run_id,
            agent.agent_id,
            agent.role,
            task_id,
            attempt.task_attempt_id,
            effect_id,
            effect_attempt_id,
            provider_request_id,
            input_receipt.object_ref.reference_id,
            input_snapshot_hash,
            output_receipt.object_ref.reference_id,
            output_receipt.object_ref,
            output_hash,
            value,
            usage,
            cost_micro,
            started_at,
            completed_at,
            "SUCCEEDED",
            "CONFIRMED_REMOTE_OBSERVATION",
        )
        self.results.append(result)
        return result

    def inject_worker_loss(
        self,
        agent: AgentIdentity,
        *,
        task_id: str,
        after_invocation_started: bool,
    ) -> dict[str, Any]:
        call_id = "call-fault-" + stable_hash(
            "TRUE_MULTI_AGENT_FAULT_CALL",
            {"run_id": self.run_id, "agent_id": agent.agent_id, "task_id": task_id, "after_started": after_invocation_started},
        )[:32]
        effect_id = "effect-" + stable_hash("TRUE_MULTI_AGENT_FAULT_EFFECT", {"call": call_id})[:40]
        request = EffectRequest(
            effect_id,
            "model_text_generation",
            {"agent_id": agent.agent_id, "task_id": task_id, "fault_injection": True},
            str(self.policy["provider_profile"]),
            self.policy_hash,
            self.activation.manifest_hash,
            "low-non-mutating-text",
            "true-multi-agent-provider-principal",
            "model-text-generation",
            "idempotency-" + stable_hash("TRUE_MULTI_AGENT_FAULT_IDEMPOTENCY", {"effect": effect_id})[:40],
        )
        attempt_id = "effect-attempt-" + stable_hash("TRUE_MULTI_AGENT_FAULT_ATTEMPT", {"call": call_id})[:32]
        now = int(time.time())
        self.gateway.open_effect(request)
        task_fence = TaskFence("task-attempt-" + call_id, 1, "task-fence-" + call_id, now + 600)
        self.gateway.claim_attempt(effect_id, attempt_id, task_fence)
        self.gateway.prepare(
            effect_id,
            attempt_id,
            approval_hash="a" * 64,
            credential_handle_id="deepseek-credential-handle",
            manifest_hash=self.activation.manifest_hash,
        )
        started: dict[str, Any] | None = None
        if after_invocation_started:
            dispatch = DispatchFence("dispatch-" + call_id, 1, "dispatch-fence-" + call_id, now + 600)
            bundle = BudgetBundle.create(
                "budget-" + call_id,
                effect_id,
                attempt_id,
                dispatch.token,
                (BudgetReservation("provider_attempts", 1, now + 600),),
            ).activate("provider_attempts")
            breaker = CircuitBreaker("breaker-" + call_id, 1)
            precheck = breaker.precheck(attempt_id, dispatch.token)
            breaker, authorization = breaker.authorize_final(precheck, expected_version=breaker.version)
            started = self.gateway.start_invocation(
                effect_id, attempt_id, dispatch, now=now, budget_bundle=bundle, breaker_authorization=authorization
            )
        recovered = self.gateway.recover_after_crash(effect_id, attempt_id)
        state = self.gateway.effect(effect_id).state
        fact = {
            "schema": "CONTROLLED_PROVIDER_WORKER_LOSS_V1",
            "call_id": call_id,
            "agent_id": agent.agent_id,
            "effect_id": effect_id,
            "effect_attempt_id": attempt_id,
            "request_hash": request.request_hash,
            "idempotency_identity": request.idempotency_binding,
            "task_attempt_id": task_fence.task_attempt_id,
            "task_fencing_token_hash": sha256_bytes(task_fence.token.encode()),
            "dispatch_fencing_token_hash": sha256_bytes(str(started["dispatch_fence"]).encode()) if started else None,
            "invocation_started": after_invocation_started,
            "physical_send_count": 0,
            "max_physical_sends": 1,
            "sdk_retry_count": 0,
            "http_retry_count": 0,
            "token_count": 0,
            "cost_micro_usd": 0,
            "usage_settled": True,
            "attempt_disposition": recovered.disposition.value if recovered.disposition else None,
            "outcome_state": state.outcome_state.value,
            "settlement_state": state.settlement_state.value,
            "unresolved_transmission_exposure_count": state.unresolved_transmission_exposure_count,
            "automatic_retry_performed": False,
            "next_action": "BLOCK_AND_RECONCILE" if after_invocation_started else "SAFE_REASSIGN",
            "started_fact": started,
        }
        attempt_facts: list[dict[str, Any]] = [
            {
                "schema": "EFFECT_ATTEMPT_CLAIMED_V1",
                "effect_id": effect_id,
                "effect_attempt_id": attempt_id,
                "task_attempt_id": task_fence.task_attempt_id,
                "task_fence": task_fence.token,
            },
            {
                "schema": "EFFECT_ATTEMPT_PREPARED_V1",
                "effect_id": effect_id,
                "effect_attempt_id": attempt_id,
                "request_hash": request.request_hash,
                "idempotency_identity": request.idempotency_binding,
            },
        ]
        if started is not None:
            attempt_facts.append(started)
        attempt_facts.extend((
            {
                "schema": "EFFECT_ATTEMPT_DISPOSITION_V1",
                "effect_id": effect_id,
                "effect_attempt_id": attempt_id,
                "disposition": recovered.disposition.value if recovered.disposition else None,
                "physical_send_count": 0,
            },
            fact,
            {
                "schema": "PROVIDER_USAGE_RECORDED_V1",
                "call_id": call_id,
                "effect_id": effect_id,
                "effect_attempt_id": attempt_id,
                "provider": self.transport.profile.name,
                "model": self.transport.profile.model,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cost_micro_usd": 0,
                "outcome": state.outcome_state.value,
                "settlement": state.settlement_state.value,
                "physical_send_count": 0,
                "retry_count": 0,
                "fallback_count": 0,
                "usage_settled": True,
            },
        ))
        CanonicalStream(self.journal, self.run_id, f"effect/{self.run_id}/{effect_id}", self.policy_hash).append(
            "controlled-provider-worker-loss", tuple(attempt_facts), actor="fault-injection-controller"
        )
        self.recovery_attempts.append(dict(fact))
        return fact

    def inject_explicit_remote_failure(self, agent: AgentIdentity, *, task_id: str) -> dict[str, Any]:
        """Send one intentionally invalid request to DeepSeek and settle its explicit HTTP failure."""

        if self.call_count >= int(self.policy["max_provider_requests_per_run"]):
            raise TrueMultiAgentRuntimeError("Provider call ceiling reached before controlled failure")
        call_id = "call-fault-" + stable_hash(
            "TRUE_MULTI_AGENT_EXPLICIT_REMOTE_FAILURE_CALL",
            {"run_id": self.run_id, "agent_id": agent.agent_id, "task_id": task_id},
        )[:32]
        effect_id = "effect-" + stable_hash("TRUE_MULTI_AGENT_EXPLICIT_REMOTE_FAILURE_EFFECT", {"call": call_id})[:40]
        system_prompt = "You are a controlled Provider recovery probe. Return JSON only."
        user_prompt = "This request is intentionally invalid at the transport contract and must not execute inference."
        request = EffectRequest(
            effect_id,
            "model_text_generation",
            {
                "agent_id": agent.agent_id,
                "task_id": task_id,
                "fault_injection": "explicit_remote_failure",
                "system_prompt_hash": sha256_bytes(system_prompt.encode()),
                "user_prompt_hash": sha256_bytes(user_prompt.encode()),
                "max_output_tokens": -1,
            },
            str(self.policy["provider_profile"]),
            self.policy_hash,
            self.activation.manifest_hash,
            "low-non-mutating-text",
            "true-multi-agent-provider-principal",
            "model-text-generation",
            "idempotency-" + stable_hash("TRUE_MULTI_AGENT_EXPLICIT_REMOTE_FAILURE_IDEMPOTENCY", {"effect": effect_id})[:40],
        )
        attempt_id = "effect-attempt-" + stable_hash(
            "TRUE_MULTI_AGENT_EXPLICIT_REMOTE_FAILURE_ATTEMPT", {"call": call_id}
        )[:32]
        now = int(time.time())
        task_fence = TaskFence("task-attempt-" + call_id, 1, "task-fence-" + call_id, now + 600)
        dispatch = DispatchFence("dispatch-" + call_id, 1, "dispatch-fence-" + call_id, now + 600)
        bundle = BudgetBundle.create(
            "budget-" + call_id,
            effect_id,
            attempt_id,
            dispatch.token,
            (BudgetReservation("provider_attempts", 1, now + 600),),
        ).activate("provider_attempts")
        breaker = CircuitBreaker("breaker-" + call_id, 1)
        precheck = breaker.precheck(attempt_id, dispatch.token)
        breaker, authorization = breaker.authorize_final(precheck, expected_version=breaker.version)
        self.gateway.open_effect(request)
        self.gateway.claim_attempt(effect_id, attempt_id, task_fence)
        self.gateway.prepare(
            effect_id,
            attempt_id,
            approval_hash="a" * 64,
            credential_handle_id="deepseek-credential-handle",
            manifest_hash=self.activation.manifest_hash,
        )
        started = self.gateway.start_invocation(
            effect_id,
            attempt_id,
            dispatch,
            now=now,
            budget_bundle=bundle,
            breaker_authorization=authorization,
        )
        self.transport.prompts[effect_id] = (system_prompt, user_prompt)
        self.transport.configure_fault(effect_id, "explicit_remote_failure")
        status_code = None
        error_hash = None
        try:
            self.gateway.transmit(effect_id, attempt_id)
        except ProviderHTTPError as error:
            status_code = int(error.status_code)
            error_hash = sha256_bytes(str(error).encode())
        if status_code is None or error_hash is None:
            raise TrueMultiAgentRuntimeError("controlled Provider request lacked an explicit remote failure")
        self.call_count += 1
        source = "deepseek-http-failure-adapter"
        observation_key = hashlib.sha256(
            b"SITINA-TRUE-MULTI-AGENT-HTTP-FAILURE-OBSERVATION-V1\0" + bytes.fromhex(self.activation.manifest_hash)
        ).digest()
        external_request_id = "provider-failure-" + stable_hash(
            "TRUE_MULTI_AGENT_PROVIDER_FAILURE_REQUEST", {"call_id": call_id, "status_code": status_code}
        )[:32]
        raw_observation = make_signed_observation(
            {
                "schema_major": 1,
                "observation_id": "observation-" + stable_hash("TRUE_MULTI_AGENT_FAILURE_OBSERVATION", {"call": call_id})[:40],
                "source_identity": source,
                "manifest_hash": self.activation.manifest_hash,
                "effect_id": effect_id,
                "effect_attempt_id": attempt_id,
                "request_hash": request.request_hash,
                "nonce": "nonce-" + stable_hash("TRUE_MULTI_AGENT_FAILURE_NONCE", {"call": call_id})[:32],
                "received_at": int(time.time()),
                "remote_outcome": OutcomeState.FAILED_CONFIRMED.value,
                "external_request_id": external_request_id,
                "remote_execution_id": None,
            },
            observation_key,
        )
        expected = {
            "source_identity": source,
            "manifest_hash": self.activation.manifest_hash,
            "effect_id": effect_id,
            "effect_attempt_id": attempt_id,
            "request_hash": request.request_hash,
            "external_request_id": external_request_id,
        }
        admission = ObservationIngress({source: observation_key}, now=lambda: int(time.time())).admit(
            raw_observation,
            expected=expected,
            external_request_id_required=True,
        )
        if admission.observation is None:
            raise TrueMultiAgentRuntimeError("explicit Provider failure observation failed admission")
        applied = EffectObservationApplier(self.gateway.effect(effect_id).state).apply(
            admission.observation,
            expected_effect_version=0,
        )
        closed_attempt = self.gateway.settle_from_observation(
            effect_id,
            attempt_id,
            admission.observation.observation_id,
            applied.state,
        )
        fact = {
            "schema": "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1",
            "call_id": call_id,
            "agent_id": agent.agent_id,
            "effect_id": effect_id,
            "effect_attempt_id": attempt_id,
            "request_hash": request.request_hash,
            "idempotency_identity": request.idempotency_binding,
            "task_attempt_id": task_fence.task_attempt_id,
            "task_fencing_token_hash": sha256_bytes(task_fence.token.encode()),
            "dispatch_fencing_token_hash": sha256_bytes(dispatch.token.encode()),
            "provider_http_status": status_code,
            "provider_error_hash": error_hash,
            "physical_send_count": closed_attempt.physical_send_count,
            "max_physical_sends": 1,
            "sdk_retry_count": 0,
            "http_retry_count": 0,
            "attempt_disposition": closed_attempt.disposition.value if closed_attempt.disposition else None,
            "outcome_state": applied.state.outcome_state.value,
            "settlement_state": applied.state.settlement_state.value,
            "settlement_basis": applied.state.settlement_basis.value,
            "unresolved_transmission_exposure_count": applied.state.unresolved_transmission_exposure_count,
            "observation_id": admission.observation.observation_id,
            "token_count": 0,
            "cost_micro_usd": 0,
            "usage_settled": True,
            "automatic_retry_performed": False,
        }
        CanonicalStream(self.journal, self.run_id, f"effect/{self.run_id}/{effect_id}", self.policy_hash).append(
            "provider-explicit-remote-failure",
            (
                {
                    "schema": "EFFECT_ATTEMPT_CLAIMED_V1",
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "task_attempt_id": task_fence.task_attempt_id,
                    "task_fence": task_fence.token,
                },
                {
                    "schema": "EFFECT_ATTEMPT_PREPARED_V1",
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "request_hash": request.request_hash,
                    "idempotency_identity": request.idempotency_binding,
                },
                started,
                {
                    "schema": "EFFECT_ATTEMPT_DISPOSITION_V1",
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "disposition": closed_attempt.disposition.value if closed_attempt.disposition else None,
                    "physical_send_count": closed_attempt.physical_send_count,
                },
                fact,
                {
                    "schema": "EFFECT_OBSERVATION_ADMITTED_V1",
                    "observation_id": admission.observation.observation_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "external_request_id": external_request_id,
                    "raw_evidence_hash": admission.observation.raw_evidence_hash,
                },
                {
                    "schema": "EFFECT_RECONCILIATION_SETTLED_V1",
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "state": applied.state.mapping(),
                    "automatic_retry_performed": False,
                },
                {
                    "schema": "PROVIDER_USAGE_RECORDED_V1",
                    "call_id": call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": attempt_id,
                    "provider": self.transport.profile.name,
                    "model": self.transport.profile.model,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "cost_micro_usd": 0,
                    "outcome": OutcomeState.FAILED_CONFIRMED.value,
                    "settlement": applied.state.settlement_state.value,
                    "physical_send_count": closed_attempt.physical_send_count,
                    "retry_count": 0,
                    "fallback_count": 0,
                    "usage_settled": True,
                },
            ),
            actor="provider-recovery-controller",
        )
        self.recovery_attempts.append(dict(fact))
        return fact
