from __future__ import annotations

import hashlib
import hmac
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
from sitina.journal.model import (
    EventEnvelope, FrontierRef, canonical_json_bytes, domain_hash,
    is_code_mode_authority_reserved, pre_provider_scope_projection,
    pre_provider_call_identity, CODE_MODE_PRE_PROVIDER_PHASES,
    CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE,
    provider_call_identity_v2,
    CODE_MODE_EXECUTION_PARENT_SCHEMA,
    CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
    CODE_MODE_LIVE_CAPABILITY_PURPOSES,
    CODE_MODE_PROVIDER_TOKEN_TEST_PURPOSE,
)
from sitina.legacy.fence import issue_frozen_network_egress_capability
from sitina.orchestrator.agent_context_v2 import AgentContextManifestRepository
from sitina.orchestrator.output_contracts import (
    OutputContractError,
    OutputContractSpec,
    is_critical_contract_task,
    resolve_output_contract,
    validate_output_contract,
)
from sitina.protocols.tasks import TaskAggregate
from sitina.runners.provider import (
    AnthropicCompatibleClient,
    ProviderCompletion,
    ProviderConnectTimeout,
    ProviderError,
    ProviderHTTPError,
    ProviderReadTimeout,
    RoleProfileResolver,
    OPENAI_CHAT_COMPLETIONS,
    infer_wire_protocol,
    provider_endpoint_allowed,
    token_usage_summary,
)
from sitina.security.key_provider import KeyPurpose
from sitina.scheduling.agents import AgentCandidate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


TENANT = "default"
RUNTIME_NAMESPACE = "sitina-true-multi-agent-v1"
SIGNING_DOMAIN = b"SITINA-TRUE-MULTI-AGENT-ACTIVATION-V1\0"
STRUCTURED_RESPONSE_TOOL_NAME = "sitina_structured_response"


class TrueMultiAgentRuntimeError(RuntimeError):
    pass


class _ControllerCapabilityIssuer:
    """Ephemeral controller-only issuer; never serialized or handed to a worker."""
    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key

    def mint(self, *, purpose: str, session_id: str, run_id: str,
             issued_at: int, expires_at: int,
             cli_session_instance_id: str | None = None) -> "LiveNetworkCapabilityHandle":
        return LiveNetworkCapabilityHandle(
            purpose=purpose, session_id=session_id, run_id=run_id,
            issued_at=issued_at, expires_at=expires_at, nonce=uuid.uuid4().hex,
            issuer=self, cli_session_instance_id=cli_session_instance_id,
        )

    def mint_pre_provider(
        self, *, session_instance_id: str, conversation_session_id: str,
        turn_index: int, run_id: str, run_attempt: int,
        generation: str,
        provider_profile: str, provider_model: str,
        issued_at: int, expires_at: int,
    ) -> "PreProviderAuthorizationHandle":
        """Mint the pre-Forge capability from the controller boundary.

        The resulting handle is deliberately a different type and signed
        domain from the post-review live/canary capability.  The host pins
        this issuer public key during the attested bind; a locally-created
        issuer therefore cannot be exchanged for a valid authorization.
        """
        return PreProviderAuthorizationHandle(
            session_instance_id=session_instance_id,
            conversation_session_id=conversation_session_id,
            turn_index=turn_index,
            run_id=run_id,
            run_attempt=run_attempt,
            generation=generation,
            provider_profile=provider_profile,
            provider_model=provider_model,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=uuid.uuid4().hex,
            issuer=self,
        )


class LiveNetworkCapabilityHandle:
    """Opaque current-session live opt-in minted by the controller."""

    __slots__ = (
        "_purpose", "_scope", "_session_id", "_run_id", "_issued_at",
        "_expires_at", "_nonce", "_consumed", "_cli_session_instance_id",
        "_issuer_public_key", "_issuer_signature",
    )

    def __init__(
        self, *, purpose: str, session_id: str, run_id: str,
        issued_at: int, expires_at: int, nonce: str, issuer: object,
        cli_session_instance_id: str | None = None,
    ) -> None:
        if not isinstance(issuer, _ControllerCapabilityIssuer):
            raise TypeError("live capability handles are controller-minted")
        if not session_id or not run_id or not nonce:
            raise ValueError("live capability binding is incomplete")
        if type(issued_at) is not int or type(expires_at) is not int or expires_at <= issued_at:
            raise ValueError("live capability lifetime is invalid")
        self._purpose = purpose
        self._scope = "current-session"
        self._session_id = session_id
        self._run_id = run_id
        self._issued_at = issued_at
        self._expires_at = expires_at
        self._nonce = nonce
        self._consumed = False
        self._cli_session_instance_id = str(cli_session_instance_id or "")
        self._issuer_public_key = issuer.public_key_bytes
        self._issuer_signature = issuer._private_key.sign(self._scope_bytes())

    def _scope_bytes(self) -> bytes:
        return canonical_json_bytes({
            # The verifier receives the exact public capability projection.
            # Keep the schema and explicit live opt-in in the signed domain;
            # omitting either field would make a valid controller handle fail
            # the host's independent signature check.
            "schema": "SITINA_SESSION_LIVE_CAPABILITY_V1",
            "live_opt_in": True,
            "purpose": self._purpose, "scope": self._scope,
            "session_id": self._session_id, "run_id": self._run_id,
            "issued_at": self._issued_at, "expires_at": self._expires_at,
            "nonce": self._nonce,
            "cli_session_instance_id": self._cli_session_instance_id,
        })
    def as_mapping(self) -> dict[str, Any]:
        if self._consumed:
            raise TrueMultiAgentRuntimeError("live capability has already been consumed")
        return {
            "schema": "SITINA_SESSION_LIVE_CAPABILITY_V1",
            "live_opt_in": True,
            "purpose": self._purpose,
            "scope": self._scope,
            "session_id": self._session_id,
            "cli_session_instance_id": self._cli_session_instance_id,
            "run_id": self._run_id,
            "issued_at": self._issued_at,
            "expires_at": self._expires_at,
            "nonce": self._nonce,
            "issuer_public_key": self._issuer_public_key.hex(),
            "issuer_signature": self._issuer_signature.hex(),
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_mapping()[key]

    def consume(self) -> None:
        if self._consumed:
            raise TrueMultiAgentRuntimeError("live capability replay is rejected")
        self._consumed = True


class PreProviderAuthorizationHandle:
    """Controller-issued, pre-Forge provider admission handle.

    This is not a canary permit and cannot be used by the post-review
    transport path.  It carries only a signed scope projection; the host
    consumes the one-use handle and returns the actual authorization.
    """

    __slots__ = (
        "_scope", "_consumed", "_issuer_public_key", "_issuer_signature",
    )

    def __init__(
        self, *, session_instance_id: str, conversation_session_id: str,
        turn_index: int, run_id: str, run_attempt: int,
        generation: str,
        provider_profile: str, provider_model: str,
        issued_at: int, expires_at: int, nonce: str, issuer: object,
    ) -> None:
        if not isinstance(issuer, _ControllerCapabilityIssuer):
            raise TypeError("pre-provider handles are controller-minted")
        self._scope = pre_provider_scope_projection(
            session_instance_id=session_instance_id,
            conversation_session_id=conversation_session_id,
            turn_index=turn_index,
            run_id=run_id,
            run_attempt=run_attempt,
            generation=generation,
            provider_profile=provider_profile,
            provider_model=provider_model,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
        )
        self._consumed = False
        self._issuer_public_key = issuer.public_key_bytes
        self._issuer_signature = issuer._private_key.sign(self._scope_bytes())

    def _scope_bytes(self) -> bytes:
        return b"SITINA-CODE-MODE-PRE-PROVIDER-HANDLE-V1\0" + canonical_json_bytes(self._scope)

    def as_mapping(self) -> dict[str, Any]:
        if self._consumed:
            raise TrueMultiAgentRuntimeError("pre-provider handle has already been consumed")
        return {
            **dict(self._scope),
            "issuer_public_key": self._issuer_public_key.hex(),
            "issuer_signature": self._issuer_signature.hex(),
        }

    def consume(self) -> None:
        if self._consumed:
            raise TrueMultiAgentRuntimeError("pre-provider handle replay is rejected")
        self._consumed = True


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_hash(label: str, value: Any) -> str:
    return domain_hash(label, canonical_json_bytes(value))


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _provider_endpoint_allowed(base_url: str, profile: Any | None = None) -> bool:
    """Apply endpoint admission from the launcher-owned provider profile."""

    return provider_endpoint_allowed(
        base_url,
        profile_name=str(getattr(profile, "name", "") or ""),
        wire_protocol=getattr(profile, "wire_protocol", None),
        allowed_hosts=getattr(profile, "allowed_endpoint_hosts", ()),
    )


def structured_response_tools(contract: OutputContractSpec | None = None) -> list[dict[str, Any]]:
    """Return the native single-tool JSON frame for live Agent results.

    The application-level validator remains authoritative for task-specific
    fields.  This tool fixes the provider transport shape to one function
    argument object while retaining those per-task checks for missing, extra,
    and wrongly typed fields.
    """

    parameters = contract.wire_schema() if contract is not None else {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string"},
            "kind": {"type": "string"},
        },
        "required": ["agent_id", "kind"],
        "additionalProperties": True,
    }
    return [{
        "type": "function",
        "function": {
            "name": STRUCTURED_RESPONSE_TOOL_NAME,
            "description": (
                "Return the complete Sitina Agent result as one JSON object in "
                "the function arguments. Do not emit prose, Markdown, wrappers, "
                "or a second object."
            ),
            "parameters": parameters,
        },
    }]


def issue_root_pre_provider_authorization(
    context: Any,
    *,
    policy: Mapping[str, Any],
    session_id: str,
    turn_index: int,
    run_id: str,
    run_attempt: int = 1,
    provider_profile: Any | None = None,
) -> Mapping[str, Any]:
    """Issue the single root permit used by every live planning path.

    FAST and MULTI must enter the same broker/ledger boundary.  Keeping the
    lookup and exact binding in this provider-neutral helper prevents one
    route from silently constructing a weaker activation envelope.
    """

    if not isinstance(policy, Mapping):
        raise TrueMultiAgentRuntimeError("root pre-provider policy is invalid")
    if not isinstance(session_id, str) or not session_id.strip():
        raise TrueMultiAgentRuntimeError("root pre-provider session binding is missing")
    if type(turn_index) is not int or turn_index < 0:
        raise TrueMultiAgentRuntimeError("root pre-provider turn binding is invalid")
    if not isinstance(run_id, str) or not run_id.strip():
        raise TrueMultiAgentRuntimeError("root pre-provider run binding is missing")
    if type(run_attempt) is not int or run_attempt != 1:
        raise TrueMultiAgentRuntimeError("root pre-provider run attempt is invalid")
    profile_getter = getattr(context, "authoritative_provider_profile", None)
    issuer = getattr(context, "issue_pre_provider_authorization", None)
    if not callable(profile_getter) or not callable(issuer):
        raise TrueMultiAgentRuntimeError(
            "root pre-provider authorization requires the broker-owned issuer"
        )
    profile = provider_profile
    if profile is None:
        profile = profile_getter(str(policy["provider_profile"]))
    profile_name = str(getattr(profile, "name", "") or "").strip()
    profile_model = str(getattr(profile, "model", "") or "").strip()
    if not profile_name or not profile_model:
        raise TrueMultiAgentRuntimeError("root pre-provider provider binding is incomplete")
    generation = str(getattr(getattr(context, "identity", None), "epoch_root", "") or "")
    if not generation:
        raise TrueMultiAgentRuntimeError("root pre-provider generation is missing")
    authorization = issuer(
        session_id=session_id,
        turn_index=turn_index,
        run_id=run_id,
        run_attempt=run_attempt,
        generation=generation,
        provider_profile=profile_name,
        provider_model=profile_model,
    )
    if not isinstance(authorization, Mapping):
        raise TrueMultiAgentRuntimeError("root pre-provider issuer returned no authorization")
    return dict(authorization)


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
    # Kept only in the live controller process.  The activation mapping and
    # all durable facts contain its non-authorizing id/hash, never this raw
    # permit or its signature.
    pre_provider_authorization: Mapping[str, Any] | None = field(default=None, repr=False)


def activate_runtime(
    home: Path,
    context: Any,
    cas: LocalCAS,
    registry: AgentRegistry,
    policy: Mapping[str, Any],
    *,
    live_capability: LiveNetworkCapabilityHandle | None = None,
    pre_provider_authorization: Mapping[str, Any] | None = None,
    run_id: str | None = None,
    session_id: str | None = None,
    provider_profile: Any | None = None,
    offline: bool = False,
    source_root: Path | None = None,
) -> RuntimeActivation:
    component_root = Path(source_root or home).expanduser().resolve(strict=True)
    source_paths = (
        component_root / "core/sitina/orchestrator/true_multi_agent_runtime.py",
        component_root / "core/sitina/orchestrator/true_multi_agent.py",
        component_root / "core/sitina/orchestrator/execution_bridge.py",
        component_root / "core/sitina/orchestrator/execution_sandbox.py",
        component_root / "core/sitina/orchestrator/execution_verification.py",
        component_root / "core/sitina/legacy/fence.py",
        component_root / "core/sitina/conversation/__init__.py",
        component_root / "core/sitina/conversation/models.py",
        component_root / "core/sitina/conversation/context.py",
        component_root / "core/sitina/conversation/router.py",
        component_root / "core/sitina/conversation/runtime.py",
        component_root / "core/sitina/conversation/fast_runtime.py",
        component_root / "core/sitina/scheduling/agents.py",
        component_root / "core/sitina/protocols/handoff_contracts.py",
        component_root / "core/sitina/runners/provider.py",
        component_root / "core/sitina/orchestrator/execution_target.py",
        component_root / "core/sitina/orchestrator/managed_processes.py",
        component_root / "config/conversation_router.json",
        component_root / "config/true_multi_agent_agents.json",
        component_root / "config/true_multi_agent_policy.json",
        component_root / "config/sitina.yaml",
    )
    try:
        base_config = json.loads((component_root / "config/sitina.yaml").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrueMultiAgentRuntimeError("live capability configuration is unavailable") from error
    effects = dict(base_config.get("effects") or {})
    configured_level = str(effects.get("activation_level") or "MOCK_ONLY")
    pre_provider = dict(pre_provider_authorization) if isinstance(pre_provider_authorization, Mapping) else None
    if live_capability is not None and not isinstance(live_capability, LiveNetworkCapabilityHandle):
        raise TrueMultiAgentRuntimeError("live activation requires a controller-owned opaque capability")
    capability = live_capability.as_mapping() if live_capability is not None else {}
    live_requested = bool(capability.get("live_opt_in"))
    requires_pre_provider = not offline and callable(getattr(context, "_authoritative_transport_ledger", None))
    if configured_level == "MOCK_ONLY" and not live_requested and pre_provider is None and not offline:
        raise TrueMultiAgentRuntimeError(
            "Provider physical send denied: configured effects activation level is MOCK_ONLY; "
            "explicit current-session live opt-in is required"
        )
    if live_requested:
        if capability.get("purpose") not in CODE_MODE_LIVE_CAPABILITY_PURPOSES or capability.get("scope") != "current-session":
            raise TrueMultiAgentRuntimeError("live capability purpose/scope is invalid")
        if not run_id or str(capability.get("run_id")) != str(run_id):
            raise TrueMultiAgentRuntimeError("live capability is not bound to this run")
        if session_id is None or str(capability.get("session_id")) != str(session_id):
            raise TrueMultiAgentRuntimeError("live capability is not bound to this session")
        now = int(time.time())
        try:
            issued_at = int(capability["issued_at"])
            expires_at = int(capability["expires_at"])
        except (KeyError, TypeError, ValueError) as error:
            raise TrueMultiAgentRuntimeError("live capability expiry is invalid") from error
        if issued_at > now or expires_at <= now or expires_at - issued_at > 3600:
            raise TrueMultiAgentRuntimeError("live capability is expired or exceeds one-session lifetime")
    elif bool(effects.get("live_capability_authorized")) and not offline:
        raise TrueMultiAgentRuntimeError("configured live capability requires an explicit session opt-in")

    # Routine Code Mode planning/execution is a separate capability domain
    # from the post-review canary.  A live activation must already have
    # completed the one-use host exchange before any ProviderExecutor exists.
    # Offline scripted providers intentionally do not cross this boundary.
    if requires_pre_provider:
        if pre_provider is None:
            raise TrueMultiAgentRuntimeError(
                "live Provider activation requires a host-issued pre-provider authorization"
            )
        required_pre = {
            "schema", "purpose", "authorization_id", "session_instance_id",
            "conversation_session_id", "turn_index", "run_id", "run_attempt",
            "generation", "provider_profile", "provider_model", "allowed_phases", "issued_at",
            "expires_at", "nonce_hash", "issuer_key_id", "authority_signature_hex",
        }
        if set(pre_provider) != required_pre or pre_provider.get("schema") != CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA:
            raise TrueMultiAgentRuntimeError("pre-provider authorization projection is not exact")
        if pre_provider.get("purpose") != "pre-provider-root-planning":
            raise TrueMultiAgentRuntimeError("pre-provider authorization purpose is invalid")
        if pre_provider.get("session_instance_id") != getattr(context, "session_instance_id", None):
            raise TrueMultiAgentRuntimeError("pre-provider authorization session instance changed")
        if pre_provider.get("conversation_session_id") != session_id:
            raise TrueMultiAgentRuntimeError("pre-provider authorization conversation binding changed")
        if pre_provider.get("run_id") != run_id or type(pre_provider.get("run_attempt")) is not int or pre_provider.get("run_attempt") != 1:
            raise TrueMultiAgentRuntimeError("pre-provider authorization run binding changed")
        if pre_provider.get("generation") != str(getattr(getattr(context, "identity", None), "epoch_root", "")):
            raise TrueMultiAgentRuntimeError("pre-provider authorization generation changed")
        if type(pre_provider.get("turn_index")) is not int or pre_provider.get("turn_index") < 0:
            raise TrueMultiAgentRuntimeError("pre-provider authorization turn binding is invalid")
        if type(pre_provider.get("issued_at")) is not int or type(pre_provider.get("expires_at")) is not int:
            raise TrueMultiAgentRuntimeError("pre-provider authorization lifetime is invalid")
        if int(pre_provider["issued_at"]) > int(time.time()) or int(pre_provider["expires_at"]) <= int(time.time()):
            raise TrueMultiAgentRuntimeError("pre-provider authorization is expired")
        if tuple(pre_provider.get("allowed_phases") or ()) != tuple(CODE_MODE_PRE_PROVIDER_PHASES):
            raise TrueMultiAgentRuntimeError("pre-provider phase allowlist changed")
        key_id = pre_provider.get("issuer_key_id")
        signature_hex = pre_provider.get("authority_signature_hex")
        if not isinstance(key_id, str) or not isinstance(signature_hex, str):
            raise TrueMultiAgentRuntimeError("pre-provider authority signature is incomplete")
        unsigned_pre = {key: value for key, value in pre_provider.items() if key != "authority_signature_hex"}
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError as error:
            raise TrueMultiAgentRuntimeError("pre-provider authority signature is malformed") from error
        verifier = getattr(context, "_verify_host_signature", None)
        if not callable(verifier) or not verifier(key_id, canonical_json_bytes(unsigned_pre), signature):
            raise TrueMultiAgentRuntimeError("pre-provider authorization authority signature is invalid")
    if not offline:
        # In live mode the host is the only profile authority. A profile
        # object supplied by an embedding caller cannot choose the canary
        # identity before the host transport is engaged.
        profile_getter = getattr(context, "authoritative_provider_profile", None)
        if not callable(profile_getter):
            raise TrueMultiAgentRuntimeError(
                "live Provider activation requires the CLI-owned host profile"
            )
        profile = profile_getter(str(policy["provider_profile"]))
    elif provider_profile is not None:
        profile = provider_profile
    else:
        profile = AnthropicCompatibleClient(component_root).load_profile(str(policy["provider_profile"]))
    host = urlparse(profile.base_url).hostname
    if not offline and not _provider_endpoint_allowed(profile.base_url, profile):
        raise TrueMultiAgentRuntimeError("true multi-agent runtime permits only the HTTPS endpoint fixed by the provider profile")
    if offline:
        # Offline clients are still required to declare a supported wire
        # protocol, but their loopback/mock endpoint never crosses the host
        # network boundary.  A mock endpoint is never admitted in live mode.
        try:
            infer_wire_protocol(profile.name, profile.base_url, getattr(profile, "wire_protocol", None))
        except Exception as error:
            raise TrueMultiAgentRuntimeError("offline Provider profile has no supported wire protocol") from error
    if not offline and profile.model not in set(policy["provider_model_allowlist"]):
        raise TrueMultiAgentRuntimeError("Provider model is outside the true multi-agent allowlist")
    unsigned = {
        "schema": "SITINA_TRUE_MULTI_AGENT_ACTIVATION_V1",
        "runtime_home": str(home),
        "source_root": str(component_root),
        "production_genesis_hash": context.genesis.genesis_hash,
        "journal_id": context.genesis.journal_id,
        "journal_epoch": int(context.genesis.epoch_root.rsplit("-", 1)[1]),
        "registry_generation": registry.generation,
        "registry_hash": registry.registry_hash,
        "policy_hash": sha256_bytes(canonical_json_bytes(dict(policy))),
        "source_sha256": {
            str(path): _physical_sha256(path)
            for path in source_paths
            if path.is_file()
        } if offline else {str(path): _physical_sha256(path) for path in source_paths},
        "provider": {
            "profile": profile.name,
            "model": profile.model,
            "base_url_host": host,
            "transport_retries": min(3, int(policy.get("transport_retries", 0))),
            "sdk_retries": min(3, int(policy.get("sdk_retries", 0))),
            "fallbacks": min(1, int(policy.get("fallbacks", 0))),
            "provider_test_no_fallback": bool(
                policy.get("provider_test_no_fallback", policy.get("deepseek_token_test_no_fallback", False))
                and capability.get("purpose") == CODE_MODE_PROVIDER_TOKEN_TEST_PURPOSE
            ),
            "configured_activation_level": configured_level,
            "effective_activation_level": "LIVE_CANARY" if live_requested else ("CODE_MODE_OFFLINE" if offline else ("LIVE_PRE_PROVIDER" if pre_provider is not None else "MOCK_ONLY")),
            "live_capability_ref": (
                "live-capability:" + sha256_bytes(canonical_json_bytes(capability))
                if live_requested else None
            ),
        },
        "allowed_mutations": [str(home / "journal"), str(home / "cas"), str(home / "projections/disposable-rebuilds"), str(home / "output")],
        "legacy_read_allowed": False,
        "acceptance_read_allowed": False,
        "external_mutation_allowed": bool(policy.get("external_mutation_allowed", False)) and live_requested,
            "created_at": now_rfc3339(),
        }
    if pre_provider is not None and not offline:
        unsigned["provider"]["pre_provider_authorization_id"] = str(pre_provider["authorization_id"])
        unsigned["provider"]["pre_provider_authorization_hash"] = sha256_bytes(canonical_json_bytes(pre_provider))
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
    return RuntimeActivation(signed, manifest_hash, receipt, pre_provider)


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
        # A root-shaped event is not a seal.  Only the Journal's durable,
        # authenticated seal index can close this stream; otherwise a normal
        # writer could create a denial-of-service marker by copying V2 fields.
        raw_sealed_streams = getattr(journal, "_sealed_code_mode_streams", ())
        try:
            sealed_streams = set(raw_sealed_streams)
        except (TypeError, ValueError):
            # A test/dummy Journal that cannot expose the durable index must
            # never be treated as sealed.  Real sealing is enforced by
            # LocalJournal itself at the append boundary.
            sealed_streams = set()
        self._sealed = self.stream_id in sealed_streams
        self.gateway = CommandGateway(journal)

    def _append(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        request_nonce: str | None = None,
        source_frontier: FrontierRef | None = None,
        deadline: str | None = None,
        authority_envelope: Mapping[str, Any] | None = None,
        planned_operation: tuple[Mapping[str, Any], str, int, str | None] | None = None,
        attempt_advance: bool = False,
        tty_nonce_consumption: bool = False,
        execution_authorization_root: bool = False,
        execution_parent_root: bool = False,
        forge_child_authorization: bool = False,
        completion_plan_fact: bool = False,
        code_mode_fact: bool = False,
        terminal_bundle: bool = False,
        producer_role: str | None = None,
        root_producer: bool = False,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        if self._sealed:
            raise TrueMultiAgentRuntimeError("canonical stream is closed after its Code Mode receipt root")
        if not facts:
            raise TrueMultiAgentRuntimeError("canonical Command requires at least one fact")
        finalization = authority_envelope is not None
        planned_logical_hash = None
        if planned_operation is not None:
            planned_logical_hash = next(
                (
                    str(item.get("logical_operation_hash"))
                    for item in (planned_operation[0].get("operations") or planned_operation[0].get("logical_operations") or ())
                    if isinstance(item, Mapping) and item.get("logical_operation_id") == planned_operation[1]
                ),
                None,
            )
            if not planned_logical_hash:
                raise TrueMultiAgentRuntimeError("planned operation commitment is missing")
        if finalization and stage not in {
            "code-mode-review-acceptance", "code-mode-terminal", "code-mode-final-root",
            "code-mode-conversation",
        }:
            raise TrueMultiAgentRuntimeError("authority operation stage is not permitted")
        if attempt_advance and (authority_envelope is not None or stage != "execution-authorization-attempt-advance"):
            raise TrueMultiAgentRuntimeError("attempt advance must use its dedicated Journal command")
        if tty_nonce_consumption and (authority_envelope is not None or stage != "tty-review-nonce-consumed"):
            raise TrueMultiAgentRuntimeError("TTY nonce consumption must use its dedicated Journal command")
        if tty_nonce_consumption and attempt_advance:
            raise TrueMultiAgentRuntimeError("conflicting reserved Journal command")
        if execution_authorization_root and (authority_envelope is not None or stage != "execution-authorization-bound"):
            raise TrueMultiAgentRuntimeError("execution authorization root must use its dedicated Journal command")
        if execution_parent_root and (authority_envelope is not None or stage != "execution-parent-bound"):
            raise TrueMultiAgentRuntimeError("execution parent must use its dedicated Journal command")
        if execution_parent_root and (execution_authorization_root or forge_child_authorization or attempt_advance or tty_nonce_consumption):
            raise TrueMultiAgentRuntimeError("conflicting execution parent command")
        if forge_child_authorization and (authority_envelope is not None or stage != "execution-child-authorization"):
            raise TrueMultiAgentRuntimeError("Forge child authorization must use its dedicated Journal command")
        if forge_child_authorization and (execution_authorization_root or attempt_advance or completion_plan_fact or tty_nonce_consumption or terminal_bundle):
            raise TrueMultiAgentRuntimeError("conflicting reserved Journal command")
        if completion_plan_fact and (authority_envelope is not None or stage != "code-mode-completion-plan"):
            raise TrueMultiAgentRuntimeError("completion plan fact must use its dedicated Journal command")
        if code_mode_fact and (authority_envelope is not None or attempt_advance or tty_nonce_consumption or execution_authorization_root or completion_plan_fact):
            raise TrueMultiAgentRuntimeError("Code Mode producer fact command is not exclusive")
        if terminal_bundle and (not code_mode_fact or stage != "code-mode-terminal"):
            raise TrueMultiAgentRuntimeError("Code Mode terminal bundle requires its dedicated producer entry")
        if producer_role is not None and (not code_mode_fact or terminal_bundle):
            raise TrueMultiAgentRuntimeError("typed producer role is only valid for one non-terminal Code Mode fact")
        if root_producer and (not code_mode_fact or producer_role not in {
            "root_scheduling", "root_dispatch_acceptance", "root_dispatch",
            "root_settled", "root_result_accepted", "root_selection",
        }):
            raise TrueMultiAgentRuntimeError("root producer requires its dedicated typed Journal entry")
        facts = tuple(
            {
                **dict(fact),
                **({
                    "finalization_transaction": True,
                    "authority_operation": dict(authority_envelope or {}),
                } if finalization else {}),
                **({
                    "logical_operation_id": planned_operation[1],
                    "logical_operation_hash": planned_logical_hash,
                } if planned_operation is not None else {}),
            }
            for fact in facts
        )
        # Producer facts can be appended through a fresh stream instance.
        # Refresh a reused writer from the authenticated Journal head before
        # allocating its next command version.
        current_head = getattr(self.journal, "_stream_heads", {}).get(self.stream_id)
        if current_head is not None and int(current_head) > self.version:
            self.version = int(current_head)
            self.ordinal = self.version
        timestamp = now_rfc3339()
        expected_version = int(planned_operation[2]) if planned_operation is not None else self.version
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
                "code-mode.authority.v3" if finalization else (
                    "code-mode.attempt-advance" if attempt_advance else "true-multi-agent." + stage
                ),
            actor,
            timestamp,
            {
                "run_id": self.run_id,
                "stage": stage,
                "expected_stream_version": expected_version,
                "source_frontier": source_frontier.__dict__ if source_frontier else None,
                "policy_hash": self.policy_hash,
                "deadline": deadline,
                # Some one-use commands intentionally have a stable command
                # identity but a fresh submission request.  This lets the
                # Journal's command-id conflict rule reject a second racing
                # submission instead of treating it as an idempotent replay.
                "request_nonce": request_nonce,
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

        if attempt_advance:
            result = self.gateway.submit_code_mode_attempt_advance(
                command, expected_version, plan, proofs,
            )
        elif tty_nonce_consumption:
            result = self.gateway.submit_code_mode_tty_nonce_consumption(
                command, expected_version, plan, proofs,
            )
        elif execution_authorization_root:
            result = self.gateway.submit_code_mode_execution_authorization(
                command, expected_version, plan, proofs,
            )
        elif execution_parent_root:
            result = self.gateway.submit_code_mode_execution_parent(
                command, expected_version, plan, proofs,
            )
        elif forge_child_authorization:
            result = self.gateway.submit_code_mode_forge_child_authorization(
                command, expected_version, plan, proofs,
            )
        elif completion_plan_fact:
            result = self.gateway.submit_code_mode_completion_plan(
                command, expected_version, plan, proofs,
            )
        elif code_mode_fact:
            if producer_role is not None:
                result = (
                    self.gateway.submit_code_mode_root_producer_fact(
                        command, expected_version, plan, proofs,
                        producer_role=producer_role,
                    ) if root_producer else self.gateway.submit_code_mode_producer_fact(
                    command, expected_version, plan, proofs,
                    producer_role=producer_role,
                    )
                )
            else:
                result = self.gateway.submit_code_mode_fact(
                    command, expected_version, plan, proofs,
                    terminal_bundle=terminal_bundle,
                )
        elif authority_envelope is None:
            result = self.gateway.submit(command, expected_version, plan, proofs)
        elif planned_operation is not None:
            completion_plan, logical_operation_id, _, completion_plan_reference = planned_operation
            result = self.gateway.submit_planned_authority(
                command, expected_version, plan, proofs,
                completion_plan=completion_plan,
                logical_operation_id=logical_operation_id,
                completion_plan_reference=completion_plan_reference,
            )
        else:
            if stage == "code-mode-review-acceptance":
                result = self.gateway.submit_code_mode_acceptance(
                    command, expected_version, plan, proofs,
                    authority_envelope=authority_envelope,
                )
            else:
                result = self.gateway.submit_authority(
                    command,
                    expected_version,
                    plan,
                    proofs,
                    authority_envelope=authority_envelope,
                )
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

    def append(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        request_nonce: str | None = None,
        source_frontier: FrontierRef | None = None,
        deadline: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append ordinary facts; no caller-controlled seal mode exists."""
        return self._append(
            stage, facts, actor=actor, proofs=proofs, command_id=command_id,
            request_nonce=request_nonce, source_frontier=source_frontier,
            deadline=deadline, authority_envelope=None,
        )

    def append_attempt_advance(
        self,
        fact: Mapping[str, Any],
        *,
        actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str,
        request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append the controller-owned exact next-attempt mapping."""
        return self._append(
            "execution-authorization-attempt-advance", (fact,), actor=actor,
            proofs=proofs, command_id=command_id, request_nonce=request_nonce,
            attempt_advance=True,
        )

    def append_tty_nonce_consumption(
        self,
        fact: Mapping[str, Any],
        *,
        actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str,
        request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append the narrow one-use TTY consumption fact."""
        if not isinstance(fact, Mapping) or fact.get("schema") != "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1":
            raise TrueMultiAgentRuntimeError("TTY nonce consumption fact is invalid")
        normalized = dict(fact)
        normalized.setdefault("event_type", "code-mode.tty-review-nonce-consumed")
        return self._append(
            "tty-review-nonce-consumed", (normalized,), actor=actor,
            proofs=proofs, command_id=command_id, request_nonce=request_nonce,
            tty_nonce_consumption=True,
        )

    def append_execution_authorization_root(
        self, fact: Mapping[str, Any], *, actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None, request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        if not isinstance(fact, Mapping) or fact.get("schema") != "SITINA_EXECUTION_AUTHORIZATION_V1":
            raise TrueMultiAgentRuntimeError("execution authorization root fact is invalid")
        return self._append(
            "execution-authorization-bound", (fact,), actor=actor,
            proofs=proofs, command_id=command_id, request_nonce=request_nonce,
            execution_authorization_root=True,
        )

    def append_execution_parent_root(
        self, fact: Mapping[str, Any], *, actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None, request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        if not isinstance(fact, Mapping) or fact.get("schema") != CODE_MODE_EXECUTION_PARENT_SCHEMA:
            raise TrueMultiAgentRuntimeError("execution parent fact is invalid")
        if fact.get("event_type") != CODE_MODE_EXECUTION_PARENT_EVENT_TYPE:
            raise TrueMultiAgentRuntimeError("execution parent event type is invalid")
        return self._append(
            "execution-parent-bound", (fact,), actor=actor,
            proofs=proofs, command_id=command_id, request_nonce=request_nonce,
            execution_parent_root=True,
        )

    def append_forge_child_authorization(
        self, fact: Mapping[str, Any], *, actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None, request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append the current attempt's child mapping through its own gate."""
        if not isinstance(fact, Mapping) or fact.get("schema") != CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA:
            raise TrueMultiAgentRuntimeError("Forge child authorization fact is invalid")
        if fact.get("event_type") != CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE or fact.get("purpose") != CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE:
            raise TrueMultiAgentRuntimeError("Forge child authorization binding is invalid")
        return self._append(
            "execution-child-authorization", (fact,), actor=actor, proofs=proofs,
            command_id=command_id, request_nonce=request_nonce,
            forge_child_authorization=True,
        )

    def append_completion_plan_fact(
        self, fact: Mapping[str, Any], *, actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None, request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        if not isinstance(fact, Mapping) or fact.get("schema") != "CODE_MODE_COMPLETION_PLAN_FACT_V1":
            raise TrueMultiAgentRuntimeError("completion plan fact is invalid")
        return self._append(
            "code-mode-completion-plan", (fact,), actor=actor,
            proofs=proofs, command_id=command_id, request_nonce=request_nonce,
            completion_plan_fact=True,
        )

    def append_code_mode_fact(
        self, stage: str, fact: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, actor: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None, request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append one reserved producer fact via the dedicated gateway."""
        facts = (fact,) if isinstance(fact, Mapping) else tuple(fact)
        if not facts or any(not isinstance(item, Mapping) for item in facts):
            raise TrueMultiAgentRuntimeError("Code Mode producer fact is invalid")
        # The terminal projection is a dedicated Code Mode bundle containing
        # both ordinary-looking run events and one reserved evidence-seal
        # fact.  Keep this exception stage-scoped and exact: it must not turn
        # this method into a general reserved-schema escape hatch, and the
        # legacy run.terminal path remains on ``append``.
        terminal_bundle = stage == "code-mode-terminal"
        if terminal_bundle:
            expected = (
                ("run.closing", None),
                ("protocol.terminal.negative.probe.rejected", None),
                ("protocol.terminal.full.validation.accepted", "TERMINAL_FULL_VALIDATION_ACCEPTED_V1"),
                ("protocol.run.evidence.package.sealed", "RUN_EVIDENCE_PACKAGE_SEALED_V1"),
                ("code-mode.terminal-success", "CODE_MODE_TERMINAL_SUCCESS_V1"),
            )
            if len(facts) != len(expected):
                raise TrueMultiAgentRuntimeError("Code Mode terminal bundle has the wrong event count")
            for item, (event_type, schema) in zip(facts, expected):
                if item.get("event_type") != event_type or (schema is not None and item.get("schema") != schema):
                    raise TrueMultiAgentRuntimeError("Code Mode terminal bundle event order is invalid")
        elif not any(is_code_mode_authority_reserved(item) for item in facts):
            raise TrueMultiAgentRuntimeError("Code Mode producer fact is not reserved")
        producer_role = None
        if not terminal_bundle and len(facts) == 1:
            item = facts[0]
            schema = item.get("schema")
            evidence_schema = item.get("evidence_schema")
            producer_role = {
                "CODE_MODE_CANDIDATE_MANIFEST_FACT_V1": "candidate",
                "CODE_MODE_MACHINE_CHECK_RECEIPT_V1": "machine",
                "CODE_MODE_EVIDENCE_PACKAGE_V1": "package",
                "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1": "core",
                "CODE_MODE_REVIEW_REQUEST_V2": "request",
                "CODE_MODE_REVIEW_RECEIPT_V2": "review",
                "CODE_MODE_EVIDENCE_CLOSING_ROOT_V1": "closing_root",
                "CODE_MODE_TERMINAL_EVIDENCE_V1": "terminal",
                "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1": "reviewed_terminal",
            }.get(str(evidence_schema or schema))
            # The Journal fact is the common wrapper for the five evidence
            # roles.  Infer its role from the explicit evidence subtype; an
            # unknown subtype stays on the generic reserved path and is
            # rejected by the role-aware host/verifier.
        return self._append(
            stage, tuple(dict(item) for item in facts), actor=actor, proofs=proofs,
            command_id=command_id, request_nonce=request_nonce,
            code_mode_fact=True, terminal_bundle=(stage == "code-mode-terminal"),
            producer_role=producer_role,
        )

    def append_root_producer_fact(
        self, fact: Mapping[str, Any], *, actor: str, producer_role: str,
        command_id: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Append one authenticated root FSM fact through its typed gate."""
        if producer_role not in {
            "root_scheduling", "root_dispatch_acceptance", "root_dispatch",
            "root_settled", "root_result_accepted", "root_selection",
        }:
            raise TrueMultiAgentRuntimeError("unknown root producer role")
        if not isinstance(fact, Mapping):
            raise TrueMultiAgentRuntimeError("root producer fact is invalid")
        return self._append(
            "code-mode-root-producer", (dict(fact),), actor=actor,
            command_id=command_id, code_mode_fact=True,
            producer_role=producer_role, root_producer=True,
        )

    def append_authority_operation(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        envelope: Mapping[str, Any],
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        request_nonce: str | None = None,
        source_frontier: FrontierRef | None = None,
        deadline: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Submit a signed authority operation through the Journal gate."""
        if not isinstance(envelope, Mapping):
            raise TrueMultiAgentRuntimeError("signed authority operation is required")
        return self._append(
            stage, facts, actor=actor, proofs=proofs, command_id=command_id,
            request_nonce=request_nonce, source_frontier=source_frontier,
            deadline=deadline, authority_envelope=dict(envelope),
        )

    def append_code_mode_acceptance(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        envelope: Mapping[str, Any],
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        request_nonce: str | None = None,
        source_frontier: FrontierRef | None = None,
        deadline: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Use the dedicated host-built Code Mode acceptance gateway."""
        if stage != "code-mode-review-acceptance":
            raise TrueMultiAgentRuntimeError("dedicated acceptance gateway received an invalid stage")
        return self._append(
            stage, facts, actor=actor, proofs=proofs, command_id=command_id,
            request_nonce=request_nonce, source_frontier=source_frontier,
            deadline=deadline, authority_envelope=dict(envelope),
        )

    def append_planned_authority_operation(
        self,
        stage: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        actor: str,
        completion_plan: Mapping[str, Any],
        logical_operation_id: str,
        completion_plan_reference: str | None = None,
        proofs: Sequence[PublishedObjectReceipt] = (),
        command_id: str | None = None,
        request_nonce: str | None = None,
    ) -> tuple[Any, tuple[dict[str, Any], ...]]:
        """Commit the exact next operation in the signed completion plan.

        Code Mode finalization uses this entry point so a host-signed logical
        commitment is checked by LocalJournal against the actual event/CAS
        projection before a physical transaction is assigned.  No caller can
        turn an ordinary append into a finalization transaction.
        """
        if not isinstance(completion_plan, Mapping):
            raise TrueMultiAgentRuntimeError("signed completion plan is required")
        operation = next(
            (item for item in (completion_plan.get("operations") or completion_plan.get("logical_operations") or ())
             if isinstance(item, Mapping) and item.get("logical_operation_id") == logical_operation_id),
            None,
        )
        if not isinstance(operation, Mapping):
            raise TrueMultiAgentRuntimeError("planned logical operation is not in the signed plan")
        # The signed operation records the first assigned event version;
        # Journal commands are submitted against its predecessor frontier.
        expected_version = max(0, int(operation.get("expected_start_version") or (self.version + 1)) - 1)
        # No caller-supplied envelope is accepted after the acceptance
        # boundary.  The Journal revalidates the host-signed completion plan
        # and independently signed stage transaction before it derives the
        # internal append projection below.
        planned_envelope = {
            "schema": "AUTHORITY_FINALIZATION_TRANSACTION_V1",
            "operation": operation.get("operation"),
            "operation_id": operation.get("logical_operation_id"),
            "run_id": operation.get("run_id") or completion_plan.get("run_id"),
            "stream_id": operation.get("stream_id") or completion_plan.get("stream_id"),
            "generation": operation.get("generation") or completion_plan.get("generation"),
            "expected_stream_version": expected_version,
            "parent_operation_hash": operation.get("parent_logical_hash"),
            "payload_hash": operation.get("logical_operation_hash"),
            "issuer_key_id": completion_plan.get("issuer_key_id"),
            "signature_hex": completion_plan.get("authority_signature_hex"),
        }
        return self._append(
            stage, facts, actor=actor, proofs=proofs, command_id=command_id,
            request_nonce=request_nonce, authority_envelope=planned_envelope,
            planned_operation=(
                dict(completion_plan), logical_operation_id, expected_version,
                completion_plan_reference,
            ),
        )

    def seal(self) -> None:
        """Close this writer after a Code Mode receipt root is committed."""

        self._sealed = True


class CapturingProviderClient(AnthropicCompatibleClient):
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


# Compatibility name retained for existing offline fixtures; the production
# implementation and evidence use the provider-neutral class above.
CapturingDeepSeekClient = CapturingProviderClient


class OneShotProviderTransport:
    def __init__(
        self, client: CapturingProviderClient, profile: Any, *, timeout: int,
        max_sends: int, run_id: str = "", authoritative_physical: bool = True,
        transport_ledger: Any | None = None,
        transport_ledger_capability: object | None = None,
        max_retries: int = 0,
        fallback_profiles: Sequence[Any] = (),
        fallback_clients: Mapping[str, Any] | None = None,
        fallback_allowed: bool = True,
        max_fallbacks: int = 0,
        pre_provider_authorization: Mapping[str, Any] | None = None,
    ):
        self.client = client
        self.profile = profile
        self.run_id = str(run_id)
        self.authoritative_physical = bool(authoritative_physical)
        self.transport_ledger = transport_ledger
        self.transport_ledger_capability = transport_ledger_capability
        self.timeout = timeout
        self.max_retries = min(3, max(0, int(max_retries)))
        self.fallback_allowed = bool(fallback_allowed)
        configured_fallbacks = list(fallback_profiles)
        self.max_fallbacks = min(
            1,
            max(0, int(max_fallbacks)),
            len(configured_fallbacks),
        ) if self.fallback_allowed else 0
        self.fallback_profiles = tuple(configured_fallbacks[: self.max_fallbacks])
        self.fallback_clients = dict(fallback_clients or {})
        # max_sends is a logical-call ceiling; physical sends include bounded
        # transient retries/fallbacks and are tracked separately for
        # billing/evidence.
        self.max_sends = max(1, int(max_sends)) * (1 + self.max_retries) * (1 + self.max_fallbacks)
        self.physical_send_count = 0
        self.retry_count = 0
        self.fallback_count = 0
        self.last_profile = profile
        self.prompts: dict[str, tuple[str, str]] = {}
        self.call_bindings: dict[str, dict[str, Any]] = {}
        self._logical_call_ids: set[str] = set()
        self.execution_authorization_ref: str | None = None
        # The executor keeps the session-scoped pre-provider authorization;
        # the transport only uses its non-secret scope fields as a fallback
        # when a call binding does not repeat them.  It is never serialized
        # into request evidence or provider payloads.
        self.pre_provider_authorization = (
            dict(pre_provider_authorization)
            if isinstance(pre_provider_authorization, Mapping)
            else None
        )
        self.root_fact_publisher: Callable[[str, Mapping[str, Any], str, Mapping[str, Any] | None], None] | None = None
        self.fault_modes: dict[str, str] = {}
        self.transport_receipts: list[dict[str, Any]] = []

    def configure_fault(self, effect_id: str, mode: str) -> None:
        if mode != "explicit_remote_failure":
            raise TrueMultiAgentRuntimeError("unsupported controlled Provider fault mode")
        self.fault_modes[effect_id] = mode

    @staticmethod
    def _retryable(error: BaseException) -> bool:
        if isinstance(error, ProviderHTTPError):
            # Only the explicitly idempotent service responses are eligible
            # for a bounded retry.  A timeout or any other transport status
            # has an unknown remote outcome and must not be sent again.
            return error.status_code in {429, 503}
        return False

    def send_once(self, request: EffectRequest, effect_attempt_id: str) -> dict[str, Any]:
        self.last_profile = self.profile
        retries_for_request = 0
        fallback_index = 0
        fallbacks_for_request = 0
        physical_attempts = 0
        while True:
            prior_physical_sends = self.physical_send_count
            try:
                value = self._send_physical(request, effect_attempt_id)
                physical_attempts += self.physical_send_count - prior_physical_sends
                value["retry_count"] = retries_for_request
                value["physical_attempts"] = physical_attempts
                value["fallback_count"] = fallbacks_for_request
                return value
            except BaseException as error:
                physical_attempts += self.physical_send_count - prior_physical_sends
                if not self._retryable(error):
                    raise
                if retries_for_request < self.max_retries:
                    retries_for_request += 1
                    self.retry_count += 1
                    delay = min(8.0, 0.25 * (2 ** (retries_for_request - 1)))
                    if isinstance(error, ProviderHTTPError) and error.retry_after_seconds is not None:
                        delay = min(8.0, max(delay, float(error.retry_after_seconds)))
                    time.sleep(delay)
                    continue
                if fallback_index >= self.max_fallbacks:
                    raise
                fallback_profile = self.fallback_profiles[fallback_index]
                fallback_index += 1
                fallbacks_for_request += 1
                self.fallback_count += 1
                self.last_profile = fallback_profile
                # The fallback is a new provider/model identity, but remains
                # one logical call.  Do not reset ``retries_for_request``:
                # the retry budget is per logical request across all provider
                # profiles, so a fallback cannot buy another three retries.
                # Its physical sends and retry facts stay in one immutable
                # call evidence record.
                continue

    def _send_physical(self, request: EffectRequest, effect_attempt_id: str) -> dict[str, Any]:
        active_profile = self.last_profile
        if request.operation != "model_text_generation" or active_profile.name not in {
            self.profile.name,
            *(item.name for item in self.fallback_profiles),
        }:
            raise TrueMultiAgentRuntimeError("Provider transport received an out-of-scope request")
        if self.physical_send_count >= self.max_sends and (
            not self.authoritative_physical or request.effect_id not in self._logical_call_ids
        ):
            raise TrueMultiAgentRuntimeError("per-run Provider request ceiling reached")
        system_prompt, user_prompt = self.prompts[request.effect_id]
        pre_provider_binding = self.call_bindings.get(request.effect_id, {})
        if request.request.get("system_prompt_hash") != sha256_bytes(system_prompt.encode()):
            raise TrueMultiAgentRuntimeError("system prompt binding changed after admission")
        if request.request.get("user_prompt_hash") != sha256_bytes(user_prompt.encode()):
            raise TrueMultiAgentRuntimeError("user prompt binding changed after admission")
        permit = None
        if self.authoritative_physical:
            if self.transport_ledger is None or self.transport_ledger_capability is None:
                raise TrueMultiAgentRuntimeError(
                    "authoritative Provider send requires the host transport"
                )
            if (
                isinstance(pre_provider_binding, Mapping)
                and self.execution_authorization_ref
                and pre_provider_binding.get("kind") in {"review", "replan"}
                and callable(getattr(self.transport_ledger, "bind_attempt_control_authorization", None))
            ):
                # Post-Forge Reviewer/replan calls use a distinct domain.  The
                # host derives it from the current Forge mapping; no worker
                # can provide a replacement body or attempt scalar.
                self.transport_ledger.bind_attempt_control_authorization()
            root_planning_call = (
                isinstance(pre_provider_binding, Mapping)
                and not self.execution_authorization_ref
                and pre_provider_binding.get("phase") in CODE_MODE_PRE_PROVIDER_PHASES
            )
            if root_planning_call:
                # This producer fact is the authenticated source for the
                # host's next-transition check.  It is written before the
                # host can perform any HTTP request.
                publisher = getattr(self, "root_fact_publisher", None)
                if not callable(publisher):
                    raise TrueMultiAgentRuntimeError("root planning transport lacks its authenticated producer")
                publisher("dispatch", pre_provider_binding, request.effect_id, None)
            # A retry/replay of the same logical call may cross the local
            # physical ceiling; a new logical call may not.  The host remains
            # the final authority for whether the call is settled or
            # OUTCOME_UNKNOWN.
            self._logical_call_ids.add(request.effect_id)
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
                # This controlled path bypasses the host only for an
                # explicitly injected test failure; it still represents a
                # physical provider attempt.
                self.physical_send_count += 1
                raise
            except ProviderError as error:
                raise TrueMultiAgentRuntimeError(
                    "controlled explicit remote failure did not return an authoritative HTTP response"
                ) from error
            raise TrueMultiAgentRuntimeError("controlled invalid Provider request unexpectedly succeeded")
        if self.authoritative_physical:
            structured_response = request.request.get("structured_response") is True
            contract = None
            if structured_response:
                try:
                    contract = resolve_output_contract(
                        str(request.request.get("task_id") or ""),
                        str(request.request.get("kind") or ""),
                        output_contract_id=request.request.get("output_contract_id"),
                        task_type=request.request.get("task_type"),
                        schema_id=request.request.get("schema_id"),
                    )
                except OutputContractError as error:
                    raise TrueMultiAgentRuntimeError("Provider output contract identity is invalid") from error
            tools = structured_response_tools(contract) if structured_response else []
            tools_hash = sha256_bytes(canonical_json_bytes(tools))
            try:
                transport_body = self.transport_ledger.send(
                    self.transport_ledger_capability,
                    run_id=self.run_id,
                    effect_attempt_id=effect_attempt_id,
                    provider_profile=active_profile.name,
                    provider_model=active_profile.model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    system_prompt_hash=request.request.get("system_prompt_hash"),
                    user_prompt_hash=request.request.get("user_prompt_hash"),
                    tools=tools,
                    tools_hash=tools_hash,
                    structured_response=structured_response,
                    structured_response_tool_name=(
                        STRUCTURED_RESPONSE_TOOL_NAME if structured_response else None
                    ),
                    max_tokens=int(request.request["max_output_tokens"]),
                    timeout=float(self.timeout),
                    session_instance_id=(pre_provider_binding or {}).get(
                        "session_instance_id", (self.pre_provider_authorization or {}).get("session_instance_id")
                    ),
                    conversation_session_id=(pre_provider_binding or {}).get(
                        "conversation_session_id", (self.pre_provider_authorization or {}).get("conversation_session_id")
                    ),
                    turn_index=(pre_provider_binding or {}).get(
                        "turn_index", (self.pre_provider_authorization or {}).get("turn_index")
                    ),
                    generation=(pre_provider_binding or {}).get(
                        "generation", (self.pre_provider_authorization or {}).get("generation")
                    ),
                    phase=(pre_provider_binding or {}).get("phase"),
                    role=(pre_provider_binding or {}).get("role"),
                    call_index=(pre_provider_binding or {}).get("call_index"),
                    pre_provider_call_identity=(pre_provider_binding or {}).get("pre_provider_call_identity"),
                    agent_id=(pre_provider_binding or {}).get("agent_id"),
                    task_id=(pre_provider_binding or {}).get("task_id"),
                    scheduling_task_id=(pre_provider_binding or {}).get("scheduling_task_id"),
                    scheduling_decision_id=(pre_provider_binding or {}).get("scheduling_decision_id"),
                    scheduling_decision_commitment=(pre_provider_binding or {}).get("scheduling_decision_commitment"),
                    dispatch_command_id=(pre_provider_binding or {}).get("dispatch_command_id"),
                    dispatch_command_commitment=(pre_provider_binding or {}).get("dispatch_command_commitment"),
                    selected_agent_id=(pre_provider_binding or {}).get("selected_agent_id"),
                    slot=(pre_provider_binding or {}).get("slot"),
                    dispatch_commitment=(pre_provider_binding or {}).get("dispatch_commitment"),
                    predecessor_identity=(pre_provider_binding or {}).get("predecessor_identity"),
                    provider_call_id=request.effect_id,
                    execution_authorization_ref=self.execution_authorization_ref,
                    max_retries=self.max_retries,
                    physical_attempt_budget=1 + self.max_retries,
                )
            except ProviderHTTPError:
                # The host only emits ProviderHTTPError after urllib has
                # attempted the physical request.  Authorization failures
                # are reported as broker errors and remain at zero.
                self.physical_send_count += 1
                raise
            except Exception as error:
                raise TrueMultiAgentRuntimeError(
                    "authoritative Provider request was not executed by the host transport"
                ) from error
            completion = ProviderCompletion(
                str(transport_body.get("completion_text") or ""),
                dict(transport_body.get("metadata") or {}),
            )
            receipt = dict(transport_body["receipt"])
            if root_planning_call:
                # A root FSM transition is not settled by the transport
                # response alone: the durable producer fact must close it.
                publisher = getattr(self, "root_fact_publisher", None)
                if not callable(publisher):
                    raise TrueMultiAgentRuntimeError("root planning transport lacks its authenticated settlement producer")
                publisher("settled", pre_provider_binding, request.effect_id, receipt)
            if not any(existing == receipt for existing in self.transport_receipts):
                self.physical_send_count += 1
                self.transport_receipts.append(receipt)
        else:
            provider_client = self.fallback_clients.get(active_profile.name, self.client)
            # Preserve the historical non-authoritative transport metric: a
            # direct client invocation is a physical attempt even if the
            # client returns a retryable error.
            self.physical_send_count += 1
            protocol = infer_wire_protocol(
                active_profile.name,
                active_profile.base_url,
                getattr(active_profile, "wire_protocol", None),
            )
            if protocol == OPENAI_CHAT_COMPLETIONS:
                completion = provider_client._complete_openai(
                    active_profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=int(request.request["max_output_tokens"]),
                    request_timeout_seconds=float(self.timeout),
                    expect_json=True,
                    json_schema=None,
                )
            else:
                completion = provider_client.complete_with_metadata(
                    active_profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=int(request.request["max_output_tokens"]),
                    request_timeout_seconds=float(self.timeout),
                    expect_json=True,
                )
        metadata = dict(completion.metadata)
        expected_protocol = infer_wire_protocol(
            active_profile.name,
            active_profile.base_url,
            getattr(active_profile, "wire_protocol", None),
        )
        if metadata.get("protocol") != expected_protocol:
            raise TrueMultiAgentRuntimeError("Provider response used an unexpected wire protocol")
        if metadata.get("protocol_fallback_used") or metadata.get("structured_feature_fallback") or metadata.get("fallback_used"):
            raise TrueMultiAgentRuntimeError("Provider fallback is forbidden")
        metadata["sitina_provider_profile"] = active_profile.name
        metadata["sitina_provider_model"] = active_profile.model
        metadata["sitina_fallback_used"] = self.fallback_count > 0
        return {
            "raw_text": completion.text,
            "metadata": metadata,
            "effect_attempt_id": effect_attempt_id,
            "physical_send_count": self.physical_send_count,
        }


# Compatibility name retained for existing offline fixtures; transport
# authorization and protocol selection are provider-neutral.
OneShotDeepSeekTransport = OneShotProviderTransport


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
    context: Any
    run_id: str
    policy_hash: str
    policy: Mapping[str, Any]
    activation: RuntimeActivation
    journal: Any
    cas: LocalCAS
    allow_provider_fallback: bool = True
    client_override: Any | None = None
    profile_override: Any | None = None
    # The authorization was validated by CodeModeRuntimeContext before the
    # executor was constructed.  Keep the exact binding here so an embedded
    # receipt cannot be imported from another run in the same host ledger.
    canary_authorization: Mapping[str, Any] | None = None
    pre_provider_authorization: Mapping[str, Any] | None = None
    call_count: int = 0
    embedded_call_count: int = 0
    embedded_physical_send_count: int = 0
    embedded_retry_count: int = 0
    embedded_fallback_count: int = 0
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
        client = self.client_override or CapturingDeepSeekClient(self.home, network_egress_capability=capability)
        if self.client_override is None:
            profile_getter = getattr(self.context, "authoritative_provider_profile", None)
            if not callable(profile_getter):
                raise TrueMultiAgentRuntimeError(
                    "authoritative Provider execution requires the CLI-owned host profile"
                )
            profile = profile_getter(str(self.policy["provider_profile"]))
        elif self.profile_override is not None:
            profile = self.profile_override
        else:
            profile = client.load_profile(str(self.policy["provider_profile"]))
        fallback_profiles: list[Any] = []
        fallback_clients: dict[str, Any] = {}
        configured_fallbacks = self.policy.get("provider_fallback_profiles") or ()
        if not isinstance(configured_fallbacks, (list, tuple)):
            raise TrueMultiAgentRuntimeError("provider_fallback_profiles must be a list")
        configured_fallbacks = list(configured_fallbacks)
        # The signed true-multi policy is the upper bound; the local provider
        # config may add an explicitly configured backup profile.  The
        # activation/endpoint/model checks below still fail closed for any
        # profile that is not part of the signed provider allowlist.
        if self.client_override is None:
            for configured in RoleProfileResolver(self.home).fallback_profiles():
                if configured not in configured_fallbacks:
                    configured_fallbacks.append(configured)
        for fallback_name in configured_fallbacks:
            name = str(fallback_name or "").strip()
            if not name or name == profile.name or name in {item.name for item in fallback_profiles}:
                continue
            fallback_profile = client.load_profile(name)
            fallback_host = urlparse(fallback_profile.base_url).hostname
            # Fallbacks are still part of the signed provider execution
            # activation.  A profile cannot silently expand the endpoint or
            # model allowlist; adding another provider requires a new policy
            # and activation review.
            if not _provider_endpoint_allowed(fallback_profile.base_url, fallback_profile):
                raise TrueMultiAgentRuntimeError("configured fallback is outside the provider profile endpoint allowlist")
            if fallback_profile.model not in set(self.policy["provider_model_allowlist"]):
                raise TrueMultiAgentRuntimeError("configured fallback model is outside the allowlist")
            fallback_profiles.append(fallback_profile)
            fallback_clients[fallback_profile.name] = client
        transport_ledger = None
        transport_ledger_capability = None
        if self.client_override is None:
            ledger_getter = getattr(self.context, "_authoritative_transport_ledger", None)
            if not callable(ledger_getter):
                raise TrueMultiAgentRuntimeError(
                    "authoritative Provider execution requires a Code Mode transport ledger"
                )
            transport_ledger, transport_ledger_capability = ledger_getter()
        self.transport = OneShotDeepSeekTransport(
            client,
            profile,
            timeout=int(self.policy["request_timeout_seconds"]),
            run_id=self.run_id,
            authoritative_physical=self.client_override is None,
            transport_ledger=transport_ledger,
            transport_ledger_capability=transport_ledger_capability,
            max_sends=int(self.policy["max_provider_requests_per_run"]),
            max_retries=min(3, int(self.policy.get("transport_retries", 0))),
            fallback_profiles=fallback_profiles,
            fallback_clients=fallback_clients,
            fallback_allowed=bool(self.allow_provider_fallback)
            and not bool(
                (self.activation.mapping.get("provider") or {}).get(
                    "provider_test_no_fallback",
                    (self.activation.mapping.get("provider") or {}).get(
                        "deepseek_token_test_no_fallback", False
                    ),
                )
            ),
            max_fallbacks=min(1, int(self.policy.get("fallbacks", 0))),
            pre_provider_authorization=self.pre_provider_authorization,
        )
        self.transport.root_fact_publisher = self._publish_root_fact
        self.gateway = EffectGateway(self.transport)
        self.pipeline = ResultPipeline(
            self.cas,
            self.context.provider,
            ResultPolicy(64 * 1024, frozenset({"agent_id", "kind"}), 64 * 1024),
        )
        self._embedded_transport_receipts: list[dict[str, Any]] = []
        self._embedded_transport_receipt_seen: set[str] = set()
        self._embedded_transport_receipts_by_identity: dict[str, dict[str, Any]] = {}
        if isinstance(self.pre_provider_authorization, Mapping):
            if self.canary_authorization is not None:
                raise TrueMultiAgentRuntimeError(
                    "pre-provider and post-review canary authorizations cannot share a transport ledger"
                )
            if transport_ledger is None or not hasattr(transport_ledger, "bind_pre_provider_authorization"):
                raise TrueMultiAgentRuntimeError("pre-provider authorization requires the host transport ledger")
            try:
                transport_ledger.bind_pre_provider_authorization(self.pre_provider_authorization)
            except Exception as error:
                raise TrueMultiAgentRuntimeError("pre-provider authorization was not bound to the host transport") from error
        current_authorization = self.canary_authorization
        if isinstance(current_authorization, Mapping):
            self._transport_authorization_id = str(
                current_authorization.get("authorization_id") or ""
            )
            self._transport_authorization_run_id = str(
                current_authorization.get("run_id") or self.run_id
            )
        elif isinstance(self.pre_provider_authorization, Mapping):
            self._transport_authorization_id = str(
                self.pre_provider_authorization.get("authorization_id") or ""
            )
            self._transport_authorization_run_id = str(
                self.pre_provider_authorization.get("run_id") or self.run_id
            )
        else:
            self._transport_authorization_id = ""
            self._transport_authorization_run_id = self.run_id
        # Only receipts accepted by ``record_embedded_transport_receipt`` are
        # eligible for canary-grade physical accounting.  Keep a settlement
        # cursor so one receipt cannot be counted again on a later callback.
        self._settled_embedded_transport_receipt_count = 0

    def _usage_cost(self, usage: Mapping[str, int]) -> int:
        pricing = dict(self.policy["pricing"])
        return (
            int(usage["input_tokens"])
            * int(pricing["input_micro_usd_per_million_tokens"])
            + int(usage["output_tokens"])
            * int(pricing["output_micro_usd_per_million_tokens"])
        ) // 1_000_000

    def _root_fact_exists(self, *, schema: str, event_type: str, provider_call_id: str) -> bool:
        for event in self.journal.iter_events(0):
            if (
                event.stream_id == f"run/{self.run_id}"
                and isinstance(event.payload, Mapping)
                and event.payload.get("schema") == schema
                and event.payload.get("event_type") == event_type
                and event.payload.get("provider_call_id") == provider_call_id
            ):
                return True
        return False

    def _publish_root_fact(
        self, kind: str, binding: Mapping[str, Any], provider_call_id: str,
        receipt: Mapping[str, Any] | None,
    ) -> None:
        if kind == "dispatch":
            self._append_root_dispatch_fact(binding, provider_call_id)
        elif kind == "settled" and isinstance(receipt, Mapping):
            self._append_root_settled_fact(binding, provider_call_id, receipt)
        elif kind == "result_accepted" and isinstance(receipt, Mapping):
            self._append_root_result_accepted_fact(binding, provider_call_id, receipt)
        else:
            raise TrueMultiAgentRuntimeError("unknown root producer fact kind")

    def _append_root_dispatch_fact(self, binding: Mapping[str, Any], provider_call_id: str) -> None:
        """Persist the authenticated dispatch before any physical HTTP send."""
        if self._root_fact_exists(
            schema="CODE_MODE_ROOT_DISPATCH_FACT_V1",
            event_type="code-mode.root-call-dispatched",
            provider_call_id=provider_call_id,
        ):
            return
        authorization = self.pre_provider_authorization
        if not isinstance(authorization, Mapping):
            raise TrueMultiAgentRuntimeError("root dispatch requires pre-provider authorization")
        fact = {
            "schema": "CODE_MODE_ROOT_DISPATCH_FACT_V1",
            "event_type": "code-mode.root-call-dispatched",
            "purpose": "code-mode-root-call-dispatch",
            "purpose_class": "code-mode-root-call-dispatch",
            "run_id": self.run_id,
            "session_instance_id": authorization.get("session_instance_id"),
            "conversation_session_id": authorization.get("conversation_session_id"),
            "turn_index": authorization.get("turn_index"),
            "generation": authorization.get("generation"),
            "run_attempt": authorization.get("run_attempt"),
            "agent_id": binding.get("agent_id"),
            "task_id": binding.get("task_id"),
            "role": binding.get("role"),
            "phase": binding.get("phase"),
            "call_index": binding.get("call_index"),
            "dispatch_commitment": binding.get("dispatch_commitment"),
            "predecessor_identity": binding.get("predecessor_identity"),
            "pre_provider_call_identity": binding.get("pre_provider_call_identity"),
            "provider_profile": authorization.get("provider_profile"),
            "provider_model": authorization.get("provider_model"),
            "provider_call_id": provider_call_id,
            "state": "DISPATCHED",
            "scheduling_task_id": binding.get("scheduling_task_id"),
            "scheduling_decision_id": binding.get("scheduling_decision_id"),
            "scheduling_decision_commitment": binding.get("scheduling_decision_commitment"),
            "dispatch_command_id": binding.get("dispatch_command_id"),
            "dispatch_command_commitment": binding.get("dispatch_command_commitment"),
            "selected_agent_id": binding.get("selected_agent_id"),
            "slot": binding.get("slot"),
        }
        CanonicalStream(
            self.journal, self.run_id, f"run/{self.run_id}", self.policy_hash,
        ).append_root_producer_fact(
            fact, actor="controller-root-dispatch",
            producer_role="root_dispatch",
            command_id="root-dispatch-" + provider_call_id,
        )

    def _append_root_settled_fact(self, binding: Mapping[str, Any], provider_call_id: str, receipt: Mapping[str, Any]) -> None:
        """Persist SETTLED only after the host returned a valid receipt."""
        if self._root_fact_exists(
            schema="CODE_MODE_ROOT_SETTLED_FACT_V1",
            event_type="code-mode.root-call-settled",
            provider_call_id=provider_call_id,
        ):
            return
        authorization = self.pre_provider_authorization
        if not isinstance(authorization, Mapping):
            raise TrueMultiAgentRuntimeError("root settlement requires pre-provider authorization")
        response_id = receipt.get("provider_response_id")
        if not isinstance(response_id, str) or not response_id:
            raise TrueMultiAgentRuntimeError("root settlement receipt has no response identity")
        fact = {
            "schema": "CODE_MODE_ROOT_SETTLED_FACT_V1",
            "event_type": "code-mode.root-call-settled",
            "purpose": "code-mode-root-call-settled",
            "purpose_class": "code-mode-root-call-settled",
            "run_id": self.run_id,
            "session_instance_id": authorization.get("session_instance_id"),
            "conversation_session_id": authorization.get("conversation_session_id"),
            "turn_index": authorization.get("turn_index"),
            "generation": authorization.get("generation"),
            "run_attempt": authorization.get("run_attempt"),
            "agent_id": binding.get("agent_id"),
            "task_id": binding.get("task_id"),
            "role": binding.get("role"),
            "phase": binding.get("phase"),
            "call_index": binding.get("call_index"),
            "dispatch_commitment": binding.get("dispatch_commitment"),
            "predecessor_identity": binding.get("predecessor_identity"),
            "pre_provider_call_identity": binding.get("pre_provider_call_identity"),
            "provider_profile": authorization.get("provider_profile"),
            "provider_model": authorization.get("provider_model"),
            "provider_call_id": provider_call_id,
            "state": "SETTLED",
            "response_id": response_id,
            "response_receipt_hash": sha256_bytes(canonical_json_bytes(dict(receipt))),
            "scheduling_task_id": binding.get("scheduling_task_id"),
            "scheduling_decision_id": binding.get("scheduling_decision_id"),
            "scheduling_decision_commitment": binding.get("scheduling_decision_commitment"),
            "dispatch_command_id": binding.get("dispatch_command_id"),
            "dispatch_command_commitment": binding.get("dispatch_command_commitment"),
            "selected_agent_id": binding.get("selected_agent_id"),
            "slot": binding.get("slot"),
        }
        CanonicalStream(
            self.journal, self.run_id, f"run/{self.run_id}", self.policy_hash,
        ).append_root_producer_fact(
            fact, actor="controller-root-settlement",
            producer_role="root_settled",
            command_id="root-settled-" + provider_call_id,
        )

    def _append_root_result_accepted_fact(
        self, binding: Mapping[str, Any], provider_call_id: str, result: Mapping[str, Any],
    ) -> None:
        """Persist the business-result acceptance after Task.accept succeeds.

        HTTP settlement is intentionally insufficient to advance the root
        FSM.  This producer fact is written only after the output contract and
        Task aggregate have accepted the exact result; the host consumes it
        from the authenticated run stream on the next transition.
        """
        if self._root_fact_exists(
            schema="CODE_MODE_ROOT_RESULT_ACCEPTED_V1",
            event_type="code-mode.root-result-accepted",
            provider_call_id=provider_call_id,
        ):
            return
        authorization = self.pre_provider_authorization
        if not isinstance(authorization, Mapping):
            raise TrueMultiAgentRuntimeError("root result acceptance requires pre-provider authorization")
        response_id = result.get("provider_response_id")
        output_ref = result.get("output_ref")
        output_hash = result.get("output_hash")
        task_attempt_id = result.get("task_attempt_id")
        if any(not isinstance(value, str) or not value for value in (
            response_id, output_ref, output_hash, task_attempt_id,
        )):
            raise TrueMultiAgentRuntimeError("root result acceptance binding is incomplete")
        fact = {
            "schema": "CODE_MODE_ROOT_RESULT_ACCEPTED_V1",
            "event_type": "code-mode.root-result-accepted",
            "purpose": "code-mode-root-result-accepted",
            "purpose_class": "code-mode-root-result-accepted",
            "run_id": self.run_id,
            "session_instance_id": authorization.get("session_instance_id"),
            "conversation_session_id": authorization.get("conversation_session_id"),
            "turn_index": authorization.get("turn_index"),
            "generation": authorization.get("generation"),
            "run_attempt": authorization.get("run_attempt"),
            "agent_id": binding.get("agent_id"),
            "task_id": binding.get("task_id"),
            "role": binding.get("role"),
            "phase": binding.get("phase"),
            "call_index": binding.get("call_index"),
            "provider_call_id": provider_call_id,
            "scheduling_task_id": binding.get("scheduling_task_id"),
            "scheduling_decision_id": binding.get("scheduling_decision_id"),
            "scheduling_decision_commitment": binding.get("scheduling_decision_commitment"),
            "dispatch_command_id": binding.get("dispatch_command_id"),
            "dispatch_command_commitment": binding.get("dispatch_command_commitment"),
            "dispatch_commitment": binding.get("dispatch_commitment"),
            "state": "ACCEPTED",
            "response_id": response_id,
            "response_receipt_hash": result.get("response_receipt_hash"),
            "output_ref": output_ref,
            "output_hash": output_hash,
            "task_attempt_id": task_attempt_id,
        }
        if not isinstance(fact["response_receipt_hash"], str) or not fact["response_receipt_hash"]:
            raise TrueMultiAgentRuntimeError("root result acceptance receipt binding is incomplete")
        CanonicalStream(
            self.journal, self.run_id, f"run/{self.run_id}", self.policy_hash,
        ).append_root_producer_fact(
            fact, actor="task-result-acceptance",
            producer_role="root_result_accepted",
            command_id="root-result-accepted-" + provider_call_id,
        )

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

    def _pre_provider_call_binding(
        self, *, kind: str, agent: AgentIdentity, ordinal: int,
        task_id: str, input_context: Mapping[str, Any],
        root_phase: str | None,
    ) -> dict[str, Any] | None:
        authorization = self.pre_provider_authorization
        if not isinstance(authorization, Mapping):
            return None
        # Once Forge has been durably bound, post-execution review and replan
        # are a different authorization domain.  They must not be forced
        # through the root-planning allowlist (and must never reacquire the
        # pre-provider root permission).  The broker will exchange this
        # typed request for the current attempt-control mapping from the
        # authenticated Forge facts.
        execution_ref = str(
            getattr(self.transport, "execution_authorization_ref", "") or ""
        )
        if execution_ref:
            if kind not in {"review", "replan"}:
                raise TrueMultiAgentRuntimeError(
                    "post-Forge Provider call requires attempt-control authorization"
                )
            return {
                "kind": kind,
                "phase": "attempt-control",
                "role": kind,
                "call_index": ordinal,
                "attempt_control": True,
                "authorization_ref": execution_ref,
                "run_attempt": authorization.get("run_attempt"),
                "run_id": self.run_id,
            }
        # The root FSM stage is an explicit typed input from the production
        # caller.  It is never inferred from the response ``kind`` (which is
        # model output and therefore not an authorization boundary).
        if root_phase not in CODE_MODE_PRE_PROVIDER_PHASES:
            raise TrueMultiAgentRuntimeError(
                "pre-provider root phase must be selected by the fixed production FSM"
            )
        phase = root_phase
        schedule_bindings = list(getattr(self, "_root_schedule_bindings", ()))
        matching_schedule = None
        for candidate in reversed(schedule_bindings):
            if candidate.get("phase") != phase:
                continue
            if phase == "discovery/controller" and task_id != "goal-discovery":
                continue
            if phase == "proposal/planner/candidate" and not task_id.startswith(("proposal-", "proposal")):
                continue
            if phase == "review/selection" and not task_id.startswith(("review-", "review")):
                continue
            if agent.agent_id not in candidate.get("selected_agents", ()):
                continue
            matching_schedule = candidate
            break
        if not isinstance(matching_schedule, Mapping):
            raise TrueMultiAgentRuntimeError("root call has no authenticated scheduling decision")
        dispatch_commitment = str(matching_schedule.get("dispatch_commitment") or "")
        if not dispatch_commitment:
            raise TrueMultiAgentRuntimeError("root call has no authenticated dispatch commitment")
        predecessor_identity = str(getattr(self, "_last_pre_provider_call_identity", "") or "root")
        identity = provider_call_identity_v2(
            session_instance_id=authorization.get("session_instance_id"),
            conversation_session_id=authorization.get("conversation_session_id"),
            turn_index=authorization.get("turn_index"),
            run_id=self.run_id,
            run_attempt=authorization.get("run_attempt"),
            agent_id=agent.agent_id,
            task_id=task_id,
            dispatch_commitment=dispatch_commitment,
            predecessor_identity=predecessor_identity,
            phase=phase,
            role=agent.role,
            call_index=ordinal,
            provider_profile=authorization.get("provider_profile"),
            provider_model=authorization.get("provider_model"),
        )
        return {
            "kind": kind,
            "phase": phase,
            "role": agent.role,
            "call_index": ordinal,
            "pre_provider_call_identity": identity,
            "agent_id": agent.agent_id,
            "task_id": task_id,
            "dispatch_commitment": dispatch_commitment,
            "predecessor_identity": predecessor_identity,
            "root_fsm_phase": phase,
            "scheduling_task_id": matching_schedule.get("scheduling_task_id"),
            "scheduling_decision_id": matching_schedule.get("scheduling_decision_id"),
            "scheduling_decision_commitment": matching_schedule.get("scheduling_decision_commitment"),
            "dispatch_command_id": matching_schedule.get("dispatch_command_id"),
            "dispatch_command_commitment": matching_schedule.get("dispatch_command_commitment"),
            "selected_agent_id": agent.agent_id,
            "slot": list(matching_schedule.get("selected_agents", ())).index(agent.agent_id) + 1,
        }

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

    def provider_transport_receipts(self) -> tuple[Mapping[str, Any], ...]:
        ledger = getattr(self.transport, "transport_ledger", None)
        ledger_capability = getattr(self.transport, "transport_ledger_capability", None)
        if getattr(self.transport, "authoritative_physical", False) and ledger is not None:
            # A host ledger is session-scoped and may contain receipts from
            # another run or a sibling executor.  Only the current executor's
            # authorization/run lineage belongs in this result.
            return tuple(
                dict(item)
                for item in ledger.snapshot(ledger_capability)
                if isinstance(item, Mapping) and self._receipt_is_current_lineage(item)
            )
        return tuple(
            dict(item)
            for item in (
                list(getattr(self.transport, "transport_receipts", ()))
                + list(getattr(self, "_embedded_transport_receipts", ()))
            )
        )

    @staticmethod
    def _embedded_receipt_identity(receipt: Mapping[str, Any]) -> str:
        """Return the immutable identity of a host-issued transport receipt."""

        receipt_hash = receipt.get("receipt_hash")
        if isinstance(receipt_hash, str) and receipt_hash:
            return "receipt-hash:" + receipt_hash
        receipt_id = receipt.get("receipt_id")
        if isinstance(receipt_id, str) and receipt_id:
            return "receipt-id:" + receipt_id
        # A host receipt is already accepted by the issuer-bound ledger.  A
        # canonical digest is a safe compatibility identity for older host
        # fixtures which predate the explicit receipt_hash field.
        return "receipt-canonical:" + sha256_bytes(canonical_json_bytes(dict(receipt)))

    def _validate_embedded_receipt_binding(self, receipt: Mapping[str, Any]) -> None:
        expected_authorization_id = str(
            getattr(self, "_transport_authorization_id", "") or ""
        )
        receipt_authorization_id = str(receipt.get("authorization_id") or "")
        if not expected_authorization_id or receipt_authorization_id != expected_authorization_id:
            raise PermissionError("embedded transport receipt authorization binding mismatch")
        executor_run_id = str(getattr(self, "run_id", "") or "")
        expected_run_id = str(
            getattr(self, "_transport_authorization_run_id", executor_run_id)
            or executor_run_id
        )
        receipt_run_id = str(receipt.get("run_id") or "")
        if receipt_run_id != expected_run_id and not receipt_run_id.startswith(
            f"forge-exec-{expected_run_id}-"
        ):
            raise PermissionError("embedded transport receipt run is outside the executor lineage")
        if receipt_run_id != executor_run_id and not receipt_run_id.startswith(
            f"forge-exec-{executor_run_id}-"
        ) and expected_run_id != executor_run_id:
            raise PermissionError("embedded transport receipt run does not match the executor")

    def _receipt_is_current_lineage(self, receipt: Mapping[str, Any]) -> bool:
        """Select every host receipt owned by this root run lineage.

        A successful Code Mode run intentionally crosses several independent
        authorization domains: pre-provider planning, Forge execution, and
        post-Forge attempt control.  Filtering the session ledger by the
        currently selected authorization id drops the planning/reviewer
        receipts and makes an otherwise complete ledger look partial.  The
        host already validates each receipt against its own exact domain when
        it is issued; this projection therefore selects by the immutable root
        run lineage, including its bounded Forge child runs.
        """

        executor_run_id = str(getattr(self, "run_id", "") or "")
        receipt_run_id = str(receipt.get("run_id") or "")
        if not executor_run_id or not receipt_run_id:
            return False
        if receipt_run_id != executor_run_id and not receipt_run_id.startswith(
            f"forge-exec-{executor_run_id}-"
        ):
            return False
        return str(receipt.get("authorization_kind") or "") in {
            "pre-provider", "forge-execution", "attempt-control", "canary",
        }

    def record_embedded_transport_receipt(self, receipt: Mapping[str, Any]) -> None:
        if not getattr(self.transport, "authoritative_physical", False):
            return
        if not isinstance(receipt, Mapping):
            raise PermissionError("embedded transport receipt is not a mapping")
        ledger = getattr(self.transport, "transport_ledger", None)
        if ledger is None or not ledger.contains(receipt):
            raise PermissionError("embedded transport receipt is not in the issuer-bound ledger")
        self._validate_embedded_receipt_binding(receipt)
        identity = self._embedded_receipt_identity(receipt)
        seen = getattr(self, "_embedded_transport_receipt_seen", set())
        by_identity = getattr(self, "_embedded_transport_receipts_by_identity", {})
        if identity in seen:
            # Exact duplicate delivery is harmless and must be idempotent.  A
            # reused identity with changed fields is evidence tampering.
            if by_identity.get(identity) != dict(receipt):
                raise PermissionError("embedded transport receipt identity was reused with different content")
            return
        seen.add(identity)
        by_identity[identity] = dict(receipt)
        self._embedded_transport_receipt_seen = seen
        self._embedded_transport_receipts_by_identity = by_identity
        self._embedded_transport_receipts.append(dict(receipt))

    def actual_provider_profile(self) -> Any:
        """Return the provider/model identity used by the latest physical send."""

        return getattr(self.transport, "last_profile", self.transport.profile)

    def usage_totals(self) -> dict[str, int]:
        return {
            "input_tokens": int(getattr(self, "usage_input_total", 0)),
            "output_tokens": int(getattr(self, "usage_output_total", 0)),
            "cache_read_tokens": int(getattr(self, "usage_cache_read_total", 0)),
            "cache_write_tokens": int(getattr(self, "usage_cache_write_total", 0)),
            "total_tokens": int(self.usage_total),
            "cost_micro_usd": int(self.cost_total_micro_usd),
            "unsettled_usage_count": int(getattr(self, "unsettled_usage_count", 0)),
            "retry_count": int(getattr(self, "embedded_retry_count", 0)),
            "fallback_count": int(getattr(self, "embedded_fallback_count", 0)),
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
        # Embedded scripted/injected clients do not cross the authoritative
        # network transport boundary.  Their metadata cannot mint physical
        # sends or token proof; the outer transport receipts remain the only
        # canary-grade source of physical/token authenticity.
        authoritative = bool(getattr(self.transport, "authoritative_physical", False))
        receipt_count = len(getattr(self, "_embedded_transport_receipts", ())) if authoritative else 0
        settled_receipt_count = int(
            getattr(self, "_settled_embedded_transport_receipt_count", 0)
        )
        if receipt_count < settled_receipt_count:
            raise TrueMultiAgentRuntimeError(
                "authoritative embedded transport receipt ledger moved backwards"
            )
        # Do not consume the caller/client-reported physical_send_count.  A
        # physical send is real for Code Mode accounting only after the
        # issuer-bound transport ledger has accepted its receipt.
        physical = receipt_count - settled_receipt_count
        self._settled_embedded_transport_receipt_count = receipt_count
        self.embedded_physical_send_count = int(
            getattr(self, "embedded_physical_send_count", 0)
        ) + physical
        self.embedded_retry_count = int(getattr(self, "embedded_retry_count", 0)) + (int(metadata.get("retry_count", 0) or 0) if getattr(self.transport, "authoritative_physical", False) else 0)
        self.embedded_fallback_count = int(getattr(self, "embedded_fallback_count", 0)) + (int(metadata.get("fallback_count", 0) or 0) if getattr(self.transport, "authoritative_physical", False) else 0)
        token_over, cost_over = self._record_usage(usage, cost_micro)
        if token_over or cost_over:
            raise TrueMultiAgentRuntimeError(
                "embedded Provider response exceeded the unified per-run model budget"
            )

    def settle_failed_embedded_provider_call(self, metadata: Mapping[str, Any]) -> None:
        """Account for physical sends whose response usage is unavailable.

        A transport failure may have consumed tokens even when no authoritative
        usage payload was returned.  Count the call and sends, but never invent
        token totals or cost; the unsettled marker keeps terminal evidence
        conservative and prevents a failed call from disappearing from the
        unified run ledger.
        """
        authoritative = bool(getattr(self.transport, "authoritative_physical", False))
        receipt_count = len(getattr(self, "_embedded_transport_receipts", ())) if authoritative else 0
        settled_receipt_count = int(
            getattr(self, "_settled_embedded_transport_receipt_count", 0)
        )
        if receipt_count < settled_receipt_count:
            raise TrueMultiAgentRuntimeError(
                "authoritative embedded transport receipt ledger moved backwards"
            )
        physical_count = receipt_count - settled_receipt_count
        self._settled_embedded_transport_receipt_count = receipt_count
        self.embedded_call_count = int(getattr(self, "embedded_call_count", 0)) + 1
        self.embedded_physical_send_count = int(getattr(self, "embedded_physical_send_count", 0)) + physical_count
        self.embedded_retry_count = int(getattr(self, "embedded_retry_count", 0)) + int(metadata.get("retry_count", 0) or 0)
        self.embedded_fallback_count = int(getattr(self, "embedded_fallback_count", 0)) + int(metadata.get("fallback_count", 0) or 0)
        self.unsettled_usage_count = int(getattr(self, "unsettled_usage_count", 0)) + 1

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
        root_phase: str | None = None,
        system_prompt: str,
        user_prompt: str,
        input_context: Mapping[str, Any],
        validate: Callable[[Mapping[str, Any]], None],
        ack_lost: bool = False,
        output_contract_id: str | None = None,
        task_type: str | None = None,
        schema_id: str | None = None,
    ) -> AgentCallResult:
        if is_critical_contract_task(task_id) and not (output_contract_id and task_type and schema_id):
            raise TrueMultiAgentRuntimeError(
                "critical Provider call requires explicit output_contract_id, task_type, and schema_id"
            )
        try:
            output_contract = resolve_output_contract(
                task_id,
                kind,
                output_contract_id=output_contract_id,
                task_type=task_type,
                schema_id=schema_id,
                allow_legacy_compat=not any((output_contract_id, task_type, schema_id)),
            )
        except OutputContractError as error:
            raise TrueMultiAgentRuntimeError("Provider output contract identity is invalid") from error
        if is_critical_contract_task(task_id):
            expected_contract = resolve_output_contract(task_id, kind)
            if (
                output_contract.output_contract_id,
                output_contract.task_type,
                output_contract.schema_id,
            ) != (
                expected_contract.output_contract_id,
                expected_contract.task_type,
                expected_contract.schema_id,
            ):
                raise TrueMultiAgentRuntimeError("critical Provider call contract identity does not match its task")
        self._assert_model_admission(int(self.policy["max_output_tokens_per_request"]))
        ordinal = self._provider_call_total() + 1
        pre_provider_binding = self._pre_provider_call_binding(
            kind=kind, agent=agent, ordinal=ordinal, task_id=task_id,
            input_context=input_context,
            root_phase=root_phase,
        )
        if isinstance(pre_provider_binding, Mapping):
            root_identity = pre_provider_binding.get("pre_provider_call_identity")
            if isinstance(root_identity, str) and root_identity:
                self._last_pre_provider_call_identity = root_identity
            elif pre_provider_binding.get("attempt_control") is not True:
                raise TrueMultiAgentRuntimeError(
                    "Provider call binding has no authenticated authorization domain"
                )
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
                "kind": kind,
                "output_contract_id": output_contract.output_contract_id,
                "task_type": output_contract.task_type,
                "schema_id": output_contract.schema_id,
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
        call_bindings = getattr(self.transport, "call_bindings", None)
        if isinstance(call_bindings, dict):
            call_bindings[effect_id] = dict(pre_provider_binding or {})
        effect_attempt_id = "effect-attempt-" + stable_hash("TRUE_MULTI_AGENT_EFFECT_ATTEMPT", {"call": call_id, "attempt": 1})[:32]
        request = EffectRequest(
            effect_id,
            "model_text_generation",
            {
                "agent_id": agent.agent_id,
                "role": agent.role,
                "task_id": task_id,
                "kind": kind,
                "output_contract_id": output_contract.output_contract_id,
                "task_type": output_contract.task_type,
                "schema_id": output_contract.schema_id,
                "task_attempt_id": attempt.task_attempt_id,
                "input_snapshot_hash": input_snapshot_hash,
                "input_snapshot_ref": input_receipt.object_ref.reference_id,
                "input_schema": input_schema,
                "rendered_input_hash": rendered_input_hash,
                "system_prompt_hash": sha256_bytes(system_prompt.encode()),
                "user_prompt_hash": sha256_bytes(user_prompt.encode()),
                "max_output_tokens": int(self.policy["max_output_tokens_per_request"]),
                "response_format": "structured_tool_call",
                "structured_response": True,
                "structured_response_tool_name": STRUCTURED_RESPONSE_TOOL_NAME,
                "tool_calls_allowed": True,
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
        transport_retry_limit = int(getattr(self.transport, "max_retries", 0) or 0)
        fallback_limit = int(getattr(self.transport, "max_fallbacks", 0) or 0)
        current = int(time.time())
        approval = issue_approval(
            "approval-" + effect_id,
            binding,
            authority="goal-owner-provider-inference-authorization",
            expires_at=current + 600,
            allowed_attempts=1,
            allowed_transport_retries=transport_retry_limit,
        )
        approval, approval_fact = approval.authorize(
            binding, effect_attempt_id=effect_attempt_id, now=current,
            transport_retries=transport_retry_limit,
        )
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
                BudgetReservation(
                    "provider_attempts",
                    (1 + transport_retry_limit) * (1 + fallback_limit),
                    current + 600,
                ),
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
            credential_handle_id="provider-credential-handle",
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
                    "transport_retry_limit": transport_retry_limit,
                    "sdk_retry_limit": min(3, int(self.policy.get("sdk_retries", 0))),
                    "fallback_limit": min(1, int(self.policy.get("fallbacks", 0))),
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
        physical_attempts = int(transport_value.pop("physical_attempts", 1) or 1)
        retry_count = int(transport_value.pop("retry_count", max(0, physical_attempts - 1)) or 0)
        fallback_count = int(transport_value.pop("fallback_count", metadata.get("fallback_count", 0)) or 0)
        self.call_count += 1
        if self.transport.physical_send_count != prior_sends + physical_attempts:
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
        bundle, attempts_fact = bundle.record_actual("provider_attempts", physical_attempts)
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
                        "physical_send_count": physical_attempts,
                        "retry_count": retry_count,
                        "fallback_count": fallback_count,
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
        source = "provider-response"
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
                        "provider": self.actual_provider_profile().name,
                        "model": self.actual_provider_profile().model,
                        "provider_request_id": provider_request_id,
                        "input_tokens": usage["input_tokens"],
                        "output_tokens": usage["output_tokens"],
                        "total_tokens": usage["total_tokens"],
                        "cost_micro_usd": cost_micro,
                        "started_at": started_at,
                        "completed_at": now_rfc3339(),
                        "outcome": "SUCCEEDED_OUTPUT_REJECTED",
                        "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                        "retry_count": retry_count,
                        "fallback_count": fallback_count,
                        "physical_send_count": physical_attempts,
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
            validate_output_contract(value, output_contract)
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
                "reason_code": str(
                    getattr(error, "reason_code", None)
                    or getattr(error.__cause__, "reason_code", None)
                    or "OUTPUT_CONTRACT_REJECTED"
                ),
                "expected_binding_hash": (
                    getattr(error, "expected_binding_hash", None)
                    or getattr(error.__cause__, "expected_binding_hash", None)
                    or input_context.get("parent_output_hash")
                ),
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
                        "provider": self.actual_provider_profile().name,
                        "model": self.actual_provider_profile().model,
                        "provider_request_id": provider_request_id,
                        "input_tokens": usage["input_tokens"],
                        "output_tokens": usage["output_tokens"],
                        "total_tokens": usage["total_tokens"],
                        "cost_micro_usd": cost_micro,
                        "started_at": started_at,
                        "completed_at": now_rfc3339(),
                        "outcome": "SUCCEEDED_OUTPUT_REJECTED",
                        "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                        "retry_count": retry_count,
                        "fallback_count": fallback_count,
                        "physical_send_count": physical_attempts,
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
        if (
            isinstance(pre_provider_binding, Mapping)
            and not getattr(self.transport, "execution_authorization_ref", None)
            and pre_provider_binding.get("phase") in CODE_MODE_PRE_PROVIDER_PHASES
            and callable(getattr(self.transport, "root_fact_publisher", None))
        ):
            transport_receipt = (
                self.transport.transport_receipts[-1]
                if self.transport.transport_receipts
                and isinstance(self.transport.transport_receipts[-1], Mapping)
                else None
            )
            if not isinstance(transport_receipt, Mapping):
                raise TrueMultiAgentRuntimeError("root result acceptance has no transport receipt")
            self._publish_root_fact(
                "result_accepted",
                pre_provider_binding,
                request.effect_id,
                {
                    "provider_response_id": provider_request_id,
                    "response_receipt_hash": sha256_bytes(canonical_json_bytes(dict(transport_receipt))),
                    "output_ref": output_receipt.object_ref.reference_id,
                    "output_hash": output_hash,
                    "task_attempt_id": attempt.task_attempt_id,
                },
            )
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
                "provider": self.actual_provider_profile().name,
                "model": self.actual_provider_profile().model,
                "provider_request_id": provider_request_id,
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "total_tokens": usage["total_tokens"],
                "cost_micro_usd": cost_micro,
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": "SUCCEEDED",
                "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                "retry_count": retry_count,
                "fallback_count": fallback_count,
                "physical_send_count": physical_attempts,
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
            retry_count,
            fallback_count,
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
            credential_handle_id="provider-credential-handle",
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
                "provider": self.actual_provider_profile().name,
                "model": self.actual_provider_profile().model,
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
        """Send one intentionally invalid request and settle its explicit HTTP failure."""

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
            credential_handle_id="provider-credential-handle",
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
        source = "provider-http-failure-adapter"
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
                    "provider": self.actual_provider_profile().name,
                    "model": self.actual_provider_profile().model,
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
