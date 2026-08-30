from __future__ import annotations

import concurrent.futures
import hashlib
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import (
    ApprovalCallback,
    HookRunner,
    ToolApprovalDenied,
    ToolCatalog,
    ToolResult,
    ToolRuntimeError,
)
from sitina.runners.provider import (
    AnthropicCompatibleClient,
    ProviderConnectTimeout,
    ProviderDeadlineExceeded,
    ProviderHTTPError,
    ProviderReadTimeout,
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
    RoleProfileResolver,
)
from sitina.security.redaction import redact_boundary_value
from sitina.security.tool_security import summarize_tool_arguments, summarize_tool_result
from sitina.runners.tool_executor import ToolExecutor
from sitina.legacy.fence import issue_frozen_network_egress_capability
from sitina.utils import iso_now, redact_text, stable_json


def _canonical(value: Any) -> bytes:
    """Canonical bytes used only for host request binding hashes."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


_WORKSPACE_PATH_IDENTITY_PREFIX = "~"


def _validate_workspace_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workspace-relative path is empty")
    candidate = Path(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("workspace-relative path is not unambiguous")
    normalized = candidate.as_posix()
    if not normalized or normalized == ".":
        raise ValueError("workspace-relative path is empty")
    return normalized


def encode_workspace_relative_path(value: str) -> str:
    """Encode a relative path into a redaction-stable Journal identity.

    The serialized token intentionally contains only ``!`` and ``~``.  It
    therefore cannot match the phone-number, base64, email, or provider-key
    redaction patterns, even when a filename contains a long digit run.
    """
    normalized = _validate_workspace_relative_path(value)
    raw = normalized.encode("utf-8")
    bits = "".join(
        "~" if byte & mask else "!"
        for byte in raw
        for mask in (128, 64, 32, 16, 8, 4, 2, 1)
    )
    return _WORKSPACE_PATH_IDENTITY_PREFIX + bits


def decode_workspace_relative_path(identity: str) -> str:
    """Decode and validate a redaction-stable workspace path identity."""
    if not isinstance(identity, str) or not identity.startswith(_WORKSPACE_PATH_IDENTITY_PREFIX):
        raise ValueError("workspace path identity prefix is invalid")
    encoded = identity[len(_WORKSPACE_PATH_IDENTITY_PREFIX):]
    if not encoded or len(encoded) % 8 or any(character not in "!~" for character in encoded):
        raise ValueError("workspace path identity encoding is invalid")
    values = bytearray()
    for offset in range(0, len(encoded), 8):
        byte = 0
        for character in encoded[offset:offset + 8]:
            byte = (byte << 1) | (character == "~")
        values.append(byte)
    try:
        decoded = bytes(values).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("workspace path identity is not UTF-8") from error
    return _validate_workspace_relative_path(decoded)


class ToolTurnClient(Protocol):
    def load_profile(self, profile_name: str) -> ProviderProfile: ...

    def complete_tool_turn(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int = 4096,
        request_timeout_seconds: float | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderToolTurn: ...


class BoundedToolTurnClient:
    """Policy-bound provider transport for the Forge embedded tool loop.

    ``AnthropicCompatibleClient`` intentionally performs one tool-turn
    request.  Forge is still a real provider consumer, so it must use the
    same retry/fallback limits and actual-profile accounting as the main
    multi-agent calls.  This adapter is injected only by the execution bridge;
    ordinary scripted/test clients remain untouched.
    """

    def __init__(
        self,
        client: ToolTurnClient,
        primary_profile: ProviderProfile,
        *,
        run_id: str = "",
        authoritative_physical: bool = False,
        transport_ledger: Any | None = None,
        transport_ledger_capability: object | None = None,
        receipt_sink: Callable[[Mapping[str, Any]], None] | None = None,
        retry_limit: int = 0,
        fallback_profiles: Sequence[ProviderProfile] = (),
        fallback_allowed: bool = False,
        max_fallbacks: int = 0,
        backoff_seconds: float = 0.25,
    ):
        self.client = client
        self.primary_profile = primary_profile
        self.run_id = str(run_id)
        self.authoritative_physical = bool(authoritative_physical)
        self.transport_ledger = transport_ledger
        self.transport_ledger_capability = transport_ledger_capability
        self.receipt_sink = receipt_sink
        self.transport_receipts: list[dict[str, Any]] = []
        self.last_profile = primary_profile
        self.retry_limit = min(3, max(0, int(retry_limit)))
        self.fallback_allowed = bool(fallback_allowed)
        self.fallback_profiles = tuple(fallback_profiles)
        self.max_fallbacks = min(1, max(0, int(max_fallbacks)), len(self.fallback_profiles)) if self.fallback_allowed else 0
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self._logical_turn_index = 0

    def load_profile(self, profile_name: str) -> ProviderProfile:
        return self.client.load_profile(profile_name)

    @staticmethod
    def _retryable(error: BaseException) -> bool:
        if isinstance(error, (ProviderConnectTimeout, ProviderReadTimeout, ProviderDeadlineExceeded)):
            return True
        return isinstance(error, ProviderHTTPError) and error.status_code in {408, 429, 500, 502, 503, 504}

    def complete_tool_turn(self, profile: ProviderProfile, **kwargs: Any) -> ProviderToolTurn:
        del profile  # the bound primary/fallback profiles are the capability scope
        active_profiles = [self.primary_profile, *self.fallback_profiles[: self.max_fallbacks]]
        profile_index = 0
        retries = 0
        fallbacks = 0
        physical_attempts = 0
        self._logical_turn_index += 1
        logical_call_id = f"{self.run_id}:embedded-call:{self._logical_turn_index}"
        while True:
            active_profile = active_profiles[profile_index]
            self.last_profile = active_profile
            try:
                physical_attempts += 1
                if self.authoritative_physical:
                    if self.transport_ledger is None or self.transport_ledger_capability is None:
                        raise RuntimeError("authoritative Forge send requires the issuer-bound transport ledger")
                    host_body = self.transport_ledger.complete_tool_turn(
                        self.transport_ledger_capability,
                        run_id=self.run_id,
                        effect_attempt_id=logical_call_id,
                        provider_call_id=logical_call_id,
                        provider_profile=active_profile.name,
                        provider_model=active_profile.model,
                        system_prompt=str(kwargs.get("system_prompt") or ""),
                        messages=[dict(item) for item in (kwargs.get("messages") or ())],
                        tools=[dict(item) for item in (kwargs.get("tools") or ())],
                        system_prompt_hash=hashlib.sha256(str(kwargs.get("system_prompt") or "").encode()).hexdigest(),
                        messages_hash=hashlib.sha256(_canonical(kwargs.get("messages") or ())).hexdigest(),
                        tools_hash=hashlib.sha256(_canonical(kwargs.get("tools") or ())).hexdigest(),
                        max_tokens=int(kwargs.get("max_tokens") or 0),
                        timeout=float(kwargs.get("request_timeout_seconds") or 60),
                    )
                    raw_calls = host_body.get("tool_calls") or ()
                    calls = []
                    for item in raw_calls:
                        if not isinstance(item, Mapping):
                            raise RuntimeError("authoritative host returned an invalid tool call")
                        arguments = item.get("arguments")
                        if not isinstance(arguments, Mapping):
                            raise RuntimeError("authoritative host returned invalid tool arguments")
                        calls.append(ProviderToolCall(
                            str(item.get("id") or ""),
                            str(item.get("name") or ""),
                            dict(arguments),
                        ))
                    metadata = dict(host_body.get("metadata") or {})
                    turn = ProviderToolTurn(
                        str(host_body.get("completion_text") or ""),
                        tuple(calls),
                        str(host_body.get("stop_reason") or "stop"),
                        metadata,
                    )
                else:
                    turn = self.client.complete_tool_turn(active_profile, **kwargs)
                metadata = dict(turn.metadata)
                if metadata.get("protocol_fallback_used") or metadata.get("structured_feature_fallback"):
                    raise RuntimeError("provider protocol fallback is outside the signed Forge contract")
                metadata.update(
                    {
                        # Scripted/injected clients never cross the
                        # controller-owned network boundary.  Their logical
                        # retry activity is useful for local budgeting, but
                        # it cannot mint a canary-grade physical send.
                        "physical_send_count": physical_attempts if self.authoritative_physical else 0,
                        "retry_count": retries,
                        "fallback_count": fallbacks,
                        "sitina_provider_profile": active_profile.name,
                        "sitina_provider_model": active_profile.model,
                    }
                )
                if self.authoritative_physical:
                    # The host already observed and atomically settled this
                    # response.  Do not accept worker-reported usage or call a
                    # worker-side settlement API.
                    receipt = host_body.get("receipt")
                    if not isinstance(receipt, Mapping):
                        raise RuntimeError("authoritative host returned no transport receipt")
                    self.transport_receipts.append(dict(receipt))
                    if self.receipt_sink is not None:
                        self.receipt_sink(dict(receipt))
                return ProviderToolTurn(turn.text, turn.tool_calls, turn.stop_reason, metadata)
            except BaseException as error:
                # Preserve bounded physical-send accounting on the original
                # provider exception.  The runtime's fail event can then
                # audit failed/recovered sends without persisting exception
                # text or changing the provider exception contract.
                try:
                    setattr(
                        error,
                        "sitina_physical_send_count",
                        physical_attempts if self.authoritative_physical else 0,
                    )
                    setattr(error, "sitina_retry_count", retries)
                    setattr(error, "sitina_fallback_count", fallbacks)
                    setattr(error, "sitina_provider_profile", active_profile.name)
                    setattr(error, "sitina_provider_model", active_profile.model)
                except Exception:
                    pass
                if not self._retryable(error):
                    raise
                if retries < self.retry_limit:
                    retries += 1
                    if self.backoff_seconds:
                        time.sleep(min(8.0, self.backoff_seconds * (2 ** (retries - 1))))
                    continue
                if not self.fallback_allowed or fallbacks >= self.max_fallbacks:
                    raise
                profile_index += 1
                fallbacks += 1
                # Retry budget is per logical request, not per provider
                # profile.  A fallback is a provider switch, never a new
                # allowance to resend three more times.


class AutonomousRuntimeError(RuntimeError):
    pass


def _stringify_floats(value: Any) -> Any:
    """Recursively convert floats to strings so audit payloads satisfy the
    Journal's canonical JSON (which forbids floats for deterministic hashing).
    Live providers put floats (latency/cost) in turn metadata; this preserves
    the value as a string rather than dropping it. Matches the codebase's
    string-valued-number convention (e.g. route confidence '0.9')."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {key: _stringify_floats(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_stringify_floats(item) for item in value]
    return value


def _redact_audit_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Redact structured audit values without rewriting serialized JSON.

    Applying ``redact_text`` to a JSON string can consume escape characters
    inside a matching value and make the result impossible to parse.  Keep the
    payload structured while redacting so audit serialization is always valid.
    """

    redacted = redact_boundary_value(dict(payload), boundary="log").value
    if not isinstance(redacted, dict):
        raise AutonomousRuntimeError("structured audit redaction must return an object")
    return _stringify_floats(redacted)


def _provider_usage_totals(
    provider_metadata: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "total_tokens": 0,
        "cost_micro_usd": 0,
    }
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens"),
        "output_tokens": ("output_tokens", "completion_tokens"),
        "cache_read_tokens": ("cache_read_tokens", "prompt_cache_hit_tokens"),
        "cache_write_tokens": ("cache_write_tokens", "prompt_cache_miss_tokens"),
        "total_tokens": ("total_tokens",),
    }
    for metadata in provider_metadata:
        summary = metadata.get("token_usage")
        details = metadata.get("provider_usage_details")
        sources = tuple(
            value for value in (summary, details) if isinstance(value, Mapping)
        )
        turn: dict[str, int] = {}
        for target, source_names in aliases.items():
            for source in sources:
                value = next(
                    (
                        source[name]
                        for name in source_names
                        if isinstance(source.get(name), int)
                        and not isinstance(source.get(name), bool)
                        and int(source[name]) >= 0
                    ),
                    None,
                )
                if value is not None:
                    turn[target] = int(value)
                    break
        turn.setdefault("input_tokens", 0)
        turn.setdefault("output_tokens", 0)
        turn.setdefault("cache_read_tokens", 0)
        turn.setdefault("cache_write_tokens", 0)
        turn.setdefault("total_tokens", turn["input_tokens"] + turn["output_tokens"])
        for name in aliases:
            totals[name] += turn[name]
        cost = metadata.get("cost_micro_usd", 0)
        if isinstance(cost, int) and not isinstance(cost, bool) and cost >= 0:
            totals["cost_micro_usd"] += cost
    return totals


def _mutation_evidence(
    tool_results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    def is_external_mutation(item: Mapping[str, Any]) -> bool:
        permission = str(item.get("permission") or "")
        value = item.get("result")
        if permission == "shell" and isinstance(value, Mapping) and value.get("unregistered_paths"):
            return True
        if str(item.get("status") or "") != "ok":
            return False
        arguments = item.get("arguments")
        args = arguments if isinstance(arguments, Mapping) else {}
        if permission == "external_service":
            return True
        if permission == "network":
            return str(args.get("method") or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}
        if permission != "shell":
            return False
        command = str(args.get("command") or "").casefold()
        # Test/build/install commands are local workspace activity.  Count
        # only commands with a clear external or irreversible side effect.
        markers = (
            "git push", "git commit", "git tag", "docker push", "docker deploy",
            "kubectl apply", "helm upgrade", "terraform apply", "pulumi up",
            "deploy", "publish", "release", "drop database", "drop table",
            "alter database", "alembic upgrade", "prisma migrate deploy",
            "curl -x post", "curl --request post", "wget --post-data",
        )
        return any(marker in command for marker in markers)

    events: list[dict[str, Any]] = []
    denied_attempts = 0
    external_mutations = 0
    for sequence, item in enumerate(tool_results, start=1):
        permission = str(item.get("permission") or "")
        status = str(item.get("status") or "")
        decision = str(item.get("permission_decision") or "")
        arguments = item.get("arguments")
        value = item.get("result")
        arguments_map = arguments if isinstance(arguments, Mapping) else {}
        value_map = value if isinstance(value, Mapping) else {}
        denied = status != "ok" and permission in {"write", "shell", "network", "external_service"}
        if denied:
            denied_attempts += 1
        if is_external_mutation(item):
            external_mutations += 1
        if permission != "write":
            continue
        raw_path = value_map.get("path", arguments_map.get("path"))
        normalized_path = None
        if isinstance(raw_path, str) and raw_path:
            normalized_path = str(Path(raw_path).expanduser().resolve(strict=False))
        before_hash = value_map.get("before_hash")
        after_hash = value_map.get("after_hash")
        operation = str(value_map.get("operation") or (
            "denied_write" if denied else "append" if value_map.get("append") else (
                "create" if before_hash is None else "modify"
            )
        ))
        events.append(
            {
                "schema": "SITINA_FILE_MUTATION_EVENT_V1",
                "sequence": sequence,
                "operation": operation,
                "path": normalized_path,
                "destination": (
                    str(Path(str(value_map["destination"])).expanduser().resolve(strict=False))
                    if isinstance(value_map.get("destination"), str) else None
                ),
                "before_hash": before_hash if isinstance(before_hash, str) else None,
                "after_hash": after_hash if isinstance(after_hash, str) else None,
                "authorization_ref": item.get("authorization_ref"),
                "tool_call_id": item.get("call_id"),
                "tool_name": item.get("name"),
                "worker_observed": value_map.get("worker_observed") is True,
                "worker_binding_hash": value_map.get("worker_binding_hash"),
                "status": status,
                "denied": denied,
            }
        )
    successful_paths = {
        str(item["path"])
        for item in events
        if not item["denied"] and isinstance(item.get("path"), str)
    }
    return {
        "events": events,
        "file_mutation_event_count": sum(not item["denied"] for item in events),
        "unique_mutated_path_count": len(successful_paths),
        "denied_effect_attempt_count": denied_attempts,
        "external_mutation_count": external_mutations,
    }


class JournalAutonomousAudit:
    """CAS-body/Journal-event evidence sink for the production tool loop."""

    TENANT = "sitina-autonomous"

    def __init__(self, journal: Any, cas: Any, key_provider: Any, *, run_id: str, policy_hash: str):
        from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream

        self.cas = cas
        self.keys = key_provider
        self.run_id = run_id
        self.stream = CanonicalStream(
            journal,
            run_id,
            f"run/{run_id}",
            policy_hash,
            namespace="sitina-autonomous-extensions-v2",
        )
        self.object_refs: list[str] = []
        self.event_ids: list[str] = []
        self.positions: list[int] = []
        self._append_lock = threading.RLock()

    def append(self, event: str, payload: Mapping[str, Any]) -> None:
        # CAS publication, canonical stream append, and the in-memory receipt
        # projections form one writer-critical section.  Tool reads may run
        # concurrently, but audit facts must never race the stream frontier.
        with self._append_lock:
            from sitina.cas.crypto import encrypt_object
            from sitina.journal.model import canonical_json_bytes

            clean = _redact_audit_payload(payload)
            record = {
                "schema": "SITINA_AUTONOMOUS_RUN_RECORD_V2",
                "timestamp": iso_now(),
                "run_id": self.run_id,
                "event": event,
                "payload": clean,
            }
            raw = canonical_json_bytes(record)
            proof = self.cas.publish_verified(
                encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="autonomous-run-record")
            )
            record_hash = hashlib.sha256(raw).hexdigest()
            safe_metadata = {
                key: clean[key]
                for key in (
                    "turn",
                    "call_id",
                    "name",
                    "permission",
                    "status",
                    "stop_reason",
                    "physical_send_count",
                    "embedded_call_id",
                    "effect_id",
                    "effect_attempt_id",
                    "provider_request_id",
                    "provider_response_id",
                    "provider_profile",
                    "provider_model",
                    "retry_count",
                    "fallback_count",
                    "retry_limit",
                    "fallback_limit",
                    "input_tokens",
                    "output_tokens",
                    "cache_read_tokens",
                    "cache_write_tokens",
                    "total_tokens",
                    "error_type",
                    "error_hash",
                )
                if key in clean and isinstance(clean[key], (str, int, bool))
            }
            if isinstance(clean.get("mutation_fact"), Mapping):
                safe_metadata["mutation_fact"] = dict(clean["mutation_fact"])
            _receipt, references = self.stream.append(
                "autonomous-" + event.replace("_", "-"),
                (
                    {
                        "schema": "SITINA_AUTONOMOUS_RUN_EVENT_V2",
                        "event_type": "autonomous." + event.replace("_", "-"),
                        "record_ref": proof.object_ref.reference_id,
                        "record_hash": record_hash,
                        **safe_metadata,
                        "_object_refs": [proof.object_ref.reference_id],
                    },
                ),
                actor="autonomous-conversation-runtime",
                proofs=(proof,),
            )
            self.object_refs.append(proof.object_ref.reference_id)
            self.event_ids.extend(str(item["event_id"]) for item in references)
            self.positions.extend(int(item["position"]) for item in references)

    def summary(self) -> dict[str, Any]:
        return {
            "journal_first_position": min(self.positions) if self.positions else None,
            "journal_last_position": max(self.positions) if self.positions else None,
            "journal_event_ids": list(self.event_ids),
            "cas_references": list(self.object_refs),
        }


class AutonomousRuntime:
    """Unbounded model/tool loop over Sitina-native global extensions.

    There are intentionally no model-turn, tool-call, duplicate-call, or read
    concurrency ceilings. The loop ends only when the provider returns no tool
    calls, the caller cancels, a provider fails, or an approval decision makes
    further progress impossible.
    """

    def __init__(
        self,
        home: Path,
        *,
        manager: ExtensionManager | None = None,
        client: ToolTurnClient | None = None,
        profile: ProviderProfile | None = None,
        profile_name: str | None = None,
        approval_callback: ApprovalCallback | None = None,
        workspace: Path | None = None,
        max_tokens: int = 4096,
        max_turns: int = 50,
        enforce_write_boundary: bool = False,
        before_hashes: Mapping[str, str | None] | None = None,
        strict_workspace: bool = False,
        managed_process_manager: Any | None = None,
        authorization_binding: Mapping[str, Any] | None = None,
        authorization_authority: Any | None = None,
        provider_preflight: Callable[[int], None] | None = None,
        provider_settlement: Callable[[Mapping[str, Any]], None] | None = None,
        provider_failure_settlement: Callable[[Mapping[str, Any]], None] | None = None,
        write_executor: Any | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.manager = manager or ExtensionManager(self.home)
        selected_profile = profile_name or RoleProfileResolver(self.home).profile_name_for_agent("default")
        if client is not None:
            self.client = client
            self.profile = profile or self.client.load_profile(selected_profile)
        else:
            base_client = AnthropicCompatibleClient(self.home)
            self.profile = profile or base_client.load_profile(selected_profile)
            if (self.home / "state/.legacy-control/frozen.json").is_file():
                from sitina.orchestrator.bplus_production import ProductionRuntimeContext

                context = ProductionRuntimeContext.load(
                    self.home,
                    allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
                )
                host = urlparse(self.profile.base_url).hostname
                if not host:
                    raise AutonomousRuntimeError("Provider profile has no valid network host")
                registry_hash = hashlib.sha256(
                    stable_json(self.manager.load_registry()).encode("utf-8")
                ).hexdigest()
                capability = issue_frozen_network_egress_capability(
                    context.authority.resolution,
                    manifest_hash=registry_hash,
                    operation="model_text_generation",
                    allowed_hosts=(host,),
                    expires_at=int(time.time()) + 1200,
                )
                self.client = AnthropicCompatibleClient(
                    self.home,
                    network_egress_capability=capability,
                )
            else:
                self.client = base_client
        self.catalog = ToolCatalog(
            self.manager,
            approval_callback=approval_callback,
            workspace=workspace or self.home,
            write_executor=write_executor or ToolExecutor(
                self.home,
                enforce_write_boundary=enforce_write_boundary,
                authorization_binding=authorization_binding,
                authorization_authority=authorization_authority,
            ),
            before_hashes=before_hashes,
            strict_workspace=strict_workspace,
            managed_process_manager=managed_process_manager,
        )
        self.hooks = HookRunner(self.catalog)
        self.max_tokens = max_tokens
        self.max_turns = max(1, int(max_turns))
        self.provider_preflight = provider_preflight
        self.provider_settlement = provider_settlement
        self.provider_failure_settlement = provider_failure_settlement
        self._journal_audit: JournalAutonomousAudit | None = None

    def globally_enabled(self) -> bool:
        registry = self.manager.load_registry()
        return any(not item.get("disabled") for item in registry["plugins"].values()) or any(
            not item.get("disabled") for item in registry["skills"].values()
        )

    def run(
        self,
        task: str,
        *,
        prior_messages: Sequence[Mapping[str, Any]] = (),
        session_id: str | None = None,
        turn_index: int | None = None,
        route_decision: Mapping[str, Any] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        status_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        task = task.strip()
        if not task:
            raise ValueError("autonomous task requires non-empty text")
        run_id = "agent-run-" + uuid.uuid4().hex
        self.catalog.bind_run(run_id)
        selected_skills = self.manager.select_skills(task)
        selected_agents = self.manager.select_agents(task)
        system_prompt = self._system_prompt(selected_skills, selected_agents)
        messages = [dict(item) for item in prior_messages]
        messages.append({"role": "user", "content": task})
        tool_schemas = self.catalog.provider_schemas()
        journal = None
        lifecycle = None
        production = (self.home / "state/.legacy-control/frozen.json").is_file()
        finished = False

        def finish() -> dict[str, Any]:
            nonlocal finished
            if finished:
                return {}
            summary = self._journal_audit.summary() if self._journal_audit is not None else {}
            self._journal_audit = None
            try:
                if journal is not None:
                    journal.close()
            finally:
                finished = True
            return summary

        try:
            if production:
                from sitina.conversation.lifecycle import ConversationLifecycle
                from sitina.conversation.models import route_decision_from_mapping
                from sitina.orchestrator.bplus_production import ProductionRuntimeContext

                # Chat invokes with a full conversation context (session +
                # turn + route). A standalone `sitina agent` run has none — it
                # still gets a full journal audit (JournalAutonomousAudit), it
                # just skips the chat-session linking (ConversationLifecycle).
                has_conversation = (
                    bool(session_id) and turn_index is not None and isinstance(route_decision, Mapping)
                )
                context = ProductionRuntimeContext.load(
                    self.home,
                    allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
                )
                journal = context.open_writer()
                cas = context.open_cas()
                registry_hash = hashlib.sha256(stable_json(self.manager.load_registry()).encode("utf-8")).hexdigest()
                self._journal_audit = JournalAutonomousAudit(
                    journal,
                    cas,
                    context.provider,
                    run_id=run_id,
                    policy_hash=registry_hash,
                )
                if has_conversation:
                    lifecycle = ConversationLifecycle(journal, cas, context.provider)
                    lifecycle.start_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        message=task,
                        route_decision=route_decision_from_mapping(route_decision),
                        occurred_at=iso_now(),
                    )
                    lifecycle.link_run(
                        session_id=session_id,
                        turn_index=turn_index,
                        run_id=run_id,
                        occurred_at=iso_now(),
                    )
            result = self._run_active(
                task=task,
                run_id=run_id,
                system_prompt=system_prompt,
                messages=messages,
                tool_schemas=tool_schemas,
                selected_skills=selected_skills,
                selected_agents=selected_agents,
                session_id=session_id,
                turn_index=turn_index,
                lifecycle=lifecycle,
                cancel_check=cancel_check,
                status_callback=status_callback,
            )
            if self._journal_audit is not None:
                result.update(self._journal_audit.summary())
            return result
        except BaseException as error:
            # Never fall back to the legacy external JSONL sink after a
            # production setup failure. If the Journal audit exists, persist a
            # bounded failure record and make the session explicitly failed.
            if not production or self._journal_audit is not None:
                try:
                    self._audit(
                        run_id,
                        "run_failed",
                        {
                            "error_type": type(error).__name__,
                            "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                            "automatic_retry_performed": False,
                            "success_claimed": False,
                        },
                    )
                except Exception:
                    pass
            if lifecycle is not None:
                assert session_id is not None and turn_index is not None
                try:
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type=type(error).__name__,
                        occurred_at=iso_now(),
                    )
                except Exception:
                    pass
            raise
        finally:
            try:
                self._cleanup_managed_processes()
            finally:
                finish()

    def run_embedded(
        self,
        task: str,
        *,
        run_id: str,
        journal_audit: "JournalAutonomousAudit | None" = None,
        cancel_check: Callable[[], bool] | None = None,
        status_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run the tool loop as a loop-instance INSIDE another runtime that
        already holds the journal writer (e.g. the MULTI orchestrator's Forge
        execution bridge). Unlike run(), this opens NO journal writer of its
        own — it borrows the caller's via `journal_audit` — so it never contends
        the exclusive writer lock. Pass the orchestrator's already-open
        JournalAutonomousAudit for fence-safe evidence."""
        task = task.strip()
        if not task:
            raise ValueError("embedded run requires non-empty task text")
        self.catalog.bind_run(run_id)
        self._journal_audit = journal_audit
        selected_skills = self.manager.select_skills(task)
        selected_agents = self.manager.select_agents(task)
        system_prompt = self._system_prompt(selected_skills, selected_agents)
        messages = [{"role": "user", "content": task}]
        tool_schemas = self.catalog.provider_schemas()
        try:
            return self._run_active(
                task=task,
                run_id=run_id,
                system_prompt=system_prompt,
                messages=messages,
                tool_schemas=tool_schemas,
                selected_skills=selected_skills,
                selected_agents=selected_agents,
                session_id=None,
                turn_index=None,
                lifecycle=None,
                cancel_check=cancel_check,
                status_callback=status_callback,
            )
        finally:
            try:
                self._cleanup_managed_processes()
            finally:
                self._journal_audit = None

    def _cleanup_managed_processes(self) -> None:
        manager = getattr(self.catalog, "_managed_process_manager", None)
        if manager is None:
            return
        try:
            reconcile = getattr(self.catalog, "reconcile_managed_processes", None)
            try:
                if callable(reconcile):
                    reconcile()
            finally:
                # Even when reconciliation raises because an async process
                # dirtied the workspace, the process itself must still be
                # stopped before the error leaves the runtime.
                manager.cleanup()
        except Exception as error:
            if self._journal_audit is not None:
                self._journal_audit.append(
                    "managed_process_cleanup_failed",
                    {
                        "error_type": type(error).__name__,
                        "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                        "success_claimed": False,
                    },
                )
            raise

    def _run_active(
        self,
        *,
        task: str,
        run_id: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tool_schemas: Sequence[Mapping[str, Any]],
        selected_skills: Sequence[Any],
        selected_agents: Sequence[Any],
        session_id: str | None,
        turn_index: int | None,
        lifecycle: Any,
        cancel_check: Callable[[], bool] | None,
        status_callback: Callable[[str, Mapping[str, Any]], None] | None,
    ) -> dict[str, Any]:
        provider_turns = 0
        tool_results: list[dict[str, Any]] = []
        provider_metadata: list[dict[str, Any]] = []
        self._audit(
            run_id,
            "run_started",
            {
                "task": task,
                "selected_skills": [item.qualified_name for item in selected_skills],
                "selected_agents": [f"{item.plugin_name}:{item.name}" for item in selected_agents],
                "tool_count": len(tool_schemas),
            },
        )
        self.hooks.run("before_agent", {"run_id": run_id, "task": task})
        recent_signatures: list[str] = []
        empty_final_repair_used = False
        while True:
            # M1.5 loop robustness: hard turn cap — graceful stop, not a crash.
            if provider_turns >= self.max_turns:
                self._audit(run_id, "run_turn_cap_reached", {"max_turns": self.max_turns})
                if lifecycle is not None:
                    assert session_id is not None and turn_index is not None
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type="TurnCapReached",
                        occurred_at=iso_now(),
                    )
                return self._result(
                    run_id,
                    "incomplete",
                    "FAILED",
                    f"stopped: reached max_turns={self.max_turns} without a final response",
                    provider_turns,
                    tool_results,
                    selected_skills,
                    selected_agents,
                    provider_metadata,
                )
            if cancel_check and cancel_check():
                self._audit(run_id, "run_cancelled", {})
                if lifecycle is not None:
                    assert session_id is not None and turn_index is not None
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type="Cancelled",
                        occurred_at=iso_now(),
                    )
                return self._result(
                    run_id,
                    "cancelled",
                    "CANCELLED",
                    "",
                    provider_turns,
                    tool_results,
                    selected_skills,
                    selected_agents,
                    provider_metadata,
                )
            if status_callback:
                status_callback("model_turn", {"run_id": run_id, "turn": provider_turns + 1})
            embedded_call_id = f"{run_id}:embedded-call:{provider_turns + 1}"
            effect_id = f"{run_id}:embedded-effect:{provider_turns + 1}"
            effect_attempt_id = f"{effect_id}:attempt:1"
            provider_profile = str(getattr(self.profile, "name", "unknown"))
            provider_model = str(getattr(self.profile, "model", "unknown"))
            self._audit(
                run_id,
                "provider_call_intended",
                {
                    "turn": provider_turns + 1,
                    "embedded_call_id": embedded_call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": effect_attempt_id,
                    "provider_profile": provider_profile,
                    "provider_model": provider_model,
                    "retry_limit": int(getattr(self.client, "retry_limit", 0) or 0),
                    "fallback_limit": int(getattr(self.client, "max_fallbacks", 0) or 0),
                    "system_prompt": system_prompt,
                    "messages": messages,
                    "tools": tool_schemas,
                    "max_tokens": self.max_tokens,
                },
            )
            if self.provider_preflight is not None:
                self.provider_preflight(self.max_tokens)
            try:
                turn = self.client.complete_tool_turn(
                    self.profile,
                    system_prompt=system_prompt,
                    messages=messages,
                    tools=tool_schemas,
                    max_tokens=self.max_tokens,
                    cancel_check=cancel_check,
                )
            except BaseException as error:
                physical_send_count = int(getattr(error, "sitina_physical_send_count", 0) or 0)
                retry_count = int(getattr(error, "sitina_retry_count", 0) or 0)
                fallback_count = int(getattr(error, "sitina_fallback_count", 0) or 0)
                failure_metadata = {
                    "embedded_call_id": embedded_call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": effect_attempt_id,
                    "provider_profile": str(getattr(error, "sitina_provider_profile", provider_profile)),
                    "provider_model": str(getattr(error, "sitina_provider_model", provider_model)),
                    "physical_send_count": physical_send_count,
                    "retry_count": retry_count,
                    "fallback_count": fallback_count,
                    "usage_status": "unknown",
                    "usage_unsettled": bool(physical_send_count),
                }
                if self.provider_failure_settlement is not None:
                    self.provider_failure_settlement(failure_metadata)
                self._audit(
                    run_id,
                    "provider_call_failed",
                    {
                        "turn": provider_turns + 1,
                        **failure_metadata,
                        "error_type": type(error).__name__,
                        "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                        "automatic_retry_performed": bool(retry_count or fallback_count),
                    },
                )
                raise
            provider_turns += 1
            turn_metadata = dict(turn.metadata)
            usage = _provider_usage_totals((turn_metadata,))
            provider_profile = str(turn_metadata.get("sitina_provider_profile") or provider_profile)
            provider_model = str(turn_metadata.get("sitina_provider_model") or provider_model)
            provider_request_id = turn_metadata.get("provider_request_id")
            provider_response_id = turn_metadata.get("provider_response_id")
            if not isinstance(provider_request_id, str) or not provider_request_id:
                provider_request_id = provider_response_id if isinstance(provider_response_id, str) else None
            if not isinstance(provider_response_id, str) or not provider_response_id:
                provider_response_id = provider_request_id
            turn_metadata.update(
                {
                    "embedded_call_id": embedded_call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": effect_attempt_id,
                    "provider_profile": provider_profile,
                    "provider_model": provider_model,
                    "input_tokens": usage["input_tokens"],
                    "output_tokens": usage["output_tokens"],
                    "cache_read_tokens": usage["cache_read_tokens"],
                    "cache_write_tokens": usage["cache_write_tokens"],
                    "total_tokens": usage["total_tokens"],
                    **({"provider_request_id": provider_request_id} if provider_request_id else {}),
                    **({"provider_response_id": provider_response_id} if provider_response_id else {}),
                }
            )
            provider_metadata.append(turn_metadata)
            if self.provider_settlement is not None:
                self.provider_settlement(turn.metadata)
            assistant_calls = [
                {"id": call.call_id, "name": call.name, "arguments": dict(call.arguments)}
                for call in turn.tool_calls
            ]
            messages.append({"role": "assistant", "content": turn.text, "tool_calls": assistant_calls})
            self._audit(
                run_id,
                "model_turn_completed",
                {
                    "turn": provider_turns,
                    "embedded_call_id": embedded_call_id,
                    "effect_id": effect_id,
                    "effect_attempt_id": effect_attempt_id,
                    "provider_profile": provider_profile,
                    "provider_model": provider_model,
                    "provider_request_id": provider_request_id,
                    "provider_response_id": provider_response_id,
                    "input_tokens": usage["input_tokens"],
                    "output_tokens": usage["output_tokens"],
                    "cache_read_tokens": usage["cache_read_tokens"],
                    "cache_write_tokens": usage["cache_write_tokens"],
                    "total_tokens": usage["total_tokens"],
                    "stop_reason": turn.stop_reason,
                    "tool_calls": assistant_calls,
                    "text": turn.text,
                    "metadata": turn_metadata,
                },
            )
            if not turn.tool_calls:
                response = turn.text.strip()
                if not response:
                    if not empty_final_repair_used:
                        empty_final_repair_used = True
                        self._audit(
                            run_id,
                            "empty_final_response_repair_requested",
                            {"turn": provider_turns, "attempt": 1},
                        )
                        messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "Previous turn ended without content. Return one concise final result now; "
                                    "do not call tools."
                                ),
                            }
                        )
                        continue
                    raise AutonomousRuntimeError("provider ended the tool loop without a final response")
                self.hooks.run("after_agent", {"run_id": run_id, "task": task, "response": response})
                if lifecycle is not None:
                    assert session_id is not None and turn_index is not None
                    lifecycle.complete_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        message=task,
                        response=response,
                        occurred_at=iso_now(),
                    )
                # The session assistant append is the user-visible success
                # marker. Only declare the autonomous run successful after it
                # commits.
                self._audit(run_id, "run_succeeded", {"response": response})
                return self._result(
                    run_id,
                    "ok",
                    "SUCCEEDED",
                    response,
                    provider_turns,
                    tool_results,
                    selected_skills,
                    selected_agents,
                    provider_metadata,
                )
            if status_callback:
                status_callback(
                    "tool_calls",
                    {"run_id": run_id, "turn": provider_turns, "tools": [call.name for call in turn.tool_calls]},
                )
            results_by_id = self._execute_calls(run_id, turn.tool_calls)
            for call in turn.tool_calls:
                result = results_by_id[call.call_id]
                record = {
                    "call_id": call.call_id,
                    "name": call.name,
                    "arguments": dict(call.arguments),
                    "permission": result.permission,
                    "permission_decision": result.permission_decision,
                    "status": result.status,
                    "result": result.value,
                    "started_at": result.started_at,
                    "completed_at": result.completed_at,
                    "authorization_ref": result.authorization_ref,
                }
                tool_results.append(record)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.call_id,
                        "name": call.name,
                        "content": result.content(),
                        "is_error": result.status != "ok",
                    }
                )
                definition = self.catalog.get(call.name)
                self._audit(
                    run_id,
                    "tool_completed",
                    {
                        "call_id": call.call_id,
                        "argument_summary": summarize_tool_arguments(
                            definition.origin,
                            call.name,
                            call.arguments,
                        ),
                        "permission": result.permission,
                        "result_summary": summarize_tool_result(
                            definition.origin,
                            call.name,
                            status=result.status,
                            value=result.value,
                            duration_ms=result.duration_ms,
                            permission_decision=result.permission_decision,
                        ),
                        # Keep the minimal hash/path mutation fact in the
                        # child Journal/CAS record.  The parent Forge result
                        # must be able to recover completed worker effects if
                        # the next Provider turn fails before ``_result`` can
                        # return; raw contents never cross this boundary.
                        "mutation_fact": self._mutation_fact(call, result),
                    },
                )
            # M1.5 loop detection: if the model repeats the exact same tool
            # calls (same names+args) AND every call errored, three turns in a
            # row, it is stuck — stop gracefully instead of spinning.
            signature = stable_json(
                [
                    {"name": call.name, "arguments": dict(call.arguments)}
                    for call in turn.tool_calls
                ]
            )
            all_errored = all(results_by_id[call.call_id].status != "ok" for call in turn.tool_calls)
            if all_errored and recent_signatures[-2:] == [signature, signature]:
                self._audit(run_id, "run_stuck_loop_detected", {"repeated_turns": 3})
                if lifecycle is not None:
                    assert session_id is not None and turn_index is not None
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type="StuckLoopDetected",
                        occurred_at=iso_now(),
                    )
                return self._result(
                    run_id,
                    "incomplete",
                    "FAILED",
                    "stopped: repeated identical failing tool calls (stuck loop)",
                    provider_turns,
                    tool_results,
                    selected_skills,
                    selected_agents,
                    provider_metadata,
                )
            recent_signatures.append(signature)

    def _execute_calls(self, run_id: str, calls: Sequence[ProviderToolCall]) -> dict[str, ToolResult]:
        read_calls: list[ProviderToolCall] = []
        gated_calls: list[ProviderToolCall] = []
        for call in calls:
            if self.catalog.get(call.name).permission == "read":
                read_calls.append(call)
            else:
                gated_calls.append(call)
        # Intended facts are provider-call ordered and must be committed by
        # this coordinator before any read worker starts.  The workers still
        # execute the read tools concurrently; they do not write Journal/CAS.
        for call in calls:
            definition = self.catalog.get(call.name)
            self._audit(
                run_id,
                "tool_call_intended",
                {
                    "call_id": call.call_id,
                    "name": call.name,
                    "argument_summary": summarize_tool_arguments(
                        definition.origin,
                        call.name,
                        call.arguments,
                    ),
                    "permission": definition.permission,
                },
            )
        results: dict[str, ToolResult] = {}
        if read_calls:
            # This pool is sized to the model's current request, not to a fixed
            # policy ceiling; Sitina imposes no read concurrency limit.
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(read_calls)) as pool:
                futures = {pool.submit(self._execute_one, run_id, call): call.call_id for call in read_calls}
                for future, call_id in futures.items():
                    results[call_id] = future.result()
        for call in gated_calls:
            results[call.call_id] = self._execute_one(run_id, call)
        return results

    def _workspace_relative_path(self, raw_path: Any) -> str | None:
        """Return a stable identity for a path inside this run's workspace.

        Journal audit payloads are redacted at the boundary, so an absolute
        temporary workspace path is not a safe identity: a timestamp-like
        component can be replaced before the parent reopens the record.  The
        workspace root is already bound by ``ToolCatalog``; emit only its
        normalized relative path for mutation facts.  Resolution is performed
        before ``relative_to`` so symlink/path escapes fail closed.
        """
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
        try:
            workspace = self.catalog.workspace.expanduser().resolve(strict=False)
            candidate = Path(raw_path).expanduser()
            if not candidate.is_absolute():
                candidate = workspace / candidate
            candidate = candidate.resolve(strict=False)
            relative = candidate.relative_to(workspace)
        except (OSError, RuntimeError, ValueError):
            return None
        # Empty, dot, and parent components are never valid mutation
        # identities.  ``resolve`` normally removes them, but rejecting them
        # explicitly keeps the serialized identity unambiguous.
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return None
        return relative.as_posix()

    def _mutation_fact(self, call: ProviderToolCall, result: ToolResult) -> dict[str, Any] | None:
        if result.permission != "write":
            return None
        value = result.value if isinstance(result.value, Mapping) else {}
        arguments = call.arguments if isinstance(call.arguments, Mapping) else {}
        before_hash = value.get("before_hash") if isinstance(value.get("before_hash"), str) else None
        after_hash = value.get("after_hash") if isinstance(value.get("after_hash"), str) else None
        path = arguments.get("path") or value.get("path")
        relative_path = self._workspace_relative_path(path)
        destination = value.get("destination") if isinstance(value.get("destination"), str) else arguments.get("destination")
        relative_destination = self._workspace_relative_path(destination)
        if not isinstance(path, str) or not path:
            return {
                "status": str(result.status),
                "denied": result.status != "ok",
                "path": None,
                "path_identity": None,
                "workspace_relative_path": None,
                "destination": None,
                "destination_identity": None,
                "workspace_relative_destination": None,
            }
        path_identity = encode_workspace_relative_path(relative_path) if relative_path else None
        destination_identity = (
            encode_workspace_relative_path(relative_destination)
            if relative_destination
            else None
        )
        return {
            "status": str(result.status),
            "denied": result.status != "ok",
            "operation": str(value.get("operation") or ("create" if before_hash is None else "modify")),
            # ``path`` is intentionally the workspace-relative identity.  Do
            # not persist an absolute temporary path as a business key: the
            # Journal redaction boundary may rewrite it before replay.
            "path": path_identity,
            "path_identity": path_identity,
            "workspace_relative_path": path_identity,
            "destination": destination_identity,
            "destination_identity": destination_identity,
            "workspace_relative_destination": destination_identity,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "authorization_ref": result.authorization_ref,
            "worker_observed": value.get("worker_observed") is True,
            "worker_binding_hash": value.get("worker_binding_hash"),
        }

    def _execute_one(self, run_id: str, call: ProviderToolCall) -> ToolResult:
        definition = self.catalog.get(call.name)
        self.hooks.run(
            "before_tool",
            {"run_id": run_id, "tool": call.name, "permission": definition.permission, "arguments": call.arguments},
        )
        try:
            result = self.catalog.execute(call.name, call.arguments)
        except (ToolApprovalDenied, ToolRuntimeError) as exc:
            now = iso_now()
            result = ToolResult(
                call.name,
                definition.permission,
                "error",
                f"{type(exc).__name__}: {exc}",
                now,
                now,
                permission_decision="denied",
                authorization_ref=getattr(exc, "authorization_ref", None),
            )
        self.hooks.run(
            "after_tool",
            {
                "run_id": run_id,
                "tool": call.name,
                "permission": definition.permission,
                "status": result.status,
                "result": result.value,
            },
        )
        return result

    def _system_prompt(self, skills: Sequence[Any], agents: Sequence[Any]) -> str:
        skill_text = "\n\n".join(
            f"<sitina-skill name=\"{skill.qualified_name}\">\n{skill.body}\n</sitina-skill>" for skill in skills
        )
        agent_text = "\n\n".join(
            f"<sitina-plugin-agent name=\"{agent.plugin_name}:{agent.name}\">\n{agent.body}\n</sitina-plugin-agent>"
            for agent in agents
        )
        return (
            "You are Sitina's autonomous task runtime. Complete the user's task, using the supplied tools whenever "
            "they provide evidence or are needed to act. Continue calling tools across as many model turns as the task "
            "requires. Read-only calls execute automatically. Write, shell, network, and external-service calls are "
            "subject to Sitina approval; if a call is denied, use the returned error and choose a safe alternative or "
            "explain what remains blocked. Never claim a tool action happened unless a tool result confirms it. Multiple "
            "active Skills apply together. Use sitina_read_skill_resource when a selected Skill directs you to its "
            "references, assets, or scripts.\n\n"
            f"Selected Skills:\n{skill_text or '(none)'}\n\n"
            f"Selected plugin Agents:\n{agent_text or '(none)'}"
        )

    def _audit(self, run_id: str, event: str, payload: Mapping[str, Any]) -> None:
        if self._journal_audit is not None:
            self._journal_audit.append(event, payload)
            return
        path = self.manager.root / "runs" / f"{run_id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "schema": "SITINA_AUTONOMOUS_RUN_EVENT_V1",
            "timestamp": iso_now(),
            "run_id": run_id,
            "event": event,
            **_redact_audit_payload(payload),
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    @staticmethod
    def _result(
        run_id: str,
        status: str,
        terminal_state: str,
        response: str,
        provider_turns: int,
        tool_results: Sequence[Mapping[str, Any]],
        skills: Sequence[Any],
        agents: Sequence[Any],
        provider_metadata: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        usage = _provider_usage_totals(provider_metadata)
        mutations = _mutation_evidence(tool_results)
        retry_count = sum(int(item.get("retry_count", 0) or 0) for item in provider_metadata)
        fallback_count = sum(int(item.get("fallback_count", 0) or 0) for item in provider_metadata)
        actual_profiles = [
            str(item["sitina_provider_profile"])
            for item in provider_metadata
            if isinstance(item.get("sitina_provider_profile"), str)
        ]
        actual_models = [
            str(item["sitina_provider_model"])
            for item in provider_metadata
            if isinstance(item.get("sitina_provider_model"), str)
        ]
        return {
            "status": status,
            "terminal_state": terminal_state,
            "run_id": run_id,
            "response": response,
            "provider_call_count": provider_turns,
            "provider_physical_send_count": sum(
                int(item.get("physical_send_count", 1)) for item in provider_metadata
            ),
            "provider_retry_count": retry_count,
            "provider_fallback_count": fallback_count,
            "provider_profile": actual_profiles[-1] if actual_profiles else None,
            "provider_model": actual_models[-1] if actual_models else None,
            "provider_profiles": list(dict.fromkeys(actual_profiles)),
            "provider_models": list(dict.fromkeys(actual_models)),
            "provider_input_tokens": usage["input_tokens"],
            "provider_output_tokens": usage["output_tokens"],
            "provider_cache_read_tokens": usage["cache_read_tokens"],
            "provider_cache_write_tokens": usage["cache_write_tokens"],
            "provider_token_total": usage["total_tokens"],
            "provider_cost_micro_usd": usage["cost_micro_usd"],
            "tool_call_count": len(tool_results),
            "tool_results": [dict(item) for item in tool_results],
            "selected_skills": [item.qualified_name for item in skills],
            "selected_plugin_agents": [f"{item.plugin_name}:{item.name}" for item in agents],
            "provider_metadata": [dict(item) for item in provider_metadata],
            "mutation_events": mutations["events"],
            "accepted_file_operation_contract": ["create", "modify", "append", "rename", "delete"],
            "unsupported_file_operations": [],
            "file_mutation_event_count": mutations["file_mutation_event_count"],
            "unique_mutated_path_count": mutations["unique_mutated_path_count"],
            "denied_effect_attempt_count": mutations["denied_effect_attempt_count"],
            "external_mutation_count": mutations["external_mutation_count"],
            "runtime": "sitina-autonomous-extensions-v1",
        }
