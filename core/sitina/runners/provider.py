from __future__ import annotations

import json
import multiprocessing
import os
import time
import urllib.error
import urllib.request
import datetime as dt
import http.client
import signal
import socket
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlparse, urlunsplit

from sitina.constants import SITINA_HOME
from sitina.install_identity import LEGACY_PRODUCTION_HOME, canonical_journal_native_home
from sitina.legacy.fence import FrozenNetworkEgressCapability, authorized_frozen_network_egress
from sitina.legacy.retirement import LegacyRuntimePolicy
from sitina.orchestrator.timeout_support import ProviderTimeoutConfig
from sitina.runners.profiles import ProfileLoader
from sitina.storage import SitinaStore
from sitina.utils import iso_now, load_json_yaml, redact_text, sha256_text, stable_json, utc_now


OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
ANTHROPIC_MESSAGES = "anthropic_messages"
SUPPORTED_WIRE_PROTOCOLS = frozenset({OPENAI_CHAT_COMPLETIONS, ANTHROPIC_MESSAGES})

def infer_wire_protocol(
    profile_name: str,
    base_url: str,
    explicit: str | None = None,
) -> str:
    """Resolve the provider wire adapter without making it core semantics.

    A profile may state the protocol explicitly.  The three well-known
    provider families are safe to infer for existing installations; an
    unknown HTTPS endpoint must declare its adapter so a new provider cannot
    accidentally inherit the wrong request/response contract.
    """

    value = str(explicit or "").strip().lower()
    if value:
        if value not in SUPPORTED_WIRE_PROTOCOLS:
            raise ProviderError(f"unsupported provider wire protocol: {value}")
        return value
    host = (urlparse(str(base_url)).hostname or "").casefold()
    name = str(profile_name or "").casefold()
    if "anthropic" in host or "anthropic" in name:
        return ANTHROPIC_MESSAGES
    if "deepseek" in host or "deepseek" in name or "openai" in host or "openai" in name:
        return OPENAI_CHAT_COMPLETIONS
    raise ProviderError("unknown provider endpoint requires an explicit wire protocol")


def provider_adapter_capabilities(
    profile_name: str,
    base_url: str,
    capabilities: Sequence[str] = (),
) -> frozenset[str]:
    """Return adapter-only capabilities; never promote them to Agent facts."""

    result = {str(value).strip() for value in capabilities if isinstance(value, str) and value.strip()}
    host = (urlparse(str(base_url)).hostname or "").casefold()
    if "deepseek" in host or str(profile_name or "").casefold() == "deepseek":
        result.add("deepseek_thinking_disabled")
    return frozenset(result)


def provider_endpoint_allowed(
    base_url: str,
    *,
    profile_name: str = "",
    wire_protocol: str | None = None,
    allowed_hosts: Sequence[str] = (),
) -> bool:
    """Enforce profile-bound HTTPS endpoint admission.

    Loopback is deliberately available only behind both existing test hooks.
    Production HTTPS admission is driven by the launcher-selected profile's
    host allowlist; when no explicit list exists, the fixed profile URL is its
    own host binding.  Unknown hosts still need an explicit wire protocol.
    """

    parsed = urlparse(str(base_url).rstrip("/"))
    hostname = (parsed.hostname or "").casefold()
    if (
        os.environ.get("SITINA_CODE_MODE_TEST_HOOKS") == "1"
        and os.environ.get("SITINA_CODE_MODE_LOCAL_PROVIDER_TEST") == "1"
        and parsed.scheme == "http"
        and hostname in {"127.0.0.1", "localhost", "::1"}
        and isinstance(parsed.port, int)
        and 1 <= parsed.port <= 65535
    ):
        return True
    if parsed.scheme != "https" or not hostname:
        return False
    try:
        infer_wire_protocol(profile_name, base_url, wire_protocol)
    except ProviderError:
        return False
    configured = {
        str(value).strip().casefold()
        for value in allowed_hosts
        if isinstance(value, str) and value.strip()
    }
    return hostname in configured if configured else True


class ProviderError(RuntimeError):
    error_type = "provider_error"


class ProviderHTTPError(ProviderError):
    error_type = "provider_http_error"

    def __init__(self, status_code: int, message: str, *, retry_after_seconds: float | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class ProviderConnectTimeout(ProviderError):
    error_type = "provider_connect_timeout"


class ProviderReadTimeout(ProviderError):
    error_type = "provider_read_timeout"


class ProviderDeadlineExceeded(ProviderError):
    error_type = "run_deadline_exceeded"


class ProviderCancelledError(ProviderError):
    error_type = "run_cancelled"


class ProviderAuthError(ProviderHTTPError):
    error_type = "provider_auth_failed"


class ProviderPermissionError(ProviderHTTPError):
    error_type = "provider_permission_denied"


class ProviderRateLimitError(ProviderHTTPError):
    error_type = "provider_rate_limited"


class ProviderMalformedResponse(ProviderError):
    error_type = "provider_parse_failed"


def provider_tools_for_wire(tools: object, wire_protocol: str) -> list[dict[str, Any]]:
    """Validate and adapt Sitina-neutral tools for one provider wire.

    The neutral form is the only normal input from the execution layer.  The
    already-published OpenAI function form remains accepted solely for the
    fixed structured-response tool path.  No aliases, defaults, coercions, or
    provider-specific names are inferred here.
    """
    if wire_protocol not in SUPPORTED_WIRE_PROTOCOLS:
        raise ProviderError("unsupported provider wire protocol")
    if not isinstance(tools, (list, tuple)):
        raise ProviderError("provider tools must be a list")
    normalized: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise ProviderError("provider tool must be an object")
        if set(tool) == {"name", "description", "input_schema"}:
            name = tool.get("name")
            description = tool.get("description")
            input_schema = tool.get("input_schema")
            strict: bool | None = None
        elif set(tool) == {"type", "function"} and tool.get("type") == "function":
            function = tool.get("function")
            if not isinstance(function, Mapping) or set(function) not in (
                {"name", "description", "parameters"},
                {"name", "description", "parameters", "strict"},
            ):
                raise ProviderError("provider function tool is malformed")
            name = function.get("name")
            description = function.get("description")
            input_schema = function.get("parameters")
            strict = function.get("strict") if "strict" in function else None
            if strict is not None and type(strict) is not bool:
                raise ProviderError("provider function strict flag is malformed")
        else:
            raise ProviderError("provider tool shape is not exact")
        if (
            type(name) is not str or not name
            or type(description) is not str
            or not isinstance(input_schema, Mapping)
        ):
            raise ProviderError("provider tool fields are malformed")
        normalized_tool = {
            "name": name,
            "description": description,
            "input_schema": dict(input_schema),
        }
        if strict is not None:
            normalized_tool["strict"] = strict
        normalized.append(normalized_tool)
    if wire_protocol == OPENAI_CHAT_COMPLETIONS:
        result = []
        for tool in normalized:
            function = {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            }
            if "strict" in tool:
                function["strict"] = tool["strict"]
            result.append({"type": "function", "function": function})
        return result
    return [
        {
            "name": tool["name"],
            "description": tool["description"],
            "input_schema": tool["input_schema"],
        }
        for tool in normalized
    ]


def provider_messages_for_wire(messages: object, wire_protocol: str) -> list[dict[str, Any]]:
    """Validate and adapt neutral multi-turn messages for one provider wire.

    The execution layer uses only ``user``, ``assistant`` and ``tool``
    records.  Provider-specific function/tool-use envelopes are constructed
    here so the Host and direct provider client cannot drift.  The conversion
    is deliberately strict: it validates the neutral record before dropping
    fields that a target protocol does not carry.
    """
    if wire_protocol not in SUPPORTED_WIRE_PROTOCOLS:
        raise ProviderError("unsupported provider wire protocol")
    if not isinstance(messages, (list, tuple)):
        raise ProviderError("provider messages must be a list")

    normalized: list[dict[str, Any]] = []
    for raw in messages:
        if not isinstance(raw, Mapping) or type(raw.get("role")) is not str:
            raise ProviderError("provider message is malformed")
        role = raw["role"]
        if role == "user":
            if set(raw) != {"role", "content"} or type(raw["content"]) is not str:
                raise ProviderError("provider user message is malformed")
            normalized.append({"role": "user", "content": raw["content"]})
            continue
        if role == "assistant":
            if set(raw) - {"role", "content", "tool_calls"} or "content" not in raw:
                raise ProviderError("provider assistant message is malformed")
            if type(raw["content"]) is not str:
                raise ProviderError("provider assistant content is malformed")
            calls = raw.get("tool_calls", [])
            if type(calls) is not list:
                raise ProviderError("provider assistant tool calls are malformed")
            normalized_calls: list[dict[str, Any]] = []
            for call in calls:
                if not isinstance(call, Mapping) or set(call) != {"id", "name", "arguments"}:
                    raise ProviderError("provider assistant tool call is malformed")
                call_id = call["id"]
                name = call["name"]
                arguments = call["arguments"]
                if (
                    type(call_id) is not str or not call_id
                    or type(name) is not str or not name
                    or not isinstance(arguments, Mapping)
                ):
                    raise ProviderError("provider assistant tool call fields are malformed")
                normalized_calls.append({
                    "id": call_id,
                    "name": name,
                    "arguments": dict(arguments),
                })
            normalized.append({
                "role": "assistant",
                "content": raw["content"],
                "tool_calls": normalized_calls,
            })
            continue
        if role == "tool":
            allowed = {"role", "tool_call_id", "content", "name", "is_error"}
            if set(raw) - allowed or "tool_call_id" not in raw or "content" not in raw:
                raise ProviderError("provider tool result is malformed")
            call_id = raw["tool_call_id"]
            content = raw["content"]
            if type(call_id) is not str or not call_id or type(content) is not str:
                raise ProviderError("provider tool result fields are malformed")
            name = raw.get("name")
            if name is not None and (type(name) is not str or not name):
                raise ProviderError("provider tool result name is malformed")
            is_error = raw.get("is_error", False)
            if type(is_error) is not bool:
                raise ProviderError("provider tool result error flag is malformed")
            normalized.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": content,
                **({"name": name} if name is not None else {}),
                "is_error": is_error,
            })
            continue
        raise ProviderError("unsupported provider message role")

    if wire_protocol == OPENAI_CHAT_COMPLETIONS:
        result: list[dict[str, Any]] = []
        for message in normalized:
            if message["role"] == "assistant":
                result.append({
                    "role": "assistant",
                    "content": message["content"],
                    "tool_calls": [
                        {
                            "id": call["id"],
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": stable_json(call["arguments"]),
                            },
                        }
                        for call in message["tool_calls"]
                    ],
                })
            elif message["role"] == "tool":
                result.append({
                    "role": "tool",
                    "tool_call_id": message["tool_call_id"],
                    "content": message["content"],
                })
            else:
                result.append({"role": "user", "content": message["content"]})
        return result

    result = []
    pending_results: list[dict[str, Any]] = []

    def flush_results() -> None:
        if pending_results:
            result.append({"role": "user", "content": list(pending_results)})
            pending_results.clear()

    for message in normalized:
        if message["role"] == "tool":
            pending_results.append({
                "type": "tool_result",
                "tool_use_id": message["tool_call_id"],
                "content": message["content"],
                **({"is_error": True} if message["is_error"] else {}),
            })
            continue
        flush_results()
        if message["role"] == "user":
            result.append({"role": "user", "content": message["content"]})
            continue
        content_blocks: list[dict[str, Any]] = []
        if message["content"]:
            content_blocks.append({"type": "text", "text": message["content"]})
        content_blocks.extend({
            "type": "tool_use",
            "id": call["id"],
            "name": call["name"],
            "input": dict(call["arguments"]),
        } for call in message["tool_calls"])
        result.append({"role": "assistant", "content": content_blocks})
    flush_results()
    return result


class _ProviderTotalRequestTimeout(RuntimeError):
    """Internal signal used to interrupt a blocking provider response read."""


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    base_url: str
    auth_token: str = field(repr=False)
    model: str
    wire_protocol: str = ""
    adapter_capabilities: tuple[str, ...] = ()
    allowed_endpoint_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderCompletion:
    """Provider text plus non-secret authenticity metadata for one request."""

    text: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ProviderToolCall:
    """One protocol-neutral model request to execute a tool."""

    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ProviderToolTurn:
    """One assistant turn that may contain text and any number of tool calls."""

    text: str
    tool_calls: tuple[ProviderToolCall, ...]
    stop_reason: str | None
    metadata: dict[str, Any]


class ScriptedMockToolClient:
    """Offline deterministic tool-turn provider for tests and rehearsals."""

    SCHEMA = "SITINA_MOCK_TOOL_SCRIPT_V1"

    def __init__(self, turns: Sequence[ProviderToolTurn]):
        self.turns = list(turns)
        self.received_messages: list[list[dict[str, Any]]] = []

    @classmethod
    def load(cls, path: Path) -> "ScriptedMockToolClient":
        raw = load_json_yaml(Path(path))
        if not isinstance(raw, dict) or raw.get("schema") != cls.SCHEMA:
            raise ProviderMalformedResponse(f"mock tool script must use schema {cls.SCHEMA}")
        raw_turns = raw.get("turns")
        if not isinstance(raw_turns, list) or not raw_turns:
            raise ProviderMalformedResponse("mock tool script requires at least one turn")
        turns: list[ProviderToolTurn] = []
        for turn_index, raw_turn in enumerate(raw_turns, start=1):
            if not isinstance(raw_turn, dict):
                raise ProviderMalformedResponse("mock tool turns must be objects")
            calls: list[ProviderToolCall] = []
            raw_calls = raw_turn.get("tool_calls", [])
            if not isinstance(raw_calls, list):
                raise ProviderMalformedResponse("mock tool_calls must be an array")
            for call_index, raw_call in enumerate(raw_calls, start=1):
                if not isinstance(raw_call, dict) or not isinstance(raw_call.get("arguments", {}), dict):
                    raise ProviderMalformedResponse("mock tool calls require object arguments")
                name = str(raw_call.get("name") or "").strip()
                if not name:
                    raise ProviderMalformedResponse("mock tool call requires a name")
                calls.append(
                    ProviderToolCall(
                        str(raw_call.get("id") or f"mock-{turn_index}-{call_index}"),
                        name,
                        dict(raw_call.get("arguments") or {}),
                    )
                )
            turns.append(
                ProviderToolTurn(
                    str(raw_turn.get("text") or ""),
                    tuple(calls),
                    str(raw_turn.get("stop_reason") or ("tool_calls" if calls else "stop")),
                    {"protocol": "mock", "script_turn": turn_index, "physical_send_count": 0},
                )
            )
        return cls(turns)

    @staticmethod
    def load_profile(_profile_name: str) -> ProviderProfile:
        return ProviderProfile("mock", "mock://offline", "", "scripted-mock")

    def complete_tool_turn(
        self,
        _profile: ProviderProfile,
        *,
        messages: Sequence[Mapping[str, Any]],
        **_kwargs: Any,
    ) -> ProviderToolTurn:
        self.received_messages.append([dict(item) for item in messages])
        if not self.turns:
            raise ProviderMalformedResponse("mock tool script ended before the model returned a final turn")
        return self.turns.pop(0)


def provider_identity_summary(profile: ProviderProfile | None, *, provider_mode: str, profile_name: str | None = None) -> dict[str, Any]:
    """Return an audit-safe provider identity summary without credentials."""

    name = profile.name if profile else profile_name
    host = urlparse(profile.base_url).netloc if profile and profile.base_url else None
    return {
        "provider_mode": provider_mode,
        "provider": name or provider_mode,
        "profile_name": name,
        "model": redact_text(profile.model)[:200] if profile and profile.model else None,
        "base_url_host": host,
        "redaction_status": "redacted",
    }


class RoleProfileResolver:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home

    def roles(self) -> dict[str, str]:
        path = self.home / "config" / "roles.env"
        roles: dict[str, str] = {}
        if not path.exists():
            return roles
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            key = key.removeprefix("export ").strip()
            value = value.strip().strip("'\"")
            if key.startswith("SITINA_ROLE_") and key.endswith("_PROFILE"):
                role = key.removeprefix("SITINA_ROLE_").removesuffix("_PROFILE").lower()
                roles[role] = value
        return roles

    def profile_name_for_agent(self, agent: str) -> str:
        roles = self.roles()
        configured = self.provider_config().get("default_profile")
        return roles.get(agent, roles.get("default", str(configured or "configured-provider")))

    def provider_config(self) -> dict[str, Any]:
        path = self.home / "config" / "sitina.yaml"
        if not path.exists():
            return {}
        try:
            config = load_json_yaml(path)
        except Exception:
            return {}
        return dict(config.get("providers", {}))

    def fallback_profiles(self) -> list[str]:
        return list(self.provider_config().get("fallback_profiles", []))

    def fallback_profiles_for_agent(self, agent: str) -> list[str]:
        provider_config = self.provider_config()
        by_agent = provider_config.get("fallback_profiles_by_agent", {})
        if isinstance(by_agent, dict) and agent in by_agent:
            return list(by_agent.get(agent) or [])
        return self.fallback_profiles()

    def profile_candidates_for_agent(
        self,
        agent: str,
        override: str | None = None,
        *,
        fallback_allowed: bool = True,
        health: "ProviderHealthRegistry | None" = None,
    ) -> list[str]:
        primary = override or self.profile_name_for_agent(agent)
        candidates = [primary]
        if fallback_allowed:
            for fallback in self.fallback_profiles_for_agent(agent):
                if fallback not in candidates:
                    candidates.append(fallback)
        return health.order_candidates(candidates) if health else candidates


class ProviderHealthRegistry:
    """Provider health derived from Journal events in protected B+ environments.

    The SQLite adapter remains only for explicit, unprotected Legacy fixtures.
    It is never constructed on the Production/clean-acceptance path.
    """

    def __init__(
        self,
        home: Path = SITINA_HOME,
        store: SitinaStore | None = None,
        *,
        journal_events: Callable[[], Sequence[Any]] | None = None,
        journal_append: Callable[[Mapping[str, Any]], Any] | None = None,
    ):
        self.home = Path(home)
        policy = LegacyRuntimePolicy.load(self.home)
        self._journal_native = journal_events is not None or journal_append is not None or policy.fully_disabled
        if self._journal_native and store is not None:
            raise ProviderError("Legacy Provider Health store is forbidden in Journal-native mode")
        self.store = None if self._journal_native else (store or SitinaStore(self.home))
        self._journal_events = journal_events or self._default_journal_events
        self._journal_append = journal_append or self._default_journal_append

    def _journal_trust_root_installed(self) -> bool:
        """True when a durable Journal trust root exists for this home.

        Provider health lives in the Journal, so without a trust root there is
        no recorded history to read -- and no way to open one.
        """
        if (self.home / "state/bplus-production-genesis/genesis.json").is_file():
            return True
        root = self.home.expanduser().resolve(strict=False)
        return root not in {canonical_journal_native_home(), LEGACY_PRODUCTION_HOME} and (
            self.home / "state/clean-acceptance/genesis.json"
        ).is_file()

    def _default_runtime_context(self) -> Any:
        """Resolve this home's Journal runtime context.

        Mirrors the CLI's context selection so Provider health does not assume
        the Production trust root when a clean-acceptance Journal is installed.
        """
        root = self.home.expanduser().resolve(strict=False)
        if root not in {canonical_journal_native_home(), LEGACY_PRODUCTION_HOME} and (
            self.home / "state/clean-acceptance/genesis.json"
        ).is_file():
            from sitina.orchestrator.clean_acceptance import CleanAcceptanceContext

            return CleanAcceptanceContext.load(self.home)
        from sitina.orchestrator.bplus_production import ProductionRuntimeContext

        return ProductionRuntimeContext.load(
            self.home,
            allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
        )

    def _default_journal_events(self) -> Sequence[Any]:
        if not self._journal_trust_root_installed():
            # No trust root means no recorded observations. Reporting an empty
            # history yields an honest "unknown" status instead of failing every
            # Provider command; reads stay strict once a root is installed.
            return ()
        return self._default_runtime_context().events

    def _default_journal_append(self, observation: Mapping[str, Any]) -> int:
        from sitina.commands.model import CommandEnvelope
        from sitina.journal.model import EventEnvelope, canonical_json_bytes

        if not self._journal_trust_root_installed():
            raise ProviderError("Provider health cannot be recorded without a durable Journal trust root")
        context = self._default_runtime_context()
        profile = str(observation["profile"])
        stream_id = f"provider/health/{profile}"
        digest = sha256_text(canonical_json_bytes(dict(observation)).decode("utf-8"))
        with context.open_writer() as journal:
            expected = journal._stream_heads.get(stream_id, 0)
            command = CommandEnvelope(
                "provider-health-" + digest[:40],
                "system",
                stream_id,
                "provider.health.observe",
                "provider-health-registry",
                str(observation["checked_at"]),
                {"observation_hash": digest},
            )
            event = EventEnvelope(
                "provider-health-event-" + digest[:34],
                "provider.health-observed",
                "system",
                stream_id,
                0,
                0,
                str(observation["checked_at"]),
                dict(observation),
            )
            return journal.append(command, expected, [event]).last_position

    @staticmethod
    def _event_payload(event: Any) -> dict[str, Any] | None:
        if isinstance(event, Mapping):
            event_type = event.get("event_type")
            payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else event
        else:
            event_type = getattr(event, "event_type", None)
            payload = getattr(event, "payload", None)
        if event_type != "provider.health-observed" or not isinstance(payload, Mapping):
            return None
        return dict(payload)

    def _journal_status(self, profile: str) -> dict[str, Any] | None:
        latest = None
        for event in self._journal_events():
            payload = self._event_payload(event)
            if payload is not None and payload.get("profile") == profile:
                latest = payload
        return latest

    def _read_row(self, profile: str) -> dict[str, Any] | None:
        if self._journal_native:
            return self._journal_status(profile)
        assert self.store is not None
        return self.store.get_provider_health(profile)

    def _write_row(self, row: Mapping[str, Any], *, source: str) -> None:
        if self._journal_native:
            observation = {
                "schema": "PROVIDER_HEALTH_OBSERVED_V1",
                "event_type": "provider.health-observed",
                "profile": row["profile"],
                "status": row["status"],
                "checked_at": row["checked_at"],
                "next_check_at": row["next_check_at"],
                "failure_count": row["failure_count"],
                "last_error": row["last_error"],
                "model": row["model"],
                "latency_ms": row["latency_ms"],
                "source": source,
            }
            self._journal_append(observation)
            return
        assert self.store is not None
        self.store.upsert_provider_health(dict(row))

    def status(self, profile: str) -> dict[str, Any]:
        row = self._read_row(profile)
        if row:
            row = {key: row.get(key) for key in (
                "profile", "status", "checked_at", "next_check_at", "failure_count",
                "last_error", "model", "latency_ms",
            )}
            row["temporarily_unavailable"] = self._row_temporarily_unavailable(row)
            row["due_for_check"] = self._row_due_for_check(row)
            return row
        return {
            "profile": profile,
            "status": "unknown",
            "checked_at": None,
            "next_check_at": None,
            "failure_count": 0,
            "last_error": None,
            "model": None,
            "latency_ms": None,
            "temporarily_unavailable": False,
            "due_for_check": True,
        }

    def list_status(self, profiles: list[str] | None = None) -> list[dict[str, Any]]:
        profiles = profiles or self.known_profiles()
        return [self.status(profile) for profile in profiles]

    def known_profiles(self) -> list[str]:
        preferred = ["gpt", "openai", "anthropic", "configured-provider"]
        profile_dir = self.home / "profiles"
        found = sorted(p.stem for p in profile_dir.glob("*.env") if not p.name.endswith(".template"))
        out: list[str] = []
        for profile in [*preferred, *found]:
            if profile not in out:
                out.append(profile)
        return out

    def order_candidates(self, candidates: list[str]) -> list[str]:
        unique: list[str] = []
        for candidate in candidates:
            if candidate not in unique:
                unique.append(candidate)
        available = [profile for profile in unique if not self.is_temporarily_unavailable(profile)]
        if not available:
            return []
        return sorted(
            available,
            key=lambda profile: (
                0 if self.status(profile)["status"] == "healthy" else 1,
                unique.index(profile),
            ),
        )

    def is_temporarily_unavailable(self, profile: str) -> bool:
        return self._row_temporarily_unavailable(self._read_row(profile))

    def _row_temporarily_unavailable(self, row: Mapping[str, Any] | None) -> bool:
        if not row or row.get("status") != "unavailable":
            return False
        next_check_at = row.get("next_check_at")
        if not next_check_at:
            return False
        return self._parse_time(next_check_at) > utc_now()

    def is_due_for_check(self, profile: str) -> bool:
        return self._row_due_for_check(self._read_row(profile))

    def _row_due_for_check(self, row: Mapping[str, Any] | None) -> bool:
        if not row:
            return True
        next_check_at = row.get("next_check_at")
        if not next_check_at:
            return True
        return self._parse_time(next_check_at) <= utc_now()

    def mark_healthy(self, profile: str, *, model: str | None = None, latency_ms: int | None = None) -> dict[str, Any]:
        row = {
            "profile": profile,
            "status": "healthy",
            "checked_at": iso_now(),
            "next_check_at": self._future_iso(self.health_check_interval_seconds()),
            "failure_count": 0,
            "last_error": None,
            "model": model,
            "latency_ms": latency_ms,
        }
        self._write_row(row, source="provider-health-registry")
        return row

    def mark_unavailable(self, profile: str, error: str, *, model: str | None = None, latency_ms: int | None = None) -> dict[str, Any]:
        prior = self._read_row(profile) or {}
        row = {
            "profile": profile,
            "status": "unavailable",
            "checked_at": iso_now(),
            "next_check_at": self._future_iso(self.unavailable_ttl_seconds()),
            "failure_count": int(prior.get("failure_count") or 0) + 1,
            "last_error": redact_text(str(error))[:500],
            "model": model or prior.get("model"),
            "latency_ms": latency_ms,
        }
        self._write_row(row, source="provider-health-registry")
        return row

    def check_profiles(self, client: "AnthropicCompatibleClient", profiles: list[str] | None = None, *, max_tokens: int = 64) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for profile in profiles or self.known_profiles():
            started = time.time()
            try:
                smoke = client.smoke(profile, max_tokens=max_tokens)
                latency_ms = int((time.time() - started) * 1000)
                if smoke.get("ok"):
                    row = {
                        "profile": profile,
                        "status": "healthy",
                        "checked_at": iso_now(),
                        "next_check_at": self._future_iso(self.health_check_interval_seconds()),
                        "failure_count": 0,
                        "last_error": None,
                        "model": smoke.get("model"),
                        "latency_ms": latency_ms,
                    }
                    try:
                        self._write_row(row, source="provider-status-check")
                    except Exception as health_error:  # noqa: BLE001
                        results.append({
                            "profile": profile, "check": "ok", **row,
                            "health_persistence_error_type": type(health_error).__name__,
                            "health_persistence_error_hash": sha256_text(str(health_error)),
                        })
                    else:
                        results.append({"profile": profile, "check": "ok", **row})
                else:
                    raise ProviderError("unexpected smoke response")
            except Exception as exc:  # noqa: BLE001
                latency_ms = int((time.time() - started) * 1000)
                prior = self._read_row(profile) or {}
                row = {
                    "profile": profile,
                    "status": "unavailable",
                    "checked_at": iso_now(),
                    "next_check_at": self._future_iso(self.unavailable_ttl_seconds()),
                    "failure_count": int(prior.get("failure_count") or 0) + 1,
                    "last_error": redact_text(str(exc))[:500],
                    "model": prior.get("model"),
                    "latency_ms": latency_ms,
                }
                result = {"profile": profile, "check": "failed", **row, "provider_error": redact_text(str(exc))[:500]}
                try:
                    self._write_row(row, source="provider-status-check")
                except Exception as health_error:  # noqa: BLE001
                    result.update({
                        "health_persistence_error_type": type(health_error).__name__,
                        "health_persistence_error_hash": sha256_text(str(health_error)),
                    })
                results.append(result)
        return results

    def unavailable_ttl_seconds(self) -> int:
        return int(self._provider_config().get("health_unavailable_ttl_seconds", 900))

    def health_check_interval_seconds(self) -> int:
        return int(self._provider_config().get("health_check_interval_seconds", 3600))

    def _provider_config(self) -> dict[str, Any]:
        return RoleProfileResolver(self.home).provider_config()

    def _future_iso(self, seconds: int) -> str:
        return (utc_now() + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def _parse_time(self, value: str) -> dt.datetime:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class AnthropicCompatibleClient:
    def __init__(
        self,
        home: Path = SITINA_HOME,
        timeout_seconds: int | None = None,
        *,
        network_egress_capability: FrozenNetworkEgressCapability | None = None,
    ):
        self.home = home
        self.network_egress_capability = network_egress_capability
        config = RoleProfileResolver(home).provider_config()
        self.timeout_config = ProviderTimeoutConfig.from_config(config)
        # Retained for callers that still inspect the former public attribute.
        self.timeout_seconds = int(timeout_seconds or self.timeout_config.read_timeout)
        self.loader = ProfileLoader(home)
        self.health = ProviderHealthRegistry(home)
        from sitina.effects.legacy_adapters import ShadowEffectBridge
        self.effect_shadow = ShadowEffectBridge.from_environment()

    def effect_shadow_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        from sitina.effects.legacy_adapters import LegacyAdapterKind
        return self.effect_shadow.identity(LegacyAdapterKind.PROVIDER, payload)

    def load_profile(self, profile_name: str) -> ProviderProfile:
        env = self.loader.load_env(profile_name)
        base_url = (
            env.get("SITINA_PROVIDER_BASE_URL")
            or env.get("ANTHROPIC_BASE_URL")
            or env.get("OPENAI_BASE_URL")
            or env.get("DEEPSEEK_BASE_URL")
        )
        auth_token = (
            env.get("SITINA_PROVIDER_AUTH_TOKEN")
            or env.get("ANTHROPIC_AUTH_TOKEN")
            or env.get("OPENAI_API_KEY")
            or env.get("DEEPSEEK_API_KEY")
        )
        model = (
            env.get("SITINA_PROVIDER_MODEL")
            or env.get("ANTHROPIC_MODEL")
            or env.get("OPENAI_MODEL")
            or env.get("DEEPSEEK_MODEL")
        )
        missing = [
            key for key, value in (
                ("SITINA_PROVIDER_BASE_URL", base_url),
                ("SITINA_PROVIDER_AUTH_TOKEN", auth_token),
                ("SITINA_PROVIDER_MODEL", model),
            ) if not value
        ]
        if missing:
            raise ProviderError(f"profile {profile_name} missing {', '.join(missing)}")
        explicit_protocol = (
            env.get("SITINA_PROVIDER_WIRE_PROTOCOL")
            or env.get("WIRE_PROTOCOL")
            or env.get("ANTHROPIC_WIRE_PROTOCOL")
            or env.get("OPENAI_WIRE_PROTOCOL")
        )
        protocol = infer_wire_protocol(profile_name, str(base_url), explicit_protocol)
        raw_hosts = env.get("SITINA_PROVIDER_ALLOWED_ENDPOINT_HOSTS") or env.get("SITINA_PROVIDER_ENDPOINT_HOSTS") or ""
        allowed_hosts = tuple(sorted({item.strip().casefold() for item in raw_hosts.split(",") if item.strip()}))
        raw_capabilities = env.get("SITINA_PROVIDER_ADAPTER_CAPABILITIES") or ""
        capabilities = tuple(sorted({item.strip() for item in raw_capabilities.split(",") if item.strip()}))
        return ProviderProfile(
            name=profile_name,
            base_url=str(base_url).rstrip("/"),
            auth_token=str(auth_token),
            model=str(model),
            wire_protocol=protocol,
            adapter_capabilities=tuple(sorted(provider_adapter_capabilities(profile_name, str(base_url), capabilities))),
            allowed_endpoint_hosts=allowed_hosts,
        )

    def complete(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        request_timeout_seconds: float | None = None,
    ) -> str:
        return self.complete_with_metadata(
            profile,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            request_timeout_seconds=request_timeout_seconds,
        ).text

    def complete_with_metadata(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        request_timeout_seconds: float | None = None,
        expect_json: bool = False,
        json_schema: dict[str, Any] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderCompletion:
        """Perform one real request without provider/profile fallback.

        Endpoint compatibility retry (Anthropic shape to OpenAI shape) is not a
        model fallback and only occurs for explicit unsupported-endpoint errors.
        The result metadata records which protocol was accepted.
        """
        shadow_payload = {
            "profile": profile.name,
            "base_url_host": urlparse(profile.base_url).netloc,
            "model": profile.model,
            "system_prompt_hash": sha256_text(system_prompt),
            "user_prompt_hash": sha256_text(user_prompt),
            "max_tokens": max_tokens,
            "expect_json": expect_json,
        }
        if self.effect_shadow.enabled:
            identity = self.effect_shadow_identity(shadow_payload)
            return ProviderCompletion("", {**identity, "effect_shadow": True, "physical_send_count": 0})
        timeout = min(
            float(request_timeout_seconds or self.timeout_config.total_request_timeout),
            self.timeout_config.total_request_timeout,
        )
        if timeout <= 0:
            raise ProviderDeadlineExceeded("provider request skipped because no request time remains")
        if self._prefers_openai_json(profile):
            try:
                return self._complete_openai(
                    profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=max_tokens,
                    request_timeout_seconds=timeout,
                    expect_json=expect_json,
                    json_schema=json_schema,
                    cancel_check=cancel_check,
                )
            except ProviderHTTPError as exc:
                if json_schema and self._should_try_structured_feature_fallback(exc):
                    return self._complete_openai(
                        profile,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        max_tokens=max_tokens,
                        request_timeout_seconds=timeout,
                        expect_json=True,
                        structured_feature_fallback=True,
                        cancel_check=cancel_check,
                    )
                if not self._should_try_openai_fallback(exc):
                    raise
                return self._complete_anthropic(
                    profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=max_tokens,
                    request_timeout_seconds=timeout,
                    protocol_fallback_used=True,
                    expect_json=True,
                    cancel_check=cancel_check,
                )
        try:
            return self._complete_anthropic(
                profile,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                request_timeout_seconds=timeout,
                expect_json=expect_json,
                json_schema=json_schema,
                cancel_check=cancel_check,
            )
        except ProviderHTTPError as exc:
            if not self._should_try_openai_fallback(exc):
                raise
            return self._complete_openai(
                profile,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                request_timeout_seconds=timeout,
                protocol_fallback_used=True,
                expect_json=expect_json,
                json_schema=json_schema,
                cancel_check=cancel_check,
            )

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
    ) -> ProviderToolTurn:
        """Perform one native tool-use turn using Anthropic or OpenAI wire shapes.

        ``messages`` and ``tools`` use Sitina's protocol-neutral representation.
        This method deliberately performs only one model turn; the autonomous
        runtime owns the unbounded multi-turn loop and executes returned calls.
        """

        shadow_payload = {
            "profile": profile.name,
            "base_url_host": urlparse(profile.base_url).netloc,
            "model": profile.model,
            "system_prompt_hash": sha256_text(system_prompt),
            "messages_hash": sha256_text(stable_json(list(messages))),
            "tools_hash": sha256_text(stable_json(list(tools))),
            "max_tokens": max_tokens,
        }
        if self.effect_shadow.enabled:
            identity = self.effect_shadow_identity(shadow_payload)
            return ProviderToolTurn("", (), "effect_shadow", {**identity, "effect_shadow": True, "physical_send_count": 0})
        timeout = min(
            float(request_timeout_seconds or self.timeout_config.total_request_timeout),
            self.timeout_config.total_request_timeout,
        )
        if timeout <= 0:
            raise ProviderDeadlineExceeded("provider request skipped because no request time remains")
        if self._prefers_openai_json(profile):
            return self._tool_turn_openai(
                profile,
                system_prompt=system_prompt,
                messages=messages,
                tools=tools,
                max_tokens=max_tokens,
                request_timeout_seconds=timeout,
                cancel_check=cancel_check,
            )
        try:
            return self._tool_turn_anthropic(
                profile,
                system_prompt=system_prompt,
                messages=messages,
                tools=tools,
                max_tokens=max_tokens,
                request_timeout_seconds=timeout,
                cancel_check=cancel_check,
            )
        except ProviderHTTPError as exc:
            if not self._should_try_openai_fallback(exc):
                raise
            return self._tool_turn_openai(
                profile,
                system_prompt=system_prompt,
                messages=messages,
                tools=tools,
                max_tokens=max_tokens,
                request_timeout_seconds=timeout,
                protocol_fallback_used=True,
                cancel_check=cancel_check,
            )

    def _tool_turn_anthropic(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderToolTurn:
        body: dict[str, Any] = {
            "model": profile.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": provider_messages_for_wire(messages, ANTHROPIC_MESSAGES),
            "tools": provider_tools_for_wire(tools, ANTHROPIC_MESSAGES),
        }
        payload, metadata = self._request_json(
            self._messages_url(profile.base_url),
            body,
            {
                "content-type": "application/json",
                "accept": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": profile.auth_token,
                "authorization": f"Bearer {profile.auth_token}",
            },
            profile=profile,
            protocol="anthropic_messages",
            request_timeout_seconds=request_timeout_seconds,
            protocol_fallback_used=protocol_fallback_used,
            cancel_check=cancel_check,
        )
        text_parts: list[str] = []
        calls: list[ProviderToolCall] = []
        content = payload.get("content")
        if not isinstance(content, list):
            raise ProviderMalformedResponse("Anthropic tool response content must be an array")
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                text_parts.append(str(item["text"]))
            elif item.get("type") == "tool_use":
                raw_arguments = item.get("input", {})
                if not isinstance(raw_arguments, dict):
                    raise ProviderMalformedResponse("Anthropic tool_use input must be an object")
                call_id = str(item.get("id") or "").strip()
                name = str(item.get("name") or "").strip()
                if not call_id or not name:
                    raise ProviderMalformedResponse("Anthropic tool_use requires id and name")
                calls.append(ProviderToolCall(call_id, name, dict(raw_arguments)))
        text = "".join(text_parts).strip()
        return ProviderToolTurn(
            text,
            tuple(calls),
            str(payload.get("stop_reason")) if payload.get("stop_reason") is not None else None,
            metadata
            | {
                "output_hash": sha256_text(text),
                "token_usage": token_usage_summary(payload),
                "tool_call_count": len(calls),
            },
        )

    def _tool_turn_openai(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderToolTurn:
        body: dict[str, Any] = {
            "model": profile.model,
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": system_prompt},
                *provider_messages_for_wire(messages, OPENAI_CHAT_COMPLETIONS),
            ],
            "tools": provider_tools_for_wire(tools, OPENAI_CHAT_COMPLETIONS),
        }
        payload, metadata = self._request_json(
            self._chat_completions_url(profile.base_url),
            body,
            {
                "content-type": "application/json",
                "accept": "application/json",
                "authorization": f"Bearer {profile.auth_token}",
            },
            profile=profile,
            protocol="openai_chat_completions",
            request_timeout_seconds=request_timeout_seconds,
            protocol_fallback_used=protocol_fallback_used,
            cancel_check=cancel_check,
        )
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderMalformedResponse("OpenAI tool response choices must contain a message")
        first = choices[0]
        message = first.get("message")
        if not isinstance(message, dict):
            raise ProviderMalformedResponse("OpenAI tool response did not contain a message")
        text = str(message.get("content") or "").strip()
        calls: list[ProviderToolCall] = []
        raw_calls = message.get("tool_calls") or []
        if not isinstance(raw_calls, list):
            raise ProviderMalformedResponse("OpenAI tool_calls must be an array")
        for item in raw_calls:
            function = item.get("function") if isinstance(item, dict) else None
            if not isinstance(function, dict):
                raise ProviderMalformedResponse("OpenAI tool call function must be an object")
            raw_arguments = function.get("arguments", "{}")
            if isinstance(raw_arguments, str):
                try:
                    arguments = json.loads(raw_arguments or "{}")
                except json.JSONDecodeError as exc:
                    raise ProviderMalformedResponse(f"OpenAI tool arguments are not valid JSON: {exc}") from exc
            else:
                arguments = raw_arguments
            if not isinstance(arguments, dict):
                raise ProviderMalformedResponse("OpenAI tool arguments must be an object")
            call_id = str(item.get("id") or "").strip()
            name = str(function.get("name") or "").strip()
            if not call_id or not name:
                raise ProviderMalformedResponse("OpenAI tool call requires id and function name")
            calls.append(ProviderToolCall(call_id, name, dict(arguments)))
        return ProviderToolTurn(
            text,
            tuple(calls),
            str(first.get("finish_reason")) if first.get("finish_reason") is not None else None,
            metadata
            | {
                "output_hash": sha256_text(text),
                "token_usage": token_usage_summary(payload),
                "tool_call_count": len(calls),
            },
        )

    def is_retryable_profile_error(self, exc: ProviderError) -> bool:
        if not isinstance(exc, ProviderHTTPError):
            return False
        text = str(exc).lower()
        if exc.status_code == 403 and any(marker in text for marker in ("cloudflare", "browser_signature", "error 1010", "access denied")):
            return True
        path = self.home / "config" / "sitina.yaml"
        statuses = [429, 500, 502, 503, 504]
        if path.exists():
            try:
                config = load_json_yaml(path)
                statuses = list(config.get("providers", {}).get("fallback_on_http_status", statuses))
            except Exception:
                pass
        return exc.status_code in statuses

    def smoke(self, profile_name: str, *, max_tokens: int = 128) -> dict[str, Any]:
        profile = self.load_profile(profile_name)
        text = self.complete(
            profile,
            system_prompt="Return a tiny plain-text provider smoke response.",
            user_prompt="Reply with exactly: SITINA_PROVIDER_SMOKE_OK",
            max_tokens=max_tokens,
        )
        return {"profile": profile.name, "model": profile.model, "ok": "SITINA_PROVIDER_SMOKE_OK" in text, "text_preview": redact_text(text)[:120]}

    def _complete_anthropic(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
        expect_json: bool = False,
        json_schema: dict[str, Any] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderCompletion:
        url = self._messages_url(profile.base_url)
        body = {
            "model": profile.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        payload, metadata = self._request_json(
            url,
            body,
            {
                "content-type": "application/json",
                "accept": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": profile.auth_token,
                "authorization": f"Bearer {profile.auth_token}",
            },
            profile=profile,
            protocol="anthropic_messages",
            request_timeout_seconds=request_timeout_seconds,
            protocol_fallback_used=protocol_fallback_used,
            cancel_check=cancel_check,
        )
        text = self._extract_text(payload)
        return ProviderCompletion(
            text=text,
            metadata=metadata | {
                "output_hash": sha256_text(text),
                "token_usage": token_usage_summary(payload),
                "structured_output_requested": expect_json,
                "structured_output_enforced": False,
            },
        )

    def _complete_openai(
        self,
        profile: ProviderProfile,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
        expect_json: bool = False,
        json_schema: dict[str, Any] | None = None,
        structured_feature_fallback: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ProviderCompletion:
        openai_json_object = bool(expect_json and not json_schema)
        openai_strict_tool = bool(json_schema)
        thinking_disabled = "deepseek_thinking_disabled" in provider_adapter_capabilities(
            profile.name, profile.base_url, profile.adapter_capabilities
        )
        url = self._chat_completions_url(profile.base_url)
        schema_instruction = (
            "\nReturn the response only through the required output tool. Do not include comments, analysis, markdown, or a second object. "
            "The tool arguments object must directly contain the schema properties; never wrap it in an extra arguments, input, or payload object. "
            "For nullable fields, JSON null is the unquoted token null; never return the string \"null\"."
            if openai_strict_tool
            else ""
        )
        body = {
            "model": profile.model,
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": system_prompt + schema_instruction},
                {"role": "user", "content": user_prompt},
            ],
        }
        if thinking_disabled and (openai_json_object or openai_strict_tool):
            body["thinking"] = {"type": "disabled"}
        if json_schema:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": "sitina_structured_response",
                        "description": "Return the complete Sitina agent response directly as these schema-valid function arguments. Do not add an arguments wrapper. This tool is output-only and must not be executed.",
                        "parameters": json_schema,
                        **({"strict": True} if openai_strict_tool else {}),
                    },
                }
            ]
            body["tool_choice"] = {"type": "function", "function": {"name": "sitina_structured_response"}}
        elif expect_json:
            body["response_format"] = {"type": "json_object"}
        payload, metadata = self._request_json(
            url,
            body,
            {
                "content-type": "application/json",
                "accept": "application/json",
                "authorization": f"Bearer {profile.auth_token}",
            },
            profile=profile,
            protocol="openai_chat_completions",
            request_timeout_seconds=request_timeout_seconds,
            protocol_fallback_used=protocol_fallback_used,
            cancel_check=cancel_check,
        )
        text = self._extract_text(payload)
        return ProviderCompletion(
            text=text,
            metadata=metadata | {
                "output_hash": sha256_text(text),
                "token_usage": token_usage_summary(payload),
                "structured_output_requested": expect_json,
                "structured_output_enforced": expect_json,
                "structured_output_method": "strict_tool_call" if openai_strict_tool else ("json_object" if expect_json else "none"),
                "structured_schema_strict": openai_strict_tool,
                "thinking_mode": "disabled" if thinking_disabled and (openai_json_object or openai_strict_tool) else "default",
                "runtime_schema_validation_required": bool(json_schema),
                "structured_feature_fallback": structured_feature_fallback,
            },
        )

    @staticmethod
    def _should_try_structured_feature_fallback(exc: ProviderHTTPError) -> bool:
        text = str(exc).lower()
        return exc.status_code in {400, 404, 405} and any(marker in text for marker in ("tool", "function", "unsupported", "parameter"))

    @staticmethod
    def _prefers_openai_json(profile: ProviderProfile) -> bool:
        """Select the OpenAI-compatible adapter from the fixed profile."""

        return infer_wire_protocol(profile.name, profile.base_url, profile.wire_protocol) == OPENAI_CHAT_COMPLETIONS

    def _request_json(
        self,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
        *,
        profile: ProviderProfile,
        protocol: str,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if cancel_check and cancel_check():
            raise ProviderCancelledError("provider request cancelled before start")
        # Frozen network capabilities are intentionally process-local. Keep
        # their one concrete connection in the issuing process, where the
        # direct path still enforces connect/read/total timeouts.
        if os.name != "posix" or self.network_egress_capability is not None:
            return self._request_json_direct(
                url, body, headers, profile=profile, protocol=protocol,
                request_timeout_seconds=request_timeout_seconds,
                protocol_fallback_used=protocol_fallback_used,
            )
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_provider_request_worker,
            args=(
                sender, str(self.home), self.timeout_config, url, body, headers, profile,
                protocol, request_timeout_seconds, protocol_fallback_used,
                self.network_egress_capability,
            ),
        )
        process.daemon = True
        process.start()
        sender.close()
        try:
            expires_at = time.monotonic() + request_timeout_seconds
            while True:
                remaining = expires_at - time.monotonic()
                if remaining <= 0:
                    process.terminate()
                    process.join(timeout=1)
                    raise ProviderReadTimeout("provider total request timeout")
                if receiver.poll(min(0.05, remaining)):
                    try:
                        result = receiver.recv()
                    except EOFError as exc:
                        process.join(timeout=1)
                        raise ProviderError(
                            "provider worker exited without a result "
                            f"(exit_code={process.exitcode})"
                        ) from exc
                    break
                if cancel_check and cancel_check():
                    process.terminate()
                    process.join(timeout=1)
                    raise ProviderCancelledError("provider request cancelled while in flight")
        finally:
            receiver.close()
            if process.is_alive():
                process.join(timeout=1)
                if process.is_alive():
                    process.terminate()
            process.join(timeout=1)
        if result[0] == "ok":
            return result[1], result[2]
        _raise_worker_error(result[1], result[2], result[3])
        raise AssertionError("unreachable")

    def _request_json_direct(
        self,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
        *,
        profile: ProviderProfile,
        protocol: str,
        request_timeout_seconds: float,
        protocol_fallback_used: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ProviderError("provider base URL must be an absolute http(s) URL")
        request_id = "provider_" + uuid.uuid4().hex
        started_at = iso_now()
        started_monotonic = time.monotonic()
        connect_timeout = min(self.timeout_config.connect_timeout, request_timeout_seconds)
        read_timeout = min(self.timeout_config.read_timeout, request_timeout_seconds)
        body_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_class(parsed.hostname, parsed.port, timeout=connect_timeout)
        request_expired = threading.Event()
        signal_timeout_enabled = False
        previous_alarm_handler: Any = None
        previous_alarm_timer: tuple[float, float] | None = None

        def abort_for_total_timeout() -> None:
            request_expired.set()
            sock = connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
            connection.close()

        total_timeout = threading.Timer(request_timeout_seconds, abort_for_total_timeout)
        total_timeout.daemon = True
        total_timeout.start()
        if threading.current_thread() is threading.main_thread():
            try:
                previous_alarm_handler = signal.getsignal(signal.SIGALRM)
                previous_alarm_timer = signal.getitimer(signal.ITIMER_REAL)

                def raise_total_timeout(_signum: int, _frame: Any) -> None:
                    request_expired.set()
                    raise _ProviderTotalRequestTimeout("provider total request timeout")

                signal.signal(signal.SIGALRM, raise_total_timeout)
                signal.setitimer(signal.ITIMER_REAL, request_timeout_seconds)
                signal_timeout_enabled = True
            except (AttributeError, OSError, ValueError):
                # The socket-closing timer remains the fallback where signals
                # are unavailable in the embedding process.
                signal_timeout_enabled = False
        try:
            try:
                with authorized_frozen_network_egress(
                    self.network_egress_capability,
                    host=parsed.hostname,
                    operation="model_text_generation",
                ):
                    connection.connect()
            except _ProviderTotalRequestTimeout as exc:
                raise ProviderConnectTimeout("provider total request timeout during connect") from exc
            except socket.timeout as exc:
                if request_expired.is_set():
                    raise ProviderConnectTimeout("provider total request timeout during connect") from exc
                raise ProviderConnectTimeout("provider connect timeout") from exc
            except OSError as exc:
                if request_expired.is_set():
                    raise ProviderConnectTimeout("provider total request timeout during connect") from exc
                raise ProviderError(f"provider connect failed: {redact_text(str(exc))[:300]}") from exc
            if request_expired.is_set():
                raise ProviderConnectTimeout("provider total request timeout during connect")
            if connection.sock:
                connection.sock.settimeout(read_timeout)
            try:
                connection.request("POST", path, body=body_bytes, headers=headers)
                response = connection.getresponse()
                response_bytes = response.read()
            except _ProviderTotalRequestTimeout as exc:
                raise ProviderReadTimeout("provider total request timeout") from exc
            except socket.timeout as exc:
                if request_expired.is_set():
                    raise ProviderReadTimeout("provider total request timeout") from exc
                raise ProviderReadTimeout("provider read timeout") from exc
            except OSError as exc:
                if request_expired.is_set():
                    raise ProviderReadTimeout("provider total request timeout") from exc
                raise ProviderError(f"provider request failed: {redact_text(str(exc))[:300]}") from exc
            if request_expired.is_set():
                raise ProviderReadTimeout("provider total request timeout")
            status = int(response.status)
            response_headers = {str(key).lower(): str(value) for key, value in response.getheaders()}
            if status < 200 or status >= 300:
                retry_after = self._retry_after_seconds(response_headers.get("retry-after"))
                message = f"provider HTTP {status}: {redact_text(response_bytes.decode('utf-8', errors='replace'))[:500]}"
                if status == 401:
                    raise ProviderAuthError(status, message, retry_after_seconds=retry_after)
                if status == 403:
                    raise ProviderPermissionError(status, message, retry_after_seconds=retry_after)
                if status == 429:
                    raise ProviderRateLimitError(status, message, retry_after_seconds=retry_after)
                raise ProviderHTTPError(status, message, retry_after_seconds=retry_after)
            try:
                payload = json.loads(response_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProviderMalformedResponse(f"provider response JSON parse failed: {exc}") from exc
            if not isinstance(payload, dict):
                raise ProviderMalformedResponse("provider response must be a JSON object")
            completed_at = iso_now()
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            metadata = {
                "provider_request_id": response_headers.get("x-request-id") or response_headers.get("request-id") or request_id,
                "provider_call_started_at": started_at,
                "provider_call_completed_at": completed_at,
                "duration_ms": duration_ms,
                "protocol": protocol,
                "protocol_fallback_used": protocol_fallback_used,
                "fallback_used": False,
                "connect_timeout_seconds": connect_timeout,
                "read_timeout_seconds": read_timeout,
                "request_timeout_seconds": request_timeout_seconds,
                "input_hash": sha256_text(stable_json({"system": system_redacted_hash_input(body.get("system")), "messages": system_redacted_hash_input(body.get("messages"))})),
                "redaction_status": "redacted",
                "provider_mode": "live",
                "profile_name": profile.name,
                "model": redact_text(profile.model)[:200],
            }
            return payload, metadata
        finally:
            if signal_timeout_enabled:
                signal.setitimer(signal.ITIMER_REAL, *(previous_alarm_timer or (0.0, 0.0)))
                signal.signal(signal.SIGALRM, previous_alarm_handler)
            total_timeout.cancel()
            connection.close()

    def _retry_after_seconds(self, value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            return None

    def _messages_url(self, base_url: str) -> str:
        if base_url.endswith("/messages"):
            return base_url
        if base_url.endswith("/v1"):
            return f"{base_url}/messages"
        return f"{base_url}/v1/messages"

    def _chat_completions_url(self, base_url: str) -> str:
        parsed = urlsplit(base_url)
        if parsed.hostname in {"api.deepseek.com", "api.deepseek.com.cn"} and parsed.path.rstrip("/") == "/anthropic":
            return urlunsplit((parsed.scheme, parsed.netloc, "/v1/chat/completions", "", ""))
        if base_url.endswith("/chat/completions"):
            return base_url
        if base_url.endswith("/v1"):
            return f"{base_url}/chat/completions"
        return f"{base_url}/v1/chat/completions"

    def _should_try_openai_fallback(self, exc: ProviderHTTPError) -> bool:
        text = str(exc).lower()
        if exc.status_code in {404, 405}:
            return True
        if exc.status_code == 400 and any(marker in text for marker in ("not found", "unsupported", "unknown url", "invalid endpoint", "messages")):
            return True
        return False

    def _extract_text(self, payload: dict[str, Any]) -> str:
        if isinstance(payload.get("content"), list):
            parts = [item.get("text", "") for item in payload["content"] if isinstance(item, dict)]
            text = "".join(parts).strip()
            if text:
                return text
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message", {})
                if isinstance(message, dict):
                    tool_calls = message.get("tool_calls")
                    if isinstance(tool_calls, list):
                        for tool_call in tool_calls:
                            function = tool_call.get("function") if isinstance(tool_call, dict) else None
                            arguments = function.get("arguments") if isinstance(function, dict) else None
                            if isinstance(arguments, str) and arguments.strip():
                                return arguments
                    if isinstance(message.get("content"), str):
                        return message["content"]
                if isinstance(first.get("text"), str):
                    return first["text"]
        if isinstance(payload.get("text"), str):
            return payload["text"]
        raise ProviderMalformedResponse("provider response did not contain text content")

def _provider_request_worker(
    sender: Any,
    home: str,
    timeout_config: ProviderTimeoutConfig,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    profile: ProviderProfile,
    protocol: str,
    request_timeout_seconds: float,
    protocol_fallback_used: bool,
    network_egress_capability: FrozenNetworkEgressCapability | None,
) -> None:
    try:
        client = AnthropicCompatibleClient(
            Path(home), network_egress_capability=network_egress_capability
        )
        client.timeout_config = timeout_config
        payload, metadata = client._request_json_direct(
            url,
            body,
            headers,
            profile=profile,
            protocol=protocol,
            request_timeout_seconds=request_timeout_seconds,
            protocol_fallback_used=protocol_fallback_used,
        )
        sender.send(("ok", payload, metadata))
    except ProviderHTTPError as exc:
        sender.send(("error", exc.error_type, redact_text(str(exc))[:500], {"status_code": exc.status_code, "retry_after_seconds": exc.retry_after_seconds}))
    except ProviderError as exc:
        sender.send(("error", exc.error_type, redact_text(str(exc))[:500], {}))
    except Exception as exc:  # noqa: BLE001
        sender.send(("error", "provider_error", redact_text(str(exc))[:500], {}))
    finally:
        sender.close()


def _raise_worker_error(error_type: str, message: str, details: dict[str, Any]) -> None:
    if error_type == "provider_connect_timeout":
        raise ProviderConnectTimeout(message)
    if error_type == "provider_read_timeout":
        raise ProviderReadTimeout(message)
    if error_type == "run_deadline_exceeded":
        raise ProviderDeadlineExceeded(message)
    if error_type == "provider_auth_failed":
        raise ProviderAuthError(int(details.get("status_code") or 401), message, retry_after_seconds=details.get("retry_after_seconds"))
    if error_type == "provider_permission_denied":
        raise ProviderPermissionError(int(details.get("status_code") or 403), message, retry_after_seconds=details.get("retry_after_seconds"))
    if error_type == "provider_rate_limited":
        raise ProviderRateLimitError(int(details.get("status_code") or 429), message, retry_after_seconds=details.get("retry_after_seconds"))
    if error_type == "provider_parse_failed":
        raise ProviderMalformedResponse(message)
    if "status_code" in details:
        raise ProviderHTTPError(int(details["status_code"]), message, retry_after_seconds=details.get("retry_after_seconds"))
    raise ProviderError(message)


def system_redacted_hash_input(value: Any) -> Any:
    """Keep request hashes tied to sent content without persisting secret text."""

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(key): system_redacted_hash_input(item) for key, item in value.items()}
    if isinstance(value, list):
        return [system_redacted_hash_input(item) for item in value]
    return value


def token_usage_summary(payload: dict[str, Any]) -> dict[str, int] | None:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens"),
        "output_tokens": ("output_tokens", "completion_tokens"),
        "total_tokens": ("total_tokens",),
        "cache_read_tokens": ("cache_read_input_tokens", "prompt_cache_hit_tokens"),
        "cache_write_tokens": ("cache_creation_input_tokens", "prompt_cache_miss_tokens"),
    }
    summary: dict[str, int] = {}
    for target, source_names in aliases.items():
        for source_name in source_names:
            value = usage.get(source_name)
            if isinstance(value, int) and value >= 0:
                summary[target] = value
                break
    return summary or None
