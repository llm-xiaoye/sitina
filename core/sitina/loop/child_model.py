from __future__ import annotations

import base64
import json
import math
import shutil
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sitina.extensions.runtime import BoundedToolTurnClient
from sitina.legacy.fence import _native_network_binding, issue_frozen_network_egress_capability
from sitina.runners.provider import AnthropicCompatibleClient, ProviderHTTPError, ProviderProfile, ProviderToolTurn

from .delegation import ReadonlyChildCapability, ReadonlyChildError, ReadonlySourceDenied
from .context_window import (
    ModelCapacityRegistry,
    ProviderContextIdentity,
    ProviderRequestPlanner,
    render_provider_tool_request,
)
from sitina.runners.provider import infer_wire_protocol


class ReadonlyChildModelRunner:
    """Bounded Provider-backed model protocol for one readonly child.

    The runner owns only a Provider client/profile and the restricted child
    capability. It never receives a Backend or general ToolCatalog. Tests may
    inject a ``ScriptedMockToolClient``-compatible client. Live use requires
    an already-authorized Provider client; readonly source scope alone does
    not authorize an account or network access.
    """

    TOOL_SCHEMA = (
        {
            "name": "sitina_child_read_source",
            "description": "Read bytes/text from one declared immutable source.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 65536},
                },
                "required": ["source_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "sitina_child_report",
            "description": "Report a sourced readonly investigation result to the parent.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "evidence_source_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["summary", "evidence_source_ids"],
                "additionalProperties": False,
            },
        },
    )

    def __init__(
        self,
        client: Any,
        profile: ProviderProfile,
        *,
        max_tokens: int | None = None,
        max_turns: int | None = None,
        total_token_budget: int | None = None,
        progress_timeout_seconds: float = 600.0,
        capacity_registry: ModelCapacityRegistry | None = None,
        capacity_identity: ProviderContextIdentity | None = None,
        thinking_mode: str = "provider_default",
        reasoning_effort: str = "high",
    ) -> None:
        if not hasattr(client, "complete_tool_turn"):
            raise TypeError("readonly child Provider client lacks complete_tool_turn")
        for name, value in (("max_tokens", max_tokens), ("max_turns", max_turns),
                            ("total_token_budget", total_token_budget)):
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError(f"readonly child {name} must be positive or unspecified")
        if (type(progress_timeout_seconds) not in (int, float)
                or not math.isfinite(progress_timeout_seconds) or progress_timeout_seconds <= 0):
            raise ValueError("readonly child progress timeout must be finite and positive")
        policy = (capacity_registry.resolve(capacity_identity)
                  if capacity_registry is not None and capacity_identity is not None else None)
        if policy is None and max_tokens is None:
            raise ValueError("readonly child output allocation requires an exact model capacity")
        if isinstance(client, BoundedToolTurnClient) and (
                client.retry_limit != 0 or client.fallback_allowed):
            raise ValueError("readonly child requires a single-attempt transport with no fallback")
        self.client = client
        self.profile = profile
        self.user_max_output_tokens = max_tokens
        self.max_tokens = min(max_tokens, policy.max_output_tokens) if (
            max_tokens is not None and policy is not None) else (
                max_tokens if max_tokens is not None else policy.max_output_tokens)
        self.max_turns = max_turns
        self.total_token_budget = total_token_budget
        self.progress_timeout_seconds = float(progress_timeout_seconds)
        self._monotonic = time.monotonic
        self.capacity_registry = capacity_registry
        self.capacity_identity = capacity_identity
        self.thinking_mode = thinking_mode
        self.reasoning_effort = reasoning_effort

    @classmethod
    def from_provider_home(
        cls,
        provider_home: str | Path,
        profile_name: str,
        *,
        client: Any | None = None,
        max_tokens: int | None = None,
        max_turns: int | None = None,
        total_token_budget: int | None = None,
    ) -> "ReadonlyChildModelRunner":
        if client is None:
            raise ReadonlyChildError("readonly source authority does not authorize Provider access; an authorized client is required")
        base = client
        profile = base.load_profile(profile_name)
        capacity_path = Path(provider_home) / "config" / "loop_context_capacity.json"
        if not capacity_path.is_file():
            raise RuntimeError("readonly child context capacity policy is unavailable")
        try:
            capacity_document = json.loads(capacity_path.read_text(encoding="utf-8"))
            registry = ModelCapacityRegistry.from_mapping(capacity_document)
            identity = ProviderContextIdentity(
                profile.name,
                profile.base_url,
                profile.model,
                infer_wire_protocol(profile.name, profile.base_url, profile.wire_protocol),
            )
            policy = registry.resolve(identity)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError("readonly child context capacity policy is invalid") from error
        if policy is None:
            raise RuntimeError("readonly child profile has no exact context capacity policy")
        if max_tokens is not None:
            if type(max_tokens) is not int or max_tokens < 1:
                raise ValueError("readonly child max_tokens must be positive")
            max_tokens = min(max_tokens, policy.max_output_tokens)
        bounded = (
            client
            if isinstance(client, BoundedToolTurnClient)
            else BoundedToolTurnClient(
                base,
                profile,
                retry_limit=0,
                fallback_allowed=False,
            )
        )
        return cls(
            bounded,
            profile,
            max_tokens=max_tokens,
            max_turns=max_turns,
            total_token_budget=total_token_budget,
            capacity_registry=registry,
            capacity_identity=identity,
            thinking_mode=policy.thinking_mode,
            reasoning_effort=policy.reasoning_effort,
        )

    @classmethod
    def from_boundary(
        cls,
        boundary: Any,
        profile_name: str,
        *,
        backend: Any,
        task_id: str | None = None,
        obligation_id: str | None = None,
        request_id: str | None = None,
        attempt_count: int | None = None,
        candidate_id: str | None = None,
        max_tokens: int | None = None,
        max_turns: int | None = None,
        total_token_budget: int | None = None,
    ) -> "ReadonlyChildModelRunner":
        """Construct a client bound to the live task or persisted obligation."""

        if profile_name != "deepseek":
            raise RuntimeError("T5A readonly child Provider is bound to the configured DeepSeek profile")
        binding = _native_network_binding(
            backend, task_id, obligation_id=obligation_id, request_id=request_id,
            attempt_count=attempt_count, candidate_id=candidate_id,
        )
        if obligation_id is not None and binding["provider_profile"] != profile_name:
            raise ReadonlyChildError("experience Provider differs from its persisted dispatch")
        provider_home = Path(boundary.state_root) / "provider-home"
        config = provider_home / "config"
        profiles = provider_home / "profiles"
        config.mkdir(parents=True, exist_ok=True)
        profiles.mkdir(parents=True, exist_ok=True)
        for source in Path(boundary.config_root).iterdir():
            destination = config / source.name
            if source.is_file() and not source.is_symlink() and (
                not destination.exists() or destination.read_bytes() != source.read_bytes()
            ):
                shutil.copy2(source, destination)
        credentials = tuple(getattr(boundary, "credential_references", ()))
        if not credentials:
            raise RuntimeError("configured DeepSeek credential reference is unavailable")
        destination = profiles / "deepseek.env"
        if destination.exists() or destination.is_symlink():
            if not destination.is_symlink() or destination.resolve(strict=True) != Path(credentials[0]).resolve(strict=True):
                raise ReadonlyChildError("configured Provider credential reference differs")
        else:
            destination.symlink_to(credentials[0])
        base_client = AnthropicCompatibleClient(provider_home)
        metadata = base_client.loader._authorization_metadata(profile_name)
        approved_sources = {
            str(Path(reference).expanduser().resolve(strict=True))
            for reference in credentials
        }
        if metadata["source_path"] not in approved_sources:
            raise ReadonlyChildError("Provider credential reference is outside the installation authorization")
        base_client.network_egress_capability = issue_frozen_network_egress_capability(
            None, manifest_hash=None, operation="model_text_generation",
            allowed_hosts=(metadata["host"],), expires_at=int(time.time()) + 1200,
            provider_name=metadata["provider_name"],
            credential_reference=metadata["credential_reference"],
            _native_backend=backend, _native_task_id=task_id,
            _native_obligation_id=obligation_id, _native_request_id=request_id,
            _native_attempt_count=attempt_count, _native_candidate_id=candidate_id,
        )
        return cls.from_provider_home(
            provider_home,
            profile_name,
            client=base_client,
            max_tokens=max_tokens,
            max_turns=max_turns,
            total_token_budget=total_token_budget,
        )

    @classmethod
    def from_development_boundary(
        cls,
        boundary: Any,
        profile_name: str,
        *,
        backend: Any,
        task_id: str | None = None,
        obligation_id: str | None = None,
        request_id: str | None = None,
        attempt_count: int | None = None,
        candidate_id: str | None = None,
        max_tokens: int | None = None,
        max_turns: int | None = None,
        total_token_budget: int | None = None,
    ) -> "ReadonlyChildModelRunner":
        """Backward-compatible name with the same explicit native authority."""

        return cls.from_boundary(
            boundary,
            profile_name,
            backend=backend,
            task_id=task_id,
            obligation_id=obligation_id,
            request_id=request_id,
            attempt_count=attempt_count,
            candidate_id=candidate_id,
            max_tokens=max_tokens,
            max_turns=max_turns,
            total_token_budget=total_token_budget,
        )

    def __call__(self, capability: ReadonlyChildCapability, objective: str) -> Mapping[str, Any]:
        return self.run(capability, objective)

    def run(
        self,
        capability: ReadonlyChildCapability,
        objective: str,
        *,
        provider_call: Callable[[Callable[[], ProviderToolTurn]], ProviderToolTurn] | None = None,
    ) -> Mapping[str, Any]:
        capability.check_binding()
        if not isinstance(objective, str) or not objective.strip():
            raise ReadonlyChildError("child objective is required")
        sources = capability.list_sources()
        source_by_id = {item["source_id"]: item for item in sources}
        system_prompt = (
            "You are Sitina's readonly child investigator.\n"
            "Use only the two supplied tools and only the declared sources for the objective. "
            "Read the evidence before reporting. Read large sources in relevant bounded segments. "
            "New verified evidence advances the investigation; repeated reads or restating a plan do not. "
            "If a decision was incomplete, provide a complete new legal tool call; never ask to execute a fragment. "
            "Never write, run processes, use network/plugins, delegate, or approve the parent. "
            "Keep reasoning private and return a concise sourced report.\n"
            f"Objective: {objective.strip()}\n"
            f"Declared sources: {json.dumps(sources, ensure_ascii=False, sort_keys=True)}"
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": objective.strip()}]
        coverage: dict[str, list[tuple[int, int]]] = {}
        read_receipts: dict[int, dict[str, Any]] = {}
        controls: list[dict[str, Any]] = []
        usage: dict[str, int | None] = {key: 0 for key in ("input_tokens", "output_tokens", "total_tokens")}
        clock = self._monotonic
        started = last_progress = clock()
        progress_bytes = 0
        provider_turn_count = 0
        budget_charge = 0
        recovery_output_floor = 0
        pending_recovery: dict[str, Any] | None = None
        incomplete_seen = False

        def absorb_usage(metadata: Mapping[str, Any]) -> None:
            reported = metadata.get("token_usage")
            for key, previous in tuple(usage.items()):
                value = reported.get(key) if isinstance(reported, Mapping) else None
                usage[key] = (previous + value if type(previous) is int
                              and type(value) is int and value >= 0 else None)

        while True:
            capability.check_binding()
            now = clock()
            if now - last_progress >= self.progress_timeout_seconds:
                raise ReadonlyChildError("child has no verified evidence progress within the allowed idle interval")
            if self.max_turns is not None and provider_turn_count >= self.max_turns:
                raise ReadonlyChildError("child reached the explicitly supplied turn budget")
            operation = "sourced_report" if progress_bytes else "read_declared_sources"
            # The wire envelope and evidence volume determine the starting
            # allowance; an observed length stop can raise it, within capacity.
            decision_shape = (
                {"summary": objective, "evidence_source_ids": sorted(coverage)}
                if progress_bytes else
                [{"source_id": item["source_id"], "offset": 0, "max_bytes": 65536} for item in sources]
            )
            decision_bytes = len(json.dumps(decision_shape, ensure_ascii=False).encode("utf-8"))
            requested_output = max(256 + decision_bytes + progress_bytes, recovery_output_floor)
            allocated_output = min(self.max_tokens, requested_output)
            admission = None
            prepared_request = None
            if self.capacity_registry is not None and self.capacity_identity is not None:
                while True:
                    rendered = render_provider_tool_request(
                        self.capacity_identity, system_prompt=system_prompt,
                        messages=messages, tools=self.TOOL_SCHEMA, max_tokens=allocated_output,
                        thinking_mode=self.thinking_mode, reasoning_effort=self.reasoning_effort,
                    )
                    admission = ProviderRequestPlanner(self.capacity_registry).plan(rendered)
                    if admission.admitted:
                        prepared_request = rendered
                        break
                    # Release an old read body, keeping its exact receipt and
                    # original tool-call linkage. It can be read on demand.
                    if not read_receipts:
                        raise ReadonlyChildError(
                            f"child Provider request blocked by context policy: {admission.reason}"
                        )
                    position = min(read_receipts)
                    receipt = read_receipts.pop(position)
                    messages[position]["content"] = json.dumps(
                        {"status": "read_body_released", **receipt,
                         "next_action": "Use sitina_child_read_source for a smaller relevant segment if needed."},
                        ensure_ascii=False, sort_keys=True,
                    )
            request_bound = (admission.input_bound_tokens + allocated_output
                             if admission is not None else None)
            if self.total_token_budget is not None:
                if request_bound is None:
                    raise ReadonlyChildError("explicit token budget requires a verified request input bound")
                if budget_charge + request_bound > self.total_token_budget:
                    raise ReadonlyChildError("child request would exceed the explicitly supplied token budget")
            retry_states: set[tuple[str, int]] = set()
            retry_evidence: list[dict[str, Any]] = []
            control = {
                "policy": "verified_progress",
                "operation": operation,
                "progress_timeout_milliseconds": math.ceil(self.progress_timeout_seconds * 1000),
                "idle_milliseconds_before_request": max(0, int((now - last_progress) * 1000)),
                "verified_evidence_bytes_before_request": progress_bytes,
                "allocated_output_tokens": allocated_output,
                "model_output_ceiling": self.max_tokens,
                "explicit_output_limit": self.user_max_output_tokens,
                "explicit_turn_limit": self.max_turns,
                "explicit_total_token_budget": self.total_token_budget,
                "budget_charge_before_request": budget_charge,
                "request_token_bound": request_bound,
                "recovery": pending_recovery,
                "retry_evidence": retry_evidence,
                "fallback_allowed": False,
            }

            def recover_retry(error: BaseException, accounting: Mapping[str, Any]) -> bool:
                # A server Retry-After on a fully observed rejection is a
                # changed condition. Timeouts/unknown sends are not retries.
                if not isinstance(error, ProviderHTTPError) or error.status_code != 429:
                    return False
                delay = error.retry_after_seconds
                key = (type(error).__name__, error.status_code)
                if (key in retry_states or type(delay) not in (int, float)
                        or not math.isfinite(delay) or delay <= 0):
                    return False
                next_attempt = accounting["physical_attempts"] + 1
                if self.total_token_budget is not None and (
                        request_bound is None
                        or budget_charge + request_bound * next_attempt > self.total_token_budget):
                    return False
                required_wait_milliseconds = math.ceil(delay * 1000)
                wait_started = clock()
                deadline = wait_started + required_wait_milliseconds / 1000
                if deadline >= last_progress + self.progress_timeout_seconds:
                    return False
                retry_states.add(key)
                while clock() < deadline:
                    if self._cancel_check(capability):
                        return False
                    time.sleep(min(0.1, max(0.0, deadline - clock())))
                if self._cancel_check(capability):
                    return False
                retry_evidence.append({
                    "basis": "observed_http_429_retry_after_elapsed",
                    "retry_after_milliseconds": required_wait_milliseconds,
                    "waited_milliseconds": int((clock() - wait_started) * 1000),
                    "failed_physical_attempt": accounting["physical_attempts"],
                })
                return True

            def dispatch_turn() -> ProviderToolTurn:
                nonlocal provider_turn_count, budget_charge
                capability.check_binding()
                provider_turn_count += 1
                transport_options = (
                    {"retry_recovery": recover_retry, "audit_all_attempts": True}
                    if isinstance(self.client, BoundedToolTurnClient) else {}
                )
                turn = self.client.complete_tool_turn(
                    self.profile, system_prompt=system_prompt, messages=messages,
                    tools=self.TOOL_SCHEMA, max_tokens=allocated_output,
                    # An admitted readonly send must finish and be persisted.
                    # Every later send/tool is fenced by current parent state.
                    cancel_check=None, prepared_request=prepared_request,
                    **transport_options,
                )
                metadata = dict(turn.metadata)
                absorb_usage(metadata)
                sends = metadata.get("physical_send_count")
                if self.total_token_budget is not None:
                    control["budget_accounting_complete"] = (
                        type(sends) is int and sends >= 0
                        and metadata.get("uncertain_physical_send_attempt_count") == 0
                    )
                    if control["budget_accounting_complete"]:
                        reported = metadata.get("token_usage")
                        actual = reported.get("total_tokens") if isinstance(reported, Mapping) else None
                        budget_charge += (actual if type(actual) is int and actual >= 0
                                          else request_bound * sends)
                control["provider_turn_count"] = provider_turn_count
                control["cumulative_reported_usage"] = dict(usage)
                control["budget_charge_after_request"] = budget_charge
                metadata["sitina_child_execution_control"] = dict(control)
                if admission is not None:
                    metadata["sitina_child_request_admission"] = admission.as_dict()
                return replace(turn, metadata=metadata)

            turn = provider_call(dispatch_turn) if provider_call is not None else dispatch_turn()
            controls.append(dict(control))
            capability.check_binding()
            metadata = turn.metadata
            if control.get("budget_accounting_complete") is False:
                raise ReadonlyChildError("explicit token budget cannot continue with unknown dispatch accounting")
            if self.total_token_budget is not None and budget_charge > self.total_token_budget:
                raise ReadonlyChildError("Provider usage exceeded its admitted explicit token budget")
            if metadata.get("uncertain_physical_send_attempt_count", 0):
                raise ReadonlyChildError("child cannot act on an uncertain Provider dispatch")
            truncated = str(turn.stop_reason or "").casefold() in {"length", "max_tokens"}
            repaired = metadata.get("json_repair_count", 0) != 0
            malformed = repaired or not turn.tool_calls or str(turn.stop_reason or "").casefold() not in {
                "tool_calls", "tool_use", "stop", "end_turn"
            }
            if metadata.get("response_refusal_present") or metadata.get("response_error_present"):
                raise ReadonlyChildError("child Provider refused or rejected the requested decision")
            if truncated or malformed:
                # Nothing in this response is executed or spliced into a tool
                # request. A later complete decision has its own durable turn.
                if truncated:
                    increased = min(self.max_tokens, max(allocated_output + 1, allocated_output * 2))
                    if increased <= allocated_output:
                        raise ReadonlyChildError("child output remains truncated at the actual output limit")
                    recovery_output_floor = increased
                    pending_recovery = {"basis": "observed_output_truncation",
                                        "prior_output_tokens": allocated_output,
                                        "next_output_tokens": increased}
                else:
                    if incomplete_seen:
                        raise ReadonlyChildError("child repeated an incomplete or repaired decision without recovery")
                    incomplete_seen = True
                    pending_recovery = {"basis": "complete_new_decision_required", "repaired_arguments_rejected": repaired}
                messages.append({
                    "role": "user",
                    "content": "The last response was incomplete or required argument repair. No tool from it was executed. Return a complete, valid tool decision using the existing evidence and exact tool schema.",
                })
                continue
            pending_recovery = None
            incomplete_seen = False
            # Validate the complete batch before its first capability action.
            for index, call in enumerate(turn.tool_calls):
                if call.name not in {"sitina_child_read_source", "sitina_child_report"}:
                    capability.deny(call.name)
                if not isinstance(call.arguments, Mapping):
                    raise ReadonlyChildError("child tool arguments must be an object")
                if call.name == "sitina_child_report" and index != len(turn.tool_calls) - 1:
                    raise ReadonlyChildError("child terminal report must be the final decision in its batch")
                if call.name == "sitina_child_read_source":
                    args = call.arguments
                    if (set(args) - {"source_id", "offset", "max_bytes"}
                            or not isinstance(args.get("source_id"), str)
                            or args.get("source_id") not in source_by_id
                            or type(args.get("offset", 0)) is not int or args.get("offset", 0) < 0
                            or type(args.get("max_bytes", 65536)) is not int
                            or not 1 <= args.get("max_bytes", 65536) <= 65536):
                        raise ReadonlyChildError("child read decision violates its declared source or schema")
                else:
                    args = call.arguments
                    if (set(args) != {"summary", "evidence_source_ids"}
                            or not isinstance(args.get("summary"), str) or not args["summary"].strip()
                            or not isinstance(args.get("evidence_source_ids"), list)
                            or any(not isinstance(item, str) or item not in source_by_id
                                   for item in args["evidence_source_ids"])):
                        raise ReadonlyChildError("child report decision violates its declared source or schema")
            assistant_message: dict[str, Any] = {
                "role": "assistant", "content": turn.text,
                "tool_calls": [{"id": call.call_id, "name": call.name, "arguments": dict(call.arguments)}
                               for call in turn.tool_calls],
            }
            if turn.reasoning_content:
                assistant_message["reasoning_content"] = turn.reasoning_content
            messages.append(assistant_message)
            for call in turn.tool_calls:
                capability.check_binding()
                result, done = self._dispatch_tool(capability, call.name, call.arguments)
                content = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)
                messages.append({"role": "tool", "tool_call_id": call.call_id, "name": call.name,
                                 "content": content, "is_error": False})
                if call.name == "sitina_child_read_source":
                    source_id = call.arguments["source_id"]
                    value = result["value"]
                    returned_bytes = (len(value.encode("utf-8")) if isinstance(value, str)
                                      else len(base64.b64decode(value["data"], validate=True)))
                    offset = call.arguments.get("offset", 0)
                    intervals = coverage.setdefault(source_id, [])
                    before = sum(end - start for start, end in intervals)
                    merged: list[tuple[int, int]] = []
                    for start, end in sorted([*intervals, (offset, offset + returned_bytes)]):
                        if merged and start <= merged[-1][1]:
                            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                        elif end > start:
                            merged.append((start, end))
                    coverage[source_id] = merged
                    added = sum(end - start for start, end in merged) - before
                    if added > 0:
                        progress_bytes += added
                        last_progress = clock()
                        recovery_output_floor = 0
                    read_receipts[len(messages) - 1] = {
                        "source_id": source_id, "offset": offset, "returned_bytes": returned_bytes,
                        "content_hash": source_by_id[source_id]["content_hash"],
                    }
                if done:
                    if not isinstance(result, Mapping):
                        raise ReadonlyChildError("child report tool returned an invalid result")
                    return {
                        **dict(result), "execution_mode": "provider_model",
                        "provider_profile": self.profile.name, "provider_call_count": provider_turn_count,
                        "execution_control": {
                            "policy": "verified_progress", "controls": controls,
                            "elapsed_milliseconds": int((clock() - started) * 1000),
                            "verified_evidence_bytes": progress_bytes,
                            "cumulative_reported_usage": dict(usage),
                            "explicit_turn_limit": self.max_turns,
                            "explicit_output_limit": self.user_max_output_tokens,
                            "explicit_total_token_budget": self.total_token_budget,
                            "budget_charge": budget_charge,
                        },
                    }

    @staticmethod
    def _cancel_check(capability: ReadonlyChildCapability) -> bool:
        try:
            capability.check_binding()
        except BaseException:
            return True
        return False

    @staticmethod
    def _dispatch_tool(
        capability: ReadonlyChildCapability,
        name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[Any, bool]:
        if not isinstance(arguments, Mapping):
            raise ReadonlyChildError("child tool arguments must be an object")
        if name == "sitina_child_read_source":
            allowed = {"source_id", "offset", "max_bytes"}
            if any(key not in allowed for key in arguments):
                raise ReadonlyChildError("child read arguments contain an unknown field")
            source_id = arguments.get("source_id")
            if not isinstance(source_id, str) or not source_id:
                raise ReadonlyChildError("child read source_id must be a non-empty string")
            offset = arguments.get("offset", 0)
            if type(offset) is not int or offset < 0:
                raise ReadonlyChildError("child read offset is outside the declared integer range")
            max_bytes = arguments.get("max_bytes", 65536)
            if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
                raise ReadonlyChildError("child read max_bytes must be an integer from 1 through 65536")
            value = capability.read_source(source_id, offset=offset, max_bytes=max_bytes)
            return {"status": "ok", "source_id": source_id, "value": value}, False
        if name == "sitina_child_report":
            if set(arguments) != {"summary", "evidence_source_ids"}:
                raise ReadonlyChildError("child report arguments do not match the report schema")
            summary = arguments.get("summary")
            evidence_raw = arguments.get("evidence_source_ids")
            if not isinstance(summary, str) or not summary.strip() or not isinstance(evidence_raw, list):
                raise ReadonlyChildError("child report arguments have invalid types")
            if any(not isinstance(item, str) or not item for item in evidence_raw):
                raise ReadonlyChildError("child report evidence ids must be non-empty strings")
            evidence = tuple(evidence_raw)
            return capability.report(summary=summary, evidence_source_ids=evidence), True
        capability.deny(name)
        raise ReadonlyChildError("unreachable child tool dispatch")
