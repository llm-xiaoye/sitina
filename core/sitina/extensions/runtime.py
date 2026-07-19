from __future__ import annotations

import concurrent.futures
import hashlib
import json
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
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
    RoleProfileResolver,
)
from sitina.security.tool_security import summarize_tool_arguments, summarize_tool_result
from sitina.legacy.fence import issue_frozen_network_egress_capability
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.utils import iso_now, redact_text, stable_json


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


class AutonomousRuntimeError(RuntimeError):
    pass


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

    def append(self, event: str, payload: Mapping[str, Any]) -> None:
        from sitina.cas.crypto import encrypt_object
        from sitina.journal.model import canonical_json_bytes

        clean = json.loads(redact_text(stable_json(dict(payload))))
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
            )
            if key in clean and isinstance(clean[key], (str, int, bool))
        }
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
        )
        self.hooks = HookRunner(self.catalog)
        self.max_tokens = max_tokens
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

                if not session_id or turn_index is None or not isinstance(route_decision, Mapping):
                    raise AutonomousRuntimeError(
                        "production autonomous execution requires a conversation session, turn, and route decision"
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
            finish()

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
        while True:
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
            self._audit(
                run_id,
                "provider_call_intended",
                {
                    "turn": provider_turns + 1,
                    "system_prompt": system_prompt,
                    "messages": messages,
                    "tools": tool_schemas,
                    "max_tokens": self.max_tokens,
                },
            )
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
                self._audit(
                    run_id,
                    "provider_call_failed",
                    {
                        "turn": provider_turns + 1,
                        "error_type": type(error).__name__,
                        "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                        "automatic_retry_performed": False,
                    },
                )
                raise
            provider_turns += 1
            provider_metadata.append(dict(turn.metadata))
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
                    "stop_reason": turn.stop_reason,
                    "tool_calls": assistant_calls,
                    "text": turn.text,
                    "metadata": turn.metadata,
                },
            )
            if not turn.tool_calls:
                response = turn.text.strip()
                if not response:
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
                    "status": result.status,
                    "result": result.value,
                    "started_at": result.started_at,
                    "completed_at": result.completed_at,
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
                    },
                )

    def _execute_calls(self, run_id: str, calls: Sequence[ProviderToolCall]) -> dict[str, ToolResult]:
        read_calls: list[ProviderToolCall] = []
        gated_calls: list[ProviderToolCall] = []
        for call in calls:
            if self.catalog.get(call.name).permission == "read":
                read_calls.append(call)
            else:
                gated_calls.append(call)
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

    def _execute_one(self, run_id: str, call: ProviderToolCall) -> ToolResult:
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
            **json.loads(redact_text(stable_json(dict(payload)))),
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
        return {
            "status": status,
            "terminal_state": terminal_state,
            "run_id": run_id,
            "response": response,
            "provider_call_count": provider_turns,
            "provider_physical_send_count": sum(
                int(item.get("physical_send_count", 1)) for item in provider_metadata
            ),
            "tool_call_count": len(tool_results),
            "tool_results": [dict(item) for item in tool_results],
            "selected_skills": [item.qualified_name for item in skills],
            "selected_plugin_agents": [f"{item.plugin_name}:{item.name}" for item in agents],
            "provider_metadata": [dict(item) for item in provider_metadata],
            "external_mutation_count": sum(
                1 for item in tool_results if item.get("permission") in {"write", "shell", "network", "external_service"}
            ),
            "runtime": "sitina-autonomous-extensions-v1",
        }
