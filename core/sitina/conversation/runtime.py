from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.conversation.context import ConversationContext
from sitina.conversation.fast_runtime import FastConversationRuntime
from sitina.conversation.models import ChatMode, ChatSession, ConversationTurn, RouteDecision, RouteSource, route_decision_from_mapping
from sitina.conversation.persistence import JournalSessionRepository
from sitina.conversation.recovery import ConversationReconciler
from sitina.conversation.state import RollingSummaryRepository, SessionStateError, WorkingStateRepository
from sitina.conversation.router import ConversationRouter
from sitina.conversation.routing_policy import RoutingHistoryState
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.extensions.tools import ApprovalCallback
from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime
from sitina.utils import iso_now


StatusCallback = Callable[[str, Mapping[str, Any]], None]


def _open_runtime_state_reader(context: Any):
    opener = getattr(type(context), "open_runtime_state_reader", None)
    return context.open_runtime_state_reader() if callable(opener) else context.open_verified_journal_reader()


def _open_runtime_writer(context: Any):
    opener = getattr(type(context), "open_runtime_writer", None)
    return context.open_runtime_writer() if callable(opener) else context.open_writer()


class ConversationRuntime:
    """Coordinates local routing, FAST execution, and reviewed MULTI execution."""

    def __init__(
        self,
        home: Path,
        *,
        router: ConversationRouter | None = None,
        fast_runtime: FastConversationRuntime | None = None,
        multi_runtime: TrueMultiAgentProductionRuntime | None = None,
        autonomous_runtime: AutonomousRuntime | None = None,
        approval_callback: ApprovalCallback | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.router = router or ConversationRouter.load(self.home)
        self.context = ConversationContext.load(self.home)
        self.fast_runtime = fast_runtime or FastConversationRuntime(self.home)
        self.multi_runtime = multi_runtime or TrueMultiAgentProductionRuntime(self.home)
        # Extensions are capabilities available to an admitted Agent runtime;
        # they must never replace Conversation Runtime, routing, or FAST/MULTI
        # execution merely because a plugin is installed.
        extension_manager = ExtensionManager(self.home)
        registry = extension_manager.load_registry()
        self.extension_tool_capabilities = tuple(
            sorted(
                name
                for group in ("plugins", "skills")
                for name, item in registry[group].items()
                if not item.get("disabled")
            )
        )
        self.autonomous_runtime = None
        self._injected_extension_adapter = autonomous_runtime
        del approval_callback

    @staticmethod
    def _emit(callback: StatusCallback | None, event: str, value: Mapping[str, Any]) -> None:
        if callback is not None:
            callback(event, value)

    def resume_or_create_session(self) -> ChatSession:
        """Rebuild the latest chat session from verified Journal/CAS state."""

        from sitina.orchestrator.bplus_production import ProductionRuntimeContext

        context = ProductionRuntimeContext.load(self.home)
        journal = _open_runtime_state_reader(context)
        historical_events = tuple(journal.iter_events(0))
        incomplete = FastConversationRuntime.incomplete_committed_runs(historical_events)
        if incomplete:
            journal.close()
            fast_runtime = getattr(self, "fast_runtime", None) or FastConversationRuntime(self.home)
            writer = _open_runtime_writer(context)
            try:
                cas = context.open_cas()
                for run_id in incomplete:
                    fast_runtime.recover_committed_run(
                        context_runtime=context,
                        journal=writer,
                        cas=cas,
                        historical_events=historical_events,
                        run_id=run_id,
                    )
            finally:
                writer.close()
            context = ProductionRuntimeContext.load(self.home)
            journal = _open_runtime_state_reader(context)
        cas = context.open_cas_reader()
        try:
            repository = JournalSessionRepository(journal, cas, context.provider)
            session_id = repository.latest_session_id()
            recoverable = (
                ConversationReconciler(journal, cas, context.provider).recoverable_turns(session_id)
                if session_id is not None
                else ()
            )
            if not recoverable:
                return self._recover_session(journal, cas, context.provider)
        finally:
            journal.close()
        if recoverable:
            writer = _open_runtime_writer(context)
            try:
                ConversationReconciler(writer, context.open_cas(), context.provider).reconcile(
                    recoverable[0].session_id,
                    occurred_at=iso_now(),
                )
            finally:
                writer.close()
            # The context may have memoized the full verified prefix used to
            # discover the reconciliation gap.  Reload authority before the
            # final read so the newly appended assistant/reconciled facts are
            # visible in this same startup call.
            context = ProductionRuntimeContext.load(self.home)
        journal = _open_runtime_state_reader(context)
        try:
            return self._recover_session(journal, context.open_cas_reader(), context.provider)
        finally:
            journal.close()

    def persist_mode(self, session: ChatSession, mode: ChatMode) -> None:
        """Commit an interactive mode selection without invoking a Provider."""

        from sitina.orchestrator.bplus_production import ProductionRuntimeContext

        if not isinstance(session, ChatSession):
            raise TypeError("mode persistence requires a ChatSession")
        if not isinstance(mode, ChatMode):
            raise TypeError("mode persistence requires a ChatMode")
        context = ProductionRuntimeContext.load(self.home)
        journal = _open_runtime_writer(context)
        try:
            repository = JournalSessionRepository(journal, context.open_cas(), context.provider)
            occurred_at = iso_now()
            repository.ensure_created(
                session_id=session.session_id,
                title="Conversation",
                created_at=occurred_at,
            )
            repository.record_mode_changed(
                session_id=session.session_id,
                mode=mode.value,
                created_at=occurred_at,
            )
        finally:
            journal.close()

    def _recover_session(self, journal: Any, cas: Any, key_provider: Any) -> ChatSession:
        repository = JournalSessionRepository(journal, cas, key_provider)
        session_id = repository.latest_session_id()
        memories: list[tuple[str, int]] = []
        from sitina.memory.native import MemoryRepository

        memory_repository = MemoryRepository(journal, cas, key_provider)
        for document in memory_repository.retrieve(actor="user"):
            _document, content = memory_repository.get(document.memory_id, actor="user")
            if content:
                memories.append((content, int(round(document.confidence * 1_000_000))))
        if session_id is None:
            return ChatSession(accepted_memories=tuple(memories), context_source_frontier=journal.head_position)
        recovered = repository.recover(session_id)
        working_state = ""
        rolling_summary = ""
        try:
            state = WorkingStateRepository(journal, cas, key_provider).recover(session_id)
            working_state = json.dumps(
                state.state.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except SessionStateError:
            pass
        try:
            summary = RollingSummaryRepository(journal, cas, key_provider).recover(session_id)
            rolling_summary = json.dumps(
                summary.content.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except SessionStateError:
            pass
        route_records = list(recovered.get("route_decisions") or ())
        last_route = (
            route_decision_from_mapping(route_records[-1]["decision"])
            if route_records
            else None
        )
        messages = list(recovered.get("messages") or ())
        failed = set(int(item) for item in recovered.get("failed_turns") or ())
        last_failed_message = None
        if failed:
            latest_failed = max(failed)
            assistant_turns = {
                int(item["turn_index"])
                for item in messages
                if item.get("role") == "assistant"
            }
            if latest_failed not in assistant_turns:
                last_failed_message = next(
                    (
                        str(item["body"])
                        for item in reversed(messages)
                        if item.get("role") == "user" and int(item["turn_index"]) == latest_failed
                    ),
                    None,
                )
        return ChatSession(
            session_id=session_id,
            mode=ChatMode(str(recovered.get("mode") or "AUTO")),
            turn_index=int(recovered.get("turn_index") or 0),
            history=[
                ConversationTurn(str(item["user"]), str(item["assistant"]))
                for item in recovered.get("successful_turns") or ()
            ][-self.context.policy.max_recent_turns :],
            last_route_decision=last_route,
            last_failed_message=last_failed_message,
            working_state=working_state,
            rolling_summary=rolling_summary,
            accepted_memories=tuple(memories),
            context_source_frontier=int(recovered.get("source_frontier") or journal.head_position),
        )

    @staticmethod
    def _safe_fast_summary(result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": "SITINA_SOURCED_FAST_CANDIDATE_V1",
            "fast_run_id": result.get("run_id"),
            "fast_output_hash": result.get("response_output_hash"),
            "candidate_ref": result.get("evidence_package_ref"),
            "candidate_role": "prior-fast-candidate-evidence",
            "confidence": result.get("confidence"),
            "needs_multi": bool(result.get("needs_multi")),
            "escalation_reasons": list(result.get("escalation_reasons") or ())[:8],
            "provider_physical_send_count": int(result.get("provider_physical_send_count", 0) or 0),
            "external_mutation_count": int(result.get("external_mutation_count", 0) or 0),
            "displayed_to_user": False,
            "repeat_side_effect_allowed": False,
        }

    def _multi_goal(
        self,
        message: str,
        *,
        snapshot,
        safe_fast_summary: Mapping[str, Any] | None = None,
    ) -> str:
        goal = self.context.goal(message, snapshot)
        if safe_fast_summary is None:
            return goal
        return (
            goal
            + "\n\nA prior FAST pass requested independent review. Treat the following content-addressed record as sourced "
            "candidate evidence; it must not be treated as a Proposal already accepted by the review pipeline. Preserve "
            "its causal run/output references, evaluate it independently, do not display it "
            "as a second answer, and never repeat any side effect. Candidate evidence: "
            + str(dict(safe_fast_summary))
        )

    @staticmethod
    def _base_result(
        session: ChatSession,
        decision: RouteDecision,
        result: Mapping[str, Any],
        *,
        escalated: bool,
    ) -> dict[str, Any]:
        return {
            **dict(result),
            "session_id": session.session_id,
            "turn_index": session.turn_index,
            "requested_mode": decision.requested_mode.value,
            "resolved_mode": decision.resolved_mode.value,
            "route_decision": decision.mapping(),
            "escalated": escalated,
            "external_mutation_count": int(result.get("external_mutation_count", 0) or 0),
            "legacy_read_count": int(result.get("legacy_read_count", 0) or 0),
            "legacy_write_count": int(result.get("legacy_write_count", 0) or 0),
            "sqlite_connect_count": int(result.get("sqlite_connect_count", 0) or 0),
            "sqlite_write_count": int(result.get("sqlite_write_count", 0) or 0),
        }

    def execute_turn(
        self,
        session: ChatSession,
        message: str,
        *,
        status_callback: StatusCallback | None = None,
    ) -> dict[str, Any]:
        message = message.strip()
        if not message:
            raise ValueError("conversation turn requires a non-empty message")
        snapshot = self.context.compose(
            session.history,
            current_user_message=message,
            goal_constraints=(
                "Fulfill the current user request while preserving Journal event authority, CAS content authority, "
                "and rebuildable-only projections."
            ),
            working_state=session.working_state,
            memories=session.accepted_memories,
            rolling_summary=session.rolling_summary,
        )
        session.begin_turn(message)
        prior_observation = dict(session.last_route_decision.observability or {}) if session.last_route_decision else {}
        prior_scores = dict(prior_observation.get("scores") or {})
        initial = self.router.decide(
            session.mode,
            message,
            snapshot,
            history=RoutingHistoryState(
                prior_mode=session.last_route_decision.resolved_mode if session.last_route_decision else None,
                prior_complexity_score=int(prior_scores.get("complexity_total", 0) or 0),
                has_bounded_history=bool(session.history),
                unfinished_goal=bool(session.working_state),
            ),
            subject_id=session.session_id,
        )
        session.last_route_decision = initial
        self._emit(status_callback, "route", initial.mapping())
        try:
            if initial.resolved_mode is ChatMode.MULTI:
                result = self.multi_runtime.execute(
                    self._multi_goal(message, snapshot=snapshot),
                    label="cli-interactive-chat-multi",
                    overrides={
                        "interactive_chat": True,
                        "conversation_user_message": message,
                        "conversation_session_id": session.session_id,
                        "conversation_turn_index": session.turn_index,
                        "conversation_route_decision": initial.canonical_mapping(),
                    },
                )
                session.active_run_id = str(result.get("run_id") or "") or None
                final = self._base_result(
                    session,
                    initial,
                    result,
                    escalated=initial.requested_mode is ChatMode.AUTO,
                )
            else:
                fast_result = self.fast_runtime.execute(
                    message,
                    context=snapshot,
                    route_decision=initial,
                    session_id=session.session_id,
                    turn_index=session.turn_index,
                    allow_escalation=session.mode is ChatMode.AUTO,
                )
                session.active_run_id = str(fast_result.get("run_id") or "") or None
                fast_succeeded = (
                    fast_result.get("terminal_state") == "SUCCEEDED"
                    and bool(str(fast_result.get("response") or "").strip())
                )
                should_escalate = (
                    session.mode is ChatMode.AUTO
                    and fast_succeeded
                    and bool(fast_result.get("escalation_recommended"))
                )
                if should_escalate:
                    escalation_reasons = list(fast_result.get("escalation_reasons") or ())
                    final_decision = RouteDecision.escalation(
                        initial,
                        escalation_reasons,
                        fast_confidence=str(fast_result.get("confidence") or "") or None,
                        needs_multi=bool(fast_result.get("needs_multi")),
                    )
                    session.last_route_decision = final_decision
                    self._emit(status_callback, "escalation", final_decision.mapping())
                    multi_result = self.multi_runtime.execute(
                        self._multi_goal(
                            message,
                            snapshot=snapshot,
                            safe_fast_summary=self._safe_fast_summary(fast_result),
                        ),
                        label="cli-interactive-chat-fast-escalation",
                        overrides={
                            "interactive_chat": True,
                            "conversation_user_message": message,
                            "conversation_session_id": session.session_id,
                            "conversation_turn_index": session.turn_index,
                            "conversation_route_decision": final_decision.canonical_mapping(),
                            "prior_fast_summary": self._safe_fast_summary(fast_result),
                        },
                    )
                    session.active_run_id = str(multi_result.get("run_id") or "") or None
                    aggregate = dict(multi_result)
                    aggregate.update(
                        {
                            "fast_run_id": fast_result.get("run_id"),
                            "multi_run_id": multi_result.get("run_id"),
                            "provider_call_count": int(fast_result.get("provider_call_count", 0) or 0)
                            + int(multi_result.get("provider_call_count", 0) or 0),
                            "provider_physical_send_count": int(
                                fast_result.get("provider_physical_send_count", 0) or 0
                            )
                            + int(multi_result.get("provider_physical_send_count", 0) or 0),
                            "provider_token_total": int(fast_result.get("provider_token_total", 0) or 0)
                            + int(multi_result.get("provider_token_total", 0) or 0),
                            "provider_cost_micro_usd": int(
                                fast_result.get("provider_cost_micro_usd", 0) or 0
                            )
                            + int(multi_result.get("provider_cost_micro_usd", 0) or 0),
                            "provider_retry_count": int(fast_result.get("provider_retry_count", 0) or 0)
                            + int(multi_result.get("provider_retry_count", 0) or 0),
                            "provider_fallback_count": int(fast_result.get("provider_fallback_count", 0) or 0)
                            + int(multi_result.get("provider_fallback_count", 0) or 0),
                            "fast_candidate_displayed": False,
                            "fast_candidate_evidence": self._safe_fast_summary(fast_result),
                            "causal_parent_run_id": fast_result.get("run_id"),
                            "duplicate_side_effect_count": 0,
                        }
                    )
                    final = self._base_result(session, final_decision, aggregate, escalated=True)
                else:
                    final = self._base_result(session, initial, fast_result, escalated=False)
                    if session.mode is ChatMode.FAST and (
                        bool(fast_result.get("needs_multi")) or fast_result.get("confidence") == "low"
                    ):
                        final["forced_fast_low_confidence"] = True
            response = str(final.get("response") or "").strip()
            if final.get("terminal_state") == "SUCCEEDED" and response:
                session.record_success(message, response, max_turns=self.context.policy.max_recent_turns)
                session.working_state = json.dumps(
                    {
                        "primary_goal": message,
                        "next_action": "Await the next user request",
                        "turn_index": session.turn_index,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                summary_lines = [line for line in session.rolling_summary.splitlines() if line]
                summary_lines.extend((f"User turn {session.turn_index}: {message}", f"Assistant turn {session.turn_index}: {response}"))
                session.rolling_summary = "\n".join(summary_lines[-24:])
            else:
                session.record_failure(message, run_id=str(final.get("run_id") or "") or None)
            return final
        except BaseException:
            session.record_failure(message, run_id=session.active_run_id)
            raise


def route_description(decision: RouteDecision) -> tuple[str, tuple[str, ...]]:
    if decision.resolved_mode is ChatMode.FAST:
        suffix = "用户强制" if decision.source is RouteSource.USER_FORCED else "单 Agent"
        return f"→ FAST · {suffix}", ()
    if decision.source is RouteSource.USER_FORCED:
        return "→ MULTI · 用户强制", ()
    return "→ MULTI · 自动升级", decision.reasons
