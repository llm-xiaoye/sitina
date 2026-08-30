from __future__ import annotations

import dataclasses
import json
import secrets
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
from sitina.conversation.session_runtime import SessionRuntimeContext
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.extensions.tools import ApprovalCallback
from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime
from sitina.orchestrator.code_mode_gate import (
    CodeModeAcceptanceV1,
    CodeModeRuntimePolicy,
    classify_code_mode_intent,
)
from sitina.utils import iso_now


StatusCallback = Callable[[str, Mapping[str, Any]], None]


class FastModeMutationDenied(RuntimeError):
    """A forced FAST turn attempted an operation that requires MULTI."""


class CodeModeRuntimeUnavailable(RuntimeError):
    """Code Mode was not given its independent runtime context."""


def _explicit_mutation_intent(message: str) -> bool:
    return bool(classify_code_mode_intent(message)["explicit_mutation"])


def _open_runtime_state_reader(context: Any):
    opener = getattr(type(context), "open_runtime_state_reader", None)
    return context.open_runtime_state_reader() if callable(opener) else context.open_verified_journal_reader()


def _open_runtime_writer(context: Any):
    opener = getattr(type(context), "open_runtime_writer", None)
    return context.open_runtime_writer() if callable(opener) else context.open_writer()


def _open_session_context(runtime: Any) -> Any:
    """Open the context used for ordinary session state, not Code Mode writes.

    Code Mode execution remains strict: its write path calls ``_code_mode_context``
    and therefore requires the independently constructed Code Mode context.  A
    session can nevertheless be resumed or have its mode persisted before a
    Code Mode turn is requested.  Those lifecycle-only operations retain the
    existing ordinary runtime contract instead of accidentally making every
    FAST startup depend on Code Mode candidate state.
    """

    factory = getattr(runtime, "runtime_context_factory", None)
    if callable(factory):
        return runtime._code_mode_context()
    provider = getattr(runtime, "session_runtime_provider", None)
    # Some ordinary-session lifecycle callers are reconstructed with __new__
    # (for example after a process restart) before ConversationRuntime.__init__
    # has run.  Give that *current* process a fresh identity rather than
    # reading one from Journal/CAS or falling back to the legacy context.
    session_instance_id = getattr(runtime, "session_instance_id", None)
    if not isinstance(session_instance_id, str) or not session_instance_id.strip():
        session_instance_id = "session-instance-" + secrets.token_hex(16)
        runtime.session_instance_id = session_instance_id
    return SessionRuntimeContext.open(
        runtime.home,
        provider=provider,
        session_instance_id=session_instance_id,
    )


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
        workspace: Path | None = None,
        live_opt_in: bool = False,
        access_mode: str = "workspace",
        runtime_context_factory: Any | None = None,
        canary_authorization: Mapping[str, Any] | None = None,
        session_runtime_provider: Any | None = None,
        session_instance_id: str | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        # This identity is deliberately process-local and is never restored
        # from Journal/CAS.  Conversation/session IDs may be recovered for UX,
        # but authority, capabilities and Code Mode facts cannot cross this
        # process boundary.
        self.session_instance_id = str(
            session_instance_id or ("session-instance-" + secrets.token_hex(16))
        )
        self._session_instance_explicit = session_instance_id is not None
        if not self.session_instance_id.strip():
            raise ValueError("conversation session instance is missing")
        selected_workspace = Path(workspace).expanduser() if workspace is not None else self.home
        self.workspace = selected_workspace.resolve(strict=True)
        self.live_opt_in = bool(live_opt_in)
        self.access_mode = access_mode
        self.code_mode_policy = CodeModeRuntimePolicy()
        self.runtime_context_factory = runtime_context_factory
        self.session_runtime_provider = session_runtime_provider
        self.canary_authorization = dict(canary_authorization) if isinstance(canary_authorization, Mapping) else None
        self._pending_code_mode_sessions: dict[str, ChatSession] = {}
        # The conversation runtime owns the first attempt number for each
        # live conversation.  It is deliberately process-local: a restarted
        # CLI creates a new session instance and must re-observe/re-plan.
        self.router = router or ConversationRouter.load(self.home)
        self.context = ConversationContext.load(self.home)
        self.fast_runtime = fast_runtime or FastConversationRuntime(
            self.home,
            runtime_context_factory=runtime_context_factory,
            session_runtime_provider=session_runtime_provider,
            provider_client=getattr(session_runtime_provider, "provider_client", None),
            provider_profile=getattr(session_runtime_provider, "profile", None),
        )
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
        # Preserve injected execution dependencies.  They are deliberately
        # capability inputs, not routing overrides: MULTI still owns the
        # reviewed execution chain, while the selected workspace and the
        # current user intent are bound per run.
        self.autonomous_runtime = autonomous_runtime
        self.approval_callback = approval_callback
        self._injected_extension_adapter = autonomous_runtime
        # The public chat owns the lifecycle of the CLI-attested reviewer host.
        # An injected runtime may omit it; that is an ordinary non-authoritative
        # embedding and must never be upgraded by this attribute.
        self.code_mode_reviewer_session = (
            getattr(runtime_context_factory, "reviewer_session", None)
            if runtime_context_factory is not None else None
        ) or getattr(multi_runtime, "code_mode_reviewer_session", None)
        if hasattr(self.multi_runtime, "bind_conversation_dependencies"):
            self.multi_runtime.bind_conversation_dependencies(
                autonomous_runtime=autonomous_runtime,
                approval_callback=approval_callback,
            )
        if hasattr(self.multi_runtime, "bind_code_mode_authorizer"):
            self.multi_runtime.bind_code_mode_authorizer(self.code_mode_policy)

    @staticmethod
    def _emit(callback: StatusCallback | None, event: str, value: Mapping[str, Any]) -> None:
        if callback is not None:
            callback(event, value)

    def _code_mode_context(self) -> Any:
        factory = getattr(self, "runtime_context_factory", None)
        if not callable(factory):
            raise CodeModeRuntimeUnavailable(
                "Code Mode execution has no independent runtime context factory"
            )
        try:
            context = factory(self.home)
        except Exception as error:  # noqa: BLE001
            raise CodeModeRuntimeUnavailable(
                "Code Mode independent runtime construction failed"
            ) from error
        context_type = type(context)
        if (
            context_type.__name__ != "CodeModeRuntimeContext"
            or context_type.__module__ != "sitina.orchestrator.code_mode_runtime"
        ):
            raise CodeModeRuntimeUnavailable(
                "Code Mode factory returned a non-Code-Mode runtime context"
            )
        context_instance = getattr(context, "session_instance_id", None)
        if context_instance != self.session_instance_id:
            # Directly opened contexts are deliberately non-authoritative test
            # seams. Bind them to this live runtime for local execution, while
            # an attested broker context must never be rebound by its caller.
            if getattr(context, "_broker_client", None) is None:
                context.session_instance_id = self.session_instance_id
            elif not self._session_instance_explicit and not getattr(self, "_bound_code_mode_context_instance", None):
                # Embedding integrations that provide one already-attested
                # factory may omit the optional constructor id. Adopt the
                # factory's stable session identity once; subsequent contexts
                # must match it. The public CLI always supplies the id
                # explicitly and therefore never uses this compatibility seam.
                self.session_instance_id = str(context_instance or "")
                self._bound_code_mode_context_instance = self.session_instance_id
            else:
                raise CodeModeRuntimeUnavailable(
                    "Code Mode context belongs to a different CLI session instance"
                )
        return context

    def maybe_confirm_tty_review(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Complete the real CLI TTY handoff when a run is review-pending.

        The execution result is only a set of locators emitted by the
        controller.  This method never builds a candidate, test receipt, or
        review request from scalar fields, and it never accepts a caller
        supplied decision/summary/TTY path.  If the controller did not emit a
        complete Review V2 handoff, or the controlling terminal is absent,
        the safe result is ``REVIEW_PENDING`` with no success promotion.
        """
        if not isinstance(result, Mapping):
            return {"code_mode_status": "CODE_MODE_REVIEW_PENDING", "review_status": "REVIEW_PENDING"}
        pending = bool(result.get("headless_review_pending")) or str(
            result.get("review_status") or ""
        ) in {"REVIEW_PENDING", "REVIEW_REQUIRED", "HEADLESS_REVIEW_PENDING"}
        if not pending:
            return dict(result)

        updated = dict(result)
        updated.update({
            "code_mode_status": "CODE_MODE_REVIEW_PENDING",
            "review_status": "REVIEW_PENDING",
            "review_authority": "TTY_REVIEW_AUTHORITY",
        })
        request = result.get("review_request") or result.get("code_mode_review_request")
        candidate_locator = result.get("candidate_locator")
        candidate = result.get("candidate")
        test_receipt = result.get("test_receipt") or result.get("machine_check_receipt")
        reviewer = getattr(self, "code_mode_reviewer_session", None)
        if reviewer is None or not callable(getattr(reviewer, "is_attested_reviewer", None)) or not reviewer.is_attested_reviewer():
            reopen = getattr(self.runtime_context_factory, "open_reviewer", None)
            if callable(reopen):
                try:
                    reviewer = reopen()
                    self.code_mode_reviewer_session = reviewer
                except Exception:
                    reviewer = None
        if not all(isinstance(item, Mapping) for item in (request, candidate_locator, test_receipt)):
            updated["review_reason_type"] = "MISSING_CONTROLLER_REVIEW_HANDOFF"
            return updated
        if reviewer is None or not callable(getattr(reviewer, "confirm_tty", None)):
            updated["review_reason_type"] = "REVIEWER_HOST_UNAVAILABLE"
            return updated

        try:
            context = self._code_mode_context()
            candidate = context.reopen_candidate_manifest(
                dict(candidate_locator), run_id=str(result.get("run_id") or "")
            )
            receipt = context.confirm_tty(
                review=request,
                candidate=dict(candidate),
                reviewer_session=reviewer,
            )
            if not isinstance(receipt, Mapping):
                raise PermissionError("TTY reviewer returned no durable receipt locator")
            gate = CodeModeAcceptanceV1(self.workspace)
            gate_result = gate.evaluate_offline(
                candidate=dict(candidate),
                runtime_context=context,
                test_receipt=dict(test_receipt),
                reviewer_receipt=dict(receipt),
                test_inventory=result.get("test_inventory"),
            )
        except (EOFError, OSError, PermissionError, TimeoutError, RuntimeError, ValueError) as error:
            # TTY absence, EOF, timeout, stale evidence, and any controller
            # failure are review-pending.  Do not expose exception text, which
            # could contain paths or provider details.
            updated["review_reason_type"] = type(error).__name__
            return updated

        updated["tty_review_receipt"] = dict(receipt)
        updated["code_mode_gate"] = dict(gate_result)
        if gate_result.get("status") == "CODE_MODE_READY":
            finalizer = getattr(self.multi_runtime, "finalize_code_mode_review", None)
            if not callable(finalizer):
                updated["review_reason_type"] = "CONTROLLER_REOPEN_UNAVAILABLE"
                return updated
            try:
                finalized = finalizer(
                    run_id=str(result.get("run_id") or ""),
                    review_receipt=dict(receipt),
                    gate_result=dict(gate_result),
                    conversation_message=str(result.get("conversation_message") or ""),
                    conversation_session_id=str(result.get("conversation_session_id") or ""),
                    conversation_turn_index=int(result.get("conversation_turn_index")),
                )
                if not isinstance(finalized, Mapping) or finalized.get("terminal_state") != "SUCCEEDED":
                    raise RuntimeError("controller did not commit a successful reviewed terminal")
                updated = dict(finalized)
                updated["code_mode_status"] = "CODE_MODE_READY"
                updated["review_status"] = "ACCEPT"
                session = self._pending_code_mode_sessions.pop(str(result.get("run_id") or ""), None)
                if session is not None:
                    response = str(updated.get("response") or "").strip()
                    if response:
                        session.record_success(
                            str(updated.get("conversation_message") or "reviewed Code Mode change"),
                            response,
                            max_turns=self.context.policy.max_recent_turns,
                        )
            except (EOFError, OSError, PermissionError, TimeoutError, RuntimeError, ValueError) as error:
                updated = dict(result)
                updated["code_mode_status"] = "CODE_MODE_REVIEW_PENDING"
                updated["review_status"] = "REVIEW_PENDING"
                updated["review_reason_type"] = type(error).__name__
                return updated
        else:
            updated["review_reason_type"] = "CODE_MODE_GATE_BLOCKED"
        return updated

    def close_code_mode_reviewer(self) -> None:
        """Close the run-scoped reviewer without closing the authority host."""
        closer = getattr(self.runtime_context_factory, "close_reviewer", None)
        if callable(closer):
            closer()
        self.code_mode_reviewer_session = None

    def resume_or_create_session(self) -> ChatSession:
        """Rebuild the latest chat session from verified Journal/CAS state."""

        context = _open_session_context(self)
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
            context = _open_session_context(self)
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
            context = _open_session_context(self)
        journal = _open_runtime_state_reader(context)
        try:
            return self._recover_session(journal, context.open_cas_reader(), context.provider)
        finally:
            journal.close()

    def persist_mode(self, session: ChatSession, mode: ChatMode) -> None:
        """Commit an interactive mode selection without invoking a Provider."""

        if not isinstance(session, ChatSession):
            raise TypeError("mode persistence requires a ChatSession")
        if not isinstance(mode, ChatMode):
            raise TypeError("mode persistence requires a ChatMode")
        context = _open_session_context(self)
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
        def observed_count(name: str) -> int | None:
            value = result.get(name)
            if value is None:
                return None
            return int(value)

        return {
            **dict(result),
            "session_id": session.session_id,
            "turn_index": session.turn_index,
            "requested_mode": decision.requested_mode.value,
            "resolved_mode": decision.resolved_mode.value,
            "route_decision": decision.mapping(),
            "escalated": escalated,
            "external_mutation_count": int(result.get("external_mutation_count", 0) or 0),
            "legacy_read_count": observed_count("legacy_read_count"),
            "legacy_write_count": observed_count("legacy_write_count"),
            "sqlite_connect_count": observed_count("sqlite_connect_count"),
            "sqlite_write_count": observed_count("sqlite_write_count"),
        }

    def execute_turn(
        self,
        session: ChatSession,
        message: str,
        *,
        status_callback: StatusCallback | None = None,
        workspace: Path | None = None,
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
        # AUTO must not let a classifier/SLA downgrade an explicit code
        # mutation into FAST.  This is a route decision only; the selected
        # MULTI path still performs the normal tool authorization and review.
        intent = classify_code_mode_intent(message)
        if session.mode is ChatMode.AUTO and intent["explicit_mutation"] and initial.resolved_mode is ChatMode.FAST:
            initial = dataclasses.replace(
                initial,
                resolved_mode=ChatMode.MULTI,
                reasons=("明确代码修改意图",),
                decision_path="AUTO_EXPLICIT_MUTATION_MULTI",
                upgrade_reason="明确代码修改意图需要 MULTI 工具执行与独立审阅",
            )
        session.last_route_decision = initial
        self._emit(status_callback, "route", initial.mapping())
        try:
            if session.mode is ChatMode.FAST and _explicit_mutation_intent(message):
                raise FastModeMutationDenied("FAST 只读；明确的代码修改请求请切换到 /multi 后重试")
            selected_workspace = (
                Path(workspace).expanduser().resolve(strict=True)
                if workspace is not None
                else self.workspace
            )
            code_mode_authorization = self.code_mode_policy.authorize(
                mode=session.mode.value,
                message=message,
                session_id=session.session_id,
                workspace=selected_workspace,
                access_mode=self.access_mode,
            )
            policy_authorization_allowed = code_mode_authorization.get("allowed") is True
            external_action_confirmation_required = bool(
                code_mode_authorization.get("external_action_confirmation_required")
            )
            # Candidate identity is an execution handoff input, not a pre-tool
            # permission gate.  Capture it from the selected workspace after
            # the intent decision so ordinary Code Mode can seal a durable,
            # review-pending handoff even when no canary is enabled.
            # A policy mapping is produced for every message so that the
            # router can explain a read-only decision.  Only an explicit
            # mutation is Code Mode execution and may construct a candidate or
            # require the independent Code Mode context.  Ordinary FAST and
            # read-only MULTI paths must not be coupled to that write context.
            code_mode_execution = bool(
                policy_authorization_allowed
                and intent.get("explicit_mutation") is True
            )
            if code_mode_execution:
                from sitina.orchestrator.code_mode_gate import build_candidate_manifest
                # This is the baseline identity used only to authorize the
                # starting workspace.  It must not be reused as the output
                # candidate after Forge has changed the workspace.
                code_mode_candidate = build_candidate_manifest(selected_workspace)
                # Generation is part of the current Code Mode runtime
                # identity.  It is an execution/review binding, not a
                # pre-tool acceptance gate; a candidate without it cannot be
                # promoted by the post-execution Gate.
                runtime_identity_context = self._code_mode_context()
                generation = str(
                    getattr(getattr(runtime_identity_context, "identity", None), "epoch_root", "")
                    or ""
                )
                if not generation:
                    raise CodeModeRuntimeUnavailable(
                        "Code Mode runtime has no current authority generation"
                    )
                code_mode_candidate = {
                    **code_mode_candidate,
                    "generation": generation,
                }
                # A fresh TrueMulti run owns attempt one.  Only that run's
                # bounded rework owner may advance the attempt.
                next_attempt = 1
                baseline_authorization_identity = {
                    "workspace": code_mode_candidate["workspace"],
                    "candidate_id": code_mode_candidate["candidate_id"],
                    "tree_hash": code_mode_candidate["tree_hash"],
                    "source_manifest_hash": code_mode_candidate["source_manifest_hash"],
                    "worktree_digest": code_mode_candidate["worktree_digest"],
                    "generation": generation,
                    "run_attempt": next_attempt,
                }
                code_mode_authorization = {
                    **code_mode_authorization,
                    "session_instance_id": self.session_instance_id,
                    "candidate_id": code_mode_candidate["candidate_id"],
                    "tree_hash": code_mode_candidate["tree_hash"],
                    "source_manifest_hash": code_mode_candidate["source_manifest_hash"],
                    "worktree_digest": code_mode_candidate["worktree_digest"],
                    "generation": generation,
                    "run_attempt": next_attempt,
                }
            else:
                code_mode_candidate = None
                baseline_authorization_identity = None
                code_mode_authorization = None
            if not policy_authorization_allowed:
                raise FastModeMutationDenied(
                    str((code_mode_authorization or {}).get("reasons", [])[0])
                    if (code_mode_authorization or {}).get("reasons")
                    else "Code Mode request denied"
                )
            if initial.resolved_mode is ChatMode.MULTI:
                if code_mode_execution:
                    # Keep the concrete context out of persisted controls and
                    # Journal JSON. TrueMulti consumes this ephemeral handoff
                    # only for this synchronous call; the caller cannot turn
                    # it into a serializable authority fact.
                    setattr(self.multi_runtime, "_active_code_mode_context", runtime_identity_context)
                if (
                    code_mode_execution
                    and isinstance(self.multi_runtime, TrueMultiAgentProductionRuntime)
                    and not callable(getattr(self, "runtime_context_factory", None))
                ):
                    raise CodeModeRuntimeUnavailable(
                        "Code Mode MULTI requires an explicitly constructed independent runtime"
                    )
                result = self.multi_runtime.execute(
                    self._multi_goal(message, snapshot=snapshot),
                    label="cli-interactive-chat-multi",
                    overrides={
                        "interactive_chat": True,
                        "conversation_user_message": message,
                        "conversation_session_id": session.session_id,
                        "conversation_turn_index": session.turn_index,
                        "conversation_route_decision": initial.canonical_mapping(),
                        "execution_workspace": str(selected_workspace),
                        "execution_access_mode": self.access_mode,
                        "live_opt_in": self.live_opt_in,
                        "code_mode_authorization": code_mode_authorization,
                        "code_mode_candidate": code_mode_candidate,
                        "baseline_authorization_identity": baseline_authorization_identity,
                        "code_mode_intent": (
                            code_mode_authorization["intent"]
                            if isinstance(code_mode_authorization, Mapping)
                            else intent
                        ),
                        "intent_authorized": bool(
                            isinstance(code_mode_authorization, Mapping)
                            and code_mode_authorization.get("intent_authorized") is True
                        ),
                        "explicit_external_action": external_action_confirmation_required,
                        "canary_authorization": dict(self.canary_authorization)
                        if self.canary_authorization is not None else None,
                        "session_instance_id": self.session_instance_id,
                        # Ordinary reviewed MULTI has no Code Mode
                        # authorization.  Do not dereference or synthesize
                        # its attempt identity here; the Code Mode producer
                        # validates run_attempt from its issued binding.
                        "run_attempt": (
                            baseline_authorization_identity["run_attempt"]
                            if isinstance(baseline_authorization_identity, Mapping)
                            else None
                        ),
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
                    live_opt_in=self.live_opt_in,
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
                    if (
                        code_mode_execution
                        and isinstance(self.multi_runtime, TrueMultiAgentProductionRuntime)
                        and not callable(getattr(self, "runtime_context_factory", None))
                    ):
                        raise CodeModeRuntimeUnavailable(
                            "Code Mode AUTO escalation requires an explicitly constructed independent runtime"
                        )
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
                            "execution_workspace": str(selected_workspace),
                            "execution_access_mode": self.access_mode,
                            "live_opt_in": self.live_opt_in,
                            "code_mode_authorization": code_mode_authorization,
                            "code_mode_candidate": code_mode_candidate,
                            "baseline_authorization_identity": baseline_authorization_identity,
                            "code_mode_intent": (
                                code_mode_authorization["intent"]
                                if isinstance(code_mode_authorization, Mapping)
                                else intent
                            ),
                            "intent_authorized": bool(
                                isinstance(code_mode_authorization, Mapping)
                                and code_mode_authorization.get("intent_authorized") is True
                            ),
                            "explicit_external_action": external_action_confirmation_required,
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
            if final.get("code_mode_status") == "CODE_MODE_REVIEW_PENDING":
                run_key = str(final.get("run_id") or "")
                if run_key:
                    self._pending_code_mode_sessions[run_key] = session
            response = str(final.get("response") or "").strip()
            if final.get("code_mode_status") == "CODE_MODE_REVIEW_PENDING":
                # Review-pending is neither success nor failure.  In
                # particular, do not persist an assistant message or mark the
                # turn failed before the controller receives TTY acceptance.
                pass
            elif final.get("terminal_state") == "SUCCEEDED" and response:
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
