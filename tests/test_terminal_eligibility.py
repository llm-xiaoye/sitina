from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.commands.model import CommandEnvelope, CommandResult, CommandStatus
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, FrontierRef, canonical_json_bytes, domain_hash
from sitina.projections.runner import ProjectionRunner
from sitina.projections.schema import open_projection
from sitina.protocols.entity_creation import EntityKind, begin_entity_creation, reconcile_source, target_create
from sitina.protocols.permits import PermitPurpose
from sitina.protocols.run import RunAggregate, RunState
from sitina.protocols.tasks import TaskAggregate, TaskGraphAggregate
from sitina.protocols.terminal import (
    AuthoritativeTerminalFacts, BlockerKind, TerminalEligibilityError, TerminalEligibilityProjection,
    apply_terminal_decision, full_validate,
)
from sitina.scheduling.dispatcher import Dispatcher, FixtureWorker, project_outbox
from sitina.scheduling.processes import ProcessManager
from sitina.scheduling.scheduler import Scheduler, TaskCandidate
from sitina.scheduling.timers import ClockSample, TimerService
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


def facts(**changes):
    values = {"blocker_refs": {kind: () for kind in BlockerKind}, "cancellation_requested_ref": None, "failure_refs": (), "required_obligations_complete_ref": "11" * 32, "policy_hash": "22" * 32}
    values.update(changes); return AuthoritativeTerminalFacts(**values)


class TerminalEligibilityTests(unittest.TestCase):
    def test_every_blocker_kind_prevents_projection_candidate(self) -> None:
        for kind in BlockerKind:
            with self.subTest(kind=kind):
                projection = TerminalEligibilityProjection.empty("run-1").apply(kind, 1, source_position=1)
                self.assertFalse(projection.candidate)
                run, _ = RunAggregate.open("run-1"); run, _ = run.begin_closing(expected_stream_version=1)
                with self.assertRaises(TerminalEligibilityError): full_validate(projection, run, facts())

    def test_projection_candidate_cannot_directly_terminal_run(self) -> None:
        projection = TerminalEligibilityProjection.empty("run-1")
        run, _ = RunAggregate.open("run-1"); run, _ = run.begin_closing(expected_stream_version=1)
        self.assertTrue(projection.candidate); self.assertEqual(run.state, RunState.CLOSING)
        with self.assertRaises(AttributeError): getattr(projection, "terminal_run")

    def test_authoritative_full_validation_rechecks_refs_and_applies_success(self) -> None:
        projection = TerminalEligibilityProjection.empty("run-1")
        run, _ = RunAggregate.open("run-1"); run, _ = run.begin_closing(expected_stream_version=1)
        decision = full_validate(projection, run, facts())
        terminal, _ = apply_terminal_decision(run, decision)
        self.assertEqual(terminal.state, RunState.SUCCEEDED)

    def test_deterministic_cancel_failure_success_priority(self) -> None:
        projection = TerminalEligibilityProjection.empty("run-1"); run, _ = RunAggregate.open("run-1"); run, _ = run.begin_closing(expected_stream_version=1)
        cancelled = full_validate(projection, run, facts(cancellation_requested_ref="33" * 32, failure_refs=("44" * 32,)))
        failed = full_validate(projection, run, facts(required_obligations_complete_ref=None, failure_refs=("44" * 32,)))
        succeeded = full_validate(projection, run, facts())
        self.assertEqual((cancelled.terminal_state, failed.terminal_state, succeeded.terminal_state), (RunState.CANCELLED, RunState.FAILED, RunState.SUCCEEDED))

    def test_projection_zero_but_authoritative_blocker_fails_closed(self) -> None:
        projection = TerminalEligibilityProjection.empty("run-1"); run, _ = RunAggregate.open("run-1"); run, _ = run.begin_closing(expected_stream_version=1)
        blockers = {kind: () for kind in BlockerKind}; blockers[BlockerKind.DEAD_LETTER] = ("55" * 32,)
        with self.assertRaises(TerminalEligibilityError): full_validate(projection, run, facts(blocker_refs=blockers))

    def test_outcome_fact_references_are_hash_bound(self) -> None:
        with self.assertRaises(TerminalEligibilityError):
            facts(required_obligations_complete_ref="not-a-canonical-hash")


class Phase2EndToEndTests(unittest.TestCase):
    """One isolated, authoritative-fact lifecycle with deterministic restarts."""

    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("phase2-e2e\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    @staticmethod
    def _fact_hash(value: dict) -> str:
        return domain_hash("PHASE2_E2E_FACT", canonical_json_bytes(value))

    @staticmethod
    def _semantic_projection(connection) -> tuple[tuple[str, tuple], ...]:
        tables = (
            "event_catalog", "stream_heads", "dispatch_outbox",
            "durable_timer_candidates", "terminal_eligibility_counts",
        )
        return tuple(
            (table, tuple(connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()))
            for table in tables
        )

    def test_run_to_task_dispatch_result_terminal_and_projection_rebuild(self) -> None:
        lifecycle_facts: list[dict] = []

        run, opened = RunAggregate.open("run-phase2-e2e")
        lifecycle_facts.append(opened)
        run, permit, granted = run.grant_permit(
            expected_stream_version=run.stream_version,
            purpose=PermitPurpose.ENTITY_CREATE,
            scope="task",
            count=1,
            max_depth=0,
            expires_at="2099-01-01T00:00:00Z",
            permit_id="permit-phase2-e2e",
        )
        lifecycle_facts.append(granted)
        create_request_hash = self._fact_hash({"task_id": "task-phase2-e2e", "specification": "fixture"})
        run, _, creation, creation_facts = begin_entity_creation(
            run,
            permit,
            process_id="process-create-task-phase2-e2e",
            entity_id="task-phase2-e2e",
            entity_kind=EntityKind.TASK,
            create_command_id="create-task-phase2-e2e",
            request_hash=create_request_hash,
            idempotency_binding="binding-task-phase2-e2e",
        )
        lifecycle_facts.extend(creation_facts)
        creation, created = target_create(
            creation,
            canonical_stream_state="NO_STREAM",
            canonical_request_hash=None,
        )
        lifecycle_facts.append(created)
        run, creation, confirmed = reconcile_source(
            run,
            creation,
            canonical_target_state="CREATED",
            canonical_request_hash=create_request_hash,
        )
        lifecycle_facts.append(confirmed)

        graph = TaskGraphAggregate.create("graph-phase2-e2e")
        graph, node_added = graph.add_task(
            expected_graph_version=0,
            node_id="node-phase2-e2e",
            specification={"kind": "controlled_fixture", "worker": "in-memory"},
            required_obligation=True,
        )
        lifecycle_facts.append(node_added)
        graph, materialization, materialization_pending = graph.begin_materialization(
            expected_graph_version=graph.version,
            node_id="node-phase2-e2e",
            create_command_id="materialize-task-phase2-e2e",
        )
        lifecycle_facts.append(materialization_pending)
        graph, materialized = graph.finish_materialization(
            expected_graph_version=graph.version,
            node_id="node-phase2-e2e",
            created=True,
            canonical_request_hash=materialization.request_hash,
        )
        lifecycle_facts.append(materialized)
        self.assertEqual(graph.closing_blockers, ())

        process, step, process_planned = ProcessManager(
            "process-dispatch-phase2-e2e", "12" * 32
        ).plan_step(
            source_event_hash=self._fact_hash(materialized),
            action="schedule-and-dispatch",
            payload={"task_id": "task-phase2-e2e"},
        )
        lifecycle_facts.extend(process_planned)
        process = ProcessManager.rebuild(
            process.process_id, process.definition_hash, process.journal_facts
        )
        self.assertEqual(process.pending_step, step)
        process, process_outcome = process.reconcile_outcome(
            lambda command_id, request_hash: CommandResult(
                CommandStatus.COMMITTED,
                command_id,
                request_hash,
                canonical_outcome_ref="13" * 32,
            )
        )
        lifecycle_facts.extend(process_outcome)

        frontier = FrontierRef("journal-phase2-e2e", 1, "local", 1, "14" * 32)
        decision = Scheduler().decide(
            (
                TaskCandidate(
                    "task-phase2-e2e", True, True, True, True, True, True, True,
                    100, 0, {"task": 1, "run": run.stream_version, "graph": graph.version},
                ),
            ),
            source_frontier=frontier,
            policy_hash="15" * 32,
        )
        decision_fact = {
            "schema": "SCHEDULER_DECISION_V1",
            "decision_id": decision.decision_id,
            "decision_commitment": decision.commitment,
            "ordered_attempts": list(decision.ordered_attempts),
        }
        lifecycle_facts.append(decision_fact)
        dispatcher = Dispatcher()
        dispatcher.register_authoritative_decision(
            decision, canonical_decision_ref=self._fact_hash(decision_fact)
        )
        worker = FixtureWorker()
        dispatch_state, tasks = dispatcher.dispatch_next(
            decision.decision_id,
            {"task-phase2-e2e": TaskAggregate("task-phase2-e2e", create_request_hash)},
            commit_claim=lambda _task_id, event: self._fact_hash(event),
            worker=worker,
        )
        lifecycle_facts.extend(dispatch_state.events)
        attempt = tasks["task-phase2-e2e"].active_attempt
        self.assertIsNotNone(attempt)

        # Lost dispatch ACK: rebuilding the dispatcher and reissuing the same
        # frozen decision reuses the exact Claim command and fencing token.
        recovered_dispatcher = Dispatcher()
        recovered_dispatcher.register_authoritative_decision(
            decision, canonical_decision_ref=self._fact_hash(decision_fact)
        )
        recovered_state, recovered_tasks = recovered_dispatcher.dispatch_next(
            decision.decision_id,
            tasks,
            commit_claim=lambda _task_id, event: self._fact_hash(event),
            worker=FixtureWorker(),
        )
        self.assertEqual(
            recovered_tasks["task-phase2-e2e"].active_attempt.fencing_token,
            attempt.fencing_token,
        )
        self.assertEqual(recovered_state.events[-1]["fencing_token"], attempt.fencing_token)

        timer_service = TimerService()
        timer, timer_scheduled = timer_service.schedule(
            timer_id="timer-phase2-e2e",
            target_id=attempt.task_attempt_id,
            purpose="claim-expiry",
            deadline_utc="2026-07-13T00:01:00Z",
            sample=ClockSample("2026-07-13T00:00:00Z", 100.0, 0.1),
        )
        lifecycle_facts.append(timer_scheduled)
        timer_service = TimerService.rebuild(timer_service.journal_facts)
        rebuilt_timer = timer_service.timers[timer.timer_id]
        self.assertEqual(rebuilt_timer.target_command_id, timer.target_command_id)

        artifact_hash = self._fact_hash({"fixture_result": "accepted"})
        task, submitted = recovered_tasks["task-phase2-e2e"].submit(
            attempt.fencing_token, artifact_hash
        )
        lifecycle_facts.append(submitted)
        task, accepted = task.accept(
            attempt.fencing_token, artifact_hash=artifact_hash, policy_hash="16" * 32
        )
        lifecycle_facts.append(accepted)
        self.assertEqual(task.state.value, "COMPLETED")
        self.assertEqual(worker.external_calls, 0)

        run, closing = run.begin_closing(expected_stream_version=run.stream_version)
        lifecycle_facts.append(closing)
        terminal_projection = TerminalEligibilityProjection.empty(run.run_id)
        terminal_facts = AuthoritativeTerminalFacts(
            blocker_refs={kind: () for kind in BlockerKind},
            cancellation_requested_ref=None,
            failure_refs=(),
            required_obligations_complete_ref=self._fact_hash(accepted),
            policy_hash="17" * 32,
        )
        terminal_decision = full_validate(terminal_projection, run, terminal_facts)
        run, terminal_event = apply_terminal_decision(run, terminal_decision)
        lifecycle_facts.append(terminal_event)
        self.assertEqual(run.state, RunState.SUCCEEDED)

        auth = JournalAuthProvider(InMemoryKeyProvider())
        journal = LocalJournal.open(
            self.home,
            auth,
            journal_id="journal-phase2-e2e",
            namespace_kind="controlled_fixture",
        )
        events = tuple(
            EventEnvelope(
                f"phase2-e2e-event-{index}",
                str(fact["schema"]).lower(),
                "tenant-phase2-e2e",
                "run-phase2-e2e",
                0,
                0,
                "2026-07-13T00:00:00Z",
                fact,
            )
            for index, fact in enumerate(lifecycle_facts, start=1)
        )
        command = CommandEnvelope(
            "phase2-e2e-lifecycle",
            "tenant-phase2-e2e",
            "run-phase2-e2e",
            "phase2-e2e-lifecycle",
            "phase2-e2e-fixture",
            "2026-07-13T00:00:00Z",
            {"fact_count": len(events)},
        )
        receipt = journal.append(command, 0, events)
        committed = tuple(journal.iter_events())
        event_hashes = tuple(event.event_hash for event in committed)
        journal.close()
        recovered_journal = LocalJournal.open(
            self.home,
            auth,
            journal_id="journal-phase2-e2e",
            namespace_kind="controlled_fixture",
        )
        self.assertEqual(tuple(event.event_hash for event in recovered_journal.iter_events()), event_hashes)
        self.assertEqual(
            recovered_journal.query_command(command.command_id, command.command_request_hash).canonical_outcome_ref,
            receipt.transaction_hash,
        )
        recovered_journal.close()

        def build_projection(path: Path):
            connection = open_projection(path)

            def handle_decision(conn, event):
                project_outbox(conn, decision, source_position=event.position)

            def handle_timer(conn, event):
                conn.execute(
                    "INSERT INTO durable_timer_candidates VALUES(?,?,?,?,?)",
                    (
                        timer.timer_id,
                        timer.deadline_utc,
                        timer.target_command_id,
                        event.position,
                        "SCHEDULED",
                    ),
                )

            def handle_terminal(conn, event):
                for kind in BlockerKind:
                    conn.execute(
                        "INSERT INTO terminal_eligibility_counts VALUES(?,?,0,?)",
                        (run.run_id, kind.value, event.position),
                    )

            ProjectionRunner(
                connection,
                {
                    "scheduler_decision_v1": handle_decision,
                    "durable_timer_scheduled_v1": handle_timer,
                    "run_terminal_v1": handle_terminal,
                },
            ).apply_batch(committed)
            return connection

        first_projection = build_projection(self.home / "projection-first.sqlite")
        rebuilt_projection = build_projection(self.home / "projection-rebuilt.sqlite")
        try:
            self.assertEqual(
                self._semantic_projection(first_projection),
                self._semantic_projection(rebuilt_projection),
            )
        finally:
            first_projection.close()
            rebuilt_projection.close()


if __name__ == "__main__": unittest.main()
