from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import FrontierRef
from sitina.projections.schema import open_projection
from sitina.protocols.tasks import TaskAggregate
from sitina.scheduling.dispatcher import DecisionState, DispatchError, Dispatcher, FixtureWorker, project_outbox
from sitina.scheduling.scheduler import Scheduler, TaskCandidate


def decision(task_ids=("task-1",)):
    candidates = [TaskCandidate(task_id, True, True, True, True, True, True, True, 10, 0, {"task": 1}) for task_id in task_ids]
    return Scheduler().decide(candidates, source_frontier=FrontierRef("journal-shadow-1", 1, "local", 1, "11" * 32), policy_hash="22" * 32)


class DispatchOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); self.connection = open_projection(self.home / "projection.sqlite")

    def tearDown(self) -> None:
        self.connection.close(); shutil.rmtree(self.home)

    def test_sqlite_only_status_cannot_dispatch(self) -> None:
        selected = decision(); project_outbox(self.connection, selected, source_position=1)
        with self.assertRaises(DispatchError): Dispatcher().dispatch_next(selected.decision_id, {"task-1": TaskAggregate("task-1", "33" * 32)}, commit_claim=lambda *_: "44" * 32, worker=FixtureWorker())

    def test_task_claim_commits_before_fixture_worker_receives_work(self) -> None:
        selected = decision(); dispatcher = Dispatcher(); dispatcher.register_authoritative_decision(selected, canonical_decision_ref="33" * 32)
        order = []; worker = FixtureWorker(); original = worker.receive
        def commit(task_id, event): order.append("commit"); return "44" * 32
        def receive(**kwargs): order.append("worker"); original(**kwargs)
        worker.receive = receive
        state, tasks = dispatcher.dispatch_next(selected.decision_id, {"task-1": TaskAggregate("task-1", "55" * 32)}, commit_claim=commit, worker=worker)
        self.assertEqual(order, ["commit", "worker"]); self.assertEqual(state.state, DecisionState.CONSUMED); self.assertIsNotNone(tasks["task-1"].active_attempt)
        self.assertEqual(worker.external_calls, 0)

    def test_cas_conflict_follows_frozen_next_candidate_policy(self) -> None:
        selected = decision(("task-1", "task-2")); dispatcher = Dispatcher(); dispatcher.register_authoritative_decision(selected, canonical_decision_ref="33" * 32)
        task1, _, _ = TaskAggregate("task-1", "55" * 32).claim(claim_command_id="other-claim", lease_expires_at="2099-01-01T00:00:00Z")
        state, _ = dispatcher.dispatch_next(selected.decision_id, {"task-1": task1, "task-2": TaskAggregate("task-2", "66" * 32)}, commit_claim=lambda *_: "44" * 32, worker=FixtureWorker())
        self.assertEqual(state.state, DecisionState.CONSUMED); self.assertEqual(state.events[0]["frozen_next_action"], "NEXT_CANDIDATE"); self.assertEqual(state.events[-1]["task_id"], "task-2")

    def test_closing_invalidates_old_decision(self) -> None:
        selected = decision(); dispatcher = Dispatcher(); dispatcher.register_authoritative_decision(selected, canonical_decision_ref="33" * 32)
        dispatcher.invalidate_by_closing(selected.decision_id, closing_ref="44" * 32)
        with self.assertRaises(DispatchError): dispatcher.dispatch_next(selected.decision_id, {"task-1": TaskAggregate("task-1", "55" * 32)}, commit_claim=lambda *_: "66" * 32, worker=FixtureWorker())

    def test_lost_ack_recovery_reuses_same_claim_command_and_fence(self) -> None:
        selected = decision(); task = TaskAggregate("task-1", "55" * 32); dispatcher = Dispatcher(); dispatcher.register_authoritative_decision(selected, canonical_decision_ref="33" * 32)
        state, tasks = dispatcher.dispatch_next(selected.decision_id, {"task-1": task}, commit_claim=lambda *_: "44" * 32, worker=FixtureWorker())
        first = tasks["task-1"].active_attempt
        recovered = Dispatcher(); recovered.register_authoritative_decision(selected, canonical_decision_ref="33" * 32); worker = FixtureWorker()
        _, replayed = recovered.dispatch_next(selected.decision_id, tasks, commit_claim=lambda *_: "44" * 32, worker=worker)
        self.assertEqual(replayed["task-1"].active_attempt.fencing_token, first.fencing_token)


if __name__ == "__main__": unittest.main()
