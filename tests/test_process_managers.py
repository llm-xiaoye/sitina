from __future__ import annotations

import unittest

from sitina.commands.model import CommandResult, CommandStatus
from sitina.scheduling.processes import ProcessError, ProcessManager, ProcessStallDetected, ProcessState


class ProcessManagerTests(unittest.TestCase):
    def test_replaying_same_source_event_regenerates_identical_step_and_command_id(self) -> None:
        manager = ProcessManager("process-1", "11" * 32)
        manager, step, _ = manager.plan_step(source_event_hash="22" * 32, action="create-task", payload={"x": 1})
        replayed, duplicate, events = manager.plan_step(source_event_hash="22" * 32, action="create-task", payload={"x": 1})
        self.assertEqual((replayed, duplicate.command_id, events), (manager, step.command_id, ()))
        with self.assertRaises(ProcessError):
            manager.plan_step(source_event_hash="22" * 32, action="create-task", payload={"x": 999})

    def test_pending_outcome_reconciles_by_same_command_id_and_hash(self) -> None:
        manager, step, _ = ProcessManager("process-1", "11" * 32).plan_step(source_event_hash="22" * 32, action="claim", payload={})
        calls = []
        def unknown(command_id, request_hash): calls.append((command_id, request_hash)); return CommandResult(CommandStatus.UNKNOWN, command_id, request_hash)
        unchanged, _ = manager.reconcile_outcome(unknown); self.assertEqual(unchanged, manager)
        def committed(command_id, request_hash): return CommandResult(CommandStatus.COMMITTED, command_id, request_hash, canonical_outcome_ref="33" * 32)
        advanced, _ = manager.reconcile_outcome(committed)
        self.assertEqual(advanced.state, ProcessState.RUNNING); self.assertEqual(advanced.step_count, 1); self.assertEqual(calls, [(step.command_id, step.request_hash)])

    def test_repeated_transition_hash_and_max_steps_stall(self) -> None:
        manager = ProcessManager("process-1", "11" * 32, max_steps=1)
        manager, _, _ = manager.plan_step(source_event_hash="22" * 32, action="a", payload={})
        manager, _ = manager.reconcile_outcome(lambda c, h: CommandResult(CommandStatus.COMMITTED, c, h))
        with self.assertRaises(ProcessStallDetected) as captured:
            manager.plan_step(source_event_hash="33" * 32, action="b", payload={})
        self.assertEqual(captured.exception.manager.state, ProcessState.STALLED)
        self.assertEqual(captured.exception.fact["schema"], "PROCESS_STALL_DETECTED_V1")
        rebuilt = ProcessManager.rebuild(
            manager.process_id,
            manager.definition_hash,
            captured.exception.manager.journal_facts,
            max_steps=manager.max_steps,
        )
        self.assertEqual(rebuilt.state, ProcessState.STALLED)

    def test_projection_deletion_cannot_lose_pending_work(self) -> None:
        manager, step, _ = ProcessManager("process-1", "11" * 32).plan_step(source_event_hash="22" * 32, action="dispatch", payload={})
        rebuilt = ProcessManager.rebuild("process-1", "11" * 32, manager.journal_facts)
        self.assertEqual(rebuilt.pending_step, step)
        self.assertEqual(rebuilt.state, ProcessState.WAITING_OUTCOME)


if __name__ == "__main__": unittest.main()
