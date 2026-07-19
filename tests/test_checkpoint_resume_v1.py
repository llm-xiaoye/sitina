from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.orchestrator.checkpoint_resume import (
    CheckpointResumeError,
    FRONTIER_SPECS,
    declared_stream_heads_match,
    finalize_checkpoint_manifest,
    verify_checkpoint_manifest,
)
from sitina.orchestrator.true_multi_agent_runtime import stable_hash
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection
from sitina.scheduling.processes import ProcessManager, ProcessState


def snapshot(kind: str) -> dict[str, object]:
    spec = next(item for item in FRONTIER_SPECS if item.frontier_kind == kind)
    value: dict[str, object] = {
        "frontier_kind": spec.frontier_kind,
        "protocol_kind": spec.protocol_kind,
        "protocol_state": spec.protocol_state,
        "protocol_id": "protocol-" + kind.lower().replace("_", "-"),
        "obligation_id": "obligation-" + kind.lower().replace("_", "-"),
    }
    value["state_hash"] = stable_hash("TEST_RESTART_FRONTIER", value)
    return value


def manifest(kind: str = "PROPOSAL_REVIEW_PENDING") -> dict[str, object]:
    command_id = "process-command-" + "1" * 64
    return finalize_checkpoint_manifest(
        {
            "schema": "SITINA_LIVE_CHECKPOINT_MANIFEST_V1",
            "checkpoint_id": "checkpoint-test",
            "run_id": "run-test",
            "journal_id": "journal-test",
            "epoch": 1,
            "genesis_hash": "2" * 64,
            "validated_through_position": 7,
            "validated_through_hash": "3" * 64,
            "stream_heads": {"run-test": {"stream_version": 1, "position": 7}},
            "active_protocol_instances": [],
            "process_manager_states": [
                {
                    "process_id": "process-test",
                    "definition_hash": "4" * 64,
                    "generation": 1,
                    "state": "WAITING_OUTCOME",
                    "step_count": 0,
                    "max_steps": 8,
                    "visited_transition_hashes": [],
                    "pending_command_id": command_id,
                    "pending_request_hash": "5" * 64,
                    "pending_transition_hash": "6" * 64,
                }
            ],
            "pending_commands": [
                {"command_id": command_id, "request_hash": "5" * 64, "action": "resume", "step_number": 1}
            ],
            "command_ids": [command_id],
            "task_claims": [],
            "lease_ids": [],
            "fencing_tokens": [],
            "blackboard_versions": [],
            "proposal_review_handoff_generations": {},
            "effect_attempt_states": [],
            "outcome_exposure_states": [],
            "obligation_states": {"obligation-test": False},
            "cas_refs": [],
            "frontier_snapshot": snapshot(kind),
            "frontier_stream_id": "restart-frontier/run-test/1",
            "provider_send_count": 3,
            "config_hash": "7" * 64,
            "policy_hash": "8" * 64,
            "code_fingerprint": "9" * 64,
            "old_process_pid": 100,
        }
    )


def event(position: int, schema: str, payload: dict[str, object]) -> EventEnvelope:
    return EventEnvelope(
        f"event-{position}",
        "checkpoint.test",
        "tenant-test",
        "checkpoint/test",
        position,
        position,
        "2026-07-16T00:00:00Z",
        {"schema": schema, "run_id": "run-test", **payload},
        event_hash=f"{position:064x}",
        journal_auth_key_id="journal-key-test",
        journal_auth_tag=f"{position + 100:064x}",
    )


class CheckpointManifestTests(unittest.TestCase):
    def test_all_eight_frontiers_are_formal_and_manifest_valid(self) -> None:
        self.assertEqual(len(FRONTIER_SPECS), 8)
        for spec in FRONTIER_SPECS:
            with self.subTest(frontier=spec.frontier_kind):
                value = manifest(spec.frontier_kind)
                verify_checkpoint_manifest(value)

    def test_manifest_tampering_fails_closed(self) -> None:
        value = manifest()
        value["provider_send_count"] = 4
        with self.assertRaisesRegex(CheckpointResumeError, "hash mismatch"):
            verify_checkpoint_manifest(value)

    def test_pending_process_identity_rebuilds_without_cache(self) -> None:
        manager = ProcessManager("process-restart-test", "a" * 64, max_steps=8)
        manager, step, facts = manager.plan_step(
            source_event_hash="b" * 64,
            action="resume-review",
            payload={"proposal": "p1"},
        )
        rebuilt = ProcessManager.rebuild("process-restart-test", "a" * 64, facts, max_steps=8)
        self.assertEqual(rebuilt.state, ProcessState.WAITING_OUTCOME)
        self.assertEqual(rebuilt.pending_step, step)
        self.assertEqual(rebuilt.step_count, manager.step_count)
        self.assertEqual(rebuilt.visited_transition_hashes, manager.visited_transition_hashes)

    def test_runtime_stream_subset_survives_projection_compaction(self) -> None:
        declared = {
            "run/run-test": {"stream_version": 7, "position": 90},
            "runtime/features/test": {"stream_version": 2, "position": 12},
        }
        canonical = {
            **declared,
            "unrelated/full-journal-stream": {"stream_version": 99, "position": 89},
        }
        self.assertTrue(declared_stream_heads_match(canonical, declared))
        self.assertFalse(declared_stream_heads_match(canonical, {}))
        self.assertFalse(
            declared_stream_heads_match(
                canonical,
                {**declared, "missing/runtime-stream": {"stream_version": 1, "position": 1}},
            )
        )
        changed = {**declared, "run/run-test": {"stream_version": 8, "position": 91}}
        self.assertFalse(declared_stream_heads_match(canonical, changed))


class CheckpointProjectionTests(unittest.TestCase):
    def test_projection_rebuilds_checkpoint_and_matrix_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            connection = open_projection(Path(directory) / "projection.sqlite")
            apply_production_event(
                connection,
                event(
                    1,
                    "CHECKPOINT_MANIFEST_PUBLISHED_V1",
                    {
                        "checkpoint_id": "checkpoint-test",
                        "frontier_kind": "PROPOSAL_REVIEW_PENDING",
                        "validated_through_position": 1,
                        "manifest_ref": "cas:" + "a" * 64,
                        "manifest_hash": "b" * 64,
                        "old_process_pid": 100,
                        "pending_command_id": "process-command-test",
                        "provider_send_count_before": 3,
                    },
                ),
            )
            apply_production_event(
                connection,
                event(
                    2,
                    "CHECKPOINT_PROCESS_RECONSTRUCTED_V1",
                    {
                        "checkpoint_id": "checkpoint-test",
                        "new_process_pid": 200,
                        "pending_command_id": "process-command-test",
                        "restored_protocol_state": "PROPOSAL_SUBMITTED_REVIEW_PENDING",
                        "restored_lease_id": None,
                        "restored_fencing_token_hash": None,
                        "restored_blackboard_version": 4,
                        "restored_blackboard_hash": "c" * 64,
                    },
                ),
            )
            apply_production_event(
                connection,
                event(
                    3,
                    "CHECKPOINT_RESUME_COMPLETED_V1",
                    {
                        "checkpoint_id": "checkpoint-test",
                        "new_process_pid": 200,
                        "pre_restart_head": 1,
                        "post_restart_head": 3,
                        "pending_command_id": "process-command-test",
                        "provider_send_count_before": 3,
                        "provider_send_count_after": 3,
                        "duplicate_provider_send_count": 0,
                        "restored_protocol_state": "PROPOSAL_SUBMITTED_REVIEW_PENDING",
                        "restored_lease_id": None,
                        "restored_fencing_token_hash": None,
                        "restored_blackboard_version": 4,
                        "restored_blackboard_hash": "c" * 64,
                        "resume_event_id": "event-resume",
                        "frontier_terminal_event_id": "event-frontier-terminal",
                    },
                ),
            )
            apply_production_event(
                connection,
                event(
                    4,
                    "CHECKPOINT_RESUME_MATRIX_COMPLETED_V1",
                    {
                        "checkpoint_count": 8,
                        "frontier_kinds": [item.frontier_kind for item in FRONTIER_SPECS],
                        "checkpoint_ids": [f"checkpoint-{index}" for index in range(8)],
                        "old_process_pid": 100,
                        "new_process_pids": list(range(200, 208)),
                        "distinct_process_boundaries": True,
                        "provider_send_count_before": 3,
                        "provider_send_count_after": 3,
                        "duplicate_provider_send_count": 0,
                        "same_pending_command_ids": True,
                        "journal_identity_preserved": True,
                        "projection_used_for_resume": False,
                        "process_cache_used_for_resume": False,
                        "legacy_reads": 0,
                        "acceptance_reads": 0,
                    },
                ),
            )
            row = connection.execute(
                "SELECT checkpoint_state,new_process_pid,provider_send_count_after,duplicate_provider_send_count "
                "FROM checkpoint_resume_runtime WHERE run_id='run-test' AND checkpoint_id='checkpoint-test'"
            ).fetchone()
            self.assertEqual(row, ("RESUMED_AND_CONTINUED", 200, 3, 0))
            matrix = connection.execute(
                "SELECT checkpoint_count,distinct_process_boundaries,duplicate_provider_send_count,legacy_reads,acceptance_reads "
                "FROM checkpoint_resume_matrix WHERE run_id='run-test'"
            ).fetchone()
            self.assertEqual(matrix, (8, 1, 0, 0, 0))
            connection.close()


if __name__ == "__main__":
    unittest.main()
