from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection


class BlackboardProjectionTests(unittest.TestCase):
    def event(self, position: int, schema: str, payload: dict) -> EventEnvelope:
        return EventEnvelope(
            f"event-blackboard-{position}",
            "blackboard." + schema.lower(),
            "tenant-1",
            "blackboard/doc-projection",
            position,
            position,
            "2026-07-16T00:00:00Z",
            {"schema": schema, "run_id": "run-projection", **payload},
        )

    def test_rebuild_materializes_full_version_conflict_merge_and_read_state(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        try:
            events = (
                self.event(1, "BLACKBOARD_DOCUMENT_CREATED_V1", {
                    "document_id": "doc-projection", "namespace": "FACTS", "schema_id": "sitina.blackboard.document",
                    "schema_version": 1, "current_version": 0, "current_hash": "10" * 32,
                    "classification": "INTERNAL", "writer_policy_hash": "11" * 32, "merge_policy_hash": "12" * 32,
                }),
                self.event(2, "BLACKBOARD_PATCH_COMMITTED_V1", {
                    "document_id": "doc-projection", "base_version": 0, "base_hash": "10" * 32,
                    "committed_version": 1, "committed_hash": "20" * 32, "patch_ref": "cas:" + "21" * 32,
                    "patch_hash": "22" * 32, "writer_agent_id": "agent-a", "writer_fence": "23" * 32,
                }),
                self.event(3, "BLACKBOARD_PATCH_CONFLICT_V1", {
                    "conflict_id": "conflict-1", "document_id": "doc-projection", "attempted_base_version": 0,
                    "attempted_base_hash": "10" * 32, "canonical_version": 1, "canonical_hash": "20" * 32,
                    "patch_hash": "30" * 32,
                }),
                self.event(4, "BLACKBOARD_MERGE_PROPOSAL_SUBMITTED_V1", {"conflict_id": "conflict-1", "merge_id": "merge-1"}),
                self.event(5, "BLACKBOARD_MERGE_REVIEWED_V1", {"conflict_id": "conflict-1", "review_id": "review-1"}),
                self.event(6, "BLACKBOARD_MERGE_DECISION_V1", {"conflict_id": "conflict-1", "decision_id": "decision-1"}),
                self.event(7, "BLACKBOARD_CONFLICT_RESOLVED_V1", {
                    "conflict_id": "conflict-1", "decision_id": "decision-1", "resolved_version": 2, "resolved_hash": "40" * 32,
                }),
                self.event(8, "BLACKBOARD_PATCH_COMMITTED_V1", {
                    "document_id": "doc-projection", "base_version": 1, "base_hash": "20" * 32,
                    "committed_version": 2, "committed_hash": "40" * 32, "patch_ref": "cas:" + "41" * 32,
                    "patch_hash": "42" * 32, "writer_agent_id": "agent-merge", "writer_fence": "43" * 32,
                    "resolution_conflict_id": "conflict-1",
                }),
                self.event(9, "BLACKBOARD_DOCUMENT_READ_V1", {
                    "read_id": "read-n2", "document_id": "doc-projection", "reader_agent_id": "agent-downstream",
                    "read_version": 2, "read_hash": "40" * 32,
                }),
            )
            for event in events:
                apply_production_event(connection, event)
            document = connection.execute(
                """SELECT current_version,current_hash,last_writer_id,object_ref
                   FROM blackboard_documents WHERE run_id='run-projection' AND document_id='doc-projection'"""
            ).fetchone()
            self.assertEqual(document, (2, "40" * 32, "agent-merge", "cas:" + "41" * 32))
            versions = connection.execute(
                "SELECT version,document_hash FROM blackboard_versions WHERE document_id='doc-projection' ORDER BY version"
            ).fetchall()
            self.assertEqual(versions, [(0, "10" * 32), (1, "20" * 32), (2, "40" * 32)])
            conflict = connection.execute(
                "SELECT conflict_state,merge_id,review_id,decision_id,resolved_version,resolved_hash FROM blackboard_conflicts WHERE conflict_id='conflict-1'"
            ).fetchone()
            self.assertEqual(conflict, ("RESOLVED", "merge-1", "review-1", "decision-1", 2, "40" * 32))
            read = connection.execute(
                "SELECT reader_agent_id,read_version,read_hash FROM blackboard_reads WHERE read_id='read-n2'"
            ).fetchone()
            self.assertEqual(read, ("agent-downstream", 2, "40" * 32))
        finally:
            connection.close()

    def test_rebuild_retains_reused_legacy_document_ids_and_derives_missing_metadata(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        try:
            for index, run_id in enumerate(("legacy-run-a", "legacy-run-b"), start=1):
                created = EventEnvelope(
                    f"event-legacy-created-{index}", "blackboard.document.created", "tenant-1",
                    f"run/{run_id}", 1, index * 10, "2026-07-16T00:00:00Z",
                    {
                        "schema": "BLACKBOARD_DOCUMENT_CREATED_V1", "run_id": run_id,
                        "document_id": "reused-document", "namespace": "DECISIONS", "version": 0,
                        "document_hash": ("1" if index == 1 else "2") * 64,
                        "classification": "internal", "policy_hash": "3" * 64,
                    },
                )
                patch = EventEnvelope(
                    f"event-legacy-patch-{index}", "blackboard.patch.committed", "tenant-1",
                    f"run/{run_id}", 2, index * 10 + 1, "2026-07-16T00:00:01Z",
                    {
                        "schema": "BLACKBOARD_PATCH_COMMITTED_V1", "run_id": run_id,
                        "document_id": "reused-document", "base_version": 0,
                        "base_hash": ("1" if index == 1 else "2") * 64,
                        "committed_version": 1, "committed_hash": ("4" if index == 1 else "5") * 64,
                        "fact_hash": ("6" if index == 1 else "7") * 64,
                        "actor_id": f"legacy-agent-{index}", "fencing_token": "8" * 64,
                    },
                )
                apply_production_event(connection, created)
                apply_production_event(connection, patch)
            rows = connection.execute(
                """SELECT run_id,current_version,current_hash FROM blackboard_documents
                   WHERE document_id='reused-document' ORDER BY run_id"""
            ).fetchall()
            self.assertEqual(rows, [
                ("legacy-run-a", 1, "4" * 64),
                ("legacy-run-b", 1, "5" * 64),
            ])
            versions = connection.execute(
                """SELECT run_id,version,patch_hash FROM blackboard_versions
                   WHERE document_id='reused-document' AND version=1 ORDER BY run_id"""
            ).fetchall()
            self.assertEqual(versions, [
                ("legacy-run-a", 1, "6" * 64),
                ("legacy-run-b", 1, "7" * 64),
            ])
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
