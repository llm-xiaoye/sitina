from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.journal.model import canonical_json_bytes
from sitina.protocols.blackboard import (
    Blackboard,
    BlackboardError,
    BlackboardNamespace,
    ConflictState,
    NamespacePolicy,
    PatchIntent,
)
from sitina.protocols.tasks import TaskAggregate
from sitina.security.key_provider import InMemoryKeyProvider


class BlackboardMVCCTests(unittest.TestCase):
    def board(
        self,
        *,
        inline_limit: int = 256,
        merge_policy: str = "APPEND_ONLY",
        cas_required: bool = False,
    ) -> Blackboard:
        policies = {
            BlackboardNamespace.FACTS: NamespacePolicy(
                schema_hash="11" * 32,
                writer_capabilities=("facts-write",),
                evidence_required=True,
                merge_policy=merge_policy,
                classification="INTERNAL",
                inline_limit=inline_limit,
                cas_required=cas_required,
            )
        }
        return Blackboard(policies)

    def claimed_task(self):
        task, attempt, _ = TaskAggregate("task-1", "21" * 32).claim(claim_command_id="claim-1", lease_expires_at="2099-01-01T00:00:00Z")
        return task, attempt

    def test_namespace_policy_schema_writer_and_evidence_are_enforced(self) -> None:
        board = self.board(); document, _ = board.create("doc-1", BlackboardNamespace.FACTS)
        task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 0, document.document_hash, {"fact": "x"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("31" * 32,), ("doc-1@0",))
        result = board.patch(intent, task=task)
        self.assertEqual(result.document.version, 1)
        self.assertEqual(result.event["schema_hash"], "11" * 32)
        self.assertEqual(result.event["evidence_refs"], ["31" * 32])
        with self.assertRaises(BlackboardError):
            board.patch(intent.__class__(**{**intent.__dict__, "writer_capabilities": ("notes-write",)}), task=task)

    def test_stale_base_returns_conflict_without_document_mutation(self) -> None:
        board = self.board(); document, _ = board.create("doc-1", BlackboardNamespace.FACTS); task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 0, document.document_hash, {"fact": "x"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("31" * 32,), ())
        first = board.patch(intent, task=task)
        stale = board.patch(intent, task=task)
        self.assertIsNone(stale.event)
        self.assertEqual(stale.document, first.document)
        self.assertEqual(stale.conflict["schema"], "BLACKBOARD_PATCH_CONFLICT_V1")

    def test_task_patch_requires_current_attempt_and_fence(self) -> None:
        board = self.board(); document, _ = board.create("doc-1", BlackboardNamespace.FACTS); task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 0, document.document_hash, {"fact": "x"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, "99" * 32, ("31" * 32,), ())
        with self.assertRaises(BlackboardError):
            board.patch(intent, task=task)

    def test_agent_read_refs_write_intents_and_committed_versions_are_recorded(self) -> None:
        board = self.board(); document, _ = board.create("doc-1", BlackboardNamespace.FACTS); task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 0, document.document_hash, {"fact": "x"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("31" * 32,), ("other-doc@4",))
        result = board.patch(intent, task=task)
        self.assertEqual(result.event["read_refs"], ["other-doc@4"])
        self.assertEqual(result.event["base_version"], 0)
        self.assertEqual(result.event["committed_version"], 1)

    def test_conflict_blocks_only_explicit_dependent_obligations(self) -> None:
        board = self.board(); document, _ = board.create("doc-1", BlackboardNamespace.FACTS); board = board.declare_dependencies("obligation-a", ("doc-1",)); board = board.declare_dependencies("obligation-b", ("other",)); task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 99, document.document_hash, {"fact": "x"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("31" * 32,), ())
        conflict = board.patch(intent, task=task)
        self.assertEqual(conflict.blocked_obligations, ("obligation-a",))

    def test_large_or_secret_content_requires_published_object_and_projection_has_no_body(self) -> None:
        board = self.board(inline_limit=8); document, _ = board.create("doc-1", BlackboardNamespace.FACTS); task, attempt = self.claimed_task()
        intent = PatchIntent("doc-1", 0, document.document_hash, {"secret": "very-long-secret-value"}, "agent-1", ("facts-write",), "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("31" * 32,), ())
        with self.assertRaises(BlackboardError):
            board.patch(intent, task=task)
        home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        try:
            provider = InMemoryKeyProvider(); cas = LocalCAS.open(home, provider)
            encrypted = encrypt_object(canonical_json_bytes(dict(intent.patch)), provider, tenant_id="tenant-1")
            receipt = cas.publish_verified(encrypted)
            result = board.patch(intent, task=task, published_object_receipt=receipt)
            self.assertNotIn("patch", result.event)
            self.assertEqual(result.event["object_ref"], receipt.object_ref.reference_id)
            self.assertIsNone(result.document.inline_body)
        finally:
            shutil.rmtree(home)

    def test_full_stale_conflict_independent_merge_review_and_n_plus_two_read(self) -> None:
        board = self.board(merge_policy="ARBITRATION", cas_required=True)
        document, created = board.create("doc-merge", BlackboardNamespace.FACTS)
        board.declare_dependencies("obligation-dependent", ("doc-merge",))
        board.declare_dependencies("obligation-unrelated", ("other-doc",))
        task, attempt = self.claimed_task()
        read_a_document, read_a = board.read("doc-merge", agent_id="agent-a", read_paths=("/facts",))
        read_b_document, read_b = board.read("doc-merge", agent_id="agent-b", read_paths=("/facts",))
        self.assertEqual(read_a_document, read_b_document)
        self.assertEqual(read_a["read_version"], 0)
        self.assertEqual(read_b["read_hash"], document.document_hash)
        self.assertEqual(created["current_version"], 0)
        self.assertEqual(created["writer_policy_hash"], document.writer_policy_hash)
        self.assertEqual(created["merge_policy_hash"], document.merge_policy_hash)

        home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        try:
            provider = InMemoryKeyProvider()
            cas = LocalCAS.open(home, provider)

            def publish(patch: dict) -> object:
                return cas.publish_verified(
                    encrypt_object(
                        canonical_json_bytes(patch),
                        provider,
                        tenant_id="tenant-1",
                        purpose="blackboard-test-patch",
                    )
                )

            patch_a = {"fact": "branch-a", "source": "agent-a"}
            receipt_a = publish(patch_a)
            intent_a = PatchIntent(
                "doc-merge", 0, document.document_hash, patch_a, "agent-a", ("facts-write",),
                "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
                ("31" * 32,), (read_a["read_id"],), patch_ref=receipt_a.object_ref.reference_id,
                target_paths=("/facts",), merge_policy_hash=document.merge_policy_hash,
            )
            committed_a = board.patch(intent_a, task=task, published_object_receipt=receipt_a)
            self.assertEqual(committed_a.document.version, 1)
            self.assertNotIn("patch", committed_a.event)

            patch_b = {"fact": "branch-b", "source": "agent-b"}
            receipt_b = publish(patch_b)
            intent_b = PatchIntent(
                "doc-merge", 0, document.document_hash, patch_b, "agent-b", ("facts-write",),
                "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
                ("32" * 32,), (read_b["read_id"],), patch_ref=receipt_b.object_ref.reference_id,
                target_paths=("/facts",), merge_policy_hash=document.merge_policy_hash,
            )
            stale = board.patch(intent_b, task=task, published_object_receipt=receipt_b)
            self.assertEqual(stale.document.version, 1)
            self.assertEqual(stale.conflict["patch_ref"], receipt_b.object_ref.reference_id)
            self.assertFalse(stale.conflict["last_write_wins"])
            self.assertEqual(stale.blocked_obligations, ("obligation-dependent",))
            self.assertEqual(board.closing_blockers, ("obligation-dependent",))
            conflict_id = stale.conflict["conflict_id"]

            merge_patch = {"fact": ["branch-a", "branch-b"], "resolution": "reviewed-merge"}
            merge_receipt = publish(merge_patch)
            merge_event = board.submit_merge(
                conflict_id,
                merge_agent_id="agent-merge",
                merge_patch=merge_patch,
                merge_read_refs=(committed_a.document.document_hash, stale.conflict["patch_hash"]),
                published_object_receipt=merge_receipt,
            )
            review_event = board.review_merge(
                conflict_id,
                reviewer_agent_id="agent-reviewer",
                reviewed_merge_hash=merge_event["merge_patch_hash"],
                review_hash="41" * 32,
                rubric_hash="42" * 32,
                accepted=True,
            )
            merge_intent = PatchIntent(
                "doc-merge", 1, committed_a.document.document_hash, merge_patch, "agent-merge", ("facts-write",),
                "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
                (committed_a.event["patch_hash"], stale.conflict["patch_hash"]),
                (committed_a.document.document_hash, stale.conflict["patch_hash"]),
                patch_ref=merge_receipt.object_ref.reference_id,
                patch_hash=merge_event["merge_patch_hash"], target_paths=("/facts",),
                merge_policy_hash=document.merge_policy_hash,
            )
            resolution = board.resolve_conflict(
                conflict_id,
                decision_agent_id="agent-reviewer",
                merge_intent=merge_intent,
                task=task,
                published_object_receipt=merge_receipt,
            )
            self.assertEqual(review_event["review_id"], resolution.merge_decision["review_id"])
            self.assertEqual(resolution.document.version, 2)
            self.assertEqual(resolution.patch_committed["committed_version"], 2)
            self.assertEqual(board.conflicts[conflict_id].state, ConflictState.RESOLVED)
            self.assertEqual(board.closing_blockers, ())
            downstream, downstream_read = board.read(
                "doc-merge", agent_id="agent-downstream", read_paths=("/facts",),
                source_event_refs=(resolution.merge_decision["decision_id"],),
            )
            self.assertEqual(downstream.version, 2)
            self.assertEqual(downstream_read["read_hash"], resolution.document.document_hash)
        finally:
            shutil.rmtree(home)

    def test_merge_author_and_reviewer_independence_is_enforced(self) -> None:
        board = self.board(merge_policy="ARBITRATION")
        document, _ = board.create("doc-independent", BlackboardNamespace.FACTS)
        task, attempt = self.claimed_task()
        first = PatchIntent(
            "doc-independent", 0, document.document_hash, {"fact": "a"}, "agent-a", ("facts-write",),
            "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
            ("31" * 32,), (), merge_policy_hash=document.merge_policy_hash,
        )
        committed = board.patch(first, task=task)
        stale_intent = PatchIntent(
            "doc-independent", 0, document.document_hash, {"fact": "b"}, "agent-b", ("facts-write",),
            "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
            ("32" * 32,), (), merge_policy_hash=document.merge_policy_hash,
        )
        stale = board.patch(stale_intent, task=task)
        conflict_id = stale.conflict["conflict_id"]
        with self.assertRaises(BlackboardError):
            board.submit_merge(
                conflict_id, merge_agent_id="agent-a", merge_patch={"fact": "merged"},
                merge_read_refs=(committed.document.document_hash, stale.conflict["patch_hash"]),
            )
        merge = board.submit_merge(
            conflict_id, merge_agent_id="agent-merge", merge_patch={"fact": "merged"},
            merge_read_refs=(committed.document.document_hash, stale.conflict["patch_hash"]),
        )
        with self.assertRaises(BlackboardError):
            board.review_merge(
                conflict_id, reviewer_agent_id="agent-merge", reviewed_merge_hash=merge["merge_patch_hash"],
                review_hash="41" * 32, rubric_hash="42" * 32, accepted=True,
            )

    def test_versioned_append_only_policy_can_authorize_recorded_auto_rebase(self) -> None:
        board = self.board(merge_policy="APPEND_ONLY")
        document, _ = board.create("doc-append", BlackboardNamespace.FACTS)
        task, attempt = self.claimed_task()
        patch_a = {"operation": "append", "items": ["a"]}
        first = board.patch(
            PatchIntent(
                "doc-append", 0, document.document_hash, patch_a, "agent-a", ("facts-write",),
                "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
                ("31" * 32,), (), merge_policy_hash=document.merge_policy_hash,
            ),
            task=task,
        )
        patch_b = {"operation": "append", "items": ["b"]}
        stale = board.patch(
            PatchIntent(
                "doc-append", 0, document.document_hash, patch_b, "agent-b", ("facts-write",),
                "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
                ("32" * 32,), (), merge_policy_hash=document.merge_policy_hash,
            ),
            task=task,
        )
        rebased = PatchIntent(
            "doc-append", 1, first.document.document_hash, patch_b, "agent-b", ("facts-write",),
            "task-1", attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token,
            ("32" * 32,), (first.document.document_hash, stale.conflict["patch_hash"]),
            patch_hash=stale.conflict["patch_hash"], merge_policy_hash=document.merge_policy_hash,
        )
        resolution = board.auto_resolve_conflict(stale.conflict["conflict_id"], rebased_intent=rebased, task=task)
        self.assertEqual(resolution.document.version, 2)
        self.assertEqual(resolution.merge_decision["original_base_version"], 0)
        self.assertEqual(resolution.merge_decision["actual_merge_base_version"], 1)
        self.assertEqual(resolution.conflict_resolved["resolution"], "POLICY_PROVEN_AUTO_REBASE")


if __name__ == "__main__":
    unittest.main()
