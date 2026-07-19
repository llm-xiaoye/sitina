from __future__ import annotations

import datetime as dt
import json
import os
import random
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.journal.model import canonical_json_bytes
from sitina.protocols.blackboard import (
    Blackboard,
    BlackboardError,
    BlackboardNamespace,
    NamespacePolicy,
    PatchIntent,
)
from sitina.protocols.blackboard_state import BlackboardLimits
from sitina.protocols.tasks import TaskAggregate
from sitina.security.key_provider import InMemoryKeyProvider


ROOT = Path(__file__).resolve().parents[2]


class DeterministicClock:
    def __init__(self) -> None:
        self._index = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            value = dt.datetime(2026, 7, 19, 12, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=self._index)
            self._index += 1
        return value.isoformat().replace("+00:00", "Z")


def policies(*, shared_facts: bool = False, writable_paths: tuple[str, ...] = ("/",)) -> dict:
    return {
        BlackboardNamespace.FACTS: NamespacePolicy(
            schema_hash="11" * 32,
            writer_capabilities=("facts-write",),
            reader_capabilities=("facts-read",),
            evidence_required=False,
            merge_policy="APPEND_ONLY",
            classification="INTERNAL",
            inline_limit=4096,
            writable_paths=writable_paths,
            persistence_scope="PROJECT_SHARED" if shared_facts else "RUN_LOCAL",
        ),
        BlackboardNamespace.WORKING_NOTES: NamespacePolicy(
            schema_hash="12" * 32,
            writer_capabilities=("notes-write",),
            reader_capabilities=("notes-read",),
            evidence_required=False,
            merge_policy="APPEND_ONLY",
            classification="INTERNAL",
            inline_limit=4096,
            persistence_scope="RUN_LOCAL",
        ),
    }


def board(
    *,
    tenant_id: str = "tenant-1",
    run_id: str = "run-1",
    shared_facts: bool = False,
    writable_paths: tuple[str, ...] = ("/",),
    limits: BlackboardLimits | None = None,
) -> Blackboard:
    return Blackboard(
        policies(shared_facts=shared_facts, writable_paths=writable_paths),
        tenant_id=tenant_id,
        run_id=run_id,
        limits=limits,
        clock=DeterministicClock(),
    )


def claimed_task() -> tuple[TaskAggregate, object]:
    task, attempt, _ = TaskAggregate("task-1", "21" * 32).claim(
        claim_command_id="claim-1",
        lease_expires_at="2099-01-01T00:00:00Z",
        holder_agent_id="agent-owner",
    )
    return task, attempt


def patch_intent(
    document,
    attempt,
    payload: dict,
    *,
    actor: str = "agent-a",
    namespace: BlackboardNamespace = BlackboardNamespace.FACTS,
    patch_schema: str = "sitina.blackboard.patch/v1",
    target_paths: tuple[str, ...] = (),
    causation_id: str | None = None,
) -> PatchIntent:
    capability = "facts-write" if namespace is BlackboardNamespace.FACTS else "notes-write"
    return PatchIntent(
        document.document_id,
        document.version,
        document.document_hash,
        payload,
        actor,
        (capability,),
        "task-1",
        attempt.task_attempt_id,
        attempt.claim_generation,
        attempt.fencing_token,
        (),
        (),
        patch_schema=patch_schema,
        target_paths=target_paths,
        merge_policy_hash=document.merge_policy_hash,
        causation_id=causation_id,
    )


def structured(notes: str, data: dict, *tags: str) -> dict:
    return {
        "schema": "SITINA_BLACKBOARD_BODY_V1",
        "schema_version": 1,
        "notes": notes,
        "data": data,
        "tags": list(tags),
    }


class BlackboardStateManagementTests(unittest.TestCase):
    def test_b01_two_agents_same_version_only_one_commits_and_conflict_is_retryable(self) -> None:
        value = board()
        initial, _ = value.create("doc-race", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        barrier = threading.Barrier(2)
        results = []

        def write(actor: str) -> None:
            intent = patch_intent(initial, attempt, {"actor": actor}, actor=actor)
            barrier.wait()
            results.append(value.patch(intent, task=task))

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(write, actor) for actor in ("agent-a", "agent-b")]
            for future in futures:
                future.result()
        committed = [result for result in results if result.event is not None]
        conflicted = [result for result in results if result.conflict is not None]
        self.assertEqual((len(committed), len(conflicted)), (1, 1))
        self.assertEqual(value.documents["doc-race"].version, 1)
        self.assertFalse(conflicted[0].conflict["document_stream_mutated"])
        retry = patch_intent(value.documents["doc-race"], attempt, {"actor": "retry"}, actor="agent-retry")
        self.assertEqual(value.patch(retry, task=task).document.version, 2)

    def test_b02_position_version_snapshot_restore_damage_and_monotonic_recovery(self) -> None:
        value = board()
        document, _ = value.create("doc-snapshot", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        first = value.patch(patch_intent(document, attempt, {"value": 1}), task=task)
        first_position = first.event["position"]
        second = value.patch(patch_intent(first.document, attempt, {"value": 2}), task=task)
        snapshot = value.snapshot(position=first_position, versions={"doc-snapshot": 1})
        self.assertTrue(snapshot.read_only)
        with self.assertRaises(FrozenInstanceError):
            snapshot.position = 0  # type: ignore[misc]
        with self.assertRaises(TypeError):
            snapshot.documents[0]["version"] = 0  # type: ignore[index]
        recovered = board()
        recovered.restore_snapshot(snapshot)
        self.assertEqual(recovered.documents["doc-snapshot"].version, 1)
        resumed = recovered.patch(
            patch_intent(recovered.documents["doc-snapshot"], attempt, {"value": "recovered"}),
            task=task,
        )
        self.assertEqual(resumed.document.version, 2)
        self.assertEqual(second.document.version, 2)
        damaged = replace(snapshot, snapshot_hash="0" * 64)
        with self.assertRaises(BlackboardError):
            board().restore_snapshot(damaged)

    def test_b03_diff_records_actor_hashes_causation_and_redacts_sensitive_values(self) -> None:
        value = board()
        document, _ = value.create("doc-diff", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        payload = {"profile": {"password": "hunter2", "label": "safe"}}
        with tempfile.TemporaryDirectory(dir=os.environ["SITINA_HOME"]) as directory:
            (Path(directory) / ".sitina-bplus-disposable-v1").write_text("blackboard-diff-test\n", encoding="utf-8")
            provider = InMemoryKeyProvider()
            cas = LocalCAS.open(Path(directory), provider)
            receipt = cas.publish_verified(
                encrypt_object(canonical_json_bytes(payload), provider, tenant_id="tenant-1")
            )
            intent = replace(
                patch_intent(document, attempt, payload, causation_id="cause-1"),
                patch_ref=receipt.object_ref.reference_id,
            )
            result = value.patch(intent, task=task, published_object_receipt=receipt)
        event = result.event
        self.assertEqual(event["actor_id"], "agent-a")
        self.assertEqual(event["causation_id"], "cause-1")
        self.assertEqual(event["before_hash"], document.document_hash)
        self.assertEqual(event["after_hash"], result.document.document_hash)
        encoded = json.dumps(event, sort_keys=True)
        self.assertNotIn("hunter2", encoded)
        password_change = next(item for item in event["field_changes"] if item["path"].endswith("password"))
        self.assertTrue(password_change["sensitive_value_redacted"])
        self.assertEqual(password_change["after_commitment"], "REDACTED")
        self.assertEqual(value.verify_diff_replay("doc-diff"), (1, result.document.document_hash))

    def test_b04_capacity_warning_and_rejection_leave_original_state_unchanged(self) -> None:
        configured = BlackboardLimits.load(ROOT / "config/blackboard_limits.json")
        self.assertEqual(configured.max_total_bytes, 16 * 1024 * 1024)
        value = board(
            limits=BlackboardLimits(
                max_total_bytes=256,
                max_document_bytes=128,
                max_field_bytes=64,
                warning_ratio_millis=600,
            )
        )
        document, _ = value.create("doc-capacity", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        near = value.patch(patch_intent(document, attempt, {"text": "x" * 58}), task=task)
        self.assertTrue(near.event["capacity_warning"])
        self.assertEqual(value.journal_facts[-1]["schema"], "BLACKBOARD_CAPACITY_WARNING_V1")
        before = value.documents["doc-capacity"]
        with self.assertRaises(BlackboardError):
            value.patch(patch_intent(before, attempt, {"text": "x" * 80}), task=task)
        self.assertEqual(value.documents["doc-capacity"], before)
        rejection = value.journal_facts[-1]
        self.assertEqual(rejection["schema"], "BLACKBOARD_CAPACITY_REJECTED_V1")
        self.assertFalse(rejection["state_mutated"])

    def test_b05_restart_recovery_project_reuse_and_tenant_run_isolation(self) -> None:
        source = board(shared_facts=True)
        shared, _ = source.create("doc-project", BlackboardNamespace.FACTS)
        local, _ = source.create("doc-local", BlackboardNamespace.WORKING_NOTES)
        target = board(run_id="run-2", shared_facts=True)
        target.reuse_project_document(shared)
        self.assertIn("doc-project", target.documents)
        with self.assertRaises(BlackboardError):
            target.reuse_project_document(local)
        with self.assertRaises(BlackboardError):
            board(tenant_id="tenant-2", run_id="run-2", shared_facts=True).reuse_project_document(shared)
        snapshot = source.snapshot()
        restarted = board(shared_facts=True)
        restarted.restore_snapshot(snapshot)
        self.assertEqual(restarted.documents, source.documents)
        with self.assertRaises(BlackboardError):
            board(run_id="run-2", shared_facts=True).restore_snapshot(snapshot)

    def test_b06_structured_schema_notes_invalid_unknown_and_deterministic_upcast(self) -> None:
        value = board()
        document, _ = value.create("doc-schema", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        body = structured("human notes remain explicit", {"answer": 42}, "gold")
        result = value.patch(
            patch_intent(
                document,
                attempt,
                body,
                patch_schema="sitina.blackboard.patch/v2",
                target_paths=("/data/answer", "/notes"),
            ),
            task=task,
        )
        parsed = value.read_structured_body(result.document.inline_body)
        self.assertEqual(parsed.body.notes, "human notes remain explicit")
        self.assertEqual(parsed.body.data["answer"], 42)
        with self.assertRaises(BlackboardError):
            value.read_structured_body(body | {"unknown": True})
        with self.assertRaises(BlackboardError):
            value.read_structured_body({"schema": "SITINA_BLACKBOARD_BODY_V2"})
        legacy = {"schema": "SITINA_BLACKBOARD_BODY_V0", "text": "legacy note"}
        first = value.read_structured_body(legacy)
        second = value.read_structured_body(json.loads(json.dumps(legacy)))
        self.assertEqual(first, second)
        self.assertEqual(first.body.notes, "legacy note")
        self.assertTrue(first.upcast_audit["deterministic"])

    def test_b07_query_filters_stable_pagination_and_hidden_unauthorized_documents(self) -> None:
        value = board()
        task, attempt = claimed_task()
        for document_id, answer, tag in (("doc-a", 1, "red"), ("doc-b", 2, "blue")):
            document, _ = value.create(document_id, BlackboardNamespace.FACTS)
            value.patch(
                patch_intent(
                    document,
                    attempt,
                    structured("note", {"answer": answer}, tag),
                    patch_schema="sitina.blackboard.patch/v2",
                    target_paths=("/data/answer",),
                ),
                task=task,
            )
        first = value.query(
            agent_id="agent-reader",
            reader_capabilities=("facts-read",),
            namespace=BlackboardNamespace.FACTS,
            key="answer",
            limit=1,
        )
        self.assertEqual([item.document_id for item in first.documents], ["doc-a"])
        added, _ = value.create("doc-aa", BlackboardNamespace.FACTS)
        value.patch(
            patch_intent(
                added,
                attempt,
                structured("late", {"answer": 3}, "red"),
                patch_schema="sitina.blackboard.patch/v2",
                target_paths=("/data/answer",),
            ),
            task=task,
        )
        second = value.query(
            agent_id="agent-reader",
            reader_capabilities=("facts-read",),
            namespace=BlackboardNamespace.FACTS,
            key="answer",
            cursor=first.next_cursor,
            limit=1,
        )
        self.assertEqual([item.document_id for item in second.documents], ["doc-b"])
        tagged = value.query(
            agent_id="agent-reader",
            reader_capabilities=("facts-read",),
            tag="red",
            run_id="run-1",
            version=1,
        )
        self.assertEqual([item.document_id for item in tagged.documents], ["doc-a", "doc-aa"])
        hidden = value.query(agent_id="agent-without-capability")
        self.assertEqual(hidden.documents, ())

    def test_b08_capabilities_nested_aliases_paths_and_access_audits(self) -> None:
        value = board(writable_paths=("/data",))
        document, _ = value.create("doc-permission", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        allowed = value.patch(
            patch_intent(
                document,
                attempt,
                structured("", {"title": "allowed"}),
                patch_schema="sitina.blackboard.patch/v2",
                target_paths=("/data/title",),
            ),
            task=task,
        )
        self.assertEqual(allowed.document.version, 1)
        missing_capability = replace(
            patch_intent(allowed.document, attempt, {"title": "denied"}),
            writer_capabilities=("other-write",),
        )
        with self.assertRaises(BlackboardError):
            value.patch(missing_capability, task=task)
        protected = patch_intent(
            allowed.document,
            attempt,
            structured("", {"nested": {"riskLevel": "low"}}),
            patch_schema="sitina.blackboard.patch/v2",
            target_paths=("/data/nested/riskLevel",),
        )
        with self.assertRaises(BlackboardError):
            value.patch(protected, task=task)
        with self.assertRaises(BlackboardError):
            value.read("doc-permission", agent_id="agent-reader")
        read, _ = value.read(
            "doc-permission",
            agent_id="agent-reader",
            reader_capabilities=("facts-read",),
        )
        self.assertEqual(read.version, 1)
        denied = [event for event in value.journal_facts if event["schema"] == "BLACKBOARD_ACCESS_DENIED_V1"]
        self.assertEqual({event["reason"] for event in denied}, {"MISSING_WRITER_CAPABILITY", "PROTECTED_FIELD", "MISSING_READER_CAPABILITY"})

    def test_b09_recoverable_deduplicated_subscription_polling_and_slow_consumer(self) -> None:
        value = board()
        document, _ = value.create("doc-subscription", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        subscription = value.subscribe(
            "subscription-1",
            namespaces=(BlackboardNamespace.FACTS,),
            from_position=value.position,
            max_pending=2,
        )
        committed_events = []
        current = document
        for index in range(3):
            result = value.patch(patch_intent(current, attempt, {"index": index}), task=task)
            current = result.document
            committed_events.append(result.event)
        value.journal_facts.append(dict(committed_events[0]))
        first = value.poll_subscription("subscription-1")
        duplicate = value.poll_subscription("subscription-1")
        self.assertTrue(first.lagging)
        self.assertEqual(len(first.notifications), 2)
        self.assertEqual(first.notifications, duplicate.notifications)
        self.assertEqual(len({item.notification_id for item in first.notifications}), 2)
        value.acknowledge_subscription(
            "subscription-1",
            through_position=first.highest_position,
        )
        value.subscriptions.clear()
        value.rebuild_subscriptions(value.journal_facts)
        resumed = value.poll_subscription("subscription-1")
        self.assertFalse(resumed.lagging)
        self.assertEqual(len(resumed.notifications), 1)
        self.assertEqual(resumed.notifications[0].committed_version, 3)
        fallback = value.poll_changes(from_position=subscription.last_acked_position)
        self.assertEqual(len(fallback), 3)
        self.assertEqual(len({event["event_id"] for event in fallback}), 3)

    def test_b10_seeded_interleaving_crash_recovery_and_high_concurrency_are_repeatable(self) -> None:
        def scenario(seed: int, *, crash_after: int | None = None):
            value = board()
            initial, _ = value.create("doc-stress", BlackboardNamespace.FACTS)
            task, attempt = claimed_task()
            actors = [f"agent-{index}" for index in range(8)]
            random.Random(seed).shuffle(actors)
            stale = [patch_intent(initial, attempt, {"winner": actor}, actor=actor) for actor in actors]
            first = value.patch(stale[0], task=task)
            conflicts = [value.patch(intent, task=task) for intent in stale[1:]]
            self.assertTrue(all(result.conflict is not None for result in conflicts))
            for index, result in enumerate(conflicts, start=1):
                current = value.documents["doc-stress"]
                retry = patch_intent(
                    current,
                    attempt,
                    {"winner": actors[index]},
                    actor=actors[index],
                    causation_id=result.conflict["event_id"],
                )
                value.patch(retry, task=task)
                if crash_after == index:
                    snapshot = value.snapshot()
                    recovered = board()
                    recovered.restore_snapshot(snapshot)
                    value = recovered
            return value.documents["doc-stress"].version, value.documents["doc-stress"].document_hash

        self.assertEqual(scenario(73), scenario(73))
        self.assertEqual(scenario(73)[0], scenario(73, crash_after=3)[0])
        self.assertEqual(scenario(73)[1], scenario(73, crash_after=3)[1])

        value = board()
        initial, _ = value.create("doc-concurrency", BlackboardNamespace.FACTS)
        task, attempt = claimed_task()
        barrier = threading.Barrier(16)
        results = []
        result_lock = threading.Lock()

        def compete(index: int) -> None:
            intent = patch_intent(initial, attempt, {"index": index}, actor=f"agent-{index}")
            barrier.wait()
            result = value.patch(intent, task=task)
            with result_lock:
                results.append(result)

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(compete, index) for index in range(16)]
            for future in futures:
                future.result()
        self.assertEqual(sum(result.event is not None for result in results), 1)
        self.assertEqual(sum(result.conflict is not None for result in results), 15)
        self.assertEqual(value.documents["doc-concurrency"].version, 1)


if __name__ == "__main__":
    unittest.main()
