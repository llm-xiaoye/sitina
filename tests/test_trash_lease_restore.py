from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.trash.leases import TrashLeaseRegistry
from sitina.trash.transactions import TrashDeletionCoordinator, TrashError


class _FakeTrash:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def move_to_trash(self, bundle: Path, *, idempotency_key: str) -> str:
        self.calls += 1
        if self.fail:
            raise OSError("injected Finder/Trash failure")
        return "fake-trash://" + bundle.name


class TrashLeaseRestoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        self.events: list[dict[str, object]] = []

    def _append(self, event: dict[str, object]) -> int:
        self.events.append(dict(event))
        return len(self.events)

    def _delete(self, session_id: str = "session-exact") -> tuple[TrashDeletionCoordinator, dict[str, object]]:
        coordinator = TrashDeletionCoordinator(self.home, adapter=_FakeTrash())
        receipt = coordinator.delete(
            session_id=session_id,
            title="Same title",
            journal_frontier=12,
            object_refs=("cas:" + "a" * 64, "cas:" + "b" * 64),
            append_event=self._append,
            confirmed=True,
            occurred_at="2026-07-18T00:00:00Z",
        )
        return coordinator, receipt

    def test_checkpoint_gate_is_retryable_and_bundle_is_refs_only(self) -> None:
        ready = False
        adapter = _FakeTrash()
        coordinator = TrashDeletionCoordinator(self.home, adapter=adapter)
        arguments = dict(
            session_id="session-checkpoint",
            title="Shared title",
            journal_frontier=8,
            object_refs=("cas:" + "c" * 64,),
            run_ids=("run-active",),
            append_event=self._append,
            confirmed=True,
            checkpoint_active_runs=lambda _session: ready,
            atomic_operations_drained=lambda _session: True,
            occurred_at="2026-07-18T00:00:00Z",
        )
        with self.assertRaisesRegex(TrashError, "terminal checkpoint"):
            coordinator.delete(**arguments)
        self.assertEqual(adapter.calls, 0)
        self.assertEqual(self.events, [])
        self.assertEqual(coordinator._load("session-checkpoint")["state"], "CHECKPOINTING")

        ready = True
        receipt = coordinator.delete(**arguments)
        self.assertEqual(receipt["lifecycle_state"], "HIDDEN_FROM_PROJECTION")
        self.assertEqual([event["event_type"] for event in self.events], ["session.deletion-prepared", "session.deleted"])
        self.assertEqual(self.events[-1]["run_ids"], ["run-active"])
        bundle = self.home / str(receipt["bundle_path"])
        self.assertEqual({path.name for path in bundle.iterdir()}, {"manifest.json", "restore.json", "checksums.json"})
        self.assertFalse(any((bundle / name).stat().st_size > 4096 for name in ("manifest.json", "restore.json", "checksums.json")))

    def test_fake_trash_failure_does_not_commit_logical_deletion(self) -> None:
        coordinator = TrashDeletionCoordinator(self.home, adapter=_FakeTrash(fail=True))
        with self.assertRaises(OSError):
            coordinator.delete(
                session_id="session-move-fails",
                title="Failure",
                journal_frontier=3,
                object_refs=("cas:" + "d" * 64,),
                append_event=self._append,
                confirmed=True,
                occurred_at="2026-07-18T00:00:00Z",
            )
        self.assertEqual([event["event_type"] for event in self.events], ["session.deletion-prepared"])
        self.assertEqual(coordinator._load("session-move-fails")["state"], "TRASH_BUNDLE_PREPARED")
        self.assertIsNone(TrashLeaseRegistry(self.home).load("session-move-fails"))

    def test_missing_grace_remains_a_gc_root_and_release_is_explicit(self) -> None:
        _coordinator, _receipt = self._delete()
        registry = TrashLeaseRegistry(self.home)
        lease = registry.observe_bundle("session-exact", present_in_trash=False, observed_at="2026-07-20T00:00:00Z")
        self.assertEqual(lease.state, "MISSING_GRACE")
        self.assertEqual({item["object_ref"] for item in registry.active_roots()}, set(lease.object_refs))
        with self.assertRaisesRegex(TrashError, "still active"):
            registry.release_after_retention(
                "session-exact",
                observed_at="2026-08-18T00:00:00Z",
                confirmed=True,
                append_event=self._append,
            )
        self.assertEqual(registry.load("session-exact").state, "MISSING_GRACE")
        released = registry.release_after_retention(
            "session-exact",
            observed_at="2026-08-20T00:00:00Z",
            confirmed=True,
            append_event=self._append,
        )
        self.assertEqual(released.state, "RELEASED")
        self.assertEqual(registry.active_roots(), ())
        self.assertEqual(self.events[-1]["event_type"], "trash.lease-released")

    def test_finder_manual_import_validates_and_never_reexecutes_side_effects(self) -> None:
        _coordinator, receipt = self._delete("session-restore")
        registry = TrashLeaseRegistry(self.home)
        registry.observe_bundle("session-restore", present_in_trash=False, observed_at="2026-07-19T00:00:00Z")
        bundle = self.home / str(receipt["bundle_path"])
        deleted = next(event for event in self.events if event["event_type"] == "session.deleted")
        rebuilt: list[tuple[str, tuple[str, ...]]] = []
        provider_calls: list[str] = []
        terminal_calls: list[str] = []

        lease = registry.import_bundle(
            bundle,
            deleted_event_lookup=lambda session_id: deleted if session_id == "session-restore" else None,
            cas_reference_resolves=lambda reference: reference in receipt["object_refs"],
            append_event=self._append,
            rebuild_active_roots=lambda session_id, refs: rebuilt.append((session_id, refs)),
        )
        self.assertEqual(lease.state, "RELEASED")
        self.assertEqual(rebuilt, [("session-restore", tuple(receipt["object_refs"]))])
        self.assertEqual(provider_calls, [])
        self.assertEqual(terminal_calls, [])
        restored = next(event for event in self.events if event["event_type"] == "session.restored")
        self.assertIs(restored["reexecute_side_effects"], False)
        self.assertEqual(registry.active_roots(), ())

    def test_tampered_or_mismatched_bundle_is_rejected(self) -> None:
        _coordinator, receipt = self._delete("session-tamper")
        bundle = self.home / str(receipt["bundle_path"])
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["session_id"] = "another-session"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(TrashError):
            TrashLeaseRegistry(self.home).import_bundle(
                bundle,
                deleted_event_lookup=lambda _session: None,
                cas_reference_resolves=lambda _reference: True,
                append_event=self._append,
                rebuild_active_roots=lambda _session, _refs: None,
            )

    def test_confirmation_preview_exposes_root_and_retention_facts(self) -> None:
        preview = TrashDeletionCoordinator.deletion_preview(
            session_id="session-preview",
            memory_roots=({"memory_id": "memory-1", "disposition": "RETAIN_PROJECT_ROOT"},),
            backup_roots=({"backup_id": "backup-1", "active": True},),
            cold_archive_present=True,
        )
        self.assertEqual(preview["deletion_kind"], "LOGICAL")
        self.assertFalse(preview["immediate_physical_destruction"])
        self.assertEqual(preview["trash_retention_days"], 30)
        self.assertEqual(preview["backup_roots"][0]["backup_id"], "backup-1")

    def test_memory_disposition_keeps_project_user_and_independently_used_private_roots(self) -> None:
        refs = ["cas:" + character * 64 for character in "abcd"]
        plan = TrashDeletionCoordinator.memory_deletion_plan(
            (
                {"memory_id": "candidate", "scope": "project_shared", "status": "candidate", "content_ref": refs[0]},
                {"memory_id": "run", "scope": "run_shared", "status": "accepted", "content_ref": refs[1]},
                {"memory_id": "project", "scope": "project_shared", "status": "accepted", "content_ref": refs[2]},
                {"memory_id": "private", "scope": "agent_private", "status": "accepted", "content_ref": refs[3]},
            ),
            independently_rooted_refs={refs[3]: ("backup",)},
        )
        self.assertEqual(plan["trash_object_refs"], refs[:2])
        self.assertEqual(plan["retained_object_refs"], refs[2:])
        self.assertEqual(plan["memory_revoked_events_appended"], 0)
        private = next(item for item in plan["dispositions"] if item["memory_id"] == "private")
        self.assertEqual(private["disposition"], "RETAIN_INDEPENDENT_USE_REVIEW_REVOKE")


if __name__ == "__main__":
    unittest.main()
