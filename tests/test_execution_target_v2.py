from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from sitina.orchestrator.execution_patch import build_patch_manifest, verify_patch_replay
from sitina.orchestrator.execution_target import apply_verified_files
from sitina.runners.tool_executor import ToolExecutor
from sitina.storage import SitinaStore


class ExecutionTargetV2Tests(unittest.TestCase):
    def test_managed_worktree_rename_and_delete_apply_to_selected_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            home = Path(parent) / "home"
            target = Path(parent) / "selected-workspace"
            worktree = Path(parent) / "managed-worktree"
            home.mkdir()
            SitinaStore(home).init_db()
            target.mkdir()
            worktree.mkdir()
            old_content = b"value = 1\n"
            remove_content = b"remove me\n"
            target_old = target / "old.py"
            target_remove = target / "remove.py"
            target_old.write_bytes(old_content)
            target_remove.write_bytes(remove_content)
            (worktree / "old.py").write_bytes(old_content)
            (worktree / "remove.py").write_bytes(remove_content)
            worktree_old = worktree / "old.py"
            worktree_new = worktree / "new.py"
            worktree_old.rename(worktree_new)
            (worktree / "remove.py").unlink()
            old_hash = hashlib.sha256(old_content).hexdigest()
            remove_hash = hashlib.sha256(remove_content).hexdigest()
            events = [
                {
                    "sequence": 1,
                    "operation": "rename",
                    "path": str(worktree_old.resolve()),
                    "destination": str(worktree_new.resolve()),
                    "before_hash": old_hash,
                    "after_hash": old_hash,
                    "authorization_ref": "execution-authorization:test",
                    "denied": False,
                },
                {
                    "sequence": 2,
                    "operation": "delete",
                    "path": str((worktree / "remove.py").resolve()),
                    "before_hash": remove_hash,
                    "after_hash": None,
                    "authorization_ref": "execution-authorization:test",
                    "denied": False,
                },
            ]
            content_ref = "cas:old-content"
            manifest, _ = build_patch_manifest(
                run_id="run-target-v2",
                execution_attempt_id="execution-attempt:" + "a" * 64,
                workspace=worktree,
                diff_paths=[str(worktree_old), str(worktree / "remove.py")],
                mutation_events=events,
                content_refs={str(worktree_old.resolve()): content_ref},
                target_repo=str(target),
            )
            verify_patch_replay(manifest, load_content=lambda ref: old_content if ref == content_ref else b"")
            authorization = {
                "authorization_ref": "approval-placeholder",
                "run_id": "run-target-v2",
                "workspace": str(target),
                "execution_root": str(worktree),
                "scope": [str(target), str(worktree)],
                "expires_at": int(time.time()) + 600,
            }
            executor = ToolExecutor(home, enforce_write_boundary=True, authorization_binding=authorization)
            apply_scan = executor.risk_scanner.scan(
                "write", target=str(target), allowed_roots=[str(target)]
            )
            approval = executor.approvals.create(
                run_id="run-target-v2", action="approve", risk_scan=apply_scan,
                plan_hash="a" * 64,
                approved_touched_files=[str(target / name) for name in ("old.py", "new.py", "remove.py")],
            )
            executor.authorization_binding["authorization_ref"] = approval.approval_id
            capability = executor._mint_direct_capability(
                run_id="run-target-v2",
                authorization_ref=approval.approval_id,
                target_repo=str(target),
                allowed_roots=[str(target)],
                purpose="accepted-patch-apply",
            )
            applied = apply_verified_files(
                target_root=target,
                source_root=worktree,
                diff_paths=[str(worktree_old), str(worktree / "remove.py")],
                mutation_events=events,
                content_loader=lambda ref: old_content if ref == content_ref else b"",
                content_refs={str(worktree_old.resolve()): content_ref},
                manifest=manifest,
                target_repo=str(target),
                executor=executor,
                run_id="run-target-v2",
                capability=capability,
            )
            self.assertEqual(
                set(applied),
                {str((target / name).resolve()) for name in ("old.py", "new.py", "remove.py")},
            )
            self.assertFalse((target / "old.py").exists())
            self.assertEqual((target / "new.py").read_bytes(), old_content)
            self.assertFalse((target / "remove.py").exists())

            wrong = executor._mint_direct_capability(
                run_id="run-target-v2",
                authorization_ref=approval.approval_id,
                target_repo=str(target),
                allowed_roots=[str(target)],
                purpose="test",
            )
            self.assertEqual(
                executor.write_direct(
                    target=str(Path(parent) / "outside.py"),
                    content="blocked",
                    run_id="run-target-v2",
                    capability=wrong,
                )["status"],
                "blocked",
            )
            self.assertEqual(
                executor.execute(
                    operation="write",
                    run_id="run-target-v2",
                    agent="test",
                    target=str(target / "no-cap.py"),
                    content="blocked",
                )["status"],
                "blocked",
            )
            expired = replace(capability, expires_at=int(time.time()) - 1)
            executor._direct_capabilities[expired.token] = expired
            self.assertEqual(
                executor.write_direct(
                    target=str(target / "expired.py"),
                    content="blocked",
                    run_id="run-target-v2",
                    capability=expired,
                )["status"],
                "blocked",
            )


if __name__ == "__main__":
    unittest.main()
