from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.orchestrator.git_ops import GitWorktreeManager
from sitina.legacy.fence import authorized_extension_effect
from sitina.storage import SitinaStore


class GitWorktreeCleanupTests(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> None:
        with authorized_extension_effect(
            permission="shell", approval_granted=True,
            purpose="test-disposable-git-bootstrap",
        ):
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)

    def test_prepare_audit_failure_removes_registration(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.email", "test@example.invalid")
            self._git(repo, "config", "user.name", "Sitina Test")
            (repo / "file.txt").write_text("base\n", encoding="utf-8")
            self._git(repo, "add", "file.txt")
            self._git(repo, "commit", "-qm", "base")
            store = SitinaStore(home)
            store.init_db()
            manager = GitWorktreeManager(home, store=store)

            with patch.object(store, "record_audit", side_effect=RuntimeError("injected audit failure")):
                with self.assertRaises(RuntimeError):
                    manager.prepare(str(repo), "run-audit-failure")

            with authorized_extension_effect(
                permission="shell", approval_granted=True,
                purpose="test-disposable-git-inspection",
            ):
                listing = subprocess.run(
                    ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            self.assertNotIn("run-audit-failure", listing)
            self.assertFalse((home / "artifacts" / "worktrees" / "run-audit-failure").exists())

    def test_cleanup_audit_failure_is_not_success_or_removed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.email", "test@example.invalid")
            self._git(repo, "config", "user.name", "Sitina Test")
            (repo / "file.txt").write_text("base\n", encoding="utf-8")
            self._git(repo, "add", "file.txt")
            self._git(repo, "commit", "-qm", "base")
            store = SitinaStore(home)
            store.init_db()
            manager = GitWorktreeManager(home, store=store)
            prepared = manager.prepare(str(repo), "run-cleanup-audit-failure")
            worktree = str(prepared["worktree"])

            with patch.object(store, "record_audit", side_effect=RuntimeError("injected audit failure")):
                report = manager.cleanup(str(repo), worktree, "run-cleanup-audit-failure")

            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["removed"])
            self.assertTrue(report["physical_removed"])
            self.assertFalse(Path(worktree).exists())

    def test_porcelain_payload_is_hash_only_and_does_not_leak_unrelated_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            manager = GitWorktreeManager(home)
            unrelated = "/Users/other-user/private-worktree"
            porcelain = f"worktree {repo}\nworktree {unrelated}\n"
            with patch.object(
                manager,
                "_worktree_porcelain",
                side_effect=[(porcelain, 0), (porcelain, 0)],
            ):
                report = manager.cleanup_for_run(str(repo), "run-redaction")
            self.assertNotIn(unrelated, str(report))
            self.assertRegex(report["porcelain_before_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(report["porcelain_after_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
