from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.orchestrator.execution_target import overlay_workspace
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

    def test_prepare_unborn_repo_preserves_untracked_workspace_in_isolated_worktree(self) -> None:
        """An unborn source gets a self-contained snapshot, not a HEAD failure."""
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            home = root / "home"
            repo = root / "repo"
            home.mkdir()
            repo.mkdir()
            self._git(repo, "init", "-q")
            source_git = repo / ".git"
            source_git_before = sorted(
                (path.relative_to(source_git).as_posix(), path.read_bytes())
                for path in source_git.rglob("*")
                if path.is_file()
            )
            (repo / "calculator.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            (repo / "test_calculator.py").write_text(
                "import unittest\nfrom calculator import add\n\n"
                "class CalculatorTests(unittest.TestCase):\n"
                "    def test_add(self):\n"
                "        self.assertEqual(add(2, 3), 5)\n",
                encoding="utf-8",
            )
            store = SitinaStore(home)
            store.init_db()
            manager = GitWorktreeManager(home, store=store)

            prepared = manager.prepare(str(repo), "run-unborn")
            self.assertEqual(prepared["status"], "ok", prepared)
            self.assertTrue(prepared["unborn_repository"])
            self.assertEqual(prepared["isolation_kind"], "unborn_snapshot")
            self.assertRegex(prepared["temporary_baseline_commit"], r"^[0-9a-f]{40}$")
            worktree = Path(prepared["worktree"])
            self.assertTrue(worktree.is_dir())
            self.assertTrue((worktree / ".git").is_dir())
            self.assertFalse(prepared["registration_created"])
            report = overlay_workspace(repo, worktree)
            self.assertEqual(sorted(report["copied_paths"]), ["calculator.py", "test_calculator.py"])
            self.assertEqual(
                (worktree / "calculator.py").read_text(encoding="utf-8"),
                (repo / "calculator.py").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (worktree / "test_calculator.py").read_text(encoding="utf-8"),
                (repo / "test_calculator.py").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
                    capture_output=True, text=True,
                ).returncode,
                128,
            )
            source_git_after = sorted(
                (path.relative_to(source_git).as_posix(), path.read_bytes())
                for path in source_git.rglob("*")
                if path.is_file()
            )
            self.assertEqual(source_git_after, source_git_before)
            cleaned = manager.cleanup_for_run(str(repo), "run-unborn")
            self.assertEqual(cleaned["status"], "ok", cleaned)
            self.assertFalse(cleaned["registered_before"])
            self.assertFalse(cleaned["registered_after"])
            self.assertFalse(worktree.exists())
            self.assertTrue((repo / "calculator.py").exists())
            self.assertTrue((repo / "test_calculator.py").exists())

    def test_prepare_committed_repo_still_uses_existing_head_anchor(self) -> None:
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
            head = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            store = SitinaStore(home)
            store.init_db()
            manager = GitWorktreeManager(home, store=store)
            prepared = manager.prepare(str(repo), "run-committed")
            self.assertEqual(prepared["status"], "ok", prepared)
            self.assertFalse(prepared["unborn_repository"])
            self.assertEqual(prepared["checkout_ref"], "HEAD")
            self.assertIsNone(prepared["temporary_baseline_commit"])
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", prepared["worktree"], "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip(),
                head,
            )
            self.assertEqual(manager.cleanup(str(repo), prepared["worktree"], "run-committed")["status"], "ok")

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
