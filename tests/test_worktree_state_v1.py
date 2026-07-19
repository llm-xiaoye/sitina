from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from sitina.cas.local import LocalCAS
from sitina.journal.model import parse_canonical_json
from sitina.orchestrator.worktree_state import WorktreeStateError, WorktreeStateRepository
from sitina.security.key_provider import InMemoryKeyProvider


def _run(repo: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(process.stderr.decode("utf-8", errors="replace"))
    return process.stdout


class WorktreeStateV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.repo = self.root / "source-repository"
        self.repo.mkdir()
        _run(self.repo, "init", "-q")
        _run(self.repo, "config", "user.name", "Fixture")
        _run(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "staged.txt").write_text("base staged\n", encoding="utf-8")
        (self.repo / "working.txt").write_text("base working\n", encoding="utf-8")
        (self.repo / "binary.dat").write_bytes(b"\x00base\xff")
        _run(self.repo, "add", ".")
        _run(self.repo, "commit", "-q", "-m", "base")
        self.cas = LocalCAS.open(self.home, InMemoryKeyProvider())
        self.states = WorktreeStateRepository(self.cas)

    def test_commit_diffs_and_untracked_manifest_reconstruct_exact_status(self) -> None:
        (self.repo / "staged.txt").write_text("staged change\n", encoding="utf-8")
        _run(self.repo, "add", "staged.txt")
        (self.repo / "working.txt").write_text("unstaged change\n", encoding="utf-8")
        (self.repo / "binary.dat").write_bytes(b"\x00changed\xfe\xfd")
        untracked = self.repo / "generated" / "run.sh"
        untracked.parent.mkdir()
        untracked.write_text("#!/bin/sh\necho recovered\n", encoding="utf-8")
        untracked.chmod(0o755)
        source_head = _run(self.repo, "rev-parse", "HEAD")
        source_status = _run(self.repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")

        state_ref, state = self.states.capture(self.repo)
        self.assertTrue(state.reconstruction_verified)
        self.assertEqual(state.base_commit.encode() + b"\n", source_head)
        raw_state = self.cas.open_verified(self.cas.resolve_reference(state_ref))
        state_value = parse_canonical_json(raw_state)
        self.assertEqual(
            set(state_value),
            {
                "schema",
                "base_commit",
                "temporary_branch",
                "diff_ref",
                "untracked_files_manifest_ref",
                "git_status_ref",
                "reconstruction_verified",
            },
        )

        manifest = parse_canonical_json(
            self.cas.open_verified(self.cas.resolve_reference(state.untracked_files_manifest_ref))
        )
        self.assertEqual([item["path"] for item in manifest["files"]], ["generated/run.sh"])
        self.assertNotIn("repository", manifest)
        self.assertNotIn("body", state_value)

        target = self.root / "reconstructed"
        report = self.states.reconstruct(self.repo, state_ref, target)
        self.assertTrue(report["verified"])
        self.assertEqual(_run(target, "status", "--porcelain=v1", "-z", "--untracked-files=all"), source_status)
        self.assertEqual((target / "staged.txt").read_text(encoding="utf-8"), "staged change\n")
        self.assertEqual((target / "working.txt").read_text(encoding="utf-8"), "unstaged change\n")
        self.assertEqual((target / "binary.dat").read_bytes(), b"\x00changed\xfe\xfd")
        self.assertEqual((target / "generated/run.sh").read_text(encoding="utf-8"), "#!/bin/sh\necho recovered\n")
        self.assertTrue((target / "generated/run.sh").stat().st_mode & 0o111)

        self.assertEqual(_run(self.repo, "rev-parse", "HEAD"), source_head)
        self.assertEqual(_run(self.repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"), source_status)
        self.assertTrue(self.repo.is_dir())

    def test_untracked_symlink_is_rejected_without_touching_source(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("do not ingest through symlink", encoding="utf-8")
        (self.repo / "unsafe-link").symlink_to(outside)
        with self.assertRaisesRegex(WorktreeStateError, "symlinks"):
            self.states.capture(self.repo)
        self.assertTrue((self.repo / "unsafe-link").is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "do not ingest through symlink")

    def test_reconstruction_never_overwrites_an_existing_target(self) -> None:
        state_ref, _state = self.states.capture(self.repo)
        target = self.root / "occupied"
        target.mkdir()
        marker = target / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(WorktreeStateError, "must not exist"):
            self.states.reconstruct(self.repo, state_ref, target)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
