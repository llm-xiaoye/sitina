from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sitina.journal.locks import WriterLock, WriterLockContended, WriterLockError


class JournalWriterLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        self.path = self.directory / "writer.lock"

    def tearDown(self) -> None:
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()

    def test_contention_fails_without_deleting_or_replacing_lock_file(self) -> None:
        first = WriterLock.acquire(self.path, "journal-1", 1)
        identity = self.path.stat().st_ino
        with self.assertRaises(WriterLockContended):
            WriterLock.acquire(self.path, "journal-1", 1)
        self.assertEqual(self.path.stat().st_ino, identity)
        first.close()

    def test_subprocess_contention_and_cloexec(self) -> None:
        first = WriterLock.acquire(self.path, "journal-1", 1)
        self.assertFalse(os.get_inheritable(first.fd))
        code = (
            "from sitina.journal.locks import WriterLock,WriterLockContended;"
            f"p={str(self.path)!r};"
            "\ntry: WriterLock.acquire(p,'journal-1',1)"
            "\nexcept WriterLockContended: raise SystemExit(23)"
            "\nraise SystemExit(24)"
        )
        child = subprocess.run([sys.executable, "-c", code], check=False)
        self.assertEqual(child.returncode, 23)
        first.close()

    def test_symlink_and_inode_replacement_fail_closed(self) -> None:
        target = self.directory / "target"
        target.write_text("", encoding="utf-8")
        link = self.directory / "link"
        link.symlink_to(target)
        with self.assertRaises(WriterLockError):
            WriterLock.acquire(link, "journal-1", 1)
        lock = WriterLock.acquire(self.path, "journal-1", 1)
        moved = self.directory / "moved.lock"
        self.path.rename(moved)
        self.path.write_text("replacement", encoding="utf-8")
        with self.assertRaises(WriterLockError):
            lock.assert_healthy()
        with self.assertRaises(WriterLockError):
            lock.close()
        moved.unlink()

    def test_duplicate_fd_close_does_not_release_primary_lock(self) -> None:
        lock = WriterLock.acquire(self.path, "journal-1", 1)
        duplicate = lock.duplicate_descriptor()
        os.close(duplicate)
        with self.assertRaises(WriterLockContended):
            WriterLock.acquire(self.path, "journal-1", 1)
        lock.close()
        replacement = WriterLock.acquire(self.path, "journal-1", 2)
        replacement.close()

    def test_explicit_poison_blocks_use(self) -> None:
        lock = WriterLock.acquire(self.path, "journal-1", 1)
        lock.poison("unknown fsync outcome")
        with self.assertRaisesRegex(WriterLockError, "unknown fsync"):
            lock.assert_healthy()
        lock.close()


if __name__ == "__main__":
    unittest.main()
