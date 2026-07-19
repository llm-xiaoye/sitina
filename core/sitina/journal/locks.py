from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .model import validate_identifier


class WriterLockError(RuntimeError):
    pass


class WriterLockContended(WriterLockError):
    pass


@dataclass
class WriterLock:
    path: Path
    journal_id: str
    epoch: int
    fd: int
    device: int
    inode: int
    poisoned_reason: str | None = None
    _closed: bool = False

    @classmethod
    def acquire(cls, path: str | os.PathLike[str], journal_id: str, epoch: int) -> "WriterLock":
        validate_identifier(journal_id, field="journal_id")
        if epoch < 1:
            raise WriterLockError("epoch must be positive")
        candidate = Path(path)
        if candidate.parent.is_symlink() or not candidate.parent.is_dir():
            raise WriterLockError("writer lock parent must be a real directory")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(candidate, flags, 0o600)
        except OSError as error:
            raise WriterLockError(f"cannot open fixed-inode writer lock: {error}") from error
        try:
            os.set_inheritable(fd, False)
            descriptor = os.fstat(fd)
            path_stat = os.lstat(candidate)
            if not stat.S_ISREG(descriptor.st_mode) or not stat.S_ISREG(path_stat.st_mode):
                raise WriterLockError("writer lock is not a regular file")
            if (descriptor.st_dev, descriptor.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                raise WriterLockError("writer lock inode changed during acquisition")
            if descriptor.st_dev != candidate.parent.stat().st_dev:
                raise WriterLockError("writer lock crosses filesystem boundary")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise WriterLockContended("another writer holds the fixed-inode lock") from error
            lock = cls(candidate, journal_id, epoch, fd, descriptor.st_dev, descriptor.st_ino)
            lock._write_generation_metadata()
            return lock
        except BaseException:
            os.close(fd)
            raise

    @property
    def generation_path(self) -> Path:
        return self.path.with_name(self.path.name + ".generation.json")

    def _write_generation_metadata(self) -> None:
        value = {
            "schema": "SITINA_WRITER_GENERATION_V1",
            "journal_id": self.journal_id,
            "epoch": self.epoch,
            "pid": os.getpid(),
            "device": self.device,
            "inode": self.inode,
            "monotonic_ns": time.monotonic_ns(),
        }
        temporary = self.generation_path.with_name(f".{self.generation_path.name}.{os.getpid()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.generation_path)
            directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.environ.get("SITINA_AUDIT_RETAIN_STAGING") != "1":
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def _verify_inode(self) -> None:
        if self._closed:
            raise WriterLockError("writer lock descriptor is closed")
        try:
            descriptor = os.fstat(self.fd)
            path_stat = os.lstat(self.path)
        except OSError as error:
            self.poison(f"descriptor or path unavailable: {error}")
            raise WriterLockError(self.poisoned_reason) from error
        if (descriptor.st_dev, descriptor.st_ino) != (self.device, self.inode) or (
            path_stat.st_dev,
            path_stat.st_ino,
        ) != (self.device, self.inode):
            self.poison("fixed writer-lock inode was replaced")
            raise WriterLockError(self.poisoned_reason)

    def assert_healthy(self) -> None:
        if self.poisoned_reason:
            raise WriterLockError(f"writer lock is poisoned: {self.poisoned_reason}")
        self._verify_inode()

    def duplicate_descriptor(self) -> int:
        self.assert_healthy()
        duplicate = os.dup(self.fd)
        os.set_inheritable(duplicate, False)
        return duplicate

    def poison(self, reason: str) -> None:
        if not self.poisoned_reason:
            self.poisoned_reason = str(reason)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._verify_inode()
        finally:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                self.poison("failed to unlock writer descriptor")
            try:
                os.close(self.fd)
            except OSError:
                self.poison("writer descriptor was already closed")
            self._closed = True

    def __enter__(self) -> "WriterLock":
        self.assert_healthy()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()
