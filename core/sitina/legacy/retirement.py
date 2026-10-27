from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sitina.install_identity import LEGACY_PRODUCTION_HOME, canonical_journal_native_home
from sitina.utils import load_json_yaml


class LegacyAccessDisabled(PermissionError):
    """Raised before any retired Legacy path is opened or created."""


@dataclass(frozen=True)
class LegacyRuntimePolicy:
    legacy_enabled: bool
    read_enabled: bool
    fallback_enabled: bool
    write_enabled: bool
    active_business_jsonl_enabled: bool
    missing_legacy_is_valid: bool
    retired_root: str | None
    protected_environment: bool

    @property
    def fully_disabled(self) -> bool:
        return not any(
            (
                self.legacy_enabled,
                self.read_enabled,
                self.fallback_enabled,
                self.write_enabled,
                self.active_business_jsonl_enabled,
            )
        )

    @classmethod
    def load(cls, home: Path) -> "LegacyRuntimePolicy":
        root = Path(home).expanduser().resolve(strict=False)
        protected = root in {canonical_journal_native_home(), LEGACY_PRODUCTION_HOME} or (
            root / ".sitina-clean-acceptance-v1"
        ).is_file()
        path = root / "config/sitina.yaml"
        values: dict[str, Any] = {}
        if path.is_file():
            loaded = load_json_yaml(path)
            if isinstance(loaded, dict):
                candidate = loaded.get("storage_authority")
                if isinstance(candidate, dict):
                    values = candidate
        retired_root = str(values["legacy_retired_root"]) if values.get("legacy_retired_root") else None
        if protected:
            # Canonical and clean-acceptance homes are a hard runtime fence:
            # configuration may describe the retired root, but can never
            # reopen a retired read, fallback, write, or JSONL authority.
            return cls(
                legacy_enabled=False,
                read_enabled=False,
                fallback_enabled=False,
                write_enabled=False,
                active_business_jsonl_enabled=False,
                missing_legacy_is_valid=True,
                retired_root=retired_root,
                protected_environment=True,
            )
        # Unmarked non-installation homes remain explicit Legacy fixtures so the
        # historical test suite can exercise migration compatibility without
        # weakening the active installation or clean-acceptance policy.
        return cls(
            legacy_enabled=True,
            read_enabled=True,
            fallback_enabled=True,
            write_enabled=True,
            active_business_jsonl_enabled=True,
            missing_legacy_is_valid=False,
            retired_root=None,
            protected_environment=False,
        )

    def validate_protected(self) -> list[str]:
        if not self.protected_environment:
            return []
        errors: list[str] = []
        if not self.fully_disabled:
            errors.append("protected B+ environment requires all Legacy and business JSONL routes disabled")
        if not self.missing_legacy_is_valid:
            errors.append("protected B+ environment must accept a missing Legacy source")
        return errors

    def unexpected_sqlite_artifacts(self, home: Path) -> tuple[Path, ...]:
        """Return retired live SQLite artifacts that cannot exist in disabled mode."""

        if not self.protected_environment or not self.fully_disabled:
            return ()
        database = Path(home).expanduser().resolve(strict=False) / "data/sitina.db"
        candidates = (database, Path(str(database) + "-wal"), Path(str(database) + "-shm"))
        return tuple(path for path in candidates if path.exists() or path.is_symlink())

    def deny_read(self, operation: str) -> None:
        raise LegacyAccessDisabled(f"Legacy read disabled by storage authority policy: {operation}")

    def deny_write(self, operation: str) -> None:
        raise LegacyAccessDisabled(f"Legacy write disabled by storage authority policy: {operation}")


class DisabledLegacyStore:
    """Non-reader sentinel: it never resolves, scans, stats, or opens Legacy."""

    enabled = False
    manifest_sha256 = None
    intended_snapshot_hash = None
    reader_generation = "legacy-disabled-v1"

    def __init__(self, policy: LegacyRuntimePolicy):
        if not policy.fully_disabled:
            raise ValueError("DisabledLegacyStore requires a fully disabled policy")
        self.policy = policy

    def connect(self) -> Any:
        self.policy.deny_read("connect")

    def list_runs(self, *, limit: int | None = 50) -> list[dict[str, Any]]:
        del limit
        self.policy.deny_read("list_runs")

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        del run_id
        self.policy.deny_read("get_run")

    def timeline(self, run_id: str) -> list[dict[str, Any]]:
        del run_id
        self.policy.deny_read("timeline")
