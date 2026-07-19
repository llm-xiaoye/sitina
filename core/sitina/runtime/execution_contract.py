"""Fail-closed execution manifests and production-home guards.

This module intentionally uses only the Python standard library.  It is safe to
load while validating Phase -1 manifests and does not import the Sitina runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class ManifestValidationError(ValueError):
    """Raised when an execution authorization cannot be proved."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the stable JSON representation used for control-record hashes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestValidationError(f"{field} must be an object")
    return value


def _require_text(mapping: Mapping[str, Any], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ManifestValidationError(f"missing or invalid field: {field}")
    return value


def _validate_sha256(value: str, field: str) -> str:
    raw = value.removeprefix("sha256:")
    if len(raw) != 64 or any(character not in "0123456789abcdef" for character in raw):
        raise ManifestValidationError(f"{field} must be a lowercase SHA-256")
    return raw


def _resolved(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _same_existing_path(left: Path, right: Path) -> bool:
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


@dataclass(frozen=True)
class ProductionHomeGuard:
    """Reject test and mutation roots that can alias production mutable data."""

    production_home: Path

    def __init__(self, production_home: str | os.PathLike[str]):
        object.__setattr__(self, "production_home", _resolved(production_home))

    @property
    def mutable_roots(self) -> tuple[Path, ...]:
        names = ("data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp")
        return tuple((self.production_home / name).resolve(strict=False) for name in names)

    def assert_test_home_isolated(self, test_home: str | os.PathLike[str]) -> Path:
        candidate = _resolved(test_home)
        production = self.production_home
        aliases = (
            candidate == production
            or _is_within(candidate, production)
            or _is_within(production, candidate)
            or _same_existing_path(candidate, production)
        )
        if aliases:
            raise ManifestValidationError(
                f"test home aliases or contains production home: {candidate}"
            )
        for mutable_root in self.mutable_roots:
            if candidate == mutable_root or _is_within(candidate, mutable_root):
                raise ManifestValidationError(
                    f"test home is inside production mutable data: {candidate}"
                )
        return candidate

    def assert_mutation_roots_safe(
        self, mutation_roots: Iterable[str | os.PathLike[str]]
    ) -> tuple[Path, ...]:
        checked: list[Path] = []
        for raw_root in mutation_roots:
            root = _resolved(raw_root)
            for mutable_root in self.mutable_roots:
                if (
                    root == mutable_root
                    or _is_within(root, mutable_root)
                    or _is_within(mutable_root, root)
                    or _same_existing_path(root, mutable_root)
                ):
                    raise ManifestValidationError(
                        f"mutation root overlaps production mutable data: {root}"
                    )
            checked.append(root)
        if not checked:
            raise ManifestValidationError("at least one mutation root is required")
        return tuple(checked)


def assert_test_home_isolated(
    production_home: str | os.PathLike[str], test_home: str | os.PathLike[str]
) -> Path:
    return ProductionHomeGuard(production_home).assert_test_home_isolated(test_home)


def sanitized_environment_fingerprint(
    environment: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    """Return a secret-free, stable environment description and its hash."""

    source = environment if environment is not None else os.environ
    safe = {
        "architecture": platform.machine(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "sitina_home": str(_resolved(source["SITINA_HOME"])) if source.get("SITINA_HOME") else None,
    }
    return {**safe, "fingerprint": sha256_prefixed(canonical_json_bytes(safe))}


def load_json_read_only(path: str | os.PathLike[str]) -> Mapping[str, Any]:
    """Open a regular manifest without following symlinks or creating files."""

    manifest_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(manifest_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ManifestValidationError(f"manifest is not a regular file: {manifest_path}")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as handle:
            value = json.load(handle)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return _require_mapping(value, "manifest")


@dataclass(frozen=True)
class BootstrapManifestV0:
    bootstrap_id: str
    authorized_phase: str
    authorized_task_range: str
    exact_authorized_files: tuple[Path, ...]
    production_home: Path
    bootstrap_workspace: Path
    initial_plan_suite_hash: str
    approval_reference: str
    required_stop_point: str
    prohibited_operations: frozenset[str]
    manifest_hash: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BootstrapManifestV0":
        if value.get("schema") != "PHASE_MINUS_1_BOOTSTRAP_V0":
            raise ManifestValidationError("wrong bootstrap schema")
        authorization = _require_mapping(value.get("authorization"), "authorization")
        roots = _require_mapping(value.get("roots"), "roots")
        hashes = _require_mapping(value.get("initial_hashes"), "initial_hashes")
        phase = _require_text(authorization, "authorized_phase")
        task_range = _require_text(authorization, "authorized_task_range")
        if phase != "-1" or task_range != "1..3":
            raise ManifestValidationError("bootstrap V0 is restricted to Phase -1 Tasks 1..3")
        if "python_profile_hash" in value or "dependency_lock_hash" in value:
            raise ManifestValidationError("bootstrap V0 cannot bind self-generated hashes")
        files = value.get("exact_authorized_files")
        if not isinstance(files, Sequence) or isinstance(files, (str, bytes)) or not files:
            raise ManifestValidationError("exact_authorized_files must be a non-empty array")
        paths = tuple(_resolved(str(item)) for item in files)
        if len(set(paths)) != len(paths):
            raise ManifestValidationError("exact_authorized_files contains aliases or duplicates")
        production_home = _resolved(_require_text(roots, "production_home"))
        ProductionHomeGuard(production_home).assert_mutation_roots_safe(
            path for path in paths if not _is_within(path, production_home)
        )
        mutable = ProductionHomeGuard(production_home).mutable_roots
        for path in paths:
            if any(path == root or _is_within(path, root) for root in mutable):
                raise ManifestValidationError(f"bootstrap file enters production mutable data: {path}")
        plan_hash = _require_text(hashes, "complete_plan_sha256")
        _validate_sha256(plan_hash, "complete_plan_sha256")
        prohibited = value.get("prohibited_operations")
        if not isinstance(prohibited, Sequence) or isinstance(prohibited, (str, bytes)):
            raise ManifestValidationError("prohibited_operations must be an array")
        required_prohibitions = {
            "IMPORT_OR_RUN_SITINA_RUNTIME",
            "RUN_ANY_TEST",
            "WRITE_PRODUCTION_MUTABLE_DATA",
            "DELETE_OVERWRITE_OR_MODIFY_LEGACY_MATERIAL",
        }
        prohibition_set = frozenset(str(item) for item in prohibited)
        if not required_prohibitions.issubset(prohibition_set):
            raise ManifestValidationError("bootstrap prohibitions are incomplete")
        core = dict(value)
        return cls(
            bootstrap_id=_require_text(value, "bootstrap_id"),
            authorized_phase=phase,
            authorized_task_range=task_range,
            exact_authorized_files=paths,
            production_home=production_home,
            bootstrap_workspace=_resolved(_require_text(roots, "bootstrap_workspace")),
            initial_plan_suite_hash=plan_hash.removeprefix("sha256:"),
            approval_reference=_require_text(authorization, "approval_reference"),
            required_stop_point=_require_text(authorization, "required_stop_point"),
            prohibited_operations=prohibition_set,
            manifest_hash=sha256_prefixed(canonical_json_bytes(core)),
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "BootstrapManifestV0":
        return cls.from_mapping(load_json_read_only(path))

    def assert_file_authorized(self, path: str | os.PathLike[str]) -> Path:
        candidate = _resolved(path)
        if candidate not in self.exact_authorized_files:
            raise ManifestValidationError(f"file is outside bootstrap authorization: {candidate}")
        return candidate


@dataclass(frozen=True)
class BootstrapFoundationRecord:
    bootstrap_id: str
    source_audit_mode: str
    baseline_manifest_hash: str
    python_profile_hash: str
    dependency_lock_hash: str
    plan_suite_hash: str
    production_sentinel_hash: str
    changed_file_manifest_hash: str
    record_hash: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BootstrapFoundationRecord":
        if value.get("schema") != "BOOTSTRAP_FOUNDATION_RECORD_V1":
            raise ManifestValidationError("wrong foundation record schema")
        fields = {
            name: _require_text(value, name)
            for name in (
                "baseline_manifest_hash",
                "python_profile_hash",
                "dependency_lock_hash",
                "plan_suite_hash",
                "production_sentinel_hash",
                "changed_file_manifest_hash",
            )
        }
        for name, field_value in fields.items():
            _validate_sha256(field_value, name)
        declared = _require_text(value, "record_hash")
        _validate_sha256(declared, "record_hash")
        hash_input = dict(value)
        hash_input.pop("record_hash", None)
        actual = sha256_prefixed(canonical_json_bytes(hash_input))
        if actual != declared:
            raise ManifestValidationError("foundation record hash mismatch")
        return cls(
            bootstrap_id=_require_text(value, "bootstrap_id"),
            source_audit_mode=_require_text(value, "source_audit_mode"),
            record_hash=declared,
            **fields,
        )


@dataclass(frozen=True)
class ExecutionManifestV1:
    execution_id: str
    authorized_phase: str
    authorized_task_range: str
    authorized_mutation_roots: tuple[Path, ...]
    exact_authorized_files: tuple[Path, ...]
    production_home: Path
    test_home_root: Path
    baseline_manifest_hash: str
    bootstrap_foundation_record_hash: str
    python_profile_hash: str
    dependency_lock_hash: str
    plan_suite_hash: str
    approval_reference: str
    required_stop_point: str
    stable_command_id: str
    stable_request_hash: str
    manifest_hash: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExecutionManifestV1":
        if value.get("schema") != "EXECUTION_MANIFEST_V1":
            raise ManifestValidationError("wrong execution manifest schema")
        authorization = _require_mapping(value.get("authorization"), "authorization")
        roots = _require_mapping(value.get("roots"), "roots")
        hashes = _require_mapping(value.get("hashes"), "hashes")
        phase = _require_text(authorization, "authorized_phase")
        task_range = _require_text(authorization, "authorized_task_range")
        production = _resolved(_require_text(roots, "production_home"))
        test_home = ProductionHomeGuard(production).assert_test_home_isolated(
            _require_text(roots, "test_home_root")
        )
        raw_mutation_roots = roots.get("authorized_mutation_roots")
        if not isinstance(raw_mutation_roots, Sequence) or isinstance(raw_mutation_roots, (str, bytes)):
            raise ManifestValidationError("authorized_mutation_roots must be an array")
        mutation_roots = ProductionHomeGuard(production).assert_mutation_roots_safe(
            str(item) for item in raw_mutation_roots
        )
        raw_files = value.get("exact_authorized_files", [])
        if not isinstance(raw_files, Sequence) or isinstance(raw_files, (str, bytes)):
            raise ManifestValidationError("exact_authorized_files must be an array")
        exact_files = tuple(_resolved(str(item)) for item in raw_files)
        if len(set(exact_files)) != len(exact_files):
            raise ManifestValidationError("exact_authorized_files contains aliases or duplicates")
        for file_path in exact_files:
            if not any(file_path == root or _is_within(file_path, root) for root in mutation_roots):
                raise ManifestValidationError(f"authorized file is outside mutation roots: {file_path}")
        hash_fields = {
            name: _require_text(hashes, name)
            for name in (
                "baseline_manifest_hash",
                "bootstrap_foundation_record_hash",
                "python_profile_hash",
                "dependency_lock_hash",
                "plan_suite_hash",
            )
        }
        for name, field_value in hash_fields.items():
            _validate_sha256(field_value, name)
        stable_request_hash = _require_text(authorization, "stable_request_hash")
        _validate_sha256(stable_request_hash, "stable_request_hash")
        return cls(
            execution_id=_require_text(value, "execution_id"),
            authorized_phase=phase,
            authorized_task_range=task_range,
            authorized_mutation_roots=mutation_roots,
            exact_authorized_files=exact_files,
            production_home=production,
            test_home_root=test_home,
            approval_reference=_require_text(authorization, "approval_reference"),
            required_stop_point=_require_text(authorization, "required_stop_point"),
            stable_command_id=_require_text(authorization, "stable_command_id"),
            stable_request_hash=stable_request_hash,
            manifest_hash=sha256_prefixed(canonical_json_bytes(dict(value))),
            **hash_fields,
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "ExecutionManifestV1":
        return cls.from_mapping(load_json_read_only(path))

    def assert_promotion_from(
        self,
        foundation: BootstrapFoundationRecord,
        previous: "ExecutionManifestV1 | None" = None,
    ) -> None:
        if self.bootstrap_foundation_record_hash != foundation.record_hash:
            raise ManifestValidationError("execution manifest does not bind foundation record")
        if self.python_profile_hash != foundation.python_profile_hash:
            raise ManifestValidationError("python profile changed after bootstrap")
        if self.dependency_lock_hash != foundation.dependency_lock_hash:
            raise ManifestValidationError("dependency lock changed after bootstrap")
        if self.plan_suite_hash != foundation.plan_suite_hash:
            raise ManifestValidationError("plan suite changed after bootstrap")
        if previous is not None:
            expanded = (
                self.authorized_phase != previous.authorized_phase
                or self.authorized_task_range != previous.authorized_task_range
                or not set(self.authorized_mutation_roots).issubset(previous.authorized_mutation_roots)
            )
            if expanded and self.approval_reference == previous.approval_reference:
                raise ManifestValidationError("phase/task/scope expansion requires a new approval reference")


@dataclass(frozen=True)
class ExecutionScope:
    manifest: ExecutionManifestV1

    def assert_test_home(self, test_home: str | os.PathLike[str]) -> Path:
        candidate = assert_test_home_isolated(self.manifest.production_home, test_home)
        if candidate != self.manifest.test_home_root and not _is_within(
            candidate, self.manifest.test_home_root
        ):
            raise ManifestValidationError(f"test home is outside authorized root: {candidate}")
        return candidate

    def assert_mutation_authorized(self, path: str | os.PathLike[str]) -> Path:
        candidate = _resolved(path)
        if self.manifest.exact_authorized_files and candidate not in self.manifest.exact_authorized_files:
            raise ManifestValidationError(f"file is outside exact authorization: {candidate}")
        if not any(
            candidate == root or _is_within(candidate, root)
            for root in self.manifest.authorized_mutation_roots
        ):
            raise ManifestValidationError(f"path is outside mutation roots: {candidate}")
        return candidate
