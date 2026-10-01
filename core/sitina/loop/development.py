from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


MARKER_NAME = ".sitina-r4-development-root-v1.json"


class DevelopmentBoundaryError(RuntimeError):
    """The batch-1b development authority is not rooted in the marked checkout."""


def _absolute_without_symlink_resolution(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _contains_symlink(path: Path) -> bool:
    current = path
    while True:
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return True
        except FileNotFoundError:
            pass
        if current.parent == current:
            return False
        current = current.parent


def _require_physical_child(path: Path, parent: Path, label: str, *, must_exist: bool) -> Path:
    lexical = _absolute_without_symlink_resolution(path)
    if _contains_symlink(lexical):
        raise DevelopmentBoundaryError(f"{label} contains a symlink component")
    if must_exist and not lexical.exists():
        raise DevelopmentBoundaryError(f"{label} is missing")
    resolved = lexical.resolve(strict=must_exist)
    if resolved != parent and parent not in resolved.parents:
        raise DevelopmentBoundaryError(f"{label} escapes its authorized root")
    return resolved


@dataclass(frozen=True)
class DevelopmentBoundary:
    source_root: Path
    interpreter: Path
    config_root: Path
    state_root: Path
    business_workspace: Path
    runtime_root: Path
    credential_references: tuple[Path, ...]
    forbidden_write_roots: tuple[Path, ...]

    @classmethod
    def validate(
        cls,
        *,
        state_root: str | os.PathLike[str],
        business_workspace: str | os.PathLike[str],
        source_root: str | os.PathLike[str] | None = None,
        interpreter: str | os.PathLike[str] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> "DevelopmentBoundary":
        env = dict(os.environ if environment is None else environment)
        derived_root = Path(__file__).resolve().parents[3]
        requested_root = source_root if source_root is not None else env.get("SITINA_R4_DEV_ROOT")
        if not requested_root:
            raise DevelopmentBoundaryError("SITINA_R4_DEV_ROOT is required; use bin/sitina-r4-dev")
        lexical_root = _absolute_without_symlink_resolution(requested_root)
        if _contains_symlink(lexical_root):
            raise DevelopmentBoundaryError("development source root contains a symlink component")
        if not lexical_root.is_dir():
            raise DevelopmentBoundaryError("development source root is missing")
        physical_root = lexical_root.resolve(strict=True)
        if source_root is None and physical_root != derived_root:
            raise DevelopmentBoundaryError("development source root differs from the executing checkout")

        marker_path = physical_root / MARKER_NAME
        if not marker_path.is_file() or marker_path.is_symlink():
            raise DevelopmentBoundaryError("development-root marker is missing or is a symlink")
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DevelopmentBoundaryError("development-root marker is unreadable") from error
        if not isinstance(marker, dict) or marker.get("schema") != "SITINA_R4_DEVELOPMENT_ROOT_V1":
            raise DevelopmentBoundaryError("development-root marker schema is invalid")
        declared = _absolute_without_symlink_resolution(str(marker.get("development_root") or ""))
        if declared != physical_root:
            raise DevelopmentBoundaryError("development-root marker is bound to another path")

        declared_home = env.get("SITINA_HOME")
        if not declared_home:
            raise DevelopmentBoundaryError("SITINA_HOME is required; use bin/sitina-r4-dev")
        if _absolute_without_symlink_resolution(declared_home) != physical_root:
            raise DevelopmentBoundaryError("SITINA_HOME differs from the physical development root")

        expected_python = physical_root / ".venv-r4" / "bin" / "python"
        selected_python = interpreter if interpreter is not None else env.get("SITINA_PYTHON")
        if not selected_python:
            raise DevelopmentBoundaryError("SITINA_PYTHON is required; use bin/sitina-r4-dev")
        lexical_python = _absolute_without_symlink_resolution(selected_python)
        if lexical_python != expected_python or not lexical_python.is_file():
            raise DevelopmentBoundaryError("development interpreter is not the pinned .venv-r4 entry")
        physical_python = lexical_python.resolve(strict=True)
        if source_root is None and physical_python != Path(sys.executable).resolve(strict=True):
            raise DevelopmentBoundaryError("running interpreter differs from SITINA_PYTHON")

        runtime_relative = str(marker.get("runtime_relative_root") or "")
        if not runtime_relative or Path(runtime_relative).is_absolute() or ".." in Path(runtime_relative).parts:
            raise DevelopmentBoundaryError("runtime_relative_root is invalid")
        runtime_root = _require_physical_child(
            physical_root / runtime_relative,
            physical_root,
            "runtime root",
            must_exist=False,
        )
        state_authority_relative = str(marker.get("state_authority_relative_root") or "")
        if (
            not state_authority_relative
            or Path(state_authority_relative).is_absolute()
            or ".." in Path(state_authority_relative).parts
        ):
            raise DevelopmentBoundaryError("state_authority_relative_root is invalid")
        state_authority_root = _require_physical_child(
            physical_root / state_authority_relative,
            runtime_root,
            "declared state authority root",
            must_exist=False,
        )
        config_root = _require_physical_child(
            physical_root / "config", physical_root, "configuration root", must_exist=True
        )
        resolved_state = _require_physical_child(
            Path(state_root), runtime_root, "state root", must_exist=False
        )
        if resolved_state != state_authority_root:
            raise DevelopmentBoundaryError(
                "state root differs from the development manifest's unique state authority root"
            )
        workspace_parent = runtime_root / "workspaces"
        resolved_workspace = _require_physical_child(
            Path(business_workspace), workspace_parent, "business workspace", must_exist=False
        )

        forbidden = tuple(
            _absolute_without_symlink_resolution(str(item)).resolve(strict=False)
            for item in marker.get("forbidden_write_roots", ())
        )
        for label, candidate in (
            ("state root", resolved_state),
            ("business workspace", resolved_workspace),
        ):
            if any(candidate == root or root in candidate.parents for root in forbidden):
                raise DevelopmentBoundaryError(f"{label} overlaps a forbidden write root")

        credentials: list[Path] = []
        for record in marker.get("credential_references", ()):
            if not isinstance(record, dict) or record.get("access") != "read_only_reference":
                raise DevelopmentBoundaryError("credential references must be explicitly read-only")
            lexical = _absolute_without_symlink_resolution(physical_root / str(record.get("path") or ""))
            if physical_root not in lexical.parents:
                raise DevelopmentBoundaryError("credential reference must be named inside the development root")
            target = lexical.resolve(strict=True)
            if not target.is_file():
                raise DevelopmentBoundaryError("credential reference target is not a file")
            credentials.append(target)

        return cls(
            source_root=physical_root,
            interpreter=physical_python,
            config_root=config_root,
            state_root=resolved_state,
            business_workspace=resolved_workspace,
            runtime_root=runtime_root,
            credential_references=tuple(credentials),
            forbidden_write_roots=forbidden,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "SITINA_R4_DEVELOPMENT_BOUNDARY_V1",
            "source_root": str(self.source_root),
            "interpreter": str(self.interpreter),
            "config_root": str(self.config_root),
            "state_root": str(self.state_root),
            "state_authority_root": str(self.state_root),
            "business_workspace": str(self.business_workspace),
            "runtime_root": str(self.runtime_root),
            "credential_references": [
                {"resolved_path": str(path), "access": "read_only_reference"}
                for path in self.credential_references
            ],
            "forbidden_write_roots": [str(path) for path in self.forbidden_write_roots],
        }


@dataclass(frozen=True)
class InstallationBoundary:
    """Physical installed-source boundary for the current Loop runtime."""

    source_root: Path
    interpreter: Path
    interpreter_entry: Path
    config_root: Path
    state_root: Path
    business_workspace: Path
    runtime_root: Path
    credential_references: tuple[Path, ...]
    forbidden_write_roots: tuple[Path, ...]

    @classmethod
    def validate(
        cls,
        *,
        state_root: str | os.PathLike[str],
        business_workspace: str | os.PathLike[str],
        source_root: str | os.PathLike[str] | None = None,
        interpreter: str | os.PathLike[str] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> "InstallationBoundary":
        env = dict(os.environ if environment is None else environment)
        derived_root = Path(__file__).resolve().parents[3]
        requested_root = (
            source_root
            if source_root is not None
            else env.get("SITINA_SOURCE_ROOT") or env.get("SITINA_HOME")
        )
        if not requested_root:
            raise DevelopmentBoundaryError(
                "SITINA_SOURCE_ROOT is required; use the installed bin/sitina launcher"
            )
        lexical_root = _absolute_without_symlink_resolution(requested_root)
        if _contains_symlink(lexical_root):
            raise DevelopmentBoundaryError("installed source root contains a symlink component")
        if not lexical_root.is_dir():
            raise DevelopmentBoundaryError("installed source root is missing")
        physical_root = lexical_root.resolve(strict=True)
        if source_root is None and physical_root != derived_root:
            raise DevelopmentBoundaryError("installed source root differs from the executing package")
        if (physical_root / MARKER_NAME).exists():
            raise DevelopmentBoundaryError(
                "a marked development checkout must use bin/sitina-r4-dev"
            )

        declared_home = env.get("SITINA_HOME")
        if not declared_home:
            raise DevelopmentBoundaryError(
                "SITINA_HOME is required; use the installed bin/sitina launcher"
            )
        if _absolute_without_symlink_resolution(declared_home) != physical_root:
            raise DevelopmentBoundaryError("SITINA_HOME differs from the installed source root")

        declared_source = env.get("SITINA_SOURCE_ROOT")
        if not declared_source:
            raise DevelopmentBoundaryError(
                "SITINA_SOURCE_ROOT is required; use the installed bin/sitina launcher"
            )
        if _absolute_without_symlink_resolution(declared_source) != physical_root:
            raise DevelopmentBoundaryError("SITINA_SOURCE_ROOT differs from the installed source root")

        selected_python = interpreter if interpreter is not None else env.get("SITINA_PYTHON")
        if not selected_python:
            raise DevelopmentBoundaryError(
                "SITINA_PYTHON is required; use the installed bin/sitina launcher"
            )
        lexical_python = _absolute_without_symlink_resolution(selected_python)
        if not lexical_python.is_file():
            raise DevelopmentBoundaryError("installed interpreter is missing")
        physical_python = lexical_python.resolve(strict=True)
        if source_root is None and physical_python != Path(sys.executable).resolve(strict=True):
            raise DevelopmentBoundaryError("running interpreter differs from SITINA_PYTHON")

        config_root = _require_physical_child(
            physical_root / "config", physical_root, "configuration root", must_exist=True
        )
        runtime_root = _require_physical_child(
            physical_root / "runtime/loop", physical_root, "runtime root", must_exist=False
        )
        state_authority_root = _require_physical_child(
            runtime_root / "state", runtime_root, "state authority root", must_exist=False
        )
        resolved_state = _require_physical_child(
            Path(state_root), runtime_root, "state root", must_exist=False
        )
        if resolved_state != state_authority_root:
            raise DevelopmentBoundaryError(
                "state root differs from the installed runtime's unique state authority root"
            )
        workspace_parent = runtime_root / "workspaces"
        resolved_workspace = _require_physical_child(
            Path(business_workspace), workspace_parent, "business workspace", must_exist=False
        )

        forbidden = tuple(
            (physical_root / name).resolve(strict=False)
            for name in ("bin", "config", "core", "docs", "profiles", "schemas", "scripts", "tests")
        )
        for label, candidate in (
            ("state root", resolved_state),
            ("business workspace", resolved_workspace),
        ):
            if any(candidate == root or root in candidate.parents for root in forbidden):
                raise DevelopmentBoundaryError(f"{label} overlaps a forbidden write root")

        credentials: tuple[Path, ...] = ()
        credential_path = physical_root / "profiles/deepseek.env"
        if credential_path.exists() or credential_path.is_symlink():
            target = credential_path.resolve(strict=True)
            if not target.is_file():
                raise DevelopmentBoundaryError("credential reference target is not a file")
            credentials = (target,)

        return cls(
            source_root=physical_root,
            interpreter=physical_python,
            interpreter_entry=lexical_python,
            config_root=config_root,
            state_root=resolved_state,
            business_workspace=resolved_workspace,
            runtime_root=runtime_root,
            credential_references=credentials,
            forbidden_write_roots=forbidden,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "SITINA_LOOP_INSTALLATION_BOUNDARY_V1",
            "source_root": str(self.source_root),
            "interpreter": str(self.interpreter),
            "config_root": str(self.config_root),
            "state_root": str(self.state_root),
            "state_authority_root": str(self.state_root),
            "business_workspace": str(self.business_workspace),
            "runtime_root": str(self.runtime_root),
            "credential_references": [
                {"resolved_path": str(path), "access": "read_only_reference"}
                for path in self.credential_references
            ],
            "forbidden_write_roots": [str(path) for path in self.forbidden_write_roots],
        }


RuntimeBoundary = DevelopmentBoundary | InstallationBoundary


def default_runtime_locations(
    environment: Mapping[str, str] | None = None,
) -> tuple[Path, Path]:
    """Return the unique current-Loop state root and default managed workspace."""

    env = dict(os.environ if environment is None else environment)
    development_root = env.get("SITINA_R4_DEV_ROOT")
    if development_root:
        root = _absolute_without_symlink_resolution(development_root)
        marker_path = root / MARKER_NAME
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DevelopmentBoundaryError("development-root marker is unreadable") from error
        runtime_relative = str(marker.get("runtime_relative_root") or "")
        state_relative = str(marker.get("state_authority_relative_root") or "")
        if (
            not runtime_relative
            or not state_relative
            or Path(runtime_relative).is_absolute()
            or Path(state_relative).is_absolute()
            or ".." in Path(runtime_relative).parts
            or ".." in Path(state_relative).parts
        ):
            raise DevelopmentBoundaryError("development runtime locations are invalid")
        runtime_root = root / runtime_relative
        return root / state_relative, runtime_root / "workspaces/default"

    requested_root = env.get("SITINA_SOURCE_ROOT") or env.get("SITINA_HOME")
    if not requested_root:
        raise DevelopmentBoundaryError(
            "SITINA_SOURCE_ROOT is required; use the installed bin/sitina launcher"
        )
    root = _absolute_without_symlink_resolution(requested_root)
    runtime_root = root / "runtime/loop"
    return runtime_root / "state", runtime_root / "workspaces/default"


def validate_runtime_boundary(
    *,
    state_root: str | os.PathLike[str] | None = None,
    business_workspace: str | os.PathLike[str] | None = None,
    source_root: str | os.PathLike[str] | None = None,
    interpreter: str | os.PathLike[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeBoundary:
    """Validate either the marked development layout or the installed layout."""

    env = dict(os.environ if environment is None else environment)
    default_state, default_workspace = default_runtime_locations(env)
    selected_state = default_state if state_root is None else Path(state_root)
    selected_workspace = default_workspace if business_workspace is None else Path(business_workspace)
    if env.get("SITINA_R4_DEV_ROOT"):
        return DevelopmentBoundary.validate(
            state_root=selected_state,
            business_workspace=selected_workspace,
            source_root=source_root,
            interpreter=interpreter,
            environment=env,
        )
    return InstallationBoundary.validate(
        state_root=selected_state,
        business_workspace=selected_workspace,
        source_root=source_root,
        interpreter=interpreter,
        environment=env,
    )


def runtime_subprocess_environment(
    boundary: RuntimeBoundary,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Bind a child host to the already-validated current-Loop runtime."""

    result = dict(os.environ if environment is None else environment)
    result.update(
        {
            "SITINA_HOME": str(boundary.source_root),
            "SITINA_SOURCE_ROOT": str(boundary.source_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(boundary.source_root / "core"),
        }
    )
    if isinstance(boundary, DevelopmentBoundary):
        result["SITINA_R4_DEV_ROOT"] = str(boundary.source_root)
    else:
        result.pop("SITINA_R4_DEV_ROOT", None)
    result["SITINA_PYTHON"] = str(boundary_interpreter_entry(boundary))
    return result


def boundary_interpreter_entry(boundary: RuntimeBoundary) -> Path:
    """Return the launcher entry that validates back to this boundary."""

    if isinstance(boundary, DevelopmentBoundary):
        return boundary.source_root / ".venv-r4/bin/python"
    try:
        physical_entry = boundary.interpreter_entry.resolve(strict=True)
    except OSError as error:
        raise DevelopmentBoundaryError("installed interpreter entry is unavailable") from error
    if physical_entry != boundary.interpreter:
        raise DevelopmentBoundaryError(
            "installed interpreter entry no longer matches the validated interpreter"
        )
    return boundary.interpreter_entry


def boundary_environment_prefix(boundary: RuntimeBoundary) -> str:
    return (
        "development-environment"
        if isinstance(boundary, DevelopmentBoundary)
        else "installation-environment"
    )
