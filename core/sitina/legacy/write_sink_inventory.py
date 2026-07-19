"""Static and dynamic inventory of Legacy mutation and external-I/O sinks."""

from __future__ import annotations

import ast
import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


MUTATING_METHODS = {
    "append_jsonl": "JSONL_APPEND",
    "write_json": "MUTABLE_JSON_WRITE",
    "write_text": "FILE_WRITE",
    "write_bytes": "FILE_WRITE",
    "write": "FILE_WRITE",
    "writelines": "FILE_WRITE",
    "mkdir": "DIRECTORY_CREATE",
    "touch": "FILE_CREATE",
    "unlink": "FILE_DELETE",
    "remove": "FILE_DELETE",
    "rmdir": "DIRECTORY_DELETE",
    "rmtree": "TREE_DELETE",
    "replace": "ATOMIC_REPLACE",
    "rename": "FILE_RENAME",
    "move": "FILE_MOVE",
    "copy": "FILE_COPY",
    "copy2": "FILE_COPY",
    "copytree": "TREE_COPY",
    "init_db": "SQLITE_SCHEMA_WRITE",
}
EXTERNAL_METHODS = {
    "urlopen": "PROVIDER_OR_NETWORK",
    "request": "PROVIDER_OR_NETWORK",
    "Popen": "EXTERNAL_PROCESS",
    "run": "EXTERNAL_PROCESS",
    "check_call": "EXTERNAL_PROCESS",
    "check_output": "EXTERNAL_PROCESS",
    "push": "REMOTE_PUBLICATION",
    "publish": "REMOTE_PUBLICATION",
}


@dataclass(frozen=True)
class SinkFinding:
    path: str
    line: int
    function: str
    operation: str
    sink_kind: str
    classification: str
    source: str


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: Path, relative: str, source: str):
        self.path = path
        self.relative = relative
        self.source = source
        self.parents: list[str] = []
        self.findings: list[SinkFinding] = []

    @property
    def function(self) -> str:
        return ".".join(self.parents) if self.parents else "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.parents.append(node.name)
        self.generic_visit(node)
        self.parents.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.parents.append(node.name)
        self.generic_visit(node)
        self.parents.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ""

    def _add(self, node: ast.Call, operation: str, sink_kind: str, classification: str) -> None:
        self.findings.append(
            SinkFinding(
                path=self.relative,
                line=node.lineno,
                function=self.function,
                operation=operation,
                sink_kind=sink_kind,
                classification=classification,
                source=self._segment(node).splitlines()[0][:240],
            )
        )

    def _call_name(self, node: ast.Call) -> str:
        function = node.func
        if isinstance(function, ast.Name):
            return function.id
        if isinstance(function, ast.Attribute):
            return function.attr
        return "<dynamic>"

    def _open_classification(self, node: ast.Call) -> tuple[str, str]:
        segment = self._segment(node)
        mode: str | None = None
        if node.args and isinstance(node.args[-1], ast.Constant) and isinstance(node.args[-1].value, str):
            possible = node.args[-1].value
            if len(possible) <= 8:
                mode = possible
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = keyword.value.value if isinstance(keyword.value.value, str) else None
        if any(token in segment for token in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")):
            return "FILE_DESCRIPTOR_WRITE", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE"
        if mode is None:
            if "os.open" in segment and "O_RDONLY" in segment:
                return "FILE_DESCRIPTOR_READ", "READ_ONLY"
            if ".open(" in segment or segment.startswith("open("):
                return "FILE_READ", "READ_ONLY_DEFAULT_MODE"
            return "DYNAMIC_OPEN", "UNKNOWN_DYNAMIC_OPEN"
        if any(character in mode for character in "wax+"):
            return "FILE_WRITE", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE"
        return "FILE_READ", "READ_ONLY"

    def _sql_classification(self, node: ast.Call) -> tuple[str, str]:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            sql = node.args[0].value.lstrip().upper()
            if sql.startswith(("SELECT", "PRAGMA QUERY_ONLY", "PRAGMA TABLE_INFO")):
                return "SQLITE_QUERY", "READ_ONLY"
            return "SQLITE_MUTATION", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE"
        return "SQLITE_DYNAMIC_STATEMENT", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE"

    def visit_Call(self, node: ast.Call) -> Any:
        name = self._call_name(node)
        segment = self._segment(node)
        if name == "open":
            operation, classification = self._open_classification(node)
            self._add(node, operation, "FILESYSTEM", classification)
        elif name in {"execute", "executemany", "executescript"}:
            operation, classification = self._sql_classification(node)
            self._add(node, operation, "SQLITE", classification)
        elif name == "connect":
            if "mode=ro" in segment or "query_only" in self.function.lower() or "scan_sqlite" in self.function.lower():
                self._add(node, "SQLITE_CONNECT", "SQLITE", "READ_ONLY")
            else:
                self._add(node, "SQLITE_CONNECT", "SQLITE", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE")
        elif name in MUTATING_METHODS:
            self._add(node, MUTATING_METHODS[name], "FILESYSTEM_OR_SQLITE", "LEGACY_MUTATION_REQUIRES_PHASE0_FENCE")
        elif name in EXTERNAL_METHODS:
            if name == "run" and not any(token in segment for token in ("subprocess", "self.runner", "tool", "git")):
                pass
            else:
                self._add(node, EXTERNAL_METHODS[name], "EXTERNAL", "LEGACY_EXTERNAL_REQUIRES_PHASE0_FENCE")
        self.generic_visit(node)


def scan_tree(root: Path) -> dict[str, Any]:
    repository = root.resolve(strict=True)
    source_root = repository / "core/sitina"
    findings: list[SinkFinding] = []
    parse_errors: list[dict[str, Any]] = []
    for path in sorted(source_root.rglob("*.py")):
        if path.is_symlink() or "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            parse_errors.append({"path": str(path.relative_to(repository)), "error": str(error)})
            continue
        scanner = _Scanner(path, path.relative_to(repository).as_posix(), source)
        scanner.visit(tree)
        findings.extend(scanner.findings)
    findings.sort(key=lambda item: (item.path, item.line, item.operation))
    entries = [asdict(item) for item in findings]
    core = {
        "schema": "LEGACY_WRITE_SINK_INVENTORY_V1",
        "root": str(repository),
        "scanner_profile": "PYTHON_AST_LEGACY_SINKS_V1",
        "entries": entries,
        "parse_errors": parse_errors,
        "summary": {
            "entry_count": len(entries),
            "read_only_count": sum(item.classification.startswith("READ_ONLY") for item in findings),
            "legacy_mutation_count": sum("MUTATION" in item.classification for item in findings),
            "legacy_external_count": sum("EXTERNAL" in item.classification for item in findings),
            "unknown_count": sum(item.classification.startswith("UNKNOWN") for item in findings) + len(parse_errors),
        },
    }
    return {**core, "inventory_sha256": hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


class AuditSinkRecorder:
    """Collect process-level mutation audit events for one disposable home."""

    def __init__(self, allowed_home: Path):
        self.allowed_home = allowed_home.resolve(strict=True)
        self.records: list[dict[str, Any]] = []

    def _record_path(self, event: str, raw_path: object) -> None:
        if not isinstance(raw_path, (str, bytes, os.PathLike)):
            return
        path = Path(os.fsdecode(raw_path)).expanduser().resolve(strict=False)
        self.records.append(
            {
                "event": event,
                "path": str(path),
                "inside_allowed_home": path == self.allowed_home or self.allowed_home in path.parents,
            }
        )

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        if event == "open" and args:
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            mutating = isinstance(mode, str) and any(character in mode for character in "wax+")
            mutating = mutating or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if mutating:
                self._record_path(event, args[0])
        elif event in {"os.remove", "os.rename", "os.rmdir", "shutil.copyfile", "shutil.copytree"} and args:
            self._record_path(event, args[0])
        elif event in {"sqlite3.connect", "subprocess.Popen", "socket.connect"}:
            self.records.append({"event": event, "arguments": repr(args)[:500]})

    def install(self) -> "AuditSinkRecorder":
        sys.addaudithook(self.hook)
        return self


def write_inventory(path: Path, inventory: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(inventory, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    inventory = scan_tree(arguments.root)
    write_inventory(arguments.output, inventory)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "inventory_sha256": inventory["inventory_sha256"],
                "summary": inventory["summary"],
            },
            sort_keys=True,
        )
    )
    return 0 if inventory["summary"]["unknown_count"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
