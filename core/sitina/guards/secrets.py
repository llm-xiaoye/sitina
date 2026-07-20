from __future__ import annotations

import base64
import binascii
import json
import math
import re
import sqlite3
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sitina.utils import read_json, sha256_text, stable_json, write_json


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "named_secret_assignment",
        re.compile(
            r"(?i)[\"']?\b([A-Za-z0-9_]*(?:api[_-]?key|auth[_-]?token|access[_-]?token|password|private[_-]?key|secret))\b[\"']?\s*[:=]\s*[\"']?([^\s\"',}\]]{8,})"
        ),
    ),
    ("authorization", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{12,})")),
    ("openai_style_key", re.compile(r"\b(sk-[A-Za-z0-9_-]{16,})\b")),
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{24,})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{20,})\b")),
    ("private_key", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
)

HIGH_ENTROPY_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{24,256})(?![A-Za-z0-9+/=_-])"
)

SENSITIVE_FIELD = re.compile(r"(?i)(^|[._-])(api[_-]?key|auth(orization)?|access[_-]?token|token|password|private[_-]?key|secret)($|[._-])")
PLACEHOLDER_MARKERS = (
    "<redacted>",
    "${",
    "your_api_key",
    "your-api-key",
    "your_token",
    "your-token",
    "placeholder",
    "example.com",
    "sk-example",
    "changeme",
    "replace_me",
)


@dataclass(frozen=True)
class SecretFinding:
    scope: str
    path: str
    field_path: str
    pattern_type: str
    table: str | None = None
    row_id: str | None = None

    @property
    def field(self) -> str:
        return self.field_path

    @property
    def pattern(self) -> str:
        return self.pattern_type

    def safe_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "path": self.path,
            "table": self.table,
            "row_id": self.row_id,
            "field_path": self.field_path,
            "pattern_type": self.pattern_type,
            "count": 1,
        }


def scan_text_for_secrets(
    text: str,
    *,
    path: str = "<text>",
    scope: str = "text",
    field_path: str = "<text>",
    table: str | None = None,
    row_id: str | None = None,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(character for character in normalized if unicodedata.category(character) != "Cf")
    variants = tuple(dict.fromkeys((normalized, urllib.parse.unquote(normalized))))
    for variant in variants:
        for pattern_name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(variant):
                candidate = match.group(match.lastindex or 0) if match.lastindex else match.group(0)
                if _is_placeholder(candidate):
                    continue
                field = match.group(1).lower() if pattern_name == "named_secret_assignment" and match.lastindex and match.lastindex >= 2 else field_path
                findings.append(
                    SecretFinding(
                        scope=scope,
                        path=path,
                        table=table,
                        row_id=row_id,
                        field_path=field_path if field_path != "<text>" else field,
                        pattern_type=pattern_name,
                    )
                )
        for match in HIGH_ENTROPY_CANDIDATE.finditer(variant):
            if _looks_like_high_entropy_secret(match.group(1)):
                findings.append(
                    SecretFinding(
                        scope=scope,
                        path=path,
                        table=table,
                        row_id=row_id,
                        field_path=field_path,
                        pattern_type="high_entropy_token",
                    )
                )
    return _dedupe(findings)


def scan_json_for_secrets(
    value: Any,
    *,
    path: str = "<json>",
    scope: str = "json",
    field_path: str = "$",
    table: str | None = None,
    row_id: str | None = None,
    _depth: int = 0,
) -> list[SecretFinding]:
    if _depth > 8:
        return []
    findings: list[SecretFinding] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            child_path = f"{field_path}.{key}"
            if isinstance(nested, str) and _is_sensitive_field_name(str(key)) and _looks_like_secret_value(nested):
                findings.append(
                    SecretFinding(
                        scope=scope,
                        path=path,
                        table=table,
                        row_id=row_id,
                        field_path=child_path,
                        pattern_type="sensitive_field",
                    )
                )
            findings.extend(
                scan_json_for_secrets(
                    nested,
                    path=path,
                    scope=scope,
                    field_path=child_path,
                    table=table,
                    row_id=row_id,
                    _depth=_depth + 1,
                )
            )
    elif isinstance(value, list):
        fragments = [nested for nested in value if isinstance(nested, str)]
        if len(fragments) > 1:
            findings.extend(
                scan_text_for_secrets(
                    "".join(fragments),
                    path=path,
                    scope=scope,
                    field_path=f"{field_path}.$joined",
                    table=table,
                    row_id=row_id,
                )
            )
        for index, nested in enumerate(value):
            findings.extend(
                scan_json_for_secrets(
                    nested,
                    path=path,
                    scope=scope,
                    field_path=f"{field_path}[{index}]",
                    table=table,
                    row_id=row_id,
                    _depth=_depth + 1,
                )
            )
    elif isinstance(value, str):
        findings.extend(scan_text_for_secrets(value, path=path, scope=scope, field_path=field_path, table=table, row_id=row_id))
        for decoded in _decoded_candidates(value, field_path):
            try:
                nested = json.loads(decoded)
            except (TypeError, json.JSONDecodeError):
                findings.extend(scan_text_for_secrets(decoded, path=path, scope=scope, field_path=field_path, table=table, row_id=row_id))
            else:
                findings.extend(
                    scan_json_for_secrets(
                        nested,
                        path=path,
                        scope=scope,
                        field_path=f"{field_path}.$decoded",
                        table=table,
                        row_id=row_id,
                        _depth=_depth + 1,
                    )
                )
    return _dedupe(findings)


def scan_paths_for_secrets(paths: Iterable[Path | str], *, scope: str = "files") -> dict[str, Any]:
    findings: list[SecretFinding] = []
    scanned_files = 0
    skipped_files = 0
    for item in paths:
        path = Path(item)
        if not path.exists():
            continue
        candidates = [path] if path.is_file() else [candidate for candidate in path.rglob("*") if candidate.is_file()]
        for candidate in candidates:
            if _should_skip(candidate):
                skipped_files += 1
                continue
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped_files += 1
                continue
            scanned_files += 1
            findings.extend(_scan_file_text(candidate, text, scope))
    findings = _dedupe(findings)
    return _summary(findings, scanned_files=scanned_files, skipped_files=skipped_files)


def scan_sqlite_for_secrets(db_path: Path | str, *, scope: str = "sqlite") -> dict[str, Any]:
    path = Path(db_path)
    if not path.is_file():
        return _summary([], scanned_files=0, skipped_files=0, scanned_rows=0)
    findings: list[SecretFinding] = []
    scanned_rows = 0
    uri = f"file:{urllib.parse.quote(str(path.resolve()))}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    try:
        conn.execute("PRAGMA query_only=ON")
        tables = [
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        ]
        for table in tables:
            columns = [
                (str(row[1]), str(row[2]).upper())
                for row in conn.execute(f"PRAGMA table_info({_quote_identifier(table)})")
                if str(row[2]).upper() in {"", "TEXT", "JSON", "VARCHAR"} or "CHAR" in str(row[2]).upper()
            ]
            if not columns:
                continue
            names = [name for name, _kind in columns]
            select = ", ".join(_quote_identifier(name) for name in names)
            cursor = conn.execute(f"SELECT rowid, {select} FROM {_quote_identifier(table)}")
            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    scanned_rows += 1
                    row_id = str(row[0])
                    for index, value in enumerate(row[1:]):
                        if not isinstance(value, str) or not value:
                            continue
                        field = names[index]
                        try:
                            parsed = json.loads(value)
                        except json.JSONDecodeError:
                            findings.extend(
                                scan_text_for_secrets(
                                    value,
                                    path=str(path),
                                    scope=scope,
                                    field_path=field,
                                    table=table,
                                    row_id=row_id,
                                )
                            )
                        else:
                            findings.extend(
                                scan_json_for_secrets(
                                    parsed,
                                    path=str(path),
                                    scope=scope,
                                    field_path=field,
                                    table=table,
                                    row_id=row_id,
                                )
                            )
    finally:
        conn.close()
    return _summary(_dedupe(findings), scanned_files=1, skipped_files=0, scanned_rows=scanned_rows)


def secret_scan_scopes(home: Path) -> dict[str, list[Path]]:
    return {
        "ledger": [home / "logs" / "runs"],
        "audit": [home / "logs" / "audit"],
        "blackboard": [home / "state" / "blackboard.json", home / "state" / "blackboard_runs"],
        "trace": [home / "logs" / "events", home / "logs" / "runs"],
        "replay": [home / "artifacts" / "replay_snapshots", home / "logs" / "runs"],
        "checkpoints": [home / "artifacts" / "checkpoints"],
        "artifacts": [home / "artifacts"],
        "provider_error_artifacts": [home / "artifacts" / "provider_parse_failures"],
        "outputs/reports": [home / "outputs" / "reports"],
        "evidence_bundles": [home / "outputs" / "evidence"],
        "docs": [home / "docs"],
    }


def scan_named_scopes(home: Path) -> dict[str, dict[str, Any]]:
    results = {name: scan_paths_for_secrets(paths, scope=name) for name, paths in secret_scan_scopes(home).items()}
    results["sqlite"] = _cached_sqlite_scan(home)
    return results


def _cached_sqlite_scan(home: Path) -> dict[str, Any]:
    db_path = home / "data" / "sitina.db"
    cache_path = home / "outputs" / "evidence" / "secret_scan_cache" / "sqlite.json"
    before = _sqlite_fingerprint(db_path)
    cached = read_json(cache_path, default=None)
    if isinstance(cached, dict):
        claimed = cached.get("evidence_hash")
        body = {key: value for key, value in cached.items() if key != "evidence_hash"}
        if (
            body.get("scanner_version") == "2.0"
            and body.get("database_fingerprint") == before
            and claimed == sha256_text(stable_json(body))
            and isinstance(body.get("result"), dict)
        ):
            return dict(body["result"]) | {"cache_status": "verified_hit", "database_fingerprint": before}
    result = scan_sqlite_for_secrets(db_path, scope="sqlite")
    after = _sqlite_fingerprint(db_path)
    if before == after:
        body = {"scanner_version": "2.0", "database_fingerprint": after, "result": result}
        write_json(cache_path, body | {"evidence_hash": sha256_text(stable_json(body))})
    return result | {"cache_status": "miss", "database_fingerprint": after}


def _sqlite_fingerprint(db_path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(db_path) + suffix)
        if not path.exists():
            values[suffix or "database"] = None
            continue
        stat = path.stat()
        values[suffix or "database"] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    return values


def _scan_file_text(path: Path, text: str, scope: str) -> list[SecretFinding]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return scan_json_for_secrets(json.loads(text), path=str(path), scope=scope)
        except json.JSONDecodeError:
            return scan_text_for_secrets(text, path=str(path), scope=scope)
    if suffix == ".jsonl":
        findings: list[SecretFinding] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                findings.extend(scan_text_for_secrets(line, path=str(path), scope=scope, field_path=f"line[{line_number}]"))
            else:
                findings.extend(scan_json_for_secrets(value, path=str(path), scope=scope, field_path=f"line[{line_number}]"))
        return findings
    return scan_text_for_secrets(text, path=str(path), scope=scope)


def _decoded_candidates(value: str, field_path: str) -> list[str]:
    candidates: list[str] = []
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        candidates.append(stripped)
    unquoted = urllib.parse.unquote(stripped)
    if unquoted != stripped:
        candidates.append(unquoted)
    if 16 <= len(stripped) <= 1_000_000:
        try:
            decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
        else:
            candidates.append(decoded)
    return list(dict.fromkeys(candidates))


def _looks_like_high_entropy_secret(value: str) -> bool:
    candidate = value.strip("=_'\"")
    if len(candidate) < 24 or _is_placeholder(candidate) or not _looks_like_secret_value(candidate):
        return False
    # Generic entropy detection is deliberately narrower than the prefix and
    # sensitive-field detectors.  Requiring mixed-case letters plus digits
    # avoids treating hashes, request IDs, filesystem paths, and prose-like
    # identifiers as credentials while still catching opaque random tokens.
    if not all(re.search(pattern, candidate) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]")):
        return False
    if candidate.count("/") > 1 or "\\" in candidate:
        return False
    if re.fullmatch(
        r"[A-Za-z][A-Za-z0-9._-]*-\d{8}T\d{6,12}(?:Z|[+-]\d{4})(?:-[A-Za-z0-9._-]+)?",
        candidate,
    ):
        return False
    if re.search(r"\d{8}T\d{6,12}$", candidate):
        return False
    if re.search(r"\d{8}T\d{6,12}Z$", candidate):
        return False
    counts = {character: candidate.count(character) for character in set(candidate)}
    entropy = -sum(
        (count / len(candidate)) * math.log2(count / len(candidate))
        for count in counts.values()
    )
    return entropy >= 4.0


def _looks_like_secret_value(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    if len(stripped) < 8 or _is_placeholder(stripped):
        return False
    if stripped.lower().replace("-", "_").replace(" ", "_") in {
        "not_granted",
        "not_required",
        "not_requested",
        "authorization_required",
        "approval_required",
        "awaiting_approval",
    }:
        return False
    if re.fullmatch(r"(?i)(sha256:)?[0-9a-f]{32,128}", stripped):
        return False
    if re.fullmatch(r"(?i)(provider|request|run|trace|ledger|audit)_[A-Za-z0-9_-]{8,}", stripped):
        return False
    return True


def _is_sensitive_field_name(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    lowered = "".join(
        character for character in normalized if unicodedata.category(character) != "Cf"
    ).lower()
    benign = (
        "token_budget",
        "token_usage",
        "token_count",
        "token_hash",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "max_tokens",
        "write_authorization",
        "authorization_status",
    )
    return lowered not in benign and bool(SENSITIVE_FIELD.search(lowered))


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().strip("\"'").lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if re.fullmatch(r"[x*._-]{8,}", lowered):
        return True
    return False


def _dedupe(findings: list[SecretFinding]) -> list[SecretFinding]:
    unique: dict[tuple[Any, ...], SecretFinding] = {}
    for finding in findings:
        key = (finding.scope, finding.path, finding.table, finding.row_id, finding.field_path, finding.pattern_type)
        unique[key] = finding
    return list(unique.values())


def _summary(findings: list[SecretFinding], **counts: Any) -> dict[str, Any]:
    return {
        "status": "ok" if not findings else "suspicious",
        "count": len(findings),
        **counts,
        "findings": [finding.safe_dict() for finding in findings],
    }


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if "profiles" in parts:
        return True
    if "__pycache__" in parts or path.suffix.lower() in {".pyc", ".pyo"}:
        return True
    if path.suffix.lower() in {".db", ".db-wal", ".db-shm", ".sqlite", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz"}:
        return True
    if path.name.startswith("."):
        return True
    return False
