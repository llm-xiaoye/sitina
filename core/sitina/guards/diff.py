from __future__ import annotations

from pathlib import Path

from sitina.utils import file_sha256, sha256_text, stable_json


class DiffVerifier:
    def before_hash(self, path: str | Path) -> str | None:
        return file_sha256(Path(path))

    def verify_scope(self, changed_files: list[str], approved_files: list[str]) -> tuple[bool, list[str]]:
        approved = {str(Path(p).expanduser().resolve(strict=False)) for p in approved_files}
        actual = {str(Path(p).expanduser().resolve(strict=False)) for p in changed_files}
        out_of_scope = sorted(actual - approved)
        return not out_of_scope, out_of_scope

    def diff_hash(self, before: dict[str, str | None], after: dict[str, str | None]) -> str:
        return sha256_text(stable_json({"before": before, "after": after}))

    def verify_before_hash(self, path: str | Path, expected: str | None) -> tuple[bool, str | None]:
        current = file_sha256(Path(path))
        return current == expected, current
