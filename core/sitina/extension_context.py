from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ExtensionPreparationContext:
    """Backend-issued, single-execution binding for extension preparation."""

    task_id: str
    operation_id: str
    source_path: str
    extension_root: str
    intent: Any
    source_tree_hash: str | None
    environment_hash: str | None
    binding_digest: str
    _backend: Any = field(repr=False, compare=False)

    def assert_issued_by(self, backend: Any) -> None:
        if self._backend is not backend:
            raise RuntimeError("extension preparation context belongs to another LoopBackend")
