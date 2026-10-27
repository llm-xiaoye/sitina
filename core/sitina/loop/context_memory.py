from __future__ import annotations

from typing import Any, Mapping

from .storage import LoopEventStore, StoredContent


class ContextMemoryModule:
    """Immutable task-content storage, the bottom layer of task memory.

    Journal events commit these CAS references. LoopContextIndex reconstructs
    versioned task notes; LoopRequestAssembler budgets their per-Agent views.
    This storage adapter itself performs no semantic retrieval or confirmation.
    """

    def __init__(self, store: LoopEventStore) -> None:
        self.store = store

    def persist(self, value: Mapping[str, Any], *, purpose: str) -> StoredContent:
        return self.store.publish_json(value, purpose=purpose)

    def read(self, reference_id: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        return self.store.read_json(reference_id, expected_hash=expected_hash)
