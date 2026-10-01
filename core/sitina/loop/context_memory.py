from __future__ import annotations

from typing import Any, Mapping

from .storage import LoopEventStore, StoredContent


class ContextMemoryModule:
    """CAS-backed task content boundary; semantic memory arrives in later batches."""

    def __init__(self, store: LoopEventStore) -> None:
        self.store = store

    def persist(self, value: Mapping[str, Any], *, purpose: str) -> StoredContent:
        return self.store.publish_json(value, purpose=purpose)

    def read(self, reference_id: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        return self.store.read_json(reference_id, expected_hash=expected_hash)
