from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from sitina.commands.model import CommandEnvelope
from sitina.journal.model import EventEnvelope, canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp

from .native import MemoryACL, MemoryDocument, MemoryRepository, MemoryStateError


class MemoryManagementError(RuntimeError):
    pass


class RetrievalBackend(Protocol):
    def rank(self, query: str, documents: Mapping[str, str]) -> Mapping[str, int]: ...


@dataclass(frozen=True)
class MemoryHit:
    document: MemoryDocument
    relevance_millis: int
    freshness_millis: int
    combined_score_millis: int
    untrusted_text: str
    backend: str


@dataclass(frozen=True)
class MemoryConsolidation:
    document: MemoryDocument
    source_memory_ids: tuple[str, ...]
    classification: str
    similarity_millis: int


@dataclass(frozen=True)
class MemoryConflictRecord:
    conflict_id: str
    namespace: str
    conflict_key: str
    memory_ids: tuple[str, ...]
    content_hashes: tuple[str, ...]
    status: str
    selected_memory_id: str | None = None
    revoked_memory_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class NamespaceCapacity:
    max_records: int
    max_content_bytes: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_records, bool)
            or isinstance(self.max_content_bytes, bool)
            or self.max_records < 1
            or self.max_content_bytes < 1
        ):
            raise MemoryManagementError("memory capacity limits must be positive")


@dataclass(frozen=True)
class MemoryCapacityPolicy:
    default: NamespaceCapacity
    tenants: Mapping[str, NamespaceCapacity]
    namespaces: Mapping[str, NamespaceCapacity]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MemoryCapacityPolicy":
        if set(value) != {"schema", "default", "tenants", "namespaces"} or value.get("schema") != "SITINA_MEMORY_CAPACITY_POLICY_V1":
            raise MemoryManagementError("memory capacity policy contains unknown fields or schema")

        def parse_limit(item: Any) -> NamespaceCapacity:
            if not isinstance(item, Mapping) or set(item) != {"max_records", "max_content_bytes"}:
                raise MemoryManagementError("memory namespace capacity is malformed")
            for field in ("max_records", "max_content_bytes"):
                number = item.get(field)
                if not isinstance(number, int) or isinstance(number, bool):
                    raise MemoryManagementError("memory capacity values must be integers")
            return NamespaceCapacity(int(item["max_records"]), int(item["max_content_bytes"]))

        def parse_scope(name: str) -> dict[str, NamespaceCapacity]:
            scoped = value.get(name)
            if not isinstance(scoped, Mapping):
                raise MemoryManagementError(f"memory {name} capacity must be an object")
            parsed = {}
            for identity, item in scoped.items():
                validate_identifier(str(identity), field=f"memory_capacity_{name}")
                parsed[str(identity)] = parse_limit(item)
            return parsed

        return cls(
            parse_limit(value.get("default")),
            parse_scope("tenants"),
            parse_scope("namespaces"),
        )

    @classmethod
    def load(cls, path: str | Path) -> "MemoryCapacityPolicy":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise MemoryManagementError("memory capacity policy is unreadable") from error
        if not isinstance(value, Mapping):
            raise MemoryManagementError("memory capacity policy must be an object")
        return cls.from_mapping(value)

    def for_namespace(self, namespace: str, *, tenant_id: str) -> NamespaceCapacity:
        return self.namespaces.get(namespace, self.tenants.get(tenant_id, self.default))


@dataclass(frozen=True)
class MemoryCapacityResult:
    tenant_id: str
    namespace: str
    before_records: int
    before_bytes: int
    after_records: int
    after_bytes: int
    evicted_memory_ids: tuple[str, ...]
    explanations: tuple[Mapping[str, Any], ...]


def _normalized(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _features(value: str) -> frozenset[str]:
    normalized = _normalized(value)
    words = set(re.findall(r"[\w-]+", normalized, flags=re.UNICODE))
    compact = normalized.replace(" ", "")
    words.update(compact[index : index + 2] for index in range(max(0, len(compact) - 1)))
    return frozenset(item for item in words if item)


def _similarity(left: str, right: str) -> int:
    first = _features(left)
    second = _features(right)
    if not first and not second:
        return 1_000
    union = first | second
    return int(1_000 * len(first & second) / len(union)) if union else 0


def _untrusted(value: str, memory_id: str) -> str:
    return f'<UNTRUSTED_MEMORY_DATA memory_id="{memory_id}" instructions="false">\n{value}\n</UNTRUSTED_MEMORY_DATA>'


class MemoryManager:
    _TIER_ORDER = {"working": 0, "episodic": 1, "long_term": 2}
    _POISON = re.compile(
        r"(?i)(ignore\s+(all\s+)?previous|system\s+prompt|developer\s+message|jailbreak|<script|执行以下指令|忽略之前)"
    )

    def __init__(self, repository: MemoryRepository, capacity_policy: MemoryCapacityPolicy):
        self.repository = repository
        self.capacity_policy = capacity_policy

    def consolidate(
        self,
        memory_ids: Sequence[str],
        *,
        actor: str,
        occurred_at: str,
        similarity_threshold_millis: int = 550,
    ) -> MemoryConsolidation:
        ids = tuple(sorted(set(memory_ids)))
        if len(ids) < 2 or not 0 <= similarity_threshold_millis <= 1_000:
            raise MemoryManagementError("memory consolidation requires at least two IDs and a valid threshold")
        records = [self.repository.get(memory_id, actor=actor) for memory_id in ids]
        documents = [item[0] for item in records]
        contents = [str(item[1]) for item in records]
        if any(document.quarantine_status != "active" for document in documents):
            raise MemoryManagementError("quarantined memory cannot propagate through consolidation")
        identity = {(item.scope, item.owner_id, item.namespace) for item in documents}
        if len(identity) != 1:
            raise MemoryManagementError("memory consolidation cannot cross scope/owner/namespace")
        similarities = [_similarity(contents[0], item) for item in contents[1:]]
        minimum_similarity = min(similarities, default=1_000)
        normalized_contents = {_normalized(item) for item in contents}
        if len(normalized_contents) == 1:
            classification = "duplicate"
        elif minimum_similarity >= similarity_threshold_millis:
            classification = "near_duplicate"
        elif any(_features(contents[0]) & _features(item) for item in contents[1:]):
            classification = "complementary"
        else:
            raise MemoryManagementError("unrelated memories cannot be consolidated")
        ordered_contents = []
        seen = set()
        for content in contents:
            key = _normalized(content)
            if key not in seen:
                ordered_contents.append(content.strip())
                seen.add(key)
        merged_content = "\n\n".join(ordered_contents)
        future_expirations = tuple(
            item.expires_at
            for item in documents
            if item.expires_at is not None and item.expires_at > occurred_at
        )
        if any(item.expires_at is not None for item in documents) and not future_expirations:
            raise MemoryManagementError("expired source memory cannot be consolidated into a current candidate")
        creation_event_ids = {
            self.repository._stream_events(document.memory_id)[0].event_id
            for document in documents
        }
        digest = domain_hash(
            "MEMORY_CONSOLIDATION_ID",
            canonical_json_bytes(
                {"memory_ids": list(ids), "content_hashes": sorted(item.content_hash for item in documents)}
            ),
        )
        readers = set(documents[0].acl.readers)
        writers = set(documents[0].acl.writers)
        reviewers = set(documents[0].acl.reviewers)
        for document in documents[1:]:
            readers.intersection_update(document.acl.readers)
            writers.intersection_update(document.acl.writers)
            reviewers.intersection_update(document.acl.reviewers)
        if not readers or not writers or not reviewers or actor not in writers:
            raise MemoryManagementError("memory consolidation ACL intersection is empty or excludes actor")
        acl = MemoryACL(
            readers=tuple(sorted(readers)),
            writers=tuple(sorted(writers)),
            reviewers=tuple(sorted(reviewers)),
        )
        trust_order = {"untrusted": 0, "derived": 1, "verified": 2, "authoritative": 3}
        merged = self.repository.create_candidate(
            memory_id="memory-consolidated-" + digest[:32],
            scope=documents[0].scope,
            owner_id=documents[0].owner_id,
            namespace=documents[0].namespace,
            content=merged_content,
            source_event_ids=tuple(sorted(creation_event_ids | {item for document in documents for item in document.source_event_ids})),
            source_run_ids=tuple(sorted({item for document in documents for item in document.source_run_ids})),
            evidence_refs=tuple(sorted({item for document in documents for item in document.evidence_refs})),
            confidence=min(document.confidence for document in documents),
            sensitivity=max((document.sensitivity for document in documents), key=("low", "moderate", "high", "restricted").index),
            valid_from=occurred_at,
            expires_at=min(future_expirations, default=None),
            retention_policy="legal-retention" if all(item.retention_policy == "legal-retention" for item in documents) else "until-superseded",
            supersedes=(),
            acl=acl,
            actor=actor,
            tier=min((item.tier for item in documents), key=self._TIER_ORDER.get),
            source_agent_ids=tuple(sorted({item for document in documents for item in document.source_agent_ids})),
            source_trust=min((item.source_trust for item in documents), key=trust_order.get),
            observed_at=min(item.observed_at or item.valid_from for item in documents),
            conflict_key=documents[0].conflict_key if len({item.conflict_key for item in documents}) == 1 else None,
        )
        return MemoryConsolidation(merged, ids, classification, minimum_similarity)

    @staticmethod
    def freshness_millis(document: MemoryDocument, *, at: str, half_life_seconds: int) -> int:
        validate_timestamp(at)
        if half_life_seconds < 1:
            raise MemoryManagementError("memory half-life must be positive")
        now = dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
        start = dt.datetime.fromisoformat(document.valid_from.replace("Z", "+00:00"))
        age = max(0, int((now - start).total_seconds()))
        return int(1_000 * half_life_seconds / (half_life_seconds + age))

    def retrieve(
        self,
        query: str,
        *,
        actor: str,
        at: str,
        limit: int = 10,
        namespace_prefix: str | None = None,
        backend: RetrievalBackend | None = None,
        half_life_seconds: int = 86_400,
    ) -> tuple[MemoryHit, ...]:
        if not query.strip() or not 1 <= limit <= 1_000:
            raise MemoryManagementError("memory query and limit are invalid")
        documents = self.repository.retrieve(
            actor=actor,
            namespace_prefix=namespace_prefix,
            at=at,
        )
        content_by_id = {
            document.memory_id: str(self.repository.get(document.memory_id, actor=actor)[1])
            for document in documents
        }
        backend_name = "deterministic-lexical-fallback"
        scores: Mapping[str, int]
        if backend is not None:
            try:
                candidate = dict(backend.rank(query, content_by_id))
                if set(candidate) - set(content_by_id) or any(
                    not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 1_000
                    for score in candidate.values()
                ):
                    raise MemoryManagementError("retrieval backend returned invalid scores")
                scores = candidate
                backend_name = type(backend).__name__
            except Exception:
                scores = {memory_id: _similarity(query, content) for memory_id, content in content_by_id.items()}
        else:
            scores = {memory_id: _similarity(query, content) for memory_id, content in content_by_id.items()}
        hits = []
        for document in documents:
            relevance = int(scores.get(document.memory_id, 0))
            freshness = self.freshness_millis(document, at=at, half_life_seconds=half_life_seconds)
            combined = (relevance * 700 + freshness * 300) // 1_000
            hits.append(
                MemoryHit(
                    document,
                    relevance,
                    freshness,
                    combined,
                    _untrusted(content_by_id[document.memory_id], document.memory_id),
                    backend_name,
                )
            )
        hits.sort(key=lambda item: (-item.combined_score_millis, -item.relevance_millis, item.document.memory_id))
        return tuple(hits[:limit])

    def _append_management_fact(
        self,
        *,
        stream_id: str,
        event_type: str,
        schema: str,
        payload: Mapping[str, Any],
        actor: str,
        occurred_at: str,
    ) -> EventEnvelope:
        activations = self.repository._assert_write_enabled()
        validate_identifier(actor, field="memory_management_actor")
        validate_timestamp(occurred_at)
        digest = domain_hash(
            "MEMORY_MANAGEMENT_EVENT",
            canonical_json_bytes({"stream_id": stream_id, "event_type": event_type, "payload": dict(payload)}),
        )
        expected = self.repository.journal._stream_heads.get(stream_id, 0)
        command = CommandEnvelope(
            "memory-management-command-" + digest[:32],
            self.repository.TENANT,
            stream_id,
            event_type,
            actor,
            occurred_at,
            {"event_hash": digest},
        )
        event = EventEnvelope(
            "memory-management-event-" + digest[:34],
            event_type,
            self.repository.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            {"schema": schema, **dict(payload)},
            (),
        )
        receipt = self.repository.journal.append(command, expected, [event])
        appended = next(
            item
            for item in self.repository.journal.iter_events(receipt.first_position - 1)
            if item.position == receipt.first_position
        )
        activations.record_first_write("memory_v1_write", journal_position=appended.position)
        return appended

    def detect_conflicts(self, *, actor: str, occurred_at: str) -> tuple[MemoryConflictRecord, ...]:
        documents = self.repository.retrieve(actor=actor, at=occurred_at)
        groups: dict[tuple[str, str], list[MemoryDocument]] = {}
        for document in documents:
            if document.conflict_key is not None:
                groups.setdefault((document.namespace, document.conflict_key), []).append(document)
        conflicts = []
        for (namespace, conflict_key), items in sorted(groups.items()):
            if len(items) < 2 or len({item.content_hash for item in items}) < 2:
                continue
            memory_ids = tuple(sorted(item.memory_id for item in items))
            hashes = tuple(sorted(item.content_hash for item in items))
            conflict_id = "memory-conflict-" + domain_hash(
                "MEMORY_CONFLICT_ID",
                canonical_json_bytes({"namespace": namespace, "conflict_key": conflict_key, "memory_ids": list(memory_ids)}),
            )[:32]
            stream_id = f"memory-conflict/{conflict_id}"
            existing = tuple(event for event in self.repository.journal.iter_events(0) if event.stream_id == stream_id)
            if not existing:
                self._append_management_fact(
                    stream_id=stream_id,
                    event_type="memory.conflict-recorded",
                    schema="SITINA_MEMORY_CONFLICT_RECORDED_V1",
                    payload={
                        "conflict_id": conflict_id,
                        "namespace": namespace,
                        "conflict_key": conflict_key,
                        "memory_ids": list(memory_ids),
                        "content_hashes": list(hashes),
                        "status": "OPEN",
                    },
                    actor=actor,
                    occurred_at=occurred_at,
                )
                conflicts.append(MemoryConflictRecord(conflict_id, namespace, conflict_key, memory_ids, hashes, "OPEN"))
            else:
                conflicts.append(self._reconstruct_conflict(existing))
        return tuple(conflicts)

    @staticmethod
    def _reconstruct_conflict(events: Sequence[EventEnvelope]) -> MemoryConflictRecord:
        if not events or events[0].event_type != "memory.conflict-recorded":
            raise MemoryManagementError("memory conflict stream is malformed")
        payload = events[0].payload
        record = MemoryConflictRecord(
            str(payload["conflict_id"]),
            str(payload["namespace"]),
            str(payload["conflict_key"]),
            tuple(str(item) for item in payload["memory_ids"]),
            tuple(str(item) for item in payload["content_hashes"]),
            "OPEN",
        )
        for event in events[1:]:
            if event.event_type != "memory.conflict-resolved" or record.status != "OPEN":
                raise MemoryManagementError("memory conflict stream has an invalid transition")
            record = MemoryConflictRecord(
                record.conflict_id,
                record.namespace,
                record.conflict_key,
                record.memory_ids,
                record.content_hashes,
                "RESOLVED",
                str(event.payload["selected_memory_id"]),
                tuple(str(item) for item in event.payload["revoked_memory_ids"]),
            )
        return record

    def resolve_conflict(
        self,
        conflict_id: str,
        *,
        selected_memory_id: str,
        actor: str,
        occurred_at: str,
    ) -> MemoryConflictRecord:
        stream_id = f"memory-conflict/{conflict_id}"
        events = tuple(event for event in self.repository.journal.iter_events(0) if event.stream_id == stream_id)
        record = self._reconstruct_conflict(events)
        if record.status != "OPEN" or selected_memory_id not in record.memory_ids:
            raise MemoryManagementError("memory conflict selection is invalid or already terminal")
        selected = self.repository._raw_get(selected_memory_id)
        selected.acl.require(actor, "review")
        revoked = []
        for memory_id in record.memory_ids:
            if memory_id == selected_memory_id:
                continue
            document = self.repository._raw_get(memory_id)
            document.acl.require(actor, "review")
            if document.status == "accepted":
                self.repository.transition(
                    memory_id,
                    "revoked",
                    actor=actor,
                    occurred_at=occurred_at,
                    reason_code="conflict-arbitration",
                )
            revoked.append(memory_id)
        self._append_management_fact(
            stream_id=stream_id,
            event_type="memory.conflict-resolved",
            schema="SITINA_MEMORY_CONFLICT_RESOLVED_V1",
            payload={
                "conflict_id": conflict_id,
                "selected_memory_id": selected_memory_id,
                "revoked_memory_ids": sorted(revoked),
                "status": "RESOLVED",
            },
            actor=actor,
            occurred_at=occurred_at,
        )
        return self._reconstruct_conflict(
            tuple(event for event in self.repository.journal.iter_events(0) if event.stream_id == stream_id)
        )

    def enforce_capacity(
        self,
        namespace: str,
        *,
        actor: str,
        occurred_at: str,
        protected_memory_ids: Sequence[str] = (),
    ) -> MemoryCapacityResult:
        documents = list(self.repository.retrieve(actor=actor, namespace_prefix=namespace, at=occurred_at))
        documents = [item for item in documents if item.namespace == namespace]
        content_sizes = {
            item.memory_id: len(str(self.repository.get(item.memory_id, actor=actor)[1]).encode("utf-8"))
            for item in documents
        }
        limit = self.capacity_policy.for_namespace(namespace, tenant_id=self.repository.TENANT)
        before_records = len(documents)
        before_bytes = sum(content_sizes.values())
        excess_records = max(0, before_records - limit.max_records)
        excess_bytes = max(0, before_bytes - limit.max_content_bytes)
        protected = set(protected_memory_ids)
        candidates = [
            item
            for item in documents
            if item.memory_id not in protected and item.retention_policy != "legal-retention"
        ]
        candidates.sort(key=lambda item: (item.confidence, item.valid_from, item.memory_id))
        chosen: list[MemoryDocument] = []
        freed_bytes = 0
        for document in candidates:
            if len(chosen) >= excess_records and freed_bytes >= excess_bytes:
                break
            chosen.append(document)
            freed_bytes += content_sizes[document.memory_id]
        if len(chosen) < excess_records or freed_bytes < excess_bytes:
            raise MemoryManagementError("memory capacity cannot be satisfied without evicting protected records")
        explanations = []
        for document in chosen:
            self.repository.transition(
                document.memory_id,
                "expired",
                actor=actor,
                occurred_at=occurred_at,
                reason_code="capacity-eviction",
            )
            explanations.append(
                {
                    "memory_id": document.memory_id,
                    "reason": "lowest-confidence-then-oldest",
                    "confidence_millionths": int(document.confidence * 1_000_000),
                    "valid_from": document.valid_from,
                    "content_bytes": content_sizes[document.memory_id],
                    "protected": False,
                }
            )
        return MemoryCapacityResult(
            self.repository.TENANT,
            namespace,
            before_records,
            before_bytes,
            before_records - len(chosen),
            before_bytes - freed_bytes,
            tuple(item.memory_id for item in chosen),
            tuple(explanations),
        )

    def assess_and_quarantine(
        self,
        memory_id: str,
        *,
        actor: str,
        occurred_at: str,
    ) -> MemoryDocument:
        document, content = self.repository.get(memory_id, actor=actor)
        if content is None:
            raise MemoryManagementError("memory content is unavailable for pollution assessment")
        if self._POISON.search(content) or document.source_trust == "untrusted":
            lowered = min(int(document.confidence * 250_000), 250_000)
            return self.repository.quarantine(
                memory_id,
                actor=actor,
                occurred_at=occurred_at,
                reason_code="untrusted-or-instruction-like",
                confidence_millionths=lowered,
            )
        return document

    def revoke_quarantined(self, memory_id: str, *, actor: str, occurred_at: str) -> MemoryDocument:
        document = self.repository._raw_get(memory_id)
        if document.quarantine_status != "quarantined":
            raise MemoryManagementError("only quarantined memory can be revoked or rejected")
        target = "revoked" if document.status == "accepted" else "rejected"
        return self.repository.transition(
            memory_id,
            target,
            actor=actor,
            occurred_at=occurred_at,
            reason_code="pollution-confirmed",
        )
