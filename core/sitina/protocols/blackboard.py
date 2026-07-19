from __future__ import annotations

import re
import threading
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping

from sitina.cas.model import CASError, PublishedObjectReceipt
from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier
from sitina.utils import iso_now

from .blackboard_state import (
    BlackboardBodyRead,
    BlackboardLimits,
    BlackboardNotification,
    BlackboardNotificationPage,
    BlackboardQueryPage,
    BlackboardQueryIndex,
    BlackboardSnapshot,
    BlackboardStateError,
    BlackboardSubscription,
    field_level_changes,
    largest_field_size,
    protected_paths,
    read_blackboard_body,
)
from .tasks import TaskAggregate


class BlackboardError(RuntimeError):
    pass


class BlackboardNamespace(str, Enum):
    FACTS = "FACTS"
    CLAIMS = "CLAIMS"
    PROPOSALS = "PROPOSALS"
    WORKING_NOTES = "WORKING_NOTES"
    DECISIONS = "DECISIONS"
    EVIDENCE = "EVIDENCE"
    CONSTRAINTS = "CONSTRAINTS"
    RISKS = "RISKS"


class ConflictState(str, Enum):
    OPEN = "OPEN"
    MERGE_PROPOSED = "MERGE_PROPOSED"
    REVIEWED = "REVIEWED"
    RESOLVED = "RESOLVED"


@dataclass(frozen=True)
class NamespacePolicy:
    schema_hash: str
    writer_capabilities: tuple[str, ...]
    evidence_required: bool
    merge_policy: str
    classification: str
    inline_limit: int
    schema_id: str = "sitina.blackboard.document"
    schema_version: int = 1
    writer_policy_hash: str | None = None
    merge_policy_hash: str | None = None
    cas_required: bool = False
    reader_capabilities: tuple[str, ...] = ()
    writable_paths: tuple[str, ...] = ("/",)
    persistence_scope: str = "RUN_LOCAL"

    def __post_init__(self) -> None:
        if len(self.schema_hash) != 64 or not self.writer_capabilities or self.inline_limit < 1:
            raise BlackboardError("invalid Blackboard Namespace policy")
        if self.merge_policy not in {"APPEND_ONLY", "COMMUTATIVE", "CRDT_COMPATIBLE", "ARBITRATION"}:
            raise BlackboardError("invalid Blackboard merge policy")
        validate_identifier(self.schema_id, field="blackboard_schema_id")
        if self.schema_version < 1:
            raise BlackboardError("invalid Blackboard schema version")
        if self.persistence_scope not in {"RUN_LOCAL", "PROJECT_SHARED"}:
            raise BlackboardError("invalid Blackboard persistence scope")
        if not self.writable_paths or any(not isinstance(path, str) or not path.startswith("/") for path in self.writable_paths):
            raise BlackboardError("invalid Blackboard writable path policy")
        for value, label in (
            (self.writer_policy_hash, "writer policy hash"),
            (self.merge_policy_hash, "merge policy hash"),
        ):
            if value is not None and len(value) != 64:
                raise BlackboardError(f"invalid Blackboard {label}")

    @property
    def frozen_writer_policy_hash(self) -> str:
        return self.writer_policy_hash or domain_hash(
            "BLACKBOARD_WRITER_POLICY",
            canonical_json_bytes(
                {
                    "writer_capabilities": list(self.writer_capabilities),
                    "evidence_required": self.evidence_required,
                    "classification": self.classification,
                }
            ),
        )

    @property
    def frozen_merge_policy_hash(self) -> str:
        return self.merge_policy_hash or domain_hash(
            "BLACKBOARD_MERGE_POLICY",
            canonical_json_bytes(
                {
                    "merge_policy": self.merge_policy,
                    "schema_hash": self.schema_hash,
                    "schema_version": self.schema_version,
                }
            ),
        )


@dataclass(frozen=True)
class BlackboardDocument:
    document_id: str
    namespace: BlackboardNamespace
    version: int
    document_hash: str
    inline_body: Mapping[str, Any] | None
    object_ref: str | None
    classification: str
    schema_id: str = "sitina.blackboard.document"
    schema_version: int = 1
    writer_policy_hash: str = ""
    merge_policy_hash: str = ""
    created_event_ref: str = ""
    last_writer_id: str | None = None
    tenant_id: str = "default"
    run_id: str | None = "default"
    tags: tuple[str, ...] = ()
    size_bytes: int = 2

    @property
    def current_version(self) -> int:
        return self.version

    @property
    def current_hash(self) -> str:
        return self.document_hash


@dataclass(frozen=True)
class PatchIntent:
    document_id: str
    base_version: int
    base_hash: str
    patch: Mapping[str, Any]
    actor_id: str
    writer_capabilities: tuple[str, ...]
    task_id: str
    task_attempt_id: str
    claim_generation: int
    fencing_token: str
    evidence_refs: tuple[str, ...]
    read_refs: tuple[str, ...]
    write_intent_id: str | None = None
    patch_ref: str | None = None
    patch_hash: str | None = None
    patch_schema: str = "sitina.blackboard.patch/v1"
    target_paths: tuple[str, ...] = ()
    merge_policy_hash: str | None = None
    causation_id: str | None = None


@dataclass(frozen=True)
class PatchResult:
    document: BlackboardDocument
    event: dict[str, Any] | None
    conflict: dict[str, Any] | None = None
    blocked_obligations: tuple[str, ...] = ()


@dataclass(frozen=True)
class BlackboardConflict:
    conflict_id: str
    document_id: str
    attempted_write_intent_id: str
    attempted_patch_ref: str | None
    attempted_patch_hash: str
    attempted_patch_schema: str
    attempted_patch: Mapping[str, Any]
    attempted_writer_id: str
    attempted_base_version: int
    attempted_base_hash: str
    canonical_version: int
    canonical_hash: str
    canonical_writer_id: str | None
    merge_policy_hash: str
    blocked_obligations: tuple[str, ...]
    state: ConflictState = ConflictState.OPEN
    merge_id: str | None = None
    merge_agent_id: str | None = None
    merge_patch_ref: str | None = None
    merge_patch_hash: str | None = None
    merge_patch: Mapping[str, Any] | None = None
    merge_read_refs: tuple[str, ...] = ()
    review_id: str | None = None
    review_agent_id: str | None = None
    review_hash: str | None = None
    review_rubric_hash: str | None = None
    review_accepted: bool | None = None
    decision_id: str | None = None
    resolved_version: int | None = None
    resolved_hash: str | None = None


@dataclass(frozen=True)
class ConflictResolutionResult:
    document: BlackboardDocument
    merge_decision: dict[str, Any]
    conflict_resolved: dict[str, Any]
    patch_committed: dict[str, Any]
    cleared_obligations: tuple[str, ...]


_SECRET = re.compile(r"(?i)(secret|password|api[_-]?key|auth[_-]?token|private[_-]?key)")


def _contains_secret(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_SECRET.search(str(key)) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_secret(item) for item in value)
    return isinstance(value, str) and bool(_SECRET.search(value))


def _patch_hash(patch: Mapping[str, Any]) -> str:
    return domain_hash("BLACKBOARD_PATCH_CONTENT", canonical_json_bytes(dict(patch)))


class Blackboard:
    """Event-backed MVCC authority model; projections retain metadata and CAS references only."""

    def __init__(
        self,
        policies: Mapping[BlackboardNamespace, NamespacePolicy],
        *,
        tenant_id: str = "default",
        run_id: str = "default",
        limits: BlackboardLimits | None = None,
        clock: Callable[[], str] = iso_now,
    ):
        if set(policies) != set(policies.keys()) or not policies:
            raise BlackboardError("Blackboard requires Namespace policies")
        validate_identifier(tenant_id, field="blackboard_tenant_id")
        validate_identifier(run_id, field="blackboard_run_id")
        self.policies = dict(policies)
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.limits = limits or BlackboardLimits()
        self.clock = clock
        self.documents: dict[str, BlackboardDocument] = {}
        self.dependencies: dict[str, tuple[str, ...]] = {}
        self.conflicts: dict[str, BlackboardConflict] = {}
        self.journal_facts: list[dict[str, Any]] = []
        self.subscriptions: dict[str, BlackboardSubscription] = {}
        self._position = 0
        self._history: dict[str, list[tuple[int, BlackboardDocument]]] = {}
        self._lock = threading.RLock()

    @property
    def position(self) -> int:
        return self._position

    def _append_fact(self, event: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            position = self._position + 1
            enriched = {
                **dict(event),
                "tenant_id": self.tenant_id,
                "run_id": self.run_id,
                "position": position,
                "occurred_at": self.clock(),
            }
            enriched.setdefault(
                "event_id",
                "blackboard-event-"
                + domain_hash(
                    "BLACKBOARD_EVENT_ID",
                    canonical_json_bytes({key: value for key, value in enriched.items() if key != "occurred_at"}),
                )[:32],
            )
            self._position = position
            self.journal_facts.append(enriched)
            return enriched

    def _record_version(self, document: BlackboardDocument, position: int) -> None:
        versions = self._history.setdefault(document.document_id, [])
        if versions and document.version <= versions[-1][1].version:
            raise BlackboardError("Blackboard document version is not monotonic")
        versions.append((position, document))

    @staticmethod
    def _document_mapping(document: BlackboardDocument) -> dict[str, Any]:
        return {
            "document_id": document.document_id,
            "namespace": document.namespace.value,
            "version": document.version,
            "document_hash": document.document_hash,
            "inline_body": dict(document.inline_body) if document.inline_body is not None else None,
            "object_ref": document.object_ref,
            "classification": document.classification,
            "schema_id": document.schema_id,
            "schema_version": document.schema_version,
            "writer_policy_hash": document.writer_policy_hash,
            "merge_policy_hash": document.merge_policy_hash,
            "created_event_ref": document.created_event_ref,
            "last_writer_id": document.last_writer_id,
            "tenant_id": document.tenant_id,
            "run_id": document.run_id,
            "tags": list(document.tags),
            "size_bytes": document.size_bytes,
        }

    @staticmethod
    def _document_from_mapping(value: Mapping[str, Any]) -> BlackboardDocument:
        expected = {
            "document_id", "namespace", "version", "document_hash", "inline_body", "object_ref",
            "classification", "schema_id", "schema_version", "writer_policy_hash", "merge_policy_hash",
            "created_event_ref", "last_writer_id", "tenant_id", "run_id", "tags", "size_bytes",
        }
        if set(value) != expected:
            raise BlackboardError("snapshot document has unknown or missing fields")
        try:
            namespace = BlackboardNamespace(str(value["namespace"]))
            body = value["inline_body"]
            if body is not None and not isinstance(body, Mapping):
                raise TypeError
            return BlackboardDocument(
                document_id=str(value["document_id"]),
                namespace=namespace,
                version=int(value["version"]),
                document_hash=str(value["document_hash"]),
                inline_body=dict(body) if body is not None else None,
                object_ref=str(value["object_ref"]) if value["object_ref"] is not None else None,
                classification=str(value["classification"]),
                schema_id=str(value["schema_id"]),
                schema_version=int(value["schema_version"]),
                writer_policy_hash=str(value["writer_policy_hash"]),
                merge_policy_hash=str(value["merge_policy_hash"]),
                created_event_ref=str(value["created_event_ref"]),
                last_writer_id=str(value["last_writer_id"]) if value["last_writer_id"] is not None else None,
                tenant_id=str(value["tenant_id"]),
                run_id=str(value["run_id"]) if value["run_id"] is not None else None,
                tags=tuple(str(item) for item in value["tags"]),
                size_bytes=int(value["size_bytes"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise BlackboardError("snapshot document is malformed") from error

    def create(
        self,
        document_id: str,
        namespace: BlackboardNamespace,
        *,
        created_event_ref: str | None = None,
    ) -> tuple[BlackboardDocument, dict[str, Any]]:
        validate_identifier(document_id, field="blackboard_document_id")
        if namespace not in self.policies:
            raise BlackboardError("Blackboard Namespace has no frozen policy")
        if document_id in self.documents:
            raise BlackboardError("Blackboard Document already exists")
        policy = self.policies[namespace]
        creation_ref = created_event_ref or "blackboard-create-" + domain_hash(
            "BLACKBOARD_CREATION_REFERENCE", canonical_json_bytes({"document_id": document_id, "namespace": namespace.value})
        )[:32]
        document_hash = domain_hash(
            "BLACKBOARD_DOCUMENT_GENESIS",
            canonical_json_bytes(
                {
                    "document_id": document_id,
                    "namespace": namespace.value,
                    "schema_id": policy.schema_id,
                    "schema_version": policy.schema_version,
                    "schema_hash": policy.schema_hash,
                    "classification": policy.classification,
                    "writer_policy_hash": policy.frozen_writer_policy_hash,
                    "merge_policy_hash": policy.frozen_merge_policy_hash,
                    "created_event_ref": creation_ref,
                }
            ),
        )
        document = BlackboardDocument(
            document_id=document_id,
            namespace=namespace,
            version=0,
            document_hash=document_hash,
            inline_body={},
            object_ref=None,
            classification=policy.classification,
            schema_id=policy.schema_id,
            schema_version=policy.schema_version,
            writer_policy_hash=policy.frozen_writer_policy_hash,
            merge_policy_hash=policy.frozen_merge_policy_hash,
            created_event_ref=creation_ref,
            tenant_id=self.tenant_id,
            run_id=None if policy.persistence_scope == "PROJECT_SHARED" else self.run_id,
            size_bytes=2,
        )
        event = {
            "schema": "BLACKBOARD_DOCUMENT_CREATED_V1",
            "document_id": document_id,
            "namespace": namespace.value,
            "namespace_key": namespace.value.lower(),
            "schema_id": policy.schema_id,
            "schema_version": policy.schema_version,
            "schema_hash": policy.schema_hash,
            "current_version": 0,
            "current_hash": document_hash,
            "version": 0,
            "document_hash": document_hash,
            "classification": policy.classification,
            "writer_policy_hash": policy.frozen_writer_policy_hash,
            "merge_policy_hash": policy.frozen_merge_policy_hash,
            "created_event_ref": creation_ref,
            "persistence_scope": policy.persistence_scope,
            "size_bytes": document.size_bytes,
        }
        event = self._append_fact(event)
        self.documents[document_id] = document
        self._record_version(document, event["position"])
        return document, event

    def read(
        self,
        document_id: str,
        *,
        agent_id: str,
        reader_capabilities: tuple[str, ...] = (),
        read_paths: tuple[str, ...] = (),
        source_event_refs: tuple[str, ...] = (),
    ) -> tuple[BlackboardDocument, dict[str, Any]]:
        validate_identifier(agent_id, field="blackboard_reader_id")
        try:
            document = self.documents[document_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard Document") from error
        policy = self.policies[document.namespace]
        if not set(policy.reader_capabilities).issubset(reader_capabilities):
            self._append_fact(
                {
                    "schema": "BLACKBOARD_ACCESS_DENIED_V1",
                    "document_id": document_id,
                    "actor_id": agent_id,
                    "operation": "READ",
                    "reason": "MISSING_READER_CAPABILITY",
                }
            )
            raise BlackboardError("actor lacks Namespace reader capability")
        read_id = "blackboard-read-" + domain_hash(
            "BLACKBOARD_READ",
            canonical_json_bytes(
                {
                    "document_id": document_id,
                    "agent_id": agent_id,
                    "version": document.version,
                    "document_hash": document.document_hash,
                    "read_paths": list(read_paths),
                    "source_event_refs": list(source_event_refs),
                }
            ),
        )[:32]
        event = {
            "schema": "BLACKBOARD_DOCUMENT_READ_V1",
            "read_id": read_id,
            "document_id": document_id,
            "reader_agent_id": agent_id,
            "read_version": document.version,
            "read_hash": document.document_hash,
            "read_paths": list(read_paths),
            "read_event_refs": list(source_event_refs),
            "object_ref": document.object_ref,
        }
        event = self._append_fact(event)
        return document, event

    def declare_dependencies(self, obligation_id: str, document_ids: tuple[str, ...]) -> "Blackboard":
        validate_identifier(obligation_id, field="obligation_id")
        for document_id in document_ids:
            validate_identifier(document_id, field="blackboard_document_id")
        self.dependencies[obligation_id] = tuple(sorted(set(document_ids)))
        return self

    def _validate_attempt(self, intent: PatchIntent, task: TaskAggregate) -> None:
        if task.task_id != intent.task_id:
            raise BlackboardError("Patch Task identity mismatch")
        attempt = task.active_attempt
        if (
            attempt is None
            or attempt.task_attempt_id != intent.task_attempt_id
            or attempt.claim_generation != intent.claim_generation
            or attempt.fencing_token != intent.fencing_token
        ):
            raise BlackboardError("Patch requires current Task Attempt and fencing token")

    def _validate_intent(self, intent: PatchIntent, document: BlackboardDocument, task: TaskAggregate) -> tuple[NamespacePolicy, str, str]:
        validate_identifier(intent.actor_id, field="blackboard_actor_id")
        if intent.causation_id is not None:
            validate_identifier(intent.causation_id, field="blackboard_causation_id")
        self._validate_attempt(intent, task)
        policy = self.policies[document.namespace]
        if not set(policy.writer_capabilities).issubset(intent.writer_capabilities):
            self._append_fact(
                {
                    "schema": "BLACKBOARD_ACCESS_DENIED_V1",
                    "document_id": intent.document_id,
                    "actor_id": intent.actor_id,
                    "operation": "WRITE",
                    "reason": "MISSING_WRITER_CAPABILITY",
                }
            )
            raise BlackboardError("actor lacks Namespace writer capability")
        nested_protected = protected_paths(intent.patch)
        target_protected = tuple(
            piece
            for path in intent.target_paths
            for piece in path.split("/")
            if piece and protected_paths({piece: None})
        )
        if nested_protected or target_protected:
            self._append_fact(
                {
                    "schema": "BLACKBOARD_ACCESS_DENIED_V1",
                    "document_id": intent.document_id,
                    "actor_id": intent.actor_id,
                    "operation": "WRITE",
                    "reason": "PROTECTED_FIELD",
                    "protected_path_count": len(nested_protected) + len(target_protected),
                }
            )
            raise BlackboardError("Blackboard safety fields cannot be written")
        if intent.target_paths and any(
            not any(allowed == "/" or path == allowed or path.startswith(allowed.rstrip("/") + "/") for allowed in policy.writable_paths)
            for path in intent.target_paths
        ):
            self._append_fact(
                {
                    "schema": "BLACKBOARD_ACCESS_DENIED_V1",
                    "document_id": intent.document_id,
                    "actor_id": intent.actor_id,
                    "operation": "WRITE",
                    "reason": "PATH_OUTSIDE_POLICY",
                }
            )
            raise BlackboardError("Patch target is outside Namespace writable paths")
        if intent.patch_schema not in {"sitina.blackboard.patch/v1", "sitina.blackboard.patch/v2"}:
            raise BlackboardError("unknown Blackboard Patch schema version")
        if intent.patch_schema == "sitina.blackboard.patch/v2":
            try:
                read_blackboard_body(intent.patch)
            except BlackboardStateError as error:
                raise BlackboardError(str(error)) from error
            if not intent.target_paths:
                raise BlackboardError("structured Blackboard Patch requires target_paths")
        if policy.evidence_required and not intent.evidence_refs:
            raise BlackboardError("Namespace requires Evidence references")
        if any(len(reference) != 64 for reference in intent.evidence_refs):
            raise BlackboardError("invalid Blackboard Evidence reference")
        if intent.merge_policy_hash is not None and intent.merge_policy_hash != policy.frozen_merge_policy_hash:
            raise BlackboardError("Patch merge policy hash is not the frozen Namespace policy")
        computed_patch_hash = _patch_hash(intent.patch)
        if intent.patch_hash is not None and intent.patch_hash != computed_patch_hash:
            raise BlackboardError("Patch hash does not match canonical Patch content")
        write_intent_id = intent.write_intent_id or "write-intent-" + domain_hash(
            "BLACKBOARD_WRITE_INTENT",
            canonical_json_bytes(
                {
                    "document_id": intent.document_id,
                    "base_version": intent.base_version,
                    "base_hash": intent.base_hash,
                    "patch_hash": computed_patch_hash,
                    "actor_id": intent.actor_id,
                    "task_attempt_id": intent.task_attempt_id,
                    "fencing_token": intent.fencing_token,
                }
            ),
        )[:32]
        validate_identifier(write_intent_id, field="blackboard_write_intent_id")
        self._validate_capacity(intent, document)
        return policy, computed_patch_hash, write_intent_id

    def _validate_capacity(self, intent: PatchIntent, document: BlackboardDocument) -> tuple[int, int, bool]:
        document_size = len(canonical_json_bytes(dict(intent.patch)))
        field_size = largest_field_size(intent.patch)
        total_before = sum(item.size_bytes for item in self.documents.values())
        total_after = total_before - document.size_bytes + document_size
        reasons: list[str] = []
        if document_size > self.limits.max_document_bytes:
            reasons.append("DOCUMENT_LIMIT")
        if field_size > self.limits.max_field_bytes:
            reasons.append("FIELD_LIMIT")
        if total_after > self.limits.max_total_bytes:
            reasons.append("TOTAL_LIMIT")
        if reasons:
            self._append_fact(
                {
                    "schema": "BLACKBOARD_CAPACITY_REJECTED_V1",
                    "document_id": intent.document_id,
                    "actor_id": intent.actor_id,
                    "reasons": reasons,
                    "document_size_bytes": document_size,
                    "largest_field_bytes": field_size,
                    "total_before_bytes": total_before,
                    "total_candidate_bytes": total_after,
                    "state_mutated": False,
                }
            )
            raise BlackboardError("Blackboard capacity limit exceeded")
        warning = any(
            used * 1_000 >= maximum * self.limits.warning_ratio_millis
            for used, maximum in (
                (document_size, self.limits.max_document_bytes),
                (field_size, self.limits.max_field_bytes),
                (total_after, self.limits.max_total_bytes),
            )
        )
        return document_size, total_after, warning

    @staticmethod
    def _published_patch(
        intent: PatchIntent,
        policy: NamespacePolicy,
        computed_patch_hash: str,
        receipt: PublishedObjectReceipt | None,
    ) -> tuple[str | None, Mapping[str, Any] | None, str, bool]:
        patch_bytes = canonical_json_bytes(dict(intent.patch))
        object_required = policy.cas_required or len(patch_bytes) > policy.inline_limit or _contains_secret(intent.patch)
        if object_required and receipt is None:
            raise BlackboardError("Blackboard Patch requires encrypted CAS publication before Event")
        if receipt is not None:
            object_ref = receipt.object_ref.reference_id
            if intent.patch_ref is not None and intent.patch_ref != object_ref:
                raise BlackboardError("Patch ref does not match published CAS receipt")
            try:
                receipt.assert_valid(object_ref)
            except CASError as error:
                raise BlackboardError("Blackboard CAS publication receipt is invalid") from error
            return object_ref, None, domain_hash(
                "BLACKBOARD_OBJECT_PATCH",
                canonical_json_bytes({"object_ref": object_ref, "patch_hash": computed_patch_hash}),
            ), True
        if intent.patch_ref is not None:
            raise BlackboardError("Patch ref requires a matching published CAS receipt")
        return None, dict(intent.patch), domain_hash("BLACKBOARD_INLINE_PATCH", patch_bytes), False

    def _committed_patch(
        self,
        intent: PatchIntent,
        *,
        document: BlackboardDocument,
        policy: NamespacePolicy,
        computed_patch_hash: str,
        write_intent_id: str,
        published_object_receipt: PublishedObjectReceipt | None,
    ) -> PatchResult:
        document_size, total_after, capacity_warning = self._validate_capacity(intent, document)
        object_ref, committed_value, patch_commitment, object_published = self._published_patch(
            intent, policy, computed_patch_hash, published_object_receipt
        )
        next_version = document.version + 1
        next_hash = domain_hash(
            "BLACKBOARD_DOCUMENT_VERSION",
            canonical_json_bytes(
                {
                    "document_id": document.document_id,
                    "base_version": document.version,
                    "base_hash": document.document_hash,
                    "committed_version": next_version,
                    "patch_commitment": patch_commitment,
                    "patch_hash": computed_patch_hash,
                    "schema_hash": policy.schema_hash,
                    "merge_policy_hash": policy.frozen_merge_policy_hash,
                    "writer_fence": intent.fencing_token,
                }
            ),
        )
        updated = replace(
            document,
            version=next_version,
            document_hash=next_hash,
            inline_body=committed_value,
            object_ref=object_ref,
            last_writer_id=intent.actor_id,
            tags=tuple(read_blackboard_body(intent.patch).body.tags) if intent.patch_schema == "sitina.blackboard.patch/v2" else document.tags,
            size_bytes=document_size,
        )
        event: dict[str, Any] = {
            "schema": "BLACKBOARD_PATCH_COMMITTED_V1",
            "document_id": document.document_id,
            "namespace": document.namespace.value,
            "schema_id": document.schema_id,
            "schema_version": document.schema_version,
            "schema_hash": policy.schema_hash,
            "classification": policy.classification,
            "writer_policy_hash": policy.frozen_writer_policy_hash,
            "merge_policy": policy.merge_policy,
            "merge_policy_hash": policy.frozen_merge_policy_hash,
            "write_intent_id": write_intent_id,
            "patch_ref": object_ref,
            "patch_hash": computed_patch_hash,
            "patch_schema": intent.patch_schema,
            "target_paths": list(intent.target_paths),
            "writer_agent_id": intent.actor_id,
            "actor_id": intent.actor_id,
            "writer_fence": intent.fencing_token,
            "task_id": intent.task_id,
            "task_attempt_id": intent.task_attempt_id,
            "claim_generation": intent.claim_generation,
            "fencing_token": intent.fencing_token,
            "base_version": intent.base_version,
            "base_hash": intent.base_hash,
            "before_hash": document.document_hash,
            "committed_version": next_version,
            "committed_hash": next_hash,
            "after_hash": next_hash,
            "field_changes": list(field_level_changes(document.inline_body, dict(intent.patch))),
            "causation_id": intent.causation_id or write_intent_id,
            "patch_commitment": patch_commitment,
            "evidence_refs": list(intent.evidence_refs),
            "read_refs": list(intent.read_refs),
            "object_ref": object_ref,
            "object_published_before_event": object_published,
            "document_size_bytes": document_size,
            "blackboard_total_bytes": total_after,
            "capacity_warning": capacity_warning,
        }
        if not object_published:
            event["patch"] = dict(intent.patch)
        return PatchResult(updated, event)

    def patch(
        self,
        intent: PatchIntent,
        *,
        task: TaskAggregate,
        published_object_receipt: PublishedObjectReceipt | None = None,
    ) -> PatchResult:
        with self._lock:
            return self._patch_locked(
                intent,
                task=task,
                published_object_receipt=published_object_receipt,
            )

    def _patch_locked(
        self,
        intent: PatchIntent,
        *,
        task: TaskAggregate,
        published_object_receipt: PublishedObjectReceipt | None = None,
    ) -> PatchResult:
        try:
            document = self.documents[intent.document_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard Document") from error
        policy, computed_patch_hash, write_intent_id = self._validate_intent(intent, document, task)
        # Validate and root the candidate Patch before deciding whether the base is stale.
        object_ref, _body, _commitment, _published = self._published_patch(
            intent, policy, computed_patch_hash, published_object_receipt
        )
        if intent.base_version != document.version or intent.base_hash != document.document_hash:
            blocked = tuple(
                sorted(
                    obligation_id
                    for obligation_id, dependencies in self.dependencies.items()
                    if intent.document_id in dependencies
                )
            )
            conflict_id = "blackboard-conflict-" + domain_hash(
                "BLACKBOARD_PATCH_CONFLICT",
                canonical_json_bytes(
                    {
                        "document_id": intent.document_id,
                        "write_intent_id": write_intent_id,
                        "attempted_base_version": intent.base_version,
                        "attempted_base_hash": intent.base_hash,
                        "canonical_version": document.version,
                        "canonical_hash": document.document_hash,
                    }
                ),
            )[:32]
            conflict_record = BlackboardConflict(
                conflict_id,
                intent.document_id,
                write_intent_id,
                object_ref,
                computed_patch_hash,
                intent.patch_schema,
                dict(intent.patch),
                intent.actor_id,
                intent.base_version,
                intent.base_hash,
                document.version,
                document.document_hash,
                document.last_writer_id,
                policy.frozen_merge_policy_hash,
                blocked,
            )
            existing = self.conflicts.get(conflict_id)
            if existing is not None and existing != conflict_record:
                raise BlackboardError("Blackboard conflict identity collision")
            self.conflicts[conflict_id] = existing or conflict_record
            conflict = {
                "schema": "BLACKBOARD_PATCH_CONFLICT_V1",
                "conflict_id": conflict_id,
                "document_id": intent.document_id,
                "write_intent_id": write_intent_id,
                "patch_ref": object_ref,
                "patch_hash": computed_patch_hash,
                "patch_schema": intent.patch_schema,
                "writer_agent_id": intent.actor_id,
                "writer_fence": intent.fencing_token,
                "target_paths": list(intent.target_paths),
                "attempted_base_version": intent.base_version,
                "attempted_base_hash": intent.base_hash,
                "canonical_version": document.version,
                "canonical_hash": document.document_hash,
                "canonical_writer_id": document.last_writer_id,
                "merge_policy": policy.merge_policy,
                "merge_policy_hash": policy.frozen_merge_policy_hash,
                "blocked_obligations": list(blocked),
                "document_stream_mutated": False,
                "last_write_wins": False,
                "silent_rebase": False,
            }
            conflict = self._append_fact(conflict)
            return PatchResult(document, None, conflict, blocked)
        result = self._committed_patch(
            intent,
            document=document,
            policy=policy,
            computed_patch_hash=computed_patch_hash,
            write_intent_id=write_intent_id,
            published_object_receipt=published_object_receipt,
        )
        assert result.event is not None
        committed_event = self._append_fact(result.event)
        self.documents[result.document.document_id] = result.document
        self._record_version(result.document, committed_event["position"])
        if committed_event["capacity_warning"]:
            self._append_fact(
                {
                    "schema": "BLACKBOARD_CAPACITY_WARNING_V1",
                    "document_id": result.document.document_id,
                    "committed_version": result.document.version,
                    "document_size_bytes": result.document.size_bytes,
                    "blackboard_total_bytes": committed_event["blackboard_total_bytes"],
                }
            )
        return replace(result, event=committed_event)

    def submit_merge(
        self,
        conflict_id: str,
        *,
        merge_agent_id: str,
        merge_patch: Mapping[str, Any],
        merge_read_refs: tuple[str, ...],
        published_object_receipt: PublishedObjectReceipt | None = None,
    ) -> dict[str, Any]:
        try:
            conflict = self.conflicts[conflict_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard conflict") from error
        if conflict.state is not ConflictState.OPEN:
            raise BlackboardError("Blackboard conflict is not open for Merge proposal")
        validate_identifier(merge_agent_id, field="blackboard_merge_agent_id")
        if merge_agent_id in {conflict.attempted_writer_id, conflict.canonical_writer_id}:
            raise BlackboardError("Merge Agent must be independent of both conflicting writers")
        if conflict.canonical_hash not in merge_read_refs or conflict.attempted_patch_hash not in merge_read_refs:
            raise BlackboardError("Merge Agent must read both canonical and conflicting branches")
        policy = self.policies[self.documents[conflict.document_id].namespace]
        merge_hash = _patch_hash(merge_patch)
        synthetic = PatchIntent(
            conflict.document_id,
            conflict.canonical_version,
            conflict.canonical_hash,
            dict(merge_patch),
            merge_agent_id,
            policy.writer_capabilities,
            "merge-task",
            "merge-attempt",
            1,
            "0" * 64,
            (conflict.attempted_patch_hash,),
            merge_read_refs,
            patch_hash=merge_hash,
            merge_policy_hash=policy.frozen_merge_policy_hash,
        )
        object_ref, _body, _commitment, _published = self._published_patch(
            synthetic, policy, merge_hash, published_object_receipt
        )
        merge_id = "blackboard-merge-" + domain_hash(
            "BLACKBOARD_MERGE_PROPOSAL",
            canonical_json_bytes(
                {
                    "conflict_id": conflict_id,
                    "merge_agent_id": merge_agent_id,
                    "merge_patch_hash": merge_hash,
                    "merge_read_refs": list(merge_read_refs),
                }
            ),
        )[:32]
        updated = replace(
            conflict,
            state=ConflictState.MERGE_PROPOSED,
            merge_id=merge_id,
            merge_agent_id=merge_agent_id,
            merge_patch_ref=object_ref,
            merge_patch_hash=merge_hash,
            merge_patch=dict(merge_patch),
            merge_read_refs=merge_read_refs,
        )
        self.conflicts[conflict_id] = updated
        event = {
            "schema": "BLACKBOARD_MERGE_PROPOSAL_SUBMITTED_V1",
            "conflict_id": conflict_id,
            "merge_id": merge_id,
            "document_id": conflict.document_id,
            "merge_agent_id": merge_agent_id,
            "canonical_version": conflict.canonical_version,
            "canonical_hash": conflict.canonical_hash,
            "conflicting_patch_hash": conflict.attempted_patch_hash,
            "merge_patch_ref": object_ref,
            "merge_patch_hash": merge_hash,
            "merge_read_refs": list(merge_read_refs),
            "merge_policy_hash": conflict.merge_policy_hash,
        }
        return self._append_fact(event)

    def review_merge(
        self,
        conflict_id: str,
        *,
        reviewer_agent_id: str,
        reviewed_merge_hash: str,
        review_hash: str,
        rubric_hash: str,
        accepted: bool,
    ) -> dict[str, Any]:
        try:
            conflict = self.conflicts[conflict_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard conflict") from error
        if conflict.state is not ConflictState.MERGE_PROPOSED or conflict.merge_patch_hash is None:
            raise BlackboardError("Blackboard conflict has no reviewable Merge proposal")
        validate_identifier(reviewer_agent_id, field="blackboard_merge_reviewer_id")
        if reviewer_agent_id in {conflict.attempted_writer_id, conflict.canonical_writer_id, conflict.merge_agent_id}:
            raise BlackboardError("Merge Reviewer must be independent of writers and Merge Agent")
        if reviewed_merge_hash != conflict.merge_patch_hash:
            raise BlackboardError("Merge Review does not bind the current Merge Patch")
        if len(review_hash) != 64 or len(rubric_hash) != 64:
            raise BlackboardError("invalid Merge Review or rubric hash")
        review_id = "blackboard-merge-review-" + domain_hash(
            "BLACKBOARD_MERGE_REVIEW",
            canonical_json_bytes(
                {
                    "conflict_id": conflict_id,
                    "reviewer_agent_id": reviewer_agent_id,
                    "merge_patch_hash": reviewed_merge_hash,
                    "review_hash": review_hash,
                    "rubric_hash": rubric_hash,
                    "accepted": accepted,
                }
            ),
        )[:32]
        updated = replace(
            conflict,
            state=ConflictState.REVIEWED,
            review_id=review_id,
            review_agent_id=reviewer_agent_id,
            review_hash=review_hash,
            review_rubric_hash=rubric_hash,
            review_accepted=accepted,
        )
        self.conflicts[conflict_id] = updated
        event = {
            "schema": "BLACKBOARD_MERGE_REVIEWED_V1",
            "conflict_id": conflict_id,
            "merge_id": conflict.merge_id,
            "review_id": review_id,
            "reviewer_agent_id": reviewer_agent_id,
            "reviewed_merge_hash": reviewed_merge_hash,
            "review_hash": review_hash,
            "rubric_hash": rubric_hash,
            "accepted": accepted,
        }
        return self._append_fact(event)

    def resolve_conflict(
        self,
        conflict_id: str,
        *,
        decision_agent_id: str,
        merge_intent: PatchIntent,
        task: TaskAggregate,
        published_object_receipt: PublishedObjectReceipt | None = None,
    ) -> ConflictResolutionResult:
        try:
            conflict = self.conflicts[conflict_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard conflict") from error
        if conflict.state is not ConflictState.REVIEWED or conflict.review_accepted is not True:
            raise BlackboardError("Blackboard conflict requires an accepted independent Merge Review")
        if decision_agent_id != conflict.review_agent_id:
            raise BlackboardError("Merge Decision must be issued by the independent reviewing authority")
        if conflict.merge_agent_id is None or conflict.merge_patch is None or conflict.merge_patch_hash is None:
            raise BlackboardError("Blackboard conflict lacks a Merge proposal")
        if merge_intent.actor_id != conflict.merge_agent_id:
            raise BlackboardError("resolved Patch must be authored by the recorded Merge Agent")
        if dict(merge_intent.patch) != dict(conflict.merge_patch):
            raise BlackboardError("resolved Patch differs from independently reviewed Merge Patch")
        if merge_intent.patch_hash not in {None, conflict.merge_patch_hash}:
            raise BlackboardError("resolved Patch hash differs from reviewed Merge Patch")
        document = self.documents[conflict.document_id]
        if document.version != conflict.canonical_version or document.document_hash != conflict.canonical_hash:
            raise BlackboardError("canonical Blackboard base changed after conflict opened")
        policy, computed_hash, write_intent_id = self._validate_intent(merge_intent, document, task)
        if computed_hash != conflict.merge_patch_hash:
            raise BlackboardError("resolved Patch canonical hash differs from reviewed Merge Patch")
        committed = self._committed_patch(
            merge_intent,
            document=document,
            policy=policy,
            computed_patch_hash=computed_hash,
            write_intent_id=write_intent_id,
            published_object_receipt=published_object_receipt,
        )
        assert committed.event is not None
        decision_id = "blackboard-merge-decision-" + domain_hash(
            "BLACKBOARD_MERGE_DECISION",
            canonical_json_bytes(
                {
                    "conflict_id": conflict_id,
                    "decision_agent_id": decision_agent_id,
                    "review_id": conflict.review_id,
                    "merge_patch_hash": conflict.merge_patch_hash,
                    "resolved_version": committed.document.version,
                    "resolved_hash": committed.document.document_hash,
                }
            ),
        )[:32]
        merge_decision = {
            "schema": "BLACKBOARD_MERGE_DECISION_V1",
            "conflict_id": conflict_id,
            "merge_id": conflict.merge_id,
            "review_id": conflict.review_id,
            "decision_id": decision_id,
            "decision_agent_id": decision_agent_id,
            "decision": "ACCEPT_MERGE",
            "review_hash": conflict.review_hash,
            "merge_patch_hash": conflict.merge_patch_hash,
            "base_version": conflict.canonical_version,
            "base_hash": conflict.canonical_hash,
        }
        resolved = {
            "schema": "BLACKBOARD_CONFLICT_RESOLVED_V1",
            "conflict_id": conflict_id,
            "document_id": conflict.document_id,
            "decision_id": decision_id,
            "resolved_version": committed.document.version,
            "resolved_hash": committed.document.document_hash,
            "cleared_obligations": list(conflict.blocked_obligations),
            "blocking_conflict_remaining": False,
        }
        committed_event = {
            **committed.event,
            "resolution_conflict_id": conflict_id,
            "merge_id": conflict.merge_id,
            "merge_review_id": conflict.review_id,
            "merge_decision_id": decision_id,
        }
        self.conflicts[conflict_id] = replace(
            conflict,
            state=ConflictState.RESOLVED,
            decision_id=decision_id,
            resolved_version=committed.document.version,
            resolved_hash=committed.document.document_hash,
        )
        merge_decision = self._append_fact(merge_decision)
        resolved = self._append_fact(resolved)
        committed_event = self._append_fact(committed_event)
        self.documents[committed.document.document_id] = committed.document
        self._record_version(committed.document, committed_event["position"])
        return ConflictResolutionResult(
            committed.document,
            merge_decision,
            resolved,
            committed_event,
            conflict.blocked_obligations,
        )

    @staticmethod
    def _policy_proves_auto_rebase(policy: NamespacePolicy, patch: Mapping[str, Any]) -> bool:
        operation = patch.get("operation")
        if policy.merge_policy == "APPEND_ONLY":
            return operation == "append" and isinstance(patch.get("items"), list) and bool(patch["items"])
        if policy.merge_policy == "COMMUTATIVE":
            return operation in {"increment", "set-union"} and (
                isinstance(patch.get("delta"), (int, float))
                or isinstance(patch.get("items"), list)
            )
        if policy.merge_policy == "CRDT_COMPATIBLE":
            return (
                operation in {"add", "remove", "assign"}
                and patch.get("crdt_type") in {"g-set", "or-set", "lww-register"}
                and isinstance(patch.get("operation_id"), str)
                and bool(str(patch.get("operation_id")).strip())
            )
        return False

    def auto_resolve_conflict(
        self,
        conflict_id: str,
        *,
        rebased_intent: PatchIntent,
        task: TaskAggregate,
        published_object_receipt: PublishedObjectReceipt | None = None,
    ) -> ConflictResolutionResult:
        try:
            conflict = self.conflicts[conflict_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard conflict") from error
        if conflict.state is not ConflictState.OPEN:
            raise BlackboardError("Blackboard conflict is not open for automatic rebase")
        document = self.documents[conflict.document_id]
        policy = self.policies[document.namespace]
        if not self._policy_proves_auto_rebase(policy, conflict.attempted_patch):
            raise BlackboardError("versioned merge policy does not prove this Patch is safe to auto-rebase")
        if rebased_intent.actor_id != conflict.attempted_writer_id or dict(rebased_intent.patch) != dict(conflict.attempted_patch):
            raise BlackboardError("automatic rebase must preserve the original writer and Patch semantics")
        if rebased_intent.base_version != document.version or rebased_intent.base_hash != document.document_hash:
            raise BlackboardError("automatic rebase must bind the actual canonical merge base")
        frozen_policy_hash = policy.frozen_merge_policy_hash
        if rebased_intent.merge_policy_hash != frozen_policy_hash:
            raise BlackboardError("automatic rebase must bind the frozen merge policy hash")
        policy, computed_hash, write_intent_id = self._validate_intent(rebased_intent, document, task)
        if computed_hash != conflict.attempted_patch_hash:
            raise BlackboardError("automatic rebase changed the original Patch hash")
        committed = self._committed_patch(
            rebased_intent,
            document=document,
            policy=policy,
            computed_patch_hash=computed_hash,
            write_intent_id=write_intent_id,
            published_object_receipt=published_object_receipt,
        )
        assert committed.event is not None
        policy_proof_hash = domain_hash(
            "BLACKBOARD_AUTO_REBASE_POLICY_PROOF",
            canonical_json_bytes(
                {
                    "conflict_id": conflict_id,
                    "merge_policy": policy.merge_policy,
                    "merge_policy_hash": frozen_policy_hash,
                    "patch_hash": computed_hash,
                    "original_base_version": conflict.attempted_base_version,
                    "original_base_hash": conflict.attempted_base_hash,
                    "actual_merge_base_version": document.version,
                    "actual_merge_base_hash": document.document_hash,
                }
            ),
        )
        decision_id = "blackboard-auto-rebase-" + policy_proof_hash[:32]
        authorized = {
            "schema": "BLACKBOARD_AUTO_REBASE_AUTHORIZED_V1",
            "conflict_id": conflict_id,
            "decision_id": decision_id,
            "writer_agent_id": conflict.attempted_writer_id,
            "merge_policy": policy.merge_policy,
            "merge_policy_hash": frozen_policy_hash,
            "policy_proof_hash": policy_proof_hash,
            "patch_hash": computed_hash,
            "original_base_version": conflict.attempted_base_version,
            "original_base_hash": conflict.attempted_base_hash,
            "actual_merge_base_version": document.version,
            "actual_merge_base_hash": document.document_hash,
            "result_version": committed.document.version,
            "result_hash": committed.document.document_hash,
        }
        resolved = {
            "schema": "BLACKBOARD_CONFLICT_RESOLVED_V1",
            "conflict_id": conflict_id,
            "document_id": conflict.document_id,
            "decision_id": decision_id,
            "resolution": "POLICY_PROVEN_AUTO_REBASE",
            "resolved_version": committed.document.version,
            "resolved_hash": committed.document.document_hash,
            "cleared_obligations": list(conflict.blocked_obligations),
            "blocking_conflict_remaining": False,
        }
        committed_event = {
            **committed.event,
            "resolution_conflict_id": conflict_id,
            "auto_rebase_decision_id": decision_id,
            "policy_proof_hash": policy_proof_hash,
        }
        self.conflicts[conflict_id] = replace(
            conflict,
            state=ConflictState.RESOLVED,
            decision_id=decision_id,
            resolved_version=committed.document.version,
            resolved_hash=committed.document.document_hash,
        )
        authorized = self._append_fact(authorized)
        resolved = self._append_fact(resolved)
        committed_event = self._append_fact(committed_event)
        self.documents[committed.document.document_id] = committed.document
        self._record_version(committed.document, committed_event["position"])
        return ConflictResolutionResult(
            committed.document,
            authorized,
            resolved,
            committed_event,
            conflict.blocked_obligations,
        )

    @staticmethod
    def read_structured_body(value: Mapping[str, Any]) -> BlackboardBodyRead:
        try:
            return read_blackboard_body(value)
        except BlackboardStateError as error:
            raise BlackboardError(str(error)) from error

    def snapshot(
        self,
        *,
        position: int | None = None,
        versions: Mapping[str, int] | None = None,
    ) -> BlackboardSnapshot:
        target_position = self._position if position is None else position
        if target_position < 0 or target_position > self._position:
            raise BlackboardError("Blackboard snapshot position is outside the canonical frontier")
        requested_versions = dict(versions or {})
        if any(document_id not in self._history for document_id in requested_versions):
            raise BlackboardError("Blackboard snapshot requests an unknown Document")
        selected: list[BlackboardDocument] = []
        for document_id, history in sorted(self._history.items()):
            candidates = [
                document
                for event_position, document in history
                if event_position <= target_position
                and (document_id not in requested_versions or document.version == requested_versions[document_id])
            ]
            if document_id in requested_versions and not candidates:
                raise BlackboardError("requested Blackboard Document version is unavailable at this position")
            if candidates:
                selected.append(candidates[-1])
        return BlackboardSnapshot.build(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            position=target_position,
            documents=tuple(self._document_mapping(document) for document in selected),
        )

    def restore_snapshot(self, snapshot: BlackboardSnapshot) -> None:
        if self.documents or self.journal_facts or self._position:
            raise BlackboardError("Blackboard snapshot restore requires an empty recovery aggregate")
        try:
            snapshot.verify()
        except BlackboardStateError as error:
            raise BlackboardError(str(error)) from error
        if snapshot.tenant_id != self.tenant_id or snapshot.run_id != self.run_id:
            raise BlackboardError("Blackboard snapshot tenant/run isolation mismatch")
        restored: dict[str, BlackboardDocument] = {}
        for item in snapshot.documents:
            document = self._document_from_mapping(item)
            if document.tenant_id != self.tenant_id or document.run_id not in {None, self.run_id}:
                raise BlackboardError("snapshot Document tenant/run isolation mismatch")
            policy = self.policies.get(document.namespace)
            if policy is None or document.schema_id != policy.schema_id or document.schema_version != policy.schema_version:
                raise BlackboardError("snapshot Document schema does not match the frozen Namespace policy")
            if document.document_id in restored:
                raise BlackboardError("snapshot contains duplicate Document IDs")
            restored[document.document_id] = document
        self.documents = restored
        self._position = snapshot.position
        self._history = {
            document_id: [(snapshot.position, document)]
            for document_id, document in restored.items()
        }

    def reuse_project_document(self, document: BlackboardDocument) -> dict[str, Any]:
        if document.tenant_id != self.tenant_id:
            raise BlackboardError("cross-tenant Blackboard reuse is forbidden")
        policy = self.policies.get(document.namespace)
        if policy is None or policy.persistence_scope != "PROJECT_SHARED" or document.run_id is not None:
            raise BlackboardError("run-local Blackboard state cannot be promoted or reused")
        if document.document_id in self.documents:
            raise BlackboardError("Blackboard Document already exists in target run")
        self.documents[document.document_id] = document
        event = self._append_fact(
            {
                "schema": "BLACKBOARD_PROJECT_DOCUMENT_REUSED_V1",
                "document_id": document.document_id,
                "document_version": document.version,
                "document_hash": document.document_hash,
                "created_event_ref": document.created_event_ref,
                "source_run_id": None,
            }
        )
        self._record_version(document, event["position"])
        return event

    @staticmethod
    def _contains_key(value: Any, key: str) -> bool:
        if isinstance(value, Mapping):
            return key in value or any(Blackboard._contains_key(item, key) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(Blackboard._contains_key(item, key) for item in value)
        return False

    def query(
        self,
        *,
        agent_id: str,
        reader_capabilities: tuple[str, ...] = (),
        namespace: BlackboardNamespace | None = None,
        key: str | None = None,
        tag: str | None = None,
        run_id: str | None = None,
        version: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> BlackboardQueryPage:
        validate_identifier(agent_id, field="blackboard_query_actor")
        if not 1 <= limit <= 1_000 or version is not None and version < 0:
            raise BlackboardError("invalid Blackboard query pagination or version")
        if cursor is None:
            snapshot_position = self._position
            last_document_id = ""
        else:
            try:
                raw_position, last_document_id = cursor.split(":", 1)
                snapshot_position = int(raw_position)
            except (ValueError, TypeError) as error:
                raise BlackboardError("invalid Blackboard query cursor") from error
            validate_identifier(last_document_id, field="blackboard_query_cursor_document")
        snapshot = self.snapshot(position=snapshot_position)
        documents = [self._document_from_mapping(item) for item in snapshot.documents]
        index = BlackboardQueryIndex.build(tuple(documents))
        candidate_ids = index.match(
            namespace=namespace.value if namespace is not None else None,
            key=key,
            tag=tag,
            run_id=run_id,
            version=version,
        )
        visible = []
        for document in documents:
            if document.document_id not in candidate_ids:
                continue
            policy = self.policies[document.namespace]
            if not set(policy.reader_capabilities).issubset(reader_capabilities):
                continue
            if document.document_id > last_document_id:
                visible.append(document)
        visible.sort(key=lambda item: (item.document_id, item.version))
        page = tuple(visible[:limit])
        next_cursor = (
            f"{snapshot_position}:{page[-1].document_id}"
            if page and len(visible) > len(page)
            else None
        )
        self._append_fact(
            {
                "schema": "BLACKBOARD_QUERY_EXECUTED_V1",
                "actor_id": agent_id,
                "snapshot_position": snapshot_position,
                "result_count": len(page),
                "has_more": next_cursor is not None,
            }
        )
        return BlackboardQueryPage(page, next_cursor, snapshot_position)

    def subscribe(
        self,
        subscription_id: str,
        *,
        namespaces: tuple[BlackboardNamespace, ...],
        from_position: int = 0,
        max_pending: int = 100,
    ) -> BlackboardSubscription:
        if from_position < 0 or from_position > self._position:
            raise BlackboardError("subscription position is outside the canonical frontier")
        subscription = BlackboardSubscription(
            subscription_id,
            tuple(sorted({namespace.value for namespace in namespaces})),
            from_position,
            max_pending,
        )
        existing = self.subscriptions.get(subscription_id)
        if existing is not None:
            if existing != subscription:
                raise BlackboardError("subscription identity already has different recovery state")
            return existing
        self.subscriptions[subscription_id] = subscription
        self._append_fact(
            {
                "schema": "BLACKBOARD_SUBSCRIPTION_CREATED_V1",
                "subscription_id": subscription_id,
                "namespaces": list(subscription.namespaces),
                "from_position": from_position,
                "max_pending": max_pending,
            }
        )
        return subscription

    def poll_subscription(self, subscription_id: str) -> BlackboardNotificationPage:
        try:
            subscription = self.subscriptions[subscription_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard subscription") from error
        candidates = [
            event
            for event in self.journal_facts
            if event["position"] > subscription.last_acked_position
            and event.get("schema") == "BLACKBOARD_PATCH_COMMITTED_V1"
            and event.get("namespace") in subscription.namespaces
        ]
        unique: dict[str, dict[str, Any]] = {str(event["event_id"]): event for event in candidates}
        ordered = sorted(unique.values(), key=lambda event: (int(event["position"]), str(event["event_id"])))
        selected = ordered[: subscription.max_pending]
        notifications = tuple(
            BlackboardNotification(
                notification_id="notification-"
                + domain_hash(
                    "BLACKBOARD_NOTIFICATION",
                    canonical_json_bytes(
                        {"subscription_id": subscription_id, "event_id": event["event_id"]}
                    ),
                )[:32],
                subscription_id=subscription_id,
                event_id=str(event["event_id"]),
                position=int(event["position"]),
                document_id=str(event["document_id"]),
                namespace=str(event["namespace"]),
                committed_version=int(event["committed_version"]),
                committed_hash=str(event["committed_hash"]),
            )
            for event in selected
        )
        highest = notifications[-1].position if notifications else subscription.last_acked_position
        return BlackboardNotificationPage(notifications, len(ordered) > len(selected), highest)

    def acknowledge_subscription(self, subscription_id: str, *, through_position: int) -> BlackboardSubscription:
        try:
            subscription = self.subscriptions[subscription_id]
        except KeyError as error:
            raise BlackboardError("unknown Blackboard subscription") from error
        if through_position < subscription.last_acked_position or through_position > self._position:
            raise BlackboardError("subscription acknowledgement is non-monotonic or beyond the frontier")
        updated = replace(subscription, last_acked_position=through_position)
        self.subscriptions[subscription_id] = updated
        self._append_fact(
            {
                "schema": "BLACKBOARD_SUBSCRIPTION_ACKNOWLEDGED_V1",
                "subscription_id": subscription_id,
                "through_position": through_position,
            }
        )
        return updated

    def resume_subscription(self, subscription: BlackboardSubscription) -> None:
        if subscription.last_acked_position > self._position:
            raise BlackboardError("subscription recovery cursor is beyond the canonical frontier")
        existing = self.subscriptions.get(subscription.subscription_id)
        if existing is not None and existing != subscription:
            raise BlackboardError("subscription recovery conflicts with current state")
        self.subscriptions[subscription.subscription_id] = subscription

    def rebuild_subscriptions(self, facts: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]) -> None:
        rebuilt: dict[str, BlackboardSubscription] = {}
        seen_event_ids: set[str] = set()
        ordered = sorted(facts, key=lambda event: (int(event.get("position", 0)), str(event.get("event_id", ""))))
        recovery_frontier = max((int(event.get("position", 0)) for event in ordered), default=self._position)
        for event in ordered:
            event_id = str(event.get("event_id", ""))
            if event_id and event_id in seen_event_ids:
                continue
            if event_id:
                seen_event_ids.add(event_id)
            schema = event.get("schema")
            if schema == "BLACKBOARD_SUBSCRIPTION_CREATED_V1":
                try:
                    subscription = BlackboardSubscription(
                        str(event["subscription_id"]),
                        tuple(str(item) for item in event["namespaces"]),
                        int(event["from_position"]),
                        int(event["max_pending"]),
                    )
                except (KeyError, TypeError, ValueError, BlackboardStateError) as error:
                    raise BlackboardError("subscription creation fact is damaged") from error
                existing = rebuilt.get(subscription.subscription_id)
                if existing is not None and existing != subscription:
                    raise BlackboardError("duplicate subscription identity has conflicting facts")
                rebuilt[subscription.subscription_id] = subscription
            elif schema == "BLACKBOARD_SUBSCRIPTION_ACKNOWLEDGED_V1":
                subscription_id = str(event.get("subscription_id", ""))
                current = rebuilt.get(subscription_id)
                try:
                    through_position = int(event["through_position"])
                except (KeyError, TypeError, ValueError) as error:
                    raise BlackboardError("subscription acknowledgement fact is damaged") from error
                if current is None or through_position < current.last_acked_position:
                    raise BlackboardError("subscription acknowledgement fact is unknown or non-monotonic")
                if through_position > recovery_frontier:
                    raise BlackboardError("subscription acknowledgement fact is beyond the canonical frontier")
                rebuilt[subscription_id] = replace(current, last_acked_position=through_position)
        self.subscriptions = rebuilt

    def poll_changes(self, *, from_position: int, limit: int = 100) -> tuple[dict[str, Any], ...]:
        if from_position < 0 or limit < 1:
            raise BlackboardError("invalid Blackboard polling request")
        candidates = (
            event
            for event in self.journal_facts
            if event["position"] > from_position and event.get("schema") == "BLACKBOARD_PATCH_COMMITTED_V1"
        )
        unique = {str(event["event_id"]): event for event in candidates}
        return tuple(sorted(unique.values(), key=lambda event: (int(event["position"]), str(event["event_id"]))))[:limit]

    def verify_diff_replay(self, document_id: str) -> tuple[int, str]:
        created = next(
            (
                event
                for event in self.journal_facts
                if event.get("schema") == "BLACKBOARD_DOCUMENT_CREATED_V1"
                and event.get("document_id") == document_id
            ),
            None,
        )
        if created is None:
            raise BlackboardError("Blackboard Diff replay is missing Document creation")
        version = int(created["current_version"])
        current_hash = str(created["current_hash"])
        body: Mapping[str, Any] | None = {}
        commits = [
            event
            for event in self.journal_facts
            if event.get("schema") == "BLACKBOARD_PATCH_COMMITTED_V1"
            and event.get("document_id") == document_id
        ]
        for event in commits:
            if event.get("before_hash") != current_hash or int(event.get("base_version", -1)) != version:
                raise BlackboardError("Blackboard Diff hash/version chain is damaged")
            if int(event.get("committed_version", -1)) != version + 1:
                raise BlackboardError("Blackboard Diff version transition is invalid")
            if "patch" in event:
                expected_changes = list(field_level_changes(body, event["patch"]))
                if event.get("field_changes") != expected_changes:
                    raise BlackboardError("Blackboard field Diff is damaged")
                body = event["patch"]
            else:
                body = None
            version = int(event["committed_version"])
            current_hash = str(event["after_hash"])
        return version, current_hash

    @property
    def active_conflicts(self) -> tuple[BlackboardConflict, ...]:
        return tuple(item for item in self.conflicts.values() if item.state is not ConflictState.RESOLVED)

    @property
    def closing_blockers(self) -> tuple[str, ...]:
        return tuple(sorted({obligation for item in self.active_conflicts for obligation in item.blocked_obligations}))
