from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .retention import RetentionBlockers


class RetentionOperationError(RuntimeError):
    pass


class OperationState(str, Enum):
    PROPOSED = "PROPOSED"
    ASSESSED = "ASSESSED"
    APPROVED = "APPROVED"
    FENCED = "FENCED"
    EXECUTING = "EXECUTING"
    EXECUTED_DRY_RUN = "EXECUTED_DRY_RUN"
    RECONCILING = "RECONCILING"
    RECONCILED = "RECONCILED"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"
    FAILED_UNKNOWN = "FAILED_UNKNOWN"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class RetentionOperation:
    operation_id: str
    kind: str
    object_ids: tuple[str, ...]
    copy_ids: tuple[str, ...]
    policy_snapshot_hash: str
    catalog_snapshot_hash: str
    frontier_hash: str
    hold_snapshot_hash: str
    approval_quorum: int
    executor_id: str
    deadline: int
    state: OperationState = OperationState.PROPOSED
    approvals: tuple[str, ...] = ()
    fence_token: str | None = None
    destructive_capability_present: bool = False
    reconciliation_evidence_hash: str | None = None
    operation_hash: str = ""

    def __post_init__(self) -> None:
        if not self.operation_hash:
            object.__setattr__(self, "operation_hash", domain_hash("RETENTION_OPERATION", canonical_json_bytes(self.identity_mapping())))

    @property
    def stream_id(self) -> str:
        return f"retention-operation/{self.operation_id}"

    def identity_mapping(self) -> dict[str, object]:
        return {
            "schema": "RETENTION_OPERATION_IDENTITY_V1",
            "operation_id": self.operation_id,
            "kind": self.kind,
            "object_ids": list(self.object_ids),
            "copy_ids": list(self.copy_ids),
            "policy_snapshot_hash": self.policy_snapshot_hash,
            "catalog_snapshot_hash": self.catalog_snapshot_hash,
            "frontier_hash": self.frontier_hash,
            "hold_snapshot_hash": self.hold_snapshot_hash,
            "approval_quorum": self.approval_quorum,
            "executor_id": self.executor_id,
            "deadline": self.deadline,
        }

    @classmethod
    def propose(cls, operation_id: str, **values: object) -> "RetentionOperation":
        validate_identifier(operation_id, field="operation_id")
        return cls(operation_id=operation_id, **values)  # type: ignore[arg-type]

    def assess(
        self,
        *,
        blockers: RetentionBlockers,
        replica_compliant_after: bool,
        current_catalog_hash: str,
        current_hold_hash: str,
    ) -> "RetentionOperation":
        if self.state is not OperationState.PROPOSED:
            raise RetentionOperationError("assessment is out of order")
        if not blockers.clear or not replica_compliant_after:
            raise RetentionOperationError("retention blockers or replica policy prevent assessment")
        if current_catalog_hash != self.catalog_snapshot_hash or current_hold_hash != self.hold_snapshot_hash:
            raise RetentionOperationError("retention snapshots drifted before assessment")
        return replace(self, state=OperationState.ASSESSED)

    def approve(self, approvers: tuple[str, ...], *, now: int) -> "RetentionOperation":
        if self.state is not OperationState.ASSESSED:
            raise RetentionOperationError("approval is out of order")
        unique = tuple(sorted(set(approvers)))
        if len(unique) < self.approval_quorum or now > self.deadline:
            raise RetentionOperationError("approval quorum is insufficient or stale")
        return replace(self, state=OperationState.APPROVED, approvals=unique)

    def fence(self, *, fence: str, current_catalog_hash: str, current_hold_hash: str) -> "RetentionOperation":
        if self.state is not OperationState.APPROVED:
            raise RetentionOperationError("fencing is out of order")
        if current_catalog_hash != self.catalog_snapshot_hash or current_hold_hash != self.hold_snapshot_hash:
            raise RetentionOperationError("retention snapshots drifted at fence")
        return replace(self, state=OperationState.FENCED, fence_token=fence)

    def execute_dry_run(self, *, outcome: str) -> tuple["RetentionOperation", dict[str, object]]:
        if self.state is not OperationState.FENCED:
            raise RetentionOperationError("execution is out of order")
        if outcome not in {"ACKNOWLEDGED", "ACK_LOST"}:
            raise RetentionOperationError("unknown executor disposition")
        state = OperationState.EXECUTED_DRY_RUN if outcome == "ACKNOWLEDGED" else OperationState.RECONCILING
        receipt = {
            "schema": "RETENTION_DRY_RUN_RECEIPT_V1",
            "operation_id": self.operation_id,
            "outcome": outcome,
            "physical_delete_executed": False,
            "destructive_capability_present": False,
        }
        return replace(self, state=state), receipt

    def reconcile(self, *, evidence_hash: str, physical_absence_claimed: bool) -> "RetentionOperation":
        if self.state not in {OperationState.EXECUTED_DRY_RUN, OperationState.RECONCILING}:
            raise RetentionOperationError("reconciliation is out of order")
        if physical_absence_claimed:
            raise RetentionOperationError("dry-run reconciliation cannot claim physical absence")
        return replace(self, state=OperationState.RECONCILED, reconciliation_evidence_hash=evidence_hash)

    def verify(self, *, verifier_id: str, dry_run_verified: bool) -> "RetentionOperation":
        if self.state is not OperationState.RECONCILED or not dry_run_verified:
            raise RetentionOperationError("verified reconciliation evidence is required")
        return replace(self, state=OperationState.VERIFIED)

    def complete(self) -> "RetentionOperation":
        if self.state is not OperationState.VERIFIED:
            raise RetentionOperationError("unknown or unverified operation cannot complete")
        return replace(self, state=OperationState.COMPLETED)

class MemoryRetention:
    """Explicit, Journal-owned expiry of one native Memory content copy.

    Scheduling is opt-in. The old RetentionOperation API remains dry-run only.
    The authoritative writer holds its Journal mutex throughout admission and
    execution; a started operation is never automatically executed again.
    """

    def __init__(self, repository):
        self.repository = repository
        self.journal = repository.journal
        self.cas = repository.cas

    @staticmethod
    def _now():
        import datetime as dt
        return dt.datetime.now(dt.timezone.utc)

    @staticmethod
    def _time(value):
        import datetime as dt
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise RetentionOperationError("retention timestamp requires a timezone")
        return parsed

    @staticmethod
    def _digest(value):
        import hashlib
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    def _events(self, operation_id):
        validate_identifier(operation_id, field="retention operation_id")
        stream = "retention-operation/" + operation_id
        return tuple(event for event in self.journal.iter_events(0) if event.stream_id == stream)

    def _append(self, operation_id, state, payload):
        from sitina.commands.model import CommandEnvelope
        from sitina.journal.model import EventEnvelope
        stream = "retention-operation/" + operation_id
        version = self.journal._stream_heads.get(stream, 0)
        now = self._now().isoformat().replace("+00:00", "Z")
        body = {"schema": "SITINA_MEMORY_RETENTION_V1", "operation_id": operation_id,
                "state": state, **payload}
        digest = self._digest(body)
        command = CommandEnvelope("retention-cmd-" + digest[:40], self.repository.TENANT,
                                  stream, "memory.retention", "memory-retention", now,
                                  {"operation_id": operation_id, "state": state})
        event = EventEnvelope("retention-event-" + digest[:40], "retention." + state.lower(),
                              self.repository.TENANT, stream, 0, 0, now, body, ())
        self.journal.append(command, version, [event])

    def _plan(self, operation_id, actor):
        events = self._events(operation_id)
        if not events or events[0].payload.get("state") != "SCHEDULED":
            raise RetentionOperationError("retention operation is not scheduled")
        plan = dict(events[0].payload)
        if plan.get("schema") != "SITINA_MEMORY_RETENTION_V1":
            raise RetentionOperationError("retention operation has an unsupported schema")
        if plan["authority"] != actor or plan["cas_home"] != str(self.cas.home):
            raise RetentionOperationError("retention authority or namespace mismatch")
        document = self.repository._raw_get(plan["memory_id"])
        document.acl.require(actor, "review")
        return plan, events, document

    @staticmethod
    def _memory_binding(repository, document):
        decision = repository._decision_event_for_memory(document.memory_id)
        return {
            "memory_id": document.memory_id,
            "content_ref": document.content_ref,
            "content_hash": document.content_hash,
            "scope": document.scope,
            "owner_id": document.owner_id,
            "namespace": document.namespace,
            "retention_policy": document.retention_policy,
            "expires_at": document.expires_at,
            "status": document.status,
            "memory_revision": repository._stream_events(document.memory_id)[-1].event_id,
            "decision_revision": decision.event_id if decision is not None else None,
        }

    def schedule(self, *, operation_id, memory_id, actor, approval_seconds=3600):
        import datetime as dt
        with self.journal._mutex:
            self.repository._assert_write_enabled()
            self.cas._assert_writable()
            existing = self._events(operation_id)
            if existing:
                plan, _, _ = self._plan(operation_id, actor)
                if plan["memory_id"] != memory_id or plan["approval_seconds"] != approval_seconds:
                    raise RetentionOperationError("retention operation id is already bound")
                return self.status(operation_id=operation_id, actor=actor)
            if type(approval_seconds) is not int or not 1 <= approval_seconds <= 86400:
                raise RetentionOperationError("approval_seconds must be between 1 and 86400")
            document = self.repository._raw_get(memory_id)
            document.acl.require(actor, "review")
            if document.retention_policy != "until-expired" or document.expires_at is None:
                raise RetentionOperationError("explicit until-expired policy is required")
            if document.status not in {"candidate", "accepted", "superseded"}:
                raise RetentionOperationError("memory is not eligible for scheduling")
            now = self._now()
            due = self._time(document.expires_at)
            if due <= now:
                raise RetentionOperationError("retention must be scheduled before its due time")
            for event in self.journal.iter_events(0):
                if (event.event_type == "retention.scheduled"
                        and event.payload.get("memory_id") == memory_id):
                    raise RetentionOperationError("memory already has a retention operation")
            reference = self.cas.resolve_reference(document.content_ref)
            copy = self.cas.inspect_retention_copy(reference)
            binding = self._memory_binding(self.repository, document)
            self._append(operation_id, "SCHEDULED", {
                "memory_id": memory_id, "cas_home": str(self.cas.home),
                "namespace_kind": self.cas.namespace_kind, "authority": actor,
                "authorization": "explicit-acl-reviewer",
                "scheduled_at": now.isoformat().replace("+00:00", "Z"),
                "due_at": document.expires_at,
                "approval_deadline": (due + dt.timedelta(seconds=approval_seconds)).isoformat().replace("+00:00", "Z"),
                "approval_seconds": approval_seconds,
                "memory_binding": binding,
                "policy_snapshot_hash": self._digest(binding),
                "copies": [copy],
                "retained_metadata": ["journal", "key-envelope", "content-commitment", "destruction-attestation"],
            })
            return self.status(operation_id=operation_id, actor=actor)

    def status(self, *, operation_id, actor):
        with self.journal._mutex:
            plan, events, _ = self._plan(operation_id, actor)
            state = events[-1].payload["state"]
            if state not in {"SCHEDULED", "STARTED", "FAILED_UNKNOWN", "COMPLETED"}:
                raise RetentionOperationError("retention action state is unknown")
            result = {"operation_id": operation_id, "memory_id": plan["memory_id"],
                      "state": state, "due_at": plan["due_at"],
                      "approval_deadline": plan["approval_deadline"],
                      "physical_delete_executed": (True if state == "COMPLETED" else
                                                   False if state == "SCHEDULED" else None),
                      "automatic_retry_allowed": state == "SCHEDULED"}
            if state == "COMPLETED":
                result["physical_outcome"] = dict(events[-1].payload["physical_outcome"])
            elif state in {"STARTED", "FAILED_UNKNOWN"}:
                result["state"] = "UNKNOWN"
                result["automatic_retry_allowed"] = False
                # Absence alone never proves which action removed the object.
                result["copy_observation"] = self.cas.observe_retention_copy(plan["copies"][0])
            return result

    def _unprotected(self, document, events):
        from sitina.cas.gc import SemanticRootIndex
        index = SemanticRootIndex()
        index.apply_tail(events)
        for root in index.roots:
            if root.object_ref != document.content_ref:
                continue
            if root.root_type == "memory" and root.root_id == document.memory_id:
                continue  # Only this expired policy owner may release its root.
            raise RetentionOperationError("retention target has an active " + root.root_type + " root")
        for root in self.repository.active_roots():
            if root["object_ref"] == document.content_ref and root["root_id"] != document.memory_id:
                raise RetentionOperationError("retention target belongs to another live memory")
        for event in events:
            if document.content_ref not in event.object_refs:
                continue
            if (event.stream_id == "memory/" + document.memory_id
                    and event.event_type == "memory.candidate-created"):
                continue  # Immutable provenance is not a live content lease.
            raise RetentionOperationError("another content reference has not been released for retention")
        frontier = {"position": events[-1].position if events else 0,
                    "event_id": events[-1].event_id if events else None,
                    "semantic_roots_commitment": index.commitment}
        return self._digest(frontier)

    def execute(self, *, operation_id, actor):
        from contextlib import nullcontext
        from sitina.cas.gc import DestructionAttestation
        with self.journal._mutex:
            self.repository._assert_write_enabled()
            self.cas._assert_writable()
            plan, events, document = self._plan(operation_id, actor)
            if events[-1].payload["state"] != "SCHEDULED":
                return self.status(operation_id=operation_id, actor=actor)
            now = self._now()
            if now < self._time(plan["due_at"]):
                return {**self.status(operation_id=operation_id, actor=actor), "state": "WAITING_DUE"}
            if now > self._time(plan["approval_deadline"]):
                raise RetentionOperationError("retention approval has expired")
            binding = self._memory_binding(self.repository, document)
            if binding != plan["memory_binding"] or self._digest(binding) != plan["policy_snapshot_hash"]:
                raise RetentionOperationError("retention memory or policy revision changed")
            if self.cas.namespace_kind != plan["namespace_kind"]:
                raise RetentionOperationError("retention namespace changed")
            all_events = tuple(self.journal.iter_events(0))
            frontier = self._unprotected(document, all_events)
            reference = self.cas.resolve_reference(document.content_ref)
            if self.cas.inspect_retention_copy(reference) != plan["copies"][0]:
                raise RetentionOperationError("retention copy identity changed")
            controller = self.journal.gc_controller
            guard = controller.retention_guard(document.content_ref) if controller is not None else nullcontext()
            with guard:
                # The same Journal fence binds the plan, roots and intent. A
                # crash after this point leaves UNKNOWN, never permission to retry.
                self._append(operation_id, "STARTED", {"frontier_commitment": frontier})
                try:
                    self.repository.apply_memory_decision(
                        decision_id="memory-decision-retention-" + self._digest({"operation_id": operation_id})[:40],
                        source_closure={"retention_operation_id": operation_id,
                                        "policy_snapshot_hash": plan["policy_snapshot_hash"]},
                        candidate_actions=[{"memory_id": document.memory_id,
                                            "expected_status": document.status,
                                            "to_status": "expired",
                                            "reason_code": "retention-expired"}],
                        actor=actor, occurred_at=self._now().isoformat().replace("+00:00", "Z"),
                        decision_kind="retention-expiry",
                    )
                    outcome = self.cas.delete_retained_content(reference, expected_copy=plan["copies"][0])
                    current = tuple(self.journal.iter_events(0))
                    attestation = DestructionAttestation(
                        object_ref=document.content_ref, disposition="PHYSICAL_DELETE",
                        journal_position=current[-1].position, frontier_commitment=frontier,
                        occurred_at=self._now().isoformat().replace("+00:00", "Z"),
                        reason="scheduled-memory-retention",
                    )
                    self.cas.record_destruction_attestation(attestation)
                    self._append(operation_id, "COMPLETED", {
                        "physical_outcome": outcome, "attestation_id": attestation.mapping()["attestation_id"],
                        "frontier_commitment": frontier,
                    })
                except Exception as error:
                    # Preserve a redacted class, not possibly sensitive messages.
                    latest = self._events(operation_id)
                    if latest[-1].payload["state"] == "COMPLETED":
                        return self.status(operation_id=operation_id, actor=actor)
                    try:
                        self._append(operation_id, "FAILED_UNKNOWN", {"error_type": type(error).__name__})
                    except Exception:
                        pass  # The durable STARTED record already prohibits retry.
                    raise RetentionOperationError("retention action is UNKNOWN; do not retry the effect") from error
            return self.status(operation_id=operation_id, actor=actor)
