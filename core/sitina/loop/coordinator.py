from __future__ import annotations

import copy
import base64
import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sitina.cas.model import CASError
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import ExpectedStreamVersionConflict
from sitina.journal.model import EventEnvelope, FrontierRef, canonical_json_bytes, validate_timestamp
from sitina.runners.provider import ProviderCancelledError
from sitina.utils import iso_now, stable_json

from .agent_runner import AgentRunnerModule
from .assessment_recovery import validate_assessment_stop_resolution
from .admission import (
    SubmissionIntent,
    build_run_descriptor,
    build_submission_intent,
    submission_fingerprint,
    validate_capability_binding,
    workspace_identity,
)
from .context_memory import ContextMemoryModule
from .model import (
    SPEC_VERSION,
    REVIEW_REQUIRED_TASK_KINDS,
    AcceptanceRecord,
    AcceptanceSubmission,
    CompletionProposal,
    ControlIntent,
    EffectStatus,
    InputKind,
    InputRecord,
    OperationMode,
    OperationRecord,
    OperationRejected,
    PersistenceFenced,
    RecoveryNotConnected,
    StaleProposal,
    TaskConflict,
    TaskProjection,
    TaskStatus,
    TERMINAL_STATUSES,
    has_no_effect_result_shape,
    operation_agent_telemetry,
)
from .operations import (
    BusinessModificationLane,
    FilePrecondition,
    OperationIntent,
    OperationOutcome,
    RecoveryPolicy,
    probe_file_effect,
    resource_scene_observation,
    resources_conflict,
)
from sitina.extension_context import ExtensionPreparationContext
from .command_runner import (
    COMMAND_POLICY,
    TASK_COMMAND_POLICY,
    TASK_EXECUTION_CONTRACT,
    _bounded_read,
    observe_command_evidence,
    observe_managed_command,
    ManagedCommandUnsettled,
    request_command_cancel_evidence,
)
from .storage import LoopEventStore, LoopRuntimeContext, StoredContent
from .context_window import LoopContextIndex, LoopHistoryQuery
from .termination import (
    COUNT_EFFECTS,
    COUNT_NEUTRAL,
    REVIEW_REPAIR_KINDS,
    AttemptPlan,
    TERMINATION_CONTRACT_VERSION,
    stable_review_issue_id,
)
from .delegation import (
    CHILD_RUNTIME_SCHEMA,
    CHILD_RUNTIME_RESULT_SCHEMA,
    CHILD_SOURCE_SCHEMA,
    DELEGATION_CONTRACT_VERSION,
    ChildDelegationProjection,
    ReadonlyChildCapability,
    ReadonlySourceDenied,
    canonical_digest,
    child_identity,
    projection_from_mapping,
)
from .validation import ValidationModule


EXPERIENCE_OBLIGATION_STREAM = "loop-obligations"
EXPERIENCE_OBLIGATION_SCHEMA = "SITINA_LOOP_EXPERIENCE_OBLIGATION_V1"
EXPERIENCE_INPUT_EVIDENCE_SCHEMA = "SITINA_EXPERIENCE_INPUT_EVIDENCE_V1"
EXPERIENCE_INPUT_MAX_RECORDS = 128
EXPERIENCE_INPUT_MAX_BODY_BYTES = 16 * 1024
EXPERIENCE_INPUT_MAX_TOTAL_BYTES = 48 * 1024


def _command_snapshot(root: str | Path) -> dict[str, str]:
    base = Path(root).expanduser().resolve(strict=False)
    snapshot: dict[str, str] = {}
    if not base.exists() or base.is_symlink():
        return snapshot
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            # Keep command recovery snapshots in the same bare digest shape
            # as the runtime's queued input snapshot.
            snapshot[str(path.relative_to(base))] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return {}
    return snapshot


def _resource_root_identity(path: str | Path) -> dict[str, Any]:
    """Cheap final-commit identity check; never reads file contents."""

    candidate = Path(path).expanduser().resolve(strict=False)
    try:
        stat_result = candidate.lstat()
    except FileNotFoundError:
        return {"exists": False, "type": "absent", "device": None, "inode": None, "size": 0, "mtime_ns": None}
    if candidate.is_file():
        kind = "file"
    elif candidate.is_dir():
        kind = "directory"
    elif candidate.is_symlink():
        kind = "symlink"
    else:
        kind = "other"
    return {
        "exists": True,
        "type": kind,
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "size": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
    }


def _resource_entry_identity(root: str | Path, relative: str) -> dict[str, Any]:
    """Read one already-enumerated entry's metadata without content I/O."""

    base = Path(root).expanduser().resolve(strict=False)
    candidate = base if relative in {"", "."} else base / Path(relative)
    try:
        stat_result = candidate.lstat()
    except FileNotFoundError:
        return {"exists": False, "type": "absent", "device": None, "inode": None, "size": 0, "mtime_ns": None}
    if stat.S_ISLNK(stat_result.st_mode):
        kind = "symlink"
    elif stat.S_ISREG(stat_result.st_mode):
        kind = "file"
    elif stat.S_ISDIR(stat_result.st_mode):
        kind = "directory"
    else:
        kind = "other"
    return {
        "exists": True,
        "type": kind,
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "size": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
    }


def _canonical_safe_audit(value: Any) -> Any:
    """Make a Journal-safe audit copy without changing runtime protocol values."""

    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_safe_audit(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_safe_audit(item) for item in value]
    return value


def _command_safe(value: Any) -> Any:
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Mapping):
        return {str(key): _command_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_command_safe(item) for item in value]
    return value


def _extension_context_digest(
    task_id: str,
    source_path: str,
    extension_root: str,
    intent: OperationIntent,
    source_tree_hash: str | None,
    environment_hash: str | None,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "task_id": task_id,
                "source_path": source_path,
                "extension_root": extension_root,
                "source_tree_hash": source_tree_hash,
                "environment_hash": environment_hash,
                "intent": {
                    "operation_id": intent.operation_id,
                    "logical_operation_id": intent.logical_operation_id,
                    "attempt_id": intent.attempt_id,
                    "mode": intent.mode.value,
                    "description": intent.description,
                    "resources": list(intent.resources),
                    "expected_task_revision": intent.expected_task_revision,
                    "expected_run_instance_id": intent.expected_run_instance_id,
                    "expected_execution_epoch": intent.expected_execution_epoch,
                    "expected_goal_version": intent.expected_goal_version,
                    "expected_acceptance_version": intent.expected_acceptance_version,
                    "expected_handled_input_seq": intent.expected_handled_input_seq,
                    "capability_snapshot_id": intent.capability_snapshot_id,
                    "preconditions": [
                        {"path": item.path, "expected_identity": item.expected_identity}
                        for item in intent.preconditions
                    ],
                    "recovery": intent.recovery.as_dict(),
                    "business_attempt_id": intent.business_attempt_id,
                },
            }
        )
    ).hexdigest()


class LoopBackend:
    """One local background coordinator with five internal responsibility modules.

    The five modules are state/scheduling (this coordinator), Agent request
    binding, operation execution, validation, and context/memory content.  The
    Journal/CAS store is shared infrastructure, not another task authority.
    """

    def __init__(
        self,
        context: LoopRuntimeContext,
        *,
        append_fault: Callable[[str], None] | None = None,
    ) -> None:
        self.context = context
        self.run_instance_id = context.run_instance_id
        self.store: LoopEventStore = context.open_store(append_fault=append_fault)
        self.agent_runner = AgentRunnerModule()
        self.operations = BusinessModificationLane()
        self.validation = ValidationModule()
        self.context_memory = ContextMemoryModule(self.store)
        self._state_lock = threading.RLock()
        self._resource_limits: dict[str, Any] | None = None
        self._monitor_state: dict[str, Any] = {}
        self._monitor_version = 0
        self._persistence_failure: str | None = None
        self._task_cache: dict[str, TaskProjection] = {}
        self._extension_contexts: dict[tuple[str, str], ExtensionPreparationContext] = {}
        # Consumer receipts are published before the normal operation result
        # is committed.  Keep their proof briefly so that the operation-result
        # Journal event can make the receipt a canonical object reference,
        # rather than leaving it as an unaudited nested CAS string.
        self._extension_receipt_proofs: dict[str, Any] = {}
        self._extension_dispatchers: dict[str, tuple[str, Callable[[], OperationOutcome], Callable[[], Mapping[str, Any]] | None]] = {}
        self._active_extension_operations: set[str] = set()
        self._publication_check_recovery_errors: list[str] = []
        self._memory_repository: Any | None = None
        self._memory_actor: str | None = None
        self._child_dispatch_tokens: dict[tuple[str, str], object] = {}
        self._child_running: set[tuple[str, str]] = set()
        # Host installs a non-blocking callback for the one bounded readonly
        # child slot.  The backend remains the only Journal/CAS authority.
        self.child_dispatch_hook: Callable[[str, str], None] | None = None
        self.child_progress_hook: Callable[[str], Any] | None = None
        for task_id in self.store.task_ids():
            task = self._project(task_id, self.store.task_events(task_id))
            self._task_cache[task_id] = copy.deepcopy(task)
            for operation in task.operations.values():
                if operation.mode is OperationMode.WRITE and (
                    operation.effect_status is EffectStatus.INTENT_RECORDED or operation.unknown_effect
                ):
                    self.operations.restore_unknown_effect_owner(
                        task_id, operation.operation_id, resources=operation.resources,
                    )

    @classmethod
    def open(
        cls,
        home: str | Path,
        *,
        keychain_backend: Any | None = None,
        run_instance_id: str | None = None,
        append_fault: Callable[[str], None] | None = None,
    ) -> "LoopBackend":
        return cls(
            LoopRuntimeContext.open(
                home,
                backend=keychain_backend,
                run_instance_id=run_instance_id,
            ),
            append_fault=append_fault,
        )

    @property
    def persistence_fenced(self) -> bool:
        return self._persistence_failure is not None or self.store.fenced_reason is not None

    def _fail_persistence(self, error: BaseException) -> None:
        if self._persistence_failure is None:
            self._persistence_failure = (
                "required persistent record failed; no dependent business effect may be dispatched: "
                f"{type(error).__name__}"
            )

    def _require_persistence(self) -> None:
        if self.persistence_fenced:
            raise PersistenceFenced(self._persistence_failure or self.store.fenced_reason or "persistence fenced")

    # Extension authority bridge (batch 4A).  Extension code receives this
    # coordinator rather than a raw Journal/CAS object.  These narrow methods
    # preserve the Loop backend's persistence fence and writer ownership while
    # allowing the extension stream to remain separate from task streams.
    def assert_extension_write_ready(self) -> None:
        with self._state_lock:
            self._require_persistence()

    def extension_publication_source_binding(self, task_id: str, snapshot_id: str) -> dict[str, Any]:
        """Return the Backend-authenticated publication role for a live task.

        The extension authority may persist these fields as evidence, but the
        caller cannot use them to grant itself the role: they are derived from
        the current Loop task projection and capability binding here.
        """

        with self._state_lock:
            self._require_persistence()
            task = self.get_task(str(task_id))
            if task.is_terminal or task.control_intent is not ControlIntent.RUN:
                raise OperationRejected("publication source task is not an active RUN task")
            if task.received_input_seq != task.handled_input_seq:
                raise OperationRejected("publication source task has unhandled input")
            if task.task_kind != "code_change":
                raise OperationRejected("publication source task lacks the code_change write boundary")
            if str(task.capability_snapshot_id or "") != str(snapshot_id or ""):
                raise OperationRejected("publication source task capability differs from the candidate snapshot")
            return {
                "actor_role": "main",
                "publication_scope": "extension-root",
                "write_authorized": True,
            }

    def assert_extension_publication_write(
        self, task_id: str, operation_id: str, extension_root: str | os.PathLike[str]
    ) -> None:
        """Verify the active persisted WRITE operation owns the publication lane."""

        with self._state_lock:
            self._require_persistence()
            task = self.get_task(str(task_id))
            operation = task.operations.get(str(operation_id))
            normalized_root = str(Path(extension_root).expanduser().resolve(strict=False))
            if task.is_terminal or task.control_intent is not ControlIntent.RUN:
                raise OperationRejected("publication task control changed before the write")
            if operation is None or operation.mode is not OperationMode.WRITE:
                raise OperationRejected("publication has no persisted WRITE operation")
            if operation.effect_status is not EffectStatus.INTENT_RECORDED:
                raise OperationRejected("publication WRITE operation is not active")
            if not self.operations.is_owner(str(task_id), str(operation_id)):
                raise OperationRejected("publication does not own the modification lane")
            if normalized_root not in tuple(str(item) for item in operation.resources):
                raise OperationRejected("publication WRITE operation does not cover the extension root")

    @staticmethod
    def extension_publication_operation_id(request_id: str) -> str:
        """Return the stable Loop operation identity for one publication request."""

        return "extension-publication-" + hashlib.sha256(
            str(request_id).encode("utf-8")
        ).hexdigest()[:32]

    def _validate_extension_publication_attempt_lineage(
        self,
        task: TaskProjection,
        *,
        producer_attempt_id: str,
        current_attempt_id: str,
    ) -> None:
        """Authorize a publication whose trial crossed one settled scope yield."""

        if not producer_attempt_id or not current_attempt_id or producer_attempt_id == current_attempt_id:
            raise OperationRejected("publication trial attempt lineage is invalid")
        plans = task.attempt_plans
        current_plan = plans.get(current_attempt_id)
        producer_plan = plans.get(producer_attempt_id)
        if not isinstance(current_plan, Mapping) or not isinstance(producer_plan, Mapping):
            raise OperationRejected("publication trial attempt lineage is not persisted")

        # Walk only the persisted parent path from the current consumer back
        # to the operation producer.  Earlier historical attempts are not
        # prerequisites for this publication and may have different outcomes.
        chain: list[str] = []
        cursor: str | None = current_attempt_id
        while cursor != producer_attempt_id:
            if cursor is None:
                raise OperationRejected("publication trial attempt is not a contiguous continuation")
            if cursor in chain:
                raise OperationRejected("publication trial attempt lineage is circular")
            chain.append(cursor)
            plan = plans.get(cursor)
            if not isinstance(plan, Mapping):
                raise OperationRejected("publication trial attempt lineage has a missing plan")
            parent = plan.get("prior_attempt_id")
            if parent in (None, ""):
                cursor = None
            elif isinstance(parent, str) and parent.strip():
                cursor = parent
            else:
                raise OperationRejected("publication trial attempt lineage has an invalid parent")
            if len(chain) > len(plans) + 1:
                raise OperationRejected("publication trial attempt lineage is not bounded")
        if producer_attempt_id in chain:
            raise OperationRejected("publication trial attempt lineage is circular")
        chain.append(producer_attempt_id)
        producer_parent = producer_plan.get("prior_attempt_id")
        if isinstance(producer_parent, str) and producer_parent in chain:
            raise OperationRejected("publication trial attempt lineage is circular")

        identity_fields = (
            "task_id", "session_id", "run_instance_id", "execution_epoch",
            "goal_version", "acceptance_version", "criteria_lineage_version",
            "handled_input_seq", "artifact_ref", "environment_ref",
            "capability_snapshot_id",
        )
        task_identity = {
            "task_id": task.task_id,
            "session_id": task.session_id,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": task.execution_epoch,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "criteria_lineage_version": task.criteria_lineage_version,
            "handled_input_seq": task.handled_input_seq,
            "artifact_ref": task.artifact_ref,
            "environment_ref": task.environment_ref,
            "capability_snapshot_id": task.capability_snapshot_id,
        }
        for field in identity_fields:
            current_value = current_plan.get(field, 1) if field == "criteria_lineage_version" else current_plan.get(field)
            producer_value = producer_plan.get(field, 1) if field == "criteria_lineage_version" else producer_plan.get(field)
            if current_value != producer_value or current_value != task_identity[field]:
                raise OperationRejected("publication trial attempt binding changed across continuation")
        for field in ("lineage_id", "acceptance_item_id", "blocker_id", "blocker_source"):
            if current_plan.get(field) != producer_plan.get(field):
                raise OperationRejected("publication trial continuation has a different investigation lineage")
        for attempt_id in chain:
            plan = plans[attempt_id]
            if any(
                (plan.get(field, 1) if field == "criteria_lineage_version" else plan.get(field))
                != (current_plan.get(field, 1) if field == "criteria_lineage_version" else current_plan.get(field))
                for field in (
                    "task_id", "session_id", "run_instance_id", "execution_epoch",
                    "goal_version", "acceptance_version", "criteria_lineage_version",
                    "handled_input_seq", "artifact_ref", "environment_ref",
                    "capability_snapshot_id", "lineage_id", "acceptance_item_id",
                    "blocker_id", "blocker_source",
                )
            ):
                raise OperationRejected("publication trial lineage contains a stale parent plan")

        if any(
            str(item.get("attempt_id") or "") == current_attempt_id
            for item in task.attempt_settlements
            if isinstance(item, Mapping)
        ):
            raise OperationRejected("publication current attempt is already settled")

        # Every persisted parent must have one contract settlement.  The
        # immediate producer additionally must have yielded its local scope;
        # NO_PROGRESS is legal and intentionally not filtered.
        for attempt_id in chain[1:]:
            settlements = [
                item for item in task.attempt_settlements
                if isinstance(item, Mapping)
                and str(item.get("attempt_id") or "") == attempt_id
            ]
            contract_settlements = [
                item for item in settlements
                if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
            ]
            if len(settlements) != 1 or len(contract_settlements) != 1:
                raise OperationRejected("publication trial lineage settlement is missing or duplicated")
            settlement = contract_settlements[0]
            plan = plans[attempt_id]
            if (
                settlement.get("lineage_id") != plan.get("lineage_id")
                or settlement.get("acceptance_item_id") != plan.get("acceptance_item_id")
                or settlement.get("registered_blocker_id") != plan.get("blocker_id")
                or settlement.get("planned_artifact_ref") != plan.get("artifact_ref")
                or int(settlement.get("goal_version", -1)) != int(plan.get("goal_version", -2))
                or int(settlement.get("acceptance_version", -1)) != int(plan.get("acceptance_version", -2))
                or int(settlement.get("criteria_lineage_version", 1)) != int(plan.get("criteria_lineage_version", 1))
                or int(settlement.get("handled_input_seq", -1)) != int(plan.get("handled_input_seq", -2))
            ):
                raise OperationRejected("publication trial settlement does not match its plan")
            closing = settlement.get("closing_binding")
            if not isinstance(closing, Mapping):
                raise OperationRejected("publication trial settlement has no closing binding")
            for field in (
                "run_instance_id", "execution_epoch", "goal_version",
                "acceptance_version", "handled_input_seq", "artifact_ref",
            ):
                if closing.get(field) != task_identity[field]:
                    raise OperationRejected("publication trial settlement binding is stale")
            if closing.get("control_intent") != ControlIntent.RUN.value:
                raise OperationRejected("publication trial settlement did not close in RUN control")
            if settlement.get("outcome") != "LOCAL_SCOPE_YIELD":
                raise OperationRejected("publication trial continuation did not settle at LOCAL_SCOPE_YIELD")

    @staticmethod
    def extension_publication_replay_operation_id(
        request_id: str, run_id: str, call_id: str
    ) -> str:
        return "extension-publication-replay-" + hashlib.sha256(
            f"{request_id}\0{run_id}\0{call_id}".encode("utf-8")
        ).hexdigest()[:32]

    def _execute_extension_publication_replay(
        self,
        task_id: str,
        *,
        request_id: str,
        existing_publication: Any,
        run_id: str,
        call_id: str,
        business_attempt_id: str | None,
    ) -> Mapping[str, Any]:
        """Persist a READ query for a repeated publication tool call.

        The publication decision remains singular.  Each actual model call
        still receives its own task operation so protocol-history recovery can
        pair the call ID with a committed result.
        """

        task = self.get_task(str(task_id))
        original_operation_id = self.extension_publication_operation_id(request_id)
        original_operation = task.operations.get(original_operation_id)
        effective_attempt_id = str(
            business_attempt_id
            or (original_operation.business_attempt_id if original_operation is not None else "")
            or ""
        )
        if not effective_attempt_id:
            raise OperationRejected("publication replay is not bound to a planned business attempt")
        replay_operation_id = self.extension_publication_replay_operation_id(
            request_id, run_id, call_id
        )
        intent = OperationIntent(
            operation_id=replay_operation_id,
            logical_operation_id=f"{run_id}:{call_id}",
            attempt_id=f"{effective_attempt_id}:publication-replay:{replay_operation_id}",
            mode=OperationMode.READ,
            description="read an already committed extension publication decision",
            resources=(),
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_handled_input_seq=task.handled_input_seq,
            capability_snapshot_id=task.capability_snapshot_id,
            preconditions=(),
            recovery=RecoveryPolicy(
                probe="read the persisted extension publication decision",
                retry="retry only with the same logical call identity",
                partial="retain the persisted replay result",
                cancel="do not dispatch a publication effect",
                unknown_exit="inspect the committed replay operation result",
                reconsider_at="after task history recovery",
            ),
            business_attempt_id=effective_attempt_id,
        )
        existing_operation = task.operations.get(replay_operation_id)
        if existing_operation is not None and existing_operation.result_ref:
            persisted = self.context_memory.read(str(existing_operation.result_ref))
            prior_result = persisted.get("result") if isinstance(persisted, Mapping) else None
            if isinstance(prior_result, Mapping):
                return dict(prior_result.get("publication") or {}) | {
                    "replayed": True,
                    "operation_id": replay_operation_id,
                    "publication_operation_id": original_operation_id,
                }

        payload = dict(existing_publication.payload)
        outcome = self.execute_operation(
            str(task_id),
            intent,
            lambda: OperationOutcome(
                EffectStatus.SUCCEEDED,
                {
                    "tool": "sitina_publish_extension",
                    "permission": "write",
                    "status": "ok",
                    "publication": {
                        "schema": "SITINA_EXTENSION_PUBLICATION_COMMIT_V1",
                        "publication_id": payload.get("publication_id"),
                        "request_id": request_id,
                        "event_id": existing_publication.event_id,
                        "stream_version": existing_publication.stream_version,
                        "content_ref": payload.get("content_ref"),
                        "content_hash": payload.get("content_hash"),
                        "check_obligation": dict(payload.get("check_obligation") or {}),
                        "replayed": True,
                    },
                    "operation_id": replay_operation_id,
                    "publication_operation_id": original_operation_id,
                    "logical_operation_id": intent.logical_operation_id,
                    "business_attempt_id": effective_attempt_id,
                    "call_id": call_id,
                },
            ),
        )
        if outcome.status is not EffectStatus.SUCCEEDED:
            raise OperationRejected("publication replay READ operation did not settle")
        result = dict(outcome.result.get("publication") or {})
        result.update(
            {
                "replayed": True,
                "operation_id": replay_operation_id,
                "publication_operation_id": original_operation_id,
            }
        )
        return result

    def execute_extension_publication_tool(
        self,
        task_id: str,
        *,
        slot_id: str,
        candidate_id: str,
        trial_operation_id: str,
        request_id: str,
        run_id: str,
        call_id: str,
        business_attempt_id: str | None = None,
        publication_context: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Rebuild a Provider publication request from persisted Loop facts.

        This is the only Runtime-facing publication entrypoint.  The logical
        arguments are intentionally small; operation results, method plans,
        receipts, task lineage, and the pre-trial default intent are read from
        the Backend/Authority stores and cannot be supplied by the Provider.
        """

        authority = getattr(self, "_extension_authority", None)
        if authority is None:
            raise OperationRejected("extension publication has no shared authority")
        logical_slot = str(slot_id or "").strip().casefold()
        candidate = str(candidate_id or "")
        trial_id = str(trial_operation_id or "")
        publish_request_id = str(request_id or "")
        if not logical_slot or not candidate or not trial_id or not publish_request_id:
            raise OperationRejected("extension publication logical arguments are incomplete")
        context = dict(publication_context or {})
        if context:
            if str(context.get("request_id") or "") != publish_request_id:
                raise OperationRejected("publication request_id differs from the pre-trial intent")
            if str(context.get("slot_id") or "").strip().casefold() != logical_slot:
                raise OperationRejected("publication slot differs from the pre-trial intent")
            if str(context.get("candidate_id") or "") != candidate:
                raise OperationRejected("publication candidate differs from the pre-trial intent")

        # Exact publication replay is resolved before consulting the current
        # task, candidate tree, environment, or trial operation.  A later
        # cancellation or snapshot drift cannot turn an already committed
        # Journal fact into a new attempted write.
        existing_publication = authority._existing_request(publish_request_id)
        if existing_publication is not None:
            if existing_publication.event_type != "extension.publication-committed":
                raise OperationRejected("publication request_id belongs to another extension fact")
            payload = dict(existing_publication.payload)
            published = dict(payload.get("published") or {})
            trial = dict(payload.get("trial") or {})
            existing_slot = dict(payload.get("slot") or {})
            if (
                str(existing_slot.get("slot_id") or "") != logical_slot
                or str(published.get("candidate_id") or "") != candidate
                or str(trial.get("operation_id") or "") != trial_id
            ):
                raise OperationRejected("publication request_id was already used differently")
            replay = self._execute_extension_publication_replay(
                str(task_id),
                request_id=publish_request_id,
                existing_publication=existing_publication,
                run_id=str(run_id),
                call_id=str(call_id),
                business_attempt_id=business_attempt_id,
            )
            replay.update(
                {
                    "trial_request_id": trial.get("trial_request_id"),
                    "trial_event_id": trial.get("trial_event_id"),
                }
            )
            return replay

        task = self.get_task(str(task_id))
        snapshot_id = str(task.capability_snapshot_id or "")
        if not snapshot_id:
            raise OperationRejected("publication source task has no authenticated candidate snapshot")
        role = self.extension_publication_source_binding(str(task_id), snapshot_id)
        if role.get("actor_role") != "main" or role.get("publication_scope") != "extension-root":
            raise OperationRejected("publication source is not the main extension-root consumer")
        snapshot = authority.build_execution_snapshot(candidate).as_dict()
        if str(snapshot.get("snapshot_id") or "") != snapshot_id:
            raise OperationRejected("publication candidate is not the task's admitted snapshot")

        intent_request_id = authority._publication_intent_request_id(publish_request_id)
        intent_event = authority._existing_request(intent_request_id)
        if intent_event is None or intent_event.event_type != "extension.publication-intent-recorded":
            raise OperationRejected("publication intent was not persisted before the trial")
        intent_payload = dict(intent_event.payload)
        if (
            str(intent_payload.get("candidate_id") or "") != candidate
            or str(intent_payload.get("snapshot_id") or "") != snapshot_id
            or dict(intent_payload.get("slot") or {}).get("slot_id") != logical_slot
        ):
            raise OperationRejected("publication intent does not match the admitted candidate or slot")

        operation = task.operations.get(trial_id)
        if operation is None or operation.result_ref is None or operation.unknown_effect:
            raise OperationRejected("publication trial operation has no settled result")
        if operation.effect_status is not EffectStatus.SUCCEEDED:
            raise OperationRejected("publication trial operation did not succeed")
        effective_business_attempt_id = str(
            business_attempt_id or operation.business_attempt_id or ""
        )
        if not effective_business_attempt_id:
            raise OperationRejected("publication trial operation is not bound to a planned business attempt")
        if operation.business_attempt_id != effective_business_attempt_id:
            self._validate_extension_publication_attempt_lineage(
                task,
                producer_attempt_id=str(operation.business_attempt_id or ""),
                current_attempt_id=effective_business_attempt_id,
            )
        persisted = self.context_memory.read(str(operation.result_ref))
        if not isinstance(persisted, Mapping):
            raise OperationRejected("publication trial result is not a persisted object")
        raw_result = persisted.get("result") if isinstance(persisted.get("result"), Mapping) else persisted
        if not isinstance(raw_result, Mapping) or raw_result.get("status") != "ok":
            raise OperationRejected("publication trial result is not a successful consumer result")
        binding = raw_result.get("execution_binding")
        if not isinstance(binding, Mapping):
            raise OperationRejected("publication trial result has no Backend consumer receipt")
        # Authority accepts only the declared method identity.  The full
        # execution receipt remains persisted in the operation result and is
        # revalidated there; passing it wholesale would let receipt-only keys
        # masquerade as a method declaration.
        method = {
            key: binding[key]
            for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")
            if key in binding
        }
        task_binding = {
            field: getattr(task, field)
            for field in (
                "task_id", "session_id", "run_instance_id", "execution_epoch",
                "goal_version", "acceptance_version", "received_input_seq",
                "handled_input_seq", "artifact_ref",
            )
        }
        trial_request_id = str(context.get("trial_request_id") or ("trial:" + publish_request_id))
        trial_event = authority.record_trial_fact(
            request_id=trial_request_id,
            candidate_id=candidate,
            snapshot=snapshot,
            task_binding=task_binding,
            operation_id=trial_id,
            method=method,
            raw_result=dict(raw_result),
            input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        source = {**task_binding, **role}
        request: dict[str, Any] = {
            "request_id": publish_request_id,
            "slot": logical_slot,
            "candidate_id": candidate,
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "location_binding": snapshot.get("location_binding"),
            "source": source,
            "trial_request_id": trial_request_id,
            "trial_event_id": trial_event.event_id,
            "operation_id": trial_id,
            "expected_previous_default": intent_payload.get("expected_previous_default"),
            "expected_stream_position": intent_payload.get("expected_stream_position"),
            # These fields are consumed only by the Backend bridge to bind
            # the formal WRITE operation to the real Runtime call.  They are
            # excluded from Authority's canonical publication hash.
            "_logical_operation_id": f"{run_id}:{call_id}",
            "_business_attempt_id": effective_business_attempt_id,
            "_call_id": call_id,
        }
        publication = authority.commit_publication(request)
        result = dict(publication)
        result.update(
            {
                "operation_id": self.extension_publication_operation_id(publish_request_id),
                "trial_request_id": trial_request_id,
                "trial_event_id": trial_event.event_id,
            }
        )
        return result

    def execute_extension_publication(
        self,
        task_id: str,
        request_id: str,
        extension_root: str | os.PathLike[str],
        snapshot_id: str,
        dispatch: Callable[[str], Mapping[str, Any]],
        replay_check: Callable[[], Mapping[str, Any] | None] | None = None,
        *,
        logical_operation_id: str | None = None,
        business_attempt_id: str | None = None,
        call_id: str | None = None,
    ) -> Any:
        """Run one publication append inside the normal Backend WRITE path."""

        if not callable(dispatch):
            raise TypeError("publication dispatch must be callable")
        normalized_root = str(Path(extension_root).expanduser().resolve(strict=False))
        with self._state_lock:
            self._require_persistence()
            authority = getattr(self, "_extension_authority", None)
            if authority is not None and normalized_root != str(authority.extension_root):
                raise OperationRejected("publication root is not the Backend-bound extension root")
            task = self.get_task(str(task_id))
            self.extension_publication_source_binding(task_id, snapshot_id)
            operation_id = self.extension_publication_operation_id(request_id)
            intent = OperationIntent(
                operation_id=operation_id,
                logical_operation_id=(
                    str(logical_operation_id)
                    if logical_operation_id
                    else "extension-publication:" + str(request_id)
                ),
                attempt_id=(
                    "extension-publication-attempt:" + operation_id
                    if not business_attempt_id
                    else f"{business_attempt_id}:extension-publication:{operation_id}"
                ),
                mode=OperationMode.WRITE,
                description="publish an authenticated extension default",
                resources=(normalized_root,),
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_handled_input_seq=task.handled_input_seq,
                capability_snapshot_id=task.capability_snapshot_id,
                preconditions=(FilePrecondition.capture(normalized_root),),
                recovery=RecoveryPolicy(
                    probe="inspect the extension Journal publication decision",
                    retry="only after request replay proves no publication was committed",
                    partial="retain the Journal decision and operation evidence",
                    cancel="stop publication before its Journal append",
                    unknown_exit="hold the extension write lane",
                    reconsider_at="after an explicit publication recovery decision",
                ),
                business_attempt_id=(
                    str(business_attempt_id) if business_attempt_id else None
                ),
            )

        def guarded_dispatch() -> OperationOutcome:
            try:
                # The lane is acquired before this short coordination region;
                # waiting callers never hold the Backend state lock.  Once
                # here, source/default/CAS checks and the single Journal append
                # are linearized together.
                result = self.coordinate_extension_publication_commit(
                    lambda: dispatch(operation_id)
                )
                return OperationOutcome(
                    EffectStatus.SUCCEEDED,
                    {
                        "tool": "sitina_publish_extension",
                        "permission": "write",
                        "status": "ok",
                        "publication": dict(result),
                        "operation_id": operation_id,
                        "logical_operation_id": intent.logical_operation_id,
                        "business_attempt_id": intent.business_attempt_id,
                        "call_id": call_id,
                    },
                )
            except BaseException as error:
                # A Journal append can succeed immediately before a caller
                # loses its return path.  Re-read the authoritative decision
                # before classifying the operation as failed; never replace a
                # committed publication with a synthetic negative result.
                authority = getattr(self, "_extension_authority", None)
                if authority is not None:
                    try:
                        existing = authority._existing_request(str(request_id))
                    except BaseException as lookup_error:
                        return OperationOutcome(
                            EffectStatus.UNKNOWN,
                            {
                                "status": "unknown",
                                "error_type": type(lookup_error).__name__,
                                "error_message": str(lookup_error),
                                "effect_requires_probe": True,
                                "operation_id": operation_id,
                            },
                        )
                    if existing is not None and existing.event_type == "extension.publication-committed":
                        return OperationOutcome(
                            EffectStatus.SUCCEEDED,
                            {
                                "status": "ok",
                                "publication": {
                                    "schema": "SITINA_EXTENSION_PUBLICATION_COMMIT_V1",
                                    "publication_id": existing.payload.get("publication_id"),
                                    "request_id": request_id,
                                    "event_id": existing.event_id,
                                    "stream_version": existing.stream_version,
                                    "content_ref": existing.payload.get("content_ref"),
                                    "content_hash": existing.payload.get("content_hash"),
                                    "check_obligation": dict(existing.payload.get("check_obligation") or {}),
                                    "replayed": True,
                                },
                                "operation_id": operation_id,
                                "recovered_after_dispatch_error": True,
                            },
                        )
                return OperationOutcome(
                    EffectStatus.FAILED,
                    {
                        "status": "error",
                        "error_type": type(error).__name__,
                        "error_message": str(error),
                        "operation_id": operation_id,
                    },
                )

        lane_acquired = False
        try:
            # BusinessModificationLane.acquire is deliberately outside the
            # state lock.  A prior WRITE operation can therefore finish its
            # result/cleanup while a publication caller waits here, and a
            # CANCEL/control commit can enter the Backend normally.
            self.operations.acquire(str(task_id), operation_id)
            lane_acquired = True
            if replay_check is not None:
                with self._state_lock:
                    replay = replay_check()
                if replay is not None:
                    self.operations.release(str(task_id), operation_id)
                    lane_acquired = False
                    return replay
            try:
                outcome = self.execute_operation(
                    str(task_id),
                    intent,
                    guarded_dispatch,
                    prepare=lambda: {
                        "effect_kind": "extension-publication",
                        "resource": normalized_root,
                        "request_id": str(request_id),
                        "snapshot_id": str(snapshot_id),
                        "run_id": (
                            str(logical_operation_id).split(":", 1)[0]
                            if logical_operation_id and ":" in str(logical_operation_id)
                            else None
                        ),
                        "call_id": str(call_id) if call_id else None,
                    },
                    lane_preacquired=True,
                )
            finally:
                # execute_operation owns release once it has been handed the
                # pre-acquired lane, including its exception path.
                lane_acquired = False
            return outcome, operation_id
        except BaseException:
            if lane_acquired:
                self.operations.release(str(task_id), operation_id)
            raise


    def authorize_extension_preparation(
        self,
        task_id: str,
        *,
        source_path: str | os.PathLike[str],
        extension_root: str | os.PathLike[str],
        source_tree_hash: str | None = None,
        environment_hash: str | None = None,
        operation_id: str | None = None,
    ) -> ExtensionPreparationContext:
        """Issue an immutable, task-bound write context for extension prep.

        This is authorization only.  It does not copy files or publish a
        candidate.  The operation is revalidated and journalled by
        :meth:`execute_extension_preparation` immediately before its effect.
        """

        supplied_source = Path(source_path).expanduser()
        if supplied_source.is_symlink():
            raise OperationRejected("extension preparation source must not be a symlink")
        source = supplied_source.resolve(strict=False)
        target = Path(extension_root).expanduser().resolve(strict=False)
        if not source.is_dir():
            raise OperationRejected("extension preparation source must be a real directory")
        if not str(source_tree_hash or "").strip() and source_tree_hash is not None:
            raise OperationRejected("extension preparation source hash is invalid")
        if not str(environment_hash or "").strip() and environment_hash is not None:
            raise OperationRejected("extension preparation environment hash is invalid")
        with self._state_lock:
            self._require_persistence()
            task = self.get_task(task_id)
            operation_id = str(operation_id or ("extension-prepare-" + secrets.token_hex(16)))
            intent = OperationIntent(
                operation_id=operation_id,
                logical_operation_id="extension-preparation:" + operation_id,
                attempt_id="extension-preparation-attempt:" + operation_id,
                mode=OperationMode.WRITE,
                description="prepare an extension candidate under Loop control",
                resources=tuple(sorted({str(source), str(target)})),
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_handled_input_seq=task.handled_input_seq,
                capability_snapshot_id=task.capability_snapshot_id,
                preconditions=(FilePrecondition.capture(source), FilePrecondition.capture(target)),
                recovery=RecoveryPolicy(
                    probe="inspect the candidate tree and extension Journal",
                    retry="only after proving no candidate fact was committed",
                    partial="retain evidence and require explicit recovery",
                    cancel="stop new preparation dispatch",
                    unknown_exit="hold the extension write lane",
                    reconsider_at="after an explicit recovery decision",
                ),
            )
            # The authorization barrier rejects a stale or uncontrolled task
            # before returning a usable context.  A later change is caught
            # again by execute_operation's dispatch barrier.
            self._assert_intent_current(task, intent)
            binding_digest = _extension_context_digest(
                task_id,
                str(source),
                str(target),
                intent,
                source_tree_hash,
                environment_hash,
            )
            context = ExtensionPreparationContext(
                task_id=task_id,
                operation_id=operation_id,
                source_path=str(source),
                extension_root=str(target),
                intent=intent,
                source_tree_hash=source_tree_hash,
                environment_hash=environment_hash,
                binding_digest=binding_digest,
                _backend=self,
            )
            self._extension_contexts[(task_id, operation_id)] = context
            return context

    def assert_extension_preparation_current(
        self,
        context: ExtensionPreparationContext,
        *,
        require_active_operation: bool = False,
    ) -> None:
        """Recheck the exact issued binding immediately before an effect."""

        if not isinstance(context, ExtensionPreparationContext):
            raise OperationRejected("extension preparation requires a Backend-issued context")
        context.assert_issued_by(self)
        if self._extension_contexts.get((context.task_id, context.operation_id)) is not context:
            raise OperationRejected("extension preparation context was not issued by this Backend instance")
        expected_digest = _extension_context_digest(
            context.task_id,
            context.source_path,
            context.extension_root,
            context.intent,
            context.source_tree_hash,
            context.environment_hash,
        )
        if expected_digest != context.binding_digest:
            raise OperationRejected("extension preparation context was modified after issuance")
        if context.intent.mode is not OperationMode.WRITE or not context.intent.resources:
            raise OperationRejected("extension preparation context must retain a WRITE operation and resources")
        with self._state_lock:
            task = self.get_task(context.task_id)
            # Once execute_operation has recorded its own intent, the task
            # revision is exactly one greater.  All semantic bindings still
            # must match and the operation record must be the active one.
            self._require_persistence()
            if task.is_terminal:
                raise OperationRejected("terminal task cannot dispatch a new operation")
            if task.run_instance_id != context.intent.expected_run_instance_id:
                raise OperationRejected("extension preparation run identity changed")
            if task.execution_epoch != context.intent.expected_execution_epoch:
                raise OperationRejected("extension preparation execution epoch changed")
            if task.goal_version != context.intent.expected_goal_version:
                raise OperationRejected("extension preparation goal binding changed")
            if task.acceptance_version != context.intent.expected_acceptance_version:
                raise OperationRejected("extension preparation acceptance binding changed")
            if task.handled_input_seq != context.intent.expected_handled_input_seq:
                raise OperationRejected("extension preparation input binding changed")
            if task.capability_snapshot_id != context.intent.capability_snapshot_id:
                raise OperationRejected("extension preparation capability binding changed")
            if task.control_intent is not ControlIntent.RUN:
                raise OperationRejected("current control intent blocks extension preparation")
            if task.received_input_seq != task.handled_input_seq:
                raise OperationRejected("persisted input remains unhandled")
            revision_delta = task.task_revision - context.intent.expected_task_revision
            if revision_delta == 0:
                if require_active_operation:
                    raise OperationRejected("extension materialization requires an active WRITE operation")
                return
            if revision_delta not in {1, 2} or context.intent.operation_id not in task.operations:
                raise OperationRejected("extension preparation task revision changed")
            if require_active_operation:
                if not self.operations.is_owner(context.task_id, context.operation_id):
                    raise OperationRejected("extension materialization does not own the modification lane")
                operation = task.operations[context.intent.operation_id]
                if operation.mode is not OperationMode.WRITE or operation.effect_status.value != "INTENT_RECORDED":
                    raise OperationRejected("extension materialization has no active persisted WRITE intent")

    def execute_extension_preparation(
        self,
        context: ExtensionPreparationContext,
        dispatch: Callable[[], OperationOutcome],
    ) -> OperationOutcome:
        """Run a prepared extension write through the normal operation path."""

        if not isinstance(context, ExtensionPreparationContext):
            raise OperationRejected("extension preparation requires a Backend-issued context")
        context.assert_issued_by(self)
        self.assert_extension_preparation_current(context)
        return self.execute_operation(
            context.task_id,
            context.intent,
            dispatch,
            prepare=lambda: {
                "effect_kind": "file",
                "resource": context.extension_root,
                "preparation_operation": True,
            },
        )

    def _register_extension_dispatch(
        self,
        operation_id: str,
        kind: str,
        dispatch: Callable[[], OperationOutcome],
        prepare: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        if kind not in {"skill-resource-reader", "plugin-command-runner"} or not callable(dispatch):
            raise OperationRejected("extension dispatch must use a fixed consumer executor")
        self._extension_dispatchers[str(operation_id)] = (str(kind), dispatch, prepare)

    @staticmethod
    def _assert_extension_plan_equal(
        supplied: Mapping[str, Any], canonical: Mapping[str, Any]
    ) -> None:
        """Reject caller contracts that differ from the candidate's facts."""

        if set(supplied) != set(canonical):
            raise OperationRejected("extension method plan contains unrecognized or missing fields")
        for key, expected in canonical.items():
            if supplied.get(key) != expected:
                raise OperationRejected(f"extension method plan differs from authenticated {key}")

    def _canonical_extension_method_plan(
        self,
        *,
        task_id: str,
        intent: OperationIntent,
        supplied: Mapping[str, Any],
        snapshot: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Rebuild the consumer method from the current candidate on disk.

        The adapter's plan is only a request.  This method independently loads
        the authenticated candidate manifest/component and derives the tool,
        argument schema, executable, method contract, and expected output or
        resource bytes.  A plan is accepted only when it is byte-for-byte
        equal to those facts, so a caller cannot use its own contract to make
        an arbitrary callback look like a registered extension consumer.
        """

        if supplied.get("task_id") != str(task_id):
            raise OperationRejected("extension method plan task binding differs from the operation")
        if supplied.get("candidate_id") != snapshot.get("candidate_id"):
            raise OperationRejected("extension method plan candidate binding differs from the snapshot")
        if supplied.get("snapshot_id") != snapshot.get("snapshot_id") or supplied.get("snapshot_hash") != snapshot.get("snapshot_hash"):
            raise OperationRejected("extension method plan snapshot binding differs from the snapshot")
        call_id = str(supplied.get("call_id") or "")
        if not call_id or not intent.logical_operation_id.endswith(":" + call_id):
            raise OperationRejected("extension method plan call binding differs from the operation")
        arguments = supplied.get("arguments")
        if not isinstance(arguments, Mapping):
            raise OperationRejected("extension method plan arguments must be an object")

        root = Path(str(snapshot.get("root") or "")).resolve(strict=True)
        base = {
            "schema": "SITINA_EXTENSION_METHOD_PLAN_V1",
            "method_plan_schema": "SITINA_EXTENSION_METHOD_PLAN_V1",
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "candidate_id": snapshot.get("candidate_id"),
            "task_id": str(task_id),
            "call_id": call_id,
            "tool_name": None,
            "handler": None,
            "method_schema": "SITINA_EXTENSION_TRIAL_METHOD_V1",
            "method_version": 1,
            "method_id": None,
            "method_contract": None,
            "arguments": dict(arguments),
            "root": str(root),
            "python_path": None,
            "python_requested": None,
            "controlled_executor": None,
            "expected": None,
        }

        # The fixed Skill reader is read-only and has exactly one public
        # schema.  Its selected name and allowed resource paths come from the
        # authenticated Skill body, never from the caller's method contract.
        if str(snapshot.get("kind") or "") == "skill":
            try:
                from sitina.extensions.spec import load_skill

                skill_bindings = list(dict(snapshot.get("bindings") or {}).get("skills") or ())
                if len(skill_bindings) != 1 or not isinstance(skill_bindings[0], Mapping):
                    raise OperationRejected("authenticated Skill snapshot has no unique Skill binding")
                skill_binding = skill_bindings[0]
                relative_skill = Path(str(skill_binding.get("relative_path") or ""))
                if relative_skill.is_absolute() or ".." in relative_skill.parts:
                    raise OperationRejected("authenticated Skill path is invalid")
                skill_path = (root / relative_skill).resolve(strict=True)
                skill_path.relative_to(root)
                skill = load_skill(skill_path)
                qualified = str(skill_binding.get("qualified_name") or skill.qualified_name)
                if skill.qualified_name != qualified:
                    raise OperationRejected("authenticated Skill name differs from its candidate")
                from sitina.runners.mcp_adapter import validate_json_schema

                validate_json_schema(
                    dict(arguments),
                    {
                        "type": "object",
                        "properties": {"skill": {"type": "string"}, "path": {"type": "string"}},
                        "required": ["skill", "path"],
                        "additionalProperties": False,
                    },
                )
                skill_name = str(arguments.get("skill") or "")
                relative = Path(str(arguments.get("path") or ""))
                expected_paths = sorted({
                    match.group(0)
                    for match in re.finditer(
                        r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", skill.body,
                    )
                    if (root / match.group(0)).is_file()
                })
                if skill_name != qualified or relative.is_absolute() or ".." in relative.parts:
                    raise OperationRejected("Skill arguments do not match the authenticated Skill")
                if expected_paths and relative.as_posix() not in expected_paths:
                    raise OperationRejected("Skill resource is not registered by the authenticated Skill")
                resource = (root / relative).resolve(strict=True)
                resource.relative_to(root)
                raw = resource.read_bytes()
                contract = {
                    "schema": "SITINA_EXTENSION_METHOD_EXPECTATION_V1",
                    "kind": "skill-resource-read",
                    "skill": qualified,
                    "expected_paths": expected_paths,
                    "result_status": "ok",
                }
                method_id = hashlib.sha256(stable_json({
                    "handler": "skill-resource-read",
                    "qualified_name": qualified,
                    "snapshot_hash": snapshot.get("snapshot_hash"),
                    "expected_paths": expected_paths,
                }).encode("utf-8")).hexdigest()
                base.update({
                    "tool_name": "sitina_read_skill_resource",
                    "handler": "skill-resource-read",
                    "method_id": method_id,
                    "method_contract": contract,
                    "expected": {
                        "kind": "resource",
                        "relative_path": relative.as_posix(),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "bytes": len(raw),
                    },
                })
            except OperationRejected:
                raise
            except Exception as error:
                raise OperationRejected("authenticated Skill method could not be resolved") from error
            self._assert_extension_plan_equal(supplied, base)
            return base

        if str(snapshot.get("kind") or "") == "plugin" and supplied.get("handler") == "mcp":
            try:
                from sitina.extensions.manager import ExtensionManager
                from sitina.extensions.tools import ToolCatalog
                authority = self._extension_authority
                home = Path(str(snapshot["environment"]["sitina_home"]))
                manager = ExtensionManager(home, global_root=authority.extension_root)
                manager.use_shared_authority(authority)
                catalog = ToolCatalog(manager)
                catalog.bind_execution_snapshot(snapshot)
                canonical = catalog.consumer_method_plan(
                    str(supplied.get("tool_name") or ""), dict(arguments),
                    task_id=str(task_id), call_id=call_id,
                )
                if not isinstance(canonical, Mapping) or canonical.get("handler") != "mcp":
                    raise OperationRejected("MCP method is not declared by the authenticated candidate")
            except OperationRejected:
                raise
            except Exception as error:
                raise OperationRejected("authenticated MCP method could not be resolved") from error
            self._assert_extension_plan_equal(supplied, canonical)
            return dict(canonical)

        # Plugin tools are resolved from the candidate's own manifest and
        # tools.json.  Only the candidate-contained Python CommandRunner lane
        # can enter this 4B consumer; legacy catalog execution remains
        # available only when no authenticated consumer snapshot is bound.
        if str(snapshot.get("kind") or "") != "plugin":
            raise OperationRejected("unsupported authenticated extension kind")
        try:
            from sitina.extensions.spec import PluginManifest, TOOLS_SCHEMA, read_json_object
            from sitina.runners.mcp_adapter import validate_json_schema

            manifest = PluginManifest.load(root)
            tool_name = str(supplied.get("tool_name") or "")
            prefix = manifest.name + "__"
            if not tool_name.startswith(prefix):
                raise OperationRejected("Plugin tool is not owned by the authenticated candidate")
            local_name = tool_name[len(prefix):]
            tools_path = manifest.component_path("tools")
            if tools_path is None:
                raise OperationRejected("Plugin has no authenticated tools component")
            raw_tools = read_json_object(tools_path, schema=TOOLS_SCHEMA)
            entries = [item for item in (raw_tools.get("tools") or ()) if isinstance(item, Mapping)]
            item = next((entry for entry in entries if str(entry.get("name") or "") == local_name), None)
            if item is None:
                raise OperationRejected("Plugin tool is not declared by the authenticated candidate")
            granted = set(dict(snapshot.get("permissions") or {}).get("granted") or ())
            permission = str(item.get("permission") or "")
            if permission not in granted or permission not in set(manifest.permissions):
                raise OperationRejected("Plugin tool permission is not granted by the snapshot")
            command = item.get("command")
            if not isinstance(command, list) or not command or any(not isinstance(part, str) for part in command):
                raise OperationRejected("Plugin tool command is not a concrete string array")
            validate_json_schema(dict(arguments), dict(item.get("input_schema") or {"type": "object", "properties": {}}))
            environment = dict(snapshot.get("environment") or {})
            executables = dict(environment.get("executables") or {})
            python_identity = dict(executables.get("python") or {})
            python_path = str(python_identity.get("path") or "")
            python_requested = str(python_identity.get("requested") or python_path)
            executable = Path(command[0]).expanduser().resolve(strict=True)
            controlled_executor = None
            if str(executable) == python_path:
                if len(command) < 2:
                    raise OperationRejected("Plugin Python command has no script")
                script = Path(str(command[1]))
                if script.is_absolute() or ".." in script.parts or script.suffix != ".py":
                    raise OperationRejected("Plugin Python entrypoint must be a candidate-relative .py file")
                script_path = (root / script).resolve(strict=True)
                script_path.relative_to(root)
                if script_path.is_symlink() or not script_path.is_file():
                    raise OperationRejected("Plugin Python entrypoint is unavailable")
                controlled_executor = "loop-command-runner"
            else:
                raise OperationRejected("Plugin command executor is outside the connected 4B boundary")
            binding_base = {
                "snapshot_id": snapshot.get("snapshot_id"),
                "snapshot_hash": snapshot.get("snapshot_hash"),
                "candidate_id": snapshot.get("candidate_id"),
                "root": str(root),
                "python_path": python_path,
                "python_requested": python_requested,
                "method_schema": "SITINA_EXTENSION_TRIAL_METHOD_V1",
                "method_version": 1,
                "handler": "subprocess-command",
            }
            expected_output = item.get("expected_output")
            if expected_output is None:
                raise OperationRejected("Plugin method has no bounded deterministic output expectation")
            contract = {
                "schema": "SITINA_EXTENSION_METHOD_EXPECTATION_V1",
                "kind": "plugin-command",
                "command": list(command),
                "timeout_seconds": str(item.get("timeout_seconds", 30)),
                "output_json": bool(item.get("output_json", True)),
                "expected_output": expected_output,
                "controlled_executor": controlled_executor,
                "input_schema": dict(item.get("input_schema") or {}),
                "output_schema": dict(item.get("output_schema") or {}) if isinstance(item.get("output_schema"), Mapping) else None,
                "cache": dict(item.get("cache") or {}) if isinstance(item.get("cache"), Mapping) else None,
                "result_status": "ok",
            }
            binding = {**binding_base, "tool_name": tool_name, "command": list(command), "method_contract": contract}
            method_id = hashlib.sha256(stable_json(binding).encode("utf-8")).hexdigest()
            base.update({
                "tool_name": tool_name,
                "handler": "subprocess-command",
                "method_id": method_id,
                "method_contract": contract,
                "python_path": python_path,
                "python_requested": python_requested,
                "controlled_executor": controlled_executor,
                "expected": {
                    "kind": "plugin-output",
                    "command": list(command),
                    "output": expected_output,
                    "timeout_seconds": contract["timeout_seconds"],
                },
            })
        except OperationRejected:
            raise
        except Exception as error:
            raise OperationRejected("authenticated Plugin method could not be resolved") from error
        self._assert_extension_plan_equal(supplied, base)
        return base

    def execute_extension_tool(
        self,
        task_id: str,
        intent: OperationIntent,
        method_plan: Mapping[str, Any],
    ) -> OperationOutcome:
        """Dispatch one registered Skill/Plugin consumer through a fixed path.

        The public entry accepts only task/intent/plan identity.  The actual
        dispatch and preparation closures are installed by the Loop adapter
        in a private operation-scoped context; callers cannot pass an
        arbitrary callback or result to mint a receipt.
        """

        if not isinstance(method_plan, Mapping) or method_plan.get("method_plan_schema") != "SITINA_EXTENSION_METHOD_PLAN_V1":
            raise OperationRejected("extension tool execution requires a method plan")
        context = self._extension_dispatchers.pop(str(intent.operation_id), None)
        if context is None:
            raise OperationRejected("extension tool has no registered fixed dispatch context")
        kind, dispatch, prepare = context
        authority = getattr(self, "_extension_authority", None)
        if authority is None:
            raise OperationRejected("extension tool has no shared execution authority")
        # A runner may have authenticated a snapshot at startup, but the
        # persisted descriptor is the admission authority.  Re-open its
        # original publication binding at every fixed dispatch so a later
        # publication, descriptor substitution, or cross-task snapshot cannot
        # silently widen the consumer's capability.
        task = self.get_task(str(task_id))
        # Older direct 4B fixture tasks are intentionally descriptor-less and
        # remain outside ordinary capability-slot admission.  A selected CLI
        # task always has a descriptor and therefore takes the strict branch.
        if task.descriptor_ref and task.descriptor_hash:
            try:
                descriptor = self.context_memory.read(
                    str(task.descriptor_ref), expected_hash=str(task.descriptor_hash)
                )
            except Exception as error:
                raise OperationRejected("extension dispatch cannot read its admitted descriptor") from error
            capability_binding = descriptor.get("capability_binding") if isinstance(descriptor, Mapping) else None
            if isinstance(capability_binding, Mapping):
                admitted_snapshot = authority.verify_capability_binding(capability_binding)
                authority.assert_publication_dispatch_allowed(capability_binding)
                if str(task.capability_snapshot_id or "") != str(admitted_snapshot.get("snapshot_id") or ""):
                    raise OperationRejected("extension dispatch task is not bound to its admitted publication snapshot")
        candidate_id = str(method_plan.get("candidate_id") or "")
        snapshot = authority.build_execution_snapshot(candidate_id).as_dict()
        if any(
            str(method_plan.get(key) or "") != str(snapshot.get(key) or "")
            for key in ("candidate_id", "snapshot_hash", "snapshot_id")
        ):
            raise OperationRejected("extension method plan is not the current authenticated snapshot")
        canonical_plan = self._canonical_extension_method_plan(
            task_id=str(task_id), intent=intent, supplied=method_plan, snapshot=snapshot,
        )
        canonical_contract = canonical_plan.get("method_contract")
        contract_kind = canonical_contract.get("kind") if isinstance(canonical_contract, Mapping) else None
        canonical_kind = {
            "skill-resource-read": "skill-resource-reader",
            "mcp-tool": "plugin-mcp-client",
        }.get(contract_kind, "plugin-command-runner")
        if kind != canonical_kind:
            raise OperationRejected("registered extension executor does not match the authenticated method")

        if kind == "skill-resource-reader":
            dispatch = lambda: self._dispatch_bound_skill_resource(task_id, canonical_plan)
            prepare = lambda: dict(canonical_plan)

        # ``execute_operation`` persists the intent and records the
        # dispatch-start barrier before invoking this fixed consumer closure;
        # read Skill/private-Plugin execution and write/publication dispatch
        # retain their existing, distinct permission boundaries.
        # Re-check the immutable admission binding here as well as in the
        # preflight above: a queued operation must not consume a publication
        # snapshot that became invalid while it waited for its lane.
        consumer_dispatch = dispatch

        def dispatch_after_admission_check() -> OperationOutcome:
            try:
                current_task = self.get_task(str(task_id))
                if current_task.descriptor_ref and current_task.descriptor_hash:
                    try:
                        current_descriptor = self.context_memory.read(
                            str(current_task.descriptor_ref),
                            expected_hash=str(current_task.descriptor_hash),
                        )
                    except Exception as error:
                        raise OperationRejected(
                            "extension dispatch cannot read its admitted descriptor"
                        ) from error
                    current_binding = (
                        current_descriptor.get("capability_binding")
                        if isinstance(current_descriptor, Mapping)
                        else None
                    )
                    if isinstance(current_binding, Mapping):
                        admitted = authority.verify_capability_binding(current_binding)
                        authority.assert_publication_dispatch_allowed(current_binding)
                        if str(current_task.capability_snapshot_id or "") != str(admitted.get("snapshot_id") or ""):
                            raise OperationRejected(
                                "extension dispatch task is not bound to its admitted publication snapshot"
                            )
                        if any(
                            str(canonical_plan.get(key) or "") != str(admitted.get(key) or "")
                            for key in ("candidate_id", "snapshot_id", "snapshot_hash")
                        ):
                            raise OperationRejected(
                                "extension method plan differs from its admitted publication binding"
                            )
            except Exception as error:
                # This validation runs before the consumer closure.  Record a
                # known no-effect failure rather than allowing execute_operation
                # to classify it as UNKNOWN (which would incorrectly retain
                # effect responsibility).  Exceptions from consumer_dispatch
                # itself intentionally remain outside this block and preserve
                # the normal UNKNOWN/reconciliation rule.
                return OperationOutcome(
                    EffectStatus.FAILED,
                    {
                        "effect_dispatched": False,
                        "recovery_decision": "NO_EFFECT",
                        "reason": f"admission binding validation failed: {type(error).__name__}: {error}",
                    },
                )
            return consumer_dispatch()

        dispatch = dispatch_after_admission_check

        def prepare_consumer() -> Mapping[str, Any]:
            prepared = dict(prepare() if prepare is not None else canonical_plan)
            prepared.setdefault("method_plan", dict(canonical_plan))
            prepared["consumer_dispatch"] = kind
            prepared["method_plan_schema"] = "SITINA_EXTENSION_METHOD_PLAN_V1"
            return prepared

        self._active_extension_operations.add(str(intent.operation_id))
        try:
            return self.execute_operation(task_id, intent, dispatch, prepare=prepare_consumer)
        finally:
            self._active_extension_operations.discard(str(intent.operation_id))

    def _dispatch_bound_skill_resource(
        self, task_id: str, method_plan: Mapping[str, Any]
    ) -> OperationOutcome:
        authority = getattr(self, "_extension_authority", None)
        if authority is None:
            raise OperationRejected("Skill resource reader has no shared authority")
        snapshot = authority.build_execution_snapshot(str(method_plan.get("candidate_id") or "")).as_dict()
        contract = method_plan.get("method_contract")
        arguments = method_plan.get("arguments")
        if not isinstance(contract, Mapping) or not isinstance(arguments, Mapping):
            raise OperationRejected("Skill resource reader method plan is incomplete")
        skill = str(arguments.get("skill") or "")
        relative = Path(str(arguments.get("path") or ""))
        if skill != str(contract.get("skill") or "") or relative.is_absolute() or ".." in relative.parts:
            raise OperationRejected("Skill resource arguments are outside the authenticated method")
        expected_paths = tuple(str(item) for item in (contract.get("expected_paths") or ()))
        if expected_paths and relative.as_posix() not in expected_paths:
            raise OperationRejected("Skill resource path is not registered by the authenticated method")
        root = Path(str(snapshot.get("root") or "")).resolve(strict=True)
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
        raw = path.read_bytes()
        value = {
            "status": "ok",
            "skill": skill,
            "path": relative.as_posix(),
            "resource_path": str(path),
            "resource_sha256": hashlib.sha256(raw).hexdigest(),
            "content": raw.decode("utf-8", errors="replace"),
        }
        expected = method_plan.get("expected")
        if not isinstance(expected, Mapping) or expected.get("sha256") != value["resource_sha256"]:
            raise OperationRejected("Skill resource changed after the method plan")
        binding = {
            key: method_plan.get(key)
            for key in (
                "snapshot_id", "snapshot_hash", "candidate_id", "handler", "tool_name",
                "method_schema", "method_version", "method_id", "method_contract", "call_id",
            )
        }
        # Keep the fixed resource identity beside the private execution
        # binding so history projection can verify the business value without
        # exposing the full method plan, arguments, or CAS proof.
        binding["expected"] = dict(expected)
        return OperationOutcome(
            EffectStatus.SUCCEEDED,
            {
                "tool": str(method_plan.get("tool_name") or "sitina_read_skill_resource"),
                "arguments": dict(arguments),
                "permission": "read",
                "status": "ok",
                "value": value,
                "execution_binding": binding,
            },
        )

    def publish_extension_json(self, value: Mapping[str, Any], *, purpose: str) -> StoredContent:
        with self._state_lock:
            self._require_persistence()
            if purpose == "sitina-extension-consumer-receipt":
                raise OperationRejected(
                    "consumer receipts are Backend-owned; use record_extension_consumer_receipt"
                )
            try:
                stored = self.store.publish_json(value, purpose=purpose)
                return stored
            except BaseException as error:
                self._fail_persistence(error)
                raise

    def record_extension_consumer_receipt(
        self,
        *,
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, Any]:
        """Re-read one committed operation and issue its Backend-owned receipt.

        This compatibility surface accepts only task/operation identity.  It
        never accepts caller binding, value, or a success callback; the
        operation's persisted method plan and result are the sole inputs.
        Normal execution issues the receipt inside ``execute_operation``
        before its result event is appended.
        """

        with self._state_lock:
            task = self.get_task(str(task_id))
            operation = task.operations.get(str(operation_id))
            if operation is None or not operation.result_ref:
                raise OperationRejected("consumer receipt requires a committed operation result")
            intent = self.context_memory.read(str(operation.intent_ref)) if operation.intent_ref else {}
            evidence_ref = str(intent.get("effect_evidence_ref") or "")
            evidence = self.context_memory.read(evidence_ref) if evidence_ref else {}
            result_document = self.context_memory.read(str(operation.result_ref))
            result = dict(result_document.get("result") or {})
            binding = result.get("execution_binding")
            if not isinstance(binding, Mapping):
                raise OperationRejected("operation has no Backend consumer receipt")
            receipt_ref = str(binding.get("backend_receipt_ref") or "")
            receipt_hash = str(binding.get("backend_receipt_hash") or "")
            if not receipt_ref or not receipt_hash:
                raise OperationRejected("operation has no Backend consumer receipt")
            receipt = self.context_memory.read(receipt_ref, expected_hash=receipt_hash)
            if receipt.get("schema") != "SITINA_EXTENSION_CONSUMER_RECEIPT_V1":
                raise OperationRejected("existing consumer receipt schema is invalid")
            return dict(receipt)

    def _issue_extension_consumer_receipt_locked(
        self,
        task_id: str,
        intent: Mapping[str, Any],
        effect_evidence: Mapping[str, Any],
        outcome: OperationOutcome,
    ) -> StoredContent | None:
        """Issue a receipt only from Backend-owned prepared evidence/result."""

        plan = effect_evidence.get("method_plan") if isinstance(effect_evidence.get("method_plan"), Mapping) else effect_evidence
        if str(intent.get("operation_id") or "") not in self._active_extension_operations:
            return None
        if str(effect_evidence.get("consumer_dispatch") or "") not in {"skill-resource-reader", "plugin-command-runner", "plugin-mcp-client"}:
            return None
        if not isinstance(plan, Mapping) or plan.get("method_plan_schema") != "SITINA_EXTENSION_METHOD_PLAN_V1":
            return None
        binding = outcome.result.get("execution_binding")
        if outcome.status is not EffectStatus.SUCCEEDED or str(outcome.result.get("status") or "") != "ok" or not isinstance(binding, Mapping):
            return None
        required = ("candidate_id", "snapshot_hash", "handler", "method_schema", "method_version", "method_id")
        if any(not binding.get(key) for key in required):
            raise OperationRejected("extension result binding is incomplete")
        if str(plan.get("task_id") or "") != str(task_id) or str(plan.get("snapshot_id") or "") != str(self.get_task(task_id).capability_snapshot_id):
            raise OperationRejected("extension result is not bound to the admitted task snapshot")
        if any(binding.get(key) != plan.get(key) for key in ("candidate_id", "snapshot_hash", "handler", "method_schema", "method_version", "method_id")):
            raise OperationRejected("extension result binding differs from the persisted method plan")
        raw_value = json.dumps(outcome.result.get("value"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        receipt = {
            "schema": "SITINA_EXTENSION_CONSUMER_RECEIPT_V1",
            "task_id": str(task_id),
            "call_id": str(plan.get("call_id") or ""),
            "operation_id": str(intent.get("operation_id") or ""),
            "snapshot_id": str(plan.get("snapshot_id") or ""),
            "snapshot_hash": plan.get("snapshot_hash"),
            "candidate_id": plan.get("candidate_id"),
            "tool_name": plan.get("tool_name"),
            "handler": plan.get("handler"),
            "method_schema": plan.get("method_schema"),
            "method_version": plan.get("method_version"),
            "method_id": plan.get("method_id"),
            "method_contract": plan.get("method_contract"),
            "result_hash": hashlib.sha256(raw_value.encode("utf-8")).hexdigest(),
            "dispatch": "LoopBackend.execute_operation",
        }
        try:
            stored = self.store.publish_json(receipt, purpose="sitina-extension-consumer-receipt")
        except BaseException as error:
            self._fail_persistence(error)
            raise
        self._extension_receipt_proofs[stored.reference_id] = stored.proof
        return stored

    def coordinate_extension_trial_commit(self, commit: Callable[[], Any]) -> Any:
        """Linearize a verified extension trial against task control/input."""

        if not callable(commit):
            raise TypeError("extension trial commit must be callable")
        with self._state_lock:
            self._require_persistence()
            return commit()

    def coordinate_extension_publication_commit(self, commit: Callable[[], Any]) -> Any:
        """Linearize publication validation and its single Journal append."""

        if not callable(commit):
            raise TypeError("extension publication commit must be callable")
        with self._state_lock:
            self._require_persistence()
            return commit()

    def coordinate_extension_publication_check(self, commit: Callable[[], Any]) -> Any:
        """Linearize one publication-check fact against the extension Journal."""

        if not callable(commit):
            raise TypeError("extension publication check commit must be callable")
        with self._state_lock:
            self._require_persistence()
            return commit()

    def pending_publication_failure_obligations(self) -> tuple[Mapping[str, Any], ...]:
        """Return actionable extension failure obligations from the Journal.

        This is a read-only scheduling view.  The extension authority's
        projection is rebuilt/verified from its Journal and only pending
        conditional-default actions are returned; no task is reopened and no
        action is appended here.
        """

        authority = getattr(self, "_extension_authority", None)
        if authority is None:
            return ()
        with self._state_lock:
            self._require_persistence()
            projection = authority.load_projection()
            obligations = projection.get("obligations")
            if not isinstance(obligations, Mapping):
                raise OperationRejected("extension obligation projection is malformed")
            pending: list[dict[str, Any]] = []
            for raw_id, raw_obligation in obligations.items():
                if not isinstance(raw_obligation, Mapping):
                    raise OperationRejected("extension obligation entry is malformed")
                obligation = dict(raw_obligation)
                declared_id = str(obligation.get("obligation_id") or "")
                obligation_id = declared_id
                obligation_type = str(obligation.get("type") or "")
                if not obligation_id or not obligation_type:
                    raise OperationRejected("extension obligation identity/type is malformed")
                if obligation_type != "CONDITIONAL_DEFAULT_ACTION":
                    continue
                if not obligation_id or obligation_id != str(raw_id or ""):
                    raise OperationRejected("conditional default action obligation identity is malformed")
                # PENDING_REVIEW, missing state, and empty state are still
                # awaiting evidence/authority classification.  Only an
                # explicit reconciled PENDING state authorizes automation.
                if obligation.get("state") != "PENDING":
                    continue
                obligation["obligation_id"] = obligation_id
                pending.append(obligation)
            pending.sort(
                key=lambda item: (
                    int(item.get("stream_version") or 0),
                    str(item.get("event_id") or ""),
                    str(item.get("obligation_id") or ""),
                )
            )
            return tuple(pending)

    def process_publication_failure_obligation(
        self,
        obligation_id: str,
        request_id: str,
        *,
        lane_timeout: float | None = None,
    ) -> Mapping[str, Any]:
        """Settle one persisted extension failure obligation without a Task.

        The obligation itself is the durable authorization.  A stable owner
        and operation identity acquire the existing BusinessModificationLane;
        only after that wait does the short Backend coordination region read
        the authoritative obligation/default projection and append one
        Journal decision.  No Provider, candidate copy, or external effect is
        dispatched here.
        """

        obligation_id = str(obligation_id or "")
        request_id = str(request_id or "")
        if not obligation_id or not request_id:
            raise OperationRejected("failure obligation and request_id are required")
        if lane_timeout is not None:
            lane_timeout = float(lane_timeout)
            if not math.isfinite(lane_timeout) or lane_timeout < 0:
                raise OperationRejected("failure obligation lane_timeout must be finite and non-negative")
        authority = getattr(self, "_extension_authority", None)
        if authority is None:
            raise OperationRejected("extension failure action has no shared authority")
        owner_id = f"extension-obligation:{obligation_id}"
        operation_id = f"extension-failure-action:{obligation_id}"
        # Exact request replay and an already-settled obligation are read-only
        # outcomes.  Resolve them before waiting on the lane so a later
        # retained resource or unknown lane owner cannot block a replay.
        with self._state_lock:
            self._require_persistence()
            existing = authority._existing_request(request_id)
            prior = authority._publication_failure_action_event_for_obligation(obligation_id)
            if existing is not None or prior is not None:
                return authority._process_publication_failure_obligation_locked(
                    obligation_id,
                    request_id,
                    owner_id=owner_id,
                    operation_id=operation_id,
                )
        self.operations.acquire(owner_id, operation_id, timeout=lane_timeout)
        try:
            with self._state_lock:
                self._require_persistence()
                existing_after_lane = authority._existing_request(request_id)
                prior_after_lane = authority._publication_failure_action_event_for_obligation(obligation_id)
                if existing_after_lane is not None or prior_after_lane is not None:
                    return authority._process_publication_failure_obligation_locked(
                        obligation_id,
                        request_id,
                        owner_id=owner_id,
                        operation_id=operation_id,
                    )
                # Reuse the Backend's canonical retained-resource check.  The
                # stable obligation owner is not a fake Task and therefore
                # cannot accidentally exclude a real task from the scan.
                self._assert_resources_available(
                    owner_id,
                    (str(Path(authority.extension_root).expanduser().resolve(strict=False)),),
                )
                return authority._process_publication_failure_obligation_locked(
                    obligation_id,
                    request_id,
                    owner_id=owner_id,
                    operation_id=operation_id,
                )
        finally:
            self.operations.release(owner_id, operation_id)

    def record_extension_publication_check_from_task(
        self,
        task_id: str,
        operation_id: str | None = None,
    ) -> Mapping[str, Any] | None:
        """Reconstruct and settle a publication check from durable task facts.

        The caller supplies only task/optional operation identity.  The
        descriptor binding, method plan, operation result, and Backend receipt
        are read from the same opened store; no Provider result or current
        default is accepted.  A task without a selected capability or a
        non-consumer operation is simply not a C3a check source.
        """

        with self._state_lock:
            self._require_persistence()
            authority = getattr(self, "_extension_authority", None)
            if authority is None:
                return None
            task = self.get_task(str(task_id))
            if not task.descriptor_ref or not task.descriptor_hash:
                return None
            try:
                descriptor = self.context_memory.read(
                    str(task.descriptor_ref), expected_hash=str(task.descriptor_hash)
                )
            except Exception:
                return None
            binding = descriptor.get("capability_binding") if isinstance(descriptor, Mapping) else None
            if not isinstance(binding, Mapping):
                return None
            publication_id = str(binding.get("publication_id") or "")
            if not publication_id:
                return None
            publication_event = next(
                (
                    event for event in authority._journal_events()
                    if event.event_type == "extension.publication-committed"
                    and str(event.payload.get("publication_id") or "") == publication_id
                ),
                None,
            )
            if publication_event is None:
                return None
            obligation = dict(publication_event.payload.get("check_obligation") or {})
            obligation_id = str(obligation.get("obligation_id") or "")
            if not obligation_id:
                return None
            prior = authority.publication_check_event_for_obligation(obligation_id)
            if prior is not None:
                return {
                    "status": "passed",
                    "replayed": True,
                    "obligation_id": obligation_id,
                    "publication_id": publication_id,
                    "event_id": prior.event_id,
                    "operation_id": str(prior.payload.get("operation", {}).get("operation_id") or ""),
                }

            candidate_ids = (
                [str(operation_id)]
                if operation_id is not None
                else [str(item) for item in task.operations]
            )
            from sitina.extensions.authority import PublicationCheckNotApplicable
            for candidate_operation_id in candidate_ids:
                operation = task.operations.get(candidate_operation_id)
                if operation is None or operation.unknown_effect or operation.effect_status is not EffectStatus.SUCCEEDED:
                    continue
                if not operation.intent_ref or not operation.result_ref:
                    continue
                try:
                    intent = self.context_memory.read(str(operation.intent_ref))
                    evidence_ref = str(intent.get("effect_evidence_ref") or "")
                    evidence = self.context_memory.read(evidence_ref) if evidence_ref else {}
                except Exception:
                    continue
                method_plan = evidence.get("method_plan") if isinstance(evidence, Mapping) else None
                method_contract = method_plan.get("method_contract") if isinstance(method_plan, Mapping) else None
                consumer_dispatch = str(evidence.get("consumer_dispatch") or "") if isinstance(evidence, Mapping) else ""
                if consumer_dispatch not in {"skill-resource-reader", "plugin-command-runner", "plugin-mcp-client"} and not (
                    isinstance(method_contract, Mapping)
                    and str(method_contract.get("kind") or "") in {"skill-resource-read", "plugin-command", "mcp-tool"}
                ):
                    continue
                request_id = f"publication-check:{obligation_id}:{task_id}:{candidate_operation_id}"
                try:
                    event = authority.record_publication_check({
                        "request_id": request_id,
                        "obligation_id": obligation_id,
                        "task_id": str(task_id),
                        "operation_id": candidate_operation_id,
                        "required_publication_id": str(obligation.get("required_publication_id") or publication_id),
                        "required_snapshot_id": str(obligation.get("required_snapshot_id") or binding.get("snapshot_id") or ""),
                        "capability_binding": dict(binding),
                    })
                except PublicationCheckNotApplicable:
                    # A valid consumer operation with different bounded input
                    # is not this publication's check; continue scanning for
                    # a later matching operation from the same task.
                    continue
                return {
                    "status": "passed",
                    "replayed": str(event.payload.get("request_id") or "") != request_id,
                    "obligation_id": obligation_id,
                    "publication_id": publication_id,
                    "event_id": event.event_id,
                    "operation_id": str(event.payload.get("operation", {}).get("operation_id") or candidate_operation_id),
                }
            return None

    def record_extension_publication_failure_from_task(
        self,
        task_id: str,
        operation_id: str | None = None,
    ) -> Mapping[str, Any] | None:
        """Reconstruct a fixed-consumer failure from durable task evidence.

        Only task/operation identity enters this boundary.  The authority
        rereads the immutable capability binding, registered method/input,
        operation result, and (for controlled Plugin runs) the private
        CommandRunner completion protocol.  No caller-supplied failure kind,
        read position, ``confirmed`` flag, or result body is accepted.
        """

        with self._state_lock:
            self._require_persistence()
            authority = getattr(self, "_extension_authority", None)
            if authority is None:
                return None
            task = self.get_task(str(task_id))
            if not task.descriptor_ref or not task.descriptor_hash:
                return None
            try:
                descriptor = self.context_memory.read(
                    str(task.descriptor_ref), expected_hash=str(task.descriptor_hash)
                )
            except Exception:
                return None
            binding = descriptor.get("capability_binding") if isinstance(descriptor, Mapping) else None
            if not isinstance(binding, Mapping) or not str(binding.get("publication_id") or ""):
                return None
            candidates = (
                [str(operation_id)]
                if operation_id is not None
                else list(reversed(tuple(str(item) for item in task.operations)))
            )
            pending_event = None
            for candidate_operation_id in candidates:
                if candidate_operation_id not in task.operations:
                    continue
                # The authority distinguishes non-consumer/non-applicable
                # operations by returning None or a PENDING_REVIEW event.
                # Persistence/CAS/Journal errors deliberately propagate so
                # Host recovery health can surface them.
                request_was_already_recorded = authority._existing_request(
                    f"publication-failure:{task_id}:{candidate_operation_id}"
                ) is not None
                event = authority.record_publication_failure_from_task(
                    str(task_id), candidate_operation_id
                )
                if event is not None:
                    if event.event_type == "extension.publication-failure-reconciled":
                        return {
                            "status": "isolated",
                            "event_id": event.event_id,
                            "publication_id": event.payload.get("failed_publication", {}).get("publication_id")
                            if isinstance(event.payload.get("failed_publication"), Mapping)
                            else None,
                            "operation_id": candidate_operation_id,
                            "replayed": request_was_already_recorded,
                        }
                    if pending_event is None:
                        pending_event = (event, candidate_operation_id)
            if pending_event is None:
                return None
            event, candidate_operation_id = pending_event
            return {
                "status": "pending_review",
                "event_id": event.event_id,
                "publication_id": event.payload.get("source", {}).get("publication_id")
                if isinstance(event.payload.get("source"), Mapping)
                else None,
                "operation_id": candidate_operation_id,
                "replayed": bool(event.payload.get("replayed")),
            }

    def append_extension_event(
        self,
        command: Any,
        expected_stream_version: int,
        event: EventEnvelope,
        proof: Any,
        additional_proofs: Sequence[Any] = (),
    ) -> Any:
        with self._state_lock:
            self._require_persistence()
            try:
                return self.store.journal.append(
                    command,
                    expected_stream_version,
                    [event],
                    object_reference_proofs=(proof, *tuple(additional_proofs)),
                )
            except ExpectedStreamVersionConflict:
                raise
            except BaseException as error:
                self._fail_persistence(error)
                raise

    def extension_events(self, stream_id: str) -> tuple[EventEnvelope, ...]:
        self._require_persistence()
        return tuple(event for event in self.store.journal.iter_events(0) if event.stream_id == stream_id)

    def read_extension_json(self, reference_id: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        self._require_persistence()
        return self.store.read_json(reference_id, expected_hash=expected_hash)

    def extension_existing_object_proof(self, reference_id: str) -> Any:
        """Return a durable Journal-root proof for an already committed CAS object."""

        self._require_persistence()
        journal = self.store.journal
        position = int(journal.head_position)
        commitment = journal._position_hash[position] if position else "0" * 64
        frontier = FrontierRef(journal.journal_id, journal.epoch, "local", position, commitment)
        object_ref = self.store.cas.resolve_reference(str(reference_id))
        return journal.lookup_existing_object_root_proof(object_ref, frontier)

    def configure_resource_monitoring(
        self, resource_limits: Mapping[str, Any], observability_policy: Mapping[str, Any],
    ) -> None:
        """Bind the native Host policy and replay facts through its sole Journal."""
        from sitina.orchestrator.observability_management import AlertEngine, ObservabilityPolicy

        policy = ObservabilityPolicy(observability_policy)
        limits = dict(resource_limits)
        for name in (
            "global", "per_run", "per_provider", "per_tool", "queue_capacity",
            "tool_calls_per_turn", "operation_output_bytes", "monitor_window_seconds",
            "monitor_max_samples", "monitor_notification_limit",
        ):
            if type(limits.get(name)) is not int or not 0 < limits[name] <= 16_777_216:
                raise ValueError(f"invalid native resource limit: {name}")
        for name in ("token_baseline_per_request", "cost_baseline_microusd"):
            if limits.get(name) is not None and (
                type(limits[name]) is not int or limits[name] <= 0
            ):
                raise ValueError(f"invalid observation baseline: {name}")
        if limits["monitor_max_samples"] > 256 or limits["monitor_notification_limit"] > 64:
            raise ValueError("native monitoring projection exceeds its bounded window")
        with self._state_lock:
            self._require_persistence()
            self._resource_limits = limits
            self._monitor_alerts = AlertEngine(policy.value["alerts"])
            self._monitor_error_budget = int(policy.value["alerts"].get("error_budget_ppm", 10_000))
            if not 0 < self._monitor_error_budget <= 1_000_000:
                raise ValueError("SLO error budget must be within 1..1000000 ppm")
            self._monitor_state = {
                "source_position": 0, "samples": [], "alerts": {"active": {}, "last_emitted": {}},
                "notifications": [], "queue_depth": 0, "metrics": {},
            }
            self._monitor_version = 0
            frontier = 0
            for event in self.store.journal.iter_events(0):
                frontier = event.position
                if event.stream_id == "loop-host/observability":
                    self._monitor_state = copy.deepcopy(dict(event.payload["state"]))
                    self._monitor_version = event.stream_version
            # A crash between a task commit and its derived observation is
            # repaired from the task fact. It never redispatches the operation.
            for event in self.store.journal.iter_events(self._monitor_state["source_position"]):
                if event.position > frontier:
                    break
                if event.stream_id.startswith("loop-task/"):
                    self._monitor_task_event(event)

    def monitoring_status(self, *, include_samples: bool = False) -> Mapping[str, Any]:
        with self._state_lock:
            if self._resource_limits is None:
                return {"enabled": False}
            state = copy.deepcopy(self._monitor_state)
            if not include_samples:
                state.pop("samples", None)
            return {
                "enabled": True, "authority": "native-loop-journal",
                "stream_id": "loop-host/observability", "stream_version": self._monitor_version,
                "limits": dict(self._resource_limits), **state,
            }

    def observe_host_resources(self, *, queue_depth: int, rejected: bool = False) -> None:
        """Called by actual Host queue transitions; it cannot settle a task."""
        if self._resource_limits is None:
            return
        if type(queue_depth) is not int or queue_depth < 0:
            raise ValueError("invalid observed queue depth")
        with self._state_lock:
            self._monitor_apply(
                fact=({"resource_rejected": 1, "error": 1, "kind": "queue_admission"}
                      if rejected else None),
                queue_depth=queue_depth,
            )

    def _monitor_task_event(self, event: EventEnvelope) -> None:
        if self._resource_limits is None or event.position <= self._monitor_state["source_position"]:
            return
        fact: dict[str, Any] | None = None
        task_id = str(event.payload.get("task_id") or "")
        if event.event_type == "loop.operation-result-recorded":
            operation_id = str(event.payload["operation_id"])
            document = self.store.read_json(
                str(event.payload["result_ref"]), expected_hash=str(event.payload["result_hash"]),
            )
            operation = self.get_task(task_id).operations[operation_id]
            telemetry = operation_agent_telemetry(
                task_id=task_id, operation_id=operation_id,
                logical_operation_id=operation.logical_operation_id,
                result_status=str(event.payload["effect_status"]),
                result_ref=str(event.payload["result_ref"]), result_document=document,
            )
            result = document["result"]
            metadata = result.get("metadata")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            failure = result.get("provider_failure")
            failure = failure if isinstance(failure, Mapping) else {}
            reported = telemetry["reported"]
            usage = reported["token_usage"]
            tokens = usage.get("total_tokens")
            # A reported token/cost field is an observation, not an estimate.
            raw_cost = metadata.get("cost_microusd")
            cost = raw_cost if type(raw_cost) is int and raw_cost >= 0 else None
            exception_type = str(failure.get("exception_type") or result.get("exception_type") or "")
            command = result.get("value")
            command = command if isinstance(command, Mapping) else result
            timeout = (
                command.get("timed_out") is True
                or command.get("program_status") == "TIMED_OUT"
                or command.get("completion_status") == "TIMED_OUT"
                or exception_type in {"TimeoutError", "ReadTimeout", "ConnectTimeout", "TimeoutException",
                                      "ProviderReadTimeout", "ProviderConnectTimeout", "ProviderDeadlineExceeded"}
            )
            cancel_failed = (
                command.get("cancel_failed") is True
                or command.get("cancel_status") in {"FAILED", "UNKNOWN"}
            )
            fact = {
                "task_id": task_id, "operation_id": operation_id,
                "source_position": event.position,
                "kind": telemetry["kind"],
                "error": int(event.payload["effect_status"] != "SUCCEEDED"
                             or result.get("status") == "error"
                             or command.get("program_status") == "FAIL"),
                "timeout": int(timeout), "cancel_failure": int(cancel_failed),
                "retry": reported["retry_count"],
                "unknown_effect": int(event.payload.get("unknown_effect") is True),
                "tokens": tokens, "cost_microusd": cost,
                "usage_unknown": int(telemetry["kind"] == "provider" and (tokens is None or cost is None)),
                "limit": result.get("resource_limit"),
                "resource_rejected": int(result.get("resource_limit") is not None
                                         or command.get("stdout_truncated") is True
                                         or command.get("stderr_truncated") is True),
            }
        elif event.event_type == "loop.task-recovery-blocked":
            report = self.store.read_json(
                str(event.payload["stop_report_ref"]), expected_hash=str(event.payload["stop_report_hash"]),
            )
            if report.get("reason_code") == "CANCEL_WITH_UNKNOWN_EFFECT":
                fact = {"task_id": task_id, "source_position": event.position,
                        "kind": "cancellation", "cancel_failure": 1}
        if fact is not None:
            self._monitor_apply(fact=fact, source_position=event.position)

    def _monitor_apply(
        self, *, fact: Mapping[str, Any] | None = None,
        source_position: int | None = None, queue_depth: int | None = None,
    ) -> None:
        from sitina.orchestrator.observability_management import AlertSignalSnapshot, AlertState

        self._require_persistence()
        assert self._resource_limits is not None
        previous = self._monitor_state
        current = copy.deepcopy(previous)
        now = int(time.time())
        window = self._resource_limits["monitor_window_seconds"]
        samples = [s for s in current["samples"] if now - int(s["observed_at_epoch"]) < window]
        if fact is not None:
            samples.append({**dict(fact), "observed_at_epoch": now})
        samples = samples[-self._resource_limits["monitor_max_samples"]:]
        current["samples"] = samples
        if source_position is not None:
            current["source_position"] = source_position
        if queue_depth is not None:
            current["queue_depth"] = queue_depth
        def count(key: str, values: Sequence[Mapping[str, Any]] = samples) -> int:
            return sum(value[key] for value in values if type(value.get(key)) is int)
        def ratio(key: str, baseline_key: str) -> int | None:
            baseline = self._resource_limits.get(baseline_key)
            known = [s[key] for s in samples if type(s.get(key)) is int]
            if not known or baseline is None:
                return None
            return max(known) * 1_000_000 // baseline
        def burn(values: Sequence[Mapping[str, Any]]) -> int:
            return (count("error", values) * 1_000_000_000_000
                    // (len(values) * self._monitor_error_budget)) if values else 0
        unresolved = sum(
            len(task.unresolved_effects) for task in self._task_cache.values()
        )
        fast = [s for s in samples if now - s["observed_at_epoch"] < min(60, window)]
        provider_samples = [s for s in samples if s.get("kind") == "provider"]
        retry_unknown = sum(s.get("retry") is None for s in provider_samples)
        metrics = {
            "sample_count": len(samples), "error_count": count("error"),
            "timeout_count": count("timeout"),
            "retry_count": None if retry_unknown else count("retry"),
            "retry_known_count": count("retry"), "retry_unknown_count": retry_unknown,
            "token_unknown_count": sum(s.get("tokens") is None for s in provider_samples),
            "cost_unknown_count": sum(s.get("cost_microusd") is None for s in provider_samples),
            "cancel_failure_count": count("cancel_failure"), "unknown_effect_count": unresolved,
            "resource_rejection_count": count("resource_rejected"),
            "usage_unknown_count": count("usage_unknown"), "queue_depth": current["queue_depth"],
            "token_ratio_ppm": ratio("tokens", "token_baseline_per_request"),
            "cost_ratio_ppm": ratio("cost_microusd", "cost_baseline_microusd"),
        }
        signals = AlertSignalSnapshot(
            fast_burn_rate_ppm=burn(fast), slow_burn_rate_ppm=burn(samples),
            repeated_failures=count("error"), queue_depth=current["queue_depth"],
            token_ratio_ppm=metrics["token_ratio_ppm"], cost_ratio_ppm=metrics["cost_ratio_ppm"],
            timeouts=metrics["timeout_count"], retries=metrics["retry_known_count"],
            cancel_failures=metrics["cancel_failure_count"], unknown_effects=unresolved,
            resource_rejections=metrics["resource_rejection_count"],
            usage_unknown=metrics["usage_unknown_count"],
        )
        evaluated = self._monitor_alerts.evaluate(
            signals, state=AlertState.model_validate(current["alerts"]), now_epoch=now,
        )
        current["alerts"] = evaluated.state.model_dump()
        current["metrics"] = metrics
        current["notifications"] = (
            current["notifications"] + [n.model_dump() for n in evaluated.notifications]
        )[-self._resource_limits["monitor_notification_limit"]:]
        # Stable active-alert timestamps are not a reason to append every poll.
        same_active = set(current["alerts"]["active"]) == set(previous["alerts"]["active"])
        if fact is None and same_active and not evaluated.notifications:
            current["alerts"]["active"] = previous["alerts"]["active"]
        if current == previous:
            return
        stream = "loop-host/observability"
        request = f"native-monitor:{self.run_instance_id}:{self._monitor_version + 1}"
        timestamp = iso_now()
        payload = {"spec_version": SPEC_VERSION, "state": current}
        command = CommandEnvelope(
            "loop-monitor-command-" + hashlib.sha256(request.encode()).hexdigest()[:40],
            self.store.TENANT, stream, "loop.host.observe", "loop-state-coordinator",
            timestamp, {"request_id": request},
        )
        event = EventEnvelope(
            "loop-monitor-event-" + hashlib.sha256(request.encode()).hexdigest()[:40],
            "loop.host-observed", self.store.TENANT, stream, 0, 0, timestamp, payload, (),
        )
        try:
            self.store.journal.append(command, self._monitor_version, [event])
        except BaseException as error:
            self._fail_persistence(error)
            raise
        self._monitor_version += 1
        self._monitor_state = current

    def _admit_operation_resources(self, task: TaskProjection, intent: OperationIntent) -> None:
        if self._resource_limits is None:
            return
        if any(item.get("execution_mode") == "task" for item in task.child_delegations.values()):
            # Team capacity follows actual host/provider pressure, never a
            # fixed per-run/per-provider slot count. Output bounds still apply.
            return
        limits = self._resource_limits
        active = [
            (owner.task_id, operation)
            for owner in self._task_cache.values()
            for operation in owner.operations.values()
            if operation.result_ref is None or operation.unknown_effect
        ]
        provider = intent.operation_id.startswith(("provider-", "child-provider-"))
        category = "per_provider" if provider else "per_tool"
        same_category = sum(
            op.operation_id.startswith(("provider-", "child-provider-")) == provider for _, op in active
        )
        reason = None
        if len(active) >= limits["global"]:
            reason = "global"
        elif sum(owner == task.task_id for owner, _ in active) >= limits["per_run"]:
            reason = "per_run"
        elif same_category >= limits[category]:
            reason = category
        if reason is not None:
            self._monitor_apply(fact={
                "task_id": task.task_id, "kind": "operation_admission",
                "resource_rejected": 1, "error": 1, "limit": reason,
            })
            raise OperationRejected(f"native resource limit {reason}; operation was not dispatched")

    def _bound_operation_result(self, outcome: OperationOutcome) -> OperationOutcome:
        if self._resource_limits is None:
            return outcome
        result = dict(outcome.result)
        calls = result.get("tool_calls")
        reason = None
        if isinstance(calls, list) and len(calls) > self._resource_limits["tool_calls_per_turn"]:
            reason = "tool_calls_per_turn"
        raw = canonical_json_bytes(result)
        if len(raw) > self._resource_limits["operation_output_bytes"]:
            reason = "operation_output_bytes"
        if reason is None:
            return outcome
        # The effect already happened. Preserve its truth and identity, but
        # never publish oversized content or execute its requested tools.
        bounded = {
            "resource_limit": reason, "result_discarded": True,
            "original_effect_status": outcome.status.value,
            "result_bytes": len(raw), "result_sha256": hashlib.sha256(raw).hexdigest(),
            "tool_call_count": len(calls) if isinstance(calls, list) else None,
            "recovery_decision": "NO_RETRY" if outcome.status is EffectStatus.UNKNOWN else "RETAIN_COMPLETED_EFFECT",
        }
        for key in ("schema", "task_id", "delegation_id", "turn", "turn_index", "work_purpose"):
            value = result.get(key)
            if type(value) is int or (isinstance(value, str) and len(value) <= 256):
                bounded[key] = value
        # Retain the authenticated completion facts even when its payload is
        # discarded. A completed timeout must not become an unknown effect.
        for key in ("tool", "status", "program_status", "completion_status", "timed_out",
                    "cancel_failed", "cancel_status", "execution_started", "effect_settled",
                    "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated"):
            value = result.get(key)
            if type(value) in {bool, int} or (isinstance(value, str) and len(value) <= 128):
                bounded[key] = value
        metadata = result.get("metadata")
        if isinstance(metadata, Mapping):
            bounded["metadata"] = {
                key: value for key, value in metadata.items()
                if key in {"duration_ms", "cost_microusd", "retry_count", "fallback_count",
                           "physical_send_count", "uncertain_physical_send_attempt_count"}
                and type(value) is int and value >= 0
            }
            usage = metadata.get("token_usage")
            if isinstance(usage, Mapping):
                bounded["metadata"]["token_usage"] = {
                    key: value for key, value in usage.items()
                    if key in {"input_tokens", "output_tokens", "total_tokens", "prompt_tokens", "completion_tokens"}
                    and type(value) is int and value >= 0
                }
        return OperationOutcome(outcome.status, bounded)

    def _append(self, **kwargs: Any) -> EventEnvelope:
        self._require_persistence()
        try:
            event = self.store.conditional_append(**kwargs)
            self._advance_task_cache(event)
            self._monitor_task_event(event)
            return event
        except ExpectedStreamVersionConflict:
            raise
        except BaseException as error:
            self._fail_persistence(error)
            raise

    def create_task(
        self,
        *,
        task_id: str,
        session_id: str,
        task_kind: str,
        goal: str,
        required_outcome_ids: tuple[str, ...],
        artifact_ref: str,
        environment_ref: str,
        capability_snapshot_id: str,
        request_id: str | None = None,
        artifact_content: StoredContent | None = None,
        submission_id: str | None = None,
        request_fingerprint: str | None = None,
        request_content: StoredContent | None = None,
        descriptor_content: StoredContent | None = None,
        goal_content: StoredContent | None = None,
        memory_view: Mapping[str, Any] | None = None,
    ) -> TaskProjection:
        with self._state_lock:
            self._require_persistence()
            requested_memory_view_hash: str | None = None
            if memory_view is not None:
                if not isinstance(memory_view, Mapping):
                    raise ValueError("memory view must be a mapping")
                view_ids = tuple(sorted({str(item) for item in memory_view.get("selected_memory_ids", ())}))
                view_versions = memory_view.get("selected_memory_versions", {})
                if not isinstance(view_versions, Mapping):
                    raise ValueError("memory view versions must be a mapping")
                view_version_items = tuple(sorted((str(key), int(value)) for key, value in view_versions.items()))
                view_reasons = tuple(str(item) for item in memory_view.get("selection_reasons", ()))
                view_entries = memory_view.get("entries", [])
                if not isinstance(view_entries, list) or len(view_entries) > 64 or any(not isinstance(item, Mapping) for item in view_entries):
                    raise ValueError("memory view entries must be a bounded list of mappings")
                if any(not item for item in view_ids) or any(version < 1 for _, version in view_version_items):
                    raise ValueError("memory view binding is malformed")
                requested_memory_view_hash = hashlib.sha256(canonical_json_bytes({
                    "schema": "SITINA_LOOP_MEMORY_VIEW_V1",
                    "task_id": task_id,
                    "selected_memory_ids": list(view_ids),
                    "selected_memory_versions": {key: version for key, version in view_version_items},
                    "selection_reasons": list(view_reasons),
                    "source_frontier": memory_view.get("source_frontier"),
                    "entries": [dict(item) for item in view_entries],
                })).hexdigest()
            events = self.store.task_events(task_id)
            if events:
                task = self._project(task_id, events)
                created = events[0].payload
                requested_goal_hash = hashlib.sha256(
                    canonical_json_bytes(
                        {"schema": "SITINA_LOOP_GOAL_V1", "task_id": task_id, "goal": goal}
                    )
                ).hexdigest()
                self.context_memory.read(
                    str(created["goal_ref"]),
                    expected_hash=str(created["goal_hash"]),
                )
                expected = {
                    "session_id": session_id,
                    "task_kind": task_kind,
                    "artifact_ref": artifact_ref,
                    "environment_ref": environment_ref,
                    "capability_snapshot_id": capability_snapshot_id,
                    "required_outcome_ids": tuple(sorted(required_outcome_ids)),
                    "initial_goal_hash": requested_goal_hash,
                    "memory_view_hash": requested_memory_view_hash,
                }
                actual = {
                    "session_id": task.session_id,
                    "task_kind": task.task_kind,
                    "artifact_ref": task.artifact_ref,
                    "environment_ref": task.environment_ref,
                    "capability_snapshot_id": task.capability_snapshot_id,
                    "required_outcome_ids": task.required_outcome_ids,
                    "initial_goal_hash": str(created["goal_hash"]),
                    "memory_view_hash": str(created.get("memory_view_hash")) if created.get("memory_view_hash") else None,
                }
                if expected != actual:
                    raise TaskConflict("task identity is already bound to different creation fields")
                if request_fingerprint is not None and (
                    str(created.get("request_fingerprint") or "") != request_fingerprint
                    or str(created.get("submission_id") or "") != str(submission_id or "")
                ):
                    raise TaskConflict("task identity is already bound to different submission intent")
                return self._effective_recovery_view(task)
            if not all(str(value).strip() for value in (
                task_id,
                session_id,
                task_kind,
                goal,
                artifact_ref,
                environment_ref,
                capability_snapshot_id,
            )):
                raise ValueError("task creation fields must be non-empty")
            outcomes = tuple(sorted(set(required_outcome_ids)))
            if outcomes != required_outcome_ids:
                raise ValueError("required outcome IDs must be sorted and unique")
            try:
                if artifact_content is not None and artifact_content.reference_id != artifact_ref:
                    raise ValueError("artifact content proof does not match the task artifact ref")
                if goal_content is None:
                    goal_content = self.context_memory.persist(
                        {"schema": "SITINA_LOOP_GOAL_V1", "task_id": task_id, "goal": goal},
                        purpose="loop-task-goal",
                    )
                else:
                    recorded_goal = self.context_memory.read(
                        goal_content.reference_id, expected_hash=goal_content.content_hash
                    )
                    if recorded_goal.get("schema") != "SITINA_LOOP_GOAL_V1" or recorded_goal.get("goal") != goal:
                        raise ValueError("goal content proof does not match the task goal")
                memory_view_content: StoredContent | None = None
                if memory_view is not None:
                    if not isinstance(memory_view, Mapping):
                        raise ValueError("memory view must be a mapping")
                    selected_ids = tuple(sorted({str(item) for item in memory_view.get("selected_memory_ids", ())}))
                    selected_versions = memory_view.get("selected_memory_versions", {})
                    if not isinstance(selected_versions, Mapping):
                        raise ValueError("memory view versions must be a mapping")
                    version_items = tuple(sorted((str(key), int(value)) for key, value in selected_versions.items()))
                    reasons = tuple(str(item) for item in memory_view.get("selection_reasons", ()))
                    entries = memory_view.get("entries", [])
                    if not isinstance(entries, list) or len(entries) > 64 or any(not isinstance(item, Mapping) for item in entries):
                        raise ValueError("memory view entries must be a bounded list of mappings")
                    if any(not item for item in selected_ids) or any(version < 1 for _, version in version_items):
                        raise ValueError("memory view binding is malformed")
                    view_document = {
                        "schema": "SITINA_LOOP_MEMORY_VIEW_V1",
                        "task_id": task_id,
                        "selected_memory_ids": list(selected_ids),
                        "selected_memory_versions": {key: version for key, version in version_items},
                        "selection_reasons": list(reasons),
                        "source_frontier": memory_view.get("source_frontier"),
                        "entries": [dict(item) for item in entries],
                    }
                    if len(canonical_json_bytes(view_document)) > 32 * 1024:
                        raise ValueError("memory view exceeds its bounded CAS budget")
                    memory_view_content = self.context_memory.persist(
                        view_document,
                        purpose="loop-task-memory-view",
                    )
            except BaseException as error:
                self._fail_persistence(error)
                raise
            self._append(
                task_id=task_id,
                expected_stream_version=0,
                request_id=request_id or f"task-create:{task_id}",
                command_type="loop.task.create",
                event_type="loop.task-created",
                payload={
                    "schema": "SITINA_LOOP_TASK_CREATED_V1",
                    "task_id": task_id,
                    "session_id": session_id,
                    "task_kind": task_kind,
                    "run_instance_id": self.run_instance_id,
                    "execution_epoch": 1,
                    "goal_version": 1,
                    "acceptance_version": 1,
                    "criteria_lineage_version": 1,
                    "artifact_version": 1,
                    "artifact_ref": artifact_ref,
                    **(
                        {"artifact_hash": artifact_content.content_hash}
                        if artifact_content is not None
                        else {}
                    ),
                    "environment_ref": environment_ref,
                    "capability_snapshot_id": capability_snapshot_id,
                    "received_input_seq": 0,
                    "handled_input_seq": 0,
                    "control_intent": ControlIntent.RUN.value,
                    "status": TaskStatus.RUNNABLE.value,
                    "required_outcome_ids": list(outcomes),
                    "goal_ref": goal_content.reference_id,
                    "goal_hash": goal_content.content_hash,
                    "recovery_state": "READY_NEW_TASK",
                    **({"submission_id": str(submission_id)} if submission_id is not None else {}),
                    **({"request_fingerprint": request_fingerprint} if request_fingerprint is not None else {}),
                    **(
                        {
                            "request_ref": request_content.reference_id,
                            "request_hash": request_content.content_hash,
                        }
                        if request_content is not None
                        else {}
                    ),
                    **(
                        {
                            "descriptor_ref": descriptor_content.reference_id,
                            "descriptor_hash": descriptor_content.content_hash,
                        }
                        if descriptor_content is not None
                        else {}
                    ),
                    **(
                        {
                            "memory_view_ref": memory_view_content.reference_id,
                            "memory_view_hash": memory_view_content.content_hash,
                        }
                        if memory_view_content is not None
                        else {}
                    ),
                },
                proofs=(
                    goal_content.proof,
                    *((artifact_content.proof,) if artifact_content is not None else ()),
                    *((request_content.proof,) if request_content is not None else ()),
                    *((descriptor_content.proof,) if descriptor_content is not None else ()),
                    *((memory_view_content.proof,) if memory_view_content is not None else ()),
                ),
            )
            return self.get_task(task_id)

    def admit_task(
        self,
        *,
        task_id: str,
        session_id: str,
        task_kind: str,
        goal: str,
        workspace_path: str,
        check_command: tuple[str, ...] = (),
        provider_profile: str = "",
        reviewer_request_timeout_seconds: float | str | None = None,
        approve_writes: bool = False,
        network_read_urls: tuple[str, ...] = (),
        public_web_read: bool = False,
        authorization: str = "",
        submission_id: str | None = None,
        environment_selection: str = "",
        capability_selection: str = "",
        environment_ref: str | None = None,
        capability_snapshot_id: str | None = None,
        provider_identity: str = "",
        software_identity: str = "",
        config_identity: str = "",
        protocol_versions: Mapping[str, str] | None = None,
        required_outcome_ids: tuple[str, ...] = ("outcome-1",),
        capability_binding: Mapping[str, Any] | None = None,
        memory_view: Mapping[str, Any] | None = None,
    ) -> tuple[TaskProjection, bool]:
        """Atomically admit a stable submission intent or return its original task.

        The duplicate path reads only the committed task-created event and its
        linked descriptor.  It never re-captures the workspace or creates a new
        CAS candidate.
        """

        intent = build_submission_intent(
            task_id=task_id,
            submission_id=submission_id,
            task_kind=task_kind,
            goal=goal,
            workspace_path=workspace_path,
            check_command=check_command,
            provider_profile=provider_profile,
            reviewer_request_timeout_seconds=reviewer_request_timeout_seconds,
            approve_writes=approve_writes,
            network_read_urls=network_read_urls,
            public_web_read=public_web_read,
            authorization=authorization,
            environment_selection=environment_selection,
            capability_selection=capability_selection,
        )
        fingerprint = submission_fingerprint(intent)
        normalized_capability_binding = None
        if capability_binding is not None:
            if not intent.capability_selection:
                raise TaskConflict("capability binding requires a logical capability selection")
            normalized_capability_binding = validate_capability_binding(
                capability_binding, intent.capability_selection
            )
        with self._state_lock:
            self._require_persistence()
            events = self.store.task_events(task_id)
            for existing_id in self.store.task_ids():
                if existing_id == task_id:
                    continue
                existing_events = self.store.task_events(existing_id)
                if not existing_events:
                    continue
                existing_task = self._project(existing_id, existing_events)
                if existing_task.submission_id == intent.submission_id:
                    raise TaskConflict("submission identity is already bound to another task")
            if events:
                task = self._project(task_id, events)
                if (
                    task.submission_id == intent.submission_id
                    and task.request_fingerprint == fingerprint
                    and task.request_ref
                    and task.descriptor_ref
                ):
                    return self._effective_recovery_view(task), False
                raise TaskConflict("task identity is already bound to different submission intent")

            if intent.capability_selection:
                if normalized_capability_binding is None:
                    raise TaskConflict("capability selection requires a host-resolved binding")
                authority = getattr(self, "_extension_authority", None)
                if authority is None:
                    raise TaskConflict("capability binding has no shared extension authority")
                authority.verify_capability_binding(normalized_capability_binding)

            observed_environment = environment_ref or f"environment:{intent.environment_selection or 'r4'}"
            observed_capabilities = capability_snapshot_id or (
                f"capabilities:{intent.capability_selection or 'r4'}"
            )
            workspace_observation = workspace_identity(intent.workspace_path)
            artifact_content = self.context_memory.persist(
                {
                    "schema": "SITINA_LOOP_INITIAL_ARTIFACT_V1",
                    "task_id": intent.task_id,
                    "workspace": workspace_observation,
                    "captured_for_submission": intent.submission_id,
                },
                purpose="loop-task-initial-artifact",
            )
            request_content = self.context_memory.persist(
                {**intent.as_dict(), "fingerprint": fingerprint},
                purpose="loop-task-submission-intent",
            )
            goal_content = self.context_memory.persist(
                {"schema": "SITINA_LOOP_GOAL_V1", "task_id": intent.task_id, "goal": intent.goal},
                purpose="loop-task-goal",
            )
            descriptor = build_run_descriptor(
                intent,
                required_outcome_ids=required_outcome_ids,
                goal_ref=goal_content.reference_id,
                goal_hash=goal_content.content_hash,
                initial_artifact_ref=artifact_content.reference_id,
                initial_artifact_hash=artifact_content.content_hash,
                environment_ref=observed_environment,
                capability_snapshot_id=observed_capabilities,
                workspace_observation=workspace_observation,
                provider_identity=provider_identity,
                software_identity=software_identity,
                config_identity=config_identity,
                protocol_versions=protocol_versions,
                capability_binding=normalized_capability_binding,
            )
            descriptor_content = self.context_memory.persist(
                descriptor,
                purpose="loop-task-executable-descriptor",
            )
            task = self.create_task(
                task_id=intent.task_id,
                session_id=session_id,
                task_kind=intent.task_kind,
                goal=intent.goal,
                required_outcome_ids=required_outcome_ids,
                artifact_ref=artifact_content.reference_id,
                environment_ref=observed_environment,
                capability_snapshot_id=observed_capabilities,
                request_id=f"task-admit:{intent.task_id}:{intent.submission_id}:{fingerprint[:16]}",
                artifact_content=artifact_content,
                submission_id=intent.submission_id,
                request_fingerprint=fingerprint,
                request_content=request_content,
                descriptor_content=descriptor_content,
                goal_content=goal_content,
                memory_view=memory_view,
            )
            return task, True

    def update_artifact(
        self,
        task_id: str,
        *,
        artifact_ref: str,
        reason: str,
        expected_goal_version: int | None = None,
        expected_acceptance_version: int | None = None,
        expected_handled_input_seq: int | None = None,
        expected_prior_artifact_ref: str | None = None,
        external_guard: Callable[[], bool] | None = None,
        artifact_content: StoredContent | None = None,
    ) -> TaskProjection:
        """Advance the task's durable artifact identity and invalidate prior acceptance."""

        if not artifact_ref.strip() or not reason.strip():
            raise ValueError("artifact update requires an identity and reason")
        if artifact_content is not None and artifact_content.reference_id != artifact_ref:
            raise ValueError("artifact content proof does not match the artifact ref")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.is_terminal:
                raise TaskConflict("terminal task artifact cannot change")
            if task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("artifact cannot advance while input is unhandled")
            expected = {
                "goal_version": expected_goal_version,
                "acceptance_version": expected_acceptance_version,
                "handled_input_seq": expected_handled_input_seq,
                "artifact_ref": expected_prior_artifact_ref,
            }
            actual = {
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
            }
            changed = [name for name, value in expected.items() if value is not None and value != actual[name]]
            if changed:
                raise TaskConflict("artifact binding changed before commit: " + ", ".join(changed))
            if external_guard is not None and not external_guard():
                raise TaskConflict("artifact content changed before version commit")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"artifact-update:{task_id}:{task.artifact_version + 1}:{artifact_ref}",
                command_type="loop.artifact.update",
                event_type="loop.artifact-updated",
                payload={
                    "schema": "SITINA_LOOP_ARTIFACT_UPDATED_V1",
                    "task_id": task_id,
                    "artifact_ref": artifact_ref,
                    **(
                        {"artifact_hash": artifact_content.content_hash}
                        if artifact_content is not None
                        else {}
                    ),
                    "artifact_version": task.artifact_version + 1,
                    "acceptance_version": task.acceptance_version + 1,
                    "run_instance_id": task.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "reason": reason,
                },
                proofs=((artifact_content.proof,) if artifact_content is not None else ()),
            )
            return self.get_task(task_id)

    def plan_attempt(self, task_id: str, plan: AttemptPlan) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.is_terminal:
                raise TaskConflict("terminal task cannot open another business attempt")
            if (
                task.control_intent is not ControlIntent.RUN
                or task.received_input_seq != task.handled_input_seq
                or task.status is not TaskStatus.RUNNABLE
            ):
                raise TaskConflict(
                    "business attempt requires RUN control, handled input, and RUNNABLE task state"
                )
            if plan.attempt_id in task.attempt_plans:
                raise TaskConflict("attempt plan identity already exists")
            settled_ids = {
                str(item.get("attempt_id"))
                for item in task.attempt_settlements
                if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
            }
            open_ids = set(task.attempt_plans) - settled_ids
            if open_ids:
                raise TaskConflict("a prior investigation attempt remains open: " + ", ".join(sorted(open_ids)))
            binding = {
                "task_id": task_id,
                "session_id": task.session_id,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "planned_from_task_revision": task.task_revision,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "criteria_lineage_version": task.criteria_lineage_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
                "environment_ref": task.environment_ref,
                "capability_snapshot_id": task.capability_snapshot_id,
            }
            document = plan.as_dict(binding)
            stored = self.context_memory.persist(document, purpose="loop-attempt-plan")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"attempt-plan:{task_id}:{plan.attempt_id}",
                command_type="loop.attempt.plan",
                event_type="loop.attempt-planned",
                payload={
                    "schema": "SITINA_LOOP_ATTEMPT_PLANNED_V1",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "attempt_id": plan.attempt_id,
                    "plan_ref": stored.reference_id,
                    "plan_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def checkpoint_attempt(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        attempt_id: str,
        reason: str,
        operation_refs: tuple[str, ...],
        evidence_refs: tuple[str, ...],
        action_observations: tuple[Mapping[str, Any], ...],
        segment_index: int,
        scope_consumed: Mapping[str, int],
        capability_sources: tuple[Mapping[str, Any], ...] = (),
        goal_input: Mapping[str, Any] | None = None,
    ) -> TaskProjection:
        if not checkpoint_id.strip() or not attempt_id.strip() or not reason.strip() or segment_index < 1:
            raise ValueError("attempt checkpoint identity, reason, and segment are required")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            plan = task.attempt_plans.get(attempt_id)
            if plan is None:
                raise TaskConflict("attempt checkpoint has no committed plan")
            if any(
                item.get("attempt_id") == attempt_id
                and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                for item in task.attempt_settlements
            ):
                raise TaskConflict("settled attempt cannot accept another checkpoint")
            if any(item.get("checkpoint_id") == checkpoint_id for item in task.attempt_checkpoints):
                raise TaskConflict("attempt checkpoint identity already exists")
            if any(
                item.get("attempt_id") == attempt_id
                and int(item.get("segment_index") or 0) == segment_index
                for item in task.attempt_checkpoints
            ):
                raise TaskConflict("attempt checkpoint segment is already recorded")
            if any(not isinstance(item, Mapping) for item in capability_sources):
                raise ValueError("attempt checkpoint capability sources must be mappings")
            scope = plan.get("scope")
            if not isinstance(scope, Mapping):
                raise PersistenceFenced("attempt plan scope is not readable")
            consumed = {str(key): int(value) for key, value in scope_consumed.items()}
            expected_scope_keys = {
                "control_segments": "max_control_segments",
                "provider_responses": "max_provider_responses",
                "tool_call_groups": "max_tool_call_groups",
            }
            if set(consumed) != set(expected_scope_keys):
                raise ValueError("attempt checkpoint scope counters are incomplete")
            if consumed["control_segments"] != segment_index:
                raise ValueError("attempt checkpoint segment and consumed control scope differ")
            if any(
                value < 0 or value > int(scope[expected_scope_keys[key]])
                for key, value in consumed.items()
            ):
                raise ValueError("attempt checkpoint exceeds its committed local scope")
            document = {
                "schema": "SITINA_LOOP_ATTEMPT_CHECKPOINT_V1",
                "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                "task_id": task_id,
                "attempt_id": attempt_id,
                "checkpoint_id": checkpoint_id,
                "reason": reason,
                "operation_refs": list(operation_refs),
                "evidence_refs": list(evidence_refs),
                "action_observations": [dict(item) for item in action_observations],
                "capability_sources": [dict(item) for item in capability_sources],
                "segment_index": segment_index,
                "scope_consumed": consumed,
                "binding_after_return": {
                    "run_instance_id": task.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "task_revision": task.task_revision,
                    "goal_version": task.goal_version,
                    "acceptance_version": task.acceptance_version,
                    "criteria_lineage_version": task.criteria_lineage_version,
                    "handled_input_seq": task.handled_input_seq,
                    "artifact_ref": task.artifact_ref,
                    "control_intent": task.control_intent.value,
                },
            }
            if goal_input is not None:
                if not isinstance(goal_input, Mapping) or reason not in {
                    "GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"
                }:
                    raise TaskConflict("goal-input checkpoint has an invalid decision")
                from sitina.extensions.runtime import AutonomousRuntime, AutonomousRuntimeError

                original_goal = self.context_memory.read(task.goal_ref)
                if not isinstance(original_goal, Mapping) or not isinstance(original_goal.get("goal"), str):
                    raise TaskConflict("goal-input checkpoint lacks the authoritative original request")
                # The interpretation derives from the authoritative request and
                # one committed Provider result; it is not the Provider's raw text.
                matching_provider_refs = []
                for operation in task.operations.values():
                    if (
                        not operation.operation_id.startswith("provider-")
                        or operation.business_attempt_id != attempt_id
                        or operation.effect_status is not EffectStatus.SUCCEEDED
                        or operation.result_ref not in operation_refs
                        or operation.bound_goal_version != task.goal_version
                        or operation.bound_acceptance_version != task.acceptance_version
                        or operation.bound_input_seq != task.handled_input_seq
                    ):
                        continue
                    provider_document = self.context_memory.read(str(operation.result_ref))
                    provider_result = provider_document.get("result")
                    if not isinstance(provider_result, Mapping) or provider_result.get("tool_calls"):
                        continue
                    try:
                        # Recompute from this task's durable request and the
                        # committed Provider bytes, never caller-supplied originals.
                        provider_decision = AutonomousRuntime._goal_input_decision(
                            str(provider_result.get("text") or ""),
                            required=(reason == "GOAL_INTERPRETED"),
                            original_request=original_goal["goal"],
                        )
                    except AutonomousRuntimeError:
                        continue
                    if provider_decision == dict(goal_input):
                        matching_provider_refs.append(str(operation.result_ref))
                if len(matching_provider_refs) != 1:
                    raise TaskConflict("goal-input decision lacks one current Provider result")
                if (reason == "CLARIFICATION_REQUIRED") != bool(goal_input.get("missing_inputs")):
                    raise TaskConflict("goal-input decision and checkpoint reason disagree")
                document["goal_input"] = dict(goal_input)
                document["goal_input_source_refs"] = matching_provider_refs
                document["original_goal_ref"] = task.goal_ref
                document["original_request_ref"] = task.request_ref
            stored = self.context_memory.persist(document, purpose="loop-attempt-checkpoint")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"attempt-checkpoint:{task_id}:{checkpoint_id}",
                command_type="loop.attempt.checkpoint",
                event_type="loop.attempt-checkpointed",
                payload={
                    "schema": "SITINA_LOOP_ATTEMPT_CHECKPOINTED_V1",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "checkpoint_id": checkpoint_id,
                    "checkpoint_ref": stored.reference_id,
                    "checkpoint_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def record_main_result_checkpoint(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        attempt_id: str,
        checkpoint: Mapping[str, Any],
    ) -> TaskProjection:
        """Persist main-result recovery metadata without changing task identity.

        This is a Journal/CAS metadata boundary, not an additional control
        segment or business attempt. It lets a host restart recover a main
        result that was returned immediately before a post-main command.
        """

        if not checkpoint_id.strip() or not attempt_id.strip():
            raise ValueError("main-result checkpoint identity is required")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            plan = task.attempt_plans.get(attempt_id)
            if plan is None:
                raise TaskConflict("main-result checkpoint has no committed plan")
            if any(
                item.get("attempt_id") == attempt_id
                and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                for item in task.attempt_settlements
            ):
                raise TaskConflict("settled attempt cannot receive a main-result checkpoint")
            document = {
                "schema": "SITINA_LOOP_MAIN_RESULT_CHECKPOINT_V1",
                "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                "task_id": task_id,
                "checkpoint_id": checkpoint_id,
                "attempt_id": attempt_id,
                **dict(checkpoint),
            }
            binding = document.get("binding")
            if not isinstance(binding, Mapping):
                raise PersistenceFenced("main-result checkpoint binding is missing")
            expected_binding = {
                "task_id": task_id,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "source_artifact_ref": task.artifact_ref,
            }
            if any(binding.get(key) != value for key, value in expected_binding.items()):
                raise TaskConflict("main-result checkpoint binding is stale")
            stored = self.context_memory.persist(document, purpose="loop-main-result-checkpoint")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"main-result-checkpoint:{task_id}:{checkpoint_id}",
                command_type="loop.main-result.checkpoint",
                event_type="loop.main-result-checkpointed",
                payload={
                    "schema": "SITINA_LOOP_MAIN_RESULT_CHECKPOINTED_V1",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "checkpoint_id": checkpoint_id,
                    "checkpoint_ref": stored.reference_id,
                    "checkpoint_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def settle_attempt(
        self,
        task_id: str,
        *,
        attempt_id: str,
        blocker_id: str,
        outcome: str,
        relevant_progress: bool,
        evidence_refs: tuple[str, ...],
        progress_basis: Mapping[str, Any] | None = None,
        count_effect: str | None = None,
        progress_decision: Mapping[str, Any] | None = None,
    ) -> TaskProjection:
        if not attempt_id.strip() or not blocker_id.strip() or not outcome.strip():
            raise ValueError("attempt settlement identity is required")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            plan = task.attempt_plans.get(attempt_id)
            if plan is not None:
                if any(
                    item.get("attempt_id") == attempt_id
                    and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                    for item in task.attempt_settlements
                ):
                    raise TaskConflict("attempt is already settled")
                if count_effect is None:
                    count_effect = COUNT_NEUTRAL
                if count_effect not in COUNT_EFFECTS:
                    raise ValueError("attempt settlement count effect is invalid")
                if count_effect == "PROGRESSED" and not relevant_progress:
                    raise ValueError("progressed settlement requires verified relevant progress")
                if count_effect == "NO_PROGRESS" and relevant_progress:
                    raise ValueError("no-progress settlement contradicts relevant progress")
                if count_effect == COUNT_NEUTRAL and relevant_progress:
                    raise ValueError("count-neutral settlement cannot claim relevant progress")
                plan_is_current = (
                    plan.get("run_instance_id") == task.run_instance_id
                    and int(plan.get("execution_epoch")) == task.execution_epoch
                    and int(plan.get("goal_version")) == task.goal_version
                    and int(plan.get("acceptance_version")) == task.acceptance_version
                    and int(plan.get("criteria_lineage_version", 1)) == task.criteria_lineage_version
                    and int(plan.get("handled_input_seq")) == task.handled_input_seq
                    and plan.get("artifact_ref") == task.artifact_ref
                )
                if not plan_is_current and (count_effect != COUNT_NEUTRAL or relevant_progress):
                    raise TaskConflict(
                        "stale attempt may only settle ABORTED_NOT_COUNTED without progress"
                    )
            elif count_effect is not None or progress_decision is not None:
                raise TaskConflict("new termination settlement requires a committed attempt plan")
            document = {
                "schema": "SITINA_LOOP_ATTEMPT_SETTLEMENT_V1",
                "task_id": task_id,
                "attempt_id": attempt_id,
                "blocker_id": blocker_id,
                "outcome": outcome,
                "relevant_progress": bool(relevant_progress),
                "evidence_refs": list(evidence_refs),
                "progress_basis": dict(progress_basis or {}),
                **(
                    {
                        "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                        "lineage_id": str(plan["lineage_id"]),
                        "acceptance_item_id": str(plan["acceptance_item_id"]),
                        "registered_blocker_id": str(plan["blocker_id"]),
                        "count_effect": count_effect,
                        "progress_decision": dict(progress_decision or {}),
                    }
                    if plan is not None
                    else {"legacy_semantics": True}
                ),
                "goal_version": int(plan["goal_version"]) if plan is not None else task.goal_version,
                "acceptance_version": (
                    int(plan["acceptance_version"]) if plan is not None else task.acceptance_version
                ),
                "criteria_lineage_version": (
                    int(plan.get("criteria_lineage_version", 1))
                    if plan is not None
                    else task.criteria_lineage_version
                ),
                "handled_input_seq": (
                    int(plan["handled_input_seq"]) if plan is not None else task.handled_input_seq
                ),
                **(
                    {
                        "planned_artifact_ref": str(plan["artifact_ref"]),
                        "closing_binding": {
                            "run_instance_id": task.run_instance_id,
                            "execution_epoch": task.execution_epoch,
                            "task_revision": task.task_revision,
                            "goal_version": task.goal_version,
                            "acceptance_version": task.acceptance_version,
                            "handled_input_seq": task.handled_input_seq,
                            "artifact_ref": task.artifact_ref,
                            "control_intent": task.control_intent.value,
                        },
                    }
                    if plan is not None
                    else {}
                ),
            }
            stored = self.context_memory.persist(document, purpose="loop-attempt-settlement")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"attempt-settle:{task_id}:{attempt_id}",
                command_type="loop.attempt.settle",
                event_type="loop.attempt-settled",
                payload={
                    "schema": "SITINA_LOOP_ATTEMPT_SETTLED_V1",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "blocker_id": blocker_id,
                    "settlement_ref": stored.reference_id,
                    "settlement_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def record_review_findings(
        self,
        task_id: str,
        review: Mapping[str, Any],
        *,
        attempt_id: str,
        expected_task_revision: int,
        expected_run_instance_id: str,
        expected_execution_epoch: int,
        expected_goal_version: int,
        expected_acceptance_version: int,
        expected_criteria_lineage_version: int,
        expected_handled_input_seq: int,
    ) -> TaskProjection:
        """Persist one validated V2 review and update its stable issue registry."""

        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            plan = task.attempt_plans.get(attempt_id)
            expected = {
                "task_revision": expected_task_revision,
                "run_instance_id": expected_run_instance_id,
                "execution_epoch": expected_execution_epoch,
                "goal_version": expected_goal_version,
                "acceptance_version": expected_acceptance_version,
                "criteria_lineage_version": expected_criteria_lineage_version,
                "handled_input_seq": expected_handled_input_seq,
            }
            actual = {
                "task_revision": task.task_revision,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "criteria_lineage_version": task.criteria_lineage_version,
                "handled_input_seq": task.handled_input_seq,
            }
            plan_is_current = bool(
                plan is not None
                and plan.get("run_instance_id") == task.run_instance_id
                and int(plan.get("execution_epoch", -1)) == task.execution_epoch
                and int(plan.get("goal_version", -1)) == task.goal_version
                and int(plan.get("acceptance_version", -1)) == task.acceptance_version
                and int(plan.get("criteria_lineage_version", 1)) == task.criteria_lineage_version
                and int(plan.get("handled_input_seq", -1)) == task.handled_input_seq
                and plan.get("artifact_ref") == task.artifact_ref
                and not any(
                    item.get("attempt_id") == attempt_id
                    and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                    for item in task.attempt_settlements
                )
            )
            if (
                not plan_is_current
                or plan.get("acceptance_item_id") != review.get("acceptance_item_id")
                or task.is_terminal
                or task.control_intent is not ControlIntent.RUN
                or task.status is not TaskStatus.RUNNABLE
                or task.received_input_seq != task.handled_input_seq
                or expected != actual
            ):
                raise StaleProposal("review attempt or task binding changed before findings commit")
            if review.get("schema") != "SITINA_LOOP_REVIEW_V2" or (
                review.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
            ):
                raise ValueError("review findings require the current V2 contract")
            if review.get("observed_artifact_ref") != task.artifact_ref:
                raise TaskConflict("review artifact binding is stale")
            expected_lineage = f"criteria:{task_id}:{task.criteria_lineage_version}"
            if review.get("criteria_lineage_id") != expected_lineage:
                raise TaskConflict("review criteria lineage is stale")
            findings = review.get("findings")
            if not isinstance(findings, list):
                raise ValueError("review findings are invalid")
            for finding in findings:
                if not isinstance(finding, Mapping):
                    raise ValueError("review finding is invalid")
                issue_id = stable_review_issue_id(
                    criteria_lineage_id=str(finding.get("criteria_lineage_id") or ""),
                    acceptance_item_id=str(review.get("acceptance_item_id") or ""),
                    review_subject_lineage_id=str(review.get("review_subject_lineage") or ""),
                    rule_id=str(finding.get("rule_id") or ""),
                    locus_id=str(finding.get("locus_id") or ""),
                    object_id=str(finding.get("object_id") or ""),
                    issue_slot_id=str(finding.get("issue_slot_id") or ""),
                    finding_code=str(finding.get("finding_code") or ""),
                )
                if finding.get("stable_issue_id") != issue_id:
                    raise ValueError("review finding stable identity is invalid")
                prior = task.review_issues.get(issue_id)
                if finding.get("disposition") in {"RESOLVED", "NOT_APPLICABLE"} and (
                    prior is None or prior.get("status") != "OPEN"
                ):
                    raise ValueError("review cannot close an issue that is not currently open")
            document = {
                "schema": "SITINA_LOOP_REVIEW_RECORD_V2",
                "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                "task_id": task_id,
                "bound_task_revision": task.task_revision,
                "bound_run_instance_id": task.run_instance_id,
                "bound_execution_epoch": task.execution_epoch,
                "bound_goal_version": task.goal_version,
                "bound_acceptance_version": task.acceptance_version,
                "bound_criteria_lineage_version": task.criteria_lineage_version,
                "bound_handled_input_seq": task.handled_input_seq,
                "bound_artifact_ref": task.artifact_ref,
                "review": dict(review),
            }
            stored = self.context_memory.persist(document, purpose="loop-review-findings")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"review-findings:{task_id}:{task.task_revision}",
                command_type="loop.review.record-findings",
                event_type="loop.review-findings-recorded",
                payload={
                    "schema": "SITINA_LOOP_REVIEW_FINDINGS_RECORDED_V2",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "review_ref": stored.reference_id,
                    "review_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def _validate_review_failure_evidence(
        self, task: TaskProjection, attempt_id: str, evidence: Mapping[str, Any],
    ) -> None:
        request = evidence.get("request")
        if (evidence.get("schema") != "SITINA_REVIEW_FAILURE_EVIDENCE_V1"
                or evidence.get("failure_origin") != "MODEL_RESPONSE"
                or evidence.get("attempt_id") != attempt_id
                or not isinstance(request, Mapping) or request.get("attempt_id") != attempt_id):
            raise TaskConflict("review repair lacks attributed native response evidence")
        operation = task.operations.get(request.get("operation_id"))
        if (operation is None or operation.business_attempt_id != attempt_id
                or operation.effect_status.value != "SUCCEEDED"
                or operation.result_ref != request.get("result_ref")):
            raise TaskConflict("review repair response belongs to another attempt or is unresolved")
        result = self.context_memory.read(request["result_ref"], expected_hash=request["result_hash"])
        wire = result.get("result", {}).get("private_review_evidence_request")
        if (not isinstance(wire, str)
                or hashlib.sha256(wire.encode("utf-8")).hexdigest() != request.get("request_body_hash")):
            raise TaskConflict("review repair request evidence no longer matches its native receipt")

    def record_review_repair(
        self,
        task_id: str,
        *,
        repair_kind: str,
        repair_index: int,
        review_subject_lineage_id: str,
        artifact_ref: str,
        detail: str,
        attempt_id: str,
        expected_task_revision: int,
        expected_run_instance_id: str,
        expected_execution_epoch: int,
        expected_goal_version: int,
        expected_acceptance_version: int,
        expected_criteria_lineage_version: int,
        expected_handled_input_seq: int,
        failure_evidence: Mapping[str, Any],
    ) -> TaskProjection:
        """Record one reviewer-local finite protocol/evidence repair."""

        if repair_kind not in REVIEW_REPAIR_KINDS or type(repair_index) is not int or repair_index < 1:
            raise ValueError("review repair kind or finite index is invalid")
        if not detail.strip() or not review_subject_lineage_id.strip():
            raise ValueError("review repair binding and detail are required")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            plan = task.attempt_plans.get(attempt_id)
            expected = (
                expected_task_revision,
                expected_run_instance_id,
                expected_execution_epoch,
                expected_goal_version,
                expected_acceptance_version,
                expected_criteria_lineage_version,
                expected_handled_input_seq,
            )
            actual = (
                task.task_revision,
                task.run_instance_id,
                task.execution_epoch,
                task.goal_version,
                task.acceptance_version,
                task.criteria_lineage_version,
                task.handled_input_seq,
            )
            plan_is_current = bool(
                plan is not None
                and plan.get("run_instance_id") == task.run_instance_id
                and int(plan.get("execution_epoch", -1)) == task.execution_epoch
                and int(plan.get("goal_version", -1)) == task.goal_version
                and int(plan.get("acceptance_version", -1)) == task.acceptance_version
                and int(plan.get("criteria_lineage_version", 1)) == task.criteria_lineage_version
                and int(plan.get("handled_input_seq", -1)) == task.handled_input_seq
                and plan.get("artifact_ref") == task.artifact_ref
                and not any(
                    item.get("attempt_id") == attempt_id
                    and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                    for item in task.attempt_settlements
                )
            )
            if task.artifact_ref != artifact_ref:
                raise TaskConflict("review repair artifact binding is stale")
            prior_indices = [row["repair_index"] for row in task.review_repairs
                             if row.get("artifact_ref") == artifact_ref
                             and row.get("review_subject_lineage") == review_subject_lineage_id]
            if (repair_index != max(prior_indices, default=0) + 1
                    or repair_index > task.review_repair_limit(artifact_ref)):
                raise TaskConflict("review repair index exceeds its explicit finite authorization")
            if (
                not plan_is_current
                or task.is_terminal
                or task.control_intent is not ControlIntent.RUN
                or task.status is not TaskStatus.RUNNABLE
                or task.received_input_seq != task.handled_input_seq
                or expected != actual
            ):
                raise StaleProposal("review attempt or task binding changed before repair commit")
            if any(
                item.get("review_subject_lineage") == review_subject_lineage_id
                and item.get("artifact_ref") == artifact_ref
                and item.get("repair_index") == repair_index
                for item in task.review_repairs
            ):
                raise TaskConflict("review repair index is already recorded for this candidate")
            self._validate_review_failure_evidence(task, attempt_id, failure_evidence)
            document = {
                "schema": "SITINA_LOOP_REVIEW_REPAIR_V3",
                "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                "task_id": task_id,
                "repair_kind": repair_kind,
                "repair_index": repair_index,
                "review_subject_lineage": review_subject_lineage_id,
                "artifact_ref": artifact_ref,
                "criteria_lineage_id": f"criteria:{task_id}:{task.criteria_lineage_version}",
                "detail": detail,
                "reviewer_local": True,
                "main_runtime_reentered": False,
                "attempt_id": attempt_id,
                "failure_origin": "MODEL_RESPONSE",
                "failure_evidence": dict(failure_evidence),
            }
            stored = self.context_memory.persist(document, purpose="loop-review-repair")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"review-repair:{task_id}:{artifact_ref}:{repair_index}",
                command_type="loop.review.record-repair",
                event_type="loop.review-repair-recorded",
                payload={
                    "schema": "SITINA_LOOP_REVIEW_REPAIR_RECORDED_V2",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "repair_ref": stored.reference_id,
                    "repair_hash": stored.content_hash,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def _persist_stop_report(
        self,
        task: TaskProjection,
        *,
        status: TaskStatus,
        blocker_id: str,
        reason: str,
        evidence_refs: tuple[str, ...],
        partial_artifact: StoredContent | None = None,
    ) -> StoredContent:
        """Build a deterministic scheduler-owned report for one exact pre-stop state."""

        current_acceptances = [
            record
            for record in task.acceptances.values()
            if record.bound_run_instance_id == task.run_instance_id
            and record.bound_execution_epoch == task.execution_epoch
            and record.goal_version == task.goal_version
            and record.acceptance_version == task.acceptance_version
            and record.bound_handled_input_seq == task.handled_input_seq
            and record.artifact_ref == task.artifact_ref
            and record.program_status == "PASS"
            and record.reviewer_status in {"PASS", "NOT_REQUIRED"}
            and record.delivery_verified
        ]
        current_outcomes = {record.outcome_id for record in current_acceptances}
        historical_verified: list[dict[str, Any]] = []
        for event in self.store.task_events(task.task_id):
            if event.event_type != "loop.acceptance-result-recorded":
                continue
            document = self.context_memory.read(
                str(event.payload["acceptance_ref"]),
                expected_hash=str(event.payload["acceptance_hash"]),
            )
            if (
                document.get("program_status") != "PASS"
                or document.get("reviewer_status") not in {"PASS", "NOT_REQUIRED"}
                or document.get("delivery_verified") is not True
            ):
                continue
            is_current = (
                document.get("bound_run_instance_id") == task.run_instance_id
                and int(document.get("bound_execution_epoch", -1)) == task.execution_epoch
                and int(document.get("goal_version", -1)) == task.goal_version
                and int(document.get("acceptance_version", -1)) == task.acceptance_version
                and int(document.get("bound_handled_input_seq", -1)) == task.handled_input_seq
                and document.get("artifact_ref") == task.artifact_ref
            )
            if not is_current:
                historical_verified.append({
                    "acceptance_id": str(document.get("acceptance_id") or ""),
                    "outcome_id": str(document.get("outcome_id") or ""),
                    "artifact_ref": str(document.get("artifact_ref") or ""),
                    "goal_version": int(document.get("goal_version", 0)),
                    "acceptance_version": int(document.get("acceptance_version", 0)),
                    "handled_input_seq": int(document.get("bound_handled_input_seq", 0)),
                    "evidence_refs": sorted(str(item) for item in document.get("evidence_refs", ())),
                })
        current_verified = (
            task.received_input_seq == task.handled_input_seq
            and set(task.required_outcome_ids).issubset(current_outcomes)
        )
        settlements = [
            item for item in task.attempt_settlements
            if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
        ]
        try:
            current_artifact_document = self.context_memory.read(task.artifact_ref)
        except (CASError, KeyError, ValueError, TypeError):
            current_artifact_document = {}
        partial_document = (
            self.context_memory.read(
                partial_artifact.reference_id,
                expected_hash=partial_artifact.content_hash,
            )
            if partial_artifact is not None
            else {}
        )
        provider_records: list[dict[str, Any]] = []
        tool_result_count = 0
        for event in self.store.task_events(task.task_id):
            if event.event_type != "loop.operation-result-recorded":
                continue
            operation_id = str(event.payload.get("operation_id") or "")
            result_document = self.context_memory.read(
                str(event.payload["result_ref"]), expected_hash=str(event.payload["result_hash"])
            )
            result = result_document.get("result") or {}
            if operation_id.startswith("provider-") and isinstance(result, Mapping):
                metadata = result.get("metadata") or {}
                usage = metadata.get("token_usage") or metadata.get("usage") or {}
                provider_records.append({
                    "physical_send_count": metadata.get("physical_send_count"),
                    "physical_send_count_lower_bound": metadata.get(
                        "physical_send_count_lower_bound",
                        metadata.get("physical_send_count"),
                    ),
                    "physical_send_count_status": metadata.get("physical_send_count_status"),
                    "uncertain_physical_send_attempt_count": metadata.get(
                        "uncertain_physical_send_attempt_count"
                    ),
                    "retry_count": metadata.get("retry_count"),
                    "fallback_count": metadata.get("fallback_count"),
                    "input_tokens": usage.get("input_tokens") if isinstance(usage, Mapping) else None,
                    "output_tokens": usage.get("output_tokens") if isinstance(usage, Mapping) else None,
                })
            elif operation_id.startswith(("tool-", "review-tool-")):
                tool_result_count += 1

        def complete_sum(field: str) -> int | None:
            values = [record.get(field) for record in provider_records]
            return (
                sum(int(value) for value in values)
                if values and all(type(value) is int and value >= 0 for value in values)
                else None
            )

        def exact_physical_send_sum() -> int | None:
            if not provider_records:
                return None
            if any(
                record.get("physical_send_count_status") != "exact"
                or record.get("uncertain_physical_send_attempt_count") != 0
                for record in provider_records
            ):
                return None
            return complete_sum("physical_send_count")

        provider_input_tokens = complete_sum("input_tokens")
        provider_output_tokens = complete_sum("output_tokens")
        report = {
            "schema": "SITINA_LOOP_STOP_REPORT_V1",
            "termination_contract_version": TERMINATION_CONTRACT_VERSION,
            "generated_without_provider": True,
            "task_id": task.task_id,
            "session_id": task.session_id,
            "status": status.value,
            "reason_code": blocker_id,
            "reason": reason,
            "pre_stop_binding": {
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "task_revision": task.task_revision,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "criteria_lineage_version": task.criteria_lineage_version,
                "received_input_seq": task.received_input_seq,
                "handled_input_seq": task.handled_input_seq,
                "artifact_version": task.artifact_version,
                "artifact_ref": task.artifact_ref,
                "environment_ref": task.environment_ref,
                "control_intent": task.control_intent.value,
            },
            "evidence_refs": sorted(set(str(item) for item in evidence_refs if str(item))),
            "artifacts": {
                "current": {
                    "artifact_ref": task.artifact_ref,
                    "verification": "CURRENT_VERIFIED" if current_verified else "CURRENT_UNVERIFIED",
                    "verified_outcome_ids": sorted(current_outcomes),
                    "workspace_path": current_artifact_document.get("workspace_path"),
                    "changed_paths": list(current_artifact_document.get("changed_paths", ())),
                },
                "historical_verified": sorted(
                    historical_verified,
                    key=lambda item: (
                        item["goal_version"], item["acceptance_version"], item["acceptance_id"]
                    ),
                ),
                "partial": (
                    {
                        "artifact_ref": partial_artifact.reference_id,
                        "artifact_hash": partial_artifact.content_hash,
                        "verification": "PARTIAL_UNVERIFIED",
                        "workspace_path": partial_document.get("workspace_path"),
                        "changed_paths": list(partial_document.get("changed_paths", ())),
                    }
                    if partial_artifact is not None
                    else None
                ),
            },
            "incomplete_outcome_ids": sorted(set(task.required_outcome_ids) - current_outcomes),
            "review": {
                "unresolved_issue_ids": sorted(
                    issue_id for issue_id, issue in task.review_issues.items() if issue.get("status") == "OPEN"
                ),
                "issue_disagreement_counts": {
                    issue_id: int(issue.get("disagreement_count", 0))
                    for issue_id, issue in sorted(task.review_issues.items())
                    if issue.get("status") == "OPEN"
                },
                "protocol_repair_count": len(task.review_repairs),
            },
            "operations": {
                "active_operation_ids": sorted(item.operation_id for item in task.active_operations),
                "partial_operation_ids": sorted(
                    item.operation_id
                    for item in task.operations.values()
                    if item.effect_status is EffectStatus.PARTIAL
                ),
                "unknown_effect_operation_ids": sorted(item.operation_id for item in task.unresolved_effects),
                "owned_resources": sorted(task.owned_resources),
            },
            "recovery_obligations": [
                "inspect and reconcile every UNKNOWN write effect before release or terminal completion"
                for _ in [0]
                if any(item.mode is OperationMode.WRITE for item in task.unresolved_effects)
            ],
            "task_scope_metrics": {
                "settled_attempt_count": len(settlements),
                "no_progress_attempt_count": sum(
                    1 for item in settlements if item.get("count_effect") == "NO_PROGRESS"
                ),
                "progressed_attempt_count": sum(
                    1 for item in settlements if item.get("count_effect") == "PROGRESSED"
                ),
                "count_neutral_attempt_count": sum(
                    1 for item in settlements if item.get("count_effect") == "COUNT_NEUTRAL"
                ),
                "provider_result_record_count": len(provider_records),
                "tool_result_record_count": tool_result_count,
                "provider_physical_send_count": exact_physical_send_sum(),
                "provider_physical_send_count_lower_bound": complete_sum(
                    "physical_send_count_lower_bound"
                ),
                "provider_uncertain_physical_send_attempt_count": complete_sum(
                    "uncertain_physical_send_attempt_count"
                ),
                "provider_retry_count": complete_sum("retry_count"),
                "provider_fallback_count": complete_sum("fallback_count"),
                "provider_input_tokens": provider_input_tokens,
                "provider_output_tokens": provider_output_tokens,
                "provider_token_total": (
                    provider_input_tokens + provider_output_tokens
                    if provider_input_tokens is not None and provider_output_tokens is not None
                    else None
                ),
                "provider_metrics_complete": bool(provider_records) and all(
                    (
                        exact_physical_send_sum() is not None
                        if field == "physical_send_count"
                        else complete_sum(field) is not None
                    )
                    for field in (
                        "physical_send_count",
                        "retry_count",
                        "fallback_count",
                        "input_tokens",
                        "output_tokens",
                    )
                ),
            },
            "optional_actions": [
                {
                    "action": "inspect_persisted_status_and_evidence",
                    "recommended": True,
                    "reason": "preserves the exact stopped binding without dispatching Provider or business work",
                },
                {
                    "action": "resume_after_blocker_resolution",
                    "recommended": status not in {TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.SUCCEEDED}
                    and not bool(task.unresolved_effects),
                    "reason": (
                        "terminal tasks retain results; continue in an explicitly related new task"
                        if status in {TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.SUCCEEDED}
                        else
                        "reconcile unknown effects first"
                        if task.unresolved_effects
                        else "resume only after the recorded blocker or user control changes"
                    ),
                },
            ],
        }
        return self.context_memory.persist(report, purpose="loop-stop-report")

    def _native_wait_binding_current(self, task: TaskProjection, document: Mapping[str, Any]) -> bool:
        return (document.get("goal_version") == task.goal_version
                and document.get("acceptance_version") == task.acceptance_version
                and document.get("handled_input_seq") == task.handled_input_seq
                and task.received_input_seq == task.handled_input_seq)

    def _record_native_execution_wait(self, task: TaskProjection, document: Mapping[str, Any]) -> TaskProjection:
        stored = self.context_memory.persist(dict(document), purpose="native-execution-wait")
        self._append(task_id=task.task_id, expected_stream_version=task.task_revision,
            request_id=f"native-execution-wait:{task.task_id}:{task.task_revision}",
            command_type="loop.task.native-execution-wait",
            event_type="loop.native-execution-wait-updated",
            payload={"task_id": task.task_id, "waiting_ref": stored.reference_id,
                     "waiting_hash": stored.content_hash, "status": document["status"]},
            proofs=(stored.proof,))
        return self.get_task(task.task_id)

    def native_execution_wait_task_ids(self) -> tuple[str, ...]:
        """Discover persisted waits once; subsequent polls use a bounded active set."""
        with self._state_lock:
            ids = getattr(self, "_native_execution_wait_ids", None)
            if ids is None:
                ids = self._native_execution_wait_ids = set()
                for task_id in self.task_ids():
                    task = self.get_task(task_id)
                    waiting = task.waiting_reason or {}
                    if waiting.get("blocker_id") == "native-execution" and waiting.get("state") in {"WAITING", "BLOCKED"}:
                        ids.add(task_id)
            return tuple(sorted(ids))

    def wait_for_native_executions(
        self, task_id: str, process_ids: tuple[str, ...], *,
        expected_goal_version: int, expected_acceptance_version: int, expected_handled_input_seq: int,
    ) -> TaskProjection:
        """Persist dependence on original finite executions; never launch or cancel them."""
        if (not process_ids or len(process_ids) > 64
                or any(not isinstance(item, str) or not item for item in process_ids)
                or len(set(process_ids)) != len(process_ids)):
            raise ValueError("native wait requires distinct original process IDs (at most 64)")
        process_ids = tuple(sorted(process_ids))
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if (task.is_terminal or task.control_intent is not ControlIntent.RUN
                    or task.received_input_seq != task.handled_input_seq
                    or (task.goal_version, task.acceptance_version, task.handled_input_seq) !=
                       (expected_goal_version, expected_acceptance_version, expected_handled_input_seq)):
                raise TaskConflict("native wait task/input binding changed")
            if task.active_operations:
                raise TaskConflict("native wait cannot replace an active operation")
            managed = self.managed_process_evidence(task_id)
            bindings = []
            for process_id in process_ids:
                owner = task.operations.get(process_id)
                evidence = managed.get(process_id)
                if (owner is None or not isinstance(evidence, Mapping)
                        or owner.mode is not OperationMode.WRITE
                        or owner.effect_status is not EffectStatus.SUCCEEDED or owner.unknown_effect
                        or evidence.get("execution_contract") != TASK_EXECUTION_CONTRACT
                        or evidence.get("execution_owner") or evidence.get("keep") is not False
                        or owner.bound_goal_version != task.goal_version
                        or owner.bound_acceptance_version != task.acceptance_version
                        or owner.bound_input_seq != task.handled_input_seq):
                    raise TaskConflict("native wait does not own the current finite execution")
                bindings.append({"process_id": process_id, "intent_ref": owner.intent_ref,
                    "result_ref": owner.result_ref, "manifest_ref": evidence["command_manifest_path"],
                    "manifest_hash": evidence["command_manifest_hash"],
                    "command_nonce": evidence["command_nonce"], "wrapper_id": evidence["wrapper_id"],
                    "run_instance_id": evidence.get("run_instance_id"),
                    "execution_epoch": evidence.get("execution_epoch")})
            identity = {"task_id": task_id, "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version, "handled_input_seq": task.handled_input_seq,
                "process_ids": list(process_ids), "bindings": bindings}
            wait_id = "native-wait-" + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
            old = task.waiting_reason or {}
            if old.get("wait_id") != wait_id:
                document = {"schema": "SITINA_NATIVE_EXECUTION_WAIT_V1", **identity,
                    "wait_id": wait_id, "blocker_id": "native-execution", "state": "WAITING",
                    "status": TaskStatus.WAITING_OPERATION.value,
                    "reason": "waiting for the original finite execution result; no model polling",
                    "results": []}
                task = self._record_native_execution_wait(task, document)
            self.native_execution_wait_task_ids()
            if (task.waiting_reason or {}).get("state") != "RESOLVED":
                self._native_execution_wait_ids.add(task_id)
        # Registration precedes the fresh observation, closing the finish-before-wait race.
        self.reconcile_native_execution_wait(task_id)
        return self.get_task(task_id)

    def reconcile_native_execution_wait(self, task_id: str) -> bool:
        with self._state_lock:
            task = self.get_task(task_id)
            waiting = task.waiting_reason or {}
            if (waiting.get("blocker_id") != "native-execution"
                    or waiting.get("state") not in {"WAITING", "BLOCKED"}
                    or task.is_terminal or task.control_intent is not ControlIntent.RUN
                    or not self._native_wait_binding_current(task, waiting)):
                return False
            managed = self.managed_process_evidence(task_id)
            bindings = copy.deepcopy(waiting["bindings"])
            wait_id = waiting["wait_id"]
        results = []
        for binding in bindings:
            process_id = binding["process_id"]
            evidence = managed.get(process_id)
            if (not isinstance(evidence, Mapping)
                    or evidence.get("command_manifest_hash") != binding["manifest_hash"]
                    or evidence.get("command_nonce") != binding["command_nonce"]
                    or evidence.get("wrapper_id") != binding["wrapper_id"]):
                results.append({"process_id": process_id, "decision": "UNKNOWN",
                                "reason": "native-wait-owner-binding-mismatch"})
                continue
            observed = observe_managed_command(evidence, task_id=task_id, operation_id=process_id, stop=False)
            completion = observed.get("completion") or {}
            manifest = observed.get("manifest") or {}
            results.append({"process_id": process_id, "decision": observed.get("decision"),
                "reason": observed.get("reason"), "manifest_ref": binding["manifest_ref"],
                "manifest_hash": binding["manifest_hash"], "owner_result_ref": binding["result_ref"],
                "completion_ref": manifest.get("completion_path"),
                "completion_hash": observed.get("completion_hash"),
                "completion_status": completion.get("status"), "exit_code": completion.get("exit_code"),
                "root_result_hash": observed.get("root_result_hash"),
                "stdout_ref": manifest.get("stdout_path"), "stderr_ref": manifest.get("stderr_path"),
                "stdout_hash": observed.get("stdout_hash"), "stderr_hash": observed.get("stderr_hash"),
                "timeout_seconds": str(manifest["timeout_seconds"]) if "timeout_seconds" in manifest else None,
                "start_ref": manifest.get("start_path")})
        resolved = all(item["decision"] in {"SUCCEEDED", "NO_EFFECT"} for item in results)
        blocked = any(item["decision"] == "UNKNOWN" for item in results)
        state = "RESOLVED" if resolved else "BLOCKED" if blocked else "WAITING"
        with self._state_lock:
            task = self.get_task(task_id)
            current = task.waiting_reason or {}
            if (task.is_terminal or task.control_intent is not ControlIntent.RUN
                    or current.get("wait_id") != wait_id or current.get("state") == "RESOLVED"
                    or not self._native_wait_binding_current(task, current)):
                return False
            if current.get("state") == state and current.get("results") == results:
                return False
            document = {**current, "state": state, "results": results,
                "status": (TaskStatus.RUNNABLE.value if resolved else
                           TaskStatus.RECOVERY_BLOCKED.value if blocked else TaskStatus.WAITING_OPERATION.value),
                "reason": ("original execution results ready" if resolved else
                           "original execution outcome remains unknown" if blocked else
                           "waiting for the original finite execution result; no model polling")}
            if resolved:
                document["resolution_id"] = hashlib.sha256(canonical_json_bytes(results)).hexdigest()
            self._record_native_execution_wait(task, document)
            if resolved:
                self._native_execution_wait_ids.discard(task_id)
        if resolved:
            hook = getattr(self, "native_execution_wait_hook", None)
            if hook is not None:
                hook(task_id)
        return resolved

    def native_execution_wait_results(self, task_id: str) -> dict[str, Any] | None:
        task = self.get_task(task_id)
        waiting = task.waiting_reason or {}
        if (waiting.get("blocker_id") != "native-execution" or waiting.get("state") != "RESOLVED"
                or not self._native_wait_binding_current(task, waiting)):
            return None
        return copy.deepcopy(dict(waiting))

    def dock_waiting(
        self,
        task_id: str,
        *,
        status: TaskStatus,
        blocker_id: str,
        reason: str,
        evidence_refs: tuple[str, ...],
        partial_artifact: StoredContent | None = None,
        assessment_resolution: Mapping[str, Any] | None = None,
    ) -> TaskProjection:
        if status not in {TaskStatus.STALLED, TaskStatus.WAITING_INPUT}:
            raise ValueError("waiting dock requires STALLED or WAITING_INPUT")
        resolution = (validate_assessment_stop_resolution(assessment_resolution, status=status.value)
                      if assessment_resolution is not None else None)
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            clarification = blocker_id.startswith("clarification:")
            if clarification:
                checkpoint_id = blocker_id.removeprefix("clarification:")
                checkpoint = next(
                    (item for item in task.attempt_checkpoints
                     if item.get("checkpoint_id") == checkpoint_id),
                    None,
                )
                decision = checkpoint.get("goal_input") if checkpoint is not None else None
                binding = checkpoint.get("binding_after_return") if checkpoint is not None else None
                if (
                    status is not TaskStatus.WAITING_INPUT
                    or task.is_terminal
                    or task.control_intent is not ControlIntent.RUN
                    or (task.received_input_seq > task.handled_input_seq)
                    or checkpoint is None
                    or checkpoint.get("reason") != "CLARIFICATION_REQUIRED"
                    or checkpoint.get("original_goal_ref") != task.goal_ref
                    or checkpoint.get("original_request_ref") != task.request_ref
                    or not isinstance(decision, Mapping)
                    or not decision.get("missing_inputs")
                    or reason != decision.get("question")
                    or not evidence_refs
                    or evidence_refs != tuple(checkpoint.get("goal_input_source_refs", ()))
                    or not isinstance(binding, Mapping)
                    or binding.get("goal_version") != task.goal_version
                    or binding.get("acceptance_version") != task.acceptance_version
                    or binding.get("handled_input_seq") != task.handled_input_seq
                ):
                    raise TaskConflict("clarification checkpoint binding changed before waiting dock")
            if blocker_id == "child-delegation" and self.can_propose_terminal(task_id):
                return task
            unknown_writes = tuple(
                operation for operation in task.unresolved_effects if operation.mode is OperationMode.WRITE
            )
            if task.active_operations or unknown_writes:
                raise TaskConflict("cannot dock while a business write remains active or unknown")
            document = {
                "schema": "SITINA_LOOP_WAITING_REASON_V1",
                "task_id": task_id,
                "status": status.value,
                "blocker_id": blocker_id,
                "reason": reason,
                "evidence_refs": list(evidence_refs),
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
            }
            if resolution is not None:
                document["assessment_resolution"] = resolution
            if clarification and task.status is TaskStatus.WAITING_INPUT and task.waiting_reason == document:
                return task
            stored = self.context_memory.persist(document, purpose="loop-waiting-reason")
            stop_report = self._persist_stop_report(
                task,
                status=status,
                blocker_id=blocker_id,
                reason=reason,
                evidence_refs=evidence_refs,
                partial_artifact=partial_artifact,
            )
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"waiting:{task_id}:{status.value}:{task.task_revision}",
                command_type="loop.task.wait",
                event_type="loop.task-waiting",
                payload={
                    "schema": "SITINA_LOOP_TASK_WAITING_V1",
                    "task_id": task_id,
                    "status": status.value,
                    "waiting_ref": stored.reference_id,
                    "waiting_hash": stored.content_hash,
                    "stop_report_ref": stop_report.reference_id,
                    "stop_report_hash": stop_report.content_hash,
                },
                proofs=(
                    stored.proof,
                    stop_report.proof,
                    *((partial_artifact.proof,) if partial_artifact is not None else ()),
                ),
            )
            return self.get_task(task_id)

    def dock_context_blocked(
        self,
        task_id: str,
        *,
        reason: str,
        capacity_identity: Mapping[str, Any],
        counting: Mapping[str, Any],
        required_source_refs: tuple[str, ...],
        expected_task_revision: int,
        expected_run_instance_id: str,
        expected_execution_epoch: int,
        expected_goal_version: int,
        expected_acceptance_version: int,
        expected_handled_input_seq: int,
        expected_artifact_ref: str,
        partial_artifact: StoredContent | None = None,
    ) -> TaskProjection:
        """Persist an R10 coverage/admission blocker without settling an attempt.

        The exact task binding is mandatory so an old context plan cannot dock a
        newer goal.  CONTEXT_BLOCKED is non-terminal and deliberately separate
        from the R11 no-progress accounting path.
        """

        if not reason.strip() or not required_source_refs:
            raise ValueError("context blocker requires a reason and affected source refs")
        if tuple(sorted(set(required_source_refs))) != required_source_refs:
            raise ValueError("context blocker source refs must be sorted and unique")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.is_terminal:
                raise TaskConflict("terminal task cannot enter CONTEXT_BLOCKED")
            if task.control_intent is not ControlIntent.RUN:
                raise TaskConflict("pause or cancel intent cannot be overwritten by CONTEXT_BLOCKED")
            if task.active_operations or task.unresolved_effects:
                raise TaskConflict("active or unknown operation prevents CONTEXT_BLOCKED")
            expected = {
                "task_revision": expected_task_revision,
                "run_instance_id": expected_run_instance_id,
                "execution_epoch": expected_execution_epoch,
                "goal_version": expected_goal_version,
                "acceptance_version": expected_acceptance_version,
                "handled_input_seq": expected_handled_input_seq,
                "artifact_ref": expected_artifact_ref,
            }
            actual = {
                "task_revision": task.task_revision,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
            }
            changed = [name for name in expected if expected[name] != actual[name]]
            if changed or task.received_input_seq != task.handled_input_seq:
                if task.received_input_seq != task.handled_input_seq:
                    changed.append("unhandled_input")
                raise TaskConflict("context blocker binding changed before commit: " + ", ".join(changed))
            document = {
                "schema": "SITINA_LOOP_CONTEXT_BLOCKER_V1",
                "task_id": task_id,
                "reason": reason,
                "capacity_identity": dict(capacity_identity),
                "counting": dict(counting),
                "required_source_refs": list(required_source_refs),
                "task_revision": task.task_revision,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
                "no_progress_incremented": False,
                "provider_effect_created": False,
            }
            stored = self.context_memory.persist(document, purpose="loop-context-blocker")
            stop_report = self._persist_stop_report(
                task,
                status=TaskStatus.CONTEXT_BLOCKED,
                blocker_id="context-admission-blocked",
                reason=reason,
                evidence_refs=required_source_refs,
                partial_artifact=partial_artifact,
            )
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"context-blocked:{task_id}:{task.task_revision}",
                command_type="loop.task.context-block",
                event_type="loop.task-context-blocked",
                payload={
                    "schema": "SITINA_LOOP_TASK_CONTEXT_BLOCKED_V1",
                    "task_id": task_id,
                    "status": TaskStatus.CONTEXT_BLOCKED.value,
                    "waiting_ref": stored.reference_id,
                    "waiting_hash": stored.content_hash,
                    "bound_run_instance_id": task.run_instance_id,
                    "bound_execution_epoch": task.execution_epoch,
                    "bound_goal_version": task.goal_version,
                    "bound_acceptance_version": task.acceptance_version,
                    "bound_handled_input_seq": task.handled_input_seq,
                    "bound_artifact_ref": task.artifact_ref,
                    "stop_report_ref": stop_report.reference_id,
                    "stop_report_hash": stop_report.content_hash,
                },
                proofs=(
                    stored.proof,
                    stop_report.proof,
                    *((partial_artifact.proof,) if partial_artifact is not None else ()),
                ),
            )
            return self.get_task(task_id)

    def dock_paused(
        self,
        task_id: str,
        *,
        reason: str = "user pause retained at a safe scheduler boundary",
        partial_artifact: StoredContent | None = None,
    ) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.control_intent is not ControlIntent.PAUSE or task.active_operations or task.unresolved_effects:
                raise TaskConflict("pause dock requires PAUSE control with no active or unknown effect")
            stop_report = self._persist_stop_report(
                task,
                status=TaskStatus.PAUSED,
                blocker_id="user-paused",
                reason=reason,
                evidence_refs=(),
                partial_artifact=partial_artifact,
            )
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"paused:{task_id}:{task.task_revision}",
                command_type="loop.task.pause-dock",
                event_type="loop.task-paused",
                payload={
                    "schema": "SITINA_LOOP_TASK_PAUSED_V1",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "status": TaskStatus.PAUSED.value,
                    "stop_report_ref": stop_report.reference_id,
                    "stop_report_hash": stop_report.content_hash,
                },
                proofs=(
                    stop_report.proof,
                    *((partial_artifact.proof,) if partial_artifact is not None else ()),
                ),
            )
            return self.get_task(task_id)

    def dock_recovery_blocked(
        self,
        task_id: str,
        *,
        blocker_id: str,
        reason: str,
        evidence_refs: tuple[str, ...],
        partial_artifact: StoredContent | None = None,
    ) -> TaskProjection:
        """Dock without releasing UNKNOWN writes or their owned resources."""

        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.active_operations:
                raise TaskConflict("active operation must return before recovery-blocked docking")
            if not task.unresolved_effects and task.recovery_state == "READY_NEW_TASK":
                raise TaskConflict("recovery-blocked dock requires an unknown effect or recovery blocker")
            stop_report = self._persist_stop_report(
                task,
                status=TaskStatus.RECOVERY_BLOCKED,
                blocker_id=blocker_id,
                reason=reason,
                evidence_refs=evidence_refs,
                partial_artifact=partial_artifact,
            )
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"recovery-blocked:{task_id}:{task.task_revision}",
                command_type="loop.task.recovery-block",
                event_type="loop.task-recovery-blocked",
                payload={
                    "schema": "SITINA_LOOP_TASK_RECOVERY_BLOCKED_V1",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "task_id": task_id,
                    "status": TaskStatus.RECOVERY_BLOCKED.value,
                    "stop_report_ref": stop_report.reference_id,
                    "stop_report_hash": stop_report.content_hash,
                    "retained_resources": list(task.owned_resources),
                    "unknown_effect_operation_ids": sorted(
                        item.operation_id for item in task.unresolved_effects
                    ),
                },
                proofs=(
                    stop_report.proof,
                    *((partial_artifact.proof,) if partial_artifact is not None else ()),
                ),
            )
            return self.get_task(task_id)

    def task_ids(self) -> tuple[str, ...]:
        return self.store.task_ids()

    def _advance_task_cache(
        self, event: EventEnvelope, *, copy_before_apply: bool = True,
    ) -> None:
        """Apply one newly verified Journal event to the process-local projection.

        Journal/CAS remain authoritative. The cache only avoids decrypting every
        old body for status, control, and binding reads; callers always receive
        detached copies and each newly referenced body is still hash-verified.
        """

        task_id = event.stream_id.removeprefix("loop-task/")
        task = self._task_cache.get(task_id)
        if task is None:
            return
        if event.stream_version != task.task_revision + 1 or event.payload.get("spec_version") != SPEC_VERSION:
            self._task_cache.pop(task_id, None)
            return
        if copy_before_apply:
            task = copy.deepcopy(task)
        # Cold replay owns an unpublished projection. Detach each event's
        # input instead of repeatedly copying its whole growing history.
        value = event.payload if copy_before_apply else copy.deepcopy(event.payload)
        try:
            if event.event_type == "loop.input-received":
                sequence = int(value["input_seq"])
                if sequence != task.received_input_seq + 1:
                    raise PersistenceFenced("task input sequence is discontinuous")
                task.inputs = (*task.inputs, InputRecord(
                    str(value["input_id"]),
                    sequence,
                    InputKind(str(value["kind"])),
                    str(value["body_ref"]),
                    str(value["body_hash"]),
                    str(value["received_at"]),
                ))
                task.received_input_seq = sequence
                task.control_intent = ControlIntent(str(value["control_intent"]))
                task.status = TaskStatus(str(value["status"]))
            elif event.event_type == "loop.input-handled":
                was_context_blocked = task.status is TaskStatus.CONTEXT_BLOCKED
                sequence = int(value["handled_input_seq"])
                if sequence != task.handled_input_seq + 1 or sequence > task.received_input_seq:
                    raise PersistenceFenced("task handled-input sequence is discontinuous")
                task.handled_input_seq = sequence
                task.goal_version = int(value["goal_version"])
                task.acceptance_version = int(value["acceptance_version"])
                task.criteria_lineage_version = int(
                    value.get("criteria_lineage_version", task.criteria_lineage_version)
                )
                task.control_intent = ControlIntent(str(value["control_intent"]))
                task.status = TaskStatus(str(value["status"]))
                if was_context_blocked or any(
                    item.sequence == sequence and item.kind is InputKind.CLARIFICATION
                    for item in task.inputs
                ):
                    task.waiting_reason = None
            elif event.event_type == "loop.task-memory-view-revalidated":
                document = self.context_memory.read(
                    str(value["revalidation_ref"]), expected_hash=str(value["revalidation_hash"])
                )
                if (
                    document.get("schema") != "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1"
                    or document.get("task_id") != task_id
                    or document.get("original_memory_view_ref") != task.memory_view_ref
                    or document.get("original_memory_view_hash") != task.memory_view_hash
                    or int(document.get("bound_task_revision", -1)) != task.task_revision
                    or str(document.get("run_instance_id") or "") != task.run_instance_id
                    or int(document.get("execution_epoch", -1)) != task.execution_epoch
                    or int(document.get("goal_version", -1)) != task.goal_version
                    or int(document.get("acceptance_version", -1)) != task.acceptance_version
                    or int(document.get("handled_input_seq", -1)) != task.handled_input_seq
                ):
                    raise PersistenceFenced("memory view revalidation binding is stale")
                correction_seq = int(document.get("correction_input_seq", -1))
                if correction_seq > task.handled_input_seq or not any(
                    item.sequence == correction_seq and item.kind is InputKind.CORRECTION
                    for item in task.inputs
                ):
                    raise PersistenceFenced("memory view revalidation is not bound to a persisted correction")
                exclusions = document.get("excluded_entries", [])
                if not isinstance(exclusions, list) or any(not isinstance(item, Mapping) for item in exclusions):
                    raise PersistenceFenced("memory view revalidation exclusions are malformed")
                prior_input_seq = task.memory_view_revalidation_input_seq
                if prior_input_seq is not None and correction_seq <= int(prior_input_seq):
                    raise PersistenceFenced("memory view revalidation correction sequence is not advancing")
                task.memory_view_revalidation_ref = str(value["revalidation_ref"])
                task.memory_view_revalidation_hash = str(value["revalidation_hash"])
                task.memory_view_revalidation_input_seq = correction_seq
                prior_exclusions = {
                    (str(item.get("memory_id") or ""), int(item.get("expected_version", -1))): dict(item)
                    for item in task.memory_view_exclusions
                    if isinstance(item, Mapping)
                }
                prior_exclusions.update({
                    (str(item.get("memory_id") or ""), int(item.get("expected_version", -1))): dict(item)
                    for item in exclusions
                })
                task.memory_view_exclusions = tuple(
                    prior_exclusions[key] for key in sorted(prior_exclusions)
                )
                # These are historical facts, but no longer current evidence
                # after a goal/acceptance-changing correction.  Their Journal
                # events remain available for history and terminal closure.
                task.acceptances.clear()
            elif event.event_type == "loop.attempt-planned":
                document = self.context_memory.read(
                    str(value["plan_ref"]), expected_hash=str(value["plan_hash"])
                )
                attempt_id = str(value["attempt_id"])
                if (
                    document.get("schema") != "SITINA_LOOP_ATTEMPT_PLAN_V1"
                    or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or document.get("attempt_id") != attempt_id
                    or document.get("task_id") != task_id
                    or attempt_id in task.attempt_plans
                ):
                    raise PersistenceFenced("attempt plan event is invalid or duplicated")
                expected_binding = {
                    "task_id": task_id,
                    "session_id": task.session_id,
                    "run_instance_id": task.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "planned_from_task_revision": task.task_revision,
                    "goal_version": task.goal_version,
                    "acceptance_version": task.acceptance_version,
                    "criteria_lineage_version": task.criteria_lineage_version,
                    "handled_input_seq": task.handled_input_seq,
                    "artifact_ref": task.artifact_ref,
                    "environment_ref": task.environment_ref,
                    "capability_snapshot_id": task.capability_snapshot_id,
                }
                if any(document.get(key) != expected for key, expected in expected_binding.items()):
                    raise PersistenceFenced("attempt plan has a stale task binding")
                settled_ids = {
                    str(item.get("attempt_id"))
                    for item in task.attempt_settlements
                    if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                }
                if set(task.attempt_plans) - settled_ids:
                    raise PersistenceFenced("task stream opens a second investigation attempt")
                task.attempt_plans[attempt_id] = dict(document)
            elif event.event_type == "loop.attempt-checkpointed":
                document = self.context_memory.read(
                    str(value["checkpoint_ref"]), expected_hash=str(value["checkpoint_hash"])
                )
                attempt_id = str(value["attempt_id"])
                if (
                    document.get("schema") != "SITINA_LOOP_ATTEMPT_CHECKPOINT_V1"
                    or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or document.get("attempt_id") != attempt_id
                    or document.get("checkpoint_id") != value.get("checkpoint_id")
                    or document.get("task_id") != task_id
                    or attempt_id not in task.attempt_plans
                    or any(
                        item.get("attempt_id") == attempt_id
                        and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                        for item in task.attempt_settlements
                    )
                ):
                    raise PersistenceFenced("attempt checkpoint is not attached to one open plan")
                if any(
                    item.get("checkpoint_id") == document.get("checkpoint_id")
                    or (
                        item.get("attempt_id") == attempt_id
                        and int(item.get("segment_index") or 0)
                        == int(document.get("segment_index") or 0)
                    )
                    for item in task.attempt_checkpoints
                ):
                    raise PersistenceFenced("attempt checkpoint identity or segment is duplicated")
                task.attempt_checkpoints = (*task.attempt_checkpoints, dict(document))
            elif event.event_type == "loop.main-result-checkpointed":
                document = self.context_memory.read(
                    str(value["checkpoint_ref"]), expected_hash=str(value["checkpoint_hash"])
                )
                attempt_id = str(value["attempt_id"])
                if (
                    document.get("schema") != "SITINA_LOOP_MAIN_RESULT_CHECKPOINT_V1"
                    or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or document.get("task_id") != task_id
                    or document.get("attempt_id") != attempt_id
                    or document.get("checkpoint_id") != value.get("checkpoint_id")
                    or attempt_id not in task.attempt_plans
                    or any(
                        item.get("attempt_id") == attempt_id
                        and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                        for item in task.attempt_settlements
                    )
                ):
                    raise PersistenceFenced("main-result checkpoint is not attached to one open plan")
                binding = document.get("binding")
                if not isinstance(binding, Mapping) or any(
                    binding.get(key) != expected
                    for key, expected in {
                        "task_id": task_id,
                        "goal_version": task.goal_version,
                        "acceptance_version": task.acceptance_version,
                        "handled_input_seq": task.handled_input_seq,
                        "source_artifact_ref": task.artifact_ref,
                    }.items()
                ):
                    raise PersistenceFenced("main-result checkpoint binding is invalid")
                if any(
                    item.get("checkpoint_id") == document.get("checkpoint_id")
                    for item in task.main_result_checkpoints
                ):
                    raise PersistenceFenced("main-result checkpoint identity is duplicated")
                task.main_result_checkpoints = (*task.main_result_checkpoints, dict(document))
            elif event.event_type == "loop.operation-intent-recorded":
                operation_id = str(value["operation_id"])
                if operation_id in task.operations:
                    raise PersistenceFenced("operation identity appears more than once")
                intent_value = self.context_memory.read(str(value["intent_ref"]), expected_hash=str(value["intent_hash"]))
                if value.get("effect_evidence_ref") is not None:
                    if not value.get("effect_evidence_hash"):
                        raise PersistenceFenced("operation effect evidence hash is missing")
                    evidence = self.context_memory.read(
                        str(value["effect_evidence_ref"]),
                        expected_hash=str(value["effect_evidence_hash"]),
                    )
                    if evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1":
                        raise PersistenceFenced("operation effect evidence schema is invalid")
                task.operations[operation_id] = OperationRecord(
                    operation_id,
                    str(value["logical_operation_id"]),
                    str(value["attempt_id"]),
                    OperationMode(str(value["mode"])),
                    EffectStatus.INTENT_RECORDED,
                    str(value["intent_ref"]),
                    None,
                    tuple(str(item) for item in value["resources"]),
                    str(value["execution_segment_id"]),
                    int(value["bound_goal_version"]),
                    int(value["bound_acceptance_version"]),
                    int(value["bound_input_seq"]),
                    False,
                    str(value["business_attempt_id"])
                    if value.get("business_attempt_id") is not None
                    else None,
                    execution_owner=intent_value.get("execution_owner"),
                    agent_role=intent_value.get("agent_role"),
                    agent_instance_id=intent_value.get("agent_instance_id"),
                    business_action_key=intent_value.get("business_action_key"),
                    business_action_family=intent_value.get("business_action_family"),
                )
                if task.operations[operation_id].mode is OperationMode.WRITE:
                    task.owned_resources = tuple(
                        sorted(set(task.owned_resources).union(task.operations[operation_id].resources))
                    )
                if task.control_intent is ControlIntent.RUN:
                    task.status = TaskStatus.WAITING_OPERATION
            elif event.event_type == "loop.operation-precondition-changed":
                operation_id = str(value["operation_id"])
                task.operations[operation_id] = OperationRecord(
                    operation_id,
                    str(value["logical_operation_id"]),
                    str(value["attempt_id"]),
                    OperationMode(str(value["mode"])),
                    EffectStatus.PRECONDITION_CHANGED,
                    None,
                    None,
                    tuple(str(item) for item in value["resources"]),
                    str(value["execution_segment_id"]),
                    task.goal_version,
                    task.acceptance_version,
                    task.handled_input_seq,
                    False,
                    str(value["business_attempt_id"])
                    if value.get("business_attempt_id") is not None
                    else None,
                )
            elif event.event_type == "loop.operation-result-recorded":
                operation_id = str(value["operation_id"])
                prior = task.operations.get(operation_id)
                replacement = bool(value.get("recovery_replaces_unknown"))
                if prior is None or (
                    prior.effect_status is not EffectStatus.INTENT_RECORDED
                    and not (replacement and prior.unknown_effect)
                ):
                    raise PersistenceFenced("operation result has no active persisted intent")
                result_document = self.context_memory.read(
                    str(value["result_ref"]), expected_hash=str(value["result_hash"])
                )
                pre_dispatch_intent = None
                if (
                    prior.effect_status is EffectStatus.INTENT_RECORDED
                    and not prior.unknown_effect and not replacement
                    and value.get("unknown_effect") is False
                    and value.get("effect_status") == EffectStatus.FAILED.value
                    and has_no_effect_result_shape(result_document)
                    and prior.intent_ref is not None
                    and not self._operation_dispatch_started(task_id, operation_id)
                ):
                    intent_document = self.context_memory.read(prior.intent_ref)
                    if all(intent_document.get(key) == expected for key, expected in (
                        ("attempt_id", prior.attempt_id),
                        ("expected_goal_version", prior.bound_goal_version),
                        ("expected_acceptance_version", prior.bound_acceptance_version),
                        ("expected_handled_input_seq", prior.bound_input_seq),
                    )):
                        pre_dispatch_intent = intent_document
                task.operations[operation_id] = replace(
                    prior,
                    effect_status=EffectStatus(str(value["effect_status"])),
                    result_ref=str(value["result_ref"]),
                    unknown_effect=bool(value["unknown_effect"]),
                    telemetry=operation_agent_telemetry(
                        task_id=task_id,
                        operation_id=operation_id,
                        logical_operation_id=prior.logical_operation_id,
                        result_status=str(value["effect_status"]),
                        result_ref=str(value["result_ref"]),
                        result_document=result_document,
                        pre_dispatch_intent=pre_dispatch_intent,
                    ),
                    recovery_decision=(
                        str(value["recovery_decision"])
                        if value.get("recovery_decision") is not None
                        else prior.recovery_decision
                    ),
                )
                if not task.active_operations:
                    if task.unresolved_effects:
                        task.status = TaskStatus.WAITING_OPERATION
                    elif task.control_intent is ControlIntent.PAUSE:
                        task.status = TaskStatus.PAUSED
                    elif task.control_intent is ControlIntent.CANCEL:
                        task.status = TaskStatus.CANCELLING
                    else:
                        task.status = TaskStatus.RUNNABLE
            elif event.event_type == "loop.operation-recovery-decided":
                operation_id = str(value["operation_id"])
                prior = task.operations.get(operation_id)
                if prior is None:
                    raise PersistenceFenced("operation recovery decision has no operation")
                task.operations[operation_id] = replace(
                    prior,
                    recovery_decision=str(value["decision"]),
                )
            elif event.event_type in {"loop.operation-dispatch-started"}:
                operation_id = str(value["operation_id"])
                prior = task.operations.get(operation_id)
                telemetry = prior.telemetry if prior is not None else None
                metrics = telemetry.get("metrics") if isinstance(telemetry, Mapping) else None
                if (
                    isinstance(telemetry, Mapping) and telemetry.get("kind") == "unknown"
                    and isinstance(metrics, Mapping)
                    and type(metrics.get("logical_turn_count")) is int
                    and metrics["logical_turn_count"] == 0
                ):
                    # A later authenticated dispatch marker withdraws an earlier
                    # zero-round observation, including from an already hot cache.
                    telemetry = copy.deepcopy(dict(telemetry))
                    telemetry["metrics"]["logical_turn_count"] = None
                    telemetry["unknown_fields"] = sorted(
                        set(telemetry["unknown_fields"]) | {"metrics.logical_turn_count"}
                    )
                    task.operations[operation_id] = replace(prior, telemetry=telemetry)
            elif event.event_type == "loop.artifact-updated":
                if int(value["artifact_version"]) != task.artifact_version + 1:
                    raise PersistenceFenced("task artifact version is discontinuous")
                if (
                    ("run_instance_id" in value or "execution_epoch" in value)
                    and (
                        value.get("run_instance_id") != task.run_instance_id
                        or int(value.get("execution_epoch", -1)) != task.execution_epoch
                    )
                ):
                    raise PersistenceFenced("artifact update publisher identity is not current")
                if "artifact_hash" in value:
                    self.context_memory.read(
                        str(value["artifact_ref"]), expected_hash=str(value["artifact_hash"])
                    )
                task.artifact_version = int(value["artifact_version"])
                task.artifact_ref = str(value["artifact_ref"])
                task.acceptance_version = int(value["acceptance_version"])
                task.acceptances.clear()
            elif event.event_type == "loop.review-findings-recorded":
                document = self.context_memory.read(
                    str(value["review_ref"]), expected_hash=str(value["review_hash"])
                )
                binding = {
                    "bound_task_revision": task.task_revision,
                    "bound_run_instance_id": task.run_instance_id,
                    "bound_execution_epoch": task.execution_epoch,
                    "bound_goal_version": task.goal_version,
                    "bound_acceptance_version": task.acceptance_version,
                    "bound_criteria_lineage_version": task.criteria_lineage_version,
                    "bound_handled_input_seq": task.handled_input_seq,
                    "bound_artifact_ref": task.artifact_ref,
                }
                if (
                    document.get("schema") != "SITINA_LOOP_REVIEW_RECORD_V2"
                    or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or document.get("task_id") != task_id
                    or any(document.get(key) != expected for key, expected in binding.items())
                ):
                    raise PersistenceFenced("review findings record has a stale task binding")
                review = document.get("review")
                if not isinstance(review, Mapping) or review.get("schema") != "SITINA_LOOP_REVIEW_V2":
                    raise PersistenceFenced("review findings record is invalid")
                issues = dict(task.review_issues)
                for finding in review.get("findings", ()):
                    if not isinstance(finding, Mapping):
                        raise PersistenceFenced("review finding is invalid")
                    issue_id = str(finding.get("stable_issue_id") or "")
                    prior = issues.get(issue_id)
                    identity = {
                        "criteria_lineage_id": str(finding.get("criteria_lineage_id") or ""),
                        "acceptance_item_id": str(review.get("acceptance_item_id") or ""),
                        "review_subject_lineage": str(review.get("review_subject_lineage") or ""),
                        "rule_id": str(finding.get("rule_id") or ""),
                        "locus_id": str(finding.get("locus_id") or ""),
                        "object_id": str(finding.get("object_id") or ""),
                        "issue_slot_id": str(finding.get("issue_slot_id") or ""),
                        "finding_code": str(finding.get("finding_code") or ""),
                    }
                    expected_issue_id = stable_review_issue_id(
                        criteria_lineage_id=identity["criteria_lineage_id"],
                        acceptance_item_id=identity["acceptance_item_id"],
                        review_subject_lineage_id=identity["review_subject_lineage"],
                        rule_id=identity["rule_id"],
                        locus_id=identity["locus_id"],
                        object_id=identity["object_id"],
                        issue_slot_id=identity["issue_slot_id"],
                        finding_code=identity["finding_code"],
                    )
                    if issue_id != expected_issue_id or (
                        prior is not None
                        and any(prior.get(key) != expected for key, expected in identity.items())
                    ):
                        raise PersistenceFenced("review issue identity changed during replay")
                    disposition = str(finding.get("disposition") or "")
                    if disposition == "OPEN":
                        count = int((prior or {}).get("disagreement_count", 0)) + 1
                        status = "OPEN"
                    elif disposition in {"RESOLVED", "NOT_APPLICABLE"}:
                        if prior is None or prior.get("status") != "OPEN":
                            raise PersistenceFenced("review closes an issue that is not open")
                        count = int(prior.get("disagreement_count", 0))
                        status = disposition
                    else:
                        raise PersistenceFenced("review issue disposition is invalid")
                    prior_fingerprints = tuple(str(item) for item in (prior or {}).get("evidence_fingerprints", ()))
                    current_fingerprints = tuple(str(item) for item in finding.get("evidence_fingerprints", ()))
                    issues[issue_id] = {
                        **identity,
                        "stable_issue_id": issue_id,
                        "status": status,
                        "disagreement_count": count,
                        "opened_artifact_ref": (prior or {}).get(
                            "opened_artifact_ref", review.get("observed_artifact_ref")
                        ),
                        "last_observed_artifact_ref": review.get("observed_artifact_ref"),
                        "object_fingerprint": finding.get("object_fingerprint"),
                        "evidence_refs": list(dict.fromkeys(
                            (*((prior or {}).get("evidence_refs", ())), *finding.get("evidence_refs", ()))
                        )),
                        "evidence_fingerprints": list(dict.fromkeys((*prior_fingerprints, *current_fingerprints))),
                        "last_summary": str(finding.get("summary") or ""),
                    }
                task.review_issues = issues
            elif event.event_type == "loop.review-repair-recorded":
                document = self.context_memory.read(
                    str(value["repair_ref"]), expected_hash=str(value["repair_hash"])
                )
                if (
                    document.get("schema") not in {"SITINA_LOOP_REVIEW_REPAIR_V2", "SITINA_LOOP_REVIEW_REPAIR_V3"}
                    or document.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or document.get("task_id") != task_id
                    or document.get("artifact_ref") != task.artifact_ref
                    or document.get("criteria_lineage_id")
                    != f"criteria:{task_id}:{task.criteria_lineage_version}"
                ):
                    raise PersistenceFenced("review repair record has a stale binding")
                if document["schema"] == "SITINA_LOOP_REVIEW_REPAIR_V3":
                    try:
                        if document.get("failure_origin") != "MODEL_RESPONSE":
                            raise TaskConflict("non-model failure cannot consume repair allowance")
                        self._validate_review_failure_evidence(
                            task, document["attempt_id"], document["failure_evidence"],
                        )
                    except (TaskConflict, KeyError, TypeError, ValueError) as error:
                        raise PersistenceFenced("review failure evidence is invalid") from error
                if any(
                    item.get("review_subject_lineage") == document.get("review_subject_lineage")
                    and item.get("artifact_ref") == document.get("artifact_ref")
                    and item.get("repair_index") == document.get("repair_index")
                    for item in task.review_repairs
                ):
                    raise PersistenceFenced("review repair record is duplicated")
                indices = [row["repair_index"] for row in task.review_repairs
                           if row.get("artifact_ref") == task.artifact_ref
                           and row.get("review_subject_lineage") == document.get("review_subject_lineage")]
                if (type(document.get("repair_index")) is not int
                        or document["repair_index"] != max(indices, default=0) + 1
                        or document["repair_index"] > task.review_repair_limit(task.artifact_ref)):
                    raise PersistenceFenced("review repair exceeds its replayed finite authorization")
                task.review_repairs = (*task.review_repairs, dict(document))
            elif event.event_type == "loop.attempt-settled":
                document = self.context_memory.read(
                    str(value["settlement_ref"]), expected_hash=str(value["settlement_hash"])
                )
                if document.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION:
                    attempt_id = str(document.get("attempt_id") or "")
                    plan = task.attempt_plans.get(attempt_id)
                    if (
                        document.get("schema") != "SITINA_LOOP_ATTEMPT_SETTLEMENT_V1"
                        or document.get("task_id") != task_id
                        or attempt_id != str(value.get("attempt_id") or "")
                        or document.get("blocker_id") != value.get("blocker_id")
                        or plan is None
                        or any(
                            item.get("attempt_id") == attempt_id
                            and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                            for item in task.attempt_settlements
                        )
                    ):
                        raise PersistenceFenced("new termination settlement has no unique open plan")
                    count_effect = str(document.get("count_effect") or "")
                    relevant_progress = bool(document.get("relevant_progress"))
                    if (
                        count_effect not in COUNT_EFFECTS
                        or (count_effect == "PROGRESSED" and not relevant_progress)
                        or (count_effect != "PROGRESSED" and relevant_progress)
                        or document.get("lineage_id") != plan.get("lineage_id")
                        or document.get("acceptance_item_id") != plan.get("acceptance_item_id")
                        or document.get("registered_blocker_id") != plan.get("blocker_id")
                        or int(document.get("goal_version", -1)) != int(plan.get("goal_version", -2))
                        or int(document.get("acceptance_version", -1))
                        != int(plan.get("acceptance_version", -2))
                        or int(document.get("criteria_lineage_version", 1))
                        != int(plan.get("criteria_lineage_version", 1))
                        or int(document.get("handled_input_seq", -1))
                        != int(plan.get("handled_input_seq", -2))
                        or document.get("planned_artifact_ref") != plan.get("artifact_ref")
                    ):
                        raise PersistenceFenced("new termination settlement contradicts its committed plan")
                task.attempt_settlements = (*task.attempt_settlements, dict(document))
            elif event.event_type == "loop.work-plan-updated":
                from .model import validate_work_plan
                if value.get("plan_ref") not in event.object_refs:
                    raise PersistenceFenced("work plan lacks a committed content proof")
                record = self.context_memory.read(str(value["plan_ref"]), expected_hash=str(value["plan_hash"]))
                previous = task.current_work_plan
                try:
                    validate_work_plan(record, task_id=task_id, goal_version=task.goal_version,
                                       previous_revision=previous["revision"] if previous else 0)
                    if record["goal_version"] != value.get("goal_version") or record["revision"] != value.get("revision"):
                        raise ValueError("work plan event binding differs")
                    self._validate_work_plan_evidence(task, record)
                except (ValueError, TaskConflict) as error:
                    raise PersistenceFenced("work plan record is not valid for its task version") from error
                task.work_plan_record = record
                task.work_plan_source_ref = str(value["plan_ref"])
            elif event.event_type == "loop.child-delegation-admitted":
                contract = self.context_memory.read(
                    str(value["contract_ref"]), expected_hash=str(value["contract_hash"])
                )
                delegation_id = str(value.get("delegation_id") or "")
                if (
                    contract.get("schema") != CHILD_RUNTIME_SCHEMA
                    or contract.get("delegation_contract_version") != DELEGATION_CONTRACT_VERSION
                    or contract.get("task_id") != task_id
                    or contract.get("delegation_id") != delegation_id
                    or delegation_id in task.child_delegations
                ):
                    raise PersistenceFenced("child admission contract is invalid or duplicated")
                binding = contract.get("parent_binding")
                expected_binding = {
                    "task_id": task_id,
                    "task_revision": task.task_revision,
                    "run_instance_id": task.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "goal_version": task.goal_version,
                    "acceptance_version": task.acceptance_version,
                    "received_input_seq": task.received_input_seq,
                    "handled_input_seq": task.handled_input_seq,
                    "artifact_ref": task.artifact_ref,
                    "control_intent": ControlIntent.RUN.value,
                }
                if not isinstance(binding, Mapping) or any(
                    binding.get(key) != expected for key, expected in expected_binding.items()
                ):
                    raise PersistenceFenced("child admission binding is stale")
                manifest = contract.get("source_manifest")
                if not isinstance(manifest, list) or (not manifest and contract.get("execution_mode") != "task"):
                    raise PersistenceFenced("child admission has no source manifest")
                projection = {
                    "schema": CHILD_RUNTIME_SCHEMA,
                    "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                    "delegation_id": delegation_id,
                    "child_task_id": str(contract["child_task_id"]),
                    "parent_task_id": task_id,
                    "problem_id": str(contract["problem_id"]),
                    "parent_attempt_id": (
                        str(contract["parent_attempt_id"])
                        if contract.get("parent_attempt_id") else None
                    ),
                    "objective": str(contract.get("objective") or ""),
                    "generation": int(contract["generation"]),
                    "status": "ADMITTED",
                    "required": bool(contract.get("required", True)),
                    "unknown_effect": False,
                    "applicability": "CURRENT_PARENT_INPUT",
                    "parent_binding": dict(binding),
                    "source_manifest": [dict(item) for item in manifest],
                    "source_ids": [str(item.get("source_id")) for item in manifest],
                    "request_fingerprint": str(contract.get("request_fingerprint") or ""),
                    "result_ref": None,
                    "settlement_ref": None,
                    "evidence_fingerprint": None,
                    "physical_send_state": "NOT_STARTED",
                    "continuation_pending": False,
                    "prior_delegation_id": contract.get("prior_delegation_id"),
                    "prior_evidence_fingerprint": contract.get("prior_evidence_fingerprint"),
                    "inherited_evidence_refs": list(contract.get("inherited_evidence_refs", ())),
                    "inherited_attempt_ids": list(contract.get("inherited_attempt_ids", ())),
                    "inherited_review_issue_ids": list(contract.get("inherited_review_issue_ids", ())),
                    "execution_mode": str(contract.get("execution_mode") or "readonly"),
                    "resources": list(contract.get("resources", ())),
                    "read_resources": list(contract.get("read_resources", ())),
                    "dependencies": list(contract.get("dependencies", ())),
                    "permissions": list(contract.get("permissions", ("read",))),
                    "required_tools": list(contract.get("required_tools", ())),
                    "completion_condition": str(contract.get("completion_condition") or ""),
                    "checkpoint_ref": contract.get("checkpoint_ref"),
                    "change_reason": str(contract.get("change_reason") or ""),
                    "failure_history": list(contract.get("failure_history", ())),
                }
                task.child_delegations[delegation_id] = projection
            elif event.event_type == "loop.child-delegation-checkpointed":
                delegation_id = str(value["delegation_id"])
                prior = task.child_delegations.get(delegation_id)
                if prior is None:
                    raise PersistenceFenced("checkpoint has no child")
                checkpoint = self.context_memory.read(str(value["checkpoint_ref"]), expected_hash=str(value["checkpoint_hash"]))
                if checkpoint.get("delegation_id") != delegation_id or checkpoint.get("task_id") != task_id:
                    raise PersistenceFenced("checkpoint child identity mismatch")
                updated = dict(prior)
                updated["checkpoint_ref"] = str(value["checkpoint_ref"])
                updated["progress_reason"] = str(checkpoint.get("reason") or "progress saved")
                if checkpoint.get("transition"):
                    updated["change_reason"] = str(checkpoint["transition"]["reason"])
                if checkpoint.get("transition"):
                    updated["pending_transition"] = dict(checkpoint["transition"])
                task.child_delegations[delegation_id] = updated
            elif event.event_type == "loop.child-delegation-dispatch-started":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or prior.get("status") not in {"ADMITTED", "DISPATCH_PENDING"}:
                    raise PersistenceFenced("child dispatch has no admitted pending child")
                if any(
                    prior.get(key) != expected
                    for key, expected in {
                        "parent_task_id": task_id,
                        "delegation_id": delegation_id,
                    }.items()
                ):
                    raise PersistenceFenced("child dispatch identity differs from admission")
                updated = dict(prior)
                updated.update({
                    "status": "RUNNING",
                    "physical_send_state": str(value.get("physical_send_state") or "NOT_STARTED"),
                    "dispatch_epoch": int(value.get("dispatch_epoch", 1)),
                    "executor_slot": str(value.get("executor_slot") or "readonly-slot-1"),
                })
                task.child_delegations[delegation_id] = updated
                if (
                    task.control_intent is ControlIntent.RUN
                    and task.received_input_seq == task.handled_input_seq
                    and all(
                        item.get("status") in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}
                        and not item.get("unknown_effect")
                        for item in task.child_delegations.values()
                    )
                ):
                    task.status = TaskStatus.RUNNABLE
                    task.waiting_reason = None
            elif event.event_type == "loop.child-delegation-result-recorded":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or prior.get("status") not in {"RUNNING", "CANCEL_REQUESTED", "DISPATCH_PENDING"}:
                    raise PersistenceFenced("child result has no active child")
                result = self.context_memory.read(
                    str(value["result_ref"]), expected_hash=str(value["result_hash"])
                )
                if (
                    result.get("schema") != CHILD_RUNTIME_RESULT_SCHEMA
                    or result.get("delegation_contract_version") != DELEGATION_CONTRACT_VERSION
                    or result.get("delegation_id") != delegation_id
                    or result.get("approves_parent") is not False
                ):
                    raise PersistenceFenced("child result schema or approval flag is invalid")
                bound = result.get("parent_binding")
                original = prior.get("parent_binding") or {}
                if not isinstance(bound, Mapping) or dict(bound) != dict(original):
                    raise PersistenceFenced("child result rewrote its original parent binding")
                current = {
                    "task_id": task_id,
                    "run_instance_id": task.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "goal_version": task.goal_version,
                    "acceptance_version": task.acceptance_version,
                    "received_input_seq": task.received_input_seq,
                    "handled_input_seq": task.handled_input_seq,
                    "artifact_ref": task.artifact_ref,
                    "control_intent": task.control_intent.value,
                }
                applicability = "CURRENT_PARENT_INPUT" if all(
                    bound.get(key) == expected for key, expected in current.items()
                ) else "LATE_EVIDENCE_ONLY"
                updated = dict(prior)
                updated.update({
                    "status": "RESULT_PERSISTED",
                    "result_ref": str(value["result_ref"]),
                    "result_hash": str(value["result_hash"]),
                    "physical_send_state": str(value.get("physical_send_state") or "UNKNOWN"),
                    "applicability": applicability,
                    "evidence_fingerprint": str(
                        value.get("evidence_fingerprint")
                        or result.get("evidence_fingerprint")
                        or ""
                    ) or None,
                    "continuation_pending": True,
                    "unknown_effect": str(value.get("physical_send_state") or "UNKNOWN") == "UNKNOWN",
                })
                if result.get("status") in {"FAILED", "REJECTED"}:
                    history = list(prior.get("failure_history", ()))
                    history.append({"generation": prior["generation"], "result_ref": str(value["result_ref"]),
                                    "error_type": result.get("error_type"), "error_message": result.get("error_message"),
                                    "summary": result.get("summary")})
                    updated["failure_history"] = history
                if prior.get("authority_revoked"):
                    updated["applicability"] = "LATE_EVIDENCE_ONLY"
                task.child_delegations[delegation_id] = updated
            elif event.event_type == "loop.child-delegation-cancel-requested":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or prior.get("status") in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                    raise PersistenceFenced("child cancel has no active child")
                updated = dict(prior)
                updated["status"] = "CANCEL_REQUESTED"
                updated["authority_revoked"] = True
                updated["cancel_reason"] = str(value.get("reason") or "parent control changed")
                task.child_delegations[delegation_id] = updated
            elif event.event_type == "loop.child-delegation-settled":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or prior.get("status") in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                    raise PersistenceFenced("child settlement is duplicated or unknown")
                settlement = self.context_memory.read(
                    str(value["settlement_ref"]), expected_hash=str(value["settlement_hash"])
                )
                status = str(settlement.get("status") or value.get("status") or "")
                if status not in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                    raise PersistenceFenced("child settlement status is invalid")
                if status == "HANDED_OFF":
                    raise PersistenceFenced("T5A handoff settlement is unsupported")
                if status == "HANDED_OFF" and not str(settlement.get("handoff_receipt_ref") or "").strip():
                    raise PersistenceFenced("child handoff settlement has no receipt")
                if status == "HANDED_OFF":
                    try:
                        handoff = self.context_memory.read(str(settlement["handoff_receipt_ref"]))
                    except BaseException as error:
                        raise PersistenceFenced("child handoff receipt is not readable") from error
                    if (
                        handoff.get("schema") != "SITINA_LOOP_CHILD_HANDOFF_RECEIPT_V1"
                        or handoff.get("task_id") != task_id
                        or handoff.get("delegation_id") != delegation_id
                        or handoff.get("status") != "ACCEPTED"
                        or not str(handoff.get("receiver_id") or "").strip()
                        or settlement.get("handoff_receipt_hash")
                        != hashlib.sha256(canonical_json_bytes(handoff)).hexdigest()
                    ):
                        raise PersistenceFenced("child handoff receipt is not a trusted accepted transfer")
                updated = dict(prior)
                updated.update({
                    "status": status,
                    "settlement_ref": str(value["settlement_ref"]),
                    "settlement_hash": str(value["settlement_hash"]),
                    "unknown_effect": bool(settlement.get("unknown_effect", False)),
                    "applicability": str(settlement.get("applicability") or prior.get("applicability") or "CURRENT_PARENT_INPUT"),
                    "continuation_pending": False,
                })
                task.child_delegations[delegation_id] = updated
                # A child settlement is also the durable wake-up boundary for
                # a parent that yielded with no provider operation of its
                # own.  Keep the parent runnable so the next business cycle
                # can consume the persisted child result without issuing a
                # duplicate child Provider call.
                if (
                    status in {"SETTLED", "CANCELLED_VERIFIED"}
                    and task.control_intent is ControlIntent.RUN
                    and task.received_input_seq == task.handled_input_seq
                    and not task.active_operations
                    and not task.unresolved_effects
                ):
                    task.status = TaskStatus.RUNNABLE
            elif event.event_type == "loop.child-delegation-applicability-updated":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or not prior.get("result_ref"):
                    raise PersistenceFenced("child applicability has no persisted result")
                ref = str(value.get("applicability_ref") or "")
                content_hash = str(value.get("applicability_hash") or "")
                if not ref or not content_hash:
                    raise PersistenceFenced("child applicability lacks proof-bound evidence")
                document = self.context_memory.read(ref, expected_hash=content_hash)
                if (
                    document.get("schema") != "SITINA_LOOP_CHILD_APPLICABILITY_V1"
                    or document.get("task_id") != task_id
                    or document.get("delegation_id") != delegation_id
                    or document.get("result_ref") != prior.get("result_ref")
                    or document.get("applicability") != value.get("applicability")
                ):
                    raise PersistenceFenced("child applicability evidence is not bound to its result")
                updated = dict(prior)
                updated.update({
                    "applicability": str(value["applicability"]),
                    "applicability_ref": ref,
                    "applicability_hash": content_hash,
                })
                task.child_delegations[delegation_id] = updated
            elif event.event_type == "loop.child-delegation-recovery-blocked":
                delegation_id = str(value.get("delegation_id") or "")
                prior = task.child_delegations.get(delegation_id)
                if prior is None or prior.get("status") in {"SETTLED", "CANCELLED_VERIFIED"}:
                    raise PersistenceFenced("child recovery block has no active responsibility")
                ref = str(value.get("recovery_ref") or "")
                content_hash = str(value.get("recovery_hash") or "")
                document = self.context_memory.read(ref, expected_hash=content_hash)
                if (
                    document.get("schema") != "SITINA_LOOP_CHILD_RECOVERY_BLOCKED_V1"
                    or document.get("task_id") != task_id
                    or document.get("delegation_id") != delegation_id
                    or document.get("status") != "RECOVERY_BLOCKED"
                ):
                    raise PersistenceFenced("child recovery block evidence is invalid")
                updated = dict(prior)
                updated.update({
                    "status": "RECOVERY_BLOCKED",
                    "unknown_effect": bool(document.get("unknown_effect", value.get("unknown_effect", True))),
                    "recovery_ref": ref,
                    "recovery_hash": content_hash,
                    "blocker_id": str(document.get("blocker_id") or value.get("blocker_id") or ""),
                    "recovery_reason": str(document.get("reason") or ""),
                    "continuation_pending": True,
                })
                task.child_delegations[delegation_id] = updated
            elif event.event_type == "loop.native-execution-wait-updated":
                document = self.context_memory.read(
                    str(value["waiting_ref"]), expected_hash=str(value["waiting_hash"]))
                state = document.get("state")
                expected_status = {"WAITING": TaskStatus.WAITING_OPERATION.value,
                    "BLOCKED": TaskStatus.RECOVERY_BLOCKED.value, "RESOLVED": TaskStatus.RUNNABLE.value}
                if (document.get("schema") != "SITINA_NATIVE_EXECUTION_WAIT_V1"
                        or document.get("task_id") != task_id
                        or document.get("blocker_id") != "native-execution"
                        or not document.get("wait_id") or state not in expected_status
                        or document.get("status") != expected_status[state]
                        or value.get("status") != expected_status[state]
                        or not self._native_wait_binding_current(task, document)):
                    raise PersistenceFenced("native execution wait binding is invalid")
                if state != "WAITING" and (task.waiting_reason or {}).get("wait_id") != document["wait_id"]:
                    raise PersistenceFenced("native execution result has no matching original wait")
                task.waiting_reason = dict(document)
                task.status = TaskStatus(expected_status[state])
            elif event.event_type in {"loop.task-waiting", "loop.task-context-blocked"}:
                document = self.context_memory.read(
                    str(value["waiting_ref"]), expected_hash=str(value["waiting_hash"])
                )
                if event.event_type == "loop.task-context-blocked":
                    binding = {
                        "run_instance_id": str(value["bound_run_instance_id"]),
                        "execution_epoch": int(value["bound_execution_epoch"]),
                        "goal_version": int(value["bound_goal_version"]),
                        "acceptance_version": int(value["bound_acceptance_version"]),
                        "handled_input_seq": int(value["bound_handled_input_seq"]),
                        "artifact_ref": str(value["bound_artifact_ref"]),
                    }
                    current_binding = {
                        "run_instance_id": task.run_instance_id,
                        "execution_epoch": task.execution_epoch,
                        "goal_version": task.goal_version,
                        "acceptance_version": task.acceptance_version,
                        "handled_input_seq": task.handled_input_seq,
                        "artifact_ref": task.artifact_ref,
                    }
                    if binding != current_binding:
                        raise PersistenceFenced("context blocker event has a stale task binding")
                if value.get("stop_report_ref"):
                    stop_report = self.context_memory.read(
                        str(value["stop_report_ref"]), expected_hash=str(value["stop_report_hash"])
                    )
                    report_binding = stop_report.get("pre_stop_binding") or {}
                    if (
                        stop_report.get("schema") != "SITINA_LOOP_STOP_REPORT_V1"
                        or stop_report.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                        or stop_report.get("task_id") != task_id
                        or stop_report.get("status") != value.get("status")
                        or int(report_binding.get("task_revision", -1)) != task.task_revision
                        or report_binding.get("artifact_ref") != task.artifact_ref
                        or int(report_binding.get("handled_input_seq", -1)) != task.handled_input_seq
                    ):
                        raise PersistenceFenced("stop report is not bound to the waiting event")
                    task.stop_report_ref = str(value["stop_report_ref"])
                    task.stop_report_hash = str(value["stop_report_hash"])
                task.waiting_reason = dict(document)
                task.status = TaskStatus(str(value["status"]))
            elif event.event_type in {"loop.task-paused", "loop.task-recovery-blocked"}:
                stop_report = self.context_memory.read(
                    str(value["stop_report_ref"]), expected_hash=str(value["stop_report_hash"])
                )
                report_binding = stop_report.get("pre_stop_binding") or {}
                if (
                    stop_report.get("schema") != "SITINA_LOOP_STOP_REPORT_V1"
                    or stop_report.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                    or stop_report.get("task_id") != task_id
                    or stop_report.get("status") != value.get("status")
                    or int(report_binding.get("task_revision", -1)) != task.task_revision
                    or report_binding.get("artifact_ref") != task.artifact_ref
                    or int(report_binding.get("handled_input_seq", -1)) != task.handled_input_seq
                ):
                    raise PersistenceFenced("stop report is not bound to the control/recovery event")
                if event.event_type == "loop.task-recovery-blocked":
                    if tuple(str(item) for item in value.get("retained_resources", ())) != task.owned_resources:
                        raise PersistenceFenced("recovery-blocked event changed resource ownership")
                    task.waiting_reason = {
                        "blocker_id": stop_report["reason_code"],
                        "reason": stop_report["reason"],
                    }
                task.stop_report_ref = str(value["stop_report_ref"])
                task.stop_report_hash = str(value["stop_report_hash"])
                task.status = TaskStatus(str(value["status"]))
            elif event.event_type == "loop.acceptance-result-recorded":
                document = self.context_memory.read(
                    str(value["acceptance_ref"]), expected_hash=str(value["acceptance_hash"])
                )
                record = AcceptanceRecord(
                    str(document["acceptance_id"]),
                    str(document["outcome_id"]),
                    int(document["bound_task_revision"]),
                    str(document["bound_run_instance_id"]),
                    int(document["bound_execution_epoch"]),
                    int(document["goal_version"]),
                    int(document["acceptance_version"]),
                    int(document["bound_handled_input_seq"]),
                    str(document["artifact_ref"]),
                    tuple(str(item) for item in document["evidence_refs"]),
                    str(document["program_status"]),
                    str(document["reviewer_status"]),
                    bool(document["delivery_verified"]),
                )
                applicable = bool(value.get("applicable_to_current_task"))
                still_current = (
                    record.bound_run_instance_id == task.run_instance_id
                    and record.bound_execution_epoch == task.execution_epoch
                    and record.goal_version == task.goal_version
                    and record.acceptance_version == task.acceptance_version
                    and record.bound_handled_input_seq == task.handled_input_seq
                    and record.artifact_ref == task.artifact_ref
                    and task.received_input_seq == task.handled_input_seq
                )
                if applicable and not still_current:
                    raise PersistenceFenced("acceptance applicability contradicts its persisted binding")
                if applicable:
                    task.acceptances[record.acceptance_id] = record
            elif event.event_type == "loop.resource-handoff-recorded":
                document = self.context_memory.read(
                    str(value["handoff_ref"]), expected_hash=str(value["handoff_hash"])
                )
                if document.get("schema") not in {
                    "SITINA_LOOP_RESOURCE_HANDOFF_V1",
                    "SITINA_LOOP_RESOURCE_HANDOFF_OBSERVATION_V1",
                }:
                    raise PersistenceFenced("resource handoff evidence schema is invalid")
                if document.get("task_id") != task_id or document.get("handoff_id") != value.get("handoff_id"):
                    raise PersistenceFenced("resource handoff evidence identity differs from its event")
                released = tuple(str(item) for item in document["resources"])
                if tuple(str(item) for item in value["resources"]) != released:
                    raise PersistenceFenced("resource handoff event differs from its durable content")
                binding = document.get("binding")
                if isinstance(binding, Mapping):
                    expected_binding = {
                        "task_id": task_id,
                        "run_instance_id": task.run_instance_id,
                        "execution_epoch": task.execution_epoch,
                        "goal_version": task.goal_version,
                        "acceptance_version": task.acceptance_version,
                        "handled_input_seq": task.handled_input_seq,
                        "artifact_ref": task.artifact_ref,
                    }
                    if any(binding.get(key) != expected for key, expected in expected_binding.items()):
                        raise PersistenceFenced("resource handoff evidence has a stale task binding")
                if any(item not in task.owned_resources for item in released):
                    raise PersistenceFenced("resource handoff releases an unowned resource")
                task.owned_resources = tuple(item for item in task.owned_resources if item not in released)
            elif event.event_type == "loop.task-recovery-docked":
                task.run_instance_id = str(value["run_instance_id"])
                task.execution_epoch = int(value["execution_epoch"])
                task.recovery_state = str(value["recovery_state"])
                task.status = TaskStatus(str(value["status"]))
            elif event.event_type == "loop.task-recovery-discovered":
                task.recovery_state = "RECOVERY_DISCOVERED"
                task.status = TaskStatus.RECOVERY_BLOCKED
            elif event.event_type == "loop.task-recovery-claimed":
                task.run_instance_id = str(value["run_instance_id"])
                task.execution_epoch = int(value["execution_epoch"])
                task.recovery_state = "RECOVERY_RECONCILING"
                task.status = TaskStatus.RECOVERY_BLOCKED
            elif event.event_type == "loop.task-recovery-ready":
                from .model import bind_reviewer_continuation

                task.recovery_state = str(value.get("recovery_state") or "READY_RECOVERED")
                prior_wait = task.waiting_reason or {}
                retained_native_wait = (prior_wait.get("blocker_id") == "native-execution"
                    and self._native_wait_binding_current(task, prior_wait))
                task.waiting_reason = dict(prior_wait) if retained_native_wait else None
                task.status = TaskStatus(str(value["status"]))
                if retained_native_wait:
                    task.status = TaskStatus(prior_wait["status"])
                task.control_intent = ControlIntent(str(value.get("control_intent") or task.control_intent.value))
                bind_reviewer_continuation(task.provider_response_dispositions, task.resume_request_id, {
                    "run_instance_id": task.run_instance_id, "execution_epoch": task.execution_epoch,
                    "goal_version": task.goal_version, "acceptance_version": task.acceptance_version,
                    "criteria_lineage_version": task.criteria_lineage_version, "artifact_ref": task.artifact_ref,
                    "handled_input_seq": task.handled_input_seq, "received_input_seq": task.received_input_seq,
                })
                task.resume_request_id = None
            elif event.event_type == "loop.task-resume-requested":
                retry = value.get("review_repair_authorization")
                authorize_retry = value.get("authorize_review_retry", False)
                if type(authorize_retry) is not bool or (authorize_retry and retry is None):
                    raise PersistenceFenced("explicit review retry authority is invalid")
                if retry is not None:
                    expected_retry = task.explicit_review_retry(
                        str(value["resume_request_id"]), authorize_new_batch=authorize_retry,
                    )
                    if (not isinstance(retry, Mapping) or expected_retry is None
                            or dict(retry) != expected_retry
                            or value.get("expected_task_revision") != task.task_revision
                            or value.get("expected_run_instance_id") != task.run_instance_id
                            or value.get("expected_execution_epoch") != task.execution_epoch
                            or value.get("expected_received_input_seq") != task.received_input_seq
                            or value.get("expected_handled_input_seq") != task.handled_input_seq
                            or value.get("prior_control_intent") != task.control_intent.value):
                        raise PersistenceFenced("explicit review retry replay binding is invalid")
                    task.review_repair_authorizations = (*task.review_repair_authorizations, dict(retry))
                update = value.get("software_update_transition")
                if update is not None:
                    try:
                        if (
                            not isinstance(update, Mapping)
                            or value.get("expected_task_revision") != task.task_revision
                            or value.get("expected_run_instance_id") != task.run_instance_id
                            or value.get("expected_execution_epoch") != task.execution_epoch
                            or value.get("expected_received_input_seq") != task.received_input_seq
                            or value.get("expected_handled_input_seq") != task.handled_input_seq
                            or value.get("prior_control_intent") != task.control_intent.value
                        ):
                            raise TaskConflict("software update event frontier differs")
                        validated_update = self._validate_software_update_transition(
                            task, update.get("request"),
                            resume_request_id=str(value["resume_request_id"]),
                            host_descriptor_context=update.get("host_descriptor_context"),
                        )
                        if dict(update) != validated_update:
                            raise TaskConflict("software update differs from its validated receipt")
                    except (TaskConflict, TypeError, ValueError, KeyError) as exc:
                        raise PersistenceFenced("software update replay validation failed") from exc
                    task.software_update_transition = validated_update
                disposition = value.get("provider_response_disposition")
                if disposition is not None:
                    try:
                        if not isinstance(disposition, Mapping):
                            raise TaskConflict("Provider disposition must be a mapping")
                        if (
                            value.get("expected_task_revision") != task.task_revision
                            or value.get("expected_run_instance_id") != task.run_instance_id
                            or value.get("expected_execution_epoch") != task.execution_epoch
                            or value.get("expected_received_input_seq") != task.received_input_seq
                            or value.get("expected_handled_input_seq") != task.handled_input_seq
                            or value.get("prior_control_intent") != task.control_intent.value
                        ):
                            raise TaskConflict("Provider disposition event frontier differs")
                        validated = self._validate_provider_response_disposition(
                            task, disposition.get("request"),
                            resume_request_id=str(value["resume_request_id"]),
                            host_descriptor_context=disposition.get("host_descriptor_context"),
                        )
                        if dict(disposition) != validated:
                            raise TaskConflict("Provider disposition differs from its validated receipt")
                    except (TaskConflict, TypeError, ValueError, KeyError) as exc:
                        raise PersistenceFenced("Provider disposition replay validation failed") from exc
                    task.provider_response_dispositions[validated["request"]["operation_id"]] = validated
                task.resume_request_id = str(value["resume_request_id"])
            elif event.event_type == 'loop.task-cancel-reconciliation-recorded':
                receipt = value.get('receipt')
                try:
                    if not isinstance(receipt, Mapping):
                        raise TaskConflict('cancel reconciliation receipt is missing')
                    validated = self._validate_cancel_reconciliation(
                        task, receipt.get('request'), request_id=receipt.get('request_id'),
                        host_descriptor_context=receipt.get('host_descriptor_context'),
                    )
                    if dict(receipt) != validated:
                        raise TaskConflict('cancel reconciliation receipt differs from original evidence')
                except (TaskConflict, ValueError, TypeError, KeyError) as error:
                    raise PersistenceFenced('cancel reconciliation replay validation failed') from error
                task.cancel_reconciliation = validated
            elif event.event_type == "loop.task-terminated":
                if task.terminal_event_id is not None:
                    raise PersistenceFenced("task stream contains more than one logical terminal event")
                document = self.context_memory.read(
                    str(value["result_ref"]), expected_hash=str(value["result_hash"])
                )
                if value.get("stop_report_ref"):
                    stop_report = self.context_memory.read(
                        str(value["stop_report_ref"]), expected_hash=str(value["stop_report_hash"])
                    )
                    report_binding = stop_report.get("pre_stop_binding") or {}
                    if (
                        stop_report.get("schema") != "SITINA_LOOP_STOP_REPORT_V1"
                        or stop_report.get("termination_contract_version") != TERMINATION_CONTRACT_VERSION
                        or stop_report.get("task_id") != task_id
                        or stop_report.get("status") != value.get("terminal_status")
                        or int(report_binding.get("task_revision", -1)) != task.task_revision
                        or report_binding.get("artifact_ref") != task.artifact_ref
                    ):
                        raise PersistenceFenced("terminal stop report binding is invalid")
                    task.stop_report_ref = str(value["stop_report_ref"])
                    task.stop_report_hash = str(value["stop_report_hash"])
                task.terminal_event_id = str(value["terminal_event_id"])
                task.terminal_result = document
                task.status = TaskStatus(str(value["terminal_status"]))
                declared_release = tuple(str(item) for item in value.get("released_resources", ()))
                if declared_release != task.owned_resources:
                    raise PersistenceFenced("terminal resource release differs from current task ownership")
                task.owned_resources = ()
            else:
                self._task_cache.pop(task_id, None)
                return
        except BaseException:
            self._task_cache.pop(task_id, None)
            raise
        task.task_revision = event.stream_version
        task.stream_frontier = event.position
        self._task_cache[task_id] = task

    def get_task(self, task_id: str) -> TaskProjection:
        with self._state_lock:
            cached = self._task_cache.get(task_id)
            if cached is not None:
                new_events = self.store.task_events(task_id, after_position=cached.stream_frontier)
                if not new_events:
                    return self._effective_recovery_view(copy.deepcopy(cached))
            events = self.store.task_events(task_id)
            if not events:
                raise KeyError(task_id)
            projected = self._project(task_id, events)
            self._task_cache[task_id] = copy.deepcopy(projected)
            return self._effective_recovery_view(copy.deepcopy(projected))

    def read_task_memory_view(self, task_id: str) -> Mapping[str, Any]:
        """Read the task's immutable, bounded memory view as untrusted data."""
        with self._state_lock:
            task = self.get_task(task_id)
            if not task.memory_view_ref or not task.memory_view_hash:
                return {
                    "schema": "SITINA_UNTRUSTED_MEMORY_DATA_V1",
                    "task_id": task_id,
                    "memory_view_ref": None,
                    "entries": [],
                }
            view = self.context_memory.read(task.memory_view_ref, expected_hash=task.memory_view_hash)
            if view.get("schema") != "SITINA_LOOP_MEMORY_VIEW_V1" or view.get("task_id") != task_id:
                raise PersistenceFenced("task memory view changed or is not bound to this task")
            entries = view.get("entries", [])
            if not isinstance(entries, list) or len(entries) > 64:
                raise PersistenceFenced("task memory view entries are not bounded")
            excluded_ids: set[str] = set()
            revalidation = None
            if task.memory_view_revalidation_ref or task.memory_view_revalidation_hash:
                if not task.memory_view_revalidation_ref or not task.memory_view_revalidation_hash:
                    raise PersistenceFenced("memory view revalidation binding is incomplete")
                revalidation = self.context_memory.read(
                    task.memory_view_revalidation_ref,
                    expected_hash=task.memory_view_revalidation_hash,
                )
                self._validate_memory_view_revalidation(task, revalidation)
                excluded_ids = {
                    str(item.get("memory_id") or "")
                    for item in revalidation.get("excluded_entries", ())
                    if isinstance(item, Mapping) and item.get("memory_id")
                }
            effective_ids = [item for item in task.memory_view_ids if item not in excluded_ids]
            effective_versions = {
                str(memory_id): int(version)
                for memory_id, version in task.memory_view_versions
                if memory_id not in excluded_ids
            }
            effective_entries = [
                dict(item)
                for item in entries
                if not isinstance(item, Mapping) or str(item.get("memory_id") or "") not in excluded_ids
            ]
            return {
                "schema": "SITINA_UNTRUSTED_MEMORY_DATA_V1",
                "task_id": task_id,
                "memory_view_ref": task.memory_view_ref,
                "memory_view_hash": task.memory_view_hash,
                "original_selected_memory_ids": list(task.memory_view_ids),
                "original_selected_memory_versions": dict(task.memory_view_versions),
                "selected_memory_ids": effective_ids,
                "selected_memory_versions": effective_versions,
                "selection_reasons": list(task.memory_view_reasons),
                "entries": effective_entries,
                "excluded_memory_ids": sorted(excluded_ids),
                "memory_view_revalidation_ref": task.memory_view_revalidation_ref,
                "memory_view_revalidation_hash": task.memory_view_revalidation_hash,
                "memory_view_revalidation_input_seq": task.memory_view_revalidation_input_seq,
            }

    def memory_retention(
        self, *, task_id: str, action: str, operation_id: str,
        memory_id: str | None = None, approval_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Local owner control; never exposed as an Agent/extension tool."""
        from sitina.archive.retention_operations import MemoryRetention
        with self._state_lock, self.store.journal._mutex:
            if action not in {"schedule", "status", "execute"}:
                raise TaskConflict("unknown retention action")
            self.get_task(task_id)
            repository = self._memory_repository
            if repository is None:
                raise TaskConflict("native memory authority is unavailable")
            retention = MemoryRetention(repository)
            if action == "schedule":
                if not memory_id:
                    raise TaskConflict("memory_id is required for retention scheduling")
                document = repository._raw_get(memory_id)
            else:
                plan, _, document = retention._plan(operation_id, "user")
                if memory_id is not None and memory_id != plan["memory_id"]:
                    raise TaskConflict("retention memory binding mismatch")
            if document.scope != "agent_private" or document.owner_id != f"agent/{task_id}":
                raise TaskConflict("retention control is limited to this task's private memory")
            if action == "status":
                return retention.status(operation_id=operation_id, actor="user")
            self._require_persistence()
            if action == "schedule":
                return retention.schedule(operation_id=operation_id, memory_id=memory_id,
                                          actor="user", approval_seconds=approval_seconds)
            tasks = tuple(self.get_task(identity) for identity in self.store.task_ids())
            if (self._child_running or self._active_extension_operations
                    or any(task.status not in TERMINAL_STATUSES for task in tasks)
                    or any(operation.unknown_effect or operation.effect_status in {
                        EffectStatus.INTENT_RECORDED, EffectStatus.PARTIAL, EffectStatus.UNKNOWN
                    } for task in tasks for operation in task.operations.values())):
                raise TaskConflict("retention execution requires quiescent tasks and known effects")
            return retention.execute(operation_id=operation_id, actor="user")


    def bind_memory_repository(self, memory_repository: Any, *, actor: str) -> None:
        if memory_repository is None or not actor:
            raise ValueError("memory repository binding requires a reader actor")
        if (
            getattr(memory_repository, "journal", None) is not self.store.journal
            or getattr(memory_repository, "cas", None) is not self.store.cas
            or getattr(memory_repository, "keys", None) is not self.context.provider
        ):
            raise TaskConflict("memory repository is not bound to this Backend Journal/CAS/key authority")
        self._memory_repository = memory_repository
        self._memory_actor = actor

    def assert_task_memory_view_actionable(self, task_id: str) -> None:
        """Fail closed before an action if a bound memory entry was revoked."""
        view = self.read_task_memory_view(task_id)
        repository = self._memory_repository
        actor = self._memory_actor
        if (view.get("selected_memory_ids") or view.get("entries")) and (repository is None or actor is None):
            raise TaskConflict("bound memory view cannot be actioned without its native authority")
        if repository is not None and actor is not None:
            with self.store.journal._mutex:
                roots = {
                    str(item.get("root_id")): int(item.get("source_position"))
                    for item in repository.active_roots()
                    if isinstance(item, Mapping) and item.get("root_id")
                }
                for memory_id, expected_version in dict(view.get("selected_memory_versions", {})).items():
                    try:
                        document, _ = repository.get(str(memory_id), actor=actor, include_content=False)
                    except Exception as error:
                        raise TaskConflict("bound memory view cannot be reread before action") from error
                    if (
                        document.status != "accepted"
                        or document.quarantine_status != "active"
                        or roots.get(str(memory_id)) != int(expected_version)
                    ):
                        raise TaskConflict("bound memory view is stale or revoked; re-review is required")
        for entry in view.get("entries", ()):
            if not isinstance(entry, Mapping):
                raise PersistenceFenced("task memory view entry is malformed")
            status = str(entry.get("status") or "accepted")
            if status in {"revoked", "quarantined", "superseded", "expired", "isolated"}:
                raise TaskConflict("bound memory view is no longer actionable; re-review is required")

    def _validate_memory_view_revalidation(
        self,
        task: TaskProjection,
        document: Mapping[str, Any],
    ) -> None:
        if (
            document.get("schema") != "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1"
            or document.get("task_id") != task.task_id
            or document.get("original_memory_view_ref") != task.memory_view_ref
            or document.get("original_memory_view_hash") != task.memory_view_hash
            or not str(document.get("run_instance_id") or "")
            or int(document.get("run_instance_id_epoch", -1)) != int(document.get("execution_epoch", -1))
        ):
            raise PersistenceFenced("memory view revalidation identity is malformed")
        correction_seq = int(document.get("correction_input_seq", -1))
        if correction_seq < 1 or not any(
            item.sequence == correction_seq and item.kind is InputKind.CORRECTION
            for item in task.inputs
        ):
            raise TaskConflict("memory view requires a durable handled correction")
        if any(item.kind is InputKind.CORRECTION and item.sequence > correction_seq for item in task.inputs):
            raise TaskConflict("memory view requires fresh evidence for the later correction")
        excluded = document.get("excluded_entries", [])
        active = document.get("active_entries", [])
        selected = set(task.memory_view_ids)
        if (
            not isinstance(excluded, list)
            or not isinstance(active, list)
            or any(not isinstance(item, Mapping) for item in (*excluded, *active))
            or set(str(item.get("memory_id") or "") for item in excluded).intersection(
                str(item.get("memory_id") or "") for item in active
            )
            or set(str(item.get("memory_id") or "") for item in (*excluded, *active)) != selected
        ):
            raise PersistenceFenced("memory view revalidation does not cover the original selection")

    def revalidate_task_memory_view_after_correction(
        self,
        task_id: str,
        *,
        correction_input_seq: int | None = None,
    ) -> TaskProjection:
        """Persist fresh native evidence after a handled correction.

        The original view CAS and selected IDs remain immutable.  A correction
        may only exclude native-authoritatively invalidated versions; it may
        not add newly accepted memories to the active task.
        """
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if not task.memory_view_ids:
                return task
            if task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("memory revalidation requires all received input to be handled")
            correction_sequences = [
                item.sequence for item in task.inputs
                if item.sequence <= task.handled_input_seq and item.kind is InputKind.CORRECTION
            ]
            sequence = int(correction_input_seq if correction_input_seq is not None else (max(correction_sequences) if correction_sequences else -1))
            if sequence not in correction_sequences:
                raise TaskConflict("memory revalidation requires a handled CORRECTION input")
            if task.memory_view_revalidation_input_seq is not None and task.memory_view_revalidation_input_seq >= sequence:
                return task
            repository = self._memory_repository
            actor = self._memory_actor
            if repository is None or not actor:
                raise TaskConflict("bound memory view cannot be revalidated without native authority")
            active_entries: list[dict[str, Any]] = []
            excluded_entries: list[dict[str, Any]] = []
            with self.store.journal._mutex:
                roots = {
                    str(item.get("root_id")): int(item.get("source_position"))
                    for item in repository.active_roots()
                    if isinstance(item, Mapping) and item.get("root_id")
                }
                for memory_id, expected_version in task.memory_view_versions:
                    try:
                        document, _content = repository.get(str(memory_id), actor=actor, include_content=False)
                    except Exception as error:
                        raise TaskConflict("native memory evidence could not be reread") from error
                    source_position = roots.get(str(memory_id))
                    if (
                        document.status == "accepted"
                        and document.quarantine_status == "active"
                        and source_position == int(expected_version)
                    ):
                        provenance = repository.verify_provenance(str(memory_id))
                        active_entries.append({
                            "memory_id": str(memory_id),
                            "expected_version": int(expected_version),
                            "source_position": int(source_position),
                            "status": document.status,
                            "content_hash": document.content_hash,
                            "provenance_hash": str(provenance.get("content_hash") or ""),
                        })
                    else:
                        excluded_entries.append({
                            "memory_id": str(memory_id),
                            "expected_version": int(expected_version),
                            "observed_source_position": source_position,
                            "observed_status": document.status,
                            "observed_quarantine_status": document.quarantine_status,
                            "reason": "native-authority-invalidated-original-version",
                        })
                document = {
                    "schema": "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1",
                    "task_id": task.task_id,
                    "original_memory_view_ref": task.memory_view_ref,
                    "original_memory_view_hash": task.memory_view_hash,
                    "bound_task_revision": task.task_revision,
                    "run_instance_id": task.run_instance_id,
                    "run_instance_id_epoch": task.execution_epoch,
                    "execution_epoch": task.execution_epoch,
                    "goal_version": task.goal_version,
                    "acceptance_version": task.acceptance_version,
                    "handled_input_seq": task.handled_input_seq,
                    "correction_input_seq": sequence,
                    "active_entries": active_entries,
                    "excluded_entries": excluded_entries,
                    "excluded_memory_ids": [str(item["memory_id"]) for item in excluded_entries],
                }
                stored = self.context_memory.persist(document, purpose="loop-memory-view-revalidation")
                self._append(
                    task_id=task_id,
                    expected_stream_version=task.task_revision,
                    request_id=f"memory-view-revalidate:{task_id}:{sequence}",
                    command_type="loop.task.memory-view-revalidate",
                    event_type="loop.task-memory-view-revalidated",
                    payload={
                        "schema": "SITINA_LOOP_MEMORY_VIEW_REVALIDATED_V1",
                        "task_id": task_id,
                        "revalidation_ref": stored.reference_id,
                        "revalidation_hash": stored.content_hash,
                        "original_memory_view_ref": task.memory_view_ref,
                        "original_memory_view_hash": task.memory_view_hash,
                        "correction_input_seq": sequence,
                        "excluded_memory_ids": [str(item["memory_id"]) for item in excluded_entries],
                    },
                    proofs=(stored.proof,),
                )
            return self.get_task(task_id)

    def build_memory_view_from_repository(
        self,
        memory_repository: Any,
        *,
        memory_ids: Sequence[str],
        actor: str,
        selection_reasons: Sequence[str],
    ) -> Mapping[str, Any]:
        """Build a fixed Loop view from the native repository's verified read."""
        if not memory_ids or not selection_reasons:
            raise TaskConflict("memory view requires selected records and a reason")
        self.bind_memory_repository(memory_repository, actor=actor)
        roots = {
            str(item.get("root_id")): int(item.get("source_position"))
            for item in memory_repository.active_roots()
            if isinstance(item, Mapping) and item.get("root_id")
        }
        entries: list[dict[str, Any]] = []
        versions: dict[str, int] = {}
        for memory_id in tuple(dict.fromkeys(str(item) for item in memory_ids)):
            document, content = memory_repository.get(memory_id, actor=actor, include_content=True)
            if document.status != "accepted" or document.quarantine_status != "active":
                raise TaskConflict("memory view selection contains a non-current record")
            provenance = memory_repository.verify_provenance(memory_id)
            version = roots.get(memory_id)
            if version is None or not provenance.get("verified"):
                raise TaskConflict("memory view selection has no verified current source position")
            versions[memory_id] = version
            entries.append({
                "memory_id": memory_id,
                "status": document.status,
                "version": version,
                "content_hash": document.content_hash,
                "source_event_ids": list(document.source_event_ids),
                "source_run_ids": list(document.source_run_ids),
                "source_agent_ids": list(document.source_agent_ids),
                "scope": document.scope, "owner_id": document.owner_id, "namespace": document.namespace,
                "valid_from": document.valid_from, "expires_at": document.expires_at,
                "supersedes": list(document.supersedes), "superseded_by": document.superseded_by,
                "source_trust": document.source_trust, "observed_at": document.observed_at,
                "provenance_hash": str(provenance.get("content_hash") or ""),
                "text": str(content or ""),
            })
        return {
            "selected_memory_ids": sorted(versions),
            "selected_memory_versions": versions,
            "selection_reasons": [str(item) for item in selection_reasons],
            "entries": entries,
            "source_frontier": max(versions.values()),
        }

    def _effective_recovery_view(self, task: TaskProjection) -> TaskProjection:
        if task.is_terminal or task.run_instance_id == self.run_instance_id:
            return task
        if task.recovery_state == "RECOVERY_NOT_CONNECTED":
            return task
        if (
            not task.is_terminal
            and task.status is TaskStatus.PAUSED
            and task.control_intent is ControlIntent.PAUSE
            and task.received_input_seq == task.handled_input_seq
            and not task.active_operations
            and not task.unresolved_effects
        ):
            task.recovery_state = "RESTART_DETECTED"
            return task
        task.recovery_state = "RESTART_DETECTED"
        task.status = TaskStatus.RECOVERY_BLOCKED
        return task

    def request_resume(
        self,
        task_id: str,
        *,
        resume_request_id: str,
        expected_task_revision: int | None = None,
    ) -> TaskProjection:
        """Persist an explicit, stable continuation intent before recovery work."""

        if not resume_request_id.strip():
            raise ValueError("resume request identity is required")
        with self._state_lock:
            task = self._project(task_id, self.store.task_events(task_id))
            if task.is_terminal:
                raise TaskConflict("terminal task cannot be resumed")
            for event in self.store.task_events(task_id):
                if (
                    event.event_type == "loop.task-resume-requested"
                    and event.payload.get("resume_request_id") == resume_request_id
                ):
                    return self.get_task(task_id)
            if expected_task_revision is not None and task.task_revision != expected_task_revision:
                raise TaskConflict("resume request task revision is stale")
            if task.control_intent is ControlIntent.CANCEL:
                raise TaskConflict("CANCEL cannot be superseded by resume")
            # A resume can only cover an already-handled, earlier pause. Any
            # later unhandled control remains authoritative.
            if any(
                record.sequence > task.handled_input_seq
                and record.kind in {InputKind.PAUSE, InputKind.CANCEL}
                for record in task.inputs
            ):
                raise TaskConflict("later pause or cancel cannot be superseded by resume")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"resume-request:{task_id}:{resume_request_id}",
                command_type="loop.task.resume-request",
                event_type="loop.task-resume-requested",
                payload={
                    "schema": "SITINA_LOOP_TASK_RESUME_REQUESTED_V1",
                    "task_id": task_id,
                    "resume_request_id": resume_request_id,
                    "expected_task_revision": task.task_revision,
                    "expected_run_instance_id": task.run_instance_id,
                    "expected_execution_epoch": task.execution_epoch,
                    "expected_handled_input_seq": task.handled_input_seq,
                    "prior_control_intent": task.control_intent.value,
                    "requested_at": iso_now(),
                },
            )
            return self.get_task(task_id)

    def _validate_provider_response_disposition(
        self, task: TaskProjection, request: Mapping[str, Any], *,
        resume_request_id: str, host_descriptor_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Accept an explicit control choice only after all original bindings match."""
        if (not isinstance(request, Mapping)
                or request.get('accept_unknown_usage') is not True
                or request.get('abandon_missing_response') is not True):
            raise TaskConflict('explicit abandonment and unknown usage acceptance are required')
        binding = self._provider_response_disposition_binding(
            task, request, host_descriptor_context=host_descriptor_context)
        return {'authorization_source': 'native_control_resume',
                'decision': 'ABANDON_MISSING_PROVIDER_RESPONSE',
                'resume_request_id': resume_request_id, **binding}

    def _provider_response_disposition_binding(
        self,
        task: TaskProjection,
        request: Mapping[str, Any],
        *,
        host_descriptor_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify immutable request and source bindings without granting continuation."""

        keys = {
            "operation_id", "result_ref", "result_hash", "descriptor_hash",
            "expected_task_revision", "expected_received_input_seq", "expected_handled_input_seq",
            "from_software_identity", "to_software_identity",
            "accept_unknown_usage", "abandon_missing_response",
        }
        if not isinstance(request, Mapping) or set(request) != keys:
            raise TaskConflict("Provider response disposition fields are invalid")
        if type(request["accept_unknown_usage"]) is not bool or type(request["abandon_missing_response"]) is not bool:
            raise TaskConflict("Provider confirmation fields must be booleans")
        for key, expected in (
            ("expected_task_revision", task.task_revision),
            ("expected_received_input_seq", task.received_input_seq),
            ("expected_handled_input_seq", task.handled_input_seq),
        ):
            if type(request[key]) is not int or request[key] != expected:
                raise TaskConflict("Provider disposition control frontier is stale")
        for key in ("operation_id", "result_ref", "result_hash", "descriptor_hash",
                    "from_software_identity", "to_software_identity"):
            if not isinstance(request[key], str) or not request[key]:
                raise TaskConflict("Provider disposition identity is incomplete")
        for key in ("result_hash", "descriptor_hash"):
            if re.fullmatch(r"[0-9a-f]{64}", request[key]) is None:
                raise TaskConflict("Provider disposition digest is invalid")
        for key in ("from_software_identity", "to_software_identity"):
            if re.fullmatch(r"source:[0-9a-f]{64}", request[key]) is None:
                raise TaskConflict("Provider disposition requires exact source identities")
        if task.is_terminal or task.control_intent is ControlIntent.CANCEL:
            raise TaskConflict("cancelled or terminal task cannot accept this disposition")
        # An acknowledged PAUSE can still be pending handling; the active-operation
        # and exact input-frontier checks below remain mandatory before persistence.
        if task.status not in {
            TaskStatus.WAITING_INPUT, TaskStatus.RECOVERY_BLOCKED, TaskStatus.PAUSED, TaskStatus.STALLED,
            TaskStatus.PAUSING,
        }:
            raise TaskConflict("Provider disposition requires a stopped task")
        if any(record.sequence > task.handled_input_seq and record.kind is not InputKind.PAUSE
               for record in task.inputs):
            raise TaskConflict("pending business input or CANCEL must not be bypassed")
        operation_id = request["operation_id"]
        if operation_id in task.provider_response_dispositions:
            raise TaskConflict("Provider response already has an explicit disposition")
        operation = task.operations.get(operation_id)
        if (
            operation is None or operation.mode is not OperationMode.READ
            or operation.effect_status is not EffectStatus.UNKNOWN or not operation.unknown_effect
            or operation.recovery_decision != "NO_RETRY"
            or operation.agent_role not in {"main", "reviewer", "goal_completion"} or operation.execution_owner is not None
            or operation.resources or ":provider-turn:" not in operation.logical_operation_id
            or not operation_id.startswith("provider-")
            or operation.result_ref != request["result_ref"]
            or operation.bound_goal_version != task.goal_version
            or operation.bound_acceptance_version != task.acceptance_version
            or operation.bound_input_seq > task.handled_input_seq
            or any(record.sequence > operation.bound_input_seq and record.kind is not InputKind.PAUSE
                   for record in task.inputs)
            or task.active_operations
            or tuple(item.operation_id for item in task.unresolved_effects) != (operation_id,)
        ):
            raise TaskConflict("only the sole current pure Provider UNKNOWN may be disposed")
        result_events = tuple(
            event for event in self.store.task_events(task.task_id)
            if event.position <= task.stream_frontier
            and event.event_type == "loop.operation-result-recorded"
            and event.payload.get("operation_id") == operation_id
            and event.payload.get("result_ref") == operation.result_ref
        )
        if len(result_events) != 1 or result_events[0].payload.get("result_hash") != request["result_hash"]:
            raise TaskConflict("Provider disposition result differs from its committed receipt")
        if not self._operation_dispatch_started(task.task_id, operation_id):
            raise TaskConflict("Provider disposition requires the original dispatch marker")
        document = self.context_memory.read(operation.result_ref, expected_hash=request["result_hash"])
        body = document.get("result")
        failure = body.get("provider_failure") if isinstance(body, Mapping) else None
        if (
            document.get("schema") != "SITINA_LOOP_OPERATION_RESULT_V1"
            or document.get("task_id") != task.task_id or document.get("operation_id") != operation_id
            or document.get("effect_status") != "UNKNOWN"
            or document.get("bound_goal_version") != task.goal_version
            or document.get("bound_acceptance_version") != task.acceptance_version
            or document.get("bound_input_seq") != operation.bound_input_seq
            or not isinstance(body, Mapping) or body.get("work_purpose") != operation.agent_role
            or body.get("business_effect_dispatched") is not False
            or body.get("provider_response_discarded") is not True
            or body.get("recovery_decision") != "NO_RETRY"
            or body.get("tool_calls") not in (None, [])
            or not isinstance(failure, Mapping)
            or failure.get("schema") != "SITINA_LOOP_PROVIDER_FAILURE_V1"
            or failure.get("failure_class") != "unknown_provider_failure"
            or type(failure.get("retry_count")) is not int or failure["retry_count"] != 0
            or type(failure.get("fallback_count")) is not int or failure["fallback_count"] != 0
            or failure.get("usage_unsettled") is not True
        ):
            raise TaskConflict("Provider receipt does not prove a missing pure model response")
        review_continuation = None
        completion_continuation = None
        uncertain_send = (
            body.get("effect_dispatched") is None
            and failure.get("effect_dispatched") is None
            and failure.get("physical_send_status") == "unknown_after_request_start"
            and failure.get("physical_send_count_status") == "lower_bound_with_uncertain_attempts"
            and all(type(failure.get(key)) is int and failure[key] == expected for key, expected in
                    (("physical_send_count", 0), ("physical_send_count_lower_bound", 0),
                     ("uncertain_physical_send_attempt_count", 1)))
        )
        if operation.agent_role == "main":
            # Preserve legacy confirmed-send replay, and use the same exact
            # uncertain-send receipt for every pure-model role. This accepts
            # a human disposition, never a retry or a claim that no send occurred.
            confirmed_main_send = (
                body.get("effect_dispatched") is True
                and failure.get("physical_send_status") == "request_sent_no_response"
                and failure.get("physical_send_count_status") == "exact"
                and type(failure.get("physical_send_count")) is int
                and failure["physical_send_count"] == 1
                and type(failure.get("uncertain_physical_send_attempt_count")) is int
                and failure["uncertain_physical_send_attempt_count"] == 0
            )
            pure_uncertain_main = (
                uncertain_send
                and body.get("effect_requires_probe") is True
                and body.get("private_rejected_tool_response") is None
                and failure.get("business_effect_dispatched") is False
            )
            if not (confirmed_main_send or pure_uncertain_main):
                raise TaskConflict("Provider receipt does not prove a missing pure model response")
        else:
            from .termination import review_subject_lineage

            # A missing pure-model response can follow either a confirmed send
            # or a transport failure whose send outcome is itself uncertain.
            # Keep the original receipt's dispatch facts; neither permits replay.
            confirmed_send = (
                body.get("effect_dispatched") is True
                and failure.get("effect_dispatched") is True
                and failure.get("physical_send_status") == "request_sent_no_response"
                and failure.get("physical_send_count_status") == "exact"
                and all(type(failure.get(key)) is int and failure[key] == expected for key, expected in
                        (("physical_send_count", 1), ("physical_send_count_lower_bound", 1),
                         ("uncertain_physical_send_attempt_count", 0)))
            )
            if (not (confirmed_send or uncertain_send)
                    or body.get("effect_requires_probe") is not True
                    or body.get("private_rejected_tool_response") is not None
                    or failure.get("business_effect_dispatched") is not False
                    or task.received_input_seq != task.handled_input_seq):
                raise TaskConflict("Provider disposition requires an exact missing-response send receipt")
            plan = task.attempt_plans.get(operation.business_attempt_id)
            intent = self.context_memory.read(operation.intent_ref) if operation.intent_ref else None
            original_fields = ("run_instance_id", "execution_epoch", "goal_version",
                               "acceptance_version", "handled_input_seq")
            if (not isinstance(plan, Mapping) or not isinstance(intent, Mapping)
                    or plan.get("acceptance_item_id") != "outcome-1"
                    or plan.get("blocker_id") not in
                        ({"review-disagreement:outcome-1", "review-protocol-repair:outcome-1"}
                         if operation.agent_role == "reviewer" else {"goal-completion:outcome-1"})
                    or plan.get("artifact_ref") != task.artifact_ref
                    or plan.get("criteria_lineage_version") != task.criteria_lineage_version
                    or set(plan.get("scope", {}).get("allowed_action_kinds", ()))
                        != {"provider-response", "history-read"}
                    or intent.get("schema") != "SITINA_LOOP_OPERATION_INTENT_V1"
                    or intent.get("task_id") != task.task_id or intent.get("operation_id") != operation_id
                    or intent.get("agent_role") != operation.agent_role or intent.get("mode") != "READ"
                    or intent.get("execution_owner") is not None or intent.get("resources") != []
                    or intent.get("write_authority_acquired") is not False
                    or intent.get("business_attempt_id") != operation.business_attempt_id
                    or intent.get("logical_operation_id") != operation.logical_operation_id
                    or intent.get("capability_snapshot_id") != task.capability_snapshot_id
                    or any(intent.get("expected_" + key) != plan.get(key) for key in original_fields)
                    or plan.get("handled_input_seq") != operation.bound_input_seq):
                raise TaskConflict("reviewer continuation lacks its current native attempt binding")
            pauses = [record for record in task.inputs if record.sequence > operation.bound_input_seq]
            for record in pauses:
                pause = self.context_memory.read(record.body_ref, expected_hash=record.body_hash)
                if (record.kind is not InputKind.PAUSE or not record.input_id.startswith("shutdown-")
                        or pause != {"schema": "SITINA_LOOP_INPUT_BODY_V1", "task_id": task.task_id,
                                     "input_id": record.input_id, "kind": "PAUSE", "body": ""}):
                    raise TaskConflict("reviewer continuation may cross only authenticated shutdown PAUSE")
            checkpoint_binding = {key: plan[key] for key in
                                  (*original_fields, "criteria_lineage_version", "artifact_ref")}
            prior_completion = None
            if operation.agent_role == "goal_completion":
                from .model import current_checkpoint_continuation
                prior_completion = current_checkpoint_continuation(
                    task.provider_response_dispositions, task_id=task.task_id,
                    binding={**plan, "received_input_seq": plan["handled_input_seq"],
                             "control_intent": "RUN"}, phase="completion_continuation",
                )
                if prior_completion is not None:
                    checkpoint_binding = dict(prior_completion["original_binding"])
            artifact_events = [event for event in self.store.task_events(task.task_id)
                               if event.position <= task.stream_frontier
                               and event.event_type == "loop.artifact-updated"
                               and event.payload.get("artifact_ref") == task.artifact_ref]
            if len(artifact_events) != 1:
                raise TaskConflict("reviewer continuation needs one committed current artifact")
            artifact_hash = artifact_events[0].payload.get("artifact_hash")
            if not isinstance(artifact_hash, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_hash) is None:
                raise TaskConflict("reviewer artifact has no committed digest")
            artifact = self.context_memory.read(task.artifact_ref, expected_hash=artifact_hash)
            binding = artifact.get("binding")
            main = artifact.get("main_result")
            if (artifact.get("schema") != "SITINA_LOOP_ARTIFACT_V1"
                    or artifact.get("task_id") != task.task_id
                    or not isinstance(binding, Mapping) or not isinstance(main, Mapping)
                    or binding.get("task_id") != task.task_id
                    or binding.get("goal_version") != task.goal_version
                    or binding.get("acceptance_version") != task.acceptance_version
                    or binding.get("handled_input_seq") != checkpoint_binding["handled_input_seq"]
                    or not isinstance(artifact.get("full_main_result_ref"), str)
                    or not isinstance(task.attempt_plans.get(main.get("attempt_id")), Mapping)
                    or (prior_completion is not None and (
                        prior_completion.get("artifact_hash") != artifact_hash
                        or prior_completion.get("main_attempt_id") != main.get("attempt_id")))):
                raise TaskConflict("reviewer continuation has no exact committed main checkpoint")
            private = body.get("private_provider_request")
            transport = private.get("transport") if isinstance(private, Mapping) else None
            if operation.agent_role == "reviewer":
                expected_contract = {
                    "schema": "SITINA_LOOP_REVIEW_V2",
                    "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                    "acceptance_item_id": "outcome-1",
                    "review_subject_lineage": review_subject_lineage(task.task_id, "outcome-1"),
                    "observed_artifact_ref": task.artifact_ref, "artifact_ref": task.artifact_ref,
                }
                if (not isinstance(private, Mapping) or not isinstance(transport, Mapping)
                        or private.get("work_purpose") != "reviewer"
                        or private.get("logical_operation_id") != operation.logical_operation_id
                        or private.get("upstream_artifact_binding") != {
                            "observation_source": "persisted_artifact_document",
                            "current_artifact_ref": task.artifact_ref,
                            "source_artifact_ref": binding.get("source_artifact_ref"),
                        }
                        or transport.get("observation_source") != "serialized_http_request_argument"
                        or transport.get("model_context_role") != "reviewer"
                        or type(transport.get("model_context_count")) is not int
                        or transport["model_context_count"] != 1
                        or type(transport.get("request_body_bytes")) is not int
                        or transport["request_body_bytes"] <= 0
                        or not isinstance(transport.get("request_body_hash"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", transport["request_body_hash"]) is None
                        or transport.get("response_contract") != expected_contract):
                    raise TaskConflict("reviewer continuation lacks its actual request contract")
                review_continuation = {
                    "original_binding": {key: plan[key] for key in
                        (*original_fields, "criteria_lineage_version", "artifact_ref")},
                    "review_attempt_id": operation.business_attempt_id,
                    "main_attempt_id": main["attempt_id"],
                    "artifact_hash": artifact_hash, "intent_ref": operation.intent_ref,
                    "request_body_hash": transport["request_body_hash"],
                    "request_body_bytes": transport["request_body_bytes"],
                    "response_contract": dict(expected_contract),
                    "shutdown_pause_refs": [record.body_ref for record in pauses],
                }
            else:
                if (not isinstance(private, Mapping) or not isinstance(transport, Mapping)
                        or private.get("work_purpose") != "goal_completion"
                        or private.get("logical_operation_id") != operation.logical_operation_id
                        or transport.get("observation_source") != "serialized_http_request_argument"
                        or transport.get("model_context_role") != "main"
                        or type(transport.get("model_context_count")) is not int
                        or transport["model_context_count"] != 1
                        or type(transport.get("request_body_bytes")) is not int
                        or transport["request_body_bytes"] <= 0
                        or not isinstance(transport.get("request_body_hash"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", transport["request_body_hash"]) is None):
                    raise TaskConflict("completion continuation lacks its actual read-only request")
                reviews = [event for event in self.store.task_events(task.task_id)
                           if event.position <= task.stream_frontier
                           and event.event_type == "loop.review-findings-recorded"]
                if not reviews:
                    if task.task_kind in REVIEW_REQUIRED_TASK_KINDS:
                        raise TaskConflict("completion continuation has no committed independent review")
                    if (any(issue.get("status") == "OPEN" for issue in task.review_issues.values())
                            or (prior_completion is not None and (
                                prior_completion.get("review_status") != "NOT_REQUIRED"
                                or prior_completion.get("accepted_review_ref") is not None
                                or prior_completion.get("accepted_review_hash") is not None))):
                        raise TaskConflict("completion continuation cannot discard a required review")
                    accepted_review_binding = {"review_status": "NOT_REQUIRED"}
                else:
                    review_receipt = reviews[-1].payload
                    review_record = self.context_memory.read(
                        review_receipt["review_ref"], expected_hash=review_receipt["review_hash"],
                    )
                    review = review_record.get("review")
                    review_binding = {
                        "bound_run_instance_id": checkpoint_binding["run_instance_id"],
                        "bound_execution_epoch": checkpoint_binding["execution_epoch"],
                        "bound_goal_version": task.goal_version,
                        "bound_acceptance_version": task.acceptance_version,
                        "bound_criteria_lineage_version": task.criteria_lineage_version,
                        "bound_handled_input_seq": checkpoint_binding["handled_input_seq"],
                        "bound_artifact_ref": task.artifact_ref,
                    }
                    if (review_record.get("schema") != "SITINA_LOOP_REVIEW_RECORD_V2"
                            or review_record.get("task_id") != task.task_id
                            or any(review_record.get(key) != value for key, value in review_binding.items())
                            or (prior_completion is not None and (
                                prior_completion.get("accepted_review_ref") != review_receipt["review_ref"]
                                or prior_completion.get("accepted_review_hash") != review_receipt["review_hash"]))
                            or type(review_record.get("bound_task_revision")) is not int
                            or review_record["bound_task_revision"] > intent["expected_task_revision"]
                            or not isinstance(review, Mapping) or review.get("verdict") != "PASS"
                            or review.get("observed_artifact_ref") != task.artifact_ref
                            or any(issue.get("status") == "OPEN" for issue in task.review_issues.values())):
                        raise TaskConflict("completion continuation requires the unchanged accepted PASS review")
                    accepted_review_binding = {
                        "accepted_review_ref": review_receipt["review_ref"],
                        "accepted_review_hash": review_receipt["review_hash"],
                    }
                completion_continuation = {
                    "phase": "goal_completion",
                    "original_binding": checkpoint_binding,
                    "completion_attempt_id": operation.business_attempt_id,
                    "main_attempt_id": main["attempt_id"],
                    "artifact_hash": artifact_hash, "intent_ref": operation.intent_ref,
                    "request_body_hash": transport["request_body_hash"],
                    "request_body_bytes": transport["request_body_bytes"],
                    **accepted_review_binding,
                    "shutdown_pause_refs": [record.body_ref for record in pauses],
                }
        if not task.descriptor_ref or task.descriptor_hash != request["descriptor_hash"]:
            raise TaskConflict("Provider disposition descriptor binding differs")
        descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
        identity_keys = (
            "provider_identity", "environment_ref", "capability_snapshot_id",
            "software_identity", "config_identity",
        )
        if not isinstance(host_descriptor_context, Mapping) or any(
            not isinstance(host_descriptor_context.get(key), str) or not host_descriptor_context[key]
            for key in identity_keys
        ):
            raise TaskConflict("current Host descriptor identity is unavailable")
        if (
            descriptor.get("software_identity") != request["from_software_identity"]
            or host_descriptor_context["software_identity"] != request["to_software_identity"]
            or any(descriptor.get(key) != host_descriptor_context[key]
                   for key in identity_keys if key != "software_identity")
        ):
            raise TaskConflict("only the exact approved source pair may change during recovery")
        # This explicit disposition approves the exact original-to-current
        # source pair above. Earlier choices retain their own historical pairs;
        # they neither authorize this Host nor prevent a newly confirmed choice.
        return {
            "request": dict(request),
            "task_id": task.task_id,
            "descriptor_ref": task.descriptor_ref,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "artifact_ref": task.artifact_ref,
            "logical_operation_id": operation.logical_operation_id,
            "host_descriptor_context": {key: host_descriptor_context[key] for key in identity_keys},
            "original_effect_status": "UNKNOWN",
            "original_recovery_decision": "NO_RETRY",
            "original_usage_unsettled": True,
            "successor": "NEW_PROVIDER_OPERATION_ONLY",
            **({"review_continuation": review_continuation} if review_continuation is not None else {}),
            **({"completion_continuation": completion_continuation} if completion_continuation is not None else {}),
        }

    def _recovery_identity_options(self, task: TaskProjection) -> dict[str, Any]:
        """Use the newest committed source authorization; retain older receipts."""
        if task.cancel_reconciliation is not None:
            if task.control_intent is not ControlIntent.CANCEL:
                raise PersistenceFenced('cancel-only authority cannot recover a running task')
            return {'cancel_reconciliation': task.cancel_reconciliation}
        options: dict[str, Any] = {}
        if task.provider_response_dispositions:
            options['provider_response_disposition'] = next(reversed(task.provider_response_dispositions.values()))
        if task.software_update_transition is not None:
            options['software_update_transition'] = task.software_update_transition
        if len(options) == 2:
            positions: dict[str, int] = {}
            for key, receipt in options.items():
                matches = []
                for event in self.store.task_events(task.task_id):
                    stored = event.payload.get(key)
                    if (event.position <= task.stream_frontier
                            and event.event_type == 'loop.task-resume-requested'
                            and isinstance(stored, Mapping)
                            and stored.get('authorization_source') == 'native_control_resume'
                            and event.payload.get('resume_request_id') == receipt.get('resume_request_id')
                            and stored.get('request') == receipt.get('request')
                            and stored.get('host_descriptor_context') == receipt.get('host_descriptor_context')):
                        matches.append(event.stream_version)
                if len(matches) != 1:
                    raise PersistenceFenced('recovery source authorization has no unique committed order')
                positions[key] = matches[0]
            if positions['provider_response_disposition'] > positions['software_update_transition']:
                # This later explicit disposition authorizes the current source
                # pair itself. An older update remains history, not current authority.
                options.pop('software_update_transition')
        return options

    def provider_response_preview(
        self, task_id: str, host_descriptor_context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Propose an unconfirmed choice; never record input or send a request."""
        with self._state_lock:
            task = self.get_task(task_id)
            pending = tuple(task.unresolved_effects)
            if task.is_terminal or not any(':provider-turn:' in op.logical_operation_id for op in pending):
                return None
            preview: dict[str, Any] = {'state': 'blocked', 'task_revision': task.task_revision}
            try:
                if len(pending) != 1:
                    raise TaskConflict('other unresolved operations must be reconciled first')
                operation = pending[0]
                if not task.descriptor_ref or not task.descriptor_hash:
                    raise TaskConflict('the original immutable descriptor is missing')
                descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
                events = [event for event in self.store.task_events(task_id)
                          if event.position <= task.stream_frontier
                          and event.event_type == 'loop.operation-result-recorded'
                          and event.payload.get('operation_id') == operation.operation_id
                          and event.payload.get('result_ref') == operation.result_ref]
                if len(events) != 1:
                    raise TaskConflict('the original missing response has no unique committed result')
                request = {
                    'operation_id': operation.operation_id, 'result_ref': operation.result_ref,
                    'result_hash': events[0].payload['result_hash'], 'descriptor_hash': task.descriptor_hash,
                    'expected_task_revision': task.task_revision,
                    'expected_received_input_seq': task.received_input_seq,
                    'expected_handled_input_seq': task.handled_input_seq,
                    'from_software_identity': descriptor['software_identity'],
                    'to_software_identity': host_descriptor_context['software_identity'],
                    'accept_unknown_usage': False, 'abandon_missing_response': False,
                }
                self._provider_response_disposition_binding(
                    task, request, host_descriptor_context=host_descriptor_context)
                preview.update(state='confirmation_required', request=request,
                               work_purpose=operation.agent_role, original_outcome='UNKNOWN',
                               original_usage_unsettled=True, successor='NEW_PROVIDER_OPERATION_ONLY',
                               software_changed=request['from_software_identity'] != request['to_software_identity'])
            except (TaskConflict, TypeError, ValueError, KeyError) as error:
                preview['reason'] = str(error)
            return preview

    def _validate_software_update_transition(
        self,
        task: TaskProjection,
        request: Mapping[str, Any],
        *,
        resume_request_id: str,
        host_descriptor_context: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        from .recovery import validate_recovery_descriptor_identity

        if (
            not isinstance(request, Mapping)
            or set(request) != {"decision", "from_software_identity", "to_software_identity"}
            or request.get("decision") != "CONTINUE_ON_UPDATED_SOFTWARE"
            or not isinstance(host_descriptor_context, Mapping)
        ):
            raise TaskConflict("software update requires an explicit source pair")
        if task.is_terminal or task.control_intent is ControlIntent.CANCEL:
            raise TaskConflict("ended or cancelled task cannot change software version")
        if task.active_operations or task.unresolved_effects:
            raise TaskConflict("software update requires reconciled operations; active or unknown effects remain")
        if not task.descriptor_ref or not task.descriptor_hash:
            raise TaskConflict("software update requires the original immutable descriptor")
        descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
        options = self._recovery_identity_options(task)
        previous = options.get("software_update_transition") or options.get("provider_response_disposition")
        prior_source = previous["request"]["to_software_identity"] if previous else descriptor["software_identity"]
        if request.get("from_software_identity") != prior_source:
            raise TaskConflict("software update source differs from the recorded task version")
        receipt = {
            "schema": "SITINA_LOOP_SOFTWARE_UPDATE_TRANSITION_V1",
            "authorization_source": "native_control_resume",
            "task_id": task.task_id,
            "resume_request_id": resume_request_id,
            "descriptor_ref": task.descriptor_ref,
            "descriptor_hash": task.descriptor_hash,
            "original_software_identity": descriptor["software_identity"],
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "artifact_ref": task.artifact_ref,
            "handled_input_seq": task.handled_input_seq,
            "received_input_seq": task.received_input_seq,
            "request": dict(request),
            "host_descriptor_context": dict(host_descriptor_context),
        }
        disposition = (
            next(reversed(task.provider_response_dispositions.values()))
            if task.provider_response_dispositions else None
        )
        validate_recovery_descriptor_identity(
            descriptor, host_descriptor_context,
            software_update_transition=receipt,
            provider_response_disposition=disposition,
        )
        return receipt

    def software_update_preview(
        self, task_id: str, host_descriptor_context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Read the current task's real boundary; this never grants continuation."""
        with self._state_lock:
            task = self.get_task(task_id)
            if task.is_terminal or not task.descriptor_ref or not task.descriptor_hash:
                return None
            descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
            options = self._recovery_identity_options(task)
            prior = options.get("software_update_transition") or options.get("provider_response_disposition")
            source = prior["request"]["to_software_identity"] if prior else descriptor["software_identity"]
            current = host_descriptor_context["software_identity"]
            if source == current:
                return None
            request = {"decision": "CONTINUE_ON_UPDATED_SOFTWARE",
                       "from_software_identity": source, "to_software_identity": current}
            preview = {"state": "confirmation_required", "request": request,
                       "task_revision": task.task_revision}
            try:
                self._validate_software_update_transition(
                    task, request, resume_request_id="preview",
                    host_descriptor_context=host_descriptor_context,
                )
            except (TaskConflict, TypeError, ValueError, KeyError) as error:
                preview.update(state="blocked", reason=str(error))
            return preview

    def request_resume_with_status(
        self,
        task_id: str,
        *,
        resume_request_id: str,
        expected_task_revision: int | None = None,
        provider_response_disposition: Mapping[str, Any] | None = None,
        software_update_transition: Mapping[str, Any] | None = None,
        host_descriptor_context: Mapping[str, Any] | None = None,
        authorize_review_retry: bool = False,
    ) -> tuple[TaskProjection, bool]:
        """Persist one explicit continuation; an identical receipt never reschedules."""

        if not resume_request_id.strip():
            raise ValueError("resume request identity is required")
        if type(authorize_review_retry) is not bool:
            raise TaskConflict("review retry authorization must be a boolean")
        with self._state_lock:
            task = self._project(task_id, self.store.task_events(task_id))
            for event in self.store.task_events(task_id):
                if (
                    event.event_type == "loop.task-resume-requested"
                    and event.payload.get("resume_request_id") == resume_request_id
                ):
                    prior = event.payload.get("provider_response_disposition")
                    prior_request = prior.get("request") if isinstance(prior, Mapping) else None
                    if prior_request != provider_response_disposition:
                        raise TaskConflict("resume identity was reused with a different Provider disposition")
                    prior_update = event.payload.get("software_update_transition")
                    prior_update_request = prior_update.get("request") if isinstance(prior_update, Mapping) else None
                    if prior_update_request != software_update_transition:
                        raise TaskConflict("resume identity was reused with a different software update")
                    if event.payload.get("authorize_review_retry", False) != authorize_review_retry:
                        raise TaskConflict("resume identity was reused with different review authority")
                    return self.get_task(task_id), False
            if task.is_terminal:
                raise TaskConflict("terminal task cannot be resumed")
            if expected_task_revision is not None and task.task_revision != expected_task_revision:
                raise TaskConflict("resume request task revision is stale")
            if task.control_intent is ControlIntent.CANCEL:
                raise TaskConflict("CANCEL cannot be superseded by resume")
            retry = task.explicit_review_retry(
                resume_request_id, authorize_new_batch=authorize_review_retry,
            )
            if retry is not None and expected_task_revision is None:
                raise TaskConflict("explicit review retry requires the confirmed task revision")
            update = None
            if software_update_transition is not None:
                if expected_task_revision is None:
                    raise TaskConflict("software update requires the confirmed task revision")
                update = self._validate_software_update_transition(
                    task, software_update_transition, resume_request_id=resume_request_id,
                    host_descriptor_context=host_descriptor_context,
                )
            disposition = None
            if provider_response_disposition is not None:
                disposition = self._validate_provider_response_disposition(
                    task, provider_response_disposition,
                    resume_request_id=resume_request_id,
                    host_descriptor_context=host_descriptor_context,
                )
            elif any(
                record.sequence > task.handled_input_seq
                and record.kind in {InputKind.PAUSE, InputKind.CANCEL}
                for record in task.inputs
            ):
                raise TaskConflict("later pause or cancel cannot be superseded by resume")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"resume-request:{task_id}:{resume_request_id}",
                command_type="loop.task.resume-request",
                event_type="loop.task-resume-requested",
                payload={
                    "schema": "SITINA_LOOP_TASK_RESUME_REQUESTED_V1",
                    "task_id": task_id,
                    "resume_request_id": resume_request_id,
                    "expected_task_revision": task.task_revision,
                    "expected_run_instance_id": task.run_instance_id,
                    "expected_execution_epoch": task.execution_epoch,
                    "expected_handled_input_seq": task.handled_input_seq,
                    "prior_control_intent": task.control_intent.value,
                    "requested_at": iso_now(),
                    **({"expected_received_input_seq": task.received_input_seq,
                        "review_repair_authorization": retry} if retry is not None else {}),
                    **({"authorize_review_retry": True} if authorize_review_retry else {}),
                    **({
                        "expected_received_input_seq": task.received_input_seq,
                        "software_update_transition": update,
                    } if update is not None else {}),
                    **({
                        "expected_received_input_seq": task.received_input_seq,
                        "provider_response_disposition": disposition,
                    } if disposition is not None else {}),
                },
            )
            return self.get_task(task_id), True

    def _append_recovery_blocked(
        self,
        task: TaskProjection,
        *,
        blocker_id: str,
        reason: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> TaskProjection:
        stop_report = self._persist_stop_report(
            task,
            status=TaskStatus.RECOVERY_BLOCKED,
            blocker_id=blocker_id,
            reason=reason,
            evidence_refs=evidence_refs,
        )
        self._append(
            task_id=task.task_id,
            expected_stream_version=task.task_revision,
            request_id=f"recovery-blocked:{task.task_id}:{task.task_revision}:{blocker_id}",
            command_type="loop.task.recovery-block",
            event_type="loop.task-recovery-blocked",
            payload={
                "schema": "SITINA_LOOP_TASK_RECOVERY_BLOCKED_V1",
                "termination_contract_version": TERMINATION_CONTRACT_VERSION,
                "task_id": task.task_id,
                "status": TaskStatus.RECOVERY_BLOCKED.value,
                "stop_report_ref": stop_report.reference_id,
                "stop_report_hash": stop_report.content_hash,
                "retained_resources": list(task.owned_resources),
                "unknown_effect_operation_ids": sorted(item.operation_id for item in task.unresolved_effects),
            },
            proofs=(stop_report.proof,),
        )
        return self.get_task(task.task_id)

    def _append_recovery_settlement(self, task: TaskProjection, attempt_id: str) -> TaskProjection:
        plan = task.attempt_plans[attempt_id]
        document = {
            "schema": "SITINA_LOOP_ATTEMPT_SETTLEMENT_V1",
            "termination_contract_version": TERMINATION_CONTRACT_VERSION,
            "task_id": task.task_id,
            "attempt_id": attempt_id,
            "blocker_id": "host-restart",
            "outcome": "ABORTED_NOT_COUNTED: prior host stopped at a safe recovery boundary",
            "relevant_progress": False,
            "evidence_refs": [],
            "progress_basis": {"recovery": True},
            "lineage_id": str(plan["lineage_id"]),
            "acceptance_item_id": str(plan["acceptance_item_id"]),
            "registered_blocker_id": str(plan["blocker_id"]),
            "count_effect": COUNT_NEUTRAL,
            "progress_decision": {"recovery": "count_neutral"},
            "goal_version": int(plan["goal_version"]),
            "acceptance_version": int(plan["acceptance_version"]),
            "criteria_lineage_version": int(plan.get("criteria_lineage_version", 1)),
            "handled_input_seq": int(plan["handled_input_seq"]),
            "planned_artifact_ref": str(plan["artifact_ref"]),
            "closing_binding": {
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "task_revision": task.task_revision,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
                "control_intent": task.control_intent.value,
            },
        }
        stored = self.context_memory.persist(document, purpose="loop-recovery-attempt-settlement")
        self._append(
            task_id=task.task_id,
            expected_stream_version=task.task_revision,
            request_id=f"recovery-attempt-settle:{task.task_id}:{attempt_id}",
            command_type="loop.attempt.settle.recovery",
            event_type="loop.attempt-settled",
            payload={
                "schema": "SITINA_LOOP_ATTEMPT_SETTLED_V1",
                "task_id": task.task_id,
                "attempt_id": attempt_id,
                "blocker_id": "host-restart",
                "settlement_ref": stored.reference_id,
                "settlement_hash": stored.content_hash,
            },
            proofs=(stored.proof,),
        )
        return self.get_task(task.task_id)

    def recover_task(
        self,
        task_id: str,
        *,
        explicit_resume: bool = False,
        descriptor_validator: Callable[..., str | None] | None = None,
    ) -> TaskProjection:
        """Claim a descriptor-validated task after reconciling its existing effects."""

        # Descriptor CAS reads and host identity validation are deliberately
        # outside the coordinator lock.  Control/status requests therefore
        # remain responsive even when a validator performs slow I/O.
        with self._state_lock:
            initial = self.get_task(task_id)
            if initial.is_terminal:
                return initial
            if (
                initial.status is TaskStatus.RECOVERY_BLOCKED
                and not explicit_resume
                and not (initial.control_intent is ControlIntent.CANCEL
                         and not initial.active_operations and not initial.unresolved_effects)
                and self.store.task_events(task_id)
                and self.store.task_events(task_id)[-1].event_type == "loop.task-recovery-blocked"
                and not any(
                    operation.mode is OperationMode.WRITE
                    for operation in (*initial.active_operations, *initial.unresolved_effects)
                )
                and not any(
                    operation.mode is OperationMode.READ
                    and ":provider-turn:" in operation.logical_operation_id
                    and self._operation_dispatch_started(task_id, operation.operation_id)
                    for operation in initial.active_operations
                )
            ):
                # Recovery parking is a finite durable state. Re-observing the
                # same unknown responsibility must not append another stop
                # report or rediscovery event.
                return initial
            if (
                initial.run_instance_id == self.run_instance_id
                and initial.recovery_state in {"READY_NEW_TASK", "READY_RECOVERED"}
                and not explicit_resume
                and initial.control_intent is not ControlIntent.CANCEL
            ):
                return initial
            descriptor_ref = initial.descriptor_ref
            descriptor_hash = initial.descriptor_hash
            initial_revision = initial.task_revision
        if not descriptor_ref or not descriptor_hash:
            with self._state_lock:
                current = self.get_task(task_id)
                if current.is_terminal:
                    return current
                return self._append_recovery_blocked(
                    current,
                    blocker_id="RUN_DESCRIPTOR_MISSING",
                    reason="task cannot be resumed because its immutable run descriptor is missing",
                )
        descriptor = self.context_memory.read(descriptor_ref, expected_hash=descriptor_hash)
        recovery_identity_note: str | None = None
        if descriptor_validator is not None:
            identity_options = self._recovery_identity_options(initial)
            recovery_identity_note = descriptor_validator(descriptor, **identity_options)
        if recovery_identity_note is not None and not isinstance(recovery_identity_note, str):
            raise ValueError("recovery identity note must be text")

        # File probing performs filesystem I/O and may be slow.  Snapshot the
        # operation identities under the state lock, then reconcile outside it
        # so control/input admission remains responsive during recovery.
        command_preclaimed = False
        with self._state_lock:
            probe_task = self.get_task(task_id)
            if probe_task.is_terminal:
                return probe_task
            if probe_task.descriptor_ref != descriptor_ref or probe_task.descriptor_hash != descriptor_hash:
                raise TaskConflict("run descriptor changed during recovery validation")
            # A provider READ is externally observable even though it owns no
            # workspace write resource. A dispatch marker without a committed
            # result cannot prove whether the remote request completed.
            # Persist UNKNOWN once under its original operation identity;
            # never infer NO_EFFECT or authorize another provider dispatch.
            for operation in tuple(probe_task.active_operations):
                if (
                    operation.mode is not OperationMode.READ
                    or ":provider-turn:" not in operation.logical_operation_id
                    or operation.result_ref is not None
                    or not self._operation_dispatch_started(task_id, operation.operation_id)
                ):
                    continue
                if not operation.intent_ref:
                    raise OperationRejected("interrupted provider intent reference is missing")
                intent_doc = self.context_memory.read(operation.intent_ref)
                prior_run = str(intent_doc["expected_run_instance_id"])
                if prior_run == self.run_instance_id:
                    # Explicit resume must not reclassify this Host's live call.
                    continue
                result_document = {
                    "schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                    "task_id": task_id,
                    "operation_id": operation.operation_id,
                    "effect_status": EffectStatus.UNKNOWN.value,
                    "result": {
                        "effect_dispatched": None,
                        "effect_settled": False,
                        "dispatch_started_observed": True,
                        "reconciliation_required": True,
                        "recovery_decision": "NO_RETRY",
                        "prior_run_instance_id": prior_run,
                        "reason": (
                            "Host restarted after provider dispatch began without a committed "
                            "result; the external effect is unknown and requires reconciliation"
                        ),
                    },
                    "bound_goal_version": operation.bound_goal_version,
                    "bound_acceptance_version": operation.bound_acceptance_version,
                    "bound_input_seq": operation.bound_input_seq,
                }
                stored = self.context_memory.persist(result_document, purpose="loop-operation-result")
                self._append(
                    task_id=task_id,
                    expected_stream_version=probe_task.task_revision,
                    request_id=f"provider-recovery-unknown:{task_id}:{operation.operation_id}",
                    command_type="loop.operation.recover-provider-unknown",
                    event_type="loop.operation-result-recorded",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                        "task_id": task_id,
                        "operation_id": operation.operation_id,
                        "effect_status": EffectStatus.UNKNOWN.value,
                        "result_ref": stored.reference_id,
                        "result_hash": stored.content_hash,
                        "unknown_effect": True,
                        "recovery_decision": "NO_RETRY",
                        "resources_released_after_commit": False,
                    },
                    proofs=(stored.proof,),
                )
                probe_task = self.get_task(task_id)
            recovery_operations = tuple(
                operation.operation_id
                for operation in (*probe_task.active_operations, *probe_task.unresolved_effects)
                if operation.mode is OperationMode.WRITE
            )
            command_operation_ids: list[str] = []
            recovery_effect_kinds: dict[str, str] = {}
            for operation_id in recovery_operations:
                operation = probe_task.operations.get(operation_id)
                if operation is None or not operation.intent_ref:
                    continue
                intent_doc = self.context_memory.read(operation.intent_ref)
                evidence_ref = str(intent_doc.get("effect_evidence_ref") or "")
                evidence_hash = str(intent_doc.get("effect_evidence_hash") or "")
                if evidence_ref and evidence_hash:
                    evidence_doc = self.context_memory.read(evidence_ref, expected_hash=evidence_hash)
                    recovery_effect_kinds[operation_id] = str(evidence_doc.get("effect_kind") or "")
                if operation_id.startswith("managed-control-"):
                    # Legacy controls have no receipt binding, but are still
                    # controls; missing evidence never makes them file writes.
                    recovery_effect_kinds[operation_id] = "task-control"
                if recovery_effect_kinds.get(operation_id) in {"command", "task-control"}:
                    command_operation_ids.append(operation_id)
            if command_operation_ids and probe_task.run_instance_id != self.run_instance_id:
                old_run = probe_task.run_instance_id
                old_epoch = probe_task.execution_epoch
                self._append(
                    task_id=task_id,
                    expected_stream_version=probe_task.task_revision,
                    request_id=f"recovery-discovered:{task_id}:{self.run_instance_id}:{old_epoch}",
                    command_type="loop.task.recovery.discover",
                    event_type="loop.task-recovery-discovered",
                    payload={
                        "schema": "SITINA_LOOP_TASK_RECOVERY_DISCOVERED_V1",
                        "task_id": task_id,
                        "run_instance_id": old_run,
                        "execution_epoch": old_epoch,
                        "descriptor_ref": probe_task.descriptor_ref,
                        "descriptor_hash": probe_task.descriptor_hash,
                        "task_revision": probe_task.task_revision,
                        "stream_frontier": probe_task.stream_frontier,
                        "reason": recovery_identity_note or "command_effect_reconciliation",
                    },
                )
                probe_task = self._project(task_id, self.store.task_events(task_id))
                self._append(
                    task_id=task_id,
                    expected_stream_version=probe_task.task_revision,
                    request_id=f"recovery-claim:{task_id}:{self.run_instance_id}:{old_epoch + 1}",
                    command_type="loop.task.recovery.claim",
                    event_type="loop.task-recovery-claimed",
                    payload={
                        "schema": "SITINA_LOOP_TASK_RECOVERY_CLAIMED_V1",
                        "task_id": task_id,
                        "prior_run_instance_id": old_run,
                        "prior_execution_epoch": old_epoch,
                        "run_instance_id": self.run_instance_id,
                        "execution_epoch": old_epoch + 1,
                        "descriptor_ref": probe_task.descriptor_ref,
                        "descriptor_hash": probe_task.descriptor_hash,
                        "business_dispatch_allowed": False,
                    },
                )
                command_preclaimed = True
        if recovery_operations:
            try:
                for operation_id in recovery_operations:
                    # Each persisted effect has exactly one recovery consumer.
                    # A dedicated UNKNOWN must not be reinterpreted as a file.
                    effect_kind = recovery_effect_kinds.get(operation_id, "")
                    if effect_kind == "command":
                        self.reconcile_command_operation(task_id, operation_id)
                    elif effect_kind == "task-control":
                        self.reconcile_task_control_operation(task_id, operation_id)
            except (OperationRejected, PersistenceFenced, OSError, ValueError, KeyError) as error:
                with self._state_lock:
                    current = self.get_task(task_id)
                    return self._append_recovery_blocked(
                        current,
                        blocker_id="COMMAND_EFFECT_RECONCILIATION_FAILED",
                        reason=f"command effect reconciliation could not establish a safe boundary: {type(error).__name__}: {error}",
                        evidence_refs=tuple(str(item.result_ref) for item in current.unresolved_effects if item.result_ref),
                    )
        file_operation_ids = tuple(operation_id for operation_id in recovery_operations
                                   if recovery_effect_kinds.get(operation_id) == "file")
        if file_operation_ids:
            try:
                for operation_id in file_operation_ids:
                    self.reconcile_file_operation(task_id, operation_id)
            except (OperationRejected, PersistenceFenced, OSError, ValueError, KeyError) as error:
                with self._state_lock:
                    current = self.get_task(task_id)
                    return self._append_recovery_blocked(
                        current,
                        blocker_id="FILE_EFFECT_RECONCILIATION_FAILED",
                        reason=f"file effect reconciliation could not establish a safe boundary: {type(error).__name__}: {error}",
                        evidence_refs=tuple(
                            str(item.result_ref) for item in current.unresolved_effects if item.result_ref
                        ),
                    )

        with self._state_lock:
            current = self.get_task(task_id)
            control_unknowns = [item for item in current.unresolved_effects
                                if recovery_effect_kinds.get(item.operation_id) == "task-control"]
            if control_unknowns:
                return self._append_recovery_blocked(current,
                    blocker_id="NATIVE_CONTROL_OUTCOME_NOT_PROVEN",
                    reason="the original native service/control has no complete bound terminal result; preserve it and do not repeat it",
                    evidence_refs=tuple(str(item.result_ref) for item in control_unknowns if item.result_ref))

        # Child lifecycle recovery is separate from file-effect recovery: a
        # persisted result can be settled/reused, while an interrupted model
        # call without a result is parked rather than blindly replayed.
        self.recover_child_delegations(task_id)

        with self._state_lock:
            task = self.get_task(task_id)
            if task.is_terminal:
                return task
            if task.descriptor_ref != descriptor_ref or task.descriptor_hash != descriptor_hash:
                raise TaskConflict("run descriptor changed during recovery validation")
            if task.active_operations or task.unresolved_effects:
                latest_events = self.store.task_events(task_id)
                if (
                    task.status is TaskStatus.RECOVERY_BLOCKED
                    and latest_events
                    and latest_events[-1].event_type == "loop.task-recovery-blocked"
                ):
                    # The same unresolved facts remain parked. A later host
                    # that supplied new file evidence reaches this point only
                    # after the reconciliation attempt above; returning here
                    # keeps unchanged parking idempotent without rejecting
                    # newly resolvable facts.
                    return task
                return self._append_recovery_blocked(
                    task,
                    blocker_id="IN_FLIGHT_EFFECT_REQUIRES_3C",
                    reason="task still has an active or unresolved effect after a new observation",
                    evidence_refs=tuple(
                        str(item.result_ref) for item in task.unresolved_effects if item.result_ref
                    ),
                )
            resume_disposition = None
            if explicit_resume:
                if not task.resume_request_id:
                    raise TaskConflict("explicit recovery requires a persisted resume request")
                resume_event = next(
                    (event for event in reversed(self.store.task_events(task_id))
                     if event.event_type == "loop.task-resume-requested"
                     and event.payload.get("resume_request_id") == task.resume_request_id),
                    None,
                )
                if resume_event is None:
                    raise TaskConflict("persisted resume event is missing")
                resume_disposition = resume_event.payload.get("provider_response_disposition")
                frontier_key = (
                    "expected_received_input_seq" if resume_disposition is not None
                    else "expected_handled_input_seq"
                )
                resume_frontier = int(resume_event.payload.get(frontier_key, -1))
                if task.control_intent is ControlIntent.CANCEL or any(
                    record.sequence > resume_frontier
                    and record.kind in {InputKind.PAUSE, InputKind.CANCEL}
                    for record in task.inputs
                ):
                    return self._append_recovery_blocked(
                        task,
                        blocker_id="CANCEL_WINS_OVER_RESUME",
                        reason="explicit resume cannot supersede a later PAUSE or CANCEL",
                    )
                if resume_disposition is not None and (
                    task.received_input_seq != resume_frontier
                    or task.handled_input_seq != resume_event.payload["expected_handled_input_seq"]
                    or task.goal_version != resume_disposition["goal_version"]
                    or task.acceptance_version != resume_disposition["acceptance_version"]
                    or task.artifact_ref != resume_disposition["artifact_ref"]
                ):
                    return self._append_recovery_blocked(
                        task,
                        blocker_id="PROVIDER_DISPOSITION_FRONTIER_CHANGED",
                        reason="task input or business version changed after the explicit disposition",
                    )
            elif task.control_intent not in {ControlIntent.RUN, ControlIntent.CANCEL}:
                return task

            # A live paused task only needs a durable recovery-ready transition;
            # an old-run task is claimed and reconciled below.
            if (task.run_instance_id == self.run_instance_id and task.recovery_state in {
                "READY_NEW_TASK", "READY_RECOVERED"
            }) or command_preclaimed:
                if command_preclaimed or resume_disposition is not None or task.control_intent is ControlIntent.CANCEL:
                    open_attempts = sorted(
                        set(task.attempt_plans)
                        - {
                            str(item.get("attempt_id"))
                            for item in task.attempt_settlements
                            if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                        }
                    )
                    for attempt_id in open_attempts:
                        task = self._append_recovery_settlement(task, attempt_id)
                    while task.received_input_seq > task.handled_input_seq:
                        record = next(
                            item
                            for item in task.inputs
                            if item.sequence == task.handled_input_seq + 1
                        )
                        task = self.handle_next_input(
                            task_id,
                            affects_goal=record.kind in {InputKind.MESSAGE, InputKind.CORRECTION},
                            affects_acceptance=record.kind in {InputKind.MESSAGE, InputKind.CORRECTION},
                            allow_recovery=True,
                        )
                    # The recovery-ready run/epoch binding is the semantic
                    # parent identity for settled child evidence.  Recompute
                    # it after any claim/handled-input transition so a
                    # result never remains falsely marked current.
                    task = self.recover_child_delegations(task_id)
                control = ControlIntent.RUN if explicit_resume else task.control_intent
                status = (TaskStatus.RUNNABLE if control is ControlIntent.RUN else
                          TaskStatus.CANCELLING if control is ControlIntent.CANCEL else task.status)
                self._append(
                    task_id=task_id,
                    expected_stream_version=task.task_revision,
                    request_id=(
                        f"recovery-ready:{task_id}:{self.run_instance_id}:{task.execution_epoch}:"
                        f"{task.resume_request_id or 'resume'}"
                    ),
                    command_type="loop.task.recovery.ready",
                    event_type="loop.task-recovery-ready",
                    payload={
                        "schema": "SITINA_LOOP_TASK_RECOVERY_READY_V1",
                        "task_id": task_id,
                        "run_instance_id": task.run_instance_id,
                        "execution_epoch": task.execution_epoch,
                        "status": status.value,
                        "control_intent": control.value,
                        "reconciled_handled_input_seq": task.handled_input_seq,
                        "recovery_state": "READY_RECOVERED",
                        "business_dispatch_allowed": control is ControlIntent.RUN,
                    },
                )
                return self.get_task(task_id)

            old_run = task.run_instance_id
            old_epoch = task.execution_epoch
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"recovery-discovered:{task_id}:{self.run_instance_id}:{old_epoch}",
                command_type="loop.task.recovery.discover",
                event_type="loop.task-recovery-discovered",
                payload={
                    "schema": "SITINA_LOOP_TASK_RECOVERY_DISCOVERED_V1",
                    "task_id": task_id,
                    "run_instance_id": old_run,
                    "execution_epoch": old_epoch,
                    "descriptor_ref": task.descriptor_ref,
                    "descriptor_hash": task.descriptor_hash,
                    "task_revision": task.task_revision,
                    "stream_frontier": task.stream_frontier,
                    "reason": recovery_identity_note or ("explicit_resume" if explicit_resume else "safe_bootstrap_continuation"),
                },
            )
            task = self._project(task_id, self.store.task_events(task_id))
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"recovery-claim:{task_id}:{self.run_instance_id}:{old_epoch + 1}",
                command_type="loop.task.recovery.claim",
                event_type="loop.task-recovery-claimed",
                payload={
                    "schema": "SITINA_LOOP_TASK_RECOVERY_CLAIMED_V1",
                    "task_id": task_id,
                    "prior_run_instance_id": old_run,
                    "prior_execution_epoch": old_epoch,
                    "run_instance_id": self.run_instance_id,
                    "execution_epoch": old_epoch + 1,
                    "descriptor_ref": task.descriptor_ref,
                    "descriptor_hash": task.descriptor_hash,
                    "business_dispatch_allowed": False,
                },
            )
            task = self._project(task_id, self.store.task_events(task_id))
            open_attempts = sorted(set(task.attempt_plans) - {
                str(item.get("attempt_id"))
                for item in task.attempt_settlements
                if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
            })
            for attempt_id in open_attempts:
                task = self._append_recovery_settlement(task, attempt_id)
            while task.received_input_seq > task.handled_input_seq:
                record = next(item for item in task.inputs if item.sequence == task.handled_input_seq + 1)
                affects = record.kind in {InputKind.MESSAGE, InputKind.CORRECTION}
                task = self.handle_next_input(
                    task_id,
                    affects_goal=affects,
                    affects_acceptance=affects,
                    allow_recovery=True,
                )
            task = self.recover_child_delegations(task_id)
            if task.control_intent is ControlIntent.CANCEL:
                final_status, final_control = TaskStatus.CANCELLING, ControlIntent.CANCEL
            elif task.control_intent is ControlIntent.PAUSE and not explicit_resume:
                final_status, final_control = TaskStatus.PAUSED, ControlIntent.PAUSE
            else:
                final_status, final_control = TaskStatus.RUNNABLE, ControlIntent.RUN
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"recovery-ready:{task_id}:{self.run_instance_id}:{task.execution_epoch}",
                command_type="loop.task.recovery.ready",
                event_type="loop.task-recovery-ready",
                payload={
                    "schema": "SITINA_LOOP_TASK_RECOVERY_READY_V1",
                    "task_id": task_id,
                    "run_instance_id": self.run_instance_id,
                    "execution_epoch": task.execution_epoch,
                    "status": final_status.value,
                    "control_intent": final_control.value,
                    "reconciled_handled_input_seq": task.handled_input_seq,
                    "recovery_state": "READY_RECOVERED",
                    "business_dispatch_allowed": final_control is ControlIntent.RUN,
                },
            )
        self.recover_child_delegations(task_id)
        return self.get_task(task_id)

    def _validate_cancel_reconciliation(self, task, request, *, request_id, host_descriptor_context):
        from .cancel_reconciliation import validate_cancel_reconciliation

        operation_id = request.get('operation_id') if isinstance(request, Mapping) else None
        if operation_id is not None and not self._operation_dispatch_started(task.task_id, operation_id):
            raise TaskConflict('cancel disposition requires the original dispatch marker')
        return validate_cancel_reconciliation(
            task, request, request_id=request_id, host_context=host_descriptor_context,
            read=self.context_memory.read, events=self.store.task_events(task.task_id),
        )

    def cancel_reconciliation_preview(self, task_id: str, host_descriptor_context: Mapping[str, Any]):
        """Return an exact, unconfirmed cancellation choice without doing work."""
        with self._state_lock:
            task = self.get_task(task_id)
            preview = {'state': 'blocked', 'task_revision': task.task_revision}
            try:
                if not task.descriptor_ref or not task.descriptor_hash:
                    raise TaskConflict('original descriptor is missing')
                descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
                pending = tuple(task.unresolved_effects)
                if len(pending) > 1:
                    raise TaskConflict('other unknown operations must be reconciled first')
                operation = pending[0] if pending else None
                result_hash = None
                if operation is not None:
                    results = [event for event in self.store.task_events(task_id)
                               if event.position <= task.stream_frontier
                               and event.event_type == 'loop.operation-result-recorded'
                               and event.payload.get('operation_id') == operation.operation_id]
                    if len(results) != 1:
                        raise TaskConflict('original result is not uniquely committed')
                    result_hash = results[0].payload['result_hash']
                request = {
                    'expected_task_revision': task.task_revision,
                    'expected_run_instance_id': task.run_instance_id,
                    'expected_execution_epoch': task.execution_epoch,
                    'expected_received_input_seq': task.received_input_seq,
                    'expected_handled_input_seq': task.handled_input_seq,
                    'descriptor_hash': task.descriptor_hash,
                    'from_software_identity': descriptor['software_identity'],
                    'to_software_identity': host_descriptor_context['software_identity'],
                    'operation_id': operation.operation_id if operation else None,
                    'result_ref': operation.result_ref if operation else None,
                    'result_hash': result_hash,
                    'confirm_cancel': True,
                    'accept_unknown_usage': operation is not None,
                    'abandon_missing_response': operation is not None,
                }
                inspection = operation is not None and operation.operation_id.startswith('task-skill-management-')
                if inspection:
                    request.update(abandon_inspection_result=True,
                                   accept_unknown_usage=False, abandon_missing_response=False)
                validated = self._validate_cancel_reconciliation(
                    task, request, request_id='preview', host_descriptor_context=host_descriptor_context)
                unconfirmed = {**request, 'confirm_cancel': False,
                               'accept_unknown_usage': False, 'abandon_missing_response': False}
                if inspection:
                    unconfirmed['abandon_inspection_result'] = False
                preview.update(state='confirmation_required',
                               request=unconfirmed,
                               original_usage_unsettled=validated['usage_unsettled'], successor='CANCEL_ONLY')
                if inspection:
                    preview.update(original_inspection_result_unsettled=True,
                                   installation_dispatch_excluded=True,
                                   temporary_download_state='UNKNOWN')
            except (TaskConflict, ValueError, TypeError, KeyError) as error:
                preview['reason'] = str(error)
            return preview

    def request_cancel_reconciliation(self, task_id: str, *, request_id: str,
                                      request: Mapping[str, Any], host_descriptor_context: Mapping[str, Any]):
        """Durably accept a cancel-only choice; never resume or dispatch work."""
        with self._state_lock:
            task = self.get_task(task_id)
            existing = task.cancel_reconciliation
            if existing is not None:
                if (existing.get('request_id') == request_id and existing.get('request') == request
                        and existing.get('host_descriptor_context') == host_descriptor_context):
                    return task
                raise TaskConflict('cancel reconciliation already has a different committed choice')
            receipt = self._validate_cancel_reconciliation(
                task, request, request_id=request_id, host_descriptor_context=host_descriptor_context)
            self._append(
                task_id=task_id, expected_stream_version=task.task_revision,
                request_id='cancel-reconciliation:' + request_id,
                command_type='loop.task.cancel.reconcile',
                event_type='loop.task-cancel-reconciliation-recorded',
                payload={'schema': 'SITINA_LOOP_TASK_CANCEL_RECONCILIATION_RECORDED_V1',
                         'task_id': task_id, 'receipt': receipt},
            )
            return self.get_task(task_id)

    def cancel_safely(self, task_id: str) -> TaskProjection:
        """Commit a CANCELLED terminal event without dispatching a Provider call.

        This is intentionally limited to a current, fully reconciled task with
        no active or unknown effects.  Unknown effects remain recovery-blocked
        for the later effect-reconciliation batch.
        """

        with self._state_lock:
            task = self.get_task(task_id)
            if task.is_terminal:
                return task
            if task.control_intent is not ControlIntent.CANCEL:
                return task
            if task.received_input_seq != task.handled_input_seq:
                if task.active_operations or task.unresolved_effects or (
                    task.run_instance_id != self.run_instance_id
                    or task.recovery_state not in {"READY_NEW_TASK", "READY_RECOVERED"}
                ):
                    return self.dock_cancel_pending(task_id)
                raise TaskConflict("cancel terminal requires all durable input to be handled")
            if task.active_operations or task.unresolved_effects:
                return self.dock_cancel_pending(task_id)
            proposal = CompletionProposal(
                proposal_id="cancel-recovery-" + secrets.token_hex(12),
                terminal_status=TaskStatus.CANCELLED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={
                    "reason": "user_cancelled",
                    "recovered_without_provider_dispatch": True,
                    "completed_effects_retained": True,
                },
            )
            return self.propose_terminal(task_id, proposal)

    def dock_cancel_pending(self, task_id: str) -> TaskProjection:
        """Persist a recoverable CANCEL dock without claiming an old executor.

        A stale host may durably accept CANCEL while an UNKNOWN write still
        owns the lane/project resources.  This boundary records the stop
        obligation and preserves all ownership; it is deliberately not a
        terminal proposal and never advances the handled-input frontier.
        """

        with self._state_lock:
            task = self.get_task(task_id)
            if task.is_terminal or task.control_intent is not ControlIntent.CANCEL:
                return task
            has_effect = bool(task.active_operations or task.unresolved_effects)
            reason_code = 'CANCEL_WITH_UNKNOWN_EFFECT' if has_effect else 'CANCEL_INPUT_PENDING'
            if task.stop_report_ref:
                try:
                    report = self.context_memory.read(task.stop_report_ref)
                except BaseException:
                    report = {}
                if report.get("reason_code") == reason_code:
                    return task
            if not (task.active_operations or task.unresolved_effects) and (
                task.received_input_seq == task.handled_input_seq
            ):
                return task
            return self._append_recovery_blocked(
                task,
                blocker_id=reason_code,
                reason=(
                    "CANCEL is durably retained while an active or unknown effect "
                    "requires explicit reconciliation; resources and input frontier remain owned"
                    if has_effect else
                    "CANCEL is durably retained; existing effects are settled, "
                    "and the cancellation input awaits recovery handling"
                ),
                evidence_refs=tuple(
                    str(item.result_ref) for item in task.unresolved_effects if item.result_ref
                ),
            )

    def dock_after_restart(self, task_id: str) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            if task.is_terminal:
                return task
            if task.recovery_state == "RECOVERY_NOT_CONNECTED":
                return task
            if task.run_instance_id == self.run_instance_id:
                return task
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"recovery-dock:{task_id}:{self.run_instance_id}",
                command_type="loop.task.recovery-dock",
                event_type="loop.task-recovery-docked",
                payload={
                    "schema": "SITINA_LOOP_TASK_RECOVERY_DOCKED_V1",
                    "task_id": task_id,
                    "prior_run_instance_id": task.run_instance_id,
                    "run_instance_id": self.run_instance_id,
                    "execution_epoch": task.execution_epoch + 1,
                    "status": TaskStatus.RECOVERY_BLOCKED.value,
                    "recovery_state": "RECOVERY_NOT_CONNECTED",
                    "business_dispatch_allowed": False,
                    "reason": "batch 1a persists state but full same-version task recovery is not connected",
                },
            )
            return self.get_task(task_id)

    @staticmethod
    def _clarification_answer(task: TaskProjection, body: str) -> Mapping[str, Any]:
        try:
            answer = json.loads(body)
        except (TypeError, ValueError):
            raise TaskConflict("clarification answer must be a bound JSON object") from None
        fields = {
            "task_id", "question_id", "goal_version", "acceptance_version",
            "question_input_seq", "answer",
        }
        waiting = task.waiting_reason
        if not isinstance(answer, dict) or set(answer) != fields or not isinstance(waiting, Mapping):
            raise TaskConflict("clarification answer has no current question binding")
        expected = {
            "task_id": task.task_id,
            "question_id": waiting.get("blocker_id"),
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "question_input_seq": task.handled_input_seq,
        }
        if (
            not isinstance(expected["question_id"], str)
            or not expected["question_id"].startswith("clarification:")
            or any(answer[key] != value for key, value in expected.items())
            or any(type(answer[key]) is not int for key in (
                "goal_version", "acceptance_version", "question_input_seq"
            ))
            or waiting.get("task_id") != task.task_id
            or waiting.get("goal_version") != task.goal_version
            or waiting.get("acceptance_version") != task.acceptance_version
            or waiting.get("handled_input_seq") != task.handled_input_seq
            or not isinstance(answer["answer"], str)
            or not answer["answer"].strip()
        ):
            raise TaskConflict("clarification answer is empty, stale, or belongs to another question")
        checkpoint_id = expected["question_id"].removeprefix("clarification:")
        if not any(
            item.get("checkpoint_id") == checkpoint_id
            and item.get("reason") == "CLARIFICATION_REQUIRED"
            and item.get("goal_input_source_refs")
            and item.get("binding_after_return", {}).get("goal_version") == task.goal_version
            and item.get("binding_after_return", {}).get("acceptance_version") == task.acceptance_version
            and item.get("binding_after_return", {}).get("handled_input_seq") == task.handled_input_seq
            and item.get("goal_input", {}).get("question") == waiting.get("reason")
            for item in task.attempt_checkpoints
        ):
            raise TaskConflict("clarification question has no durable Provider checkpoint")
        return answer

    def accept_input(
        self,
        task_id: str,
        *,
        input_id: str,
        kind: InputKind,
        body: str,
    ) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            # Persistence/authority fencing still applies before any input
            # decision.  Exact replay is checked before the terminal guard so
            # a durable receipt remains observable after terminal settlement;
            # only a genuinely new input reaches the terminal rejection.
            self._require_persistence()
            body_document = {
                "schema": "SITINA_LOOP_INPUT_BODY_V1",
                "task_id": task_id,
                "input_id": input_id,
                "kind": kind.value,
                "body": body,
            }
            body_hash = hashlib.sha256(canonical_json_bytes(body_document)).hexdigest()
            existing = next((item for item in task.inputs if item.input_id == input_id), None)
            if existing is not None:
                if existing.kind is not kind or existing.body_hash != body_hash:
                    raise TaskConflict("input ID is already bound to different content")
                return task
            if task.is_terminal:
                raise TaskConflict("new work after a terminal task requires a related new task")
            if kind is InputKind.CLARIFICATION:
                if (
                    task.status is not TaskStatus.WAITING_INPUT
                    or task.control_intent is not ControlIntent.RUN
                    or task.received_input_seq != task.handled_input_seq
                ):
                    raise TaskConflict("clarification requires an unanswered current waiting task")
                self._clarification_answer(task, body)
            try:
                body_content = self.context_memory.persist(body_document, purpose="loop-user-input")
            except BaseException as error:
                self._fail_persistence(error)
                raise
            sequence = task.received_input_seq + 1
            control = task.control_intent
            status = task.status
            # CANCEL is a monotonic terminal control intent for dispatch: later
            # messages, corrections, pauses, or resume requests remain durable
            # inputs but cannot reopen business work.
            if task.control_intent is ControlIntent.CANCEL:
                control = ControlIntent.CANCEL
                status = TaskStatus.CANCELLING
            elif kind is InputKind.PAUSE:
                control = ControlIntent.PAUSE
                status = TaskStatus.PAUSING
            elif kind is InputKind.CANCEL:
                control = ControlIntent.CANCEL
                status = TaskStatus.CANCELLING
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"input-receive:{task_id}:{input_id}",
                command_type="loop.input.receive",
                event_type="loop.input-received",
                payload={
                    "schema": "SITINA_LOOP_INPUT_RECEIVED_V1",
                    "task_id": task_id,
                    "input_id": input_id,
                    "input_seq": sequence,
                    "kind": kind.value,
                    "body_ref": body_content.reference_id,
                    "body_hash": body_hash,
                    "control_intent": control.value,
                    "status": status.value,
                    "received_at": iso_now(),
                },
                proofs=(body_content.proof,),
            )
            # A newly received correction/control input changes the semantic
            # parent binding immediately, even before the input is handled.
            # Settled child evidence therefore becomes late evidence at the
            # receive boundary and is never accidentally presented as current.
            updated = self.get_task(task_id)
            for delegation_id, child in tuple(updated.child_delegations.items()):
                if child.get("result_ref"):
                    self.refresh_child_applicability(task_id, delegation_id)
            return self.get_task(task_id)

    def handle_next_input(
        self,
        task_id: str,
        *,
        affects_goal: bool = False,
        affects_acceptance: bool = False,
        allow_recovery: bool = False,
        expected_input_seq: int | None = None,
        expected_input_id: str | None = None,
        derive_effects_from_record: bool = False,
    ) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            if not allow_recovery:
                self._assert_current_executor(task)
            next_sequence = task.handled_input_seq + 1
            record = next((item for item in task.inputs if item.sequence == next_sequence), None)
            if record is None:
                raise TaskConflict("there is no next persisted input to handle")
            if expected_input_seq is not None and next_sequence != int(expected_input_seq):
                raise TaskConflict(
                    "next persisted input sequence changed before handling: "
                    f"expected {int(expected_input_seq)}, found {next_sequence}"
                )
            if expected_input_id is not None and record.input_id != str(expected_input_id):
                raise TaskConflict(
                    "next persisted input identity changed before handling: "
                    f"expected {expected_input_id}, found {record.input_id}"
                )
            # Callers that observed a record before acquiring this lock must
            # not carry its kind-derived version decision across a concurrent
            # handle.  Recompute from the record selected under this lock.
            if derive_effects_from_record:
                affects_goal = record.kind in {InputKind.MESSAGE, InputKind.CORRECTION}
                affects_acceptance = affects_goal
            self.stop_managed_processes(task_id, reason="native-input-invalidation")
            if record.kind is InputKind.CLARIFICATION:
                body_document = self.context_memory.read(record.body_ref)
                if (
                    body_document.get("task_id") != task_id
                    or body_document.get("input_id") != record.input_id
                    or body_document.get("kind") != InputKind.CLARIFICATION.value
                ):
                    raise TaskConflict("clarification input body identity changed")
                self._clarification_answer(task, body_document.get("body"))
                affects_goal = False
                affects_acceptance = False
            goal_version = task.goal_version + (1 if affects_goal else 0)
            acceptance_version = task.acceptance_version + (1 if affects_acceptance else 0)
            criteria_lineage_version = task.criteria_lineage_version + (
                1 if affects_goal or affects_acceptance else 0
            )
            if record.kind is InputKind.CORRECTION and not affects_goal and not affects_acceptance:
                goal_version += 1
                criteria_lineage_version += 1
            if task.control_intent is ControlIntent.PAUSE:
                status = TaskStatus.PAUSING if task.active_operations else TaskStatus.PAUSED
            elif task.control_intent is ControlIntent.CANCEL:
                status = TaskStatus.CANCELLING
            else:
                status = TaskStatus.WAITING_OPERATION if task.active_operations else TaskStatus.RUNNABLE
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"input-handle:{task_id}:{next_sequence}",
                command_type="loop.input.handle",
                event_type="loop.input-handled",
                payload={
                    "schema": "SITINA_LOOP_INPUT_HANDLED_V1",
                    "task_id": task_id,
                    "input_id": record.input_id,
                    "input_seq": next_sequence,
                    "handled_input_seq": next_sequence,
                    "goal_version": goal_version,
                    "acceptance_version": acceptance_version,
                    "criteria_lineage_version": criteria_lineage_version,
                    "control_intent": task.control_intent.value,
                    "status": status.value,
                },
            )
            # Refreshing a child's applicability returns a child projection;
            # the input-handling API must continue to return the parent task
            # projection.  Keep the parent frontier authoritative even when
            # several settled children need evidence-only reclassification.
            updated = self.get_task(task_id)
            for delegation_id, child in tuple(updated.child_delegations.items()):
                if child.get("result_ref"):
                    self.refresh_child_applicability(task_id, delegation_id)
            return self.get_task(task_id)

    def bind_agent_request(self, task_id: str):
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            return self.agent_runner.bind(task)

    def execute_operation(
        self,
        task_id: str,
        intent: OperationIntent,
        dispatch: Callable[[], OperationOutcome],
        *,
        prepare: Callable[[], Mapping[str, Any]] | None = None,
        lane_preacquired: bool = False,
    ) -> OperationOutcome:
        if lane_preacquired:
            if intent.mode is not OperationMode.WRITE:
                raise OperationRejected("pre-acquired operation lane requires WRITE mode")
            if not self.operations.is_owner(str(task_id), str(intent.operation_id)):
                raise OperationRejected("pre-acquired operation lane is not owned by this operation")
        lane_acquired = bool(lane_preacquired)
        intent_committed = False
        result_committed = False
        unknown_effect_committed = False
        if intent.mode is OperationMode.WRITE and not lane_preacquired:
            self.operations.acquire(task_id, intent.operation_id, resources=intent.resources)
            lane_acquired = True
        try:
            with self._state_lock:
                task = self.get_task(task_id)
                existing = task.operations.get(intent.operation_id)
                if existing is not None:
                    raise OperationRejected(
                        "operation ID already exists; inspect its persisted effect before any retry"
                    )
                self._assert_intent_current(task, intent)
                self._admit_operation_resources(task, intent)
                if intent.execution_owner and intent.mode is OperationMode.WRITE:
                    action_key = intent.business_action_key or intent.logical_operation_id
                    action_family = intent.business_action_family or action_key
                    related = [op for op in task.operations.values()
                               if (op.business_action_family or op.business_action_key or op.logical_operation_id) == action_family]
                    if any(op.unknown_effect or (not op.result_ref and op.effect_status is EffectStatus.INTENT_RECORDED)
                           for op in related):
                        raise OperationRejected("business action has an unresolved effect; reconcile before retry")
                    matches = [op for op in task.operations.values()
                               if (op.business_action_key or op.logical_operation_id) == action_key]
                    for previous in reversed(matches):
                        if previous.unknown_effect or not previous.result_ref:
                            raise OperationRejected("business action has an unresolved effect; reconcile before retry")
                        if previous.effect_status is EffectStatus.SUCCEEDED:
                            saved = self.context_memory.read(previous.result_ref)
                            return OperationOutcome(EffectStatus.SUCCEEDED, {
                                **dict(saved["result"]), "replayed_operation_id": previous.operation_id,
                                "effect_dispatched": False,
                            })
                if intent.business_attempt_id is not None:
                    plan = task.attempt_plans.get(intent.business_attempt_id)
                    if plan is None:
                        raise OperationRejected("business operation has no committed attempt plan")
                    if any(
                        item.get("attempt_id") == intent.business_attempt_id
                        and item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                        for item in task.attempt_settlements
                    ):
                        raise OperationRejected("business operation belongs to an already settled attempt")
                    if (
                        plan.get("run_instance_id") != task.run_instance_id
                        or int(plan.get("execution_epoch") or 0) != task.execution_epoch
                        or int(plan.get("goal_version") or 0) != task.goal_version
                        or int(plan.get("acceptance_version") or 0) != task.acceptance_version
                        or int(plan.get("criteria_lineage_version", 1)) != task.criteria_lineage_version
                        or int(plan.get("handled_input_seq", -1)) != task.handled_input_seq
                        or plan.get("artifact_ref") != task.artifact_ref
                        or plan.get("environment_ref") != task.environment_ref
                        or plan.get("capability_snapshot_id") != task.capability_snapshot_id
                    ):
                        raise OperationRejected("business operation attempt plan is stale")
                if intent.mode is OperationMode.WRITE:
                    self._assert_resources_available(task_id, intent.resources)
                observations = tuple(item.observe() for item in intent.preconditions)
                mismatches = tuple(item for item in observations if not item["matches"])
                segment_id = "execution-segment-" + secrets.token_hex(12)
                if mismatches:
                    self._append(
                        task_id=task_id,
                        expected_stream_version=task.task_revision,
                        request_id=f"operation-precondition:{task_id}:{intent.operation_id}",
                        command_type="loop.operation.precondition-changed",
                        event_type="loop.operation-precondition-changed",
                        payload={
                            "schema": "SITINA_LOOP_OPERATION_PRECONDITION_CHANGED_V1",
                            "task_id": task_id,
                            "operation_id": intent.operation_id,
                            "logical_operation_id": intent.logical_operation_id,
                            "attempt_id": intent.attempt_id,
                            "business_attempt_id": intent.business_attempt_id,
                            "mode": intent.mode.value,
                            "execution_segment_id": segment_id,
                            "resources": list(intent.resources),
                            "observations": [dict(item) for item in observations],
                            "effect_dispatched": False,
                        },
                    )
                    raise OperationRejected("operation prerequisite changed after authorization")
                effect_evidence: Mapping[str, Any] = {}
                if prepare is not None:
                    prepared = prepare()
                    if not isinstance(prepared, Mapping):
                        raise TypeError("operation preparation must return a mapping")
                    effect_evidence = dict(prepared)
                intent_document = intent.as_dict(observations)
                intent_document["task_id"] = task_id
                intent_document["execution_segment_id"] = segment_id
                intent_document["write_authority_acquired"] = intent.mode is OperationMode.WRITE
                stored_evidence = None
                if effect_evidence:
                    effect_document = {
                        "task_id": task_id,
                        "operation_id": intent.operation_id,
                        "logical_operation_id": intent.logical_operation_id,
                        "attempt_id": intent.attempt_id,
                        "business_attempt_id": intent.business_attempt_id,
                        "run_instance_id": intent.expected_run_instance_id,
                        "execution_epoch": intent.expected_execution_epoch,
                        "phase": "AUTHORIZED_NOT_STARTED",
                        **dict(effect_evidence),
                        "schema": "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1",
                    }
                    if effect_evidence.get("method_plan_schema") == "SITINA_EXTENSION_METHOD_PLAN_V1":
                        effect_document["method_plan"] = dict(effect_evidence)
                    try:
                        stored_evidence = self.context_memory.persist(
                            effect_document,
                            purpose="loop-operation-effect-evidence",
                        )
                    except BaseException as error:
                        self._fail_persistence(error)
                        raise
                    intent_document["effect_evidence_ref"] = stored_evidence.reference_id
                    intent_document["effect_evidence_hash"] = stored_evidence.content_hash
                try:
                    stored_intent = self.context_memory.persist(
                        intent_document,
                        purpose="loop-operation-intent",
                    )
                except BaseException as error:
                    self._fail_persistence(error)
                    raise
                self._append(
                    task_id=task_id,
                    expected_stream_version=task.task_revision,
                    request_id=f"operation-intent:{task_id}:{intent.operation_id}",
                    command_type="loop.operation.record-intent",
                    event_type="loop.operation-intent-recorded",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_INTENT_RECORDED_V1",
                        "task_id": task_id,
                        "operation_id": intent.operation_id,
                        "logical_operation_id": intent.logical_operation_id,
                        "attempt_id": intent.attempt_id,
                        "business_attempt_id": intent.business_attempt_id,
                        "mode": intent.mode.value,
                        "execution_segment_id": segment_id,
                        "resources": list(intent.resources),
                        "intent_ref": stored_intent.reference_id,
                        "intent_hash": stored_intent.content_hash,
                        "effect_evidence_ref": (
                            stored_evidence.reference_id if stored_evidence is not None else None
                        ),
                        "effect_evidence_hash": (
                            stored_evidence.content_hash if stored_evidence is not None else None
                        ),
                        "bound_goal_version": task.goal_version,
                        "bound_acceptance_version": task.acceptance_version,
                        "bound_input_seq": task.handled_input_seq,
                        "run_instance_id": task.run_instance_id,
                        "execution_epoch": task.execution_epoch,
                        "effect_dispatched": True,
                    },
                    proofs=(
                        stored_intent.proof,
                        *((stored_evidence.proof,) if stored_evidence is not None else ()),
                    ),
                )
                intent_committed = True

            outcome: OperationOutcome | None = None
            dispatch_blocked: str | None = (
                "pre-dispatch file validation rejected the requested effect: "
                + str(effect_evidence.get("planning_error"))
                if effect_evidence.get("planning_error")
                else None
            )
            if effect_evidence or intent.mode is OperationMode.READ or intent.execution_owner:
                with self._state_lock:
                    current = self.get_task(task_id)
                    binding_changes = []
                    for name, expected, actual in (
                        ("run_instance_id", intent.expected_run_instance_id, current.run_instance_id),
                        ("execution_epoch", intent.expected_execution_epoch, current.execution_epoch),
                        ("goal_version", intent.expected_goal_version, current.goal_version),
                        ("acceptance_version", intent.expected_acceptance_version, current.acceptance_version),
                        ("handled_input_seq", intent.expected_handled_input_seq, current.handled_input_seq),
                        ("capability_snapshot_id", intent.capability_snapshot_id, current.capability_snapshot_id),
                    ):
                        if expected != actual:
                            binding_changes.append(name)
                    if current.control_intent is not ControlIntent.RUN:
                        binding_changes.append("control_intent")
                    if current.received_input_seq != current.handled_input_seq:
                        binding_changes.append("unhandled_input")
                    if intent.execution_owner and not self.child_execution_current(task_id, intent.execution_owner):
                        binding_changes.append("child_ownership_revoked")
                    if binding_changes and dispatch_blocked is None:
                        dispatch_blocked = "dispatch barrier changed: " + ", ".join(binding_changes)
                if dispatch_blocked is not None:
                    # Intent is durable, but no dispatch-start marker exists;
                    # result persistence below records a safe no-dispatch
                    # outcome and the original effect is never retried here.
                    outcome = OperationOutcome(
                        EffectStatus.FAILED,
                        {
                            "effect_dispatched": False,
                            "recovery_decision": "NO_EFFECT",
                            "reason": dispatch_blocked,
                        },
                    )
                else:
                    with self._state_lock:
                        current = self.get_task(task_id)
                        started_document = {
                            "schema": "SITINA_LOOP_OPERATION_DISPATCH_STARTED_V1",
                            "task_id": task_id,
                            "operation_id": intent.operation_id,
                            "logical_operation_id": intent.logical_operation_id,
                            "attempt_id": intent.attempt_id,
                            "business_attempt_id": intent.business_attempt_id,
                            "run_instance_id": intent.expected_run_instance_id,
                            "execution_epoch": intent.expected_execution_epoch,
                            "effect_evidence_ref": (
                                stored_evidence.reference_id if stored_evidence is not None else None
                            ),
                            "phase": "DISPATCH_STARTED",
                        }
                        stored_started = self.context_memory.persist(
                            started_document,
                            purpose="loop-operation-dispatch-start",
                        )
                        self._append(
                            task_id=task_id,
                            expected_stream_version=current.task_revision,
                            request_id=f"operation-dispatch-started:{task_id}:{intent.operation_id}",
                            command_type="loop.operation.dispatch-start",
                            event_type="loop.operation-dispatch-started",
                            payload={
                                "schema": "SITINA_LOOP_OPERATION_DISPATCH_STARTED_V1",
                                "task_id": task_id,
                                "operation_id": intent.operation_id,
                                "logical_operation_id": intent.logical_operation_id,
                                "attempt_id": intent.attempt_id,
                                "business_attempt_id": intent.business_attempt_id,
                                "dispatch_ref": stored_started.reference_id,
                                "dispatch_hash": stored_started.content_hash,
                                "effect_evidence_ref": (
                                    stored_evidence.reference_id if stored_evidence is not None else None
                                ),
                                "run_instance_id": intent.expected_run_instance_id,
                                "execution_epoch": intent.expected_execution_epoch,
                            },
                            proofs=(stored_started.proof,),
                        )
            if dispatch_blocked is None and effect_evidence.get("effect_kind") == "file":
                # File effects are host-local synchronous operations.  Keep
                # the coordinator lock across the final barrier and the
                # actual call so a CANCEL accepted by a re-entrant barrier
                # hook cannot slip between validation and mutation.
                with self._state_lock:
                    current = self.get_task(task_id)
                    binding_changes = []
                    for name, expected, actual in (
                        ("run_instance_id", intent.expected_run_instance_id, current.run_instance_id),
                        ("execution_epoch", intent.expected_execution_epoch, current.execution_epoch),
                        ("goal_version", intent.expected_goal_version, current.goal_version),
                        ("acceptance_version", intent.expected_acceptance_version, current.acceptance_version),
                        ("handled_input_seq", intent.expected_handled_input_seq, current.handled_input_seq),
                        ("capability_snapshot_id", intent.capability_snapshot_id, current.capability_snapshot_id),
                    ):
                        if expected != actual:
                            binding_changes.append(name)
                    if current.control_intent is not ControlIntent.RUN:
                        binding_changes.append("control_intent")
                    if current.received_input_seq != current.handled_input_seq:
                        binding_changes.append("unhandled_input")
                    if binding_changes:
                        dispatch_blocked = "dispatch barrier changed before file effect: " + ", ".join(binding_changes)
                    else:
                        try:
                            outcome = dispatch()
                            if not isinstance(outcome, OperationOutcome):
                                raise TypeError("operation dispatch must return OperationOutcome")
                        except BaseException as error:
                            outcome = OperationOutcome(
                                EffectStatus.UNKNOWN,
                                {
                                    "exception_type": type(error).__name__,
                                    "exception_hash": "sha256:" + hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                                    "effect_requires_probe": True,
                                },
                            )
            if dispatch_blocked is not None and outcome is None:
                blocked_result = {
                    "effect_dispatched": False,
                    "recovery_decision": "NO_EFFECT",
                    "reason": dispatch_blocked,
                }
                if effect_evidence.get("effect_kind") == "command":
                    blocked_result.update(
                        {
                            "program_status": "NOT_RUN",
                            "execution_started": False,
                            "effect_settled": True,
                            "command_policy": effect_evidence.get("command_policy"),
                        }
                    )
                outcome = OperationOutcome(
                    EffectStatus.FAILED,
                    blocked_result,
                )
            if dispatch_blocked is None and outcome is None:
                try:
                    outcome = dispatch()
                    if not isinstance(outcome, OperationOutcome):
                        raise TypeError("operation dispatch must return OperationOutcome")
                except BaseException as error:
                    outcome = OperationOutcome(
                        EffectStatus.UNKNOWN,
                        {
                            "exception_type": type(error).__name__,
                            "exception_hash": "sha256:" + hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                            "effect_requires_probe": True,
                        },
                    )

            assert outcome is not None
            outcome = self._bound_operation_result(outcome)
            with self._state_lock:
                current = self.get_task(task_id)
                # Extension consumer credentials are minted here, after the
                # real handler/controlled executor returned and before the
                # operation result event.  No catalog callback can grant a
                # receipt by submitting a binding/value pair.
                receipt_binding = self._issue_extension_consumer_receipt_locked(
                    task_id, intent.as_dict(()), effect_evidence, outcome,
                )
                if receipt_binding is not None:
                    result_with_receipt = dict(outcome.result)
                    original_binding = dict(result_with_receipt.get("execution_binding") or {})
                    original_binding.update(
                        {
                            "backend_receipt_schema": "SITINA_EXTENSION_CONSUMER_RECEIPT_V1",
                            "backend_receipt_ref": receipt_binding.reference_id,
                            "backend_receipt_hash": receipt_binding.content_hash,
                            "call_id": effect_evidence.get("call_id"),
                        }
                    )
                    result_with_receipt["execution_binding"] = original_binding
                    outcome = OperationOutcome(outcome.status, result_with_receipt)
                result_document = {
                    "schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                    "task_id": task_id,
                    "operation_id": intent.operation_id,
                    "effect_status": outcome.status.value,
                    "result": dict(outcome.result),
                    # Keep the authenticated tool receipt visible at the
                    # operation-result boundary as well as inside the
                    # generic result envelope.  This is still one CAS
                    # document; consumers cannot manufacture the duplicate
                    # without the persisted Loop operation.
                    **(
                        {
                            key: value
                            for key, value in dict(outcome.result).items()
                            if key in {"tool", "status", "value", "execution_binding", "permission"}
                        }
                        if "tool" in outcome.result
                        else {}
                    ),
                    "bound_goal_version": intent.expected_goal_version,
                    "bound_acceptance_version": intent.expected_acceptance_version,
                    "bound_input_seq": intent.expected_handled_input_seq,
                }
                try:
                    stored_result = self.context_memory.persist(
                        result_document,
                        purpose="loop-operation-result",
                    )
                except BaseException as error:
                    self._fail_persistence(error)
                    raise
                result_proofs: list[Any] = [stored_result.proof]
                delivery = outcome.result.get("private_request_delivery")
                if delivery is not None:
                    from .request_delivery import delivery_publication_proofs
                    if not isinstance(delivery, Mapping):
                        raise ValueError("private request delivery must be an object")
                    result_proofs.extend(delivery_publication_proofs(
                        self.context_memory, delivery, task_id=task_id, operation_id=intent.operation_id,
                        owner=intent.execution_owner or outcome.result.get("delegation_id"),
                    ))
                execution_binding = outcome.result.get("execution_binding")
                if isinstance(execution_binding, Mapping):
                    receipt_ref = str(execution_binding.get("backend_receipt_ref") or "")
                    receipt_proof = self._extension_receipt_proofs.get(receipt_ref)
                    if receipt_proof is not None:
                        result_proofs.append(receipt_proof)
                self._append(
                    task_id=task_id,
                    expected_stream_version=current.task_revision,
                    request_id=f"operation-result:{task_id}:{intent.operation_id}",
                    command_type="loop.operation.record-result",
                    event_type="loop.operation-result-recorded",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                        "task_id": task_id,
                        "operation_id": intent.operation_id,
                        "effect_status": outcome.status.value,
                        "result_ref": stored_result.reference_id,
                        "result_hash": stored_result.content_hash,
                        "unknown_effect": outcome.status is EffectStatus.UNKNOWN,
                        "recovery_decision": (
                            str(outcome.result.get("recovery_decision"))
                            if outcome.result.get("recovery_decision") is not None
                            else None
                        ),
                        "resources_released_after_commit": outcome.status is not EffectStatus.UNKNOWN,
                    },
                    proofs=tuple(result_proofs),
                )
                result_committed = True
                unknown_effect_committed = outcome.status is EffectStatus.UNKNOWN
            return outcome
        finally:
            if lane_acquired:
                if intent_committed and (not result_committed or unknown_effect_committed):
                    self.operations.hold_for_unknown_effect(task_id, intent.operation_id)
                else:
                    self.operations.release(task_id, intent.operation_id)
            # If an effect was dispatched but its result could not be recorded,
            # keep both the write lane and persistence fence.  Recovery must
            # probe the effect before another business writer can proceed.

    def _operation_dispatch_started(self, task_id: str, operation_id: str) -> bool:
        return any(
            event.event_type == "loop.operation-dispatch-started"
            and str(event.payload.get("operation_id") or "") == operation_id
            for event in self.store.task_events(task_id)
        )

    def reconcile_operation_no_effect(
        self,
        task_id: str,
        operation_id: str,
        *,
        reason: str,
    ) -> TaskProjection:
        """Close a durably recorded operation proven never to have dispatched.

        This boundary is intentionally narrower than UNKNOWN reconciliation:
        it requires the original operation identity, an INTENT_RECORDED
        projection, and the absence of the immutable dispatch-start marker.
        Once dispatch-start exists this method refuses to manufacture a
        no-effect result.
        """

        with self._state_lock:
            task = self.get_task(task_id)
            operation = task.operations.get(operation_id)
            if operation is None:
                raise OperationRejected("cannot reconcile an unknown operation")
            if operation.result_ref is not None or operation.effect_status is not EffectStatus.INTENT_RECORDED:
                return task
            if self._operation_dispatch_started(task_id, operation_id):
                raise TaskConflict("operation dispatch-started evidence forbids a no-effect settlement")
            if not operation.intent_ref:
                raise OperationRejected("operation intent reference is missing")
            intent = self.context_memory.read(operation.intent_ref)
            result_document = {
                "schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                "task_id": task_id,
                "operation_id": operation_id,
                "effect_status": EffectStatus.FAILED.value,
                "result": {
                    "effect_dispatched": False,
                    "recovery_decision": "NO_EFFECT",
                    "execution_started": False,
                    "effect_settled": True,
                    "reason": str(reason),
                },
                "recovery_decision": "NO_EFFECT",
                "bound_goal_version": int(intent.get("expected_goal_version", operation.bound_goal_version)),
                "bound_acceptance_version": int(
                    intent.get("expected_acceptance_version", operation.bound_acceptance_version)
                ),
                "bound_input_seq": int(intent.get("expected_handled_input_seq", operation.bound_input_seq)),
            }
            stored = self.context_memory.persist(result_document, purpose="loop-operation-result")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"operation-no-effect:{task_id}:{operation_id}",
                command_type="loop.operation.reconcile-no-effect",
                event_type="loop.operation-result-recorded",
                payload={
                    "schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                    "task_id": task_id,
                    "operation_id": operation_id,
                    "effect_status": EffectStatus.FAILED.value,
                    "result_ref": stored.reference_id,
                    "result_hash": stored.content_hash,
                    "unknown_effect": False,
                    "recovery_decision": "NO_EFFECT",
                    "resources_released_after_commit": True,
                },
                proofs=(stored.proof,),
            )
            return self.get_task(task_id)

    def managed_process_evidence(self, task_id: str) -> dict[str, Mapping[str, Any]]:
        """Read task-owned background command handles from authenticated operation intents."""
        with self._state_lock:
            task = self.get_task(task_id)
            active_tasks = getattr(self, "_managed_process_task_ids", None)
            if active_tasks is None:
                active_tasks = self._managed_process_task_ids = set()
            active_tasks.add(task_id)
            owners: dict[str, Mapping[str, Any]] = {}
            for operation_id, operation in task.operations.items():
                if not operation_id.startswith("managed-process-"):
                    continue
                if operation.effect_status is EffectStatus.PRECONDITION_CHANGED:
                    continue
                if not operation.intent_ref:
                    raise PersistenceFenced("managed process owner lacks its durable intent")
                intent = self.context_memory.read(operation.intent_ref)
                reference = str(intent.get("effect_evidence_ref") or "")
                digest = str(intent.get("effect_evidence_hash") or "")
                if not reference or not digest:
                    raise PersistenceFenced("managed process owner lacks bound command evidence")
                evidence = self.context_memory.read(reference, expected_hash=digest)
                if (
                    evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1"
                    or evidence.get("task_id") != task_id
                    or evidence.get("operation_id") != operation_id
                    or evidence.get("effect_kind") != "command"
                    or evidence.get("command_policy") not in {COMMAND_POLICY, TASK_COMMAND_POLICY}
                    or evidence.get("managed_process") is not True
                ):
                    raise PersistenceFenced("managed process owner binding is invalid")
                if evidence.get("phase") == "UNSUPPORTED_NOT_STARTED" or evidence.get("planning_error"):
                    continue
                owners[operation_id] = evidence
            return owners

    def stop_managed_processes(
        self, task_id: str, *, reason: str, stale_only: bool = False,
        retain_kept: bool = False, require_completed: bool = False,
        preserve_running: bool = False,
    ) -> dict[str, Mapping[str, Any]]:
        """Observe original owners; planned handoff preserves authorized original execution."""
        task = self.get_task(task_id)
        if task.control_intent is ControlIntent.CANCEL or reason in {"native-backend-drain", "native-backend-handoff"}:
            from .task_commands import close_task_gateways
            close_task_gateways(self.context.home, task_id)
        observations: dict[str, Mapping[str, Any]] = {}
        for operation_id, evidence in self.managed_process_evidence(task_id).items():
            operation = task.operations[operation_id]
            general = evidence.get("execution_contract") == TASK_EXECUTION_CONTRACT
            stale = (
                operation.bound_goal_version != task.goal_version
                or operation.bound_acceptance_version != task.acceptance_version
                or operation.bound_input_seq != task.handled_input_seq
                or evidence.get("run_instance_id") != task.run_instance_id
                or evidence.get("execution_epoch") != task.execution_epoch
            )
            if (general and reason == "native-backend-handoff" and preserve_running
                    and task.control_intent is not ControlIntent.CANCEL
                    and (not evidence.get("execution_owner") or
                         self.child_execution_current(task_id, str(evidence["execution_owner"])))):
                observation = observe_managed_command(evidence, task_id=task_id, operation_id=operation_id)
                if observation.get("decision") == "RUNNING":
                    observations[operation_id] = {**observation, "retained": True,
                        "retention_reason": "planned_host_handoff", "resources": list(evidence.get("write_roots", ())) }
                    continue
                if observation.get("decision") not in {"SUCCEEDED", "NO_EFFECT"}:
                    raise ManagedCommandUnsettled("planned handoff cannot verify original execution: " + operation_id)
                observations[operation_id] = observation
                continue
            if general:
                owner = evidence.get("execution_owner")
                stale = bool(owner and not self.child_execution_current(task_id, str(owner)))
                if reason == "native-input-invalidation" and task.control_intent is not ControlIntent.CANCEL:
                    continue
                if require_completed:
                    observation = observe_managed_command(evidence, task_id=task_id, operation_id=operation_id)
                    if observation.get("decision") == "RUNNING":
                        if retain_kept and evidence.get("keep") is True:
                            observations[operation_id] = {**observation, "retained": True,
                                "retention_reason": "explicit_task_keep", "resources": list(evidence.get("write_roots", ())) }
                            continue
                        raise TaskConflict("required execution is still running: " + operation_id)
                    if observation.get("decision") not in {"SUCCEEDED", "NO_EFFECT"}:
                        raise ManagedCommandUnsettled("original execution is unresolved: " + operation_id)
                    observations[operation_id] = observation
                    continue
            if stale_only and not stale:
                continue
            observation = observe_managed_command(
                evidence, task_id=task_id, operation_id=operation_id, stop=True, reason=reason,
            )
            observations[operation_id] = observation
            if observation.get("decision") not in {"SUCCEEDED", "NO_EFFECT"}:
                raise ManagedCommandUnsettled(
                    "managed process owner " + operation_id + " remains UNKNOWN: "
                    + str(observation.get("reason") or "unobserved"),
                )
        return observations

    def reconcile_task_control_operation(self, task_id: str, operation_id: str) -> TaskProjection:
        """Append an original native-control result only when its private Host receipt proves it."""
        from .task_commands import observe_task_control_evidence

        with self._state_lock:
            task = self.get_task(task_id)
            operation = task.operations.get(operation_id)
            if operation is None or not operation.intent_ref:
                raise OperationRejected("native control operation or original intent is missing")
            if operation.mode is not OperationMode.WRITE:
                return task
            if operation.result_ref is not None and not operation.unknown_effect:
                return task
            intent = self.context_memory.read(operation.intent_ref)
            evidence_ref, evidence_hash = intent.get("effect_evidence_ref"), intent.get("effect_evidence_hash")
            if evidence_ref and evidence_hash:
                evidence = self.context_memory.read(str(evidence_ref), expected_hash=str(evidence_hash))
                if (not isinstance(evidence, Mapping)
                        or evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1"
                        or evidence.get("task_id") != task_id or evidence.get("operation_id") != operation_id):
                    raise PersistenceFenced("native control private evidence is not bound to its original operation")
                if evidence.get("effect_kind") != "task-control":
                    return task
                if (evidence.get("run_instance_id") != intent.get("expected_run_instance_id")
                        or evidence.get("execution_epoch") != intent.get("expected_execution_epoch")):
                    raise PersistenceFenced("native control evidence is not bound to its original run")
                observation = observe_task_control_evidence(evidence, task_id=task_id, operation_id=operation_id)
            elif operation_id.startswith("managed-control-"):
                evidence = {}
                observation = {"decision": "UNKNOWN", "reason": "legacy-native-control-effect-evidence-missing"}
            else:
                return task
            document = {"schema": "SITINA_LOOP_TASK_CONTROL_RECOVERY_OBSERVATION_V1",
                "task_id": task_id, "operation_id": operation_id,
                "original_intent_ref": operation.intent_ref, "original_result_ref": operation.result_ref,
                "evidence_ref": evidence_ref, "evidence_hash": evidence_hash,
                "observation": observation}
            final_records = [event for event in self.store.task_events(task_id)
                if event.event_type == "loop.operation-recovery-decided"
                and event.payload.get("operation_id") == operation_id and event.payload.get("final") is True]
            if final_records:
                if len(final_records) != 1:
                    raise PersistenceFenced("native control has conflicting final recovery decisions")
                payload = final_records[0].payload
                if (payload.get("run_instance_id") != intent.get("expected_run_instance_id")
                        or payload.get("execution_epoch") != intent.get("expected_execution_epoch")):
                    raise PersistenceFenced("native control final decision is not bound to its original run")
                restored = self.context_memory.read(str(payload["observation_ref"]),
                    expected_hash=str(payload["observation_content_hash"]))
                if (not isinstance(restored, Mapping)
                        or restored.get("schema") != "SITINA_LOOP_TASK_CONTROL_RECOVERY_OBSERVATION_V1"
                        or restored.get("task_id") != task_id or restored.get("operation_id") != operation_id
                        or restored.get("original_intent_ref") != operation.intent_ref
                        or restored.get("original_result_ref") != operation.result_ref
                        or restored.get("evidence_ref") != evidence_ref or restored.get("evidence_hash") != evidence_hash
                        or hashlib.sha256(canonical_json_bytes(restored)).hexdigest() != payload.get("observation_hash")):
                    raise PersistenceFenced("native control final observation is not bound to its original operation")
                proven = restored.get("observation")
                if (not isinstance(proven, Mapping) or proven.get("decision") != payload.get("decision")
                        or proven.get("effect_status") != payload.get("decision")
                        or proven.get("decision") not in {EffectStatus.SUCCEEDED.value, EffectStatus.FAILED.value}
                        or not isinstance(proven.get("result"), Mapping)):
                    raise PersistenceFenced("native control final observation is incomplete")
                document, observation = dict(restored), dict(proven)
            digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
            decision = str(observation["decision"])
            started = self._operation_dispatch_started(task_id, operation_id)
            final = decision in {EffectStatus.SUCCEEDED.value, EffectStatus.FAILED.value} and started
            if decision != "UNKNOWN" and not started:
                observation = {"decision": "UNKNOWN", "reason": "completion-without-original-dispatch-marker"}
                document["observation"] = observation
                decision = "UNKNOWN"
                digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
            previous = [event for event in self.store.task_events(task_id)
                if event.event_type == "loop.operation-recovery-decided"
                and event.payload.get("operation_id") == operation_id
                and event.payload.get("observation_hash") == digest]
            if previous:
                if not final:
                    return task
                observation_ref = str(previous[-1].payload["observation_ref"])
                observation_content_hash = str(previous[-1].payload["observation_content_hash"])
                if self.context_memory.read(observation_ref, expected_hash=observation_content_hash) != document:
                    raise PersistenceFenced("native control recovery observation changed")
            else:
                stored = self.context_memory.persist(document, purpose="loop-task-control-recovery-observation")
                observation_ref, observation_content_hash = stored.reference_id, stored.content_hash
                self._append(task_id=task_id, expected_stream_version=task.task_revision,
                    request_id=f"task-control-recovery:{task_id}:{operation_id}:{digest}",
                    command_type="loop.operation.recovery-decision", event_type="loop.operation-recovery-decided",
                    payload={"schema": "SITINA_LOOP_OPERATION_RECOVERY_DECISION_V1",
                        "task_id": task_id, "operation_id": operation_id,
                        "logical_operation_id": operation.logical_operation_id, "attempt_id": operation.attempt_id,
                        "business_attempt_id": operation.business_attempt_id, "decision": decision, "final": final,
                        "observation_ref": observation_ref, "observation_hash": digest,
                        "observation_content_hash": observation_content_hash,
                        "evidence_ref": evidence_ref, "evidence_hash": evidence_hash,
                        "dispatch_started": started,
                        "run_instance_id": intent.get("expected_run_instance_id"),
                        "execution_epoch": intent.get("expected_execution_epoch")}, proofs=(stored.proof,))
            if not final:
                return self.get_task(task_id)
            outcome = self._bound_operation_result(OperationOutcome(
                EffectStatus(str(observation["effect_status"])), dict(observation["result"])))
            result_value = {**dict(outcome.result), "recovery_observation_ref": observation_ref,
                "recovery_observation_hash": observation_content_hash,
                "original_control_completion_hash": observation["completion_hash"],
                "recovery_decision": decision, "effect_settled": True,
                "current_service_availability": "NOT_INFERRED"}
            result_document = {"schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                "task_id": task_id, "operation_id": operation_id, "effect_status": outcome.status.value,
                "result": result_value,
                **{key: value for key, value in result_value.items()
                   if key in {"tool", "status", "value", "execution_binding", "permission"}},
                "bound_goal_version": int(intent["expected_goal_version"]),
                "bound_acceptance_version": int(intent["expected_acceptance_version"]),
                "bound_input_seq": int(intent["expected_handled_input_seq"])}
            saved = self.context_memory.persist(result_document, purpose="loop-operation-result")
            current = self.get_task(task_id)
            self._append(task_id=task_id, expected_stream_version=current.task_revision,
                request_id=f"task-control-recovery-result:{task_id}:{operation_id}:{digest}",
                command_type="loop.operation.record-recovery-result", event_type="loop.operation-result-recorded",
                payload={"schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                    "task_id": task_id, "operation_id": operation_id,
                    "effect_status": outcome.status.value, "result_ref": saved.reference_id,
                    "result_hash": saved.content_hash, "unknown_effect": False,
                    "recovery_decision": decision, "resources_released_after_commit": True,
                    "recovery_replaces_unknown": operation.unknown_effect}, proofs=(saved.proof,))
            if self.operations.is_owner(task_id, operation_id):
                self.operations.resolve_unknown_effect_owner(task_id, operation_id, release=True)
            return self.get_task(task_id)

    def reconcile_command_operation(self, task_id: str, operation_id: str) -> TaskProjection:
        """Observe one durable command wrapper; never launch a replacement command."""
        with self._state_lock:
            task = self.get_task(task_id)
            operation = task.operations.get(operation_id)
            if operation is None:
                raise OperationRejected("cannot reconcile an unknown command operation")
            if operation.mode is not OperationMode.WRITE:
                return task
            if operation.effect_status not in {
                EffectStatus.INTENT_RECORDED,
                EffectStatus.UNKNOWN,
                EffectStatus.PARTIAL,
            } and not operation.unknown_effect:
                return task
            if not operation.intent_ref:
                raise OperationRejected("command operation intent reference is missing")
            intent_document = self.context_memory.read(operation.intent_ref)
            evidence_ref = str(intent_document.get("effect_evidence_ref") or "")
            evidence_hash = str(intent_document.get("effect_evidence_hash") or "")
            if not evidence_ref or not evidence_hash:
                raise OperationRejected("command operation has no private effect evidence")
            evidence = dict(self.context_memory.read(evidence_ref, expected_hash=evidence_hash))
            if evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1":
                raise PersistenceFenced("command effect evidence schema is invalid")
            if evidence.get("effect_kind") != "command" or evidence.get("command_policy") not in {COMMAND_POLICY, TASK_COMMAND_POLICY}:
                return task
            if evidence.get("operation_id") != operation_id or evidence.get("task_id") != task_id:
                raise PersistenceFenced("command effect evidence is bound to another operation")
            started = self._operation_dispatch_started(task_id, operation_id)
            persisted_final_decision: Mapping[str, Any] | None = next(
                (
                    event.payload
                    for event in self.store.task_events(task_id)
                    if event.event_type == "loop.operation-recovery-decided"
                    and str(event.payload.get("operation_id") or "") == operation_id
                    and bool(event.payload.get("final"))
                ),
                None,
            )
            persisted_observation_document: Mapping[str, Any] | None = None
            if persisted_final_decision is not None:
                observation_ref = str(persisted_final_decision.get("observation_ref") or "")
                observation_hash = str(persisted_final_decision.get("observation_content_hash") or "")
                if observation_ref and observation_hash:
                    try:
                        persisted_observation_document = self.context_memory.read(
                            observation_ref, expected_hash=observation_hash
                        )
                    except (CASError, KeyError, TypeError, ValueError):
                        raise PersistenceFenced("final command recovery decision observation CAS is unreadable")
                else:
                    raise PersistenceFenced("final command recovery decision has no observation CAS binding")
            self._state_lock.release()
            try:
                if persisted_observation_document is not None:
                    observation = dict(persisted_observation_document.get("observation") or {})
                else:
                    observation = observe_command_evidence(evidence, task_id=task_id, operation_id=operation_id)
                if started and observation.get("decision") == "UNKNOWN" and observation.get("reason") in {
                    "started-without-completion",
                    "completion-ready-missing",
                }:
                    deadline = time.monotonic() + 6.0
                    while time.monotonic() < deadline:
                        current_control = self.get_task(task_id).control_intent
                        if current_control is ControlIntent.CANCEL:
                            request_command_cancel_evidence(
                                evidence,
                                task_id=task_id,
                                operation_id=operation_id,
                                reason="cancel-during-command-recovery",
                            )
                        time.sleep(0.1)
                        observation = observe_command_evidence(
                            evidence, task_id=task_id, operation_id=operation_id
                        )
                        if observation.get("decision") != "UNKNOWN" or observation.get("reason") not in {
                            "started-without-completion",
                            "completion-ready-missing",
                        }:
                            break
            finally:
                self._state_lock.acquire()
            task = self.get_task(task_id)
            operation = task.operations.get(operation_id)
            if operation is None:
                raise OperationRejected("command operation disappeared during recovery observation")
            decision = str(observation.get("decision") or ("UNKNOWN" if started else "NO_EFFECT"))
            observation_document = {
                "schema": "SITINA_LOOP_COMMAND_RECOVERY_OBSERVATION_V1",
                "task_id": task_id,
                "operation_id": operation_id,
                "logical_operation_id": operation.logical_operation_id,
                "attempt_id": operation.attempt_id,
                "business_attempt_id": operation.business_attempt_id,
                "dispatch_started": started,
                "evidence_ref": evidence_ref,
                "evidence_hash": evidence_hash,
                "policy": COMMAND_POLICY,
                "decision": decision,
                "observation": _command_safe(dict(observation)),
            }
            computed_observation_hash = hashlib.sha256(canonical_json_bytes(observation_document)).hexdigest()
            existing_decision: Mapping[str, Any] | None = persisted_final_decision or next(
                (
                    event.payload
                    for event in self.store.task_events(task_id)
                    if event.event_type == "loop.operation-recovery-decided"
                    and str(event.payload.get("operation_id") or "") == operation_id
                    and str(event.payload.get("observation_hash") or "") == computed_observation_hash
                ),
                None,
            )
            observation_hash = (
                str(existing_decision.get("observation_hash") or computed_observation_hash)
                if existing_decision is not None
                else computed_observation_hash
            )
            stored_observation = None
            if existing_decision is None:
                stored_observation = self.context_memory.persist(
                    observation_document,
                    purpose="loop-command-recovery-observation",
                )
                observation_ref = stored_observation.reference_id
                observation_content_hash = stored_observation.content_hash
            else:
                observation_ref = str(existing_decision.get("observation_ref") or "")
                observation_content_hash = str(existing_decision.get("observation_content_hash") or "")
            final = decision in {"SUCCEEDED", "NO_EFFECT"}
            if existing_decision is None:
                current = self.get_task(task_id)
                self._append(
                    task_id=task_id,
                    expected_stream_version=current.task_revision,
                    request_id=f"command-recovery-decision:{task_id}:{operation_id}:{observation_hash}",
                    command_type="loop.operation.recovery-decision",
                    event_type="loop.operation-recovery-decided",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RECOVERY_DECISION_V1",
                        "task_id": task_id,
                        "operation_id": operation_id,
                        "logical_operation_id": operation.logical_operation_id,
                        "attempt_id": operation.attempt_id,
                        "business_attempt_id": operation.business_attempt_id,
                        "decision": decision,
                        "final": final,
                        "observation_ref": observation_ref,
                        "observation_hash": observation_hash,
                        "observation_content_hash": observation_content_hash,
                        "evidence_ref": evidence_ref,
                        "evidence_hash": evidence_hash,
                        "dispatch_started": started,
                        "run_instance_id": intent_document.get("expected_run_instance_id"),
                        "execution_epoch": intent_document.get("expected_execution_epoch"),
                    },
                    proofs=((stored_observation.proof,) if stored_observation is not None else ()),
                )

            needs_result = operation.result_ref is None or (operation.unknown_effect and final)
            if needs_result:
                tool_name = str(evidence.get("tool_name") or "sitina_program_check")
                tool_permission = str(evidence.get("tool_permission") or "write")
                tool_arguments = evidence.get("tool_arguments")
                if not isinstance(tool_arguments, Mapping):
                    tool_arguments = {"command_policy": evidence.get("command_policy")}
                if decision == "SUCCEEDED" and evidence.get("execution_contract") == TASK_EXECUTION_CONTRACT:
                    from types import SimpleNamespace
                    from .task_commands import public_execution
                    result_value = public_execution(
                        SimpleNamespace(backend=self, task_id=task_id, execution_owner=None),
                        operation_id, include_output=True,
                    )
                    result_value.update({"tool": tool_name, "permission": tool_permission,
                                         "arguments": dict(tool_arguments), "sandbox": "macos-task-scope-v1"})
                elif decision == "SUCCEEDED":
                    completion = observation.get("completion") if isinstance(observation.get("completion"), Mapping) else {}
                    manifest = observation.get("manifest") if isinstance(observation.get("manifest"), Mapping) else {}
                    input_snapshot = manifest.get("input_snapshot") if isinstance(manifest.get("input_snapshot"), Mapping) else {}
                    check_input = _command_snapshot(str(manifest.get("input_root") or ""))
                    business_root = str(evidence.get("business_workspace") or "")
                    business_snapshot = _command_snapshot(business_root) if business_root else input_snapshot
                    unchanged = dict(input_snapshot) == check_input and dict(input_snapshot) == business_snapshot
                    exit_code = completion.get("exit_code")
                    program_status = "PASS" if exit_code == 0 and unchanged else "FAIL"
                    stdout_path = Path(str(manifest.get("stdout_path") or ""))
                    stderr_path = Path(str(manifest.get("stderr_path") or ""))
                    if stdout_path.is_file() and stderr_path.is_file():
                        stdout, stdout_hash, _stdout_retained, _ = _bounded_read(stdout_path)
                        stderr, stderr_hash, _stderr_retained, _ = _bounded_read(stderr_path)
                    else:
                        stdout = str(observation.get("stdout") or "")
                        stderr = str(observation.get("stderr") or "")
                        stdout_hash = str(observation.get("stdout_hash") or "")
                        stderr_hash = str(observation.get("stderr_hash") or "")
                    stdout_bytes = int(observation.get("stdout_bytes") or completion.get("stdout_bytes") or 0)
                    stderr_bytes = int(observation.get("stderr_bytes") or completion.get("stderr_bytes") or 0)
                    stdout_truncated = bool(observation.get("stdout_truncated") if "stdout_truncated" in observation else completion.get("stdout_truncated"))
                    stderr_truncated = bool(observation.get("stderr_truncated") if "stderr_truncated" in observation else completion.get("stderr_truncated"))
                    result_value = {
                        "effect_kind": "command",
                        "method_id": str(evidence.get("method_id") or "recovered-command"),
                        "shell_capability": evidence.get("shell_capability"),
                        "shell_tool": evidence.get("shell_tool"),
                        "sandbox": "macos-seatbelt-check-copy-v1",
                        "command_policy": evidence.get("command_policy"),
                        "command": list(manifest.get("argv") or evidence.get("command") or ()),
                        "cwd": str(manifest.get("cwd") or evidence.get("check_input") or ""),
                        "write_root": str(manifest.get("output_root") or evidence.get("check_output") or ""),
                        "checked_snapshot_hash": hashlib.sha256(
                            canonical_json_bytes(dict(input_snapshot))
                        ).hexdigest(),
                        "program_status": program_status,
                        "execution_started": True,
                        "effect_settled": True,
                        "completion_status": completion.get("status"),
                        "exit_code": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                        "stdout_hash": stdout_hash,
                        "stderr_hash": stderr_hash,
                        "stdout_bytes": stdout_bytes,
                        "stderr_bytes": stderr_bytes,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                        "business_artifact_unchanged": dict(input_snapshot) == business_snapshot,
                        "check_input_unchanged": dict(input_snapshot) == check_input,
                        "completion_ref": str(evidence.get("completion_path") or ""),
                        "completion_hash": str(observation.get("completion_hash") or ""),
                        "manifest_ref": str(evidence.get("command_manifest_path") or ""),
                        "manifest_hash": str(observation.get("manifest_hash") or ""),
                        "recovery_decision": decision,
                    }
                    effect_status = EffectStatus.SUCCEEDED
                    tool_status = "ok" if program_status == "PASS" else "error"
                elif decision == "NO_EFFECT":
                    result_value = {
                        "program_status": "NOT_RUN",
                        "execution_started": False,
                        "effect_settled": True,
                        "recovery_decision": decision,
                    }
                    effect_status = EffectStatus.FAILED
                    tool_status = "error"
                else:
                    result_value = {
                        "program_status": "UNKNOWN",
                        "execution_started": started,
                        "effect_settled": False,
                        "recovery_decision": decision,
                    }
                    effect_status = EffectStatus.UNKNOWN
                    tool_status = "error"
                result_document = {
                    "schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                    "task_id": task_id,
                    "operation_id": operation_id,
                    "effect_status": effect_status.value,
                    "recovery_decision": decision,
                    "result": {
                        "tool": tool_name,
                        "arguments": dict(tool_arguments),
                        "permission": tool_permission,
                        "status": tool_status,
                        "value": result_value,
                        "permission_decision": "reconciled",
                        "recovery_decision": decision,
                        **result_value,
                    },
                    "bound_goal_version": operation.bound_goal_version,
                    "bound_acceptance_version": operation.bound_acceptance_version,
                    "bound_input_seq": operation.bound_input_seq,
                    "evidence_ref": observation_ref,
                    "evidence_hash": observation_hash,
                }
                stored_result = self.context_memory.persist(
                    result_document,
                    purpose="loop-command-recovery-result",
                )
                current = self.get_task(task_id)
                self._append(
                    task_id=task_id,
                    expected_stream_version=current.task_revision,
                    request_id=f"command-recovery-result:{task_id}:{operation_id}:{observation_hash}",
                    command_type="loop.operation.record-recovery-result",
                    event_type="loop.operation-result-recorded",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                        "task_id": task_id,
                        "operation_id": operation_id,
                        "effect_status": effect_status.value,
                        "result_ref": stored_result.reference_id,
                        "result_hash": stored_result.content_hash,
                        "unknown_effect": not final,
                        "resources_released_after_commit": final,
                        "recovery_decision": decision,
                        "recovery_replaces_unknown": operation.unknown_effect and final,
                    },
                    proofs=(stored_result.proof,),
                )
            if final:
                if self.operations.is_owner(task_id, operation_id):
                    self.operations.resolve_unknown_effect_owner(task_id, operation_id, release=True)
            elif self.operations.is_owner(task_id, operation_id):
                self.operations.hold_for_unknown_effect(task_id, operation_id)
            return self.get_task(task_id)

    def reconcile_file_operation(self, task_id: str, operation_id: str) -> TaskProjection:
        """Probe one persisted file operation and append an idempotent decision.

        This is deliberately limited to the synchronous ToolExecutor file
        path.  It never calls a tool, rewrites a target, or claims historical
        executor identity; a complete post-state is simply verified as the
        expected effect when no completion receipt survived.
        """

        with self._state_lock:
            task = self.get_task(task_id)
            operation = task.operations.get(operation_id)
            if operation is None:
                raise OperationRejected("cannot reconcile an unknown operation")
            if operation.mode is not OperationMode.WRITE:
                return task
            if operation.effect_status not in {
                EffectStatus.INTENT_RECORDED,
                EffectStatus.UNKNOWN,
                EffectStatus.PARTIAL,
            } and not operation.unknown_effect:
                return task
            if not operation.intent_ref:
                raise OperationRejected("file operation intent reference is missing")
            if operation_id.startswith("managed-control-"):
                return task
            intent_document = self.context_memory.read(operation.intent_ref)
            evidence_ref = str(intent_document.get("effect_evidence_ref") or "")
            evidence_hash = str(intent_document.get("effect_evidence_hash") or "")
            if not evidence_ref or not evidence_hash:
                raise OperationRejected("file operation has no private effect evidence")
            evidence = dict(self.context_memory.read(evidence_ref, expected_hash=evidence_hash))
            if evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1":
                raise PersistenceFenced("file operation effect evidence schema is invalid")
            if evidence.get("effect_kind") != "file":
                return task
            if evidence.get("operation_id") != operation_id or evidence.get("task_id") != task_id:
                raise PersistenceFenced("file effect evidence is bound to another operation")
            started = self._operation_dispatch_started(task_id, operation_id)
            # The probe may perform arbitrarily slow filesystem work.  Do not
            # hold the coordinator lock while it observes the target; control
            # and input admission must remain responsive during recovery.
            self._state_lock.release()
            try:
                observation = probe_file_effect(evidence, dispatch_started=started)
            finally:
                self._state_lock.acquire()
            task = self.get_task(task_id)
            current_operation = task.operations.get(operation_id)
            if current_operation is None:
                raise OperationRejected("file operation disappeared during recovery probe")
            operation = current_operation
            observation_document = {
                "schema": "SITINA_LOOP_OPERATION_RECOVERY_OBSERVATION_V1",
                "task_id": task_id,
                "operation_id": operation_id,
                "logical_operation_id": operation.logical_operation_id,
                "attempt_id": operation.attempt_id,
                "business_attempt_id": operation.business_attempt_id,
                "run_instance_id": str(intent_document.get("expected_run_instance_id") or ""),
                "execution_epoch": int(intent_document.get("expected_execution_epoch") or 0),
                "dispatch_started": started,
                "evidence_ref": evidence_ref,
                "evidence_hash": evidence_hash,
                **observation,
            }
            observation_hash = hashlib.sha256(
                canonical_json_bytes(observation_document)
            ).hexdigest()
            existing_decision: Mapping[str, Any] | None = None
            for event in self.store.task_events(task_id):
                if (
                    event.event_type == "loop.operation-recovery-decided"
                    and str(event.payload.get("operation_id") or "") == operation_id
                    and str(event.payload.get("observation_hash") or "") == observation_hash
                ):
                    existing_decision = event.payload
                    break
            if existing_decision is None:
                stored_observation = self.context_memory.persist(
                    observation_document,
                    purpose="loop-operation-recovery-observation",
                )
                observation_ref = stored_observation.reference_id
                observation_content_hash = stored_observation.content_hash
            else:
                observation_ref = str(existing_decision.get("observation_ref") or "")
                observation_content_hash = str(existing_decision.get("observation_content_hash") or "")
            decision = str(
                (existing_decision or {}).get("decision")
                or observation.get("decision")
                or "UNKNOWN"
            )
            final = decision in {"SUCCEEDED", "NO_EFFECT"}
            if existing_decision is None:
                current = self.get_task(task_id)
                self._append(
                    task_id=task_id,
                    expected_stream_version=current.task_revision,
                    request_id=f"operation-recovery-decision:{task_id}:{operation_id}:{observation_hash}",
                    command_type="loop.operation.recovery-decision",
                    event_type="loop.operation-recovery-decided",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RECOVERY_DECISION_V1",
                        "task_id": task_id,
                        "operation_id": operation_id,
                        "logical_operation_id": operation.logical_operation_id,
                        "attempt_id": operation.attempt_id,
                        "business_attempt_id": operation.business_attempt_id,
                        "decision": decision,
                        "final": final,
                        "observation_ref": observation_ref,
                        "observation_hash": observation_hash,
                        "observation_content_hash": observation_content_hash,
                        "evidence_ref": evidence_ref,
                        "evidence_hash": evidence_hash,
                        "dispatch_started": started,
                        "run_instance_id": intent_document.get("expected_run_instance_id"),
                        "execution_epoch": intent_document.get("expected_execution_epoch"),
                    },
                    proofs=(stored_observation.proof,),
                )

            # An active operation has no result event yet.  A final recovery
            # decision, or a newly proven completion replacing an UNKNOWN
            # result, must publish one private synthetic result so the original
            # Provider tool call becomes history-paired without replaying it.
            replacement = operation.unknown_effect and final
            needs_result = operation.result_ref is None or replacement
            if needs_result:
                if decision == "SUCCEEDED":
                    effect_status = EffectStatus.SUCCEEDED
                    tool_status = "ok"
                elif decision == "NO_EFFECT":
                    effect_status = EffectStatus.FAILED
                    tool_status = "error"
                elif decision in {"PARTIAL", "CONFLICT"}:
                    effect_status = EffectStatus.PARTIAL
                    tool_status = "error"
                else:
                    effect_status = EffectStatus.UNKNOWN
                    tool_status = "error"
                result_value = {
                    "recovery_decision": decision,
                    "effect_verified": decision == "SUCCEEDED",
                    "retry_authorized": decision == "NO_EFFECT",
                    "historical_executor_proven": False,
                    "observation_ref": observation_ref,
                    "observation_hash": observation_hash,
                }
                result_document = {
                    "schema": "SITINA_LOOP_OPERATION_RESULT_V1",
                    "task_id": task_id,
                    "operation_id": operation_id,
                    "effect_status": effect_status.value,
                    "recovery_decision": decision,
                    "result": {
                        "tool": str(evidence.get("tool") or "unknown_file_tool"),
                        "arguments": dict(evidence.get("arguments") or {}),
                        "permission": "write",
                        "status": tool_status,
                        "value": result_value,
                        "permission_decision": "reconciled",
                        "recovery_decision": decision,
                    },
                    "bound_goal_version": operation.bound_goal_version,
                    "bound_acceptance_version": operation.bound_acceptance_version,
                    "bound_input_seq": operation.bound_input_seq,
                    "evidence_ref": observation_ref,
                    "evidence_hash": observation_hash,
                }
                stored_result = self.context_memory.persist(
                    result_document,
                    purpose="loop-operation-recovery-result",
                )
                current = self.get_task(task_id)
                self._append(
                    task_id=task_id,
                    expected_stream_version=current.task_revision,
                    request_id=f"operation-recovery-result:{task_id}:{operation_id}:{observation_hash}",
                    command_type="loop.operation.record-recovery-result",
                    event_type="loop.operation-result-recorded",
                    payload={
                        "schema": "SITINA_LOOP_OPERATION_RESULT_RECORDED_V1",
                        "task_id": task_id,
                        "operation_id": operation_id,
                        "effect_status": effect_status.value,
                        "result_ref": stored_result.reference_id,
                        "result_hash": stored_result.content_hash,
                        "unknown_effect": not final,
                        "resources_released_after_commit": final,
                        "recovery_decision": decision,
                        "recovery_replaces_unknown": replacement,
                    },
                    proofs=(stored_result.proof,),
                )
            if final:
                if self.operations.is_owner(task_id, operation_id):
                    self.operations.resolve_unknown_effect_owner(
                        task_id,
                        operation_id,
                        release=True,
                    )
            else:
                # Keep the lane held for a later, newly identified probe.
                if self.operations.is_owner(task_id, operation_id):
                    self.operations.hold_for_unknown_effect(task_id, operation_id)
            return self.get_task(task_id)

    def reconcile_file_operations(self, task_id: str) -> TaskProjection:
        task = self.get_task(task_id)
        operation_ids = tuple(
            operation.operation_id
            for operation in (*task.active_operations, *task.unresolved_effects)
            if operation.mode is OperationMode.WRITE
        )
        for operation_id in operation_ids:
            task = self.reconcile_file_operation(task_id, operation_id)
        return task

    def observe_resource_handoff(
        self,
        task_id: str,
        *,
        handoff_id: str,
        resources: tuple[str, ...],
        stable_state: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> StoredContent:
        """Capture and persist independently re-verifiable handoff evidence.

        Only the small task/ownership binding is captured under the coordinator
        lock.  CAS reads and filesystem observations happen after releasing it,
        so status and control input remain responsive during large directory
        observations.  The returned CAS receipt is the only evidence accepted
        by :meth:`stabilize_resources`.
        """

        normalized = tuple(sorted({str(Path(item).expanduser().resolve(strict=False)) for item in resources}))
        if normalized != resources or not handoff_id.strip() or not stable_state.strip():
            raise ValueError("resource handoff observation requires normalized resources, identity, and state")
        if tuple(sorted(set(str(item) for item in evidence_refs))) != tuple(str(item) for item in evidence_refs):
            raise ValueError("resource handoff evidence refs must be sorted and unique")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            missing = [item for item in resources if item not in task.owned_resources]
            if missing:
                raise TaskConflict("task does not own every resource in the requested handoff")
            blocked = [
                item
                for operation in (*task.active_operations, *task.unresolved_effects)
                for item in resources
                if any(resources_conflict(item, held) for held in operation.resources)
            ]
            if blocked:
                raise TaskConflict("active or unknown operation prevents stable resource handoff")
            binding = {
                "task_id": task.task_id,
                "task_revision": task.task_revision,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "received_input_seq": task.received_input_seq,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
            }
            owner = {
                "task_id": task.task_id,
                "resources": list(task.owned_resources),
                "active_operation_ids": sorted(item.operation_id for item in task.active_operations),
                "unknown_effect_operation_ids": sorted(item.operation_id for item in task.unresolved_effects),
            }

        # Evidence CAS and filesystem access intentionally remain outside the
        # state lock.  Each supplied reference must resolve to a structured
        # document; a caller cannot release ownership using an invented token.
        referenced_evidence: list[dict[str, Any]] = []
        for reference_id in evidence_refs:
            try:
                evidence = self.context_memory.read(str(reference_id))
            except BaseException as error:
                raise TaskConflict(f"resource handoff evidence is unavailable: {reference_id}") from error
            if not isinstance(evidence, Mapping) or not str(evidence.get("schema") or ""):
                raise TaskConflict("resource handoff evidence must be a structured CAS document")
            evidence_task = evidence.get("task_id")
            if evidence_task is not None and str(evidence_task) != task_id:
                raise TaskConflict("resource handoff evidence belongs to a different task")
            evidence_binding = evidence.get("binding")
            if isinstance(evidence_binding, Mapping):
                for key in (
                    "task_id",
                    "run_instance_id",
                    "execution_epoch",
                    "goal_version",
                    "acceptance_version",
                    "handled_input_seq",
                    "artifact_ref",
                ):
                    if key in evidence_binding and evidence_binding.get(key) != binding.get(key):
                        raise TaskConflict("resource handoff evidence belongs to a different task generation")
            evidence_resources = evidence.get("resources") or evidence.get("targets") or ()
            normalized_evidence_resources = tuple(
                sorted({str(Path(item).expanduser().resolve(strict=False)) for item in evidence_resources})
            ) if isinstance(evidence_resources, (list, tuple)) else ()
            if str(evidence.get("schema")) == "SITINA_LOOP_RESOURCE_HANDOFF_OBSERVATION_V1":
                if not isinstance(evidence_binding, Mapping) or normalized_evidence_resources != resources:
                    raise TaskConflict("resource handoff observation evidence has different resources")
                evidence_owner = evidence.get("owner")
                if (
                    not isinstance(evidence_owner, Mapping)
                    or evidence_owner.get("task_id") != task_id
                    or any(item not in tuple(str(value) for value in evidence_owner.get("resources", ())) for item in resources)
                ):
                    raise TaskConflict("resource handoff observation evidence has a different owner")
            if normalized_evidence_resources and not all(
                any(resources_conflict(item, expected) for expected in resources)
                for item in normalized_evidence_resources
            ):
                raise TaskConflict("resource handoff evidence does not cover the requested resources")
            referenced_evidence.append({
                "reference_id": str(reference_id),
                "content_hash": hashlib.sha256(canonical_json_bytes(dict(evidence))).hexdigest(),
                "schema": str(evidence.get("schema")),
                "resources": list(normalized_evidence_resources),
            })

        scene = [resource_scene_observation(item) for item in resources]
        if any(
            bool(item.get("truncated"))
            or any(
                entry.get("read_error")
                or entry.get("content_hash_scope")
                for entry in item.get("entries", ())
            )
            for item in scene
        ):
            raise TaskConflict("resource scene observation is incomplete")
        document = {
            "schema": "SITINA_LOOP_RESOURCE_HANDOFF_OBSERVATION_V1",
            "task_id": task_id,
            "handoff_id": handoff_id,
            "resources": list(resources),
            "stable_state": stable_state,
            "binding": binding,
            "owner": owner,
            "evidence_refs": list(evidence_refs),
            "evidence": referenced_evidence,
            "scene": scene,
            "observation_contract": {
                "cas_read_outside_state_lock": True,
                "filesystem_read_outside_state_lock": True,
                "symlinks_not_traversed": True,
                "secret_content_retained": False,
            },
        }
        try:
            return self.context_memory.persist(document, purpose="loop-resource-handoff-observation")
        except BaseException as error:
            self._fail_persistence(error)
            raise

    def stabilize_resources(
        self,
        task_id: str,
        *,
        handoff_id: str,
        resources: tuple[str, ...],
        stable_state: str,
        evidence_refs: tuple[str, ...] = (),
        observation: StoredContent | None = None,
    ) -> TaskProjection:
        """Journal a verified handoff, then let replay release ownership."""

        normalized = tuple(sorted({str(Path(item).expanduser().resolve(strict=False)) for item in resources}))
        if normalized != resources or not handoff_id.strip() or not stable_state.strip():
            raise ValueError("stable resource handoff requires normalized resources, identity, and state")
        if observation is not None and evidence_refs:
            raise ValueError("observation receipt and raw evidence refs cannot be mixed")

        # A completed handoff is idempotent by handoff identity.  Read its CAS
        # before checking current ownership so a replay can succeed after the
        # resource has already been released by the reducer.
        with self._state_lock:
            events = self.store.task_events(task_id)
            prior = next(
                (
                    event.payload
                    for event in events
                    if event.event_type == "loop.resource-handoff-recorded"
                    and str(event.payload.get("handoff_id") or "") == handoff_id
                ),
                None,
            )
            current = self.get_task(task_id)
        if prior is not None:
            prior_document = self.context_memory.read(
                str(prior["handoff_ref"]), expected_hash=str(prior["handoff_hash"])
            )
            prior_resources = tuple(str(item) for item in prior_document.get("resources", ()))
            prior_state = str(prior_document.get("stable_state") or "")
            prior_evidence = tuple(str(item) for item in prior_document.get("evidence_refs", ()))
            if prior_resources != resources or prior_state != stable_state or (
                evidence_refs and prior_evidence != tuple(str(item) for item in evidence_refs)
            ):
                raise TaskConflict("handoff ID is already bound to different resource evidence")
            if observation is not None and (
                str(prior.get("observation_ref") or prior.get("handoff_ref")) != observation.reference_id
                or str(prior.get("observation_hash") or prior.get("handoff_hash")) != observation.content_hash
            ):
                raise TaskConflict("handoff ID is already bound to a different observation receipt")
            return current

        if observation is None:
            observation = self.observe_resource_handoff(
                task_id,
                handoff_id=handoff_id,
                resources=resources,
                stable_state=stable_state,
                evidence_refs=evidence_refs,
            )
        try:
            document = self.context_memory.read(
                observation.reference_id,
                expected_hash=observation.content_hash,
            )
        except BaseException as error:
            raise TaskConflict("resource handoff observation CAS cannot be verified") from error
        if document.get("schema") != "SITINA_LOOP_RESOURCE_HANDOFF_OBSERVATION_V1":
            raise TaskConflict("resource handoff requires a verified observation CAS document")
        if (
            document.get("task_id") != task_id
            or document.get("handoff_id") != handoff_id
            or tuple(str(item) for item in document.get("resources", ())) != resources
            or str(document.get("stable_state") or "") != stable_state
        ):
            raise TaskConflict("resource handoff observation identity does not match the commit request")
        owner = document.get("owner")
        if not isinstance(owner, Mapping) or owner.get("task_id") != task_id:
            raise TaskConflict("resource handoff observation owner does not match the task")
        owner_resources = tuple(str(item) for item in owner.get("resources", ()))
        if tuple(sorted(set(owner_resources))) != owner_resources or any(
            item not in owner_resources for item in resources
        ):
            raise TaskConflict("resource handoff observation owner does not cover the requested resources")
        scene = document.get("scene")
        if not isinstance(scene, list) or len(scene) != len(resources):
            raise TaskConflict("resource handoff observation has incomplete filesystem evidence")
        if any(
            bool(item.get("truncated"))
            or any(
                entry.get("read_error")
                or entry.get("content_hash_scope")
                for entry in item.get("entries", ())
            )
            for item in scene
        ):
            raise TaskConflict("resource handoff observation is incomplete")

        # Re-observe the external scene outside the lock before committing the
        # Journal decision.  A changed scene invalidates this observation and
        # leaves resource ownership untouched.
        current_scene = [resource_scene_observation(item) for item in resources]
        if current_scene != scene:
            raise TaskConflict("resource scene changed during handoff observation")

        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            for resource, observed_resource in zip(resources, scene, strict=True):
                observed_root = observed_resource.get("root") if isinstance(observed_resource, Mapping) else None
                if not isinstance(observed_root, Mapping):
                    raise TaskConflict("resource handoff observation has no root identity")
                current_identity = _resource_root_identity(resource)
                if any(
                    observed_root.get(key) != current_identity.get(key)
                    for key in ("exists", "type", "device", "inode", "size", "mtime_ns")
                ):
                    raise TaskConflict("resource root changed before handoff commit")
                observed_entries = observed_resource.get("entries")
                if not isinstance(observed_entries, list):
                    raise TaskConflict("resource handoff observation has no entry identities")
                for entry in observed_entries:
                    if not isinstance(entry, Mapping):
                        raise TaskConflict("resource handoff observation contains an invalid entry")
                    current_entry = _resource_entry_identity(resource, str(entry.get("path") or "."))
                    if any(
                        entry.get(key) != current_entry.get(key)
                        for key in ("exists", "type", "device", "inode", "size", "mtime_ns")
                    ):
                        raise TaskConflict("resource entry changed before handoff commit")
            binding = document.get("binding")
            expected_binding = {
                "task_id": task.task_id,
                "task_revision": task.task_revision,
                "run_instance_id": task.run_instance_id,
                "execution_epoch": task.execution_epoch,
                "goal_version": task.goal_version,
                "acceptance_version": task.acceptance_version,
                "handled_input_seq": task.handled_input_seq,
                "artifact_ref": task.artifact_ref,
            }
            if not isinstance(binding, Mapping) or any(
                binding.get(key) != expected for key, expected in expected_binding.items()
            ):
                raise TaskConflict("task binding changed during handoff observation")
            missing = [item for item in resources if item not in task.owned_resources]
            if missing:
                raise TaskConflict("task does not own every resource in the requested handoff")
            blocked = [
                item
                for operation in (*task.active_operations, *task.unresolved_effects)
                for item in resources
                if any(resources_conflict(item, held) for held in operation.resources)
            ]
            if blocked:
                raise TaskConflict("active or unknown operation prevents stable resource handoff")
            if tuple(sorted(task.owned_resources)) != tuple(sorted(owner_resources)):
                raise TaskConflict("resource ownership changed during handoff observation")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"resource-handoff:{task_id}:{handoff_id}",
                command_type="loop.resource.stabilize",
                event_type="loop.resource-handoff-recorded",
                payload={
                    "schema": "SITINA_LOOP_RESOURCE_HANDOFF_RECORDED_V1",
                    "task_id": task_id,
                    "handoff_id": handoff_id,
                    "resources": list(resources),
                    "handoff_ref": observation.reference_id,
                    "handoff_hash": observation.content_hash,
                    "observation_ref": observation.reference_id,
                    "observation_hash": observation.content_hash,
                },
                proofs=(observation.proof,),
            )
        return self.get_task(task_id)

    def record_acceptance(
        self,
        task_id: str,
        submission: AcceptanceSubmission,
        *,
        require_current: bool = False,
        external_guard: Callable[[], bool] | None = None,
    ) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            document = {
                "schema": "SITINA_LOOP_ACCEPTANCE_RECORD_V1",
                "task_id": task_id,
                "acceptance_id": submission.acceptance_id,
                "outcome_id": submission.outcome_id,
                "bound_task_revision": submission.expected_task_revision,
                "bound_run_instance_id": submission.expected_run_instance_id,
                "bound_execution_epoch": submission.expected_execution_epoch,
                "goal_version": submission.expected_goal_version,
                "acceptance_version": submission.expected_acceptance_version,
                "bound_handled_input_seq": submission.expected_handled_input_seq,
                "artifact_ref": submission.artifact_ref,
                "evidence_refs": list(submission.evidence_refs),
                "program_status": submission.program_status,
                "reviewer_status": submission.reviewer_status,
                "delivery_verified": bool(submission.delivery_verified),
                "details": dict(submission.details),
            }
            content_hash = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
            prior_event = next(
                (
                    event
                    for event in reversed(self.store.task_events(task_id))
                    if event.event_type == "loop.acceptance-result-recorded"
                    and event.payload.get("acceptance_id") == submission.acceptance_id
                ),
                None,
            )
            if prior_event is not None:
                prior = self.context_memory.read(
                    str(prior_event.payload["acceptance_ref"]),
                    expected_hash=str(prior_event.payload["acceptance_hash"]),
                )
                if hashlib.sha256(canonical_json_bytes(prior)).hexdigest() != content_hash:
                    raise TaskConflict("acceptance ID is already bound to different evidence")
                return task
            bindings = {
                "task_revision": (task.task_revision, submission.expected_task_revision),
                "run_instance_id": (task.run_instance_id, submission.expected_run_instance_id),
                "execution_epoch": (task.execution_epoch, submission.expected_execution_epoch),
                "goal_version": (task.goal_version, submission.expected_goal_version),
                "acceptance_version": (task.acceptance_version, submission.expected_acceptance_version),
                "handled_input_seq": (task.handled_input_seq, submission.expected_handled_input_seq),
                "artifact_ref": (task.artifact_ref, submission.artifact_ref),
            }
            mismatches = tuple(name for name, pair in bindings.items() if pair[0] != pair[1])
            if task.received_input_seq != task.handled_input_seq:
                mismatches += ("unhandled_input",)
            if require_current and mismatches:
                raise StaleProposal("acceptance binding changed before commit: " + ", ".join(mismatches))
            # MemoryRepository writers use the same Journal mutex.  Keep the
            # final memory-view guard, CAS persistence, and conditional task
            # append in state-lock -> Journal-lock order so an independent
            # native revoke cannot commit between the guard and acceptance.
            with self.store.journal._mutex:
                if external_guard is not None and not external_guard():
                    raise StaleProposal("artifact content changed before acceptance commit")
                try:
                    stored = self.context_memory.persist(document, purpose="loop-acceptance-record")
                except BaseException as error:
                    self._fail_persistence(error)
                    raise
                self._append(
                    task_id=task_id,
                    expected_stream_version=task.task_revision,
                    request_id=f"acceptance:{task_id}:{submission.acceptance_id}",
                    command_type="loop.acceptance.record-result",
                    event_type="loop.acceptance-result-recorded",
                    payload={
                        "schema": "SITINA_LOOP_ACCEPTANCE_RESULT_RECORDED_V1",
                        "task_id": task_id,
                        "acceptance_id": submission.acceptance_id,
                        "acceptance_ref": stored.reference_id,
                        "acceptance_hash": stored.content_hash,
                        "applicable_to_current_task": not mismatches,
                        "binding_mismatches": list(mismatches),
                    },
                    proofs=(stored.proof,),
                )
            return self.get_task(task_id)

    # ------------------------------------------------------------------
    # T5A direct parent/child readonly delegation
    # ------------------------------------------------------------------
    def _child_parent_binding(self, task: TaskProjection) -> dict[str, Any]:
        return {
            "task_id": task.task_id,
            "task_revision": task.task_revision,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": task.execution_epoch,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "received_input_seq": task.received_input_seq,
            "handled_input_seq": task.handled_input_seq,
            "artifact_ref": task.artifact_ref,
            "control_intent": task.control_intent.value,
        }

    def _child_source_manifest(
        self,
        task: TaskProjection,
        sources: Sequence[Mapping[str, Any]],
    ) -> tuple[dict[str, Any], ...]:
        if not isinstance(sources, Sequence) or isinstance(sources, (str, bytes)) or not sources:
            raise ValueError("readonly delegation requires a non-empty source manifest")
        manifest: list[dict[str, Any]] = []
        # Real submissions carry the authorized workspace in the immutable
        # run descriptor.  A child must not widen scope because an artifact
        # happens to contain a convenient path; missing descriptor identity is
        # a hard admission failure.
        if not task.descriptor_ref or not task.descriptor_hash:
            raise ReadonlySourceDenied("readonly child requires a proof-bound run descriptor")
        descriptor = self.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
        workspace_observation = descriptor.get("workspace")
        workspace_path = workspace_observation.get("path") if isinstance(workspace_observation, Mapping) else None
        if not isinstance(workspace_path, str) or not workspace_path.strip():
            raise ReadonlySourceDenied("run descriptor has no authorized workspace identity")
        workspace_root = Path(workspace_path).expanduser().resolve(strict=False)
        for raw in sources:
            if not isinstance(raw, Mapping):
                raise ValueError("readonly source entries must be objects")
            kind = str(raw.get("kind") or "")
            if kind == "history":
                source_ref = str(raw.get("source_ref") or "")
                if not source_ref:
                    raise ValueError("history source_ref is required")
                # Model-visible history refs are authenticated handles of the
                # form history:<binding>:<ordinal>:<digest>, not internal CAS
                # IDs. Resolve them through the same task-bound index/query
                # used by the parent history tool and retain its public
                # projection (which strips private reasoning fields).
                history_index = LoopContextIndex(self.store, task.task_id)
                history_index.refresh()
                if not any(entry.source_ref == source_ref for entry in history_index.entries):
                    raise ReadonlySourceDenied("history source is not visible in the parent task index")
                requested_max = raw.get("max_bytes", 16384)
                if type(requested_max) is not int or not 768 <= requested_max <= 65536:
                    raise ReadonlySourceDenied("history source max_bytes is outside the bounded query range")
                history_page = LoopHistoryQuery(
                    history_index,
                    max_page_bytes=requested_max,
                ).read(
                    source_ref=source_ref,
                    max_bytes=requested_max,
                )
                if history_page.get("status") != "OK":
                    raise ReadonlySourceDenied("history source could not be read through the authenticated query")
                source_id = "source:" + canonical_digest({"kind": kind, "ref": source_ref})
                encoded = json.loads(json.dumps(history_page, ensure_ascii=False, sort_keys=True))
                content_hash = hashlib.sha256(canonical_json_bytes(encoded)).hexdigest()
                manifest.append({
                    "schema": CHILD_SOURCE_SCHEMA,
                    "source_id": source_id,
                    "kind": "history",
                    "source_ref": source_ref,
                    "content_hash": content_hash,
                    "content_json": encoded,
                    "complete": bool(raw.get("complete", True)) and not bool(history_page.get("has_more")),
                })
                continue
            if kind == "file":
                raw_path = str(raw.get("path") or "")
                if not raw_path:
                    raise ValueError("file source path is required")
                raw_candidate = Path(raw_path).expanduser()
                candidate = raw_candidate if raw_candidate.is_absolute() else workspace_root / raw_candidate
                # Reject a symlink at the requested leaf before canonicalizing
                # it; the canonical boundary below rejects links escaping the
                # authorized root.  System aliases such as /var -> /private/var
                # are normalized rather than mistaken for user workspace links.
                if candidate.is_symlink():
                    raise ReadonlySourceDenied("symlink file source is not admitted")
                path = candidate.resolve(strict=False)
                if path.is_symlink() or not path.is_file():
                    raise ReadonlySourceDenied("file source must be an existing regular non-symlink file")
                try:
                    path.relative_to(workspace_root)
                except ValueError as error:
                    raise ReadonlySourceDenied("file source escapes the authorized workspace") from error
                raw_bytes = path.read_bytes()
                source_id = "source:" + canonical_digest({"kind": kind, "path": str(path)})
                manifest.append({
                    "schema": CHILD_SOURCE_SCHEMA,
                    "source_id": source_id,
                    "kind": "file",
                    "path": str(path),
                    "content_hash": hashlib.sha256(raw_bytes).hexdigest(),
                    "content_b64": base64.b64encode(raw_bytes).decode("ascii"),
                    "size": len(raw_bytes),
                    "complete": True,
                })
                continue
            raise ReadonlySourceDenied("T5A supports only verified history and regular file sources")
        if len({str(item["source_id"]) for item in manifest}) != len(manifest):
            raise ValueError("readonly source manifest contains duplicate identities")
        return tuple(manifest)

    def _child_projection(self, task: TaskProjection, delegation_id: str) -> ChildDelegationProjection:
        try:
            return projection_from_mapping(task.child_delegations[delegation_id])
        except KeyError as error:
            raise TaskConflict("unknown child delegation") from error

    def admit_child_delegation(
        self,
        task_id: str,
        *,
        problem_id: str,
        objective: str,
        sources: Sequence[Mapping[str, Any]],
        required: bool = True,
        request_id: str | None = None,
        execution_mode: str = "readonly",
        resources: Sequence[str] = (),
        read_resources: Sequence[str] = (),
        dependencies: Sequence[str] = (),
        permissions: Sequence[str] = ("read",),
        completion_condition: str = "",
        change_reason: str = "new independent work",
        predecessor_id: str | None = None,
        required_tools: Sequence[str] = (),
    ) -> ChildDelegationProjection:
        """Persist one direct child before any executor/tool dispatch."""

        if not isinstance(problem_id, str) or not problem_id.strip() or not isinstance(objective, str) or not objective.strip():
            raise ValueError("child problem and objective are required")
        if type(required) is not bool:
            raise ValueError("child required flag must be boolean")
        if execution_mode not in {"readonly", "task"}:
            raise ValueError("unsupported child execution mode")
        resources = tuple(sorted({str(Path(item).expanduser().resolve(strict=False)) for item in resources}))
        if not isinstance(read_resources, (list, tuple)) or any(
            not isinstance(item, str) or not item.strip() or not Path(item).expanduser().is_absolute()
            for item in read_resources
        ):
            raise ValueError("child read_resources must contain absolute paths")
        read_resources = tuple(sorted({str(Path(item).expanduser().resolve(strict=False)) for item in read_resources}))
        if execution_mode == "readonly" and read_resources:
            raise TaskConflict("readonly investigation uses its immutable source manifest")
        dependencies = tuple(dict.fromkeys(dependencies))
        permissions = tuple(sorted(set(permissions)))
        required_tools = tuple(sorted(set(required_tools)))
        self._require_child_tools(task_id, required_tools, permissions)
        if not set(permissions) <= {"read", "write", "shell", "network", "external_service"}:
            raise ValueError("unknown child tool permission")
        if execution_mode == "readonly" and set(permissions) != {"read"}:
            raise TaskConflict("readonly child permissions cannot be expanded")
        # Snapshot the semantic binding, then perform filesystem/CAS reads
        # outside the coordinator lock.  A final re-read below turns a racing
        # input/control change into a clean admission conflict.
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.is_terminal:
                raise TaskConflict("terminal task cannot admit a child")
            if task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("child admission requires current RUN control and handled input")
            source_task = copy.deepcopy(task)
            source_binding = self._child_parent_binding(task)
            if execution_mode == "task":
                descriptor = self.context_memory.read(str(task.descriptor_ref), expected_hash=str(task.descriptor_hash))
                authorization = descriptor.get("authorization") or {}
                if set(permissions) & {"write", "shell", "external_service"} and authorization.get("approve_writes") is not True:
                    raise TaskConflict("parent task has not authorized writable work")
                if "network" in permissions and not authorization.get("public_web_read") and not authorization.get("network_read_urls"):
                    raise TaskConflict("parent task has not authorized network work")
                if set(permissions) & {"write", "shell", "external_service"} and not resources:
                    raise TaskConflict("writable work must declare its actual resources")
                if not completion_condition.strip():
                    raise ValueError("child completion condition is required")
                known_problems = {str(item.get("problem_id")) for item in task.child_delegations.values()}
                if problem_id in dependencies or not set(dependencies) <= known_problems:
                    raise TaskConflict("child dependencies must identify existing other work items")
                if predecessor_id:
                    predecessor = task.child_delegations.get(predecessor_id)
                    if not predecessor or predecessor.get("problem_id") != problem_id or predecessor.get("status") not in {"SETTLED", "CANCELLED_VERIFIED"} or predecessor.get("unknown_effect"):
                        raise TaskConflict("predecessor must be durably drained before replacement")
        manifest = self._child_source_manifest(source_task, sources) if sources or execution_mode == "readonly" else ()
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if task.is_terminal or task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("parent changed while readonly sources were being captured")
            binding = self._child_parent_binding(task)
            if any(
                source_binding.get(key) != binding.get(key)
                for key in (
                    "task_id", "run_instance_id", "execution_epoch", "goal_version",
                    "acceptance_version", "received_input_seq", "handled_input_seq", "artifact_ref", "control_intent",
                )
            ):
                raise TaskConflict("parent binding changed while readonly sources were being captured")
            fingerprint_binding = {
                key: value for key, value in binding.items() if key != "task_revision"
            }
            base_fingerprint = canonical_digest({
                "contract": DELEGATION_CONTRACT_VERSION,
                "parent_binding": fingerprint_binding,
                "problem_id": problem_id,
                "objective": objective.strip(),
                "source_manifest": manifest,
                "required": required,
                "execution_mode": execution_mode,
                "resources": list(resources),
                **({"read_resources": list(read_resources)} if read_resources else {}),
                "dependencies": list(dependencies),
                "permissions": list(permissions),
                "completion_condition": completion_condition,
                "predecessor_id": predecessor_id,
                "required_tools": list(required_tools),
            })
            existing_items = [
                item for item in task.child_delegations.values()
                if item.get("problem_id") == problem_id
            ]
            if execution_mode == "task" and not predecessor_id:
                for item in task.child_delegations.values():
                    if (item.get("execution_mode") == "task" and item.get("problem_id") != problem_id
                            and item.get("objective") == objective.strip()
                            and tuple(item.get("resources", ())) == resources
                            and tuple(item.get("read_resources", ())) == read_resources
                            and tuple(item.get("permissions", ())) == permissions
                            and self._child_binding_compatible(item.get("parent_binding") or {}, binding)):
                        raise TaskConflict("duplicate work already belongs to " + str(item["problem_id"]))
            for item in existing_items:
                if execution_mode == "task":
                    if item.get("request_fingerprint") == base_fingerprint:
                        return projection_from_mapping(item)
                    continue
                if item.get("request_fingerprint") == base_fingerprint or (
                    item.get("objective") == objective.strip()
                    and tuple(item.get("source_ids", ())) == tuple(entry["source_id"] for entry in manifest)
                    and tuple(
                        entry.get("content_hash") for entry in item.get("source_manifest", ())
                    ) == tuple(entry.get("content_hash") for entry in manifest)
                    and all(
                        (item.get("parent_binding") or {}).get(key) == binding.get(key)
                        for key in (
                            "task_id", "run_instance_id", "execution_epoch", "goal_version",
                            "acceptance_version", "received_input_seq", "handled_input_seq", "artifact_ref", "control_intent",
                        )
                    )
                ):
                    return projection_from_mapping(item)
            generation = max((int(item.get("generation", 0)) for item in existing_items), default=0) + 1
            source_signature = tuple(
                (str(entry.get("source_id") or ""), str(entry.get("content_hash") or ""))
                for entry in manifest
            )
            semantic_prior_candidates = [
                item
                for item in task.child_delegations.values()
                if source_signature and item.get("execution_mode") == "readonly" and item.get("result_ref")
                and tuple(
                    (str(entry.get("source_id") or ""), str(entry.get("content_hash") or ""))
                    for entry in item.get("source_manifest", ())
                ) == source_signature
            ]
            # Problem/objective labels are presentation details.  When a
            # parent renames the same immutable investigation, retain the
            # previous child's evidence/attempt lineage instead of creating a
            # fresh neutral loop with no durable predecessor.
            prior_candidates = [item for item in existing_items if item.get("result_ref")]
            if not prior_candidates:
                prior_candidates = semantic_prior_candidates or existing_items
            prior = max(
                enumerate(prior_candidates),
                key=lambda pair: (int(pair[1].get("generation", 0)), pair[0]),
                default=(0, None),
            )[1]
            if predecessor_id:
                prior = task.child_delegations[predecessor_id]
            if execution_mode == "task" and existing_items and not predecessor_id:
                raise TaskConflict("work item already exists; hand off or replace its current attempt")
            open_attempt_ids = sorted(
                set(task.attempt_plans)
                - {
                    str(item.get("attempt_id"))
                    for item in task.attempt_settlements
                    if item.get("termination_contract_version") == TERMINATION_CONTRACT_VERSION
                }
            )
            parent_attempt_id = open_attempt_ids[-1] if open_attempt_ids else None
            delegation_id = child_identity(task_id, problem_id, generation, base_fingerprint)
            child_task_id = f"child-task:{task_id}:{delegation_id.removeprefix('delegation:')}"
            inherited_evidence = tuple(str(item) for item in (prior or {}).get("inherited_evidence_refs", ()))
            inherited_attempts = tuple(str(item) for item in (prior or {}).get("inherited_attempt_ids", ()))
            inherited_issues = tuple(str(item) for item in (prior or {}).get("inherited_review_issue_ids", ()))
            if prior is not None:
                prior_attempt = str(prior.get("parent_attempt_id") or "")
                if prior_attempt:
                    inherited_attempts = tuple(dict.fromkeys((*inherited_attempts, prior_attempt)))
                prior_result_ref = str(prior.get("result_ref") or "")
                if prior_result_ref:
                    inherited_evidence = tuple(dict.fromkeys((*inherited_evidence, prior_result_ref)))
            contract = {
                "schema": CHILD_RUNTIME_SCHEMA,
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "task_id": task_id,
                "delegation_id": delegation_id,
                "child_task_id": child_task_id,
                "problem_id": problem_id,
                "parent_attempt_id": parent_attempt_id,
                "objective": objective.strip(),
                "generation": generation,
                "required": required,
                "parent_binding": binding,
                "source_manifest": [dict(item) for item in manifest],
                "source_ids": [str(item["source_id"]) for item in manifest],
                "request_fingerprint": base_fingerprint,
                "prior_delegation_id": (prior or {}).get("delegation_id"),
                "prior_evidence_fingerprint": (prior or {}).get("evidence_fingerprint"),
                "inherited_evidence_refs": list(inherited_evidence),
                "inherited_attempt_ids": list(inherited_attempts),
                "inherited_review_issue_ids": list(inherited_issues),
                # This is a description of the validated delegation, not a
                # separate grant. Keep it consistent with the actual tool
                # permissions so a writable handoff is not labelled read-only.
                "allowed_actions": [*(permission.upper() for permission in permissions), "ANALYZE", "REPORT"],
                "execution_mode": execution_mode,
                "resources": list(resources),
                "read_resources": list(read_resources),
                "dependencies": list(dependencies),
                "permissions": list(permissions),
                "completion_condition": completion_condition,
                "change_reason": change_reason,
                "required_tools": list(required_tools),
                "checkpoint_ref": (prior or {}).get("checkpoint_ref"),
                "failure_history": list((prior or {}).get("failure_history", ())),
                "recursive_delegation": False,
                "status": "ADMITTED",
            }
            stored = self.context_memory.persist(contract, purpose="loop-child-runtime-contract")
            append_request = request_id or f"child-admit:{task_id}:{delegation_id}"
            try:
                self._append(
                    task_id=task_id,
                    expected_stream_version=task.task_revision,
                    request_id=append_request,
                    command_type="loop.child-delegation.admit",
                    event_type="loop.child-delegation-admitted",
                    payload={
                        "schema": "SITINA_LOOP_CHILD_DELEGATION_ADMITTED_V1",
                        "task_id": task_id,
                        "delegation_id": delegation_id,
                        "child_task_id": child_task_id,
                        "problem_id": problem_id,
                        "parent_attempt_id": parent_attempt_id,
                        "generation": generation,
                        "required": required,
                        "physical_send_state": "NOT_STARTED",
                        "parent_binding": dict(binding),
                        "request_fingerprint": base_fingerprint,
                        "contract_ref": stored.reference_id,
                        "contract_hash": stored.content_hash,
                        "prior_delegation_id": (prior or {}).get("delegation_id"),
                        "prior_evidence_fingerprint": (prior or {}).get("evidence_fingerprint"),
                    },
                    proofs=(stored.proof,),
                )
            except ExpectedStreamVersionConflict:
                current = self.get_task(task_id)
                for item in current.child_delegations.values():
                    if item.get("request_fingerprint") == base_fingerprint:
                        return projection_from_mapping(item)
                raise
            return self._child_projection(self.get_task(task_id), delegation_id)

    def update_work_plan(self, task_id: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Version a main task's plan in its existing Journal; never complete the task here."""
        from .model import validate_work_plan
        if set(arguments) != {"goal_version", "expected_revision", "reason", "steps"}:
            raise ValueError("work plan update fields are invalid")
        with self._state_lock:
            task = self.get_task(task_id)
            self._assert_current_executor(task)
            if (task.is_terminal or task.control_intent is not ControlIntent.RUN
                    or task.received_input_seq != task.handled_input_seq):
                raise TaskConflict("handle current task controls before updating its plan")
            previous = task.current_work_plan
            revision = previous["revision"] if previous else 0
            if (type(arguments["goal_version"]) is not int or arguments["goal_version"] != task.goal_version
                    or type(arguments["expected_revision"]) is not int or arguments["expected_revision"] != revision):
                raise TaskConflict("work plan update has a stale goal or plan revision; read current context")
            record = {"schema": "SITINA_WORK_PLAN_V1", "task_id": task_id, "goal_version": task.goal_version,
                      "revision": revision + 1, "reason": arguments["reason"], "steps": copy.deepcopy(arguments["steps"])}
            validate_work_plan(record, task_id=task_id, goal_version=task.goal_version, previous_revision=revision)
            if any(ref.startswith("history:") for step in record["steps"] for ref in step["evidence_refs"]):
                index = LoopContextIndex(self.store, task_id)
                index.refresh()
                references = {entry.source_ref: entry.internal_cas_ref for entry in index.entries
                              if entry.kind in {"operation_result", "child_result"}}
                for step_index, step in enumerate(record["steps"], 1):
                    for reference_index, reference in enumerate(step["evidence_refs"], 1):
                        if reference.startswith("history:") and reference not in references:
                            raise TaskConflict(
                                "plan evidence must reference a successful business operation in this task; "
                                f"unrecognized history handle at step {step_index}, reference {reference_index}. "
                                "Query the operation history and copy its exact source_ref; do not reconstruct a handle."
                            )
                    # Different public aliases can identify the same committed
                    # evidence. Preserve first-seen order after canonicalization;
                    # raw duplicate inputs were already rejected above.
                    step["evidence_refs"] = list(dict.fromkeys(
                        references.get(ref, ref) for ref in step["evidence_refs"]
                    ))
            validate_work_plan(record, task_id=task_id, goal_version=task.goal_version, previous_revision=revision)
            self._validate_work_plan_evidence(task, record)
            stored = self.context_memory.persist(record, purpose="loop-work-plan")
            self._append(
                task_id=task_id, expected_stream_version=task.task_revision,
                request_id=f"work-plan:{task_id}:{task.goal_version}:{revision + 1}",
                command_type="loop.work-plan.update", event_type="loop.work-plan-updated",
                payload={"schema": "SITINA_LOOP_WORK_PLAN_UPDATED_V1", "task_id": task_id,
                         "goal_version": task.goal_version, "revision": revision + 1,
                         "plan_ref": stored.reference_id, "plan_hash": stored.content_hash},
                proofs=(stored.proof,),
            )
            return {"status": "ok", "work_plan": record, "source_ref": stored.reference_id}

    def _validate_work_plan_evidence(self, task: TaskProjection, record: Mapping[str, Any]) -> None:
        successful = {op.result_ref for op in task.operations.values()
                      if op.effect_status is EffectStatus.SUCCEEDED and not op.operation_id.startswith("provider-")
                      and op.result_ref}
        results: dict[str, Any] = {}
        requested = {reference for step in record["steps"] for reference in step["evidence_refs"]}
        for delegation_id, child in task.child_delegations.items():
            reference = child.get("result_ref")
            if (child.get("status") != "SETTLED" or child.get("unknown_effect") is not False
                    or not isinstance(reference, str) or reference not in requested
                    or reference in successful):
                continue
            report = self.context_memory.read(reference)
            binding = report.get("parent_binding")
            if (report.get("schema") == "SITINA_LOOP_CHILD_RUNTIME_RESULT_V1"
                    and report.get("status") == "SUCCEEDED"
                    and report.get("delegation_id") == delegation_id
                    and isinstance(binding, Mapping) and binding.get("task_id") == task.task_id
                    and report.get("approves_parent") is False):
                # This is a factual phase-evidence source, not a parent verdict.
                # The selected child, authenticated CAS body and current settled
                # state must agree. Final artifact/review checks remain separate.
                successful.add(reference)
                results[reference] = report
        for step in record["steps"]:
            for reference in step["evidence_refs"]:
                if reference not in successful:
                    raise TaskConflict("plan evidence must reference a successful business operation or a settled "
                                       "successful child report in this task; "
                                       f"invalid reference at step {step['id']}")
                if reference not in results:
                    results[reference] = self.context_memory.read(reference).get("result")
                result = results[reference]
                if isinstance(result, Mapping) and result.get("tool") == "sitina_plan":
                    raise TaskConflict(
                        f"a plan update cannot prove business completion; step {step['id']} references sitina_plan. "
                        "If this step only maintains the plan or sends the final response, remove that administrative "
                        "step and reconnect its business successors to their actual business predecessors. "
                        "Keep real deliverables and mark them completed only with their successful operation evidence."
                    )

    def delegate_readonly(
        self,
        task_id: str,
        *,
        problem_id: str,
        objective: str,
        sources: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return self._delegate_readonly(task_id, problem_id=problem_id, objective=objective, sources=sources)

    def child_execution_current(self, task_id: str, delegation_id: str) -> bool:
        task = self.get_task(task_id)
        child = task.child_delegations.get(delegation_id)
        return bool(child and child.get("status") == "RUNNING" and not task.is_terminal
                    and task.control_intent is ControlIntent.RUN
                    and task.received_input_seq == task.handled_input_seq
                    and self._child_binding_compatible(child.get("parent_binding") or {}, self._child_parent_binding(task)))

    def child_dependency_failures(self, task_id: str, delegation_id: str) -> list[dict[str, Any]]:
        """Return prerequisites needing parent reconciliation, not ordinary waits.

        Readiness and waiting must use the same current-input classification.
        A successful report from an earlier input is retained, but waiting cannot
        make it current; the parent must arrange fresh verification or recovery.
        """
        task = self.get_task(task_id)
        child = task.child_delegations[delegation_id]
        failures = []
        for problem_id in child.get("dependencies", ()):
            prerequisite, result = self._child_dependency_result(task, problem_id)
            if prerequisite["status"] == "STALE_BINDING":
                failures.append({**prerequisite, "reason": (
                    "The prerequisite report belongs to an earlier parent input. Preserve its files and history; "
                    "hand off that prerequisite for fresh verification against the current requirements, "
                    "then consume the new report. Do not treat the old report as current or redo completed writes blindly."
                )})
            elif prerequisite["status"] == "NEEDS_ATTENTION" and result is not None:
                failure = {**prerequisite, "status": result.get("status")}
                reason = result.get("report_error") or result.get("error_message")
                if isinstance(reason, str) and reason:
                    failure["reason"] = reason[:1024]
                    failure["reason_truncated"] = len(reason) > 1024
                failures.append(failure)
        return failures

    def _child_dependency_result(self, task: TaskProjection, problem_id: str) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
        """One current native prerequisite, shared by readiness and handoff consumers."""
        attempts = [item for item in task.child_delegations.values() if item.get("problem_id") == problem_id]
        latest = max(attempts, key=lambda item: int(item["generation"]), default={})
        row = {"problem_id": problem_id, "delegation_id": latest.get("delegation_id"),
               "generation": latest.get("generation"), "status": "WAITING",
               "result_ref": latest.get("result_ref"), "result_hash": latest.get("result_hash")}
        if latest and latest.get("unknown_effect") is not False:
            row["status"] = "UNKNOWN_EFFECT"
            return row, None
        if latest.get("status") != "SETTLED" or not latest.get("result_ref"):
            return row, None
        if self._child_applicability(latest, task) != "CURRENT_PARENT_INPUT":
            row["status"] = "STALE_BINDING"
            return row, None
        if not isinstance(latest.get("result_hash"), str) or not latest["result_hash"]:
            raise PersistenceFenced("dependency result lacks its committed content identity")
        result = self.context_memory.read(str(latest["result_ref"]), expected_hash=latest["result_hash"])
        if (result.get("schema") != CHILD_RUNTIME_RESULT_SCHEMA
                or result.get("delegation_id") != latest.get("delegation_id")
                or result.get("parent_binding") != latest.get("parent_binding")
                or result.get("approves_parent") is not False):
            raise PersistenceFenced("dependency result differs from its committed delegation")
        row["status"] = "READY" if result.get("status") == "SUCCEEDED" else "NEEDS_ATTENTION"
        row["reported_status"] = result.get("status")
        return row, result

    def child_dependency_handoffs(self, task_id: str, delegation_id: str) -> list[dict[str, Any]]:
        """Deliver actual prerequisite locators; neither grant paths nor approve work."""
        from .delegation import child_operation_navigation
        with self._state_lock:
            task = self.get_task(task_id)
            child = task.child_delegations[delegation_id]
            rows = []
            for problem_id in child.get("dependencies", ()):
                row, result = self._child_dependency_result(task, problem_id)
                if row["status"] != "READY" or result is None:
                    raise TaskConflict("dependency is not consumable: " + problem_id + " (" + row["status"] + ")")
                prerequisite = task.child_delegations[row["delegation_id"]]
                summary = str(result.get("summary") or "")
                row["child_summary_excerpt"] = summary[:1200]
                row["summary_truncated"] = len(summary) > 1200
                row["operation_navigation"] = child_operation_navigation(task, prerequisite, self.context_memory.read)
                row["use"] = (
                    "Start from these committed prerequisite reports and operation receipts. The summary is "
                    "child-authored, not independent approval. Read relevant report pages and current file versions "
                    "before integrating. Preserve successful work; investigate only missing or changed inputs. "
                    "References do not expand your file permissions. Report a necessary missing grant to the parent."
                )
                rows.append(row)
            return rows

    def child_ready(self, task_id: str, delegation_id: str) -> tuple[bool, str]:
        task = self.get_task(task_id)
        child = task.child_delegations[delegation_id]
        if child.get("status") not in {"ADMITTED", "DISPATCH_PENDING"}:
            return False, str(child.get("status"))
        for dependency in child.get("dependencies", ()):
            prerequisite, _result = self._child_dependency_result(task, dependency)
            if prerequisite["status"] != "READY":
                return False, "dependency " + dependency + ": " + prerequisite["status"]
        for other in task.child_delegations.values():
            if other.get("delegation_id") == delegation_id:
                continue
            if other.get("status") not in {"RUNNING", "CANCEL_REQUESTED", "RESULT_PERSISTED"} and not other.get("unknown_effect"):
                continue
            if any(resources_conflict(left, right) for left in child.get("resources", ()) for right in other.get("resources", ())):
                return False, "waiting for resource owned by: " + str(other.get("problem_id"))
        for operation in task.active_operations + task.unresolved_effects:
            if operation.mode is OperationMode.WRITE and any(resources_conflict(left, right) for left in child.get("resources", ()) for right in operation.resources):
                return False, "waiting for operation: " + operation.operation_id
        return True, "ready"

    def team_snapshot(self, task_id: str) -> dict[str, Any]:
        task = self.get_task(task_id)
        children = []
        for child in task.child_delegations.values():
            item = {key: child.get(key) for key in (
                "delegation_id", "problem_id", "generation", "objective", "status", "resources", "read_resources",
                "permissions", "dependencies", "completion_condition", "change_reason", "result_ref",
                "required_tools",
                "checkpoint_ref", "unknown_effect", "prior_delegation_id", "failure_history", "progress_reason",
                "pending_transition",
            )}
            if child.get("status") in {"ADMITTED", "DISPATCH_PENDING"}:
                item["waiting_reason"] = self.child_ready(task_id, str(child["delegation_id"]))[1]
            if (child.get("pending_transition") and child["pending_transition"].get("action") != "retire"
                    and not any(other.get("prior_delegation_id") == child["delegation_id"]
                                for other in task.child_delegations.values())):
                reason = self._child_transition_capability_wait(task_id, child)
                if reason:
                    item["waiting_reason"] = reason
                    item["transition_waiting"] = True
            if child.get("result_ref"):
                result = self.context_memory.read(str(child["result_ref"]))
                item["result"] = {key: result.get(key) for key in ("status", "summary", "work_report", "report_error", "error_type", "error_message", "operation_ids")}
                from .delegation import child_operation_navigation
                item["operation_navigation"] = child_operation_navigation(task, child, self.context_memory.read)
            completed_writes = [op for op in task.operations.values()
                                if op.execution_owner == child["delegation_id"] and op.mode is OperationMode.WRITE
                                and op.effect_status is EffectStatus.SUCCEEDED]
            if completed_writes:
                latest_write = completed_writes[-1]
                item["last_completed_write"] = {"operation_id": latest_write.operation_id,
                                                "resources": list(latest_write.resources), "result_ref": latest_write.result_ref}
            children.append(item)
        return {
            "task_id": task_id, "children": children,
            "running": sum(item["status"] in {"RUNNING", "CANCEL_REQUESTED"} for item in children),
            "waiting": sum(item["status"] in {"ADMITTED", "DISPATCH_PENDING", "BLOCKED"}
                           or bool(item["unknown_effect"]) or bool(item.get("transition_waiting")) for item in children),
            "created": len(children),
            "executor_tool_permissions": dict(getattr(self, "_child_tool_capabilities", {}).get(task_id, {})),
            "capability_scope": "Current task executor catalogue, not a particular child's filtered catalogue. "
                                "Permissions and resources still require parent authorization; this is not a grant.",
        }

    def save_child_checkpoint(self, task_id: str, delegation_id: str, *, reason: str, transition: Mapping[str, Any] | None = None) -> str:
        with self._state_lock:
            task = self.get_task(task_id)
            child = task.child_delegations[delegation_id]
            lineage = {str(item["delegation_id"]) for item in task.child_delegations.values() if item.get("problem_id") == child.get("problem_id")}
            operations = [operation for operation in task.operations.values() if operation.execution_owner in lineage]
            document = {
                "task_id": task_id, "delegation_id": delegation_id, "problem_id": child["problem_id"],
                "objective": child["objective"], "parent_binding": dict(child["parent_binding"]),
                "resources": list(child.get("resources", ())), "permissions": list(child.get("permissions", ())),
                "completion_condition": child.get("completion_condition"), "reason": reason,
                "previous_checkpoint_ref": child.get("checkpoint_ref"), "result_ref": child.get("result_ref"),
                "transition": dict(transition if transition is not None else child.get("pending_transition") or {}),
                "last_report": self.context_memory.read(str(child["result_ref"])) if child.get("result_ref") else None,
                "operations": [{"operation_id": op.operation_id, "logical_operation_id": op.logical_operation_id,
                                "status": op.effect_status.value, "unknown_effect": op.unknown_effect,
                                "resources": list(op.resources), "intent_ref": op.intent_ref, "result_ref": op.result_ref,
                                "execution_owner": op.execution_owner} for op in operations],
            }
            stored = self.context_memory.persist(document, purpose="loop-child-checkpoint")
            self._append(task_id=task_id, expected_stream_version=task.task_revision,
                         request_id=f"child-checkpoint:{task_id}:{delegation_id}:{stored.content_hash}",
                         command_type="loop.child-delegation.checkpoint", event_type="loop.child-delegation-checkpointed",
                         payload={"delegation_id": delegation_id, "checkpoint_ref": stored.reference_id, "checkpoint_hash": stored.content_hash},
                         proofs=(stored.proof,))
            return stored.reference_id

    def bind_child_tool_capabilities(self, task_id: str, tools: Mapping[str, str]) -> None:
        """Bind actual native catalogue capabilities; never called from model arguments."""
        with self._state_lock:
            if not hasattr(self, "_child_tool_capabilities"):
                self._child_tool_capabilities = {}
            self._child_tool_capabilities[task_id] = dict(tools)
            pending = [child["delegation_id"] for child in self.get_task(task_id).child_delegations.values()
                       if child.get("pending_transition")]
        for delegation_id in pending:
            self._continue_child_transition(task_id, delegation_id)

    def _child_transition_capability_wait(self, task_id: str, child: Mapping[str, Any]) -> str | None:
        transition = child.get("pending_transition") or {}
        required = tuple(transition.get("required_tools", child.get("required_tools", ())))
        permissions = tuple(transition.get("permissions", child.get("permissions", ())))
        if required and task_id not in getattr(self, "_child_tool_capabilities", {}):
            return "waiting for actual executor capabilities after recovery"
        try:
            self._require_child_tools(task_id, required, permissions)
        except TaskConflict as error:
            return str(error)
        return None

    def _require_child_tools(self, task_id: str, required: Sequence[str], permissions: Sequence[str]) -> None:
        if not set(permissions) <= {"read", "write", "shell", "network", "external_service"}:
            raise TaskConflict("unknown child tool permission")
        if set(permissions) - {"read"}:
            task = self.get_task(task_id)
            descriptor = self.context_memory.read(str(task.descriptor_ref), expected_hash=str(task.descriptor_hash))
            authorization = descriptor.get("authorization") or {}
            if set(permissions) & {"write", "shell", "external_service"} and authorization.get("approve_writes") is not True:
                raise TaskConflict("parent task has not authorized writable work")
            if "network" in permissions and not authorization.get("public_web_read") and not authorization.get("network_read_urls"):
                raise TaskConflict("parent task has not authorized network work")
        tools = getattr(self, "_child_tool_capabilities", {}).get(task_id, {})
        unavailable = [name for name in required if name not in tools]
        missing_permissions = {name: tools[name] for name in required
                               if name in tools and tools[name] not in permissions}
        if unavailable or missing_permissions:
            raise TaskConflict(
                "child admission rejected before dispatch: "
                + json.dumps({"unavailable_tools": unavailable,
                              "required_tool_permissions": missing_permissions,
                              "requested_permissions": list(permissions)}, sort_keys=True)
                + ". Missing permission is not missing capability. Use sitina_team status for the current "
                "executor_tool_permissions; request only necessary permissions already authorized by the parent. "
                "A read-only child's catalogue describes that child only, not all executors."
            )

    @staticmethod
    def _resolve_team_target(task: TaskProjection, arguments: Mapping[str, Any]) -> Mapping[str, Any] | None:
        delegation_id = str(arguments.get("delegation_id") or "")
        problem_id = str(arguments.get("problem_id") or "")
        if delegation_id:
            child = task.child_delegations.get(delegation_id)
            if child is None:
                raise TaskConflict("team work item not found: " + delegation_id)
            if problem_id and child["problem_id"] != problem_id:
                raise TaskConflict("team control target differs from its problem")
            return child
        if problem_id:
            candidates = [item for item in task.child_delegations.values() if item["problem_id"] == problem_id]
            if not candidates:
                raise TaskConflict("team work item not found: " + problem_id)
            return max(candidates, key=lambda item: int(item["generation"]))
        return None

    def manage_team(self, task_id: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        action = str(arguments.get("action") or "status")
        if "read_resources" in arguments and action != "start":
            raise ValueError("read_resources is declared at start; handoff and replacement preserve the existing grant")
        if action in {"status", "wait"}:
            with self._state_lock:
                snapshot = self.team_snapshot(task_id)
                # Both reads must explain the same dependency state. Returning
                # only the catalogue for status hid the actionable prerequisite
                # diagnosis that wait had already exposed; neither read dispatches
                # or changes a child, its grant, or its committed report.
                task = self.get_task(task_id)
                problem_id = str(arguments.get("problem_id") or "")
                delegation_id = str(arguments.get("delegation_id") or "")
                target = self._resolve_team_target(task, arguments)
                candidates = [target] if target is not None else list(task.child_delegations.values())
                pending = [item for item in candidates
                           if item["status"] not in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}]
                blocked = []
                available = []
                for child in pending:
                    failures = self.child_dependency_failures(task_id, str(child["delegation_id"]))
                    if failures:
                        blocked.append({"delegation_id": child["delegation_id"],
                                        "problem_id": child["problem_id"], "failed_dependencies": failures})
                    else:
                        available.append(child)
                if blocked:
                    snapshot["blocked_dependencies"] = blocked
                if available:
                    selected = next((item for item in available if item["status"] == "RUNNING"), available[0])
                    snapshot.update(status="WAITING_CHILD", delegation_id=selected["delegation_id"],
                                    problem_id=selected["problem_id"])
                elif blocked:
                    selected = blocked[0]
                    stale = any(item["status"] == "STALE_BINDING" for item in selected["failed_dependencies"])
                    snapshot.update(status="DEPENDENCY_NEEDS_ATTENTION" if stale else "DEPENDENCY_FAILED", delegation_id=selected["delegation_id"],
                                    problem_id=selected["problem_id"], failed_dependencies=selected["failed_dependencies"],
                                    reason="Settled prerequisites will not become current and successful by waiting. Preserve their records and completed work; reconcile the prerequisite or plan independent verification.")
                elif (problem_id or delegation_id) and candidates:
                    child = candidates[0]
                    status = child["status"]
                    if status == "SETTLED" and child.get("result_ref") and not child.get("unknown_effect"):
                        result = self.context_memory.read(str(child["result_ref"]), expected_hash=child.get("result_hash"))
                        status = result["status"]
                    snapshot.update(status=status, delegation_id=child["delegation_id"],
                                    problem_id=child["problem_id"], result_ref=child.get("result_ref"),
                                    result_hash=child.get("result_hash"))
                return snapshot
        if action == "start":
            child = self.admit_child_delegation(
                task_id, problem_id=str(arguments.get("problem_id") or ""),
                objective=str(arguments.get("objective") or ""), sources=(), execution_mode="task",
                resources=tuple(arguments.get("resources", ())), dependencies=tuple(arguments.get("dependencies", ())),
                read_resources=arguments.get("read_resources", ()),
                permissions=tuple(arguments.get("permissions", ("read",))),
                completion_condition=str(arguments.get("completion_condition") or ""),
                change_reason=str(arguments.get("reason") or "independent work required by the goal"),
                required_tools=tuple(arguments.get("required_tools", ())),
            )
            if self.child_dispatch_hook:
                self.child_dispatch_hook(task_id, child.delegation_id)
            return {"status": child.status, "child": child.as_dict(), "team": self.team_snapshot(task_id)}
        if action not in {"retire", "handoff", "replace"}:
            raise ValueError("unknown team action")
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._resolve_team_target(task, arguments)
            if not child or child.get("execution_mode") != "task":
                raise TaskConflict("team control requires an existing work item")
            delegation_id = str(child["delegation_id"])
            if task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("parent controls must be handled before changing the team")
            if child.get("unknown_effect"):
                raise TaskConflict("reconcile unknown effects before replacing this work item")
            if action == "replace":
                failed = any(op.execution_owner == delegation_id and op.effect_status is EffectStatus.FAILED for op in task.operations.values())
                if child.get("result_ref"):
                    failed = failed or self.context_memory.read(str(child["result_ref"])).get("status") in {"FAILED", "REJECTED"}
                if not failed:
                    raise TaskConflict("replacement requires an observed failure; use handoff for a change in assignment")
                if len(child.get("failure_history", ())) >= 2 and not str(arguments.get("recovery_plan") or "").strip():
                    raise TaskConflict("repeated failures require a concrete recovery plan before another execution")
            prior_plans = [str((item.get("pending_transition") or {}).get("recovery_plan") or "").strip()
                           for item in task.child_delegations.values() if item.get("problem_id") == child["problem_id"]]
            recovery_plan = str(arguments.get("recovery_plan") or "").strip()
            if action != "retire" and len(child.get("failure_history", ())) >= 2 and (not recovery_plan or recovery_plan in prior_plans):
                raise TaskConflict("repeated failure or transfer requires a new evidence-based recovery plan; reused plans are blocked")
            if (action == "handoff" and child.get("prior_delegation_id") and not recovery_plan
                    and not any(op.execution_owner == delegation_id and op.effect_status is EffectStatus.SUCCEEDED
                                for op in task.operations.values())):
                raise TaskConflict("no verified progress since the previous transfer; diagnose the missing capability or dependency first")
            permissions = tuple(arguments.get("permissions", child.get("permissions", ("read",))))
            required_tools = tuple(arguments.get("required_tools", child.get("required_tools", ())))
            if action != "retire":
                self._require_child_tools(task_id, required_tools, permissions)
            reason = str(arguments.get("reason") or "").strip()
            if not reason:
                raise ValueError("team change reason is required")
            transition = {"action": action, "reason": reason,
                          "objective": str(arguments.get("objective") or child["objective"]),
                          "recovery_plan": recovery_plan, "permissions": list(permissions),
                          "required_tools": list(required_tools)}
            self.save_child_checkpoint(task_id, delegation_id, reason=reason, transition=transition)
            if child.get("status") not in {"SETTLED", "CANCELLED_VERIFIED"}:
                self.request_child_cancel(task_id, delegation_id, reason=reason)
            if (task_id, delegation_id) not in self._child_running:
                current = self.get_task(task_id).child_delegations[delegation_id]
                if current.get("status") not in {"SETTLED", "CANCELLED_VERIFIED"}:
                    self.settle_child_delegation(task_id, delegation_id, status="CANCELLED_VERIFIED")
        self._continue_child_transition(task_id, delegation_id)
        return self.team_snapshot(task_id)

    def _continue_child_transition(self, task_id: str, delegation_id: str) -> None:
        with self._state_lock:
            task = self.get_task(task_id)
            child = task.child_delegations[delegation_id]
            transition = child.get("pending_transition") or {}
            if (task.is_terminal or task.run_instance_id != self.run_instance_id
                    or task.recovery_state not in {"READY_NEW_TASK", "READY_RECOVERED"}):
                return
            if not transition or transition.get("action") == "retire" or child.get("unknown_effect"):
                return
            if child.get("status") not in {"SETTLED", "CANCELLED_VERIFIED"} or (task_id, delegation_id) in self._child_running:
                return
            if task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                return
            if any(op.execution_owner == delegation_id and (not op.result_ref or op.unknown_effect) for op in task.operations.values()):
                return
            if any(item.get("prior_delegation_id") == delegation_id for item in task.child_delegations.values()):
                return
            if self._child_transition_capability_wait(task_id, child):
                return
            successor = self.admit_child_delegation(
                task_id, problem_id=str(child["problem_id"]), objective=str(transition["objective"]), sources=(),
                execution_mode="task", resources=tuple(child.get("resources", ())),
                read_resources=tuple(child.get("read_resources", ())),
                permissions=tuple(transition.get("permissions", child.get("permissions", ()))),
                required_tools=tuple(transition.get("required_tools", child.get("required_tools", ()))),
                dependencies=tuple(child.get("dependencies", ())),
                completion_condition=str(child["completion_condition"]), change_reason=str(transition["reason"]),
                predecessor_id=delegation_id,
            )
        if self.child_dispatch_hook:
            self.child_dispatch_hook(task_id, successor.delegation_id)

    def _delegate_readonly(
        self,
        task_id: str,
        *,
        problem_id: str,
        objective: str,
        sources: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Formal parent-assistant entry: admit, then hand off non-blockingly."""

        child = self.admit_child_delegation(
            task_id,
            problem_id=problem_id,
            objective=objective,
            sources=sources,
            required=True,
        )
        scheduled = False
        hook = self.child_dispatch_hook
        if hook is not None and child.status in {"ADMITTED", "DISPATCH_PENDING"}:
            hook(task_id, child.delegation_id)
            scheduled = True
        raw_child = self.get_task(task_id).child_delegations.get(child.delegation_id, {})
        return {
            "schema": CHILD_RUNTIME_SCHEMA,
            "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
            "status": "WAITING_CHILD" if scheduled else child.status,
            "delegation_id": child.delegation_id,
            "child_task_id": child.child_task_id,
            "parent_task_id": task_id,
            "problem_id": child.problem_id,
            "generation": child.generation,
            "required": child.required,
            "continuation_pending": True,
            # These fields let the parent termination protocol recognize a
            # renamed re-delegation of already observed immutable evidence.
            # They do not grant the child approval authority and do not expose
            # private reasoning or a mutable child binding.
            "prior_evidence_fingerprint": raw_child.get("prior_evidence_fingerprint"),
            "inherited_evidence_refs": list(raw_child.get("inherited_evidence_refs", ())),
            "approves_parent": False,
        }

    def execute_child_provider_turn(
        self,
        task_id: str,
        delegation_id: str,
        dispatch: Callable[[], Any],
    ) -> Any:
        """Run one child-model turn through the durable operation boundary.

        The callable is invoked only after the current parent binding/control
        barrier is rechecked.  Provider metadata and private protocol fields
        are stored as the child operation result; reasoning never enters the
        public child result envelope.
        """

        if not callable(dispatch):
            raise TypeError("child provider dispatch must be callable")
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status not in {"DISPATCH_PENDING", "RUNNING", "CANCEL_REQUESTED"}:
                raise TaskConflict("child provider turn requires an active child")
            if task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                raise TaskConflict("parent control or unhandled input blocks child provider dispatch")
            current_binding = self._child_parent_binding(task)
            if not self._child_binding_compatible(child.parent_binding, current_binding):
                raise TaskConflict("child provider binding is stale")
            prefix = f"child:{delegation_id}:provider:"
            turn_index = 1 + sum(
                1
                for operation in task.operations.values()
                if operation.logical_operation_id.startswith(prefix)
            )
            operation_id = f"child-provider-{delegation_id.removeprefix('delegation:')}-{turn_index}-{secrets.token_hex(6)}"
            intent = OperationIntent(
                operation_id=operation_id,
                logical_operation_id=f"{prefix}{turn_index}",
                attempt_id=f"child-attempt:{delegation_id}",
                mode=OperationMode.READ,
                description=f"readonly child Provider turn {turn_index}",
                resources=(),
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_handled_input_seq=task.handled_input_seq,
                capability_snapshot_id=task.capability_snapshot_id,
                preconditions=(),
                recovery=RecoveryPolicy(
                    probe="inspect the persisted child Provider operation",
                    retry="retry only after a new child turn identity is admitted",
                    partial="retain the private protocol and stop the child",
                    cancel="finish or reconcile the current child Provider call",
                    unknown_exit="hold the child responsibility until reconciliation",
                    reconsider_at="after new parent input or independently verified evidence",
                ),
            )
            box: dict[str, Any] = {}

        from .request_delivery import NativeRequestDelivery
        from sitina.runners.provider import provider_request_evidence
        recorder = NativeRequestDelivery(self.context_memory, {
            "task_id": task_id, "operation_id": intent.operation_id,
            "logical_operation_id": intent.logical_operation_id,
            "execution_owner": delegation_id, "work_purpose": "readonly_child",
            "goal_version": task.goal_version, "acceptance_version": task.acceptance_version,
            "handled_input_seq": task.handled_input_seq, "turn": turn_index,
        })

        def execute_provider() -> OperationOutcome:
            try:
                turn = dispatch()
                if not hasattr(turn, "tool_calls") or not hasattr(turn, "text"):
                    raise TypeError("child provider returned an invalid tool turn")
                box["turn"] = turn
                # Only the durable audit copy is canonicalized. The original
                # turn remains in ``box`` so the model receives tool arguments
                # and private protocol fields with their original types.
                return OperationOutcome(
                    EffectStatus.SUCCEEDED,
                    {
                        "schema": "SITINA_LOOP_CHILD_PROVIDER_TURN_V1",
                        "task_id": task_id,
                        "delegation_id": delegation_id,
                        "turn_index": turn_index,
                        "text": str(getattr(turn, "text", "")),
                        "reasoning_content": str(getattr(turn, "reasoning_content", "")),
                        "tool_calls": [
                            {
                                "id": str(getattr(call, "call_id", "")),
                                "name": str(getattr(call, "name", "")),
                                "arguments": _canonical_safe_audit(
                                    dict(getattr(call, "arguments", {}) or {})
                                ),
                            }
                            for call in tuple(getattr(turn, "tool_calls", ()))
                        ],
                        "stop_reason": getattr(turn, "stop_reason", None),
                        "metadata": _canonical_safe_audit(dict(getattr(turn, "metadata", {}) or {})),
                        "private_protocol": True,
                    },
                )
            except ProviderCancelledError as error:
                raw_count = getattr(error, "sitina_physical_send_count", None)
                count = raw_count if type(raw_count) is int and raw_count >= 0 else None
                count_status = str(
                    getattr(
                        error,
                        "sitina_physical_send_count_status",
                        getattr(error, "sitina_physical_send_status", "unknown"),
                    )
                )
                raw_uncertain = getattr(error, "sitina_uncertain_physical_send_attempt_count", None)
                uncertain = raw_uncertain if type(raw_uncertain) is int and raw_uncertain >= 0 else None
                physical_status = str(
                    getattr(error, "sitina_physical_send_status", count_status)
                )
                exact_no_send = count == 0 and count_status == "exact" and uncertain == 0
                evidence: dict[str, Any] = {
                    "schema": "SITINA_LOOP_CHILD_PROVIDER_CANCELLED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "turn_index": turn_index,
                    "provider_cancelled": True,
                    "physical_send_count": (
                        count if count is not None else _canonical_safe_audit(raw_count)
                    ),
                    "physical_send_count_status": count_status,
                    "physical_send_status": physical_status,
                    "uncertain_physical_send_attempt_count": (
                        uncertain if uncertain is not None else _canonical_safe_audit(raw_uncertain)
                    ),
                    "provider_physical_send_count_lower_bound": count,
                    "private_protocol": True,
                }
                if exact_no_send:
                    evidence.update(
                        {
                            "effect_dispatched": False,
                            "recovery_decision": "NO_EFFECT",
                            "execution_started": False,
                            "effect_settled": True,
                        }
                    )
                    return OperationOutcome(EffectStatus.FAILED, evidence)
                evidence.update(
                    {
                        "recovery_decision": "UNKNOWN",
                        "effect_requires_probe": True,
                    }
                )
                return OperationOutcome(EffectStatus.UNKNOWN, evidence)

        def execute() -> OperationOutcome:
            with provider_request_evidence(recorder.persist, recorder.observe):
                try:
                    observed = execute_provider()
                except BaseException as error:
                    # Preserve the transport observation even when no usable
                    # model turn exists. No response tools are dispatched.
                    count = getattr(error, "sitina_physical_send_count", None)
                    state = str(getattr(error, "sitina_physical_send_status", "unknown"))
                    not_sent = type(count) is int and count == 0 and state.startswith("pre_send_")
                    observed = OperationOutcome(EffectStatus.FAILED if not_sent else EffectStatus.UNKNOWN, {
                        "schema": "SITINA_LOOP_CHILD_PROVIDER_FAILED_V1", "task_id": task_id,
                        "delegation_id": delegation_id, "turn_index": turn_index,
                        "error_type": type(error).__name__, "physical_send_count": count,
                        "physical_send_status": state, "business_effect_dispatched": False,
                        "private_protocol": True,
                    })
            return OperationOutcome(observed.status, {**dict(observed.result),
                                                       "private_request_delivery": recorder.as_record()})

        outcome = self.execute_operation(task_id, intent, execute)
        if outcome.result.get("result_discarded") is True:
            raise TaskConflict("child Provider result exceeded resource limits; effect retained and no requested tools executed")
        if outcome.status is not EffectStatus.SUCCEEDED or "turn" not in box:
            error = TaskConflict("child Provider turn did not complete with a durable result")
            # A transport/operation UNKNOWN is not equivalent to a safe
            # pre-send rejection; carry that physical uncertainty to child
            # settlement so parent terminal remains blocked.
            error.child_physical_send_state = (
                "UNKNOWN" if outcome.status is EffectStatus.UNKNOWN else "NOT_APPLICABLE"
            )
            raise error
        return box["turn"]

    def request_child_cancel(self, task_id: str, delegation_id: str, *, reason: str) -> ChildDelegationProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                return child
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-cancel:{task_id}:{delegation_id}",
                command_type="loop.child-delegation.cancel",
                event_type="loop.child-delegation-cancel-requested",
                payload={
                    "schema": "SITINA_LOOP_CHILD_DELEGATION_CANCEL_REQUESTED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "reason": str(reason),
                    "parent_binding": self._child_parent_binding(task),
                },
            )
            return self._child_projection(self.get_task(task_id), delegation_id)

    @staticmethod
    def _child_applicability(child: Mapping[str, Any], task: TaskProjection) -> str:
        if child.get("authority_revoked"):
            return "LATE_EVIDENCE_ONLY"
        binding = child.get("parent_binding") or {}
        current = {
            "task_id": task.task_id,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": task.execution_epoch,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "received_input_seq": task.received_input_seq,
            "handled_input_seq": task.handled_input_seq,
            "artifact_ref": task.artifact_ref,
            "control_intent": task.control_intent.value,
        }
        return "CURRENT_PARENT_INPUT" if all(binding.get(key) == value for key, value in current.items()) else "LATE_EVIDENCE_ONLY"

    @staticmethod
    def _child_binding_compatible(
        child_binding: Mapping[str, Any],
        current_binding: Mapping[str, Any],
    ) -> bool:
        """Allow only a same-input recovery identity transition.

        A host/process claim necessarily changes ``run_instance_id`` and
        ``execution_epoch``. Those two fields remain preserved in the child
        result binding and therefore make the result late evidence, but they
        do not invalidate an admitted, not-yet-sent child. Every semantic
        input/control/artifact field still has to match exactly.
        """

        return all(
            child_binding.get(key) == current_binding.get(key)
            for key in (
                "task_id",
                "goal_version",
                "acceptance_version",
                "received_input_seq",
                "handled_input_seq",
                "artifact_ref",
                "control_intent",
            )
        )

    def refresh_child_applicability(self, task_id: str, delegation_id: str) -> ChildDelegationProjection:
        """Record current applicability without rewriting the original result binding."""

        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if not child.result_ref:
                return child
            applicability = self._child_applicability(task.child_delegations[delegation_id], task)
            if applicability == child.applicability:
                return child
            document = {
                "schema": "SITINA_LOOP_CHILD_APPLICABILITY_V1",
                "task_id": task_id,
                "delegation_id": delegation_id,
                "result_ref": child.result_ref,
                "original_parent_binding": dict(child.parent_binding),
                "current_parent_binding": self._child_parent_binding(task),
                "applicability": applicability,
                "evidence_only": applicability == "LATE_EVIDENCE_ONLY",
            }
            stored = self.context_memory.persist(document, purpose="loop-child-applicability")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-applicability:{task_id}:{delegation_id}:{stored.content_hash}",
                command_type="loop.child-delegation.refresh-applicability",
                event_type="loop.child-delegation-applicability-updated",
                payload={
                    "schema": "SITINA_LOOP_CHILD_APPLICABILITY_UPDATED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "applicability_ref": stored.reference_id,
                    "applicability_hash": stored.content_hash,
                    "applicability": applicability,
                },
                proofs=(stored.proof,),
            )
            return self._child_projection(self.get_task(task_id), delegation_id)

    def block_child_recovery(
        self,
        task_id: str,
        delegation_id: str,
        *,
        blocker_id: str,
        reason: str,
        unknown_effect: bool = True,
    ) -> ChildDelegationProjection:
        """Persist finite child recovery parking without blind redispatch."""

        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status in {"SETTLED", "CANCELLED_VERIFIED", "RECOVERY_BLOCKED"}:
                return child
            document = {
                "schema": "SITINA_LOOP_CHILD_RECOVERY_BLOCKED_V1",
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "task_id": task_id,
                "delegation_id": delegation_id,
                "status": "RECOVERY_BLOCKED",
                "unknown_effect": bool(unknown_effect),
                "blocker_id": str(blocker_id),
                "reason": str(reason),
                "original_parent_binding": dict(child.parent_binding),
                "result_ref": child.result_ref,
            }
            stored = self.context_memory.persist(document, purpose="loop-child-recovery-blocked")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-recovery-blocked:{task_id}:{delegation_id}:{blocker_id}",
                command_type="loop.child-delegation.recovery-block",
                event_type="loop.child-delegation-recovery-blocked",
                payload={
                    "schema": "SITINA_LOOP_CHILD_RECOVERY_BLOCKED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "recovery_ref": stored.reference_id,
                    "recovery_hash": stored.content_hash,
                    "blocker_id": str(blocker_id),
                    "unknown_effect": bool(unknown_effect),
                },
                proofs=(stored.proof,),
            )
            return self._child_projection(self.get_task(task_id), delegation_id)

    def recover_child_delegations(self, task_id: str) -> TaskProjection:
        """Reconcile durable child facts after a host/process restart."""

        task = self.get_task(task_id)
        for delegation_id, raw in tuple(task.child_delegations.items()):
            status = str(raw.get("status") or "")
            if raw.get("execution_mode") == "task" and (task_id, delegation_id) not in self._child_running:
                current = self.get_task(task_id)
                binding = raw.get("parent_binding") or {}
                if status in {"ADMITTED", "DISPATCH_PENDING"} and binding.get("run_instance_id") == self.run_instance_id and binding.get("execution_epoch") == current.execution_epoch and self._child_binding_compatible(binding, self._child_parent_binding(current)):
                    continue
                if status in {"SETTLED", "CANCELLED_VERIFIED"}:
                    self._continue_child_transition(task_id, delegation_id)
                    continue
                if status == "RECOVERY_BLOCKED":
                    continue
                owned = [op for op in self.get_task(task_id).operations.values() if op.execution_owner == delegation_id]
                if any(not op.result_ref or op.unknown_effect for op in owned):
                    self.block_child_recovery(task_id, delegation_id, blocker_id="CHILD_ACTION_RECONCILIATION_REQUIRED",
                                              reason="reconcile the recorded child actions before transfer", unknown_effect=True)
                    continue
                if raw.get("result_ref"):
                    self.settle_child_delegation(task_id, delegation_id, status="SETTLED")
                    self._continue_child_transition(task_id, delegation_id)
                    continue
                current = self.get_task(task_id)
                compatible = self._child_binding_compatible(raw.get("parent_binding") or {}, self._child_parent_binding(current))
                transition = raw.get("pending_transition") or {
                    "action": "handoff" if compatible else "retire",
                    "reason": "resume the same work item after host recovery" if compatible else "parent input or control changed",
                    "objective": raw["objective"],
                }
                self.save_child_checkpoint(task_id, delegation_id, reason=str(transition["reason"]), transition=transition)
                self.request_child_cancel(task_id, delegation_id, reason=str(transition["reason"]))
                self.settle_child_delegation(task_id, delegation_id, status="CANCELLED_VERIFIED")
                self._continue_child_transition(task_id, delegation_id)
                continue
            if status in {"SETTLED", "CANCELLED_VERIFIED"}:
                if raw.get("result_ref"):
                    self.refresh_child_applicability(task_id, delegation_id)
                continue
            if status == "RECOVERY_BLOCKED":
                continue
            if raw.get("result_ref"):
                self.refresh_child_applicability(task_id, delegation_id)
                self.settle_child_delegation(
                    task_id,
                    delegation_id,
                    status="SETTLED",
                    unknown_effect=bool(raw.get("unknown_effect")),
                )
                task = self.get_task(task_id)
                continue
            current = self.get_task(task_id)
            provider_operations = [
                operation for operation in current.operations.values()
                if operation.logical_operation_id.startswith(f"child:{delegation_id}:provider:")
            ]
            if (
                not provider_operations
                and status in {"ADMITTED", "DISPATCH_PENDING"}
                and current.control_intent is ControlIntent.RUN
                and current.received_input_seq == current.handled_input_seq
            ):
                # Admission is durable before dispatch. A host exit at this
                # boundary keeps the original delegation resumable; it is
                # not silently converted into a cancellation.
                continue
            # An operation intent is not proof that a Provider request was
            # sent.  The durable operation-dispatch-started marker is the
            # physical send boundary; if it is absent, recovery may verify a
            # safe no-send cancellation even though the intent itself was
            # persisted before a host/process exit.
            provider_dispatch_started = any(
                self._operation_dispatch_started(task_id, operation.operation_id)
                for operation in provider_operations
            )
            if provider_operations and not provider_dispatch_started:
                # The child Provider intent was durably written, but no
                # physical dispatch boundary exists. Close that original
                # operation identity as trusted NO_EFFECT before deciding the
                # child lifecycle; leaving INTENT_RECORDED active would park
                # the parent forever despite verified no-send facts.
                for operation in provider_operations:
                    self.reconcile_operation_no_effect(
                        task_id,
                        operation.operation_id,
                        reason="child Provider intent persisted before dispatch-start; verified no physical send",
                    )
                current = self.get_task(task_id)
                provider_operations = [
                    operation
                    for operation in current.operations.values()
                    if operation.logical_operation_id.startswith(f"child:{delegation_id}:provider:")
                ]
            if (
                not provider_dispatch_started
                and status in {"ADMITTED", "DISPATCH_PENDING", "CANCEL_REQUESTED", "RUNNING"}
                and str(raw.get("physical_send_state") or "NOT_APPLICABLE") in {"NOT_STARTED", "NOT_APPLICABLE"}
            ):
                self.settle_child_delegation(
                    task_id,
                    delegation_id,
                    status="CANCELLED_VERIFIED",
                    recovery_verified_no_send=True,
                )
                task = self.get_task(task_id)
                continue
            if any(operation.unknown_effect or operation.effect_status is EffectStatus.UNKNOWN for operation in provider_operations):
                self.block_child_recovery(
                    task_id,
                    delegation_id,
                    blocker_id="CHILD_PROVIDER_UNKNOWN",
                    reason="child Provider operation has unknown physical effect; no blind redispatch is authorized",
                    unknown_effect=True,
                )
            else:
                self.block_child_recovery(
                    task_id,
                    delegation_id,
                    blocker_id="CHILD_RESULT_MISSING_AFTER_DISPATCH",
                    reason="child dispatch/provider facts exist without a durable child result; explicit reconciliation is required",
                    unknown_effect=bool(provider_operations),
                )
            task = self.get_task(task_id)
        # Applicability refreshes may append events while iterating settled
        # children; return the replayed projection at the current stream head,
        # never the pre-refresh snapshot.
        return self.get_task(task_id)

    def dispatch_child_delegation(
        self,
        task_id: str,
        delegation_id: str,
        executor: Callable[[ReadonlyChildCapability], Mapping[str, Any]],
    ) -> ChildDelegationProjection:
        if not callable(executor):
            raise TypeError("child executor must be callable")
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status not in {"ADMITTED", "DISPATCH_PENDING"}:
                return child
            ready, _reason = self.child_ready(task_id, delegation_id)
            if not ready:
                return child
            current_binding = self._child_parent_binding(task)
            if task.control_intent is not ControlIntent.RUN or task.received_input_seq != task.handled_input_seq:
                self.request_child_cancel(task_id, delegation_id, reason="parent control or unhandled input changed before dispatch")
                self.settle_child_delegation(task_id, delegation_id, status="CANCELLED_VERIFIED")
                return self._child_projection(self.get_task(task_id), delegation_id)
            if not self._child_binding_compatible(child.parent_binding, current_binding):
                self.request_child_cancel(task_id, delegation_id, reason="parent binding changed before dispatch")
                self.settle_child_delegation(task_id, delegation_id, status="CANCELLED_VERIFIED")
                return self._child_projection(self.get_task(task_id), delegation_id)
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-dispatch-start:{task_id}:{delegation_id}:1",
                command_type="loop.child-delegation.dispatch-start",
                event_type="loop.child-delegation-dispatch-started",
                payload={
                    "schema": "SITINA_LOOP_CHILD_DELEGATION_DISPATCH_STARTED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "dispatch_epoch": 1,
                    "executor_slot": delegation_id,
                    "physical_send_state": "NOT_APPLICABLE",
                },
            )
            capability = ReadonlyChildCapability(
                child.source_manifest,
                parent_binding=child.parent_binding,
                binding_guard=lambda: (
                    dict(child.parent_binding)
                    if self.child_execution_current(task_id, delegation_id)
                    else {}
                ),
                objective=child.objective,
            )
            dispatch_token = object()
            self._child_dispatch_tokens[(task_id, delegation_id)] = dispatch_token
            self._child_running.add((task_id, delegation_id))

        def rejected_result(*, status: str, error: BaseException | None = None, reason: str | None = None) -> dict[str, Any]:
            document: dict[str, Any] = {
                "schema": CHILD_RUNTIME_RESULT_SCHEMA,
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "delegation_id": delegation_id,
                "parent_binding": dict(child.parent_binding),
                "summary": reason or (f"child executor failed: {type(error).__name__}" if error else "child report rejected"),
                "status": status,
                "approves_parent": False,
                "evidence_source_ids": [],
            }
            if error is not None:
                document["error_type"] = type(error).__name__
                document["error_message"] = str(error)
            if reason is not None:
                document["rejection_reason"] = reason
            return document

        try:
            result = executor(capability)
            if not isinstance(result, Mapping):
                raise TypeError("child executor result must be a mapping")
            if result.get("schema") != CHILD_RUNTIME_RESULT_SCHEMA:
                raise TaskConflict("child executor returned a non-runtime result schema")
            supplied_binding = result.get("parent_binding")
            if supplied_binding is not None and dict(supplied_binding) != dict(child.parent_binding):
                raise TaskConflict("child executor changed the parent binding")
            if "approves_parent" in result and result.get("approves_parent") is not False:
                raise TaskConflict("child executor attempted to approve its parent")
            result_document = dict(result)
            result_document.setdefault("delegation_contract_version", DELEGATION_CONTRACT_VERSION)
            result_document.setdefault("delegation_id", delegation_id)
            result_document.setdefault("parent_binding", dict(child.parent_binding))
            result_document["approves_parent"] = False
            result_document["observations"] = [dict(item) for item in capability.observations]
            if not result_document.get("evidence_source_ids"):
                result_document["evidence_source_ids"] = list(dict.fromkeys(
                    str(item["source_id"]) for item in capability.observations
                ))
            physical_state = str(result_document.get("physical_send_state") or "NOT_APPLICABLE")
        except BaseException as error:
            # Revoked ownership/control ends this execution. Preserve the
            # exception, without reporting the parent's cancellation as a new
            # business failure that could incorrectly authorize replacement.
            cancelled = not self.child_execution_current(task_id, delegation_id)
            result_document = rejected_result(status="CANCELLED" if cancelled else "FAILED", error=error)
            physical_state = str(getattr(error, "child_physical_send_state", "NOT_APPLICABLE"))

        try:
            self.record_child_result(
                task_id,
                delegation_id,
                result_document,
                physical_send_state=physical_state,
                observations=capability.observations,
                _dispatch_token=dispatch_token,
            )
        except ReadonlySourceDenied as error:
            # A callable may have returned a syntactically valid envelope
            # whose evidence was not actually observed.  Record a durable
            # rejection and settle the completed execution, without treating
            # its content as valid investigation evidence.
            rejected = rejected_result(
                status="REJECTED",
                reason=f"child report rejected: {error}",
            )
            self.record_child_result(
                task_id,
                delegation_id,
                rejected,
                physical_send_state=physical_state,
                observations=capability.observations,
                _dispatch_token=dispatch_token,
            )
        settled = self.settle_child_delegation(task_id, delegation_id, status="SETTLED", unknown_effect=physical_state == "UNKNOWN")
        if child.execution_mode == "task":
            self.save_child_checkpoint(task_id, delegation_id, reason="execution drained; result and operation ledger saved")
            self._continue_child_transition(task_id, delegation_id)
        return settled

    def record_child_result(
        self,
        task_id: str,
        delegation_id: str,
        result: Mapping[str, Any],
        *,
        physical_send_state: str = "NOT_APPLICABLE",
        observations: Sequence[Mapping[str, Any]] | None = None,
        _dispatch_token: object | None = None,
    ) -> ChildDelegationProjection:
        if not isinstance(result, Mapping):
            raise TypeError("child result must be an object")
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status not in {"RUNNING", "CANCEL_REQUESTED", "DISPATCH_PENDING"}:
                raise TaskConflict("child result requires an active dispatched child")
            expected_token = self._child_dispatch_tokens.get((task_id, delegation_id))
            if expected_token is None or _dispatch_token is not expected_token:
                raise TaskConflict("child result lacks a backend dispatch credential")
            if child.result_ref and child.status in {"RESULT_PERSISTED", "SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                return child
            bound = result.get("parent_binding")
            if not isinstance(bound, Mapping) or dict(bound) != dict(child.parent_binding):
                raise TaskConflict("child result must retain its original parent binding")
            if result.get("approves_parent") is not False:
                raise TaskConflict("child result cannot approve its parent")
            source_ids = set(str(item["source_id"]) for item in child.source_manifest)
            evidence_ids = set(str(item) for item in result.get("evidence_source_ids", ()))
            if not evidence_ids <= source_ids:
                raise ReadonlySourceDenied("child result cites an undeclared source")
            verified_observations = tuple(dict(item) for item in (observations if observations is not None else ()))
            observed_ids = {str(item.get("source_id") or "") for item in verified_observations}
            outcome = str(result.get("status") or result.get("outcome") or "").upper()
            if child.execution_mode == "readonly" and not evidence_ids and outcome not in {"FAILED", "REJECTED", "CANCELLED"}:
                raise ReadonlySourceDenied(
                    "a successful readonly result must cite at least one observed source"
                )
            if not observed_ids <= source_ids or not evidence_ids <= observed_ids:
                raise ReadonlySourceDenied("child result evidence was not observed by the backend capability")
            for observation in verified_observations:
                source = next(
                    (item for item in child.source_manifest if item.get("source_id") == observation.get("source_id")),
                    None,
                )
                if source is None or str(source.get("content_hash")) != str(observation.get("content_hash")):
                    raise ReadonlySourceDenied("child observation hash is not bound to the immutable source")
            document = dict(result)
            if child.execution_mode == "task":
                operations = [op for op in task.operations.values() if op.execution_owner == delegation_id]
                if any(not op.result_ref or op.unknown_effect for op in operations):
                    physical_send_state = "UNKNOWN"
                document["operation_ids"] = [op.operation_id for op in operations]
                document["operation_result_refs"] = [op.result_ref for op in operations if op.result_ref]
                if outcome == "SUCCEEDED" and not operations:
                    raise ReadonlySourceDenied("task result has no recorded execution")
                if task.child_delegations[delegation_id].get("authority_revoked"):
                    document["late_report_status"] = document.get("status")
                    document["status"] = "CANCELLED"
                    document["summary"] = "Execution retired; saved progress is available to its successor. " + str(document.get("summary") or "")
            document.update({
                "schema": CHILD_RUNTIME_RESULT_SCHEMA,
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "delegation_id": delegation_id,
                "parent_binding": dict(child.parent_binding),
                "approves_parent": False,
                "physical_send_state": str(physical_send_state),
                "observations": [dict(item) for item in verified_observations],
            })
            evidence_fingerprint = canonical_digest({
                "source_manifest": [
                    {
                        "source_id": str(item.get("source_id") or ""),
                        "content_hash": str(item.get("content_hash") or ""),
                    }
                    for item in child.source_manifest
                ],
                "status": str(document.get("status") or document.get("outcome") or "").upper(),
                "summary": str(document.get("summary") or ""),
                "evidence_source_ids": sorted(evidence_ids),
            })
            document["evidence_fingerprint"] = evidence_fingerprint
            stored = self.context_memory.persist(document, purpose="loop-child-runtime-result")
            current_binding = self._child_parent_binding(task)
            applicability = "CURRENT_PARENT_INPUT" if all(
                child.parent_binding.get(key) == current_binding.get(key)
                for key in (
                    "task_id", "run_instance_id", "execution_epoch", "goal_version",
                    "acceptance_version", "received_input_seq", "handled_input_seq",
                    "artifact_ref", "control_intent",
                )
            ) else "LATE_EVIDENCE_ONLY"
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-result:{task_id}:{delegation_id}:{stored.content_hash}",
                command_type="loop.child-delegation.record-result",
                event_type="loop.child-delegation-result-recorded",
                payload={
                    "schema": "SITINA_LOOP_CHILD_DELEGATION_RESULT_RECORDED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "result_ref": stored.reference_id,
                    "result_hash": stored.content_hash,
                    "physical_send_state": str(physical_send_state),
                    "applicability": applicability,
                    "evidence_fingerprint": evidence_fingerprint,
                    "parent_binding": dict(child.parent_binding),
                },
                proofs=(stored.proof,),
            )
            self._child_dispatch_tokens.pop((task_id, delegation_id), None)
            self._child_running.discard((task_id, delegation_id))
            return self._child_projection(self.get_task(task_id), delegation_id)

    def settle_child_delegation(
        self,
        task_id: str,
        delegation_id: str,
        *,
        status: str = "SETTLED",
        unknown_effect: bool = False,
        handoff_receipt_ref: str | None = None,
        recovery_verified_no_send: bool = False,
    ) -> ChildDelegationProjection:
        if status not in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
            raise ValueError("invalid child settlement status")
        if status == "HANDED_OFF":
            raise TaskConflict("T5A does not support handoff settlement without an atomic receiver authority")
        with self._state_lock:
            task = self.get_task(task_id)
            child = self._child_projection(task, delegation_id)
            if child.status in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}:
                return child
            if status == "SETTLED" and not child.result_ref:
                raise TaskConflict("child cannot settle as completed before a durable result")
            if status == "CANCELLED_VERIFIED" and (
                child.status in {"RUNNING", "RESULT_PERSISTED"}
                or (task_id, delegation_id) in self._child_running
            ):
                if not recovery_verified_no_send or child.result_ref or child.physical_send_state != "NOT_APPLICABLE":
                    raise TaskConflict("running child requires a result or verified handoff before cancellation settlement")
            if child.result_ref:
                applicability = self._child_applicability(task.child_delegations[delegation_id], task)
                if applicability != child.applicability:
                    self.refresh_child_applicability(task_id, delegation_id)
                    task = self.get_task(task_id)
                    child = self._child_projection(task, delegation_id)
            else:
                applicability = child.applicability
            effective_unknown = bool(unknown_effect or child.unknown_effect or child.physical_send_state == "UNKNOWN")
            handoff_receipt: Mapping[str, Any] | None = None
            if status == "HANDED_OFF":
                try:
                    handoff_receipt = self.context_memory.read(str(handoff_receipt_ref))
                except BaseException as error:
                    raise TaskConflict("child handoff receipt is not a readable CAS object") from error
                if (
                    handoff_receipt.get("schema") != "SITINA_LOOP_CHILD_HANDOFF_RECEIPT_V1"
                    or handoff_receipt.get("task_id") != task_id
                    or handoff_receipt.get("delegation_id") != delegation_id
                    or handoff_receipt.get("status") != "ACCEPTED"
                    or not str(handoff_receipt.get("receiver_id") or "").strip()
                ):
                    raise TaskConflict("child handoff receipt is not a trusted accepted transfer")
            document = {
                "schema": "SITINA_LOOP_CHILD_SETTLEMENT_V1",
                "delegation_contract_version": DELEGATION_CONTRACT_VERSION,
                "task_id": task_id,
                "delegation_id": delegation_id,
                "status": status,
                "unknown_effect": effective_unknown,
                "handoff_receipt_ref": handoff_receipt_ref,
                "handoff_receipt_hash": (
                    hashlib.sha256(canonical_json_bytes(handoff_receipt)).hexdigest()
                    if handoff_receipt is not None else None
                ),
                "original_parent_binding": dict(child.parent_binding),
                "applicability": applicability,
            }
            stored = self.context_memory.persist(document, purpose="loop-child-runtime-settlement")
            self._append(
                task_id=task_id,
                expected_stream_version=task.task_revision,
                request_id=f"child-settle:{task_id}:{delegation_id}:{status}",
                command_type="loop.child-delegation.settle",
                event_type="loop.child-delegation-settled",
                payload={
                    "schema": "SITINA_LOOP_CHILD_DELEGATION_SETTLED_V1",
                    "task_id": task_id,
                    "delegation_id": delegation_id,
                    "settlement_ref": stored.reference_id,
                    "settlement_hash": stored.content_hash,
                    "status": status,
                },
                proofs=(stored.proof,),
            )
            return self._child_projection(self.get_task(task_id), delegation_id)

    def child_terminal_obligations(self, task_id: str) -> tuple[Mapping[str, Any], ...]:
        task = self.get_task(task_id)
        return tuple(dict(item) for item in task.child_delegations.values())

    def can_propose_terminal(self, task_id: str) -> bool:
        for item in self.child_terminal_obligations(task_id):
            if item.get("unknown_effect"):
                return False
            if item.get("status") not in {"SETTLED", "CANCELLED_VERIFIED"}:
                return False
        return True

    def _terminal_source_closure(
        self,
        task: TaskProjection,
        terminal_event: EventEnvelope,
    ) -> dict[str, Any]:
        """Return the authenticated, immutable source identity for B6 work."""
        value = terminal_event.payload
        if not isinstance(value, Mapping) or value.get("schema") != "SITINA_LOOP_TASK_TERMINATED_V1":
            raise PersistenceFenced("terminal obligation source has an invalid schema")
        terminal_result = task.terminal_result or {}
        if (
            terminal_result.get("schema") != "SITINA_LOOP_TERMINAL_RESULT_V1"
            or terminal_result.get("task_id") != task.task_id
            or terminal_result.get("processor_version") != value.get("processor_version")
            or tuple(sorted(str(item) for item in terminal_result.get("obligation_types", ())))
            != tuple(sorted(str(item) for item in value.get("obligation_types", ())))
            or terminal_result.get("artifact_ref") != value.get("artifact_ref")
        ):
            raise PersistenceFenced("terminal obligation CAS does not match its Envelope binding")
        result_ref = str(value.get("result_ref") or "")
        result_hash = str(value.get("result_hash") or "")
        if not result_ref or not result_hash:
            raise PersistenceFenced("terminal obligation source is missing result closure")
        try:
            goal_document = self.context_memory.read(str(task.goal_ref))
        except BaseException as error:
            raise PersistenceFenced("terminal obligation source is missing goal closure") from error
        if (
            goal_document.get("schema") != "SITINA_LOOP_GOAL_V1"
            or goal_document.get("task_id") != task.task_id
            or goal_document.get("goal") is None
        ):
            raise PersistenceFenced("terminal obligation goal closure is malformed")
        goal_hash = hashlib.sha256(canonical_json_bytes(goal_document)).hexdigest()
        # The reducer already verified result/stop-report CAS bindings while
        # replaying the task.  Keep the exact refs and hashes here; do not
        # construct a new run id or infer source identity from the payload.
        operation_ids = tuple(sorted(str(item) for item in task.operations))
        acceptance_ids = tuple(sorted(str(item) for item in task.acceptances))
        operation_closure = tuple(
            {
                "operation_id": operation.operation_id,
                "intent_ref": operation.intent_ref,
                "result_ref": operation.result_ref,
                "effect_status": operation.effect_status.value,
                "unknown_effect": operation.unknown_effect,
                "business_attempt_id": operation.business_attempt_id,
            }
            for operation in sorted(task.operations.values(), key=lambda item: item.operation_id)
        )
        acceptance_closure = tuple(
            {
                "acceptance_id": acceptance.acceptance_id,
                "outcome_id": acceptance.outcome_id,
                "evidence_refs": tuple(sorted(acceptance.evidence_refs)),
                "program_status": acceptance.program_status,
                "reviewer_status": acceptance.reviewer_status,
                "artifact_ref": acceptance.artifact_ref,
            }
            for acceptance in sorted(task.acceptances.values(), key=lambda item: item.acceptance_id)
        )
        closure = {
            "schema": "SITINA_LOOP_TERMINAL_SOURCE_CLOSURE_V1",
            "task_id": task.task_id,
            "session_id": task.session_id,
            "actual_envelope_event_id": terminal_event.event_id,
            "terminal_event_id": str(value.get("terminal_event_id") or ""),
            "terminal_event_position": int(terminal_event.position),
            "terminal_stream_version": int(terminal_event.stream_version),
            "terminal_occurred_at": terminal_event.occurred_at,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": int(task.execution_epoch),
            "goal_version": int(task.goal_version),
            "acceptance_version": int(task.acceptance_version),
            "goal_ref": task.goal_ref,
            "goal_hash": goal_hash,
            "artifact_ref": task.artifact_ref,
            "result_ref": result_ref,
            "result_hash": result_hash,
            "terminal_status": str(value.get("terminal_status") or ""),
            "processor_version": str(value.get("processor_version") or ""),
            "obligation_types": tuple(sorted(str(item) for item in value.get("obligation_types", ()))),
            "operation_ids": operation_ids,
            "acceptance_ids": acceptance_ids,
            "operation_closure": operation_closure,
            "acceptance_closure": acceptance_closure,
            "task_stream_frontier": int(task.stream_frontier),
            "task_revision": int(task.task_revision),
            "stop_report_ref": value.get("stop_report_ref"),
            "stop_report_hash": value.get("stop_report_hash"),
        }
        if not closure["terminal_event_id"] or not closure["processor_version"]:
            raise PersistenceFenced("terminal obligation source is missing stable identity")
        closure["closure_hash"] = hashlib.sha256(canonical_json_bytes(closure)).hexdigest()
        return closure

    def _experience_obligation_events(self) -> tuple[EventEnvelope, ...]:
        return tuple(
            event
            for event in self.store.journal.iter_events(0)
            if event.stream_id == EXPERIENCE_OBLIGATION_STREAM
        )

    def _experience_obligation_projection(self) -> dict[str, Mapping[str, Any]]:
        projection: dict[str, Mapping[str, Any]] = {}
        for event in self._experience_obligation_events():
            payload = event.payload
            if not isinstance(payload, Mapping) or payload.get("schema") != EXPERIENCE_OBLIGATION_SCHEMA:
                raise PersistenceFenced("experience obligation stream contains an invalid schema")
            obligation_id = str(payload.get("obligation_id") or "")
            if not obligation_id:
                raise PersistenceFenced("experience obligation is missing identity")
            if event.event_type == "loop.experience-obligation-created":
                if obligation_id in projection:
                    raise PersistenceFenced("experience obligation was created twice")
                projection[obligation_id] = dict(payload)
                continue
            if event.event_type == "loop.experience-obligation-updated":
                current = projection.get(obligation_id)
                if current is None:
                    raise PersistenceFenced("experience obligation update has no creation")
                updated = dict(current)
                updated.update(dict(payload.get("patch") or {}))
                projection[obligation_id] = updated
                continue
            raise PersistenceFenced("experience obligation stream contains an unknown event")
        return projection

    @staticmethod
    def _bounded_provider_value(value: Any, *, max_bytes: int = 24 * 1024) -> Any:
        """Project verified CAS evidence to a small, JSON-safe model input."""
        if isinstance(value, Mapping):
            projected: dict[str, Any] = {}
            truncated = False
            for key in sorted(value, key=str):
                item = LoopBackend._bounded_provider_value(value[key], max_bytes=max_bytes)
                projected[str(key)] = item
                if len(canonical_json_bytes(projected)) > max_bytes:
                    projected.pop(str(key), None)
                    truncated = True
                    break
            if truncated:
                projected["_truncated"] = True
            return projected
        if isinstance(value, (list, tuple)):
            result: list[Any] = []
            truncated = False
            for item in value:
                candidate = LoopBackend._bounded_provider_value(item, max_bytes=max_bytes)
                result.append(candidate)
                if len(canonical_json_bytes(result)) > max_bytes:
                    result.pop()
                    truncated = True
                    break
            if truncated:
                result.append({"_truncated": True})
            return result
        if isinstance(value, str):
            encoded = value.encode("utf-8")
            if len(encoded) <= max_bytes:
                return value
            return {
                "value": encoded[: max(1, max_bytes - 96)].decode("utf-8", errors="ignore"),
                "truncated": True,
                "original_bytes": len(encoded),
            }
        if isinstance(value, (int, bool)) or value is None:
            return value
        if isinstance(value, float):
            return repr(value)
        return str(value)[:max_bytes]

    @staticmethod
    def _bounded_projection_has_truncation(value: Any) -> bool:
        if isinstance(value, Mapping):
            return bool(
                value.get("truncated")
                or value.get("_truncated")
                or value.get("_projection_truncated")
                or any(LoopBackend._bounded_projection_has_truncation(item) for item in value.values())
            )
        if isinstance(value, (list, tuple)):
            return any(LoopBackend._bounded_projection_has_truncation(item) for item in value)
        return False

    @classmethod
    def _bounded_experience_check_detail(
        cls,
        value: Any,
        *,
        max_bytes: int = 2048,
    ) -> Any:
        """Keep check conclusions and source refs ahead of verbose diagnostics."""
        if not isinstance(value, Mapping):
            return cls._bounded_provider_value(value, max_bytes=max_bytes)
        preferred = (
            "status", "program_status", "exit_code", "method_id", "satisfied",
            "remaining", "result_ref", "result_hash", "source_ref", "source_hash",
            "source_content_hash", "evidence_refs", "reason", "error", "stderr",
            "stdout", "command", "path",
        )
        projected: dict[str, Any] = {}
        for key in preferred:
            if key not in value:
                continue
            item_budget = 512 if key in {"stderr", "stdout", "command", "path"} else 1024
            item = cls._bounded_provider_value(value[key], max_bytes=item_budget)
            candidate = dict(projected)
            candidate[key] = item
            if len(canonical_json_bytes(candidate)) <= max_bytes:
                projected[key] = item
        if any(str(key) not in projected for key in value) or any(
            cls._bounded_projection_has_truncation(item) for item in projected.values()
        ):
            projected["_projection_truncated"] = True
        return projected

    @classmethod
    def _bounded_experience_check_summary(
        cls,
        value: Any,
        *,
        max_bytes: int = 1024,
    ) -> Mapping[str, Any]:
        """Reserve a fixed conclusion/source budget before verbose details."""
        if not isinstance(value, Mapping):
            bounded = cls._bounded_provider_value(value, max_bytes=max_bytes)
            if isinstance(bounded, Mapping):
                return dict(bounded)
            return {"value": bounded}
        preferred = (
            "status", "program_status", "exit_code", "error_code", "reason", "error",
            "source_ref", "source_hash", "source_content_hash", "result_ref",
            "result_hash", "evidence_refs",
        )
        projected: dict[str, Any] = {}
        omitted = False
        for key in preferred:
            if key not in value:
                continue
            item_budget = 384 if key in {"reason", "error"} else 512
            item = cls._bounded_provider_value(value[key], max_bytes=item_budget)
            candidate = dict(projected)
            candidate[key] = item
            if len(canonical_json_bytes(candidate)) <= max_bytes:
                projected[key] = item
            else:
                omitted = True
        if (
            omitted
            or any(str(key) not in projected for key in value)
            or any(cls._bounded_projection_has_truncation(item) for item in projected.values())
        ):
            projected["_projection_truncated"] = True
        if len(canonical_json_bytes(projected)) > max_bytes:
            # Required conclusion fields are individually bounded; if they
            # still cannot fit, the source is not safe to expose to Provider.
            raise PersistenceFenced("experience check summary exceeds bounded evidence budget")
        return projected

    @classmethod
    def _bounded_experience_final_result(
        cls,
        value: Any,
        *,
        max_bytes: int = 6144,
    ) -> Any:
        """Project terminal output with useful business values before diagnostics."""
        if not isinstance(value, Mapping):
            return cls._bounded_provider_value(value, max_bytes=max_bytes)
        outcome = ("status", "program_status", "exit_code", "review_status")
        checks = ("preflight_check", "program_check")
        source_identity = (
            "source_hash", "source_sha256", "source_content_hash", "source_ref",
            "source_refs", "evidence_refs", "artifact_ref", "result_ref", "result_hash",
        )
        error_fields = ("error_code", "reason", "error")
        secondary = ("shared_contract_evaluation", "changed_paths", "cycle")
        narrative = ("response", "result", "answer", "summary")
        projected: dict[str, Any] = {}
        omitted: list[str] = []

        def add(key: str, item: Any) -> None:
            candidate = dict(projected)
            candidate[key] = item
            if len(canonical_json_bytes(candidate)) <= max_bytes:
                projected[key] = item
            else:
                omitted.append(key)

        # Reserve outcome and both check summaries before long errors or model
        # narrative.  A check summary is never silently dropped as a block.
        for key in outcome:
            if key not in value:
                continue
            add(key, cls._bounded_provider_value(value[key], max_bytes=512))
        for key in checks:
            if key not in value:
                continue
            item = cls._bounded_experience_check_summary(value[key], max_bytes=1024)
            candidate = dict(projected)
            candidate[key] = item
            if len(canonical_json_bytes(candidate)) > max_bytes:
                raise PersistenceFenced("experience check summary cannot fit bounded terminal evidence")
            projected[key] = item
        for key in source_identity:
            if key not in value:
                continue
            item = cls._bounded_provider_value(value[key], max_bytes=768)
            candidate = dict(projected)
            candidate[key] = item
            if len(canonical_json_bytes(candidate)) > max_bytes:
                raise PersistenceFenced("experience source identity cannot fit bounded terminal evidence")
            projected[key] = item
        for key in error_fields:
            if key not in value:
                continue
            add(key, cls._bounded_provider_value(value[key], max_bytes=512))
        for key in secondary:
            if key not in value:
                continue
            add(key, cls._bounded_provider_value(value[key], max_bytes=768))
        for key in narrative:
            if key not in value:
                continue
            add(key, cls._bounded_provider_value(value[key], max_bytes=2048))
        # Preserve small scalar facts not covered above, but never let verbose
        # command/path/log fields displace the outcome or source identity.
        for key in sorted(value, key=str):
            key = str(key)
            if key in projected or key in outcome or key in checks or key in source_identity or key in error_fields or key in secondary or key in narrative or key in {
                "command", "commands", "path", "paths", "stderr", "stdout",
                "traceback", "raw", "raw_result",
            }:
                continue
            item_value = value[key]
            if not isinstance(item_value, (str, int, bool, float)) and item_value is not None:
                continue
            add(key, cls._bounded_provider_value(item_value, max_bytes=512))
        omitted.extend(str(key) for key in value if str(key) not in projected and str(key) not in omitted)
        if omitted or any(cls._bounded_projection_has_truncation(item) for item in projected.values()):
            # Make truncation explicit. If the marker itself needs room, drop
            # the least important narrative fields first.
            projected["_projection_truncated"] = True
            while len(canonical_json_bytes(projected)) > max_bytes:
                removed = next((key for key in reversed(narrative) if key in projected), None)
                if removed is None:
                    break
                projected.pop(removed, None)
        if not projected and value:
            fallback = cls._bounded_provider_value(value, max_bytes=max_bytes)
            if isinstance(fallback, Mapping):
                return dict(fallback)
        return projected

    @classmethod
    def _bounded_terminal_result(
        cls,
        result: Mapping[str, Any],
        *,
        max_bytes: int = 8192,
    ) -> Mapping[str, Any]:
        """Keep the required terminal identity and a bounded useful result."""
        if "final_result" not in result:
            raise PersistenceFenced("experience source result has no terminal final result")
        fields = (
            "schema", "task_id", "terminal_status", "processor_version", "artifact_ref",
            "result_ref", "result_hash",
        )
        projected: dict[str, Any] = {}
        for key in fields:
            if key in result:
                projected[key] = cls._bounded_provider_value(result[key], max_bytes=1024)
        final_result = cls._bounded_experience_final_result(
            result.get("final_result"),
            max_bytes=min(6144, max_bytes),
        )
        projected["final_result"] = final_result
        if len(canonical_json_bytes(projected)) <= max_bytes:
            return projected
        # Retain the mandatory final_result by shrinking only its optional
        # projection; never increase the source-evidence budget.
        for budget in (5120, 4096, 3072, 2048, 1024):
            candidate = dict(projected)
            candidate["final_result"] = cls._bounded_experience_final_result(
                result.get("final_result"), max_bytes=budget
            )
            if len(canonical_json_bytes(candidate)) <= max_bytes:
                return candidate
        raise PersistenceFenced("experience source terminal result exceeds bounded evidence budget")

    def _verified_experience_input_evidence(
        self,
        obligation: Mapping[str, Any],
        closure: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Project the complete handled input frontier for one terminal task.

        The terminal source closure predates this projection and intentionally
        remains immutable.  Replaying the task stream through the persisted
        terminal Envelope gives us the exact historical frontier without
        rewriting that closure or admitting later inputs.
        """
        task_id = str(closure.get("task_id") or obligation.get("task_id") or "")
        actual_terminal_event_id = str(closure.get("actual_envelope_event_id") or "")
        terminal_event_id = str(closure.get("terminal_event_id") or "")
        if not task_id or not actual_terminal_event_id or not terminal_event_id:
            raise PersistenceFenced("experience input evidence has no terminal identity")
        events = self.store.task_events(task_id)
        terminal_index = next(
            (
                index for index, event in enumerate(events)
                if event.event_id == actual_terminal_event_id
            ),
            None,
        )
        if terminal_index is None:
            raise PersistenceFenced("experience input evidence terminal Envelope is not in the task stream")
        terminal_event = events[terminal_index]
        if (
            terminal_event.position != int(closure.get("terminal_event_position", -1))
            or terminal_event.stream_version != int(closure.get("terminal_stream_version", -1))
        ):
            raise PersistenceFenced("experience input evidence terminal identity differs from closure")
        historical = self._project(task_id, events[: terminal_index + 1])
        if (
            historical.terminal_event_id != terminal_event_id
            or historical.status not in TERMINAL_STATUSES
            or historical.task_id != task_id
            or historical.session_id != str(closure.get("session_id") or historical.session_id)
            or historical.run_instance_id != str(closure.get("run_instance_id") or "")
            or historical.execution_epoch != int(closure.get("execution_epoch", -1))
            or historical.goal_version != int(closure.get("goal_version", -1))
            or historical.acceptance_version != int(closure.get("acceptance_version", -1))
            or historical.received_input_seq != historical.handled_input_seq
        ):
            raise PersistenceFenced("experience input evidence terminal binding is stale")
        if historical.handled_input_seq < 0 or historical.handled_input_seq > EXPERIENCE_INPUT_MAX_RECORDS:
            raise PersistenceFenced("experience input evidence exceeds its bounded input frontier")
        records = tuple(sorted(historical.inputs, key=lambda item: item.sequence))
        if tuple(item.sequence for item in records) != tuple(range(1, historical.handled_input_seq + 1)):
            raise PersistenceFenced("experience input evidence sequence is incomplete or out of order")

        projected: list[dict[str, Any]] = []
        semantic_sequences: list[int] = []
        total_bytes = 0
        for record in records:
            body = self.context_memory.read(record.body_ref, expected_hash=record.body_hash)
            if (
                body.get("schema") != "SITINA_LOOP_INPUT_BODY_V1"
                or body.get("task_id") != task_id
                or body.get("input_id") != record.input_id
                or body.get("kind") != record.kind.value
                or not isinstance(body.get("body"), str)
            ):
                raise PersistenceFenced("experience input evidence body is not bound to its input record")
            text = str(body["body"])
            text_bytes = len(text.encode("utf-8"))
            if text_bytes > EXPERIENCE_INPUT_MAX_BODY_BYTES:
                raise PersistenceFenced("experience input evidence body exceeds its bounded budget")
            semantic = record.kind in {InputKind.MESSAGE, InputKind.CORRECTION}
            if semantic:
                semantic_sequences.append(record.sequence)
            item = {
                "sequence": record.sequence,
                "input_id": record.input_id,
                "kind": record.kind.value,
                "body_ref": record.body_ref,
                "body_hash": record.body_hash,
                "received_at": record.received_at,
                "semantic_role": "task_instruction" if semantic else "control_only",
                "body": text,
            }
            candidate = [*projected, item]
            encoded_bytes = len(canonical_json_bytes(candidate))
            if encoded_bytes > EXPERIENCE_INPUT_MAX_TOTAL_BYTES:
                raise PersistenceFenced("experience input evidence exceeds its total bounded budget")
            projected.append(item)
            total_bytes = encoded_bytes
        return {
            "schema": EXPERIENCE_INPUT_EVIDENCE_SCHEMA,
            "task_id": task_id,
            "session_id": historical.session_id,
            "actual_envelope_event_id": actual_terminal_event_id,
            "terminal_event_id": terminal_event_id,
            "terminal_event_position": terminal_event.position,
            "terminal_stream_version": terminal_event.stream_version,
            "run_instance_id": historical.run_instance_id,
            "execution_epoch": historical.execution_epoch,
            "goal_version": historical.goal_version,
            "acceptance_version": historical.acceptance_version,
            "handled_input_seq": historical.handled_input_seq,
            "received_input_seq": historical.received_input_seq,
            "semantic_input_sequences": semantic_sequences,
            "records": projected,
            "total_bytes": total_bytes,
        }

    def _verified_experience_source_evidence(
        self,
        obligation: Mapping[str, Any],
        *,
        candidate_id: str | None = None,
        memory_repository: Any | None = None,
        memory_actor: str | None = None,
    ) -> Mapping[str, Any]:
        """Read the exact closure/manifest CAS roots before Provider dispatch."""
        closure = dict(obligation.get("source_closure") or {})
        evidence: dict[str, Any] = {
            "schema": "SITINA_EXPERIENCE_SOURCE_EVIDENCE_V1",
            "closure_hash": str(closure.get("closure_hash") or ""),
            "goal_ref": str(closure.get("goal_ref") or ""),
            "result_ref": str(closure.get("result_ref") or ""),
            "result_hash": str(closure.get("result_hash") or ""),
            "acceptance_closure": self._bounded_provider_value(closure.get("acceptance_closure") or (), max_bytes=4096),
            "operation_closure": self._bounded_provider_value(closure.get("operation_closure") or (), max_bytes=4096),
        }
        goal_ref = str(closure.get("goal_ref") or "")
        result_ref = str(closure.get("result_ref") or "")
        if not goal_ref or not result_ref:
            raise PersistenceFenced("experience source closure has no readable goal/result roots")
        goal = self.store.read_json(goal_ref, expected_hash=str(closure.get("goal_hash") or ""))
        result = self.store.read_json(result_ref, expected_hash=str(closure.get("result_hash") or ""))
        evidence["goal"] = self._bounded_provider_value({
            key: goal.get(key) for key in ("schema", "task_id", "goal", "goal_version") if key in goal
        }, max_bytes=8192)
        evidence["terminal_result"] = self._bounded_terminal_result(result, max_bytes=8192)
        evidence["input_evidence"] = self._verified_experience_input_evidence(obligation, closure)
        if candidate_id is None:
            # The extraction must know the identities of rules actually shown
            # to this task before it can name the rule a correction replaces.
            # Keep the original view, including subsequently excluded entries:
            # these are low-trust supersession evidence, not active instructions.
            task_id = str(closure.get("task_id") or "")
            task = self.get_task(task_id)
            prior_entries: list[Mapping[str, Any]] = []
            if task.memory_view_ref:
                view = self.context_memory.read(task.memory_view_ref, expected_hash=task.memory_view_hash)
                entries = view.get("entries")
                if (view.get("schema") != "SITINA_LOOP_MEMORY_VIEW_V1"
                        or view.get("task_id") != task_id or not isinstance(entries, list)
                        or len(entries) > 64 or any(not isinstance(item, Mapping) for item in entries)):
                    raise PersistenceFenced("experience prior memory view is not bound to this task")
                ids = [item.get("memory_id") for item in entries]
                if (any(not isinstance(item, str) or not item for item in ids)
                        or len(ids) != len(set(ids)) or set(ids) != set(task.memory_view_ids)
                        or any(not isinstance(item.get("text"), str) for item in entries)):
                    raise PersistenceFenced("experience prior memory entries have incomplete identities")
                prior_entries = [{"memory_id": item["memory_id"], "text": item["text"]}
                                 for item in entries]
            prior_memory = {
                "task_id": task_id, "memory_view_ref": task.memory_view_ref,
                "memory_view_hash": task.memory_view_hash, "entries": prior_entries,
            }
            # Preserve the complete snapshot entries. The existing Provider
            # request-size admission applies to the complete request below.
            evidence["prior_task_memory"] = prior_memory
        goal_value = evidence.get("goal")
        if not isinstance(goal_value, Mapping) or not goal_value.get("goal"):
            raise PersistenceFenced("experience source evidence has no bounded goal正文")
        terminal_value = evidence.get("terminal_result")
        if not isinstance(terminal_value, Mapping) or "final_result" not in terminal_value:
            raise PersistenceFenced("experience source evidence has no bounded terminal result")
        manifest_ref = str(obligation.get("manifest_ref") or "")
        manifest_hash = str(obligation.get("manifest_hash") or "")
        if manifest_ref and manifest_hash:
            manifest = self.store.read_json(manifest_ref, expected_hash=manifest_hash)
            candidates = manifest.get("candidates") if isinstance(manifest, Mapping) else ()
            if candidate_id is not None:
                candidates = tuple(
                    item for item in (candidates or ())
                    if isinstance(item, Mapping) and str(item.get("candidate_id") or "") == candidate_id
                )
            evidence["manifest"] = self._bounded_provider_value({
                key: manifest.get(key) for key in ("schema", "batch_id", "source_closure_hash", "status") if key in manifest
            }, max_bytes=4096)
            evidence["candidates"] = self._bounded_provider_value(candidates or (), max_bytes=12000)
        binding = obligation.get("review_memory_binding")
        repository = memory_repository or self._memory_repository
        actor = str(memory_actor or self._memory_actor or "")
        if candidate_id is not None and isinstance(binding, Mapping) and repository is not None and actor:
            memory_evidence: list[Mapping[str, Any]] = []
            memories = binding.get("memories")
            if isinstance(memories, Mapping):
                for memory_id in sorted(str(item) for item in memories):
                    document, content = repository.get(memory_id, actor=actor, include_content=True)
                    memory_evidence.append({
                        "memory_id": memory_id,
                        "status": document.status,
                        "quarantine_status": document.quarantine_status,
                        "content_hash": document.content_hash,
                        "supersedes": list(document.supersedes),
                        "conflict_key": document.conflict_key,
                        "content": content,
                    })
            evidence["native_memory_evidence"] = self._bounded_provider_value(memory_evidence, max_bytes=12000)
            if not memory_evidence:
                raise PersistenceFenced("review source binding has no readable native memory evidence")
        return evidence

    def reconcile_experience_obligations(self) -> tuple[Mapping[str, Any], ...]:
        """Materialize obligations from committed terminal events only."""
        with self._state_lock:
            self._require_persistence()
            current = self._experience_obligation_projection()
            for task_id in self.store.task_ids():
                task = self._project(task_id, self.store.task_events(task_id))
                terminal_events = tuple(
                    event for event in self.store.task_events(task_id)
                    if event.event_type == "loop.task-terminated"
                )
                if not terminal_events or task.status not in TERMINAL_STATUSES:
                    continue
                terminal_event = terminal_events[-1]
                closure = self._terminal_source_closure(task, terminal_event)
                for obligation_type in closure["obligation_types"]:
                    if obligation_type not in {"EPISODE", "EXPERIENCE_EXTRACTION"}:
                        continue
                    obligation_id = ":".join((
                        closure["terminal_event_id"],
                        obligation_type,
                        closure["processor_version"],
                    ))
                    if obligation_id in current:
                        continue
                    payload = {
                        "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                        "obligation_id": obligation_id,
                        "obligation_type": obligation_type,
                        "processor_version": closure["processor_version"],
                        "task_id": task_id,
                        "actual_envelope_event_id": closure["actual_envelope_event_id"],
                        "terminal_event_id": closure["terminal_event_id"],
                        "source_closure": closure,
                        "state": "PENDING",
                        "attempt_count": 0,
                        "max_attempts": 3,
                        "next_due_at": iso_now(),
                        "last_error": None,
                    }
                    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
                    command = CommandEnvelope(
                        "loop-obligation-command-" + digest[:40],
                        self.store.TENANT,
                        EXPERIENCE_OBLIGATION_STREAM,
                        "loop.experience-obligation.create",
                        "loop-state-coordinator",
                        iso_now(),
                        {"obligation_id": obligation_id, "payload_hash": digest},
                    )
                    event = EventEnvelope(
                        "loop-obligation-event-" + hashlib.sha256(obligation_id.encode("utf-8")).hexdigest()[:42],
                        "loop.experience-obligation-created",
                        self.store.TENANT,
                        EXPERIENCE_OBLIGATION_STREAM,
                        0,
                        0,
                        iso_now(),
                        payload,
                        (),
                    )
                    try:
                        self.store.journal.append(
                            command,
                            self.store.journal._stream_heads.get(EXPERIENCE_OBLIGATION_STREAM, 0),
                            [event],
                        )
                    except ExpectedStreamVersionConflict:
                        # A concurrent Host scan may have materialized this
                        # exact identity; the next projection read is enough.
                        pass
                    except BaseException as error:
                        self._fail_persistence(error)
                        raise
                    current = self._experience_obligation_projection()
            return tuple(current.values())

    def _reconcile_native_candidate_decisions_locked(self) -> None:
        """Recover loop dispositions from already committed native decisions.

        The native decision stream is the source of truth for a reviewed
        candidate.  A process can lose the subsequent loop disposition patch
        (or record UNKNOWN after a lost return); on restart we must recover the
        exact prior decision before selecting another review.  Current native
        status is checked as well, so a later revoke/supersede can never be
        resurrected by this repair.
        """
        repository = self._memory_repository
        if repository is None or not hasattr(repository, "decision_projection"):
            return
        projection = self._experience_obligation_projection()
        native = repository.decision_projection()
        decisions = tuple((native.get("by_decision") or {}).values())
        if not decisions:
            return
        for obligation in tuple(projection.values()):
            if obligation.get("state") not in {"MANIFEST_RECORDED", "CANDIDATE_REVIEW"}:
                continue
            candidate_memory_ids = dict(obligation.get("candidate_memory_ids") or {})
            revisions = dict(obligation.get("candidate_revisions") or {})
            dispositions = dict(obligation.get("candidate_dispositions") or {})
            closure_hash = str((obligation.get("source_closure") or {}).get("closure_hash") or "")
            for candidate_id in tuple(str(item) for item in obligation.get("candidate_ids", ())):
                memory_id = str(candidate_memory_ids.get(candidate_id) or "")
                revision = str(revisions.get(candidate_id) or "")
                if not memory_id or not revision:
                    continue
                prior = dispositions.get(candidate_id) or {}
                if str(prior.get("disposition") or "") in {"PUBLISHED", "REJECTED", "FAILED_FINAL"}:
                    continue
                historical_review_ids: set[str] = set()
                historical_review_bindings: dict[str, Mapping[str, Any]] = {}
                for review_event in self._experience_obligation_events():
                    review_payload = review_event.payload
                    if (
                        not isinstance(review_payload, Mapping)
                        or review_event.event_type != "loop.experience-obligation-updated"
                        or str(review_payload.get("obligation_id") or "") != str(obligation.get("obligation_id") or "")
                    ):
                        continue
                    review_patch = review_payload.get("patch")
                    if (
                        isinstance(review_patch, Mapping)
                        and str(review_patch.get("review_candidate_id") or "") == candidate_id
                        and str(review_patch.get("review_candidate_revision") or "") == revision
                        and str(review_patch.get("review_request_id") or "")
                    ):
                        review_request = str(review_patch["review_request_id"])
                        historical_review_ids.add(review_request)
                        if isinstance(review_patch.get("review_memory_binding"), Mapping):
                            historical_review_bindings[review_request] = dict(review_patch["review_memory_binding"])
                matched: tuple[Mapping[str, Any], Mapping[str, Any]] | None = None
                for decision in reversed(decisions):
                    if not isinstance(decision, Mapping):
                        continue
                    if str(decision.get("decision_kind") or "") != "experience-review":
                        continue
                    if str(decision.get("review_request_id") or "") not in historical_review_ids:
                        continue
                    decision_request = str(decision.get("review_request_id") or "")
                    historical_binding = historical_review_bindings.get(decision_request)
                    decision_binding = decision.get("review_binding")
                    if not isinstance(historical_binding, Mapping) or not isinstance(decision_binding, Mapping):
                        continue
                    historical_memory = (historical_binding.get("memories") or {}).get(memory_id)
                    decision_memory = (decision_binding.get("memories") or {}).get(memory_id)
                    if not isinstance(historical_memory, Mapping) or decision_memory != historical_memory:
                        continue
                    source = decision.get("source_closure")
                    if not isinstance(source, Mapping) or str(source.get("closure_hash") or "") != closure_hash:
                        continue
                    candidate_revisions = decision.get("candidate_revisions")
                    if not isinstance(candidate_revisions, Mapping) or str(candidate_revisions.get(memory_id) or "") != revision:
                        continue
                    actions = decision.get("candidate_actions")
                    if not isinstance(actions, list):
                        continue
                    action = next(
                        (item for item in actions
                         if isinstance(item, Mapping) and str(item.get("memory_id") or "") == memory_id),
                        None,
                    )
                    if isinstance(action, Mapping):
                        matched = (decision, action)
                        break
                if matched is None:
                    continue
                decision, action = matched
                to_status = str(action.get("to_status") or "")
                expected = "accepted" if to_status == "accepted" else "rejected" if to_status == "rejected" else ""
                if not expected:
                    continue
                # The loop fact records that this review decision completed
                # at that historical revision.  Do not require the memory to
                # remain accepted: a later revoke/supersede is authoritative
                # for current retrieval and must not resurrect the record,
                # while the original PUBLISHED disposition still settles the
                # already-committed obligation.
                try:
                    repository.get(memory_id, actor=str(self._memory_actor or ""), include_content=False)
                except Exception:
                    continue
                decision_id = str(decision.get("decision_id") or "")
                native_disposition = "PUBLISHED" if expected == "accepted" else "REJECTED"
                self.record_experience_candidate_disposition(
                    str(obligation.get("obligation_id") or ""),
                    candidate_id=candidate_id,
                    candidate_revision=revision,
                    disposition=native_disposition,
                    request_id=f"native-reconcile:{decision_id}:{candidate_id}",
                    source_closure_hash=closure_hash,
                    reason="native-decision-reconciled",
                    attempt_count=int(prior.get("attempt_count") or 0),
                )

    @staticmethod
    def _candidate_review_is_runnable(obligation: Mapping[str, Any], *, now: str | None = None) -> bool:
        """Return whether at least one candidate can be dispatched now."""
        now_value = now or iso_now()
        dispositions = obligation.get("candidate_dispositions") or {}
        for candidate_id in obligation.get("candidate_ids", ()):
            prior = dispositions.get(str(candidate_id)) or {}
            state = str(prior.get("disposition") or "")
            if state in {"PUBLISHED", "REJECTED", "FAILED_FINAL", "UNKNOWN"}:
                continue
            attempts = int(prior.get("attempt_count") or 0)
            maximum = int(prior.get("max_attempts") or 3)
            if attempts >= maximum:
                return True
            due = str(prior.get("next_due_at") or "")
            if due and due > now_value:
                continue
            # The due-time guard above has already excluded future work;
            # remaining bounded attempts are dispatchable.
            return attempts >= 0
        return False

    @staticmethod
    def _experience_obligation_is_due(obligation: Mapping[str, Any], *, now: str | None = None) -> bool:
        """Apply the durable retry deadline before exposing or claiming work."""
        raw = obligation.get("next_due_at")
        if raw in (None, ""):
            return True
        try:
            due = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if due.tzinfo is None:
                return False
            current = dt.datetime.fromisoformat(
                str(now or iso_now()).replace("Z", "+00:00")
            )
            return current >= due
        except (TypeError, ValueError, OverflowError):
            # A malformed persisted deadline must never turn into an eager
            # Provider dispatch after restart.
            return False

    def pending_experience_obligations(self, *, materialize: bool = True) -> tuple[Mapping[str, Any], ...]:
        """Read pending work; only background coordination may materialize."""
        projection = (
            self.reconcile_experience_obligations()
            if materialize
            else tuple(self._experience_obligation_projection().values())
        )
        if not materialize:
            return tuple(
                dict(item)
                for item in projection
                if (
                    item.get("state") in {"MANIFEST_RECORDED", "CANDIDATE_REVIEW"}
                    or (
                        item.get("state") == "PENDING"
                        and self._experience_obligation_is_due(item)
                    )
                )
            )
        # A process can die after the durable DISPATCHED fact and before the
        # provider result.  Reclassify that responsibility as UNKNOWN before
        # exposing work to the single Host slot; never silently resend it.
        for item in tuple(projection):
            if item.get("state") != "DISPATCHED":
                continue
            obligation_id = str(item.get("obligation_id") or "")
            with self._state_lock:
                self._append_experience_obligation_event(
                    event_type="loop.experience-obligation-updated",
                    payload={
                        "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                        "obligation_id": obligation_id,
                        "patch": {
                            "state": "UNKNOWN",
                            "unknown_effect": True,
                            "last_error": "provider-return-not-verified-after-restart",
                            "next_due_at": None,
                        },
                    },
                    request_id=str(item.get("dispatch_request_id") or obligation_id) + ":restart-unknown",
                )
        projection = self._experience_obligation_projection()
        with self._state_lock:
            self._reconcile_native_candidate_decisions_locked()
            projection = self._experience_obligation_projection()
        return tuple(
            dict(item)
            for item in projection.values()
            if (
                (
                    item.get("state") == "PENDING"
                    and self._experience_obligation_is_due(item)
                )
                or (
                    item.get("state") in {"MANIFEST_RECORDED", "CANDIDATE_REVIEW"}
                    and self._candidate_review_is_runnable(item)
                )
            )
            and str(item.get("obligation_type") or "") in {"EPISODE", "EXPERIENCE_EXTRACTION"}
        )

    def _append_experience_obligation_event(
        self,
        *,
        event_type: str,
        payload: Mapping[str, Any],
        request_id: str,
        proofs: Sequence[Any] = (),
    ) -> EventEnvelope:
        self._require_persistence()
        digest = hashlib.sha256(canonical_json_bytes({
            "event_type": event_type,
            "request_id": request_id,
            "payload": dict(payload),
        })).hexdigest()
        timestamp = iso_now()
        command = CommandEnvelope(
            "loop-obligation-command-" + digest[:40],
            self.store.TENANT,
            EXPERIENCE_OBLIGATION_STREAM,
            "loop.experience-obligation.update",
            "loop-state-coordinator",
            timestamp,
            {"request_id": request_id, "request_hash": digest},
        )
        event = EventEnvelope(
            "loop-obligation-event-" + digest[:42],
            event_type,
            self.store.TENANT,
            EXPERIENCE_OBLIGATION_STREAM,
            0,
            0,
            timestamp,
            dict(payload),
            tuple(sorted(proof.object_ref.reference_id for proof in proofs)),
        )
        try:
            receipt = self.store.journal.append(
                command,
                self.store.journal._stream_heads.get(EXPERIENCE_OBLIGATION_STREAM, 0),
                [event],
                object_reference_proofs=tuple(proofs),
            )
        except ExpectedStreamVersionConflict:
            raise
        except BaseException as error:
            self._fail_persistence(error)
            raise
        return next(
            item for item in self.store.journal.iter_events(receipt.first_position - 1)
            if item.position == receipt.first_position
        )

    @staticmethod
    def _experience_provider_dispatch_facts(
        source: Any,
        *,
        default_attempt_count: int = 1,
        default_error_code: str = "unclassified-provider-error",
    ) -> dict[str, Any]:
        """Project only bounded Provider observations into durable Loop state.

        Missing physical-send fields are intentionally retained as unknown;
        they must never be coerced to zero merely because a worker returned an
        exception or an invalid result.
        """
        is_mapping = isinstance(source, Mapping)

        def read(*keys: str, default: Any = None) -> Any:
            for key in keys:
                value = source.get(key) if is_mapping else getattr(source, key, None)
                if value is not None:
                    return value
            return default

        def safe_int(value: Any, *, minimum: int = 0, maximum: int | None = None) -> int | None:
            if type(value) is not int or value < minimum:
                return None
            if maximum is not None and value > maximum:
                return None
            return int(value)

        send_count = safe_int(read("provider_send_count", "sitina_provider_send_count", "sitina_physical_send_count"))
        send_count_status = str(
            read("provider_send_count_status", "sitina_provider_send_count_status", "sitina_physical_send_count_status", default="unknown")
            or "unknown"
        ).strip().casefold()
        if send_count_status not in {"exact", "lower_bound_with_uncertain_attempts", "unknown"}:
            send_count_status = "unknown"
        send_status = str(
            read("provider_send_status", "physical_send_status", "sitina_physical_send_status", default="unknown")
            or "unknown"
        ).strip().casefold()
        if send_status not in {
            "response_received", "not_sent", "unknown", "unknown_after_request_start",
            "unknown_after_worker_start", "pre_send_failure", "pre_send_cancelled",
            "pre_send_deadline", "pre_send_validation_rejected",
        }:
            send_status = "unknown"
        uncertain = safe_int(
            read("uncertain_physical_send_attempt_count", "sitina_uncertain_physical_send_attempt_count")
        )
        if uncertain is None:
            uncertain = 0
        response_value = read("response_received", "sitina_response_received")
        response_received = response_value if type(response_value) is bool else False
        usage_raw = read("provider_usage", "sitina_provider_usage")
        usage = None
        if isinstance(usage_raw, Mapping):
            candidate_usage = {}
            for key in ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens"):
                item = usage_raw.get(key)
                if type(item) is int and item >= 0:
                    candidate_usage[key] = int(item)
            usage = candidate_usage or None
        finish_reason = read("finish_reason", "sitina_finish_reason")
        if isinstance(finish_reason, str):
            finish_reason = finish_reason.strip().casefold()
            if finish_reason not in {"stop", "length", "tool_calls", "end_turn", "max_tokens", "content_filter", "error", "other"}:
                finish_reason = "other"
        else:
            finish_reason = None
        truncation = read("output_truncation", "sitina_output_truncation")
        if isinstance(truncation, str):
            truncation = truncation.strip().casefold()
            if truncation not in {
                "not_truncated", "output_truncated", "tool_call_truncated", "metadata_malformed",
                "finish_reason_missing", "unknown",
            }:
                truncation = "unknown"
        else:
            truncation = "unknown"
        metadata_status = str(
            read("provider_metadata_status", "sitina_provider_metadata_status", default="unknown")
            or "unknown"
        ).strip().casefold()
        if metadata_status not in {"complete", "missing", "malformed", "unknown"}:
            metadata_status = "unknown"
        raw_code = read("error_code", "sitina_error_code")
        safe_codes = {
            "provider-result-invalid", "provider-result-malformed", "provider-result-truncated",
            "provider-tool-call-truncated", "provider-result-metadata-invalid", "provider-output-invalid",
            "provider-capacity-rejected", "provider-timeout", "provider-transport-unknown",
            "provider-http-error", "provider-auth-error", "provider-permission-denied",
            "provider-rate-limited", "provider-dependency-error", "provider-cancelled",
            "provider-slot-busy-before-send", "unclassified-provider-error",
        }
        if isinstance(raw_code, str) and raw_code.strip().casefold() in safe_codes:
            error_code = raw_code.strip().casefold()
        elif raw_code is None and is_mapping:
            error_code = None
        else:
            error_code = default_error_code if default_error_code in safe_codes else "unclassified-provider-error"
        http_status = safe_int(read("provider_http_status", "sitina_http_status", "status_code"), minimum=100, maximum=599)
        attempt_count = safe_int(read("dispatch_attempt_count", "sitina_dispatch_attempt_count"))
        if attempt_count is None:
            attempt_count = max(0, int(default_attempt_count))
        retry_count = safe_int(read("provider_retry_count", "sitina_retry_count")) or 0
        fallback_count = safe_int(read("provider_fallback_count", "sitina_fallback_count")) or 0
        profile = read("provider_profile", "sitina_provider_profile")
        model = read("provider_model", "sitina_provider_model")
        error_type = read("provider_error_type", "sitina_provider_error_type")
        if error_type is None and not is_mapping:
            error_type = type(source).__name__
        if not isinstance(error_type, str):
            error_type = None
        error_type = error_type[:128] if error_type else None
        lower_bound = safe_int(read("provider_send_count_lower_bound", "sitina_provider_send_count_lower_bound"))
        if lower_bound is None and send_count_status == "lower_bound_with_uncertain_attempts":
            lower_bound = send_count
        raw_observation = read("provider_output_observation", "sitina_provider_output_observation")
        output_observation = None
        if isinstance(raw_observation, Mapping):
            output_observation = {}
            for key in (
                "tool_names_complete", "arguments_is_mapping", "status_present",
                "refusal_observed", "response_error_observed", "uncertain_send_count_observed",
            ):
                value = raw_observation.get(key)
                output_observation[key] = value if type(value) is bool else None
            for key in (
                "tool_call_count", "arguments_key_count", "arguments_unknown_key_count",
                "status_value_bytes", "json_repair_count",
            ):
                output_observation[key] = safe_int(raw_observation.get(key))
            for key in ("arguments_type", "status_type"):
                value = raw_observation.get(key)
                output_observation[key] = value if isinstance(value, str) and value in {
                    "dict", "list", "str", "int", "float", "bool", "NoneType", "missing", "other",
                } else "other"
            value = raw_observation.get("status_value")
            output_observation["status_value"] = value if isinstance(value, str) and value in {
                "SUCCEEDED", "FAILED", "RETRYABLE", "COMPLETE", "EMPTY",
            } else None
            for key in ("tool_names_sha256", "arguments_keyset_sha256", "status_value_sha256"):
                value = raw_observation.get(key)
                output_observation[key] = value if (
                    isinstance(value, str) and len(value) == 64
                    and all(character in "0123456789abcdef" for character in value)
                ) else None
            names = raw_observation.get("tool_names")
            output_observation["tool_names"] = list(names) if (
                isinstance(names, list) and len(names) <= 8
                and all(name is None or name == "experience_result" for name in names)
            ) else None
            keys = raw_observation.get("arguments_keys")
            allowed_keys = {"status", "manifest", "error_code", "retry_after", "provider_operation_id", "disposition", "reason"}
            output_observation["arguments_keys"] = list(keys) if (
                isinstance(keys, list) and len(keys) <= len(allowed_keys)
                and all(isinstance(key, str) and key in allowed_keys for key in keys)
            ) else None
        return {
            "dispatch_attempt_count": attempt_count,
            "provider_send_count": send_count,
            "provider_send_count_lower_bound": lower_bound,
            "provider_send_count_status": send_count_status,
            "provider_send_status": send_status,
            "uncertain_physical_send_attempt_count": uncertain,
            "response_received": response_received,
            "usage_known": usage is not None,
            "provider_usage_status": "exact" if usage is not None else "unknown",
            "provider_usage": usage,
            "provider_http_status": http_status,
            "provider_retry_count": retry_count,
            "provider_fallback_count": fallback_count,
            "provider_profile": str(profile)[:128] if isinstance(profile, str) and profile else None,
            "provider_model": str(model)[:256] if isinstance(model, str) and model else None,
            "provider_error_type": error_type,
            "finish_reason": finish_reason,
            "truncated_tool_call_count": safe_int(read("truncated_tool_call_count", "sitina_truncated_tool_call_count")),
            "output_truncation": truncation,
            "provider_metadata_status": metadata_status,
            "output_limit_tokens": safe_int(read("output_limit_tokens", "sitina_output_limit_tokens"), minimum=1),
            "error_code": error_code,
            "provider_output_observation": output_observation,
        }

    @staticmethod
    def _experience_dispatch_is_known_failure(facts: Mapping[str, Any]) -> bool:
        """Return true only when send outcome is exact and contradiction-free."""
        if facts.get("provider_send_count_status") != "exact":
            return False
        if type(facts.get("uncertain_physical_send_attempt_count")) is not int:
            return False
        if facts.get("uncertain_physical_send_attempt_count") != 0:
            return False
        count = facts.get("provider_send_count")
        status = facts.get("provider_send_status")
        if type(count) is not int or count < 0:
            return False
        if facts.get("response_received") is True:
            return status == "response_received" and count > 0
        return count == 0 and status in {
            "not_sent", "pre_send_failure", "pre_send_cancelled", "pre_send_deadline", "pre_send_validation_rejected",
        }

    @staticmethod
    def _normalize_experience_manifest_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
        """Convert the Provider's numeric confidence to canonical fixed-point.

        Provider tool arguments use a JSON number for confidence, while the
        Journal/CAS canonical profile forbids floats.  Keep the value and its
        review identity by storing the same millionths representation used by
        ``MemoryDocument.journal_mapping``.  Missing confidence remains a
        legacy-compatible omission; malformed values are rejected before any
        manifest CAS object is published.
        """
        normalized = dict(candidate)
        if "sensitivity" in normalized and normalized["sensitivity"] not in {
            "low", "moderate", "high", "restricted",
        }:
            raise ValueError("experience manifest candidate sensitivity is invalid")
        if "retention_policy" in normalized and normalized["retention_policy"] not in {
            "until-superseded", "until-expired", "explicit-revocation", "legal-retention",
        }:
            raise ValueError("experience manifest candidate retention_policy is invalid")
        if "applicability_scope" in normalized and normalized["applicability_scope"] not in {
            "task_specific", "reusable",
        }:
            raise ValueError("experience manifest candidate applicability_scope is invalid")
        if normalized.get("applicability_scope") == "task_specific" and not (
            isinstance(normalized.get("applicability_condition"), str)
            and normalized["applicability_condition"].strip()
        ):
            raise ValueError("task-specific experience applicability_condition is required")
        if "applicability_condition" in normalized:
            if not isinstance(normalized["applicability_condition"], str) or len(
                normalized["applicability_condition"].encode("utf-8")
            ) > 4096:
                raise ValueError("experience manifest candidate applicability_condition is invalid")
            if (
                normalized.get("applicability_scope") == "task_specific"
                and not normalized["applicability_condition"].strip()
            ):
                raise ValueError("task-specific experience applicability_condition cannot be empty")
        if "evidence_input_sequences" in normalized:
            sequences = normalized["evidence_input_sequences"]
            if (
                not isinstance(sequences, list)
                or any(type(item) is not int or item < 1 for item in sequences)
                or sequences != sorted(set(sequences))
                or len(sequences) > EXPERIENCE_INPUT_MAX_RECORDS
            ):
                raise ValueError("experience manifest candidate evidence_input_sequences is invalid")
        for key in ("valid_from", "observed_at"):
            if key in normalized:
                try:
                    validate_timestamp(normalized[key])
                except ValueError as error:
                    raise ValueError(f"experience manifest candidate {key} is invalid") from error
        if "expires_at" in normalized and normalized["expires_at"] is not None:
            try:
                validate_timestamp(normalized["expires_at"])
            except ValueError as error:
                raise ValueError("experience manifest candidate expires_at is invalid") from error
        if "confidence" not in normalized:
            return normalized
        raw = normalized.pop("confidence")
        if type(raw) is bool or not isinstance(raw, (int, float)):
            raise ValueError("experience manifest candidate confidence must be a finite number")
        if isinstance(raw, float) and not math.isfinite(raw):
            raise ValueError("experience manifest candidate confidence must be finite")
        if raw < 0 or raw > 1:
            raise ValueError("experience manifest candidate confidence is outside [0,1]")
        confidence_millionths = int(round(raw * 1_000_000))
        if not 0 <= confidence_millionths <= 1_000_000:
            raise ValueError("experience manifest candidate confidence is outside [0,1]")
        normalized["confidence_millionths"] = confidence_millionths
        return normalized

    @staticmethod
    def _experience_manifest_confidence(candidate: Mapping[str, Any]) -> float:
        """Read new fixed-point confidence and bounded legacy forms."""
        if "confidence_millionths" in candidate:
            value = candidate.get("confidence_millionths")
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise PersistenceFenced("experience manifest confidence_millionths is invalid")
            return value / 1_000_000
        if "confidence" not in candidate:
            return 0.5
        value = candidate.get("confidence")
        # Canonical manifests from older writers could retain an integer
        # confidence (0 or 1).  Do not accept strings, bools, or floats here:
        # a float could not have been persisted by the canonical profile.
        if type(value) is not int or not 0 <= value <= 1:
            raise PersistenceFenced("legacy experience manifest confidence is invalid")
        return float(value)

    @staticmethod
    def _experience_review_reason_code(
        *,
        review_request_id: str,
        candidate_id: str,
        candidate_revision: str,
        disposition: str,
        reason: str,
    ) -> str:
        """Keep native decision reason codes principal-safe and review-bound."""
        if reason and len(reason) <= 255 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", reason):
            return reason
        if not reason:
            return "review-decision"
        digest = hashlib.sha256(canonical_json_bytes({
            "schema": "SITINA_MEMORY_REVIEW_REASON_CODE_V1",
            "review_request_id": review_request_id,
            "candidate_id": candidate_id,
            "candidate_revision": candidate_revision,
            "disposition": disposition,
            "reason": reason,
        })).hexdigest()[:48]
        return "review-natural-" + digest

    def process_experience_obligation(
        self,
        obligation_id: str,
        *,
        request_id: str,
        provider_profile: str,
        provider_dispatch: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        """Dispatch one extraction/review request without reopening its task.

        The provider callback is a formal, injected transport boundary. A
        dispatch fact is committed before calling it; any exception after
        dispatch is durably classified UNKNOWN and is never auto-resubmitted by
        this method. The callback receives only the obligation/source closure,
        not a task execution token or capability to mutate the terminal task.
        """
        if not request_id or not provider_profile or not callable(provider_dispatch):
            raise ValueError("experience dispatch requires request, profile, and provider factory")
        with self._state_lock:
            obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                self.reconcile_experience_obligations()
                obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                raise KeyError(obligation_id)
            if obligation.get("state") != "PENDING":
                if obligation.get("dispatch_request_id") == request_id:
                    return dict(obligation)
                raise TaskConflict("experience obligation is not pending for a new dispatch")
            if not self._experience_obligation_is_due(obligation):
                raise TaskConflict("experience obligation is not due for dispatch")
            attempt_count = int(obligation.get("attempt_count") or 0) + 1
            max_attempts = int(obligation.get("max_attempts") or 0)
            if max_attempts < 1 or attempt_count > max_attempts:
                raise TaskConflict("experience obligation has exhausted its persisted retry budget")
            correction_feedback = obligation.get("status_correction")
            if correction_feedback is not None and (
                not isinstance(correction_feedback, Mapping)
                or type(correction_feedback.get("attempt_count")) is not int
                or correction_feedback.get("request_id") == request_id
            ):
                raise TaskConflict("experience correction requires a new request identity")
            # All deterministic source/CAS validation must complete before a
            # DISPATCHED fact exists.  A malformed local closure therefore
            # remains PENDING and cannot be reclassified as an unknown send
            # after a restart.
            try:
                source_evidence = self._verified_experience_source_evidence(obligation)
            except (CASError, KeyError, OSError, PersistenceFenced, TypeError, ValueError) as error:
                # Persist a bounded, explicitly not-sent observation without
                # creating a DISPATCHED fact.  Keep a separate finite local
                # budget so restart cannot turn this into an endless eager
                # loop; before exhaustion, a corrected local source can be
                # retried without consuming a Provider attempt.
                preflight_attempt_count = int(obligation.get("preflight_attempt_count") or 0) + 1
                preflight_max_attempts = int(
                    obligation.get("preflight_max_attempts")
                    or obligation.get("max_attempts")
                    or 3
                )
                exhausted = preflight_attempt_count >= preflight_max_attempts
                delay_seconds = min(8.0, max(0.5, 0.5 * (2 ** min(preflight_attempt_count - 1, 4))))
                next_due_at = None if exhausted else (
                    dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=delay_seconds)
                ).isoformat()
                self._append_experience_obligation_event(
                    event_type="loop.experience-obligation-updated",
                    payload={
                        "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                        "obligation_id": obligation_id,
                        "patch": {
                            "state": "FAILED_FINAL" if exhausted else "PENDING",
                            "dispatch_request_id": None,
                            "preflight_request_id": request_id,
                            "preflight_attempt_count": preflight_attempt_count,
                            "preflight_max_attempts": preflight_max_attempts,
                            "preflight_error": f"{type(error).__name__}: {str(error)[:512]}",
                            "unknown_effect": False,
                            "last_error": (
                                "source-preflight-budget-exhausted"
                                if exhausted else "source-preflight-failed-before-dispatch"
                            ),
                            "next_due_at": next_due_at,
                            "provider_dispatch_facts": {
                                "dispatch_attempt_count": 0,
                                "provider_send_count": 0,
                                "provider_send_count_status": "exact",
                                "provider_send_status": "not_sent",
                                "uncertain_physical_send_attempt_count": 0,
                                "response_received": False,
                                "usage_known": False,
                                "provider_usage": None,
                            },
                        },
                    },
                    request_id=f"{request_id}:preflight:{preflight_attempt_count}",
                )
                raise
            source_closure = dict(obligation.get("source_closure") or {})
            dispatch_payload = {
                "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                "obligation_id": obligation_id,
                "patch": {
                    "state": "DISPATCHED",
                    "dispatch_request_id": request_id,
                    "provider_profile": provider_profile,
                    "attempt_count": attempt_count,
                    "last_error": None,
                    "validation_failure": None,
                    "next_due_at": None,
                    "result_ref": None,
                    "result_hash": None,
                    "result_request_id": None,
                    "result_attempt_count": None,
                },
            }
            self._append_experience_obligation_event(
                event_type="loop.experience-obligation-updated",
                payload=dispatch_payload,
                request_id=request_id,
            )
            request = {
                "schema": "SITINA_EXPERIENCE_PROVIDER_REQUEST_V1",
                "request_id": request_id,
                "provider_profile": provider_profile,
                "obligation_id": obligation_id,
                "obligation_type": obligation.get("obligation_type"),
                "processor_version": obligation.get("processor_version"),
                "attempt_count": attempt_count,
                "source_closure": source_closure,
                "source_evidence": source_evidence,
            }
            if correction_feedback is not None and attempt_count == correction_feedback["attempt_count"] + 1:
                request["validation_feedback"] = dict(correction_feedback)
        dispatch_facts: dict[str, Any] | None = None
        validation_stage = "PROVIDER_DISPATCH"
        validation_field: str | None = None
        validation_candidate_index: int | None = None
        try:
            result = provider_dispatch(request)
            validation_stage = "RESULT_ENVELOPE"
            if not isinstance(result, Mapping):
                raise ValueError("provider result must be a mapping")
            # Capture the adapter's already-observed transport facts before
            # validating the business result.  A malformed manifest must not
            # erase a known HTTP response/send count from the returned result.
            validation_stage = "DISPATCH_FACTS"
            dispatch_facts = self._experience_provider_dispatch_facts(result)
            validation_stage = "RESULT_STATUS"
            status = str(result.get("status") or "")
            if status not in {"SUCCEEDED", "FAILED", "RETRYABLE"}:
                raise ValueError("provider result status is not classified")
            manifest_stored: StoredContent | None = None
            manifest_status: str | None = None
            manifest_candidate_ids: tuple[str, ...] = ()
            manifest_candidate_revisions: dict[str, str] = {}
            if status == "SUCCEEDED":
                validation_stage = "MANIFEST_CONTRACT"
                manifest = result.get("manifest")
                closure = request["source_closure"]
                manifest_checks = [("manifest", isinstance(manifest, Mapping))]
                if isinstance(manifest, Mapping):
                    manifest_checks.extend((
                        ("manifest.schema", manifest.get("schema") == "SITINA_EXPERIENCE_MANIFEST_V1"),
                        ("manifest.batch_id", bool(str(manifest.get("batch_id") or ""))),
                        ("manifest.source_closure_hash", manifest.get("source_closure_hash") == closure.get("closure_hash")),
                        ("manifest.status", manifest.get("status") in {"COMPLETE", "EMPTY"}),
                        ("manifest.candidates", isinstance(manifest.get("candidates"), list)),
                    ))
                validation_field = next((field for field, valid in manifest_checks if not valid), None)
                if validation_field is not None:
                    raise ValueError("provider result manifest is incomplete or not bound to the terminal closure")
                candidates = manifest["candidates"]
                validation_stage = "MANIFEST_EMPTY"
                if manifest.get("status") == "EMPTY" and candidates:
                    raise ValueError("valid empty experience manifest contains candidates")
                validation_stage = "MANIFEST_COUNT"
                if len(candidates) > 64:
                    raise ValueError("experience manifest candidate count exceeds its bounded contract")
                candidate_ids: list[str] = []
                normalized_candidates: list[dict[str, Any]] = []
                for index, candidate in enumerate(candidates):
                    validation_candidate_index = index
                    validation_stage = "CANDIDATE_SHAPE"
                    if not isinstance(candidate, Mapping):
                        raise ValueError("experience manifest candidate is malformed")
                    validation_stage = "CANDIDATE_NORMALIZATION"
                    normalized_candidate = self._normalize_experience_manifest_candidate(candidate)
                    validation_stage = "CANDIDATE_INPUT_EVIDENCE"
                    scoped_fields = {
                        "applicability_scope", "applicability_condition", "evidence_input_sequences",
                    }
                    if scoped_fields.intersection(normalized_candidate):
                        if not {
                            "applicability_scope", "evidence_input_sequences",
                        }.issubset(normalized_candidate):
                            raise ValueError(
                                "experience manifest candidate applicability evidence is incomplete"
                            )
                        input_evidence = request.get("source_evidence", {}).get("input_evidence")
                        if not isinstance(input_evidence, Mapping):
                            raise ValueError("experience manifest candidate has no verified input evidence")
                        semantic_sequences = {
                            int(item)
                            for item in input_evidence.get("semantic_input_sequences", ())
                            if type(item) is int
                        }
                        supplied_sequences = set(normalized_candidate["evidence_input_sequences"])
                        handled_input_seq = int(input_evidence.get("handled_input_seq", -1))
                        if (
                            any(item > handled_input_seq for item in supplied_sequences)
                            or not supplied_sequences.issubset(semantic_sequences)
                        ):
                            raise ValueError(
                                "experience manifest candidate cites an unverified or control-only input"
                            )
                    validation_stage = "CANDIDATE_SUPERSESSION_EVIDENCE"
                    allowed_prior_ids = {
                        item["memory_id"]
                        for item in request["source_evidence"]["prior_task_memory"]["entries"]
                    }
                    supersedes = normalized_candidate.get("supersedes_memory_ids", [])
                    if (not isinstance(supersedes, list)
                            or any(not isinstance(item, str) or item not in allowed_prior_ids for item in supersedes)
                            or len(supersedes) != len(set(supersedes))):
                        validation_field = "supersedes_memory_ids"
                        raise ValueError("experience candidate supersedes memory outside the verified task view")
                    validation_stage = "CANDIDATE_IDENTITY"
                    candidate_id = str(normalized_candidate.get("candidate_id") or "")
                    content = normalized_candidate.get("content")
                    if not candidate_id or not isinstance(content, str) or not content or len(content.encode("utf-8")) > 256 * 1024:
                        raise ValueError("experience manifest candidate is missing bounded content identity")
                    if candidate_id in candidate_ids:
                        raise ValueError("experience manifest candidate identity is duplicated")
                    candidate_ids.append(candidate_id)
                    normalized_candidates.append(normalized_candidate)
                    validation_stage = "CANDIDATE_REVISION"
                    manifest_candidate_revisions[candidate_id] = str(
                        normalized_candidate.get("revision")
                        or hashlib.sha256(canonical_json_bytes(normalized_candidate)).hexdigest()
                    )
                validation_candidate_index = None
                validation_stage = "MANIFEST_PUBLICATION"
                manifest_status = str(manifest["status"])
                manifest_candidate_ids = tuple(candidate_ids)
                manifest_to_store = dict(manifest)
                manifest_to_store["candidates"] = normalized_candidates
                manifest_stored = self.store.publish_json(manifest_to_store, purpose="experience-manifest")
            validation_stage = "RESULT_PUBLICATION"
            public_result: dict[str, Any] = {
                "schema": "SITINA_EXPERIENCE_PROVIDER_RESULT_V1",
                "request_id": request_id,
                "status": status,
                "program_status": result.get("program_status"),
                "manifest": None,
                "manifest_ref": result.get("manifest_ref"),
                "manifest_hash": result.get("manifest_hash"),
                "candidate_results": result.get("candidate_results"),
                "error_code": dispatch_facts.get("error_code"),
                "retry_after": result.get("retry_after"),
                "provider_operation_id": result.get("provider_operation_id"),
                **dispatch_facts,
            }
            stored = self.store.publish_json(public_result, purpose="experience-provider-result")
            validation_stage = "OBLIGATION_COMMIT"
            with self._state_lock:
                payload = {
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": (
                            "SETTLED_EMPTY"
                            if status == "SUCCEEDED" and manifest_status == "EMPTY"
                            else "MANIFEST_RECORDED"
                            if status == "SUCCEEDED"
                            else "FAILED_FINAL"
                            if status == "FAILED" or attempt_count >= max_attempts
                            else "PENDING"
                        ),
                        "result_ref": stored.reference_id,
                        "result_hash": stored.content_hash,
                        "result_request_id": request_id,
                        "result_attempt_count": attempt_count,
                        "result_status": status,
                        "manifest_ref": manifest_stored.reference_id if manifest_stored is not None else None,
                        "manifest_hash": manifest_stored.content_hash if manifest_stored is not None else None,
                        "manifest_status": manifest_status,
                        "candidate_ids": list(manifest_candidate_ids),
                        "candidate_revisions": manifest_candidate_revisions,
                        "candidate_dispositions": {},
                        "unknown_effect": False,
                        "last_error": public_result.get("error_code"),
                        "next_due_at": result.get("retry_after") if status == "RETRYABLE" else None,
                        "provider_dispatch_facts": {
                            key: public_result.get(key)
                            for key in (
                                "dispatch_attempt_count", "provider_send_count",
                                "provider_send_count_lower_bound",
                                "provider_send_count_status", "provider_send_status",
                                "uncertain_physical_send_attempt_count",
                                "response_received", "usage_known", "provider_usage_status",
                                "provider_usage", "provider_http_status", "provider_retry_count",
                                "provider_fallback_count", "provider_profile", "provider_model",
                                "provider_error_type", "finish_reason", "truncated_tool_call_count",
                                "output_truncation", "provider_metadata_status", "output_limit_tokens",
                                "error_code",
                            )
                        },
                    },
                }
                self._append_experience_obligation_event(
                    event_type="loop.experience-obligation-updated",
                    payload=payload,
                    request_id=request_id + ":result",
                    proofs=(stored.proof, *((manifest_stored.proof,) if manifest_stored is not None else ())),
                )
                return dict(self._experience_obligation_projection()[obligation_id])
        except BaseException as error:
            with self._state_lock:
                try:
                    current = self._experience_obligation_projection().get(obligation_id)
                except BaseException:
                    # The authoritative stream is unreadable; do not append a
                    # second fact that could mask a committed result.
                    raise
                if (
                    current is not None
                    and current.get("dispatch_request_id") == request_id
                    and (
                        current.get("state") in {"RESULT_RECORDED", "FAILED_FINAL", "UNKNOWN"}
                        or (
                            current.get("result_ref")
                            and current.get("result_request_id") == request_id
                            and int(current.get("result_attempt_count") or -1) == attempt_count
                        )
                    )
                ):
                    return dict(current)
                if (
                    bool(getattr(error, "sitina_not_sent_retryable", False))
                    and current is not None
                    and current.get("dispatch_request_id") == request_id
                ):
                    self._append_experience_obligation_event(
                        event_type="loop.experience-obligation-updated",
                        payload={
                            "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                            "obligation_id": obligation_id,
                            "patch": {
                                "state": "PENDING",
                                "unknown_effect": False,
                                "attempt_count": max(0, attempt_count - 1),
                                "last_error": "provider-slot-busy-before-send",
                                "next_due_at": getattr(error, "sitina_retry_after", None),
                                "provider_dispatch_facts": {
                                    "dispatch_attempt_count": 0,
                                    "provider_send_count": 0,
                                    "provider_send_count_status": "exact",
                                    "provider_send_status": "not_sent",
                                    "uncertain_physical_send_attempt_count": 0,
                                    "response_received": False,
                                    "usage_known": False,
                                    "provider_usage": None,
                                },
                            },
                        },
                        request_id=request_id + ":not-sent",
                    )
                    raise
                facts = dispatch_facts or self._experience_provider_dispatch_facts(
                    error,
                    default_error_code=(
                        "provider-result-invalid" if isinstance(error, ValueError) else "unclassified-provider-error"
                    ),
                )
                if isinstance(error, ValueError) and dispatch_facts is not None and facts.get("error_code") is None:
                    facts = {**facts, "error_code": "provider-result-invalid"}
                # Only program-owned, exact messages from this stage may enter
                # the durable error record. Never copy arbitrary exception text,
                # model content, reasoning, transport bodies, or credentials.
                approved_reasons = {
                    "PROVIDER_DISPATCH": {
                        "native experience Provider returned malformed truncation metadata": "PROVIDER_METADATA_MALFORMED",
                        "native experience Provider result was truncated before the structured tool result completed": "PROVIDER_RESULT_TRUNCATED",
                        "native experience Provider result has no classified finish reason": "PROVIDER_FINISH_REASON_MISSING",
                        "native experience Provider must return exactly one experience_result tool call": "PROVIDER_TOOL_CARDINALITY_OR_NAME",
                        "native experience Provider must return one structured experience_result tool call": "PROVIDER_TOOL_ARGUMENTS_MISSING",
                        "native experience extraction result has no valid status": "PROVIDER_EXTRACTION_STATUS_INVALID",
                        "native experience Provider result exceeds bounded transport budget": "PROVIDER_RESULT_BUDGET_EXCEEDED",
                    },
                    "RESULT_ENVELOPE": {"provider result must be a mapping": "RESULT_NOT_MAPPING"},
                    "RESULT_STATUS": {"provider result status is not classified": "RESULT_STATUS_UNCLASSIFIED"},
                    "MANIFEST_CONTRACT": {"provider result manifest is incomplete or not bound to the terminal closure": "MANIFEST_INCOMPLETE_OR_UNBOUND"},
                    "MANIFEST_EMPTY": {"valid empty experience manifest contains candidates": "EMPTY_MANIFEST_HAS_CANDIDATES"},
                    "MANIFEST_COUNT": {"experience manifest candidate count exceeds its bounded contract": "CANDIDATE_COUNT_EXCEEDED"},
                    "CANDIDATE_SHAPE": {"experience manifest candidate is malformed": "CANDIDATE_NOT_MAPPING"},
                    "CANDIDATE_NORMALIZATION": {
                        "experience manifest candidate sensitivity is invalid": "SENSITIVITY_INVALID",
                        "experience manifest candidate retention_policy is invalid": "RETENTION_POLICY_INVALID",
                        "experience manifest candidate applicability_scope is invalid": "APPLICABILITY_SCOPE_INVALID",
                        "task-specific experience applicability_condition is required": "APPLICABILITY_CONDITION_REQUIRED",
                        "experience manifest candidate applicability_condition is invalid": "APPLICABILITY_CONDITION_INVALID",
                        "task-specific experience applicability_condition cannot be empty": "APPLICABILITY_CONDITION_EMPTY",
                        "experience manifest candidate evidence_input_sequences is invalid": "INPUT_SEQUENCE_SHAPE_INVALID",
                        "experience manifest candidate valid_from is invalid": "VALID_FROM_INVALID",
                        "experience manifest candidate observed_at is invalid": "OBSERVED_AT_INVALID",
                        "experience manifest candidate expires_at is invalid": "EXPIRES_AT_INVALID",
                        "experience manifest candidate confidence must be a finite number": "CONFIDENCE_TYPE_INVALID",
                        "experience manifest candidate confidence must be finite": "CONFIDENCE_NOT_FINITE",
                        "experience manifest candidate confidence is outside [0,1]": "CONFIDENCE_RANGE_INVALID",
                    },
                    "CANDIDATE_INPUT_EVIDENCE": {
                        "experience manifest candidate applicability evidence is incomplete": "APPLICABILITY_EVIDENCE_INCOMPLETE",
                        "experience manifest candidate has no verified input evidence": "VERIFIED_INPUT_EVIDENCE_MISSING",
                        "experience manifest candidate cites an unverified or control-only input": "INPUT_EVIDENCE_UNVERIFIED",
                    },
                    "CANDIDATE_IDENTITY": {
                        "experience manifest candidate is missing bounded content identity": "CANDIDATE_CONTENT_IDENTITY_INVALID",
                        "experience manifest candidate identity is duplicated": "CANDIDATE_IDENTITY_DUPLICATED",
                    },
                }
                message = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
                stage_reasons = approved_reasons.get(validation_stage, {})
                reason_code = stage_reasons.get(message, "UNCLASSIFIED_AT_STAGE")
                if reason_code == "PROVIDER_EXTRACTION_STATUS_INVALID":
                    validation_field = "status"
                validation_failure = {
                    "obligation_id": obligation_id,
                    "request_id": request_id,
                    "attempt_count": attempt_count,
                    "stage": validation_stage,
                    "field": validation_field,
                    "candidate_index": validation_candidate_index,
                    "reason_code": reason_code,
                    "detail": message if message in stage_reasons else "No approved specific program validation reason was retained.",
                }
                observation = facts.get("provider_output_observation")
                if observation is not None:
                    validation_failure["output_observation"] = observation
                known_failure = self._experience_dispatch_is_known_failure(facts)
                if isinstance(error, ValueError) and current is not None and current.get("dispatch_request_id") == request_id:
                    correct_status_once = (
                        known_failure
                        and obligation.get("obligation_type") == "EXPERIENCE_EXTRACTION"
                        and reason_code == "PROVIDER_EXTRACTION_STATUS_INVALID"
                        and validation_stage == "PROVIDER_DISPATCH"
                        and facts.get("provider_error_type") == "ProviderResultInvalid"
                        and facts.get("provider_send_count") == 1
                        and facts.get("response_received") is True
                        and facts.get("provider_retry_count") == 0
                        and facts.get("provider_fallback_count") == 0
                        and facts.get("output_truncation") == "not_truncated"
                        and facts.get("provider_metadata_status") == "complete"
                        and facts.get("truncated_tool_call_count") == 0
                        and facts.get("finish_reason") in {"tool_calls", "stop", "end_turn"}
                        and isinstance(observation, Mapping)
                        and observation.get("tool_call_count") == 1
                        and observation.get("tool_names") == ["experience_result"]
                        and observation.get("arguments_is_mapping") is True
                        and observation.get("refusal_observed") is False
                        and observation.get("response_error_observed") is False
                        and observation.get("uncertain_send_count_observed") is True
                        and current.get("status_correction") is None
                        and attempt_count < max_attempts
                        and not current.get("manifest_ref")
                        and not current.get("candidate_ids")
                        and not current.get("candidate_dispositions")
                    )
                    invalid_patch = {
                        "state": "PENDING" if correct_status_once else "FAILED_FINAL" if known_failure else "UNKNOWN",
                        "unknown_effect": not known_failure,
                        "last_error": facts.get("error_code") or "provider-result-invalid",
                        "next_due_at": (
                            dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=0.5)
                        ).isoformat() if correct_status_once else None,
                        "provider_dispatch_facts": facts,
                        "validation_failure": validation_failure,
                    }
                    if correct_status_once:
                        # The immutable failure event remains authoritative.
                        # This marker survives restart and consumes the sole
                        # targeted correction without changing max_attempts.
                        invalid_patch["status_correction"] = dict(validation_failure)
                    self._append_experience_obligation_event(
                        event_type="loop.experience-obligation-updated",
                        payload={
                            "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                            "obligation_id": obligation_id,
                            "patch": invalid_patch,
                        },
                        request_id=request_id + ":invalid",
                    )
                    raise
                payload = {
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": "FAILED_FINAL" if known_failure else "UNKNOWN",
                            "unknown_effect": not known_failure,
                            "last_error": facts.get("error_code") or "unclassified-provider-error",
                            "next_due_at": None,
                            "provider_dispatch_facts": facts,
                            "validation_failure": validation_failure,
                    },
                }
                self._append_experience_obligation_event(
                    event_type="loop.experience-obligation-updated",
                    payload=payload,
                    request_id=request_id + ":unknown",
                )
            raise

    def record_experience_candidate_disposition(
        self,
        obligation_id: str,
        *,
        candidate_id: str,
        candidate_revision: str,
        disposition: str,
        request_id: str,
        source_closure_hash: str,
        reason: str = "",
        next_due_at: str | None = None,
        attempt_count: int | None = None,
        provider_dispatch_facts: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Persist one independent candidate disposition and rebuild parent state."""
        final = {"PUBLISHED", "REJECTED", "FAILED_FINAL"}
        allowed = final | {"NEEDS_WORK", "UNKNOWN"}
        if disposition not in allowed or not candidate_id or not candidate_revision or not request_id:
            raise ValueError("candidate disposition identity or status is invalid")
        with self._state_lock:
            obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                raise KeyError(obligation_id)
            if obligation.get("state") not in {"MANIFEST_RECORDED", "CANDIDATE_REVIEW", "PENDING"}:
                raise TaskConflict("experience manifest is not open for candidate disposition")
            if str(obligation.get("source_closure", {}).get("closure_hash") or "") != source_closure_hash:
                raise TaskConflict("candidate source closure is stale")
            candidate_ids = tuple(str(item) for item in obligation.get("candidate_ids", ()))
            if candidate_id not in candidate_ids:
                raise TaskConflict("candidate is not in the committed manifest")
            dispositions = dict(obligation.get("candidate_dispositions") or {})
            prior = dispositions.get(candidate_id)
            current_record = {
                "candidate_revision": candidate_revision,
                "disposition": disposition,
                "request_id": request_id,
                "reason": reason,
                "next_due_at": next_due_at,
                "attempt_count": int(attempt_count if attempt_count is not None else (prior or {}).get("attempt_count", 0) or 0),
                "max_attempts": int((prior or {}).get("max_attempts", 3) or 3),
                "provider_dispatch_facts": dict(provider_dispatch_facts or (prior or {}).get("provider_dispatch_facts") or {}),
            }
            if prior is not None:
                if prior == current_record:
                    return dict(obligation)
                if str(prior.get("disposition") or "") in final:
                    raise TaskConflict("candidate already has a final disposition")
            dispositions[candidate_id] = current_record
            all_final = bool(candidate_ids) and all(
                str(dispositions.get(item, {}).get("disposition") or "") in final
                for item in candidate_ids
            )
            self._append_experience_obligation_event(
                event_type="loop.experience-obligation-updated",
                payload={
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": "SETTLED" if all_final else "CANDIDATE_REVIEW",
                        "candidate_dispositions": dispositions,
                        "last_candidate_id": candidate_id,
                        "last_candidate_revision": candidate_revision,
                        "next_due_at": next_due_at,
                    },
                },
                request_id=request_id,
            )
            return dict(self._experience_obligation_projection()[obligation_id])

    def process_experience_candidate_review(
        self,
        obligation_id: str,
        *,
        request_id: str,
        provider_profile: str,
        review_dispatch: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        memory_repository: Any | None = None,
        memory_actor: str | None = None,
    ) -> Mapping[str, Any]:
        """Run one bounded candidate review without reopening its terminal task."""
        with self._state_lock:
            obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                raise KeyError(obligation_id)
            dispositions = dict(obligation.get("candidate_dispositions") or {})
            candidate_id = None
            candidate_attempt_count = 0
            for item in obligation.get("candidate_ids", ()):
                item_id = str(item)
                prior = dispositions.get(item_id, {})
                prior_status = str(prior.get("disposition") or "")
                if prior_status in {"PUBLISHED", "REJECTED", "FAILED_FINAL", "UNKNOWN"}:
                    continue
                prior_attempt_count = int(prior.get("attempt_count") or 0)
                max_attempts = int(prior.get("max_attempts") or 3)
                if prior_attempt_count >= max_attempts:
                    self.record_experience_candidate_disposition(
                        obligation_id,
                        candidate_id=item_id,
                        candidate_revision=str((obligation.get("candidate_revisions") or {}).get(item_id) or ""),
                        disposition="FAILED_FINAL",
                        request_id=f"candidate-budget:{obligation_id}:{item_id}",
                        source_closure_hash=str((obligation.get("source_closure") or {}).get("closure_hash") or ""),
                        reason="candidate-review-budget-exhausted",
                        attempt_count=max_attempts,
                    )
                    continue
                next_due = str(prior.get("next_due_at") or "")
                if next_due and next_due > iso_now():
                    continue
                candidate_attempt_count = prior_attempt_count + 1
                if candidate_attempt_count > max_attempts:
                    self.record_experience_candidate_disposition(
                        obligation_id,
                        candidate_id=item_id,
                        candidate_revision=str((obligation.get("candidate_revisions") or {}).get(item_id) or ""),
                        disposition="FAILED_FINAL",
                        request_id=f"candidate-budget:{obligation_id}:{item_id}",
                        source_closure_hash=str((obligation.get("source_closure") or {}).get("closure_hash") or ""),
                        reason="candidate-review-budget-exhausted",
                        attempt_count=max_attempts,
                    )
                    continue
                candidate_id = item_id
                break
            if candidate_id is None:
                return dict(obligation)
            # Bind the durable review identity to the selected candidate. A
            # Host attempt stem is shared by the scan, but each candidate
            # must have its own dispatch/result/decision identity.
            # The Host request stem is derived from the parent extraction
            # attempt and can be reused for every candidate retry. Bind the
            # actual candidate attempt into the durable review identity so a
            # pre-dispatch failure (or a later NEEDS_WORK retry) cannot reuse
            # one Journal request identity for a different attempt.
            review_request_id = (
                f"{request_id}:candidate:{candidate_id}:attempt:{candidate_attempt_count}"
            )
            source_closure = dict(obligation.get("source_closure") or {})
            candidate_revision = str((obligation.get("candidate_revisions") or {}).get(candidate_id) or "")
            if not candidate_revision:
                raise PersistenceFenced("candidate manifest has no stable revision")
            review_memory_binding = None
            try:
                if memory_repository is not None:
                    candidate_memory_id = str((obligation.get("candidate_memory_ids") or {}).get(candidate_id) or "")
                    if not candidate_memory_id:
                        raise TaskConflict("candidate has not been materialized into native memory")
                    review_memory_binding = memory_repository.capture_review_binding(candidate_memory_id)
                # Source/CAS validation is deliberately before CANDIDATE_REVIEW:
                # a missing input body is a deterministic no-send failure, not
                # a Provider attempt and not an in-memory Host backoff.
                source_evidence = self._verified_experience_source_evidence(
                    {**obligation, "review_memory_binding": review_memory_binding},
                    candidate_id=candidate_id,
                    memory_repository=memory_repository,
                    memory_actor=memory_actor,
                )
            except (CASError, KeyError, OSError, PersistenceFenced, TypeError, ValueError) as error:
                max_attempts = int(
                    (dispositions.get(candidate_id) or {}).get("max_attempts") or 3
                )
                max_attempts = max(1, max_attempts)
                preflight_final = candidate_attempt_count >= max_attempts
                delay_seconds = min(
                    8.0,
                    max(0.5, 0.5 * (2 ** min(candidate_attempt_count - 1, 4))),
                )
                next_due_at = None if preflight_final else (
                    dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=delay_seconds)
                ).isoformat()
                facts = {
                    "dispatch_attempt_count": 0,
                    "provider_send_count": 0,
                    "provider_send_count_status": "exact",
                    "provider_send_status": "not_sent",
                    "uncertain_physical_send_attempt_count": 0,
                    "response_received": False,
                    "usage_known": False,
                    "provider_usage": None,
                }
                return dict(self.record_experience_candidate_disposition(
                    obligation_id,
                    candidate_id=candidate_id,
                    candidate_revision=candidate_revision,
                    disposition="FAILED_FINAL" if preflight_final else "NEEDS_WORK",
                    request_id=f"{review_request_id}:preflight:{candidate_attempt_count}",
                    source_closure_hash=str(source_closure.get("closure_hash") or ""),
                    reason=(
                        "review-source-preflight:"
                        + type(error).__name__
                        + ":"
                        + str(error)[:256]
                    ),
                    next_due_at=next_due_at,
                    attempt_count=candidate_attempt_count,
                    provider_dispatch_facts=facts,
                ))
            self._append_experience_obligation_event(
                event_type="loop.experience-obligation-updated",
                payload={
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": "CANDIDATE_REVIEW",
                        "review_request_id": review_request_id,
                        "review_candidate_id": candidate_id,
                        "review_candidate_revision": candidate_revision,
                        "review_provider_profile": provider_profile,
                        "review_memory_binding": review_memory_binding,
                    },
                },
                request_id=review_request_id,
            )
            request = {
                "schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1",
                "request_id": review_request_id,
                "provider_profile": provider_profile,
                "obligation_id": obligation_id,
                "candidate_id": candidate_id,
                "candidate_revision": candidate_revision,
                "attempt_count": candidate_attempt_count,
                "max_attempts": 3,
                "source_closure": source_closure,
                "manifest_ref": obligation.get("manifest_ref"),
                "manifest_hash": obligation.get("manifest_hash"),
                "memory_binding": review_memory_binding,
                "source_evidence": source_evidence,
            }
        dispatch_facts: Mapping[str, Any] | None = None
        native_decision_started = False
        try:
            result = review_dispatch(request)
            if not isinstance(result, Mapping):
                raise ValueError("review result must be a mapping")
            # Capture transport facts before validating the bounded business
            # fields so a malformed reason cannot erase a known response.
            dispatch_facts = self._experience_provider_dispatch_facts(result)
            status = str(result.get("disposition") or "")
            if status not in {"PUBLISHED", "REJECTED", "NEEDS_WORK", "RETRYABLE"}:
                raise ValueError("review result disposition is not classified")
            disposition = "NEEDS_WORK" if status == "RETRYABLE" else status
            review_reason = result.get("reason")
            if review_reason is None:
                review_reason = ""
            elif not isinstance(review_reason, str):
                raise ValueError("review result reason must be a string")
            if len(review_reason) > 4096:
                raise ValueError("review result reason exceeds its bounded contract")
            if memory_repository is not None and disposition in {"PUBLISHED", "REJECTED"}:
                native_action = {
                    "candidate_id": candidate_id,
                    "to_status": "accepted" if disposition == "PUBLISHED" else "rejected",
                    "reason_code": self._experience_review_reason_code(
                        review_request_id=review_request_id,
                        candidate_id=candidate_id,
                        candidate_revision=candidate_revision,
                        disposition=disposition,
                        reason=review_reason,
                    ),
                }
                native_decision_started = True
                self.commit_experience_candidate_memory_decision(
                    obligation_id,
                    memory_repository=memory_repository,
                    actor=str(memory_actor or ""),
                    decision_id="memory-decision-" + hashlib.sha256(review_request_id.encode("utf-8")).hexdigest()[:40],
                    candidate_actions=[native_action],
                    review_request_id=review_request_id,
                    provider_dispatch_facts=dispatch_facts,
                    review_reason=review_reason,
                )
                return dict(self._experience_obligation_projection()[obligation_id])
            return self.record_experience_candidate_disposition(
                obligation_id,
                candidate_id=candidate_id,
                candidate_revision=candidate_revision,
                disposition=disposition,
                request_id=review_request_id + ":disposition",
                source_closure_hash=str(source_closure.get("closure_hash") or ""),
                reason=review_reason,
                next_due_at=result.get("next_due_at"),
                attempt_count=candidate_attempt_count,
                provider_dispatch_facts=dispatch_facts,
            )
        except BaseException as error:
            with self._state_lock:
                try:
                    current = self._experience_obligation_projection().get(obligation_id)
                except BaseException:
                    raise
                if current is not None and current.get("review_request_id") == review_request_id:
                    try:
                        if bool(getattr(error, "sitina_not_sent_retryable", False)):
                            return self.record_experience_candidate_disposition(
                                obligation_id,
                                candidate_id=candidate_id,
                                candidate_revision=candidate_revision,
                                disposition="NEEDS_WORK",
                                request_id=review_request_id + ":not-sent",
                                source_closure_hash=str(current.get("source_closure", {}).get("closure_hash") or ""),
                                reason="provider-slot-busy-before-send",
                                next_due_at=getattr(error, "sitina_retry_after", None),
                                attempt_count=max(0, candidate_attempt_count - 1),
                                provider_dispatch_facts={
                                    "dispatch_attempt_count": 0,
                                    "provider_send_count": 0,
                                    "provider_send_count_status": "exact",
                                    "provider_send_status": "not_sent",
                                    "uncertain_physical_send_attempt_count": 0,
                                    "response_received": False,
                                    "usage_known": False,
                                    "provider_usage": None,
                                },
                            )
                        facts = dispatch_facts or self._experience_provider_dispatch_facts(
                            error,
                            default_error_code="unclassified-provider-error",
                        )
                        if isinstance(error, ValueError) and dispatch_facts is not None and facts.get("error_code") is None:
                            facts = {**facts, "error_code": "provider-result-invalid"}
                        known_failure = (
                            not native_decision_started
                            and self._experience_dispatch_is_known_failure(facts)
                        )
                        return self.record_experience_candidate_disposition(
                            obligation_id,
                            candidate_id=candidate_id,
                            candidate_revision=candidate_revision,
                            disposition="FAILED_FINAL" if known_failure else "UNKNOWN",
                            request_id=review_request_id + ":unknown",
                            source_closure_hash=str(current.get("source_closure", {}).get("closure_hash") or ""),
                            reason=facts.get("error_code") or "unclassified-provider-error",
                            attempt_count=candidate_attempt_count,
                            provider_dispatch_facts=facts,
                        )
                    except TaskConflict:
                        return dict(current)
            raise

    def materialize_experience_candidates(
        self,
        obligation_id: str,
        *,
        memory_repository: Any,
        actor: str,
        acl: Any,
        owner_id: str,
        namespace: str,
    ) -> Mapping[str, str]:
        """Create/replay native candidates from a committed complete manifest."""
        with self._state_lock:
            obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                raise KeyError(obligation_id)
            if obligation.get("state") not in {"MANIFEST_RECORDED", "CANDIDATE_REVIEW"}:
                raise TaskConflict("experience manifest is not ready for candidate materialization")
            manifest_ref = str(obligation.get("manifest_ref") or "")
            manifest_hash = str(obligation.get("manifest_hash") or "")
            if not manifest_ref or not manifest_hash:
                raise PersistenceFenced("complete experience manifest has no CAS binding")
            manifest = self.context_memory.read(manifest_ref, expected_hash=manifest_hash)
            if manifest.get("schema") != "SITINA_EXPERIENCE_MANIFEST_V1" or manifest.get("status") != "COMPLETE":
                raise TaskConflict("only a complete experience manifest can materialize candidates")
            closure = dict(obligation.get("source_closure") or {})
            candidate_memory_ids = dict(obligation.get("candidate_memory_ids") or {})
            for candidate in manifest.get("candidates", ()):
                if not isinstance(candidate, Mapping):
                    raise PersistenceFenced("experience manifest candidate is malformed")
                candidate_id = str(candidate.get("candidate_id") or "")
                revision = str((obligation.get("candidate_revisions") or {}).get(candidate_id) or "")
                content = candidate.get("content")
                if not candidate_id or not revision or not isinstance(content, str):
                    raise PersistenceFenced("experience manifest candidate lacks stable content identity")
                memory_id = candidate_memory_ids.get(candidate_id)
                if memory_id is None:
                    memory_id = "memory-" + hashlib.sha256(
                        f"{obligation_id}\0{candidate_id}\0{revision}".encode("utf-8")
                    ).hexdigest()[:40]
                supersedes = tuple(sorted(str(item) for item in candidate.get("supersedes_memory_ids", ())))
                memory_content = content
                applicability_condition = candidate.get("applicability_condition")
                if isinstance(applicability_condition, str) and applicability_condition.strip():
                    # MemoryDocument intentionally has no new applicability field. Keep the
                    # reviewed condition in the recallable content instead of dropping it at
                    # the native materialization boundary.
                    marker = "Applicability condition: " + applicability_condition.strip()
                    if marker not in memory_content:
                        memory_content = memory_content + "\n\n" + marker
                    if len(memory_content.encode("utf-8")) > 256 * 1024:
                        raise PersistenceFenced("experience candidate applicability content exceeds memory budget")
                memory_repository.create_candidate(
                    memory_id=memory_id,
                    scope="project_shared",
                    owner_id=owner_id,
                    namespace=namespace,
                    content=memory_content,
                    source_event_ids=(str(closure.get("actual_envelope_event_id") or ""),),
                    source_run_ids=(str(closure.get("run_instance_id") or ""),),
                    evidence_refs=tuple(
                        sorted(
                            str(item)
                            for item in (closure.get("goal_ref"), closure.get("result_ref"))
                            if item
                        )
                    ),
                    confidence=self._experience_manifest_confidence(candidate),
                    sensitivity=str(candidate.get("sensitivity") or "low"),
                    valid_from=str(candidate.get("valid_from") or closure.get("terminal_occurred_at") or ""),
                    expires_at=candidate.get("expires_at"),
                    retention_policy=str(candidate.get("retention_policy") or "until-superseded"),
                    supersedes=supersedes,
                    acl=acl,
                    actor=actor,
                    tier="episodic",
                    source_trust="derived",
                    observed_at=str(candidate.get("observed_at") or closure.get("terminal_occurred_at") or ""),
                    conflict_key=(str(candidate.get("conflict_key")) if candidate.get("conflict_key") else None),
                )
                candidate_memory_ids[candidate_id] = memory_id
            self._append_experience_obligation_event(
                event_type="loop.experience-obligation-updated",
                payload={
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": "CANDIDATE_REVIEW",
                        "candidate_memory_ids": candidate_memory_ids,
                    },
                },
                request_id=f"experience-candidates:{obligation_id}:{manifest_hash}",
            )
            return dict(candidate_memory_ids)

    def commit_experience_candidate_memory_decision(
        self,
        obligation_id: str,
        **kwargs: Any,
    ) -> tuple[Any, ...]:
        """Commit a review decision while holding the coordinator state lock."""
        with self._state_lock:
            return self._commit_experience_candidate_memory_decision_locked(obligation_id, **kwargs)

    def _commit_experience_candidate_memory_decision_locked(
        self,
        obligation_id: str,
        *,
        memory_repository: Any,
        actor: str,
        decision_id: str,
        candidate_actions: Sequence[Mapping[str, Any]],
        review_request_id: str,
        provider_dispatch_facts: Mapping[str, Any] | None = None,
        review_reason: str | None = None,
    ) -> tuple[Any, ...]:
        """Bridge a reviewed manifest to native's one-event memory decision."""
        obligation = self._experience_obligation_projection().get(obligation_id)
        if obligation is None:
            raise KeyError(obligation_id)
        closure = dict(obligation.get("source_closure") or {})
        candidate_memory_ids = dict(obligation.get("candidate_memory_ids") or {})
        revisions = dict(obligation.get("candidate_revisions") or {})
        if obligation.get("review_request_id") != review_request_id:
            raise TaskConflict("review request is no longer the current candidate review")
        binding = obligation.get("review_memory_binding")
        if memory_repository is not None and not isinstance(binding, Mapping):
            raise TaskConflict("review candidate has no persisted native revision binding")
        normalized: list[dict[str, Any]] = []
        bound_revisions: dict[str, str] = {}
        for action in candidate_actions:
            candidate_id = str(action.get("candidate_id") or "")
            mapped_memory_id = str(candidate_memory_ids.get(candidate_id) or "")
            supplied_memory_id = str(action.get("memory_id") or "")
            if supplied_memory_id and mapped_memory_id and supplied_memory_id != mapped_memory_id:
                raise TaskConflict("review candidate memory binding conflicts with the manifest")
            memory_id = supplied_memory_id or mapped_memory_id
            if not candidate_id or not memory_id:
                raise TaskConflict("memory decision action is not bound to a manifest candidate")
            if str(obligation.get("review_candidate_id") or "") != candidate_id:
                raise TaskConflict("review candidate identity is stale")
            if str(obligation.get("review_candidate_revision") or "") != str(revisions.get(candidate_id) or ""):
                raise TaskConflict("review candidate revision is stale")
            normalized.append({
                **dict(action),
                "memory_id": memory_id,
                "expected_status": str(action.get("expected_status") or "candidate"),
            })
            bound_revisions[memory_id] = str(revisions.get(candidate_id) or "")
        # A replacement review is one native decision: accepted B and every
        # currently accepted root declared by B as superseded.  The old roots
        # are taken from the pre-dispatch binding, not re-resolved after the
        # provider returns.
        if memory_repository is not None:
            for item in tuple(normalized):
                if item.get("to_status") != "accepted":
                    continue
                document, _ = memory_repository.get(item["memory_id"], actor=actor, include_content=False)
                for old_id in document.supersedes:
                    if any(existing.get("memory_id") == old_id for existing in normalized):
                        continue
                    old_binding = (obligation.get("review_memory_binding") or {}).get("memories", {}).get(old_id)
                    if not isinstance(old_binding, Mapping):
                        raise TaskConflict("review replacement is missing its related native revision")
                    normalized.append({
                        "memory_id": old_id,
                        "expected_status": str(old_binding.get("status") or ""),
                        "to_status": "superseded",
                        "superseded_by": item["memory_id"],
                        "reason_code": "review-superseded",
                    })
                    bound_revisions[old_id] = (
                        "native-review:"
                        + str(old_binding.get("stream_version") or "")
                        + ":"
                        + str(old_binding.get("content_hash") or "")[:32]
                    )
        result = memory_repository.apply_memory_decision(
            decision_id=decision_id,
            source_closure=closure,
            candidate_actions=normalized,
            actor=actor,
            occurred_at=iso_now(),
            decision_kind="experience-review",
            review_request_id=review_request_id,
            candidate_revisions=bound_revisions,
            review_binding=binding,
        )
        for action in candidate_actions:
            candidate_id = str(action.get("candidate_id") or "")
            disposition = "PUBLISHED" if str(action.get("to_status")) == "accepted" else "REJECTED"
            self.record_experience_candidate_disposition(
                obligation_id,
                candidate_id=candidate_id,
                candidate_revision=revisions.get(candidate_id, ""),
                disposition=disposition,
                request_id=review_request_id + ":disposition:" + candidate_id,
                source_closure_hash=str(closure.get("closure_hash") or ""),
                reason=(
                    str(review_reason)
                    if review_reason is not None
                    else str(action.get("reason_code") or "native-decision")
                ),
                provider_dispatch_facts=provider_dispatch_facts,
            )
        return tuple(result)

    def materialize_episode_obligation(
        self,
        obligation_id: str,
        *,
        episode_repository: Any,
        lesson: str | None = None,
    ) -> Mapping[str, Any]:
        """Create/replay the factual episode from the terminal source closure."""
        with self._state_lock:
            obligation = self._experience_obligation_projection().get(obligation_id)
            if obligation is None:
                raise KeyError(obligation_id)
            if obligation.get("obligation_type") != "EPISODE":
                raise TaskConflict("obligation is not an episode fact")
            if obligation.get("state") in {"EPISODE_SETTLED", "SETTLED"}:
                return dict(obligation)
            closure = dict(obligation.get("source_closure") or {})
            goal_ref = self.store.cas.resolve_reference(str(closure.get("goal_ref") or ""))
            terminal_ref = self.store.cas.resolve_reference(str(closure.get("result_ref") or ""))
            status = str(closure.get("terminal_status") or "")
            outcome = {
                "SUCCEEDED": "succeeded",
                "FAILED": "failed",
                "CANCELLED": "cancelled",
            }.get(status)
            if outcome is None:
                raise TaskConflict("non-final terminal status cannot become an episode")
            terminal_result = self.store.read_json(str(closure["result_ref"]), expected_hash=str(closure["result_hash"]))
            if lesson is None:
                lesson = json.dumps(
                    terminal_result.get("final_result", terminal_result),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            episode_id = "episode-" + hashlib.sha256(obligation_id.encode("utf-8")).hexdigest()[:40]
            episode = episode_repository.create(
                episode_id=episode_id,
                source_run_id=str(closure.get("run_instance_id") or ""),
                goal_ref=goal_ref,
                action_event_range=(1, int(closure.get("terminal_event_position") or 0)),
                terminal_evidence_ref=terminal_ref,
                outcome=outcome,
                failure_reason_code=(str(terminal_result.get("final_result", {}).get("reason") or "terminal-failure") if outcome == "failed" else None),
                lesson=lesson,
                occurred_at=str(closure.get("terminal_occurred_at") or iso_now()),
                obligation_id=obligation_id,
                processor_version=str(closure.get("processor_version") or ""),
                terminal_event_id=str(closure.get("terminal_event_id") or ""),
                source_closure=closure,
                source_frontier=int(closure.get("terminal_event_position") or 0),
            )
            self._append_experience_obligation_event(
                event_type="loop.experience-obligation-updated",
                payload={
                    "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                    "obligation_id": obligation_id,
                    "patch": {
                        "state": "EPISODE_SETTLED",
                        "episode_id": episode.episode_id,
                        "episode_source_frontier": episode.source_frontier,
                    },
                },
                request_id=f"episode-settle:{obligation_id}",
            )
            return dict(self._experience_obligation_projection()[obligation_id])

    def propose_terminal(
        self,
        task_id: str,
        proposal: CompletionProposal,
        *,
        external_guard: Callable[[], bool] | None = None,
    ) -> TaskProjection:
        with self._state_lock:
            task = self.get_task(task_id)
            if task.terminal_event_id is not None:
                return task
            self._assert_current_executor(task)
            if not self.can_propose_terminal(task_id):
                raise TaskConflict("parent terminal is blocked by an active or unknown child delegation")
            self.validation.require_completion(task, proposal)
            managed_observations = self.stop_managed_processes(task_id, reason="native-terminal",
                retain_kept=proposal.terminal_status is TaskStatus.SUCCEEDED,
                require_completed=proposal.terminal_status is TaskStatus.SUCCEEDED)
            managed_refs: list[dict[str, Any]] = []
            managed_proofs = []
            for owner_id, observation in managed_observations.items():
                owner_receipt = self.context_memory.persist(
                    {
                        "schema": "SITINA_LOOP_COMMAND_RECOVERY_OBSERVATION_V1",
                        "task_id": task_id, "operation_id": owner_id,
                        "observation": _canonical_safe_audit(observation),
                    },
                    purpose="loop-command-recovery-observation",
                )
                managed_refs.append({
                    "operation_id": owner_id,
                    "observation_ref": owner_receipt.reference_id,
                    "observation_hash": owner_receipt.content_hash,
                })
                managed_proofs.append(owner_receipt.proof)
            terminal_document = {
                "schema": "SITINA_LOOP_TERMINAL_RESULT_V1",
                "managed_process_observations": managed_refs,
                "task_id": task_id,
                "proposal_id": proposal.proposal_id,
                "terminal_status": proposal.terminal_status.value,
                "artifact_ref": proposal.artifact_ref,
                "final_result": dict(proposal.final_result),
                "processor_version": proposal.processor_version,
                "obligation_types": list(proposal.obligation_types),
            }
            # Keep memory-view authorization, terminal CAS evidence, and the
            # conditional Journal append under state-lock -> Journal-lock.
            # Provider/model work has already completed before entering this
            # narrow commit section.
            with self.store.journal._mutex:
                if external_guard is not None and not external_guard():
                    raise StaleProposal("artifact content changed before terminal commit")
                stop_report = (
                    self._persist_stop_report(
                        task,
                        status=TaskStatus.CANCELLED,
                        blocker_id=str(proposal.final_result.get("reason") or "cancelled"),
                        reason=str(proposal.final_result.get("reason") or "task was cancelled"),
                        evidence_refs=tuple(
                            sorted(
                                str(reference)
                                for record in task.acceptances.values()
                                for reference in record.evidence_refs
                            )
                        ),
                    )
                    if proposal.terminal_status is TaskStatus.CANCELLED
                    else None
                )
                try:
                    stored = self.context_memory.persist(terminal_document, purpose="loop-terminal-result")
                except BaseException as error:
                    self._fail_persistence(error)
                    raise
                terminal_event_id = "task-terminal-" + hashlib.sha256(
                    (task_id + "\0" + proposal.proposal_id).encode("utf-8")
                ).hexdigest()[:40]
                try:
                    self._append(
                        task_id=task_id,
                        expected_stream_version=task.task_revision,
                        request_id=f"task-terminal:{task_id}:{proposal.proposal_id}",
                        command_type="loop.task.terminate",
                        event_type="loop.task-terminated",
                        payload={
                            "schema": "SITINA_LOOP_TASK_TERMINATED_V1",
                            "task_id": task_id,
                            "terminal_event_id": terminal_event_id,
                            "terminal_status": proposal.terminal_status.value,
                            "artifact_ref": proposal.artifact_ref,
                            "result_ref": stored.reference_id,
                            "result_hash": stored.content_hash,
                            "processor_version": proposal.processor_version,
                            "obligation_types": list(proposal.obligation_types),
                            "released_resources": list(task.owned_resources),
                            **(
                                {
                                    "stop_report_ref": stop_report.reference_id,
                                    "stop_report_hash": stop_report.content_hash,
                                }
                                if stop_report is not None
                                else {}
                            ),
                        },
                        proofs=(stored.proof, *((stop_report.proof,) if stop_report is not None else ()), *managed_proofs),
                    )
                except ExpectedStreamVersionConflict:
                    current = self.get_task(task_id)
                    if current.terminal_event_id is not None:
                        return current
                    raise
            return self.get_task(task_id)

    def _assert_current_executor(self, task: TaskProjection) -> None:
        self._require_persistence()
        if task.run_instance_id != self.run_instance_id:
            raise RecoveryNotConnected("task belongs to a prior run instance; recovery is not connected in batch 1a")
        if task.recovery_state not in {"READY_NEW_TASK", "READY_RECOVERED"}:
            raise RecoveryNotConnected("task is durably docked because full recovery is not connected")

    def _assert_control_owner(self, task: TaskProjection) -> None:
        """Authorize durable input admission independently of worker epoch."""

        self._require_persistence()
        if task.is_terminal:
            raise TaskConflict("new work after a terminal task requires a related new task")

    def _managed_control_resource(self, task: TaskProjection, intent: OperationIntent) -> str | None:
        """Authenticate one control record without granting general state writes."""
        process_id = intent.controlled_process_id
        if process_id is None:
            return None
        if intent.mode is not OperationMode.WRITE or not intent.operation_id.startswith("managed-control-"):
            raise OperationRejected("process binding is only valid for managed control writes")
        process = task.operations.get(process_id)
        if process is None:
            raise OperationRejected("controlled process has no launch in this task")
        if intent.execution_owner and process.execution_owner != intent.execution_owner:
            raise OperationRejected("controlled process belongs to another execution owner")
        evidence = self.managed_process_evidence(task.task_id).get(process_id)
        if not isinstance(evidence, Mapping):
            raise OperationRejected("controlled process lacks authenticated launch evidence")
        if "execution_owner" in evidence and evidence["execution_owner"] != process.execution_owner:
            raise OperationRejected("controlled process evidence owner differs from its launch")
        path = evidence.get("command_manifest_path")
        if not isinstance(path, str) or not path or not Path(path).is_absolute():
            raise OperationRejected("controlled process has no exact control resource")
        resource = str(Path(path).resolve(strict=False))
        expected = {resource}
        if intent.execution_owner:
            if not process.resources and process.mode is not OperationMode.READ:
                raise OperationRejected("controlled process lacks its business write resources")
            expected.update(process.resources)
        if intent.resources != tuple(sorted(expected)):
            raise OperationRejected("managed control resources differ from its authenticated launch")
        return resource

    def _assert_intent_current(self, task: TaskProjection, intent: OperationIntent) -> None:
        self._assert_current_executor(task)
        if task.is_terminal:
            raise OperationRejected("terminal task cannot dispatch a new operation")
        if task.received_input_seq != task.handled_input_seq:
            raise OperationRejected("persisted input remains unhandled")
        if task.control_intent is not ControlIntent.RUN:
            raise OperationRejected("current control intent blocks business dispatch")
        if intent.mode is OperationMode.WRITE and any(
            operation.mode is OperationMode.WRITE and any(
                resources_conflict(left, right) for left in intent.resources for right in operation.resources
            ) for operation in task.unresolved_effects
        ):
            raise OperationRejected("requested resource has an unresolved operation effect")
        control_resource = self._managed_control_resource(task, intent)
        if intent.execution_owner:
            if not self.child_execution_current(task.task_id, intent.execution_owner):
                raise OperationRejected("child execution ownership was revoked or superseded")
            child = task.child_delegations[intent.execution_owner]
            if intent.mode is OperationMode.WRITE:
                if not set(child.get("permissions", ())) & {"write", "shell", "external_service"}:
                    raise OperationRejected("child has no mutation authority")
                for path in intent.resources:
                    if path == control_resource:
                        continue
                    if not any(path == root or Path(root) in Path(path).parents for root in child.get("resources", ())):
                        raise OperationRejected("operation is outside child resource ownership: " + path)
        if intent.mode is OperationMode.WRITE:
            for child in task.child_delegations.values():
                if child.get("delegation_id") == intent.execution_owner:
                    continue
                if child.get("status") in {"RUNNING", "CANCEL_REQUESTED", "RESULT_PERSISTED"} or child.get("unknown_effect"):
                    if any(resources_conflict(left, right) for left in intent.resources for right in child.get("resources", ())):
                        raise OperationRejected("resource belongs to work item: " + str(child.get("problem_id")))
        expected = {
            "task_revision": intent.expected_task_revision,
            "run_instance_id": intent.expected_run_instance_id,
            "execution_epoch": intent.expected_execution_epoch,
            "goal_version": intent.expected_goal_version,
            "acceptance_version": intent.expected_acceptance_version,
            "handled_input_seq": intent.expected_handled_input_seq,
            "capability_snapshot_id": intent.capability_snapshot_id,
        }
        actual = {
            "task_revision": task.task_revision,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": task.execution_epoch,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "handled_input_seq": task.handled_input_seq,
            "capability_snapshot_id": task.capability_snapshot_id,
        }
        # Sibling actions advance the stream while semantic versions remain fixed.
        if (intent.execution_owner or any(item.get("execution_mode") == "task" for item in task.child_delegations.values())) and intent.expected_task_revision <= task.task_revision:
            expected.pop("task_revision")
            actual.pop("task_revision")
        changed = [name for name in expected if expected[name] != actual[name]]
        if changed:
            raise OperationRejected("operation binding changed after authorization: " + ", ".join(changed))

    def _assert_resources_available(self, task_id: str, requested: tuple[str, ...]) -> None:
        for owner_task_id in self.store.task_ids():
            if owner_task_id == task_id:
                continue
            owner = self._project(owner_task_id, self.store.task_events(owner_task_id))
            conflicts = [
                (candidate, held)
                for candidate in requested
                for held in owner.owned_resources
                if resources_conflict(candidate, held)
            ]
            if conflicts:
                raise OperationRejected(
                    "business resource remains owned by another task: "
                    + owner_task_id
                    + " ("
                    + ", ".join(f"{candidate} conflicts with {held}" for candidate, held in conflicts)
                    + ")"
                )

    def _project(self, task_id: str, events: tuple[EventEnvelope, ...]) -> TaskProjection:
        if not events:
            raise KeyError(task_id)
        created = events[0]
        if created.event_type != "loop.task-created" or created.payload.get("spec_version") != SPEC_VERSION:
            raise PersistenceFenced("task stream does not begin with the current r4 creation event")
        payload = created.payload
        memory_view_ref = str(payload["memory_view_ref"]) if payload.get("memory_view_ref") else None
        memory_view_hash = str(payload["memory_view_hash"]) if payload.get("memory_view_hash") else None
        memory_view_ids: tuple[str, ...] = ()
        memory_view_versions: tuple[tuple[str, int], ...] = ()
        memory_view_reasons: tuple[str, ...] = ()
        if (memory_view_ref is None) != (memory_view_hash is None):
            raise PersistenceFenced("task memory view binding is incomplete")
        if memory_view_ref is not None:
            view = self.context_memory.read(memory_view_ref, expected_hash=memory_view_hash)
            if view.get("schema") != "SITINA_LOOP_MEMORY_VIEW_V1" or view.get("task_id") != task_id:
                raise PersistenceFenced("task memory view reference has an invalid binding")
            selected_ids = view.get("selected_memory_ids", ())
            selected_versions = view.get("selected_memory_versions", {})
            reasons = view.get("selection_reasons", ())
            if (
                not isinstance(selected_ids, list)
                or not isinstance(selected_versions, Mapping)
                or not isinstance(reasons, list)
                or any(not isinstance(item, str) or not item for item in selected_ids)
                or any(not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool) or value < 1 for key, value in selected_versions.items())
            ):
                raise PersistenceFenced("task memory view document is malformed")
            memory_view_ids = tuple(sorted(str(item) for item in selected_ids))
            memory_view_versions = tuple(sorted((str(key), int(value)) for key, value in selected_versions.items()))
            memory_view_reasons = tuple(str(item) for item in reasons)
        task = TaskProjection(
            task_id=task_id,
            session_id=str(payload["session_id"]),
            task_kind=str(payload["task_kind"]),
            spec_version=str(payload["spec_version"]),
            run_instance_id=str(payload["run_instance_id"]),
            execution_epoch=int(payload["execution_epoch"]),
            task_revision=created.stream_version,
            stream_frontier=created.position,
            goal_version=int(payload["goal_version"]),
            acceptance_version=int(payload["acceptance_version"]),
            criteria_lineage_version=int(payload.get("criteria_lineage_version", 1)),
            artifact_version=int(payload.get("artifact_version", 1)),
            artifact_ref=str(payload["artifact_ref"]),
            environment_ref=str(payload["environment_ref"]),
            capability_snapshot_id=str(payload["capability_snapshot_id"]),
            received_input_seq=int(payload["received_input_seq"]),
            handled_input_seq=int(payload["handled_input_seq"]),
            control_intent=ControlIntent(str(payload["control_intent"])),
            status=TaskStatus(str(payload["status"])),
            required_outcome_ids=tuple(str(item) for item in payload["required_outcome_ids"]),
            goal_ref=str(payload["goal_ref"]),
            recovery_state=str(payload["recovery_state"]),
            submission_id=(str(payload["submission_id"]) if payload.get("submission_id") is not None else None),
            request_fingerprint=(
                str(payload["request_fingerprint"])
                if payload.get("request_fingerprint") is not None
                else None
            ),
            request_ref=(str(payload["request_ref"]) if payload.get("request_ref") is not None else None),
            request_hash=(str(payload["request_hash"]) if payload.get("request_hash") is not None else None),
            descriptor_ref=(
                str(payload["descriptor_ref"]) if payload.get("descriptor_ref") is not None else None
            ),
            descriptor_hash=(
                str(payload["descriptor_hash"]) if payload.get("descriptor_hash") is not None else None
            ),
            resume_request_id=(
                str(payload["resume_request_id"]) if payload.get("resume_request_id") is not None else None
            ),
            child_delegations={},
            memory_view_ref=memory_view_ref,
            memory_view_hash=memory_view_hash,
            memory_view_ids=memory_view_ids,
            memory_view_versions=memory_view_versions,
            memory_view_reasons=memory_view_reasons,
            memory_view_revalidation_ref=None,
            memory_view_revalidation_hash=None,
            memory_view_revalidation_input_seq=None,
            memory_view_exclusions=(),
        )
        if "artifact_hash" in payload:
            self.context_memory.read(
                str(payload["artifact_ref"]), expected_hash=str(payload["artifact_hash"])
            )
        if payload.get("request_ref") and payload.get("request_hash"):
            request = self.context_memory.read(
                str(payload["request_ref"]), expected_hash=str(payload["request_hash"])
            )
            if request.get("schema") != "SITINA_LOOP_SUBMISSION_INTENT_V1":
                raise PersistenceFenced("task request reference has an invalid schema")
            if request.get("fingerprint") != payload.get("request_fingerprint"):
                raise PersistenceFenced("task request fingerprint does not match its content")
        if payload.get("descriptor_ref") and payload.get("descriptor_hash"):
            descriptor = self.context_memory.read(
                str(payload["descriptor_ref"]), expected_hash=str(payload["descriptor_hash"])
            )
            if descriptor.get("schema") != "SITINA_LOOP_RUN_DESCRIPTOR_V1":
                raise PersistenceFenced("task descriptor reference has an invalid schema")
            required_descriptor_fields = (
                "submission_id", "task_kind", "spec_version", "termination_contract_version",
                "continuity_contract_version", "goal_ref", "goal_hash", "initial_artifact", "workspace",
                "acceptance", "provider_identity", "provider_profile", "capability_snapshot_id",
                "environment_ref", "authorization", "allowed_roots", "software_identity",
                "config_identity", "protocol_versions",
            )
            if any(field not in descriptor for field in required_descriptor_fields):
                raise PersistenceFenced("task descriptor is missing required fields")
            if (
                descriptor.get("task_id") != task_id
                or descriptor.get("submission_id") != payload.get("submission_id")
                or descriptor.get("task_kind") != payload.get("task_kind")
                or descriptor.get("goal_ref") != payload.get("goal_ref")
                or descriptor.get("goal_hash") != payload.get("goal_hash")
                or descriptor.get("initial_artifact", {}).get("reference") != payload.get("artifact_ref")
                or descriptor.get("initial_artifact", {}).get("hash") != payload.get("artifact_hash")
                or descriptor.get("environment_ref") != payload.get("environment_ref")
                or descriptor.get("capability_snapshot_id") != payload.get("capability_snapshot_id")
            ):
                raise PersistenceFenced("task descriptor is not bound to task creation")
        # Cold replay and hot incremental updates deliberately share the exact
        # same event reducer. Any invariant failure removes the disposable
        # cache and leaves Journal/CAS as the sole recovery authority.
        self._task_cache[task_id] = copy.deepcopy(task)
        for event in events[1:]:
            self._advance_task_cache(event, copy_before_apply=False)
            if task_id not in self._task_cache:
                raise PersistenceFenced("task projection cache reducer rejected a committed event")
        return copy.deepcopy(self._task_cache[task_id])
    def prepare_managed_process_handoff(self) -> tuple[str, ...]:
        """Check durable owners without revoking authority or stopping work."""
        active = tuple(sorted(self.store.task_ids()))
        for task_id in active:
            task = self.get_task(task_id)
            if task.control_intent is ControlIntent.CANCEL:
                continue
            for operation_id, evidence in self.managed_process_evidence(task_id).items():
                if evidence.get("execution_contract") != TASK_EXECUTION_CONTRACT:
                    continue
                owner = evidence.get("execution_owner")
                if owner and not self.child_execution_current(task_id, str(owner)):
                    continue
                observation = observe_managed_command(evidence, task_id=task_id, operation_id=operation_id)
                if observation.get("decision") not in {"RUNNING", "SUCCEEDED", "NO_EFFECT"}:
                    raise ManagedCommandUnsettled("planned handoff cannot verify original execution: " + operation_id)
        return active

    def close(self, *, preserve_running: bool = False, handoff_current=None) -> None:
        """Destroy by default; planned handoff preserves verified authorized execution."""
        errors: list[BaseException] = []
        active = (self.prepare_managed_process_handoff() if preserve_running else
                  tuple(sorted(getattr(self, "_managed_process_task_ids", ()))))
        reason = "native-backend-handoff" if preserve_running else "native-backend-drain"
        for task_id in active:
            try:
                self.stop_managed_processes(task_id, reason=reason, preserve_running=preserve_running)
            except BaseException as error:
                errors.append(error)
        # This is the final handoff decision, before relinquishing store ownership.
        # A normal-exit request received during inspection still drains original work.
        if preserve_running and handoff_current is not None and not handoff_current():
            self.close()
            return
        if errors and preserve_running:
            raise errors[0]
        if hasattr(self, "_managed_process_task_ids"):
            self._managed_process_task_ids.clear()
        self.store.close()
        if errors:
            raise errors[0]

    def __enter__(self) -> "LoopBackend":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()
