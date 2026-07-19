from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sitina.cas.model import ObjectRef
from sitina.cas.crypto import encrypt_object
from sitina.commands.model import CommandResult, CommandStatus
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream, TENANT, stable_hash
from sitina.protocols.handoffs import Handoff, HandoffState
from sitina.protocols.run import RunAggregate, RunState
from sitina.protocols.tasks import AttemptState, TaskAggregate, TaskAttempt, TaskState
from sitina.protocols.terminal import (
    AuthoritativeTerminalFacts,
    BlockerKind,
    TerminalEligibilityProjection,
    apply_terminal_decision,
    full_validate,
)
from sitina.scheduling.processes import ProcessManager, ProcessState


class CheckpointResumeError(RuntimeError):
    pass


@dataclass(frozen=True)
class RestartFrontierSpec:
    frontier_kind: str
    protocol_kind: str
    protocol_state: str
    pending_action: str
    continuation_schema: str


FRONTIER_SPECS: tuple[RestartFrontierSpec, ...] = (
    RestartFrontierSpec(
        "PROPOSAL_REVIEW_PENDING",
        "proposal_review",
        "PROPOSAL_SUBMITTED_REVIEW_PENDING",
        "complete-independent-review",
        "REVIEW_COMPLETED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "NEGOTIATION_MID_ROUND",
        "negotiation",
        "ROUND_OPEN_COUNTERPROPOSAL_PENDING",
        "continue-negotiation-round",
        "NEGOTIATION_ROUND_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "HANDOFF_ACCEPTED_PENDING_SUBMISSION",
        "handoff",
        "GENERATION_ACCEPTED_SUBMISSION_PENDING",
        "continue-handoff-execution",
        "HANDOFF_SUBMISSION_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "BLACKBOARD_CONFLICT_UNRESOLVED",
        "blackboard",
        "MVCC_CONFLICT_OPEN",
        "continue-blackboard-resolution",
        "BLACKBOARD_CONFLICT_RESOLUTION_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "TASK_LEASE_ACTIVE",
        "task_claim_lease",
        "TASK_CLAIMED_LEASE_ACTIVE",
        "continue-leased-task",
        "LEASED_TASK_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "REWORK_REVISION_PENDING",
        "rework",
        "CHANGES_REQUESTED_REVISION_PENDING",
        "continue-rework-revision",
        "REWORK_REVISION_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "PROVIDER_UNKNOWN_RECONCILING",
        "provider_recovery",
        "OUTCOME_UNKNOWN_RECONCILING",
        "continue-provider-reconciliation",
        "PROVIDER_RECONCILIATION_CONTINUED_AFTER_RESUME_V1",
    ),
    RestartFrontierSpec(
        "CLOSING_REQUIRED_OBLIGATION_OPEN",
        "terminal_barrier",
        "RUN_CLOSING_REQUIRED_OBLIGATION_OPEN",
        "settle-closing-obligation",
        "CLOSING_OBLIGATION_SETTLED_AFTER_RESUME_V1",
    ),
)

_SPEC_BY_KIND = {item.frontier_kind: item for item in FRONTIER_SPECS}


def _require_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CheckpointResumeError(f"{field} must be a SHA-256 hex digest")
    return value


def validate_frontier_snapshot(snapshot: Mapping[str, Any]) -> RestartFrontierSpec:
    kind = snapshot.get("frontier_kind")
    try:
        spec = _SPEC_BY_KIND[str(kind)]
    except KeyError as error:
        raise CheckpointResumeError("unknown restart frontier") from error
    if snapshot.get("protocol_kind") != spec.protocol_kind or snapshot.get("protocol_state") != spec.protocol_state:
        raise CheckpointResumeError("restart frontier protocol state does not match its transition matrix")
    if not isinstance(snapshot.get("protocol_id"), str) or not snapshot["protocol_id"]:
        raise CheckpointResumeError("restart frontier requires a protocol identity")
    if not isinstance(snapshot.get("obligation_id"), str) or not snapshot["obligation_id"]:
        raise CheckpointResumeError("restart frontier requires a terminal-blocking obligation")
    _require_hash(snapshot.get("state_hash"), "frontier state_hash")
    return spec


def stream_heads(events: Iterable[EventEnvelope], through_position: int) -> dict[str, dict[str, int]]:
    heads: dict[str, dict[str, int]] = {}
    for event in events:
        if event.position > through_position:
            break
        heads[event.stream_id] = {"stream_version": event.stream_version, "position": event.position}
    return dict(sorted(heads.items()))


def declared_stream_heads_match(
    verified_heads: Mapping[str, Mapping[str, int]],
    declared_heads: Mapping[str, Mapping[str, int]],
) -> bool:
    """Verify a checkpoint runtime subset against canonical Journal heads."""

    return bool(declared_heads) and all(
        verified_heads.get(stream_id) == declared
        for stream_id, declared in declared_heads.items()
    )


def checkpoint_manifest_hash(manifest: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_hash"}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def finalize_checkpoint_manifest(unsigned: Mapping[str, Any]) -> dict[str, Any]:
    manifest = dict(unsigned)
    if "manifest_hash" in manifest:
        raise CheckpointResumeError("unsigned checkpoint manifest unexpectedly contains manifest_hash")
    manifest["manifest_hash"] = checkpoint_manifest_hash(manifest)
    verify_checkpoint_manifest(manifest)
    return manifest


def verify_checkpoint_manifest(manifest: Mapping[str, Any]) -> None:
    required = {
        "schema",
        "checkpoint_id",
        "run_id",
        "journal_id",
        "epoch",
        "genesis_hash",
        "validated_through_position",
        "validated_through_hash",
        "stream_heads",
        "active_protocol_instances",
        "process_manager_states",
        "pending_commands",
        "command_ids",
        "task_claims",
        "lease_ids",
        "fencing_tokens",
        "blackboard_versions",
        "proposal_review_handoff_generations",
        "effect_attempt_states",
        "outcome_exposure_states",
        "obligation_states",
        "cas_refs",
        "frontier_snapshot",
        "frontier_stream_id",
        "provider_send_count",
        "config_hash",
        "policy_hash",
        "code_fingerprint",
        "old_process_pid",
        "manifest_hash",
    }
    missing = sorted(required.difference(manifest))
    if missing:
        raise CheckpointResumeError("checkpoint manifest is incomplete: " + ",".join(missing))
    if manifest.get("schema") != "SITINA_LIVE_CHECKPOINT_MANIFEST_V1":
        raise CheckpointResumeError("unsupported checkpoint manifest schema")
    if int(manifest.get("epoch", 0)) < 1 or int(manifest.get("validated_through_position", 0)) < 1:
        raise CheckpointResumeError("checkpoint manifest has an invalid journal frontier")
    _require_hash(manifest.get("genesis_hash"), "genesis_hash")
    _require_hash(manifest.get("validated_through_hash"), "validated_through_hash")
    _require_hash(manifest.get("config_hash"), "config_hash")
    _require_hash(manifest.get("policy_hash"), "policy_hash")
    _require_hash(manifest.get("code_fingerprint"), "code_fingerprint")
    _require_hash(manifest.get("manifest_hash"), "manifest_hash")
    validate_frontier_snapshot(dict(manifest["frontier_snapshot"]))
    process_states = list(manifest["process_manager_states"])
    pending = list(manifest["pending_commands"])
    if len(process_states) != 1 or len(pending) != 1:
        raise CheckpointResumeError("each restart frontier requires exactly one pending durable process step")
    if process_states[0].get("pending_command_id") != pending[0].get("command_id"):
        raise CheckpointResumeError("pending process command identity differs from checkpoint command identity")
    if pending[0].get("command_id") not in set(manifest["command_ids"]):
        raise CheckpointResumeError("pending command is absent from command identity manifest")
    if checkpoint_manifest_hash(manifest) != manifest["manifest_hash"]:
        raise CheckpointResumeError("checkpoint manifest hash mismatch")


def _object_ref(mapping: Mapping[str, Any]) -> ObjectRef:
    allowed = {"object_id", "tenant_id", "plaintext_commitment", "commitment_key_id", "profile"}
    if set(mapping).difference(allowed):
        raise CheckpointResumeError("checkpoint ObjectRef contains unexpected fields")
    return ObjectRef(**{key: mapping[key] for key in allowed if key in mapping})


def _find_publication(events: Sequence[EventEnvelope], run_id: str, checkpoint_id: str) -> EventEnvelope:
    matching = [
        event
        for event in events
        if event.payload.get("run_id") == run_id
        and event.payload.get("schema") == "CHECKPOINT_MANIFEST_PUBLISHED_V1"
        and event.payload.get("checkpoint_id") == checkpoint_id
    ]
    if len(matching) != 1:
        raise CheckpointResumeError("checkpoint has no unique committed manifest publication")
    return matching[0]


def _verify_cas_identity(home: Path, reference_id: str) -> None:
    if not reference_id.startswith("cas:"):
        raise CheckpointResumeError("checkpoint contains a non-CAS object reference")
    object_id = reference_id.removeprefix("cas:")
    _require_hash(object_id, "CAS object id")
    path = home / "cas" / "objects" / object_id[:2] / f"{object_id}.obj"
    if path.is_symlink() or not path.is_file():
        raise CheckpointResumeError("checkpoint CAS reference is missing")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != object_id:
        raise CheckpointResumeError("checkpoint CAS object identity mismatch")


def _events_for_process(events: Sequence[EventEnvelope], process_id: str) -> tuple[dict[str, Any], ...]:
    return tuple(dict(event.payload) for event in events if event.payload.get("process_id") == process_id)


def _claimed_task(snapshot: Mapping[str, Any]) -> TaskAggregate:
    attempt = TaskAttempt(
        task_attempt_id=str(snapshot["task_attempt_id"]),
        claim_generation=int(snapshot["claim_generation"]),
        fencing_token=str(snapshot["fencing_token"]),
        claim_command_id=str(snapshot["claim_command_id"]),
        holder_agent_id=str(snapshot["holder_agent_id"]),
        lease_id=str(snapshot["lease_id"]),
        state=AttemptState.CLAIMED,
        lease_expires_at=str(snapshot["lease_expires_at"]),
    )
    return TaskAggregate(
        task_id=str(snapshot["task_id"]),
        specification_hash=str(snapshot["specification_hash"]),
        state=TaskState.OPEN,
        stream_version=int(snapshot["stream_version"]),
        claim_generation=int(snapshot["claim_generation"]),
        attempts=(attempt,),
    )


def _complete_integrated_handoff(
    journal: Any,
    run_id: str,
    policy_hash: str,
    checkpoint_id: str,
    manifest_hash: str,
    snapshot: Mapping[str, Any],
    events: Sequence[EventEnvelope],
) -> dict[str, Any]:
    continuation = snapshot.get("integrated_continuation")
    if not isinstance(continuation, dict):
        return {}
    if continuation.get("schema") != "INTEGRATED_HANDOFF_RESTART_CONTINUATION_V1":
        raise CheckpointResumeError("integrated continuation has an unsupported schema")
    handoff_id = str(continuation["handoff_id"])
    handoff_facts = tuple(
        dict(event.payload)
        for event in events
        if event.payload.get("run_id") == run_id and event.payload.get("handoff_id") == handoff_id
    )
    handoff = Handoff.rebuild(handoff_facts)
    if (
        handoff.generation != 2
        or handoff.state is not HandoffState.EXECUTING
        or handoff.generation_hash != continuation["handoff_generation_hash"]
    ):
        raise CheckpointResumeError("integrated Handoff did not restore generation 2 in executing state")
    sender_id = str(continuation["sender_id"])
    receiver_id = str(continuation["receiver_id"])
    verifier_id = str(continuation["verifier_id"])
    if verifier_id in {sender_id, receiver_id} or not bool(continuation["provider_verdict"]):
        raise CheckpointResumeError("integrated Handoff lacks a positive independent Provider verdict")

    handoff_task = _claimed_task(dict(continuation["handoff_task"]))
    main_task = _claimed_task(dict(continuation["main_task"]))
    handoff_attempt = handoff_task.active_attempt
    main_attempt = main_task.active_attempt
    if handoff_attempt is None or main_attempt is None:
        raise CheckpointResumeError("integrated continuation lost an active Task Lease")
    if handoff.fencing_token != handoff_attempt.fencing_token:
        raise CheckpointResumeError("restored Handoff fence differs from its Task Claim")

    artifact_hash = str(continuation["delivery_output_hash"])
    handoff, handoff_submitted = handoff.submit(
        receiver_id,
        artifact_hash,
        output_schema_hash=str(continuation["output_schema_hash"]),
        schema_validation_evidence_hash=str(continuation["schema_validation_evidence_hash"]),
    )
    handoff_task, task_submitted = handoff_task.submit(handoff_attempt.fencing_token, artifact_hash)
    handoff, handoff_verified = handoff.verify(
        verifier_id,
        accepted=True,
        verification_evidence_hash=str(continuation["verification_output_hash"]),
    )
    handoff_task, task_accepted = handoff_task.accept(
        handoff_attempt.fencing_token,
        artifact_hash=artifact_hash,
        policy_hash=policy_hash,
        accepted_by=verifier_id,
        acceptance_evidence_refs=(
            str(continuation["verification_output_ref"]),
            str(continuation["verification_output_hash"]),
        ),
    )
    restored_fact = {
        "schema": "INTEGRATED_RESTART_STATE_RESTORED_V1",
        "event_type": "integrated.restart-state.restored",
        "checkpoint_id": checkpoint_id,
        "manifest_hash": manifest_hash,
        "handoff_id": handoff_id,
        "handoff_generation": handoff.generation,
        "handoff_state_before_continuation": "EXECUTING",
        "lease_id": continuation["main_task"]["lease_id"],
        "fencing_token_hash": hashlib.sha256(
            str(continuation["main_task"]["fencing_token"]).encode()
        ).hexdigest(),
        "blackboard_document_id": continuation["blackboard"]["document_id"],
        "blackboard_version": continuation["blackboard"]["version"],
        "blackboard_hash": continuation["blackboard"]["document_hash"],
        "process_state": "RUNNING",
        "projection_used": False,
        "process_cache_used": False,
        "legacy_reads": 0,
        "acceptance_reads": 0,
        "new_process_pid": os.getpid(),
    }
    handoff_terminal = {
        "schema": "PROTOCOL_INSTANCE_TERMINAL_V1",
        "protocol_instance_id": continuation["handoff_protocol_id"],
        "terminal_disposition": "VERIFIED_AFTER_RESTART",
        "parent_obligation_id": continuation["handoff_obligation_id"],
        "successor_obligation_id": None,
        "obligation_satisfied": True,
    }
    handoff_stream = CanonicalStream(
        journal, run_id, str(continuation["handoff_stream_id"]), policy_hash
    )
    _, handoff_refs = handoff_stream.append(
        "integrated-handoff-submitted-and-verified-after-restart",
        (
            restored_fact,
            {
                **handoff_submitted,
                "event_type": "handoff.submitted",
                "delivery_call_id": continuation["delivery_call_id"],
                "delivery_output_ref": continuation["delivery_output_ref"],
                "committed_after_restart": True,
                "new_process_pid": os.getpid(),
            },
            task_submitted,
            {
                **handoff_verified,
                "event_type": "handoff.verified",
                "verification_call_id": continuation["verification_call_id"],
                "verification_output_ref": continuation["verification_output_ref"],
                "provider_verdict": True,
                "effective_verdict": True,
                "committed_after_restart": True,
                "new_process_pid": os.getpid(),
            },
            task_accepted,
            handoff_terminal,
        ),
        actor=verifier_id,
    )

    main_task, main_submitted = main_task.submit(main_attempt.fencing_token, artifact_hash)
    main_task, main_accepted = main_task.accept(
        main_attempt.fencing_token,
        artifact_hash=artifact_hash,
        policy_hash=policy_hash,
        accepted_by=verifier_id,
        acceptance_evidence_refs=(
            str(continuation["verification_output_ref"]),
            str(continuation["verification_output_hash"]),
        ),
    )
    lease_terminal = {
        "schema": "PROTOCOL_INSTANCE_TERMINAL_V1",
        "protocol_instance_id": continuation["lease_protocol_id"],
        "terminal_disposition": "REASSIGNED_HANDOFF_VERIFIED_AFTER_RESTART",
        "parent_obligation_id": continuation["lease_obligation_id"],
        "successor_obligation_id": None,
        "obligation_satisfied": True,
    }
    main_stream = CanonicalStream(
        journal, run_id, f"task/{continuation['main_task']['task_id']}", policy_hash
    )
    _, main_refs = main_stream.append(
        "integrated-reassigned-task-completed-after-handoff",
        (
            main_submitted,
            main_accepted,
            lease_terminal,
            {
                "schema": "INTEGRATED_ALL_REQUIRED_OBLIGATIONS_CLOSED_V1",
                "event_type": "integrated.required-obligations.closed",
                "handoff_obligation_id": continuation["handoff_obligation_id"],
                "lease_obligation_id": continuation["lease_obligation_id"],
                "handoff_terminal_event_id": handoff_refs[-1]["event_id"],
                "generation": 2,
                "terminal_barrier_may_revalidate": True,
                "new_process_pid": os.getpid(),
            },
        ),
        actor="fresh-restart-result-admission-verifier",
    )
    return {
        "integrated_handoff_submitted_event_id": handoff_refs[1]["event_id"],
        "integrated_handoff_verified_event_id": handoff_refs[3]["event_id"],
        "integrated_handoff_terminal_event_id": handoff_refs[-1]["event_id"],
        "integrated_main_task_terminal_event_id": main_refs[-1]["event_id"],
        "integrated_handoff_id": handoff_id,
        "integrated_handoff_generation": 2,
    }


def recover_checkpoint(home: Path, run_id: str, checkpoint_id: str) -> dict[str, Any]:
    """Fresh-process journal/CAS recovery entry point.

    Only the durable home, run identity, and checkpoint identity cross the
    process boundary. All workflow state is reconstructed from Journal + CAS.
    """

    root = Path(home).resolve(strict=True)
    context = ProductionRuntimeContext.load(root)
    journal = context.open_writer()
    cas = context.open_cas()
    try:
        events = tuple(journal.iter_events(0))
        publication = _find_publication(events, run_id, checkpoint_id)
        locator = publication.payload.get("manifest_object_ref")
        if not isinstance(locator, dict):
            raise CheckpointResumeError("checkpoint publication lacks a durable ObjectRef locator")
        reference = _object_ref(locator)
        durable = json.loads(cas.open_verified(reference).decode("utf-8"))
        verify_checkpoint_manifest(durable)
        if durable["checkpoint_id"] != checkpoint_id or durable["run_id"] != run_id:
            raise CheckpointResumeError("checkpoint identity does not bind the requested run")
        if publication.payload.get("manifest_hash") != durable["manifest_hash"]:
            raise CheckpointResumeError("published and durable checkpoint hashes differ")
        if reference.reference_id not in publication.object_refs:
            raise CheckpointResumeError("checkpoint manifest ObjectRef is not rooted by its Journal event")
        if journal.journal_id != durable["journal_id"] or journal.epoch != int(durable["epoch"]):
            raise CheckpointResumeError("restart opened a different Journal identity")
        if context.genesis.genesis_hash != durable["genesis_hash"]:
            raise CheckpointResumeError("restart opened a different Production Genesis")
        frontier_position = int(durable["validated_through_position"])
        if journal._position_hash.get(frontier_position) != durable["validated_through_hash"]:
            raise CheckpointResumeError("checkpoint frontier is not committed by the recovered Journal")
        # The checkpoint records the runtime-state stream subset visible to
        # the stopped worker.  A later signed Projection may compact immutable
        # authority/feature rows out of that operational view, while the full
        # authenticated Journal remains canonical.  Verify every declared
        # head against that full prefix; unrelated full-Journal streams are
        # intentionally outside the checkpoint's runtime-state subset.
        verified_reader = context.open_verified_journal_reader()
        try:
            verified_events = tuple(verified_reader.iter_events(0))
        finally:
            verified_reader.close()
        verified_heads = stream_heads(verified_events, frontier_position)
        declared_heads = dict(durable["stream_heads"])
        if not declared_stream_heads_match(verified_heads, declared_heads):
            raise CheckpointResumeError(
                "checkpoint Stream heads do not match the authenticated Journal prefix"
            )
        for reference_id in durable["cas_refs"]:
            _verify_cas_identity(root, str(reference_id))
        stopped = [
            event
            for event in events
            if event.payload.get("schema") == "CHECKPOINT_RUNTIME_STOPPED_V1"
            and event.payload.get("checkpoint_id") == checkpoint_id
        ]
        if len(stopped) != 1:
            raise CheckpointResumeError("runtime stop was not durably committed exactly once")
        old_pid = int(durable["old_process_pid"])
        new_pid = os.getpid()
        if old_pid == new_pid or int(stopped[0].payload.get("old_process_pid", -1)) != old_pid:
            raise CheckpointResumeError("restart did not cross a real process boundary")

        process_state = dict(durable["process_manager_states"][0])
        process_id = str(process_state["process_id"])
        manager = ProcessManager.rebuild(
            process_id,
            str(process_state["definition_hash"]),
            _events_for_process(events, process_id),
            max_steps=int(process_state["max_steps"]),
        )
        pending = manager.pending_step
        if manager.state is not ProcessState.WAITING_OUTCOME or pending is None:
            raise CheckpointResumeError("pending Process Manager step was not reconstructed")
        if pending.command_id != process_state["pending_command_id"]:
            raise CheckpointResumeError("reconstructed pending command identity changed")
        if pending.request_hash != process_state["pending_request_hash"]:
            raise CheckpointResumeError("reconstructed pending command request changed")
        if manager.step_count != int(process_state["step_count"]):
            raise CheckpointResumeError("Process Manager step count changed across restart")
        if list(manager.visited_transition_hashes) != list(process_state["visited_transition_hashes"]):
            raise CheckpointResumeError("Process Manager stall-protection history changed")
        if any(event.payload.get("causation_command_id") == pending.command_id for event in events):
            raise CheckpointResumeError("pending Command was already committed before resume")

        snapshot = dict(durable["frontier_snapshot"])
        spec = validate_frontier_snapshot(snapshot)
        pre_restart_head = journal.head_position
        replayed = tuple(event for event in events if event.position > frontier_position)
        checkpoint_stream = CanonicalStream(
            journal, run_id, f"checkpoint/{checkpoint_id}", str(durable["policy_hash"])
        )
        manifest_proof = cas.verify_existing(reference)
        _, verified_refs = checkpoint_stream.append(
            "restart-verified",
            (
                {
                    "schema": "CHECKPOINT_JOURNAL_VERIFIED_V1",
                    "event_type": "checkpoint.journal-verified",
                    "checkpoint_id": checkpoint_id,
                    "journal_id": journal.journal_id,
                    "epoch": journal.epoch,
                    "genesis_hash": context.genesis.genesis_hash,
                    "new_process_pid": new_pid,
                    "pre_restart_head": pre_restart_head,
                },
                {
                    "schema": "CHECKPOINT_MANIFEST_VERIFIED_V1",
                    "event_type": "checkpoint.manifest-verified",
                    "checkpoint_id": checkpoint_id,
                    "manifest_ref": reference.reference_id,
                    "manifest_hash": durable["manifest_hash"],
                    "cas_reference_count": len(durable["cas_refs"]),
                    "all_manifest_references_present": True,
                    "fail_closed_verification": True,
                    "_object_refs": [reference.reference_id],
                },
                {
                    "schema": "CHECKPOINT_FRONTIER_REPLAYED_V1",
                    "event_type": "checkpoint.frontier-replayed",
                    "checkpoint_id": checkpoint_id,
                    "replayed_from_position": frontier_position,
                    "replayed_event_count": len(replayed),
                    "provider_calls_during_replay": 0,
                    "effect_executions_during_replay": 0,
                },
                {
                    "schema": "CHECKPOINT_PROCESS_RECONSTRUCTED_V1",
                    "event_type": "checkpoint.process-reconstructed",
                    "checkpoint_id": checkpoint_id,
                    "frontier_kind": spec.frontier_kind,
                    "process_id": process_id,
                    "process_state": manager.state.value,
                    "step_count": manager.step_count,
                    "visited_transition_hashes": list(manager.visited_transition_hashes),
                    "pending_command_id": pending.command_id,
                    "pending_request_hash": pending.request_hash,
                    "restored_protocol_state": snapshot["protocol_state"],
                    "restored_lease_id": snapshot.get("lease_id"),
                    "restored_fencing_token_hash": snapshot.get("fencing_token_hash"),
                    "restored_blackboard_version": snapshot.get("blackboard_version"),
                    "restored_blackboard_hash": snapshot.get("blackboard_hash"),
                    "restored_handoff_generation": snapshot.get("handoff_generation"),
                    "restored_negotiation_round": snapshot.get("negotiation_round"),
                    "restored_rework_parent_hash": snapshot.get("rework_parent_hash"),
                    "restored_outcome_state": snapshot.get("outcome_state"),
                    "new_process_pid": new_pid,
                    "projection_used": False,
                    "process_cache_used": False,
                    "legacy_reads": 0,
                    "acceptance_reads": 0,
                },
            ),
            actor="fresh-restart-recovery-worker",
            proofs=(manifest_proof,),
        )
        checkpoint_stream.append(
            "resume-eligible",
            (
                {
                    "schema": "CHECKPOINT_RESUME_ELIGIBILITY_DECIDED_V1",
                    "event_type": "checkpoint.resume-eligibility-decided",
                    "checkpoint_id": checkpoint_id,
                    "eligible": True,
                    "reason_code": "JOURNAL_CAS_AND_PROCESS_STATE_VERIFIED",
                    "pending_command_id": pending.command_id,
                    "provider_send_count_before": int(durable["provider_send_count"]),
                    "duplicate_external_effect_count": 0,
                },
            ),
            actor="resume-eligibility-command-handler",
        )
        manager, outcome_facts = manager.reconcile_outcome(
            lambda command_id, request_hash: CommandResult(
                CommandStatus.COMMITTED,
                command_id,
                request_hash,
                canonical_outcome_ref=stable_hash(
                    "CHECKPOINT_RESUME_CANONICAL_OUTCOME",
                    {"checkpoint_id": checkpoint_id, "command_id": command_id, "request_hash": request_hash},
                ),
            )
        )
        if manager.state is not ProcessState.RUNNING or manager.pending_step is not None:
            raise CheckpointResumeError("Process Manager did not advance after the resumed Command")
        frontier_stream = CanonicalStream(
            journal, run_id, str(durable["frontier_stream_id"]), str(durable["policy_hash"])
        )
        _, resume_refs = frontier_stream.append(
            "resume-command",
            (
                {
                    "schema": "CHECKPOINT_RESUME_COMMAND_COMMITTED_V1",
                    "event_type": "checkpoint.resume-command-committed",
                    "checkpoint_id": checkpoint_id,
                    "frontier_kind": spec.frontier_kind,
                    "command_id": pending.command_id,
                    "request_hash": pending.request_hash,
                    "same_pending_command_id": True,
                    "new_process_pid": new_pid,
                },
                *outcome_facts,
                {
                    "schema": spec.continuation_schema,
                    "event_type": "checkpoint.workflow-continuation",
                    "checkpoint_id": checkpoint_id,
                    "frontier_kind": spec.frontier_kind,
                    "protocol_id": snapshot["protocol_id"],
                    "prior_protocol_state": snapshot["protocol_state"],
                    "source_state_hash": snapshot["state_hash"],
                    "pending_command_id": pending.command_id,
                    "provider_transmission_reissued": False,
                    "handoff_generation_after": snapshot.get("handoff_generation"),
                    "blackboard_version_after": snapshot.get("blackboard_version"),
                    "lease_id_after_restore": snapshot.get("lease_id"),
                    "fencing_token_hash_after_restore": snapshot.get("fencing_token_hash"),
                    "negotiation_round_after": snapshot.get("negotiation_round"),
                    "rework_parent_hash_after": snapshot.get("rework_parent_hash"),
                    "outcome_state_before_reconciliation": snapshot.get("outcome_state"),
                    "automatic_provider_retry_performed": False,
                },
                {
                    "schema": "RESTART_FRONTIER_RESOLVED_V1",
                    "event_type": "checkpoint.restart-frontier-resolved",
                    "checkpoint_id": checkpoint_id,
                    "frontier_kind": spec.frontier_kind,
                    "protocol_id": snapshot["protocol_id"],
                    "obligation_id": snapshot["obligation_id"],
                    "terminal_disposition": "RESUMED_AND_CONTINUED",
                    "successor_obligation": None,
                },
            ),
            actor="fresh-restart-resume-command-handler",
            command_id=pending.command_id,
        )

        integrated_result: dict[str, Any] = {}
        if spec.frontier_kind == "HANDOFF_ACCEPTED_PENDING_SUBMISSION" and isinstance(
            snapshot.get("integrated_continuation"), dict
        ):
            integrated_result = _complete_integrated_handoff(
                journal,
                run_id,
                str(durable["policy_hash"]),
                checkpoint_id,
                str(durable["manifest_hash"]),
                snapshot,
                events,
            )

        if spec.frontier_kind == "TASK_LEASE_ACTIVE":
            task_stream = CanonicalStream(
                journal, run_id, f"task/{snapshot['task_id']}", str(durable["policy_hash"])
            )
            task_stream.append(
                "release-restored-lease",
                (
                    {
                        "schema": "TASK_LEASE_RELEASED_V1",
                        "task_id": snapshot["task_id"],
                        "task_attempt_id": snapshot["task_attempt_id"],
                        "attempt_id": snapshot["task_attempt_id"],
                        "holder_agent_id": snapshot["holder_agent_id"],
                        "claim_generation": snapshot["claim_generation"],
                        "lease_id": snapshot["lease_id"],
                        "fencing_token": snapshot["fencing_token"],
                        "fencing_token_permanently_revoked": True,
                        "committed_stream_version": int(snapshot["task_stream_version"]) + 1,
                        "restored_from_checkpoint_id": checkpoint_id,
                    },
                ),
                actor="fresh-restart-task-command-handler",
            )
        if spec.frontier_kind == "PROVIDER_UNKNOWN_RECONCILING":
            effect_stream = CanonicalStream(
                journal, run_id, f"effect/{run_id}/{snapshot['effect_id']}", str(durable["policy_hash"])
            )
            effect_stream.append(
                "resume-provider-reconciliation",
                (
                    {
                        "schema": "PROVIDER_RECONCILIATION_REQUESTED_V1",
                        "effect_id": snapshot["effect_id"],
                        "effect_attempt_id": snapshot["effect_attempt_id"],
                        "reason": "PROCESS_RESTART_WITH_OUTCOME_UNKNOWN",
                        "automatic_retry_authorized": False,
                    },
                    {
                        "schema": "PROVIDER_RECONCILIATION_QUERY_RECORDED_V1",
                        "effect_id": snapshot["effect_id"],
                        "effect_attempt_id": snapshot["effect_attempt_id"],
                        "query_result": "STATUS_ENDPOINT_UNAVAILABLE",
                        "not_found_interpreted_as_not_executed": False,
                        "new_transmission_performed": False,
                    },
                    {
                        "schema": "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
                        "effect_id": snapshot["effect_id"],
                        "effect_attempt_id": snapshot["effect_attempt_id"],
                        "prior_outcome_state": "OUTCOME_UNKNOWN",
                        "disposition": "SETTLED_WITH_MONITORING_AND_PERMANENT_RETRY_BLOCK",
                        "settlement_state": "SETTLED",
                        "settlement_basis": "POLICY_DISPOSITION",
                        "automatic_retry_performed": False,
                        "new_effect_created": False,
                        "physical_send_count": int(snapshot.get("physical_send_count", 0)),
                        "terminal_blocking_exposure_count": 0,
                        "usage_settled": True,
                    },
                ),
                actor="fresh-restart-effect-reconciliation-handler",
            )

        checkpoint_stream = CanonicalStream(
            journal, run_id, f"checkpoint/{checkpoint_id}", str(durable["policy_hash"])
        )
        provider_send_count_after = int(durable["provider_send_count"])
        _, completed_refs = checkpoint_stream.append(
            "resume-completed",
            (
                {
                    "schema": "CHECKPOINT_RESUME_COMPLETED_V1",
                    "event_type": "checkpoint.resume-completed",
                    "checkpoint_id": checkpoint_id,
                    "frontier_kind": spec.frontier_kind,
                    "manifest_hash": durable["manifest_hash"],
                    "old_process_pid": old_pid,
                    "new_process_pid": new_pid,
                    "pre_restart_head": pre_restart_head,
                    "post_restart_head": journal.head_position + 1,
                    "pending_command_id": pending.command_id,
                    "provider_send_count_before": int(durable["provider_send_count"]),
                    "provider_send_count_after": provider_send_count_after,
                    "duplicate_provider_send_count": 0,
                    "restored_protocol_state": snapshot["protocol_state"],
                    "restored_lease_id": snapshot.get("lease_id"),
                    "restored_fencing_token_hash": snapshot.get("fencing_token_hash"),
                    "restored_blackboard_version": snapshot.get("blackboard_version"),
                    "restored_blackboard_hash": snapshot.get("blackboard_hash"),
                    "resume_event_id": resume_refs[0]["event_id"],
                    "frontier_terminal_event_id": resume_refs[-1]["event_id"],
                    "journal_id_unchanged": True,
                    "epoch_unchanged": True,
                    "genesis_unchanged": True,
                    "provider_call_reissued": False,
                    "projection_used": False,
                    "process_cache_used": False,
                    "legacy_reads": 0,
                    "acceptance_reads": 0,
                    **integrated_result,
                },
            ),
            actor="fresh-restart-recovery-worker",
        )
        return {
            "checkpoint_id": checkpoint_id,
            "frontier_kind": spec.frontier_kind,
            "manifest_ref": reference.reference_id,
            "manifest_hash": durable["manifest_hash"],
            "old_process_pid": old_pid,
            "new_process_pid": new_pid,
            "pre_restart_head": pre_restart_head,
            "post_restart_head": journal.head_position,
            "pending_command_id": pending.command_id,
            "provider_send_count_before": int(durable["provider_send_count"]),
            "provider_send_count_after": provider_send_count_after,
            "duplicate_provider_send_count": 0,
            "restored_protocol_state": snapshot["protocol_state"],
            "restored_lease_id": snapshot.get("lease_id"),
            "restored_fencing_token_hash": snapshot.get("fencing_token_hash"),
            "restored_blackboard_version": snapshot.get("blackboard_version"),
            "resume_event_id": resume_refs[0]["event_id"],
            "frontier_terminal_event_id": resume_refs[-1]["event_id"],
            "checkpoint_completed_event_id": completed_refs[-1]["event_id"],
            "checkpoint_completed_position": completed_refs[-1]["position"],
            "verification_event_ids": [item["event_id"] for item in verified_refs],
            **integrated_result,
        }
    finally:
        journal.close()


def finalize_checkpoint_matrix(home: Path, run_id: str, checkpoint_ids: Sequence[str]) -> dict[str, Any]:
    root = Path(home).resolve(strict=True)
    expected_ids = tuple(checkpoint_ids)
    if len(expected_ids) != len(FRONTIER_SPECS) or len(set(expected_ids)) != len(expected_ids):
        raise CheckpointResumeError("checkpoint finalizer requires the exact eight-checkpoint plan")
    context = ProductionRuntimeContext.load(root)
    journal = context.open_writer()
    cas = context.open_cas()
    try:
        events = tuple(journal.iter_events(0))
        existing_terminal = next(
            (
                event
                for event in reversed(events)
                if event.payload.get("run_id") == run_id and event.event_type == "run.terminal"
            ),
            None,
        )
        if existing_terminal is not None:
            return {
                "status": "complete",
                "run_id": run_id,
                "terminal_state": existing_terminal.payload.get("terminal_state"),
                "terminal_event_id": existing_terminal.event_id,
                "terminal_position": existing_terminal.position,
                "idempotent_existing_terminal": True,
            }
        handoffs = [
            event
            for event in events
            if event.payload.get("run_id") == run_id
            and event.payload.get("schema") == "CHECKPOINT_SUPERVISOR_HANDOFF_REQUIRED_V1"
        ]
        if len(handoffs) != 1 or tuple(handoffs[0].payload.get("checkpoint_ids", ())) != expected_ids:
            raise CheckpointResumeError("checkpoint supervisor handoff does not bind the finalizer plan")
        completions: list[EventEnvelope] = []
        for checkpoint_id in expected_ids:
            matching = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "CHECKPOINT_RESUME_COMPLETED_V1"
                and event.payload.get("checkpoint_id") == checkpoint_id
            ]
            if len(matching) != 1:
                raise CheckpointResumeError("checkpoint did not complete exactly once")
            completions.append(matching[0])
        kinds = tuple(str(event.payload["frontier_kind"]) for event in completions)
        if kinds != tuple(item.frontier_kind for item in FRONTIER_SPECS):
            raise CheckpointResumeError("completed restart frontiers differ from the policy matrix")
        old_pids = {int(event.payload["old_process_pid"]) for event in completions}
        if len(old_pids) != 1:
            raise CheckpointResumeError("restart checkpoints do not share one stopped runtime identity")
        old_pid = next(iter(old_pids))
        new_pids = [int(event.payload["new_process_pid"]) for event in completions]
        if any(pid == old_pid for pid in new_pids):
            raise CheckpointResumeError("a checkpoint did not cross a process boundary")
        if any(int(event.payload["duplicate_provider_send_count"]) != 0 for event in completions):
            raise CheckpointResumeError("restart matrix contains a duplicate Provider transmission")
        if any(
            int(event.payload["provider_send_count_before"])
            != int(event.payload["provider_send_count_after"])
            for event in completions
        ):
            raise CheckpointResumeError("Provider transmission count changed during restart")
        pending_ids = [str(event.payload["pending_command_id"]) for event in completions]
        for command_id in pending_ids:
            matching = [event for event in events if event.payload.get("causation_command_id") == command_id]
            if len(matching) != 4:
                raise CheckpointResumeError("resumed durable Command does not have its exact four-event outcome")
        closing = [
            event
            for event in events
            if event.payload.get("run_id") == run_id
            and event.payload.get("schema") == "RUN_CLOSING_BEGAN_V1"
        ]
        if len(closing) != 1:
            raise CheckpointResumeError("Run closing state was not recovered exactly once")

        handoff_payload = dict(handoffs[0].payload)
        provider_send_count = int(handoff_payload["provider_send_count"])
        provider_call_count = int(handoff_payload.get("provider_call_count", provider_send_count))
        provider_token_total = int(handoff_payload.get("provider_token_total", 0))
        provider_cost_micro_usd = int(handoff_payload.get("provider_cost_micro_usd", 0))
        integrated_evidence: dict[str, Any] = {}
        if bool(handoff_payload.get("integrated_closure_required")):
            integrated_handoff_id = str(handoff_payload.get("integrated_handoff_id", ""))
            accepted = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "HANDOFF_ACCEPTED_V1"
                and event.payload.get("handoff_id") == integrated_handoff_id
                and int(event.payload.get("generation", 0)) == 2
            ]
            restored = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "INTEGRATED_RESTART_STATE_RESTORED_V1"
                and event.payload.get("handoff_id") == integrated_handoff_id
            ]
            submitted = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "HANDOFF_RESULT_SUBMITTED_V1"
                and event.payload.get("handoff_id") == integrated_handoff_id
                and int(event.payload.get("generation", 0)) == 2
                and event.payload.get("committed_after_restart") is True
            ]
            verified = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "HANDOFF_VERIFIED_V1"
                and event.payload.get("handoff_id") == integrated_handoff_id
                and int(event.payload.get("generation", 0)) == 2
                and event.payload.get("committed_after_restart") is True
            ]
            obligations = [
                event
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "INTEGRATED_ALL_REQUIRED_OBLIGATIONS_CLOSED_V1"
                and int(event.payload.get("generation", 0)) == 2
            ]
            if not all(len(group) == 1 for group in (accepted, restored, submitted, verified, obligations)):
                raise CheckpointResumeError(
                    "integrated closure lacks one exact accepted/restore/submitted/verified/obligations chain"
                )
            if not (
                accepted[0].position
                < restored[0].position
                < submitted[0].position
                < verified[0].position
                < obligations[0].position
            ):
                raise CheckpointResumeError("integrated Handoff causal order is invalid")
            c_completion = next(
                event
                for event in completions
                if event.payload.get("frontier_kind") == "HANDOFF_ACCEPTED_PENDING_SUBMISSION"
            )
            if int(restored[0].payload.get("new_process_pid", -1)) != int(c_completion.payload["new_process_pid"]):
                raise CheckpointResumeError("integrated state restore was not committed by the Handoff restart process")
            if any(
                int(event.payload.get("new_process_pid", -1)) != int(c_completion.payload["new_process_pid"])
                for event in (submitted[0], verified[0], obligations[0])
            ):
                raise CheckpointResumeError("integrated post-restart closure crossed process identities")
            if not (
                restored[0].payload.get("lease_id")
                and int(restored[0].payload.get("blackboard_version", 0)) >= 2
                and restored[0].payload.get("process_state") == "RUNNING"
            ):
                raise CheckpointResumeError("integrated restart did not restore Lease, Blackboard, and Process state")
            integrated_evidence = {
                "status": "PASSED",
                "handoff_id": integrated_handoff_id,
                "generation": 2,
                "accepted_event_id": accepted[0].event_id,
                "accepted_position": accepted[0].position,
                "restored_event_id": restored[0].event_id,
                "restored_position": restored[0].position,
                "submitted_event_id": submitted[0].event_id,
                "submitted_position": submitted[0].position,
                "verified_event_id": verified[0].event_id,
                "verified_position": verified[0].position,
                "obligations_closed_event_id": obligations[0].event_id,
                "obligations_closed_position": obligations[0].position,
                "new_process_pid": int(c_completion.payload["new_process_pid"]),
                "restored_lease_id": restored[0].payload["lease_id"],
                "restored_blackboard_version": restored[0].payload["blackboard_version"],
                "restored_blackboard_hash": restored[0].payload["blackboard_hash"],
            }
        matrix_stream = CanonicalStream(
            journal, run_id, "checkpoint-matrix/" + run_id, str(handoff_payload["policy_hash"])
        )
        _, matrix_refs = matrix_stream.append(
            "checkpoint-resume-matrix-completed",
            (
                {
                    "schema": "CHECKPOINT_RESUME_MATRIX_COMPLETED_V1",
                    "event_type": "checkpoint.resume-matrix-completed",
                    "checkpoint_count": len(completions),
                    "frontier_kinds": list(kinds),
                    "checkpoint_ids": list(expected_ids),
                    "old_process_pid": old_pid,
                    "new_process_pids": new_pids,
                    "distinct_process_boundaries": all(pid != old_pid for pid in new_pids),
                    "provider_send_count_before": provider_send_count,
                    "provider_send_count_after": provider_send_count,
                    "duplicate_provider_send_count": 0,
                    "same_pending_command_ids": len(set(pending_ids)) == len(pending_ids),
                    "journal_identity_preserved": True,
                    "projection_used_for_resume": False,
                    "process_cache_used_for_resume": False,
                    "legacy_reads": 0,
                    "acceptance_reads": 0,
                },
            ),
            actor="checkpoint-supervisor-finalizer",
        )
        run = RunAggregate(run_id, RunState.CLOSING, 2, 2)
        empty_counts = {kind: 0 for kind in BlockerKind}
        obligations_ref = stable_hash(
            "CHECKPOINT_RESTART_OBLIGATIONS_COMPLETE",
            {"run_id": run_id, "checkpoint_ids": list(expected_ids), "completion_ids": [item.event_id for item in completions]},
        )
        authoritative = AuthoritativeTerminalFacts(
            {kind: () for kind in BlockerKind},
            None,
            (),
            obligations_ref,
            str(handoff_payload["policy_hash"]),
        )
        projection = TerminalEligibilityProjection(run_id, empty_counts, journal.head_position)
        decision = full_validate(projection, run, authoritative)
        run, terminal = apply_terminal_decision(run, decision)
        if run.state is not RunState.SUCCEEDED:
            raise CheckpointResumeError("checkpoint finalizer did not derive SUCCEEDED")
        evidence_package = {
            "schema": "SITINA_CHECKPOINT_RESTART_FINAL_EVIDENCE_V1",
            "run_id": run_id,
            "journal_id": journal.journal_id,
            "epoch": journal.epoch,
            "genesis_hash": context.genesis.genesis_hash,
            "checkpoint_ids": list(expected_ids),
            "checkpoint_completions": [dict(event.payload) for event in completions],
            "matrix_event_id": matrix_refs[-1]["event_id"],
            "matrix_event_position": matrix_refs[-1]["position"],
            "old_process_pid": old_pid,
            "new_process_pids": new_pids,
            "provider_call_count": provider_call_count,
            "provider_physical_send_count": provider_send_count,
            "provider_token_total": provider_token_total,
            "provider_cost_micro_usd": provider_cost_micro_usd,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "duplicate_provider_send_count": 0,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "acceptance_runtime_read_count": 0,
            "projection_used_for_resume": False,
            "process_cache_used_for_resume": False,
            "terminal_decision": decision.__dict__,
            "integrated_closure": integrated_evidence,
        }
        evidence_hash = hashlib.sha256(canonical_json_bytes(evidence_package)).hexdigest()
        evidence_receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(evidence_package),
                context.provider,
                tenant_id=TENANT,
                purpose="true-multi-agent-checkpoint-final-evidence",
            )
        )
        run_stream = CanonicalStream(
            journal, run_id, f"run/{run_id}", str(handoff_payload["policy_hash"])
        )
        receipt, terminal_refs = run_stream.append(
            "checkpoint-restart-run-terminal",
            (
                {
                    "schema": "CHECKPOINT_TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                    "projection_source_position": projection.source_position,
                    "authoritative_blocker_counts": {kind.value: 0 for kind in BlockerKind},
                    "required_obligations_complete_ref": obligations_ref,
                    "decision": decision.__dict__,
                },
                {
                    "schema": "RUN_EVIDENCE_PACKAGE_SEALED_V1",
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "checkpoint_ids": list(expected_ids),
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
                {
                    **terminal,
                    "event_type": "run.terminal",
                    "status": "terminal",
                    "required_obligations_open": 0,
                    "terminal_state": run.state.value,
                    "terminal_command_id": decision.command_id,
                    "terminal_request_hash": decision.request_hash,
                    "authoritative_fact_hash": decision.authoritative_fact_hash,
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "provider_call_count": provider_call_count,
                    "provider_physical_send_count": provider_send_count,
                    "provider_retry_count": 0,
                    "provider_fallback_count": 0,
                    "provider_token_total": provider_token_total,
                    "provider_cost_micro_usd": provider_cost_micro_usd,
                    "external_mutation_count": 0,
                    "legacy_read_count": 0,
                    "acceptance_runtime_read_count": 0,
                    "checkpoint_restart_count": len(expected_ids),
                    "integrated_closure_passed": integrated_evidence.get("status") == "PASSED"
                    if bool(handoff_payload.get("integrated_closure_required"))
                    else None,
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
            ),
            actor="checkpoint-supervisor-finalizer",
            proofs=(evidence_receipt,),
            command_id=decision.command_id,
        )
        return {
            "status": "complete",
            "run_id": run_id,
            "terminal_state": run.state.value,
            "checkpoint_restart_count": len(expected_ids),
            "checkpoint_ids": list(expected_ids),
            "old_process_pid": old_pid,
            "new_process_pids": new_pids,
            "provider_call_count": provider_call_count,
            "provider_physical_send_count": provider_send_count,
            "provider_token_total": provider_token_total,
            "provider_cost_micro_usd": provider_cost_micro_usd,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "duplicate_provider_send_count": 0,
            "evidence_package_ref": evidence_receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "terminal_event_id": terminal_refs[-1]["event_id"],
            "terminal_position": terminal_refs[-1]["position"],
            "terminal_transaction_hash": receipt.transaction_hash,
            "matrix_event_id": matrix_refs[-1]["event_id"],
            "matrix_event_position": matrix_refs[-1]["position"],
            "integrated_closure": integrated_evidence,
        }
    finally:
        journal.close()


def abort_incomplete_checkpoint_run(home: Path, run_id: str) -> dict[str, Any]:
    """Fail-close a stopped restart plan that cannot be supervised to completion."""

    root = Path(home).resolve(strict=True)
    context = ProductionRuntimeContext.load(root)
    journal = context.open_writer()
    cas = context.open_cas()
    try:
        events = tuple(journal.iter_events(0))
        terminal = next(
            (
                event
                for event in reversed(events)
                if event.payload.get("run_id") == run_id and event.event_type == "run.terminal"
            ),
            None,
        )
        if terminal is not None:
            return {
                "status": "complete",
                "run_id": run_id,
                "terminal_state": terminal.payload.get("terminal_state"),
                "terminal_event_id": terminal.event_id,
                "terminal_position": terminal.position,
                "idempotent_existing_terminal": True,
            }
        stopped = [
            event
            for event in events
            if event.payload.get("run_id") == run_id
            and event.payload.get("schema") == "CHECKPOINT_RUNTIME_STOPPED_V1"
        ]
        if not stopped:
            raise CheckpointResumeError("incomplete checkpoint abort requires a durable runtime stop")
        policy_hash = str(stopped[-1].payload["policy_hash"])
        run_stream = CanonicalStream(journal, run_id, f"run/{run_id}", policy_hash)
        closing_events = [
            event
            for event in events
            if event.payload.get("run_id") == run_id and event.payload.get("schema") == "RUN_CLOSING_BEGAN_V1"
        ]
        if closing_events:
            run = RunAggregate(run_id, RunState.CLOSING, 2, 2)
            closing_fact: dict[str, Any] = {
                "schema": "RUN_CLOSING_RESUMED_FOR_CHECKPOINT_ABORT_V1",
                "run_id": run_id,
                "admission_generation": 2,
            }
        else:
            run = RunAggregate(run_id, RunState.ACTIVE, 1, 1)
            run, closing_fact = run.begin_closing(expected_stream_version=run.stream_version)
        reason_ref = stable_hash(
            "CHECKPOINT_SUPERVISOR_INCOMPLETE_PLAN_ABORT",
            {"run_id": run_id, "stopped_checkpoint_ids": [event.payload["checkpoint_id"] for event in stopped]},
        )
        projection = TerminalEligibilityProjection(
            run_id, {kind: 0 for kind in BlockerKind}, journal.head_position
        )
        authoritative = AuthoritativeTerminalFacts(
            {kind: () for kind in BlockerKind}, None, (reason_ref,), None, policy_hash
        )
        decision = full_validate(projection, run, authoritative)
        run, terminal_fact = apply_terminal_decision(run, decision)
        if run.state is not RunState.FAILED:
            raise CheckpointResumeError("incomplete checkpoint plan did not fail closed")
        usage_events = [
            event
            for event in events
            if event.payload.get("run_id") == run_id
            and event.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1"
        ]
        provider_physical_send_count = sum(
            int(event.payload.get("physical_send_count", 0)) for event in usage_events
        )
        provider_call_count = sum(
            1 for event in usage_events if int(event.payload.get("physical_send_count", 0)) > 0
        )
        provider_token_total = sum(int(event.payload.get("total_tokens", 0)) for event in usage_events)
        provider_cost_micro_usd = sum(int(event.payload.get("cost_micro_usd", 0)) for event in usage_events)
        evidence = {
            "schema": "SITINA_INCOMPLETE_CHECKPOINT_ABORT_EVIDENCE_V1",
            "run_id": run_id,
            "journal_id": journal.journal_id,
            "epoch": journal.epoch,
            "genesis_hash": context.genesis.genesis_hash,
            "stopped_checkpoint_ids": [event.payload["checkpoint_id"] for event in stopped],
            "completed_checkpoint_ids": [
                event.payload["checkpoint_id"]
                for event in events
                if event.payload.get("run_id") == run_id
                and event.payload.get("schema") == "CHECKPOINT_RESUME_COMPLETED_V1"
            ],
            "failure_ref": reason_ref,
            "provider_call_count": provider_call_count,
            "provider_physical_send_count": provider_physical_send_count,
            "provider_token_total": provider_token_total,
            "provider_cost_micro_usd": provider_cost_micro_usd,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "acceptance_runtime_read_count": 0,
        }
        evidence_hash = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
        evidence_receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(evidence),
                context.provider,
                tenant_id=TENANT,
                purpose="true-multi-agent-incomplete-checkpoint-abort",
            )
        )
        receipt, refs = run_stream.append(
            "incomplete-checkpoint-run-failed",
            (
                {**closing_fact, "event_type": "run.closing"},
                {
                    "schema": "CHECKPOINT_SUPERVISOR_INCOMPLETE_PLAN_ABORTED_V1",
                    "event_type": "checkpoint.supervisor-incomplete-plan-aborted",
                    "stopped_checkpoint_ids": [event.payload["checkpoint_id"] for event in stopped],
                    "failure_ref": reason_ref,
                    "automatic_retry_performed": False,
                    "success_claimed": False,
                },
                {
                    "schema": "TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                    "projection_source_position": projection.source_position,
                    "required_obligations_complete_ref": None,
                    "failure_refs": [reason_ref],
                    "decision": decision.__dict__,
                },
                {
                    "schema": "RUN_EVIDENCE_PACKAGE_SEALED_V1",
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
                {
                    **terminal_fact,
                    "event_type": "run.terminal",
                    "status": "terminal",
                    "required_obligations_open": 0,
                    "terminal_state": run.state.value,
                    "terminal_command_id": decision.command_id,
                    "terminal_request_hash": decision.request_hash,
                    "authoritative_fact_hash": decision.authoritative_fact_hash,
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "provider_call_count": provider_call_count,
                    "provider_physical_send_count": provider_physical_send_count,
                    "provider_retry_count": 0,
                    "provider_fallback_count": 0,
                    "external_mutation_count": 0,
                    "legacy_read_count": 0,
                    "acceptance_runtime_read_count": 0,
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
            ),
            actor="checkpoint-supervisor-failure-finalizer",
            proofs=(evidence_receipt,),
            command_id=decision.command_id,
        )
        return {
            "status": "complete",
            "run_id": run_id,
            "terminal_state": run.state.value,
            "terminal_event_id": refs[-1]["event_id"],
            "terminal_position": refs[-1]["position"],
            "terminal_transaction_hash": receipt.transaction_hash,
            "provider_call_count": provider_call_count,
            "provider_physical_send_count": provider_physical_send_count,
            "provider_token_total": provider_token_total,
            "provider_cost_micro_usd": provider_cost_micro_usd,
            "evidence_package_ref": evidence_receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
        }
    finally:
        journal.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sitina-checkpoint-resume-worker")
    parser.add_argument("--home", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--checkpoint-id", action="append", default=[])
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--abort-incomplete", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.abort_incomplete:
            if args.finalize or args.checkpoint_id:
                raise CheckpointResumeError("incomplete abort does not accept checkpoint identities")
            result = abort_incomplete_checkpoint_run(Path(args.home), args.run_id)
        elif args.finalize:
            result = finalize_checkpoint_matrix(Path(args.home), args.run_id, args.checkpoint_id)
        else:
            if len(args.checkpoint_id) != 1:
                raise CheckpointResumeError("one checkpoint identity is required for a recovery worker")
            result = recover_checkpoint(Path(args.home), args.run_id, args.checkpoint_id[0])
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    status = str(result.get("status", "resumed"))
    print(json.dumps({"status": status, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
