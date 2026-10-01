from __future__ import annotations

from dataclasses import dataclass

from .model import CompletionProposal, ControlIntent, StaleProposal, TaskProjection, TaskStatus


@dataclass(frozen=True)
class CompletionCheck:
    allowed: bool
    reasons: tuple[str, ...]


class ValidationModule:
    """Shared daily/benchmark task contract checks for the 1a state skeleton."""

    REVIEW_REQUIRED_KINDS = frozenset(
        {"code_change", "reviewed_readonly", "capability_install", "installation", "modification"}
    )

    def check_completion(self, task: TaskProjection, proposal: CompletionProposal) -> CompletionCheck:
        reasons: list[str] = []
        if task.terminal_event_id is not None:
            reasons.append("task already has a logical terminal event")
        exact = {
            "task_revision": (task.task_revision, proposal.expected_task_revision),
            "run_instance_id": (task.run_instance_id, proposal.expected_run_instance_id),
            "execution_epoch": (task.execution_epoch, proposal.expected_execution_epoch),
            "goal_version": (task.goal_version, proposal.expected_goal_version),
            "acceptance_version": (task.acceptance_version, proposal.expected_acceptance_version),
            "received_input_seq": (task.received_input_seq, proposal.expected_received_input_seq),
            "handled_input_seq": (task.handled_input_seq, proposal.expected_handled_input_seq),
            "artifact_ref": (task.artifact_ref, proposal.artifact_ref),
        }
        reasons.extend(
            f"{name} changed before terminal commit"
            for name, (current, expected) in exact.items()
            if current != expected
        )
        if task.received_input_seq != task.handled_input_seq:
            reasons.append("received input remains unhandled")
        if proposal.terminal_status is TaskStatus.CANCELLED:
            if task.control_intent is not ControlIntent.CANCEL:
                reasons.append("cancel terminal lacks current cancel intent")
        elif task.control_intent is not ControlIntent.RUN:
            reasons.append("current control intent blocks completion")
        if task.recovery_state not in {"READY_NEW_TASK", "READY_RECOVERED"}:
            reasons.append("full task recovery is not connected")
        if task.active_operations:
            reasons.append("task has an active operation")
        if task.unresolved_effects:
            reasons.append("task has an operation with unknown effect")
        if proposal.terminal_status is TaskStatus.SUCCEEDED:
            current = {
                item.outcome_id: item
                for item in task.acceptances.values()
                if item.bound_run_instance_id == task.run_instance_id
                and item.bound_execution_epoch == task.execution_epoch
                and item.goal_version == task.goal_version
                and item.acceptance_version == task.acceptance_version
                and item.bound_handled_input_seq == task.handled_input_seq
                and item.artifact_ref == task.artifact_ref
            }
            for outcome_id in task.required_outcome_ids:
                receipt = current.get(outcome_id)
                if receipt is None:
                    reasons.append(f"required outcome lacks current evidence: {outcome_id}")
                    continue
                if receipt.program_status != "PASS":
                    reasons.append(f"program check did not pass: {outcome_id}")
                if not receipt.delivery_verified:
                    reasons.append(f"delivery was not verified: {outcome_id}")
                if task.task_kind in self.REVIEW_REQUIRED_KINDS and receipt.reviewer_status != "PASS":
                    reasons.append(f"independent review did not pass: {outcome_id}")
        return CompletionCheck(not reasons, tuple(reasons))

    def require_completion(self, task: TaskProjection, proposal: CompletionProposal) -> None:
        check = self.check_completion(task, proposal)
        if not check.allowed:
            raise StaleProposal("; ".join(check.reasons))
