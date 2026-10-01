from __future__ import annotations

"""Same-version recovery orchestration for the persistent Loop host."""

from typing import Any, Callable, Mapping

from .coordinator import LoopBackend
from .model import ControlIntent, PersistenceFenced, RecoveryNotConnected, TaskConflict, TaskStatus


class RecoveryCoordinator:
    def __init__(
        self,
        backend: LoopBackend,
        *,
        descriptor_validator: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        self.backend = backend
        self.descriptor_validator = descriptor_validator

    def bootstrap_candidates(self) -> tuple[str, ...]:
        candidates: list[str] = []
        for task_id in self.backend.task_ids():
            task = self.backend._project(task_id, self.backend.store.task_events(task_id))
            if task.is_terminal or task.run_instance_id == self.backend.run_instance_id:
                continue
            if (
                task.resume_request_id
                or task.control_intent in {ControlIntent.RUN, ControlIntent.CANCEL}
                or not task.descriptor_ref
            ):
                candidates.append(task_id)
        return tuple(sorted(candidates))

    def recover(self, task_id: str, *, explicit_resume: bool = False):
        try:
            return self.backend.recover_task(
                task_id,
                explicit_resume=explicit_resume,
                descriptor_validator=self.descriptor_validator,
            )
        except (PersistenceFenced, RecoveryNotConnected, TaskConflict, ValueError, KeyError) as error:
            task = self.backend._project(task_id, self.backend.store.task_events(task_id))
            if task.is_terminal:
                return task
            return self.backend._append_recovery_blocked(
                task,
                blocker_id="RECOVERY_VALIDATION_FAILED",
                reason=f"same-version recovery could not establish a safe boundary: {type(error).__name__}: {error}",
            )
