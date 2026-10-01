from __future__ import annotations

from dataclasses import dataclass

from .model import TaskProjection


@dataclass(frozen=True)
class AgentRequestBinding:
    task_id: str
    run_instance_id: str
    execution_epoch: int
    task_revision: int
    goal_version: int
    acceptance_version: int
    handled_input_seq: int
    capability_snapshot_id: str


class AgentRunnerModule:
    """Builds version bindings; Provider/model work remains outside state locks."""

    @staticmethod
    def bind(task: TaskProjection) -> AgentRequestBinding:
        return AgentRequestBinding(
            task.task_id,
            task.run_instance_id,
            task.execution_epoch,
            task.task_revision,
            task.goal_version,
            task.acceptance_version,
            task.handled_input_seq,
            task.capability_snapshot_id,
        )
