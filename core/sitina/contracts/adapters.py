from __future__ import annotations

from sitina.journal.model import canonical_json_bytes, domain_hash
from sitina.protocols.tasks import MaterializationState, TaskGraphAggregate

from .models import (
    DependencyContract,
    SourceDescriptor,
    TaskContract,
    TaskGraphContract,
    TrustLevel,
)


_TASK_STATUS = {
    MaterializationState.PENDING: "PENDING",
    MaterializationState.MATERIALIZED: "READY",
    MaterializationState.ABORTED: "CANCELLED",
}


def task_graph_contract_view(
    aggregate: TaskGraphAggregate,
    *,
    run_id: str,
    created_at: str,
    correlation_id: str,
    source: SourceDescriptor,
    trust: TrustLevel,
) -> TaskGraphContract:
    """Create an immutable view; the TaskGraphAggregate remains authoritative."""

    common = {
        "schema_version": "1.0",
        "correlation_id": correlation_id,
        "causation_id": None,
        "created_at": created_at,
        "source": source,
        "trust": trust,
    }
    tasks = tuple(
        TaskContract(
            schema="SITINA_TASK_V1",
            task_id=node.node_id,
            graph_id=aggregate.graph_id,
            specification_hash=node.specification_hash,
            status=_TASK_STATUS[node.materialization_state],
            required=node.required_obligation,
            **common,
        )
        for node in sorted(aggregate.nodes, key=lambda item: item.node_id)
    )
    dependencies = tuple(
        DependencyContract(
            schema="SITINA_TASK_DEPENDENCY_V1",
            dependency_id="dependency-"
            + domain_hash(
                "TASK_DEPENDENCY_ID",
                canonical_json_bytes(
                    {
                        "graph_id": aggregate.graph_id,
                        "task_id": task_id,
                        "depends_on_task_id": depends_on,
                    }
                ),
            ),
            graph_id=aggregate.graph_id,
            task_id=task_id,
            depends_on_task_id=depends_on,
            **common,
        )
        for task_id, depends_on in sorted(aggregate.dependencies)
    )
    return TaskGraphContract(
        schema="SITINA_TASK_GRAPH_V1",
        graph_id=aggregate.graph_id,
        run_id=run_id,
        graph_version=aggregate.version,
        tasks=tasks,
        dependencies=dependencies,
        **common,
    )
