from __future__ import annotations

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from sitina.contracts import (
    CONTRACT_OWNERSHIP,
    CROSS_CUTTING_OWNERS,
    ContractReadError,
    DependencyContract,
    FailureContract,
    InvalidContractTransition,
    SpanContract,
    SpanEventContract,
    TaskContract,
    TaskGraphContract,
    TokenBudgetContract,
    UnsupportedContractVersion,
    UsageContract,
    read_contract,
    read_contract_json,
    task_graph_contract_view,
    validate_contract_transition,
)
from sitina.contracts.feature_flags import (
    SharedContractFeatureError,
    assert_shared_contract_write_enabled,
    shared_contract_writes_enabled,
)
from sitina.contracts.models import CONTRACT_MODELS
from sitina.contracts.schema import contract_schema_bundle
from sitina.protocols.tasks import TaskGraphAggregate


ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-07-19T12:00:00Z"
DIGEST = "a" * 64


def common(record_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "correlation_id": record_id,
        "causation_id": None,
        "created_at": NOW,
        "source": {"component": "optimization-test", "actor_id": "tester", "source_ref": record_id},
        "trust": "verified",
    }


class SharedContractTests(unittest.TestCase):
    def test_schema_bundle_is_checked_in_without_drift_and_forbids_unknown_fields(self) -> None:
        path = ROOT / "schemas/contracts/shared-contracts-v1.schema.json"
        checked_in = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, contract_schema_bundle())
        self.assertEqual(checked_in["x-sitina-unknown-field-strategy"], "reject")
        self.assertEqual(checked_in["x-sitina-new-write-default"], "disabled")
        self.assertEqual(len(CONTRACT_MODELS), 13)
        serialized = json.dumps(checked_in, sort_keys=True)
        for schema_id in CONTRACT_MODELS:
            self.assertIn(schema_id, serialized)

    def test_task_graph_contract_is_structural_view_over_existing_owner(self) -> None:
        first = TaskContract(
            schema="SITINA_TASK_V1",
            task_id="task-a",
            graph_id="graph-1",
            specification_hash=DIGEST,
            status="READY",
            required=True,
            **common("task-a"),
        )
        second = TaskContract(
            schema="SITINA_TASK_V1",
            task_id="task-b",
            graph_id="graph-1",
            specification_hash="b" * 64,
            status="PENDING",
            required=True,
            **common("task-b"),
        )
        edge = DependencyContract(
            schema="SITINA_TASK_DEPENDENCY_V1",
            dependency_id="dependency-1",
            graph_id="graph-1",
            task_id="task-b",
            depends_on_task_id="task-a",
            **common("dependency-1"),
        )
        graph = TaskGraphContract(
            schema="SITINA_TASK_GRAPH_V1",
            graph_id="graph-1",
            run_id="run-1",
            graph_version=1,
            tasks=(first, second),
            dependencies=(edge,),
            **common("graph-1"),
        )
        self.assertEqual(graph.tasks[1].task_id, "task-b")
        self.assertEqual(graph.model_dump(by_alias=True)["schema"], "SITINA_TASK_GRAPH_V1")

    def test_canonical_task_graph_adapter_preserves_identity_and_has_no_store(self) -> None:
        aggregate = TaskGraphAggregate.create("graph-owner")
        aggregate, _ = aggregate.add_task(
            expected_graph_version=0,
            node_id="task-a",
            specification={"objective_ref": DIGEST},
            required_obligation=True,
        )
        aggregate, _ = aggregate.add_task(
            expected_graph_version=1,
            node_id="task-b",
            specification={"objective_ref": "b" * 64},
            required_obligation=False,
        )
        aggregate, _ = aggregate.add_dependency(
            expected_graph_version=2,
            node_id="task-b",
            depends_on="task-a",
        )
        view = task_graph_contract_view(
            aggregate,
            run_id="run-1",
            created_at=NOW,
            correlation_id="run-1",
            source={"component": "task-protocol", "actor_id": "scheduler"},
            trust="authoritative",
        )
        self.assertEqual(view.graph_version, aggregate.version)
        self.assertEqual([item.task_id for item in view.tasks], ["task-a", "task-b"])
        self.assertEqual(view.dependencies[0].depends_on_task_id, "task-a")
        self.assertFalse(hasattr(view, "save"))

    def test_task_graph_rejects_cycles_and_duplicate_dependencies(self) -> None:
        tasks = tuple(
            TaskContract(
                schema="SITINA_TASK_V1",
                task_id=task_id,
                graph_id="graph-cycle",
                specification_hash=DIGEST,
                status="PENDING",
                required=True,
                **common(task_id),
            )
            for task_id in ("task-a", "task-b")
        )
        edges = (
            DependencyContract(
                schema="SITINA_TASK_DEPENDENCY_V1",
                dependency_id="edge-a",
                graph_id="graph-cycle",
                task_id="task-a",
                depends_on_task_id="task-b",
                **common("edge-a"),
            ),
            DependencyContract(
                schema="SITINA_TASK_DEPENDENCY_V1",
                dependency_id="edge-b",
                graph_id="graph-cycle",
                task_id="task-b",
                depends_on_task_id="task-a",
                **common("edge-b"),
            ),
        )
        with self.assertRaises(ValidationError):
            TaskGraphContract(
                schema="SITINA_TASK_GRAPH_V1",
                graph_id="graph-cycle",
                run_id="run-1",
                graph_version=1,
                tasks=tasks,
                dependencies=edges,
                **common("graph-cycle"),
            )

    def test_unknown_fields_and_sensitive_fields_fail_closed(self) -> None:
        value = {
            "schema": "SITINA_FAILURE_V1",
            "failure_id": "failure-1",
            "run_id": "run-1",
            "failure_type": "provider-failed",
            "severity": "major",
            "retryable": True,
            "message": "provider failed after redaction",
            "redacted": True,
            **common("failure-1"),
        }
        with self.assertRaises(ContractReadError):
            read_contract(value | {"future_field": "not-negotiated"})
        with self.assertRaises(ValidationError):
            FailureContract.model_validate(value | {"extensions": {"api_key": "must-not-cross"}})

    def test_v0_read_upcasts_deterministically_without_clock_or_io(self) -> None:
        legacy = {
            "schema": "SITINA_TOKEN_USAGE_V0",
            "usage_id": "usage-1",
            "run_id": "run-1",
            "task_id": None,
            "call_id": "call-1",
            "attempt": 1,
            "prompt_tokens": 7,
            "completion_tokens": 5,
            "total_tokens": 12,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "provider_receipt_ref": None,
            "budget_id": None,
            "created_at": NOW,
        }
        first = read_contract(legacy)
        second = read_contract(json.loads(json.dumps(legacy)))
        self.assertEqual(first.contract, second.contract)
        self.assertEqual(first.audit_record, second.audit_record)
        self.assertEqual(first.contract.schema_id, "SITINA_TOKEN_USAGE_V1")
        self.assertEqual(first.contract.correlation_id, "usage-1")
        self.assertEqual(first.contract.trust, "untrusted")
        self.assertTrue(first.audit_record["deterministic"])

    def test_damaged_input_unknown_version_and_unknown_legacy_field_are_rejected(self) -> None:
        with self.assertRaises(ContractReadError):
            read_contract_json(b'{"schema":"SITINA_TOKEN_USAGE_V1"')
        with self.assertRaises(UnsupportedContractVersion):
            read_contract({"schema": "SITINA_TOKEN_USAGE_V2"})
        with self.assertRaises(ContractReadError):
            read_contract({"schema": "SITINA_TOKEN_USAGE_V0", "usage_id": "usage-1", "mystery": 1})

    def test_duplicate_span_event_is_rejected(self) -> None:
        event = SpanEventContract(
            schema="SITINA_SPAN_EVENT_V1",
            event_id="event-1",
            trace_id="trace-1",
            span_id="span-1",
            name="dispatch",
            redacted=True,
            **common("event-1"),
        )
        with self.assertRaises(ValidationError):
            SpanContract(
                schema="SITINA_SPAN_V1",
                trace_id="trace-1",
                span_id="span-1",
                name="agent-call",
                kind="agent",
                status="RUNNING",
                started_at=NOW,
                events=(event, event),
                **common("span-1"),
            )

    def test_negative_tokens_and_inconsistent_usage_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            TokenBudgetContract(
                schema="SITINA_TOKEN_BUDGET_V1",
                budget_id="budget-1",
                scope_type="run",
                scope_id="run-1",
                maximum_tokens=100,
                consumed_tokens=-1,
                **common("budget-1"),
            )
        with self.assertRaises(ValidationError):
            UsageContract(
                schema="SITINA_TOKEN_USAGE_V1",
                usage_id="usage-1",
                run_id="run-1",
                prompt_tokens=4,
                completion_tokens=5,
                total_tokens=8,
                **common("usage-1"),
            )

    def test_invalid_and_duplicate_state_transitions_are_rejected(self) -> None:
        validate_contract_transition("task", "READY", "RUNNING")
        with self.assertRaises(InvalidContractTransition):
            validate_contract_transition("task", "COMPLETED", "RUNNING")
        with self.assertRaises(InvalidContractTransition):
            validate_contract_transition("task", "RUNNING", "RUNNING")

    def test_old_configuration_is_compatible_and_new_writes_default_off(self) -> None:
        self.assertFalse(shared_contract_writes_enabled({"features": {}}))
        self.assertFalse(shared_contract_writes_enabled(None))
        current = json.loads((ROOT / "config/feature_flags.json").read_text(encoding="utf-8"))
        self.assertFalse(shared_contract_writes_enabled(current))
        with self.assertRaises(SharedContractFeatureError):
            assert_shared_contract_write_enabled(current)
        with self.assertRaises(SharedContractFeatureError):
            shared_contract_writes_enabled({"features": {"shared_contracts_v1_write": "yes"}})

    def test_cross_cutting_and_runtime_owners_are_unique_and_explicit(self) -> None:
        families = [item.contract_family for item in CONTRACT_OWNERSHIP]
        self.assertEqual(len(families), len(set(families)))
        self.assertTrue(all(item.shared_contract_role == "validation-and-interchange-only" for item in CONTRACT_OWNERSHIP))
        self.assertEqual(CROSS_CUTTING_OWNERS["concurrency_limits"], "sitina.scheduling.scheduler.Scheduler")
        self.assertIn("ProviderAccounting", CROSS_CUTTING_OWNERS["token_budget_and_accounting"])
        self.assertEqual(CROSS_CUTTING_OWNERS["security_redaction"], "sitina.security.redaction")


if __name__ == "__main__":
    unittest.main()
