from __future__ import annotations

import unittest

from sitina.protocols.tasks import MaterializationState, TaskGraphAggregate, TaskProtocolError


class TaskGraphProtocolTests(unittest.TestCase):
    def test_expected_version_cycle_rejection_and_topology_hash(self) -> None:
        graph = TaskGraphAggregate.create("graph-1")
        graph, _ = graph.add_task(expected_graph_version=0, node_id="a", specification={"goal": "a"}, required_obligation=True)
        with self.assertRaises(TaskProtocolError): graph.add_task(expected_graph_version=0, node_id="b", specification={}, required_obligation=False)
        graph, _ = graph.add_task(expected_graph_version=1, node_id="b", specification={"goal": "b"}, required_obligation=False)
        graph, _ = graph.add_dependency(expected_graph_version=2, node_id="b", depends_on="a")
        with self.assertRaises(TaskProtocolError): graph.add_dependency(expected_graph_version=3, node_id="a", depends_on="b")
        self.assertEqual(len(graph.topology_hash), 64)

    def test_supersede_split_merge_preserve_immutable_lineage_and_obligation(self) -> None:
        graph = TaskGraphAggregate.create("graph-1"); graph, _ = graph.add_task(expected_graph_version=0, node_id="a", specification={"v": 1}, required_obligation=True)
        graph, _ = graph.supersede_task(expected_graph_version=1, old_node_id="a", new_node_id="a2", specification={"v": 2})
        self.assertEqual(graph._node("a").specification, {"v": 1}); self.assertEqual(graph._node("a2").supersedes, ("a",))
        graph, _ = graph.split_task(expected_graph_version=2, old_node_id="a2", replacements={"b": {"v": 3}, "c": {"v": 4}})
        graph, _ = graph.merge_tasks(expected_graph_version=4, source_node_ids=("b", "c"), new_node_id="d", specification={"v": 5})
        self.assertTrue(graph._node("d").required_obligation)

    def test_block_is_explicit_gating_constraint_not_task_state(self) -> None:
        graph = TaskGraphAggregate.create("graph-1"); graph, _ = graph.add_task(expected_graph_version=0, node_id="a", specification={}, required_obligation=False)
        graph, event = graph.block_task_node(expected_graph_version=1, node_id="a", reason_code="dependency-review")
        self.assertEqual(event["schema"], "TASK_GATING_CONSTRAINT_ADDED_V1")
        self.assertFalse(hasattr(graph._node("a"), "blocked_state"))

    def test_materialization_pending_created_and_aborted_semantics(self) -> None:
        graph = TaskGraphAggregate.create("graph-1")
        graph, _ = graph.add_task(expected_graph_version=0, node_id="a", specification={}, required_obligation=True)
        self.assertFalse(graph._node("a").schedulable)
        graph, process, _ = graph.begin_materialization(expected_graph_version=1, node_id="a", create_command_id="create-a")
        self.assertIn("materialization:a", graph.closing_blockers)
        graph, _ = graph.finish_materialization(expected_graph_version=2, node_id="a", created=True, canonical_request_hash=process.request_hash)
        self.assertTrue(graph._node("a").schedulable); self.assertEqual(graph.closing_blockers, ())
        graph, _ = graph.add_task(expected_graph_version=3, node_id="b", specification={}, required_obligation=True)
        graph, process, _ = graph.begin_materialization(expected_graph_version=4, node_id="b", create_command_id="create-b")
        graph, _ = graph.finish_materialization(expected_graph_version=5, node_id="b", created=False, canonical_request_hash=process.request_hash)
        self.assertFalse(graph._node("b").schedulable); self.assertIn("required-aborted:b", graph.closing_blockers)


if __name__ == "__main__": unittest.main()
