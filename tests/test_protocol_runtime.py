from __future__ import annotations

import unittest

from sitina.protocols.runtime import (
    ProtocolDefinition, ProtocolInstance, ProtocolTransitionRejected, Transition, apply_transition,
)


def definition():
    return ProtocolDefinition(
        "fixture-protocol", 1, "OPEN", frozenset({"DONE", "TIMED_OUT"}),
        (
            Transition("advance", frozenset({"OPEN"}), "WORKING", "FixtureAdvanced"),
            Transition("complete", frozenset({"WORKING"}), "DONE", "FixtureCompleted"),
            Transition("timeout", frozenset({"OPEN", "WORKING"}), "TIMED_OUT", "FixtureTimedOut", timeout=True),
        ),
        "11" * 32,
    )


class ProtocolRuntimeTests(unittest.TestCase):
    def test_allowed_transition_emits_event_and_binds_definition_policy(self) -> None:
        protocol = definition(); instance = ProtocolInstance.create("instance-1", protocol)
        result = apply_transition(protocol, instance, "advance", "command-1", {"x": 1})
        self.assertEqual(result.instance.state, "WORKING")
        self.assertEqual(result.events[0]["definition_hash"], protocol.definition_hash)
        self.assertEqual(result.events[0]["policy_hash"], protocol.policy_hash)

    def test_invalid_terminal_and_timeout_transitions_fail_closed(self) -> None:
        protocol = definition(); instance = ProtocolInstance.create("instance-1", protocol)
        with self.assertRaises(ProtocolTransitionRejected): apply_transition(protocol, instance, "complete", "command-1", {})
        with self.assertRaises(ProtocolTransitionRejected): apply_transition(protocol, instance, "timeout", "command-2", {}, timeout_fired=False)
        done = apply_transition(protocol, apply_transition(protocol, instance, "advance", "command-3", {}).instance, "complete", "command-4", {}).instance
        with self.assertRaises(ProtocolTransitionRejected): apply_transition(protocol, done, "advance", "command-5", {})

    def test_duplicate_command_is_idempotent_and_emits_no_second_event(self) -> None:
        protocol = definition(); instance = ProtocolInstance.create("instance-1", protocol)
        first = apply_transition(protocol, instance, "advance", "command-1", {})
        duplicate = apply_transition(protocol, first.instance, "advance", "command-1", {})
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(duplicate.instance, first.instance)
        self.assertEqual(duplicate.events, ())

    def test_definition_hash_changes_with_transition_or_policy(self) -> None:
        left = definition()
        right = ProtocolDefinition(left.protocol_id, left.major, left.initial_state, left.terminal_states, left.transitions, "22" * 32)
        self.assertNotEqual(left.definition_hash, right.definition_hash)


if __name__ == "__main__": unittest.main()
