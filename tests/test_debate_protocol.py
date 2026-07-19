from __future__ import annotations

import unittest

from sitina.protocols.claims import ClaimRegistry
from sitina.protocols.debate import Debate, DebateError, DebateOutcome


class DebateProtocolTests(unittest.TestCase):
    def registry(self) -> ClaimRegistry:
        registry = ClaimRegistry()
        registry, _, _ = registry.create("claim-1", "topic-1", "11" * 32, ("21" * 32,))
        registry, _, _ = registry.create("claim-2", "topic-1", "12" * 32, ("22" * 32,))
        return registry

    def test_response_references_existing_claim_and_target(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        debate, response, _ = debate.respond(self.registry(), "response-1", "claim-1", "claim-2", "agent-a", 1, 20, "31" * 32)
        self.assertEqual(response.claim_id, "claim-1")
        with self.assertRaises(DebateError):
            debate.respond(self.registry(), "response-2", "missing", "claim-2", "agent-a", 1, 20, "32" * 32)

    def test_round_token_and_deadline_bounds_fail_closed(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=1, max_tokens=10, deadline="2026-07-13T00:00:01Z")
        with self.assertRaises(DebateError):
            debate.respond(self.registry(), "r-1", "claim-1", "claim-2", "a", 2, 1, "31" * 32, now="2026-07-13T00:00:00Z")
        with self.assertRaises(DebateError):
            debate.respond(self.registry(), "r-2", "claim-1", "claim-2", "a", 1, 11, "31" * 32, now="2026-07-13T00:00:00Z")
        with self.assertRaises(DebateError):
            debate.respond(self.registry(), "r-3", "claim-1", "claim-2", "a", 1, 1, "31" * 32, now="2026-07-13T00:00:02Z")

    def test_synthesis_is_exact_partition_with_evidence_map(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        debate, _, _ = debate.respond(
            self.registry(), "response-1", "claim-1", "claim-2", "agent-a", 1, 20, "31" * 32
        )
        debate, submitted = debate.submit_synthesis(
            self.registry(),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            synthesizer_id="synthesizer-1",
        )
        final, event = debate.finalize(
            self.registry(),
            included=("claim-1",),
            excluded=("claim-2",),
            unresolved=(),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            outcome=DebateOutcome.CONSENSUS,
        )
        self.assertTrue(final.terminal)
        self.assertEqual(submitted["schema"], "DEBATE_SYNTHESIS_SUBMITTED_V1")
        self.assertEqual(event["synthesis_candidate_hash"], submitted["synthesis_candidate_hash"])
        self.assertEqual(event["schema"], "DEBATE_SYNTHESIS_FINALIZED_V1")
        with self.assertRaises(DebateError):
            debate.finalize(self.registry(), included=("claim-1",), excluded=(), unresolved=(), evidence_map={"claim-1": ("21" * 32,)}, outcome=DebateOutcome.CONSENSUS)

    def test_no_consensus_requires_successor_obligation(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        debate, _, _ = debate.respond(
            self.registry(), "response-1", "claim-1", "claim-2", "agent-a", 1, 20, "31" * 32
        )
        debate, _ = debate.submit_synthesis(
            self.registry(),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            synthesizer_id="synthesizer-1",
        )
        final, event = debate.finalize(
            self.registry(), included=(), excluded=(), unresolved=("claim-1", "claim-2"),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            outcome=DebateOutcome.NO_CONSENSUS,
        )
        self.assertIsNotNone(final.successor_obligation_id)
        self.assertEqual(event["next_action"], "CREATE_SUCCESSOR_OBLIGATION")

    def test_max_round_excess_fails_closed_then_escalates_to_successor(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        debate, _, _ = debate.respond(
            self.registry(), "response-1", "claim-1", "claim-2", "agent-a", 2, 20, "31" * 32
        )
        with self.assertRaises(DebateError):
            debate.respond(
                self.registry(), "response-2", "claim-2", "claim-1", "agent-b", 3, 20, "32" * 32
            )
        debate, _ = debate.submit_synthesis(
            self.registry(),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            synthesizer_id="synthesizer-1",
        )
        final, event = debate.finalize(
            self.registry(), included=(), excluded=(), unresolved=("claim-1", "claim-2"),
            evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
            outcome=DebateOutcome.NO_CONSENSUS,
        )
        self.assertEqual(final.outcome, DebateOutcome.NO_CONSENSUS)
        self.assertIsNotNone(final.successor_obligation_id)
        self.assertEqual(event["next_action"], "CREATE_SUCCESSOR_OBLIGATION")

    def test_finalization_without_submitted_synthesis_fails_closed(self) -> None:
        debate, _ = Debate.open("debate-1", "topic-1", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        with self.assertRaises(DebateError):
            debate.finalize(
                self.registry(), included=("claim-1", "claim-2"), excluded=(), unresolved=(),
                evidence_map={"claim-1": ("21" * 32,), "claim-2": ("22" * 32,)},
                outcome=DebateOutcome.CONSENSUS,
            )


if __name__ == "__main__":
    unittest.main()
