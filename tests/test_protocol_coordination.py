from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.protocols.arbitration import Arbitration, ArbitrationState
from sitina.protocols.blackboard import Blackboard, BlackboardNamespace, NamespacePolicy, PatchIntent
from sitina.protocols.claims import ClaimRegistry
from sitina.protocols.coordinator import CoordinationError, ProtocolCoordinator
from sitina.protocols.debate import Debate, DebateOutcome
from sitina.protocols.handoffs import Handoff, HandoffState
from sitina.protocols.merge import MergeOperationKind, MergeProtocol, MergeState
from sitina.protocols.obligations import ProtocolRegistryProjection
from sitina.protocols.proposals import ProposalRound
from sitina.protocols.reviews import ArtifactAcceptanceProcess, ReviewError, ReviewRequest, ReviewVerdict
from sitina.protocols.tasks import TaskAggregate
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class ProtocolCoordinationTests(unittest.TestCase):
    def test_terminal_event_derives_stable_successor_command_without_cross_stream_mutation(self) -> None:
        coordinator = ProtocolCoordinator("coordinator-1", "11" * 32, max_steps=5)
        first, command, facts = coordinator.observe(
            "21" * 32,
            {"schema": "DEBATE_SYNTHESIS_FINALIZED_V1", "outcome": "NO_CONSENSUS", "debate_id": "debate-1"},
        )
        replayed, duplicate, replay_facts = first.observe(
            "21" * 32,
            {"schema": "DEBATE_SYNTHESIS_FINALIZED_V1", "outcome": "NO_CONSENSUS", "debate_id": "debate-1"},
        )
        self.assertEqual(command, duplicate)
        self.assertEqual(replay_facts, ())
        self.assertEqual(command.target_stream_id.startswith("obligation/"), True)
        self.assertNotIn("target_mutation", command.payload)

    def test_event_process_command_target_event_chain_rebuilds(self) -> None:
        coordinator = ProtocolCoordinator("coordinator-1", "11" * 32, max_steps=5)
        coordinator, command, _ = coordinator.observe("21" * 32, {"schema": "MERGE_FAILED_V1", "merge_id": "merge-1"})
        rebuilt = ProtocolCoordinator.rebuild("coordinator-1", "11" * 32, coordinator.journal_facts, max_steps=5)
        rebuilt, event = rebuilt.record_outcome(command, "31" * 32, target_event_hash="32" * 32)
        self.assertEqual(event["schema"], "PROTOCOL_COORDINATION_TARGET_OBSERVED_V1")

    def test_cross_protocol_loop_or_max_steps_stalls(self) -> None:
        coordinator = ProtocolCoordinator("coordinator-1", "11" * 32, max_steps=2)
        coordinator, command, _ = coordinator.observe("21" * 32, {"schema": "DEBATE_SYNTHESIS_FINALIZED_V1", "outcome": "NO_CONSENSUS", "debate_id": "d-1"})
        coordinator, _ = coordinator.record_outcome(command, "31" * 32, target_event_hash="32" * 32)
        coordinator, command, _ = coordinator.observe("22" * 32, {"schema": "PROPOSAL_ROUND_NO_SELECTION_V1", "next_action": "ARBITRATION", "round_id": "r-1"})
        coordinator, _ = coordinator.record_outcome(command, "33" * 32, target_event_hash="34" * 32)
        with self.assertRaises(CoordinationError) as captured:
            coordinator.observe("23" * 32, {"schema": "ARBITRATION_FAILED_V1", "arbitration_id": "a-1"})
        self.assertEqual(captured.exception.fact["schema"], "PROTOCOL_COORDINATION_STALL_DETECTED_V1")


class Phase3EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("phase3-e2e\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    def test_parallel_proposal_review_handoff_blackboard_merge_arbitration_replays(self) -> None:
        legacy_paths = ("state/handoffs.json", "state/blackboard.json", "state/proposals.json")
        legacy_before = {
            path: (self.home / path).read_bytes() if (self.home / path).is_file() else None
            for path in legacy_paths
        }
        facts: list[dict] = []

        round_, opened = ProposalRound.open(
            "round-e2e", generation=1, participants=("agent-a", "agent-b"),
            evaluators=("reviewer-1",), rubric_hash="11" * 32,
            policy_hash="12" * 32, deadline="2099-01-01T00:00:00Z",
            minimum_score=70, max_revisions=2,
        )
        facts.append(opened)
        round_, _, submitted_a = round_.submit("proposal-a", "agent-a", "21" * 32)
        round_, _, submitted_b = round_.submit("proposal-b", "agent-b", "22" * 32)
        facts.extend((submitted_a, submitted_b))
        round_, evaluated_a = round_.evaluate("proposal-a", "reviewer-1", score=90, disposition="ACCEPT")
        round_, evaluated_b = round_.evaluate("proposal-b", "reviewer-1", score=60, disposition="NEEDS_REVISION")
        round_, _, revised_b = round_.revise("proposal-b", "23" * 32)
        round_, evaluated_b2 = round_.evaluate("proposal-b", "reviewer-1", score=80, disposition="ACCEPT")
        round_, selected = round_.select("proposal-a", expected_version=round_.version)
        facts.extend((evaluated_a, evaluated_b, revised_b, evaluated_b2, selected))

        claims = ClaimRegistry()
        claims, _, claim_a = claims.create("claim-a", "topic-e2e", "31" * 32, ("41" * 32,))
        claims, _, claim_b = claims.create("claim-b", "topic-e2e", "32" * 32, ("42" * 32,))
        debate, debate_opened = Debate.open("debate-e2e", "topic-e2e", max_rounds=2, max_tokens=100, deadline="2099-01-01T00:00:00Z")
        debate, _, response = debate.respond(claims, "response-e2e", "claim-a", "claim-b", "agent-a", 1, 20, "43" * 32)
        debate, synthesis_submitted = debate.submit_synthesis(
            claims,
            evidence_map={"claim-a": ("41" * 32,), "claim-b": ("42" * 32,)},
            synthesizer_id="synthesizer-e2e",
        )
        debate, synthesis = debate.finalize(
            claims, included=(), excluded=(), unresolved=("claim-a", "claim-b"),
            evidence_map={"claim-a": ("41" * 32,), "claim-b": ("42" * 32,)},
            outcome=DebateOutcome.NO_CONSENSUS,
        )
        facts.extend((claim_a, claim_b, debate_opened, response, synthesis_submitted, synthesis))
        coordinator = ProtocolCoordinator("coordinator-e2e", "51" * 32, max_steps=10)
        coordinator, successor_command, coordination_facts = coordinator.observe("52" * 32, synthesis)
        facts.extend(coordination_facts)
        coordinator = ProtocolCoordinator.rebuild("coordinator-e2e", "51" * 32, coordinator.journal_facts, max_steps=10)
        coordinator, target_observed = coordinator.record_outcome(successor_command, "53" * 32, target_event_hash="54" * 32)
        facts.append(target_observed)

        changed_review, review_opened = ReviewRequest.open("review-changes", "61" * 32, "author-1", "62" * 32, quorum=1, high_risk=False, security_review_required=False)
        changed_review, response_accept = changed_review.respond("reviewer-1", ("review",), False, ReviewVerdict.ACCEPT, "63" * 32)
        changed_review, response_changes = changed_review.respond("reviewer-2", ("review",), False, ReviewVerdict.NEEDS_CHANGES, "64" * 32)
        changed_review, changes_disposition = changed_review.dispose()
        with self.assertRaises(ReviewError):
            ArtifactAcceptanceProcess.freeze(changed_review, criteria_hash="65" * 32, policy_hash="66" * 32)
        facts.extend((review_opened, response_accept, response_changes, changes_disposition))
        review, review_opened = ReviewRequest.open("review-final", "67" * 32, "author-1", "62" * 32, quorum=2, high_risk=True, security_review_required=True)
        review, response_one = review.respond("reviewer-1", ("review",), False, ReviewVerdict.ACCEPT, "68" * 32)
        review, response_two = review.respond("security-1", ("review", "security-review"), False, ReviewVerdict.ACCEPT, "69" * 32)
        review, review_disposition = review.dispose()
        acceptance = ArtifactAcceptanceProcess.freeze(review, criteria_hash="65" * 32, policy_hash="66" * 32)
        acceptance, artifact_accepted = acceptance.accept(review.artifact_hash, approval_artifact_hash=review.artifact_hash)
        facts.extend((review_opened, response_one, response_two, review_disposition, artifact_accepted))

        handoff, offered = Handoff.offer("handoff-e2e", 1, "sender-1", "receiver-1", "task-e2e", "71" * 32, policy_hash="72" * 32, capability_hash="73" * 32, budget=100, deadline="2099-01-01T00:00:00Z", high_risk=True, required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",), input_freeze_hash="74" * 32, output_schema_hash="75" * 32)
        handoff, rejected = handoff.reject("receiver-1", "needs-reframing")
        handoff, generation = handoff.new_generation(specification_hash="76" * 32, policy_hash="77" * 32, capability_hash="78" * 32, budget=80, deadline="2099-02-01T00:00:00Z", required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",), input_freeze_hash="79" * 32, output_schema_hash="7a" * 32, previous_generation_ref="cas:" + "7b" * 32, previous_rejection_event_ref="event-handoff-rejected-e2e", reject_reason_resolution_hash="7c" * 32)
        handoff, accepted_handoff = handoff.accept("receiver-1")
        task, attempt, claimed = TaskAggregate("task-e2e", "76" * 32).claim(claim_command_id="claim-e2e", lease_expires_at="2099-01-01T00:00:00Z", holder_agent_id="receiver-1")
        handoff, claim_pending = handoff.mark_claim_pending("receiver-1", task_claim_ref="7d" * 32, fencing_token=attempt.fencing_token)
        handoff, claim_bound = handoff.bind_claim(task, attempt.fencing_token)
        handoff, executing = handoff.execute("receiver-1")
        handoff, submitted = handoff.submit("receiver-1", review.artifact_hash, output_schema_hash="7a" * 32, schema_validation_evidence_hash="7e" * 32)
        handoff, verified = handoff.verify("independent-verifier", accepted=True, verification_evidence_hash="7f" * 32)
        self.assertEqual(handoff.state, HandoffState.VERIFIED)
        facts.extend((offered, rejected, generation, accepted_handoff, claim_pending, claimed, claim_bound, executing, submitted, verified))

        board = Blackboard({BlackboardNamespace.FACTS: NamespacePolicy("81" * 32, ("facts-write",), True, "APPEND_ONLY", "INTERNAL", 256)})
        document, created_document = board.create("document-e2e", BlackboardNamespace.FACTS)
        board.declare_dependencies("obligation-blackboard", ("document-e2e",))
        patch = PatchIntent("document-e2e", 0, document.document_hash, {"fact": "candidate-a"}, "receiver-1", ("facts-write",), task.task_id, attempt.task_attempt_id, attempt.claim_generation, attempt.fencing_token, ("82" * 32,), ("proposal-a@1", "proposal-b@2"))
        patched = board.patch(patch, task=task)
        conflict = board.patch(patch, task=task)
        self.assertEqual(conflict.blocked_obligations, ("obligation-blackboard",))
        facts.extend((created_document, patched.event, conflict.conflict))
        merge, merge_opened = MergeProtocol.open("merge-e2e", "document-e2e", patched.document.version, patched.document.document_hash, allowed_kinds=(MergeOperationKind.APPEND_ONLY,))
        merge, merge_failed = merge.fail("stale-base-conflict")
        self.assertEqual(merge.state, MergeState.ESCALATED)
        arbitration, arbitration_opened = Arbitration.open("arbitration-e2e", merge.arbitration_obligation_id, "91" * 32, max_appeals=1, appeal_deadline="2099-01-01T00:00:00Z", appeal_authorities=("appeals-board",))
        arbitration, admitted = arbitration.admit(("claim-a", "claim-b"), "arbiter-1")
        arbitration, decided = arbitration.decide("candidate-a-wins", binding_scope=("task-e2e",), evidence_refs=("92" * 32,))
        self.assertTrue(arbitration.blocks_dispatch("task-e2e"))
        arbitration, enforced = arbitration.enforce("93" * 32)
        self.assertEqual(arbitration.state, ArbitrationState.ENFORCED)
        self.assertTrue(arbitration.obligation_satisfied)
        facts.extend((merge_opened, merge_failed, arbitration_opened, admitted, decided, enforced))

        registry_facts = (
            {"schema": "PROTOCOL_CREATED_V1", "protocol_id": "protocol-e2e", "run_id": "run-e2e"},
            {"schema": "OBLIGATION_CREATED_V1", "obligation_id": "obligation-e2e", "run_id": "run-e2e", "required_for_run_terminal": True},
            {"schema": "PROTOCOL_TERMINAL_V1", "protocol_id": "protocol-e2e", "state": "COMPLETED"},
            {"schema": "OBLIGATION_TERMINAL_V1", "obligation_id": "obligation-e2e", "state": "SATISFIED"},
        )
        facts.extend(registry_facts)
        registry = ProtocolRegistryProjection()
        for position, fact in enumerate(registry_facts, start=1):
            registry = registry.apply(fact, source_position=position)
        rebuilt_registry = ProtocolRegistryProjection()
        for position, fact in enumerate(registry_facts, start=1):
            rebuilt_registry = rebuilt_registry.apply(fact, source_position=position)
        self.assertEqual(registry, rebuilt_registry)
        self.assertEqual(registry.required_open_count("run-e2e"), 0)

        auth = JournalAuthProvider(InMemoryKeyProvider())
        journal = LocalJournal.open(self.home, auth, journal_id="journal-phase3-e2e", namespace_kind="controlled_fixture")
        events = tuple(EventEnvelope(f"phase3-e2e-event-{index}", str(fact["schema"]).lower(), "tenant-e2e", "run-e2e", 0, 0, "2026-07-13T00:00:00Z", fact) for index, fact in enumerate(facts, start=1))
        command = CommandEnvelope("phase3-e2e-lifecycle", "tenant-e2e", "run-e2e", "phase3-e2e", "fixture", "2026-07-13T00:00:00Z", {"fact_count": len(facts)})
        receipt = journal.append(command, 0, events)
        event_hashes = tuple(event.event_hash for event in journal.iter_events())
        journal.close()
        recovered = LocalJournal.open(self.home, auth, journal_id="journal-phase3-e2e", namespace_kind="controlled_fixture")
        self.assertEqual(tuple(event.event_hash for event in recovered.iter_events()), event_hashes)
        self.assertEqual(recovered.query_command(command.command_id, command.command_request_hash).canonical_outcome_ref, receipt.transaction_hash)
        recovered.close()
        legacy_after = {path: (self.home / path).read_bytes() if (self.home / path).is_file() else None for path in legacy_paths}
        self.assertEqual(legacy_before, legacy_after)


if __name__ == "__main__":
    unittest.main()
