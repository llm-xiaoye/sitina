from __future__ import annotations

from pathlib import Path

import pytest

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.local import LocalJournal
from sitina.commands.model import CommandEnvelope
from sitina.journal.model import EventEnvelope
from sitina.memory.native import EpisodeRepository, MemoryACL, MemoryRepository, MemoryStateError
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


def _activated(home: Path):
    leases = CompatibilityLeaseRegistry(home)
    leases.register(RuntimeCompatibilityLease.build(
        process_id="b6-decision-test",
        binary_version="2.0.0",
        reader_capabilities=("memory-v1",),
        writer_capabilities=("memory-v1",),
        started_at="2026-07-18T00:00:00Z",
        lease_expires_at="2026-07-18T01:00:00Z",
        fencing_token=1,
    ))
    activations = FeatureActivationRegistry()
    activations.prepare(
        "memory_v1_write",
        required_reader_capabilities=("memory-v1",),
        leases=leases,
        now="2026-07-18T00:00:01Z",
        journal_position=1,
        journal_control_event={"schema": "RUNTIME_FEATURE_PREPARED_V1", "event_type": "runtime.feature-prepared", "feature": "memory_v1_write"},
    )
    activations.activate(
        "memory_v1_write",
        rollback_floor_version=2,
        journal_position=2,
        journal_control_event={"schema": "RUNTIME_FEATURE_ACTIVATED_V1", "event_type": "runtime.feature-activated", "feature": "memory_v1_write", "rollback_safe_after_first_write": True},
    )
    return activations


def _candidate(repo: MemoryRepository, memory_id: str, *, supersedes: tuple[str, ...] = ()):
    return repo.create_candidate(
        memory_id=memory_id,
        scope="project_shared",
        owner_id="project/example",
        namespace="project/example/b6",
        content=f"lesson {memory_id}",
        source_event_ids=("event-source-1",),
        source_run_ids=("run-source-1",),
        evidence_refs=(),
        confidence=0.8,
        sensitivity="low",
        valid_from="2026-07-18T00:00:00Z",
        expires_at=None,
        retention_policy="until-superseded",
        supersedes=supersedes,
        acl=MemoryACL(
            readers=("memory-agent", "reviewer-1"),
            writers=("memory-agent",),
            reviewers=("reviewer-1",),
        ),
        actor="memory-agent",
    )


def test_decision_lifecycle_reduces_reopen_and_rejects_stale_review(tmp_path: Path) -> None:
    (tmp_path / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
    keys = InMemoryKeyProvider()
    cas = LocalCAS.open(tmp_path, keys)
    journal = LocalJournal.open(tmp_path, JournalAuthProvider(keys))
    activations = _activated(tmp_path)
    try:
        repo = MemoryRepository(journal, cas, keys, feature_activations=activations)
        _candidate(repo, "memory-a")
        repo.apply_memory_decision(
            decision_id="memory-decision-a-accept",
            source_closure={"terminal_event_id": "task-terminal-1", "source_hash": "a" * 64},
            candidate_actions=[{"memory_id": "memory-a", "expected_status": "candidate", "to_status": "accepted", "reason_code": "review-ok"}],
            actor="reviewer-1",
            occurred_at="2026-07-18T00:01:00Z",
        )
        _candidate(repo, "memory-b", supersedes=("memory-a",))
        with pytest.raises(MemoryStateError, match="atomically dispose"):
            repo.apply_memory_decision(
                decision_id="memory-decision-b-only",
                source_closure={"terminal_event_id": "task-terminal-1", "source_hash": "b-only"},
                candidate_actions=[{"memory_id": "memory-b", "expected_status": "candidate", "to_status": "accepted", "reason_code": "review-ok"}],
                actor="reviewer-1",
                occurred_at="2026-07-18T00:01:30Z",
            )
        assert "memory-decision-b-only" not in repo.decision_projection()["by_decision"]
        repo.apply_memory_decision(
            decision_id="memory-decision-b-replace",
            source_closure={"terminal_event_id": "task-terminal-1", "source_hash": "b" * 64},
            candidate_actions=[
                {"memory_id": "memory-b", "expected_status": "candidate", "to_status": "accepted", "reason_code": "review-ok"},
                {"memory_id": "memory-a", "expected_status": "accepted", "to_status": "superseded", "superseded_by": "memory-b", "reason_code": "newer-fact"},
            ],
            actor="reviewer-1",
            occurred_at="2026-07-18T00:02:00Z",
        )
        repo.apply_memory_decision(
            decision_id="memory-decision-b-revoke",
            source_closure={"terminal_event_id": "task-terminal-1", "source_hash": "c" * 64},
            candidate_actions=[{"memory_id": "memory-b", "expected_status": "accepted", "to_status": "revoked", "reason_code": "source-revoked"}],
            actor="reviewer-1",
            occurred_at="2026-07-18T00:03:00Z",
        )
        reopened = MemoryRepository(journal, cas, keys, feature_activations=activations)
        assert reopened.get("memory-a", actor="reviewer-1", include_content=False)[0].status == "superseded"
        assert reopened.get("memory-b", actor="reviewer-1", include_content=False)[0].status == "revoked"
        assert reopened.retrieve(actor="reviewer-1") == ()
        with pytest.raises(MemoryStateError, match="stale"):
            reopened.apply_memory_decision(
                decision_id="memory-decision-b-late",
                source_closure={"terminal_event_id": "task-terminal-1", "source_hash": "late"},
                candidate_actions=[{"memory_id": "memory-b", "expected_status": "accepted", "to_status": "rejected", "reason_code": "late-review"}],
                actor="reviewer-1",
                occurred_at="2026-07-18T00:04:00Z",
            )
    finally:
        journal.close()


def test_episode_b6_identity_cannot_rebind_or_use_legacy_partial_replay(tmp_path: Path) -> None:
    (tmp_path / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
    keys = InMemoryKeyProvider()
    cas = LocalCAS.open(tmp_path, keys)
    journal = LocalJournal.open(tmp_path, JournalAuthProvider(keys))
    activations = _activated(tmp_path)
    try:
        goal = cas.publish_verified(encrypt_object(b"goal", keys, tenant_id="run", purpose="goal"))
        evidence = cas.publish_verified(encrypt_object(b"evidence", keys, tenant_id="run", purpose="evidence"))
        journal.append(
            CommandEnvelope("source-command", "run", "run/source", "run.source", "test", "2026-07-18T00:00:00Z", {}),
            0,
            [EventEnvelope("source-event", "run.source", "run", "run/source", 0, 0, "2026-07-18T00:00:00Z", {"run_id": "run-1"}, ())],
        )
        repo = EpisodeRepository(journal, cas, keys, feature_activations=activations)
        closure = {"actual_envelope_event_id": "loop-event-1", "terminal_event_id": "task-terminal-1", "run_instance_id": "run-1", "execution_epoch": 1}
        frontier = journal.head_position
        first = repo.create(
            episode_id="episode-b6-1",
            source_run_id="run-1",
            goal_ref=goal.object_ref,
            action_event_range=(1, 1),
            terminal_evidence_ref=evidence.object_ref,
            outcome="succeeded",
            failure_reason_code=None,
            lesson="lesson",
            occurred_at="2026-07-18T00:01:00Z",
            obligation_id="task-terminal-1:EPISODE:p1",
            processor_version="p1",
            terminal_event_id="task-terminal-1",
            source_closure=closure,
            source_frontier=frontier,
        )
        assert repo.create(
            episode_id="episode-b6-1",
            source_run_id="run-1",
            goal_ref=goal.object_ref,
            action_event_range=(1, 1),
            terminal_evidence_ref=evidence.object_ref,
            outcome="succeeded",
            failure_reason_code=None,
            lesson="lesson",
            occurred_at="2026-07-18T00:02:00Z",
            obligation_id="task-terminal-1:EPISODE:p1",
            processor_version="p1",
            terminal_event_id="task-terminal-1",
            source_closure=closure,
            source_frontier=frontier,
        ) == first
        with pytest.raises(MemoryStateError, match="different B6 request"):
            repo.create(
                episode_id="episode-b6-1",
                source_run_id="run-1",
                goal_ref=goal.object_ref,
                action_event_range=(1, 1),
                terminal_evidence_ref=evidence.object_ref,
                outcome="succeeded",
                failure_reason_code=None,
                lesson="lesson",
                occurred_at="2026-07-18T00:03:00Z",
                obligation_id="task-terminal-1:EPISODE:p2",
                processor_version="p2",
                terminal_event_id="task-terminal-1",
                source_closure=closure,
                source_frontier=frontier,
            )
        with pytest.raises(MemoryStateError, match="complete terminal identity"):
            repo.create(
                episode_id="episode-b6-1",
                source_run_id="run-1",
                goal_ref=goal.object_ref,
                action_event_range=(1, 1),
                terminal_evidence_ref=evidence.object_ref,
                outcome="succeeded",
                failure_reason_code=None,
                lesson="lesson",
                occurred_at="2026-07-18T00:04:00Z",
                source_closure=closure,
            )
    finally:
        journal.close()


def test_candidate_exact_replay_uses_creation_document_after_lifecycle_updates(tmp_path: Path) -> None:
    (tmp_path / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
    keys = InMemoryKeyProvider()
    cas = LocalCAS.open(tmp_path, keys)
    journal = LocalJournal.open(tmp_path, JournalAuthProvider(keys))
    activations = _activated(tmp_path)
    try:
        repo = MemoryRepository(journal, cas, keys, feature_activations=activations)
        original = _candidate(repo, "memory-replay-lifecycle")
        accepted = repo.transition(
            original.memory_id, "accepted", actor="reviewer-1",
            occurred_at="2026-07-18T00:01:00Z", reason_code="review-approved",
        )
        promoted = repo.promote(
            original.memory_id, to_tier="episodic", actor="reviewer-1",
            occurred_at="2026-07-18T00:02:00Z", reason_code="promote-reviewed",
        )
        quarantined = repo.quarantine(
            original.memory_id, actor="reviewer-1", occurred_at="2026-07-18T00:03:00Z",
            reason_code="quarantine-reviewed", confidence_millionths=100_000,
        )
        replay = _candidate(repo, "memory-replay-lifecycle")
        assert accepted.status == "accepted"
        assert promoted.tier == "episodic"
        assert quarantined.quarantine_status == "quarantined"
        assert replay.memory_id == original.memory_id
        assert replay.status == "accepted"
        assert replay.quarantine_status == "quarantined"
        assert replay.tier == "episodic"
        assert replay.confidence == quarantined.confidence
    finally:
        journal.close()


def test_review_binding_rejects_legacy_change_after_dispatch_snapshot(tmp_path: Path) -> None:
    (tmp_path / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
    keys = InMemoryKeyProvider()
    cas = LocalCAS.open(tmp_path, keys)
    journal = LocalJournal.open(tmp_path, JournalAuthProvider(keys))
    activations = _activated(tmp_path)
    try:
        repo = MemoryRepository(journal, cas, keys, feature_activations=activations)
        _candidate(repo, "memory-review-binding")
        binding = repo.capture_review_binding("memory-review-binding")
        repo.transition(
            "memory-review-binding", "accepted", actor="reviewer-1",
            occurred_at="2026-07-18T00:01:00Z", reason_code="legacy-review",
        )
        with pytest.raises(MemoryStateError, match="review binding is stale"):
            repo.assert_review_binding(binding)
        with pytest.raises(MemoryStateError, match="stale"):
            repo.apply_memory_decision(
                decision_id="memory-decision-review-binding-late",
                source_closure={"terminal_event_id": "task-terminal-review-binding"},
                candidate_actions=[{
                    "memory_id": "memory-review-binding",
                    "expected_status": "candidate",
                    "to_status": "accepted",
                    "reason_code": "review-approved",
                }],
                actor="reviewer-1",
                occurred_at="2026-07-18T00:02:00Z",
                review_request_id="review-request-1",
                candidate_revisions={"memory-review-binding": "rev-1"},
            )
    finally:
        journal.close()


def test_review_binding_exact_replay_reads_current_state_after_commit_and_revoke(tmp_path: Path) -> None:
    (tmp_path / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
    keys = InMemoryKeyProvider()
    cas = LocalCAS.open(tmp_path, keys)
    journal = LocalJournal.open(tmp_path, JournalAuthProvider(keys))
    activations = _activated(tmp_path)
    try:
        repo = MemoryRepository(journal, cas, keys, feature_activations=activations)
        _candidate(repo, "memory-review-replay")
        binding = repo.capture_review_binding("memory-review-replay")
        kwargs = {
            "decision_id": "memory-decision-review-replay",
            "source_closure": {"terminal_event_id": "task-terminal-review-replay"},
            "candidate_actions": [{
                "memory_id": "memory-review-replay",
                "expected_status": "candidate",
                "to_status": "accepted",
                "reason_code": "review-approved",
            }],
            "actor": "reviewer-1",
            "occurred_at": "2026-07-18T00:01:00Z",
            "review_request_id": "review-request-replay",
            "candidate_revisions": {"memory-review-replay": "revision-1"},
            "review_binding": binding,
        }
        first = repo.apply_memory_decision(**kwargs)
        head = journal.head_position
        replay = repo.apply_memory_decision(**kwargs)
        assert replay[0].status == "accepted" and replay[0] == first[0]
        assert journal.head_position == head
        repo.apply_memory_decision(
            decision_id="memory-decision-review-replay-revoke",
            source_closure={"terminal_event_id": "task-terminal-review-replay"},
            candidate_actions=[{
                "memory_id": "memory-review-replay",
                "expected_status": "accepted",
                "to_status": "revoked",
                "reason_code": "review-revoked",
            }],
            actor="reviewer-1",
            occurred_at="2026-07-18T00:02:00Z",
        )
        old_replay = repo.apply_memory_decision(**kwargs)
        assert old_replay[0].status == "revoked"
        assert journal.head_position == head + 1
    finally:
        journal.close()
