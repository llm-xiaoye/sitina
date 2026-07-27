from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.step7_readiness_gate import (
    CANDIDATE_SCHEMA,
    ENTRY_CANDIDATE_SHA256,
    FORBIDDEN_ACTION_FIELDS,
    HISTORICAL_SKIP_IDS,
    READY_MARKER,
    REQUIRED_GATES,
    validate_step7_candidate,
)


ENTRY_CANDIDATE = Path(
    "/Users/moss/Desktop/sitina/output/"
    "sitina-step7-entry-review-candidate-step56-45a36be.json"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Step7ReadinessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        if not ENTRY_CANDIDATE.is_file():
            self.fail(f"missing authoritative entry candidate: {ENTRY_CANDIDATE}")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.deployment = self.root / "deployment"
        self.output = self.root / "output"
        for path in (self.source, self.deployment, self.output):
            path.mkdir()
        policy = {
            "schema": "SITINA_TRUE_MULTI_AGENT_POLICY_V1",
            "tool_calls_allowed": False,
            "external_mutation_allowed": False,
            "execution_bridge_enabled": False,
            "execution_handoff_bypass_enabled": False,
        }
        (self.source / "config").mkdir()
        (self.source / "config/true_multi_agent_policy.json").write_text(
            json.dumps(policy, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (self.source / "tracked.txt").write_text("Step7 tracked source\n", encoding="utf-8")
        shutil.copytree(self.source / "config", self.deployment / "config")
        shutil.copy2(self.source / "tracked.txt", self.deployment / "tracked.txt")
        self._git("init", "-q")
        self._git("config", "user.email", "step7-tests@example.invalid")
        self._git("config", "user.name", "Step7 Tests")
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")

        cleanup_candidate = {
            "schema": "SITINA_CLEANUP_CANDIDATE_STEP7_V1",
            "new_cleanup_actions_proposed": 0,
            "objects": [
                {
                    "path": "/recoverable/quarantine",
                    "recommendation": "KEEP",
                    "approval_status": "NOT_REQUIRED_NO_NEW_ACTION",
                }
            ],
        }
        cleanup_ledger = {
            "schema": "SITINA_CLEANUP_LEDGER_STEP7_V1",
            "approved_action_count": 1,
            "completed_approved_action_count": 1,
            "new_actions_performed_during_step7": 0,
            "unapproved_actions_performed": 0,
            "permanent_deletion": False,
        }
        self.cleanup_candidate = self._json_file("cleanup-candidate.json", cleanup_candidate)
        self.cleanup_ledger = self._json_file("cleanup-ledger.json", cleanup_ledger)
        self.rollback = self._json_file(
            "rollback.json",
            {
                "schema": "SITINA_STEP7_ROLLBACK_PROOF_V1",
                "recoverable": True,
            },
        )
        self.general_evidence = self._json_file(
            "general-evidence.json",
            {"schema": "SITINA_STEP7_TEST_EVIDENCE_V1", "accepted": True},
        )
        self.audit = self.output / "review.jsonl"
        self.audit.write_text(
            json.dumps({"event": "run_succeeded", "verdict": "PASS"}) + "\n",
            encoding="utf-8",
        )
        self.gate_evidence: dict[str, Path] = {
            stage: self._json_file(
                f"{stage}.json",
                {"schema": "SITINA_TEST_GATE_EVIDENCE_V1", "stage": stage},
            )
            for stage in REQUIRED_GATES
        }
        self.candidate = self._valid_candidate()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", *arguments],
            cwd=self.source,
            text=True,
        ).strip()

    def _json_file(self, name: str, value: dict[str, object]) -> Path:
        path = self.output / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _reference(path: Path) -> dict[str, str]:
        return {"path": str(path), "sha256": sha256(path)}

    def _review(self) -> dict[str, object]:
        return {
            "run_id": "agent-run-step7-fixture",
            "provider_mode": "live",
            "profile": "deepseek",
            "model": "deepseek-v4-pro",
            "started_at_utc": "2026-07-27T00:00:00Z",
            "ended_at_utc": "2026-07-27T00:01:00Z",
            "provider_calls": 2,
            "physical_sends": 2,
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "cost_micro_usd": 1,
            "verdict": "PASS",
            "input_sha256": "a" * 64,
            "output_sha256": "b" * 64,
            "tool_call_types": ["read"],
            "file_changes": 0,
            "external_changes": 0,
            "audit": self._reference(self.audit),
        }

    def _valid_candidate(self) -> dict[str, object]:
        counts = {
            "minimal_negative_contract": 8,
            "identity_sentinel_directed": 56,
            "execution_activation": 60,
            "step7_readiness_gate": 24,
            "unit_fast": 232,
            "integration_isolated": 200,
            "all_registered_unique": 985,
        }
        gates: list[dict[str, object]] = []
        for stage in REQUIRED_GATES:
            skipped = 5 if stage == "all_registered_unique" else 0
            gate: dict[str, object] = {
                "stage": stage,
                "collected": counts[stage],
                "executed": counts[stage],
                "passed": counts[stage] - skipped,
                "failed": 0,
                "errors": 0,
                "skipped": skipped,
                "xfail": 0,
                "xpass": 0,
                "warnings": 0,
                "external_attempts": 0,
                "production_attempts": 0,
                "collection_complete": True,
                "execution_complete": True,
                "control_override_used": False,
                "live_override_used": False,
                "skip_ids": list(HISTORICAL_SKIP_IDS) if skipped else [],
                "evidence": self._reference(self.gate_evidence[stage]),
            }
            if stage == "all_registered_unique":
                gate.update(
                    {
                        "skip_allowlist_match": True,
                        "discovered_test_files": 170,
                        "registered_unique_selectors": 170,
                    }
                )
            gates.append(gate)
        return {
            "schema": CANDIDATE_SCHEMA,
            "marker": READY_MARKER,
            "step5_step6_formally_accepted": True,
            "step56_entry_candidate": {
                "path": str(ENTRY_CANDIDATE),
                "sha256": ENTRY_CANDIDATE_SHA256,
            },
            "source": {
                "root": str(self.source.resolve()),
                "head": self._git("rev-parse", "HEAD^{commit}"),
                "tree": self._git("rev-parse", "HEAD^{tree}"),
                "worktree_clean": True,
                "changed_files": [
                    "scripts/step7_readiness_gate.py",
                    "tests/foundation/test_step7_readiness_gate.py",
                    "tests/test_suites.json",
                ],
            },
            "gates": gates,
            "cleanup": {
                "candidate": self._reference(self.cleanup_candidate),
                "ledger": self._reference(self.cleanup_ledger),
                "real_sitina_review": self._review(),
            },
            "real_sitina_review": self._review(),
            "source_deployment": {
                "source_root": str(self.source.resolve()),
                "deployment_root": str(self.deployment.resolve()),
                "tracked_file_count": 2,
                "exact_match_count": 2,
            },
            "execution_switches": {
                "tool_calls_allowed": False,
                "external_mutation_allowed": False,
                "execution_bridge_enabled": False,
                "execution_handoff_bypass_enabled": False,
            },
            "production_sentinel": {
                "goal_id": "goal-step7-fixture",
                "base_v2_before": "1" * 64,
                "base_v2_after": "1" * 64,
                "mutable_v3_before": "2" * 64,
                "mutable_v3_after": "2" * 64,
                "production_attempts": 0,
            },
            "rollback_proof": {
                "verified": True,
                "artifacts": [self._reference(self.rollback)],
            },
            "evidence": [self._reference(self.general_evidence)],
            "remaining_risks": [],
            "pending_production_actions": [
                {
                    "action": "STEP8_CONTROLLED_CANARY",
                    "approval_required": True,
                    "status": "NOT_AUTHORIZED",
                }
            ],
            "forbidden_actions": {
                field: False for field in FORBIDDEN_ACTION_FIELDS
            },
            "authorization_to_enter_step8": False,
        }

    def _validate(self, candidate: dict[str, object] | None = None) -> dict[str, object]:
        return validate_step7_candidate(
            candidate or self.candidate,
            source_root=self.source,
            deployment_root=self.deployment,
        )

    def assertRejected(
        self,
        candidate: dict[str, object],
        fragment: str,
    ) -> None:
        result = self._validate(candidate)
        self.assertFalse(result["accepted"])
        self.assertTrue(
            any(fragment in error for error in result["errors"]),
            result["errors"],
        )

    def test_valid_candidate_is_accepted_without_granting_step8(self) -> None:
        result = self._validate()
        self.assertTrue(result["accepted"], result["errors"])
        self.assertEqual(result["error_count"], 0)
        self.assertFalse(result["step8_admission_granted"])
        self.assertEqual(result["marker"], READY_MARKER)

    def test_wrong_schema_or_marker_is_rejected(self) -> None:
        for field, value, fragment in (
            ("schema", "OLD_STEP7", "schema"),
            ("marker", "SITINA_STEP8_CANARY", "marker"),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate[field] = value
                self.assertRejected(candidate, fragment)

    def test_wrong_entry_candidate_hash_or_formal_status_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["step56_entry_candidate"]["sha256"] = "0" * 64
        self.assertRejected(candidate, "Step5/6 entry candidate")
        candidate = copy.deepcopy(self.candidate)
        candidate["step5_step6_formally_accepted"] = False
        self.assertRejected(candidate, "formal Step5/6")

    def test_stale_head_or_tree_is_rejected(self) -> None:
        for field, fragment in (("head", "HEAD"), ("tree", "tree")):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["source"][field] = "0" * 40
                self.assertRejected(candidate, fragment)

    def test_dirty_worktree_is_rejected(self) -> None:
        (self.source / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        self.assertRejected(self.candidate, "not clean")

    def test_incomplete_or_unknown_gate_set_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"].pop()
        self.assertRejected(candidate, "gate set")
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"].append(copy.deepcopy(candidate["gates"][0]))
        candidate["gates"][-1]["stage"] = "old_phase6b_step7"
        self.assertRejected(candidate, "gate set")

    def test_each_nonpass_gate_category_is_rejected(self) -> None:
        for field in ("failed", "errors", "xfail", "xpass", "warnings"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                gate = candidate["gates"][0]
                gate[field] = 1
                gate["passed"] -= 1
                self.assertRejected(candidate, field)

    def test_incomplete_or_under_count_gate_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"][2]["executed"] -= 1
        self.assertRejected(candidate, "execute every collected")
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"][4].update(
            {"collected": 207, "executed": 207, "passed": 207}
        )
        self.assertRejected(candidate, "acceptance floor")

    def test_skip_allowlist_must_match_exactly(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        aggregate = candidate["gates"][-1]
        aggregate["skip_ids"] = aggregate["skip_ids"][:-1] + ["replacement.skip"]
        self.assertRejected(candidate, "skip allowlist mismatch")

    def test_unexpected_skip_outside_registered_aggregate_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        gate = candidate["gates"][0]
        gate["skipped"] = 1
        gate["passed"] -= 1
        gate["skip_ids"] = ["unexpected.skip"]
        self.assertRejected(candidate, "unexpected skip")

    def test_control_or_live_override_is_rejected(self) -> None:
        for field in ("control_override_used", "live_override_used"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["gates"][0][field] = True
                self.assertRejected(candidate, "used an override")

    def test_non_live_wrong_model_or_missing_verdict_review_is_rejected(self) -> None:
        for field, value, fragment in (
            ("provider_mode", "mock", "live provider"),
            ("model", "substitute-model", "profile/model"),
            ("verdict", None, "PASS verdict"),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["real_sitina_review"][field] = value
                self.assertRejected(candidate, fragment)

    def test_zero_or_inconsistent_review_usage_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["total_tokens"] = 0
        self.assertRejected(candidate, "total_tokens")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["total_tokens"] = 100
        self.assertRejected(candidate, "token accounting")

    def test_non_read_tool_or_review_mutation_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["tool_call_types"] = ["read", "write"]
        self.assertRejected(candidate, "non-read tool")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["file_changes"] = 1
        self.assertRejected(candidate, "changed files")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["external_changes"] = 1
        self.assertRejected(candidate, "external state")

    def test_sentinel_drift_wrong_goal_or_production_attempt_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["production_sentinel"]["base_v2_after"] = "3" * 64
        self.assertRejected(candidate, "base_v2")
        candidate = copy.deepcopy(self.candidate)
        candidate["production_sentinel"]["goal_id"] = ""
        self.assertRejected(candidate, "Goal binding")
        candidate = copy.deepcopy(self.candidate)
        candidate["production_sentinel"]["production_attempts"] = 1
        self.assertRejected(candidate, "production attempt")

    def test_each_execution_switch_must_remain_false(self) -> None:
        for field in self.candidate["execution_switches"]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["execution_switches"][field] = True
                self.assertRejected(candidate, field)

    def test_missing_deployment_file_is_rejected(self) -> None:
        (self.deployment / "tracked.txt").unlink()
        self.assertRejected(self.candidate, "missing")

    def test_source_deployment_content_mismatch_is_rejected(self) -> None:
        (self.deployment / "tracked.txt").write_text("different\n", encoding="utf-8")
        self.assertRejected(self.candidate, "content mismatch")

    def test_source_deployment_mode_mismatch_is_rejected(self) -> None:
        deployment_file = self.deployment / "tracked.txt"
        deployment_file.chmod(stat.S_IMODE(deployment_file.stat().st_mode) ^ stat.S_IXUSR)
        self.assertRejected(self.candidate, "mode mismatch")

    def test_source_deployment_symlink_is_rejected(self) -> None:
        deployment_file = self.deployment / "tracked.txt"
        deployment_file.unlink()
        deployment_file.symlink_to(self.deployment / "config/true_multi_agent_policy.json")
        self.assertRejected(self.candidate, "unsafe tracked")

    def test_incomplete_unapproved_or_destructive_cleanup_is_rejected(self) -> None:
        for field, value, fragment in (
            ("completed_approved_action_count", 0, "not fully completed"),
            ("new_actions_performed_during_step7", 1, "new cleanup action"),
            ("unapproved_actions_performed", 1, "unapproved action"),
            ("permanent_deletion", True, "permanent deletion"),
        ):
            with self.subTest(field=field):
                ledger = json.loads(self.cleanup_ledger.read_text(encoding="utf-8"))
                ledger[field] = value
                self.cleanup_ledger.write_text(
                    json.dumps(ledger, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                candidate = copy.deepcopy(self.candidate)
                candidate["cleanup"]["ledger"] = self._reference(self.cleanup_ledger)
                self.assertRejected(candidate, fragment)
                self.cleanup_ledger.write_text(
                    json.dumps(
                        {
                            "schema": "SITINA_CLEANUP_LEDGER_STEP7_V1",
                            "approved_action_count": 1,
                            "completed_approved_action_count": 1,
                            "new_actions_performed_during_step7": 0,
                            "unapproved_actions_performed": 0,
                            "permanent_deletion": False,
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )

    def test_cleanup_requires_its_own_real_sitina_review(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["cleanup"]["real_sitina_review"]["verdict"] = "FAIL"
        self.assertRejected(candidate, "cleanup Sitina review")

    def test_cleanup_ledger_hash_mismatch_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["cleanup"]["ledger"]["sha256"] = "0" * 64
        self.assertRejected(candidate, "cleanup ledger SHA-256")

    def test_rollback_proof_and_artifact_hash_are_required(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["verified"] = False
        self.assertRejected(candidate, "rollback proof")
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["artifacts"][0]["sha256"] = "0" * 64
        self.assertRejected(candidate, "rollback artifact")

    def test_bound_evidence_must_be_regular_and_hash_verified(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"][0]["sha256"] = "0" * 64
        self.assertRejected(candidate, "bound evidence")
        link = self.output / "evidence-link.json"
        link.symlink_to(self.general_evidence)
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"] = [{"path": str(link), "sha256": sha256(link)}]
        self.assertRejected(candidate, "regular non-symlink")

    def test_every_forbidden_action_and_step8_admission_is_rejected(self) -> None:
        for field in FORBIDDEN_ACTION_FIELDS:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["forbidden_actions"][field] = True
                self.assertRejected(candidate, field)
        candidate = copy.deepcopy(self.candidate)
        candidate["authorization_to_enter_step8"] = True
        self.assertRejected(candidate, "Step8 admission")

    def test_pending_production_actions_remain_unauthorized(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["pending_production_actions"] = []
        self.assertRejected(candidate, "pending production actions")
        candidate = copy.deepcopy(self.candidate)
        candidate["pending_production_actions"][0]["status"] = "AUTHORIZED"
        self.assertRejected(candidate, "approval-bound and unauthorized")


if __name__ == "__main__":
    unittest.main()
