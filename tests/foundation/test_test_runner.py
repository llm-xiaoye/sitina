from __future__ import annotations

import json
import hashlib
import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/test-bplus.py"


class LayeredRunnerTests(unittest.TestCase):
    def test_every_test_file_is_registered_in_exactly_one_primary_suite_or_explicitly_reused(self) -> None:
        config = json.loads((ROOT / "tests/test_suites.json").read_text(encoding="utf-8"))
        registered = {
            selector
            for definition in config["suites"].values()
            for selector in definition["selectors"]
        }
        discovered = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "tests").rglob("test_*.py")
        }
        self.assertEqual(discovered, registered)

    def test_suites_are_isolated_and_live_is_opt_in(self) -> None:
        config = json.loads((ROOT / "tests/test_suites.json").read_text(encoding="utf-8"))
        production = Path(config["production_home"]).resolve()
        test_root = Path(config["test_home_root"]).resolve()
        self.assertNotEqual(production, test_root)
        self.assertNotIn(str(production), str(test_root))
        for name in ("unit_fast", "integration_isolated", "crash_fault"):
            definition = config["suites"][name]
            self.assertEqual(definition["external_io_policy"], "DENY_NETWORK_AND_LIVE_ADAPTERS")
            self.assertNotIn("test_live_", " ".join(definition["selectors"]))
        self.assertEqual(
            config["suites"]["live_provider_opt_in"]["external_io_policy"],
            "EXPLICIT_CURRENT_MANIFEST_ONLY",
        )

    def test_execution_activation_gate_has_independent_strict_policy(self) -> None:
        config = json.loads((ROOT / "tests/test_suites.json").read_text(encoding="utf-8"))
        gate = config["suites"]["execution_activation_gate"]
        self.assertEqual(gate["result_policy"], "ZERO_NONPASS_AND_COMPLETE_V1")
        self.assertNotIn("development_pending_skip", gate)
        self.assertIn("tests/test_execution_verifier_frozen.py", gate["selectors"])
        self.assertIn("tests/test_execution_sandbox.py", gate["selectors"])
        from tests.test_execution_verifier_frozen import ProductionVerifierFrozenHomeTests
        pending = ProductionVerifierFrozenHomeTests.test_sandbox_success_accepts_with_test_evidence
        self.assertFalse(getattr(pending, "__unittest_skip__", False))

    def test_activation_gate_accepts_complete_all_pass_suite(self) -> None:
        from tests.foundation.activation_gate_runner import LoadedGateSuite, run_loaded_gate

        class Probe(unittest.TestCase):
            def test_passes(self):
                pass

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Probe)
        test_ids = tuple(test.id() for test in suite)
        summary = run_loaded_gate(
            LoadedGateSuite(suite, {"probe": len(test_ids)}, test_ids, ()),
            stream=io.StringIO(),
        )
        self.assertTrue(summary["accepted"])
        self.assertTrue(summary["collection_complete"])
        self.assertTrue(summary["execution_complete"])
        self.assertEqual(summary["passed"], 1)

    def test_activation_gate_rejects_every_nonpass_category(self) -> None:
        from tests.foundation.activation_gate_runner import LoadedGateSuite, run_loaded_gate

        class Probe(unittest.TestCase):
            def test_failure(self):
                self.fail("failure")

            def test_error(self):
                raise RuntimeError("error")

            @unittest.skip("skip")
            def test_skip(self):
                pass

            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail("expected")

            @unittest.expectedFailure
            def test_unexpected_success(self):
                pass

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Probe)
        test_ids = tuple(test.id() for test in suite)
        summary = run_loaded_gate(
            LoadedGateSuite(suite, {"probe": len(test_ids)}, test_ids, ()),
            stream=io.StringIO(),
        )
        self.assertFalse(summary["accepted"])
        self.assertEqual(summary["failures"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["expected_failures"], 1)
        self.assertEqual(summary["unexpected_successes"], 1)

    def test_runner_uses_timeout_process_group_and_sentinel_checks(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg", source)
        self.assertIn("capture_production_sentinel", source)
        self.assertIn("capture_production_mutable_sentinel", source)
        self.assertIn("production_sentinel_unchanged", source)
        self.assertIn("sys.addaudithook", source)
        self.assertIn("SITINA_PRODUCTION_HOME", source)
        self.assertIn("cwd=home", source)
        self.assertIn("_unittest_selector", source)
        self.assertIn("suite_result_root", source)
        self.assertIn("--execution-manifest", source)
        self.assertIn("--production-sentinel", source)
        self.assertIn("--production-mutable-sentinel", source)
        self.assertNotIn("--record-legacy-baseline", source)

    def test_sentinel_baseline_validation_binds_schema_goal_home_and_manifest_hash(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="sentinel_baseline_probe")
        validate = namespace["_validate_sentinel_baseline"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "production"
            production.mkdir()
            validate.__globals__["CONTROL_ROOT"] = root
            core = {
                "schema": "PRODUCTION_SENTINEL_V1",
                "goal_thread_id": "goal-test",
                "production_home": str(production.resolve()),
                "observation_mode": "RAW_BYTES_READ_ONLY_NO_SQLITE_NO_JSON_PARSE",
                "hash_algorithm": "sha256",
                "categories": [],
            }
            report_hash = hashlib.sha256(
                json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            baseline = root / "sentinel.json"
            baseline.write_text(json.dumps({**core, "report_sha256": report_hash}), encoding="utf-8")
            resolved, value = validate(
                baseline,
                expected_schema="PRODUCTION_SENTINEL_V1",
                production_home=production,
                goal_thread_id="goal-test",
                expected_report_hash="sha256:" + report_hash,
            )
            self.assertEqual(resolved, baseline.resolve())
            self.assertEqual(value["report_sha256"], report_hash)
            with self.assertRaisesRegex(SystemExit, "not bound"):
                validate(
                    baseline,
                    expected_schema="PRODUCTION_SENTINEL_V1",
                    production_home=production,
                    goal_thread_id="goal-test",
                    expected_report_hash="sha256:" + "f" * 64,
                )

    def test_child_process_sees_disposable_home(self) -> None:
        home = Path(os.environ["SITINA_HOME"]).resolve()
        self.assertNotEqual(home, Path("/Users/moss/SitinaHub").resolve())
        self.assertTrue((home / ".sitina-bplus-disposable-v1").is_file())

    def test_application_guard_denies_fake_production_mutation(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="phase_minus1_runner_probe")
        guard_source = namespace["NETWORK_GUARD"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "production"
            disposable = root / "disposable"
            guard = disposable / ".guard"
            (production / "outputs").mkdir(parents=True)
            guard.mkdir(parents=True)
            (guard / "sitecustomize.py").write_text(guard_source, encoding="utf-8")
            attempt_log = disposable / "production-attempts.jsonl"
            environment = dict(os.environ)
            environment.update(
                {
                    "SITINA_PRODUCTION_HOME": str(production),
                    "SITINA_PRODUCTION_ATTEMPT_LOG": str(attempt_log),
                    "SITINA_EXTERNAL_ATTEMPT_LOG": str(disposable / "external-attempts.jsonl"),
                    "PYTHONPATH": str(guard),
                    "HOME": str(disposable),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            program = (
                "from pathlib import Path\n"
                f"allowed=Path({str(disposable / 'allowed.txt')!r})\n"
                f"denied=Path({str(production / 'outputs/denied.txt')!r})\n"
                "allowed.write_text('ok', encoding='utf-8')\n"
                "try:\n"
                " denied.write_text('forbidden', encoding='utf-8')\n"
                "except PermissionError:\n"
                " print('DENIED')\n"
                "else:\n"
                " raise SystemExit('guard allowed fake Production mutation')\n"
            )
            completed = subprocess.run(
                [sys.executable, "-c", program],
                cwd=disposable,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout.strip(), "DENIED")
            self.assertTrue((disposable / "allowed.txt").is_file())
            self.assertFalse((production / "outputs/denied.txt").exists())
            records = [json.loads(line) for line in attempt_log.read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(record.get("event") == "open" for record in records), records)


if __name__ == "__main__":
    unittest.main()
