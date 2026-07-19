"""Fixture-only semantic baseline for the pre-B+ Sitina runtime."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.orchestrator.evidence_bundle import EvidenceBundleManager
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.storage import SitinaStore


NORMALIZATION_PROFILE = "LEGACY_BEHAVIOR_NORMALIZATION_V1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _hash_files(paths: list[Path], root: Path, *, normalize_home: bool = False) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        content = path.read_bytes()
        if normalize_home:
            content = content.replace(str(root).encode("utf-8"), b"$SITINA_HOME")
        digest.update(hashlib.sha256(content).digest())
        digest.update(b"\n")
    return digest.hexdigest()


@dataclass(frozen=True)
class LegacyBehaviorBaseline:
    document: Mapping[str, Any]

    @property
    def semantic_hash(self) -> str:
        return str(self.document["semantic_hash"])


class LegacyBehaviorBaselineBuilder:
    def __init__(self, home: Path, *, python_profile_hash: str):
        self.home = home.resolve(strict=True)
        self.python_profile_hash = python_profile_hash.removeprefix("sha256:")

    def _cli_semantics(self, run_id: str) -> dict[str, Any]:
        launcher = self.home / "bin/sitina"
        environment = dict(os.environ)
        environment.update({"SITINA_HOME": str(self.home), "SITINA_LIVE_TEST": "0"})
        commands = {
            "list": ["list"],
            "show": ["show", run_id],
            "trace": ["trace", run_id],
            "replay": ["replay", run_id],
            "report_live": ["report", "live", run_id],
            "report_acceptance": ["report", "acceptance", run_id],
            "export_run": ["export-run", run_id],
        }
        results: dict[str, Any] = {}
        for name, arguments in commands.items():
            completed = subprocess.run(
                [str(launcher), *arguments],
                cwd=self.home,
                env=environment,
                text=True,
                capture_output=True,
                timeout=90,
            )
            parsed: Any = None
            if completed.stdout.strip():
                try:
                    parsed = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    parsed = None
            results[name] = {
                "return_code": completed.returncode,
                "json_object": isinstance(parsed, dict),
                "status": parsed.get("status") if isinstance(parsed, dict) else None,
            }
        return results

    def capture(self) -> LegacyBehaviorBaseline:
        store = SitinaStore(self.home)
        engine = SitinaEngine(self.home)
        engine.initialize()
        result = engine.run(
            "proposal-competition-fixture phase-minus1 legacy behavior baseline",
            provider_mode="mock",
        )
        run_id = str(result["run_id"])
        timeline = RunLedger(self.home, store).timeline(run_id)
        replay = ReplayEngine(self.home, store).replay(run_id, record=False)
        event_counts = collections.Counter(str(item.get("event_type")) for item in timeline)
        evidence = EvidenceBundleManager(self.home, store).export(run_id)
        task_graph = replay.task_graph_summary
        graph_semantics = {
            "node_count": int(task_graph.get("node_count", len(replay.node_states)) or 0),
            "node_state_counts": dict(sorted(collections.Counter(replay.node_states.values()).items())),
            "gate_count": len(replay.gates),
            "rework_edge_count": len(replay.rework_edges),
        }
        proposals = replay.proposals or {}
        semantic = {
            "run": {
                "status": result.get("status"),
                "terminal_event_types": [
                    event_type
                    for event_type in ("run_completed", "run_blocked", "run_failed", "run_timeout", "run_cancelled")
                    if event_counts.get(event_type)
                ],
                "event_type_counts": dict(sorted(event_counts.items())),
            },
            "task_graph": graph_semantics,
            "proposal": {
                "submitted_count": len(proposals.get("submitted", [])),
                "evaluation_count": len(proposals.get("evaluations", [])),
                "selection_count": len(proposals.get("selections", [])),
            },
            "review": {
                "review_event_count": sum(count for name, count in event_counts.items() if "review" in name),
                "reviewer_merge_count": len(replay.reviewer_merges),
            },
            "handoff": {"count": len(replay.handoff_chain)},
            "arbitration": {"count": len(replay.arbitrations)},
            "blackboard": {
                "present": bool(replay.blackboard_summary),
                "keys": sorted(replay.blackboard_summary),
            },
            "lease": {"count": len(replay.leases)},
            "side_effect": {
                "count": len(replay.side_effects),
                "status_counts": dict(
                    sorted(collections.Counter(item.status for item in replay.side_effects).items())
                ),
            },
            "replay": {
                "status": replay.status,
                "missing_event_count": len(replay.missing_events),
                "inconsistent_event_count": len(replay.inconsistent_events),
            },
            "evidence_export": {"status": evidence.get("status")},
            "cli": self._cli_semantics(run_id),
            "external_call_count": 0,
        }
        source_files = [path for path in (self.home / "core").rglob("*.py") if path.is_file()]
        config_files = [
            path
            for path in (self.home / "config").rglob("*")
            if path.is_file() and path.suffix in {".json", ".yaml", ".yml"}
        ]
        fixture_path = self.home / "fixtures/legacy"
        fixture_files = [path for path in fixture_path.rglob("*") if path.is_file()]
        bindings = {
            "source_manifest_hash": _hash_files(source_files, self.home),
            "fixture_hash": _hash_files(fixture_files, self.home),
            "config_policy_hash": _hash_files(config_files, self.home, normalize_home=True),
            "python_profile_hash": self.python_profile_hash,
        }
        core = {
            "schema": "LEGACY_BEHAVIOR_BASELINE_V1",
            "normalization_profile": NORMALIZATION_PROFILE,
            "normalization_rules": [
                "DROP_TIMESTAMPS",
                "DROP_RANDOM_IDS",
                "DROP_ABSOLUTE_PATHS",
                "DROP_REPRESENTATION_ROW_IDS",
                "PRESERVE_DISPOSITIONS_COUNTS_HASHES_APPROVALS_SAFETY_AND_EXTERNAL_CALL_COUNT",
            ],
            "bindings": bindings,
            "semantic": semantic,
            "difference_classes": [
                "EXPECTED_REPRESENTATION_CHANGE",
                "APPROVED_SEMANTIC_CHANGE",
                "REGRESSION",
            ],
        }
        return LegacyBehaviorBaseline({**core, "semantic_hash": hashlib.sha256(_canonical(core)).hexdigest()})


def _verify_existing_baseline(path: Path, baseline: LegacyBehaviorBaseline) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        existing = json.load(handle)
    if existing != baseline.document:
        existing_hash = hashlib.sha256(_canonical(existing)).hexdigest()
        candidate_hash = hashlib.sha256(_canonical(baseline.document)).hexdigest()
        raise RuntimeError(
            "existing baseline differs from deterministic recapture: "
            f"existing={existing_hash} candidate={candidate_hash}"
        )
    return "verified_existing"


def write_baseline(path: Path, baseline: LegacyBehaviorBaseline) -> str:
    if path.exists():
        return _verify_existing_baseline(path, baseline)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _verify_existing_baseline(path, baseline)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(baseline.document, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return "created"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--python-profile-hash", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    baseline = LegacyBehaviorBaselineBuilder(
        arguments.home, python_profile_hash=arguments.python_profile_hash
    ).capture()
    action = write_baseline(arguments.output, baseline)
    print(json.dumps({"output": str(arguments.output), "semantic_hash": baseline.semantic_hash, "action": action}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
