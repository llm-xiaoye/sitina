#!/usr/bin/env python3
"""Read-only offline Code Mode runner.

The runner freezes a candidate in memory and optionally evaluates an externally
provided offline test result and independent review.  It never loads Legacy B+
foundation/activation data and never sends a Provider request.  A real canary
must be authorized by the existing conversation/runtime path after this
offline result is independently reviewed.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "core") not in sys.path:
    sys.path.insert(0, str(ROOT / "core"))

from sitina.orchestrator.code_mode_gate import (  # noqa: E402
    CODE_MODE_BLOCKED,
    CodeModeAcceptanceV1,
    build_candidate_manifest,
    load_code_mode_profile,
    verify_candidate_manifest,
)


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--test-result", type=Path)
    parser.add_argument("--review-status", default="NOT_REVIEWED")
    parser.add_argument("--review-candidate-id")
    parser.add_argument("--dry-run", action="store_true", help="prove the runner uses zero Provider requests")
    parser.add_argument("--output", type=Path, help="optional explicit output path")
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve(strict=True)
    profile = load_code_mode_profile(workspace)
    candidate = build_candidate_manifest(
        workspace,
        identity_paths=tuple(str(item) for item in profile.get("identity_paths", ())),
    )
    if args.test_result:
        test_result = _load(args.test_result)
        reviewer = {
            "status": args.review_status,
            "candidate_id": args.review_candidate_id or candidate["candidate_id"],
        }
        result = CodeModeAcceptanceV1(workspace, profile=profile).evaluate_offline(
            candidate,
            test_result=test_result,
            reviewer=reviewer,
        )
    else:
        candidate_valid, candidate_drift = verify_candidate_manifest(workspace, candidate)
        result = {
            "schema": "CODE_EXECUTION_ACCEPTANCE_V1",
            "status": CODE_MODE_BLOCKED,
            "code_mode_status": "CODE_MODE_CANDIDATE_FROZEN" if candidate_valid else CODE_MODE_BLOCKED,
            "candidate_id": candidate["candidate_id"],
            "candidate": candidate,
            "candidate_valid": candidate_valid,
            "candidate_drift": candidate_drift,
            "reasons": ["offline test result and independent review are not supplied"],
            "legacy_bplus_status": "LEGACY_BPLUS_BLOCKED",
            "legacy_foundation_consulted": False,
        }
    result = dict(result)
    result.update({
        "runner": "code-mode-runner-v1",
        "run_id": "code-mode-offline-" + uuid.uuid4().hex,
        "dry_run": bool(args.dry_run),
        "provider_mode": "offline_non_authoritative",
        "authoritative": False,
        "canary_eligible": False,
        "provider_requests": 0,
        "physical_requests": 0,
        "fallback_requests": 0,
        "deployment_triggered": False,
        "execution_performed": False,
    })
    if args.dry_run:
        result["dry_run_status"] = "DRY_RUN_PASSED"
    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.expanduser().resolve().write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    # A dry-run may complete successfully while Code Mode remains blocked due
    # to missing test/reviewer evidence.  Keep those statuses distinct.
    if args.dry_run:
        return 0
    return 0 if result.get("status") in {"CODE_MODE_CANDIDATE_FROZEN", "CODE_MODE_READY"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
