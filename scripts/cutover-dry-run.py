#!/usr/bin/env python3
"""Render a Phase 6A cutover checklist. This program cannot execute cutover."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sitina.legacy.cutover_contracts import CutoverCommandIdentity
from sitina.legacy.maintenance_manifest import CutoverDryRun, MaintenanceManifestBuilder


def main() -> int:
    parser=argparse.ArgumentParser(description="Phase 6A fixture-only cutover dry-run")
    parser.add_argument("--candidate-input",type=Path,help="JSON candidate inputs; omitted for help/review only")
    args=parser.parse_args()
    if args.candidate_input is None:
        print(json.dumps({"status":"DRY_RUN_ONLY","executed":False,"execute_capability_present":False},indent=2)); return 0
    raw=json.loads(args.candidate_input.read_text(encoding="utf-8"))
    command=CutoverCommandIdentity(str(raw["command_id"]),str(raw["request_hash"]))
    candidate=MaintenanceManifestBuilder().build_candidate(predicates=raw["predicates"],command=command,intended_snapshot_hash=raw["intended_snapshot_hash"],genesis_hash=raw["genesis_hash"],operators=tuple(raw["operators"]),allowed_paths=tuple(raw["allowed_paths"]),window=tuple(raw["window"]),expires_at=int(raw["expires_at"]),expected_pre_state=raw["expected_pre_state"],stop_conditions=tuple(raw["stop_conditions"]))
    print(json.dumps(CutoverDryRun().evaluate(candidate),sort_keys=True,indent=2)); return 0


if __name__=="__main__": raise SystemExit(main())
