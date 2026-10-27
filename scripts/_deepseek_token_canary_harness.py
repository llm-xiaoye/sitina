from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Mapping, Sequence

from tests.foundation.home_factory import DisposableHomeFactory, capture_production_sentinel
from sitina.legacy.coverage import FrozenSnapshotBuilder
from sitina.legacy.fence import LegacyWriteGate
from sitina.legacy.fence import authorized_extension_effect
from sitina.journal.local import LocalJournal
from sitina.operations.phase6b import PHASE6B_OPERATION_IDS, AuthorityControlStream, Phase6BManifestVerifier
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime
from sitina.legacy.production_genesis import ProductionGenesisBuilder
from sitina.runners.profiles import ProfileLoader
from sitina.security.key_provider import JournalAuthProvider
from sitina.security.macos_keychain import MacOSKeychainProvider, MemoryKeychainBackend
from sitina.storage.store import SCHEMA_SQL, SitinaStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SOURCE = Path(__file__).resolve().parents[1]
PRODUCTION = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub')).resolve(strict=True)
_configured_canary_root = os.environ.get("SITINA_CANARY_ROOT")
CANARY_ROOT = (
    Path(_configured_canary_root).expanduser()
    if isinstance(_configured_canary_root, str) and _configured_canary_root.strip()
    else Path(tempfile.gettempdir()) / "sitina-deepseek-token-canary"
).resolve(strict=False)


def _assert_external_canary_root(root: Path) -> None:
    candidate = Path(root).expanduser().resolve(strict=False)
    for protected in (SOURCE, PRODUCTION):
        if candidate == protected or protected in candidate.parents:
            raise RuntimeError("canary writable root must be outside SOURCE and PRODUCTION")


_assert_external_canary_root(CANARY_ROOT)
ARTIFACTS = CANARY_ROOT / "artifacts" / "deepseek-token-canary"


def bootstrap_authority(sim: Path, ops: Path, now: int) -> tuple[object, object, object, object, dict[str, object]]:
    """Create a signed, disposable-only authority with explicit identities."""

    code_path = SOURCE / "core/sitina/journal/local.py"
    source_hash = file_sha256(code_path)
    control_root = ops / "control"
    control_root.mkdir(parents=True, exist_ok=True)
    source_core = {
        "schema": "CONTENT_MANIFEST_V1", "root": str(SOURCE), "scope": "DEEPSEEK_TOKEN_CANARY_SOURCE",
        "excluded_roots": [], "excluded_patterns": [], "previous_manifest_hash": "sha256:" + "0" * 64,
        "entries": [{"path": str(code_path.relative_to(SOURCE)), "size": code_path.stat().st_size,
                     "mode": oct(code_path.stat().st_mode & 0o7777), "sha256": source_hash}],
    }
    source_manifest_hash = hashlib.sha256(canonical(source_core)).hexdigest()
    source_manifest_path = control_root / "source-content-manifest.json"
    source_manifest_path.write_text(json.dumps({**source_core, "manifest_sha256": source_manifest_hash}, sort_keys=True) + "\n", encoding="utf-8")
    prerequisites = {}
    for name in ("effect_drain", "monitoring_transfer", "key_profile"):
        path = control_root / f"{name}.json"
        path.write_text(json.dumps({"schema": "CANARY_PREREQUISITE_V1", "name": name}, sort_keys=True) + "\n", encoding="utf-8")
        prerequisites[name] = {"path": str(path), "physical_sha256": file_sha256(path)}
    readiness = {"schema": "BPLUS_CUTOVER_TOOLING_READY_R1_V1", "status": "CUTOVER_TOOLING_READY", "authority": False, "maintenance_authorized": False, "cutover_authorized": False, "predicates": {"fixture_production_tooling_complete": True, "production_sentinels_unchanged": True}}
    readiness["readiness_sha256"] = hashlib.sha256(canonical(readiness)).hexdigest()
    genesis_values = {
        "installation_id": "sitina-production-sim", "journal_id": "journal-production-sim",
        "epoch_root": "epoch-production-sim-1", "key_namespace": "sitina-production-sim-v1",
        "intended_snapshot_hash": "a" * 64, "format_profile_hash": "1" * 64,
        "operator_id": "phase6b-executor", "verifier_id": "phase6b-read-only-verifier",
    }
    expected_genesis = ProductionGenesisBuilder(sim).derive_manifest_artifact(genesis_values, environment_kind="CONTROLLED_PRODUCTION_SIMULATION")
    genesis_values["genesis_hash"] = expected_genesis.genesis_hash
    migration_contract_hash = hashlib.sha256(b"SITINA-BPLUS-V1\0MIGRATION_CONTRACT\0" + canonical({"snapshot_hash": "a" * 64, "format_profile_hash": "1" * 64})).hexdigest()
    cutover_body = {
        "schema": "AUTHORITY_CUTOVER_REQUEST_V1", "snapshot_hash": "a" * 64, "genesis_hash": expected_genesis.genesis_hash,
        "migration_contract_hash": migration_contract_hash, "effect_drain_hash": prerequisites["effect_drain"]["physical_sha256"],
        "monitoring_transfer_hash": prerequisites["monitoring_transfer"]["physical_sha256"], "source_manifest_sha256": source_manifest_hash,
        "readiness_sha256": readiness["readiness_sha256"],
        "key_profile_hash": prerequisites["key_profile"]["physical_sha256"],
        "operator_authorization_hash": "05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601",
    }
    core = {
        "schema": "PHASE6B_MAINTENANCE_MANIFEST_V1", "environment_kind": "CONTROLLED_PRODUCTION_SIMULATION",
        "goal_thread_id": "019f5c6b-3083-7860-b45b-c8b487c4e3ab", "owner_principal": "user-standing-owner-authorization-v1",
        "standing_owner_authorization_hash": "sha256:05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601",
        "approval_derivation": "AUTOMATIC_FROM_STANDING_OWNER_AUTHORIZATION_V1",
        "phase6a_readiness_sha256": readiness["readiness_sha256"],
        "source_manifest_sha256": source_manifest_hash, "source_manifest_path": str(source_manifest_path),
        "window": {"starts_at": now - 10, "ends_at": now + 3600, "expires_at": now + 3000},
        "roots": {"production_home": str(sim), "snapshot_root": str(ops / "snapshot"), "migration_root": str(ops / "migration"), "backup_root": str(ops / "backup"), "control_root": str(control_root)},
        "authorized_operations": list(PHASE6B_OPERATION_IDS), "code_identities": {str(code_path): source_hash},
        "production_genesis": genesis_values,
        "cutover_command": {"command_id": "cutover-production-sim-v1", "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), "request_body": cutover_body},
        "cutover_verified_command": {"command_id": "cutover-verified-production-sim-v1", "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 1)), "required_predicates": ["rebuild", "dual_read", "legacy_zero_write", "backup_restore", "mock_only"], "required_report_hashes": ["rebuild", "dual_read", "evidence"]},
        "operator_quorum": [{"principal_id": "user-standing-owner-authorization-v1", "role": "OWNER_PRINCIPAL", "human_identity_claimed": False}, {"principal_id": "phase6b-read-only-verifier", "role": "INDEPENDENT_TECHNICAL_VERIFIER", "human_identity_claimed": False}, {"principal_id": "phase6b-executor", "role": "EXECUTION_PRINCIPAL", "human_identity_claimed": False}],
        "prerequisites": {"source_coverage": True, "restore_drill": True, "effect_drain": True, "monitoring_transfer": True},
        "prerequisite_artifacts": prerequisites, "stop_conditions": ["ANY_IDENTITY_DRIFT", "ANY_UNKNOWN_OUTCOME", "ANY_UNEXPLAINED_OMISSION"],
    }
    core["cutover_command"]["request_hash"] = hashlib.sha256(b"SITINA-BPLUS-V1\0CUTOVER_COMMAND_REQUEST\0" + canonical(cutover_body)).hexdigest()
    signer = Ed25519PrivateKey.generate(); signed = canonical(core)
    report = {**core, "technical_verifier_public_key_hex": signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), "technical_verifier_signature_hex": signer.sign(signed).hex(), "signed_body_sha256": hashlib.sha256(signed).hexdigest()}
    report["manifest_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
    capability = Phase6BManifestVerifier.verify_mapping(report, readiness_report=readiness, now=now, allow_simulation=True)
    genesis = ProductionGenesisBuilder(sim).build_authorized(capability, now=now)
    ProductionGenesisBuilder(sim).persist_authorized(genesis, capability, now=now)
    backend = MemoryKeychainBackend()
    provider = MacOSKeychainProvider(environment="production-simulation", namespace=genesis.key_namespace, backend=backend)
    LegacyWriteGate(sim).freeze_authorized("snapshot-production-sim-v1", capability, now=now)
    snapshot_result = FrozenSnapshotBuilder().build(sim, ops / "snapshot", capability, now=now)
    journal = LocalJournal.open(sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1, namespace_kind="production_simulation", operational_capability=capability, genesis_hash=genesis.genesis_hash)
    control = AuthorityControlStream(journal, capability, genesis, now=now)
    control.record_genesis_and_prepare(migration_frontier_hash="c" * 64, fence_record_hash=LegacyWriteGate(sim).status().record_hash)
    control.submit_cutover(); resolution = control.resolve_authority(now=now); journal.close()
    metadata = {"manifest_sha256": str(capability.manifest_sha256), "source_manifest_sha256": source_manifest_hash, "genesis_hash": genesis.genesis_hash, "authority_resolution_id": resolution.resolution_id, "authority_state": resolution.state.value, "snapshot_id": snapshot_result.snapshot_id, "snapshot_manifest_sha256": snapshot_result.manifest_sha256, "schema_lineage": schema_lineage(sim)}
    return capability, genesis, backend, provider, metadata


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def schema_lineage(home: Path) -> dict[str, object]:
    """Capture the production schema used before the disposable freeze."""
    with sqlite3.connect(home / "data/sitina.db") as db:
        version = db.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
        tables = [
            str(row[0])
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
    return {
        "schema_sql_sha256": hashlib.sha256(SCHEMA_SQL.encode()).hexdigest(),
        "schema_version": int(version[0]) if version else None,
        "required_table_names": tables,
        "required_table_names_sha256": hashlib.sha256(canonical(tables)).hexdigest(),
        "initialized_before_freeze": True,
    }


def initialize_disposable_repo(target: Path) -> None:
    """Create the canary's own Git root, outside the source repository."""
    with authorized_extension_effect(
        permission="shell", approval_granted=True,
        purpose="canary-disposable-repo-bootstrap",
    ):
        commands = (
            ["git", "-C", str(target), "init", "-q"],
            ["git", "-C", str(target), "config", "user.email", "sitina-canary@example.invalid"],
            ["git", "-C", str(target), "config", "user.name", "Sitina Canary"],
            ["git", "-C", str(target), "add", "hello.py"],
            ["git", "-C", str(target), "commit", "-qm", "canary baseline"],
        )
        for command in commands:
            subprocess.run(command, check=True, capture_output=True, text=True)


def snapshot(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        try:
            metadata = path.lstat()
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            result[relative] = {
                "kind": "symlink",
                "target_hash": hashlib.sha256(target.encode()).hexdigest(),
                "size": len(target),
            }
        elif stat.S_ISREG(metadata.st_mode):
            result[relative] = {"kind": "file", "sha256": file_sha256(path), "size": metadata.st_size}
        elif stat.S_ISDIR(metadata.st_mode):
            result[relative] = {"kind": "directory"}
        else:
            result[relative] = {"kind": "special"}
    return result


def path_identity(path: Path) -> dict[str, object]:
    """Return a content-free identity for exact disposable-root cleanup."""
    try:
        metadata = path.lstat()
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "symlink" if stat.S_ISLNK(metadata.st_mode) else "special"
        exists = True
        resolved = str(path.resolve(strict=False))
    except OSError:
        kind = "absent"
        exists = False
        resolved = str(path.resolve(strict=False))
    descriptor = {"path": str(path), "resolved": resolved, "kind": kind, "exists": exists}
    return {**descriptor, "identity_sha256": hashlib.sha256(canonical(descriptor)).hexdigest()}


def safe_event(event: object) -> dict[str, object]:
    payload = dict(getattr(event, "payload", {}) or {})
    keys = {
        "schema", "event_type", "stage", "role", "agent_id", "call_id", "output_hash", "decision",
        "accepted", "attempt", "attempts", "execution_attempt_id", "diff_hash", "tester_verdict_hash",
        "tester_evidence_hash", "test_evidence_ref", "test_evidence_hash", "patch_manifest_ref",
        "patch_manifest_hash", "execution_identity_hash", "reviewer_decision_bound_to_execution",
        "run_id", "authorization_ref", "workspace", "execution_root", "workspace_mode",
        "handoff_id", "task_id", "task_attempt_id", "task_claim_ref", "generation",
        "max_generations", "generation_hash", "contract_hash", "contract_object_ref",
        "input_freeze_hash", "output_schema_hash", "previous_generation_ref",
        "previous_rejection_event_ref", "reject_reason_resolution_hash",
        "selected_proposal_projection_hash", "semantic_delta_hash",
        "resolved_field_paths", "reason_signature", "reason_count",
        "reason_code", "verified_corrections",
        "assessment_call_id", "assessment_output_hash", "accept", "missing_count",
        "missing_information_hash", "reason_hash", "terminal_disposition",
        "old_generation_reusable", "generation_permanently_closed",
        "embedded_provider_call_count", "embedded_physical_send_count", "embedded_tool_call_count",
        "embedded_input_tokens", "embedded_output_tokens", "embedded_cache_read_tokens",
        "embedded_cache_write_tokens", "embedded_total_tokens", "external_mutation_count",
        "sandbox_mutation_count", "sandbox_unique_mutated_path_count", "denied_effect_attempt_count",
        "status", "result_id", "verification_accepted", "verifier_id", "post_execution_reviewer_id",
        "operation", "before_hash", "after_hash", "destination", "sequence", "path",
        "provider_physical_send_count", "provider_call_count", "provider_retry_count",
        "provider_fallback_count", "provider_input_tokens", "provider_output_tokens", "provider_token_total",
        "embedded_call_id", "effect_id", "effect_attempt_id", "provider_request_id", "provider_response_id",
        "provider_profile", "provider_model", "retry_count", "fallback_count", "retry_limit", "fallback_limit", "input_tokens", "output_tokens", "cache_read_tokens",
        "cache_write_tokens", "total_tokens", "same_failure", "prior_failure_type", "prior_failure_hash",
        "plan_hash", "prior_plan_hash", "replan_plan_hash", "replan", "rollback", "rollback_failure_type", "rollback_failure_hash", "stage", "automatic", "same_failure_requires_replan", "replan_plan_hashes",
        "worktree_lifecycle",
        "worktree_cleanup",
        "error_type", "error_hash", "error_message_hash", "notes",
    }
    result = {key: payload[key] for key in sorted(keys) if key in payload}

    def safe_worktree(value: object) -> object:
        if not isinstance(value, Mapping):
            return None
        allowed = {
            "schema", "event_type", "run_id", "status",
            "registration_created", "registration_before_sha256", "registration_after_sha256",
            "registered_before", "registered_after", "removed", "physical_removed",
            "audit_recorded", "porcelain_before_sha256", "porcelain_after_sha256",
        }
        result = {key: value[key] for key in sorted(allowed) if key in value}
        # A full repo/worktree path can disclose unrelated local topology.  The
        # lifecycle event is independently checkable using a content-free path
        # identity, while the exact paths remain runtime-only.
        for source_key, identity_key in (("repo", "repo_identity_sha256"), ("worktree", "worktree_identity_sha256")):
            source = value.get(source_key)
            if isinstance(source, str) and source:
                result[identity_key] = hashlib.sha256(canonical({"path": source})).hexdigest()
        return result

    for key in ("worktree_lifecycle", "worktree_cleanup"):
        if key in result:
            result[key] = safe_worktree(result[key])
    mutations = payload.get("mutation_events")
    if isinstance(mutations, list):
        result["mutation_events"] = [
            {key: item[key] for key in ("sequence", "operation", "path", "destination", "before_hash", "after_hash", "denied", "tool_call_id") if key in item}
            for item in mutations if isinstance(item, dict)
        ]
    ledger = payload.get("attempt_ledger")
    if isinstance(ledger, list):
        result["attempt_ledger"] = [
            {
                key: item[key]
                for key in (
                    "attempt", "plan_hash", "result", "stage", "failure_type", "failure_hash",
                    "prior_failure_type", "prior_failure_hash", "same_failure", "replan",
                    "rollback", "rollback_failure_type", "rollback_failure_hash",
                )
                if key in item
            }
            for item in ledger if isinstance(item, dict)
        ]
    return result


def evaluate_evidence_closure(
    *,
    run_id: str,
    run_result: Mapping[str, object],
    evidence_ref: object,
    package: Mapping[str, object],
    events: Sequence[object],
    cas_receipts: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Evaluate whether an exported run can be reopened after authority cleanup.

    This is deliberately independent of the JSON renderer so fault fixtures can
    remove a stream, introduce a version gap, or invalidate one CAS receipt
    without accidentally testing only the happy-path serializer.
    """

    package_hash = hashlib.sha256(canonical(package)).hexdigest() if package else None
    expected_package_hash = run_result.get("evidence_package_hash")
    package_hash_matches = (
        isinstance(evidence_ref, str)
        and evidence_ref.startswith("cas:")
        and bool(package)
        and isinstance(expected_package_hash, str)
        and package_hash == expected_package_hash
    )
    stream_versions: dict[str, list[int]] = {}
    stream_ids: set[str] = set()
    event_payloads: list[Mapping[str, object]] = []
    for event in events:
        stream = str(getattr(event, "stream_id", ""))
        stream_ids.add(stream)
        version = int(getattr(event, "stream_version", 0))
        stream_versions.setdefault(stream, []).append(version)
        payload = getattr(event, "payload", {})
        event_payloads.append(dict(payload) if isinstance(payload, Mapping) else {})
    stream_continuity = all(
        versions == list(range(1, max(versions, default=0) + 1))
        for versions in stream_versions.values()
    )
    calls = package.get("calls") if isinstance(package.get("calls"), list) else []
    call_task_ids = {
        str(item.get("task_id"))
        for item in calls
        if isinstance(item, Mapping) and item.get("task_id")
    }
    effect_streams = sorted(
        stream for stream in stream_ids if stream.startswith(f"effect/{run_id}/")
    )
    task_streams = sorted(
        stream for stream in stream_ids
        if stream.startswith("task/") and (
            stream.removeprefix("task/") in call_task_ids
            or any(
                payload.get("run_id") == run_id
                and payload.get("task_id")
                and stream == "task/" + str(payload["task_id"])
                for payload in event_payloads
            )
        )
    )
    protocol_streams = sorted(
        stream for stream in stream_ids if stream.startswith(f"protocol/{run_id}/")
    )
    protocol_events = [
        {
            "event_id": str(getattr(event, "event_id", "")),
            "stream_id": str(getattr(event, "stream_id", "")),
            "payload": payload,
        }
        for event, payload in zip(events, event_payloads, strict=True)
        if str(getattr(event, "stream_id", "")).startswith(f"protocol/{run_id}/")
    ]
    handoff_events = [
        item for item in protocol_events
        if item["payload"].get("handoff_id")
        or str(item["payload"].get("schema", "")).startswith("HANDOFF_")
    ]
    handoff_expected = bool(run_result.get("handoff_protocol_count")) or any(
        "handoff" in str(item.get("task_id", "")).casefold()
        for item in calls if isinstance(item, Mapping)
    ) or bool(handoff_events)
    # Validate one immutable chain per handoff.  A terminal event from an old
    # generation cannot close a newer successor that is still open.
    handoff_chains: list[dict[str, object]] = []
    for handoff_id in sorted({
        str(item["payload"].get("handoff_id"))
        for item in handoff_events if item["payload"].get("handoff_id")
    }):
        chain_events = [item for item in handoff_events if item["payload"].get("handoff_id") == handoff_id]
        by_generation: dict[int, list[dict[str, object]]] = {}
        for item in chain_events:
            generation = item["payload"].get("generation")
            if isinstance(generation, int) and not isinstance(generation, bool):
                by_generation.setdefault(generation, []).append(item)
        generations = sorted(by_generation)
        contiguous = bool(generations) and generations == list(range(1, max(generations) + 1))
        generation_contracts = {
            generation: sorted({
                str(item["payload"].get("contract_hash"))
                for item in items
                if isinstance(item["payload"].get("contract_hash"), str)
                and len(str(item["payload"].get("contract_hash"))) == 64
            })
            for generation, items in by_generation.items()
        }
        generation_projections = {
            generation: sorted({
                str(item["payload"].get("selected_proposal_projection_hash"))
                for item in items
                if isinstance(item["payload"].get("selected_proposal_projection_hash"), str)
                and len(str(item["payload"].get("selected_proposal_projection_hash"))) == 64
            })
            for generation, items in by_generation.items()
        }
        predecessor_event_ids = {
            str(item["event_id"])
            for item in chain_events if item["event_id"]
        }
        successor_links: list[dict[str, object]] = []
        links_valid = True
        for generation in generations:
            if generation == 1:
                continue
            candidates = [
                item["payload"] for item in by_generation[generation]
                if item["payload"].get("previous_generation_ref")
                or item["payload"].get("previous_rejection_event_ref")
            ]
            link = next(iter(candidates), None)
            valid = bool(link) and bool(link.get("previous_generation_ref")) and bool(
                link.get("previous_rejection_event_ref")
            ) and bool(
                link.get("reject_reason_resolution_hash") or link.get("semantic_delta_hash")
            )
            if valid and link.get("previous_rejection_event_ref") not in predecessor_event_ids:
                valid = False
            predecessor_contract_refs = {
                str(item["payload"].get("contract_object_ref"))
                for item in by_generation.get(generation - 1, ())
                if item["payload"].get("contract_object_ref")
            }
            if valid and predecessor_contract_refs and link.get("previous_generation_ref") not in predecessor_contract_refs:
                valid = False
            successor_links.append({
                "generation": generation,
                "valid": valid,
                "previous_generation_ref": link.get("previous_generation_ref") if link else None,
                "previous_rejection_event_ref": link.get("previous_rejection_event_ref") if link else None,
            })
            links_valid = links_valid and valid
        latest_generation = max(generations, default=0)
        latest_events = by_generation.get(latest_generation, [])
        latest_terminal = any(
            item["payload"].get("event_type") == "handoff.accepted"
            or item["payload"].get("schema") in {
                "HANDOFF_GENERATION_LIMIT_REACHED_V1", "HANDOFF_REPAIR_NO_PROGRESS_V1",
            }
            or item["payload"].get("terminal_disposition") in {
                "FAILED_GENERATION_LIMIT_REACHED", "FAILED_NO_PROGRESS",
            }
            for item in latest_events
        )
        handoff_chains.append({
            "handoff_id": handoff_id,
            "generation_numbers": generations,
            "latest_generation": latest_generation,
            "latest_generation_has_terminal": latest_terminal,
            "generation_contracts": generation_contracts,
            "generation_projections": generation_projections,
            "successor_links": successor_links,
            "contiguous": contiguous,
            "links_valid": links_valid,
            "complete": bool(
                contiguous and latest_terminal and all(generation_contracts.get(generation)
                                                       for generation in generations)
                and all(generation_projections.get(generation) for generation in generations)
                and links_valid
            ),
        })
    handoff_complete = (
        not handoff_expected
        or bool(handoff_chains)
        and all(bool(chain["complete"]) for chain in handoff_chains)
    )
    cas_complete = bool(cas_receipts) and all(
        bool(item.get("fresh_verified"))
        and bool(item.get("no_replace_published"))
        and item.get("verified", True) is not False
        for item in cas_receipts
    )
    evidence_receipt_complete = any(
        item.get("reference_id") == evidence_ref
        and bool(item.get("fresh_verified"))
        and bool(item.get("no_replace_published"))
        and item.get("verified", True) is not False
        for item in cas_receipts
    )
    package_closed = package_hash_matches and evidence_receipt_complete
    provider_streams_required = bool(calls) or int(run_result.get("provider_call_count", 0) or 0) > 0
    return {
        "package_closed": package_closed,
        "evidence_receipt_complete": evidence_receipt_complete,
        "stream_continuity_verified": stream_continuity,
        "protocol_streams_exported": protocol_streams,
        "effect_streams_exported": effect_streams,
        "task_streams_exported": task_streams,
        "provider_streams_complete": not provider_streams_required or bool(effect_streams) and bool(task_streams),
        "handoff_expected": handoff_expected,
        "handoff_complete": handoff_complete,
        "handoff_chains": handoff_chains,
        "cas_complete": cas_complete,
        "complete": (
            package_closed
            and stream_continuity
            and (not provider_streams_required or bool(effect_streams) and bool(task_streams))
            and handoff_complete
            and cas_complete
        ),
    }


def export_evidence(*, sim: Path, target: Path, ops: Path, backend: object, run_result: dict[str, object], before: dict[str, object], production_before: str, profile_before: dict[str, object], profile_digest: str, session_id: str, bootstrap_metadata: dict[str, object], artifact_path: Path | None = None) -> Path:
    run_id = str(run_result.get("run_id") or "unknown")
    reopened = ProductionRuntimeContext.load(sim, keychain_backend=backend, allow_simulation=True)
    cas = reopened.open_cas()
    evidence_ref = run_result.get("evidence_package_ref")
    package: dict[str, object] = {}
    if isinstance(evidence_ref, str) and evidence_ref.startswith("cas:"):
        package = json.loads(cas.open_verified(cas.resolve_reference(evidence_ref)).decode())
    calls: list[dict[str, object]] = []
    raw_calls = package.get("calls") if isinstance(package, dict) else None
    for call in raw_calls if isinstance(raw_calls, list) else []:
        if not isinstance(call, dict):
            continue
        usage = call.get("usage") if isinstance(call.get("usage"), dict) else {}
        calls.append({
            key: call.get(key) for key in (
                "call_id", "agent_id", "role", "task_id", "task_attempt_id", "effect_id", "effect_attempt_id",
                "provider_request_id", "output_hash", "outcome", "settlement", "retry_count", "fallback_count",
            ) if key in call
        } | {"usage": {key: usage.get(key) for key in ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens") if key in usage}})
    rejected_calls = [
        item for item in ((package.get("rejected_calls") or ()) if isinstance(package, dict) else ())
        if isinstance(item, dict)
    ]
    last_call = calls[-1] if calls else {}
    events = [
        event for event in reopened.events
        if (
            dict(getattr(event, "payload", {}) or {}).get("run_id") == run_id
            or getattr(event, "stream_id", "") == f"run/{run_id}"
            or str(getattr(event, "stream_id", "")).startswith(f"run/forge-exec-{run_id}-")
            or str(getattr(event, "stream_id", "")).startswith(f"protocol/{run_id}/")
            or str(getattr(event, "stream_id", "")).startswith(f"effect/{run_id}/")
            or (
                str(getattr(event, "stream_id", "")).startswith("task/")
                and str(getattr(event, "stream_id", "")).removeprefix("task/") in {
                    str(item.get("task_id")) for item in (raw_calls or ()) if isinstance(item, dict) and item.get("task_id")
                }
            )
        )
    ]
    stages = [safe_event(event) for event in events if dict(getattr(event, "payload", {}) or {}).get("stage") in {"Controller", "Planner", "Forge", "Tester", "Reviewer"}]
    forge = [safe_event(event) for event in events if dict(getattr(event, "payload", {}) or {}).get("event_type") == "forge.execution.result"]
    rework = [
        safe_event(event)
        for event in events
        if str(dict(getattr(event, "payload", {}) or {}).get("event_type", "")).startswith("execution.rework")
    ]
    worktree_events = [
        safe_event(event)
        for event in events
        if str(dict(getattr(event, "payload", {}) or {}).get("event_type", "")).startswith("execution.worktree.")
    ]
    embedded_events = [
        safe_event(event)
        for event in events
        if str(dict(getattr(event, "payload", {}) or {}).get("event_type", "")).startswith("autonomous.")
    ]
    embedded_intended = {
        str(item.get("embedded_call_id"))
        for item in embedded_events
        if str(item.get("event_type", "")).endswith("provider-call-intended") and item.get("embedded_call_id")
    }
    embedded_completed = [
        item for item in embedded_events
        if str(item.get("event_type", "")).endswith("model-turn-completed")
    ]
    embedded_failed = {
        str(item.get("embedded_call_id"))
        for item in embedded_events
        if str(item.get("event_type", "")).endswith("provider-call-failed") and item.get("embedded_call_id")
    }
    protocol_events = [
        safe_event(event)
        for event in events
        if str(getattr(event, "stream_id", "")).startswith(f"protocol/{run_id}/")
    ]
    protocol_streams = sorted({
        str(getattr(event, "stream_id", ""))
        for event in events
        if str(getattr(event, "stream_id", "")).startswith(f"protocol/{run_id}/")
    })
    effect_streams = sorted({
        str(getattr(event, "stream_id", ""))
        for event in events
        if str(getattr(event, "stream_id", "")).startswith(f"effect/{run_id}/")
    })
    task_streams = sorted({
        str(getattr(event, "stream_id", ""))
        for event in events
        if str(getattr(event, "stream_id", "")).startswith("task/")
        and str(getattr(event, "stream_id", "")).removeprefix("task/") in {
            str(item.get("task_id")) for item in (raw_calls or ())
            if isinstance(item, dict) and item.get("task_id")
        }
    })
    handoff_protocol_events = [
        item for item in protocol_events
        if item.get("handoff_id") or str(item.get("schema", "")).startswith("HANDOFF_")
    ]
    handoff_generations = sorted({
        int(item["generation"])
        for item in handoff_protocol_events
        if isinstance(item.get("generation"), int) and not isinstance(item.get("generation"), bool)
    })
    handoff_has_limit = any(
        item.get("schema") == "HANDOFF_GENERATION_LIMIT_REACHED_V1"
        for item in handoff_protocol_events
    )
    stream_heads: dict[str, int] = {}
    stream_versions: dict[str, list[int]] = {}
    event_lineage: list[dict[str, object]] = []
    object_refs = sorted({ref for event in events for ref in getattr(event, "object_refs", ())})
    for event in events:
        stream = str(getattr(event, "stream_id", ""))
        version = int(getattr(event, "stream_version", 0))
        stream_heads[stream] = max(stream_heads.get(stream, 0), version)
        stream_versions.setdefault(stream, []).append(version)
        event_lineage.append({
            "event_id": str(getattr(event, "event_id", "")),
            "event_type": str(getattr(event, "event_type", "")),
            "stream_id": stream,
            "stream_version": int(getattr(event, "stream_version", 0)),
            "position": int(getattr(event, "position", 0)),
            "event_hash": str(getattr(event, "event_hash", "")),
        })
    cas_receipts: list[dict[str, object]] = []
    for reference_id in object_refs:
        try:
            reference = cas.resolve_reference(reference_id)
            receipt = cas.verify_existing(reference)
            cas_receipts.append({
                "reference_id": reference_id,
                "object_id": reference.object_id,
                "plaintext_commitment": reference.plaintext_commitment,
                "core_header_hash": receipt.core_header_hash,
                "envelope_id": receipt.envelope_id,
                "fresh_verified": receipt.fresh_verified,
                "no_replace_published": receipt.no_replace_published,
            })
        except Exception as error:
            cas_receipts.append({"reference_id": reference_id, "verified": False, "error_type": type(error).__name__})
    closure = evaluate_evidence_closure(
        run_id=run_id,
        run_result=run_result,
        evidence_ref=evidence_ref,
        package=package,
        events=events,
        cas_receipts=cas_receipts,
    )
    # Renderer and closure must describe the identical canonical stream set.
    # In particular, task streams are keyed by task_id, not by run_id.
    protocol_streams = list(closure.get("protocol_streams_exported", ()))
    effect_streams = list(closure.get("effect_streams_exported", ()))
    task_streams = list(closure.get("task_streams_exported", ()))
    protocol_events = [
        safe_event(event)
        for event in events
        if str(getattr(event, "stream_id", "")) in set(protocol_streams)
    ]
    handoff_protocol_events = [
        item for item in protocol_events
        if item.get("handoff_id") or str(item.get("schema", "")).startswith("HANDOFF_")
    ]
    handoff_generations = sorted({
        int(item["generation"])
        for item in handoff_protocol_events
        if isinstance(item.get("generation"), int) and not isinstance(item.get("generation"), bool)
    })
    after = snapshot(target)
    changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    production_after = capture_production_sentinel(PRODUCTION, "019f5c6b-3083-7860-b45b-c8b487c4e3ab")["report_sha256"]
    profile_after = ProfileLoader(PRODUCTION).inspect_profile_security("deepseek")
    core: dict[str, object] = {
        "schema": "SITINA_DEEPSEEK_TOKEN_CANARY_EVIDENCE_V2",
        "run_status": str(run_result.get("terminal_state") or ("SUCCEEDED" if run_result.get("accepted") else "FAILED")),
        "evidence_capture_status": "COMPLETE" if closure["complete"] else "INCOMPLETE",
        "run_id": run_id,
        "canary_entrypoint": run_result.get("canary_entrypoint", "true-multi-production-runtime"),
        "route_mode_asserted": run_result.get("route_mode_asserted"),
        "authority_bootstrap": dict(bootstrap_metadata),
        "source_home": str(SOURCE),
        "disposable_authority_home": str(sim),
        "operational_roots": str(ops),
        "selected_workspace": str(target),
        "production_home_touched": production_before != production_after,
        "production_profile_copied_or_symlinked": False,
        "credential_source": "existing direct-profile exception loaded once in memory; opaque keychain reference injected into disposable profile; secret value omitted",
        "credential_exception_id": "direct-profile-exception-" + profile_digest[:16],
        "credential_security": {
            "profile_mode_verified": True,
            "profile_security_status_before": profile_before.get("status"),
            "profile_security_status_after": profile_after.get("status"),
            "findings_before": list(profile_before.get("findings") or []),
            "findings_after": list(profile_after.get("findings") or []),
            "secret_values_included": False,
            "production_profile_unchanged_sentinel": production_before == production_after,
        },
        "provider_activation": {
            "purpose": "deepseek-token-test", "scope": "current-session", "live_opt_in": True,
            "session_id": session_id, "run_id": run_id, "provider": "deepseek", "profile": "deepseek", "model": "deepseek-v4-pro",
            "physical_send_count": run_result.get("provider_physical_send_count"),
            "provider_call_count": run_result.get("provider_call_count"),
            "input_tokens": run_result.get("provider_input_tokens"), "output_tokens": run_result.get("provider_output_tokens"),
            "total_tokens": run_result.get("provider_token_total"), "retry_count": run_result.get("provider_retry_count"),
            "fallback_count": run_result.get("provider_fallback_count"), "fallback_forbidden_by_signed_policy": True,
        },
        "provider_calls": calls,
        "last_successful_call_id": last_call.get("call_id"),
        "last_successful_task_id": last_call.get("task_id"),
        "failure_phase": run_result.get("failure_phase") or (
            "provider_output_contract"
            if rejected_calls else
            (str(run_result.get("error_type")) if run_result.get("error_type") else None)
        ),
        "rejected_provider_output_count": len(rejected_calls),
        "rejected_provider_output_reason_types": sorted({
            str(item.get("reason_type"))
            for item in rejected_calls
            if item.get("reason_type")
        }),
        "rejected_provider_output_reason_hashes": sorted({
            str(item.get("reason_hash"))
            for item in rejected_calls
            if item.get("reason_hash")
        }),
        "rejected_provider_outputs": [
            {
                key: item[key]
                for key in (
                    "call_id", "task_id", "task_attempt_id", "effect_id",
                    "effect_attempt_id", "provider_request_id", "reason_type",
                    "reason_code", "reason_hash", "expected_binding_hash",
                    "result_admission",
                )
                if key in item
            }
            for item in rejected_calls
        ],
        "embedded_provider_calls": embedded_completed,
        "embedded_provider_events": embedded_events,
        "embedded_call_lineage_complete": embedded_intended.issubset(
            {str(item.get("embedded_call_id")) for item in embedded_completed if item.get("embedded_call_id")} | embedded_failed
        ),
        "embedded_call_lineage": {
            "intended_count": len(embedded_intended),
            "completed_count": len(embedded_completed),
            "failed_count": len(embedded_failed),
            "missing_call_ids": sorted(
                embedded_intended
                - ({str(item.get("embedded_call_id")) for item in embedded_completed if item.get("embedded_call_id")} | embedded_failed)
            ),
        },
        "stage_events": stages,
        "execution_rework_events": rework,
        "forge_execution_events": forge,
        "protocol_streams_exported": protocol_streams,
        "effect_streams_exported": effect_streams,
        "task_streams_exported": task_streams,
        "handoff_protocol_events": handoff_protocol_events,
        "handoff_lineage": {
            "stream_count": len(protocol_streams),
            "generation_numbers": handoff_generations,
            "has_generation_limit_fact": handoff_has_limit,
            "cas_receipt_count": len(cas_receipts) if "cas_receipts" in locals() else 0,
            "complete": bool(closure["handoff_complete"]),
            "expected": bool(closure["handoff_expected"]),
            "closure": closure,
        },
        "worktree_lifecycle_events": worktree_events,
        "journal_lineage": {
            "head_position": max((item["position"] for item in event_lineage), default=0),
            "stream_heads": stream_heads,
            "stream_versions": stream_versions,
            "stream_continuity_verified": bool(closure["stream_continuity_verified"]),
            "events": event_lineage,
        },
        "cas_verification_receipts": cas_receipts,
        "tool_call_ids_observed": sorted({str(item.get("tool_call_id")) for event in forge for item in event.get("mutation_events", []) if item.get("tool_call_id")}),
        "evidence_package_ref": evidence_ref,
        "evidence_package_hash": run_result.get("evidence_package_hash"),
        "target_before": before, "target_after": after, "changed_paths": changed, "target_changed": bool(changed),
        "result_summary": {key: run_result.get(key) for key in (
            "accepted", "terminal_state", "execution_failed_closed", "error_type", "error_hash", "external_mutation_count",
            "provider_physical_send_count", "provider_call_count", "provider_input_tokens", "provider_output_tokens",
            "provider_token_total", "provider_retry_count", "provider_fallback_count", "patch_manifest_ref", "patch_manifest_hash",
            "failure_phase", "last_successful_call_id", "last_successful_task_id",
            "rejected_provider_output_count", "rejected_provider_output_reason_types",
            "rejected_provider_output_reason_hashes",
        ) if key in run_result},
        "production_sentinels": {"before": production_before, "after": production_after, "unchanged": production_before == production_after},
        "target_file_contents_omitted": True,
        "secret_values_included": False,
    }
    if forge:
        core["result_summary"]["attempt_ledger"] = forge[-1].get("attempt_ledger", [])
    core["evidence_export_hash"] = hashlib.sha256(canonical(core)).hexdigest()
    artifact = artifact_path or ARTIFACTS / f"canary-final-{run_id}.json"
    artifact.write_text(json.dumps(core, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return artifact


def main() -> None:
    import sys

    dry_run = "--dry-run" in sys.argv
    interactive = "--interactive" in sys.argv
    _assert_external_canary_root(CANARY_ROOT)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    CANARY_ROOT.mkdir(parents=True, exist_ok=True)
    disposable = DisposableHomeFactory(SOURCE, PRODUCTION, CANARY_ROOT).create(prefix="deepseek-token-test-")
    sim = disposable.path
    ops = (CANARY_ROOT / f"{sim.name}-ops").resolve()
    ops.mkdir()
    target = (CANARY_ROOT / f"deepseek-canary-target-{uuid.uuid4().hex[:12]}").resolve()
    original_load = None
    original_resolve = None
    backend = None
    artifact: Path | None = None
    cleanup: dict[str, object] = {}
    try:
        target.mkdir()
        (target / "hello.py").write_text('def greet(name):\n    return f"hello {name}"\n', encoding="utf-8")
        initialize_disposable_repo(target)
        for relative in ("data", "logs/events", "logs/audit", "state", "artifacts", "outputs", "memory"):
            (sim / relative).mkdir(parents=True, exist_ok=True)
        # Initialise the complete production schema before the disposable
        # authority is frozen.  A hand-written runs/events subset is not
        # sufficient: the execution bridge records audit_log rows for the
        # worktree/ToolExecutor path, and missing tables must fail the harness
        # preflight rather than masquerade as a product result.
        SitinaStore(sim).init_db()
        now = int(time.time())
        _, _, backend, _, bootstrap_metadata = bootstrap_authority(sim, ops, now)
        if dry_run:
            original_load = ProductionRuntimeContext.load.__func__
            def dry_load(cls, home, **kwargs):
                kwargs.setdefault("keychain_backend", backend)
                kwargs.setdefault("allow_simulation", True)
                return original_load(cls, home, **kwargs)
            ProductionRuntimeContext.load = classmethod(dry_load)
            context = ProductionRuntimeContext.load(sim)
            before = snapshot(target)
            production_before = capture_production_sentinel(PRODUCTION, "019f5c6b-3083-7860-b45b-c8b487c4e3ab")["report_sha256"]
            profile_before = ProfileLoader(PRODUCTION).inspect_profile_security("deepseek")
            profile_digest = hashlib.sha256(canonical({"status": profile_before.get("status"), "findings": profile_before.get("findings")})).hexdigest()
            run_id = "dry-run-" + uuid.uuid4().hex[:12]
            artifact = export_evidence(
                sim=sim, target=target, ops=ops, backend=backend,
                run_result={"run_id": run_id, "terminal_state": "FAILED", "accepted": False,
                            "provider_call_count": 0, "handoff_protocol_count": 0},
                before=before, production_before=production_before,
                profile_before=profile_before, profile_digest=profile_digest,
                session_id="dry-run-session", bootstrap_metadata=bootstrap_metadata,
                artifact_path=ARTIFACTS / f"canary-preflight-{uuid.uuid4().hex[:12]}.json",
            )
            preflight = json.loads(artifact.read_text(encoding="utf-8"))
            preflight.update({
                "status": "DRY_RUN_PASSED", "physical_send_count": 0,
                "secret_values_included": False, "credential_read": False,
                "context_reopen": context.authority.resolution.state.value,
                "target": str(target), "ops": str(ops),
                "evidence_export_exercised": True,
            })
            preflight.pop("evidence_export_hash", None)
            preflight["evidence_export_hash"] = hashlib.sha256(canonical(preflight)).hexdigest()
            artifact.write_text(json.dumps(preflight, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"PREFLIGHT_ARTIFACT": str(artifact), "STATUS": "DRY_RUN_PASSED", "PHYSICAL_SEND_COUNT": 0}, sort_keys=True))
            return
        loader = ProfileLoader(PRODUCTION)
        profile_before = loader.inspect_profile_security("deepseek")
        raw_env = loader._raw_env("deepseek")
        token = raw_env.get(ProfileLoader.TOKEN_KEY, "")
        if not token:
            raise RuntimeError("no authorized in-memory profile credential")
        profile_digest = hashlib.sha256(canonical({"status": profile_before.get("status"), "findings": profile_before.get("findings"), "mode": oct((PRODUCTION / "profiles/deepseek.env").stat().st_mode & 0o7777)})).hexdigest()
        (sim / "profiles").mkdir(parents=True, exist_ok=True)
        profile = sim / "profiles/deepseek.env"
        profile.write_text('unset ANTHROPIC_API_KEY\nexport ANTHROPIC_BASE_URL="https://api.deepseek.com"\nexport ANTHROPIC_AUTH_TOKEN_REF="keychain://com.sitina.canary/deepseek"\nexport ANTHROPIC_MODEL="deepseek-v4-pro"\nexport ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-v4-pro"\nexport ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-v4-pro"\nexport ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-v4-pro"\n', encoding="utf-8")
        os.chmod(profile, 0o600)
        original_load = ProductionRuntimeContext.load.__func__
        original_resolve = ProfileLoader._resolve_keychain_reference
        def patched_load(cls, home, **kwargs):
            kwargs.setdefault("keychain_backend", backend)
            kwargs.setdefault("allow_simulation", True)
            return original_load(cls, home, **kwargs)
        def broker(self, reference):
            return token if reference == "keychain://com.sitina.canary/deepseek" else original_resolve(self, reference)
        ProductionRuntimeContext.load = classmethod(patched_load)
        ProfileLoader._resolve_keychain_reference = broker
        before = snapshot(target)
        production_before = capture_production_sentinel(PRODUCTION, "019f5c6b-3083-7860-b45b-c8b487c4e3ab")["report_sha256"]
        session_id = "canary-session-" + target.name.rsplit("-", 1)[-1]
        goal = "Modify hello.py in the selected workspace by adding a small tested function named farewell(name) that returns a greeting string. Run a focused Python test or smoke check for the changed file. Do not modify anything outside the selected workspace and do not commit or push."
        if interactive:
            from sitina.conversation.models import ChatMode, ChatSession
            from sitina.conversation.runtime import ConversationRuntime

            conversation = ConversationRuntime(
                sim,
                multi_runtime=TrueMultiAgentProductionRuntime(sim),
                workspace=target,
                live_opt_in=True,
                approval_callback=lambda _request: False,
            )
            session = ChatSession(mode=ChatMode.MULTI)
            session_id = session.session_id
            result = conversation.execute_turn(session, goal)
            result = {**result, "canary_entrypoint": "conversation-runtime:/multi", "route_mode_asserted": "MULTI"}
        else:
            result = TrueMultiAgentProductionRuntime(sim).execute(
                goal,
                label="deepseek-token-test-source-canary",
                overrides={"conversation_session_id": session_id, "conversation_turn_index": 0, "execution_workspace": str(target), "execution_access_mode": "workspace", "live_opt_in": True},
            )
            result = {**result, "canary_entrypoint": "true-multi-production-runtime", "route_mode_asserted": "MULTI"}
        artifact = export_evidence(sim=sim, target=target, ops=ops, backend=backend, run_result=result, before=before, production_before=production_before, profile_before=profile_before, profile_digest=profile_digest, session_id=session_id, bootstrap_metadata=bootstrap_metadata)
        rendered_artifact = json.loads(artifact.read_text(encoding="utf-8"))
        evidence_status = str(rendered_artifact.get("evidence_capture_status", "INCOMPLETE"))
        print(json.dumps({"CANARY_ARTIFACT": str(artifact), "RUN_STATUS": rendered_artifact.get("run_status"), "RUN_ID": result.get("run_id"), "PHYSICAL_SEND_COUNT": result.get("provider_physical_send_count"), "TARGET_CHANGED": rendered_artifact.get("target_changed"), "EVIDENCE_CAPTURE_STATUS": evidence_status}, sort_keys=True))
        if evidence_status != "COMPLETE":
            raise RuntimeError("evidence capture incomplete; refusing to report canary success")
    except Exception as error:
        failure = {"schema": "SITINA_DEEPSEEK_TOKEN_CANARY_PREFLIGHT_V1", "failure_phase": type(error).__name__, "status": "HARNESS_BLOCKED", "error_type": type(error).__name__, "error_hash": hashlib.sha256(str(error).encode()).hexdigest(), "physical_send_count": 0, "secret_values_included": False, "authority_bootstrap": locals().get("bootstrap_metadata", {}), "target": str(target), "ops": str(ops)}
        artifact = ARTIFACTS / f"canary-preflight-failure-{uuid.uuid4().hex[:12]}.json"
        artifact.write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"PREFLIGHT_ARTIFACT": str(artifact), "STATUS": "HARNESS_BLOCKED", "PHYSICAL_SEND_COUNT": 0}, sort_keys=True))
    finally:
        cleanup_receipt: dict[str, object] = {
            "schema": "SITINA_CANARY_CLEANUP_RECEIPT_V1",
            "cleanup_started_at": time.time_ns(),
            "roots": {
                "authority": {"path": str(sim), "before": path_identity(sim)},
                "ops": {"path": str(ops), "before": path_identity(ops)},
                "target": {"path": str(target), "before": path_identity(target)},
            },
        }
        if original_load is not None:
            ProductionRuntimeContext.load = classmethod(original_load)
        if original_resolve is not None:
            ProfileLoader._resolve_keychain_reference = original_resolve
        try:
            disposable.cleanup()
            cleanup["authority_home_removed"] = not sim.exists()
        except Exception as error:
            cleanup["authority_home_removed"] = False
            cleanup["authority_cleanup_error_type"] = type(error).__name__
        try:
            with authorized_extension_effect(permission="shell", approval_granted=True, purpose="canary-exact-disposable-cleanup"):
                subprocess.run(["/usr/bin/trash", str(ops)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cleanup["ops_removed"] = not ops.exists()
        except Exception as error:
            cleanup["ops_removed"] = False
            cleanup["ops_cleanup_error_type"] = type(error).__name__
        try:
            with authorized_extension_effect(permission="shell", approval_granted=True, purpose="canary-exact-disposable-cleanup"):
                subprocess.run(["/usr/bin/trash", str(target)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cleanup["target_removed"] = not target.exists()
        except Exception as error:
            cleanup["target_removed"] = False
            cleanup["target_cleanup_error_type"] = type(error).__name__
        if artifact is not None and artifact.exists():
            value = json.loads(artifact.read_text(encoding="utf-8"))
            value["cleanup"] = cleanup
            cleanup_receipt["roots"]["authority"]["after"] = path_identity(sim)
            cleanup_receipt["roots"]["ops"]["after"] = path_identity(ops)
            cleanup_receipt["roots"]["target"]["after"] = path_identity(target)
            cleanup_receipt["cleanup_finished_at"] = time.time_ns()
            cleanup_receipt["receipt_sha256"] = hashlib.sha256(canonical(cleanup_receipt)).hexdigest()
            value["cleanup_receipt"] = cleanup_receipt
            value.pop("evidence_export_hash", None)
            value["evidence_export_hash"] = hashlib.sha256(canonical(value)).hexdigest()
            artifact.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
