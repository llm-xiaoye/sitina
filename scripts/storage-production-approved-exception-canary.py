#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping

from sitina.archive.production_backup import ProductionBackupManifest
from sitina.cas.local import LocalCAS
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.conversation.models import ChatMode
from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.fast_start import FullJournalVerifier
from sitina.journal.model import canonical_json_bytes
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.runners.profiles import ProfileLoader
from sitina.security.key_provider import JournalAuthProvider
from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"
CANARY_MESSAGE = (
    "Return a concise confirmation that the production storage canary completed. "
    "Do not include configuration, credentials, secrets, or diagnostic data."
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any], literals: tuple[bytes, ...]) -> str:
    raw = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if any(literal in raw for literal in literals):
        raise RuntimeError("canary evidence contains a configured Provider literal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short canary evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    return hashlib.sha256(raw).hexdigest()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one body-free, bounded real Provider canary under the approved DeepSeek storage exception.")
    parser.add_argument("--home", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pre-canary-sentinel", type=Path, required=True)
    parser.add_argument("--rollback-backup-id", default="storage-closure-final-20260719T003146Z")
    parser.add_argument("--accept-deepseek-direct-storage-risk", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve(strict=False)
    sentinel_path = args.pre_canary_sentinel.expanduser().resolve(strict=True)
    if home != PRODUCTION_HOME or output == home or home in output.parents:
        raise RuntimeError("approved-exception canary requires exact Production and external evidence output")
    if not args.accept_deepseek_direct_storage_risk:
        raise RuntimeError("approved-exception canary requires the explicit DeepSeek risk-acceptance flag")

    profile_loader = ProfileLoader(home)
    profile_audit = profile_loader.audit_profiles()
    exception = evaluate_deepseek_direct_storage_exception(profile_audit, user_accepted=True)
    if exception["status"] != "accepted":
        raise RuntimeError("current Provider profile state does not match the exact approved exception")
    profile_path = home / "profiles/deepseek.env"
    profile_before = profile_path.lstat()
    if not stat.S_ISREG(profile_before.st_mode) or profile_before.st_mode & 0o7777 != 0o600:
        raise RuntimeError("approved Provider profile is not an owner-only regular file")
    profile_sha_before = _sha256(profile_path)
    raw_env = profile_loader._raw_env("deepseek")
    literal = raw_env.get(ProfileLoader.TOKEN_KEY, "").encode("utf-8")
    if not literal:
        raise RuntimeError("approved direct Provider profile has no configured literal")
    literals = (literal,)

    sentinel = json.loads(sentinel_path.read_text(encoding="utf-8"))
    if (
        sentinel.get("schema") != "SITINA_STORAGE_PRODUCTION_SENTINEL_V1"
        or sentinel.get("production_home") != str(home)
        or not isinstance(sentinel.get("report_sha256"), str)
    ):
        raise RuntimeError("pre-canary Sentinel is invalid")
    rollback = ProductionBackupManifest.load(home / "backups" / args.rollback_backup_id)
    if rollback.body_mapping().get("credentials_copied") is not False:
        raise RuntimeError("rollback backup copied credentials")

    before_context = ProductionRuntimeContext.load(home)
    before_fast = before_context.authority.fast_start_report
    if before_fast is None or not before_fast.fast_start_checkpoint_used:
        raise RuntimeError("canary requires verified Fast Start before Provider execution")
    before_frontier = int(before_fast.authority_state.head_position)
    if rollback.metadata.frontier.position != before_frontier:
        raise RuntimeError("rollback backup does not cover the exact pre-canary frontier")

    runtime = ConversationRuntime(home)
    session = runtime.resume_or_create_session()
    before_turn_index = session.turn_index
    before_session_id = session.session_id
    session.mode = ChatMode.FAST
    result = runtime.execute_turn(session, CANARY_MESSAGE)
    if (
        result.get("terminal_state") != "SUCCEEDED"
        or int(result.get("provider_call_count", -1)) != 1
        or int(result.get("provider_physical_send_count", -1)) != 1
        or int(result.get("provider_retry_count", -1)) != 0
        or int(result.get("provider_fallback_count", -1)) != 0
        or not str(result.get("response") or "").strip()
    ):
        raise RuntimeError("bounded Provider canary did not complete with exactly one clean logical/physical send")
    run_id = str(result.get("run_id") or "")
    if not run_id:
        raise RuntimeError("bounded Provider canary returned no run identity")

    after_context = ProductionRuntimeContext.load(home)
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(after_context.provider),
        authority_key_provider=after_context.provider,
    ).verify()
    events = tuple(full.verified_events)
    selected = tuple(item for item in events if item.payload.get("run_id") == run_id)
    terminal = [item for item in selected if item.event_type == "run.terminal"]
    usage = [item for item in selected if item.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1"]
    if len(terminal) != 1 or len(usage) != 1:
        raise RuntimeError("bounded Provider canary does not have one terminal and one usage fact")
    usage_payload = usage[0].payload
    if (
        usage_payload.get("provider") != "deepseek"
        or usage_payload.get("outcome") != "SUCCEEDED"
        or int(usage_payload.get("physical_send_count", -1)) != 1
        or int(usage_payload.get("retry_count", -1)) != 0
        or int(usage_payload.get("fallback_count", -1)) != 0
    ):
        raise RuntimeError("bounded Provider usage fact does not match the approved DeepSeek canary")
    journal_exact_hits = sum(canonical_json_bytes(item.core_mapping()).count(literal) for item in selected)
    refs = sorted({reference for item in selected for reference in item.object_refs})
    cas = LocalCAS(
        home,
        after_context.provider,
        "production",
        authority_resolution=after_context.authority.resolution,
        genesis_hash=after_context.genesis.genesis_hash,
        feature_activations=FeatureActivationRegistry.from_journal_events(after_context.events),
        read_only=True,
    )
    cas_exact_hits = 0
    for reference_id in refs:
        cas_exact_hits += cas.open_verified(cas.resolve_reference(reference_id)).count(literal)
    if journal_exact_hits or cas_exact_hits:
        raise RuntimeError("configured Provider literal entered canary Journal/CAS persistence")
    replay = after_context.replay_run(run_id)
    if (
        replay.get("status") != "replay_ok"
        or int(replay.get("external_call_count", -1)) != 0
        or int(replay.get("effect_execution_count", -1)) != 0
    ):
        raise RuntimeError("bounded Provider canary replay failed closed")
    restarted = ConversationRuntime(home).resume_or_create_session()
    if (
        restarted.session_id != before_session_id
        or restarted.turn_index != before_turn_index + 1
        or len(restarted.history) < 1
        or restarted.last_failed_message is not None
    ):
        raise RuntimeError("bounded Provider canary did not recover after restart")

    profile_after = profile_path.lstat()
    profile_sha_after = _sha256(profile_path)
    if (
        profile_sha_after != profile_sha_before
        or profile_after.st_mode & 0o7777 != 0o600
        or (profile_after.st_dev, profile_after.st_ino, profile_after.st_size)
        != (profile_before.st_dev, profile_before.st_ino, profile_before.st_size)
    ):
        raise RuntimeError("approved Provider profile changed during the canary")
    after_audit = profile_loader.audit_profiles()
    after_exception = evaluate_deepseek_direct_storage_exception(after_audit, user_accepted=True)
    if after_exception["status"] != "accepted":
        raise RuntimeError("approved Provider exception changed during the canary")

    evidence: dict[str, Any] = {
        "schema": "SITINA_APPROVED_EXCEPTION_PROVIDER_CANARY_V1",
        "status": "PASSED",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "goal_thread_id": GOAL_THREAD_ID,
        "profile_storage_exception": after_exception,
        "profile_integrity": {
            "profile": "deepseek",
            "file_mode": "0600",
            "sha256_before": profile_sha_before,
            "sha256_after": profile_sha_after,
            "content_unchanged": True,
            "credential_modified": False,
            "credential_value_included": False,
        },
        "pre_canary_sentinel": {
            "path": str(sentinel_path),
            "file_sha256": _sha256(sentinel_path),
            "report_sha256": sentinel["report_sha256"],
        },
        "rollback": {
            "backup_id": rollback.backup_id,
            "manifest_hash": rollback.manifest_hash,
            "frontier_position": rollback.metadata.frontier.position,
            "credentials_copied": False,
        },
        "session": {
            "session_id": before_session_id,
            "turn_index_before": before_turn_index,
            "turn_index_after_restart": restarted.turn_index,
            "restart_provider_send_count": 0,
        },
        "run": {
            "run_id": run_id,
            "requested_mode": "FAST",
            "resolved_mode": "FAST",
            "provider": usage_payload.get("provider"),
            "model": usage_payload.get("model"),
            "logical_call_count": 1,
            "physical_send_count": 1,
            "retry_count": 0,
            "fallback_count": 0,
            "journal_range": [min(item.position for item in selected), max(item.position for item in selected)],
            "terminal_position": terminal[0].position,
            "terminal_event_id": terminal[0].event_id,
            "cas_reference_count": len(refs),
            "cas_references": refs,
            "journal_exact_provider_literal_hit_count": 0,
            "cas_plaintext_exact_provider_literal_hit_count": 0,
            "response_body_included": False,
        },
        "authority": {
            "journal_id": full.authority_state.journal_id,
            "epoch": full.authority_state.epoch,
            "frontier_before": before_frontier,
            "frontier_after": full.authority_state.head_position,
            "frontier_commitment_after": full.authority_state.last_transaction_hash,
            "checkpoint_commitment_before": before_fast.checkpoint_commitment,
            "checkpoint_verified_through_before": before_fast.verified_through_position,
        },
        "replay": {
            "status": replay["status"],
            "semantic_checksum": replay["semantic_checksum"],
            "event_count": replay["event_count"],
            "cas_reference_count": replay["cas_reference_count"],
            "external_call_count": replay["external_call_count"],
            "effect_execution_count": replay["effect_execution_count"],
            "writer_activated": replay["writer_activated"],
        },
        "cli_or_debug_output_contains_credential": False,
        "response_body_printed_by_canary": False,
        "message_or_response_bodies_included": False,
        "secret_values_included": False,
    }
    digest = _atomic_json(output, evidence, literals)
    print(
        json.dumps(
            {
                "status": "PASSED",
                "path": str(output),
                "sha256": digest,
                "run_id": run_id,
                "logical_call_count": 1,
                "physical_send_count": 1,
                "secret_values_included": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "FAILED_CLOSED",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                    "secret_values_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)
