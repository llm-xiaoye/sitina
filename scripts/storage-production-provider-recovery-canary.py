#!/usr/bin/env python3
"""Run and independently seal one real Provider-failure checkpoint canary.

The supervisor process deliberately imports no Sitina modules.  Preparation,
AUTO-mode restart verification, the live run, and evidence sealing therefore
cross real process boundaries while the existing shell supervisor performs the
eight checkpoint resume workers.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
PYTHON = Path("/Users/moss/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3")
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"
CANARY_GOAL = (
    "Run one bounded real provider recovery after an explicit remote failure, "
    "then prove checkpoint restart resume and replay consistency without external mutation."
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the bounded Production Provider-failure/checkpoint recovery canary."
    )
    parser.add_argument("--home", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--accept-deepseek-direct-storage-risk", action="store_true")
    parser.add_argument(
        "--phase",
        choices=("prepare", "verify-auto", "execute", "discover-plan", "seal"),
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _direct_provider_literal(home: Path) -> bytes:
    path = home / "profiles/deepseek.env"
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key.removeprefix("export ").strip() == "ANTHROPIC_AUTH_TOKEN":
            literal = value.strip().strip("'\"").encode("utf-8")
            if literal:
                return literal
    raise RuntimeError("DeepSeek direct profile contains no active credential")


def _safe_child(
    command: list[str],
    *,
    home: Path,
    literal: bytes,
    input_value: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ)
    environment.update(
        {
            "SITINA_HOME": str(home),
            "SITINA_PYTHON": str(PYTHON),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(home / "core"),
        }
    )
    completed = subprocess.run(
        command,
        input=_canonical(input_value) if input_value is not None else None,
        capture_output=True,
        env=environment,
        check=False,
    )
    combined = completed.stdout + completed.stderr
    if literal in combined:
        raise RuntimeError("canary child output contained the configured Provider literal")
    if completed.returncode != 0:
        raise RuntimeError(
            "canary child failed closed: status="
            + str(completed.returncode)
            + " output_hash="
            + hashlib.sha256(combined).hexdigest()
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("canary child returned non-JSON output") from error
    if not isinstance(value, dict):
        raise RuntimeError("canary child output is not an object")
    return value


def _atomic_json(path: Path, value: Mapping[str, Any], literal: bytes) -> str:
    raw = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if literal in raw:
        raise RuntimeError("canary evidence contains the configured Provider literal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
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


def _provider_usage_count(events: tuple[Any, ...]) -> int:
    return sum(event.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1" for event in events)


def _prepare(home: Path) -> dict[str, Any]:
    from sitina.conversation.models import ChatMode
    from sitina.conversation.runtime import ConversationRuntime
    from sitina.journal.fast_start import FullJournalVerifier
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext
    from sitina.runners.profiles import ProfileLoader
    from sitina.security.key_provider import JournalAuthProvider
    from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception

    if home != PRODUCTION_HOME or any(
        (home / relative).exists() or (home / relative).is_symlink()
        for relative in ("data/sitina.db", "data/sitina.db-wal", "data/sitina.db-shm")
    ):
        raise RuntimeError("Provider recovery canary requires exact Production with no retired SQLite artifacts")
    audit = ProfileLoader(home).audit_profiles()
    exception = evaluate_deepseek_direct_storage_exception(audit, user_accepted=True)
    if exception.get("status") != "accepted":
        raise RuntimeError("DeepSeek direct-storage exception no longer matches the approved scope")
    profile = home / "profiles/deepseek.env"
    profile_stat = profile.lstat()
    if not stat.S_ISREG(profile_stat.st_mode) or profile_stat.st_mode & 0o7777 != 0o600:
        raise RuntimeError("DeepSeek profile is not an owner-only regular file")

    context = ProductionRuntimeContext.load(home)
    before = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    usage_before = _provider_usage_count(tuple(before.verified_events))
    runtime = ConversationRuntime(home)
    session = runtime.resume_or_create_session()
    runtime.persist_mode(session, ChatMode.AUTO)

    after_context = ProductionRuntimeContext.load(home)
    after = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(after_context.provider),
        authority_key_provider=after_context.provider,
    ).verify()
    usage_after = _provider_usage_count(tuple(after.verified_events))
    if usage_after != usage_before:
        raise RuntimeError("AUTO persistence performed a Provider operation")
    return {
        "status": "prepared",
        "session_id": session.session_id,
        "session_turn_index": session.turn_index,
        "journal_frontier": after.authority_state.head_position,
        "journal_commitment": after.authority_state.last_transaction_hash,
        "provider_usage_count_before": usage_before,
        "provider_usage_count_after_auto": usage_after,
        "profile_sha256": _sha256(profile),
        "profile_mode": "0600",
        "credential_value_included": False,
    }


def _verify_auto(home: Path, expected: Mapping[str, Any]) -> dict[str, Any]:
    from sitina.conversation.models import ChatMode
    from sitina.conversation.runtime import ConversationRuntime
    from sitina.journal.fast_start import FullJournalVerifier
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext
    from sitina.security.key_provider import JournalAuthProvider

    session = ConversationRuntime(home).resume_or_create_session()
    if session.session_id != expected.get("session_id") or session.mode is not ChatMode.AUTO:
        raise RuntimeError("fresh-process conversation recovery did not restore AUTO")
    context = ProductionRuntimeContext.load(home)
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    usage = _provider_usage_count(tuple(full.verified_events))
    if usage != int(expected["provider_usage_count_after_auto"]):
        raise RuntimeError("fresh-process AUTO verification performed a Provider operation")
    return {
        "status": "PASSED",
        "session_id": session.session_id,
        "prompt_label": session.mode.prompt_label,
        "provider_send_count": 0,
        "fresh_process_pid": os.getpid(),
    }


def _execute(home: Path) -> dict[str, Any]:
    """Run only the initial live worker; the parent supervises fresh resumes."""

    from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime

    result = TrueMultiAgentProductionRuntime(home).execute(
        CANARY_GOAL,
        label="formal-provider-failure-checkpoint-canary",
    )
    checkpoint_ids = tuple(str(item) for item in result.get("checkpoint_ids") or ())
    if result.get("status") != "checkpoint_restart_required" or len(checkpoint_ids) != 8:
        raise RuntimeError("initial canary worker did not commit the exact checkpoint supervisor plan")
    return dict(result)


def _discover_plan(home: Path, prepared: Mapping[str, Any]) -> dict[str, Any]:
    """Recover one committed stopped plan if the initial child lost stdout."""

    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    context = ProductionRuntimeContext.load(home)
    reader = context.open_verified_journal_reader()
    try:
        events = tuple(
            event
            for event in reader.iter_events(0)
            if event.position > int(prepared["journal_frontier"])
        )
    finally:
        reader.close()
    handoffs = [
        event
        for event in events
        if event.payload.get("schema") == "CHECKPOINT_SUPERVISOR_HANDOFF_REQUIRED_V1"
    ]
    if len(handoffs) != 1:
        raise RuntimeError("no unique committed checkpoint supervisor plan can be recovered")
    handoff = handoffs[0]
    run_id = str(handoff.payload.get("run_id") or "")
    selected = [event for event in events if event.payload.get("run_id") == run_id]
    checkpoint_ids = tuple(str(item) for item in handoff.payload.get("checkpoint_ids") or ())
    if (
        not run_id
        or len(checkpoint_ids) != 8
        or any(event.event_type == "run.terminal" for event in selected)
        or any(event.payload.get("schema") == "CHECKPOINT_RESUME_COMPLETED_V1" for event in selected)
        or sum(
            event.payload.get("schema") == "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1"
            for event in selected
        )
        != 1
        or sum(
            event.payload.get("schema") == "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1"
            for event in selected
        )
        != 1
    ):
        raise RuntimeError("recovered checkpoint plan is not the exact pre-resume canary state")
    return {
        "status": "checkpoint_restart_required",
        "run_id": run_id,
        "checkpoint_ids": list(checkpoint_ids),
        "journal_head_before_worker_exit": handoff.position,
        "terminal_state": "RESTART_REQUIRED",
        "recovered_from_authenticated_journal": True,
    }


def _seal(home: Path, envelope: Mapping[str, Any]) -> dict[str, Any]:
    from sitina.conversation.persistence import JournalSessionRepository
    from sitina.journal.fast_start import FullJournalVerifier
    from sitina.journal.model import canonical_json_bytes
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext
    from sitina.security.key_provider import JournalAuthProvider
    from sitina.utils import iso_now

    prepared = dict(envelope["prepared"])
    auto = dict(envelope["auto"])
    result = dict(envelope["result"])
    run_id = str(result.get("run_id") or "")
    checkpoint_ids = tuple(str(item) for item in result.get("checkpoint_ids") or ())
    if result.get("terminal_state") != "SUCCEEDED" or not run_id or len(checkpoint_ids) != 8:
        raise RuntimeError("supervised canary did not return one successful eight-checkpoint run")

    context = ProductionRuntimeContext.load(home)
    writer = context.open_runtime_writer()
    try:
        repository = JournalSessionRepository(writer, context.open_cas(), context.provider)
        repository.link_run(
            session_id=str(prepared["session_id"]),
            run_id=run_id,
            turn_index=int(prepared["session_turn_index"]),
            created_at=iso_now(),
        )
    finally:
        writer.close()

    context = ProductionRuntimeContext.load(home)
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    events = tuple(full.verified_events)
    selected = tuple(event for event in events if event.payload.get("run_id") == run_id)
    if not selected or min(event.position for event in selected) != int(prepared["journal_frontier"]) + 1:
        raise RuntimeError("canary Journal range does not begin immediately after its prepared frontier")

    terminal = [event for event in selected if event.event_type == "run.terminal"]
    failure = [
        event for event in selected if event.payload.get("schema") == "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1"
    ]
    recovery = [
        event for event in selected if event.payload.get("schema") == "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1"
    ]
    publications = [
        event for event in selected if event.payload.get("schema") == "CHECKPOINT_MANIFEST_PUBLISHED_V1"
    ]
    completions = [
        event for event in selected if event.payload.get("schema") == "CHECKPOINT_RESUME_COMPLETED_V1"
    ]
    matrix = [
        event for event in selected if event.payload.get("schema") == "CHECKPOINT_RESUME_MATRIX_COMPLETED_V1"
    ]
    links = [
        event
        for event in selected
        if event.event_type == "session.run-linked" and event.payload.get("session_id") == prepared["session_id"]
    ]
    if not (
        len(terminal) == len(failure) == len(recovery) == len(matrix) == len(links) == 1
        and len(publications) == len(completions) == 8
    ):
        raise RuntimeError("canary recovery/checkpoint/session evidence cardinality is invalid")
    if (
        terminal[0].payload.get("terminal_state") != "SUCCEEDED"
        or failure[0].payload.get("outcome_state") != "FAILED_CONFIRMED"
        or failure[0].payload.get("settlement_state") != "SETTLED"
        or int(failure[0].payload.get("physical_send_count", -1)) != 1
        or recovery[0].payload.get("physical_send_counts") != [0, 0, 1, 1]
    ):
        raise RuntimeError("explicit Provider failure did not settle through the bounded recovery matrix")
    if tuple(event.payload.get("checkpoint_id") for event in publications) != checkpoint_ids:
        raise RuntimeError("checkpoint publication identities differ from the supervisor result")
    completion_by_id = {str(event.payload["checkpoint_id"]): event for event in completions}
    if set(completion_by_id) != set(checkpoint_ids):
        raise RuntimeError("checkpoint completion identities differ from the supervisor plan")
    if any(
        int(event.payload.get("provider_send_count_before", -1))
        != int(event.payload.get("provider_send_count_after", -2))
        or int(event.payload.get("duplicate_provider_send_count", -1)) != 0
        or int(event.payload.get("new_process_pid", -1)) == int(event.payload.get("old_process_pid", -1))
        for event in completions
    ):
        raise RuntimeError("checkpoint resume duplicated a Provider send or reused the stopped process")

    cas = context.open_cas_reader()
    run_refs = sorted({reference for event in selected for reference in event.object_refs})
    checkpoint_refs: set[str] = set()
    checkpoint_records: list[dict[str, Any]] = []
    for event in publications:
        manifest_ref = str(event.payload["manifest_ref"])
        raw = cas.open_verified(cas.resolve_reference(manifest_ref))
        manifest = json.loads(raw)
        if manifest.get("checkpoint_id") != event.payload.get("checkpoint_id"):
            raise RuntimeError("checkpoint manifest identity differs from its Journal publication")
        refs = {str(reference) for reference in manifest.get("cas_refs") or ()}
        checkpoint_refs.update(refs)
        checkpoint_records.append(
            {
                "checkpoint_id": event.payload["checkpoint_id"],
                "manifest_ref": manifest_ref,
                "manifest_hash": event.payload["manifest_hash"],
                "validated_through_position": event.payload["validated_through_position"],
                "cas_reference_count": len(refs),
            }
        )
    literal = _direct_provider_literal(home)
    verified_refs = sorted(set(run_refs) | checkpoint_refs)
    for reference in verified_refs:
        plaintext = cas.open_verified(cas.resolve_reference(reference))
        if literal in plaintext:
            raise RuntimeError("configured Provider literal entered canary CAS evidence")
    if any(literal in canonical_json_bytes(event.core_mapping()) for event in selected):
        raise RuntimeError("configured Provider literal entered canary Journal evidence")

    replay = context.replay_run(run_id)
    if (
        replay.get("status") != "replay_ok"
        or int(replay.get("external_call_count", -1)) != 0
        or int(replay.get("effect_execution_count", -1)) != 0
    ):
        raise RuntimeError("canary replay was not a zero-external-effect reconstruction")
    profile = home / "profiles/deepseek.env"
    if _sha256(profile) != prepared["profile_sha256"] or profile.lstat().st_mode & 0o7777 != 0o600:
        raise RuntimeError("DeepSeek profile content or permissions changed during the canary")

    send_before = {int(event.payload["provider_send_count_before"]) for event in completions}
    send_after = {int(event.payload["provider_send_count_after"]) for event in completions}
    if len(send_before) != 1 or send_before != send_after:
        raise RuntimeError("checkpoint send counts are not globally consistent")
    return {
        "schema": "SITINA_PROVIDER_FAILURE_CHECKPOINT_RECOVERY_CANARY_V1",
        "status": "PASSED",
        "generated_at": _utc_now(),
        "goal_thread_id": GOAL_THREAD_ID,
        "run_id": run_id,
        "session_id": prepared["session_id"],
        "auto_mode_process_restart": auto,
        "provider_failure": {
            "effect_id": failure[0].payload["effect_id"],
            "effect_attempt_id": failure[0].payload["effect_attempt_id"],
            "outcome_state": "FAILED_CONFIRMED",
            "settlement_state": "SETTLED",
            "physical_send_count": 1,
            "automatic_retry_performed": False,
        },
        "checkpoints": checkpoint_records,
        "checkpoint_count": 8,
        "checkpoint_identities": list(checkpoint_ids),
        "fresh_process_restart": {
            "old_process_pid": completions[0].payload["old_process_pid"],
            "new_process_pids": [completion_by_id[item].payload["new_process_pid"] for item in checkpoint_ids],
            "all_crossed_process_boundary": True,
        },
        "journal": {
            "journal_id": full.authority_state.journal_id,
            "epoch": full.authority_state.epoch,
            "range_start": min(event.position for event in selected),
            "range_end": max(event.position for event in selected),
            "verified_frontier": full.authority_state.head_position,
            "verified_commitment": full.authority_state.last_transaction_hash,
            "selected_event_count": len(selected),
            "full_verification_passed": True,
        },
        "cas": {
            "run_object_references": run_refs,
            "run_object_reference_count": len(run_refs),
            "checkpoint_reference_count": len(checkpoint_refs),
            "verified_reference_count": len(verified_refs),
            "checkpoint_reference_set_sha256": hashlib.sha256(_canonical(sorted(checkpoint_refs))).hexdigest(),
            "all_references_opened_and_verified": True,
        },
        "provider_sends": {
            "checkpoint_send_count_before": next(iter(send_before)),
            "checkpoint_send_count_after": next(iter(send_after)),
            "duplicate_send_count": 0,
            "terminal_physical_send_count": terminal[0].payload["provider_physical_send_count"],
        },
        "terminal": {
            "state": "SUCCEEDED",
            "event_id": terminal[0].event_id,
            "position": terminal[0].position,
        },
        "replay": {
            "status": replay["status"],
            "external_call_count": replay["external_call_count"],
            "effect_execution_count": replay["effect_execution_count"],
            "cas_reference_count": replay["cas_reference_count"],
        },
        "security": {
            "approved_direct_deepseek_storage_exception": True,
            "profile_mode": "0600",
            "profile_content_unchanged": True,
            "credential_modified": False,
            "credential_value_included": False,
            "journal_exact_credential_hits": 0,
            "cas_exact_credential_hits": 0,
        },
    }


def _outer(args: argparse.Namespace, home: Path) -> int:
    if args.output is None:
        raise RuntimeError("canary evidence output is required")
    if not args.accept_deepseek_direct_storage_risk:
        raise RuntimeError("canary requires the explicit approved DeepSeek storage-risk flag")
    output = args.output.expanduser().resolve(strict=False)
    if home != PRODUCTION_HOME or output == home or home in output.parents:
        raise RuntimeError("canary requires exact Production and external evidence output")
    if not PYTHON.is_file():
        raise RuntimeError("bundled Python runtime is unavailable")
    literal = _direct_provider_literal(home)
    script = Path(__file__).resolve(strict=True)
    prepared = _safe_child([str(PYTHON), str(script), "--home", str(home), "--phase", "prepare"], home=home, literal=literal)
    auto = _safe_child(
        [str(PYTHON), str(script), "--home", str(home), "--phase", "verify-auto"],
        home=home,
        literal=literal,
        input_value=prepared,
    )
    try:
        plan = _safe_child(
            [str(PYTHON), str(script), "--home", str(home), "--phase", "execute"],
            home=home,
            literal=literal,
        )
    except RuntimeError:
        # Never retry a possibly committed Provider run. Recover only one
        # exact stopped plan from the authenticated Journal.
        plan = _safe_child(
            [str(PYTHON), str(script), "--home", str(home), "--phase", "discover-plan"],
            home=home,
            literal=literal,
            input_value=prepared,
        )
    checkpoint_ids = tuple(str(item) for item in plan.get("checkpoint_ids") or ())
    if plan.get("status") != "checkpoint_restart_required" or len(checkpoint_ids) != 8:
        raise RuntimeError("canary worker returned an invalid checkpoint supervisor plan")
    for checkpoint_id in checkpoint_ids:
        _safe_child(
            [
                str(PYTHON),
                "-m",
                "sitina.orchestrator.checkpoint_resume",
                "--home",
                str(home),
                "--run-id",
                str(plan["run_id"]),
                "--checkpoint-id",
                checkpoint_id,
            ],
            home=home,
            literal=literal,
        )
    finalize_command = [
        str(PYTHON),
        "-m",
        "sitina.orchestrator.checkpoint_resume",
        "--home",
        str(home),
        "--run-id",
        str(plan["run_id"]),
        "--finalize",
    ]
    for checkpoint_id in checkpoint_ids:
        finalize_command.extend(("--checkpoint-id", checkpoint_id))
    result = _safe_child(finalize_command, home=home, literal=literal)
    evidence = _safe_child(
        [str(PYTHON), str(script), "--home", str(home), "--phase", "seal"],
        home=home,
        literal=literal,
        input_value={"prepared": prepared, "auto": auto, "result": result},
    )
    digest = _atomic_json(output, evidence, literal)
    print(
        json.dumps(
            {
                "status": "PASSED",
                "run_id": evidence["run_id"],
                "session_id": evidence["session_id"],
                "output": str(output),
                "file_sha256": digest,
                "credential_value_included": False,
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    if args.phase == "prepare":
        print(json.dumps(_prepare(home), sort_keys=True))
        return 0
    if args.phase == "verify-auto":
        print(json.dumps(_verify_auto(home, json.load(sys.stdin)), sort_keys=True))
        return 0
    if args.phase == "execute":
        print(json.dumps(_execute(home), sort_keys=True))
        return 0
    if args.phase == "discover-plan":
        print(json.dumps(_discover_plan(home, json.load(sys.stdin)), sort_keys=True))
        return 0
    if args.phase == "seal":
        print(json.dumps(_seal(home, json.load(sys.stdin)), sort_keys=True))
        return 0
    return _outer(args, home)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error_hash": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                    "credential_value_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2)
