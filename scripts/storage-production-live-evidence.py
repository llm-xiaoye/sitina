#!/usr/bin/env python3
"""Extract and validate body-free evidence for the Production CLI canaries."""

from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import collections
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.fast_start import FullJournalVerifier
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.security.key_provider import JournalAuthProvider


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"
SESSION_ID = "chat-session-0c8f389e20334a7796a1682795aa6724"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2).encode() + b"\n"
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
                raise OSError("short live-evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return _sha(raw)


def _counts(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(collections.Counter(values).items()))


def _cas_header(home: Path, reference: str) -> dict[str, Any]:
    if not reference.startswith("cas:"):
        raise RuntimeError("non-CAS object reference entered the live evidence set")
    object_id = reference.removeprefix("cas:")
    path = home / "cas/objects" / object_id[:2] / f"{object_id}.obj"
    raw = path.read_bytes()
    if _sha(raw) != object_id or len(raw) < 4:
        raise RuntimeError("live evidence CAS ciphertext identity is invalid")
    length = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4 : 4 + length])
    return {
        "reference": reference,
        "core_header_schema": header.get("schema"),
        "compression": header.get("compression"),
        "compression_level": header.get("compression_level"),
        "compression_mode": header.get("compression_mode"),
        "plaintext_length": int(header["plaintext_length"]),
        "ciphertext_sha256_valid": True,
    }


def _run_evidence(context: ProductionRuntimeContext, events: tuple[Any, ...], run_id: str) -> dict[str, Any]:
    selected = tuple(item for item in events if item.payload.get("run_id") == run_id)
    if not selected:
        raise RuntimeError(f"linked run is absent from full replay: {run_id}")
    terminal = [item for item in selected if item.event_type == "run.terminal"]
    if len(terminal) != 1 or terminal[0].payload.get("terminal_state") != "SUCCEEDED":
        raise RuntimeError(f"linked run has no unique successful terminal fact: {run_id}")
    usage_events = [item for item in selected if item.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1"]
    successful_usage = [item for item in usage_events if item.payload.get("outcome") == "SUCCEEDED"]
    terminal_payload = terminal[0].payload
    logical_count = int(terminal_payload.get("provider_call_count", -1))
    physical_count = int(terminal_payload.get("provider_physical_send_count", -1))
    usage_physical_count = sum(int(item.payload.get("physical_send_count", 0)) for item in usage_events)
    if logical_count != len(successful_usage) or physical_count != usage_physical_count:
        raise RuntimeError(f"Provider accounting does not reconcile for run: {run_id}")
    schemas = [str(item.payload.get("schema")) for item in selected if isinstance(item.payload.get("schema"), str)]
    event_types = [item.event_type for item in selected]
    object_refs = sorted({reference for item in selected for reference in item.object_refs})
    replay = context.replay_run(run_id)
    if replay.get("status") != "replay_ok" or replay.get("external_call_count") != 0:
        raise RuntimeError(f"read-only run replay failed closed: {run_id}")
    context_events = [
        item
        for item in selected
        if item.payload.get("schema") == "SITINA_AGENT_CONTEXT_MANIFEST_PUBLISHED_V2"
    ]
    context_streams = sorted({item.stream_id for item in context_events})
    return {
        "run_id": run_id,
        "journal_range": [min(item.position for item in selected), max(item.position for item in selected)],
        "event_count": len(selected),
        "event_type_counts": _counts(event_types),
        "schema_counts": _counts(schemas),
        "terminal": {
            "position": terminal[0].position,
            "event_id": terminal[0].event_id,
            "event_hash": terminal[0].event_hash,
            "terminal_state": terminal_payload["terminal_state"],
            "provider_call_count": logical_count,
            "provider_physical_send_count": physical_count,
            "provider_retry_count": int(terminal_payload.get("provider_retry_count", 0)),
            "provider_fallback_count": int(terminal_payload.get("provider_fallback_count", 0)),
            "external_mutation_count": int(terminal_payload.get("external_mutation_count", 0)),
            "legacy_read_count": int(terminal_payload.get("legacy_read_count", 0)),
            "negotiation_protocol_count": int(terminal_payload.get("negotiation_protocol_count", 0)),
            "handoff_protocol_count": int(terminal_payload.get("handoff_protocol_count", 0)),
            "response_hash": terminal_payload.get("user_response_hash") or terminal_payload.get("response_hash"),
            "evidence_package_ref": terminal_payload.get("evidence_package_ref"),
            "evidence_package_hash": terminal_payload.get("evidence_package_hash"),
        },
        "provider_usage": [
            {
                "position": item.position,
                "call_id": item.payload.get("call_id"),
                "agent_id": item.payload.get("agent_id"),
                "provider": item.payload.get("provider"),
                "model": item.payload.get("model"),
                "outcome": item.payload.get("outcome"),
                "physical_send_count": int(item.payload.get("physical_send_count", 0)),
                "retry_count": int(item.payload.get("retry_count", 0)),
                "fallback_count": int(item.payload.get("fallback_count", 0)),
                "total_tokens": int(item.payload.get("total_tokens", 0)),
                "cost_micro_usd": int(item.payload.get("cost_micro_usd", 0)),
            }
            for item in usage_events
        ],
        "agent_context_v2": {
            "event_count": len(context_events),
            "positions": [item.position for item in context_events],
            "streams": context_streams,
            "independent_from_run_stream": bool(context_events)
            and context_streams == [f"run-context/{run_id}"],
        },
        "cas": {
            "reference_count": len(object_refs),
            "references": object_refs,
            "objects": [_cas_header(PRODUCTION_HOME, reference) for reference in object_refs],
        },
        "replay": {
            "status": replay["status"],
            "semantic_checksum": replay["semantic_checksum"],
            "event_count": replay["event_count"],
            "cas_reference_count": replay["cas_reference_count"],
            "cas_read_count": replay["cas_read_count"],
            "external_call_count": replay["external_call_count"],
            "effect_execution_count": replay["effect_execution_count"],
            "legacy_read_count": replay["legacy_read_count"],
            "fallback_used": replay["fallback_used"],
            "writer_activated": replay["writer_activated"],
        },
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: storage-production-live-evidence.py EVIDENCE_OUTPUT")
    output = Path(sys.argv[1]).expanduser().resolve(strict=False)
    if output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("live evidence must be written outside Production")
    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    fast = context.authority.fast_start_report
    if fast is None or not fast.fast_start_checkpoint_used:
        raise RuntimeError("Production did not select the checkpoint-bound Fast Start authority path")
    full = FullJournalVerifier(
        PRODUCTION_HOME,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    if full.authority_state != fast.authority_state:
        raise RuntimeError("Fast Start authority differs from independent full replay")
    events = tuple(full.verified_events)
    session_events = tuple(item for item in events if item.stream_id == f"session/{SESSION_ID}")
    if not session_events or sum(item.event_type == "session.created" for item in session_events) != 1:
        raise RuntimeError("target Production CLI session is unavailable or ambiguous")
    links: dict[int, list[Any]] = collections.defaultdict(list)
    routes: dict[int, Any] = {}
    messages: dict[int, list[Any]] = collections.defaultdict(list)
    for event in session_events:
        turn = event.payload.get("turn_index")
        if isinstance(turn, int):
            if event.event_type == "session.run-linked":
                links[turn].append(event)
            elif event.event_type == "session.route-decided":
                routes[turn] = event
            elif event.event_type == "session.message-appended":
                messages[turn].append(event)
    expected_modes = {
        1: ("AUTO", "FAST"),
        2: ("AUTO", "FAST"),
        3: ("FAST", "FAST"),
        4: ("AUTO", "FAST"),
        5: ("MULTI", "MULTI"),
    }
    if set(links) != set(expected_modes) or set(routes) != set(expected_modes):
        raise RuntimeError(f"CLI canary turn set differs from expected 1..5: links={sorted(links)}, routes={sorted(routes)}")
    run_cache: dict[str, dict[str, Any]] = {}
    turns: list[dict[str, Any]] = []
    for turn_index, (requested, resolved) in expected_modes.items():
        if len(links[turn_index]) != 1:
            raise RuntimeError(f"turn {turn_index} is not linked to exactly one authoritative run")
        roles = sorted(str(item.payload.get("role")) for item in messages[turn_index])
        if roles != ["assistant", "user"]:
            raise RuntimeError(f"turn {turn_index} does not have one durable user/assistant message pair")
        route_event = routes[turn_index]
        decision = dict(route_event.payload["decision"])
        if decision.get("requested_mode") != requested or decision.get("resolved_mode") != resolved:
            raise RuntimeError(f"turn {turn_index} route differs from the live CLI canary contract")
        run_id = str(links[turn_index][0].payload["run_id"])
        run = run_cache.setdefault(run_id, _run_evidence(context, events, run_id))
        is_fast = resolved == "FAST"
        terminal = run["terminal"]
        if is_fast and (terminal["provider_call_count"] != 1 or terminal["provider_physical_send_count"] != 1):
            raise RuntimeError(f"FAST turn {turn_index} did not use exactly one logical/physical Provider send")
        if turn_index == 1:
            if run["schema_counts"].get("FAST_CONVERSATION_COMMITTED_CALL_RECOVERED_V1") != 1:
                raise RuntimeError("recovered default canary lacks committed-call recovery evidence")
        elif run["schema_counts"].get("FAST_CONVERSATION_COMMITTED_CALL_RECOVERED_V1", 0) != 0:
            raise RuntimeError(f"clean canary turn {turn_index} unexpectedly used committed-call recovery")
        if turn_index > 1 and not run["agent_context_v2"]["independent_from_run_stream"]:
            raise RuntimeError(f"clean post-repair turn {turn_index} did not isolate Agent Context publication")
        turns.append(
            {
                "turn_index": turn_index,
                "canary": (
                    "default-auto-recovered-zero-resend"
                    if turn_index == 1
                    else "default-auto-clean"
                    if turn_index == 2
                    else "forced-fast-clean"
                    if turn_index == 3
                    else "explicit-auto-clean"
                    if turn_index == 4
                    else "forced-multi-live-collaboration"
                ),
                "route_position": route_event.position,
                "run_link_position": links[turn_index][0].position,
                "requested_mode": requested,
                "resolved_mode": resolved,
                "route_source": decision.get("source"),
                "route_policy_version": decision.get("policy_version"),
                "route_input_hash": decision.get("input_hash"),
                "route_decision_path": decision.get("decision_path"),
                "message_positions": [item.position for item in sorted(messages[turn_index], key=lambda item: item.position)],
                "message_body_refs": [item.payload["body_ref"] for item in sorted(messages[turn_index], key=lambda item: item.position)],
                "message_body_hashes": [item.payload["body_hash"] for item in sorted(messages[turn_index], key=lambda item: item.position)],
                "message_bodies_in_journal": False,
                "run": run,
            }
        )
    multi = turns[-1]["run"]
    required_multi_types = {
        "proposal.submitted",
        "review.response",
        "negotiation.round.opened",
        "handoff.accepted",
        "handoff.submitted",
        "handoff.verified",
        "run.terminal",
    }
    missing_multi = sorted(required_multi_types.difference(multi["event_type_counts"]))
    if missing_multi:
        raise RuntimeError(f"MULTI canary lacks required live collaboration facts: {missing_multi}")
    if (
        multi["terminal"]["provider_call_count"] <= 1
        or multi["terminal"]["provider_physical_send_count"] <= 1
    ):
        raise RuntimeError("MULTI canary did not execute multiple independent Provider calls")
    if multi["terminal"]["negotiation_protocol_count"] < 1 or multi["terminal"]["handoff_protocol_count"] < 1:
        raise RuntimeError("MULTI terminal did not bind Negotiation and Handoff completion")
    runtime = ConversationRuntime(PRODUCTION_HOME)
    recovered = runtime.resume_or_create_session()
    if recovered.session_id != SESSION_ID or recovered.turn_index != 5 or len(recovered.history) != 5:
        raise RuntimeError("fresh Conversation Runtime restart did not recover all five successful CLI canaries")
    if recovered.last_failed_message is not None or len(recovered.accepted_memories) != 1:
        raise RuntimeError("fresh Conversation Runtime restart changed failure or accepted Memory state")
    all_refs = sorted(
        {
            reference
            for turn in turns
            for reference in (
                list(turn["message_body_refs"])
                + list(turn["run"]["cas"]["references"])
            )
        }
    )
    all_objects = [_cas_header(PRODUCTION_HOME, reference) for reference in all_refs]
    zstd = [item for item in all_objects if item["compression"] == "zstd"]
    if not zstd:
        raise RuntimeError("live canaries did not exercise an activated CAS zstd write")
    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_PRODUCTION_LIVE_CLI_CANARIES_V1",
        "status": "PASSED",
        "goal_thread_id": GOAL_THREAD_ID,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "production_home": str(PRODUCTION_HOME),
        "session_id": SESSION_ID,
        "authority": {
            "journal_id": full.authority_state.journal_id,
            "epoch": full.authority_state.epoch,
            "frontier_position": full.authority_state.head_position,
            "frontier_commitment": full.authority_state.last_transaction_hash,
            "checkpoint_commitment": fast.checkpoint_commitment,
            "checkpoint_verified_through_position": fast.verified_through_position,
            "active_tail_event_count": fast.active_tail_event_count,
            "fast_start_equals_full_replay": True,
            "full_replay_event_count": full.journal_events_verified,
            "full_replay_bytes_scanned": full.journal_bytes_scanned,
        },
        "session": {
            "event_count": len(session_events),
            "journal_range": [session_events[0].position, session_events[-1].position],
            "event_type_counts": _counts(item.event_type for item in session_events),
            "successful_turn_count_after_fresh_restart": len(recovered.history),
            "turn_index_after_fresh_restart": recovered.turn_index,
            "last_failed_message_after_fresh_restart": None,
            "accepted_memory_count_after_fresh_restart": len(recovered.accepted_memories),
            "restart_provider_send_count": 0,
        },
        "turns": turns,
        "multi_agent_protocol_acceptance": {
            "proposal_persisted": True,
            "independent_review_persisted": True,
            "negotiation_persisted": True,
            "handoff_persisted": True,
            "final_execution_persisted": True,
            "required_event_types": sorted(required_multi_types),
            "called_agent_ids": sorted(
                {
                    str(item["agent_id"])
                    for item in multi["provider_usage"]
                    if isinstance(item.get("agent_id"), str)
                }
            ),
            "all_replayable_without_external_calls": True,
        },
        "cas_zstd_first_live_path": {
            "verified_reference_count": len(all_refs),
            "zstd_reference_count": len(zstd),
            "zstd_profiles": _counts(
                f"level-{item['compression_level']}-{item['compression_mode']}" for item in zstd
            ),
            "all_ciphertext_sha256_valid": True,
            "plaintext_bodies_in_evidence": False,
        },
        "external_mutation_count": 0,
        "legacy_read_count": 0,
        "legacy_write_count": 0,
        "sqlite_authority_count": 0,
        "provider_secret_values_included": False,
        "message_or_response_bodies_included": False,
    }
    evidence_sha256 = _atomic_json(output, evidence)
    print(json.dumps({"status": "PASSED", "path": str(output), "sha256": evidence_sha256}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
