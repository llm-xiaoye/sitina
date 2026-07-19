"""Cross-check ledger, audit, replay, manifests, and persisted IDs."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.guards.secrets import scan_json_for_secrets
from sitina.orchestrator.accounting import ProviderAccounting
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.orchestrator.revision import CodeRevisionResolver
from sitina.orchestrator.run_manifest import RunManifestManager
from sitina.orchestrator.terminal import terminal_summary
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, read_json, sha256_text, stable_json, write_json


class AuditVerifier:
    SCHEMA_VERSION = "2.0"

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def verify(self, run_id: str) -> dict[str, Any]:
        ledger = RunLedger(self.home, self.store)
        timeline = ledger.timeline(run_id)
        if not timeline:
            return {
                "run_id": run_id,
                "status": "incomplete",
                "errors": ["run ledger not found"],
                "checks": {},
                "verifier_schema_version": self.SCHEMA_VERSION,
                "verified_at": iso_now(),
            }
        audit_rows = self._audit_rows(run_id)
        ledger_trace_ids = {str(event.get("_trace_id")) for event in timeline if event.get("_trace_id")}
        audit_ledger_trace_ids = {str(row.get("trace_id")) for row in audit_rows if row.get("operation") == "run_ledger" and row.get("trace_id")}
        terminal = terminal_summary(timeline)
        replay = ReplayEngine(self.home, self.store).replay(run_id, record=False)
        accounting = ProviderAccounting(self.home, self.store).for_run(run_id, timeline=timeline, replay=replay)
        checkpoint_index = CheckpointManager(self.home).list(run_id)
        checkpoint_events = [event for event in timeline if event.get("event_type") == "checkpoint_created"]
        provider_request_ids = self._provider_request_ids(timeline, replay)
        duplicate_provider_ids = sorted({value for value in provider_request_ids if provider_request_ids.count(value) > 1})
        secret_findings = []
        for event in timeline:
            secret_findings.extend(scan_json_for_secrets(event.get("payload_json") or {}, path="ledger", scope="audit_verify", field_path="payload_json"))
        for row in audit_rows:
            secret_findings.extend(scan_json_for_secrets(row.get("payload") or {}, path="audit", scope="audit_verify", field_path="payload_json"))
        manifest_path = RunManifestManager(self.home, self.store).path(run_id)
        manifest_ok = True
        manifest_errors: list[str] = []
        if manifest_path.exists():
            manifest_ok, manifest_errors = RunManifestManager(self.home, self.store).verify(manifest_path)
        revision = CodeRevisionResolver(self.home).for_run(run_id)
        current_revision = CodeRevisionResolver(self.home).current()
        revision_matches_current = all(
            revision.get(field) == current_revision.get(field)
            for field in ("code_revision", "config_hash", "roles_hash", "policy_hash")
        )
        run_started = next((event for event in timeline if event.get("event_type") == "run_started"), {})
        run_start_payload = run_started.get("payload_json") or {}
        run_provider_mode = str(run_start_payload.get("provider_mode") or "")
        relationships = self._agent_call_relationships(
            timeline,
            audit_rows,
            run_provider_mode=run_provider_mode,
            controlled_fixture=bool(accounting.get("controlled_fixture")),
        )
        checks = {
            "ledger_audit_linked": ledger_trace_ids <= audit_ledger_trace_ids,
            "no_orphan_ledger_audit": audit_ledger_trace_ids <= ledger_trace_ids,
            "terminal_unique": terminal["count"] == 1,
            "terminal_normalized": terminal.get("normalized_terminal") is not None,
            **relationships["checks"],
            "proposal_ids_unique": self._ids_unique(replay.proposals.get("submitted", []), "proposal_id"),
            "evaluation_ids_unique": self._ids_unique(replay.proposals.get("evaluations", []), "evaluation_id"),
            "handoff_ids_present": all(item.get("handoff_id") for item in replay.handoff_chain),
            "checkpoint_count_consistent": len(checkpoint_index) == len(checkpoint_events),
            "replay_source_events_present": replay.event_count == len(timeline),
            "replay_not_inconsistent": replay.status != "replay_inconsistent",
            "replay_snapshot_integrity": replay.snapshot_integrity.get("status") in {"passed", "not_recorded", "legacy_unverified"},
            "no_duplicate_provider_request_id": not duplicate_provider_ids,
            "manifest_present_or_legacy": manifest_path.exists() or bool(revision.get("legacy_unversioned")),
            "manifest_integrity": manifest_ok,
            "revision_matches_current": revision_matches_current,
            "no_secret": not secret_findings,
        }
        errors = [name for name, passed in checks.items() if not passed] + manifest_errors
        missing_unified_live_audit = (
            run_provider_mode == "live"
            and not accounting.get("controlled_fixture")
            and relationships["counts"]["high_level_agent_call_starts"] == 0
            and accounting.get("logical_agent_calls", 0) > 0
        )
        non_revision_errors = [error for error in errors if error != "revision_matches_current"]
        if missing_unified_live_audit:
            status = "legacy_unverified"
        elif non_revision_errors:
            status = "failed"
        elif not revision_matches_current:
            status = "stale"
        elif revision.get("legacy_unversioned"):
            status = "legacy_unverified"
        else:
            status = "passed"
        return {
            "run_id": run_id,
            "status": status,
            "verifier_schema_version": self.SCHEMA_VERSION,
            "verified_at": iso_now(),
            "checks": checks,
            "errors": errors,
            "terminal": terminal,
            "counts": {
                "ledger_events": len(timeline),
                "audit_entries": len(audit_rows),
                "logical_agent_calls": accounting["logical_agent_calls"],
                "http_attempts": accounting["http_attempts"],
                **relationships["counts"],
                "checkpoints": len(checkpoint_index),
                "secret_findings": len(secret_findings),
            },
            "agent_call_relationships": relationships["calls"],
            "orphan_logical_call_ids": relationships["orphan_logical_call_ids"],
            "orphan_attempt_ids": relationships["orphan_attempt_ids"],
            "duplicate_provider_request_ids": duplicate_provider_ids,
            "replay_snapshot_integrity": replay.snapshot_integrity,
            "legacy_unversioned": bool(revision.get("legacy_unversioned")),
            "code_revision": revision,
            "current_code_revision": current_revision,
            "revision_matches_current": revision_matches_current,
        }

    def verify_evidence(self, run_id: str) -> dict[str, Any]:
        result = self.verify(run_id)
        document = dict(result)
        document["evidence_hash"] = sha256_text(stable_json(document))
        path = self.home / "outputs" / "reports" / "audit" / run_id / f"audit_verify_{new_id()}.json"
        write_json(path, document)
        return document | {"artifact_path": str(path)}

    @staticmethod
    def evidence_is_valid(result: dict[str, Any]) -> bool:
        path_value = result.get("artifact_path")
        if not isinstance(path_value, str) or not path_value:
            return False
        path = Path(path_value)
        document = read_json(path, default=None)
        if not isinstance(document, dict):
            return False
        claimed = document.get("evidence_hash")
        body = {key: value for key, value in document.items() if key != "evidence_hash"}
        returned_document = {key: value for key, value in result.items() if key != "artifact_path"}
        return (
            claimed == sha256_text(stable_json(body))
            and claimed == result.get("evidence_hash")
            and document.get("run_id") == result.get("run_id")
            and document.get("verifier_schema_version") == result.get("verifier_schema_version")
            and document == returned_document
        )

    def _agent_call_relationships(
        self,
        timeline: list[dict[str, Any]],
        audit_rows: list[dict[str, Any]],
        *,
        run_provider_mode: str,
        controlled_fixture: bool,
    ) -> dict[str, Any]:
        starts = [
            row
            for row in audit_rows
            if row.get("operation") == "agent_call_started"
            and (row.get("payload") or {}).get("provider_mode") == "live"
        ]
        terminals = [
            row
            for row in audit_rows
            if row.get("operation") == "agent_call_terminal"
            and (row.get("payload") or {}).get("provider_mode") == "live"
        ]
        if controlled_fixture:
            starts = []
            terminals = []

        attempt_starts = [
            event
            for event in timeline
            if event.get("event_type") == "provider_http_attempt_started"
            and (event.get("payload_json") or {}).get("provider_mode") == "live"
        ]
        attempt_terminals = [
            event
            for event in timeline
            if event.get("event_type") in {"provider_http_attempt_completed", "provider_http_attempt_failed"}
            and (event.get("payload_json") or {}).get("provider_mode") == "live"
        ]
        if controlled_fixture:
            attempt_starts = []
            attempt_terminals = []

        start_ids = [str((row.get("payload") or {}).get("logical_call_id") or "") for row in starts]
        terminal_ids = [str((row.get("payload") or {}).get("logical_call_id") or "") for row in terminals]
        attempt_start_ids = [str((event.get("payload_json") or {}).get("attempt_id") or "") for event in attempt_starts]
        attempt_terminal_ids = [str((event.get("payload_json") or {}).get("attempt_id") or "") for event in attempt_terminals]
        attempt_logical_ids = [str((event.get("payload_json") or {}).get("logical_call_id") or "") for event in attempt_terminals]
        start_counts = Counter(start_ids)
        terminal_counts = Counter(terminal_ids)
        attempt_start_counts = Counter(attempt_start_ids)
        attempt_terminal_counts = Counter(attempt_terminal_ids)
        start_set = {value for value in start_ids if value}
        terminal_set = {value for value in terminal_ids if value}
        attempt_logical_set = {value for value in attempt_logical_ids if value}
        attempt_start_set = {value for value in attempt_start_ids if value}
        attempt_terminal_set = {value for value in attempt_terminal_ids if value}
        successful_attempts = {
            str((event.get("payload_json") or {}).get("logical_call_id"))
            for event in attempt_terminals
            if event.get("event_type") == "provider_http_attempt_completed"
            and (event.get("payload_json") or {}).get("logical_call_id")
        }
        successful_attempt_events = [
            event for event in attempt_terminals if event.get("event_type") == "provider_http_attempt_completed"
        ]
        completed_calls = {
            str((row.get("payload") or {}).get("logical_call_id"))
            for row in terminals
            if (row.get("payload") or {}).get("terminal_status") == "completed"
            and (row.get("payload") or {}).get("logical_call_id")
        }
        terminal_statuses = {
            str((row.get("payload") or {}).get("terminal_status") or "")
            for row in terminals
        }
        required = run_provider_mode == "live" and not controlled_fixture
        identities_consistent = self._agent_call_identities_consistent(starts, terminals, attempt_starts, attempt_terminals)
        logical_one_to_one = (
            bool(start_set) if required else True
        ) and start_set == terminal_set and all(start_counts[value] == 1 and terminal_counts[value] == 1 for value in start_set | terminal_set)
        attempt_one_to_one = (
            all(value for value in attempt_start_ids + attempt_terminal_ids)
            and attempt_start_set == attempt_terminal_set
            and all(attempt_start_counts[value] == 1 and attempt_terminal_counts[value] == 1 for value in attempt_start_set | attempt_terminal_set)
        ) if (attempt_starts or attempt_terminals) else not required
        attempts_require_logical = all(attempt_logical_ids) and attempt_logical_set <= start_set if attempt_terminals else not required
        logical_calls_have_attempts = start_set <= attempt_logical_set if start_set else not required
        completed_have_success = completed_calls <= successful_attempts
        terminal_status_valid = terminal_statuses <= {"completed", "failed", "timeout", "cancelled"} and (bool(terminal_statuses) if required else True)
        relationship_checks = {
            "high_level_start_ids_present": all(start_ids) and (bool(start_ids) if required else True),
            "high_level_terminal_ids_present": all(terminal_ids) and (bool(terminal_ids) if required else True),
            "high_level_starts_unique": all(count == 1 for value, count in start_counts.items() if value),
            "high_level_terminals_unique": all(count == 1 for value, count in terminal_counts.items() if value),
            "high_level_start_terminal_one_to_one": logical_one_to_one,
            "provider_attempt_ids_present": all(attempt_start_ids + attempt_terminal_ids) and (bool(attempt_terminal_ids) if required else True),
            "provider_attempt_start_terminal_one_to_one": attempt_one_to_one,
            "provider_attempts_require_logical_call": attempts_require_logical,
            "logical_calls_have_provider_attempts": logical_calls_have_attempts,
            "completed_calls_have_successful_attempt": completed_have_success,
            "successful_attempts_have_request_id": all(
                (event.get("payload_json") or {}).get("provider_request_id")
                for event in successful_attempt_events
            ) and (bool(successful_attempt_events) if completed_calls else True),
            "high_level_terminal_status_valid": terminal_status_valid,
            "agent_call_identity_consistent": identities_consistent,
            "retry_does_not_inflate_logical_calls": len(start_ids) == len(start_set),
            "mock_controlled_calls_excluded": True,
        }
        relationship_checks["no_duplicate_logical_terminal"] = relationship_checks["high_level_terminals_unique"]
        relationship_checks["no_orphan_provider_attempt"] = relationship_checks["provider_attempts_require_logical_call"]
        relationship_checks["no_completed_without_successful_attempt"] = relationship_checks["completed_calls_have_successful_attempt"]
        relationship_checks["provider_call_count_consistent"] = all(relationship_checks.values())

        attempts_by_logical: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in attempt_terminals:
            payload = event.get("payload_json") or {}
            logical_id = str(payload.get("logical_call_id") or "")
            if logical_id:
                attempts_by_logical[logical_id].append(event)
        starts_by_id = {str((row.get("payload") or {}).get("logical_call_id")): row for row in starts if (row.get("payload") or {}).get("logical_call_id")}
        calls: list[dict[str, Any]] = []
        for logical_id in sorted(start_set | terminal_set | attempt_logical_set):
            start = starts_by_id.get(logical_id, {})
            start_payload = start.get("payload") or {}
            attempts = attempts_by_logical.get(logical_id, [])
            terminal_rows = [row for row in terminals if (row.get("payload") or {}).get("logical_call_id") == logical_id]
            calls.append(
                {
                    "logical_call_id": logical_id,
                    "agent_id": start_payload.get("agent_id") or start.get("agent"),
                    "role": start_payload.get("role"),
                    "task_id": start_payload.get("task_id"),
                    "task_type": start_payload.get("task_type"),
                    "call_origin": (start_payload.get("context") or {}).get("call_origin"),
                    "start_count": start_counts.get(logical_id, 0),
                    "terminal_count": terminal_counts.get(logical_id, 0),
                    "terminal_status": (terminal_rows[0].get("payload") or {}).get("terminal_status") if terminal_rows else None,
                    "http_attempts": len(attempts),
                    "successful_http_attempts": sum(1 for event in attempts if event.get("event_type") == "provider_http_attempt_completed"),
                    "provider_request_ids": sorted(
                        {
                            str((event.get("payload_json") or {}).get("provider_request_id"))
                            for event in attempts
                            if (event.get("payload_json") or {}).get("provider_request_id")
                        }
                    ),
                }
            )
        orphan_logical = sorted((terminal_set | attempt_logical_set) - start_set)
        orphan_attempts = sorted(attempt_terminal_set - attempt_start_set)
        return {
            "checks": relationship_checks,
            "counts": {
                "high_level_agent_call_starts": len(starts),
                "high_level_agent_call_terminals": len(terminals),
                "provider_attempt_starts": len(attempt_starts),
                "provider_attempt_terminals": len(attempt_terminals),
                "orphan_logical_calls": len(orphan_logical),
                "orphan_provider_attempts": len(orphan_attempts),
            },
            "calls": calls,
            "orphan_logical_call_ids": orphan_logical,
            "orphan_attempt_ids": orphan_attempts,
        }

    @staticmethod
    def _agent_call_identities_consistent(
        starts: list[dict[str, Any]],
        terminals: list[dict[str, Any]],
        attempt_starts: list[dict[str, Any]],
        attempt_terminals: list[dict[str, Any]],
    ) -> bool:
        identities: dict[str, tuple[str, str, str, str, str]] = {}
        for row in starts:
            payload = row.get("payload") or {}
            logical_id = str(payload.get("logical_call_id") or "")
            if not logical_id:
                continue
            identities[logical_id] = (
                str(payload.get("agent_id") or row.get("agent") or ""),
                str(payload.get("task_id") or ""),
                str(payload.get("provider_mode") or ""),
                str(payload.get("profile_name") or ""),
                str(payload.get("model") or ""),
            )
        for row in terminals:
            payload = row.get("payload") or {}
            logical_id = str(payload.get("logical_call_id") or "")
            if logical_id not in identities:
                continue
            candidate = (
                str(payload.get("agent_id") or row.get("agent") or ""),
                str(payload.get("task_id") or ""),
                str(payload.get("provider_mode") or ""),
            )
            if candidate != identities[logical_id][:3]:
                return False
            agent, task_id, provider_mode, start_profile, start_model = identities[logical_id]
            identities[logical_id] = (
                agent,
                task_id,
                provider_mode,
                str(payload.get("profile_name") or start_profile),
                str(payload.get("model") or start_model),
            )
        for event in attempt_starts + attempt_terminals:
            payload = event.get("payload_json") or {}
            logical_id = str(payload.get("logical_call_id") or "")
            if logical_id not in identities:
                continue
            agent, task_id, provider_mode, profile_name, model = identities[logical_id]
            if str(event.get("agent_id") or "") != agent:
                return False
            if str(event.get("task_id") or "") != task_id:
                return False
            if str(payload.get("provider_mode") or "") != provider_mode:
                return False
            if profile_name and payload.get("profile_name") and str(payload.get("profile_name")) != profile_name:
                return False
            if model and payload.get("model") and str(payload.get("model")) != model:
                return False
        return True

    def _audit_rows(self, run_id: str) -> list[dict[str, Any]]:
        self.store.init_db()
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT id, ts, trace_id, agent, operation, input_hash, output_hash, artifact_hash, exit_status, duration_ms, payload_json FROM audit_log WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row_id, ts, trace_id, agent, operation, input_hash, output_hash, artifact_hash, exit_status, duration_ms, payload_json in rows:
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                payload = {}
            values.append(
                {
                    "id": row_id,
                    "ts": ts,
                    "trace_id": trace_id,
                    "agent": agent,
                    "operation": operation,
                    "input_hash": input_hash,
                    "output_hash": output_hash,
                    "artifact_hash": artifact_hash,
                    "exit_status": exit_status,
                    "duration_ms": duration_ms,
                    "payload": payload,
                }
            )
        return values

    @staticmethod
    def _ids_unique(items: list[dict[str, Any]], field: str) -> bool:
        values = [str(item.get(field)) for item in items if item.get(field)]
        return len(values) == len(set(values))

    @staticmethod
    def _provider_request_ids(timeline: list[dict[str, Any]], replay: Any) -> list[str]:
        explicit = [
            str((event.get("payload_json") or {}).get("provider_request_id"))
            for event in timeline
            if event.get("event_type") == "provider_http_attempt_completed" and (event.get("payload_json") or {}).get("provider_request_id")
        ]
        if explicit:
            return explicit
        return [
            str(call.get("provider_request_id"))
            for snapshot in replay.agent_snapshots
            for call in snapshot.get("provider_calls") or []
            if call.get("provider_request_id")
        ]
