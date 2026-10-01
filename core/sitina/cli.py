from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import shutil
import subprocess
import sys
import time
import fcntl
import stat
from pathlib import Path
from typing import Any, Mapping
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sitina.config import ConfigValidator, export_json_schemas
from sitina.constants import REQUIRED_DIRS, SITINA_HOME
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.evals import run_safety_eval
from sitina.extensions.manager import ExtensionInstallError, ExtensionManager, PermissionGrantRequired
from sitina.extensions.runtime import AutonomousRuntime
from sitina.extensions.tools import ApprovalRequest
from sitina.guards.risk import RiskScanner
from sitina.install_identity import canonical_journal_native_home
from sitina.memory.native import EpisodeRepository, MemoryACL, MemoryAccessDenied, MemoryRepository, MemoryStateError
from sitina.orchestrator.autonomy import AutonomyManager
from sitina.orchestrator.arbitration import ArbitrationManager
from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.audit_verify import AuditVerifier
from sitina.orchestrator.cli_evidence import CliEvidenceRecorder
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.context import ContextBuilder
from sitina.orchestrator.code_mode_gate import CodeModeAcceptanceV1, build_candidate_manifest
from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
from sitina.orchestrator.code_mode_authority_broker import _connect_attested_host
from sitina.orchestrator.code_mode_reviewer import (
    CodeModeReviewerProducerSession,
    CodeModeReviewerSession,
)
from sitina.orchestrator.evidence_bundle import EvidenceBundleManager
from sitina.orchestrator.git_ops import GitWorktreeManager
from sitina.orchestrator.handoff import HandoffManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.local_runtime import JournalNativeLocalRuntime
from sitina.orchestrator.leases import LeaseManager
from sitina.orchestrator.maintenance import MaintenanceOps
from sitina.orchestrator.observability_management import TraceQuery, TraceQueryEngine
from sitina.orchestrator.parallel import ParallelCoordinator
from sitina.orchestrator.performance_management import RuntimeCostMonitor
from sitina.orchestrator.policy import TASK_TYPES, WorkflowPolicyEngine
from sitina.orchestrator.proposals import ProposalManager
from sitina.orchestrator.replay import ReplayEngine
from sitina.orchestrator.retry import RetryPolicy
from sitina.orchestrator.reviewers import MultiReviewer
from sitina.orchestrator.reporting import ReportPersistence, report_exit_code
from sitina.orchestrator.schema_registry import SchemaRegistry
from sitina.orchestrator.side_effects import SideEffectManager
from sitina.orchestrator.task_graph import TaskGraphRuntime
from sitina.orchestrator.team import DynamicTeamBuilder
from sitina.runners.mcp_adapter import McpAdapter
from sitina.runners.profiles import ProfileLoader
from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception
from sitina.runners.provider import AnthropicCompatibleClient, ScriptedMockToolClient
from sitina.security.key_provider import InMemoryKeyProvider
from sitina.storage import LegacyRuntimePolicy, SitinaStore
from sitina.utils import ensure_dir, iso_now, load_json_yaml, write_json
from sitina.runners.provider import RoleProfileResolver


_LAST_PRINTED_JSON: Any = None

_SUGGEST_LATENCY_CLASS_CHOICES = ("interactive", "standard", "batch")


def _is_production_home() -> bool:
    return SITINA_HOME.expanduser().resolve(strict=False) == canonical_journal_native_home()


def _bplus_installed() -> bool:
    production_genesis = (SITINA_HOME / "state/bplus-production-genesis/genesis.json").is_file()
    if _is_production_home():
        return production_genesis
    return production_genesis or (SITINA_HOME / "state/clean-acceptance/genesis.json").is_file()


def _bplus_context() -> Any:
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    if not _is_production_home() and (SITINA_HOME / "state/clean-acceptance/genesis.json").is_file():
        from sitina.orchestrator.clean_acceptance import CleanAcceptanceContext

        return CleanAcceptanceContext.load(SITINA_HOME)  # type: ignore[return-value]
    return ProductionRuntimeContext.load(
        SITINA_HOME,
        allow_simulation=(SITINA_HOME / ".sitina-bplus-disposable-v1").is_file(),
    )


def _fence_orphaned_code_mode_sessions(runtime_parent: Path, current_session: str) -> None:
    """Fence stale controller-owned worker groups without reopening old state."""
    sessions_root = runtime_parent / "sessions"
    if not sessions_root.is_dir():
        return
    for namespace in sorted(sessions_root.iterdir(), key=lambda item: item.name):
        if not namespace.is_dir() or namespace.name == current_session:
            continue
        lock = None
        try:
            lock = (namespace / ".code-mode-session.lock").open("a+")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            if lock is not None:
                lock.close()
            continue
        try:
            records_path = namespace / ".code-mode-managed-processes.json"
            try:
                records = json.loads(records_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                records = []
            if not isinstance(records, list):
                records = []
            for record in records:
                if not isinstance(record, Mapping):
                    continue
                try:
                    pid = int(record.get("pid") or 0)
                except (TypeError, ValueError):
                    continue
                expected = str(record.get("start_identity") or "").removeprefix("sha256:")
                if pid <= 1 or pid == os.getpid() or not expected:
                    continue
                try:
                    observed = subprocess.run(
                        ["/bin/ps", "-p", str(pid), "-o", "lstart="],
                        check=True, capture_output=True, text=True, timeout=2,
                    ).stdout.strip()
                except (OSError, subprocess.SubprocessError):
                    observed = ""
                if hashlib.sha256(observed.encode("utf-8")).hexdigest() != expected:
                    continue
                try:
                    if os.getpgid(pid) != pid:
                        continue
                    os.killpg(pid, 15)
                    deadline = time.monotonic() + 1.0
                    while time.monotonic() < deadline:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.02)
                    else:
                        os.killpg(pid, 9)
                except (OSError, ProcessLookupError):
                    pass
            try:
                records_path.write_text("[]", encoding="utf-8")
            except OSError:
                pass
        finally:
            if lock is not None:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                finally:
                    lock.close()


def _discover_provider_profile_paths(home: Path) -> dict[str, str]:
    """Return only launcher-approved, non-secret profile file references.

    The CLI deliberately does not parse these files.  Their contents, including
    direct credentials and keychain references, are authority-host material.
    The launcher only forwards a regular mode-0600 file that is not a symlink or
    template; the host performs the actual profile/keychain load in its own
    process.
    """

    profile_dir = Path(home) / "profiles"
    try:
        directory_info = profile_dir.lstat()
    except OSError:
        return {}
    if not stat.S_ISDIR(directory_info.st_mode) or profile_dir.is_symlink():
        return {}
    result: dict[str, str] = {}
    try:
        entries = sorted(profile_dir.iterdir(), key=lambda item: item.name)
    except OSError:
        return {}
    for path in entries:
        if path.suffix != ".env" or path.name.endswith(".template") or not path.stem:
            continue
        try:
            info = path.lstat()
        except OSError:
            continue
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            continue
        if stat.S_IMODE(info.st_mode) != 0o600:
            continue
        result[path.stem] = str(path)
    return result


def _provider_policy_for_profile(source_root: Path, selected: str | None) -> dict[str, Any] | None:
    """Build a non-secret policy selection for a configured profile.

    A profile selection is meaningful only when the signed source policy lists
    its model allowlist.  This keeps the host authoritative for secrets while
    preventing a caller from selecting an arbitrary endpoint/model pair.
    """

    requested = str(selected or "").strip()
    if not requested:
        return None
    policy_path = Path(source_root) / "config" / "true_multi_agent_policy.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("provider profile policy is unavailable") from error
    if not isinstance(policy, dict):
        raise RuntimeError("provider profile policy is invalid")
    configured = policy.get("provider_profile")
    if requested == configured:
        return None
    profile_table = policy.get("provider_profiles")
    entry = profile_table.get(requested) if isinstance(profile_table, Mapping) else None
    if not isinstance(entry, Mapping):
        raise RuntimeError("provider profile is not authorized by the Code Mode policy")
    models = entry.get("provider_model_allowlist", entry.get("allowed_models"))
    if not isinstance(models, list) or not models or any(type(item) is not str or not item for item in models):
        raise RuntimeError("provider profile has no exact model allowlist")
    selected_policy = dict(policy)
    selected_policy["provider_profile"] = requested
    selected_policy["provider_model_allowlist"] = list(models)
    return selected_policy
def authority_writer_label(resolution: object, *, now: int, phase_flag: str | None = None) -> str:
    """Return the already-resolved writer; a CLI/phase flag is never authority."""
    del phase_flag
    from sitina.authority.model import AuthorityResolution
    if not isinstance(resolution, AuthorityResolution):
        raise PermissionError("CLI business dispatch requires AuthorityResolution")
    resolution.assert_fresh(now=now)
    if resolution.writer_count != 1:
        raise PermissionError("CLI business dispatch has no unique writer")
    return "legacy" if resolution.authorizes_legacy else "journal"


def print_json(value) -> None:
    global _LAST_PRINTED_JSON
    _LAST_PRINTED_JSON = value
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def cmd_init(args: argparse.Namespace) -> int:
    policy = LegacyRuntimePolicy.load(SITINA_HOME)
    if not policy.fully_disabled:
        print_json({
            "status": "blocked",
            "reason": "Legacy initialization was retired; initialize a Journal-native B+ home instead",
            "legacy_database_created": False,
        })
        return 3
    # A clean B+ root must not recreate retired Legacy runtime directories.
    clean_acceptance = not _is_production_home() and (SITINA_HOME / ".sitina-clean-acceptance-v1").is_file()
    runtime_dirs = ("journal", "cas", "projections") + (("state/locks",) if clean_acceptance else ())
    for rel in runtime_dirs:
        path = SITINA_HOME / rel
        if not path.exists():
            ensure_dir(path)
    print_json({
        "status": "ok",
        "home": str(SITINA_HOME),
        "canonical_authority": "journal" if policy.fully_disabled else "legacy_fixture",
        "legacy_enabled": policy.legacy_enabled,
        "legacy_database_created": False if policy.fully_disabled else True,
        "active_business_jsonl_enabled": policy.active_business_jsonl_enabled,
    })
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_cmd == "export-schemas":
        paths = export_json_schemas(SITINA_HOME)
        print_json({"status": "ok", "schemas": [str(p) for p in paths]})
        return 0
    if args.config_cmd == "validate":
        result = ConfigValidator(SITINA_HOME).validate()
        print_json(result)
        return 0 if result["ok"] else 2
    raise SystemExit("unknown config command")


def cmd_doctor(args: argparse.Namespace) -> int:
    policy = LegacyRuntimePolicy.load(SITINA_HOME)
    if args.fix:
        if policy.fully_disabled:
            print_json({"status": "blocked", "reason": "doctor --fix is unavailable in Legacy-disabled B+ mode"})
            return 3
        store = SitinaStore(SITINA_HOME)
        scan = RiskScanner(SITINA_HOME).scan("doctor_fix", target=str(SITINA_HOME), allowed_roots=[str(SITINA_HOME)])
        store.insert_risk_scan(scan.model_dump())
        if scan.approval_required and not args.approval_id:
            print_json({"status": "blocked", "reason": "doctor --fix requires approval_id", "risk_scan": scan.model_dump()})
            return 3
    result = ConfigValidator(SITINA_HOME).validate()
    provider_secret_audit = ProfileLoader(SITINA_HOME).audit_profiles()
    provider_storage_exception = evaluate_deepseek_direct_storage_exception(
        provider_secret_audit,
        user_accepted=_is_production_home(),
    )
    provider_security_ok = (
        provider_secret_audit["status"] == "ok"
        or provider_storage_exception["status"] == "accepted"
    )
    # This diagnostic checks only the three exact retired artifact names. It
    # never opens SQLite and therefore cannot create or mutate the database.
    unexpected_sqlite = policy.unexpected_sqlite_artifacts(SITINA_HOME)
    db_ok = (SITINA_HOME / "data" / "sitina.db").is_file()
    legacy_storage_ok = not unexpected_sqlite if policy.fully_disabled else db_ok
    bplus_ok = True
    authority: dict[str, Any] | None = None
    if _bplus_installed():
        try:
            context = _bplus_context()
            authority = {
                "state": context.authority.resolution.state.value,
                "writer_count": context.authority.resolution.writer_count,
                "journal_head": context.events[-1].position if context.events else 0,
                "legacy_read_enabled": context.legacy.enabled,
            }
            bplus_ok = context.authority.resolution.authorizes_journal and context.authority.resolution.writer_count == 1
        except Exception as error:  # noqa: BLE001
            bplus_ok = False
            authority = {"error": f"{type(error).__name__}: {error}"}
    sqlite_status = "disabled_and_absent" if policy.fully_disabled and not unexpected_sqlite else (
        "disabled_unexpected_legacy_artifact" if policy.fully_disabled else ("ok" if db_ok else "missing")
    )
    extension_manager = ExtensionManager(SITINA_HOME)
    extension_ok = True
    try:
        active_plugins = extension_manager.active_plugins()
        active_skills = extension_manager.skills()
        extension_status: dict[str, Any] = {
            "status": "ok",
            "scope": "global",
            "root": str(extension_manager.root),
            "active_plugin_count": len(active_plugins),
            "active_skill_count": len(active_skills),
        }
    except Exception as error:  # noqa: BLE001
        extension_ok = False
        extension_status = {
            "status": "invalid",
            "scope": "global",
            "root": str(extension_manager.root),
            "error": f"{type(error).__name__}: {error}",
        }
    out = {
        "status": "ok" if result["ok"] and bplus_ok and extension_ok and legacy_storage_ok and provider_security_ok else "requires_user_action",
        "config": result,
        "provider_secret_audit": provider_secret_audit,
        "provider_storage_exception": provider_storage_exception,
        "sqlite": sqlite_status,
        "unexpected_legacy_sqlite_artifacts": [path.name for path in unexpected_sqlite],
        "storage_authority": authority,
        "legacy_enabled": policy.legacy_enabled,
        "legacy_read_enabled": policy.read_enabled,
        "legacy_fallback_enabled": policy.fallback_enabled,
        "legacy_write_enabled": policy.write_enabled,
        "active_business_jsonl_enabled": policy.active_business_jsonl_enabled,
        "missing_legacy_is_valid": policy.missing_legacy_is_valid,
        "shell_entry": "ok" if (SITINA_HOME / "bin" / "sitina").exists() else "missing",
        "extensions": extension_status,
        "fix_mode": bool(args.fix),
    }
    print_json(out)
    return 0 if out["status"] == "ok" else 2


def _stable_projection_overlay(context: Any):
    from sitina.projections.generations import ProjectionGenerationError, ProjectionGenerationReader
    from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers

    report = context.authority.fast_start_report
    if report is None:
        raise ProjectionGenerationError("stable Projection diagnostics require an Authority Checkpoint")
    return ProjectionGenerationReader(SITINA_HOME / "projections").select_with_tail(
        authority_checkpoint_commitments=(report.checkpoint_commitment,),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
        current_journal_frontier=int(report.authority_state.head_position),
        tail_events=report.active_tail_events,
        handlers=production_handlers(),
    )


def cmd_storage_diagnostics(args: argparse.Namespace) -> int:
    if args.storage_cmd == "archive-plan":
        from sitina.archive.legacy_plan import LegacyArchivePlanError, LegacyArchivePlanner

        policy = LegacyRuntimePolicy.load(SITINA_HOME)
        sources = [Path(item) for item in args.source]
        if not sources and policy.retired_root:
            sources = [Path(policy.retired_root)]
        if not sources and (SITINA_HOME / "legacy-retired").is_dir():
            sources = [SITINA_HOME / "legacy-retired"]
        if not sources:
            print_json({"status": "not_available", "dry_run": True, "reason": "no Legacy retired root is configured", "source_deleted": False})
            return 2
        try:
            plan = LegacyArchivePlanner().plan(sources, cold_archive_target=args.target)
        except (OSError, LegacyArchivePlanError) as error:
            print_json({"status": "blocked", "dry_run": True, "reason": str(error), "source_deleted": False})
            return 3
        print_json({"status": "ok", **plan})
        return 0

    if args.storage_cmd == "migration-plan":
        policy = LegacyRuntimePolicy.load(SITINA_HOME)
        print_json(
            {
                "status": "ok",
                "schema": "SITINA_STORAGE_MIGRATION_PLAN_V1",
                "dry_run": True,
                "canonical_authority": "Journal",
                "canonical_content_store": "CAS",
                "legacy_source": policy.retired_root,
                "legacy_enabled": policy.legacy_enabled,
                "planned_steps": ["INVENTORY", "DUAL_READ_VERIFY", "ISOLATED_REPLAY", "SEPARATE_USER_AUTHORIZATION"],
                "migration_executed": False,
                "files_modified": 0,
                "objects_deleted": 0,
            }
        )
        return 0

    if args.storage_cmd == "inspect":
        from sitina.diagnostics.storage_metrics import StorageMetricsCollector, StorageMetricsError

        frontier = 0
        report = None
        memory_events: tuple[object, ...] = ()
        if _bplus_installed():
            context = _bplus_context()
            report = context.authority.fast_start_report
            frontier = int(report.authority_state.head_position) if report is not None else (context.events[-1].position if context.events else 0)
            memory_events = tuple(event for event in context.events if event.event_type.startswith("memory."))
        try:
            snapshot = StorageMetricsCollector(SITINA_HOME).collect(
                startup_duration_ms=0,
                journal_frontier=frontier,
                fast_start_report=report,
                memory_events=memory_events,
            )
        except StorageMetricsError as error:
            print_json({"status": "blocked", "read_only": True, "reason": str(error)})
            return 3
        print_json({"status": "ok", **snapshot})
        return 0

    if args.storage_cmd == "gc":
        if not args.dry_run:
            print_json({"status": "blocked", "reason": "storage gc requires --dry-run", "physical_delete_executed": False})
            return 3
        if not _bplus_installed():
            print_json({"status": "not_available", "dry_run": True, "physical_delete_executed": False, "reason": "B+ authority is not installed"})
            return 2
        from types import SimpleNamespace
        from sitina.cas.gc import SemanticGCDryRunPlanner, SemanticRootIndex
        from sitina.journal.fast_start import FullJournalVerifier
        from sitina.journal.recovery import scan_active_segment_read_only, scan_sealed_segment
        from sitina.security.key_provider import JournalAuthProvider
        import time

        context = _bplus_context()
        fast_report = context.authority.fast_start_report
        historical_references: tuple[str, ...]
        if fast_report is not None and fast_report.active_roots_snapshot:
            roots = SemanticRootIndex.from_fast_start(fast_report)
            verified_reader = context.open_verified_journal_reader()
            try:
                historical_references = tuple(
                    reference
                    for event in verified_reader.iter_events(0)
                    for reference in event.object_refs
                )
            finally:
                verified_reader.close()
        else:
            if fast_report is not None:
                FullJournalVerifier(
                    SITINA_HOME,
                    journal_authenticator=JournalAuthProvider(context.provider),
                    authority_key_provider=context.provider,
                ).verify()
            events = tuple(
                event
                for path in sorted((SITINA_HOME / "journal/sealed").glob("*.seg"))
                for frame in scan_sealed_segment(path).frames
                for event in frame.transaction.events
            ) + tuple(
                event
                for frame in scan_active_segment_read_only(SITINA_HOME / "journal/active.seg").frames
                for event in frame.transaction.events
            )
            roots = SemanticRootIndex()
            roots.apply_tail(events)
            historical_references = tuple(reference for event in events for reference in event.object_refs)
        plan = SemanticGCDryRunPlanner(SimpleNamespace(root=SITINA_HOME / "cas")).plan(
            roots,
            historical_references=historical_references,
            now_epoch_seconds=int(time.time()),
            grace_seconds=args.grace_seconds,
        )
        print_json({"status": "ok", **plan})
        return 0
    raise SystemExit("unknown storage diagnostics command")


def cmd_journal_diagnostics(args: argparse.Namespace) -> int:
    if not _bplus_installed():
        print_json({"status": "not_available", "read_only": True, "reason": "B+ authority is not installed"})
        return 2
    context = _bplus_context()
    report = context.authority.fast_start_report
    if args.journal_cmd == "startup-report":
        value = {
            "status": "ok",
            "schema": "SITINA_JOURNAL_STARTUP_REPORT_V1",
            "read_only": True,
            "read_mode": context.authority.read_mode,
            "journal_bytes_scanned": context.authority.journal_bytes_scanned,
            "fast_start_checkpoint_used": report is not None,
            "journal_events_verified": report.journal_events_verified if report is not None else len(context.events),
            "active_tail_event_count": report.active_tail_event_count if report is not None else len(context.events),
            "sealed_segment_count": report.sealed_segment_count if report is not None else len(tuple((SITINA_HOME / "journal/sealed").glob("*.seg"))),
            "authority_head_position": report.authority_state.head_position if report is not None else (context.events[-1].position if context.events else 0),
        }
        print_json(value)
        return 0
    if args.journal_cmd in {"verify", "scrub"}:
        if args.journal_cmd == "verify" and not args.full:
            print_json({"status": "blocked", "reason": "journal verify requires --full", "read_only": True})
            return 3
        if args.journal_cmd == "scrub" and not args.background:
            print_json({"status": "blocked", "reason": "journal scrub requires --background", "read_only": True})
            return 3
        from sitina.journal.fast_start import FullJournalVerifier
        from sitina.security.key_provider import JournalAuthProvider

        if report is not None:
            verified = FullJournalVerifier(
                SITINA_HOME,
                journal_authenticator=JournalAuthProvider(context.provider),
                authority_key_provider=context.provider,
            ).verify()
            bytes_scanned = verified.journal_bytes_scanned
            events_verified = verified.journal_events_verified
            sealed_count = verified.sealed_segment_count
            head_position = verified.authority_state.head_position
            checkpoint_commitment = verified.checkpoint_commitment
        else:
            bytes_scanned = context.authority.journal_bytes_scanned
            events_verified = len(context.events)
            sealed_count = len(tuple((SITINA_HOME / "journal/sealed").glob("*.seg")))
            head_position = context.events[-1].position if context.events else 0
            checkpoint_commitment = None
        print_json(
            {
                "status": "verified",
                "schema": "SITINA_FULL_JOURNAL_VERIFY_REPORT_V1",
                "read_only": True,
                "background_requested": args.journal_cmd == "scrub",
                "physical_mutations": 0,
                "journal_bytes_scanned": bytes_scanned,
                "journal_events_verified": events_verified,
                "sealed_segment_count": sealed_count,
                "head_position": head_position,
                "checkpoint_commitment": checkpoint_commitment,
            }
        )
        return 0
    raise SystemExit("unknown journal diagnostics command")


def cmd_projection_diagnostics(args: argparse.Namespace) -> int:
    if not _bplus_installed():
        print_json({"status": "not_available", "read_only": True, "reason": "B+ authority is not installed"})
        return 2
    try:
        applied = _stable_projection_overlay(_bplus_context())
    except Exception as error:  # fail closed at the query boundary
        print_json({"status": "degraded", "read_only": True, "reason": str(error), "fallback_used": False})
        return 3
    try:
        if args.projection_cmd == "report":
            row = applied.connection.execute(
                "SELECT last_position,state FROM projection_offsets WHERE projection_name='kernel'"
            ).fetchone()
            result = {
                "status": "ok",
                "schema": "SITINA_PROJECTION_REPORT_V1",
                "read_only": True,
                "base_generation": applied.selected.pointer,
                "used_previous": applied.selected.used_previous,
                "applied_through": applied.applied_through,
                "projection_state": row[1],
                "fallback_used": False,
            }
        elif args.projection_cmd == "coverage":
            rows = applied.connection.execute(
                "SELECT schema_id,requirement,handler_id,coverage_state FROM projection_schema_coverage ORDER BY schema_id"
            ).fetchall()
            result = {
                "status": "ok",
                "schema": "SITINA_PROJECTION_COVERAGE_REPORT_V1",
                "read_only": True,
                "entries": [
                    {"schema_id": row[0], "requirement": row[1], "handler_id": row[2], "coverage_state": row[3]}
                    for row in rows
                ],
                "missing_required_count": sum(1 for row in rows if row[3] == "MISSING_REQUIRED"),
            }
        else:
            raise SystemExit("unknown projection diagnostics command")
    finally:
        applied.close()
    print_json(result)
    return 0 if result.get("missing_required_count", 0) == 0 else 3


def cmd_runtime_diagnostics(args: argparse.Namespace) -> int:
    if args.runtime_cmd != "compatibility":
        raise SystemExit("unknown runtime diagnostics command")
    from sitina.diagnostics.runtime_compatibility import runtime_compatibility_report

    print_json({"status": "ok", **runtime_compatibility_report(SITINA_HOME, now=iso_now())})
    return 0


def cmd_loop_state(args: argparse.Namespace) -> int:
    """Development-only batch-1a control plane for the persistent loop skeleton."""

    from sitina.loop import LoopBackend, SPEC_VERSION
    from sitina.loop.control import LoopAuthorityError, LoopAuthorityLease, send_control_request

    state_root = Path(args.state_root).expanduser().resolve(strict=False)
    if (SITINA_HOME / ".sitina-r4-development-root-v1.json").is_file():
        from sitina.loop.development import DevelopmentBoundary, DevelopmentBoundaryError

        diagnostic_workspace = SITINA_HOME / "runtime/r4-loop-dev/workspaces/loop-state-diagnostic"
        try:
            DevelopmentBoundary.validate(
                state_root=state_root,
                business_workspace=diagnostic_workspace,
            )
        except DevelopmentBoundaryError as error:
            print_json({
                "schema": "SITINA_LOOP_STATE_COMMAND_V1",
                "spec_version": SPEC_VERSION,
                "state_root": str(state_root),
                "status": "blocked",
                "reason": str(error),
                "state_root_created": False,
                "new_coordinator_opened": False,
            })
            return 3
    try:
        lease = LoopAuthorityLease(state_root).acquire()
    except LoopAuthorityError:
        if args.loop_state_cmd == "status" and not args.dock_restart:
            try:
                response = send_control_request(state_root, {"command": "status", "task_id": args.task_id})
            except LoopAuthorityError:
                pass
            else:
                print_json({
                    "schema": "SITINA_LOOP_STATE_COMMAND_V1",
                    "spec_version": SPEC_VERSION,
                    "state_root": str(state_root),
                    "status": "ok",
                    "routed_to_live_authority": True,
                    "task": response["task"],
                })
                return 0
        print_json({
            "schema": "SITINA_LOOP_STATE_COMMAND_V1",
            "spec_version": SPEC_VERSION,
            "state_root": str(state_root),
            "status": "blocked",
            "reason": "a live Loop authority owns this state root",
            "new_coordinator_opened": False,
        })
        return 3
    try:
        with LoopBackend.open(state_root) as backend:
            common = {
                "schema": "SITINA_LOOP_STATE_COMMAND_V1",
                "spec_version": SPEC_VERSION,
                "state_root": str(state_root),
                "run_instance_id": backend.run_instance_id,
                "key_readback": backend.context.key_readback.as_dict(),
                "production_cutover": False,
                "full_recovery_connected": False,
            }
            if args.loop_state_cmd == "initialize":
                print_json({**common, "status": "initialized", "task_ids": list(backend.task_ids())})
                return 0
            if args.loop_state_cmd == "create":
                outcomes = tuple(sorted(set(args.required_outcome)))
                task = backend.create_task(
                    task_id=args.task_id,
                    session_id=args.session_id,
                    task_kind=args.task_kind,
                    goal=args.goal,
                    required_outcome_ids=outcomes,
                    artifact_ref=args.artifact_ref,
                    environment_ref=args.environment_ref,
                    capability_snapshot_id=args.capability_snapshot_id,
                )
                print_json({**common, "status": "task_created", "task": task.as_dict()})
                return 0
            if args.loop_state_cmd == "status":
                task = backend.dock_after_restart(args.task_id) if args.dock_restart else backend.get_task(args.task_id)
                print_json({**common, "status": "ok", "task": task.as_dict()})
                return 0
    finally:
        lease.close()
    raise SystemExit("unknown loop-state command")


_LOOP_HOST_DRAIN_TIMEOUT_SECONDS = 30.0
_LOOP_HOST_GRACEFUL_EXIT_CODES = frozenset({0, 130})


def _owned_loop_host_exit_failure(returncode: int | None) -> str | None:
    if returncode in _LOOP_HOST_GRACEFUL_EXIT_CODES:
        return None
    if returncode is None:
        return "owned Host exit could not be confirmed"
    return f"owned Host exited without a graceful drain (return code {returncode})"


def _drain_owned_loop_host_processes(
    processes: list[subprocess.Popen[Any]],
    *,
    timeout: float = _LOOP_HOST_DRAIN_TIMEOUT_SECONDS,
) -> tuple[str, ...]:
    """Gracefully stop only Host processes created by this controller."""

    failures: list[str] = []
    seen: set[int] = set()
    for process in reversed(processes):
        identity = id(process)
        if identity in seen:
            continue
        seen.add(identity)
        returncode = process.poll()
        if returncode is None:
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
            except OSError as error:
                failures.append(f"could not request owned Host drain: {error}")
                continue
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                failures.append(
                    "owned Host is still draining; no force termination was attempted"
                )
                continue
            except OSError as error:
                failures.append(f"could not confirm owned Host exit: {error}")
                continue
        failure = _owned_loop_host_exit_failure(returncode)
        if failure is not None:
            failures.append(failure)
    return tuple(failures)


def _submit_loop_task(
    boundary: Any,
    submit_payload: Mapping[str, Any],
    *,
    provider_profile: str,
    approve_writes: bool,
    owned_host_processes: list[subprocess.Popen[Any]] | None = None,
) -> Mapping[str, Any]:
    """Submit through the sole Loop host, starting that same host if absent."""

    from sitina.loop.control import LoopAuthorityError, send_control_request
    from sitina.loop.development import (
        boundary_interpreter_entry,
        runtime_subprocess_environment,
    )

    try:
        return send_control_request(boundary.state_root, submit_payload)
    except LoopAuthorityError as first_error:
        try:
            environment = runtime_subprocess_environment(boundary)
            host_process = subprocess.Popen(
                [
                    str(boundary_interpreter_entry(boundary)),
                    "-B",
                    "-m",
                    "sitina.cli",
                    "loop-host",
                    "serve",
                    "--state-root",
                    str(boundary.state_root),
                    "--workspace",
                    str(boundary.business_workspace),
                    "--provider-profile",
                    provider_profile,
                    *(["--approve-writes"] if approve_writes else []),
                ],
                cwd=str(boundary.source_root),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                # Startup failures must remain visible on the controller's
                # real stderr.  Do not use an unread PIPE here: a noisy child
                # could otherwise block before the authority becomes live.
                stderr=None,
                start_new_session=True,
            )
            if owned_host_processes is not None:
                owned_host_processes.append(host_process)
            deadline = time.monotonic() + 8.0
            while True:
                try:
                    return send_control_request(boundary.state_root, submit_payload)
                except LoopAuthorityError:
                    returncode = host_process.poll()
                    if returncode is not None:
                        # Keep the terminal child in the owned set so the
                        # session's final drain preserves its abnormal exit.
                        # The missing authority means submission was not
                        # confirmed; it does not prove the Host performed no
                        # durable action before exiting.
                        raise LoopAuthorityError(
                            "Loop Host exited during startup "
                            f"(return code {returncode}); task submission was not confirmed"
                        ) from first_error
                    if time.monotonic() >= deadline:
                        raise first_error
                    time.sleep(0.05)
        except (OSError, LoopAuthorityError):
            raise


def _run_loop_session(
    args: argparse.Namespace,
    owned_host_processes: list[subprocess.Popen[Any]],
) -> int:
    """AUTO-only controller with read-only attachment to existing Loop tasks."""

    from sitina.conversation.context import ConversationContextSnapshot
    from sitina.conversation.models import ChatMode
    from sitina.conversation.router import ConversationRouter, ConversationRouterError
    from sitina.loop.control import LoopAuthorityError, send_control_request
    from sitina.loop.development import DevelopmentBoundaryError, validate_runtime_boundary
    from sitina.loop.status_reader import StatusReadUnavailable, read_task_status

    try:
        boundary = validate_runtime_boundary(
            state_root=args.state_root,
            business_workspace=args.workspace,
        )
        router = ConversationRouter.load(boundary.source_root)
    except (DevelopmentBoundaryError, ConversationRouterError, OSError, ValueError) as error:
        print(f"Sitina Loop is unavailable: {error}", file=sys.stderr)
        return 3

    print("Sitina Loop — AUTO routing is always on. Type /help for commands.")
    last_route: Mapping[str, Any] | None = None
    empty_context = ConversationContextSnapshot(
        transcript="",
        turn_count=0,
        char_count=0,
        context_hash=hashlib.sha256(b"").hexdigest(),
        token_count=0,
    )
    while True:
        try:
            message = input("sitina> ").strip()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 130
        if not message:
            continue
        command = message.casefold()
        if command in {"/exit", "/quit"}:
            return 0
        if command == "/help":
            print("/mode  show the latest automatic route")
            print("/attach TASK_ID  watch an existing task without starting or resuming it")
            print("/exit  leave Sitina Loop")
            print("Routing is automatic; manual route selection is unavailable.")
            continue
        if command == "/mode":
            if last_route is None:
                print("AUTO · no task has been routed yet.")
            else:
                reasons = "；".join(str(item) for item in last_route["reasons"])
                print(f"AUTO · {last_route['strategy']} · {reasons}")
            continue
        if command in {"/fast", "/multi", "/auto"}:
            print("Routing is always automatic; manual route commands do not change it.")
            continue

        parts = message.split(maxsplit=1)
        attaching = parts[0].casefold() == "/attach"
        if attaching:
            if len(parts) != 2 or not parts[1].strip():
                print("Usage: /attach TASK_ID")
                continue
            task_id = parts[1].strip()
        else:
            if message.startswith("/"):
                print("Unknown command. Type /help for available commands.")
                continue
            try:
                decision = router.decide(ChatMode.AUTO, message, empty_context)
            except (ConversationRouterError, ValueError) as error:
                print(f"Automatic routing failed closed: {error}", file=sys.stderr)
                continue
            reviewed = decision.resolved_mode is ChatMode.MULTI
            task_kind = "reviewed_readonly" if reviewed else "readonly"
            strategy = "main Agent + independent reviewer" if reviewed else "single main Agent"
            last_route = {"strategy": strategy, "reasons": decision.reasons}
            print(f"AUTO · {strategy}")
            task_id = "loop-" + secrets.token_hex(12)
            submit_payload = {
                "command": "submit",
                "task_id": task_id,
                "submission_id": task_id,
                "task_kind": task_kind,
                "goal": message,
                "workspace": str(boundary.business_workspace),
                "check_command": [],
                "provider_profile": args.provider_profile,
                "reviewer_request_timeout_seconds": RoleProfileResolver(boundary.config_root.parent).provider_config().get("reviewer_request_timeout_seconds"),
                "approve_writes": False,
                "authorization": "cli",
                "provider_identity": None,
                "environment_ref": None,
                "capability_snapshot_id": None,
                "software_identity": None,
                "config_identity": None,
                "capability_selection": "",
            }
            try:
                submitted = _submit_loop_task(
                    boundary,
                    submit_payload,
                    provider_profile=args.provider_profile,
                    approve_writes=False,
                    owned_host_processes=owned_host_processes,
                )
            except (OSError, LoopAuthorityError) as error:
                print(f"Loop submission failed closed: {error}", file=sys.stderr)
                continue
            if submitted.get("status") != "accepted":
                print(
                    f"Loop submission was not accepted: {submitted.get('reason') or submitted.get('status')}",
                    file=sys.stderr,
                )
                continue

        previous_display: str | None = None
        first_read = True
        while True:
            read_source = "live authority"
            try:
                status_response = send_control_request(
                    boundary.state_root,
                    {"command": "attach" if attaching and first_read else "status", "task_id": task_id},
                )
            except LoopAuthorityError:
                read_source = "read-only Journal"
                try:
                    status_response = read_task_status(boundary.state_root, task_id)
                except KeyError:
                    print(f"Task {task_id} was not found in the authenticated Journal.", file=sys.stderr)
                    break
                except (StatusReadUnavailable, OSError, ValueError) as error:
                    print(f"Loop status is unavailable: {error}", file=sys.stderr)
                    break
            first_read = False
            if status_response.get("status") != "ok":
                detail = status_response.get("reason") or status_response.get("status")
                print(f"Loop status is unavailable for {task_id}: {detail}", file=sys.stderr)
                break
            task = status_response.get("task")
            if not isinstance(task, Mapping) or task.get("task_id") != task_id:
                print("Loop returned an invalid task identity.", file=sys.stderr)
                break
            status = task.get("status")
            revision = task.get("task_revision")
            waiting = task.get("waiting_reason")
            active = task.get("active_operation_ids")
            terminal = task.get("terminal_result")
            if (
                not isinstance(status, str) or not status
                or type(revision) is not int
                or (waiting is not None and not isinstance(waiting, Mapping))
                or not isinstance(active, (list, tuple))
                or any(not isinstance(item, str) for item in active)
                or (terminal is not None and not isinstance(terminal, Mapping))
            ):
                print("Loop returned an invalid task status.", file=sys.stderr)
                break
            final_status = terminal.get("terminal_status") if terminal is not None else None
            final_result = terminal.get("final_result") if terminal is not None else None
            response = (
                str(final_result.get("response") or "")
                if isinstance(final_result, Mapping)
                else ""
            )
            waiting_text = json.dumps(dict(waiting or {}), ensure_ascii=False, sort_keys=True)
            active_text = json.dumps(list(active), ensure_ascii=False)
            display = json.dumps(
                [task_id, revision, read_source, status, waiting_text, active_text, final_status, response],
                ensure_ascii=False,
            )
            if display != previous_display:
                print(f"Task: {json.dumps(task_id, ensure_ascii=False)}")
                print(f"Revision: {revision}")
                print(f"Source: {read_source}")
                print(f"Phase: {status}")
                print(f"Waiting reason: {waiting_text}")
                print(f"Active operations: {active_text}")
                print(f"Final status: {json.dumps(final_status, ensure_ascii=False)}")
                if response:
                    print(response)
                previous_display = display
            if read_source == "read-only Journal":
                break
            if status in {
                "SUCCEEDED", "FAILED", "CANCELLED", "WAITING_INPUT", "STALLED",
                "RECOVERY_BLOCKED", "CONTEXT_BLOCKED", "PAUSED",
            }:
                break
            time.sleep(0.1)


def cmd_loop(args: argparse.Namespace) -> int:
    """Run one AUTO-only session and close only the Host it created."""

    owned_host_processes: list[subprocess.Popen[Any]] = []
    exit_code = 0
    shutdown_failures: tuple[str, ...] = ()
    try:
        exit_code = _run_loop_session(args, owned_host_processes)
    except KeyboardInterrupt:
        print()
        exit_code = 130
    finally:
        shutdown_failures = _drain_owned_loop_host_processes(owned_host_processes)
    if shutdown_failures:
        print(
            "Sitina Loop exit is incomplete: " + "; ".join(shutdown_failures),
            file=sys.stderr,
        )
        return 3
    return exit_code


def cmd_loop_task(args: argparse.Namespace) -> int:
    """Guarded batch-1b command surface for one executable Loop authority."""

    from sitina.loop.control import LoopAuthorityError, send_control_request
    from sitina.loop.development import validate_runtime_boundary
    from sitina.loop.status_reader import StatusReadUnavailable, read_task_status

    boundary = validate_runtime_boundary(
        state_root=args.state_root,
        business_workspace=args.workspace,
    )
    common = {
        "schema": "SITINA_LOOP_TASK_COMMAND_V1",
        "boundary": boundary.as_dict(),
        "production_cutover": False,
    }
    if args.loop_task_cmd == "boundary":
        print_json({**common, "status": "ok"})
        return 0
    if args.loop_task_cmd == "retention":
        payload = {
            "command": "retention", "task_id": args.task_id,
            "action": args.action, "operation_id": args.operation_id,
        }
        if args.memory_id is not None:
            payload["memory_id"] = args.memory_id
        if args.action == "schedule":
            payload["approval_seconds"] = args.approval_seconds
        response = send_control_request(boundary.state_root, payload)
        print_json({**common, **response, "routed_to_live_authority": True})
        state = response.get("retention", {}).get("state")
        return 0 if response.get("status") == "ok" and state != "UNKNOWN" else 3
    if args.loop_task_cmd == "input":
        response = send_control_request(boundary.state_root, {
            "command": "input",
            "task_id": args.task_id,
            "input_id": args.input_id or ("input-" + secrets.token_hex(12)),
            "kind": args.kind,
            "body": args.body,
        })
        print_json({**common, **response, "routed_to_live_authority": True})
        return 0 if response.get("status") == "accepted" else 3
    if args.loop_task_cmd == "status":
        try:
            response = send_control_request(
                boundary.state_root,
                {"command": "status", "task_id": args.task_id},
            )
            print_json({**common, **response, "routed_to_live_authority": True})
            return 0
        except LoopAuthorityError:
            try:
                response = read_task_status(boundary.state_root, args.task_id)
            except KeyError:
                print_json({
                    **common,
                    "status": "not_found",
                    "reason": "task is absent from the authenticated read-only state snapshot",
                    "new_coordinator_opened": False,
                })
                return 3
            except StatusReadUnavailable as error:
                print_json({
                    **common,
                    "status": "unavailable",
                    "reason": str(error),
                    "new_coordinator_opened": False,
                })
                return 3
            print_json({**common, **response})
            return 0
    if args.loop_task_cmd == "attach":
        try:
            response = send_control_request(
                boundary.state_root,
                {"command": "attach", "task_id": args.task_id},
            )
        except LoopAuthorityError as error:
            try:
                response = read_task_status(boundary.state_root, args.task_id)
            except (KeyError, StatusReadUnavailable):
                print_json({**common, "status": "unavailable", "reason": str(error), "read_only": True})
                return 3
            print_json({**common, **response, "read_only": True, "routed_to_live_authority": False})
            return 0
        print_json({**common, **response, "read_only": True})
        return 0 if response.get("status") == "ok" else 3
    if args.loop_task_cmd == "resume":
        try:
            response = send_control_request(
                boundary.state_root,
                {
                    "command": "resume",
                    "task_id": args.task_id,
                    "resume_request_id": args.resume_request_id or ("resume-" + secrets.token_hex(12)),
                },
            )
        except LoopAuthorityError as error:
            print_json({**common, "status": "unavailable", "reason": str(error)})
            return 3
        print_json({**common, **response})
        return 0 if response.get("status") == "accepted" else 3
    if args.loop_task_cmd == "run":
        try:
            parsed = json.loads(args.check_command_json) if args.check_command_json else []
        except json.JSONDecodeError as error:
            raise SystemExit(f"--check-command-json is invalid JSON: {error}") from error
        if not isinstance(parsed, list) or any(not isinstance(item, str) or not item for item in parsed):
            raise SystemExit("--check-command-json must be a JSON array of non-empty strings")
        submit_payload = {
                "command": "submit",
                "task_id": args.task_id,
                "submission_id": args.submission_id,
                "task_kind": args.task_kind,
                "goal": args.goal,
                "workspace": str(boundary.business_workspace),
                "check_command": parsed,
                "provider_profile": args.provider_profile,
                "reviewer_request_timeout_seconds": RoleProfileResolver(boundary.config_root.parent).provider_config().get("reviewer_request_timeout_seconds"),
                "approve_writes": args.approve_writes,
                "network_read_urls": list(getattr(args, "network_read_urls", ()) or ()),
                "authorization": "cli",
                "provider_identity": args.provider_identity,
                "environment_ref": args.environment_ref,
                "capability_snapshot_id": args.capability_snapshot_id,
                "software_identity": args.software_identity,
                "config_identity": args.config_identity,
                "capability_selection": getattr(args, "capability_selection", "") or "",
        }
        try:
            result = _submit_loop_task(
                boundary,
                submit_payload,
                provider_profile=args.provider_profile,
                approve_writes=args.approve_writes,
            )
        except (OSError, LoopAuthorityError) as error:
            print_json({**common, "status": "unavailable", "reason": str(error), "host_delegated": True})
            return 3
        print_json({**common, **result, "host_delegated": True})
        return 0 if result.get("status") == "accepted" else 3
    raise SystemExit("unknown loop-task command")


def cmd_loop_host(args: argparse.Namespace) -> int:
    """Run the isolated host and delegate admitted work to LoopTaskRunner."""

    from sitina.loop.host import LoopHost, NativeExperienceProviderFactory
    from sitina.loop.child_model import ReadonlyChildModelRunner
    from sitina.loop.development import (
        boundary_environment_prefix,
        boundary_interpreter_entry,
        validate_runtime_boundary,
    )
    from sitina.loop.task_runtime import LoopTaskRunner
    from sitina.extensions.manager import ExtensionManager
    from sitina.extensions.runtime import BoundedToolTurnClient
    from sitina.loop.context_window import ModelCapacityRegistry

    boundary = validate_runtime_boundary(
        state_root=args.state_root,
        business_workspace=args.workspace,
    )

    capacity_path = boundary.config_root / "loop_context_capacity.json"
    try:
        capacity_document = json.loads(capacity_path.read_text(encoding="utf-8"))
        capacity_entry = next(
            item for item in capacity_document.get("entries", ())
            if isinstance(item, Mapping) and item.get("profile") == args.provider_profile
        )
    except (OSError, ValueError, StopIteration) as error:
        raise SystemExit("host provider capacity policy is unavailable for the selected profile") from error
    provider_identity = json.dumps(
        {
            "profile": args.provider_profile,
            "endpoint": capacity_entry.get("endpoint"),
            "model": capacity_entry.get("model"),
            "wire_protocol": capacity_entry.get("wire_protocol"),
            "context_capacity_tokens": capacity_entry.get("context_capacity_tokens"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    def _digest_tree(root: Path) -> str:
        digest = hashlib.sha256()
        if not root.exists():
            raise RuntimeError(f"host identity input is unavailable: {root}")
        if root.is_file():
            digest.update(root.name.encode("utf-8"))
            try:
                digest.update(root.read_bytes())
            except OSError as error:
                raise RuntimeError(f"host identity input is unreadable: {root}") from error
        elif root.is_dir():
            for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or path.suffix in {".pyc", ".pyo"}
                    or "__pycache__" in path.parts
                ):
                    continue
                digest.update(str(path.relative_to(root)).encode("utf-8"))
                try:
                    digest.update(path.read_bytes())
                except OSError as error:
                    raise RuntimeError(f"host identity input is unreadable: {path}") from error
        return digest.hexdigest()

    def _runner_executor(backend, task_id: str, task: Mapping[str, Any]) -> None:
        projection = backend.get_task(task_id)
        descriptor = backend.context_memory.read(
            str(projection.descriptor_ref), expected_hash=str(projection.descriptor_hash)
        )
        descriptor_workspace = str(descriptor.get("workspace", {}).get("path") or "")
        task_boundary = type(boundary).validate(
            state_root=boundary.state_root,
            business_workspace=descriptor_workspace,
            source_root=boundary.source_root,
            interpreter=boundary_interpreter_entry(boundary),
        )
        capability_binding = descriptor.get("capability_binding")
        execution_snapshot = None
        if isinstance(capability_binding, Mapping):
            manager = ExtensionManager(boundary.source_root, global_root=extension_root)
            authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
            execution_snapshot = authority.verify_capability_binding(capability_binding)
        runner_kwargs = {
            "provider_profile": str(descriptor.get("provider_profile") or args.provider_profile),
            "approve_writes": bool((descriptor.get("authorization") or {}).get("approve_writes", False)),
        }
        # Preserve the legacy unselected runner-construction contract.  A
        # selected capability receives the authenticated snapshot explicitly;
        # an unselected task does not get a new keyword with a meaningless
        # None value (older strict test/runtime factories reject it).
        if execution_snapshot is not None:
            runner_kwargs["execution_snapshot"] = execution_snapshot
        if descriptor.get("reviewer_request_timeout_seconds") is not None:
            runner_kwargs["reviewer_request_timeout_seconds"] = descriptor["reviewer_request_timeout_seconds"]
        task_runner = LoopTaskRunner(task_boundary, **runner_kwargs)
        task_runner.run_existing(
            backend,
            task_id=task_id,
            task_kind=projection.task_kind,
            check_command=tuple(str(item) for item in descriptor.get("acceptance", {}).get("check_command", ())),
            baseline_snapshot=(descriptor.get("workspace", {}).get("content_snapshot") or {}),
        )

    def _validate_submission(payload: Mapping[str, Any]) -> None:
        type(boundary).validate(
            state_root=boundary.state_root,
            business_workspace=str(payload.get("workspace") or ""),
            source_root=boundary.source_root,
            interpreter=boundary_interpreter_entry(boundary),
        )

    extension_root = Path(
        os.environ.get("SITINA_EXTENSIONS_HOME") or (boundary.state_root / "extensions")
    ).expanduser().resolve(strict=False)

    # Native experience repositories are reconstructed from this Backend's
    # already-open Journal/CAS/key provider.  No fresh feature activation or
    # per-task store is synthesized; an unactivated memory writer therefore
    # fails closed when the first durable candidate/episode is attempted.
    memory_actor = "loop-memory-reviewer"
    memory_materializer_actor = "loop-memory-materializer"
    project_identity = hashlib.sha256(str(boundary.business_workspace).encode("utf-8")).hexdigest()[:32]
    memory_owner = "project/" + project_identity
    memory_namespace = memory_owner + "/memory"
    memory_acl = MemoryACL(
        readers=tuple(sorted({memory_actor, memory_materializer_actor})),
        writers=(memory_materializer_actor,),
        reviewers=(memory_actor,),
    )
    repository_cache: dict[str, Any] = {}

    def _memory_repository_for_backend(backend):
        cached = repository_cache.get("bundle")
        if cached is None:
            activations = FeatureActivationRegistry.from_journal_events(
                backend.store.journal.iter_events(0)
            )
            memory = MemoryRepository(
                backend.store.journal,
                backend.store.cas,
                backend.context.provider,
                feature_activations=activations,
            )
            episode = EpisodeRepository(
                backend.store.journal,
                backend.store.cas,
                backend.context.provider,
                feature_activations=activations,
            )
            cached = (memory, episode)
            repository_cache["bundle"] = cached
        return cached[0]

    def _episode_repository_for_backend(backend):
        _memory_repository_for_backend(backend)
        return repository_cache["bundle"][1]

    def _select_project_memory(backend, _payload):
        repository = _memory_repository_for_backend(backend)
        return tuple(
            document.memory_id
            for document in repository.retrieve(
                actor=memory_actor,
                owner_id=memory_owner,
                namespace_prefix=memory_namespace,
                tier="episodic",
                include_noncurrent=False,
            )[:8]
        )

    # The formal extraction/review callbacks are lazy: host startup resolves
    # no credential and makes no network request.  On a real dispatch they use
    # the same configured DeepSeek profile/capacity policy as the readonly
    # child runner, wrapped by the bounded tool-turn transport.
    # Experience turns need enough room for a bounded manifest/tool result,
    # while remaining below the selected provider's declared capacity.  This
    # is a fixed ceiling, not an adaptive retry budget.
    experience_output_budget_tokens = 8192

    def _native_experience_factory(request: Mapping[str, Any]):
        child_runner = ReadonlyChildModelRunner.from_boundary(
            boundary,
            args.provider_profile,
            backend=host.backend,
            obligation_id=request["obligation_id"],
            request_id=request["request_id"],
            attempt_count=request["attempt_count"],
            candidate_id=request.get("candidate_id"),
            max_tokens=experience_output_budget_tokens,
            max_turns=1,
        )
        policy = child_runner.capacity_registry.resolve(child_runner.capacity_identity)
        if policy is None:
            raise RuntimeError("selected provider has no exact experience capacity policy")
        experience_max_tokens = min(
            experience_output_budget_tokens,
            int(getattr(policy, "max_output_tokens", experience_output_budget_tokens)),
        )
        if experience_max_tokens < 1:
            raise RuntimeError("selected provider has no usable bounded experience output budget")
        bounded_client = child_runner.client
        if not isinstance(bounded_client, BoundedToolTurnClient):
            raise RuntimeError("selected provider is not using the bounded tool-turn transport")
        # The readonly child transport has its own retry policy.  Experience
        # obligations cannot inherit it: an uncertain physical result must
        # stop at one logical send and remain UNKNOWN for reconciliation.
        bounded_client = BoundedToolTurnClient(
            bounded_client.client,
            child_runner.profile,
            run_id="experience-" + request["request_id"],
            retry_limit=0,
            fallback_allowed=False,
        )
        factory = NativeExperienceProviderFactory.from_anthropic_profile(
            bounded_client,
            child_runner.profile,
            policy,
            capacity_registry=child_runner.capacity_registry,
            capacity_identity=child_runner.capacity_identity,
            max_tokens=experience_max_tokens,
            timeout_seconds=540.0,
        )
        return factory

    def _experience_dispatch(request):
        return _native_experience_factory(request)(request)

    def _review_dispatch(request):
        return _native_experience_factory(request)(request)

    def _resolve_capability(backend, capability_slot: str) -> Mapping[str, Any]:
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        resolution = authority.resolve_default(capability_slot)
        projection_ref = str(resolution.get("projection_ref") or "")
        projection_hash = str(resolution.get("projection_hash") or "")
        if not projection_ref or not projection_hash:
            raise LoopAuthorityError("capability default lacks a durable resolution projection")
        proof = backend.extension_existing_object_proof(projection_ref)
        proof_view = {
            "schema": "SITINA_EXISTING_DURABLE_OBJECT_ROOT_PROOF_V1",
            "object_ref": proof.object_ref.reference_id,
            "journal_id": proof.journal_id,
            "rooted_transaction_hash": proof.rooted_transaction_hash,
            "rooted_position": proof.rooted_position,
            "verified_frontier_position": proof.verified_frontier_position,
            "verified_frontier_transaction_hash": str(
                backend.store.journal._position_hash.get(proof.verified_frontier_position) or ""
            ),
            "object_reference_manifest_hash": proof.object_reference_manifest_hash,
        }
        if not proof_view["verified_frontier_transaction_hash"]:
            raise LoopAuthorityError("capability default lacks a canonical Journal frontier commitment")
        return {
            "schema": "SITINA_LOOP_CAPABILITY_BINDING_V1",
            "slot_id": str(resolution["slot"]["slot_id"]),
            "publication_id": str(resolution["publication_id"]),
            "candidate_id": str(resolution["candidate_id"]),
            "snapshot_id": str(resolution["snapshot_id"]),
            "snapshot_hash": str(resolution["snapshot_hash"]),
            "location_binding": str(resolution["location_binding"]),
            "resolution_stream_id": str(resolution["stream_id"]),
            "read_position": dict(resolution["read_position"]),
            "resolution_ref": projection_ref,
            "resolution_hash": projection_hash,
            "resolution_cas_proof": proof_view,
        }

    resource_path = Path(args.resource_policy).expanduser().resolve(strict=True) if getattr(args, "resource_policy", None) else boundary.config_root / "orchestration_policy.json"
    observability_path = Path(args.observability_policy).expanduser().resolve(strict=True) if getattr(args, "observability_policy", None) else boundary.config_root / "observability_policy.json"
    policy_bytes = []
    for policy_path in (resource_path, observability_path):
        with policy_path.open("rb") as policy_file:
            policy_bytes.append(policy_file.read(65537))
    if any(len(raw) > 65536 for raw in policy_bytes):
        raise SystemExit("host resource or observability policy exceeds its input bound")
    resource_policy = json.loads(policy_bytes[0].decode("utf-8"))
    observability_policy = json.loads(policy_bytes[1].decode("utf-8"))
    if (not isinstance(resource_policy, Mapping) or not isinstance(resource_policy.get("resource_limits"), Mapping)
            or not isinstance(observability_policy, Mapping)):
        raise SystemExit("host resource and observability policies must contain the existing policy mappings")
    resource_identity = {
        "resource_policy": {"path": str(resource_path), "sha256": hashlib.sha256(policy_bytes[0]).hexdigest()},
        "observability_policy": {"path": str(observability_path), "sha256": hashlib.sha256(policy_bytes[1]).hexdigest()},
    }
    effective_policy_digest = hashlib.sha256(json.dumps(resource_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    environment_identity = {
        "source_root": str(boundary.source_root),
        "state_root": str(boundary.state_root),
        "runtime_root": str(boundary.runtime_root),
        "interpreter": str(boundary.interpreter),
        "config_root": str(boundary.config_root),
        "extension_root": str(extension_root),
        "resource_policy_identity": resource_identity,
    }
    host_descriptor_context = {
        "provider_identity": provider_identity,
        "environment_ref": boundary_environment_prefix(boundary) + ":" + hashlib.sha256(
            json.dumps(environment_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "capability_snapshot_id": f"loop-cli-capabilities:{_digest_tree(boundary.config_root)}",
        "software_identity": f"source:{_digest_tree(boundary.source_root / 'core' / 'sitina')}",
        "config_identity": f"config:{_digest_tree(boundary.config_root)}:resources:{effective_policy_digest}",
    }

    def _validate_recovery_descriptor(descriptor: Mapping[str, Any]) -> None:
        descriptor_workspace = str(descriptor.get("workspace", {}).get("path") or "")
        type(boundary).validate(
            state_root=boundary.state_root,
            business_workspace=descriptor_workspace,
            source_root=boundary.source_root,
            interpreter=boundary_interpreter_entry(boundary),
        )
        for key in ("provider_identity", "environment_ref", "capability_snapshot_id", "software_identity", "config_identity"):
            if key == "capability_snapshot_id" and isinstance(descriptor.get("capability_binding"), Mapping):
                binding = descriptor["capability_binding"]
                if descriptor.get(key) != binding.get("snapshot_id"):
                    raise ValueError("task descriptor capability snapshot differs from its binding")
                continue
            if descriptor.get(key) != host_descriptor_context[key]:
                raise ValueError(f"task descriptor {key} is incompatible with this host")

    def _recover_publication_checks(backend) -> None:
        """Reconcile only existing consumer evidence during Host startup.

        An explicit extension root is taken over only when its r4 authority
        binding already exists.  Empty/legacy roots are not migrated and no
        default or consumer task is created merely because the host starts.
        """

        binding_path = extension_root / ".sitina-extension-authority-v1.json"
        if not binding_path.is_file():
            return
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        for task_id in backend.task_ids():
            try:
                backend.record_extension_publication_check_from_task(task_id)
            except Exception as error:
                # C3a leaves missing/mismatched/failed evidence PENDING for
                # C3b; startup must not dispatch a replacement consumer.  Do
                # not hide an integrity/persistence failure: expose it on the
                # existing Host health surface while continuing other tasks.
                backend._publication_check_recovery_errors.append(
                    f"publication-check:{type(error).__name__}: {error}"
                )
            try:
                backend.record_extension_publication_failure_from_task(task_id)
            except Exception as error:
                # Failure reconstruction is independent of the C3a success
                # check.  A check validation error must not prevent a real
                # failed-consumer source from being classified on restart.
                backend._publication_check_recovery_errors.append(
                    f"publication-failure:{type(error).__name__}: {error}"
                )

    host_kwargs: dict[str, Any] = {
        "resource_limits": resource_policy["resource_limits"],
        "observability_policy": observability_policy,
        "runner_executor": _runner_executor,
        "admission_validator": _validate_submission,
        "capability_resolver": _resolve_capability,
        "authorized_workspace_root": boundary.runtime_root,
        "recovery_validator": _validate_recovery_descriptor,
        "publication_check_recovery": _recover_publication_checks,
        "descriptor_context": host_descriptor_context,
        "experience_provider_factory": _experience_dispatch,
        "experience_provider_profile": args.provider_profile,
        "experience_review_factory": _review_dispatch,
        "memory_repository_factory": _memory_repository_for_backend,
        "episode_repository_factory": _episode_repository_for_backend,
        "memory_actor": memory_actor,
        "memory_materializer_actor": memory_materializer_actor,
        "memory_selector": _select_project_memory,
        "memory_candidate_acl": memory_acl,
        "memory_candidate_owner_id": memory_owner,
        "memory_candidate_namespace": memory_namespace,
    }
    # Bind the real Provider-backed child-model factory at the formal CLI
    # boundary. Construction is lazy until a child is dispatched; missing
    # credentials/configuration therefore fail explicitly and never fall back
    # to a deterministic scripted result.
    host_kwargs["child_model_factory"] = lambda task_id: ReadonlyChildModelRunner.from_boundary(
        boundary,
        args.provider_profile,
        backend=host.backend,
        task_id=task_id,
    )
    host = LoopHost(boundary.state_root, **host_kwargs)
    try:
        host.start()
        print_json({
            "schema": "SITINA_LOOP_HOST_COMMAND_V1",
            "status": "listening",
            "state_root": str(Path(args.state_root).expanduser().resolve(strict=False)),
            "provider_started": False,
            "boundary": boundary.as_dict(),
        })
        host.serve_forever()
    except KeyboardInterrupt:
        host.begin_drain()
        host.wait_for_quiescence()
        return 130
    finally:
        host.begin_drain()
        host.wait_for_quiescence()
        host.close()
    return 0


def cmd_legacy(args: argparse.Namespace) -> int:
    from sitina.legacy.fence import LegacyWriteGate

    gate = LegacyWriteGate(SITINA_HOME)
    policy = LegacyRuntimePolicy.load(SITINA_HOME)
    if args.legacy_cmd == "status":
        status = gate.status()
        print_json(
            {
                "status": "ok",
                "state": status.state,
                "snapshot_id": status.snapshot_id,
                "fence_record_hash": status.record_hash,
                "production_writer": "legacy" if status.state == "LEGACY_ACTIVE" else None,
                "legacy_enabled": policy.legacy_enabled,
                "legacy_read_enabled": policy.read_enabled,
                "legacy_fallback_enabled": policy.fallback_enabled,
                "legacy_write_enabled": policy.write_enabled,
                "active_business_jsonl_enabled": policy.active_business_jsonl_enabled,
                "missing_legacy_is_valid": policy.missing_legacy_is_valid,
                "retired_root": policy.retired_root,
            }
        )
        return 0
    if args.legacy_cmd == "inventory":
        from sitina.legacy.inventory import build_observational_inventory

        manifest = build_observational_inventory(SITINA_HOME, Path(args.output))
        print_json({"status": "ok", "coherence": manifest.coherence, "semantic_manifest_hash": manifest.semantic_manifest_hash, "output": str(Path(args.output).resolve())})
        return 0
    raise SystemExit("unknown legacy command")


def cmd_eval(args: argparse.Namespace) -> int:
    results = run_safety_eval(SITINA_HOME)
    ok = all(item["result"] == "pass" for item in results)
    print_json({"ok": ok, "results": results})
    return 0 if ok else 1


def cmd_policy(args: argparse.Namespace) -> int:
    validators = {
        "workflow": WorkflowPolicyEngine(SITINA_HOME),
        "retry": RetryPolicy(SITINA_HOME),
        "reviewers": MultiReviewer(SITINA_HOME),
        "parallel": ParallelCoordinator(SITINA_HOME),
        "proposal": ProposalManager(SITINA_HOME),
        "team": DynamicTeamBuilder(SITINA_HOME),
        "autonomy": AutonomyManager(SITINA_HOME),
        "schema_registry": SchemaRegistry(SITINA_HOME),
    }
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for name, validator in validators.items():
        validator_errors, validator_warnings = validator.validate()
        details[name] = {"ok": not validator_errors, "errors": validator_errors, "warnings": validator_warnings}
        errors.extend(f"{name}: {item}" for item in validator_errors)
        warnings.extend(f"{name}: {item}" for item in validator_warnings)
    print_json({"ok": not errors, "errors": errors, "warnings": warnings, "details": details})
    return 0 if not errors else 2


def cmd_report(args: argparse.Namespace) -> int:
    if _bplus_installed():
        context = _bplus_context()
        run_id = getattr(args, "run_id", None)
        trace = context.trace_run(run_id) if run_id else None
        terminal = bool(trace and trace.get("status") == "ok" and any(
            item.get("event_type") in {"run.terminal", "run_completed"}
            for item in trace.get("timeline", [])
        ))
        cutover_verified = context.cutover_verified()
        status = "passed" if (run_id is None or terminal) else "incomplete"
        report = {
            "overall_status": status,
            "report_kind": f"bplus-{args.report_cmd}",
            "run_id": run_id,
            "writer": "journal",
            "authority_state": context.authority.resolution.state.value,
            "reader_generations": ["bplus-journal-v1"] + (["legacy-frozen-snapshot-v1"] if context.legacy.enabled else []),
            "journal_control_frontier_hash": context.authority.control_frontier_hash,
            "legacy_snapshot_manifest_sha256": context.legacy.manifest_sha256,
            "legacy_read_enabled": context.legacy.enabled,
            "legacy_fallback_enabled": context.legacy_policy.fallback_enabled,
            "cutover_verified": cutover_verified,
            "trace": trace,
            "external_call_count": 0,
            "writer_activated_by_report": False,
        }
        print_json(report)
        return report_exit_code(status)
    generator = AcceptanceReportGenerator(SITINA_HOME)
    if args.report_cmd == "v1":
        report = ReportPersistence(SITINA_HOME).persist(generator.generate_v1_report(refresh_baseline=bool(args.refresh_baseline)))
        print_json(report)
        return report_exit_code(str(report.get("overall_status")))
    if args.report_cmd == "live":
        report = ReportPersistence(SITINA_HOME).persist(generator.generate_live_report(args.run_id))
        print_json(report)
        return report_exit_code(str(report.get("overall_status")))
    if args.report_cmd == "acceptance":
        live_report = generator.generate_live_report(args.run_id)
        audit_result = AuditVerifier(SITINA_HOME).verify_evidence(args.run_id)
        domain_report = generator.generate_acceptance_report(
            args.run_id,
            live_report=live_report,
            enforce_cli_protocol=False,
            audit_result=audit_result,
        )
        current = CliEvidenceRecorder(SITINA_HOME).summary(args.run_id)
        missing_before_current = [name for name in current["missing_commands"] if name != "report_acceptance"]
        expected_status = "incomplete" if missing_before_current else str(domain_report.get("overall_status"))
        expected_exit = report_exit_code(expected_status)
        CliEvidenceRecorder(SITINA_HOME).record(
            args.run_id,
            "report_acceptance",
            expected_exit,
            dict(domain_report) | {"overall_status": expected_status},
        )
        args._cli_evidence_recorded = True
        report = generator.generate_acceptance_report(
            args.run_id,
            live_report=live_report,
            enforce_cli_protocol=True,
            audit_result=audit_result,
        )
        persistence = ReportPersistence(SITINA_HOME)
        formal_report_path = persistence.persist_formal_acceptance(report)
        report["formal_report_path"] = str(formal_report_path)
        report = persistence.persist(report)
        print_json(report)
        return report_exit_code(str(report.get("overall_status")))
    raise SystemExit("unknown report command")


def cmd_run(args: argparse.Namespace) -> int:
    if args.goal and args.goal[0] == "graph":
        if len(args.goal) != 2:
            print_json({"status": "blocked", "reason": "usage: sitina run graph <run_id>"})
            return 2
        return cmd_run_graph(argparse.Namespace(run_id=args.goal[1]))
    extension_manager = ExtensionManager(SITINA_HOME)
    extension_registry = extension_manager.load_registry()
    extensions_enabled = any(
        not item.get("disabled") for item in extension_registry["plugins"].values()
    ) or any(not item.get("disabled") for item in extension_registry["skills"].values())
    if not _bplus_installed() and extensions_enabled and args.provider_mode in {"auto", "live"}:
        if getattr(args, "approve_risky", False):
            approval_callback = lambda _request: True
        elif sys.stdin.isatty() and sys.stdout.isatty():
            approval_callback = _interactive_tool_approval
        else:
            approval_callback = lambda _request: False
        result = AutonomousRuntime(
            SITINA_HOME,
            manager=extension_manager,
            approval_callback=approval_callback,
        ).run(" ".join(args.goal))
        print_json(result)
        return 0 if result.get("terminal_state") == "SUCCEEDED" else 2
    if _bplus_installed():
        if not _is_production_home() and (SITINA_HOME / "state/clean-acceptance/genesis.json").is_file():
            print_json({
                "status": "blocked",
                "reason": "clean acceptance is immutable; ordinary runs belong to the active Sitina installation",
                "production_home": str(canonical_journal_native_home()),
                "legacy_read_enabled": False,
                "legacy_write_enabled": False,
                "fallback_attempted": False,
            })
            return 3
        if args.provider_mode in {"auto", "live"} and args.profile_override:
            print_json({
                "status": "blocked",
                "reason": "profile overrides are forbidden for the manifest-bound Production multi-Agent runtime",
                "journal_mutated": False,
                "cas_mutated": False,
                "fallback_attempted": False,
            })
            return 3
        if args.provider_mode in {"auto", "live"}:
            if args.goal_id or args.backlog_item_id:
                print_json({
                    "status": "blocked",
                    "reason": "Production multi-Agent runs do not accept Legacy goal/backlog link fields",
                    "journal_mutated": False,
                    "cas_mutated": False,
                    "fallback_attempted": False,
                })
                return 3
            from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime

            result = TrueMultiAgentProductionRuntime(SITINA_HOME).execute(
                " ".join(args.goal),
                label="cli-production-ordinary-goal",
            )
            print_json(result)
            if result.get("status") == "checkpoint_restart_required":
                return 75
            return 0 if result.get("terminal_state") == "SUCCEEDED" else 2
        if args.profile_override:
            print_json({
                "status": "blocked",
                "reason": "profile overrides are invalid for the Journal-native local mock path because it performs no Provider call",
                "journal_mutated": False,
                "cas_mutated": False,
                "fallback_attempted": False,
            })
            return 3
        result = JournalNativeLocalRuntime(SITINA_HOME).execute(
            " ".join(args.goal),
            parent_goal_id=getattr(args, "goal_id", None),
            backlog_item_id=getattr(args, "backlog_item_id", None),
        )
        print_json(result)
        return 0 if result.get("status") in {"ok", "terminal"} else 2
    print_json({
        "status": "blocked",
        "reason": "Legacy orchestration is retired and this home has no verified Journal-native runtime",
        "legacy_fallback_attempted": False,
    })
    return 3


def _interactive_tool_approval(request: ApprovalRequest) -> bool:
    print(
        f"\n需要审批：{request.tool_name} · 权限 {request.permission} · 风险 {request.risk}\n"
        f"来源：{request.origin}\n参数：{json.dumps(dict(request.arguments), ensure_ascii=False, sort_keys=True)}"
    )
    while True:
        try:
            answer = input("允许本次调用？[y/N] ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer in {"y", "yes", "是"}:
            return True
        if answer in {"", "n", "no", "否"}:
            return False
        print("请输入 y 或 n。")


def _build_code_mode_runtime(
    selected_workspace: Path,
    *,
    state_root: str | Path | None = None,
    provider: Any | None = None,
    session_instance_id: str | None = None,
    provider_profile_name: str | None = None,
) -> tuple[Path, Any, Any]:
    """Construct the retained independent Code Mode test/bootstrap runtime.

    This is intentionally a small runtime bootstrap, not an acceptance gate:
    it creates only local Code Mode Journal/CAS state and copies non-secret
    project configuration.  It never reads Legacy B+ genesis/foundation or
    asks the old ProductionRuntimeContext to authorize the session.
    """

    from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime

    session_instance_id = str(
        session_instance_id or ("session-instance-" + secrets.token_hex(16))
    )
    runtime_parent = Path(state_root).expanduser().resolve(strict=False) if state_root else (
        SITINA_HOME / "state" / "code-mode"
    ).resolve(strict=False)
    # A CLI process never reuses a prior Code Mode authority namespace.  The
    # parent remains available for audit, while Journal/CAS for this run live
    # below a fresh instance directory and are never used to restore authority.
    runtime_home = runtime_parent / "sessions" / session_instance_id
    if runtime_home.is_symlink():
        raise RuntimeError("Code Mode state root may not be a symlink")
    # Keep a non-authoritative discovery marker at the caller-selected parent
    # for existing CLI diagnostics. All journal/CAS/session state remains in
    # the fresh per-instance child and the marker never grants authority.
    runtime_parent.mkdir(parents=True, exist_ok=True)
    _fence_orphaned_code_mode_sessions(runtime_parent, session_instance_id)
    (runtime_parent / ".sitina-code-mode-v1").touch(exist_ok=True)
    runtime_home.mkdir(parents=True, exist_ok=True)
    config_root = runtime_home / "config"
    config_root.mkdir(parents=True, exist_ok=True)
    source_config = Path(__file__).resolve().parents[2] / "config"
    source_root = Path(__file__).resolve().parents[2]
    if not source_config.is_dir():
        raise RuntimeError("Code Mode source configuration is unavailable")
    selected_policy = _provider_policy_for_profile(source_root, provider_profile_name)
    selected_profile = str(provider_profile_name or "").strip()
    discovered_profile_paths = (
        _discover_provider_profile_paths(SITINA_HOME) if provider is None else {}
    )
    if selected_profile and provider is None and selected_profile not in discovered_profile_paths:
        raise RuntimeError("selected provider profile is not an installed 0600 profile")
    for source in source_config.iterdir():
        destination = config_root / source.name
        if destination.exists() or source.is_symlink() or not source.is_file():
            continue
        shutil.copy2(source, destination)
    if selected_policy is not None:
        (config_root / "true_multi_agent_policy.json").write_text(
            json.dumps(selected_policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    runtime_keys = InMemoryKeyProvider(environment="code-mode", namespace="cli-runtime")
    # The attested authority host is a read-only verifier of this exact
    # runtime. Give it only ephemeral symmetric verification material; the
    # controller's authority signing key remains separate and is never part
    # of this bundle.
    verification_material = runtime_keys.export_read_only_verification_material()
    # Compute the runtime identity from the source checkout once, before the
    # host is started.  The host receives this as a launcher-owned bootstrap
    # fact; a later RPC cannot replace it with caller-selected identity.
    preview_context = CodeModeRuntimeContext.open(
        runtime_home,
        provider=runtime_keys,
        source_root=source_root,
        session_instance_id=session_instance_id,
    )
    preview_root_stat = os.stat(runtime_home, follow_symlinks=False)
    workspace_stat = os.stat(selected_workspace, follow_symlinks=False)
    # The signing key and one-use authority state live in the separately
    # exec'd host entrypoint.  The imported package contains only a verifier
    # client; no bool/private method can start an issuer.
    control_parent, control_child = socket.socketpair()
    bootstrap_read, bootstrap_write = os.pipe()
    host_entrypoint = source_root / "scripts" / "code_mode_authority_host.py"
    if not host_entrypoint.is_file() or host_entrypoint.is_symlink():
        raise RuntimeError("Code Mode authority host entrypoint is unavailable")
    # The reviewer is attested before the authority host is bootstrapped so
    # its verification identity is a fixed launcher input, never a later RPC
    # claim.  The authority host receives only verification material.
    reviewer = _launch_code_mode_reviewer(source_root)
    process = subprocess.Popen(
        [sys.executable, str(host_entrypoint), "--control-fd", str(control_child.fileno()), "--bootstrap-fd", str(bootstrap_read)],
        pass_fds=(control_child.fileno(), bootstrap_read), close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    control_child.close()
    os.close(bootstrap_read)
    profile = getattr(provider, "profile", None)
    profile_paths = discovered_profile_paths
    challenge_secret = secrets.token_bytes(32)
    # The controller creates the ephemeral authority key and injects it once
    # through the bootstrap pipe.  It is never persisted or exposed to the
    # worker/client; the host uses it only for typed authority envelopes.
    authority_private_key = secrets.token_bytes(32)
    controller_capability_private_key = Ed25519PrivateKey.generate()
    controller_capability_public_key = controller_capability_private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    bootstrap_payload = {
        "nonce": secrets.token_hex(32),
        "challenge_secret": challenge_secret.hex(),
        "authority_private_key_hex": authority_private_key.hex(),
        "controller_capability_public_key": controller_capability_public_key.hex(),
        "state_root": str(runtime_home),
        "state_root_identity": f"{preview_root_stat.st_dev}:{preview_root_stat.st_ino}",
        "runtime_state_identity": preview_context.identity.state_identity,
        "runtime_journal_id": preview_context.identity.journal_id,
        # This is a process-local session identity, never recovered from the
        # state directory.  The host must echo the exact launcher value in its
        # binding; a host-created or caller-supplied identity is not accepted.
        "session_instance_id": session_instance_id,
        "workspace": str(selected_workspace),
        "workspace_identity": f"{workspace_stat.st_dev}:{workspace_stat.st_ino}",
        "source_root": str(source_root),
        "source_root_identity": f"{os.stat(source_root, follow_symlinks=False).st_dev}:{os.stat(source_root, follow_symlinks=False).st_ino}",
        "source_manifest_hash": preview_context.identity.source_manifest_hash,
        "verification_material": verification_material,
        "profiles": ({str(profile.name): {
            "name": str(profile.name), "base_url": str(profile.base_url),
            "model": str(profile.model),
            "wire_protocol": str(getattr(profile, "wire_protocol", "") or ""),
            "adapter_capabilities": list(getattr(profile, "adapter_capabilities", ()) or ()),
            "allowed_endpoint_hosts": list(getattr(profile, "allowed_endpoint_hosts", ()) or ()),
        }} if profile is not None else {}),
        "profile_paths": profile_paths,
        "reviewer_verification": dict(reviewer.tty_verification_material),
    }
    bootstrap = json.dumps(bootstrap_payload, separators=(",", ":")).encode("utf-8")
    try:
        os.write(bootstrap_write, bootstrap)
    finally:
        os.close(bootstrap_write)
        del bootstrap, bootstrap_payload, authority_private_key
    broker = _connect_attested_host(
        control_parent, process, expected_entrypoint=host_entrypoint, challenge=challenge_secret,
        controller_capability_private_key=controller_capability_private_key,
    )
    del challenge_secret
    del controller_capability_private_key, controller_capability_public_key
    runtime_context_factory = broker.context_factory(
        provider=runtime_keys,
        source_root=source_root,
        session_instance_id=session_instance_id,
    )

    reviewer_holder = {"session": reviewer}

    def open_code_mode_reviewer() -> CodeModeReviewerSession:
        current = reviewer_holder.get("session")
        if current is not None and current.is_attested_reviewer():
            return current
        # The authority host pins the launcher's reviewer verification
        # material for the entire CLI session.  Replacing a dead reviewer
        # here would create a new issuer that the already-running authority
        # host must (and does) reject.  Keep the two hosts in one lifecycle
        # and require a fresh CLI bootstrap after either side is lost.
        raise RuntimeError(
            "launcher-pinned Code Mode reviewer is unavailable; restart the CLI session"
        )

    def close_code_mode_reviewer() -> None:
        current = reviewer_holder.pop("session", None)
        if current is not None:
            current.close()
        setattr(runtime_context_factory, "reviewer_session", None)

    def close_code_mode_hosts() -> None:
        try:
            close_code_mode_reviewer()
        finally:
            broker.close()

    # The factory remains the authority-host context factory, but its close
    # lifecycle owns the independent reviewer as well.  No reviewer process
    # or TTY descriptor is passed to the worker.
    setattr(runtime_context_factory, "reviewer_session", reviewer)
    setattr(runtime_context_factory, "open_reviewer", open_code_mode_reviewer)
    setattr(runtime_context_factory, "close_reviewer", close_code_mode_reviewer)
    setattr(runtime_context_factory, "close", close_code_mode_hosts)
    try:
        multi_runtime = TrueMultiAgentProductionRuntime(
            runtime_home,
            source_root=source_root,
            runtime_context_factory=runtime_context_factory,
            provider_client=provider,
            provider_profile=getattr(provider, "profile", None),
        )
        if selected_policy is not None:
            # The launcher-selected policy is non-secret configuration.  Keep
            # its exact hash in the runtime object so activation signs the
            # selected profile, while the host still resolves credentials from
            # the forwarded profile path.
            multi_runtime.policy = selected_policy
            multi_runtime.policy_hash = hashlib.sha256(
                json.dumps(selected_policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
    except BaseException:
        close_code_mode_hosts()
        raise
    setattr(multi_runtime, "code_mode_reviewer_session", reviewer)
    return runtime_home, runtime_context_factory, multi_runtime


def _launch_code_mode_reviewer(source_root: Path) -> CodeModeReviewerSession:
    """Launch and attest the production Code Mode reviewer pair.

    This is intentionally kept in the CLI host, not in the test fixtures.
    The producer owns its signing key and the reviewer host owns the TTY
    confirmation MAC key; the parent receives only attested client sessions.
    """
    def launch(entrypoint: Path, payload: Mapping[str, Any]) -> tuple[socket.socket, subprocess.Popen[bytes], bytes]:
        parent, child = socket.socketpair()
        bootstrap_read, bootstrap_write = os.pipe()
        challenge = secrets.token_bytes(32)
        bootstrap = dict(payload)
        bootstrap["challenge_secret"] = challenge.hex()
        process = subprocess.Popen(
            [sys.executable, str(entrypoint), "--control-fd", str(child.fileno()), "--bootstrap-fd", str(bootstrap_read)],
            pass_fds=(child.fileno(), bootstrap_read), close_fds=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        child.close()
        os.close(bootstrap_read)
        try:
            os.write(bootstrap_write, json.dumps(bootstrap, separators=(",", ":")).encode("utf-8"))
        finally:
            os.close(bootstrap_write)
        return parent, process, challenge

    producer_entrypoint = source_root / "scripts" / "code_mode_reviewer_producer.py"
    reviewer_entrypoint = source_root / "scripts" / "code_mode_reviewer_host.py"
    if any(not path.is_file() or path.is_symlink() for path in (producer_entrypoint, reviewer_entrypoint)):
        raise RuntimeError("Code Mode reviewer entrypoint is unavailable")
    producer_channel = producer_process = producer = None
    reviewer_channel = reviewer_process = None
    try:
        producer_channel, producer_process, producer_challenge = launch(producer_entrypoint, {})
        producer = CodeModeReviewerProducerSession.connect_host(
            producer_channel, producer_process,
            expected_entrypoint=producer_entrypoint, challenge=producer_challenge,
        )
        reviewer_channel, reviewer_process, reviewer_challenge = launch(
            reviewer_entrypoint,
            {"producer_id": producer.identity["producer_id"], "producer_public_key": producer.identity["public_key"]},
        )
        return CodeModeReviewerSession.connect_host(
            reviewer_channel, reviewer_process,
            expected_entrypoint=reviewer_entrypoint, challenge=reviewer_challenge,
            producer_session=producer,
        )
    except Exception:
        for channel in (reviewer_channel, producer_channel):
            try:
                if channel is not None:
                    channel.close()
            except OSError:
                pass
        for process in (reviewer_process, producer_process):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        raise


def cmd_chat(args: argparse.Namespace) -> int:
    """Reject the retired legacy chat entry without inspecting arguments."""

    del args
    print_json(
        {
            "schema": "SITINA_RETIRED_CHAT_ENTRY_V1",
            "status": "blocked",
            "reason": (
                "The legacy chat entry is retired; "
                "use sitina with no arguments or run sitina loop"
            ),
            "command": "chat",
            "retired_modes": ["FAST", "MULTI"],
            "automatic_reinterpretation": False,
            "replacement_dispatched": False,
            "task_created": False,
            "host_started": False,
            "provider_call_count": 0,
            "physical_requests": 0,
            "workspace_inspected": False,
            "workspace_created": False,
            "journal_mutated": False,
            "cas_mutated": False,
            "user_state_read": False,
            "user_state_migrated": False,
        }
    )
    return 3


def cmd_ask(args: argparse.Namespace) -> int:
    return cmd_run(args)


def cmd_code_mode(args: argparse.Namespace) -> int:
    """Read-only Code Mode status; it never consults Legacy B+ activation."""

    workspace = Path(args.workspace).expanduser() if getattr(args, "workspace", None) else SITINA_HOME
    try:
        candidate = build_candidate_manifest(workspace)
        result = CodeModeAcceptanceV1(workspace).status_summary(candidate=candidate)
        result.update({"status": "ok", "read_only": True, "physical_requests": 0})
        print_json(result)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print_json(
            {
                "status": "blocked",
                "read_only": True,
                "code_mode_status": "CODE_MODE_BLOCKED",
                "legacy_bplus_status": "LEGACY_BPLUS_BLOCKED",
                "legacy_foundation_consulted": False,
                "physical_requests": 0,
                "reason_type": type(error).__name__,
                "reason": str(error),
            }
        )
        return 3


def _retired_legacy_command(command: str, *, replacement: str | None = None) -> int:
    payload: dict[str, Any] = {
        "status": "blocked",
        "reason": f"{command} belonged to the retired Legacy orchestration engine",
        "legacy_read_enabled": False,
        "legacy_write_enabled": False,
        "fallback_attempted": False,
    }
    if replacement:
        payload["replacement"] = replacement
    print_json(payload)
    return 3


def _extension_error(error: BaseException) -> int:
    payload: dict[str, Any] = {
        "status": "blocked",
        "error_type": type(error).__name__,
        "reason": str(error),
    }
    if isinstance(error, PermissionGrantRequired):
        payload["plugin"] = error.plugin
        payload["missing_permissions"] = list(error.missing)
    print_json(payload)
    return 3


def cmd_plugin(args: argparse.Namespace) -> int:
    manager = ExtensionManager(SITINA_HOME)
    try:
        if args.plugin_cmd == "list":
            print_json(
                {
                    "status": "ok",
                    "scope": "global",
                    "extension_root": str(manager.root),
                    "plugins": manager.list_plugins(),
                }
            )
            return 0
        if args.plugin_cmd == "install":
            result = manager.install_plugin(
                args.source,
                grants=args.grant,
                approve_network=args.approve_network,
                expected_sha256=args.sha256,
                git_ref=args.git_ref,
            )
            print_json(result)
            return 0
        if args.plugin_cmd == "update":
            registry = manager.load_registry()
            state = dict(registry["plugins"].get(args.name) or {})
            active = manager._version_record(state, str(state.get("active") or ""))
            source = args.source or active.get("source")
            if not source:
                raise ExtensionInstallError(f"plugin is not installed or has no pinned source: {args.name}")
            result = manager.install_plugin(
                str(source),
                grants=args.grant,
                approve_network=args.approve_network,
                expected_sha256=args.sha256,
                git_ref=args.git_ref,
                update=True,
            )
            print_json(result)
            return 0
        if args.plugin_cmd == "rollback":
            print_json(manager.rollback_plugin(args.name, install_id=args.to))
            return 0
        if args.plugin_cmd == "disable":
            print_json(manager.disable_plugin(args.name))
            return 0
        if args.plugin_cmd == "marketplace-add":
            print_json(manager.add_marketplace(args.source, approve_network=args.approve_network))
            return 0
        if args.plugin_cmd == "marketplace-list":
            registry = manager.load_registry()
            print_json(
                {
                    "status": "ok",
                    "scope": "global",
                    "marketplaces": [
                        {
                            "name": name,
                            "source": item.get("source"),
                            "sha256": item.get("sha256"),
                            "plugin_count": len(dict(item.get("manifest") or {}).get("plugins", [])),
                        }
                        for name, item in sorted(registry["marketplaces"].items())
                    ],
                }
            )
            return 0
        if args.plugin_cmd == "marketplace-install":
            print_json(
                manager.install_from_marketplace(
                    args.marketplace,
                    args.name,
                    grants=args.grant,
                    approve_network=args.approve_network,
                )
            )
            return 0
    except (ExtensionInstallError, ValueError, OSError) as error:
        return _extension_error(error)
    raise SystemExit("unknown plugin command")


def cmd_skill(args: argparse.Namespace) -> int:
    manager = ExtensionManager(SITINA_HOME)
    try:
        if args.skill_cmd == "install":
            print_json(manager.install_skill(args.source))
            return 0
        if args.skill_cmd == "list":
            skills = manager.skills()
            print_json(
                {
                    "status": "ok",
                    "scope": "global",
                    "extension_root": str(manager.root),
                    "skills": [skill.metadata() for skill in skills],
                }
            )
            return 0
        if args.skill_cmd == "show":
            skill = next((item for item in manager.skills() if item.qualified_name == args.name), None)
            if skill is None:
                raise ExtensionInstallError(f"skill is not installed: {args.name}")
            print_json({"status": "ok", "skill": skill.metadata(), "instructions": skill.body})
            return 0
        if args.skill_cmd == "rollback":
            print_json(manager.rollback_skill(args.name, install_id=args.to))
            return 0
        if args.skill_cmd == "disable":
            print_json(manager.disable_skill(args.name))
            return 0
    except (ExtensionInstallError, ValueError, OSError) as error:
        return _extension_error(error)
    raise SystemExit("unknown skill command")


def cmd_agent(args: argparse.Namespace) -> int:
    if args.approve_risky:
        approval_callback = lambda _request: True
    elif sys.stdin.isatty() and sys.stdout.isatty():
        approval_callback = _interactive_tool_approval
    else:
        approval_callback = lambda _request: False
    try:
        runtime = AutonomousRuntime(
            SITINA_HOME,
            profile_name=args.profile,
            client=(ScriptedMockToolClient.load(Path(args.mock_script)) if args.mock_script else None),
            approval_callback=approval_callback,
            workspace=Path(args.workspace).expanduser() if args.workspace else SITINA_HOME,
            max_tokens=args.max_tokens,
            max_turns=args.max_turns,
        )
        result = runtime.run(" ".join(args.task))
    except (ExtensionInstallError, ValueError, OSError, RuntimeError) as error:
        return _extension_error(error)
    print_json(result)
    return 0 if result.get("terminal_state") == "SUCCEEDED" else 2


def cmd_resume(args: argparse.Namespace) -> int:
    return _retired_legacy_command("resume", replacement="Journal-native checkpoint recovery")


def cmd_cancel(args: argparse.Namespace) -> int:
    return _retired_legacy_command("cancel", replacement="runtime-specific cancellation")


def cmd_checkpoint(args: argparse.Namespace) -> int:
    manager = CheckpointManager(SITINA_HOME)
    if args.checkpoint_cmd == "list":
        checkpoints = manager.list(args.run_id)
        print_json({"status": "ok", "run_id": args.run_id, "count": len(checkpoints), "checkpoints": checkpoints})
        return 0
    if args.checkpoint_cmd == "show":
        checkpoint = manager.show(args.checkpoint_id)
        print_json({"status": "ok" if checkpoint else "not_found", "checkpoint": checkpoint})
        return 0 if checkpoint else 2
    raise SystemExit("unknown checkpoint command")


def cmd_list(args: argparse.Namespace) -> int:
    if _bplus_installed():
        context = _bplus_context()
        runs = context.list_runs()
        print_json({
            "runs": runs,
            "reader_generation": runs[0].get("reader_generation") if runs else (
                "projection-v2+active-tail" if context.authority.fast_start_report is not None else "bplus-journal-v1"
            ),
            "legacy_read_enabled": context.legacy.enabled,
            "fallback_used": False,
        })
        return 0
    store = SitinaStore(SITINA_HOME)
    store.init_db()
    print_json({"runs": store.list_runs()})
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    if _bplus_installed():
        state = _bplus_context().show_run(args.run_id)
        if state is None:
            print_json({"status": "not_found", "run_id": args.run_id})
            return 2
        print_json(state)
        return 0
    store = SitinaStore(SITINA_HOME)
    store.init_db()
    state = store.get_run(args.run_id)
    if not state:
        print_json({"status": "not_found", "run_id": args.run_id})
        return 2
    print_json(state)
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    if _bplus_installed():
        result = _bplus_context().trace_run(args.run_id)
    else:
        SitinaStore(SITINA_HOME).init_db()
        result = RunLedger(SITINA_HOME).trace_summary(args.run_id)
    query_requested = bool(getattr(args, "query", False))
    if query_requested:
        timeline = result.get("timeline", []) if isinstance(result, dict) else []
        query = TraceQuery(
            run_id=args.run_id,
            agent=getattr(args, "agent", None),
            tool=getattr(args, "tool", None),
            status=getattr(args, "status", None),
            started_at=getattr(args, "started_at", None),
            ended_at=getattr(args, "ended_at", None),
            correlation_id=getattr(args, "correlation_id", None),
            cursor=getattr(args, "cursor", 0),
            limit=getattr(args, "limit", 100),
        )
        result = TraceQueryEngine().query(timeline, query).model_dump(by_alias=True)
    print_json(result)
    count = result.get("total_matches", 0) if query_requested else result.get("event_count", 0)
    return 0 if count > 0 else 2


def cmd_replay(args: argparse.Namespace) -> int:
    if _bplus_installed():
        values = list(args.run_id)
        if len(values) == 2 and values[0] in {"diff", "simulate"}:
            result = _bplus_context().replay_run(values[1])
            if values[0] == "diff" and result.get("status") == "replay_ok":
                result = {**result, "status": "match", "mismatches": []}
            elif values[0] == "simulate" and result.get("status") == "replay_ok":
                result = {**result, "status": "replay_simulated", "sandbox_mutation_count": 0}
        elif len(values) == 1:
            result = _bplus_context().replay_run(values[0])
        else:
            print_json({"status": "blocked", "reason": "usage: sitina replay [diff|simulate] <run_id>"})
            return 2
        print_json(result)
        return 0 if result.get("status") in {"replay_ok", "match", "replay_simulated"} else 2
    SitinaStore(SITINA_HOME).init_db()
    if args.run_id and args.run_id[0] == "diff":
        if len(args.run_id) != 2:
            print_json({"status": "blocked", "reason": "usage: sitina replay diff <run_id>"})
            return 2
        return cmd_replay_diff(argparse.Namespace(run_id=args.run_id[1]))
    if args.run_id and args.run_id[0] == "simulate":
        if len(args.run_id) != 2:
            print_json({"status": "blocked", "reason": "usage: sitina replay simulate <run_id> [--sandbox <path>]"})
            return 2
        return cmd_replay_simulate(argparse.Namespace(run_id=args.run_id[1], sandbox=args.sandbox))
    if len(args.run_id) != 1:
        print_json({"status": "blocked", "reason": "usage: sitina replay <run_id>"})
        return 2
    result = ReplayEngine(SITINA_HOME).replay(args.run_id[0]).model_dump()
    print_json(result)
    return 0 if result.get("status") in {"replay_ok", "replay_incomplete"} else 2


def cmd_cost_status(args: argparse.Namespace) -> int:
    if _bplus_installed():
        trace = _bplus_context().trace_run(args.run_id)
        timeline = trace.get("timeline", []) if isinstance(trace, dict) else []
    else:
        SitinaStore(SITINA_HOME).init_db()
        timeline = RunLedger(SITINA_HOME).timeline(args.run_id)
    result = RuntimeCostMonitor.snapshot(
        args.run_id,
        timeline,
        hard_limit_tokens=args.hard_limit_tokens,
        forecast_additional_tokens=args.forecast_additional_tokens,
    )
    print_json(result.model_dump(by_alias=True))
    return 0


def cmd_suggest(args: argparse.Namespace) -> int:
    from sitina.conversation.suggestion import SuggestionEngine, SuggestionError

    try:
        result = SuggestionEngine(SITINA_HOME).suggest(
            " ".join(args.description),
            mode="AUTO",
            budget_tokens=args.budget_tokens,
            sla_class=args.sla_class,
            sla_remaining_ms=args.sla_remaining_ms,
            context=args.context or "",
            prior_mode=None,
            prior_complexity=args.prior_complexity,
            unfinished_goal=bool(args.unfinished_goal),
            task_type_override=args.task_type,
            risk_override=args.risk,
            topology_override=args.topology,
        )
    except (SuggestionError, ValueError) as error:
        print_json(
            {
                "schema": SuggestionEngine.SCHEMA,
                "version": SuggestionEngine.VERSION,
                "status": "configuration_error",
                "reason": str(error),
                "side_effects": {"provider_calls": 0, "network_calls": 0, "state_writes": 0},
            }
        )
        return 2
    print_json(result)
    return 0


def cmd_replay_diff(args: argparse.Namespace) -> int:
    replay = ReplayEngine(SITINA_HOME).replay(args.run_id, record=False)
    graph = TaskGraphRuntime(SITINA_HOME).load(args.run_id)
    snapshot_nodes = {node.task_id: node.status for node in graph.nodes} if graph else {}
    replay_nodes = replay.node_states
    mismatches = []
    if set(snapshot_nodes) != set(replay_nodes):
        mismatches.append({"type": "snapshot_mismatch", "reason": "node set differs", "snapshot_nodes": sorted(snapshot_nodes), "replay_nodes": sorted(replay_nodes)})
    for task_id in sorted(set(snapshot_nodes) & set(replay_nodes)):
        if snapshot_nodes[task_id] != replay_nodes[task_id]:
            mismatches.append({"type": "inconsistent_node_state", "task_id": task_id, "snapshot": snapshot_nodes[task_id], "replay": replay_nodes[task_id]})
    out = {
        "status": "match" if not mismatches and not replay.inconsistent_events else "snapshot_mismatch",
        "run_id": args.run_id,
        "replay_status": replay.status,
        "mismatches": mismatches + [{"type": "replay_inconsistent", "reason": item} for item in replay.inconsistent_events],
        "blackboard_count": replay.blackboard_summary.get("count", 0),
        "side_effect_count": len(replay.side_effects),
    }
    print_json(out)
    return 0 if out["status"] == "match" else 2


def cmd_replay_simulate(args: argparse.Namespace) -> int:
    result = ReplayEngine(SITINA_HOME).simulate(args.run_id, sandbox=args.sandbox).model_dump()
    print_json(result)
    return 0 if result.get("status") == "replay_simulated" else 2


def cmd_agents(args: argparse.Namespace) -> int:
    if args.agents_cmd == "status":
        print_json(DynamicTeamBuilder(SITINA_HOME).agents_status())
        return 0
    raise SystemExit("unknown agents command")


def _proposal_lifecycle(run_id: str) -> dict[str, Any]:
    if _bplus_installed():
        return _bplus_context().protocol_view(run_id, "proposals")
    replay = ReplayEngine(SITINA_HOME).replay(run_id, record=False)
    proposals = replay.proposals or {"rounds": [], "submitted": [], "evaluations": [], "selected": [], "rejected": [], "blocked": []}
    return {
        "status": "ok",
        "run_id": run_id,
        "run_exists": replay.status != "run_not_found",
        "proposals": proposals,
        "blackboard_docs": replay.blackboard_summary.get("documents", []),
    }


def cmd_proposals(args: argparse.Namespace) -> int:
    if args.proposals_cmd == "list":
        if not args.run_id:
            print_json({"status": "blocked", "reason": "--run-id is required"})
            return 2
        result = _proposal_lifecycle(args.run_id)
        print_json(result)
        return 0 if result["status"] == "ok" else 2
    if args.proposals_cmd == "show":
        if _bplus_installed():
            result = _bplus_context().find_protocol_entity(
                "proposals",
                args.proposal_id,
                id_fields=("proposal_id", "selected_proposal_id"),
            )
            print_json(result)
            return 0 if result["status"] == "ok" else 2
        store = SitinaStore(SITINA_HOME)
        store.init_db()
        with store.connect() as conn:
            rows = conn.execute("SELECT run_id, payload_json FROM events WHERE event_type = 'run_ledger' ORDER BY id ASC").fetchall()
        matches = []
        for run_id, payload_json in rows:
            try:
                event = json.loads(payload_json)
            except json.JSONDecodeError:
                continue
            payload = event.get("payload_json") or {}
            if payload.get("proposal_id") == args.proposal_id or payload.get("selected_proposal_id") == args.proposal_id:
                matches.append({"run_id": run_id, "event_type": event.get("event_type"), "payload": payload})
        print_json({"status": "ok" if matches else "not_found", "proposal_id": args.proposal_id, "events": matches})
        return 0 if matches else 2
    raise SystemExit("unknown proposals command")


def cmd_blackboard(args: argparse.Namespace) -> int:
    if args.blackboard_cmd == "show":
        if _bplus_installed():
            result = _bplus_context().protocol_view(args.run_id, "blackboard")
            result["requested_type"] = args.type
            print_json(result)
            return 0 if result["status"] == "ok" else 2
        docs = Blackboard(SITINA_HOME).documents(args.run_id, args.type)
        print_json({"status": "ok", "run_id": args.run_id, "type": args.type, "count": len(docs), "documents": docs, "conflicts": Blackboard(SITINA_HOME).conflicts(args.run_id)})
        return 0
    raise SystemExit("unknown blackboard command")


def cmd_handoff(args: argparse.Namespace) -> int:
    if _bplus_installed():
        context = _bplus_context()
        if args.handoff_cmd == "list":
            if not args.run_id:
                print_json({"status": "blocked", "reason": "--run-id is required for B+ protocol reads"})
                return 2
            result = context.protocol_view(args.run_id, "handoff")
        else:
            result = context.find_protocol_entity("handoff", args.handoff_id, id_fields=("handoff_id",))
        print_json(result)
        return 0 if result["status"] == "ok" else 2
    manager = HandoffManager(SITINA_HOME)
    if args.handoff_cmd == "list":
        handoffs = manager.handoffs(run_id=args.run_id)
        print_json({"status": "ok", "run_id": args.run_id, "count": len(handoffs), "handoffs": [item.model_dump() for item in handoffs]})
        return 0
    if args.handoff_cmd == "show":
        handoff = manager.get_handoff(args.handoff_id)
        print_json({"status": "ok" if handoff else "not_found", "handoff_id": args.handoff_id, "handoff": handoff.model_dump() if handoff else None})
        return 0 if handoff else 2
    raise SystemExit("unknown handoff command")


def cmd_lease(args: argparse.Namespace) -> int:
    if _bplus_installed():
        context = _bplus_context()
        if args.lease_cmd == "list":
            if not args.run_id:
                print_json({"status": "blocked", "reason": "--run-id is required for B+ protocol reads"})
                return 2
            result = context.protocol_view(args.run_id, "lease")
        else:
            result = context.find_protocol_entity(
                "lease", args.lease_id, id_fields=("lease_id", "task_attempt_id", "claim_command_id")
            )
        print_json(result)
        return 0 if result["status"] == "ok" else 2
    manager = LeaseManager(SITINA_HOME)
    if args.lease_cmd == "list":
        leases = manager.leases(run_id=args.run_id)
        print_json({"status": "ok", "run_id": args.run_id, "count": len(leases), "leases": [item.model_dump() for item in leases]})
        return 0
    if args.lease_cmd == "show":
        lease = manager.get_lease(args.lease_id)
        print_json({"status": "ok" if lease else "not_found", "lease_id": args.lease_id, "lease": lease.model_dump() if lease else None})
        return 0 if lease else 2
    raise SystemExit("unknown lease command")


def cmd_arbitration(args: argparse.Namespace) -> int:
    if _bplus_installed():
        context = _bplus_context()
        if args.arbitration_cmd == "list":
            if not args.run_id:
                print_json({"status": "blocked", "reason": "--run-id is required for B+ protocol reads"})
                return 2
            result = context.protocol_view(args.run_id, "arbitration")
        else:
            result = context.find_protocol_entity("arbitration", args.arbitration_id, id_fields=("arbitration_id",))
        print_json(result)
        return 0 if result["status"] == "ok" else 2
    manager = ArbitrationManager(SITINA_HOME)
    if args.arbitration_cmd == "list":
        arbitrations = manager.list(run_id=args.run_id)
        print_json({"status": "ok", "run_id": args.run_id, "count": len(arbitrations), "arbitrations": [item.model_dump() for item in arbitrations]})
        return 0
    if args.arbitration_cmd == "show":
        arbitration = manager.show(args.arbitration_id)
        print_json({"status": "ok" if arbitration else "not_found", "arbitration_id": args.arbitration_id, "arbitration": arbitration.model_dump() if arbitration else None})
        return 0 if arbitration else 2
    raise SystemExit("unknown arbitration command")


def cmd_bplus_protocol_status(args: argparse.Namespace) -> int:
    if not _bplus_installed():
        print_json({"status": "blocked", "reason": "B+ Production runtime is not installed"})
        return 2
    result = _bplus_context().protocol_view(args.run_id, args.protocol_family)
    print_json(result)
    return 0 if result["status"] == "ok" else 2


def cmd_run_graph(args: argparse.Namespace) -> int:
    graph = TaskGraphRuntime(SITINA_HOME).load(args.run_id)
    if not graph:
        print_json({"status": "not_found", "run_id": args.run_id})
        return 2
    replay = ReplayEngine(SITINA_HOME).replay(args.run_id, record=False)
    print_json(
        {
            "status": "ok",
            "run_id": args.run_id,
            "task_type": graph.task_type,
            "nodes": [node.model_dump() for node in graph.nodes],
            "dependencies": {node.task_id: node.depends_on for node in graph.nodes},
            "gates": {node.task_id: node.required_gates for node in graph.nodes if node.required_gates},
            "rework_edges": [edge.model_dump() for edge in graph.rework_edges],
            "proposal_selection": {"proposal_round_id": graph.proposal_round_id, "selected_proposal_id": graph.selected_proposal_id},
            "leases": [lease.model_dump() for lease in LeaseManager(SITINA_HOME).leases(run_id=args.run_id)],
            "arbitrations": [node.model_dump() for node in LeaseManager(SITINA_HOME).arbitrations(run_id=args.run_id)],
            "side_effect_descriptors": [item.model_dump() for item in SideEffectManager(SITINA_HOME).descriptors(run_id=args.run_id)],
            "replay_status": replay.status,
        }
    )
    return 0


def cmd_goal(args: argparse.Namespace) -> int:
    manager = AutonomyManager(SITINA_HOME)
    if args.goal_cmd == "create":
        result = manager.create_goal(args.title, args.objective)
    elif args.goal_cmd == "list":
        result = manager.list_goals()
    elif args.goal_cmd == "show":
        result = manager.show_goal(args.goal_id)
    elif args.goal_cmd == "pause":
        result = manager.update_goal_status(args.goal_id, "paused")
    elif args.goal_cmd == "resume":
        result = manager.update_goal_status(args.goal_id, "active")
    elif args.goal_cmd == "complete":
        result = manager.update_goal_status(args.goal_id, "completed")
    else:
        raise SystemExit("unknown goal command")
    print_json(result)
    return 0 if result.get("status") == "ok" else 2


def cmd_backlog(args: argparse.Namespace) -> int:
    manager = AutonomyManager(SITINA_HOME)
    if args.backlog_cmd == "list":
        result = manager.list_backlog(status=args.status, goal_id=args.goal_id)
    elif args.backlog_cmd == "show":
        result = manager.show_backlog(args.backlog_item_id)
    elif args.backlog_cmd == "approve":
        result = manager.review_backlog(args.backlog_item_id, "approve")
    elif args.backlog_cmd == "reject":
        result = manager.review_backlog(args.backlog_item_id, "reject", reason=args.reason)
    elif args.backlog_cmd == "create":
        result = manager.create_backlog_candidate(title=args.title, description=args.description, goal_id=args.goal_id, source_agent="cli", priority=args.priority, risk=args.risk)
    elif args.backlog_cmd == "propose-from-run":
        result = manager.propose_from_run(
            run_id=args.run_id,
            title=args.title,
            description=args.description,
            goal_id=args.goal_id,
            source_agent="goal_agent",
            priority=args.priority,
            risk=args.risk,
        )
    else:
        raise SystemExit("unknown backlog command")
    print_json(result)
    return 0 if result.get("status") == "ok" else 2


def cmd_plan(args: argparse.Namespace) -> int:
    result = AutonomyManager(SITINA_HOME).plan_show(args.goal_id)
    print_json(result)
    return 0 if result.get("status") == "ok" else 2


def cmd_backup(args: argparse.Namespace) -> int:
    return _retired_legacy_command("backup", replacement="Production authority backup")


def cmd_restore(args: argparse.Namespace) -> int:
    result = MaintenanceOps(SITINA_HOME).restore(args.archive, approve_now=args.approve_now, apply=args.apply)
    print_json(result)
    return 0 if result.get("status") == "ok" else 3


def cmd_rollback(args: argparse.Namespace) -> int:
    result = MaintenanceOps(SITINA_HOME).rollback_run(args.run_id, approve_now=args.approve_now)
    print_json(result)
    return 0 if result.get("status") == "ok" else 3


def cmd_prune(args: argparse.Namespace) -> int:
    older_than_days = args.older_than_days if args.older_than_days is not None else _parse_older_than(args.older_than)
    result = MaintenanceOps(SITINA_HOME).prune(
        older_than_days=older_than_days,
        dry_run=not args.archive,
        archive=bool(args.archive),
        approve_now=args.approve_now,
    )
    print_json(result)
    return 0 if result.get("status") == "ok" else 3


def _parse_older_than(value: str) -> int:
    raw = str(value or "").strip().lower()
    if raw.endswith("d") and raw[:-1].isdigit():
        return int(raw[:-1])
    raise SystemExit("--older-than must use day syntax such as 30d")


def cmd_export_run(args: argparse.Namespace) -> int:
    return _retired_legacy_command("export-run", replacement="Journal trace/evidence export")


def cmd_audit(args: argparse.Namespace) -> int:
    if args.audit_cmd != "verify":
        raise SystemExit("unknown audit command")
    result = AuditVerifier(SITINA_HOME).verify(args.run_id)
    print_json(result)
    return {"passed": 0, "failed": 1, "incomplete": 3, "stale": 4, "legacy_unverified": 4}.get(str(result.get("status")), 1)


def cmd_export_evidence(args: argparse.Namespace) -> int:
    result = EvidenceBundleManager(SITINA_HOME).export(args.run_id)
    print_json(result)
    return {"passed": 0, "failed": 1, "incomplete": 3}.get(str(result.get("status")), 1)


def cmd_verify_evidence(args: argparse.Namespace) -> int:
    result = EvidenceBundleManager(SITINA_HOME).verify(args.bundle)
    print_json(result)
    return {"passed": 0, "failed": 1, "incomplete": 3}.get(str(result.get("status")), 1)


def cmd_memory(args: argparse.Namespace) -> int:
    if args.memory_cmd == "report":
        if not _bplus_installed():
            print_json({"status": "not_available", "read_only": True, "reason": "B+ authority is not installed"})
            return 2
        try:
            applied = _stable_projection_overlay(_bplus_context())
        except Exception as error:
            print_json({"status": "degraded", "read_only": True, "reason": str(error), "fallback_used": False})
            return 3
        try:
            statuses = {
                str(row[0]): int(row[1])
                for row in applied.connection.execute("SELECT status,count(*) FROM memory_items GROUP BY status")
            }
            episodes = int(applied.connection.execute("SELECT count(*) FROM memory_episodes").fetchone()[0])
        finally:
            applied.close()
        candidates = statuses.get("candidate", 0)
        accepted = statuses.get("accepted", 0)
        total_reviewable = candidates + accepted + statuses.get("rejected", 0)
        print_json(
            {
                "status": "ok",
                "schema": "SITINA_MEMORY_REPORT_V1",
                "read_only": True,
                "status_counts": statuses,
                "memory_candidate_count": candidates,
                "memory_acceptance_rate": round(accepted / total_reviewable, 6) if total_reviewable else 0.0,
                "episode_count": episodes,
                "projection_frontier": applied.applied_through,
                "journal_events_appended": 0,
            }
        )
        return 0
    policy = LegacyRuntimePolicy.load(SITINA_HOME)
    if policy.protected_environment and policy.fully_disabled:
        if not _bplus_installed():
            print_json({
                "status": "blocked",
                "reason": "Journal-native Memory requires a verified B+ runtime context",
                "legacy_read_enabled": False,
                "legacy_write_enabled": False,
                "fallback_attempted": False,
            })
            return 3
        context = _bplus_context()
        mutating = args.memory_cmd in {"accept", "reject"} or (
            args.memory_cmd == "review" and bool(args.accept or args.reject)
        )
        journal = context.open_runtime_writer() if mutating else context.open_runtime_state_reader()
        try:
            activations = (
                FeatureActivationRegistry.from_journal_events(tuple(journal.iter_events(0)))
                if mutating
                else None
            )
            cas = context.open_cas() if mutating else context.open_cas_reader()
            repository = MemoryRepository(
                journal,
                cas,
                context.provider,
                feature_activations=activations,
            )
            actor = "user"
            if args.memory_cmd == "review" and (args.accept or args.reject):
                candidate_id = args.accept or args.reject
                to_status = "accepted" if args.accept else "rejected"
                reason = args.reason or ("review-approved" if args.accept else "review-rejected")
                reason_code = "cli-review-" + hashlib.sha256(reason.encode("utf-8")).hexdigest()[:24]
                document = repository.transition(
                    candidate_id,
                    to_status,
                    actor=actor,
                    occurred_at=iso_now(),
                    reason_code=reason_code,
                )
                result = {"status": "ok", "action": to_status, "memory": document.model_dump(mode="json", by_alias=True)}
            elif args.memory_cmd == "review":
                requested = None if args.status == "all" else {"pending": "candidate"}.get(args.status, args.status)
                memories = repository.retrieve(actor=actor, include_noncurrent=True)
                selected = [item for item in memories if requested is None or item.status == requested]
                result = {
                    "status": "ok",
                    "filter": args.status,
                    "memories": [item.model_dump(mode="json", by_alias=True) for item in selected],
                    "storage_authority": "Canonical Journal",
                    "legacy_fallback_used": False,
                }
            elif args.memory_cmd == "show":
                document, content = repository.get(args.candidate_id, actor=actor)
                result = {
                    "status": "ok",
                    "memory": document.model_dump(mode="json", by_alias=True),
                    "content": content,
                    "storage_authority": "Canonical Journal",
                    "legacy_fallback_used": False,
                }
            elif args.memory_cmd in {"accept", "reject"}:
                to_status = "accepted" if args.memory_cmd == "accept" else "rejected"
                reason = getattr(args, "reason", None) or ("review-approved" if to_status == "accepted" else "review-rejected")
                reason_code = "cli-review-" + hashlib.sha256(reason.encode("utf-8")).hexdigest()[:24]
                document = repository.transition(
                    args.candidate_id,
                    to_status,
                    actor=actor,
                    occurred_at=iso_now(),
                    reason_code=reason_code,
                )
                result = {"status": "ok", "action": to_status, "memory": document.model_dump(mode="json", by_alias=True)}
            else:
                raise SystemExit("unknown memory command")
        except KeyError:
            result = {"status": "not_found", "reason": "memory_id not found"}
        except (MemoryAccessDenied, MemoryStateError, ValueError) as error:
            result = {"status": "blocked", "reason": str(error), "error_type": type(error).__name__}
        finally:
            if mutating:
                journal.close()
        print_json(result)
        if result.get("status") == "ok":
            return 0
        return 2 if result.get("status") == "not_found" else 3

    return _retired_legacy_command("legacy memory", replacement="Journal-native memory")


def cmd_provider(args: argparse.Namespace) -> int:
    if args.provider_cmd == "smoke":
        try:
            result = AnthropicCompatibleClient(SITINA_HOME).smoke(args.profile, max_tokens=args.max_tokens)
        except Exception as exc:  # noqa: BLE001
            print_json({"status": "blocked", "profile": args.profile, "reason": str(exc)})
            return 3
        print_json({"status": "ok" if result["ok"] else "unexpected_response", **result})
        return 0 if result["ok"] else 2
    if args.provider_cmd == "status":
        client = AnthropicCompatibleClient(SITINA_HOME)
        profiles = args.profile or None
        if args.check:
            results = client.health.check_profiles(client, profiles, max_tokens=args.max_tokens)
            ok = all(item.get("status") == "healthy" for item in results)
            print_json({"status": "ok" if ok else "degraded", "checked": True, "profiles": results})
            return 0 if ok else 2
        print_json({"status": "ok", "checked": False, "profiles": client.health.list_status(profiles)})
        return 0
    raise SystemExit("unknown provider command")


def cmd_approve_run(args: argparse.Namespace) -> int:
    return _retired_legacy_command("approve-run", replacement="runtime-scoped effect approval")


def cmd_mcp(args: argparse.Namespace) -> int:
    adapter = McpAdapter(SITINA_HOME)
    if args.mcp_cmd == "list":
        print_json({"status": "ok", "items": adapter.list_registry()})
        return 0
    if args.mcp_cmd == "validate":
        result = adapter.validate_registry()
        print_json(result)
        return 0 if result.get("ok") else 2
    if args.mcp_cmd == "invoke":
        payload = _mcp_payload_from_args(args)
        if args.payload_json:
            try:
                decoded = json.loads(args.payload_json)
            except json.JSONDecodeError as exc:
                print_json({"status": "blocked", "reason": f"invalid --payload-json: {exc}"})
                return 3
            if not isinstance(decoded, dict):
                print_json({"status": "blocked", "reason": "--payload-json must decode to an object"})
                return 3
            payload.update(decoded)
        result = adapter.invoke(args.server, args.tool, payload, run_id=args.run_id, mock=args.mock)
        print_json(result)
        return 0 if result.get("status") in {"ok", "not_git", "mock"} else 3
    raise SystemExit("unknown mcp command")


def _mcp_payload_from_args(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in ("path", "repo", "db_path", "query", "root", "rev", "max_bytes", "limit", "max_count"):
        value = getattr(args, key, None)
        if value is not None:
            payload[key.replace("-", "_")] = value
    return payload


def cmd_obsidian(args: argparse.Namespace) -> int:
    builder = ContextBuilder(SITINA_HOME)
    roots = args.root or None
    if args.obsidian_cmd == "index":
        print_json(builder.index_obsidian(roots, incremental=not args.full))
        return 0
    if args.obsidian_cmd == "search":
        print_json({"status": "ok", "results": builder.retrieve_obsidian(" ".join(args.query), roots)})
        return 0
    raise SystemExit("unknown obsidian command")


def cmd_worktree(args: argparse.Namespace) -> int:
    if args.worktree_cmd == "prepare":
        result = GitWorktreeManager(SITINA_HOME).prepare(args.repo, args.run_id)
        print_json(result)
        return 0 if result.get("status") in {"ok", "not_git"} else 3
    if args.worktree_cmd == "patch":
        result = GitWorktreeManager(SITINA_HOME).generate_patch(args.repo, args.run_id, source=args.source)
        print_json(result)
        return 0 if result.get("status") in {"ok", "no_changes", "not_git"} else 3
    if args.worktree_cmd == "review":
        result = GitWorktreeManager(SITINA_HOME).record_review(args.patch, args.run_id, decision=args.decision, reviewer=args.reviewer, notes=args.notes)
        print_json(result)
        return 0 if result.get("status") == "ok" else 3
    if args.worktree_cmd == "apply":
        result = GitWorktreeManager(SITINA_HOME).apply_patch(args.repo, args.patch, args.run_id, approve=args.approve)
        print_json(result)
        return 0 if result.get("status") in {"ok", "awaiting_user_approval", "not_git"} else 3
    raise SystemExit("unknown worktree command")


def parse_profile_overrides(items: list[str] | None) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit("--profile-override must be AGENT=PROFILE")
        agent, profile = item.split("=", 1)
        agent = agent.strip()
        profile = profile.strip()
        if not agent or not profile:
            raise SystemExit("--profile-override must be AGENT=PROFILE")
        overrides[agent] = profile
    return overrides


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sitina")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("config")
    config_sub = p.add_subparsers(dest="config_cmd", required=True)
    v = config_sub.add_parser("validate")
    v.set_defaults(func=cmd_config)
    e = config_sub.add_parser("export-schemas")
    e.set_defaults(func=cmd_config)

    p = sub.add_parser("doctor")
    p.add_argument("--fix", action="store_true")
    p.add_argument("--approval-id")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("storage")
    storage_sub = p.add_subparsers(dest="storage_cmd", required=True)
    storage_inspect = storage_sub.add_parser("inspect")
    storage_inspect.set_defaults(func=cmd_storage_diagnostics)
    storage_gc = storage_sub.add_parser("gc")
    storage_gc.add_argument("--dry-run", action="store_true")
    storage_gc.add_argument("--grace-seconds", type=int, default=7 * 24 * 3600)
    storage_gc.set_defaults(func=cmd_storage_diagnostics)
    storage_migration = storage_sub.add_parser("migration-plan")
    storage_migration.set_defaults(func=cmd_storage_diagnostics)
    storage_archive = storage_sub.add_parser("archive-plan")
    storage_archive.add_argument("--source", action="append", default=[])
    storage_archive.add_argument("--target", default=str(SITINA_HOME / "cold-archives" / "legacy"))
    storage_archive.set_defaults(func=cmd_storage_diagnostics)

    p = sub.add_parser("journal")
    journal_sub = p.add_subparsers(dest="journal_cmd", required=True)
    journal_startup = journal_sub.add_parser("startup-report")
    journal_startup.set_defaults(func=cmd_journal_diagnostics)
    journal_verify = journal_sub.add_parser("verify")
    journal_verify.add_argument("--full", action="store_true")
    journal_verify.set_defaults(func=cmd_journal_diagnostics)
    journal_scrub = journal_sub.add_parser("scrub")
    journal_scrub.add_argument("--background", action="store_true")
    journal_scrub.set_defaults(func=cmd_journal_diagnostics)

    p = sub.add_parser("projection")
    projection_sub = p.add_subparsers(dest="projection_cmd", required=True)
    projection_report = projection_sub.add_parser("report")
    projection_report.set_defaults(func=cmd_projection_diagnostics)
    projection_coverage = projection_sub.add_parser("coverage")
    projection_coverage.set_defaults(func=cmd_projection_diagnostics)

    p = sub.add_parser("runtime")
    runtime_sub = p.add_subparsers(dest="runtime_cmd", required=True)
    runtime_compatibility = runtime_sub.add_parser("compatibility")
    runtime_compatibility.set_defaults(func=cmd_runtime_diagnostics)

    p = sub.add_parser("loop", help="open the current Loop with automatic routing")
    p.add_argument("--state-root")
    p.add_argument("--workspace")
    p.add_argument("--provider-profile", default="deepseek")
    p.set_defaults(func=cmd_loop)

    p = sub.add_parser("loop-state", help="inspect the isolated r4 batch-1a persistent task skeleton")
    loop_state_sub = p.add_subparsers(dest="loop_state_cmd", required=True)
    loop_initialize = loop_state_sub.add_parser("initialize")
    loop_initialize.add_argument("--state-root", required=True)
    loop_initialize.set_defaults(func=cmd_loop_state)
    loop_create = loop_state_sub.add_parser("create")
    loop_create.add_argument("--state-root", required=True)
    loop_create.add_argument("--task-id", required=True)
    loop_create.add_argument("--session-id", required=True)
    loop_create.add_argument("--task-kind", required=True)
    loop_create.add_argument("--goal", required=True)
    loop_create.add_argument("--required-outcome", action="append", default=[])
    loop_create.add_argument("--artifact-ref", required=True)
    loop_create.add_argument("--environment-ref", required=True)
    loop_create.add_argument("--capability-snapshot-id", required=True)
    loop_create.set_defaults(func=cmd_loop_state)
    loop_status = loop_state_sub.add_parser("status")
    loop_status.add_argument("--state-root", required=True)
    loop_status.add_argument("--task-id", required=True)
    loop_status.add_argument("--dock-restart", action="store_true")
    loop_status.set_defaults(func=cmd_loop_state)

    p = sub.add_parser("loop-task", help="run one guarded sitina-loop-v1-r4 batch-1b task")
    loop_task_sub = p.add_subparsers(dest="loop_task_cmd", required=True)
    loop_retention = loop_task_sub.add_parser(
        "retention", help="explicitly schedule or execute expiry of task-private native memory",
    )
    loop_retention.add_argument("--state-root", required=True)
    loop_retention.add_argument("--workspace", required=True)
    loop_retention.add_argument("--task-id", required=True)
    loop_retention.add_argument("--operation-id", required=True)
    loop_retention.add_argument("--action", choices=["status", "schedule", "execute"], default="status")
    loop_retention.add_argument("--memory-id")
    loop_retention.add_argument("--approval-seconds", type=int, default=3600)
    loop_retention.set_defaults(func=cmd_loop_task)
    loop_boundary = loop_task_sub.add_parser("boundary")
    loop_boundary.add_argument("--state-root", required=True)
    loop_boundary.add_argument("--workspace", required=True)
    loop_boundary.set_defaults(func=cmd_loop_task)
    loop_run = loop_task_sub.add_parser("run")
    loop_run.add_argument("--state-root", required=True)
    loop_run.add_argument("--workspace", required=True)
    loop_run.add_argument("--task-id", required=True)
    loop_run.add_argument(
        "--task-kind",
        choices=["code_change", "readonly", "reviewed_readonly", "no_change"],
        required=True,
    )
    loop_run.add_argument("--goal", required=True)
    loop_run.add_argument("--submission-id")
    loop_run.add_argument("--provider-profile", default="deepseek")
    loop_run.add_argument("--provider-identity")
    loop_run.add_argument("--environment-ref")
    loop_run.add_argument("--capability-snapshot-id")
    loop_run.add_argument("--software-identity")
    loop_run.add_argument("--config-identity")
    loop_run.add_argument("--capability-slot", dest="capability_selection", default="")
    loop_run.add_argument("--check-command-json")
    loop_run.add_argument("--approve-writes", action="store_true")
    loop_run.add_argument("--network-read-url", dest="network_read_urls", action="append", default=[], help="Allow anonymous GET/HEAD for this exact URL in this task; repeat for each endpoint")
    loop_run.set_defaults(func=cmd_loop_task)
    loop_input = loop_task_sub.add_parser("input")
    loop_input.add_argument("--state-root", required=True)
    loop_input.add_argument("--workspace", required=True)
    loop_input.add_argument("--task-id", required=True)
    loop_input.add_argument("--kind", choices=["MESSAGE", "CORRECTION", "CLARIFICATION", "PAUSE", "CANCEL"], required=True)
    loop_input.add_argument("--body", default="")
    loop_input.add_argument("--input-id")
    loop_input.set_defaults(func=cmd_loop_task)
    loop_task_status = loop_task_sub.add_parser("status")
    loop_task_status.add_argument("--state-root", required=True)
    loop_task_status.add_argument("--workspace", required=True)
    loop_task_status.add_argument("--task-id", required=True)
    loop_task_status.set_defaults(func=cmd_loop_task)
    loop_attach = loop_task_sub.add_parser("attach")
    loop_attach.add_argument("--state-root", required=True)
    loop_attach.add_argument("--workspace", required=True)
    loop_attach.add_argument("--task-id", required=True)
    loop_attach.set_defaults(func=cmd_loop_task)
    loop_resume = loop_task_sub.add_parser("resume")
    loop_resume.add_argument("--state-root", required=True)
    loop_resume.add_argument("--workspace", required=True)
    loop_resume.add_argument("--task-id", required=True)
    loop_resume.add_argument("--resume-request-id")
    loop_resume.set_defaults(func=cmd_loop_task)

    p = sub.add_parser("loop-host", help="serve the isolated 3A Loop host")
    host_sub = p.add_subparsers(dest="loop_host_cmd", required=True)
    host_serve = host_sub.add_parser("serve")
    host_serve.add_argument("--state-root", required=True)
    host_serve.add_argument("--workspace", required=True)
    host_serve.add_argument("--provider-profile", default="deepseek")
    host_serve.add_argument("--approve-writes", action="store_true")
    host_serve.add_argument("--resource-policy", help="explicit orchestration policy for this host; bound into task recovery identity")
    host_serve.add_argument("--observability-policy", help="explicit alert policy for this host; bound into task recovery identity")
    host_serve.set_defaults(func=cmd_loop_host)

    p = sub.add_parser("eval")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("policy")
    policy_sub = p.add_subparsers(dest="policy_cmd", required=True)
    pv = policy_sub.add_parser("validate")
    pv.set_defaults(func=cmd_policy)

    p = sub.add_parser("report")
    report_sub = p.add_subparsers(dest="report_cmd", required=True)
    rv1 = report_sub.add_parser("v1")
    rv1.add_argument("--refresh-baseline", action="store_true")
    rv1.set_defaults(func=cmd_report)
    rlive = report_sub.add_parser("live")
    rlive.add_argument("run_id")
    rlive.set_defaults(func=cmd_report)
    racc = report_sub.add_parser("acceptance")
    racc.add_argument("run_id")
    racc.set_defaults(func=cmd_report)

    p = sub.add_parser("run")
    p.add_argument("--provider-mode", choices=["auto", "mock", "live"], default="auto")
    p.add_argument("--profile-override", action="append", default=[])
    p.add_argument("--goal-id")
    p.add_argument("--backlog-item-id")
    p.add_argument("--approve-risky", action="store_true")
    p.add_argument("goal", nargs="+")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("chat", help="retired legacy interactive entry (always blocked)")
    p.add_argument("--workspace", help=argparse.SUPPRESS)
    p.add_argument("--code-mode-state", help=argparse.SUPPRESS)
    p.add_argument("--offline-scripted", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--access-mode", choices=["workspace", "full"], default="workspace", help=argparse.SUPPRESS)
    p.add_argument("--profile", help=argparse.SUPPRESS)
    # Retain old spellings only so stale invocations reach the safe refusal.
    live_group = p.add_mutually_exclusive_group()
    live_group.add_argument("--live", action="store_true", default=True, dest="live", help=argparse.SUPPRESS)
    live_group.add_argument("--no-live", action="store_false", dest="live", help=argparse.SUPPRESS)
    p.add_argument("--allow-self-modify", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_chat)

    p = sub.add_parser("agent", help="run the Sitina autonomous multi-turn tool loop")
    agent_provider = p.add_mutually_exclusive_group()
    agent_provider.add_argument("--profile")
    agent_provider.add_argument("--mock-script")
    p.add_argument("--workspace")
    p.add_argument("--max-tokens", type=int, default=4096)
    p.add_argument("--max-turns", type=int, default=50, help="hard cap on agent tool-loop turns (graceful stop)")
    p.add_argument("--approve-risky", action="store_true", help="approve every risky tool call in this run")
    p.add_argument("task", nargs="+")
    p.set_defaults(func=cmd_agent)

    p = sub.add_parser("plugin", help="manage global Sitina-native plugins")
    plugin_sub = p.add_subparsers(dest="plugin_cmd", required=True)
    plugin_list = plugin_sub.add_parser("list")
    plugin_list.set_defaults(func=cmd_plugin)
    plugin_install = plugin_sub.add_parser("install")
    plugin_install.add_argument("source")
    plugin_install.add_argument("--grant", action="append", default=[])
    plugin_install.add_argument("--approve-network", action="store_true")
    plugin_install.add_argument("--sha256")
    plugin_install.add_argument("--git-ref")
    plugin_install.set_defaults(func=cmd_plugin)
    plugin_update = plugin_sub.add_parser("update")
    plugin_update.add_argument("name")
    plugin_update.add_argument("--source")
    plugin_update.add_argument("--grant", action="append", default=[])
    plugin_update.add_argument("--approve-network", action="store_true")
    plugin_update.add_argument("--sha256")
    plugin_update.add_argument("--git-ref")
    plugin_update.set_defaults(func=cmd_plugin)
    plugin_rollback = plugin_sub.add_parser("rollback")
    plugin_rollback.add_argument("name")
    plugin_rollback.add_argument("--to")
    plugin_rollback.set_defaults(func=cmd_plugin)
    plugin_disable = plugin_sub.add_parser("disable")
    plugin_disable.add_argument("name")
    plugin_disable.set_defaults(func=cmd_plugin)
    marketplace_add = plugin_sub.add_parser("marketplace-add")
    marketplace_add.add_argument("source")
    marketplace_add.add_argument("--approve-network", action="store_true")
    marketplace_add.set_defaults(func=cmd_plugin)
    marketplace_list = plugin_sub.add_parser("marketplace-list")
    marketplace_list.set_defaults(func=cmd_plugin)
    marketplace_install = plugin_sub.add_parser("marketplace-install")
    marketplace_install.add_argument("marketplace")
    marketplace_install.add_argument("name")
    marketplace_install.add_argument("--grant", action="append", default=[])
    marketplace_install.add_argument("--approve-network", action="store_true")
    marketplace_install.set_defaults(func=cmd_plugin)

    p = sub.add_parser("skill", help="manage global Sitina-native Skills")
    skill_sub = p.add_subparsers(dest="skill_cmd", required=True)
    skill_list = skill_sub.add_parser("list")
    skill_list.set_defaults(func=cmd_skill)
    skill_install = skill_sub.add_parser("install")
    skill_install.add_argument("source")
    skill_install.set_defaults(func=cmd_skill)
    skill_show = skill_sub.add_parser("show")
    skill_show.add_argument("name")
    skill_show.set_defaults(func=cmd_skill)
    skill_rollback = skill_sub.add_parser("rollback")
    skill_rollback.add_argument("name")
    skill_rollback.add_argument("--to")
    skill_rollback.set_defaults(func=cmd_skill)
    skill_disable = skill_sub.add_parser("disable")
    skill_disable.add_argument("name")
    skill_disable.set_defaults(func=cmd_skill)

    p = sub.add_parser("ask")
    p.add_argument("--provider-mode", choices=["mock", "live"], default="mock")
    p.add_argument("--profile-override", action="append", default=[])
    p.add_argument("goal", nargs="+")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("code-mode", help="show read-only Code Mode candidate status")
    p.add_argument("code_mode_cmd", choices=["status"], nargs="?", default="status")
    p.add_argument("--workspace", default=str(SITINA_HOME))
    p.set_defaults(func=cmd_code_mode)

    p = sub.add_parser("resume")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("cancel")
    p.add_argument("run_id")
    p.add_argument("--reason", default="cancel requested by user")
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("checkpoint")
    checkpoint_sub = p.add_subparsers(dest="checkpoint_cmd", required=True)
    checkpoint_list = checkpoint_sub.add_parser("list")
    checkpoint_list.add_argument("--run-id", required=True)
    checkpoint_list.set_defaults(func=cmd_checkpoint)
    checkpoint_show = checkpoint_sub.add_parser("show")
    checkpoint_show.add_argument("checkpoint_id")
    checkpoint_show.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("trace")
    p.add_argument("run_id")
    p.add_argument("--query", action="store_true", help="return a paginated, read-only structured trace query")
    p.add_argument("--agent")
    p.add_argument("--tool")
    p.add_argument("--status")
    p.add_argument("--started-at")
    p.add_argument("--ended-at")
    p.add_argument("--correlation-id")
    p.add_argument("--cursor", type=int, default=0)
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("replay")
    p.add_argument("run_id", nargs="+")
    p.add_argument("--sandbox", nargs="?", const=str(SITINA_HOME / "temp" / "replay-sandbox"))
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("cost-status")
    p.add_argument("run_id")
    p.add_argument("--hard-limit-tokens", type=int, default=100000)
    p.add_argument("--forecast-additional-tokens", type=int, default=0)
    p.set_defaults(func=cmd_cost_status)

    p = sub.add_parser("suggest", help="preview automatic routing without Provider calls or side effects")
    p.add_argument("description", nargs="+")
    p.add_argument("--budget-tokens", type=int)
    p.add_argument("--sla-class", choices=_SUGGEST_LATENCY_CLASS_CHOICES, default="standard")
    p.add_argument("--sla-remaining-ms", type=int)
    p.add_argument("--context")
    p.add_argument("--prior-complexity", type=int, default=0)
    p.add_argument("--unfinished-goal", action="store_true")
    p.add_argument("--task-type", choices=sorted(TASK_TYPES))
    p.add_argument("--risk", choices=["low", "medium", "high", "critical"])
    p.add_argument("--topology", choices=["pipeline", "supervisor", "network", "hierarchy"])
    p.set_defaults(func=cmd_suggest)

    p = sub.add_parser("goal")
    goal_sub = p.add_subparsers(dest="goal_cmd", required=True)
    gc = goal_sub.add_parser("create")
    gc.add_argument("title")
    gc.add_argument("objective")
    gc.set_defaults(func=cmd_goal)
    gl = goal_sub.add_parser("list")
    gl.set_defaults(func=cmd_goal)
    gs = goal_sub.add_parser("show")
    gs.add_argument("goal_id")
    gs.set_defaults(func=cmd_goal)
    gp = goal_sub.add_parser("pause")
    gp.add_argument("goal_id")
    gp.set_defaults(func=cmd_goal)
    gr = goal_sub.add_parser("resume")
    gr.add_argument("goal_id")
    gr.set_defaults(func=cmd_goal)
    gd = goal_sub.add_parser("complete")
    gd.add_argument("goal_id")
    gd.set_defaults(func=cmd_goal)

    p = sub.add_parser("backlog")
    backlog_sub = p.add_subparsers(dest="backlog_cmd", required=True)
    bc = backlog_sub.add_parser("create")
    bc.add_argument("title")
    bc.add_argument("description")
    bc.add_argument("--goal-id")
    bc.add_argument("--priority", type=int, default=3)
    bc.add_argument("--risk", choices=["low", "medium", "high", "critical"], default="low")
    bc.set_defaults(func=cmd_backlog)
    bp = backlog_sub.add_parser("propose-from-run")
    bp.add_argument("run_id")
    bp.add_argument("title")
    bp.add_argument("description")
    bp.add_argument("--goal-id")
    bp.add_argument("--priority", type=int, default=3)
    bp.add_argument("--risk", choices=["low", "medium", "high", "critical"], default="low")
    bp.set_defaults(func=cmd_backlog)
    bl = backlog_sub.add_parser("list")
    bl.add_argument("--status", default=None)
    bl.add_argument("--goal-id")
    bl.set_defaults(func=cmd_backlog)
    bs = backlog_sub.add_parser("show")
    bs.add_argument("backlog_item_id")
    bs.set_defaults(func=cmd_backlog)
    ba = backlog_sub.add_parser("approve")
    ba.add_argument("backlog_item_id")
    ba.set_defaults(func=cmd_backlog)
    br = backlog_sub.add_parser("reject")
    br.add_argument("backlog_item_id")
    br.add_argument("--reason", default="Rejected by reviewer.")
    br.set_defaults(func=cmd_backlog)

    p = sub.add_parser("plan")
    plan_sub = p.add_subparsers(dest="plan_cmd", required=True)
    ps = plan_sub.add_parser("show")
    ps.add_argument("goal_id")
    ps.set_defaults(func=cmd_plan)

    p = sub.add_parser("agents")
    agents_sub = p.add_subparsers(dest="agents_cmd", required=True)
    ast = agents_sub.add_parser("status")
    ast.set_defaults(func=cmd_agents)

    p = sub.add_parser("proposals")
    proposals_sub = p.add_subparsers(dest="proposals_cmd", required=True)
    pl = proposals_sub.add_parser("list")
    pl.add_argument("--run-id", required=True)
    pl.set_defaults(func=cmd_proposals)
    ps = proposals_sub.add_parser("show")
    ps.add_argument("proposal_id")
    ps.set_defaults(func=cmd_proposals)

    p = sub.add_parser("blackboard")
    blackboard_sub = p.add_subparsers(dest="blackboard_cmd", required=True)
    bs = blackboard_sub.add_parser("show")
    bs.add_argument("--run-id", required=True)
    bs.add_argument("--type")
    bs.set_defaults(func=cmd_blackboard)

    p = sub.add_parser("handoff")
    handoff_sub = p.add_subparsers(dest="handoff_cmd", required=True)
    hl = handoff_sub.add_parser("list")
    hl.add_argument("--run-id")
    hl.set_defaults(func=cmd_handoff)
    hs = handoff_sub.add_parser("show")
    hs.add_argument("handoff_id")
    hs.set_defaults(func=cmd_handoff)

    p = sub.add_parser("lease")
    lease_sub = p.add_subparsers(dest="lease_cmd", required=True)
    ll = lease_sub.add_parser("list")
    ll.add_argument("--run-id")
    ll.set_defaults(func=cmd_lease)
    ls = lease_sub.add_parser("show")
    ls.add_argument("lease_id")
    ls.set_defaults(func=cmd_lease)

    p = sub.add_parser("arbitration")
    arbitration_sub = p.add_subparsers(dest="arbitration_cmd", required=True)
    al = arbitration_sub.add_parser("list")
    al.add_argument("--run-id")
    al.set_defaults(func=cmd_arbitration)
    ash = arbitration_sub.add_parser("show")
    ash.add_argument("arbitration_id")
    ash.set_defaults(func=cmd_arbitration)

    p = sub.add_parser("effects")
    effects_sub = p.add_subparsers(dest="effects_cmd", required=True)
    effects_list = effects_sub.add_parser("list")
    effects_list.add_argument("--run-id", required=True)
    effects_list.set_defaults(func=cmd_bplus_protocol_status, protocol_family="effects")

    p = sub.add_parser("evidence")
    evidence_sub = p.add_subparsers(dest="evidence_cmd", required=True)
    evidence_status = evidence_sub.add_parser("status")
    evidence_status.add_argument("--run-id", required=True)
    evidence_status.set_defaults(func=cmd_bplus_protocol_status, protocol_family="evidence")

    p = sub.add_parser("archive")
    archive_sub = p.add_subparsers(dest="archive_cmd", required=True)
    archive_status = archive_sub.add_parser("status")
    archive_status.add_argument("--run-id", required=True)
    archive_status.set_defaults(func=cmd_bplus_protocol_status, protocol_family="archive")

    p = sub.add_parser("backup")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("legacy")
    legacy_sub = p.add_subparsers(dest="legacy_cmd", required=True)
    legacy_status = legacy_sub.add_parser("status")
    legacy_status.set_defaults(func=cmd_legacy)
    legacy_inventory = legacy_sub.add_parser("inventory")
    legacy_inventory.add_argument("--output", required=True)
    legacy_inventory.set_defaults(func=cmd_legacy)

    p = sub.add_parser("restore")
    p.add_argument("archive")
    p.add_argument("--approval-id")
    p.add_argument("--approve-now", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("rollback")
    p.add_argument("run_id")
    p.add_argument("--approval-id")
    p.add_argument("--approve-now", action="store_true")
    p.set_defaults(func=cmd_rollback)

    p = sub.add_parser("prune")
    p.add_argument("--older-than", default="30d")
    p.add_argument("--older-than-days", type=int, default=None, help=argparse.SUPPRESS)
    prune_mode = p.add_mutually_exclusive_group()
    prune_mode.add_argument("--dry-run", action="store_true")
    prune_mode.add_argument("--archive", action="store_true")
    p.add_argument("--approval-id")
    p.add_argument("--approve-now", action="store_true")
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser("export-run")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_export_run)

    p = sub.add_parser("audit")
    audit_sub = p.add_subparsers(dest="audit_cmd", required=True)
    verify = audit_sub.add_parser("verify")
    verify.add_argument("run_id")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_audit)

    p = sub.add_parser("export-evidence")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_export_evidence)

    p = sub.add_parser("verify-evidence")
    p.add_argument("bundle")
    p.set_defaults(func=cmd_verify_evidence)

    p = sub.add_parser("memory")
    mem_sub = p.add_subparsers(dest="memory_cmd", required=True)
    r = mem_sub.add_parser("review")
    r.add_argument("--status", choices=["pending", "accepted", "rejected", "blocked", "persist_failed", "all"], default="pending")
    r.add_argument("--accept")
    r.add_argument("--reject")
    r.add_argument("--reason")
    r.set_defaults(func=cmd_memory)
    show = mem_sub.add_parser("show")
    show.add_argument("candidate_id")
    show.set_defaults(func=cmd_memory)
    accept = mem_sub.add_parser("accept")
    accept.add_argument("candidate_id")
    accept.set_defaults(func=cmd_memory)
    reject = mem_sub.add_parser("reject")
    reject.add_argument("candidate_id")
    reject.add_argument("--reason", default="Rejected by reviewer.")
    reject.set_defaults(func=cmd_memory)
    memory_report = mem_sub.add_parser("report")
    memory_report.set_defaults(func=cmd_memory)

    p = sub.add_parser("provider")
    provider_sub = p.add_subparsers(dest="provider_cmd", required=True)
    smoke = provider_sub.add_parser("smoke")
    smoke.add_argument("profile")
    smoke.add_argument("--max-tokens", type=int, default=128)
    smoke.set_defaults(func=cmd_provider)
    status = provider_sub.add_parser("status")
    status.add_argument("profile", nargs="*")
    status.add_argument("--check", action="store_true")
    status.add_argument("--max-tokens", type=int, default=64)
    status.set_defaults(func=cmd_provider)

    p = sub.add_parser("approve-run")
    p.add_argument("run_id")
    p.add_argument("--action", choices=["approve", "reject", "request_changes"], default="approve")
    p.add_argument("--file", action="append", default=[])
    p.add_argument("--no-continue", action="store_true")
    p.set_defaults(func=cmd_approve_run)

    p = sub.add_parser("mcp")
    mcp_sub = p.add_subparsers(dest="mcp_cmd", required=True)
    list_cmd = mcp_sub.add_parser("list")
    list_cmd.set_defaults(func=cmd_mcp)
    validate = mcp_sub.add_parser("validate")
    validate.set_defaults(func=cmd_mcp)
    invoke = mcp_sub.add_parser("invoke")
    invoke.add_argument("server")
    invoke.add_argument("tool")
    invoke.add_argument("--payload-json")
    invoke.add_argument("--run-id", default="mcp_manual")
    invoke.add_argument("--mock", action="store_true")
    invoke.add_argument("--path")
    invoke.add_argument("--repo")
    invoke.add_argument("--db-path", dest="db_path")
    invoke.add_argument("--query")
    invoke.add_argument("--root")
    invoke.add_argument("--rev")
    invoke.add_argument("--max-bytes", dest="max_bytes", type=int)
    invoke.add_argument("--limit", type=int)
    invoke.add_argument("--max-count", dest="max_count", type=int)
    invoke.set_defaults(func=cmd_mcp)

    p = sub.add_parser("obsidian")
    obsidian_sub = p.add_subparsers(dest="obsidian_cmd", required=True)
    idx = obsidian_sub.add_parser("index")
    idx.add_argument("--root", action="append", default=[])
    idx.add_argument("--full", action="store_true")
    idx.set_defaults(func=cmd_obsidian)
    search = obsidian_sub.add_parser("search")
    search.add_argument("--root", action="append", default=[])
    search.add_argument("query", nargs="+")
    search.set_defaults(func=cmd_obsidian)

    p = sub.add_parser("worktree")
    worktree_sub = p.add_subparsers(dest="worktree_cmd", required=True)
    prepare = worktree_sub.add_parser("prepare")
    prepare.add_argument("--repo", default=str(SITINA_HOME))
    prepare.add_argument("--run-id", default="manual")
    prepare.set_defaults(func=cmd_worktree)
    patch = worktree_sub.add_parser("patch")
    patch.add_argument("--repo", default=str(SITINA_HOME))
    patch.add_argument("--source")
    patch.add_argument("--run-id", default="manual")
    patch.set_defaults(func=cmd_worktree)
    review = worktree_sub.add_parser("review")
    review.add_argument("--patch", required=True)
    review.add_argument("--run-id", default="manual")
    review.add_argument("--decision", choices=["accept", "reject", "needs_changes"], default="accept")
    review.add_argument("--reviewer", default="cli")
    review.add_argument("--notes", default="")
    review.set_defaults(func=cmd_worktree)
    apply = worktree_sub.add_parser("apply")
    apply.add_argument("--repo", default=str(SITINA_HOME))
    apply.add_argument("--patch", required=True)
    apply.add_argument("--run-id", default="manual")
    apply.add_argument("--approve", action="store_true")
    apply.set_defaults(func=cmd_worktree)
    return parser


def _install_legacy_fence_for_explicit_command(home: Path) -> None:
    """Load the process-global Legacy fence only at an old-command boundary."""

    from sitina.legacy.fence import install_legacy_mutation_guard

    install_legacy_mutation_guard(home)


def main(argv: list[str] | None = None) -> int:
    global _LAST_PRINTED_JSON
    _LAST_PRINTED_JSON = None
    parser = build_parser()
    args = parser.parse_args(argv)
    # The retired chat boundary is intentionally earlier than every runtime,
    # policy, state, workspace, Provider, and evidence lookup.
    if args.func is cmd_chat:
        return int(cmd_chat(args))
    # The current Loop owns its Journal/CAS state and must not consult the
    # retired Legacy policy before establishing that authority.
    if args.func is cmd_loop:
        return int(cmd_loop(args))
    policy = LegacyRuntimePolicy.load(SITINA_HOME)
    # NOTE: cmd_agent was removed from this set. It was grouped here because the
    # OLD agent depended on retired Legacy state files; the current cmd_agent
    # builds the Journal/CAS-native AutonomousRuntime and touches none of them.
    # It is now the explicit production coder entry (M1.6, journal-audit-only).
    legacy_only_handlers = {
        cmd_legacy,
        cmd_goal,
        cmd_backlog,
        cmd_plan,
        cmd_obsidian,
        cmd_worktree,
        cmd_resume,
        cmd_cancel,
        cmd_checkpoint,
        cmd_backup,
        cmd_restore,
        cmd_rollback,
        cmd_prune,
        cmd_export_run,
        cmd_approve_run,
    }
    legacy_run_graph = (
        args.func is cmd_run
        and bool(getattr(args, "goal", ()))
        and args.goal[0] == "graph"
    )
    legacy_mcp_invoke = args.func is cmd_mcp and getattr(args, "mcp_cmd", None) == "invoke"
    legacy_boundary = args.func in legacy_only_handlers or legacy_run_graph or legacy_mcp_invoke
    if policy.protected_environment and policy.fully_disabled and legacy_boundary:
        print_json({
            "status": "blocked",
            "reason": "command belongs to the retired Legacy runtime and has no Journal-native implementation",
            "legacy_read_enabled": False,
            "legacy_write_enabled": False,
            "fallback_attempted": False,
        })
        return 3
    if legacy_boundary:
        _install_legacy_fence_for_explicit_command(SITINA_HOME)
    exit_code = int(args.func(args))
    evidence_target = CliEvidenceRecorder.command_for_args(args)
    if evidence_target and not _bplus_installed() and not getattr(args, "_cli_evidence_recorded", False):
        command_name, run_id = evidence_target
        CliEvidenceRecorder(SITINA_HOME).record(run_id, command_name, exit_code, _LAST_PRINTED_JSON)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
