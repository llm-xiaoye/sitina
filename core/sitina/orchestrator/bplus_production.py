from __future__ import annotations

import hashlib
import json
import time
import uuid
import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from sitina.authority.model import AuthorityResolution
from sitina.commands.model import CommandEnvelope
from sitina.cas.crypto import decrypt_object, encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import EncryptedObject, ObjectEnvelope, ObjectRef
from sitina.journal.local import LocalJournal
from sitina.journal.fast_start import (
    AutomaticRolloverCoordinator,
    FullJournalVerifier,
    JournalFastStartMaintainer,
    RollbackAnchorStore,
    RolloverPolicy,
)
from sitina.journal.model import EventEnvelope, FrontierRef, canonical_json_bytes, domain_hash
from sitina.legacy.fence import LegacyWriteGate
from sitina.legacy.production_genesis import GenesisArtifact, ProductionGenesisBuilder
from sitina.operations.phase6b import ProductionAuthorityReadResult, ProductionAuthorityReader
from sitina.projections.production import production_handlers
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE
from sitina.projections.generations import ProjectionGenerationError, ProjectionGenerationReader
from sitina.projections.rebuild import ProjectionGeneration
from sitina.cas.gc import SemanticRootIndex
from sitina.compatibility.capabilities import FormatCapabilityRegistry
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.security.key_provider import JournalAuthProvider
from sitina.security.macos_keychain import KeychainBackend, MacOSKeychainProvider, MemoryKeychainBackend
from sitina.storage import DisabledLegacyStore, LegacyRuntimePolicy, LegacySnapshotStore


class BPlusProductionRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifiedJournalReadView:
    events: tuple[EventEnvelope, ...]
    authority_head_position: int | None = None
    reader_generation: str = "bplus-journal-full-verify-v1"
    authority_checkpoint_commitment: str | None = None
    projection_generation_id: str | None = None

    @property
    def head_position(self) -> int:
        if self.authority_head_position is not None:
            return self.authority_head_position
        return self.events[-1].position if self.events else 0

    def iter_events(self, after_position: int = 0):
        return iter(event for event in self.events if event.position > after_position)

    def close(self) -> None:
        """Match the Journal reader lifecycle without owning a writer or fd."""

    def __enter__(self) -> "VerifiedJournalReadView":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


@dataclass
class RuntimeStateJournalView:
    """Delegate writes to Journal while adding signed Projection state reads."""

    journal: LocalJournal
    state: VerifiedJournalReadView

    @property
    def head_position(self) -> int:
        return self.journal.head_position

    def iter_events(self, after_position: int = 0):
        by_position: dict[int, EventEnvelope] = {}
        for event in (*self.state.events, *tuple(self.journal.iter_events(after_position))):
            if event.position <= after_position:
                continue
            existing = by_position.get(event.position)
            if existing is not None and existing.event_hash != event.event_hash:
                raise BPlusProductionRuntimeError("runtime state Projection conflicts with authenticated Journal tail")
            by_position[event.position] = event
        return tuple(by_position[position] for position in sorted(by_position))

    def close(self) -> None:
        self.journal.close()

    def __enter__(self) -> "RuntimeStateJournalView":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.journal, name)


def _key_environment(environment_kind: str) -> str:
    values = {
        "PRODUCTION": "production",
        "CONTROLLED_PRODUCTION_SIMULATION": "production-simulation",
    }
    try:
        return values[environment_kind]
    except KeyError as error:
        raise BPlusProductionRuntimeError("Production Genesis has an unsupported environment") from error


def _journal_epoch(epoch_root: str) -> int:
    try:
        value = int(epoch_root.rsplit("-", 1)[1])
    except (IndexError, ValueError) as error:
        raise BPlusProductionRuntimeError("Production Genesis epoch root has no numeric epoch") from error
    if value < 1:
        raise BPlusProductionRuntimeError("Production Genesis epoch must be positive")
    return value


@dataclass
class ProductionRuntimeContext:
    """Reopen Production entirely from durable Genesis, fence, Keychain, and Journal bytes."""

    home: Path
    genesis: GenesisArtifact
    fence_record: dict[str, object]
    provider: MacOSKeychainProvider
    authority: ProductionAuthorityReadResult
    legacy: LegacySnapshotStore | DisabledLegacyStore
    legacy_policy: LegacyRuntimePolicy
    _restored_simulation_namespace: bool = field(default=False, repr=False)
    _rollback_anchor_backend: KeychainBackend | None = field(default=None, repr=False)
    _full_events_cache: tuple[EventEnvelope, ...] | None = field(default=None, init=False, repr=False)

    @classmethod
    def load(
        cls,
        home: Path,
        *,
        now: int | None = None,
        keychain_backend: KeychainBackend | None = None,
        allow_simulation: bool = False,
    ) -> "ProductionRuntimeContext":
        root = Path(home).expanduser().resolve(strict=True)
        moment = int(time.time()) if now is None else int(now)
        genesis = ProductionGenesisBuilder(root).load_persisted()
        if genesis.environment_kind == "PRODUCTION":
            if root != Path("/Users/moss/SitinaHub"):
                raise BPlusProductionRuntimeError("Production Genesis is installed under an unexpected root")
        elif not allow_simulation or not (root / ".sitina-bplus-disposable-v1").is_file():
            raise BPlusProductionRuntimeError("controlled Production simulation was not explicitly enabled")
        gate = LegacyWriteGate(root)
        try:
            record = gate.read_verified_record()
        except Exception as error:
            raise BPlusProductionRuntimeError("Production Legacy writer fence is invalid") from error
        if record is None or record.get("state") != "FROZEN_NO_WRITER":
            raise BPlusProductionRuntimeError("Production runtime requires the durable Legacy no-writer fence")
        if record.get("production_genesis_journal_id") != genesis.journal_id:
            raise BPlusProductionRuntimeError("Production fence and Genesis Journal identities differ")
        if record.get("intended_snapshot_hash") != genesis.intended_snapshot_hash:
            raise BPlusProductionRuntimeError("Production fence and Genesis snapshot intents differ")
        policy = LegacyRuntimePolicy.load(root)
        policy_errors = policy.validate_protected()
        if policy_errors:
            raise BPlusProductionRuntimeError("; ".join(policy_errors))
        unexpected_sqlite = policy.unexpected_sqlite_artifacts(root)
        if unexpected_sqlite:
            names = ",".join(path.name for path in unexpected_sqlite)
            raise BPlusProductionRuntimeError(
                "Production runtime is fail-closed because retired live SQLite artifacts exist: " + names
            )
        if policy.fully_disabled:
            legacy: LegacySnapshotStore | DisabledLegacyStore = DisabledLegacyStore(policy)
        else:
            snapshot_text = record.get("snapshot_destination")
            if not isinstance(snapshot_text, str) or not Path(snapshot_text).is_absolute():
                raise BPlusProductionRuntimeError("Production fence lacks an absolute frozen snapshot destination")
            legacy = LegacySnapshotStore(Path(snapshot_text), intended_snapshot_hash=genesis.intended_snapshot_hash)
        provider = MacOSKeychainProvider(
            environment=_key_environment(genesis.environment_kind),
            namespace=genesis.key_namespace,
            backend=keychain_backend,
        )
        authenticator = JournalAuthProvider(provider)
        try:
            authority = ProductionAuthorityReader.resolve(
                root,
                authenticator,
                journal_id=genesis.journal_id,
                epoch=_journal_epoch(genesis.epoch_root),
                command_id=str(record["cutover_command_id"]),
                request_hash=str(record["cutover_request_hash"]),
                genesis_hash=genesis.genesis_hash,
                snapshot_hash=genesis.intended_snapshot_hash,
                fence_record_hash=str(record["record_hash"]),
                now=moment,
                authority_key_provider=provider,
                rollback_anchor=RollbackAnchorStore(provider.backend, journal_id=genesis.journal_id),
            )
        except Exception as error:
            raise BPlusProductionRuntimeError("Production authority cannot be reconstructed from durable Journal bytes") from error
        if not authority.resolution.authorizes_journal or authority.resolution.writer_count != 1:
            raise BPlusProductionRuntimeError(
                f"Production runtime is fail-closed: {authority.resolution.state.value}"
            )
        return cls(root, genesis, dict(record), provider, authority, legacy, policy)

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self.authority.events)

    def _verified_history_events(self) -> tuple[EventEnvelope, ...]:
        """Explicit slow path for history/trace/replay; never used by list."""

        fast_start_report = getattr(self.authority, "fast_start_report", None)
        if fast_start_report is None:
            return self.events
        if self._full_events_cache is None:
            report = FullJournalVerifier(
                self.home,
                journal_authenticator=JournalAuthProvider(self.provider),
                authority_key_provider=self.provider,
            ).verify()
            if report.authority_state != fast_start_report.authority_state:
                raise BPlusProductionRuntimeError("full history verification differs from fast-start Authority state")
            self._full_events_cache = tuple(report.verified_events)
        return self._full_events_cache

    def _storage_namespace_kind(self) -> str:
        if self._restored_simulation_namespace:
            if (
                self.home == Path("/Users/moss/SitinaHub")
                or not (self.home / ".sitina-bplus-disposable-v1").is_file()
                or self.genesis.environment_kind != "PRODUCTION"
                or not isinstance(self._rollback_anchor_backend, MemoryKeychainBackend)
            ):
                raise BPlusProductionRuntimeError("restored Production simulation isolation is invalid")
            return "production_simulation"
        return "production" if self.genesis.environment_kind == "PRODUCTION" else "production_simulation"

    def open_writer(self) -> LocalJournal:
        authenticator = JournalAuthProvider(self.provider)
        journal = LocalJournal.open(
            self.home,
            authenticator,
            journal_id=self.genesis.journal_id,
            epoch=_journal_epoch(self.genesis.epoch_root),
            namespace_kind=self._storage_namespace_kind(),
            authority_resolution=self.authority.resolution,
            genesis_hash=self.genesis.genesis_hash,
            fast_start_report=getattr(self.authority, "fast_start_report", None),
        )
        feature_state = FeatureActivationRegistry.from_journal_events(self.events)
        authority_checkpoint_feature = feature_state.state("authority_checkpoint_v1_write")
        if authority_checkpoint_feature is None or authority_checkpoint_feature.state != "ACTIVATED":
            return journal
        registry_path = self.home / "config/format_capabilities.json"
        if not registry_path.is_file() and self.genesis.environment_kind == "CONTROLLED_PRODUCTION_SIMULATION":
            # Disposable Production simulations intentionally contain only
            # durable runtime state.  Bind them to the installed code's
            # capability registry without weakening the real Production path.
            registry_path = Path(__file__).resolve().parents[3] / "config/format_capabilities.json"
        registry = FormatCapabilityRegistry.load(registry_path)
        anchor = RollbackAnchorStore(
            self._rollback_anchor_backend or self.provider.backend,
            journal_id=self.genesis.journal_id,
        )
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=authenticator,
            authority_key_provider=self.provider,
            rollback_anchor=anchor,
            schema_registry_hash=registry.registry_hash,
            feature_activations=feature_state,
        )

        def semantic_roots_at(frontier: int) -> tuple[dict[str, object], ...]:
            events = tuple(event for event in journal.iter_events_authoritative_slow() if event.position <= frontier)
            roots = SemanticRootIndex()
            roots.apply_tail(events)
            return tuple(root.mapping() for root in roots.roots)

        resolution_hash = domain_hash(
            "AUTHORITY_FENCING_STATE",
            canonical_json_bytes(
                {
                    "state": self.authority.resolution.state.value,
                    "writer_count": self.authority.resolution.writer_count,
                    "issued_at": self.authority.resolution.issued_at,
                    "expires_at": self.authority.resolution.expires_at,
                    "resolution_id": self.authority.resolution.resolution_id,
                    "input_frontier_hash": self.authority.resolution.input_frontier_hash,
                }
            ),
        )

        def checkpoint_context(_reason: str) -> dict[str, object]:
            now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            current_feature_state = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
            active_features = [
                value
                for name in (
                    "journal_event_v2_write",
                    "checkpoint_v2_write",
                    "authority_checkpoint_v1_write",
                    "evidence_v2_write",
                    "agent_context_v2_write",
                    "memory_v1_write",
                    "cas_zstd_write",
                    "alias_pack_v1_write",
                    "trash_bundle_v1_write",
                    "projection_v2_build",
                )
                if (value := current_feature_state.state(name)) is not None and value.state == "ACTIVATED"
            ]
            rollback_floor = max((value.rollback_floor_version for value in active_features), default=1)
            active_capabilities_hash = current_feature_state.active_capabilities_hash
            return {
                "created_at": now,
                "verified_at": now,
                "authority_control_state_hash": "0" * 64,
                "active_format_capabilities_hash": active_capabilities_hash,
                "fencing_state_hash": resolution_hash,
                "minimum_writer_version": str(rollback_floor),
                "rollback_floor_version": str(rollback_floor),
                "semantic_active_roots_builder": semantic_roots_at,
            }

        journal.attach_rollover_coordinator(
            AutomaticRolloverCoordinator(
                maintainer,
                policy=RolloverPolicy(),
                checkpoint_context=checkpoint_context,
            )
        )
        return journal

    def open_cas(self) -> LocalCAS:
        """Open the CAS under the same resolved Production authority as Journal."""

        return LocalCAS.open(
            self.home,
            self.provider,
            namespace_kind=self._storage_namespace_kind(),
            authority_resolution=self.authority.resolution,
            genesis_hash=self.genesis.genesis_hash,
            feature_activations=FeatureActivationRegistry.from_journal_events(self.events),
        )

    def open_verified_journal_reader(self) -> VerifiedJournalReadView:
        return VerifiedJournalReadView(self._verified_history_events())

    @staticmethod
    def _runtime_event_from_row(row: Sequence[object]) -> EventEnvelope:
        try:
            payload = json.loads(str(row[7]))
            object_refs = tuple(json.loads(str(row[8])))
            event = EventEnvelope(
                event_id=str(row[1]),
                event_type=str(row[2]),
                tenant_id=str(row[3]),
                stream_id=str(row[4]),
                stream_version=int(row[5]),
                position=int(row[0]),
                occurred_at=str(row[6]),
                payload=payload,
                object_refs=object_refs,
                schema_major=int(row[9]),
                event_hash=str(row[10]) if row[10] is not None else None,
                journal_auth_key_id=str(row[11]) if row[11] is not None else None,
                journal_auth_tag=str(row[12]) if row[12] is not None else None,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BPlusProductionRuntimeError("runtime state Projection contains an invalid event envelope") from error
        if event.event_hash is None or event.computed_event_hash != event.event_hash:
            raise BPlusProductionRuntimeError("runtime state Projection event hash is invalid")
        return event

    def open_runtime_state_reader(self) -> VerifiedJournalReadView:
        """Recover operational state from a signed Checkpoint Projection + exact tail."""

        fast_report = getattr(self.authority, "fast_start_report", None)
        if fast_report is None:
            return VerifiedJournalReadView(
                self.events,
                authority_head_position=self.events[-1].position if self.events else 0,
                reader_generation="bplus-journal-v1",
            )
        require_signed = self.genesis.environment_kind == "PRODUCTION"
        try:
            applied = ProjectionGenerationReader(
                self.home / "projections",
                authority_key_provider=self.provider,
                require_signed_pointer=require_signed,
            ).select_with_tail(
                authority_checkpoint_commitments=(fast_report.checkpoint_commitment,),
                schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
                current_journal_frontier=int(fast_report.authority_state.head_position),
                tail_events=fast_report.active_tail_events,
                handlers=production_handlers(),
            )
        except ProjectionGenerationError as error:
            if not require_signed:
                return self.open_verified_journal_reader()
            raise BPlusProductionRuntimeError(
                "Production runtime state requires a signed Projection bound to the Authority Checkpoint"
            ) from error
        try:
            metadata = dict(applied.connection.execute("SELECT key,value FROM projection_metadata"))
            if metadata.get("runtime_state_projection_schema") != "SITINA_RUNTIME_STATE_PROJECTION_V1":
                raise BPlusProductionRuntimeError("Production Projection lacks the runtime state schema")
            columns = (
                "position,event_id,event_type,tenant_id,stream_id,stream_version,occurred_at,payload_json,"
                "object_refs_json,schema_major,event_hash,journal_auth_key_id,journal_auth_tag"
            )
            rows = list(applied.connection.execute(f"SELECT {columns} FROM runtime_state_events"))
            rows.extend(applied.connection.execute(f"SELECT {columns} FROM runtime_pending_run_events"))
            pointer = dict(applied.selected.pointer)
        finally:
            applied.close()
        by_position: dict[int, EventEnvelope] = {}
        authenticator = JournalAuthProvider(self.provider)
        for row in rows:
            event = self._runtime_event_from_row(row)
            if not authenticator.verify(
                fast_report.authority_state.journal_id,
                fast_report.authority_state.epoch,
                str(event.journal_auth_key_id),
                str(event.event_hash),
                str(event.journal_auth_tag),
            ):
                raise BPlusProductionRuntimeError("runtime state Projection event authentication failed")
            existing = by_position.get(event.position)
            if existing is not None and existing.event_hash != event.event_hash:
                raise BPlusProductionRuntimeError("runtime state Projection has a position collision")
            by_position[event.position] = event
        events = tuple(by_position[position] for position in sorted(by_position))
        if events and events[-1].position > fast_report.authority_state.head_position:
            raise BPlusProductionRuntimeError("runtime state Projection exceeds the authenticated Journal frontier")
        return VerifiedJournalReadView(
            events,
            authority_head_position=fast_report.authority_state.head_position,
            reader_generation="signed-projection-v2+authenticated-active-tail",
            authority_checkpoint_commitment=fast_report.checkpoint_commitment,
            projection_generation_id=str(pointer["generation_id"]),
        )

    def open_runtime_writer(self) -> RuntimeStateJournalView:
        state = self.open_runtime_state_reader()
        return RuntimeStateJournalView(self.open_writer(), state)

    def open_cas_reader(self) -> LocalCAS:
        return LocalCAS.open_read_only(
            self.home,
            self.provider,
            namespace_kind=self._storage_namespace_kind(),
            authority_resolution=self.authority.resolution,
            genesis_hash=self.genesis.genesis_hash,
        )

    def cutover_verified(self) -> dict[str, object]:
        matching = [
            event for event in self.events
            if event.stream_id == "authority/control"
            and event.event_type == "authority.cutover-verified.committed"
            and event.payload.get("outcome") == "COMMITTED"
        ]
        if not matching:
            return {"verified": False, "reason": "CUTOVER_VERIFIED_FACT_ABSENT"}
        event = matching[-1]
        predicates = event.payload.get("predicates")
        report_hashes = event.payload.get("report_hashes")
        exact = (
            event.payload.get("manifest_sha256") == self.fence_record.get("phase6b_manifest_sha256")
            and event.payload.get("cutover_command_id") == self.fence_record.get("cutover_command_id")
            and event.payload.get("cutover_request_hash") == self.fence_record.get("cutover_request_hash")
            and event.payload.get("genesis_hash") == self.genesis.genesis_hash
            and event.payload.get("snapshot_hash") == self.genesis.intended_snapshot_hash
            and event.payload.get("outcome") == "COMMITTED"
            and isinstance(predicates, dict) and bool(predicates)
            and all(value is True for value in predicates.values())
            and isinstance(report_hashes, dict) and bool(report_hashes)
            and all(
                isinstance(value, str) and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for value in report_hashes.values()
            )
        )
        return {
            "verified": exact,
            "event_hash": event.event_hash,
            "position": event.position,
            "predicates": dict(predicates) if isinstance(predicates, dict) else {},
        }

    def list_runs(self, *, limit: int = 50) -> list[dict[str, object]]:
        fast_report = getattr(self.authority, "fast_start_report", None)
        if fast_report is not None:
            try:
                applied = ProjectionGenerationReader(self.home / "projections").select_with_tail(
                    authority_checkpoint_commitments=(fast_report.checkpoint_commitment,),
                    schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
                    current_journal_frontier=int(fast_report.authority_state.head_position),
                    tail_events=fast_report.active_tail_events,
                    handlers=production_handlers(),
                )
            except ProjectionGenerationError as error:
                raise BPlusProductionRuntimeError(
                    "fast-start list requires a verified Projection bound to the Authority Checkpoint"
                ) from error
            try:
                rows = applied.connection.execute(
                    "SELECT run_id,status,goal_hash,agent_count,created_position,terminal_position "
                    "FROM bplus_runs ORDER BY COALESCE(terminal_position,created_position) DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            finally:
                applied.close()
            return [
                {
                    "run_id": str(row[0]),
                    "phase": "done" if str(row[1]) == "terminal" else "active",
                    "risk_level": "journal-canonical",
                    "verification_status": "verified" if str(row[1]) == "terminal" else "pending",
                    "goal_hash": str(row[2]),
                    "agent_count": int(row[3]),
                    "reader_generation": "projection-v2+active-tail",
                    "journal_position": int(row[5]) if row[5] is not None else int(row[4]),
                    "authority_checkpoint_commitment": fast_report.checkpoint_commitment,
                    "fallback_used": False,
                }
                for row in rows
            ]
        created: dict[str, EventEnvelope] = {}
        terminal: set[str] = set()
        for event in self.events:
            run_id = event.payload.get("run_id")
            if not isinstance(run_id, str):
                continue
            if event.event_type == "run.created":
                created[run_id] = event
            elif event.event_type == "run.terminal":
                terminal.add(run_id)
        current = [
            {
                "run_id": run_id,
                "phase": "done" if run_id in terminal else "active",
                "risk_level": "journal-canonical",
                "verification_status": "verified" if run_id in terminal else "pending",
                "updated_at": event.occurred_at,
                "reader_generation": "bplus-journal-v1",
                "journal_position": event.position,
            }
            for run_id, event in created.items()
        ]
        combined: list[dict[str, object]] = current
        if getattr(self.legacy, "enabled", True):
            combined.extend(self.legacy.list_runs(limit=None))
        combined.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
        return combined[:limit]

    def show_run(self, run_id: str) -> dict[str, object] | None:
        events = [event for event in self._verified_history_events() if event.payload.get("run_id") == run_id]
        if events:
            terminal = next((event for event in reversed(events) if event.event_type == "run.terminal"), None)
            return {
                "run_id": run_id,
                "phase": "done" if terminal else "active",
                "status": "terminal" if terminal else "active",
                "verification_status": "verified" if terminal else "pending",
                "reader_generation": "bplus-journal-full-verify-v1" if getattr(self.authority, "fast_start_report", None) else "bplus-journal-v1",
                "event_count": len(events),
                "event_types": [event.event_type for event in events],
                "journal_frontier": events[-1].position,
            }
        if not getattr(self.legacy, "enabled", True):
            return None
        return self.legacy.get_run(run_id)

    def trace_run(self, run_id: str) -> dict[str, object]:
        history = self._verified_history_events()
        events = [event for event in history if event.payload.get("run_id") == run_id]
        if events:
            return {
                "status": "ok",
                "run_id": run_id,
                "event_count": len(events),
                "timeline": [
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "timestamp": event.occurred_at,
                        "position": event.position,
                        "stream_version": event.stream_version,
                        "payload_json": dict(event.payload),
                        "event_hash": event.event_hash,
                    }
                    for event in events
                ],
                "reader_generation": "bplus-journal-full-verify-v1" if getattr(self.authority, "fast_start_report", None) else "bplus-journal-v1",
            }
        if not getattr(self.legacy, "enabled", True):
            return {
                "status": "not_found",
                "run_id": run_id,
                "event_count": 0,
                "timeline": [],
                "reader_generation": "bplus-journal-v1",
                "legacy_read_enabled": False,
                "fallback_used": False,
            }
        timeline = self.legacy.timeline(run_id)
        return {
            "status": "ok" if timeline else "not_found",
            "run_id": run_id,
            "event_count": len(timeline),
            "timeline": timeline,
            "reader_generation": "legacy-frozen-snapshot-v1",
            "as_of_snapshot_manifest_sha256": self.legacy.manifest_sha256,
        }

    def replay_run(self, run_id: str) -> dict[str, object]:
        trace = self.trace_run(run_id)
        if trace["status"] != "ok":
            return {"status": "run_not_found", "run_id": run_id, "external_call_count": 0}
        native_events = [event for event in self._verified_history_events() if event.payload.get("run_id") == run_id]
        references = sorted({reference for event in native_events for reference in event.object_refs})
        verified_objects: list[dict[str, object]] = []
        try:
            for reference in references:
                verified_objects.append(self._verify_cas_reference(reference))
        except Exception as error:
            return {
                "status": "replay_failed_closed",
                "run_id": run_id,
                "reason": "CAS_OBJECT_UNAVAILABLE_OR_INVALID",
                "error_type": type(error).__name__,
                "error_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                "journal_event_count": len(native_events),
                "cas_reference_count": len(references),
                "verified_cas_object_count": len(verified_objects),
                "legacy_read_count": 0,
                "fallback_used": False,
                "external_call_count": 0,
                "effect_execution_count": 0,
                "writer_activated": False,
            }
        encoded = json.dumps(trace["timeline"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return {
            "status": "replay_ok",
            "run_id": run_id,
            "event_count": trace["event_count"],
            "semantic_checksum": hashlib.sha256(encoded).hexdigest(),
            "reader_generation": trace["reader_generation"],
            "external_call_count": 0,
            "effect_execution_count": 0,
            "cas_reference_count": len(references),
            "cas_read_count": len(verified_objects),
            "verified_cas_objects": verified_objects,
            "legacy_read_count": 0,
            "fallback_used": False,
            "writer_activated": False,
        }

    def _verify_cas_reference(self, reference_id: str) -> dict[str, object]:
        if not reference_id.startswith("cas:"):
            raise ValueError("unsupported object reference scheme")
        object_id = reference_id.removeprefix("cas:")
        object_path = self.home / "cas/objects" / object_id[:2] / f"{object_id}.obj"
        if object_path.is_symlink() or not object_path.is_file():
            raise FileNotFoundError("CAS object is missing")
        raw = object_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != object_id or len(raw) < 4:
            raise ValueError("CAS object digest is invalid")
        header_length = int.from_bytes(raw[:4], "big")
        if header_length > len(raw) - 4:
            raise ValueError("CAS object header length is invalid")
        header = json.loads(raw[4 : 4 + header_length])
        alias_path = self.home / "cas/aliases" / f"{object_id}.json"
        if alias_path.is_symlink() or not alias_path.is_file():
            raise FileNotFoundError("CAS envelope alias is missing")
        alias = json.loads(alias_path.read_text(encoding="utf-8"))
        if alias.get("object_id") != object_id:
            raise ValueError("CAS envelope alias binds another object")
        envelope_id = str(alias["envelope_id"])
        envelope_path = self.home / "cas/envelopes" / envelope_id[:2] / f"{envelope_id}.json"
        envelope = ObjectEnvelope.from_bytes(envelope_path.read_bytes())
        reference = ObjectRef(
            object_id,
            str(header["tenant_id"]),
            str(header["plaintext_commitment"]),
            str(header["commitment_key_id"]),
        )
        plaintext = decrypt_object(
            EncryptedObject(reference, header, raw[4 + header_length :], envelope),
            self.provider,
        )
        return {
            "reference": reference_id,
            "ciphertext_sha256_valid": True,
            "envelope_bound": envelope.object_id == object_id,
            "plaintext_commitment_verified": True,
            "plaintext_length": len(plaintext),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        }

    _PROTOCOL_FAMILIES = {
        "proposals": ("proposal.", "selection.", "review."),
        "blackboard": ("blackboard.",),
        "handoff": ("handoff.",),
        "lease": ("lease.", "task.claimed", "task.claim.released"),
        "arbitration": ("arbitration.",),
        "effects": ("effect.", "provider.", "budget.", "observation.", "external.result."),
        "evidence": ("evidence.",),
        "archive": ("archive.", "backup."),
    }

    @staticmethod
    def _event_matches_family(event_type: str, markers: tuple[str, ...]) -> bool:
        normalized = event_type.removeprefix("protocol.").replace("_", ".").replace("-", ".")
        return any(marker in normalized for marker in markers)

    @staticmethod
    def _journal_event_view(event: EventEnvelope) -> dict[str, object]:
        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "position": event.position,
            "stream_id": event.stream_id,
            "stream_version": event.stream_version,
            "occurred_at": event.occurred_at,
            "event_hash": event.event_hash,
            "causation_command_id": event.payload.get("causation_command_id"),
            "fact_hash": event.payload.get("fact_hash"),
            "object_refs": list(event.object_refs),
            "payload": dict(event.payload),
        }

    def protocol_view(self, run_id: str, family: str) -> dict[str, object]:
        """Read one protocol family without ever mixing native and Legacy sources."""

        try:
            markers = self._PROTOCOL_FAMILIES[family]
        except KeyError as error:
            raise ValueError(f"unknown protocol family: {family}") from error
        native = [event for event in self.events if event.payload.get("run_id") == run_id]
        if native:
            selected = [
                self._journal_event_view(event)
                for event in native
                if self._event_matches_family(event.event_type, markers)
            ]
            return {
                "status": "ok",
                "run_exists": True,
                "run_id": run_id,
                "family": family,
                "storage_class": "NATIVE_JOURNAL",
                "read_source": "Canonical Journal",
                "reader_generation": "bplus-journal-v1",
                "projection_used": False,
                "legacy_adapter_used": False,
                "fallback_used": False,
                "event_count": len(selected),
                "events": selected,
            }
        if not getattr(self.legacy, "enabled", True):
            return {
                "status": "not_found",
                "run_exists": False,
                "run_id": run_id,
                "family": family,
                "storage_class": "NOT_FOUND",
                "read_source": None,
                "reader_generation": "bplus-journal-v1",
                "projection_used": False,
                "legacy_adapter_used": False,
                "legacy_read_enabled": False,
                "fallback_used": False,
                "event_count": 0,
                "events": [],
            }
        legacy_state = self.legacy.get_run(run_id)
        if legacy_state is None:
            return {
                "status": "not_found",
                "run_exists": False,
                "run_id": run_id,
                "family": family,
                "storage_class": "NOT_FOUND",
                "read_source": None,
                "reader_generation": None,
                "projection_used": False,
                "legacy_adapter_used": False,
                "fallback_used": False,
                "event_count": 0,
                "events": [],
            }
        legacy_timeline = self.legacy.timeline(run_id)
        selected_legacy = [
            item
            for item in legacy_timeline
            if self._event_matches_family(str(item.get("event_type", "")), markers)
        ]
        return {
            "status": "ok",
            "run_exists": True,
            "run_id": run_id,
            "family": family,
            "storage_class": "LEGACY_SNAPSHOT",
            "read_source": "Frozen Legacy snapshot",
            "reader_generation": "legacy-frozen-snapshot-v1",
            "projection_used": False,
            "legacy_adapter_used": True,
            "fallback_used": False,
            "as_of_snapshot_manifest_sha256": self.legacy.manifest_sha256,
            "event_count": len(selected_legacy),
            "events": selected_legacy,
        }

    def find_protocol_entity(
        self,
        family: str,
        entity_id: str,
        *,
        id_fields: Sequence[str],
    ) -> dict[str, object]:
        """Find a protocol entity in Journal first, then the frozen snapshot only."""

        markers = self._PROTOCOL_FAMILIES.get(family)
        if markers is None:
            raise ValueError(f"unknown protocol family: {family}")
        native_matches = [
            self._journal_event_view(event)
            for event in self.events
            if self._event_matches_family(event.event_type, markers)
            and any(event.payload.get(field) == entity_id for field in id_fields)
        ]
        if native_matches:
            return {
                "status": "ok",
                "family": family,
                "entity_id": entity_id,
                "storage_class": "NATIVE_JOURNAL",
                "read_source": "Canonical Journal",
                "reader_generation": "bplus-journal-v1",
                "legacy_adapter_used": False,
                "fallback_used": False,
                "events": native_matches,
            }
        if not getattr(self.legacy, "enabled", True):
            return {
                "status": "not_found",
                "family": family,
                "entity_id": entity_id,
                "storage_class": "NOT_FOUND",
                "read_source": None,
                "reader_generation": "bplus-journal-v1",
                "legacy_adapter_used": False,
                "legacy_read_enabled": False,
                "fallback_used": False,
                "events": [],
            }
        legacy_matches: list[dict[str, object]] = []
        with self.legacy.connect() as connection:
            rows = connection.execute(
                "SELECT run_id,payload_json FROM events WHERE event_type='run_ledger' ORDER BY id ASC"
            ).fetchall()
        for run_id, payload_json in rows:
            try:
                item = json.loads(payload_json)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or not self._event_matches_family(str(item.get("event_type", "")), markers):
                continue
            payload = item.get("payload_json")
            if isinstance(payload, dict) and any(payload.get(field) == entity_id for field in id_fields):
                legacy_matches.append({"run_id": run_id, **item})
        return {
            "status": "ok" if legacy_matches else "not_found",
            "family": family,
            "entity_id": entity_id,
            "storage_class": "LEGACY_SNAPSHOT" if legacy_matches else "NOT_FOUND",
            "read_source": "Frozen Legacy snapshot" if legacy_matches else None,
            "reader_generation": "legacy-frozen-snapshot-v1" if legacy_matches else None,
            "legacy_adapter_used": bool(legacy_matches),
            "fallback_used": False,
            "as_of_snapshot_manifest_sha256": self.legacy.manifest_sha256 if legacy_matches else None,
            "events": legacy_matches,
        }


class BPlusProductionRuntime:
    """Small deployed Journal-first boundary used after a committed cutover.

    The orchestration facts are canonical events.  Projections are disposable
    views and never grant claims, writer authority, or protocol outcomes.
    """

    def __init__(self, home: Path, journal: Any, resolution: AuthorityResolution, *, now: int):
        self.home = Path(home).resolve(strict=True)
        resolution.assert_fresh(now=now)
        if not resolution.authorizes_journal or resolution.writer_count != 1:
            raise BPlusProductionRuntimeError("B+ Production runtime requires unique Journal authority")
        if journal.home != self.home:
            raise BPlusProductionRuntimeError("Journal belongs to another Production root")
        journal.activate_business_authority(resolution)
        self.journal = journal
        self.resolution = resolution
        self.now = now
        self.occurred_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    def create_canary_run(
        self,
        goal: str,
        *,
        agents: Sequence[str],
        command_id: str | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        unique = tuple(dict.fromkeys(str(item) for item in agents))
        if len(unique) < 3:
            raise BPlusProductionRuntimeError("dynamic canary requires at least three stable Agent identities")
        goal_hash = hashlib.sha256(goal.encode()).hexdigest()
        timestamp = self.occurred_at if occurred_at is None else occurred_at
        command_identity = command_id or "run-create-" + domain_hash(
            "BPLUS_PRODUCTION_COMMAND_ID",
            canonical_json_bytes({"goal_hash": goal_hash, "agents": list(unique), "occurred_at": timestamp}),
        )[:40]
        run_id = "bplus-run-" + domain_hash(
            "BPLUS_PRODUCTION_RUN_ID",
            canonical_json_bytes({"goal_hash": goal_hash, "agents": list(unique), "command_id": command_identity}),
        )[:32]
        stream_id = f"run/{run_id}"
        command = CommandEnvelope(
            command_identity, "default", stream_id, "run.create-dynamic-canary", "bplus-runtime",
            timestamp, {"run_id": run_id, "goal_hash": goal_hash, "agents": list(unique)},
        )
        proposal_a = domain_hash("CANARY_PROPOSAL", canonical_json_bytes({"run_id": run_id, "agent": unique[0], "branch": "a"}))
        proposal_b = domain_hash("CANARY_PROPOSAL", canonical_json_bytes({"run_id": run_id, "agent": unique[1], "branch": "b"}))
        payloads = (
            ("run.created", {"run_id": run_id, "goal_hash": goal_hash, "agent_count": len(unique)}),
            ("taskgraph.materialized", {"run_id": run_id, "tasks": ["analyze", "propose", "review", "handoff", "close"], "dynamic": True}),
            ("proposal.submitted", {"run_id": run_id, "agent_id": unique[0], "proposal_hash": proposal_a}),
            ("proposal.submitted", {"run_id": run_id, "agent_id": unique[1], "proposal_hash": proposal_b}),
            ("review.accepted", {"run_id": run_id, "reviewer_id": unique[2], "proposal_hash": proposal_b, "independent": True}),
            ("selection.committed", {"run_id": run_id, "selected_proposal_hash": proposal_b, "rejected_proposal_hash": proposal_a}),
            ("handoff.accepted", {"run_id": run_id, "source_agent": unique[1], "target_agent": unique[2], "generation": 2}),
            ("blackboard.updated", {"run_id": run_id, "generation": 2, "conflict_policy": "explicit"}),
            ("task.completed", {"run_id": run_id, "task_id": "close", "fencing_generation": 2}),
            ("obligation.satisfied", {"run_id": run_id, "obligation_id": "canary-evidence"}),
            ("run.terminal", {"run_id": run_id, "status": "terminal", "required_obligations_open": 0}),
        )
        events = [
            EventEnvelope(
                "event-" + domain_hash("BPLUS_CANARY_EVENT_ID", canonical_json_bytes({"run_id": run_id, "ordinal": index, "type": event_type}))[:48],
                event_type, "default", stream_id, 0, 0, timestamp, payload,
            )
            for index, (event_type, payload) in enumerate(payloads, 1)
        ]
        receipt = self.journal.append(command, 0, events)
        return {
            "run_id": run_id,
            "status": "terminal",
            "transaction_hash": receipt.transaction_hash,
            "first_position": receipt.first_position,
            "last_position": receipt.last_position,
            "agents": list(unique),
            "proposal_hashes": [proposal_a, proposal_b],
        }

    def create_local_run(
        self,
        goal: str,
        *,
        cas: LocalCAS,
        provider: MacOSKeychainProvider,
        parent_goal_id: str | None = None,
        backlog_item_id: str | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        """Commit one ordinary CLI mock run to Production Journal + encrypted CAS.

        This is deliberately a local, non-Provider execution.  It records no
        fabricated Agent or effect facts: the accepted goal, deterministic
        summary, and evidence package are encrypted CAS objects referenced by
        one canonical Journal transaction.
        """

        if cas.home != self.home or cas.namespace_kind not in {"production", "production_simulation"}:
            raise BPlusProductionRuntimeError("local run CAS belongs to another authority domain")
        if not isinstance(goal, str) or not goal.strip():
            raise BPlusProductionRuntimeError("local run requires a non-empty goal")
        timestamp = self.occurred_at if occurred_at is None else occurred_at
        nonce = uuid.uuid4().hex
        goal_hash = hashlib.sha256(goal.encode("utf-8")).hexdigest()
        run_id = "bplus-run-" + domain_hash(
            "BPLUS_PRODUCTION_LOCAL_RUN_ID",
            canonical_json_bytes({"goal_hash": goal_hash, "nonce": nonce, "occurred_at": timestamp}),
        )[:32]
        stream_id = f"run/{run_id}"
        command_id = "run-local-" + domain_hash(
            "BPLUS_PRODUCTION_LOCAL_COMMAND_ID",
            canonical_json_bytes({"run_id": run_id, "nonce": nonce}),
        )[:40]
        link_hashes = {
            "parent_goal_id_sha256": hashlib.sha256(parent_goal_id.encode()).hexdigest() if parent_goal_id else None,
            "backlog_item_id_sha256": hashlib.sha256(backlog_item_id.encode()).hexdigest() if backlog_item_id else None,
        }
        goal_object = {
            "schema": "SITINA_PRODUCTION_LOCAL_GOAL_V1",
            "run_id": run_id,
            "goal": goal,
            "goal_sha256": goal_hash,
            "provider_mode": "mock",
            "external_mutation_allowed": False,
        }
        goal_receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(goal_object),
                provider,
                tenant_id="default",
                purpose="production-local-goal",
            )
        )
        summary_object = {
            "schema": "SITINA_PRODUCTION_LOCAL_SUMMARY_V1",
            "run_id": run_id,
            "status": "terminal",
            "summary": "Goal accepted and durably recorded by the Journal-native local execution path.",
            "goal_sha256": goal_hash,
            "provider_call_count": 0,
            "external_effect_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "fallback_attempt_count": 0,
        }
        summary_receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(summary_object),
                provider,
                tenant_id="default",
                purpose="production-local-summary",
            )
        )
        evidence_object = {
            "schema": "SITINA_PRODUCTION_LOCAL_RUN_EVIDENCE_V1",
            "run_id": run_id,
            "goal_sha256": goal_hash,
            "journal_id": self.journal.journal_id,
            "journal_epoch": self.journal.epoch,
            "goal_object_ref": goal_receipt.object_ref.reference_id,
            "summary_object_ref": summary_receipt.object_ref.reference_id,
            "execution_mode": "journal-native-local",
            "provider_mode": "mock",
            "provider_call_count": 0,
            "external_effect_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "fallback_attempt_count": 0,
            "active_business_jsonl_write_count": 0,
            **link_hashes,
        }
        evidence_receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(evidence_object),
                provider,
                tenant_id="default",
                purpose="production-local-evidence",
            )
        )
        goal_ref = goal_receipt.object_ref.reference_id
        summary_ref = summary_receipt.object_ref.reference_id
        evidence_ref = evidence_receipt.object_ref.reference_id
        all_refs = tuple(sorted((goal_ref, summary_ref, evidence_ref)))
        command = CommandEnvelope(
            command_id,
            "default",
            stream_id,
            "run.execute-local",
            "sitina-cli",
            timestamp,
            {
                "run_id": run_id,
                "goal_hash": goal_hash,
                "provider_mode": "mock",
                "execution_mode": "journal-native-local",
                **link_hashes,
            },
        )
        fact_rows: tuple[tuple[str, dict[str, object], tuple[str, ...]], ...] = (
            (
                "run.created",
                {
                    "run_id": run_id,
                    "goal_hash": goal_hash,
                    "agent_count": 0,
                    "provider_mode": "mock",
                    "execution_mode": "journal-native-local",
                },
                (),
            ),
            (
                "goal.accepted",
                {
                    "run_id": run_id,
                    "goal_hash": goal_hash,
                    "goal_object_ref": goal_ref,
                    "legacy_read_allowed": False,
                    "external_mutation_allowed": False,
                },
                (goal_ref,),
            ),
            (
                "taskgraph.materialized",
                {
                    "run_id": run_id,
                    "tasks": ["accept-goal", "local-summary", "close"],
                    "dynamic": False,
                    "agent_count": 0,
                },
                (),
            ),
            (
                "task.completed",
                {
                    "run_id": run_id,
                    "task_id": "local-summary",
                    "executor": "journal-native-local",
                    "provider_call_count": 0,
                    "external_effect_count": 0,
                },
                (),
            ),
            (
                "summary.readonly.committed",
                {
                    "run_id": run_id,
                    "summary_object_ref": summary_ref,
                    "provider_call_count": 0,
                    "external_mutation_count": 0,
                },
                (summary_ref,),
            ),
            (
                "evidence.package.published",
                {
                    "run_id": run_id,
                    "evidence_package_id": evidence_ref,
                    "goal_object_ref": goal_ref,
                    "summary_object_ref": summary_ref,
                    "secret_findings": 0,
                },
                all_refs,
            ),
            (
                "run.terminal",
                {
                    "run_id": run_id,
                    "status": "terminal",
                    "required_obligations_open": 0,
                    "provider_call_count": 0,
                    "external_effect_count": 0,
                    "legacy_read_count": 0,
                    "legacy_write_count": 0,
                    "fallback_attempt_count": 0,
                },
                (),
            ),
        )
        events = [
            EventEnvelope(
                "event-" + domain_hash(
                    "BPLUS_PRODUCTION_LOCAL_EVENT_ID",
                    canonical_json_bytes({"run_id": run_id, "ordinal": index, "event_type": event_type}),
                )[:48],
                event_type,
                "default",
                stream_id,
                0,
                0,
                timestamp,
                payload,
                tuple(sorted(object_refs)),
            )
            for index, (event_type, payload, object_refs) in enumerate(fact_rows, 1)
        ]
        receipt = self.journal.append(
            command,
            0,
            events,
            object_reference_proofs=(goal_receipt, summary_receipt, evidence_receipt),
        )
        return {
            "run_id": run_id,
            "status": "terminal",
            "phase": "done",
            "verification_status": "verified",
            "writer": "journal",
            "canonical_authority": "Canonical Journal",
            "content_authority": "encrypted CAS referenced by Journal",
            "routing_generation": "bplus-production-journal-cas-v1",
            "execution_mode": "journal-native-local",
            "provider_mode": "mock",
            "provider_call_count": 0,
            "external_effect_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "fallback_attempt_count": 0,
            "active_business_jsonl_write_count": 0,
            "legacy_writer_activated": False,
            "transaction_hash": receipt.transaction_hash,
            "first_position": receipt.first_position,
            "last_position": receipt.last_position,
            "journal_id": receipt.journal_id,
            "journal_epoch": receipt.epoch,
            "journal_path": str(self.home / "journal/active.seg"),
            "cas_path": str(self.home / "cas"),
            "object_refs": list(all_refs),
            "goal_object_ref": goal_ref,
            "summary_object_ref": summary_ref,
            "evidence_object_ref": evidence_ref,
        }

    def show_run(self, run_id: str) -> dict[str, object]:
        events = [event for event in self.journal.iter_events(0) if event.payload.get("run_id") == run_id]
        if not events:
            return {"status": "not_found", "run_id": run_id}
        terminal = next((event for event in reversed(events) if event.event_type == "run.terminal"), None)
        return {
            "run_id": run_id,
            "status": "terminal" if terminal else "active",
            "event_count": len(events),
            "event_types": [event.event_type for event in events],
            "frontier": events[-1].position,
        }

    def rebuild_projection(self, *, disposable: bool) -> ProjectionGeneration:
        if not disposable:
            raise BPlusProductionRuntimeError("acceptance rebuild must target a disposable Projection generation")
        if self.journal.head_position < 1:
            raise BPlusProductionRuntimeError("cannot rebuild an empty Production Journal")
        commitment = self.journal._position_hash[self.journal.head_position]
        frontier = FrontierRef(self.journal.journal_id, self.journal.epoch, "local", self.journal.head_position, commitment)
        root = self.home / "projections/disposable-rebuilds"
        return ProjectionGeneration.build(root, self.journal, frontier, production_handlers())
