from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sitina.authority.model import AuthorityResolution, AuthorityState
from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes, domain_hash
from sitina.legacy.retirement import DisabledLegacyStore, LegacyRuntimePolicy
from sitina.orchestrator.bplus_production import ProductionRuntimeContext, VerifiedJournalReadView
from sitina.security.key_provider import JournalAuthProvider
from sitina.security.macos_keychain import MacOSKeychainProvider


class CleanAcceptanceError(RuntimeError):
    pass


class CleanAcceptanceContext:
    """Durably reopen an isolated B+ acceptance epoch with no Legacy source."""

    MARKER = ".sitina-clean-acceptance-v1"
    GENESIS = "state/clean-acceptance/genesis.json"
    _PROTOCOL_FAMILIES = ProductionRuntimeContext._PROTOCOL_FAMILIES
    _event_matches_family = staticmethod(ProductionRuntimeContext._event_matches_family)
    _journal_event_view = staticmethod(ProductionRuntimeContext._journal_event_view)
    _verify_cas_reference = ProductionRuntimeContext._verify_cas_reference

    def __init__(
        self,
        home: Path,
        genesis: dict[str, Any],
        provider: MacOSKeychainProvider,
        resolution: AuthorityResolution,
        events: tuple[EventEnvelope, ...],
        policy: LegacyRuntimePolicy,
    ):
        self.home = home
        self.clean_genesis = genesis
        self.genesis = SimpleNamespace(
            genesis_hash=genesis["genesis_hash"],
            journal_id=genesis["journal_id"],
            key_namespace=genesis["key_namespace"],
            epoch_root=f"clean-acceptance-{genesis['epoch']}",
        )
        self.provider = provider
        self.authority = SimpleNamespace(
            resolution=resolution,
            events=events,
            control_frontier_hash=genesis["genesis_hash"],
        )
        self.legacy_policy = policy
        self.legacy = DisabledLegacyStore(policy)

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    @classmethod
    def _config_hash(cls, home: Path) -> str:
        paths = [
            path
            for root in (home / "core", home / "config", home / "profiles", home / "prompts", home / "schemas")
            if root.exists()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
            and "__pycache__" not in path.parts and path.suffix != ".pyc" and path.name != ".DS_Store"
        ]
        values = [
            {
                "path": str(path.relative_to(home)),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(paths)
        ]
        return hashlib.sha256(cls._canonical({"files": values})).hexdigest()

    @classmethod
    def _genesis_body(cls, home: Path, *, created_at: str) -> dict[str, Any]:
        config_hash = cls._config_hash(home)
        seed = {
            "root": str(home),
            "config_sha256": config_hash,
            "created_at": created_at,
        }
        identity = domain_hash("CLEAN_ACCEPTANCE_ID", canonical_json_bytes(seed))
        return {
            "schema": "SITINA_CLEAN_ACCEPTANCE_GENESIS_V1",
            "acceptance_id": "clean-acceptance-" + identity[:32],
            "environment": "acceptance",
            "root": str(home),
            "journal_id": "sitina-clean-acceptance-journal-" + identity[:24],
            "epoch": 1,
            "key_namespace": "sitina-clean-acceptance-" + identity[:24],
            "config_sha256": config_hash,
            "created_at": created_at,
            "legacy_enabled": False,
            "legacy_read_enabled": False,
            "legacy_fallback_enabled": False,
            "legacy_write_enabled": False,
            "active_business_jsonl_enabled": False,
        }

    @classmethod
    def initialize(cls, home: Path) -> "CleanAcceptanceContext":
        root = Path(home).expanduser().resolve(strict=True)
        if root == Path("/Users/moss/SitinaHub") or not (root / cls.MARKER).is_file():
            raise CleanAcceptanceError("clean acceptance requires a marked non-Production root")
        policy = LegacyRuntimePolicy.load(root)
        if not policy.fully_disabled or not policy.missing_legacy_is_valid:
            raise CleanAcceptanceError("clean acceptance policy does not fully disable Legacy")
        if (root / "data/sitina.db").exists():
            raise CleanAcceptanceError("clean acceptance must not contain a Legacy SQLite database")
        for relative in ("journal", "cas", "projections/disposable-rebuilds", "output", "logs"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        path = root / cls.GENESIS
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            genesis = cls._load_genesis(root)
        else:
            body = cls._genesis_body(
                root,
                created_at=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            )
            genesis = body | {"genesis_hash": hashlib.sha256(cls._canonical(body)).hexdigest()}
            raw = json.dumps(genesis, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        provider = MacOSKeychainProvider(
            environment="clean-acceptance",
            namespace=str(genesis["key_namespace"]),
        )
        journal = LocalJournal.open(
            root,
            JournalAuthProvider(provider),
            journal_id=str(genesis["journal_id"]),
            epoch=int(genesis["epoch"]),
            namespace_kind="controlled_fixture",
        )
        try:
            existing = tuple(journal.iter_events(0))
            if not existing:
                occurred_at = str(genesis["created_at"])
                command = CommandEnvelope(
                    "clean-acceptance-genesis-v1",
                    "default",
                    "authority/clean-acceptance",
                    "acceptance.genesis",
                    "clean-acceptance-bootstrap",
                    occurred_at,
                    {"genesis_hash": genesis["genesis_hash"], "config_sha256": genesis["config_sha256"]},
                )
                event = EventEnvelope(
                    "event-clean-acceptance-genesis-v1",
                    "acceptance.genesis",
                    "default",
                    "authority/clean-acceptance",
                    0,
                    0,
                    occurred_at,
                    {
                        "acceptance_id": genesis["acceptance_id"],
                        "genesis_hash": genesis["genesis_hash"],
                        "config_sha256": genesis["config_sha256"],
                        "legacy_enabled": False,
                        "legacy_fallback_enabled": False,
                    },
                )
                journal.append(command, 0, (event,))
        finally:
            journal.close()
        # Opening CAS initializes only the isolated acceptance namespace.
        LocalCAS.open(root, provider, namespace_kind="controlled_fixture")
        return cls.load(root)

    @classmethod
    def _load_genesis(cls, root: Path) -> dict[str, Any]:
        path = root / cls.GENESIS
        if path.is_symlink() or not path.is_file():
            raise CleanAcceptanceError("clean acceptance Genesis is unavailable")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            claimed = str(value.pop("genesis_hash"))
        except Exception as error:
            raise CleanAcceptanceError("clean acceptance Genesis is malformed") from error
        actual = hashlib.sha256(cls._canonical(value)).hexdigest()
        value["genesis_hash"] = claimed
        if claimed != actual or value.get("schema") != "SITINA_CLEAN_ACCEPTANCE_GENESIS_V1":
            raise CleanAcceptanceError("clean acceptance Genesis hash is invalid")
        if value.get("root") != str(root) or value.get("config_sha256") != cls._config_hash(root):
            raise CleanAcceptanceError("clean acceptance Genesis root/config binding differs")
        if any(bool(value.get(field)) for field in (
            "legacy_enabled", "legacy_read_enabled", "legacy_fallback_enabled",
            "legacy_write_enabled", "active_business_jsonl_enabled",
        )):
            raise CleanAcceptanceError("clean acceptance Genesis enables a Legacy route")
        return value

    @classmethod
    def load(cls, home: Path) -> "CleanAcceptanceContext":
        root = Path(home).expanduser().resolve(strict=True)
        if root == Path("/Users/moss/SitinaHub") or not (root / cls.MARKER).is_file():
            raise CleanAcceptanceError("clean acceptance marker is missing")
        policy = LegacyRuntimePolicy.load(root)
        if not policy.fully_disabled or not policy.missing_legacy_is_valid:
            raise CleanAcceptanceError("clean acceptance Legacy policy is invalid")
        if (root / "data/sitina.db").exists():
            raise CleanAcceptanceError("clean acceptance unexpectedly contains Legacy SQLite")
        genesis = cls._load_genesis(root)
        provider = MacOSKeychainProvider(
            environment="clean-acceptance",
            namespace=str(genesis["key_namespace"]),
        )
        journal = LocalJournal.open(
            root,
            JournalAuthProvider(provider),
            journal_id=str(genesis["journal_id"]),
            epoch=int(genesis["epoch"]),
            namespace_kind="controlled_fixture",
        )
        try:
            events = tuple(journal.iter_events(0))
        finally:
            journal.close()
        if not events or events[0].event_type != "acceptance.genesis" or events[0].payload.get("genesis_hash") != genesis["genesis_hash"]:
            raise CleanAcceptanceError("canonical Journal lacks the bound clean acceptance Genesis event")
        now = int(time.time())
        resolution = AuthorityResolution(
            AuthorityState.JOURNAL_WRITER_AUTHORIZED,
            "clean-resolution-" + genesis["genesis_hash"][:32],
            genesis["genesis_hash"],
            domain_hash("CLEAN_ACCEPTANCE_AUTHORITY_INPUT", canonical_json_bytes(genesis)),
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "CLEAN_ACCEPTANCE_JOURNAL_ONLY_V1",
            now,
            now + 3600,
            "isolated acceptance Genesis authorizes exactly one controlled Journal writer",
        )
        return cls(root, genesis, provider, resolution, events, policy)

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self.authority.events)

    def open_writer(self) -> LocalJournal:
        return LocalJournal.open(
            self.home,
            JournalAuthProvider(self.provider),
            journal_id=str(self.clean_genesis["journal_id"]),
            epoch=int(self.clean_genesis["epoch"]),
            namespace_kind="controlled_fixture",
        )

    def open_cas(self) -> LocalCAS:
        return LocalCAS.open(
            self.home,
            self.provider,
            namespace_kind="controlled_fixture",
            feature_activations=FeatureActivationRegistry.from_journal_events(self.events),
        )

    def open_verified_journal_reader(self) -> VerifiedJournalReadView:
        return VerifiedJournalReadView(self.events)

    def open_cas_reader(self) -> LocalCAS:
        return LocalCAS.open_read_only(self.home, self.provider, namespace_kind="controlled_fixture")

    def cutover_verified(self) -> dict[str, object]:
        return {
            "verified": True,
            "mode": "CLEAN_ACCEPTANCE_GENESIS_NO_LEGACY_CUTOVER",
            "event_hash": self.events[0].event_hash,
            "position": self.events[0].position,
        }

    # Reuse the already-tested Journal-native readers. DisabledLegacyStore would
    # raise if a future regression attempted any compatibility access.
    def list_runs(self, *, limit: int = 50) -> list[dict[str, object]]:
        return ProductionRuntimeContext.list_runs(self, limit=limit)

    def show_run(self, run_id: str) -> dict[str, object] | None:
        return ProductionRuntimeContext.show_run(self, run_id)

    def trace_run(self, run_id: str) -> dict[str, object]:
        return ProductionRuntimeContext.trace_run(self, run_id)

    def replay_run(self, run_id: str) -> dict[str, object]:
        return ProductionRuntimeContext.replay_run(self, run_id)

    def protocol_view(self, run_id: str, family: str) -> dict[str, object]:
        return ProductionRuntimeContext.protocol_view(self, run_id, family)

    def find_protocol_entity(self, family: str, entity_id: str, *, id_fields: tuple[str, ...]) -> dict[str, object]:
        return ProductionRuntimeContext.find_protocol_entity(self, family, entity_id, id_fields=id_fields)
