from __future__ import annotations

import hashlib
import json
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sitina.authority.model import AuthorityControlFacts, LegacyAuthorityFact
from sitina.authority.resolver import AuthorityResolver
from sitina.commands.model import CommandEnvelope, CommandResult, CommandStatus
from sitina.journal.model import EventEnvelope, canonical_json_bytes, domain_hash
from sitina.journal.recovery import scan_active_segment_read_only, scan_sealed_segment
from sitina.journal.fast_start import FastStartLoader


class Phase6BManifestError(RuntimeError):
    pass


PHASE6B_OPERATION_IDS = (
    "FREEZE_LEGACY_WRITER",
    "CREATE_FROZEN_SNAPSHOT",
    "CREATE_AND_VERIFY_CANONICAL_BACKUP",
    "CREATE_PRODUCTION_GENESIS",
    "INITIALIZE_PRODUCTION_KEY_NAMESPACE",
    "OPEN_PRODUCTION_JOURNAL_CONTROL_PLANE",
    "OPEN_PRODUCTION_CAS_MIGRATION_PLANE",
    "PUBLISH_MIGRATION_CONTROL_FACTS",
    "SUBMIT_STABLE_CUTOVER_COMMAND",
    "RECOVER_STABLE_CUTOVER_COMMAND",
    "OPEN_JOURNAL_BUSINESS_WRITER_AFTER_COMMITTED_CUTOVER",
    "SUBMIT_STABLE_CUTOVER_VERIFIED_COMMAND",
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_STANDING_HASH = "sha256:05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601"
_THREAD_ID = "019f5c6b-3083-7860-b45b-c8b487c4e3ab"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _hash_file(path: Path) -> str:
    before = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise Phase6BManifestError(f"identity path is not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise Phase6BManifestError(f"identity path changed during verification: {path}")
    return digest.hexdigest()


@dataclass(frozen=True)
class Phase6BOperationalCapability:
    manifest_sha256: str
    environment_kind: str
    production_home: Path
    snapshot_root: Path
    migration_root: Path
    backup_root: Path
    control_root: Path
    authorized_operations: tuple[str, ...]
    starts_at: int
    ends_at: int
    expires_at: int
    production_genesis: Mapping[str, object]
    cutover_command: Mapping[str, object]
    cutover_verified_command: Mapping[str, object]
    source_manifest_sha256: str
    readiness_sha256: str
    _issuer_token: str

    def assert_operation(self, operation: str, root: Path, *, now: int | None = None) -> None:
        moment = int(time.time()) if now is None else int(now)
        if not self._issuer_token.startswith("verified-phase6b:"):
            raise Phase6BManifestError("operational capability issuer is invalid")
        if not self.starts_at <= moment <= self.expires_at <= self.ends_at:
            raise Phase6BManifestError("Phase 6B operational capability is outside its approved window")
        if operation not in self.authorized_operations:
            raise Phase6BManifestError(f"operation is outside the Maintenance Manifest: {operation}")
        candidate = Path(root).expanduser().resolve(strict=False)
        permitted = (
            candidate == self.production_home
            or _inside(candidate, self.production_home)
            or candidate in {self.snapshot_root, self.migration_root, self.backup_root, self.control_root}
            or any(_inside(candidate, item) for item in (self.snapshot_root, self.migration_root, self.backup_root, self.control_root))
        )
        if not permitted:
            raise Phase6BManifestError(f"operation root is outside the Maintenance Manifest: {candidate}")


class Phase6BManifestVerifier:
    @staticmethod
    def verify_mapping(
        value: Mapping[str, object],
        *,
        readiness_report: Mapping[str, object],
        now: int | None = None,
        allow_simulation: bool = False,
    ) -> Phase6BOperationalCapability:
        moment = int(time.time()) if now is None else int(now)
        raw = dict(value)
        claimed_manifest = str(raw.pop("manifest_sha256", ""))
        if not _SHA.fullmatch(claimed_manifest) or hashlib.sha256(_canonical(raw)).hexdigest() != claimed_manifest:
            raise Phase6BManifestError("Maintenance Manifest canonical hash is invalid")
        public_hex = str(raw.pop("technical_verifier_public_key_hex", ""))
        signature_hex = str(raw.pop("technical_verifier_signature_hex", ""))
        signed_hash = str(raw.pop("signed_body_sha256", ""))
        signed = _canonical(raw)
        if hashlib.sha256(signed).hexdigest() != signed_hash:
            raise Phase6BManifestError("Maintenance Manifest signed-body hash is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), signed)
        except Exception as error:
            raise Phase6BManifestError("independent technical verifier signature is invalid") from error
        if raw.get("schema") != "PHASE6B_MAINTENANCE_MANIFEST_V1":
            raise Phase6BManifestError("unsupported Maintenance Manifest schema")
        if raw.get("goal_thread_id") != _THREAD_ID or raw.get("standing_owner_authorization_hash") != _STANDING_HASH:
            raise Phase6BManifestError("Maintenance Manifest is not bound to this Goal and Standing Authorization")
        if raw.get("owner_principal") != "user-standing-owner-authorization-v1" or raw.get("approval_derivation") != "AUTOMATIC_FROM_STANDING_OWNER_AUTHORIZATION_V1":
            raise Phase6BManifestError("Maintenance Manifest owner derivation is invalid")

        readiness = dict(readiness_report)
        readiness_claim = str(readiness.pop("readiness_sha256", ""))
        if not _SHA.fullmatch(readiness_claim) or hashlib.sha256(_canonical(readiness)).hexdigest() != readiness_claim:
            raise Phase6BManifestError("CutoverToolingReady report hash is invalid")
        if raw.get("phase6a_readiness_sha256") != readiness_claim or readiness.get("status") != "CUTOVER_TOOLING_READY":
            raise Phase6BManifestError("Maintenance Manifest is not bound to current CutoverToolingReady evidence")
        if any(bool(readiness.get(name)) for name in ("authority", "maintenance_authorized", "cutover_authorized")):
            raise Phase6BManifestError("readiness evidence must not itself assert operational authority")
        predicates = readiness.get("predicates")
        if not isinstance(predicates, Mapping) or not predicates or not all(item is True for item in predicates.values()):
            raise Phase6BManifestError("CutoverToolingReady predicates are incomplete")

        environment = str(raw.get("environment_kind", ""))
        if environment == "CONTROLLED_PRODUCTION_SIMULATION":
            if not allow_simulation:
                raise Phase6BManifestError("simulation manifest cannot issue a Production capability")
        elif environment != "PRODUCTION":
            raise Phase6BManifestError("unknown Phase 6B environment kind")
        roots_raw = raw.get("roots")
        if not isinstance(roots_raw, Mapping):
            raise Phase6BManifestError("Maintenance Manifest roots are missing")
        required_roots = ("production_home", "snapshot_root", "migration_root", "backup_root", "control_root")
        try:
            roots = {name: Path(str(roots_raw[name])).expanduser().resolve(strict=False) for name in required_roots}
        except KeyError as error:
            raise Phase6BManifestError("Maintenance Manifest root is missing") from error
        if any(not path.is_absolute() for path in roots.values()) or len(set(roots.values())) != len(roots):
            raise Phase6BManifestError("Maintenance Manifest roots must be absolute and distinct")
        operational_roots = [roots[name] for name in required_roots[1:]]
        if any(
            _inside(left, right) or _inside(right, left)
            for index, left in enumerate(operational_roots)
            for right in operational_roots[index + 1 :]
        ):
            raise Phase6BManifestError("Maintenance operational roots must not contain one another")
        production = roots["production_home"]
        if any(_inside(production, roots[name]) or _inside(roots[name], production) for name in required_roots[1:]):
            raise Phase6BManifestError("Production and operational roots must be physically disjoint")
        if environment == "CONTROLLED_PRODUCTION_SIMULATION":
            if not (production / ".sitina-bplus-disposable-v1").is_file() or production == Path("/Users/moss/SitinaHub"):
                raise Phase6BManifestError("controlled Production simulation requires a disposable marker")
        elif production != Path("/Users/moss/SitinaHub").resolve(strict=False):
            raise Phase6BManifestError("Production manifest names an unexpected installation")

        window = raw.get("window")
        if not isinstance(window, Mapping):
            raise Phase6BManifestError("Maintenance window is missing")
        try:
            starts, ends, expires = (int(window[name]) for name in ("starts_at", "ends_at", "expires_at"))
        except (KeyError, TypeError, ValueError) as error:
            raise Phase6BManifestError("Maintenance window is malformed") from error
        if not starts <= moment <= expires <= ends or ends - starts > 6 * 3600:
            raise Phase6BManifestError("Maintenance window is expired, premature, or too broad")

        operations = tuple(str(item) for item in raw.get("authorized_operations", ()))
        if operations != PHASE6B_OPERATION_IDS:
            raise Phase6BManifestError("Maintenance Manifest operation registry is incomplete or reordered")
        code = raw.get("code_identities")
        if not isinstance(code, Mapping) or not code:
            raise Phase6BManifestError("code/config identities are missing")
        for name, expected in code.items():
            path = Path(str(name)).expanduser().resolve(strict=True)
            if not _SHA.fullmatch(str(expected)) or _hash_file(path) != expected:
                raise Phase6BManifestError(f"code/config identity drift: {path}")

        quorum = raw.get("operator_quorum")
        if not isinstance(quorum, Sequence) or isinstance(quorum, (str, bytes)) or len(quorum) < 3:
            raise Phase6BManifestError("owner, verifier, and executor quorum is required")
        principals: set[str] = set()
        roles: set[str] = set()
        for item in quorum:
            if not isinstance(item, Mapping) or item.get("human_identity_claimed") is not False:
                raise Phase6BManifestError("technical quorum may not fabricate a human identity")
            principals.add(str(item.get("principal_id", "")))
            roles.add(str(item.get("role", "")))
        if len(principals) != len(quorum) or roles != {"OWNER_PRINCIPAL", "INDEPENDENT_TECHNICAL_VERIFIER", "EXECUTION_PRINCIPAL"}:
            raise Phase6BManifestError("operator quorum roles are not independent and complete")
        prerequisites = raw.get("prerequisites")
        if not isinstance(prerequisites, Mapping) or not prerequisites or not all(item is True for item in prerequisites.values()):
            raise Phase6BManifestError("Maintenance prerequisites are incomplete")
        prerequisite_artifacts = raw.get("prerequisite_artifacts")
        if not isinstance(prerequisite_artifacts, Mapping) or not prerequisite_artifacts:
            raise Phase6BManifestError("Maintenance prerequisite artifacts are missing")
        verified_prerequisites: dict[str, str] = {}
        for name, artifact in prerequisite_artifacts.items():
            if not isinstance(artifact, Mapping):
                raise Phase6BManifestError("Maintenance prerequisite artifact is malformed")
            path = Path(str(artifact.get("path", ""))).expanduser().resolve(strict=True)
            expected = str(artifact.get("physical_sha256", ""))
            if not _SHA.fullmatch(expected) or _hash_file(path) != expected:
                raise Phase6BManifestError(f"Maintenance prerequisite artifact drift: {path}")
            verified_prerequisites[str(name)] = expected
        stops = raw.get("stop_conditions")
        if not isinstance(stops, Sequence) or isinstance(stops, (str, bytes)) or not stops:
            raise Phase6BManifestError("Maintenance stop conditions are required")
        genesis = raw.get("production_genesis")
        command = raw.get("cutover_command")
        verified_command = raw.get("cutover_verified_command")
        if not isinstance(genesis, Mapping) or not isinstance(command, Mapping) or not isinstance(verified_command, Mapping):
            raise Phase6BManifestError("Production Genesis or stable authority command contract is missing")
        source_manifest = str(raw.get("source_manifest_sha256", ""))
        if not _SHA.fullmatch(source_manifest):
            raise Phase6BManifestError("source manifest identity is invalid")
        body = command.get("request_body")
        request_hash = str(command.get("request_hash", ""))
        if not isinstance(body, Mapping) or request_hash != domain_hash("CUTOVER_COMMAND_REQUEST", canonical_json_bytes(dict(body))):
            raise Phase6BManifestError("stable Cutover Command request hash is invalid")
        quorum_by_role = {str(item["role"]): str(item["principal_id"]) for item in quorum}
        if (
            genesis.get("operator_id") != quorum_by_role["EXECUTION_PRINCIPAL"]
            or genesis.get("verifier_id") != quorum_by_role["INDEPENDENT_TECHNICAL_VERIFIER"]
        ):
            raise Phase6BManifestError("Production Genesis operator/verifier bindings differ from the quorum")
        try:
            from sitina.legacy.production_genesis import ProductionGenesisBuilder
            expected_genesis = ProductionGenesisBuilder(production).derive_manifest_artifact(
                genesis, environment_kind=environment
            )
        except Exception as error:
            raise Phase6BManifestError("Production Genesis exact bytes are invalid") from error
        if genesis.get("genesis_hash") != expected_genesis.genesis_hash:
            raise Phase6BManifestError("Production Genesis hash differs from its exact bytes")
        if (
            body.get("genesis_hash") != expected_genesis.genesis_hash
            or body.get("snapshot_hash") != genesis.get("intended_snapshot_hash")
        ):
            raise Phase6BManifestError("stable Cutover Command does not bind the exact Genesis and snapshot intent")
        expected_migration_contract = domain_hash(
            "MIGRATION_CONTRACT",
            canonical_json_bytes({
                "snapshot_hash": genesis.get("intended_snapshot_hash"),
                "format_profile_hash": genesis.get("format_profile_hash"),
            }),
        )
        if (
            body.get("schema") != "AUTHORITY_CUTOVER_REQUEST_V1"
            or body.get("migration_contract_hash") != expected_migration_contract
            or body.get("source_manifest_sha256") != source_manifest
            or body.get("readiness_sha256") != readiness_claim
            or body.get("operator_authorization_hash") != _STANDING_HASH.removeprefix("sha256:")
            or body.get("effect_drain_hash") != verified_prerequisites.get("effect_drain")
            or body.get("monitoring_transfer_hash") != verified_prerequisites.get("monitoring_transfer")
            or body.get("key_profile_hash") != verified_prerequisites.get("key_profile")
        ):
            raise Phase6BManifestError("stable Cutover Command contract bindings are incomplete or invalid")
        if not _UTC.fullmatch(str(command.get("occurred_at", ""))):
            raise Phase6BManifestError("stable Cutover Command timestamp is invalid")
        verified_id = str(verified_command.get("command_id", ""))
        required_predicates = verified_command.get("required_predicates")
        required_reports = verified_command.get("required_report_hashes")
        if (
            not verified_id or verified_id == str(command.get("command_id", ""))
            or not isinstance(required_predicates, Sequence) or isinstance(required_predicates, (str, bytes))
            or not isinstance(required_reports, Sequence) or isinstance(required_reports, (str, bytes))
            or not required_predicates or not required_reports
            or len(set(map(str, required_predicates))) != len(required_predicates)
            or len(set(map(str, required_reports))) != len(required_reports)
            or not _UTC.fullmatch(str(verified_command.get("occurred_at", "")))
        ):
            raise Phase6BManifestError("stable CutoverVerified command contract is invalid")
        source_manifest_path = Path(str(raw.get("source_manifest_path", ""))).expanduser().resolve(strict=True)
        try:
            source_value = json.loads(source_manifest_path.read_text(encoding="utf-8"))
            if not isinstance(source_value, dict):
                raise TypeError("source manifest is not an object")
            source_claim = str(source_value.pop("manifest_sha256"))
        except Exception as error:
            raise Phase6BManifestError("source content manifest cannot be verified") from error
        if source_claim != source_manifest or hashlib.sha256(_canonical(source_value)).hexdigest() != source_claim:
            raise Phase6BManifestError("source content manifest canonical hash is invalid")
        source_root = Path(str(source_value.get("root", ""))).expanduser().resolve(strict=True)
        entries = source_value.get("entries")
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)) or not entries:
            raise Phase6BManifestError("source content manifest has no entries")
        source_entries: dict[Path, Mapping[str, object]] = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise Phase6BManifestError("source content manifest entry is malformed")
            relative = Path(str(entry.get("path", "")))
            if relative.is_absolute() or ".." in relative.parts:
                raise Phase6BManifestError("source content manifest path escapes its root")
            path = (source_root / relative).resolve(strict=True)
            if path.is_symlink() or not path.is_file() or not _inside(path, source_root):
                raise Phase6BManifestError("source content manifest entry is not a regular in-root file")
            metadata = path.stat()
            if (
                _hash_file(path) != entry.get("sha256")
                or metadata.st_size != int(entry.get("size", -1))
                or oct(stat.S_IMODE(metadata.st_mode)) != entry.get("mode")
            ):
                raise Phase6BManifestError(f"source content identity drift: {path}")
            source_entries[path] = entry
        for name, expected in code.items():
            path = Path(str(name)).expanduser().resolve(strict=True)
            if path.is_relative_to(source_root):
                if path not in source_entries or source_entries[path].get("sha256") != expected:
                    raise Phase6BManifestError(f"code identity is absent from the source content manifest: {path}")
        return Phase6BOperationalCapability(
            claimed_manifest,
            environment,
            production,
            roots["snapshot_root"],
            roots["migration_root"],
            roots["backup_root"],
            roots["control_root"],
            operations,
            starts,
            ends,
            expires,
            dict(genesis),
            dict(command),
            dict(verified_command),
            source_manifest,
            readiness_claim,
            "verified-phase6b:" + hashlib.sha256(signed + bytes.fromhex(signature_hex)).hexdigest(),
        )


class AuthorityControlStream:
    """Append and independently recover the stable Phase 6B authority commands."""

    stream_id = "authority/control"

    def __init__(self, journal: Any, capability: Phase6BOperationalCapability, genesis: Any, *, now: int):
        capability.assert_operation("OPEN_PRODUCTION_JOURNAL_CONTROL_PLANE", journal.home, now=now)
        if genesis.genesis_hash != getattr(journal, "genesis_hash", None):
            raise Phase6BManifestError("Journal and Production Genesis bindings differ")
        self.journal = journal
        self.capability = capability
        self.genesis = genesis
        self.now = int(now)
        self._occurred_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now))

    def _expected(self) -> int:
        return sum(1 for event in self.journal.iter_events(0) if event.stream_id == self.stream_id)

    def _append(
        self,
        command_id: str,
        command_type: str,
        payload: Mapping[str, object],
        event_type: str,
        *,
        occurred_at: str | None = None,
    ):
        timestamp = self._occurred_at if occurred_at is None else occurred_at
        command = CommandEnvelope(command_id, "system", self.stream_id, command_type, "phase6b-executor", timestamp, dict(payload))
        event = EventEnvelope(
            "event-" + domain_hash("AUTHORITY_CONTROL_EVENT_ID", canonical_json_bytes({"command_id": command_id, "request_hash": command.command_request_hash}))[:48],
            event_type,
            "system",
            self.stream_id,
            0,
            0,
            timestamp,
            dict(payload),
        )
        return self.journal.append(command, self._expected(), [event])

    def record_genesis_and_prepare(self, *, migration_frontier_hash: str, fence_record_hash: str | None):
        if not _SHA.fullmatch(migration_frontier_hash) or not isinstance(fence_record_hash, str) or not fence_record_hash.startswith("sha256:"):
            raise Phase6BManifestError("migration frontier or writer fence proof is invalid")
        payload = {
            "schema": "CUTOVER_PREPARED_FACT_V1",
            "manifest_sha256": self.capability.manifest_sha256,
            "genesis_hash": self.genesis.genesis_hash,
            "snapshot_hash": str(self.capability.production_genesis["intended_snapshot_hash"]),
            "migration_frontier_hash": migration_frontier_hash,
            "fence_record_hash": fence_record_hash,
            "cutover_command_id": str(self.capability.cutover_command["command_id"]),
            "cutover_request_hash": str(self.capability.cutover_command["request_hash"]),
            "business_writer_count": 0,
        }
        return self._append(
            "prepare-" + self.capability.manifest_sha256[:48],
            "authority.cutover.prepare",
            payload,
            "authority.cutover.prepared",
            occurred_at=str(self.capability.cutover_command["occurred_at"]),
        )

    def _cutover_payload(self, request_body: Mapping[str, object] | None = None) -> dict[str, object]:
        body = dict(request_body) if request_body is not None else dict(self.capability.cutover_command["request_body"])
        prepared = next(
            (event for event in reversed(self._events()) if event.event_type == "authority.cutover.prepared"),
            None,
        )
        if prepared is None or not _SHA.fullmatch(str(prepared.payload.get("migration_frontier_hash", ""))):
            raise Phase6BManifestError("stable Cutover Command requires the committed prepared migration frontier")
        return {
            "schema": "AUTHORITY_CUTOVER_COMMITTED_V1",
            "manifest_sha256": self.capability.manifest_sha256,
            "command_id": str(self.capability.cutover_command["command_id"]),
            "request_hash": domain_hash("CUTOVER_COMMAND_REQUEST", canonical_json_bytes(body)),
            "request_body": body,
            "genesis_hash": self.genesis.genesis_hash,
            "snapshot_hash": str(self.capability.production_genesis["intended_snapshot_hash"]),
            "migration_frontier_hash": str(prepared.payload["migration_frontier_hash"]),
            "outcome": "COMMITTED",
        }

    def _cutover_command(self, request_body: Mapping[str, object] | None = None) -> CommandEnvelope:
        payload = self._cutover_payload(request_body)
        return CommandEnvelope(
            str(self.capability.cutover_command["command_id"]),
            "system",
            self.stream_id,
            "authority.cutover.commit",
            "phase6b-executor",
            str(self.capability.cutover_command["occurred_at"]),
            payload,
        )

    def submit_cutover(self, request_body: Mapping[str, object] | None = None):
        self.capability.assert_operation("SUBMIT_STABLE_CUTOVER_COMMAND", self.journal.home, now=self.now)
        command = self._cutover_command(request_body)
        payload = dict(command.payload)
        event = EventEnvelope(
            "event-" + domain_hash("AUTHORITY_CUTOVER_EVENT_ID", command.canonical_request_bytes())[:48],
            "authority.cutover.committed",
            "system",
            self.stream_id,
            0,
            0,
            str(self.capability.cutover_command["occurred_at"]),
            payload,
        )
        return self.journal.append(command, self._expected(), [event])

    def recover_cutover(self) -> CommandResult:
        self.capability.assert_operation("RECOVER_STABLE_CUTOVER_COMMAND", self.journal.home, now=self.now)
        command = self._cutover_command()
        return self.journal.query_command(command.command_id, command.command_request_hash)

    def _events(self) -> tuple[Any, ...]:
        return tuple(event for event in self.journal.iter_events(0) if event.stream_id == self.stream_id)

    def resolve_authority(self, *, now: int):
        events = self._events()
        prepared = next((event for event in events if event.event_type == "authority.cutover.prepared"), None)
        committed = next((event for event in events if event.event_type == "authority.cutover.committed"), None)
        request_hash = str(self.capability.cutover_command["request_hash"])
        snapshot_hash = str(self.capability.production_genesis["intended_snapshot_hash"])
        frontier = events[-1].event_hash if events and events[-1].event_hash else "0" * 64
        committed_valid = bool(committed) and bool(prepared) and all((
            committed.payload.get("command_id") == self.capability.cutover_command["command_id"],
            committed.payload.get("request_hash") == request_hash,
            committed.payload.get("genesis_hash") == self.genesis.genesis_hash,
            committed.payload.get("snapshot_hash") == snapshot_hash,
            committed.payload.get("migration_frontier_hash") == prepared.payload.get("migration_frontier_hash"),
            committed.payload.get("outcome") == "COMMITTED",
        ))
        facts = AuthorityControlFacts(
            True,
            all(bool(event.event_hash and event.journal_auth_tag) for event in events),
            all(event.position == index for index, event in enumerate(self.journal.iter_events(0), 1)),
            False,
            False,
            LegacyAuthorityFact(True, str(prepared.payload.get("fence_record_hash")), frontier) if prepared else None,
            not prepared,
            prepared is not None,
            str(self.capability.cutover_command["command_id"]),
            request_hash,
            self.genesis.genesis_hash,
            snapshot_hash,
            "COMMITTED" if committed else "ABSENT",
            committed_valid,
            str(committed.payload.get("command_id")) if committed else None,
            str(committed.payload.get("request_hash")) if committed else None,
            str(committed.payload.get("genesis_hash")) if committed else None,
            str(committed.payload.get("snapshot_hash")) if committed else None,
            frontier,
        )
        return AuthorityResolver("phase6b-authority-control-reader-v1", "authority-resolver-v1", ttl=300).resolve(facts, now=now)

    def submit_cutover_verified(
        self,
        *,
        command_id: str,
        predicates: Mapping[str, bool],
        report_hashes: Mapping[str, str],
    ):
        self.capability.assert_operation("SUBMIT_STABLE_CUTOVER_VERIFIED_COMMAND", self.journal.home, now=self.now)
        contract = self.capability.cutover_verified_command
        if command_id != str(contract["command_id"]):
            raise Phase6BManifestError("CutoverVerified Command ID differs from the Maintenance Manifest")
        if set(predicates) != set(map(str, contract["required_predicates"])):
            raise Phase6BManifestError("CutoverVerified predicates differ from the frozen verification contract")
        if set(report_hashes) != set(map(str, contract["required_report_hashes"])):
            raise Phase6BManifestError("CutoverVerified report hashes differ from the frozen verification contract")
        resolution = self.resolve_authority(now=self.now)
        if not resolution.authorizes_journal or resolution.writer_count != 1:
            raise Phase6BManifestError("CutoverVerified requires committed Journal writer authority")
        if not predicates or not all(item is True for item in predicates.values()):
            raise Phase6BManifestError("CutoverVerified predicates are incomplete")
        if not report_hashes or any(not _SHA.fullmatch(str(item)) for item in report_hashes.values()):
            raise Phase6BManifestError("CutoverVerified report hashes are invalid")
        payload = {
            "schema": "CUTOVER_VERIFIED_COMMITTED_V1",
            "manifest_sha256": self.capability.manifest_sha256,
            "cutover_command_id": str(self.capability.cutover_command["command_id"]),
            "cutover_request_hash": str(self.capability.cutover_command["request_hash"]),
            "genesis_hash": self.genesis.genesis_hash,
            "snapshot_hash": str(self.capability.production_genesis["intended_snapshot_hash"]),
            "predicates": dict(sorted(predicates.items())),
            "report_hashes": dict(sorted(report_hashes.items())),
            "outcome": "COMMITTED",
        }
        return self._append(
            command_id,
            "authority.cutover-verified.commit",
            payload,
            "authority.cutover-verified.committed",
            occurred_at=str(contract["occurred_at"]),
        )

    def verify_committed_cutover_verified(self, command_id: str) -> dict[str, object]:
        matching = [
            event for event in self._events()
            if event.event_type == "authority.cutover-verified.committed" and event.payload.get("outcome") == "COMMITTED"
        ]
        if not matching:
            return {"verified": False, "command_id": command_id}
        event = matching[-1]
        payload = dict(event.payload)
        command = CommandEnvelope(
            command_id,
            "system",
            self.stream_id,
            "authority.cutover-verified.commit",
            "phase6b-executor",
            str(self.capability.cutover_verified_command["occurred_at"]),
            payload,
        )
        outcome = self.journal.query_command(command_id, command.command_request_hash)
        predicates = payload.get("predicates")
        reports = payload.get("report_hashes")
        exact = all((
            outcome.status is CommandStatus.COMMITTED,
            payload.get("manifest_sha256") == self.capability.manifest_sha256,
            payload.get("cutover_command_id") == self.capability.cutover_command["command_id"],
            payload.get("cutover_request_hash") == self.capability.cutover_command["request_hash"],
            payload.get("genesis_hash") == self.genesis.genesis_hash,
            payload.get("snapshot_hash") == self.capability.production_genesis["intended_snapshot_hash"],
            payload.get("outcome") == "COMMITTED",
            isinstance(predicates, Mapping) and set(predicates) == set(self.capability.cutover_verified_command["required_predicates"]),
            isinstance(predicates, Mapping) and all(value is True for value in predicates.values()),
            isinstance(reports, Mapping) and set(reports) == set(self.capability.cutover_verified_command["required_report_hashes"]),
            isinstance(reports, Mapping) and all(_SHA.fullmatch(str(value)) for value in reports.values()),
            bool(event.event_hash and event.journal_auth_tag),
        ))
        return {
            "verified": exact,
            "command_id": command_id,
            "event_hash": event.event_hash,
            "position": event.position,
            "genesis_hash": event.payload.get("genesis_hash"),
        }


@dataclass(frozen=True)
class ProductionAuthorityReadResult:
    resolution: Any
    events: tuple[Any, ...]
    command_count: int
    control_frontier_hash: str
    read_mode: str = "AUTHORITATIVE_SLOW_READ"
    journal_bytes_scanned: int = 0
    fast_start_report: Any | None = None


class ProductionAuthorityReader:
    """Resolve Production writer authority from authenticated Journal bytes only."""

    @staticmethod
    def resolve(
        home: Path,
        authenticator: Any,
        *,
        journal_id: str,
        epoch: int,
        command_id: str,
        request_hash: str,
        genesis_hash: str,
        snapshot_hash: str,
        fence_record_hash: str,
        now: int,
        authority_key_provider: Any | None = None,
        rollback_anchor: Any | None = None,
    ) -> ProductionAuthorityReadResult:
        root = Path(home).resolve(strict=True) / "journal"
        fast_report = None
        bytes_scanned = 0
        checkpoint_paths = tuple((root / "checkpoints").glob("checkpoint-*.json"))
        if checkpoint_paths:
            if authority_key_provider is None or rollback_anchor is None:
                raise Phase6BManifestError("Production fast-start metadata exists but its Keychain verifier is unavailable")
            fast_report = FastStartLoader(
                Path(home),
                journal_authenticator=authenticator,
                authority_key_provider=authority_key_provider,
                rollback_anchor=rollback_anchor,
            ).load()
            if fast_report.authority_state.journal_id != journal_id or fast_report.authority_state.epoch != epoch:
                raise Phase6BManifestError("Production fast-start authority identity differs from Genesis")
            events = list(fast_report.authority_control_events) + list(fast_report.active_tail_events)
            commands = {
                str(item[0]): str(item[1])
                for item in fast_report.authority_state.command_bindings
            }
            conflicting = False
            continuity = True
            bytes_scanned = fast_report.journal_bytes_scanned
            read_mode = "FAST_START_CHECKPOINT_PLUS_ACTIVE_TAIL"
        else:
            frames = []
            for path in sorted((root / "sealed").glob("*.seg")):
                frames.extend(scan_sealed_segment(path).frames)
                bytes_scanned += path.stat().st_size
            active = root / "active.seg"
            if not active.is_file() or active.is_symlink():
                raise Phase6BManifestError("Production Journal active prefix is unavailable")
            frames.extend(scan_active_segment_read_only(active).frames)
            bytes_scanned += active.stat().st_size
            expected = 1
            events = []
            commands = {}
            conflicting = False
            continuity = True
            for frame in frames:
                transaction = frame.transaction
                if transaction.first_position != expected:
                    continuity = False
                previous = commands.get(transaction.command_id)
                if previous is not None and previous != transaction.command_request_hash:
                    conflicting = True
                commands[transaction.command_id] = transaction.command_request_hash
                for event in transaction.events:
                    if not event.verify(journal_id=journal_id, epoch=epoch, authenticator=authenticator):
                        raise Phase6BManifestError("Production Journal auth verification failed")
                    events.append(event)
                expected = transaction.last_position + 1
            read_mode = "AUTHORITATIVE_SLOW_READ_NO_CHECKPOINT"
        control = tuple(event for event in events if event.stream_id == AuthorityControlStream.stream_id)
        prepared_events = tuple(event for event in control if event.event_type == "authority.cutover.prepared")
        committed_events = tuple(event for event in control if event.event_type == "authority.cutover.committed")
        prepared = prepared_events[-1] if prepared_events else None
        committed = committed_events[-1] if committed_events else None
        frontier = control[-1].event_hash if control and control[-1].event_hash else "0" * 64
        prepared_valid = bool(prepared) and all((
            prepared.payload.get("genesis_hash") == genesis_hash,
            prepared.payload.get("snapshot_hash") == snapshot_hash,
            prepared.payload.get("fence_record_hash") == fence_record_hash,
            prepared.payload.get("cutover_command_id") == command_id,
            prepared.payload.get("cutover_request_hash") == request_hash,
            prepared.payload.get("business_writer_count") == 0,
        ))
        committed_valid = bool(committed) and all((
            committed.payload.get("command_id") == command_id,
            committed.payload.get("request_hash") == request_hash,
            committed.payload.get("genesis_hash") == genesis_hash,
            committed.payload.get("snapshot_hash") == snapshot_hash,
            bool(prepared) and committed.payload.get("migration_frontier_hash") == prepared.payload.get("migration_frontier_hash"),
            committed.payload.get("outcome") == "COMMITTED",
        ))
        conflicting = conflicting or len(prepared_events) > 1 or len(committed_events) > 1
        same_identity_conflict = commands.get(command_id) is not None and not committed_valid
        facts = AuthorityControlFacts(
            True,
            True,
            continuity,
            conflicting,
            same_identity_conflict,
            LegacyAuthorityFact(prepared_valid, fence_record_hash, frontier) if prepared else None,
            not prepared,
            prepared is not None,
            command_id,
            request_hash,
            genesis_hash,
            snapshot_hash,
            "COMMITTED" if committed else "ABSENT",
            committed_valid,
            str(committed.payload.get("command_id")) if committed else None,
            str(committed.payload.get("request_hash")) if committed else None,
            str(committed.payload.get("genesis_hash")) if committed else None,
            str(committed.payload.get("snapshot_hash")) if committed else None,
            frontier,
        )
        resolution = AuthorityResolver("phase6b-production-journal-reader-v1", "authority-resolver-v1", ttl=300).resolve(facts, now=now)
        return ProductionAuthorityReadResult(
            resolution,
            tuple(events),
            len(commands),
            frontier,
            read_mode,
            bytes_scanned,
            fast_report,
        )
