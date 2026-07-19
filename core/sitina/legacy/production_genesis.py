from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class GenesisError(RuntimeError):
    pass


@dataclass(frozen=True)
class GenesisArtifact:
    genesis_id: str
    installation_id: str
    journal_id: str
    epoch_root: str
    key_namespace: str
    intended_snapshot_hash: str
    format_profile_hash: str
    operator_id: str
    verifier_id: str | None
    environment_kind: str
    root_path_hash: str
    authority: bool
    independently_verified: bool
    genesis_hash: str

    def body_mapping(self) -> dict[str, object]:
        return {
            "schema": "PRODUCTION_GENESIS_ARTIFACT_V1",
            "genesis_id": self.genesis_id,
            "installation_id": self.installation_id,
            "journal_id": self.journal_id,
            "epoch_root": self.epoch_root,
            "key_namespace": self.key_namespace,
            "intended_snapshot_hash": self.intended_snapshot_hash,
            "format_profile_hash": self.format_profile_hash,
            "operator_id": self.operator_id,
            "verifier_id": self.verifier_id,
            "environment_kind": self.environment_kind,
            "root_path_hash": self.root_path_hash,
            "authority": self.authority,
            "independently_verified": self.independently_verified,
        }

    def with_updates(self, **changes: object) -> "GenesisArtifact":
        changed = replace(self, **changes, genesis_hash="")
        return replace(changed, genesis_hash=domain_hash("PRODUCTION_GENESIS_ARTIFACT", canonical_json_bytes(changed.body_mapping())))


class ProductionGenesisBuilder:
    def __init__(self, root: Path):
        self.root = Path(root).resolve(strict=True)

    def build_fixture(
        self,
        *,
        installation_id: str,
        journal_id: str,
        epoch_root: str,
        key_namespace: str,
        intended_snapshot_hash: str,
        format_profile_hash: str,
        operator_id: str,
        feature_flags: Mapping[str, object] | None = None,
    ) -> GenesisArtifact:
        if not (self.root / ".sitina-bplus-disposable-v1").is_file() or self.root == Path("/Users/moss/SitinaHub"):
            raise GenesisError("Phase 6A fixture genesis requires a marked disposable root")
        for value, field in ((installation_id,"installation_id"),(journal_id,"journal_id"),(key_namespace,"key_namespace"),(operator_id,"operator_id")):
            validate_identifier(value,field=field)
        if "shadow" in journal_id.lower() or "shadow" in key_namespace.lower():
            raise GenesisError("Shadow identity cannot be reinterpreted as a Production genesis")
        if feature_flags and any(bool(value) for value in feature_flags.values()):
            raise GenesisError("phase or feature flags cannot grant genesis identity")
        if "fixture" not in key_namespace.lower() or "fixture" not in journal_id.lower():
            raise GenesisError("Phase 6A may build fixture-distinguished identities only")
        identity = domain_hash("FIXTURE_GENESIS_ID", canonical_json_bytes({"installation_id":installation_id,"journal_id":journal_id}))
        provisional = GenesisArtifact(
            "fixture-genesis:"+identity,installation_id,journal_id,epoch_root,key_namespace,intended_snapshot_hash,
            format_profile_hash,operator_id,None,"FIXTURE",domain_hash("GENESIS_ROOT_PATH",str(self.root).encode()),False,False,"",
        )
        return replace(provisional,genesis_hash=domain_hash("PRODUCTION_GENESIS_ARTIFACT",canonical_json_bytes(provisional.body_mapping())))

    def build_authorized(self, capability: object, *, now: int) -> GenesisArtifact:
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise GenesisError("Production Genesis requires a verified Phase 6B capability")
        capability.assert_operation("CREATE_PRODUCTION_GENESIS", self.root, now=now)
        if capability.production_home != self.root:
            raise GenesisError("Production Genesis root differs from the Maintenance Manifest")
        values = dict(capability.production_genesis)
        required = (
            "installation_id", "journal_id", "epoch_root", "key_namespace",
            "intended_snapshot_hash", "format_profile_hash", "operator_id", "verifier_id", "genesis_hash",
        )
        if any(name not in values for name in required):
            raise GenesisError("Maintenance Manifest Production Genesis is incomplete")
        artifact = self.derive_manifest_artifact(values, environment_kind=capability.environment_kind)
        if artifact.genesis_hash != str(values["genesis_hash"]):
            raise GenesisError("Maintenance Manifest Production Genesis hash is invalid")
        return artifact

    def derive_manifest_artifact(
        self,
        values: Mapping[str, object],
        *,
        environment_kind: str,
    ) -> GenesisArtifact:
        """Derive the exact Genesis bytes before signing a Maintenance Manifest."""
        required = (
            "installation_id", "journal_id", "epoch_root", "key_namespace",
            "intended_snapshot_hash", "format_profile_hash", "operator_id", "verifier_id",
        )
        if any(name not in values for name in required):
            raise GenesisError("Production Genesis derivation inputs are incomplete")
        for field in ("installation_id", "journal_id", "key_namespace", "operator_id"):
            validate_identifier(str(values[field]), field=field)
        validate_identifier(str(values["verifier_id"]), field="verifier_id")
        if str(values["operator_id"]) == str(values["verifier_id"]):
            raise GenesisError("Production Genesis verifier must be independent")
        if "fixture" in str(values["journal_id"]).lower() or "fixture" in str(values["key_namespace"]).lower():
            raise GenesisError("fixture identity cannot become a Production Genesis")
        identity = domain_hash(
            "PRODUCTION_GENESIS_ID",
            canonical_json_bytes({
                "installation_id": str(values["installation_id"]),
                "journal_id": str(values["journal_id"]),
                "epoch_root": str(values["epoch_root"]),
                "key_namespace": str(values["key_namespace"]),
                "intended_snapshot_hash": str(values["intended_snapshot_hash"]),
                "format_profile_hash": str(values["format_profile_hash"]),
                "root_path_hash": domain_hash("GENESIS_ROOT_PATH", str(self.root).encode()),
                "environment_kind": environment_kind,
            }),
        )
        provisional = GenesisArtifact(
            "production-genesis:" + identity,
            str(values["installation_id"]),
            str(values["journal_id"]),
            str(values["epoch_root"]),
            str(values["key_namespace"]),
            str(values["intended_snapshot_hash"]),
            str(values["format_profile_hash"]),
            str(values["operator_id"]),
            str(values["verifier_id"]),
            environment_kind,
            domain_hash("GENESIS_ROOT_PATH", str(self.root).encode()),
            False,
            True,
            "",
        )
        artifact = replace(
            provisional,
            genesis_hash=domain_hash("PRODUCTION_GENESIS_ARTIFACT", canonical_json_bytes(provisional.body_mapping())),
        )
        claimed = values.get("genesis_hash")
        if claimed is not None and str(claimed) != artifact.genesis_hash:
            raise GenesisError("claimed Production Genesis hash differs from its exact bytes")
        return artifact

    def verify_independent(self, artifact: GenesisArtifact, *, verifier_id: str) -> GenesisArtifact:
        validate_identifier(verifier_id,field="verifier_id")
        if verifier_id == artifact.operator_id:
            raise GenesisError("genesis requires an independent second verifier")
        if artifact.independently_verified:
            if artifact.verifier_id != verifier_id:
                raise GenesisError("Genesis is already bound to a different independent verifier")
            return artifact
        return artifact.with_updates(verifier_id=verifier_id,independently_verified=True)

    def persist_authorized(self, artifact: GenesisArtifact, capability: object, *, now: int) -> GenesisArtifact:
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise GenesisError("persisting Production Genesis requires a verified Phase 6B capability")
        capability.assert_operation("CREATE_PRODUCTION_GENESIS", self.root, now=now)
        if not artifact.independently_verified or artifact.environment_kind != capability.environment_kind:
            raise GenesisError("Production Genesis lacks independent verification or environment binding")
        if artifact.intended_snapshot_hash != str(capability.production_genesis["intended_snapshot_hash"]):
            raise GenesisError("Production Genesis snapshot binding differs from the Maintenance Manifest")
        value = {**artifact.body_mapping(), "genesis_hash": artifact.genesis_hash}
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
        directory = self.root / "state/bplus-production-genesis"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "genesis.json"
        if path.exists():
            if path.is_symlink() or path.read_bytes() != raw:
                raise GenesisError("Production Genesis path already contains different bytes")
            return artifact
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return artifact

    def load_persisted(self) -> GenesisArtifact:
        """Reconstruct and verify the durable Genesis without a Maintenance capability."""
        path = self.root / "state/bplus-production-genesis/genesis.json"
        if path.is_symlink() or not path.is_file():
            raise GenesisError("persisted Production Genesis is unavailable")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or value.get("schema") != "PRODUCTION_GENESIS_ARTIFACT_V1":
                raise GenesisError("persisted Production Genesis schema is invalid")
            artifact = GenesisArtifact(
                str(value["genesis_id"]),
                str(value["installation_id"]),
                str(value["journal_id"]),
                str(value["epoch_root"]),
                str(value["key_namespace"]),
                str(value["intended_snapshot_hash"]),
                str(value["format_profile_hash"]),
                str(value["operator_id"]),
                str(value["verifier_id"]) if value.get("verifier_id") is not None else None,
                str(value["environment_kind"]),
                str(value["root_path_hash"]),
                bool(value["authority"]),
                bool(value["independently_verified"]),
                str(value["genesis_hash"]),
            )
        except GenesisError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as error:
            raise GenesisError("persisted Production Genesis is malformed") from error
        expected_root = domain_hash("GENESIS_ROOT_PATH", str(self.root).encode())
        expected_hash = domain_hash("PRODUCTION_GENESIS_ARTIFACT", canonical_json_bytes(artifact.body_mapping()))
        if artifact.root_path_hash != expected_root or artifact.genesis_hash != expected_hash:
            raise GenesisError("persisted Production Genesis identity or root binding is invalid")
        if artifact.authority or not artifact.independently_verified or not artifact.verifier_id:
            raise GenesisError("persisted Production Genesis improperly asserts authority or lacks verification")
        if artifact.verifier_id == artifact.operator_id:
            raise GenesisError("persisted Production Genesis verifier is not independent")
        if artifact.environment_kind not in {"PRODUCTION", "CONTROLLED_PRODUCTION_SIMULATION"}:
            raise GenesisError("persisted Production Genesis environment is invalid")
        if any(len(item) != 64 or any(character not in "0123456789abcdef" for character in item) for item in (
            artifact.intended_snapshot_hash, artifact.format_profile_hash, artifact.genesis_hash,
        )):
            raise GenesisError("persisted Production Genesis hashes are invalid")
        return artifact


class GenesisRegistry:
    def __init__(self) -> None: self._accepted: dict[str,str] = {}
    def accept(self, artifact: GenesisArtifact) -> None:
        previous=self._accepted.get(artifact.genesis_id)
        if previous is not None and previous != artifact.genesis_hash:
            raise GenesisError("same genesis identity has different bytes")
        self._accepted[artifact.genesis_id]=artifact.genesis_hash
