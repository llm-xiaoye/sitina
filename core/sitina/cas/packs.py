from __future__ import annotations

import hashlib
import json
import os
import struct
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes


class PackError(RuntimeError):
    pass


class PackWriteDisabled(PackError):
    pass


class MetadataPackWriter:
    def __init__(
        self,
        home: str | Path,
        *,
        kind: str,
        write_enabled: bool,
        feature_activations: object | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ):
        if kind not in {"alias", "envelope"}:
            raise PackError("pack kind must be alias or envelope")
        self.home = Path(home).resolve(strict=True)
        self.kind = kind
        self.write_enabled = write_enabled
        self.feature_activations = feature_activations
        self.fault_injector = fault_injector
        self.root = self.home / "cas" / "packs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.pack_path = self.root / f"{kind}-pack-000001.dat"
        self.index_path = self.root / f"{kind}-pack-000001.idx"
        self.manifest_path = self.root / f"{kind}-pack-manifest.json"

    def _fault(self, boundary: str) -> None:
        if self.fault_injector:
            self.fault_injector(boundary)

    def _assert_write_enabled(self) -> None:
        if not self.write_enabled:
            raise PackWriteDisabled("metadata pack writer feature is disabled")
        protected = (
            self.home == Path("/Users/moss/SitinaHub")
            or (self.home / ".sitina-clean-acceptance-v1").is_file()
            or (self.home / "state/bplus-production-genesis/genesis.json").is_file()
        )
        if self.feature_activations is None:
            if protected:
                raise PackWriteDisabled("protected metadata pack writer requires Journal feature activation")
            return
        try:
            self.feature_activations.assert_write_enabled("alias_pack_v1_write")
        except Exception as error:
            raise PackWriteDisabled("metadata pack writer requires alias_pack_v1_write activation") from error

    def _assert_active_pack(self) -> None:
        if not self.manifest_path.is_file():
            return
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if manifest.get("state", "ACTIVE") == "SEALED":
            raise PackWriteDisabled("sealed metadata pack is immutable")

    def _scan(self) -> tuple[dict[str, dict[str, Any]], int]:
        index: dict[str, dict[str, Any]] = {}
        if not self.pack_path.exists():
            return index, 0
        with self.pack_path.open("rb") as handle:
            while True:
                offset = handle.tell()
                header = handle.read(4)
                if not header:
                    return index, offset
                if len(header) != 4:
                    return index, offset
                length = struct.unpack(">I", header)[0]
                raw = handle.read(length)
                digest = handle.read(32)
                if len(raw) != length or len(digest) != 32 or hashlib.sha256(raw).digest() != digest:
                    return index, offset
                value = json.loads(raw)
                record_id = value.get("record_id")
                if not isinstance(record_id, str) or not record_id:
                    raise PackError("pack record has invalid identity")
                index[record_id] = {
                    "offset": offset,
                    "record_length": 4 + length + 32,
                    "payload_length": length,
                    "record_hash": digest.hex(),
                }

    def _sync_directory(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic(self, path: Path, value: Mapping[str, Any]) -> None:
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, canonical_json_bytes(dict(value)) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        self._sync_directory()

    def append(self, record_id: str, payload: Mapping[str, Any], *, replace: bool = False) -> None:
        self._assert_write_enabled()
        self._assert_active_pack()
        indexed, _ = self._scan()
        existing_payload = MetadataPackReader(self.home, kind=self.kind).get(record_id)
        if existing_payload == dict(payload):
            return
        if record_id in indexed and not replace:
            raise PackError("metadata pack record identity is already bound to different content")
        if record_id not in indexed or replace:
            value = {"schema": "SITINA_METADATA_PACK_RECORD_V1", "record_id": record_id, "payload": dict(payload)}
            raw = canonical_json_bytes(value)
            record = struct.pack(">I", len(raw)) + raw + hashlib.sha256(raw).digest()
            fd = os.open(self.pack_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                view = memoryview(record)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short pack append")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._fault("after_pack_fsync")
        self.reconcile()

    def reconcile_candidates(self) -> tuple[str, ...]:
        scanned, _ = self._scan()
        committed: set[str] = set()
        if self.manifest_path.is_file() and self.index_path.is_file():
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            index = json.loads(self.index_path.read_text(encoding="utf-8"))
            if manifest.get("index_hash") == hashlib.sha256(canonical_json_bytes(index)).hexdigest():
                committed = set(index.get("records", {}))
        return tuple(sorted(set(scanned) - committed))

    def reconcile(self) -> None:
        self._assert_write_enabled()
        self._assert_active_pack()
        index, pack_size = self._scan()
        index_value = {
            "schema": "SITINA_METADATA_PACK_INDEX_V1",
            "kind": self.kind,
            "pack": self.pack_path.name,
            "indexed_pack_size": pack_size,
            "records": index,
        }
        self._atomic(self.index_path, index_value)
        self._fault("after_index_fsync")
        manifest = {
            "schema": "SITINA_METADATA_PACK_MANIFEST_V1",
            "kind": self.kind,
            "active_pack": self.pack_path.name,
            "active_index": self.index_path.name,
            "index_hash": hashlib.sha256(canonical_json_bytes(index_value)).hexdigest(),
            "indexed_pack_size": pack_size,
            "state": "ACTIVE",
        }
        self._atomic(self.manifest_path, manifest)
        self._fault("after_manifest_switch")

    def seal(self) -> None:
        self._assert_write_enabled()
        self._assert_active_pack()
        if not self.manifest_path.is_file():
            self.reconcile()
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        manifest["state"] = "SEALED"
        manifest["sealed_pack_hash"] = hashlib.sha256(self.pack_path.read_bytes() if self.pack_path.exists() else b"").hexdigest()
        self._atomic(self.manifest_path, manifest)


class MetadataPackReader:
    def __init__(self, home: str | Path, *, kind: str):
        self.home = Path(home).resolve(strict=True)
        self.kind = kind
        self.root = self.home / "cas" / "packs"

    def get(self, record_id: str) -> dict[str, Any] | None:
        manifest_path = self.root / f"{self.kind}-pack-manifest.json"
        if not manifest_path.is_file():
            return None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != "SITINA_METADATA_PACK_MANIFEST_V1" or manifest.get("kind") != self.kind:
            raise PackError("pack manifest schema/kind mismatch")
        active_index = manifest.get("active_index")
        active_pack = manifest.get("active_pack")
        if (
            not isinstance(active_index, str)
            or not isinstance(active_pack, str)
            or Path(active_index).name != active_index
            or Path(active_pack).name != active_pack
        ):
            raise PackError("pack manifest contains an unsafe path")
        index_path = self.root / active_index
        pack_path = self.root / active_pack
        if not index_path.is_file() or index_path.is_symlink() or not pack_path.is_file() or pack_path.is_symlink():
            raise PackError("pack manifest target is missing or unsafe")
        if manifest.get("state", "ACTIVE") == "SEALED":
            expected = manifest.get("sealed_pack_hash")
            if expected != hashlib.sha256(pack_path.read_bytes()).hexdigest():
                raise PackError("sealed metadata pack hash mismatch")
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if index.get("schema") != "SITINA_METADATA_PACK_INDEX_V1" or index.get("kind") != self.kind:
            raise PackError("pack index schema/kind mismatch")
        if hashlib.sha256(canonical_json_bytes(index)).hexdigest() != manifest.get("index_hash"):
            raise PackError("pack index commitment mismatch")
        entry = index.get("records", {}).get(record_id)
        if entry is None:
            return None
        if entry["offset"] + entry["record_length"] > manifest["indexed_pack_size"]:
            raise PackError("unindexed pack tail is not visible")
        with pack_path.open("rb") as handle:
            handle.seek(entry["offset"])
            length = struct.unpack(">I", handle.read(4))[0]
            raw = handle.read(length)
            digest = handle.read(32)
        if hashlib.sha256(raw).digest() != digest or digest.hex() != entry["record_hash"]:
            raise PackError("pack record verification failed")
        value = json.loads(raw)
        if value.get("record_id") != record_id:
            raise PackError("pack record identity mismatch")
        return dict(value["payload"])
